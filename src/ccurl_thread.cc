/*
 *
 * Conky, a system monitor, based on torsmo
 *
 * Please see COPYING for details
 *
 * Copyright (c) 2005-2021 Brenden Matthews, Philip Kovacs, et. al.
 *	(see AUTHORS)
 * All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "ccurl_thread.h"
#include <cmath>
#include <mutex>
#include "conky.h"
#include "logging.h"
#include "text_object.h"

#ifdef DEBUG
#include <assert.h>
#endif /* DEBUG */

#include <curl/easy.h>


#ifdef BUILD_CURL_ADVANCED
//declare curl_opts config entry
conky::simple_config_setting<std::string> curl_opts("curl_opts", "", true);
#endif /* CURL_ADVANCED */



/*
 * The following code is the conky curl thread lib, which can be re-used to
 * create any curl-based object (see weather and rss).  Below is an
 * implementation of a curl-only object ($curl) which can also be used as an
 * example.
 */

namespace priv {
/* callback used by curl for parsing the header data */
size_t curl_internal::parse_header_cb(void *ptr, size_t size, size_t nmemb,
                                      void *data) {
  curl_internal *obj = static_cast<curl_internal *>(data);
  const char *value = static_cast<const char *>(ptr);
  size_t realsize = size * nmemb;

  if (realsize > 0 &&
      (value[realsize - 1] == '\r' || value[realsize - 1] == 0)) {
    --realsize;
  }

  if (strncmp(value, "Last-Modified: ", 15) == EQUAL) {
    obj->last_modified = std::string(value + 15, realsize - 15);
  } else if (strncmp(value, "ETag: ", 6) == EQUAL) {
    obj->etag = std::string(value + 6, realsize - 6);
  }

  return size * nmemb;
}

/* callback used by curl for writing the received data */
size_t curl_internal::write_cb(void *ptr, size_t size, size_t nmemb,
                               void *data) {
  curl_internal *obj = static_cast<curl_internal *>(data);
  const char *value = static_cast<const char *>(ptr);
  size_t realsize = size * nmemb;

  obj->data += std::string(value, realsize);

  return realsize;
}

curl_internal::curl_internal(const std::string &url) : curl(curl_easy_init()) {
  if (!curl) throw std::runtime_error("curl_easy_init() failed");

  curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1);
  curl_easy_setopt(curl, CURLOPT_HEADERDATA, this);
  curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, parse_header_cb);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, this);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(curl, CURLOPT_USERAGENT, "conky-curl/1.1");
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
  curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, 1000);
  curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, 60);

  // curl's usage of alarm()+longjmp() is a really bad idea for multi-threaded
  // applications
  curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);

#ifdef BUILD_CURL_ADVANCED

  if (0 != strcmp(curl_opts.get(*state).c_str(), "")) {
    // we have curl_opts to consider
    // convert curl_opts string into a json struct
    Json::Value curl_conf;
    Json::Reader reader;
    bool parse_success = reader.parse(curl_opts.get(*state), curl_conf);
    if (!parse_success) {
      NORM_ERR(
        "conky.config entry 'curl_opts' failed to parse as valid json."
        "Continuing without advanced options.\n");
      return;
    }
    if (!curl_conf.isObject()) {
      NORM_ERR(
        "conky.config entry 'curl_opts' did not parse as a json object."
        "%s"
        "Continuing without advanced options.\n",curl_opts.get(*state).c_str());
      return;
    }
    // look for key matching url
    if (curl_conf.isMember(url)) {
      const Json::Value& opts = curl_conf[url];
      //expect dictionary
      if (!opts.isObject()) {
        NORM_ERR(
          "'curl_opts' entry for '%s' did not parse as a json object."
          "Continuing without advanced options.\n", url.c_str());
        return;
      }
      apply_opts(curl, opts);
    } else {
      NORM_ERR("no curl_opts for url: %s", url.c_str());
    }
  }
#endif /* CURL_ADVANCED */

}

/* fetch our datums */
void curl_internal::do_work() {
  CURLcode res;
  //copy construct a temporary header list, so as not to destroy the original
  wrapped_slist headers(user_headers);
  data.clear();

  //updating the headers with etag and last_modified values is clever,
  //but it makes handling the data a little wonky....
  if (!last_modified.empty()) {
    headers.push("If-Modified-Since: " + last_modified);
    last_modified.clear();
  }
  if (!etag.empty()) {
    headers.push("If-None-Match: " + etag);
    etag.clear();
  }
  if (headers.slist)
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.slist);

  res = curl_easy_perform(curl);
  char *url = NULL;
  if (res == CURLE_OK) {
    long http_status_code;
    if (curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_status_code) ==
        CURLE_OK) {
      switch (http_status_code) {
        case 200:
          process_data();
          break;
        case 304:
          break;
        default:
          curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &url);
          NORM_ERR("curl: no data from server '%s', got HTTP status %ld",
                   url, http_status_code);
          break;
      }
    } else {
      curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &url);
      NORM_ERR("curl: no HTTP status from server '%s'", url);
    }
  } else {
    curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &url);
    NORM_ERR("curl: could not retrieve data from server '%s'",url);
  }
}

#ifdef BUILD_CURL_ADVANCED
//simple string opt
#define CASE_STR_OPT(name) \
    case cexpr_hash(#name): \
      curl_easy_setopt(curl, CURLOPT_##name, opts[opt_name].asString().c_str()); \
      break;

#define CASE_STR_CACHE_OPT(name, cache_var) \
    case cexpr_hash(#name): \
      cache_var = opts[opt_name].asString(); \
      curl_easy_setopt(curl, CURLOPT_##name, cache_var.c_str()); \
      break;

//simple long opt
#define CASE_LONG_OPT(name) \
    case cexpr_hash(#name): \
      curl_easy_setopt(curl, CURLOPT_##name, opts[opt_name].asInt64()); \
      break;

//bitmask opt defines
#define BEGIN_CASE_MASK_OPT(name) \
    case cexpr_hash(#name): \
      { /* extra scoping for initialized variables */ \
        long mask {0}; \
        for (const auto& token : vectorize(opts[opt_name], ",")) { \
          switch (cexpr_hash( token.c_str(), token.size() )) {

// fully expanded mask chunk
#define CASE_MASK(name, stem) \
          case cexpr_hash(#name): \
            mask |= stem##name ; \
            break;

// specific instantiations of CASE_MASK
#define CASE_AUTH_MASK(name) CASE_MASK(name, CURLAUTH_)
#define CASE_PROTO_MASK(name) CASE_MASK(name, CURLPROTO_)

#define END_CASE_MASK_OPT(name) \
          default: \
            NORM_ERR("curl option '##name' given unknown token '%s'", token.c_str()); \
            break; \
          } /* end switch */ \
        } /* end for */ \
        curl_easy_setopt(curl, CURLOPT_##name, mask); \
      }  /* end scope */ \
      break;



//enum opt defines
#define BEGIN_CASE_ENUM_OPT(name) \
    case cexpr_hash(#name): \
      { /* extra scope for variable initialization */ \
        auto type_str = opts[opt_name].asString(); \
        unsigned long type{0}; \
        switch (cexpr_hash( type_str.c_str(), type_str.size() )) {

// fully expanded enum chunk
#define CASE_ENUM(name, stem) \
        case cexpr_hash(#name): \
          type = stem##name; \
          break;

// specific instantiations
#define CASE_PROXY_ENUM(name) CASE_ENUM(name, CURLPROXY_)

#define END_CASE_ENUM_OPT(name) \
        default: \
          NORM_ERR("curl option '##name' given unknown token '%s'", type_str.c_str()); \
          break; \
        } \
        curl_easy_setopt(curl, CURLOPT_##name, type); \
      } /* end scope */ \
      break;


// expect cache_var to be of type wrapped_slist.
// the cache_var must have a lifecycle preceeding assignment here
// and extending past the call to curl_easy_perform.
#define CASE_LIST_OPT(name, cache_var) \
    case cexpr_hash(#name): \
      cache_var.batch_push(vectorize(opts[opt_name], ",")); \
      curl_easy_setopt(curl, CURLOPT_##name, cache_var.slist); \
      break; 

    

std::vector<std::string> vectorize(const Json::Value& input, const char* delim)
{
  std::vector<std::string> tokens;
  if (input.isArray()) {
    for (const auto& item : input) {
      tokens.emplace_back(item.asString());
    }
  } else if (input.isString() && delim != nullptr) {
    const auto& in_str = input.asString();
    std::string::size_type start{0};
    do {
      std::string::size_type end = in_str.find(delim, start);
      if (end == std::string::npos) {
        tokens.emplace_back(in_str.substr(start));
        start = end;
      } else {
        tokens.emplace_back(in_str.substr(start,end-start));
        start = end+1;
      }
    } while (start != std::string::npos);
  } else {
    tokens.emplace_back(input.asString());
  }
  return tokens;
}

//helpers to do compile-time hashing of tokens
class conststr
{
    const char* p;
    std::size_t sz;
public:
    template<std::size_t N>
    constexpr conststr(const char(&a)[N]) : p(a), sz(N - 1) {}
 
    constexpr char operator[](std::size_t n) const
    {
        return n < sz ? p[n] : throw std::out_of_range("");
    }
    constexpr std::size_t size() const { return sz; }
    constexpr const char* data() const {return p; }
};

constexpr std::size_t cexpr_hash(const char* s, std::size_t n_max, std::size_t n = 0, std::size_t p_pow=1, std::size_t h = 0) {
  //yoink constants and algorithm from https://cp-algorithms.com/string/string-hashing.html
  const int p = 31;
  const int m = 1e9 + 9;
  return n == n_max ? h :
      cexpr_hash( s, n_max, n+1, (p_pow * p) % m, (h + (s[n] - '`') * p_pow) % m );
}

constexpr std::size_t cexpr_hash(conststr s) {
  return cexpr_hash(s.data(), s.size());
}


//function to apply opts to curl
void curl_internal::apply_opts(CURL* curl, const Json::Value& opts) {
  for (const auto& opt_name : opts.getMemberNames()) {
    // built against documentation from https://curl.se/libcurl/c/curl_easy_setopt.html
    switch (cexpr_hash( opt_name.c_str(), opt_name.size() ))
    {
    CASE_LONG_OPT(VERBOSE)
    CASE_LONG_OPT(HEADER)
    CASE_STR_OPT(URL)
    CASE_LONG_OPT(PATH_AS_IS)
    BEGIN_CASE_MASK_OPT(PROTOCOLS)
      CASE_PROTO_MASK(DICT)
      CASE_PROTO_MASK(FILE)
      CASE_PROTO_MASK(FTP)
      CASE_PROTO_MASK(FTPS)
      CASE_PROTO_MASK(GOPHER)
      CASE_PROTO_MASK(HTTP)
      CASE_PROTO_MASK(HTTPS)
      CASE_PROTO_MASK(IMAP)
      CASE_PROTO_MASK(IMAPS)
      CASE_PROTO_MASK(LDAP)
      CASE_PROTO_MASK(LDAPS)
      CASE_PROTO_MASK(POP3)
      CASE_PROTO_MASK(POP3S)
      CASE_PROTO_MASK(RTMP)
      CASE_PROTO_MASK(RTMPE)
      CASE_PROTO_MASK(RTMPS)
      CASE_PROTO_MASK(RTMPT)
      CASE_PROTO_MASK(RTMPTE)
      CASE_PROTO_MASK(RTMPTS)
      CASE_PROTO_MASK(RTSP)
      CASE_PROTO_MASK(SCP)
      CASE_PROTO_MASK(SFTP)
      CASE_PROTO_MASK(SMB)
      CASE_PROTO_MASK(SMBS)
      CASE_PROTO_MASK(SMTP)
      CASE_PROTO_MASK(SMTPS)
      CASE_PROTO_MASK(TELNET)
      CASE_PROTO_MASK(TFTP)
    END_CASE_MASK_OPT(PROTOCOLS)
    BEGIN_CASE_MASK_OPT(REDIR_PROTOCOLS)
      CASE_PROTO_MASK(DICT)
      CASE_PROTO_MASK(FILE)
      CASE_PROTO_MASK(FTP)
      CASE_PROTO_MASK(FTPS)
      CASE_PROTO_MASK(GOPHER)
      CASE_PROTO_MASK(HTTP)
      CASE_PROTO_MASK(HTTPS)
      CASE_PROTO_MASK(IMAP)
      CASE_PROTO_MASK(IMAPS)
      CASE_PROTO_MASK(LDAP)
      CASE_PROTO_MASK(LDAPS)
      CASE_PROTO_MASK(POP3)
      CASE_PROTO_MASK(POP3S)
      CASE_PROTO_MASK(RTMP)
      CASE_PROTO_MASK(RTMPE)
      CASE_PROTO_MASK(RTMPS)
      CASE_PROTO_MASK(RTMPT)
      CASE_PROTO_MASK(RTMPTE)
      CASE_PROTO_MASK(RTMPTS)
      CASE_PROTO_MASK(RTSP)
      CASE_PROTO_MASK(SCP)
      CASE_PROTO_MASK(SFTP)
      CASE_PROTO_MASK(SMB)
      CASE_PROTO_MASK(SMBS)
      CASE_PROTO_MASK(SMTP)
      CASE_PROTO_MASK(SMTPS)
      CASE_PROTO_MASK(TELNET)
      CASE_PROTO_MASK(TFTP)
    END_CASE_MASK_OPT(REDIR_PROTOCOLS)
    CASE_STR_OPT(DEFAULT_PROTOCOL)
    CASE_STR_OPT(PROXY)
    CASE_STR_OPT(PRE_PROXY)
    CASE_LONG_OPT(PROXYPORT)
    BEGIN_CASE_ENUM_OPT(PROXYTYPE)
      CASE_PROXY_ENUM(HTTP)
      CASE_PROXY_ENUM(HTTPS)
      CASE_PROXY_ENUM(HTTP_1_0)
      CASE_PROXY_ENUM(SOCKS4)
      CASE_PROXY_ENUM(SOCKS4A)
      CASE_PROXY_ENUM(SOCKS5)
      CASE_PROXY_ENUM(SOCKS5_HOSTNAME)
    END_CASE_ENUM_OPT(PROXYTYPE)
    CASE_STR_OPT(NOPROXY)
    CASE_LONG_OPT(HTTPPROXYTUNNEL)
    CASE_LIST_OPT(CONNECT_TO, connect_to_list)
    BEGIN_CASE_MASK_OPT(SOCKS5_AUTH)
      CASE_AUTH_MASK(BASIC)
      CASE_AUTH_MASK(GSSAPI)
      CASE_AUTH_MASK(NONE)
    END_CASE_MASK_OPT(SOCKS5_AUTH)
    CASE_STR_OPT(SOCKS5_GSSAPI_SERVICE)
    CASE_LONG_OPT(SOCKS5_GSSAPI_NEC)
    CASE_STR_OPT(PROXY_SERVICE_NAME)
    CASE_LONG_OPT(HAPROXYPROTOCOL)
    CASE_STR_OPT(SERVICE_NAME)
    CASE_STR_OPT(INTERFACE)
    CASE_LONG_OPT(LOCALPORT)
    CASE_LONG_OPT(LOCALPORTRANGE)
    CASE_LONG_OPT(DNS_CACHE_TIMEOUT)
    CASE_STR_OPT(DOH_URL)
    CASE_LONG_OPT(BUFFERSIZE)
    CASE_LONG_OPT(PORT)
    CASE_LONG_OPT(TCP_FASTOPEN)
    CASE_LONG_OPT(TCP_NODELAY)
    CASE_LONG_OPT(ADDRESS_SCOPE)
    CASE_LONG_OPT(TCP_KEEPALIVE)
    CASE_LONG_OPT(TCP_KEEPIDLE)
    CASE_LONG_OPT(TCP_KEEPINTVL)
    CASE_STR_OPT(UNIX_SOCKET_PATH)
    CASE_STR_OPT(ABSTRACT_UNIX_SOCKET)


    CASE_LONG_OPT(NETRC)
    CASE_STR_OPT(NETRC_FILE)
    CASE_STR_OPT(USERPWD)
    CASE_STR_OPT(PROXYUSERPWD)
    CASE_STR_OPT(USERNAME)
    CASE_STR_OPT(PASSWORD)
    CASE_STR_OPT(LOGIN_OPTIONS)
    CASE_STR_OPT(PROXYUSERNAME)
    CASE_STR_OPT(PROXYPASSWORD)
    BEGIN_CASE_MASK_OPT(HTTPAUTH)
      CASE_AUTH_MASK(BASIC)
      CASE_AUTH_MASK(DIGEST)
      CASE_AUTH_MASK(DIGEST_IE)
      CASE_AUTH_MASK(BEARER)
      CASE_AUTH_MASK(NEGOTIATE)
      CASE_AUTH_MASK(NTLM)
      CASE_AUTH_MASK(NTLM_WB)
      CASE_AUTH_MASK(ANY)
      CASE_AUTH_MASK(ANYSAFE)
      CASE_AUTH_MASK(ONLY)
      //CASE_AUTH_MASK(AWS_SIGV4) //not available in my version of curl?
    END_CASE_MASK_OPT(HTTPAUTH)
    CASE_STR_OPT(TLSAUTH_USERNAME)
    CASE_STR_OPT(PROXY_TLSAUTH_USERNAME)
    CASE_STR_OPT(TLSAUTH_PASSWORD)
    CASE_STR_OPT(PROXY_TLSAUTH_PASSWORD)
    CASE_STR_OPT(TLSAUTH_TYPE)
    CASE_STR_OPT(PROXY_TLSAUTH_TYPE)
    CASE_LONG_OPT(PROXYAUTH)
    CASE_STR_OPT(SASL_AUTHZID)
    CASE_LONG_OPT(SASL_IR)
    CASE_STR_OPT(XOAUTH2_BEARER)
    CASE_LONG_OPT(DISALLOW_USERNAME_IN_URL)
    
    
    CASE_LONG_OPT(AUTOREFERER)
    CASE_STR_OPT(ACCEPT_ENCODING)
    CASE_LONG_OPT(TRANSFER_ENCODING)
    CASE_LONG_OPT(FOLLOWLOCATION)
    CASE_LONG_OPT(UNRESTRICTED_AUTH)
    CASE_LONG_OPT(MAXREDIRS)
    CASE_LONG_OPT(POSTREDIR)
    CASE_LONG_OPT(PUT)
    CASE_LONG_OPT(POST)
    CASE_STR_CACHE_OPT(POSTFIELDS, postfields)
    CASE_LONG_OPT(POSTFIELDSIZE)
    CASE_LONG_OPT(POSTFIELDSIZE_LARGE)
    CASE_STR_OPT(COPYPOSTFIELDS)

    CASE_STR_OPT(REFERER)
    CASE_STR_OPT(USERAGENT)
    CASE_LIST_OPT(HTTPHEADER, user_headers)
    CASE_LONG_OPT(HEADEROPT)
    CASE_LIST_OPT(PROXYHEADER, proxyheaders)

    default:
      NORM_ERR("unhandled curl option '%s'", opt_name.c_str()); \
      break;
    }

    //TODO: a lot more of libcurl
  }
}
#endif /* CURL_ADVANCED */
}  // namespace priv

namespace {
class simple_curl_cb : public curl_callback<std::string> {
  typedef curl_callback<std::string> Base;

 protected:
  virtual void process_data() {
    std::lock_guard<std::mutex> lock(result_mutex);
    result = data;
  }

 public:
  simple_curl_cb(uint32_t period, const std::string &uri)
      : Base(period, Tuple(uri)) {}
};
}  // namespace

/*
 * This is where the $curl section begins.
 */

struct curl_data {
  char *uri;
  float interval;
};

/* prints result data to text buffer, used by $curl */
void ccurl_process_info(char *p, int p_max_size, const std::string &uri,
                        int interval) {
  uint32_t period = std::max(lround(interval / active_update_interval()), 1l);
  auto cb = conky::register_cb<simple_curl_cb>(period, uri);

  strncpy(p, cb->get_result_copy().c_str(), p_max_size);
}

void curl_parse_arg(struct text_object *obj, const char *arg) {
  struct curl_data *cd;
  float interval = 0;
  char *space;

  if (strlen(arg) < 1) {
    NORM_ERR("wrong number of arguments for $curl");
    return;
  }

  cd = static_cast<struct curl_data *>(malloc(sizeof(struct curl_data)));
  memset(cd, 0, sizeof(struct curl_data));

  // Default to a 15 minute interval
  cd->interval = 15 * 60;

  cd->uri = strdup(arg);
  space = strchr(cd->uri, ' ');
  if (space) {
    // If an explicit interval was given, use that
    char *interval_str = &space[1];
    *space = '\0';
    sscanf(interval_str, "%f", &interval);
    cd->interval = interval > 0 ? interval : active_update_interval();
  }

  obj->data.opaque = cd;
}

void curl_print(struct text_object *obj, char *p, unsigned int p_max_size) {
  struct curl_data *cd = static_cast<struct curl_data *>(obj->data.opaque);

  if (!cd) {
    NORM_ERR("error processing Curl data");
    return;
  }
  ccurl_process_info(p, p_max_size, cd->uri, cd->interval);
}

void curl_obj_free(struct text_object *obj) {
  struct curl_data *cd = static_cast<struct curl_data *>(obj->data.opaque);
  free_and_zero(cd->uri);
  free_and_zero(obj->data.opaque);
}
