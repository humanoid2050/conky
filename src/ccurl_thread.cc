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
  struct headers_ {
    struct curl_slist *h;

    headers_() : h(nullptr) {}
    ~headers_() { curl_slist_free_all(h); }
  } headers;

  data.clear();

  for (const auto& usr_hdr : user_headers) {
    headers.h = curl_slist_append(headers.h, usr_hdr.c_str());
  }

  if (!last_modified.empty()) {
    headers.h = curl_slist_append(
        headers.h, ("If-Modified-Since: " + last_modified).c_str());
    last_modified.clear();
  }
  if (!etag.empty()) {
    headers.h =
        curl_slist_append(headers.h, ("If-None-Match: " + etag).c_str());
    etag.clear();
  }
  if (headers.h)
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.h);

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

#define TRY_STR_OPT(name) \
  if (opt_name == #name) { \
    curl_easy_setopt(curl, CURLOPT_##name, opts[opt_name].asString().c_str()); \
    continue; \
  }

#define TRY_LONG_OPT(name) \
  if (opt_name == #name) { \
    curl_easy_setopt(curl, CURLOPT_##name, opts[opt_name].asUInt64()); \
    continue; \
  }

#define TRY_MASK(name, stem, in_var, mask_var) \
  if (in_var == #name) { \
    mask_var |= stem##name ; \
    continue; \
  }

#define TRY_AUTH_MASK(name) TRY_MASK(name, CURLAUTH_, token, mask)
#define TRY_PROTO_MASK(name) TRY_MASK(name, CURLPROTO_, token, mask)

#define TRY_PROXY_TYPE(name) if (type_str == #name) type = CURLPROXY_##name;

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

//function to apply opts to curl
void curl_internal::apply_opts(CURL* curl, const Json::Value& opts) {
  for (const auto& opt_name : opts.getMemberNames()) {
    TRY_LONG_OPT(VERBOSE)
    TRY_LONG_OPT(HEADER)
    TRY_LONG_OPT(PATH_AS_IS)
    if (opt_name == "PROTOCOLS") {
      auto tokens = vectorize(opts[opt_name], ",");
      unsigned long mask{0};
      for (const auto& token : tokens) {
        TRY_PROTO_MASK(DICT)
        TRY_PROTO_MASK(FILE)
        TRY_PROTO_MASK(FTP)
        TRY_PROTO_MASK(FTPS)
        TRY_PROTO_MASK(GOPHER)
        TRY_PROTO_MASK(HTTP)
        TRY_PROTO_MASK(HTTPS)
        TRY_PROTO_MASK(IMAP)
        TRY_PROTO_MASK(IMAPS)
        TRY_PROTO_MASK(LDAP)
        TRY_PROTO_MASK(LDAPS)
        TRY_PROTO_MASK(POP3)
        TRY_PROTO_MASK(POP3S)
        TRY_PROTO_MASK(RTMP)
        TRY_PROTO_MASK(RTMPE)
        TRY_PROTO_MASK(RTMPS)
        TRY_PROTO_MASK(RTMPT)
        TRY_PROTO_MASK(RTMPTE)
        TRY_PROTO_MASK(RTMPTS)
        TRY_PROTO_MASK(RTSP)
        TRY_PROTO_MASK(SCP)
        TRY_PROTO_MASK(SFTP)
        TRY_PROTO_MASK(SMB)
        TRY_PROTO_MASK(SMBS)
        TRY_PROTO_MASK(SMTP)
        TRY_PROTO_MASK(SMTPS)
        TRY_PROTO_MASK(TELNET)
        TRY_PROTO_MASK(TFTP)
        NORM_ERR("curl option 'PROTOCOLS' given unknown token '%s'", token.c_str());
      }
      curl_easy_setopt(curl, CURLOPT_PROTOCOLS, mask);
      continue;
    } 
    if (opt_name == "REDIR_PROTOCOLS") {
      auto tokens = vectorize(opts[opt_name], ",");
      unsigned long mask{0};
      for (const auto& token : tokens) {
        TRY_PROTO_MASK(DICT)
        TRY_PROTO_MASK(FILE)
        TRY_PROTO_MASK(FTP)
        TRY_PROTO_MASK(FTPS)
        TRY_PROTO_MASK(GOPHER)
        TRY_PROTO_MASK(HTTP)
        TRY_PROTO_MASK(HTTPS)
        TRY_PROTO_MASK(IMAP)
        TRY_PROTO_MASK(IMAPS)
        TRY_PROTO_MASK(LDAP)
        TRY_PROTO_MASK(LDAPS)
        TRY_PROTO_MASK(POP3)
        TRY_PROTO_MASK(POP3S)
        TRY_PROTO_MASK(RTMP)
        TRY_PROTO_MASK(RTMPE)
        TRY_PROTO_MASK(RTMPS)
        TRY_PROTO_MASK(RTMPT)
        TRY_PROTO_MASK(RTMPTE)
        TRY_PROTO_MASK(RTMPTS)
        TRY_PROTO_MASK(RTSP)
        TRY_PROTO_MASK(SCP)
        TRY_PROTO_MASK(SFTP)
        TRY_PROTO_MASK(SMB)
        TRY_PROTO_MASK(SMBS)
        TRY_PROTO_MASK(SMTP)
        TRY_PROTO_MASK(SMTPS)
        TRY_PROTO_MASK(TELNET)
        TRY_PROTO_MASK(TFTP)
        NORM_ERR("curl option 'REDIR_PROTOCOLS' given unknown token '%s'", token.c_str());
      }
      curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS, mask);
      continue;
    } 
    TRY_STR_OPT(DEFAULT_PROTOCOL)
    TRY_STR_OPT(PROXY)
    TRY_STR_OPT(PRE_PROXY)
    TRY_LONG_OPT(PROXYPORT)
    if (opt_name == "PROXYTYPE") {
      auto type_str = opts[opt_name].asString();
      unsigned long type{0};
      TRY_PROXY_TYPE(HTTP)
      else TRY_PROXY_TYPE(HTTPS)
      else TRY_PROXY_TYPE(HTTP_1_0)
      else TRY_PROXY_TYPE(SOCKS4)
      else TRY_PROXY_TYPE(SOCKS4A)
      else TRY_PROXY_TYPE(SOCKS5)
      else TRY_PROXY_TYPE(SOCKS5_HOSTNAME)
      curl_easy_setopt(curl, CURLOPT_PROXYTYPE, type);
      continue;
    }
    TRY_STR_OPT(NOPROXY)
    TRY_LONG_OPT(HTTPPROXYTUNNEL)


    if (opt_name == "HTTPAUTH") {
      auto tokens = vectorize(opts[opt_name], ",");
      unsigned long mask{0};
      for (const auto& token : tokens) {
        TRY_AUTH_MASK(BASIC)
        TRY_AUTH_MASK(DIGEST)
        TRY_AUTH_MASK(DIGEST_IE)
        TRY_AUTH_MASK(BEARER)
        TRY_AUTH_MASK(NEGOTIATE)
        TRY_AUTH_MASK(NTLM)
        TRY_AUTH_MASK(NTLM_WB)
        TRY_AUTH_MASK(ANY)
        TRY_AUTH_MASK(ANYSAFE)
        TRY_AUTH_MASK(ONLY)
        NORM_ERR("curl option 'HTTPAUTH' given unknown token '%s'", token.c_str());
      }
      curl_easy_setopt(curl, CURLOPT_HTTPAUTH, mask);
      continue;
    } 
    TRY_STR_OPT(XOAUTH2_BEARER)
    
    
    if (opt_name == "HTTPHEADER") {
      user_headers = vectorize(opts[opt_name], ",");
      //headers get mucked with in do_work(), so we just cache the raw list here
      continue;
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
