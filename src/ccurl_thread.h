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

#ifndef _CURL_THREAD_H_
#define _CURL_THREAD_H_

#include <curl/curl.h>

#include "logging.h"
#include "update-cb.hh"

#ifdef BUILD_CURL_ADVANCED
#include <vector>
#include "json/json.h"
#endif /* BUILD_CURL_ADVANCED */

namespace priv {
struct wrapped_slist {
  struct curl_slist *slist;

  wrapped_slist() : slist(nullptr) {}
  wrapped_slist(const wrapped_slist& other)
  {
    struct curl_slist *tmp = other.slist;
    while (tmp != nullptr) {
      slist = curl_slist_append(slist, tmp->data);
      tmp = tmp->next;
    }
  }
  ~wrapped_slist() { clear(); }

  void push(const std::string& str) { slist = curl_slist_append(slist, str.c_str()); }
  void batch_push(std::vector<std::string> strs) {
    for (const auto& str : strs) push(str);
  }
  std::size_t size() {
    std::size_t count{0};
    struct curl_slist *tmp = slist;
    while (tmp != nullptr) {
      ++count;
      tmp = tmp->next;
    }
    return count;
  };

  void clear() { curl_slist_free_all(slist); }
};

// factored out stuff that does not depend on the template parameters
class curl_internal {
 public:
  std::string last_modified;
  std::string etag;
  std::string data;
  CURL *curl;

  static size_t parse_header_cb(void *ptr, size_t size, size_t nmemb,
                                void *data);
  static size_t write_cb(void *ptr, size_t size, size_t nmemb, void *data);

  void do_work();

  // called by do_work() after downloading data from the uri
  // it should populate the result variable
  virtual void process_data() = 0;

  explicit curl_internal(const std::string &url);
  virtual ~curl_internal() {
    if (curl) curl_easy_cleanup(curl);
  }

#ifdef BUILD_CURL_ADVANCED
 protected:
  wrapped_slist user_headers;
  wrapped_slist connect_to_list;
  wrapped_slist proxyheaders;
  std::string postfields;
  void apply_opts(CURL* curl, const Json::Value& opts);
#endif /* BUILD_CURL_ADVANCED */
};

std::vector<std::string> vectorize(const std::string& input, const char* delim = nullptr);


}  // namespace priv

/*
 * Curl callback class template
 * the key is an url
 */
template <typename Result, typename... Keys>
class curl_callback : public conky::callback<Result, std::string, Keys...>,
                      public priv::curl_internal {
  typedef conky::callback<Result, std::string, Keys...> Base1;
  typedef priv::curl_internal Base2;

 protected:
  virtual void work() {
    DBGP("reading curl data from '%s'", std::get<0>(Base1::tuple).c_str());
    do_work();
  }

 public:
  curl_callback(uint32_t period, const typename Base1::Tuple &tuple)
      : Base1(period, false, tuple), Base2(std::get<0>(tuple)) {}
};

/* $curl exports begin */

/* runs instance of $curl */
void ccurl_process_info(char *p, int p_max_size, const std::string &uri,
                        int interval);

void curl_parse_arg(struct text_object *, const char *);
void curl_print(struct text_object *, char *, unsigned int);
void curl_obj_free(struct text_object *);

/* $curl exports end */

#endif /* _CURL_THREAD_H_ */
