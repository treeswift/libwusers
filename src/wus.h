/**
 * This file has no copyright assigned and is placed in the public domain.
 * This file is part of the libwusers compatibility library:
 *   https://github.com/treeswift/libwusers
 * No warranty is given; refer to the LICENSE file in the project root.
 */

#ifndef _CHR_H_
#define _CHR_H_

#include <functional>
#include <list>
#include <string>

#include <windows.h> // SID -> sid.h, sid.cpp

namespace wusers_impl {

unsigned int get_cp();

void set_last_error(int last_error);

// conversion functions set EINVAL if input is empty or conversion fails
std::wstring to_win_str(const char* posix_str, bool einval_if_empty = true);

std::wstring to_win_str(const std::string& posix_str, bool einval_if_empty = true);

using OutWriter = std::function<char*(const wchar_t*)>;

using OutBinder = std::list<std::string>;

// "reentrant" (blahblah_r()) conversions into client-provided memory
OutWriter buffer_writer(char*& out_buf, /* no std:: here! */ size_t buf_len);

// conversions into library-owned memory
OutWriter binder_writer(OutBinder& out_str);

std::wstring ExpandEnvvars(const wchar_t * percent_str);

unsigned int GetRID(PSID sid);

}

#endif /* !_CHR_H_ */
