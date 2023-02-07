/**
 * This file has no copyright assigned and is placed in the public domain.
 * This file is part of the libwusers compatibility library:
 *   https://github.com/treeswift/libwusers
 * No warranty is given; refer to the LICENSE file in the project root.
 */

#include "wusers/wuser_cpage.h"
#include "wus.h"

#include <errno.h>
#include <stdlib.h>
#include <cstring>
#include <cwchar>

#include <windows.h> // stringapiset.h, errhandlingapi.h, userenv.h

namespace {
constexpr unsigned int WUSER_UNSET_CP = ~0u;
constexpr unsigned int WUSER_USE_UTF8 = 65001; // CP_UTF8 per <winnls.h>

static volatile \
    unsigned int app_cp = WUSER_UNSET_CP;

static thread_local \
    unsigned int tls_cp = WUSER_UNSET_CP;
}

namespace wusers_impl {
unsigned int get_cp() {
    return tls_cp != WUSER_UNSET_CP ? tls_cp : app_cp != WUSER_UNSET_CP ? app_cp : WUSER_USE_UTF8;
}

void set_last_error(int last_error) {
#ifdef ERRNO_IS_LVALUE
    errno = last_error; // POSIX way
#else
    _set_errno(last_error); // cannonical native Windows way
#endif
}

std::wstring to_win_str(const char* posix_str, std::size_t in_len, bool einval_if_empty) {
    if(!in_len) {
        if(einval_if_empty) {
            set_last_error(EINVAL);
        }
        return {};
    }
    std::wstring wuser_name(in_len, L'\0'); // a conservative estimate
    wuser_name.resize(MultiByteToWideChar(get_cp(), 0 /* flags */, posix_str, in_len, &wuser_name[0], in_len));
    if(wuser_name.empty()) {
        set_last_error(EINVAL);
    }
    return wuser_name;
}

std::wstring to_win_str(const std::string& posix_str, bool einval_if_empty) {
    return to_win_str(posix_str.c_str(), posix_str.size(), einval_if_empty);
}

std::wstring to_win_str(const char* posix_str, bool einval_if_empty) {
    if(posix_str) {
        return to_win_str(posix_str, std::strlen(posix_str), einval_if_empty);
    } else {
        set_last_error(EINVAL);
        return {};
    }
}

OutWriter buffer_writer(char** out_buf, size_t *buf_len) {
    return [&] (const wchar_t* out_wstr) -> char* {
        if(!out_wstr) {
            return nullptr;
        }
        char* out_put = *out_buf;
        std::size_t out_wlen = std::wcslen(out_wstr);
        if(out_wlen) {
            int conv_len = WideCharToMultiByte(get_cp(), 0 /* flags */, out_wstr, out_wlen, *out_buf, *buf_len, nullptr, nullptr);
            if(conv_len) {
                *out_buf += conv_len;
                *buf_len -= conv_len;
            }
            else switch(GetLastError()) {
                case ERROR_INSUFFICIENT_BUFFER:
                    set_last_error(ERANGE);
                    break;
                default:
                    set_last_error(EINVAL);
                    break;
            }
            return nullptr;
        }
        return out_put;
    };
}

OutWriter binder_writer(OutBinder& out_bdr) {
    return [&] (const wchar_t* out_wstr) -> char* {
        if(!out_wstr) {
            return nullptr;
        }
        out_bdr.push_back({});
        std::size_t out_wlen = std::wcslen(out_wstr);
        std::string& out_str = out_bdr.back();
        if(out_wlen) {
            std::size_t grow_amt = sizeof(wchar_t) * out_wlen;
            int conv_len, last_err;
            do {
                out_str.resize(out_str.size() + grow_amt);
                conv_len = WideCharToMultiByte(get_cp(), 0 /* flags */, out_wstr, out_wlen, &out_str[0], out_str.size(), nullptr, nullptr);
                last_err = conv_len ? ERROR_SUCCESS : GetLastError();
            }
            while(!conv_len && ERROR_INSUFFICIENT_BUFFER == last_err);
            if(ERROR_SUCCESS != last_err) {
                set_last_error(EINVAL);
                return nullptr;
            }
        }
        return &out_str[0];
    };
}

std::wstring ExpandEnvvars(const wchar_t * percent_str) {
    std::size_t def_len = MAX_PATH;
    std::wstring out(def_len, L'\0');
    std::size_t out_len = ExpandEnvironmentStringsW(percent_str, &out[0], out.size());
    out.resize(out_len, L'\0');
    if(out_len > def_len) {
        // request complete data
        ExpandEnvironmentStringsW(percent_str, &out[0], out.size());
    }
    return out;
}

unsigned int GetRID(PSID sid) {
    return *GetSidSubAuthority(sid, *GetSidSubAuthorityCount(sid)-1);
}

} // namespace wusers_impl

#ifdef __cplusplus
extern "C" {
#endif

void wuser_set_code_page_app(unsigned int codepage) {
    app_cp = codepage;
}

void wuser_set_code_page_tls(unsigned int codepage) {
    tls_cp = codepage;
}

void wuser_unset_code_page_app() {
    wuser_set_code_page_app(WUSER_UNSET_CP);
}

void wuser_unset_code_page_tls() {
    wuser_set_code_page_tls(WUSER_UNSET_CP);
}

#ifdef __cplusplus
}
#endif
