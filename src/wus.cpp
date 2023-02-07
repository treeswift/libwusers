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
#include <sstream>

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

char* BufferWriter::operator()(const wchar_t* out_wstr) const {
    if(!out_wstr) {
        return nullptr;
    }
    if(!buf_len) {
        set_last_error(ERANGE);
        return nullptr;
    }
    char* out_put = out_buf;
    std::size_t out_wlen = std::wcslen(out_wstr);
    if(out_wlen) {
        int conv_len = WideCharToMultiByte(get_cp(), 0 /* flags */, out_wstr, out_wlen, out_put, buf_len - 1, nullptr, nullptr);
        if(conv_len) {
            out_buf += conv_len;
            buf_len -= conv_len;
        }
        else {
            switch(GetLastError()) {
            case ERROR_INSUFFICIENT_BUFFER:
                set_last_error(ERANGE);
                break;
            default:
                set_last_error(EINVAL);
                break;
            }
            return nullptr;
        }
    }
    return (*out_buf = '\0'), out_buf++, buf_len++, out_put;
}

char* BufferWriter::operator()(const void* buf, std::size_t len) const {
    if(!buf) {
        return nullptr;
    }
    // harmless implicit alignment to uintptr_t
    constexpr uintptr_t mask = sizeof(uintptr_t) - 1;
    uintptr_t uiptrbuf = reinterpret_cast<uintptr_t>(out_buf);
    uintptr_t fraction = ((uiptrbuf & mask) + mask) & ~mask;
    if(len + fraction > buf_len) {
        return nullptr;
    }
    // slightly suboptimal arithmetic, for clarity
    out_buf += fraction;
    buf_len -= fraction;
    char* out_put = out_buf;
    memcpy(out_buf, buf, len);
    out_buf += len;
    buf_len -= len;
    return out_put;
}

char* BinderWriter::operator()(const wchar_t* out_wstr) const {
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
}

char* BinderWriter::operator()(const void* buf, std::size_t len) const {
    // we _hope_ your string heap is aligned... but check as well
    constexpr uintptr_t mask = sizeof(uintptr_t) - 1;
    out_bdr.emplace_back(len + sizeof(uintptr_t), '\0');
    char* out_buf = &out_bdr.back()[0];
    uintptr_t uiptrbuf = reinterpret_cast<uintptr_t>(out_buf);
    uintptr_t fraction = ((uiptrbuf & mask) + mask) & ~mask;
    out_buf += fraction;
    memcpy(out_buf, buf, len);
    return out_buf;
}

const char* IDToA(OutBinder& out_bdr, unsigned int id, int no) {
    if(no) return nullptr;
    std::stringstream ss;
    ss << id;
    out_bdr.push_back(ss.str());
    return out_bdr.back().c_str();
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
