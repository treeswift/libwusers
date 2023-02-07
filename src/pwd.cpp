/**
 * This file has no copyright assigned and is placed in the public domain.
 * This file is part of the libwusers compatibility library:
 *   https://github.com/treeswift/libwusers
 * No warranty is given; refer to the LICENSE file in the project root.
 */

#include "pwd.h"      // API
#include "wus.h"  // library state
#include <windows.h>  // *backend deps
#include <lm.h>       // backend
#include <errno.h>    // error codes

#include <cstdio>   // logging

// pw_class somehow maps into one of:
// USER_PRIV_GUEST Guest
// USER_PRIV_USER  User
// USER_PRIV_ADMIN Administrator
// (conversion back to enum is case insensitive)

namespace {
using namespace wusers_impl;

static thread_local struct passwd tls_pwd;
static thread_local OutBinder tls_pwd_bnd;

constexpr const char* ASTER = "*"; // the elusive password "hash"
constexpr const char* SHELL = "cmd.exe"; // default shell

//#define _WUSER_USE_WINXP_API

#ifdef _WUSER_USE_WINXP_API
using USER_INFO_X = USER_INFO_4;
constexpr int LVL = 4;
#define USRI(name) usri4_##name
#else
using USER_INFO_X = USER_INFO_3;
constexpr int LVL = 3;
#define USRI(name) usri3_##name
#endif

struct Privilege {
static constexpr const char* const GUEST = "Guest";
static constexpr const char* const RUSER = "User";
static constexpr const char* const ADMIN = "Administrator";
static constexpr const char* const GENIE = "Daemon";

static const char* win_to_text(DWORD priv) {
    switch(priv) {
        case USER_PRIV_GUEST:
            return GUEST;
        case USER_PRIV_USER:
            return RUSER;
        case USER_PRIV_ADMIN:
            return ADMIN;
        default: // unrecognized; must be some service account
            return GENIE;
    }
}
};

bool FillFrom(struct passwd& pwd, const USER_INFO_X& wu_infoX, OutWriter writer) {
     // TODO extract code below to support "reentrant" (*_r()) API
    // the user name is available since USER_INFO_1::usri1_name
    pwd.pw_name = /* CantBeNull() */ writer(wu_infoX.USRI(name));
    // return immutable ("rodata") `*' in place of password hash
    pwd.pw_passwd = const_cast<char*>(ASTER);
    // return respective RIDs as UID and GID
#ifdef _WUSER_USE_WINXP_API
    pwd.pw_uid = GetRID(wu_infoX.USRI(user_sid));
#else
    pwd.pw_uid = wu_infoX.USRI(user_id);
#endif
    // users belong to more than one group; use the primary group
    pwd.pw_gid = wu_infoX.USRI(primary_group_id);
    
    // the user access class string representation is unspecified and unused
    pwd.pw_class = const_cast<char*>(Privilege::win_to_text(wu_infoX.USRI(priv)));

    // the mysterious "gecos" is simply full name and/or contacts; put full name for now
    pwd.pw_gecos = writer(wu_infoX.USRI(full_name));

    pwd.pw_dir = writer(wu_infoX.USRI(profile)); // %USERPROFILE% eq %HOMEDRIVE%%HOMEDIR%
#ifndef _WUSER_NO_HEURISTICS
    if(!pwd.pw_dir || !*pwd.pw_dir) {
        std::wstring cur_user = ExpandEnvvars(L"%USERNAME%");
        std::wstring cur_home = ExpandEnvvars(L"%USERPROFILE%");
        if(_wcsicmp(cur_user.c_str(), wu_infoX.USRI(name))) {
            // the profile is not the current user
            std::size_t last_bs = cur_home.find_last_of('\\');
            if(last_bs != std::wstring::npos) {
                cur_home.resize(last_bs + 1u);
                cur_home.append(wu_infoX.USRI(name));
                if(FILE_ATTRIBUTE_DIRECTORY & GetFileAttributesW(cur_home.c_str())) {
                    pwd.pw_dir = writer(cur_home.c_str());
                }
            }
        } else {
            pwd.pw_dir = writer(cur_home.c_str());
        }
    }
#endif

    // The Windows setting for the default shell is
    // HKEY_CLASSES_ROOT\{Drive|Directory|Directory\Background}\shell\cmd\command -- according to
    // https://superuser.com/questions/608194/how-to-set-powershell-as-default-instead-of-cmd-exe
    // -- and the per-user classes root is HKEY_USERS\<SID>\SOFTWARE\Classes (insert actual SID).
    // There is also HKEY_USERS\<SID>\Environment which we can check for user-specific %ComSpec%.
    // Getting the user SID is our exclusive reason to request USER_INFO_4 (introduced in WinXP)
    // instead of USER_INFO_3 (which is available since Windows 2K). Also, GetEnvironmentVariable
    // and GetEnvironmentStrings have been introduced in XP. ExpandEnvironmentStrings is Win 2K.
    // ExpandEnvironmentStringsForUser needs a user token which our clients don't typically have.
    // Note that usri?_script_path is the logon script path, which is not the same thing.
    std::wstring shell = ExpandEnvvars(L"%ComSpec%");
    if(shell.empty() || shell[0] == '%') {
        pwd.pw_shell = const_cast<char*>(SHELL);
    } else {
        pwd.pw_shell = writer(shell.c_str());
    }

    // pw_expire stands for account expiration (not password expiration)
    // usri?_acct_expires is, conveniently, seconds since the UNIX epoch
    pwd.pw_change = pwd.pw_expire = wu_infoX.USRI(acct_expires);
    if(wu_infoX.USRI(password_expired)) {
        // absent better knowledge, let's pretend it expired one day ago
        time(&pwd.pw_change);
        pwd.pw_change -= 86400;
    }
    
    return pwd.pw_name; // if this is defined, the record is kinda valid
}

struct passwd* QueryByName(const std::wstring& wuser_name, OutWriter writer) {
    struct passwd * retval = nullptr;
    USER_INFO_X * wu_infoX = nullptr;
    switch(NetUserGetInfo(nullptr, wuser_name.data(), LVL, reinterpret_cast<unsigned char**>(&wu_infoX))) {
    case ERROR_ACCESS_DENIED:
        set_last_error(EACCES);
        break;
    case ERROR_BAD_NETPATH: // can't happen -- we are local
    case NERR_InvalidComputer: // ^^ ditto
        set_last_error(EHOSTUNREACH);
        break;
    case NERR_UserNotFound:
        set_last_error(ENOENT);
        break;
    case NERR_Success:
        retval = &tls_pwd;
        FillFrom(*retval, *wu_infoX, writer);
        break;
    default:
        set_last_error(EIO);
    }
    if(wu_infoX) {
        NetApiBufferFree(wu_infoX);
    }
   // tls_pwd_bnd can't fail with ERANGE (the client buffer can)
    return retval;
}
} // namespace

#ifdef __cplusplus
extern "C" {
#endif

// map uid/gi to RID: https://learn.microsoft.com/en-us/windows/win32/secauthz/sid-components
// -- it's probably reasonable to treat user RID as UID and group RID as GID, but there is no
// -- obvious way to map either of them back into SID without enumerating all available domain
// -- authorities beforehand, and all available users/groups if this initial conjecture fails.
// -- However, *nix tools ported to Windows are unlikely to be used on Active Directory/domain
// -- controllers for native user management anyway. TODO put a note in README.md

struct passwd *getpwuid(uid_t) {
    // 
    return nullptr;
}

struct passwd *getpwnam(const char * user_name) {
    const std::wstring wuser_name = to_win_str(user_name);
    if(wuser_name.empty()) return nullptr; // sets EINVAL
    return QueryByName(wuser_name, binder_writer(tls_pwd_bnd = {}));
}

// "_shadow()" functions are defined but return EACCES. We don't HAVE_SHADOW_H (or provide it).

struct passwd *getpwuid_shadow(uid_t) {
    set_last_error(EACCES); // we aren't an NTLM harvester, at least as of yet
    return nullptr;
}

struct passwd *getpwnam_shadow(const char *) {
    set_last_error(EACCES); // ditto ^^
    return nullptr;
}

// user_name
int getpwnam_r(const char * user_name, struct passwd * out_pwd, char * out_buf, size_t buf_len, struct passwd ** out_ptr) {
    set_last_error(0);
    *out_ptr = nullptr;
    const std::wstring wuser_name = to_win_str(user_name);
    if(wuser_name.empty()) {
        auto writer = buffer_writer(&out_buf, &buf_len);
        *out_ptr = QueryByName(wuser_name, writer);
        if(errno) *out_ptr = nullptr; // kill partial|inconsistent output
    }
    return errno;
}

int getpwuid_r(uid_t, struct passwd *, char *, size_t, struct passwd **) {
    //
    return 0;
}

#if __BSD_VISIBLE || __XPG_VISIBLE
void setpwent(void) {
    //
}

struct passwd *getpwent(void) {
    //
    return nullptr;
}

void endpwent(void) {
    //
}
#endif

#if __BSD_VISIBLE
int setpassent(int) {
    //
    return 0;
}

int uid_from_user(const char * user_name, uid_t * out_uid) {
    if(!user_name) {
        set_last_error(EINVAL);
        return -1;
    }
    if(tls_pwd_bnd.empty() || (tls_pwd.pw_name && !std::strcmp(tls_pwd.pw_name, user_name)) || getpwnam(user_name)) {
        *out_uid = tls_pwd.pw_uid;
        return 0;
    }
    return -1;
}

const char *user_from_uid(uid_t, int) {
    //
    return "";
}

#if _WUSERS_ENABLE_BCRYPT
char *bcrypt_gensalt(uint8_t) {
    //
    return nullptr;
}

char *bcrypt(const char *, const char *) {
    //
    return nullptr;
}

int bcrypt_newhash(const char *, int, char *, size_t) {
    //
    return 0;
}

int bcrypt_checkpass(const char *, const char *) {
    //
    return 0;
}
#endif // _WUSERS_ENABLE_BCRYPT

struct passwd *pw_dup(const struct passwd * src) {
    std::size_t size = sizeof(struct passwd);
    auto len = [](const char* str) { return str ? std::strlen(str) + 1u : 0u; };
    // now allocate space for strings
    size += len(src->pw_name);
    size += len(src->pw_passwd);
    size += len(src->pw_class);
    size += len(src->pw_gecos);
    size += len(src->pw_dir);
    size += len(src->pw_shell);

    struct passwd * trg = reinterpret_cast<struct passwd*>(malloc(size));
    memcpy(trg, src, sizeof(struct passwd));
    char* ptr = reinterpret_cast<char*>(trg) + sizeof(struct passwd);
    auto pass = [&ptr](const char* src_str) {
        if(src_str) {
            char* fld = ptr;
            strcpy(fld, src_str);
            ptr += strlen(src_str) + 1u;
            return fld;
        } else {
            return static_cast<char*>(nullptr);
        }
    };
    trg->pw_name = pass(src->pw_name);
    trg->pw_passwd = pass(src->pw_passwd);
    trg->pw_class = pass(src->pw_class);
    trg->pw_gecos = pass(src->pw_gecos);
    trg->pw_dir = pass(src->pw_dir);
    trg->pw_shell = pass(src->pw_shell);
    return trg;
}
#endif // __BSD_VISIBLE

#ifdef __cplusplus
}
#endif
