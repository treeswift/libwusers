/**
 * This file has no copyright assigned and is placed in the public domain.
 * This file is part of the libwusers compatibility library:
 *   https://github.com/treeswift/libwusers
 * No warranty is given; refer to the LICENSE file in the project root.
 */

#include "pwd.h"      // API
#include "state.hpp"  // library state
#include <windows.h>  // *backend deps
#include <lm.h>       // backend
#include <errno.h>    // error codes

#include <stringapiset.h> // -> state.cpp
#include <cstring>
#include <string>

// passwd fields, again:
// 
// char *pw_name; /* user name */   // available since USER_INFO_1 :: usri1_name
// char *pw_passwd; /* encrypted password */ // ditto; usri1_password, "Get" returns nullptr -> `*'
// uid_t pw_uid; /* user uid */	// USER_INFO_3 contains DWORD usri3_user_id;
// gid_t pw_gid; /* user gid */ // USER_INFO_3 contains DWORD usri3_primary_group_id
// time_t pw_change; /* password change time */ // no LM equivalent; return usri3_password_expired?midnight():usri2_acct_expires
// char *pw_class; /* user access class */      // USER_INFO_1 :: usri1_priv
// char *pw_gecos; /* Honeywell login info */   // USER_INFO_2 :: usri2_full_name
// char *pw_dir; /* home directory */           // USER_INFO_1 :: usri1_home_dir
// char *pw_shell; /* default shell */ // no Windows equivalent; let's return `cmd.exe'
// time_t pw_expire; /* account expiration */   // USER_INFO_2 :: usri2_acct_expires
// output freed by NetApiBufferFree

// pw_class somehow maps into one of:
// USER_PRIV_GUEST Guest
// USER_PRIV_USER  User
// USER_PRIV_ADMIN Administrator
// (conversion back to enum is case insensitive)

namespace {
static thread_local int curr_recid;

using namespace wusers_impl;
}

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
    // this one is a one-to-one LM call mapping
    int u_length = std::strlen(user_name);
    if(!u_length) {
        set_last_error(EINVAL);
        return nullptr;
    }
    std::wstring wuser_name(u_length, L'\0'); // a conservative estimate
    int w_length = MultiByteToWideChar(get_cp(), 0 /* flags */, user_name, u_length, &wuser_name[0], wuser_name.size());
    if(!w_length) {
        set_last_error(EINVAL);
        return nullptr;
    }
    struct passwd * retval = nullptr;
    USER_INFO_3 * wu_info3 = nullptr;
    switch(NetUserGetInfo(nullptr, wuser_name.data(), 3, reinterpret_cast<unsigned char**>(&wu_info3))) {
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
        retval = new struct passwd; // TODO provide templated assignment operations; FIXME don't allocate!!!
        // TODO
        break;
    default:
        set_last_error(EIO);
    }
    if(wu_info3) {
        NetApiBufferFree(wu_info3);
    }
    return retval;
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

int getpwnam_r(const char *, struct passwd *, char *, size_t, struct passwd **) {
    //
    return 0;
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

int uid_from_user(const char *, uid_t *) {
    //
    return 0;
}

const char *user_from_uid(uid_t, int) {
    //
    return "";
}

#if __HAVE_BCRYPT
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
#endif // _HAVE_BCRYPT

struct passwd *pw_dup(const struct passwd *) {
    //
    return nullptr;
}
#endif // __BSD_VISIBLE

#ifdef __cplusplus
}
#endif
