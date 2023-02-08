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

#include <memory>
#include <sstream>

namespace {
using namespace wusers_impl;

constexpr const char* ASTER = "*"; // the elusive password "hash"
constexpr const char* SHELL = "cmd.exe"; // default shell

// WinXP introduces the notion of SID (fully qualified principal ID).
// There is no use case for them in libwusers at present though, so
// we don't even mention _WUSER_USE_WINXP_API in CMakeLists.txt
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

bool FillFrom(struct passwd& pwd, const USER_INFO_X& wu_infoX, const OutWriter& writer) {
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
    // Getting the user SID mb our exclusive reason to request USER_INFO_4 (introduced in WinXP)
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

struct passwd* QueryByName(const std::wstring& wuser_name, struct passwd* out_ptr, const OutWriter& writer) {
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
        retval = out_ptr;
        FillFrom(*retval, *wu_infoX, writer);
        break;
    default:
        set_last_error(EIO);
    }
    if(wu_infoX) {
        NetApiBufferFree(wu_infoX);
    }
   // tls_es.pwd_bnd can't fail with ERANGE (the client buffer can)
    return retval;
}

struct EntryState {
    struct passwd pwd;
    OutBinder pwd_bnd;
};

// while EntryState(^) is pretty much a passive storage container,
// there is enough logic in QueryState to warrant objectification

struct QueryState {
    // set large enough to fit in a single query on a workstation
    // but small enough to avoid hoarding too much memory.
    // MAX_PREFERRED_LENGTH will request as much memory as needed
    // to finish enumeration in one pass even on a server.
    static constexpr const std::size_t PAGE = 32768u;

    std::unique_ptr<BYTE, FreeNetBuffer> buf;
    std::size_t offset;
    std::size_t cursor;
    DWORD entries_full;
    DWORD entries_read;
    DWORD query_resume;

    const USER_INFO_X* buffer() const { return reinterpret_cast<const USER_INFO_X*>(buf.get()); }

    void reset() {
        buf.reset();
        offset = 0u;
        entries_read = 0u;
        entries_full = 0u;
        query_resume = 0u;
    }

    void query() {
        set_last_error(0);
        LPBYTE optr;
        auto page = PAGE;
        do switch(NetUserEnum(nullptr, LVL, FILTER_NORMAL_ACCOUNT /* use 0 to list roaming accounts */,  
                                    &optr, page, &entries_read, &entries_full, &query_resume)) {
        case ERROR_ACCESS_DENIED:
            set_last_error(EACCES);
            return;
        case ERROR_INVALID_LEVEL:
            set_last_error(EINVAL);
            return;
        case NERR_InvalidComputer:
            set_last_error(EHOSTUNREACH);
            return;
        case ERROR_MORE_DATA:
        case NERR_Success:
            buf.reset(optr);
            offset += cursor;
            cursor = 0u;
            return;
        case NERR_BufTooSmall:
            page <<= 1;
            break;
        default:
            set_last_error(EIO);
            return;
        } while(!errno);
    }

    const USER_INFO_X* curr() const {
        return &buffer()[cursor];
    }

    const USER_INFO_X* step() {
        if(buf.get()) {
            if(cursor >= entries_read) {
                if(cursor + offset >= entries_full) {
                    return nullptr;
                } else {
                    query();
                }
            }
            return &buffer()[cursor++];
        } else {
            return nullptr;
        }
    }
};

static thread_local EntryState tls_es;
static thread_local QueryState tls_qs;

struct passwd* FillInternalEntry(const USER_INFO_X* wu_info) {
    return (wu_info && FillFrom(tls_es.pwd, *wu_info, BinderWriter(tls_es.pwd_bnd = {}))) ? &tls_es.pwd : nullptr;
}

struct passwd* Identity(struct passwd& pwd) { return &pwd; } // as is
struct passwd* NotFound() { return nullptr; } // typed neutral element

// note that we could extract the condition predicate as well; but there is no POSIX API to request a generic query
template<typename R>
R QueryByUid(uid_t uid, std::function<R(struct passwd&)> report_asis,
                        std::function<R(const USER_INFO_X*)> process,
                        std::function<R()> not_found) {
    // let's examine our caches first
    if(tls_es.pwd.pw_uid == uid) { // lucky!
        return report_asis(tls_es.pwd);
    }
    if(tls_qs.buffer() && tls_qs.entries_read) {
        for(std::size_t i = 0; i < tls_qs.entries_read; ++i) {
            const USER_INFO_X * candidate = tls_qs.buffer()+i;
            if(candidate->USRI(user_id) == uid) { // lucky too
                return process(candidate);
            }
        }
    }
    // bummer. run a full query, albeit without touching state
    QueryState qs;
    qs.reset();
    qs.query();
    const USER_INFO_X * candidate = nullptr;
    while((candidate = qs.step())) {
        if(candidate->USRI(user_id) == uid) {
            return process(candidate);
        }
    }
    return not_found();
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

struct passwd *getpwuid(uid_t uid) {
    return QueryByUid<struct passwd*>(uid, &Identity, &FillInternalEntry, &NotFound);
}

struct passwd *getpwnam(const char * user_name) {
    set_last_error(0);
    const std::wstring wuser_name = to_win_str(user_name);
    if(wuser_name.empty()) return nullptr; // sets EINVAL
    return QueryByName(wuser_name, &tls_es.pwd, BinderWriter(tls_es.pwd_bnd = {}));
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
        *out_ptr = QueryByName(wuser_name, out_pwd, BufferWriter(out_buf, buf_len));
        if(errno) *out_ptr = nullptr; // kill partial|inconsistent output
    }
    return errno;
}

int getpwuid_r(uid_t uid, struct passwd * out_pwd, char * out_buf, size_t buf_len, struct passwd ** out_ptr) {
    set_last_error(0);
    *out_ptr = nullptr;
    BufferWriter writer(out_buf, buf_len);
    QueryByUid<int>(uid,
        [&](struct passwd& pwd) {
            // inefficient double string copy, but we save a (waaay more expensive) trip to the kernel/COM/NET
            struct passwd* copy = pw_dup(&pwd);
            // assumes that pw_shell is last (see note under `struct passwd` in <pwd.h>)
            char* copy_chars =  reinterpret_cast<char*>(copy) + sizeof(struct passwd);
            std::size_t breq = copy->pw_shell - copy_chars + std::strlen(copy->pw_shell);
            if(breq > buf_len) {
                set_last_error(ERANGE);
                return -1;
            } else {
                memcpy(out_pwd, copy, sizeof(struct passwd));
                memcpy(out_buf, copy_chars, breq);
                // six char* fields exactly
                out_pwd->pw_name   = out_buf + (copy->pw_name   - copy_chars);
                out_pwd->pw_passwd = out_buf + (copy->pw_passwd - copy_chars);
                out_pwd->pw_class  = out_buf + (copy->pw_class  - copy_chars);
                out_pwd->pw_gecos  = out_buf + (copy->pw_gecos  - copy_chars);
                out_pwd->pw_dir    = out_buf + (copy->pw_dir    - copy_chars);
                out_pwd->pw_shell  = out_buf + (copy->pw_shell  - copy_chars);
                *out_ptr = out_pwd;
                free(copy);
                return 0;
            }
        },
        [&](const USER_INFO_X* wu_info) {
            return FillFrom(*out_pwd, *wu_info, writer) && !errno
                ? (*out_ptr = out_pwd, 0)
                : (*out_ptr = nullptr, -1);
        },
        [](){ return -1; });
    return errno;
}

#if __BSD_VISIBLE || __XPG_VISIBLE
void setpwent(void) {
    tls_qs.reset();
    tls_qs.query();
}

struct passwd *getpwent(void) {
    return FillInternalEntry(tls_qs.step());
}

void endpwent(void) {
    tls_qs.reset();
}
#endif

#if __BSD_VISIBLE
int setpassent(int) {
    setpwent();
    return !errno;
}

int uid_from_user(const char * user_name, uid_t * out_uid) {
    if(!user_name) {
        set_last_error(EINVAL);
        return -1;
    }
    if((tls_es.pwd_bnd.size() && tls_es.pwd.pw_name && !std::strcmp(tls_es.pwd.pw_name, user_name)) || getpwnam(user_name)) {
        *out_uid = tls_es.pwd.pw_uid;
        return 0;
    }
    return -1;
}

const char *user_from_uid(uid_t uid, int nouser) {
    // memory leak prevention; constants=arbitrary
    if(tls_es.pwd_bnd.size() > 512u) {
        // too many entries used...
        auto itr = tls_es.pwd_bnd.begin();
        // keep the last complete entry intact, but keep erasing
        // those singular strings that are piling up on top of it
        for(std::size_t i = 0; i < 12u; ++i) {
            ++itr;
        }
        // ...yep, this. looks old enough.
        tls_es.pwd_bnd.erase(itr);
    }
    return QueryByUid<const char*>(uid,
        [](struct passwd& pwd) { return pwd.pw_name; },
        [&](const USER_INFO_X* wu_info) { return BinderWriter(tls_es.pwd_bnd)(wu_info->USRI(name)); },
        [&]() { return IDToA(tls_es.pwd_bnd, uid, nouser); }
    );
}

#if _WUSERS_ENABLE_BCRYPT
char *bcrypt_gensalt(uint8_t) {
    // UNIMPLEMENTED
    return nullptr;
}

char *bcrypt(const char *, const char *) {
    // UNIMPLEMENTED
    return nullptr;
}

int bcrypt_newhash(const char *, int, char *, size_t) {
    // UNIMPLEMENTED
    return 0;
}

int bcrypt_checkpass(const char *, const char *) {
    // UNIMPLEMENTED
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
