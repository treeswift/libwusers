/**
 * This file has no copyright assigned and is placed in the public domain.
 * This file is part of the libwusers compatibility library:
 *   https://github.com/treeswift/libwusers
 * No warranty is given; refer to the LICENSE file in the project root.
 */

#include "grp.h"      // API
#include "wus.h"  // library state
#include <windows.h>  // *backend deps
#include <lm.h>       // backend
#include <errno.h>    // error codes

#include <memory>
#include <string>

namespace wusers_impl {

constexpr const char* ASTER = "*"; // no such thing as a group password on Windows

using NETAPI_INFO_T = GROUP_INFO_2;
constexpr int LVL = 2;
#define GRPI(name) grpi2_##name

void GetUsersFrom(const wchar_t* group_name, std::function<void(const wchar_t*)> on_member) {
    // there is no stateful member iteration API, so we keep everything local.
    // we only need names, hence level 0 and GROUP_USERS_INFO_0
    std::unique_ptr<BYTE, FreeNetBuffer> buf;
    DWORD entries_read;
    DWORD entries_full;
    DWORD query_resume;
    LPBYTE raw_records;
    do switch(NetGroupGetUsers(nullptr, group_name, 0, &raw_records, MAX_PREFERRED_LENGTH,
                                        &entries_read, &entries_full, &query_resume)) {
    case ERROR_ACCESS_DENIED:
        set_last_error(EACCES);
        return;
    case ERROR_NOT_ENOUGH_MEMORY:
        set_last_error(ENOMEM);
        return;
    case ERROR_INVALID_LEVEL:
        set_last_error(EINVAL);
        return;
    case NERR_InvalidComputer:
        set_last_error(EHOSTUNREACH);
        return;
    case NERR_GroupNotFound:
        set_last_error(ENOENT);
        return;
    case ERROR_MORE_DATA:
    case NERR_Success: {
        buf.reset(raw_records);
        const GROUP_USERS_INFO_0 * records = reinterpret_cast<const GROUP_USERS_INFO_0 *>(raw_records);
        while(entries_read > 0 && !errno) {
            on_member((records++)->grui0_name);
        }
        break; 
    }
    case NERR_InternalError:
    default:
        set_last_error(EIO);
        return;
    } while(!errno);
}

// no heuristics and/or second guesses here, unlike FillFrom() in grp.cpp.
// getting the member list requires a catch-up call to NetGroupGetUsers();
// storing it requires passing a raw memory range into `writer`. therefore
// `writer` can't be std::function anymore. making it a virtual class.
bool FillFrom(struct group& grp, const NETAPI_INFO_T& wg_infoX, const OutWriter& writer) {
    // all we need is:
    grp.gr_name = writer(wg_infoX.GRPI(name));
    grp.gr_passwd = const_cast<char*>(ASTER);
    grp.gr_gid = wg_infoX.GRPI(group_id);
    
    // typically, dynamic information is represented in string format;
    // the member list, however, is a null-terminated array of pointers.
    // we represent this special case as a string containing raw data.
    // don't be surprised if you see supposedly "garbage" text at the end
    // of `out_buf` (reentrant API) or in the terminal OutBinder records
    // (non-reentrant API).
    std::basic_string<uintptr_t> mem_name_ptrs; // nullptr-terminated

    GetUsersFrom(wg_infoX.GRPI(name), [&](const wchar_t* member) {
        mem_name_ptrs.push_back(reinterpret_cast<uintptr_t>(writer(member)));
    });

    grp.gr_mem = reinterpret_cast<char**>(writer(mem_name_ptrs.c_str(),
                        (mem_name_ptrs.size() + 1u) * sizeof(uintptr_t)));

    return grp.gr_name && !errno;
}

// IA = InfoAdapter/Infodapter
template<> struct IA<struct group>
{
};

} // namespace wusers_impl

namespace
{ 
using namespace wusers_impl; 

static struct group* QueryByName(const std::wstring& name, struct group* out_ptr, const OutWriter& writer) {
    return QueryInfoByName<struct group, NETAPI_INFO_T, LVL, &NetUserGetInfo, NERR_UserNotFound>(name, out_ptr, writer);
}

static thread_local struct /*State*/ {
    using QueryState = EnumQueryState<NETAPI_INFO_T, LVL, &NetGroupEnum>;

    struct {
        struct group grp;
        OutBinder grp_bnd;
    } es;
    QueryState qs;

    // note that we could extract the condition predicate as well; but there is no POSIX API to request a generic query
    template<typename R>
    R QueryByUid(uid_t gid, std::function<R(struct group&)> report_asis,
                            std::function<R(const NETAPI_INFO_T*)> process,
                            std::function<R()> not_found) {
        // let's examine our caches first
        if(es.grp.gr_gid == gid) { // lucky!
            return report_asis(es.grp);
        }
        if(qs.buffer() && qs.entries_read) {
            for(std::size_t i = 0; i < qs.entries_read; ++i) {
                const NETAPI_INFO_T * candidate = qs.buffer()+i;
                if(candidate->GRPI(group_id) == gid) { // lucky too
                    return process(candidate);
                }
            }
        }
        // bummer. run a full query, albeit without touching state
        QueryState qs;
        qs.reset();
        qs.query();
        const NETAPI_INFO_T * candidate = nullptr;
        while((candidate = qs.step())) {
            if(candidate->GRPI(group_id) == gid) {
                return process(candidate);
            }
        }
        return not_found();
    }
} tls;

struct group* FillInternalEntry(const NETAPI_INFO_T* wu_info) {
    return (wu_info && FillFrom(tls.es.grp, *wu_info, BinderWriter(tls.es.grp_bnd = {}))) ? &tls.es.grp : nullptr;
}

} // anonymous


#ifdef __cplusplus
extern "C" {
#endif

struct group *getgrgid(gid_t) {
    //
    return nullptr;
}

struct group *getgrnam(const char *) {
    //
    return nullptr;
}

#if __BSD_VISIBLE || __XPG_VISIBLE
void setgrent(void) {
    //
}

struct group *getgrent(void) {
    //
    return nullptr;
}

void endgrent(void) {
    //
}
#endif

#if __BSD_VISIBLE || __POSIX_VISIBLE >= 199506 || __XPG_VISIBLE
int getgrgid_r(gid_t, struct group *, char *, size_t, struct group **) {
    return 0;
}

int getgrnam_r(const char *, struct group *, char *, size_t, struct group **) {
    return 0;
}
#endif

#if __BSD_VISIBLE
int setgroupent(int) {
    setgrent();
    return !errno;
}

int gid_from_group(const char *, gid_t *) {
    //
    return 0;
}

const char *group_from_gid(gid_t, int) {
    //
    return "";
}
#endif

#ifdef __cplusplus
}
#endif
