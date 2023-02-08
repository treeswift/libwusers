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

using GROUP_INFO_X = GROUP_INFO_2;
constexpr int GLVL = 2;
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
bool FillFrom(struct group& grp, const GROUP_INFO_X& wg_infoX, const OutWriter& writer) {
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
    using id_t = gid_t;
    using NETAPI_INFO_T = GROUP_INFO_X;
    static constexpr int LVL = GLVL;
    static constexpr NET_API_STATUS NotFound = NERR_GroupNotFound;

    static id_t IdOf(const struct group& grp) { return grp.gr_gid; }
    static id_t IdOf(const NETAPI_INFO_T* wui) { return wui->GRPI(group_id); }
    static const char* NameOf(struct group& grp) { return grp.gr_name; }
    static const wchar_t* WNameOf(const NETAPI_INFO_T* wui) { return wui->GRPI(name); }

    static NET_API_STATUS Enumerate(LPCWSTR servername, DWORD level, LPBYTE *bufptr, DWORD prefmaxlen,
                                LPDWORD entriesread, LPDWORD totalentries, PDWORD_PTR resume_handle) {
        return NetGroupEnum(servername, level, bufptr, prefmaxlen, entriesread, totalentries, resume_handle);
    }

    static NET_API_STATUS GetInfo(LPCWSTR servername, LPCWSTR name, DWORD level, LPBYTE* bufptr) {
        return NetGroupGetInfo(servername, name, level, bufptr);
    }
};

} // namespace wusers_impl

namespace
{ 
using namespace wusers_impl; 

static thread_local State<struct group> tls;

} // anonymous


#ifdef __cplusplus
extern "C" {
#endif

struct group *getgrgid(gid_t gid) {
    return tls.queryById(gid);
}

struct group *getgrnam(const char * group_name) {
    return tls.queryByName(group_name);
}

#if __BSD_VISIBLE || __XPG_VISIBLE
void setgrent(void) {
    tls.beginEnum();
}

struct group *getgrent(void) {
    return tls.nextEntry();
}

void endgrent(void) {
    tls.endEnum();
}
#endif

#if __BSD_VISIBLE || __POSIX_VISIBLE >= 199506 || __XPG_VISIBLE
int getgrnam_r(const char * group_name, struct group * out_grp, char * out_buf, size_t buf_len, struct group ** out_ptr) {
    // the code is identical to getpwnam_r, but set_last_error() would probably look funny in Stateless<>; leave for now
    set_last_error(0);
    *out_ptr = nullptr;
    const std::wstring wgroup_name = to_win_str(group_name);
    if(wgroup_name.size()) {
        *out_ptr = Stateless<struct group>::QueryByName(wgroup_name, out_grp, BufferWriter(out_buf, buf_len));
        if(errno) *out_ptr = nullptr; // kill partial|inconsistent output
    }
    return errno;
}

int getgrgid_r(gid_t gid, struct group * out_grp, char * out_buf, size_t buf_len, struct group ** out_ptr) {
    // most of the (e.g. visual) complexity of getpwuid_r comes from the owned entry duplication block.
    // as the comment in pwd.cpp correctly indicates (I know: I wrote it), it's still worth the saved trip
    // to the kernel and system services. however, getpwuid_r takes pw_dup for granted. there is no gr_dup.
    // instead of creating it for the sole purpose of abusing it, we'd rather code a faithful cloning op /
    // buffer writeout here.
    set_last_error(0);
    *out_ptr = nullptr;
    BufferWriter writer(out_buf, buf_len);
    tls.queryByIdAndMap<int>(gid,
        [&](struct group& grp) {
            std::size_t name_sz = std::strlen(grp.gr_name) + 1u;
            std::size_t pass_sz = std::strlen(grp.gr_passwd) + 1u;
            std::size_t estimate = sizeof(struct group) + name_sz + pass_sz;
            std::basic_string<std::size_t> mem_lengths;
            const char* mem_ptr;
            while((estimate <= buf_len) && (mem_ptr = grp.gr_mem[mem_lengths.size()])) {
                mem_lengths.push_back(std::strlen(mem_ptr) + 1u);
                estimate += mem_lengths.back();
            }
            if(estimate > buf_len) {
                set_last_error(ERANGE);
                return -1;
            }

            memcpy(out_grp, &grp, sizeof(struct group)); // only copies the gid
                // ... but if more fixed-size fields are added, we are covered
            out_grp->gr_mem = reinterpret_cast<char**>(out_buf);
            std::size_t msz = sizeof(uintptr_t) * (mem_lengths.size() + 1u);
            out_buf += msz;
            buf_len -= msz;
            out_grp->gr_name = writer(grp.gr_name, name_sz);
            out_grp->gr_passwd = writer(grp.gr_passwd, pass_sz);
            for(std::size_t i = 0; i < mem_lengths.size(); ++i) {
                out_grp->gr_mem[i] = writer(grp.gr_mem[i], mem_lengths.at(i));
            }
            return 0;
        },
        [&](const GROUP_INFO_X* wu_info) {
            return FillFrom(*out_grp, *wu_info, writer) && !errno
                ? (*out_ptr = out_grp, 0)
                : (*out_ptr = nullptr, -1);
        },
        [](){ return -1; });
    return errno;
}
#endif

#if __BSD_VISIBLE
int setgroupent(int) {
    setgrent();
    return !errno;
}

int gid_from_group(const char * group_name, gid_t * out_gid) {
    return tls.nameToId(group_name, out_gid);
}

const char *group_from_gid(gid_t gid, int nogroup) {
    return tls.idToName(gid, nogroup);
}
#endif

#ifdef __cplusplus
}
#endif
