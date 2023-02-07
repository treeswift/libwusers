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

#include <vector>

#ifdef __cplusplus
extern "C" {
#endif

namespace {
using namespace wusers_impl;

constexpr const char* ASTER = "*"; // no such thing as a group password on Windows

using GROUP_INFO_X = GROUP_INFO_2;
constexpr int LVL = 2;
#define GRPI(name) grpi2_##name

// no heuristics and/or second guesses here, unlike FillFrom() in pwd.cpp.
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
    // TODO std::vector<char*> mem_name_ptrs;

    //writer.

    // char **gr_mem;  // member list

    return grp.gr_name && !errno;
}

}

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
