/**
 * This file has no copyright assigned and is placed in the public domain.
 * This file is part of the libwusers compatibility library:
 *   https://github.com/treeswift/libwusers
 * No warranty is given; refer to the LICENSE file in the project root.
 */

#include "grp.h"      // API
#include "state.hpp"  // library state
#include <windows.h>  // *backend deps
#include <lm.h>       // backend
#include <errno.h>    // error codes

#ifdef __cplusplus
extern "C" {
#endif

// group fields in struct group:
//
// -- preferring NetGroupGetInfo (up to level 2) to NetLocalGroupGetInfo (up to level 1)
// char *gr_name; /* group name */
// char *gr_passwd; /* group password */
// gid_t gr_gid; /* group id */ 
// -- GROUP_INFO_2 contains name and gid, ditto NET_DISPLAY_GROUP
// -- level 3 is supported since XP
// char **gr_mem; /* group members */ // access via: NetGroupGetUsers or NetLocalGroupGetMembers
// -- LOCALGROUP_MEMBERS_INFO_1 conveniently includes both SID and name (_2 includes domain)
// output freed by NetApiBufferFree

namespace {
static thread_local int curr_group;
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
    //
    return 0;
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
