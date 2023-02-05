/**
 * This file is a modified "grp.h" from OpenBSD headers
 * available under the 3-clause BSD license ("bsd_license.h").
 * The use of this file is free as in freedom; no warranty is given.
 */

#ifndef _GRP_H_
#define _GRP_H_

#include "bsd_license.h"
#include "wuser_types.h"
#include "wuser_names.h"

#define group __WUSER_UNICODE_AWARE(group)

struct group {
    TCHAR *gr_name; /* group name */
    TCHAR *gr_passwd; /* group password */
    gid_t gr_gid; /* group id */
    TCHAR **gr_mem; /* group members */
};

/* __BEGIN_DECLS */
#ifdef __cplusplus
extern "C" {
#endif

#define getgrgid __WUSER_UNICODE_AWARE(getgrgid)
#define getgrnam __WUSER_UNICODE_AWARE(getgrnam)

struct group *getgrgid(gid_t);
struct group *getgrnam(const TCHAR *);

#if __BSD_VISIBLE || __XPG_VISIBLE
#define setgrent __WUSER_UNICODE_AWARE(setgrent)
#define getgrent __WUSER_UNICODE_AWARE(getgrent)
#define endgrent __WUSER_UNICODE_AWARE(endgrent)

void setgrent(void);
struct group *getgrent(void);
void endgrent(void);
#endif

#if __BSD_VISIBLE || __POSIX_VISIBLE >= 199506 || __XPG_VISIBLE
#define getgrgid_r __WUSER_UNICODE_AWARE(getgrgid_r)
#define getgrnam_r __WUSER_UNICODE_AWARE(getgrnam_r)

int getgrgid_r(gid_t, struct group *, TCHAR *, size_t, struct group **);
int getgrnam_r(const TCHAR *, struct group *, TCHAR *, size_t, struct group **);
#endif

#if __BSD_VISIBLE
#define setgroupent    __WUSER_UNICODE_AWARE(setgroupent)
#define gid_from_group __WUSER_UNICODE_AWARE(gid_from_group)
#define group_from_gid __WUSER_UNICODE_AWARE(group_from_gid)

int setgroupent(int);
int gid_from_group(const TCHAR *, gid_t *);
const TCHAR *group_from_gid(gid_t, int);
#endif

/* __END_DECLS */
#ifdef __cplusplus
}
#endif

#endif /* !_GRP_H_ */
