/**
 * This file is a modified "grp.h" from OpenBSD headers
 * available under the 3-clause BSD license ("bsd_license.h").
 * The use of this file is free as in freedom; no warranty is given.
 */

#ifndef _GRP_H_
#define _GRP_H_

#include "bsd_license.h"
#include "wuser_types.h"

struct group {
    char *gr_name; /* group name */
    char *gr_passwd; /* group password */
    gid_t gr_gid; /* group id */
    char **gr_mem; /* group members */
};

/* __BEGIN_DECLS */
#ifdef __cplusplus
extern "C" {
#endif

struct group *getgrgid(gid_t);
struct group *getgrnam(const char *);

#if __BSD_VISIBLE || __XPG_VISIBLE
void setgrent(void);
struct group *getgrent(void);
void endgrent(void);
#endif

#if __BSD_VISIBLE || __POSIX_VISIBLE >= 199506 || __XPG_VISIBLE
int getgrgid_r(gid_t, struct group *, char *, size_t, struct group **);
int getgrnam_r(const char *, struct group *, char *, size_t, struct group **);
#endif

#if __BSD_VISIBLE
int setgroupent(int);
int gid_from_group(const char *, gid_t *);
const char *group_from_gid(gid_t, int);
#endif

/* __END_DECLS */
#ifdef __cplusplus
}
#endif

#endif /* !_GRP_H_ */
