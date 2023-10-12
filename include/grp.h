/**
 * This file has no copyright assigned and is placed in the public domain.
 * This file is part of the libwusers compatibility library:
 *   https://github.com/treeswift/libwusers
 * No warranty is given; refer to the LICENSE file in the project root.
 */

#ifndef _GRP_H_
#define _GRP_H_

#include "wusers/wuser_types.h"

struct group {
    char *gr_name;
    char *gr_passwd;
    gid_t gr_gid;
    char **gr_mem;
};

/* __BEGIN_DECLS */
#ifdef __cplusplus
extern "C" {
#endif

struct group *getgrgid(gid_t);
struct group *getgrnam(const char *);

void setgrent(void);
struct group *getgrent(void);
void endgrent(void);

/* NOTE: no Windows equivalents exist for fgetgrent, fgetgrent_r */

int getgrgid_r(gid_t, struct group *, char *, size_t, struct group **);
int getgrnam_r(const char *, struct group *, char *, size_t, struct group **);

int setgroupent(int);
int gid_from_group(const char *, gid_t *);
const char *group_from_gid(gid_t, int);

/* __END_DECLS */
#ifdef __cplusplus
}
#endif

#endif /* _GRP_H_ */  
