/**
 * This file is a modified "pwd.h" from OpenBSD headers
 * available under the 3-clause BSD license ("bsd_license.h").
 * The use of this file is free as in freedom; no warranty is given.
 */

#ifndef _PWD_H_
#define _PWD_H_

#include "bsd_license.h"
#include "wuser_types.h"

struct passwd {
    char *pw_name; /* user name */
    char *pw_passwd; /* encrypted password */
    uid_t pw_uid; /* user uid */
    gid_t pw_gid; /* user gid */
    time_t pw_change; /* password change time */
    char *pw_class; /* user access class */
    char *pw_gecos; /* Honeywell login info */
    char *pw_dir; /* home directory */
    char *pw_shell; /* default shell */
    time_t pw_expire; /* account expiration */
};

/* __BEGIN_DECLS */
#ifdef __cplusplus
extern "C" {
#endif

struct passwd *getpwuid(uid_t);
struct passwd *getpwnam(const char *);
struct passwd *getpwuid_shadow(uid_t);
struct passwd *getpwnam_shadow(const char *);
int getpwuid_r(uid_t, struct passwd *, char *, size_t, struct passwd **);
int getpwnam_r(const char *, struct passwd *, char *, size_t, struct passwd **);

#if __BSD_VISIBLE || __XPG_VISIBLE
struct passwd *getpwent(void);
void setpwent(void);
void endpwent(void);
#endif

#if __BSD_VISIBLE
int setpassent(int);
int uid_from_user(const char *, uid_t *);
const char *user_from_uid(uid_t, int);
char *bcrypt_gensalt(uint8_t);
char *bcrypt(const char *, const char *);
int bcrypt_newhash(const char *, int, char *, size_t);
int bcrypt_checkpass(const char *, const char *);
struct passwd *pw_dup(const struct passwd *);
#endif

/* __END_DECLS */
#ifdef __cplusplus
}
#endif

#endif /* !_PWD_H_ */
