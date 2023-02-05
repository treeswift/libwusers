/**
 * This file is a modified "pwd.h" from OpenBSD headers
 * available under the 3-clause BSD license ("bsd_license.h").
 * The use of this file is free as in freedom; no warranty is given.
 */

#ifndef _PWD_H_
#define _PWD_H_

#include "bsd_license.h"
#include "wuser_types.h"
#include "wuser_names.h"

#define passwd __WUSER_UNICODE_AWARE(passwd)

struct passwd {
    TCHAR *pw_name; /* user name */
    TCHAR *pw_passwd; /* encrypted password */
    uid_t pw_uid; /* user uid */
    gid_t pw_gid; /* user gid */
    time_t pw_change; /* password change time */
    TCHAR *pw_class; /* user access class */
    TCHAR *pw_gecos; /* Honeywell login info */
    TCHAR *pw_dir; /* home directory */
    TCHAR *pw_shell; /* default shell */
    time_t pw_expire; /* account expiration */
};

/* __BEGIN_DECLS */
#ifdef __cplusplus
extern "C" {
#endif

#define getpwuid __WUSER_UNICODE_AWARE(getpwuid)
#define getpwnam __WUSER_UNICODE_AWARE(getpwnam)
#define getpwuid_shadow __WUSER_UNICODE_AWARE(getpwuid_shadow)
#define getpwnam_shadow __WUSER_UNICODE_AWARE(getpwnam_shadow)
#define getpwuid_r __WUSER_UNICODE_AWARE(getpwuid_r)
#define getpwnam_r __WUSER_UNICODE_AWARE(getpwnam_r)

struct passwd *getpwuid(uid_t);
struct passwd *getpwnam(const TCHAR *);
struct passwd *getpwuid_shadow(uid_t);
struct passwd *getpwnam_shadow(const TCHAR *);
int getpwuid_r(uid_t, struct passwd *, TCHAR *, size_t, struct passwd **);
int getpwnam_r(const TCHAR *, struct passwd *, TCHAR *, size_t, struct passwd **);

#if __BSD_VISIBLE || __XPG_VISIBLE
#define setpwent __WUSER_UNICODE_AWARE(setpwent)
#define getpwent __WUSER_UNICODE_AWARE(getpwent)
#define endpwent __WUSER_UNICODE_AWARE(endpwent)

struct passwd *getpwent(void);
void setpwent(void);
void endpwent(void);
#endif

#if __BSD_VISIBLE
#define setpassent      __WUSER_UNICODE_AWARE(setpassent)
#define uid_from_user   __WUSER_UNICODE_AWARE(uid_from_user)
#define user_from_uid   __WUSER_UNICODE_AWARE(user_from_uid)
#define bcrypt_gensalt  __WUSER_UNICODE_AWARE(bcrypt_gensalt)
#define bcrypt          __WUSER_UNICODE_AWARE(bcrypt)
#define bcrypt_newhash  __WUSER_UNICODE_AWARE(bcrypt_newhash)
#define bcrypt_checkpass __WUSER_UNICODE_AWARE(bcrypt_checkpass)
#define pw_dup          __WUSER_UNICODE_AWARE(pw_dup)

int setpassent(int);
int uid_from_user(const TCHAR *, uid_t *);
const TCHAR *user_from_uid(uid_t, int);
TCHAR *bcrypt_gensalt(uint8_t);
TCHAR *bcrypt(const TCHAR *, const TCHAR *);
int bcrypt_newhash(const TCHAR *, int, TCHAR *, size_t);
int bcrypt_checkpass(const TCHAR *, const TCHAR *);
struct passwd *pw_dup(const struct passwd *);
#endif

/* __END_DECLS */
#ifdef __cplusplus
}
#endif

#endif /* !_PWD_H_ */
