/**
 * This file has no copyright assigned and is placed in the public domain.
 * This file is part of the libwusers compatibility library:
 *   https://github.com/treeswift/libwusers
 * No warranty is given; refer to the LICENSE file in the project root.
 */

#ifndef _PWD_H_
#define _PWD_H_

#include "wusers/wuser_types.h"

struct passwd {
    char *pw_name;
    char *pw_passwd;
    uid_t pw_uid;
    gid_t pw_gid;
    time_t pw_change;
    char *pw_class;
    char *pw_gecos;
    char *pw_dir;
    char *pw_shell;
    time_t pw_expire;
};

/* libwusers note: pw_shell MUST be the last char* field lest certain buffer sizing assumptions break */

/* __BEGIN_DECLS */
#ifdef __cplusplus
extern "C" {
#endif

struct passwd *getpwuid(uid_t uid);
struct passwd *getpwnam(const char * user_name);

/* Not implemented, returns nullptr and sets EACCES */
struct passwd *getpwuid_shadow(uid_t uid);
/* Not implemented, returns nullptr and sets EACCES */
struct passwd *getpwnam_shadow(const char * user_name);

int getpwuid_r(uid_t uid, struct passwd * out_pwd, char * out_buf, size_t buf_len, struct passwd ** out_ptr);
int getpwnam_r(const char * user_name, struct passwd * out_pwd, char * out_buf, size_t buf_len, struct passwd ** out_ptr);

void setpwent(void);
struct passwd *getpwent(void);
void endpwent(void);

/* NOTE: no Windows equivalents exist for fgetpwent, fgetpwent_r */

/* Equivalent to setpwent(); `stayopen` is irrelevant and, therefore, ignored. */
int setpassent(int stayopen);

/* Caching and reentrancy as per @link https://man.openbsd.org/uid_from_user.3 */
int uid_from_user(const char * user_name, uid_t * out_uid);

/* Caching and reentrancy as per @link https://man.openbsd.org/uid_from_user.3 */
const char *user_from_uid(uid_t uid, int nouser);

#if _WUSERS_ENABLE_BCRYPT
/* Not currently implemented, though may be needed by clients relying on system-provided crypto. */
char *bcrypt_gensalt(uint8_t);
char *bcrypt(const char *, const char *);
int bcrypt_newhash(const char *, int, char *, size_t);
int bcrypt_checkpass(const char *, const char *);
#endif // _WUSERS_ENABLE_BCRYPT

struct passwd *pw_dup(const struct passwd * src);

/* __END_DECLS */
#ifdef __cplusplus
}
#endif

#endif /* _PWD_H_ */
