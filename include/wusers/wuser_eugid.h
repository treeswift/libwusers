/**
 * This file has no copyright assigned and is placed in the public domain.
 * This file is part of the libwusers compatibility library:
 *   https://github.com/treeswift/libwusers
 * No warranty is given; refer to the LICENSE file in the project root.
 */
#ifndef _WUSER_EUGID_H_
#define _WUSER_EUGID_H_

#include "wusers/wuser_types.h"

/* __BEGIN_DECLS */
#ifdef __cplusplus
extern "C" {
#endif

/**
 * The below functions are drop-in replacements for the respective POSIX API functions.
 * 
 * The contract of GetUserNameEx{A|W} is to always report the name of the user that the
 * calling thread is executing on behalf of -- i.e. that of geteuid(). To get the "real"
 * user, we expand the %USERNAME% environment variable instead. If that is not suitable
 * to your porting needs, you can
 *
 *  #define getuid geteuid
 *  #define getgid getegid
 * 
 * -- or use any other suitable means of client-side call redirection.
 * 
 * For a detailed explanation of what these venerable functions do, refer to (e.g.):
 * 
 *  https://man.openbsd.org/getuid.2
 *  https://man.openbsd.org/getgid.2
 * 
 * Implementations provided by `libwusers` use the reentrant versions of <pwd.h> API.
 * This design is intentional in order to preserve both global and thread local state.
 */

uid_t getuid(void);
uid_t geteuid(void);

uid_t getgid(void);
uid_t getegid(void);

/* __END_DECLS */
#ifdef __cplusplus
}
#endif


#endif /* _WUSER_EUGID_H_ */