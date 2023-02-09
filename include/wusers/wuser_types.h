/**
 * This file has no copyright assigned and is placed in the public domain.
 * This file is part of the libwusers compatibility library:
 *   https://github.com/treeswift/libwusers
 * No warranty is given; refer to the LICENSE file in the project root.
 */
#ifndef _WUSER_TYPES_H_
#define _WUSER_TYPES_H_

#include <stdint.h>
#include <time.h>

#ifndef uid_t
#ifndef _UID_T_DEFINED_
#define _UID_T_DEFINED_
typedef int uid_t;
#endif // as a type
#endif // as a macro

#ifndef gid_t
#ifndef _GID_T_DEFINED_
#define _GID_T_DEFINED_
typedef int gid_t;
#endif // as a type
#endif // as a macro

#endif /* _WUSER_TYPES_H_ */