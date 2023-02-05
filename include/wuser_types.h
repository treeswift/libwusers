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

#ifndef _UID_T_DEFINED_
#define _UID_T_DEFINED_
typedef uint32_t uid_t;
#endif

#ifndef _GID_T_DEFINED_
#define _GID_T_DEFINED_
typedef uint32_t gid_t;
#endif

#ifndef __WCHAR_DEFINED
#define __WCHAR_DEFINED
typedef wchar_t WCHAR;
#endif

#ifdef __WUSERS_BUILDING_LIBRARY
#define __WUSERS_ATTRIBUTE __declspec((dllexport))
#else /* client code */
#define __WUSERS_ATTRIBUTE __declspec((dllimport))
#endif

#endif /* _WUSER_TYPES_H_ */