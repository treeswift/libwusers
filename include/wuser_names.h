/**
 * This file has no copyright assigned and is placed in the public domain.
 * This file is part of the libwusers compatibility library:
 *   https://github.com/treeswift/libwusers
 * No warranty is given; refer to the LICENSE file in the project root.
 */
#ifndef _WUSER_NAMES_H_
#define _WUSER_NAMES_H_

#include <tchar.h>

#ifdef UNICODE
#define __WUSER_UNICODE_SUFFIX W
#else
#define __WUSER_UNICODE_SUFFIX A
#endif

#define __WUSER_UNICODE_MACRO(name, suffix) name##suffix
#define __WUSER_UNICODE_MCALL(name, suffix) __WUSER_UNICODE_MACRO(name, suffix)
#define __WUSER_UNICODE_AWARE(name) __WUSER_UNICODE_MCALL(name, __WUSER_UNICODE_SUFFIX)

#endif /* _WUSER_NAMES_H_ */
