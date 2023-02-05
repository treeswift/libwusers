/**
 * This file has no copyright assigned and is placed in the public domain.
 * This file is part of the libwusers compatibility library:
 *   https://github.com/treeswift/libwusers
 * No warranty is given; refer to the LICENSE file in the project root.
 */
#ifndef _WUSER_CPAGE_H_
#define _WUSER_CPAGE_H_

/**
 * For specific encoding numbers, see:
 *  https://learn.microsoft.com/en-us/windows/win32/intl/code-page-identifiers
 * For special constants such as CP_ACP, CP_THREAD_ACP, CP_UTF8 see <winnls.h>
 */

/* __BEGIN_DECLS */
#ifdef __cplusplus
extern "C" {
#endif

/**
 * Set code page to use for Unicode string representation:
 * - any fixed code page enumerated in <stringapiset.h>, or
 * - CP_THREAD_ACP (current setup by SetThreadLocale()), or
 * - CP_ACP (current user setup in the Control Panel), or
 * - CP_UTF8 (recommended).
 *
 * CP_UTF8 is used if neither "app" nor "tls" value is set.
 */
void wuser_set_code_page_app(unsigned int codepage);
void wuser_set_code_page_tls(unsigned int codepage);
void wuser_unset_code_page_app();
void wuser_unset_code_page_tls();

/* __END_DECLS */
#ifdef __cplusplus
}
#endif

#endif /* _WUSER_CPAGE_H_ */
