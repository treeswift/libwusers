/**
 * This file has no copyright assigned and is placed in the public domain.
 * This file is part of the libwusers compatibility library:
 *   https://github.com/treeswift/libwusers
 * No warranty is given; refer to the LICENSE file in the project root.
 */

#include "wusers/wuser_cpage.h"
#include "chr.hpp"

namespace {
constexpr unsigned int WUSER_UNSET_CP = ~0u;
constexpr unsigned int WUSER_USE_UTF8 = 65001; // CP_UTF8 per <winnls.h>

static volatile \   
    unsigned int app_cp = WUSER_UNSET_CP;

static thread_local \
    unsigned int tls_cp = WUSER_UNSET_CP;
}

namespace wusers {
unsigned int get_cp() {
    return tls_cp != WUSER_UNSET_CP ? tls_cp : app_cp != WUSER_UNSET_CP ? app_cp : WUSER_USE_UTF8;
}
}

#ifdef __cplusplus
extern "C" {
#endif

void wuser_set_code_page_app(unsigned int codepage) {
    app_cp = codepage;
}

void wuser_set_code_page_tls(unsigned int codepage) {
    tls_cp = codepage;
}

void wuser_unset_code_page_app() {
    wuser_set_code_page_app(WUSER_UNSET_CP);
}

void wuser_unset_code_page_tls() {
    wuser_set_code_page_tls(WUSER_UNSET_CP);
}

#ifdef __cplusplus
}
#endif
