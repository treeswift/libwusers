# This file has no copyright assigned and is placed in the public domain.
# This file is the build script of the libwusers compatibility library:
#   https://github.com/treeswift/libwusers
# No warranty is given; refer to the LICENSE file in the project root.

# Inspired by: https://github.com/krux02/minimal_cmake_example (public domain)

cmake_minimum_required(VERSION 3.2)
project(wusers)

set(libheaders
"include/wusers/bsd_license.h"
"include/wusers/wuser_types.h"
"include/wusers/wuser_cpage.h"
"include/grp.h"
"include/pwd.h"
)

set(libsources
"src/grp.cpp"
"src/pwd.cpp"
"src/wus.h"
"src/wus.cpp"
)

# Tuning:
# _WUSER_NO_HEURISTICS to bypass home folder search

set(compiledefs "__BSD_VISIBLE=1")

if(MINGW)
    # only affects the library & samples, not headers
    set(compiledefs ${compiledefs} "ERRNO_IS_LVALUE")
endif()

if(MSVC)
    set(compile_flags "/Wall")
else()
    set(compile_flags "-fPIC" "-Wall")
endif()

include_directories(include)

add_library(wusers ${libheaders} ${libsources})
target_compile_options(wusers PRIVATE ${compile_flags})
target_compile_definitions(wusers PRIVATE ${compiledefs})
target_link_libraries(wusers -lnetapi32 -lkernel32 -ladvapi32)

set(exesources "samples/wuserinfo.cpp")
add_executable(wuserinfo ${exesources})
target_compile_definitions(wuserinfo PRIVATE __BSD_VISIBLE)
target_link_libraries(wuserinfo wusers)

install(FILES ${libheaders} DESTINATION include)
install(TARGETS wusers wuserinfo DESTINATION bin)

set(CPACK_PACKAGE_NAME "wusers")
set(CPACK_PACKAGE_VERSION "0.0.1")
set(CPACK_MONOLITHIC_INSTALL 1)
include(CPack)
