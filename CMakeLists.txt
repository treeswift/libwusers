# This file has no copyright assigned and is placed in the public domain.
# This file is the build script of the libwusers compatibility library:
#   https://github.com/treeswift/libwusers
# No warranty is given; refer to the LICENSE file in the project root.

# Inspired by: https://github.com/krux02/minimal_cmake_example (public domain)

cmake_minimum_required(VERSION 3.0)
project(wusers)

set(libheaders
"include/wusers/bsd_license.h"
"include/wusers/wuser_types.h"
"include/wusers/wuser_cpage.h"
"include/grp.h"
"include/pwd.h"
)

set(libsources
"src/chr.hpp"
"src/chr.cpp"
"src/grp.cpp"
"src/pwd.cpp")

set(compiledefs "__BSD_VISIBLE")
if(MSVC)
    set(compile_flags "/Wall")
else()
    set(compile_flags "-fPIC" "-Wall")
endif()
include_directories(include)

add_library(wusers ${libheaders} ${libsources})
target_compile_options(wusers PRIVATE ${compile_flags})
target_compile_definitions(wusers PRIVATE ${compiledefs})

set(exesources "samples/wusersapp.cpp")
add_executable(wusersapp ${exesources})
target_compile_definitions(wusersapp PRIVATE __BSD_VISIBLE)
target_link_libraries(wusersapp wusers)

install(FILES ${libheaders} DESTINATION include)
install(TARGETS wusers wusersapp DESTINATION bin)

set(CPACK_PACKAGE_NAME "wusers")
set(CPACK_PACKAGE_VERSION "0.0.1")
set(CPACK_MONOLITHIC_INSTALL 1)
include(CPack)
