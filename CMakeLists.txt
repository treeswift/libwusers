# This file has no copyright assigned and is placed in the public domain.
# This file is the build script of the libwusers compatibility library:
#   https://github.com/treeswift/libwusers
# No warranty is given; refer to the LICENSE file in the project root.

# Inspired by: https://github.com/krux02/minimal_cmake_example (public domain)

cmake_minimum_required(VERSION 3.0)
project(wusers)

set(libheaders
"include/bsd_license.h"
"include/wuser_names.h"
"include/wuser_types.h"
"include/grp.h"
"include/pwd.h"
)

set(libsources
"src/grp.cpp"
"src/pwd.cpp")

set(compiledefs "__WUSERS_BUILDING_LIBRARY" "__BSD_VISIBLE")
set(compile_flags "-fPIC" "-Wall") # MOREINFO provide flags for MSVC
include_directories(include)

add_library(wusers_a OBJECT ${libheaders} ${libsources})
target_compile_options(wusers_a PRIVATE ${compile_flags})
target_compile_definitions(wusers_a PRIVATE ${compiledefs})

add_library(wusers_w OBJECT ${libheaders} ${libsources})
target_compile_options(wusers_w PRIVATE ${compile_flags})
target_compile_definitions(wusers_w PRIVATE ${compiledefs} "UNICODE")

# Now combine Unicode and non-Unicode flavors into the output (expectedly a DLL)
add_library(wusers "include/bsd_license.h") # CMake wants at least one input file
target_link_libraries(wusers PUBLIC wusers_a wusers_w)

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
