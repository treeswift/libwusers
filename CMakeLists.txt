
# inspired by https://github.com/krux02/minimal_cmake_example (public domain)
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

include_directories(include)

add_library(wusers_a STATIC ${libheaders} ${libsources})
target_compile_options(wusers_a PRIVATE -fPIC -Wall) # MOREINFO provide flags for MSVC
target_compile_definitions(wusers_a PRIVATE __BSD_VISIBLE)

add_library(wusers_w STATIC ${libheaders} ${libsources})
target_compile_options(wusers_w PRIVATE -fPIC -Wall) # MOREINFO provide flags for MSVC
target_compile_definitions(wusers_w PRIVATE __BSD_VISIBLE UNICODE) # see the difference?

# Now combine Unicode and non-Unicode flavors into the output (expectedly a DLL)
add_library(wusers "include/bsd_license.h") # CMake wants at least one input file
target_link_libraries(wusers wusers_a wusers_w)

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
