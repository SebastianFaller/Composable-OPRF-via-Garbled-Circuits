set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(OPENSSL_ROOT_DIR /usr/bin/openssl)

add_executable(user_pq-oprf User.cpp User.h oprf_utils.h)
add_executable(server_pq-oprf Server.cpp Server.h oprf_utils.h)

# Search OpenSSL
find_package(PkgConfig REQUIRED)
pkg_search_module(OPENSSL REQUIRED openssl)

if( OPENSSL_FOUND )
    include_directories(${OPENSSL_INCLUDE_DIRS})
    message(STATUS "Using OpenSSL ${OPENSSL_VERSION}")
else()
    # Error; with REQUIRED, pkg_search_module() will throw an error by it's own
endif()

target_link_libraries(user_pq-oprf
    PUBLIC
    emp-tool
    pq-ot
    pq-yao
    ${OPENSSL_LIBRARIES}
)

target_link_libraries(server_pq-oprf
    PUBLIC
    emp-tool
    pq-ot
    pq-yao
)