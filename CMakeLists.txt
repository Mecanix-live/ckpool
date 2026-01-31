cmake_minimum_required(VERSION 3.10)

project (ckpool
	VERSION 1.0.0
	DESCRIPTION "Next-Gen Mining Stratum Server"
	LANGUAGES C)
	
# Compiler Optimization
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2")
if(NOT CMAKE_BUILD_TYPE OR CMAKE_BUILD_TYPE STREQUAL "")
	set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)
endif()

# Enable ccache
find_program(CCACHE_PROGRAM ccache)
if(CCACHE_PROGRAM)
	set(CMAKE_C_COMPILER_LAUNCHER   "${CCACHE_PROGRAM}")
	set(CMAKE_CXX_COMPILER_LAUNCHER "${CCACHE_PROGRAM}")
	message(STATUS "Found ccache: ${CCACHE_PROGRAM}")
endif()

# GNU standard installation directories
include(GNUInstallDirs)
set(CMAKE_INSTALL_PREFIX "/usr/local" CACHE PATH "Installation prefix")

# System extensions
add_compile_definitions(_GNU_SOURCE)

# Required libraries
find_package(OpenSSL REQUIRED)
if(OPENSSL_FOUND)
    add_compile_definitions(HAVE_OPENSSL)
    message(STATUS "OpenSSL found: ${OPENSSL_VERSION}")
endif()
find_library(OpenSSL_LIB crypto)
find_library(SSL_LIB ssl)
find_library(JANSSON_LIB NAMES jansson libjansson)
find_library(RT_LIB rt)
find_library(M_LIB m)
find_library(PTHREAD_LIB pthread)
find_library(ZMQ_LIB zmq)

# Verify all libraries were found
foreach(LIB IN ITEMS OpenSSL JANSSON RT M PTHREAD ZMQ)
    if(NOT ${LIB}_LIB)
        message(FATAL_ERROR "${LIB} library not found")
    endif()
endforeach()

# Create logs and certs directories
file(MAKE_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/certs")
file(MAKE_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/logs")

# Certificate paths
set(KEY_FILE "${CMAKE_CURRENT_SOURCE_DIR}/certs/server.key")
set(CERT_FILE "${CMAKE_CURRENT_SOURCE_DIR}/certs/server.crt")
set(CA_FILE "${CMAKE_CURRENT_SOURCE_DIR}/certs/ca.crt")

find_program(OPENSSL openssl)

option(GENERATE_SELF_SIGNED "Generate self-signed certificates" OFF)

if(GENERATE_SELF_SIGNED)
    add_custom_command(
        OUTPUT ${KEY_FILE} ${CERT_FILE} ${CA_FILE}
        COMMAND ${CMAKE_COMMAND} -E echo "Generating TLS certificates with CA..."
        # Generate CA key and certificate
        COMMAND ${OPENSSL} 
            genrsa 
            -out "${CMAKE_CURRENT_SOURCE_DIR}/certs/ca.key" 
            4096
        COMMAND ${OPENSSL} 
            req -x509 -new -nodes 
            -key "${CMAKE_CURRENT_SOURCE_DIR}/certs/ca.key" 
            -subj "/C=US/ST=State/L=City/O=ckpool CA/CN=ckpool.internal" 
            -days 3650 
            -out ${CA_FILE}
        # Generate server key
        COMMAND ${OPENSSL} 
            genrsa 
            -out ${KEY_FILE} 
            4096
        # Create CSR
        COMMAND ${OPENSSL} 
            req -new 
            -key ${KEY_FILE} 
            -subj "/C=US/ST=State/L=City/O=ckpool/CN=localhost" 
            -out "${CMAKE_CURRENT_SOURCE_DIR}/certs/server.csr"
        # Sign server certificate with CA
        COMMAND ${OPENSSL} 
            x509 -req 
            -in "${CMAKE_CURRENT_SOURCE_DIR}/certs/server.csr" 
            -CA ${CA_FILE} 
            -CAkey "${CMAKE_CURRENT_SOURCE_DIR}/certs/ca.key" 
            -CAcreateserial 
            -out ${CERT_FILE} 
            -days 365 
            -sha256
        # Clean up
        COMMAND ${CMAKE_COMMAND} 
            -E remove 
            "${CMAKE_CURRENT_SOURCE_DIR}/certs/server.csr" 
            "${CMAKE_CURRENT_SOURCE_DIR}/certs/ca.srl"
        COMMENT "Generating TLS certificates with proper CA"
        VERBATIM
    )

    add_custom_target(generate_certs ALL
        DEPENDS ${KEY_FILE} ${CERT_FILE} ${CA_FILE}
    )
endif()

# Subdirectory - now generate_certs exists
add_subdirectory(src)

# Ensures certs are generated AFTER the build, not during
if(OPENSSL AND TARGET generate_certs AND TARGET ckpool)
    add_dependencies(generate_certs ckpool)
endif()


# Uninstall target
set(CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}" CACHE PATH "Install prefix for uninstall")
configure_file(
	"${CMAKE_CURRENT_SOURCE_DIR}/uninstall.cmake.in"
	"${CMAKE_CURRENT_BINARY_DIR}/uninstall.cmake"
	@ONLY
)

add_custom_target(uninstall
	COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/uninstall.cmake
)

message(STATUS "\nConfigured ckpool ${PROJECT_VERSION}")
message(STATUS "==========================================")
message(STATUS "  prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "  C compiler: ${CMAKE_C_COMPILER}")
message(STATUS "  C flags: ${CMAKE_C_FLAGS}")
if(OPENSSL)
    message(STATUS "  TLS certs:")
    message(STATUS "    - ${KEY_FILE} (private key)")
    message(STATUS "    - ${CERT_FILE} (certificate)")
    message(STATUS "    - ${CA_FILE} (CA bundle)")
endif()
message(STATUS "  Logs dir:  ${CMAKE_CURRENT_SOURCE_DIR}/logs")
message(STATUS "==========================================\n")