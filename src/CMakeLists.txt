
include_directories(
	${CMAKE_CURRENT_SOURCE_DIR}
	${CMAKE_CURRENT_BINARY_DIR}
)

# Main library
add_library(ckpool_lib STATIC
	libckpool.c
	sha2.c
)

if(CMAKE_SYSTEM_PROCESSOR MATCHES "(x86_64|i386|AMD64)")
    target_compile_options(ckpool_lib PRIVATE -msha -msse4.1)
endif()

# Executables
add_executable(ckpool
	ckpool.c
	generator.c
	bitcoin.c
	stratifier.c
	connector.c
)

# Links
target_link_libraries(ckpool
	ckpool_lib 
	${JANSSON_LIB} 
	${PTHREAD_LIB} 
	${M_LIB} 
	${RT_LIB} 
	${ZMQ_LIB}
	${SSL_LIB}
	${OpenSSL_LIB}
)

# Add OpenSSL includes
target_include_directories(ckpool PRIVATE ${OPENSSL_INCLUDE_DIR})
target_include_directories(ckpool_lib PRIVATE ${OPENSSL_INCLUDE_DIR})

# Installation
install(TARGETS ckpool
	RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Post-install hooks
install(CODE "
	execute_process(COMMAND setcap CAP_NET_BIND_SERVICE=+eip \$ENV{DESTDIR}${CMAKE_INSTALL_FULL_BINDIR}/ckpool)
")

