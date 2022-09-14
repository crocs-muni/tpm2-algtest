project(tpm2-algtest C)
cmake_minimum_required(VERSION 3.10)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -D_GNU_SOURCE -DOPENSSL_SUPPRESS_DEPRECATED")

set(LIB_SRC ${CMAKE_SOURCE_DIR}/lib)
set(TOOLS_SRC ${CMAKE_SOURCE_DIR}/tools)
set(ALGTEST_SRC ${CMAKE_SOURCE_DIR}/algtest)

set(SOURCES
    ${LIB_SRC}/files.c
    ${LIB_SRC}/log.c
    ${LIB_SRC}/pcr.c
    ${LIB_SRC}/tpm2_alg_util.c
    ${LIB_SRC}/tpm2_attr_util.c
    ${LIB_SRC}/tpm2_auth_util.c
    ${LIB_SRC}/tpm2_capability.c
    ${LIB_SRC}/tpm2_convert.c
    ${LIB_SRC}/tpm2_ctx_mgmt.c
    ${LIB_SRC}/tpm2_errata.c
    ${LIB_SRC}/tpm2_error.c
    ${LIB_SRC}/tpm2_hash.c
    ${LIB_SRC}/tpm2_hierarchy.c
    ${LIB_SRC}/tpm2_openssl.c
    ${LIB_SRC}/tpm2_options.c
    ${LIB_SRC}/tpm2_policy.c
    ${LIB_SRC}/tpm2_session.c
    ${LIB_SRC}/tpm2_tcti_ldr.c
    ${LIB_SRC}/tpm2_util.c
    ${LIB_SRC}/tpm_kdfa.c
    ${LIB_SRC}/status.c
    ${TOOLS_SRC}/tpm2_tool.c
    ${TOOLS_SRC}/tpm2_algtest.c
    ${ALGTEST_SRC}/util.c
    ${ALGTEST_SRC}/logging.c
    ${ALGTEST_SRC}/options.c
    ${ALGTEST_SRC}/key_params_generator.c
    ${ALGTEST_SRC}/scenario.c
    ${ALGTEST_SRC}/keygen.c
    ${ALGTEST_SRC}/perf.c
    ${ALGTEST_SRC}/cryptoops.c
    ${ALGTEST_SRC}/rng.c
    ${ALGTEST_SRC}/object_util.c
    ${ALGTEST_SRC}/perf_util.c
)

include_directories(${LIB_SRC} ${TOOLS_SRC} ${ALGTEST_SRC})

add_executable(tpm2_algtest ${SOURCES})

target_link_libraries(tpm2_algtest tss2-mu tss2-sys crypto dl)

install(TARGETS tpm2_algtest DESTINATION /usr/bin)
