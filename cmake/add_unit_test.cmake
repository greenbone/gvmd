# Copyright (C) 2025 Greenbone AG
#
# SPDX-License-Identifier: GPL-2.0-or-later

macro(add_unit_test _baseName _objects _extraSource)
  string(REPLACE "-" "_" _testSource "${_baseName}")
  # manage_filter_utils.c
  set(_source "${_testSource}.c")
  # manage_filter_utils_tests.c
  set(_testSource "${_testSource}_tests.c")
  # manage-filter-utils-test
  set(_testName "${_baseName}-test")

  list(APPEND TEST_DEPENDENCIES ${_testName})
  set(TEST_TARGET_EXTRA_SRC ${_extraSource})
  list(REMOVE_ITEM TEST_TARGET_EXTRA_SRC ${_source})

  add_executable(
    ${_testName}
    EXCLUDE_FROM_ALL
    ${_testSource}
    ${_objects}
    ${TEST_TARGET_EXTRA_SRC}
  )
  target_compile_options(${_testName} PRIVATE "-fsanitize=address")
  target_link_options(${_testName} PRIVATE "-fsanitize=address")
  add_test(${_testName} ${_testName})
  set_tests_properties(
    ${_testName}
    PROPERTIES
      ENVIRONMENT "ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:abort_on_error=1"
  )
  target_link_libraries(
    ${_testName}
    cgreen
    m
    ${GNUTLS_LDFLAGS}
    ${GPGME_LDFLAGS}
    ${CMAKE_THREAD_LIBS_INIT}
    ${LINKER_HARDENING_FLAGS}
    ${LINKER_DEBUG_FLAGS}
    ${PostgreSQL_LIBRARIES}
    ${LIBBSD_LDFLAGS}
    ${CJSON_LDFLAGS}
    ${GLIB_LDFLAGS}
    ${GTHREAD_LDFLAGS}
    ${LIBGVM_AGENT_CONTROLLER_LDFLAGS}
    ${LIBGVM_BASE_LDFLAGS}
    ${LIBGVM_UTIL_LDFLAGS}
    ${LIBGVM_OSP_LDFLAGS}
    ${LIBGVM_OPENVASD_LDFLAGS}
    ${LIBGVM_GMP_LDFLAGS}
    ${LIBGVM_HTTP_LDFLAGS}
    ${LIBGVM_HTTP_SCANNER_LDFLAGS}
    ${LIBGVM_CYBERARK_LDFLAGS}
    ${LIBGVM_CONTAINER_IMAGE_SCANNER_LDFLAGS}
    ${LIBICAL_LDFLAGS}
    ${LINKER_HARDENING_FLAGS}
    ${OPT_THEIA_TGT}
  )
  set_target_properties(${_testName} PROPERTIES LINKER_LANGUAGE C)
  if(NOT CMAKE_BUILD_TYPE MATCHES "Release")
    target_compile_options(${_testName} PUBLIC ${C_FLAGS_DEBUG_GVMD})
  endif(NOT CMAKE_BUILD_TYPE MATCHES "Release")
endmacro()
