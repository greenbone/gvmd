# Copyright (C) 2018-2022 Greenbone AG
#
# SPDX-License-Identifier: GPL-2.0-or-later

# This script attempts to determine the Git commit ID and writes or updates
# a "gitrevision.h" file if successful.

find_package(Git)

macro(git_get_revision dir variable)
  execute_process(
    COMMAND ${GIT_EXECUTABLE} rev-parse --abbrev-ref HEAD
    WORKING_DIRECTORY ${dir}
    OUTPUT_VARIABLE GIT_BRANCH
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )
  execute_process(
    COMMAND ${GIT_EXECUTABLE} log -1 --format=%h
    WORKING_DIRECTORY ${dir}
    OUTPUT_VARIABLE GIT_COMMIT_HASH
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )
  string(REPLACE "/" "_" GIT_BRANCH ${GIT_BRANCH})
  set(${variable} "${GIT_COMMIT_HASH}-${GIT_BRANCH}")
endmacro()

if(EXISTS "${SOURCE_DIR}/.git/")
  if(GIT_EXECUTABLE)
    git_get_revision(${SOURCE_DIR} GIT_REVISION)
  endif(GIT_EXECUTABLE)
endif(EXISTS "${SOURCE_DIR}/.git/")

if(GIT_REVISION)
  file(WRITE gitrevision.h.in "#define GVMD_GIT_REVISION \"${GIT_REVISION}\"\n")
  execute_process(
    COMMAND ${CMAKE_COMMAND} -E copy_if_different gitrevision.h.in gitrevision.h
  )
  file(REMOVE gitrevision.h.in)
endif()
