/* Copyright (C) 2009-2022 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Main function of gvmd.
 *
 * This file separates out the "main" function of gvmd.
 */

#include "gvmd.h"

/**
 * @brief Main function.
 *
 * @param[in]  argc  The number of arguments in argv.
 * @param[in]  argv  The list of arguments to the program.
 * @param[in]  env   The program's environment arguments.
 *
 * @return EXIT_SUCCESS on success, EXIT_FAILURE on failure.
 */
int
main (int argc, char **argv, char *env[])
{
  return gvmd (argc, argv, env);
}
