/* Copyright (C) 2009-2018 Greenbone Networks GmbH
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @file  main.c
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
 *
 * @return EXIT_SUCCESS on success, EXIT_FAILURE on failure.
 */
int
main (int argc, char **argv)
{
  return gvmd (argc, argv);
}
