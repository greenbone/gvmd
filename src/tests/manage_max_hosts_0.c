/* Test 0 of manage_max_hosts.
 * $Id$
 * Description: Test manage_max_hosts on various host lists.
 *
 * Authors:
 * Matthew Mundell <matthew.mundell@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2010 Greenbone Networks GmbH
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * or, at your option, any later version as published by the Free
 * Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "../manage.h"

int
main ()
{
  if (manage_max_hosts ("") != 0)
    return EXIT_FAILURE;

#if 0
  if (manage_max_hosts (",") != 0)  -1?
    return EXIT_FAILURE;
#endif

  if (manage_max_hosts ("localhost") != 1)
    return EXIT_FAILURE;

  if (manage_max_hosts ("127.0.0.1") != 1)
    return EXIT_FAILURE;

  if (manage_max_hosts ("127.0.0.1, 192.0.32.10") != 2)
    return EXIT_FAILURE;

  if (manage_max_hosts ("127.0.0.1,192.0.32.10") != 2)
    return EXIT_FAILURE;

  if (manage_max_hosts ("192.0.2.0/24") != 255)
    return EXIT_FAILURE;

  if (manage_max_hosts ("localhost/24") != -1)
    return EXIT_FAILURE;

  if (manage_max_hosts ("a") != 1)
    return EXIT_FAILURE;

  if (manage_max_hosts ("a, b") != 2)
    return EXIT_FAILURE;

  if (manage_max_hosts ("127.0.0.1, localhost") != 2)
    return EXIT_FAILURE;

  if (manage_max_hosts ("127.0.0.1,localhost") != 2)
    return EXIT_FAILURE;

  if (manage_max_hosts ("127.0.0.1, localhost/24") != -1)
    return EXIT_FAILURE;

  if (manage_max_hosts ("127.0.0.1,localhost/24") != -1)
    return EXIT_FAILURE;

  if (manage_max_hosts ("127.0.0.1, /24") != -1)
    return EXIT_FAILURE;

  if (manage_max_hosts ("127.0.0.1,/24") != -1)
    return EXIT_FAILURE;

  if (manage_max_hosts ("a-a.b-b.c-c") != 1)
    return EXIT_FAILURE;

  if (manage_max_hosts ("192.0.2.0/24, 192.0.32.10,a,a-a.b-b.c-c, 127.0.0.1 ") != 259)
    return EXIT_FAILURE;

  return EXIT_SUCCESS;
}
