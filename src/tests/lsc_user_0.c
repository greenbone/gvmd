/* Test 0 of lsc_user module.
 * $Id$
 * Description: Test lsc user installer package creation.
 *
 * Authors:
 * Felix Wolfsteller <felix.wolfsteller@greenbone.net>
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

#include "../lsc_user.h"
#include "common.h"

/**
 * @warning Relies on scripts installed (so make for proper testing need to
 * @warning `make install` before testing).
 */

int
main (int argc, char* argv [])
{

  gchar* uname = "harmless";
  gchar* upass = "harmless";
  if (argc >= 2)
    {
      uname = argv[1];
      upass = argv[1];
    }

  gchar * public_key_out = NULL;
  gchar * private_key_out = NULL;
  gchar * rpm_out = NULL;
  gchar * deb_out = NULL;
  gchar * exe_out = NULL;
  gsize rpm_size_out, deb_size_out, exe_size_out;
  /* lsc_user_all_create@return 0 success, -1 error. */
  int ret = lsc_user_all_create (uname,
                                 upass,
                                 &public_key_out,
                                 &private_key_out,
                                 (void **) &rpm_out, &rpm_size_out,
                                 (void **) &deb_out, &deb_size_out,
                                 (void **) &exe_out, &exe_size_out);
  return ret;
/*
  return EXIT_FAILURE;

  return EXIT_SUCCESS;*/
}
