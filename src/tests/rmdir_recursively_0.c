/* Test 0 of rmdir_recursively.
 * $Id$
 * Description: Test rmdir_recursively on an empty directory.
 *
 * Authors:
 * Matthew Mundell <matt@mundell.ukfsn.org>
 *
 * Copyright:
 * Copyright (C) 2009 Greenbone Networks GmbH
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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "common.h"
#include "../file.h"

int
main ()
{
  char dir[] = "rmdir_recursively_0_XXXXXX";

  setup_test ();

  if (mkdtemp (dir) == NULL)
    {
      perror ("Failed to make temp dir");
      return EXIT_FAILURE;
    }

  GError* error = NULL;
  if (rmdir_recursively (dir, &error))
    {
      /* Check that the directory is really gone. */

      struct stat buf;
      if (stat (dir, &buf))
        {
          if (errno == ENOENT) return EXIT_SUCCESS;
          perror ("Stat failed");
        }
      return EXIT_FAILURE;
    }

  fprintf (stderr, "rmdir_recursively failed: %s.", error->message);
  g_error_free (error);
  return EXIT_FAILURE;
}
