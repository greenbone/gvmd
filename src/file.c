/* OpenVAS Manager file utilities.
 * $Id$
 * Description: File utilities for the manager.
 *
 * Authors:
 * Matthew Mundell <matt@mundell.ukfsn.org>
 *
 * Copyright:
 * Copyright (C) 2009 Intevation GmbH
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

/**
 * @file file.c
 * @brief File utilities.
 */

/**
 * @brief Trace flag.
 *
 * 0 to turn off all tracing messages.
 */
#define TRACE 0

#include "tracef.h"
#include "file.h"

#include <errno.h>
#include <fcntl.h>
#include <glib/gstdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

/**
 * @brief Remove a directory, including all contents.
 *
 * @param[in]   dir_name  Name of the directory.
 * @param[out]  error     Error.
 *
 * @return TRUE on success, FALSE on error.
 */
gboolean
rmdir_recursively (const gchar* dir_name, GError** error)
{
  GError* temp_error = NULL;
  g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

  GDir* dir = g_dir_open (dir_name, 0, &temp_error);
  if (temp_error)
    {
      if (g_error_matches (temp_error, G_FILE_ERROR, G_FILE_ERROR_NOENT))
        {
          g_error_free (temp_error);
          return TRUE;
        }
      g_propagate_error (error, temp_error);
      return FALSE;
    }

  int pwd = open (".", O_RDONLY);
  if (pwd == -1)
    {
      g_set_error (error,
                   G_FILE_ERROR,
                   g_file_error_from_errno (errno),
                   (gchar*) strerror (errno));
      g_dir_close (dir);
      return FALSE;
    }

  if (g_chdir (dir_name))
    {
      g_set_error (error,
                   G_FILE_ERROR,
                   g_file_error_from_errno (errno),
                   (gchar*) strerror (errno));
      g_dir_close (dir);
      return FALSE;
    }

  const gchar* file_name = g_dir_read_name (dir);
  while (file_name)
    {
      if (g_file_test (file_name, G_FILE_TEST_IS_DIR))
        {
          rmdir_recursively (file_name, &temp_error);
          if (temp_error)
            {
              g_propagate_error (error, temp_error);
              g_dir_close (dir);
              fchdir (pwd);
              return FALSE;
            }
        }
      else if (g_unlink (file_name))
        {
          g_set_error (error,
                       G_FILE_ERROR,
                       g_file_error_from_errno (errno),
                       (gchar*) strerror (errno));
          g_dir_close (dir);
          fchdir (pwd);
          return FALSE;
        }
      file_name = g_dir_read_name (dir);
    }

  g_dir_close (dir);

  if (fchdir (pwd))
    g_set_error (error,
                 G_FILE_ERROR,
                 g_file_error_from_errno (errno),
                 (gchar*) strerror (errno));

  if (g_rmdir (dir_name))
    {
      g_set_error (error,
                   G_FILE_ERROR,
                   g_file_error_from_errno (errno),
                   (gchar*) strerror (errno));
      g_dir_close (dir);
      fchdir (pwd);
      return FALSE;
    }

  return TRUE;
}
