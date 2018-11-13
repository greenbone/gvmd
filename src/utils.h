/* GVM
 * $Id$
 * Description: Headers for Greenbone Vulnerability Manager: General utilities.
 *
 * Authors:
 * Matthew Mundell <matthew.mundell@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2012 Greenbone Networks GmbH
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
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

#ifndef _GVMD_UTILS_H
#define _GVMD_UTILS_H

#include <time.h>
#include <glib.h>

int
gvm_usleep (unsigned int);

int
gvm_sleep (unsigned int);

int
parse_otp_time (const char *);

int
parse_feed_timestamp (const char *);

int
parse_ctime (const char *);

int
days_from_now (time_t *);

char *
iso_time (time_t *);

char *
iso_time_tz (time_t *, const char *, const char **);

/**
 * @brief Lockfile.
 */
typedef struct
{
  int fd;         ///< File descriptor.
  gchar *name;    ///< Name.
} lockfile_t;

int
lockfile_lock (lockfile_t *, const gchar *);

int
lockfile_lock_nb (lockfile_t *, const gchar *);

int
lockfile_lock_shared_nb (lockfile_t *, const gchar *);

int
lockfile_unlock (lockfile_t *);

int
lockfile_locked (const gchar *);

#endif /* not _GVMD_UTILS_H */
