/* Copyright (C) 2012-2022 Greenbone AG
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
 * @file utils.h
 * @brief Headers for Greenbone Vulnerability Manager: General utilities.
 */

#ifndef _GVMD_UTILS_H
#define _GVMD_UTILS_H

#include <glib.h>
#include <gvm/util/xmlutils.h>
#include <time.h>

int
gvm_usleep (unsigned int);

int
gvm_sleep (unsigned int);

int
parse_utc_ctime (const char *);

int
parse_feed_timestamp (const char *);

int
parse_ctime (const char *);

int
days_from_now (time_t *);

time_t
parse_iso_time_tz (const char *, const char *);

char *
iso_time (time_t *);

char *
iso_time_tz (time_t *, const char *, const char **);

char *
iso_if_time (time_t epoch_time);

/**
 * @brief Lockfile.
 */
typedef struct
{
  int fd;      ///< File descriptor.
  gchar *name; ///< Name.
} lockfile_t;

int
lockfile_lock (lockfile_t *, const gchar *);

int
lockfile_lock_nb (lockfile_t *, const gchar *);

int
lockfile_lock_path_nb (lockfile_t *, const gchar *);

int
lockfile_lock_shared_nb (lockfile_t *, const gchar *);

int
lockfile_unlock (lockfile_t *);

int
lockfile_locked (const gchar *);

int
is_uuid (const char *);

int
parse_xml_file (const gchar *, entity_t *);

void
setup_signal_handler (int, void (*) (int), int);

void
setup_signal_handler_info (int, void (*) (int, siginfo_t *, void *), int);

int
fork_with_handlers ();

void
wait_for_pid (pid_t, const char *);

guint64
phys_mem_available ();

guint64
phys_mem_total ();

#endif /* not _GVMD_UTILS_H */
