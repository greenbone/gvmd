/* Copyright (C) 2020 Greenbone Networks GmbH
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

/*
 * @file manage_preferences.h
 * @brief Headers for Greenbone Vulnerability Manager: Manage lib: Preferences.
 */

#ifndef _GVMD_MANAGE_PREFERENCES_H
#define _GVMD_MANAGE_PREFERENCES_H

#include <gvm/base/array.h>

/**
 * @brief An NVT preference.
 */
typedef struct
{
  char *name;          ///< Name of preference.
  char *id;            ///< ID of preference.
  char *type;          ///< Type of preference (radio, password, ...).
  char *value;         ///< Value of preference.
  char *nvt_name;      ///< Name of NVT preference affects.
  char *nvt_oid;       ///< OID of NVT preference affects.
  array_t *alts;       ///< Array of gchar's.  Alternate values for radio type.
  char *default_value; ///< Default value of preference.
  char *hr_name;       ///< Extended, more human-readable name used by OSP.
  int free_strings;    ///< Whether string fields are freed by preference_free.
} preference_t;

gpointer
preference_new (char *, char *, char *, char *, char *,
                char *, array_t *, char*,
                char *, int);

void
preference_free (preference_t *);

void
cleanup_import_preferences (array_t *);

#endif /* not _GVMD_MANAGE_PREFERENCES_H */
