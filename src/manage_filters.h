/* Copyright (C) 2025 Greenbone AG
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

#ifndef _GVMD_MANAGE_FILTERS_H
#define _GVMD_MANAGE_FILTERS_H

#include "gmp_get.h"
#include "manage_resources.h"

/**
 * @brief filt_id value to use term or built-in default filter.
 */
#define FILT_ID_NONE "0"

/**
 * @brief filt_id value to use the filter in the user setting if possible.
 */
#define FILT_ID_USER_SETTING "-2"

void
manage_filter_controls (const gchar *, int *, int *, gchar **, int *);

void
manage_report_filter_controls (const gchar *, int *, int *, gchar **, int *,
                               int *, gchar **, gchar **, gchar **, gchar **,
                               gchar **, int *, int *, int *, int *, gchar **);

gchar *
manage_clean_filter (const gchar *, int);

gchar *
manage_clean_filter_remove (const gchar *, const gchar *, int);

gboolean
find_filter (const char *, filter_t *);

gboolean
find_filter_with_permission (const char *, filter_t *, const char *);

char *
filter_uuid (filter_t);

char *
trash_filter_uuid (filter_t);

char *
filter_name (filter_t);

char *
trash_filter_name (filter_t);

int
create_filter (const char *, const char *, const char *, const char *,
               filter_t *);

int
copy_filter (const char *, const char *, const char *, filter_t *);

int
delete_filter (const char *, int);

int
trash_filter_in_use (filter_t);

int
filter_in_use (filter_t);

int
trash_filter_writable (filter_t);

int
filter_writable (filter_t);

int
filter_count (const get_data_t *);

int
init_filter_iterator (iterator_t *, get_data_t *);

const char*
filter_iterator_type (iterator_t *);

const char*
filter_iterator_term (iterator_t *);

void
init_filter_alert_iterator (iterator_t *, filter_t);

const char*
filter_alert_iterator_name (iterator_t *);

const char*
filter_alert_iterator_uuid (iterator_t *);

int
filter_alert_iterator_readable (iterator_t *);

int
modify_filter (const char *, const char *, const char *, const char *,
               const char *);

#endif /* not _GVMD_MANAGE_FILTERS_H */
