/* Copyright (C) 2019-2025 Greenbone AG
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

#ifndef _GVMD_MANAGE_SQL_FILTERS_H
#define _GVMD_MANAGE_SQL_FILTERS_H

#include "manage_get.h"

#include <glib.h>

/**
 * @brief Filter columns for filter iterator.
 */
#define FILTER_ITERATOR_FILTER_COLUMNS                        \
 { GET_ITERATOR_FILTER_COLUMNS, "type", "term", NULL }

/**
 * @brief Filter iterator columns.
 */
#define FILTER_ITERATOR_COLUMNS                               \
 {                                                            \
   GET_ITERATOR_COLUMNS (filters),                            \
   { "type" , NULL, KEYWORD_TYPE_STRING },                    \
   { "term", NULL, KEYWORD_TYPE_STRING },                     \
   { NULL, NULL, KEYWORD_TYPE_UNKNOWN }                       \
 }

/**
 * @brief Filter iterator columns for trash case.
 */
#define FILTER_ITERATOR_TRASH_COLUMNS                         \
 {                                                            \
   GET_ITERATOR_COLUMNS (filters_trash),                      \
   { "type" , NULL, KEYWORD_TYPE_STRING },                    \
   { "term", NULL, KEYWORD_TYPE_STRING },                     \
   { NULL, NULL, KEYWORD_TYPE_UNKNOWN }                       \
 }

const char *
get_join (int, int, int);

gchar *
columns_select_column (column_t *, column_t *, const char *);

#endif /* not _GVMD_MANAGE_SQL_FILTERS_H */
