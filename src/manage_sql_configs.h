/* GVM
 * $Id$
 * Description: GVM management layer SQL: Config headers
 *
 * Authors:
 * Matthew Mundell <matthew.mundell@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2019 Greenbone Networks GmbH
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

#ifndef _GVMD_MANAGE_SQL_CONFIGS_H
#define _GVMD_MANAGE_SQL_CONFIGS_H

#include "manage.h"

/**
 * @brief Filter columns for scan configs iterator.
 */
#define CONFIG_ITERATOR_FILTER_COLUMNS                                        \
 { GET_ITERATOR_FILTER_COLUMNS, "nvt_selector", "families_total",             \
   "nvts_total", "families_trend", "nvts_trend", "type", "usage_type",        \
   NULL }

/**
 * @brief Scan config iterator columns.
 */
#define CONFIG_ITERATOR_COLUMNS                                               \
 {                                                                            \
   GET_ITERATOR_COLUMNS (configs),                                            \
   { "nvt_selector", NULL, KEYWORD_TYPE_STRING },                             \
   { "family_count", "families_total", KEYWORD_TYPE_INTEGER },                \
   { "nvt_count", "nvts_total", KEYWORD_TYPE_INTEGER},                        \
   { "families_growing", "families_trend", KEYWORD_TYPE_INTEGER},             \
   { "nvts_growing", "nvts_trend", KEYWORD_TYPE_INTEGER },                    \
   { "type", NULL, KEYWORD_TYPE_INTEGER },                                    \
   { "scanner", NULL, KEYWORD_TYPE_INTEGER },                                 \
   { "0", NULL, KEYWORD_TYPE_INTEGER },                                       \
   { "usage_type", NULL, KEYWORD_TYPE_STRING },                               \
   { NULL, NULL, KEYWORD_TYPE_UNKNOWN }                                       \
 }

/**
 * @brief Scan config iterator columns for trash case.
 */
#define CONFIG_ITERATOR_TRASH_COLUMNS                                         \
 {                                                                            \
   GET_ITERATOR_COLUMNS (configs_trash),                                      \
   { "nvt_selector", NULL, KEYWORD_TYPE_STRING },                             \
   { "family_count", "families_total", KEYWORD_TYPE_INTEGER },                \
   { "nvt_count", "nvts_total", KEYWORD_TYPE_INTEGER},                        \
   { "families_growing", "families_trend", KEYWORD_TYPE_INTEGER},             \
   { "nvts_growing", "nvts_trend", KEYWORD_TYPE_INTEGER },                    \
   { "type", NULL, KEYWORD_TYPE_INTEGER },                                    \
   { "scanner", NULL, KEYWORD_TYPE_INTEGER },                                 \
   { "scanner_location", NULL, KEYWORD_TYPE_INTEGER },                        \
   { "usage_type", NULL, KEYWORD_TYPE_STRING },                               \
   { NULL, NULL, KEYWORD_TYPE_UNKNOWN }                                       \
 }

gchar *
configs_extra_where (const char *);

#endif /* not _GVMD_MANAGE_SQL_CONFIGS_H */
