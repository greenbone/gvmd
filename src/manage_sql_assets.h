/* Copyright (C) 2009-2025 Greenbone AG
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

#ifndef _GVMD_MANAGE_SQL_ASSETS_H
#define _GVMD_MANAGE_SQL_ASSETS_H

#include "manage_resources.h"

/**
 * @file
 * @brief GVM management layer: Asset SQL
 *
 * The Asset SQL for the GVM management layer.
 */

/**
 * @brief Filter columns for host iterator.
 */
#define HOST_ITERATOR_FILTER_COLUMNS                                        \
 { GET_ITERATOR_FILTER_COLUMNS, "severity", "os", "oss", "hostname", "ip",  \
   "severity_level", "updated", "best_os_cpe", NULL }

/**
 * @brief Host iterator columns.
 */
#define HOST_ITERATOR_COLUMNS                                         \
 {                                                                    \
   GET_ITERATOR_COLUMNS (hosts),                                      \
   {                                                                  \
     "1",                                                             \
     "writable",                                                      \
     KEYWORD_TYPE_INTEGER                                             \
   },                                                                 \
   {                                                                  \
     "0",                                                             \
     "in_use",                                                        \
     KEYWORD_TYPE_INTEGER                                             \
   },                                                                 \
   {                                                                  \
     "(SELECT round (CAST (severity AS numeric), 1)"                  \
     " FROM host_max_severities"                                      \
     " WHERE host = hosts.id"                                         \
     " ORDER by creation_time DESC"                                   \
     " LIMIT 1)",                                                     \
     "severity",                                                      \
     KEYWORD_TYPE_DOUBLE                                              \
   },                                                                 \
   {                                                                  \
     "(SELECT CASE"                                                   \
     "        WHEN best_os_text LIKE '%[possible conflict]%'"         \
     "        THEN best_os_text"                                      \
     "        WHEN best_os_cpe IS NULL"                               \
     "        THEN '[unknown]'"                                       \
     "        ELSE best_os_cpe"                                       \
     "        END"                                                    \
     " FROM (SELECT (SELECT value"                                    \
     "               FROM (SELECT max (id) AS id"                     \
     "                     FROM host_details"                         \
     "                     WHERE host = hosts.id"                     \
     "                     AND name = 'best_os_cpe')"                 \
     "                     AS sub,"                                   \
     "                    host_details"                               \
     "               WHERE sub.id = host_details.id)"                 \
     "              AS best_os_cpe,"                                  \
     "              (SELECT value"                                    \
     "               FROM (SELECT max (id) AS id"                     \
     "                     FROM host_details"                         \
     "                     WHERE host = hosts.id"                     \
     "                     AND name = 'best_os_text')"                \
     "                     AS sub,"                                   \
     "                    host_details"                               \
     "               WHERE sub.id = host_details.id)"                 \
     "              AS best_os_text)"                                 \
     "      AS vars)",                                                \
     "os",                                                            \
     KEYWORD_TYPE_STRING                                              \
   },                                                                 \
   {                                                                  \
     "(SELECT group_concat (name, ', ') FROM oss"                     \
     "  WHERE id IN (SELECT distinct os FROM host_oss"                \
     "               WHERE host = hosts.id))",                        \
     "oss",                                                           \
     KEYWORD_TYPE_INTEGER                                             \
   },                                                                 \
   {                                                                  \
     "(SELECT value"                                                  \
     " FROM host_identifiers"                                         \
     " WHERE host = hosts.id"                                         \
     " AND name = 'hostname'"                                         \
     " ORDER by creation_time DESC"                                   \
     " LIMIT 1)",                                                     \
     "hostname",                                                      \
     KEYWORD_TYPE_STRING                                              \
   },                                                                 \
   {                                                                  \
     "(SELECT value"                                                  \
     " FROM host_identifiers"                                         \
     " WHERE host = hosts.id"                                         \
     " AND name = 'ip'"                                               \
     " ORDER by creation_time DESC"                                   \
     " LIMIT 1)",                                                     \
     "ip",                                                            \
     KEYWORD_TYPE_STRING                                              \
   },                                                                 \
   { NULL, NULL, KEYWORD_TYPE_UNKNOWN }                               \
 }

/**
 * @brief Host iterator WHERE columns.
 */
#define HOST_ITERATOR_WHERE_COLUMNS                                   \
 {                                                                    \
   {                                                                  \
     "(SELECT severity_to_level (CAST (severity AS numeric), 0)"      \
     " FROM host_max_severities"                                      \
     " WHERE host = hosts.id"                                         \
     " ORDER by creation_time DESC"                                   \
     " LIMIT 1)",                                                     \
     "severity_level",                                                \
     KEYWORD_TYPE_STRING                                              \
   },                                                                 \
   {                                                                  \
     "modification_time", "updated", KEYWORD_TYPE_INTEGER             \
   },                                                                 \
   {                                                                  \
     "(SELECT value"                                                  \
     "   FROM (SELECT max (id) AS id"                                 \
     "           FROM host_details"                                   \
     "          WHERE host = hosts.id"                                \
     "            AND name = 'best_os_cpe')"                          \
     "         AS sub, host_details"                                  \
     "  WHERE sub.id = host_details.id)",                             \
     "best_os_cpe",                                                   \
     KEYWORD_TYPE_STRING                                              \
   },                                                                 \
   { NULL, NULL, KEYWORD_TYPE_UNKNOWN }                               \
 }

char *
result_host_asset_id (const char *, result_t);

int
manage_report_host_detail (report_t, const char *, const char *, GHashTable *);

gchar*
asset_host_extra_where (const char *);

#endif /* not _GVMD_MANAGE_SQL_ASSETS_H */
