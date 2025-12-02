/* Copyright (C) 2009-2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
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

/**
 * @brief Filter columns for os iterator.
 */
#define OS_ITERATOR_FILTER_COLUMNS                                           \
 { GET_ITERATOR_FILTER_COLUMNS, "title", "hosts", "latest_severity",         \
   "highest_severity", "average_severity", "average_severity_score",         \
   "severity", "all_hosts", NULL }

/**
 * @brief OS iterator columns.
 */
#define OS_ITERATOR_COLUMNS                                                   \
 {                                                                            \
   GET_ITERATOR_COLUMNS (oss),                                                \
   {                                                                          \
     "0",                                                                     \
     "writable",                                                              \
     KEYWORD_TYPE_INTEGER                                                     \
   },                                                                         \
   {                                                                          \
     "(SELECT count (*) > 0 FROM host_oss WHERE os = oss.id)",                \
     "in_use",                                                                \
     KEYWORD_TYPE_INTEGER                                                     \
   },                                                                         \
   {                                                                          \
     "(SELECT coalesce (cpe_title (oss.name), ''))",                          \
     "title",                                                                 \
     KEYWORD_TYPE_STRING                                                      \
   },                                                                         \
   {                                                                          \
     "(SELECT count(*)"                                                       \
     " FROM (SELECT inner_cpes[1] AS cpe, host"                               \
     "       FROM (SELECT array_agg (host_details.value"                      \
     "                               ORDER BY host_details.id DESC)"          \
     "                    AS inner_cpes,"                                     \
     "                    host"                                               \
     "             FROM host_details, hosts"                                  \
     "             WHERE host_details.name = 'best_os_cpe'"                   \
     "             AND hosts.id = host_details.host"                          \
     "             AND (" ACL_USER_MAY_OPTS ("hosts") ")"                     \
     "             GROUP BY host)"                                            \
     "            AS host_details_subselect)"                                 \
     "      AS array_removal_subselect"                                       \
     " WHERE cpe = oss.name)",                                                \
     "hosts",                                                                 \
     KEYWORD_TYPE_INTEGER                                                     \
   },                                                                         \
   {                                                                          \
     "(SELECT round (CAST (severity AS numeric), 1) FROM host_max_severities" \
     " WHERE host = (SELECT host FROM host_oss"                               \
     "               WHERE os = oss.id"                                       \
     "               ORDER BY creation_time DESC LIMIT 1)"                    \
     " ORDER BY creation_time DESC LIMIT 1)",                                 \
     "latest_severity",                                                       \
     KEYWORD_TYPE_DOUBLE                                                      \
   },                                                                         \
   {                                                                          \
     "(SELECT round (max (CAST (severity AS numeric)), 1)"                    \
     " FROM host_max_severities"                                              \
     " WHERE host IN (SELECT DISTINCT host FROM host_oss"                     \
     "                WHERE os = oss.id))",                                   \
     "highest_severity",                                                      \
     KEYWORD_TYPE_DOUBLE                                                      \
   },                                                                         \
   {                                                                          \
     "(SELECT round (CAST (avg (severity) AS numeric), 2)"                    \
     " FROM (SELECT (SELECT severity FROM host_max_severities"                \
     "               WHERE host = hosts.host"                                 \
     "               ORDER BY creation_time DESC LIMIT 1)"                    \
     "              AS severity"                                              \
     "       FROM (SELECT distinct host FROM host_oss WHERE os = oss.id)"     \
     "       AS hosts)"                                                       \
     " AS severities)",                                                       \
     "average_severity",                                                      \
     KEYWORD_TYPE_DOUBLE                                                      \
   },                                                                         \
   {                                                                          \
     "(SELECT count(DISTINCT host) FROM host_oss WHERE os = oss.id)",         \
     "all_hosts",                                                             \
     KEYWORD_TYPE_INTEGER                                                     \
   },                                                                         \
   { NULL, NULL, KEYWORD_TYPE_UNKNOWN }                                       \
 }

/**
 * @brief OS iterator optional filtering columns.
 */
#define OS_ITERATOR_WHERE_COLUMNS                                             \
 {                                                                            \
   {                                                                          \
     "(SELECT round (CAST (avg (severity) AS numeric)"                        \
     "               * (SELECT count (distinct host)"                         \
     "                  FROM host_oss WHERE os = oss.id), 2)"                 \
     " FROM (SELECT (SELECT severity FROM host_max_severities"                \
     "               WHERE host = hosts.host"                                 \
     "               ORDER BY creation_time DESC LIMIT 1)"                    \
     "              AS severity"                                              \
     "       FROM (SELECT distinct host FROM host_oss WHERE os = oss.id)"     \
     "       AS hosts)"                                                       \
     " AS severities)",                                                       \
     "average_severity_score",                                                \
     KEYWORD_TYPE_DOUBLE                                                      \
   },                                                                         \
   {                                                                          \
     "(SELECT round (CAST (avg (severity) AS numeric), 2)"                    \
     " FROM (SELECT (SELECT severity FROM host_max_severities"                \
     "               WHERE host = hosts.host"                                 \
     "               ORDER BY creation_time DESC LIMIT 1)"                    \
     "              AS severity"                                              \
     "       FROM (SELECT distinct host FROM host_oss WHERE os = oss.id)"     \
     "       AS hosts)"                                                       \
     " AS severities)",                                                       \
     "severity",                                                              \
     KEYWORD_TYPE_DOUBLE                                                      \
   },                                                                         \
   { NULL, NULL, KEYWORD_TYPE_UNKNOWN }                                       \
 }

char *
result_host_asset_id (const char *, result_t);

int
manage_report_host_detail (report_t, const char *, const char *, GHashTable *);

char *
report_host_ip (const char *);

gchar *
report_host_hostname (report_host_t);

gchar *
report_host_best_os_cpe (report_host_t);

gchar *
report_host_best_os_txt (report_host_t);

int
report_host_noticeable (report_t, const gchar *);

gchar*
asset_host_extra_where (const char *);

gchar *
asset_os_iterator_opts_table ();

#endif /* not _GVMD_MANAGE_SQL_ASSETS_H */
