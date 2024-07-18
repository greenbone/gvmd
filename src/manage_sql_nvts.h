/* Copyright (C) 2010-2022 Greenbone AG
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
 * @file manage_sql_nvts.h
 * @brief Manager Manage library: SQL backend headers.
 */

#ifndef _GVMD_MANAGE_SQL_NVTS_H
#define _GVMD_MANAGE_SQL_NVTS_H

/**
 * @brief Filter columns for NVT info iterator.
 */
#define NVT_INFO_ITERATOR_FILTER_COLUMNS                                    \
 { GET_ITERATOR_FILTER_COLUMNS, "version", "cve",                           \
   "family", "cvss_base", "severity", "cvss", "script_tags", "qod",         \
   "qod_type", "solution_type", "solution", "summary", "insight",           \
   "affected", "impact", "detection", "solution_method", "epss_score",      \
   "epss_percentile", "max_epss_score", "max_epss_percentile",              \
   NULL }

/**
 * @brief NVT iterator columns.
 */
#define NVT_ITERATOR_COLUMNS                                                \
 {                                                                          \
   GET_ITERATOR_COLUMNS_PREFIX (""),                                        \
   { "''", "_owner", KEYWORD_TYPE_STRING },                                 \
   { "0", NULL, KEYWORD_TYPE_INTEGER },                                     \
   { "oid", NULL, KEYWORD_TYPE_STRING },                                    \
   { "modification_time", "version", KEYWORD_TYPE_INTEGER },                \
   { "name", NULL, KEYWORD_TYPE_STRING },                                   \
   { "cve", NULL, KEYWORD_TYPE_STRING },                                    \
   { "tag", NULL, KEYWORD_TYPE_STRING },                                    \
   { "category", NULL, KEYWORD_TYPE_STRING },                               \
   { "family", NULL, KEYWORD_TYPE_STRING },                                 \
   { "cvss_base", NULL, KEYWORD_TYPE_DOUBLE },                              \
   { "cvss_base", "severity", KEYWORD_TYPE_DOUBLE },                        \
   { "cvss_base", "cvss", KEYWORD_TYPE_DOUBLE },                            \
   { "qod", NULL, KEYWORD_TYPE_INTEGER },                                   \
   { "qod_type", NULL, KEYWORD_TYPE_STRING },                               \
   { "solution_type", NULL, KEYWORD_TYPE_STRING },                          \
   { "tag", "script_tags", KEYWORD_TYPE_STRING},                            \
   { "solution", NULL, KEYWORD_TYPE_STRING},                                \
   { "summary", NULL, KEYWORD_TYPE_STRING },                                \
   { "insight", NULL, KEYWORD_TYPE_STRING },                                \
   { "affected", NULL, KEYWORD_TYPE_STRING },                               \
   { "impact", NULL, KEYWORD_TYPE_STRING },                                 \
   { "detection", NULL, KEYWORD_TYPE_STRING },                              \
   { "solution_method", NULL, KEYWORD_TYPE_STRING },                        \
   { "coalesce (epss_score, 0.0)", "epss_score",                            \
     KEYWORD_TYPE_DOUBLE },                                                 \
   { "coalesce (epss_percentile, 0.0)", "epss_percentile",                  \
     KEYWORD_TYPE_DOUBLE },                                                 \
   { "epss_cve", NULL, KEYWORD_TYPE_STRING },                               \
   { "epss_severity", NULL, KEYWORD_TYPE_DOUBLE },                          \
   { "coalesce (max_epss_score, 0.0)", "max_epss_score",                    \
     KEYWORD_TYPE_DOUBLE },                                                 \
   { "coalesce (max_epss_percentile, 0.0)", "max_epss_percentile",          \
     KEYWORD_TYPE_DOUBLE },                                                 \
   { "max_epss_cve", NULL, KEYWORD_TYPE_STRING },                           \
   { "max_epss_severity", NULL, KEYWORD_TYPE_DOUBLE },                      \
   { NULL, NULL, KEYWORD_TYPE_UNKNOWN }                                     \
 }

/**
 * @brief NVT iterator columns.
 */
#define NVT_ITERATOR_COLUMNS_NVTS                                           \
 {                                                                          \
   GET_ITERATOR_COLUMNS_PREFIX ("nvts."),                                   \
   { "''", "_owner", KEYWORD_TYPE_STRING },                                 \
   { "0", NULL, KEYWORD_TYPE_STRING },                                      \
   { "oid", NULL, KEYWORD_TYPE_STRING },                                    \
   { "modification_time", "version", KEYWORD_TYPE_INTEGER },                \
   { "nvts.name", NULL, KEYWORD_TYPE_STRING },                              \
   { "cve", NULL, KEYWORD_TYPE_STRING },                                    \
   { "tag", NULL, KEYWORD_TYPE_STRING },                                    \
   { "category", NULL, KEYWORD_TYPE_STRING },                               \
   { "nvts.family", NULL, KEYWORD_TYPE_STRING },                            \
   { "cvss_base", NULL, KEYWORD_TYPE_DOUBLE },                              \
   { "cvss_base", "severity", KEYWORD_TYPE_DOUBLE },                        \
   { "cvss_base", "cvss", KEYWORD_TYPE_DOUBLE },                            \
   { "qod", NULL, KEYWORD_TYPE_INTEGER },                                   \
   { "qod_type", NULL, KEYWORD_TYPE_STRING },                               \
   { "solution_type", NULL, KEYWORD_TYPE_STRING },                          \
   { "tag", "script_tags", KEYWORD_TYPE_STRING },                           \
   { "solution", NULL, KEYWORD_TYPE_STRING },                               \
   { "summary", NULL, KEYWORD_TYPE_STRING },                                \
   { "insight", NULL, KEYWORD_TYPE_STRING },                                \
   { "affected", NULL, KEYWORD_TYPE_STRING },                               \
   { "impact", NULL, KEYWORD_TYPE_STRING },                                 \
   { "detection", NULL, KEYWORD_TYPE_STRING },                              \
   { "solution_method", NULL, KEYWORD_TYPE_STRING },                        \
   { "coalesce (epss_score, 0.0)", "epss_score",                            \
     KEYWORD_TYPE_DOUBLE },                                                 \
   { "coalesce (epss_percentile, 0.0)", "epss_percentile",                  \
     KEYWORD_TYPE_DOUBLE },                                                 \
   { "epss_cve", NULL, KEYWORD_TYPE_STRING },                               \
   { "epss_severity", NULL, KEYWORD_TYPE_DOUBLE },                          \
   { "coalesce (max_epss_score, 0.0)", "max_epss_score",                    \
     KEYWORD_TYPE_DOUBLE },                                                 \
   { "coalesce (max_epss_percentile, 0.0)", "max_epss_percentile",          \
     KEYWORD_TYPE_DOUBLE },                                                 \
   { "max_epss_cve", NULL, KEYWORD_TYPE_STRING },                           \
   { "max_epss_severity", NULL, KEYWORD_TYPE_DOUBLE },                      \
   { NULL, NULL, KEYWORD_TYPE_UNKNOWN }                                     \
 }

/**
 * @brief Default for vt_ref_insert_size.
 */
#define VT_REF_INSERT_SIZE_DEFAULT 50000

void
set_vt_ref_insert_size (int);

/**
 * @brief Default for vt_sev_insert_size.
 *
 * There are about 80k vt_severities.
 */
#define VT_SEV_INSERT_SIZE_DEFAULT 100000

void
set_vt_sev_insert_size (int);

const char *
get_osp_vt_update_socket ();

void
set_osp_vt_update_socket (const char *new_socket);

int
check_osp_vt_update_socket ();

void
check_db_nvts ();

int
check_config_families ();

pid_t
manage_sync_nvts (int (*) (pid_t*));

int
update_or_rebuild_nvts (int);

int
nvts_feed_version_status ();

int
manage_update_nvt_cache_osp (const gchar *);

char *
nvt_family (const char *);

int
family_count ();

#endif /* not _GVMD_MANAGE_SQL_NVTS_H */
