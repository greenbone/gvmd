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

/*
 * @file manage_sql_secinfo.h
 * @brief Manager Manage library: SQL backend headers.
 */

#include <glib.h>
#ifndef _GVMD_MANAGE_SQL_SECINFO_H
#define _GVMD_MANAGE_SQL_SECINFO_H

/**
 * @brief SQL to check if a result has CERT Bunds.
 */
#define SECINFO_SQL_RESULT_HAS_CERT_BUNDS                          \
 "(SELECT EXISTS (SELECT * FROM cert_bund_cves"                    \
 "                WHERE cve_name IN (SELECT ref_id"                \
 "                                   FROM vt_refs"                 \
 "                                   WHERE vt_oid = results.nvt"   \
 "                                     AND type = 'cve')))"

/**
 * @brief SQL to get a result's CERT Bunds.
 */
#define SECINFO_SQL_RESULT_CERT_BUNDS                                    \
 "(ARRAY (SELECT name::text"                                             \
 "        FROM cert_bund_advs"                                           \
 "        WHERE id IN (SELECT adv_id FROM cert_bund_cves"                \
 "                     WHERE cve_name IN (SELECT ref_id"                 \
 "                                        FROM vt_refs"                  \
 "                                        WHERE vt_oid = results.nvt"    \
 "                                        AND type = 'cve'))"            \
 "        ORDER BY name DESC))"

/**
 * @brief SQL to check if a result has CERT Bunds.
 */
#define SECINFO_SQL_RESULT_HAS_DFN_CERTS                           \
 "(SELECT EXISTS (SELECT * FROM dfn_cert_cves"                     \
 "                WHERE cve_name IN (SELECT ref_id"                \
 "                                   FROM vt_refs"                 \
 "                                   WHERE vt_oid = results.nvt"   \
 "                                     AND type = 'cve')))"

/**
 * @brief SQL to check if a result has CERT Bunds.
 */
#define SECINFO_SQL_RESULT_DFN_CERTS                                     \
 "(ARRAY (SELECT name::text"                                             \
 "        FROM dfn_cert_advs"                                            \
 "        WHERE id IN (SELECT adv_id FROM dfn_cert_cves"                 \
 "                     WHERE cve_name IN (SELECT ref_id"                 \
 "                                        FROM vt_refs"                  \
 "                                        WHERE vt_oid = results.nvt"    \
 "                                        AND type = 'cve'))"            \
 "        ORDER BY name DESC))"

/**
 * @brief Filter columns for CVE iterator.
 */
#define CVE_INFO_ITERATOR_FILTER_COLUMNS                         \
 { GET_ITERATOR_FILTER_COLUMNS, "cvss_vector", "products",       \
   "description", "published", "severity", "epss_score",         \
   "epss_percentile", NULL }

/**
 * @brief CVE iterator columns.
 */
#define CVE_INFO_ITERATOR_COLUMNS                               \
 {                                                              \
   GET_ITERATOR_COLUMNS_PREFIX (""),                            \
   { "''", "_owner", KEYWORD_TYPE_STRING },                     \
   { "0", NULL, KEYWORD_TYPE_INTEGER },                         \
   { "cvss_vector", NULL, KEYWORD_TYPE_STRING },                \
   { "products", NULL, KEYWORD_TYPE_STRING },                   \
   { "severity", NULL, KEYWORD_TYPE_DOUBLE },                   \
   { "description", NULL, KEYWORD_TYPE_STRING },                \
   { "creation_time", "published", KEYWORD_TYPE_INTEGER },      \
   { "coalesce (epss, 0.0)", "epss_score", KEYWORD_TYPE_DOUBLE },             \
   { "coalesce (percentile, 0.0)", "epss_percentile", KEYWORD_TYPE_DOUBLE },  \
   { NULL, NULL, KEYWORD_TYPE_UNKNOWN }                         \
 }

/**
 * @brief Filter columns for CVE iterator.
 */
#define CPE_INFO_ITERATOR_FILTER_COLUMNS                    \
 { GET_ITERATOR_FILTER_COLUMNS, "title", "status",          \
   "deprecated_by_id", "severity", "cves", "nvd_id",        \
   NULL }

/**
 * @brief CPE iterator columns.
 */
#define CPE_INFO_ITERATOR_COLUMNS                               \
 {                                                              \
   GET_ITERATOR_COLUMNS_PREFIX (""),                            \
   { "''", "_owner", KEYWORD_TYPE_STRING },                     \
   { "0", NULL, KEYWORD_TYPE_INTEGER },                         \
   { "title", NULL, KEYWORD_TYPE_STRING },                      \
   { "status", NULL, KEYWORD_TYPE_STRING },                     \
   { "deprecated_by_id", NULL, KEYWORD_TYPE_INTEGER },          \
   { "severity", NULL, KEYWORD_TYPE_DOUBLE },                   \
   { "cve_refs", "cves", KEYWORD_TYPE_INTEGER },                \
   { "nvd_id", NULL, KEYWORD_TYPE_INTEGER },                    \
   { NULL, NULL, KEYWORD_TYPE_UNKNOWN }                         \
 }

/**
 * @brief Filter columns for CERT_BUND_ADV iterator.
 */
#define CERT_BUND_ADV_INFO_ITERATOR_FILTER_COLUMNS           \
 { GET_ITERATOR_FILTER_COLUMNS, "title", "summary",          \
   "cves", "severity", NULL }

/**
 * @brief CERT_BUND_ADV iterator columns.
 */
#define CERT_BUND_ADV_INFO_ITERATOR_COLUMNS                       \
 {                                                               \
   GET_ITERATOR_COLUMNS_PREFIX (""),                             \
   { "''", "_owner", KEYWORD_TYPE_STRING },                      \
   { "0", NULL, KEYWORD_TYPE_INTEGER },                          \
   { "title", NULL, KEYWORD_TYPE_STRING },                       \
   { "summary", NULL, KEYWORD_TYPE_STRING },                     \
   { "cve_refs", "cves", KEYWORD_TYPE_INTEGER },                 \
   { "severity", NULL, KEYWORD_TYPE_DOUBLE },                    \
   { NULL, NULL, KEYWORD_TYPE_UNKNOWN }                          \
 }

/**
 * @brief Filter columns for DFN_CERT_ADV iterator.
 */
#define DFN_CERT_ADV_INFO_ITERATOR_FILTER_COLUMNS           \
 { GET_ITERATOR_FILTER_COLUMNS, "title", "summary",         \
   "cves", "severity", NULL }

/**
 * @brief DFN_CERT_ADV iterator columns.
 */
#define DFN_CERT_ADV_INFO_ITERATOR_COLUMNS                       \
 {                                                               \
   GET_ITERATOR_COLUMNS_PREFIX (""),                             \
   { "''", "_owner", KEYWORD_TYPE_STRING },                      \
   { "0", NULL, KEYWORD_TYPE_INTEGER },                          \
   { "title", NULL, KEYWORD_TYPE_STRING },                       \
   { "summary", NULL, KEYWORD_TYPE_STRING },                     \
   { "cve_refs", "cves", KEYWORD_TYPE_INTEGER },                 \
   { "severity", NULL, KEYWORD_TYPE_DOUBLE },                    \
   { NULL, NULL, KEYWORD_TYPE_UNKNOWN }                          \
 }

/**
 * @brief Default for secinfo_commit_size.
 */
#define SECINFO_COMMIT_SIZE_DEFAULT 0

int
secinfo_feed_version_status ();

pid_t
manage_sync_scap (sigset_t *);

int
manage_rebuild_scap (GSList *, const db_conn_info_t *);

pid_t
manage_sync_cert (sigset_t *);

int
check_scap_db_version ();

int
check_cert_db_version ();

int
get_secinfo_commit_size ();

void
set_secinfo_commit_size (int);

#endif /* not _GVMD_MANAGE_SQL_SECINFO_H */
