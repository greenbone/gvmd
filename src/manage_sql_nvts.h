/* Copyright (C) 2010-2022 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Manager Manage library: SQL backend headers.
 */

#ifndef _GVMD_MANAGE_SQL_NVTS_H
#define _GVMD_MANAGE_SQL_NVTS_H

#include "manage_nvts.h"
#include "manage_sql_nvts_openvasd.h"
#include "manage_sql_nvts_osp.h"

/**
 * @brief Filter columns for NVT info iterator.
 */
#define NVT_INFO_ITERATOR_FILTER_COLUMNS                                    \
 { GET_ITERATOR_FILTER_COLUMNS, "version", "cve",                           \
   "family", "cvss_base", "severity", "cvss", "script_tags", "qod",         \
   "qod_type", "solution_type", "solution", "summary", "insight",           \
   "affected", "impact", "detection", "solution_method", "epss_score",      \
   "epss_percentile", "max_epss_score", "max_epss_percentile", "discovery", \
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
   { "discovery", NULL, KEYWORD_TYPE_INTEGER },                             \
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
   { "discovery", NULL, KEYWORD_TYPE_INTEGER },                             \
   { NULL, NULL, KEYWORD_TYPE_UNKNOWN }                                     \
 }

gboolean
skip_update_nvti_cache ();

void
check_db_nvts ();

char *
nvt_family (const char *);

int
family_count ();

#endif /* not _GVMD_MANAGE_SQL_NVTS_H */
