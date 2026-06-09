/* Copyright (C) 2026 Greenbone AG
*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: Web Application Targets SQL.
 *
 * SQL web application targets code for the GVM management layer.
 */

#if ENABLE_WEB_APPLICATION_SCANNING

#ifndef _GVMD_MANAGE_SQL_WEB_APPLICATION_TARGETS_H
#define _GVMD_MANAGE_SQL_WEB_APPLICATION_TARGETS_H

#include "manage_web_application_targets.h"

/**
 * @brief Filter columns for web application target iterator.
 */
#define WEB_APPLICATION_TARGET_ITERATOR_FILTER_COLUMNS          \
 { GET_ITERATOR_FILTER_COLUMNS, "urls", "exclude_urls",         \
   "credential_name", NULL }

/**
 * @brief Web application target iterator columns.
 */
#define WEB_APPLICATION_TARGET_ITERATOR_COLUMNS                 \
 {                                                              \
   GET_ITERATOR_COLUMNS (web_application_targets),              \
   { "urls", NULL, KEYWORD_TYPE_STRING },                       \
   { "exclude_urls", NULL, KEYWORD_TYPE_STRING },               \
   { "credential", NULL, KEYWORD_TYPE_INTEGER },                \
   {                                                            \
     "(SELECT name FROM credentials WHERE id = credential)",    \
     "credential_name",                                         \
     KEYWORD_TYPE_STRING                                        \
   },                                                           \
   { "0", NULL, KEYWORD_TYPE_INTEGER },                         \
   { NULL, NULL, KEYWORD_TYPE_UNKNOWN }                         \
 }

/**
 * @brief Web application target iterator columns for trash case.
 */
#define WEB_APPLICATION_TARGET_ITERATOR_TRASH_COLUMNS                    \
 {                                                                       \
   GET_ITERATOR_COLUMNS (web_application_targets_trash),                 \
   { "urls", NULL, KEYWORD_TYPE_STRING },                                \
   { "exclude_urls", NULL, KEYWORD_TYPE_STRING },                        \
   { "credential", NULL, KEYWORD_TYPE_INTEGER },                         \
   {                                                                     \
     "(SELECT CASE"                                                      \
     " WHEN credential_location = " G_STRINGIFY (LOCATION_TABLE)         \
     " THEN (SELECT name FROM credentials WHERE id = credential)"        \
     " ELSE (SELECT name FROM credentials_trash WHERE id = credential)"  \
     " END)",                                                            \
     "credential_name",                                                  \
     KEYWORD_TYPE_STRING                                                 \
   },                                                                    \
   { "credential_location", NULL, KEYWORD_TYPE_INTEGER },                \
   { NULL, NULL, KEYWORD_TYPE_UNKNOWN }                                  \
 }

char*
web_application_target_urls (web_application_target_t);

char*
web_application_target_exclude_urls (web_application_target_t);

credential_t
web_application_target_credential (web_application_target_t);

#endif /* not _GVMD_MANAGE_SQL_WEB_APPLICATION_TARGETS_H */

#endif /* ENABLE_WEB_APPLICATION_SCANNING */
