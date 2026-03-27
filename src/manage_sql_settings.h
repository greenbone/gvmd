/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GVMD_MANAGE_SQL_SETTINGS_H
#define _GVMD_MANAGE_SQL_SETTINGS_H

#include "manage_settings.h"

/**
 * @brief Filter columns for setting iterator.
 */
#define SETTING_ITERATOR_FILTER_COLUMNS \
 { "name", "comment", "value", NULL }

/**
 * @brief Setting iterator columns.
 */
#define SETTING_ITERATOR_COLUMNS                              \
 {                                                            \
   { "id" , NULL, KEYWORD_TYPE_INTEGER },                     \
   { "uuid", NULL, KEYWORD_TYPE_STRING },                     \
   { "name", NULL, KEYWORD_TYPE_STRING },                     \
   { "comment", NULL, KEYWORD_TYPE_STRING },                  \
   { "value", NULL, KEYWORD_TYPE_STRING },                    \
   { NULL, NULL, KEYWORD_TYPE_UNKNOWN }                       \
 }

char *
setting_timezone ();

int
setting_dynamic_severity_int ();

int
setting_auto_cache_rebuild_int ();

int
setting_value_sql (const char *, char **);

int
setting_value_int_sql (const char *, int *);

#endif // not _GVMD_MANAGE_SQL_SETTINGS_H
