/* Copyright (C) 2019-2022 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GVMD_MANAGE_SQL_CONFIGS_H
#define _GVMD_MANAGE_SQL_CONFIGS_H

#include "manage_configs.h"

/**
 * @brief Filter columns for scan configs iterator.
 */
#define CONFIG_ITERATOR_FILTER_COLUMNS                                        \
 { GET_ITERATOR_FILTER_COLUMNS, "nvt_selector", "families_total",             \
   "nvts_total", "families_trend", "nvts_trend", "usage_type",                \
   "predefined", NULL }

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
   { "0", NULL, KEYWORD_TYPE_INTEGER },                                       \
   { "usage_type", NULL, KEYWORD_TYPE_STRING },                               \
   { "predefined", NULL, KEYWORD_TYPE_INTEGER },                              \
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
   { "scanner_location", NULL, KEYWORD_TYPE_INTEGER },                        \
   { "usage_type", NULL, KEYWORD_TYPE_STRING },                               \
   { "predefined", NULL, KEYWORD_TYPE_INTEGER },                              \
   { NULL, NULL, KEYWORD_TYPE_UNKNOWN }                                       \
 }

gchar *
configs_extra_where (const char *);

int
create_config_no_acl (const char *, const char *, int, const char *,
                      int, const array_t *, const array_t *, const char *,
                      config_t *, char **);

gboolean
find_config_no_acl (const char *, config_t *);

gboolean
find_trash_config_no_acl (const char *, config_t *);

int
config_predefined (config_t config);

int
trash_config_predefined (config_t);

void
migrate_predefined_configs ();

int
config_updated_in_feed (config_t, const gchar *);

int
deprecated_config_id_updated_in_feed (const char *, const gchar *);

void
update_config (config_t, const gchar *, const gchar *, const gchar *,
               int, const array_t*, const array_t*, const gchar *);

void
check_db_configs (int);

void
check_whole_only_in_configs ();

int
check_config_families ();

#endif /* not _GVMD_MANAGE_SQL_CONFIGS_H */
