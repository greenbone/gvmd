/* Copyright (C) 2019-2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GVMD_MANAGE_SQL_FILTERS_H
#define _GVMD_MANAGE_SQL_FILTERS_H

#include "manage_filters.h"
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
