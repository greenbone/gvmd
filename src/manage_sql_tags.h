/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GVMD_MANAGE_SQL_TAGS_H
#define _GVMD_MANAGE_SQL_TAGS_H

#include "manage_tags.h"

/**
 * @brief Filter columns for Tag iterator.
 */
#define TAG_ITERATOR_FILTER_COLUMNS                                           \
 { GET_ITERATOR_FILTER_COLUMNS, "resource_type", "active", "value",           \
   "resources", NULL }

/**
 * @brief Tag iterator columns.
 */
#define TAG_ITERATOR_COLUMNS                                                  \
 {                                                                           \
   GET_ITERATOR_COLUMNS (tags),                                              \
   { "resource_type", NULL, KEYWORD_TYPE_STRING },                           \
   { "active", NULL, KEYWORD_TYPE_INTEGER },                                 \
   { "value", NULL, KEYWORD_TYPE_STRING },                                   \
   { "tag_resources_count (tags.id, tags.resource_type)",                    \
     "resources", KEYWORD_TYPE_INTEGER },                                    \
   { NULL, NULL, KEYWORD_TYPE_UNKNOWN }                                      \
 }

/**
 * @brief Tag iterator trash columns.
 */
#define TAG_ITERATOR_TRASH_COLUMNS                                           \
 {                                                                           \
   GET_ITERATOR_COLUMNS (tags_trash),                                        \
   { "resource_type", NULL, KEYWORD_TYPE_STRING },                           \
   { "active", NULL, KEYWORD_TYPE_INTEGER },                                 \
   { "value", NULL, KEYWORD_TYPE_STRING },                                   \
   { "tag_resources_trash_count (tags_trash.id, tags_trash.resource_type)",  \
     "resources", KEYWORD_TYPE_INTEGER },                                    \
   { NULL, NULL, KEYWORD_TYPE_UNKNOWN }                                      \
 }

/**
 * @brief Filter columns for Tag name iterator.
 */
#define TAG_NAME_ITERATOR_FILTER_COLUMNS                         \
 { "name", "resource_type", NULL }

/**
 * @brief Tag name iterator columns.
 */
#define TAG_NAME_ITERATOR_COLUMNS                                \
 {                                                               \
   { "name", NULL, KEYWORD_TYPE_STRING },                        \
   { "resource_type", NULL, KEYWORD_TYPE_STRING },               \
   { NULL, NULL, KEYWORD_TYPE_UNKNOWN }                          \
 }

void
tags_remove_resource (const char *, resource_t, int);

void
tags_set_locations (const char *, resource_t, resource_t, int);

#endif // not _GVMD_MANAGE_SQL_TAGS_H
