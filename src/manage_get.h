/* Copyright (C) 2020-2022 Greenbone AG
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
 * @file manage_get.h
 * @brief Headers for Greenbone Vulnerability Manager: Manage lib: GET support.
 */

#ifndef _GVMD_MANAGE_GET_H
#define _GVMD_MANAGE_GET_H

#include "iterator.h"
#include "manage_resources.h"
#include "manage_filter_utils.h"

#include <glib.h>

/**
 * @brief Command data for a get command.
 */
typedef struct
{
  int details;         ///< Boolean.  Whether to include full details.
  char *filt_id;       ///< Filter ID.  Overrides "filter".
  char *filter;        ///< Filter term.
  char *filter_replace; ///< Column to replace in filter.
  char *filter_replacement; ///< Filter term to replace the one in filt_id.
  char *id;            ///< ID of single item to get.
  int trash;           ///< Boolean.  Whether to return from trashcan.
  gchar *type;         ///< Type of resource.
  gchar *subtype;      ///< Subtype, or NULL.
  int ignore_max_rows_per_page; ///< Whether to ignore the Max Rows Per Page setting.
  int ignore_pagination; ///< Whether to ignore the pagination (first and max).
  int minimal;         ///< Whether to respond with minimal information.
  GHashTable *extra_params; ///< Hashtable of type-specific extra parameters.
} get_data_t;

void
get_data_reset (get_data_t*);

const char *
get_data_get_extra (const get_data_t *, const char *);

void
get_data_set_extra (get_data_t *, const char *, const char *);

resource_t
get_iterator_resource (iterator_t*);

const char*
get_iterator_uuid (iterator_t*);

const char*
get_iterator_name (iterator_t*);

const char*
get_iterator_comment (iterator_t*);

time_t
get_iterator_creation_time (iterator_t*);

time_t
get_iterator_modification_time (iterator_t*);

user_t
get_iterator_owner (iterator_t*);

const char*
get_iterator_owner_name (iterator_t*);

/**
 * @brief Generate accessor for an SQL iterator.
 *
 * This convenience macro is used to generate an accessor returning a
 * const string pointer.
 *
 * @param[in]  name  Name of accessor.
 * @param[in]  col   Column number to access.
 */
#define DEF_ACCESS(name, col)                                     \
const char*                                                       \
name (iterator_t* iterator)                                       \
{                                                                 \
  const char *ret;                                                \
  if (iterator->done) return NULL;                                \
  ret = iterator_string (iterator, col);                          \
  return ret;                                                     \
}

/**
 * @brief Iterator column.
 */
typedef struct
{
  gchar *select;       ///< Column for SELECT.
  gchar *filter;       ///< Filter column name.  NULL to use select_column.
  keyword_type_t type; ///< Type of column.
} column_t;

/**
 * @brief Filter columns for GET iterator.
 */
#define ANON_GET_ITERATOR_FILTER_COLUMNS "uuid", \
 "created", "modified", "_owner"

/**
 * @brief Filter columns for GET iterator.
 */
#define GET_ITERATOR_FILTER_COLUMNS "uuid", "name", "comment", \
 "created", "modified", "_owner"

/**
 * @brief Columns for GET iterator, as a single string.
 *
 * @param[in]  prefix  Column prefix.
 */
#define GET_ITERATOR_COLUMNS_STRING                     \
  "id, uuid, name, comment, creation_time,"             \
  " modification_time, creation_time AS created,"       \
  " modification_time AS modified"

/**
 * @brief Columns for GET iterator.
 *
 * @param[in]  prefix  Column prefix.
 */
#define GET_ITERATOR_COLUMNS_PREFIX(prefix)                                 \
  { prefix "id", NULL, KEYWORD_TYPE_INTEGER },                              \
  { prefix "uuid", NULL, KEYWORD_TYPE_STRING },                             \
  { prefix "name", NULL, KEYWORD_TYPE_STRING },                             \
  { prefix "comment", NULL, KEYWORD_TYPE_STRING },                          \
  { prefix "creation_time", NULL, KEYWORD_TYPE_INTEGER },                   \
  { prefix "modification_time", NULL, KEYWORD_TYPE_INTEGER },               \
  { prefix "creation_time", "created", KEYWORD_TYPE_INTEGER },              \
  { prefix "modification_time", "modified", KEYWORD_TYPE_INTEGER }

/**
 * @brief Columns for GET iterator.
 *
 * @param[in]  table  Table.
 */
#define GET_ITERATOR_COLUMNS(table)                                             \
  GET_ITERATOR_COLUMNS_PREFIX(""),                                              \
  {                                                                             \
    "(SELECT name FROM users AS inner_users"                                    \
    " WHERE inner_users.id = " G_STRINGIFY (table) ".owner)",                   \
    "_owner",                                                                   \
    KEYWORD_TYPE_STRING                                                         \
  },                                                                            \
  { "owner", NULL, KEYWORD_TYPE_INTEGER }

/**
 * @brief Number of columns for GET iterator.
 */
#define GET_ITERATOR_COLUMN_COUNT 10

#endif /* not _GVMD_MANAGE_GET_H */
