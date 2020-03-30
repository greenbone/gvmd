/* Copyright (C) 2020 Greenbone Networks GmbH
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

const char*
get_iterator_uuid (iterator_t*);

const char*
get_iterator_name (iterator_t*);

const char*
get_iterator_comment (iterator_t*);

const char*
get_iterator_creation_time (iterator_t*);

const char*
get_iterator_modification_time (iterator_t*);

const char*
get_iterator_owner_name (iterator_t*);

#endif /* not _GVMD_MANAGE_GET_H */
