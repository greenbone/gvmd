/* Copyright (C) 2019-2025 Greenbone AG
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

#ifndef _GVMD_MANAGE_SQL_ALERTS_H
#define _GVMD_MANAGE_SQL_ALERTS_H

#include "manage.h"

/**
 * @brief Filter columns for alert iterator.
 */
#define ALERT_ITERATOR_FILTER_COLUMNS                                         \
 { GET_ITERATOR_FILTER_COLUMNS, "event", "condition", "method",               \
   "filter",  NULL }

/**
 * @brief Alert iterator columns.
 */
#define ALERT_ITERATOR_COLUMNS                                                \
 {                                                                            \
   GET_ITERATOR_COLUMNS (alerts),                                             \
   { "event", NULL, KEYWORD_TYPE_INTEGER },                                   \
   { "condition", NULL, KEYWORD_TYPE_INTEGER },                               \
   { "method", NULL, KEYWORD_TYPE_INTEGER },                                  \
   { "filter", NULL, KEYWORD_TYPE_INTEGER },                                  \
   { G_STRINGIFY (LOCATION_TABLE), NULL, KEYWORD_TYPE_INTEGER },              \
   { "active", NULL, KEYWORD_TYPE_INTEGER },                                  \
   { NULL, NULL, KEYWORD_TYPE_UNKNOWN }                                       \
 }

/**
 * @brief Alert iterator columns for trash case.
 */
#define ALERT_ITERATOR_TRASH_COLUMNS                                          \
 {                                                                            \
   GET_ITERATOR_COLUMNS (alerts_trash),                                       \
   { "event", NULL, KEYWORD_TYPE_INTEGER },                                   \
   { "condition", NULL, KEYWORD_TYPE_INTEGER },                               \
   { "method", NULL, KEYWORD_TYPE_INTEGER },                                  \
   { "filter", NULL, KEYWORD_TYPE_STRING },                                   \
   { "filter_location", NULL, KEYWORD_TYPE_INTEGER},                          \
   { "active", NULL, KEYWORD_TYPE_INTEGER },                                  \
   { NULL, NULL, KEYWORD_TYPE_UNKNOWN }                                       \
 }

user_t
alert_owner (alert_t);

char *
alert_owner_uuid (alert_t);

char*
alert_owner_name (alert_t);

char *
alert_name (alert_t);

event_t
alert_event (alert_t);

char *
alert_data (alert_t, const char *, const char *);

int
alert_applies_to_task (alert_t, task_t);

#endif /* not _GVMD_MANAGE_SQL_ALERTS_H */
