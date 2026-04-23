/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GVMD_MANAGE_SQL_SCHEDULES_H
#define _GVMD_MANAGE_SQL_SCHEDULES_H

#include "manage_schedules.h"

/**
 * @brief Filter columns for schedule iterator.
 */
#define SCHEDULE_ITERATOR_FILTER_COLUMNS                                      \
 { GET_ITERATOR_FILTER_COLUMNS, "first_time", "period", "period_months",      \
   "duration", "timezone", "first_run", "next_run", NULL }

/**
 * @brief Schedule iterator columns.
 */
#define SCHEDULE_ITERATOR_COLUMNS                                          \
 {                                                                         \
   GET_ITERATOR_COLUMNS (schedules),                                       \
   { "first_time", NULL, KEYWORD_TYPE_INTEGER },                           \
   { "period", NULL, KEYWORD_TYPE_INTEGER },                               \
   { "period_months", NULL, KEYWORD_TYPE_INTEGER },                        \
   { "duration", NULL, KEYWORD_TYPE_INTEGER },                             \
   { "timezone", NULL, KEYWORD_TYPE_STRING },                              \
   { "icalendar", NULL, KEYWORD_TYPE_STRING },                             \
   { "next_time_ical (icalendar, m_now()::bigint, timezone)",              \
     "next_run",                                                           \
     KEYWORD_TYPE_INTEGER },                                               \
   { "first_time", "first_run", KEYWORD_TYPE_INTEGER },                    \
   { NULL, NULL, KEYWORD_TYPE_UNKNOWN }                                    \
 }

/**
 * @brief Schedule iterator columns for trash case.
 */
#define SCHEDULE_ITERATOR_TRASH_COLUMNS                                    \
 {                                                                         \
   GET_ITERATOR_COLUMNS (schedules_trash),                                 \
   { "first_time", NULL, KEYWORD_TYPE_INTEGER },                           \
   { "period", NULL, KEYWORD_TYPE_INTEGER },                               \
   { "period_months", NULL, KEYWORD_TYPE_INTEGER },                        \
   { "duration", NULL, KEYWORD_TYPE_INTEGER },                             \
   { "timezone", NULL, KEYWORD_TYPE_STRING },                              \
   { "icalendar", NULL, KEYWORD_TYPE_STRING },                             \
   { NULL, NULL, KEYWORD_TYPE_UNKNOWN }                                    \
 }

#endif // not _GVMD_MANAGE_SQL_SCHEDULES_H
