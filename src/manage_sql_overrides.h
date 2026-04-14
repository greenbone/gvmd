/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GVMD_MANAGE_SQL_OVERRIDES_H
#define _GVMD_MANAGE_SQL_OVERRIDES_H

#include "manage_overrides.h"

/**
 * @brief Filter columns for override iterator.
 */
#define OVERRIDE_ITERATOR_FILTER_COLUMNS                                      \
 { ANON_GET_ITERATOR_FILTER_COLUMNS, "name", "nvt", "text", "nvt_id",         \
   "task_name", "task_id", "hosts", "port", "threat", "new_threat", "active", \
   "result", "severity", "new_severity", "active_days", NULL }

/**
 * @brief Override iterator columns.
 */
#define OVERRIDE_ITERATOR_COLUMNS                                           \
 {                                                                          \
   { "overrides.id", "id", KEYWORD_TYPE_INTEGER },                          \
   { "overrides.uuid", "uuid", KEYWORD_TYPE_STRING },                       \
   {                                                                        \
     "(CASE"                                                                \
     " WHEN overrides.nvt LIKE 'CVE-%%'"                                    \
     " THEN overrides.nvt"                                                  \
     " ELSE (SELECT name FROM nvts WHERE oid = overrides.nvt)"              \
     " END)",                                                               \
     "name",                                                                \
     KEYWORD_TYPE_STRING                                                    \
   },                                                                       \
   { "CAST ('' AS TEXT)", NULL, KEYWORD_TYPE_STRING },                      \
   { "overrides.creation_time", NULL, KEYWORD_TYPE_INTEGER },               \
   { "overrides.modification_time", NULL, KEYWORD_TYPE_INTEGER },           \
   { "overrides.creation_time", "created", KEYWORD_TYPE_INTEGER },          \
   { "overrides.modification_time", "modified", KEYWORD_TYPE_INTEGER },     \
   {                                                                        \
     "(SELECT name FROM users WHERE users.id = overrides.owner)",           \
     "_owner",                                                              \
     KEYWORD_TYPE_STRING                                                    \
   },                                                                       \
   { "owner", NULL, KEYWORD_TYPE_INTEGER },                                 \
   /* Columns specific to overrides. */                                     \
   { "overrides.nvt", "oid", KEYWORD_TYPE_STRING },                         \
   { "overrides.text", "text", KEYWORD_TYPE_STRING },                       \
   { "overrides.hosts", "hosts", KEYWORD_TYPE_STRING },                     \
   { "overrides.port", "port", KEYWORD_TYPE_STRING },                       \
   { "severity_to_level (overrides.severity, 1)",                           \
     "threat",                                                              \
     KEYWORD_TYPE_STRING },                                                 \
   { "severity_to_level (overrides.new_severity, 0)",                       \
     "new_threat",                                                          \
     KEYWORD_TYPE_STRING },                                                 \
   { "overrides.task", NULL, KEYWORD_TYPE_STRING },                         \
   { "overrides.result", "result", KEYWORD_TYPE_INTEGER },                  \
   { "overrides.end_time", NULL, KEYWORD_TYPE_INTEGER },                    \
   {                                                                        \
     "CAST (((overrides.end_time = 0) OR (overrides.end_time >= m_now ()))" \
     "      AS INTEGER)",                                                   \
     "active",                                                              \
     KEYWORD_TYPE_INTEGER                                                   \
   },                                                                       \
   {                                                                        \
     "(CASE"                                                                \
     " WHEN overrides.nvt LIKE 'CVE-%%'"                                    \
     " THEN overrides.nvt"                                                  \
     " ELSE (SELECT name FROM nvts WHERE oid = overrides.nvt)"              \
     " END)",                                                               \
     "nvt",                                                                 \
     KEYWORD_TYPE_STRING                                                    \
   },                                                                       \
   { "overrides.nvt", "nvt_id", KEYWORD_TYPE_STRING },                      \
   { "(SELECT uuid FROM tasks WHERE id = overrides.task)",                  \
     "task_id",                                                             \
     KEYWORD_TYPE_STRING },                                                 \
   { "(SELECT name FROM tasks WHERE id = overrides.task)",                  \
     "task_name",                                                           \
     KEYWORD_TYPE_STRING },                                                 \
   { "overrides.severity", "severity", KEYWORD_TYPE_DOUBLE },               \
   { "overrides.new_severity", "new_severity", KEYWORD_TYPE_DOUBLE },       \
   {                                                                        \
     "(SELECT name FROM users WHERE users.id = overrides.owner)",           \
     "_owner",                                                              \
     KEYWORD_TYPE_STRING                                                    \
   },                                                                       \
   { "days_from_now (overrides.end_time)",                                  \
     "active_days",                                                         \
     KEYWORD_TYPE_INTEGER },                                                \
   { NULL, NULL, KEYWORD_TYPE_UNKNOWN }                                     \
 }

/**
 * @brief Override iterator columns for trash case.
 */
#define OVERRIDE_ITERATOR_TRASH_COLUMNS                                     \
 {                                                                          \
   { "overrides_trash.id", "id", KEYWORD_TYPE_INTEGER },                    \
   { "overrides_trash.uuid", "uuid", KEYWORD_TYPE_STRING },                 \
   { "CAST ('' AS TEXT)", NULL, KEYWORD_TYPE_STRING },                      \
   { "CAST ('' AS TEXT)", NULL, KEYWORD_TYPE_STRING },                      \
   { "overrides_trash.creation_time",                                       \
     NULL,                                                                  \
     KEYWORD_TYPE_INTEGER },                                                \
   { "overrides_trash.modification_time",                                   \
     NULL,                                                                  \
     KEYWORD_TYPE_INTEGER },                                                \
   { "overrides_trash.creation_time",                                       \
     "created",                                                             \
     KEYWORD_TYPE_INTEGER },                                                \
   { "overrides_trash.modification_time",                                   \
     "modified",                                                            \
     KEYWORD_TYPE_INTEGER },                                                \
   {                                                                        \
     "(SELECT name FROM users WHERE users.id = overrides_trash.owner)",     \
     "_owner",                                                              \
     KEYWORD_TYPE_STRING                                                    \
   },                                                                       \
   { "owner", NULL, KEYWORD_TYPE_STRING },                                  \
   /* Columns specific to overrides_trash. */                               \
   { "overrides_trash.nvt", "oid", KEYWORD_TYPE_STRING },                   \
   { "overrides_trash.text", "text", KEYWORD_TYPE_STRING },                 \
   { "overrides_trash.hosts", "hosts", KEYWORD_TYPE_STRING },               \
   { "overrides_trash.port", "port", KEYWORD_TYPE_STRING },                 \
   { "severity_to_level (overrides_trash.severity, 1)",                     \
     "threat",                                                              \
     KEYWORD_TYPE_STRING },                                                 \
   { "severity_to_level (overrides_trash.new_severity, 0)",                 \
     "new_threat",                                                          \
     KEYWORD_TYPE_STRING },                                                 \
   { "overrides_trash.task", NULL, KEYWORD_TYPE_INTEGER },                  \
   { "overrides_trash.result", "result", KEYWORD_TYPE_INTEGER },            \
   { "overrides_trash.end_time", NULL, KEYWORD_TYPE_INTEGER },              \
   {                                                                        \
     "CAST (((overrides_trash.end_time = 0)"                                \
     "       OR (overrides_trash.end_time >= m_now ())) AS INTEGER)",       \
     "active",                                                              \
     KEYWORD_TYPE_INTEGER                                                   \
   },                                                                       \
   {                                                                        \
     "(CASE"                                                                \
     " WHEN overrides_trash.nvt LIKE 'CVE-%%'"                              \
     " THEN overrides_trash.nvt"                                            \
     " ELSE (SELECT name FROM nvts WHERE oid = overrides_trash.nvt)"        \
     " END)",                                                               \
     "nvt",                                                                 \
     KEYWORD_TYPE_STRING                                                    \
   },                                                                       \
   { "overrides_trash.nvt", "nvt_id", KEYWORD_TYPE_STRING },                \
   {                                                                        \
     "(SELECT uuid FROM tasks WHERE id = overrides_trash.task)",            \
     "task_id",                                                             \
     KEYWORD_TYPE_STRING                                                    \
   },                                                                       \
   {                                                                        \
     "(SELECT name FROM tasks WHERE id = overrides_trash.task)",            \
     "task_name",                                                           \
     KEYWORD_TYPE_STRING                                                    \
   },                                                                       \
   { "overrides_trash.severity", NULL, KEYWORD_TYPE_DOUBLE },               \
   { "overrides_trash.new_severity", NULL, KEYWORD_TYPE_DOUBLE },           \
   { NULL, NULL, KEYWORD_TYPE_UNKNOWN }                                     \
 }

#endif // not _GVMD_MANAGE_SQL_OVERRIDES_H
