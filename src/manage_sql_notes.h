/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GVMD_MANAGE_SQL_NOTES_H
#define _GVMD_MANAGE_SQL_NOTES_H

#include "manage_notes.h"

/**
 * @brief Filter columns for note iterator.
 */
#define NOTE_ITERATOR_FILTER_COLUMNS                                          \
 { ANON_GET_ITERATOR_FILTER_COLUMNS, "name", "nvt", "text", "nvt_id",         \
   "task_name", "task_id", "hosts", "port", "active", "result", "severity",   \
   "end_time", "active_days", NULL }

/**
 * @brief Note iterator columns.
 */
#define NOTE_ITERATOR_COLUMNS                                              \
 {                                                                         \
   { "notes.id", "id", KEYWORD_TYPE_INTEGER },                             \
   { "notes.uuid", "uuid", KEYWORD_TYPE_STRING },                          \
   {                                                                       \
     "(CASE"                                                               \
     " WHEN notes.nvt LIKE 'CVE-%%'"                                       \
     " THEN notes.nvt"                                                     \
     " ELSE (SELECT name FROM nvts WHERE oid = notes.nvt)"                 \
     " END)",                                                              \
     "name",                                                               \
     KEYWORD_TYPE_STRING                                                   \
   },                                                                      \
   { "CAST ('' AS TEXT)", NULL, KEYWORD_TYPE_STRING },                     \
   { "notes.creation_time", NULL, KEYWORD_TYPE_INTEGER },                  \
   { "notes.modification_time", NULL, KEYWORD_TYPE_INTEGER },              \
   { "notes.creation_time", "created", KEYWORD_TYPE_INTEGER },             \
   { "notes.modification_time", "modified", KEYWORD_TYPE_INTEGER },        \
   { "(SELECT name FROM users WHERE users.id = notes.owner)",              \
     "_owner",                                                             \
     KEYWORD_TYPE_STRING },                                                \
   { "owner", NULL, KEYWORD_TYPE_INTEGER },                                \
   /* Columns specific to notes. */                                        \
   { "notes.nvt", "oid", KEYWORD_TYPE_STRING },                            \
   { "notes.text", "text", KEYWORD_TYPE_STRING },                          \
   { "notes.hosts", "hosts", KEYWORD_TYPE_STRING },                        \
   { "notes.port", "port", KEYWORD_TYPE_STRING },                          \
   { "notes.task", NULL, KEYWORD_TYPE_INTEGER },                           \
   { "notes.result", "result", KEYWORD_TYPE_INTEGER },                     \
   { "notes.end_time", "end_time", KEYWORD_TYPE_INTEGER },                 \
   { "CAST (((notes.end_time = 0) OR (notes.end_time >= m_now ()))"        \
     "      AS INTEGER)",                                                  \
     "active",                                                             \
     KEYWORD_TYPE_INTEGER },                                               \
   {                                                                       \
     "(CASE"                                                               \
     " WHEN notes.nvt LIKE 'CVE-%%'"                                       \
     " THEN notes.nvt"                                                     \
     " ELSE (SELECT name FROM nvts WHERE oid = notes.nvt)"                 \
     " END)",                                                              \
     "nvt",                                                                \
     KEYWORD_TYPE_STRING                                                   \
   },                                                                      \
   { "notes.nvt", "nvt_id", KEYWORD_TYPE_STRING },                         \
   { "(SELECT uuid FROM tasks WHERE id = notes.task)",                     \
     "task_id",                                                            \
     KEYWORD_TYPE_STRING },                                                \
   { "(SELECT name FROM tasks WHERE id = notes.task)",                     \
     "task_name",                                                          \
     KEYWORD_TYPE_STRING },                                                \
   { "notes.severity", "severity", KEYWORD_TYPE_DOUBLE },                  \
   { "(SELECT name FROM users WHERE users.id = notes.owner)",              \
     "_owner",                                                             \
     KEYWORD_TYPE_STRING },                                                \
   { "days_from_now (notes.end_time)",                                     \
     "active_days",                                                        \
     KEYWORD_TYPE_INTEGER },                                               \
   { NULL, NULL, KEYWORD_TYPE_UNKNOWN }                                    \
 }

/**
 * @brief Note iterator columns for trash case.
 */
#define NOTE_ITERATOR_TRASH_COLUMNS                                              \
 {                                                                               \
   { "notes_trash.id", "id", KEYWORD_TYPE_INTEGER },                             \
   { "notes_trash.uuid", "uuid", KEYWORD_TYPE_STRING },                          \
   { "CAST ('' AS TEXT)", NULL, KEYWORD_TYPE_STRING },                           \
   { "CAST ('' AS TEXT)", NULL, KEYWORD_TYPE_STRING },                           \
   { "notes_trash.creation_time", NULL, KEYWORD_TYPE_INTEGER },                  \
   { "notes_trash.modification_time", NULL, KEYWORD_TYPE_INTEGER },              \
   { "notes_trash.creation_time", "created", KEYWORD_TYPE_INTEGER },             \
   { "notes_trash.modification_time", "modified", KEYWORD_TYPE_INTEGER },        \
   { "(SELECT name FROM users WHERE users.id = notes_trash.owner)",              \
     "_owner",                                                                   \
     KEYWORD_TYPE_STRING },                                                      \
   { "owner", NULL, KEYWORD_TYPE_INTEGER },                                      \
   /* Columns specific to notes_trash. */                                        \
   { "notes_trash.nvt", "oid", KEYWORD_TYPE_STRING },                            \
   { "notes_trash.text", "text", KEYWORD_TYPE_STRING  },                         \
   { "notes_trash.hosts", "hosts", KEYWORD_TYPE_STRING },                        \
   { "notes_trash.port", "port", KEYWORD_TYPE_STRING },                          \
   { "severity_to_level (notes_trash.severity, 1)",                              \
     "threat",                                                                   \
     KEYWORD_TYPE_STRING },                                                      \
   { "notes_trash.task", NULL, KEYWORD_TYPE_INTEGER },                           \
   { "notes_trash.result", "result", KEYWORD_TYPE_INTEGER },                     \
   { "notes_trash.end_time", NULL, KEYWORD_TYPE_INTEGER },                       \
   { "CAST (((notes_trash.end_time = 0) OR (notes_trash.end_time >= m_now ()))"  \
     "      AS INTEGER)",                                                        \
     "active",                                                                   \
     KEYWORD_TYPE_INTEGER },                                                     \
   {                                                                             \
     "(CASE"                                                                     \
     " WHEN notes_trash.nvt LIKE 'CVE-%%'"                                       \
     " THEN notes_trash.nvt"                                                     \
     " ELSE (SELECT name FROM nvts WHERE oid = notes_trash.nvt)"                 \
     " END)",                                                                    \
     "nvt",                                                                      \
     KEYWORD_TYPE_STRING                                                         \
   },                                                                            \
   { "notes_trash.nvt", "nvt_id", KEYWORD_TYPE_STRING },                         \
   { "(SELECT uuid FROM tasks WHERE id = notes_trash.task)",                     \
     "task_id",                                                                  \
     KEYWORD_TYPE_STRING },                                                      \
   { "(SELECT name FROM tasks WHERE id = notes_trash.task)",                     \
     "task_name",                                                                \
     KEYWORD_TYPE_STRING },                                                      \
   { "notes_trash.severity", "severity", KEYWORD_TYPE_DOUBLE },                  \
   { NULL, NULL, KEYWORD_TYPE_UNKNOWN }                                          \
 }

#endif // not _GVMD_MANAGE_SQL_NOTES_H
