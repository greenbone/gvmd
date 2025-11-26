/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM SQL layer: Agent installer headers.
 *
 * Headers for SQL handlers of agent installers.
 */

#ifndef _GVMD_MANAGE_SQL_AGENT_INSTALLERS_H
#define _GVMD_MANAGE_SQL_AGENT_INSTALLERS_H

#include "manage_sql.h"
#include "manage_agent_installers.h"

/**
 * @brief Filter columns for Agent Installer iterator.
 */
#define AGENT_INSTALLER_ITERATOR_FILTER_COLUMNS                             \
 { GET_ITERATOR_FILTER_COLUMNS, "description", "content_type",              \
   "file_extension", "version",                              \
   NULL }

/**
 * @brief Agent Installer iterator columns.
 */
#define AGENT_INSTALLER_ITERATOR_COLUMNS                                    \
 {                                                                          \
   { "id", NULL, KEYWORD_TYPE_INTEGER },                                    \
   { "uuid", NULL, KEYWORD_TYPE_STRING },                                   \
   { "name", NULL, KEYWORD_TYPE_STRING },                                   \
   { "comment", NULL, KEYWORD_TYPE_STRING },                                \
   { "creation_time", NULL, KEYWORD_TYPE_INTEGER },                         \
   { "modification_time", NULL, KEYWORD_TYPE_INTEGER },                     \
   { "creation_time", "created", KEYWORD_TYPE_INTEGER },                    \
   { "modification_time", "modified", KEYWORD_TYPE_INTEGER },               \
   {                                                                        \
     "(SELECT name FROM users WHERE users.id = agent_installers.owner)",    \
     "_owner",                                                              \
     KEYWORD_TYPE_STRING                                                    \
   },                                                                       \
   { "owner", NULL, KEYWORD_TYPE_INTEGER },                                 \
   { "description", NULL, KEYWORD_TYPE_STRING },                            \
   { "content_type", NULL, KEYWORD_TYPE_STRING },                           \
   { "file_extension", NULL, KEYWORD_TYPE_STRING },                         \
   { "installer_path", NULL, KEYWORD_TYPE_STRING },                         \
   { "version", NULL, KEYWORD_TYPE_STRING },                                \
   { "checksum", NULL, KEYWORD_TYPE_STRING },                               \
   { NULL, NULL, KEYWORD_TYPE_UNKNOWN }                                     \
 }


#endif // not _GVMD_MANAGE_SQL_AGENT_INSTALLERS_H
