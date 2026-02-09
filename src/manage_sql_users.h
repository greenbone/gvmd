/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GVMD_MANAGE_SQL_USERS_H
#define _GVMD_MANAGE_SQL_USERS_H

#include "manage_users.h"

#include <gvm/util/authutils.h>

/**
 * @brief User columns for user iterator.
 */
#define USER_ITERATOR_FILTER_COLUMNS                                  \
 { GET_ITERATOR_FILTER_COLUMNS, "method", "roles", "groups", "hosts", \
   NULL }

/**
 * @brief User iterator columns.
 */
#define USER_ITERATOR_COLUMNS                                              \
 {                                                                         \
   GET_ITERATOR_COLUMNS (users),                                           \
   { "method", NULL, KEYWORD_TYPE_STRING },                                \
   { "hosts", NULL, KEYWORD_TYPE_STRING },                                 \
   { "hosts_allow", NULL, KEYWORD_TYPE_INTEGER },                          \
   {                                                                       \
     "coalesce ((SELECT group_concat (name, ', ')"                         \
     "           FROM (SELECT DISTINCT name, order_role (name)"            \
     "                 FROM roles, role_users"                             \
     "                 WHERE role_users.role = roles.id"                   \
     "                 AND \"user\" = users.id"                            \
     "                 ORDER BY order_role (roles.name) ASC)"              \
     "                 AS user_iterator_sub),"                             \
     "           '')",                                                     \
     "roles",                                                              \
     KEYWORD_TYPE_STRING                                                   \
   },                                                                      \
   {                                                                       \
     "coalesce ((SELECT group_concat (name, ', ')"                         \
     "           FROM (SELECT DISTINCT name FROM groups, group_users"      \
     "                 WHERE group_users.\"group\" = groups.id"            \
     "                 AND \"user\" = users.id"                            \
     "                 ORDER BY groups.name ASC)"                          \
     "                AS user_iterator_sub),"                              \
     "           '')",                                                     \
     "groups",                                                             \
     KEYWORD_TYPE_STRING                                                   \
   },                                                                      \
   { NULL, NULL, KEYWORD_TYPE_UNKNOWN }                                    \
 }

/**
 * @brief User iterator columns for trash case.
 */
#define USER_ITERATOR_TRASH_COLUMNS                                        \
 {                                                                         \
   GET_ITERATOR_COLUMNS (users_trash),                                     \
   { "method", NULL, KEYWORD_TYPE_STRING },                                \
   { "hosts", NULL, KEYWORD_TYPE_STRING },                                 \
   { "hosts_allow", NULL, KEYWORD_TYPE_INTEGER },                          \
   { NULL, NULL, KEYWORD_TYPE_UNKNOWN }                                    \
 }

gboolean
find_user_with_permission (const char *, user_t *, const char *);

gboolean
find_user_by_name_with_permission (const char *, user_t *, const char *);

gboolean
find_user_by_name (const char *, user_t *);

int
user_exists (const gchar *);

int
user_exists_method (const gchar *, auth_method_t);

gchar *
user_uuid_any_method (const gchar *);

int
add_users (const gchar *, resource_t, const char *);

int
set_password (const gchar *, const gchar *, const gchar *, gchar **);

GArray*
all_users_array ();

/* Defined in manage_users.c, but internal to libmanage. */

int
validate_username (const gchar *);

#endif // not _GVMD_MANAGE_SQL_USERS_H
