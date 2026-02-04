/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GVMD_MANAGE_SQL_PERMISSIONS_H
#define _GVMD_MANAGE_SQL_PERMISSIONS_H

#include "manage_permissions.h"
#include "manage_resources.h"

/**
 * @brief Predefined role UUID.
 */
#define PERMISSION_UUID_ADMIN_EVERYTHING "b3b56a8c-c2fd-11e2-a135-406186ea4fc5"

/**
 * @brief Predefined role UUID.
 */
#define PERMISSION_UUID_SUPER_ADMIN_EVERYTHING "a9801074-6fe2-11e4-9d81-406186ea4fc5"

/**
 * @brief Filter columns for permission iterator.
 */
#define PERMISSION_ITERATOR_FILTER_COLUMNS                               \
 { GET_ITERATOR_FILTER_COLUMNS, "type", "resource_uuid", "subject_type", \
   "_subject", "_resource", "subject_uuid", "orphan", NULL }

/**
 * @brief Permission iterator columns.
 */
#define PERMISSION_ITERATOR_COLUMNS                                          \
 {                                                                           \
   GET_ITERATOR_COLUMNS (permissions),                                       \
   { "resource_type", "type", KEYWORD_TYPE_STRING },                         \
   { "resource_uuid", NULL, KEYWORD_TYPE_STRING },                           \
   {                                                                         \
     "(CASE"                                                                 \
     " WHEN resource_type = '' OR resource_type IS NULL"                     \
     " THEN ''"                                                              \
     " ELSE resource_name (resource_type, resource_uuid, resource_location)" \
     " END)",                                                                \
     "_resource",                                                            \
     KEYWORD_TYPE_STRING                                                     \
   },                                                                        \
   { "CAST ((resource_location = " G_STRINGIFY (LOCATION_TRASH) ")"          \
     "      AS INTEGER)",                                                    \
     NULL,                                                                   \
     KEYWORD_TYPE_INTEGER },                                                 \
   {                                                                         \
     "(CASE"                                                                 \
     " WHEN resource = -1"                                                   \
     " THEN 1"                                                               \
     " ELSE 0"                                                               \
     " END)",                                                                \
     "orphan",                                                               \
     KEYWORD_TYPE_INTEGER                                                    \
   },                                                                        \
   { "subject_type", NULL, KEYWORD_TYPE_STRING },                            \
   {                                                                         \
     "(CASE"                                                                 \
     " WHEN subject_type = 'user'"                                           \
     " THEN (SELECT uuid FROM users WHERE users.id = subject)"               \
     " WHEN subject_type = 'group'"                                          \
     "      AND subject_location = " G_STRINGIFY (LOCATION_TRASH)            \
     " THEN (SELECT uuid FROM groups_trash"                                  \
     "       WHERE groups_trash.id = subject)"                               \
     " WHEN subject_type = 'group'"                                          \
     " THEN (SELECT uuid FROM groups WHERE groups.id = subject)"             \
     " WHEN subject_location = " G_STRINGIFY (LOCATION_TRASH)                \
     " THEN (SELECT uuid FROM roles_trash"                                   \
     "       WHERE roles_trash.id = subject)"                                \
     " ELSE (SELECT uuid FROM roles WHERE roles.id = subject)"               \
     " END)",                                                                \
     "subject_uuid",                                                         \
     KEYWORD_TYPE_STRING                                                     \
   },                                                                        \
   {                                                                         \
     "(CASE"                                                                 \
     " WHEN subject_type = 'user'"                                           \
     " THEN (SELECT name FROM users WHERE users.id = subject)"               \
     " WHEN subject_type = 'group'"                                          \
     "      AND subject_location = " G_STRINGIFY (LOCATION_TRASH)            \
     " THEN (SELECT name FROM groups_trash"                                  \
     "       WHERE groups_trash.id = subject)"                               \
     " WHEN subject_type = 'group'"                                          \
     " THEN (SELECT name FROM groups WHERE groups.id = subject)"             \
     " WHEN subject_location = " G_STRINGIFY (LOCATION_TRASH)                \
     " THEN (SELECT name FROM roles_trash"                                   \
     "       WHERE roles_trash.id = subject)"                                \
     " ELSE (SELECT name FROM roles WHERE roles.id = subject)"               \
     " END)",                                                                \
     "_subject",                                                             \
     KEYWORD_TYPE_STRING                                                     \
   },                                                                        \
   { "CAST ((subject_location = " G_STRINGIFY (LOCATION_TRASH) ")"           \
     "      AS INTEGER)",                                                    \
     NULL,                                                                   \
     KEYWORD_TYPE_INTEGER },                                                 \
   { NULL, NULL, KEYWORD_TYPE_UNKNOWN }                                      \
 }

/**
 * @brief Permission iterator columns for trash case.
 */
#define PERMISSION_ITERATOR_TRASH_COLUMNS                                    \
 {                                                                           \
   GET_ITERATOR_COLUMNS (permissions_trash),                                 \
   { "resource_type", "type", KEYWORD_TYPE_STRING },                         \
   { "resource_uuid", NULL, KEYWORD_TYPE_STRING },                           \
   {                                                                         \
     "(CASE"                                                                 \
     " WHEN resource_type = '' OR resource_type IS NULL"                     \
     " THEN ''"                                                              \
     " ELSE resource_name (resource_type, resource_uuid, resource_location)" \
     " END)",                                                                \
     "_resource",                                                            \
     KEYWORD_TYPE_STRING                                                     \
   },                                                                        \
   { "CAST ((resource_location = " G_STRINGIFY (LOCATION_TRASH) ")"          \
     "      AS INTEGER)",                                                    \
     NULL,                                                                   \
     KEYWORD_TYPE_INTEGER },                                                 \
   { "resource = -1", NULL, KEYWORD_TYPE_INTEGER },                          \
   { "subject_type", NULL, KEYWORD_TYPE_STRING },                            \
   {                                                                         \
     "(CASE"                                                                 \
     " WHEN subject_type = 'user'"                                           \
     " THEN (SELECT uuid FROM users WHERE users.id = subject)"               \
     " WHEN subject_type = 'group'"                                          \
     "      AND subject_location = " G_STRINGIFY (LOCATION_TRASH)            \
     " THEN (SELECT uuid FROM groups_trash"                                  \
     "       WHERE groups_trash.id = subject)"                               \
     " WHEN subject_type = 'group'"                                          \
     " THEN (SELECT uuid FROM groups WHERE groups.id = subject)"             \
     " WHEN subject_location = " G_STRINGIFY (LOCATION_TRASH)                \
     " THEN (SELECT uuid FROM roles_trash"                                   \
     "       WHERE roles_trash.id = subject)"                                \
     " ELSE (SELECT uuid FROM roles WHERE roles.id = subject)"               \
     " END)",                                                                \
     "subject_uuid",                                                         \
     KEYWORD_TYPE_STRING                                                     \
   },                                                                        \
   {                                                                         \
     "(CASE"                                                                 \
     " WHEN subject_type = 'user'"                                           \
     " THEN (SELECT name FROM users WHERE users.id = subject)"               \
     " WHEN subject_type = 'group'"                                          \
     "      AND subject_location = " G_STRINGIFY (LOCATION_TRASH)            \
     " THEN (SELECT name FROM groups_trash"                                  \
     "       WHERE groups_trash.id = subject)"                               \
     " WHEN subject_type = 'group'"                                          \
     " THEN (SELECT name FROM groups WHERE groups.id = subject)"             \
     " WHEN subject_location = " G_STRINGIFY (LOCATION_TRASH)                \
     " THEN (SELECT name FROM roles_trash"                                   \
     "       WHERE roles_trash.id = subject)"                                \
     " ELSE (SELECT name FROM roles WHERE roles.id = subject)"               \
     " END)",                                                                \
     "_subject",                                                             \
     KEYWORD_TYPE_STRING                                                     \
   },                                                                        \
   { "CAST ((subject_location = " G_STRINGIFY (LOCATION_TRASH) ")"           \
     "      AS INTEGER)",                                                    \
     NULL,                                                                   \
     KEYWORD_TYPE_INTEGER },                                                 \
   { NULL, NULL, KEYWORD_TYPE_UNKNOWN }                                      \
 }

resource_t
permission_resource (permission_t);

int
permission_is_predefined (permission_t);

char *
permission_resource_type (permission_t);

resource_t
permission_subject (permission_t);

char *
permission_subject_type (permission_t);

char *
permission_name (permission_t);

void
permissions_set_locations (const char *, resource_t, resource_t, int);

void
permissions_set_orphans (const char *, resource_t, int);

void
permissions_set_subjects (const char *, resource_t, resource_t, int);

void
add_feed_role_permissions (const char *, const char *, int *, int *);

void
clean_feed_role_permissions (const char *, const char *, int *, int *);

gchar *
subject_where_clause (const char *, resource_t);

#endif //_GVMD_MANAGE_SQL_PERMISSIONS_H
