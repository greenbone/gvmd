/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GVMD_MANAGE_SQL_ROLES_H
#define _GVMD_MANAGE_SQL_ROLES_H

/**
 * @brief Filter columns for role iterator.
 */
#define ROLE_ITERATOR_FILTER_COLUMNS                                         \
 { GET_ITERATOR_FILTER_COLUMNS, NULL }

/**
 * @brief Role iterator columns.
 */
#define ROLE_ITERATOR_COLUMNS                                                \
 {                                                                           \
   GET_ITERATOR_COLUMNS (roles),                                             \
   { NULL, NULL, KEYWORD_TYPE_UNKNOWN }                                      \
 }

/**
 * @brief Role iterator columns for trash case.
 */
#define ROLE_ITERATOR_TRASH_COLUMNS                                          \
 {                                                                           \
   GET_ITERATOR_COLUMNS (roles_trash),                                       \
   { NULL, NULL, KEYWORD_TYPE_UNKNOWN }                                      \
 }

int
role_is_predefined (role_t);

int
role_is_predefined_id (const char *);

gboolean
find_role_with_permission (const char *, role_t *, const char *);

gboolean
find_role_by_name (const char *, role_t *);

#endif //_GVMD_MANAGE_SQL_ROLES_H
