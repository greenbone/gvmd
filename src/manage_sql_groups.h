/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GVMD_MANAGE_SQL_GROUPS_H
#define _GVMD_MANAGE_SQL_GROUPS_H

/**
 * @brief Filter columns for group iterator.
 */
#define GROUP_ITERATOR_FILTER_COLUMNS                                         \
 { GET_ITERATOR_FILTER_COLUMNS, NULL }

/**
 * @brief Group iterator columns.
 */
#define GROUP_ITERATOR_COLUMNS                                                \
 {                                                                            \
   GET_ITERATOR_COLUMNS (groups),                                             \
   { NULL, NULL, KEYWORD_TYPE_UNKNOWN }                                       \
 }

/**
 * @brief Group iterator columns for trash case.
 */
#define GROUP_ITERATOR_TRASH_COLUMNS                                          \
 {                                                                            \
   GET_ITERATOR_COLUMNS (groups_trash),                                       \
   { NULL, NULL, KEYWORD_TYPE_UNKNOWN }                                       \
 }

gboolean
find_group_with_permission (const char *, group_t *,
                            const char *);

#endif //_GVMD_MANAGE_SQL_GROUPS_H
