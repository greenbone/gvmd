/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GVMD_MANAGE_SQL_GROUPS_H
#define _GVMD_MANAGE_SQL_GROUPS_H

gboolean
find_group_with_permission (const char *, group_t *,
                            const char *);

#endif //_GVMD_MANAGE_SQL_GROUPS_H
