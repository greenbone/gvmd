/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GVMD_MANAGE_GROUPS_H
#define _GVMD_MANAGE_GROUPS_H

#include "manage_get.h"
#include "manage_resources.h"

char*
group_uuid (group_t);

gchar *
group_users (group_t);

int
copy_group (const char *, const char *, const char *, group_t *);

int
trash_group_in_use (group_t);

int
group_in_use (group_t);

int
trash_group_writable (group_t);

int
group_writable (group_t);

int
create_group (const char *, const char *, const char *, int, group_t *);

int
delete_group (const char *, int);

int
modify_group (const char *, const char *, const char *, const char *);

int
init_group_iterator (iterator_t *, get_data_t *);

int
group_count (const get_data_t *);

#endif /* not _GVMD_MANAGE_GROUPS_H */
