/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GVMD_MANAGE_ROLES_H
#define _GVMD_MANAGE_ROLES_H

#include "manage_get.h"
#include "manage_resources_types.h"
#include "sql.h" // Sadly, for db_conn_info_t

int
manage_get_roles (GSList *, const db_conn_info_t *, int);

int
trash_role_in_use (role_t);

int
role_in_use (role_t);

int
copy_role (const char *, const char *, const char *, role_t *);

int
create_role (const char *, const char *, const char *, role_t *);

int
delete_role (const char *, int);

int
init_role_iterator (iterator_t *, get_data_t *);

int
role_count (const get_data_t *);

int
modify_role (const char *, const char *, const char *, const char *);

char*
role_uuid (role_t);

gchar *
role_users (role_t);

int
trash_role_writable (role_t);

int
role_writable (role_t);

#endif /* not _GVMD_MANAGE_ROLES_H */
