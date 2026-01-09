/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GVMD_MANAGE_USERS_H
#define _GVMD_MANAGE_USERS_H

#include "manage_get.h"
#include "manage_resources.h"

gchar *
user_name (const char *);

char *
user_uuid (user_t);

int
user_in_use (user_t);

int
trash_user_in_use (user_t);

int
user_writable (user_t);

int
trash_user_writable (user_t);

gchar *
user_hosts (const char *);

int
user_hosts_allow (const char *);

int
init_user_iterator (iterator_t *, get_data_t *);

const char*
user_iterator_role (iterator_t *);

const char*
user_iterator_method (iterator_t *);

const char*
user_iterator_hosts (iterator_t *);

int
user_iterator_hosts_allow (iterator_t *);

void
init_user_group_iterator (iterator_t *, user_t);

const char*
user_group_iterator_uuid (iterator_t *);

const char*
user_group_iterator_name (iterator_t *);

int
user_group_iterator_readable (iterator_t *);

void
init_user_role_iterator (iterator_t *, user_t);

const char*
user_role_iterator_uuid (iterator_t *);

const char*
user_role_iterator_name (iterator_t *);

int
user_role_iterator_readable (iterator_t *);

#endif /* not _GVMD_MANAGE_USERS_H */
