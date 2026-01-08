/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GVMD_MANAGE_USERS_H
#define _GVMD_MANAGE_USERS_H

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

#endif /* not _GVMD_MANAGE_USERS_H */
