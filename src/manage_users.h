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

#endif /* not _GVMD_MANAGE_USERS_H */
