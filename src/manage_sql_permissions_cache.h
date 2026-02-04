/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GVMD_MANAGE_SQL_PERMISSIONS_CACHE_H
#define _GVMD_MANAGE_SQL_PERMISSIONS_CACHE_H

#include "manage_resources.h"

void
cache_permissions_for_resource (const char *, resource_t, GArray *);

void
cache_all_permissions_for_users (GArray *);

void
delete_permissions_cache_for_resource (const char *, resource_t);

void
delete_permissions_cache_for_user (user_t);

#endif //_GVMD_MANAGE_SQL_PERMISSIONS_CACHE_H
