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

void
permissions_set_locations (const char *, resource_t, resource_t, int);

#endif //_GVMD_MANAGE_SQL_PERMISSIONS_H
