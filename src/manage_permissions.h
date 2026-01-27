/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GVMD_MANAGE_PERMISSIONS_H
#define _GVMD_MANAGE_PERMISSIONS_H

#include "manage_resources.h"

int
permission_is_admin (const char *);

char *
permission_uuid (permission_t);

#endif /* not _GVMD_MANAGE_PERMISSIONS_H */
