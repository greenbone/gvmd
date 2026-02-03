/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GVMD_MANAGE_SQL_RESOURCES_H
#define _GVMD_MANAGE_SQL_RESOURCES_H

#include "manage_resources.h"

#include <glib.h>

gboolean
find_resource (const char *, const char *, resource_t *);

gchar *
resource_uuid (const gchar *, resource_t);

gboolean
find_resource_no_acl (const char *, const char *, resource_t *);

gboolean
find_resource_with_permission (const char *, const char *,
                               resource_t *, const char *, int);

gboolean
find_resource_by_name (const char *, const char *, resource_t *);

#endif // not _GVMD_MANAGE_SQL_RESOURCES_H
