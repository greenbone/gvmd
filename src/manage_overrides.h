/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GVMD_MANAGE_OVERRIDES_H
#define _GVMD_MANAGE_OVERRIDES_H

#include "manage_resources_types.h"

int
create_override (const char *, const char *, const char *, const char *,
                 const char *, const char *, const char *, const char *,
                 const char *, task_t, result_t, override_t*);

int
copy_override (const char *, override_t *);

int
delete_override (const char *, int);

int
override_uuid (override_t, char **);

int
modify_override (const gchar *, const char *, const char *, const char *,
                 const char *, const char *, const char *, const char *,
                 const char *, const char *, const gchar *, const gchar *);

gboolean
find_override_with_permission (const char *, override_t *, const char *);

#endif /* not _GVMD_MANAGE_OVERRIDES_H */
