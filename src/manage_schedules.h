/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GVMD_MANAGE_SCHEDULES_H
#define _GVMD_MANAGE_SCHEDULES_H

#include "manage_resources_types.h"

int
create_schedule (const char *, const char*, const char *,
                 const char *, schedule_t *, gchar **);

int
copy_schedule (const char *, const char *, const char *, schedule_t *);

#endif /* not _GVMD_MANAGE_SCHEDULES_H */
