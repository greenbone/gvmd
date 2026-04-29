/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GVMD_MANAGE_SCHEDULES_SCHEDULAR_H
#define _GVMD_MANAGE_SCHEDULES_SCHEDULAR_H

int
get_schedule_timeout ();

void
set_schedule_timeout (int);

int
manage_schedule (manage_connection_forker_t,
                 gboolean,
                 sigset_t *);

#endif /* not _GVMD_MANAGE_SCHEDULES_SCHEDULAR_H */
