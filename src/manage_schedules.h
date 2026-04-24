/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GVMD_MANAGE_SCHEDULES_H
#define _GVMD_MANAGE_SCHEDULES_H

#include "manage_get.h"
#include "manage_resources_types.h"

int
create_schedule (const char *, const char*, const char *,
                 const char *, schedule_t *, gchar **);

int
copy_schedule (const char *, const char *, const char *, schedule_t *);

int
delete_schedule (const char *, int);

int
trash_schedule_in_use (schedule_t);

int
schedule_in_use (schedule_t);

int
trash_schedule_writable (schedule_t);

int
trash_schedule_readable (schedule_t);

int
schedule_writable (schedule_t);

char *
schedule_uuid (schedule_t);

char *
trash_schedule_uuid (schedule_t);

char *
schedule_name (schedule_t);

char *
trash_schedule_name (schedule_t);

int
schedule_duration (schedule_t);

int
schedule_period (schedule_t);

int
schedule_info (schedule_t, int, gchar **, gchar **);

gboolean
find_schedule_with_permission (const char *, schedule_t *, const char *);

int
init_schedule_iterator (iterator_t *, get_data_t *);

const char*
schedule_iterator_timezone (iterator_t *);

const char*
schedule_iterator_icalendar (iterator_t *);

int
schedule_count (const get_data_t *);

void
init_schedule_task_iterator (iterator_t *, schedule_t);

const char*
schedule_task_iterator_uuid (iterator_t *);

const char*
schedule_task_iterator_name (iterator_t *);

int
schedule_task_iterator_readable (iterator_t *);

#endif /* not _GVMD_MANAGE_SCHEDULES_H */
