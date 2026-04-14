/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GVMD_MANAGE_OVERRIDES_H
#define _GVMD_MANAGE_OVERRIDES_H

#include "manage_resources_types.h"
#include "manage_get.h"

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

int
override_count (const get_data_t *, nvt_t, result_t, task_t);

int
init_override_iterator (iterator_t *, const get_data_t *, nvt_t, result_t,
                        task_t);

int
init_override_iterator_all (iterator_t *, get_data_t *);

const char *
override_iterator_nvt_oid (iterator_t *);

time_t
override_iterator_creation_time (iterator_t *);

time_t
override_iterator_modification_time (iterator_t *);

const char *
override_iterator_text (iterator_t *);

const char *
override_iterator_hosts (iterator_t *);

const char *
override_iterator_port (iterator_t *);

const char *
override_iterator_threat (iterator_t *);

const char *
override_iterator_new_threat (iterator_t *);

task_t
override_iterator_task (iterator_t *);

result_t
override_iterator_result (iterator_t *);

time_t
override_iterator_end_time (iterator_t *);

int
override_iterator_active (iterator_t *);

const char *
override_iterator_nvt_name (iterator_t *);

const char *
override_iterator_nvt_type (iterator_t *);

const char *
override_iterator_severity (iterator_t *);

const char *
override_iterator_new_severity (iterator_t *);

#endif /* not _GVMD_MANAGE_OVERRIDES_H */
