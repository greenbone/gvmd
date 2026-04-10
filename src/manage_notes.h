/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GVMD_MANAGE_NOTES_H
#define _GVMD_MANAGE_NOTES_H

#include "manage_resources_types.h"
#include "manage_get.h"

int
create_note (const char *, const char *, const char *, const char *,
             const char *, const char *, const char *, task_t, result_t,
             note_t *);

int
copy_note (const char *, note_t *);

int
delete_note (const char *, int);

int
note_uuid (note_t, char **);

int
modify_note (const gchar *, const char *, const char *, const char *,
             const char *, const char *, const char *, const char *,
             const gchar *, const gchar *);

gboolean
find_note_with_permission (const char*, note_t*, const char *);

int
note_count (const get_data_t *, nvt_t, result_t, task_t);

int
init_note_iterator (iterator_t*, const get_data_t*, nvt_t, result_t, task_t);

int
init_note_iterator_all (iterator_t* iterator, get_data_t *get);

const char*
note_iterator_nvt_oid (iterator_t*);

time_t
note_iterator_creation_time (iterator_t*);

time_t
note_iterator_modification_time (iterator_t*);

const char*
note_iterator_text (iterator_t*);

const char*
note_iterator_hosts (iterator_t*);

const char*
note_iterator_port (iterator_t*);

const char*
note_iterator_threat (iterator_t*);

task_t
note_iterator_task (iterator_t*);

result_t
note_iterator_result (iterator_t*);

time_t
note_iterator_end_time (iterator_t*);

int
note_iterator_active (iterator_t*);

const char*
note_iterator_nvt_name (iterator_t *);

const char *
note_iterator_nvt_type (iterator_t *);

const char*
note_iterator_severity (iterator_t *);

#endif /* not _GVMD_MANAGE_NOTES_H */
