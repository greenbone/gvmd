/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GVMD_MANAGE_NOTES_H
#define _GVMD_MANAGE_NOTES_H

#include "manage_resources_types.h"

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

#endif /* not _GVMD_MANAGE_NOTES_H */
