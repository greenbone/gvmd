/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GVMD_MANAGE_TARGETS_H
#define _GVMD_MANAGE_TARGETS_H

#include "manage_resources.h"

int
manage_max_hosts ();

void
manage_set_max_hosts (int);

gboolean
find_target_with_permission (const char *, target_t *, const char *);

char*
target_uuid (target_t);

char*
trash_target_uuid (target_t);

char*
target_name (target_t);

char*
trash_target_name (target_t);

char*
target_hosts (target_t);

char*
target_exclude_hosts (target_t);

char*
target_reverse_lookup_only (target_t);

char*
target_reverse_lookup_unify (target_t);

char*
target_ssh_port (target_t);

int
copy_target (const char *, const char *, const char *, target_t *);

int
delete_target (const char *, int);

int
create_target (const char *, const char *, const char *, const char *,
               const char *, const char *, const char *, credential_t,
               credential_t, const char *, credential_t, credential_t,
               credential_t, credential_t, const char *, const char *,
               GPtrArray *, const char *, const char *, target_t*);

int
modify_target (const char *, const char *, const char *, const char *,
               const char *, const char *, const char *, const char *,
               const char *, const char *, const char *, const char *,
               const char *, const char *, const char *, GPtrArray *,
               const char *, const char *);

#endif /* not _GVMD_MANAGE_TARGETS_H */
