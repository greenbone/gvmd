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

int
manage_count_hosts (const char *, const char *);

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

int
init_target_iterator (iterator_t *, get_data_t *);

const char *
target_iterator_hosts (iterator_t *);

const char *
target_iterator_exclude_hosts (iterator_t *);

const char *
target_iterator_reverse_lookup_only (iterator_t *);

const char *
target_iterator_reverse_lookup_unify (iterator_t *);

const char *
target_iterator_comment (iterator_t *);

int
target_iterator_ssh_credential (iterator_t *);

const char *
target_iterator_ssh_port (iterator_t *);

int
target_iterator_smb_credential (iterator_t *);

int
target_iterator_esxi_credential (iterator_t *);

int
target_iterator_snmp_credential (iterator_t *);

int
target_iterator_ssh_elevate_credential (iterator_t *);

int
target_iterator_krb5_credential (iterator_t *);

int
target_iterator_ssh_trash (iterator_t *);

int
target_iterator_smb_trash (iterator_t *);

int
target_iterator_esxi_trash (iterator_t *);

int
target_iterator_snmp_trash (iterator_t *);

int
target_iterator_ssh_elevate_trash (iterator_t *);

int
target_iterator_krb5_trash (iterator_t *);

const char *
target_iterator_allow_simultaneous_ips (iterator_t *);

const char *
target_iterator_port_list_uuid (iterator_t *);

const char *
target_iterator_port_list_name (iterator_t *);

int
target_iterator_port_list_trash (iterator_t *);

int
target_iterator_alive_tests (iterator_t *);

void
init_target_task_iterator (iterator_t *, target_t);

const char *
target_task_iterator_name (iterator_t *);

const char *
target_task_iterator_uuid (iterator_t *);

int
target_task_iterator_readable (iterator_t *);

#endif /* not _GVMD_MANAGE_TARGETS_H */
