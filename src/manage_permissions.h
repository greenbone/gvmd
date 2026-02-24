/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GVMD_MANAGE_PERMISSIONS_H
#define _GVMD_MANAGE_PERMISSIONS_H

#include "manage_resources_types.h"
#include "gmp_get.h"

int
permission_is_admin (const char *);

char *
permission_uuid (permission_t);

int
permission_count (const get_data_t *);

int
init_permission_iterator (iterator_t*, get_data_t *);

const char*
permission_iterator_resource_type (iterator_t*);

const char*
permission_iterator_resource_uuid (iterator_t*);

const char*
permission_iterator_resource_name (iterator_t*);

int
permission_iterator_resource_in_trash (iterator_t*);

int
permission_iterator_resource_orphan (iterator_t*);

int
permission_iterator_resource_readable (iterator_t*);

const char*
permission_iterator_subject_type (iterator_t*);

const char*
permission_iterator_subject_uuid (iterator_t*);

const char*
permission_iterator_subject_name (iterator_t*);

int
permission_iterator_subject_in_trash (iterator_t*);

int
permission_iterator_subject_readable (iterator_t*);

int
create_permission (const char *, const char *, const char *, const char *,
                   const char *, const char *, permission_t *);

int
copy_permission (const char*, const char *, permission_t *);

int
delete_permission (const char *, int);

int
modify_permission (const char *, const char *, const char *, const char *,
                   const char *, const char *, const char *);

int
permission_in_use (permission_t);

int
trash_permission_in_use (permission_t);

int
permission_writable (permission_t);

int
trash_permission_writable (permission_t);

#endif /* not _GVMD_MANAGE_PERMISSIONS_H */
