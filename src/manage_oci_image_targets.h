/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM manage layer headers: OCI Image Targets.
 *
 * General management headers of OCI Image Targets.
 */

#if ENABLE_CONTAINER_SCANNING

#ifndef _GVMD_MANAGE_OCI_IMAGE_TARGETS_H
#define _GVMD_MANAGE_OCI_IMAGE_TARGETS_H

#include "iterator.h"
#include "manage_get.h"

typedef resource_t oci_image_target_t;

gboolean
find_oci_image_target_with_permission (const char*,
                                       oci_image_target_t*,
                                       const char *);

int
oci_image_target_writable (oci_image_target_t);

int
trash_oci_image_target_writable (oci_image_target_t);

int
validate_oci_image_references (const char *, gchar **);

int
valid_oci_url (const gchar *);

int
create_oci_image_target (const char*, const char*, const char*,
                         const char*, oci_image_target_t*, gchar**);

int
copy_oci_image_target (const char*, const char*, 
                       const char*, oci_image_target_t*);

int
modify_oci_image_target (const char*, const char*, const char*,
                         const char*, const char*, gchar**);

int
delete_oci_image_target (const char*, int);

int
restore_oci_image_target (const char *);

int
oci_image_target_count (const get_data_t *);

int
init_oci_image_target_iterator (iterator_t* , get_data_t *);

const char*
oci_image_target_task_iterator_uuid (iterator_t*);

const char*
oci_image_target_task_iterator_name (iterator_t*);

const char*
oci_image_target_iterator_image_refs (iterator_t*);

const char*
oci_image_target_iterator_credential_name (iterator_t*);

credential_t
oci_image_target_iterator_credential (iterator_t*);

int
oci_image_target_iterator_credential_trash (iterator_t *);

char*
oci_image_target_uuid (oci_image_target_t);

char*
trash_oci_image_target_uuid (oci_image_target_t);

char*
oci_image_target_name (oci_image_target_t);

char*
trash_oci_image_target_name (oci_image_target_t);

char*
oci_image_target_comment (oci_image_target_t);

char*
trash_oci_image_target_comment (oci_image_target_t);

int
trash_oci_image_target_readable (oci_image_target_t);

int
oci_image_target_in_use (oci_image_target_t);

int
trash_oci_image_target_in_use (oci_image_target_t);

void
init_oci_image_target_task_iterator (iterator_t*, oci_image_target_t);

int
oci_image_target_task_iterator_readable (iterator_t*);

#endif /* _GVMD_MANAGE_OCI_IMAGE_TARGETS_H */

#endif /* ENABLE_CONTAINER_SCANNING */