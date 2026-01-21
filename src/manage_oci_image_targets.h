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

typedef enum {
  CREATE_OCI_IMAGE_TARGET_OK = 0,
  CREATE_OCI_IMAGE_TARGET_EXISTS_ALREADY = 1,
  CREATE_OCI_IMAGE_TARGET_INVALID_IMAGE_URLS = 2,
  CREATE_OCI_IMAGE_TARGET_INVALID_CREDENTIAL = 3,
  CREATE_OCI_IMAGE_TARGET_CREDENTIAL_NOT_FOUND = 4,
  CREATE_OCI_IMAGE_TARGET_INVALID_CREDENTIAL_TYPE = 5,
  CREATE_OCI_IMAGE_TARGET_INVALID_EXCLUDE_IMAGES = 6,
  CREATE_OCI_IMAGE_TARGET_PERMISSION_DENIED = 99,
  CREATE_OCI_IMAGE_TARGET_INTERNAL_ERROR = -1
} create_oci_image_target_return_t;

typedef enum {
  MODIFY_OCI_IMAGE_TARGET_OK = 0,
  MODIFY_OCI_IMAGE_TARGET_NOT_FOUND = 1,
  MODIFY_OCI_IMAGE_TARGET_INVALID_NAME = 2,
  MODIFY_OCI_IMAGE_TARGET_EXISTS_ALREADY = 3,
  MODIFY_OCI_IMAGE_TARGET_IN_USE = 4,
  MODIFY_OCI_IMAGE_TARGET_CREDENTIAL_NOT_FOUND = 5,
  MODIFY_OCI_IMAGE_TARGET_INVALID_CREDENTIAL_TYPE = 6,
  MODIFY_OCI_IMAGE_TARGET_INVALID_IMAGE_URLS = 7,
  MODIFY_OCI_IMAGE_TARGET_INVALID_EXCLUDE_IMAGES = 8,
  MODIFY_OCI_IMAGE_TARGET_PERMISSION_DENIED = 99,
  MODIFY_OCI_IMAGE_TARGET_INTERNAL_ERROR = -1
} modify_oci_image_target_return_t;

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

create_oci_image_target_return_t
create_oci_image_target (const char*, const char*, const char*,
                         const char*, const char*, oci_image_target_t*,
                         gchar**);

int
copy_oci_image_target (const char*, const char*,
                       const char*, oci_image_target_t*);

modify_oci_image_target_return_t
modify_oci_image_target (const char*, const char*, const char*,
                         const char*, const char*, const char*, gchar**);

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
oci_image_target_iterator_exclude_images (iterator_t*);

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

gchar*
clean_images (const char *);

#endif /* _GVMD_MANAGE_OCI_IMAGE_TARGETS_H */

#endif /* ENABLE_CONTAINER_SCANNING */