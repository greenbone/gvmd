/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: OCI Image Targets SQL.
 *
 * SQL OCI image targets code for the GVM management layer.
 */

#if ENABLE_CONTAINER_SCANNING

#ifndef _GVMD_MANAGE_SQL_OCI_IMAGE_TARGETS_H
#define _GVMD_MANAGE_SQL_OCI_IMAGE_TARGETS_H

#include "manage_oci_image_targets.h"
#include "manage.h"
#include "manage_sql.h"

char*
oci_image_target_image_references (oci_image_target_t);

char*
oci_image_target_exclude_images (oci_image_target_t);

credential_t
oci_image_target_credential (oci_image_target_t);

#endif /* not _GVMD_MANAGE_SQL_OCI_IMAGE_TARGETS_H */

#endif /* ENABLE_CONTAINER_SCANNING */