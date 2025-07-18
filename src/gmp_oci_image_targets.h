/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file gmp_oci_image_targets.h
 * @brief GVM GMP layer: OCI Image Target headers.
 *
 * Headers for GMP handlers for OCI image target commands.
 */
#ifndef _GVMD_GMP_OCI_IMAGE_TARGETS_H
#define _GVMD_GMP_OCI_IMAGE_TARGETS_H

#include "gmp_base.h"

/* GET_OCI_IMAGE_TARGETS. */

void
get_oci_image_targets_start (const gchar **,
                            const gchar **);

void
get_oci_image_targets_run (gmp_parser_t *gmp_parser, GError **error);

/* CREATE_OCI_IMAGE_TARGET. */

void
create_oci_image_target_start (gmp_parser_t *,
                               const gchar **,
                               const gchar **);

                               void
create_oci_image_target_element_start (gmp_parser_t *,
                                       const gchar *,
                                       const gchar **,
                                       const gchar **);

void
create_oci_image_target_element_text (const gchar *,
                                      gsize);

int
create_oci_image_target_element_end (gmp_parser_t *,
                                     GError **,
                                     const gchar *);

void
create_oci_image_target_run (gmp_parser_t *, GError **);

/* MODIFY_OCI_IMAGE_TARGET. */

void
modify_oci_image_target_start (gmp_parser_t *,
                               const gchar **,
                               const gchar **);
    
void modify_oci_image_target_element_start (gmp_parser_t *,
                                            const gchar *,
                                            const gchar **,
                                            const gchar **);
void
modify_oci_image_target_element_text (const gchar *,
                                      gsize);

int
modify_oci_image_target_element_end (gmp_parser_t *,
                                     GError **,
                                     const gchar *);

void
modify_oci_image_target_run (gmp_parser_t *, GError **);

#endif //_GVMD_GMP_OCI_IMAGE_TARGETS_H
