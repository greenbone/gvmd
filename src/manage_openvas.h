/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Greenbone Vulnerability Manager OpenVAS scan handling headers.
 *
 * This contains functions common to setting up OSP and openvasd scans.
 */

#ifndef _GVMD_MANAGE_OPENVAS_H
#define _GVMD_MANAGE_OPENVAS_H

#include <gvm/osp/osp.h>
#include <glib.h>
#include "manage_resources.h"
#if ENABLE_CREDENTIAL_STORES
#include "manage_credential_store_cyberark.h"
#endif

void
add_user_scan_preferences (GHashTable *);

#if ENABLE_CREDENTIAL_STORES

typedef enum {
  TARGET_OSP_INTERNAL_ERROR = -1,
  TARGET_OSP_CREDENTIAL_OK = 0,
  TARGET_OSP_MISSING_CREDENTIAL,
  TARGET_OSP_CREDENTIAL_NOT_FOUND,
  TARGET_OSP_CREDENTIAL_TYPE_MISMATCH,
  TARGET_OSP_FAILED_CS_RETRIEVAL,
} target_osp_credential_return_t;

typedef target_osp_credential_return_t
(*target_osp_credential_getter_t)(target_t, osp_credential_t **);

int
target_osp_add_credentials (osp_target_t *, target_t, task_t, char **);

target_osp_credential_return_t
target_osp_ssh_credential (target_t, osp_credential_t **);

target_osp_credential_return_t
target_osp_smb_credential (target_t, osp_credential_t **);

target_osp_credential_return_t
target_osp_esxi_credential (target_t, osp_credential_t **);

target_osp_credential_return_t
target_osp_snmp_credential (target_t, osp_credential_t **);

target_osp_credential_return_t
target_osp_krb5_credential (target_t, osp_credential_t **);


#else
osp_credential_t *
target_osp_ssh_credential_db (target_t);

osp_credential_t *
target_osp_smb_credential_db (target_t);

osp_credential_t *
target_osp_esxi_credential_db (target_t);
#endif

osp_credential_t *
target_osp_snmp_credential_db (target_t);

osp_credential_t *
target_osp_krb5_credential_db (target_t);

#endif /* not _GVMD_MANAGE_OPENVAS_H */
