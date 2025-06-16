/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file manage_openvas.h
 * @brief Greenbone Vulnerability Manager OpenVAS scan handling headers.
 * 
 * This contains functions common to setting up OSP and openvasd scans.
 */

#ifndef _GVMD_MANAGE_OPENVAS_H
#define _GVMD_MANAGE_OPENVAS_H

#include <gvm/osp/osp.h>
#include <glib.h>
#include "manage_resources.h"

void
add_user_scan_preferences (GHashTable *);

osp_credential_t *
target_osp_ssh_credential (target_t);

osp_credential_t *
target_osp_smb_credential (target_t);

osp_credential_t *
target_osp_esxi_credential (target_t);

osp_credential_t *
target_osp_snmp_credential (target_t);

osp_credential_t *
target_osp_krb5_credential (target_t);

#endif /* _GVMD_MANAGE_OPENVAS_H */
