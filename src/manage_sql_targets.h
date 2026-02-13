/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GVMD_MANAGE_SQL_TARGETS_H
#define _GVMD_MANAGE_SQL_TARGETS_H

#include "manage_targets.h"

char*
target_comment (target_t);

char*
trash_target_comment (target_t);

credential_t
target_ssh_credential (target_t);

credential_t
target_credential (target_t, const char *);

credential_t
target_smb_credential (target_t);

credential_t
target_esxi_credential (target_t);

credential_t
target_ssh_elevate_credential (target_t);

credential_t
target_krb5_credential (target_t);

#endif // not _GVMD_MANAGE_SQL_TARGETS_H
