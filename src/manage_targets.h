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

char*
target_uuid (target_t);

char*
trash_target_uuid (target_t);

#endif /* not _GVMD_MANAGE_TARGETS_H */
