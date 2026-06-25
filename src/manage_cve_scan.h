/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Greenbone Vulnerability Manager CVE scan handling headers.
 *
 * This contains functions common to setting up CVE scans.
 */

#ifndef _GVM_MANAGE_CVE_SCAN_H
#define _GVM_MANAGE_CVE_SCAN_H

#include "manage_resources_types.h"

#include <gvm/base/hosts.h>

int
cve_scan_host (task_t, report_t, gvm_host_t *);

#endif //_GVM_MANAGE_CVE_SCAN_H
