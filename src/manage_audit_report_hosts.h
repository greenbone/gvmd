/* Copyright (C) 2026 Greenbone AG
*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: Audit report hosts.
 *
 * Headers for non-SQL audit report hosts code.
 */

#ifndef _GVM_MANAGE_AUDIT_REPORT_HOSTS_H
#define _GVM_MANAGE_AUDIT_REPORT_HOSTS_H

#include "manage.h"

int
manage_send_audit_report_hosts (report_t,
                                const get_data_t *,
                                int,
                                gboolean (*)(const char*,
                                             int (*)(const char*, void*),
                                             void*),
                                int (*) (const char *, void *),
                                void *);

#endif /* _GVM_MANAGE_AUDIT_REPORT_HOSTS_H */
