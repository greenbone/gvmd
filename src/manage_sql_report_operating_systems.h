/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM SQL layer: Report operating systems.
 *
 * Headers for SQL handlers for report operating system XML.
 */

#ifndef _GVM_MANAGE_SQL_REPORT_OPERATING_SYSTEMS_H
#define _GVM_MANAGE_SQL_REPORT_OPERATING_SYSTEMS_H

#include "manage_report_operating_systems.h"

const gchar *
report_os_iterator_cpe (iterator_t *);

const gchar *
report_os_iterator_os_name (iterator_t *);

report_host_t
report_os_iterator_report_host_id (iterator_t *);

void
init_report_os_iterator (iterator_t *, report_t);

#endif //_GVM_MANAGE_SQL_REPORT_OPERATING_SYSTEMS_H
