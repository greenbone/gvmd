/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM SQL layer: Report applications.
 *
 * Headers for SQL handlers for report application XML.
 */

#ifndef _GVM_MANAGE_SQL_REPORT_APPLICATIONS_H
#define _GVM_MANAGE_SQL_REPORT_APPLICATIONS_H

#include "manage_report_applications.h"

const gchar *
report_app_iterator_application_name (iterator_t *);

int
report_app_iterator_host_count (iterator_t *);

int
report_app_iterator_occurrences (iterator_t *);

void
init_report_app_iterator (iterator_t *, report_t);

int
fill_report_applications_severities (const get_data_t *,
                                     report_t,
                                     iterator_t *,
                                     GHashTable **);

#endif //_GVM_MANAGE_SQL_REPORT_APPLICATIONS_H
