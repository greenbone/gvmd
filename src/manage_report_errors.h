/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: Report errors.
 *
 * Non-SQL report errors code for the GVM management layer.
 */

#ifndef _GVM_MANAGE_REPORT_ERRORS_H
#define _GVM_MANAGE_REPORT_ERRORS_H

#include "manage_get.h"

int
manage_send_report_errors (report_t ,
                           const get_data_t *,
                           gboolean (*)(const char*,
                                        int (*)(const char*, void*),
                                        void*),
                           int (*) (const char *, void *),
                           void *);

void
init_report_errors_iterator (iterator_t *, report_t);

const char *
report_errors_iterator_host (iterator_t *);

const char *
report_errors_iterator_severity (iterator_t *);

const char *
report_errors_iterator_scan_nvt_version (iterator_t *);

const char *
report_errors_iterator_port (iterator_t *);

const char *
report_errors_iterator_nvt_oid (iterator_t *);

const char *
report_errors_iterator_desc (iterator_t *);

const char *
report_errors_iterator_nvt_name (iterator_t *);

const char *
report_errors_iterator_nvt_cvss (iterator_t *);

int
report_error_count (report_t);

#endif //_GVM_MANAGE_REPORT_ERRORS_H
