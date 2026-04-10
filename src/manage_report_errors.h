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

#endif //_GVM_MANAGE_REPORT_ERRORS_H
