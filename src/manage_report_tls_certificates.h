/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: Report tls certificates.
 *
 * Non-SQL report tls certificates code for the GVM management layer.
*/

#ifndef _GVM_MANAGE_REPORT_TLS_CERTIFICATES_H
#define _GVM_MANAGE_REPORT_TLS_CERTIFICATES_H

#include "manage_resources.h"

#include <glib.h>

int
manage_send_report_tls_certificates (report_t ,
                                     const get_data_t *,
                                     gboolean,
                                     gboolean (*)(const char*,
                                                  int (*)(const char*, void*),
                                                  void*),
                                     int (*) (const char *, void *),
                                     void *);

int
report_ssl_cert_count (report_t report);

#endif //_GVM_MANAGE_REPORT_TLS_CERTIFICATES_H
