/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: Report ports.
 *
 * Non-SQL report ports code for the GVM management layer.
 */

#ifndef _GVM_MANAGE_REPORT_PORTS_H
#define _GVM_MANAGE_REPORT_PORTS_H

#include "iterator.h"
#include "manage_resources.h"

#include <glib.h>
#include <stdio.h>

int
manage_send_report_ports (report_t ,
                          const get_data_t *,
                          const gchar *,
                          gboolean (*)(const char*,
                                       int (*)(const char*, void*),
                                       void*),
                          int (*) (const char *, void *),
                          void *,
                          int *);
int
report_port_count (report_t report);

#endif //_GVM_MANAGE_REPORT_PORTS_H
