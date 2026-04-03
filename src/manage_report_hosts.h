/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: Report hosts.
 *
 * Non-SQL report hosts code for the GVM management layer.
 */

#ifndef _GVM_MANAGE_REPORT_HOSTS_H
#define _GVM_MANAGE_REPORT_HOSTS_H

#include "iterator.h"
#include "manage_resources.h"

#include <glib.h>
#include <stdio.h>

void
init_report_host_iterator (iterator_t *, report_t, const char *, report_host_t);

void
init_report_host_iterator_hostname (iterator_t *, report_t, const char *,
                                    const char *);

const char*
host_iterator_host (iterator_t *);

const char*
host_iterator_start_time (iterator_t *);

const char*
host_iterator_end_time (iterator_t *);

int
host_iterator_current_port (iterator_t *);

int
host_iterator_max_port (iterator_t *);

int
manage_send_report_hosts (report_t ,
                          const get_data_t *,
                          const gchar *,
                          gboolean,
                          int,
                          gboolean (*)(const char*,
                                       int (*)(const char*, void*),
                                       void*),
                          int (*) (const char *, void *),
                          void *);

gchar *
report_hosts_extra_where (const gchar *);

#endif //_GVM_MANAGE_REPORT_HOSTS_H
