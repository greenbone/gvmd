/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file manage_osp.h
 * @brief Greenbone Vulnerability Manager OSP scan handling.
 */

#ifndef _GVMD_SCAN_HANDLER_H
#define _GVMD_SCAN_HANDLER_H

#include <gvm/osp/osp.h>
#include <glib.h>
#include "manage_resources.h"

typedef struct
{
  char *host;
  int port;
  char *ca_pub;
  char *key_pub;
  char *key_priv;
  gboolean use_relay_mapper;
} osp_connect_data_t;

void
osp_connect_data_free (osp_connect_data_t *);

osp_connect_data_t *
osp_connect_data_from_scanner (scanner_t scanner);

void
osp_connect_data_from_scanner_iterator (iterator_t *, osp_connect_data_t *);

osp_connection_t *
osp_connect_with_data (osp_connect_data_t *);

osp_connection_t *
osp_scanner_connect (scanner_t);

int
run_osp_scan_get_report (task_t, int, char **);

int
handle_osp_scan_start (task_t, target_t, const char *, int);

int
handle_osp_scan (task_t, report_t, const char *);

int
handle_osp_scan_end (task_t, int);

#endif /* _GVMD_SCAN_HANDLER_H */
