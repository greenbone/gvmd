/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Greenbone Vulnerability Manager OSP scan handling.
 */

#ifndef _GVMD_MANAGE_OSP_H
#define _GVMD_MANAGE_OSP_H

#include <gvm/osp/osp.h>
#include <glib.h>
#include "manage_openvas.h"
#include "manage_resources.h"

typedef struct
{
  char *host;               ///< Hostname, IP or socket path of the scanner
  int port;                 ///< Port of the scanner
  char *ca_pub;             ///< CA Certificate of the scanner
  char *key_pub;            ///< Public key used to connect
  char *key_priv;           ///< Private key used to connect
  gboolean use_relay_mapper;///< Whether to use the external relay mapper.
                            ///< Does not indicate use of arelay from the DB.
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
handle_osp_scan_start (task_t, target_t, const char *, int, gboolean, gboolean*);

int
handle_osp_scan (task_t, report_t, const char *, time_t);

int
handle_osp_scan_end (task_t, int, gboolean);

#endif /* _GVMD_MANAGE_OSP_H */
