/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Greenbone Vulnerability Manager scanner relays headers.
 */

#ifndef _GVMD_MANAGE_SCANNER_RELAYS
#define _GVMD_MANAGE_SCANNER_RELAYS

#include <glib.h>

/**
 * @brief  Data structure describing an item from a scanner relays list.
 */
typedef struct {
  char *original_host;  ///< The original host / socket path of the scanner
  int original_port;    ///< Original port of the scanner
  char *relay_host;     ///< Host or socket path of the relay
  int relay_port;       ///< Port of the relay
  char *scanner_type;   ///< Scanner type string defining the scanner type.
} relays_list_item_t;

const char *
get_relays_path ();

void
set_relays_path (const char *);

gboolean
relays_managed_externally ();

int
sync_scanner_relays ();

int
get_single_relay_from_file (int, const char *, int, char **, int *);

#endif /* _GVMD_MANAGE_SCANNER_RELAYS */
