/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Greenbone Vulnerability Manager scanner relays headers.
 */

#ifndef _GVMD_MANAGE_SQL_SCANNER_RELAYS
#define _GVMD_MANAGE_SQL_SCANNER_RELAYS

#include "manage_scanner_relays.h"

time_t
get_scanner_relays_db_update_time ();

void
set_scanner_relays_update_time (time_t);

int
update_all_scanner_relays_start ();

int
update_all_scanner_relays_from_item (relays_list_item_t *, GHashTable *);

int
update_all_scanner_relays_end (time_t);

#endif /* _GVMD_MANAGE_SQL_SCANNER_RELAYS */
