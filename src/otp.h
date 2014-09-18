/* OpenVAS Manager
 * $Id$
 * Description: Headers for OpenVAS Manager: the OTP library.
 *
 * Authors:
 * Matthew Mundell <matthew.mundell@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2009 Greenbone Networks GmbH
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * or, at your option, any later version as published by the Free
 * Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef OPENVAS_MANAGER_OTP_H
#define OPENVAS_MANAGER_OTP_H

#include "manage.h"
#include <glib.h>

void
init_otp_data ();

int
process_otp_scanner_input (void (*progress) ());

/** @todo Exported for following functions. */
/**
 * @brief Possible initialisation states of the scanner.
 */
typedef enum
{
  SCANNER_INIT_CONNECT_INTR,    /* `connect' to scanner was interrupted. */
  SCANNER_INIT_CONNECTED,
  SCANNER_INIT_DONE,
  SCANNER_INIT_DONE_CACHE_MODE,        /* Done, when in NVT cache rebuild. */
  SCANNER_INIT_DONE_CACHE_MODE_UPDATE, /* Done, when in NVT cache update. */
  SCANNER_INIT_GOT_FEED_VERSION,
  SCANNER_INIT_GOT_PLUGINS,
  SCANNER_INIT_SENT_COMPLETE_LIST,
  SCANNER_INIT_SENT_COMPLETE_LIST_UPDATE,
  SCANNER_INIT_SENT_VERSION,
  SCANNER_INIT_TOP
} scanner_init_state_t;

/** @todo Exported for ompd.c. */
extern scanner_init_state_t scanner_init_state;

extern int scanner_current_loading;
extern int scanner_total_loading;

/** @todo Exported for ompd.c. */
void
set_scanner_init_state (scanner_init_state_t state);

/** @todo Exported for ompd.c. */
extern int scanner_init_offset;
#endif
