/* OpenVAS Manager
 * $Id$
 * Description: Headers for OpenVAS Manager: the OTP library.
 *
 * Authors:
 * Matthew Mundell <matt@mundell.ukfsn.org>
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

#include <openvas/certificate.h>
#include <openvas/nvti.h>

void
init_otp_data ();

int
process_otp_server_input ();

// FIX for next 2
/**
 * @brief Possible initialisation states of the server.
 */
typedef enum
{
  SERVER_INIT_CONNECT_INTR,    /* `connect' to server was interrupted. */
  SERVER_INIT_CONNECTED,
  SERVER_INIT_DONE,
  SERVER_INIT_GOT_MD5SUM,
  SERVER_INIT_GOT_PASSWORD,
  SERVER_INIT_GOT_PLUGINS,
  SERVER_INIT_GOT_USER,
  SERVER_INIT_GOT_VERSION,
  SERVER_INIT_SENT_COMPLETE_LIST,
  SERVER_INIT_SENT_PASSWORD,
  SERVER_INIT_SENT_USER,
  SERVER_INIT_SENT_VERSION,
  SERVER_INIT_TOP
} server_init_state_t;

// FIX for ompd.c
extern server_init_state_t server_init_state;

// FIX for otpd.c,ompd.c
void
set_server_init_state (server_init_state_t state);

// FIX for ompd.c
extern int server_init_offset;

// FIX for next
/**
 * @brief Structure of information about the server.
 */
typedef struct
{
  certificates_t* certificates;      ///< List of certificates.
  char* plugins_md5;                 ///< MD5 sum over all tests.
  GHashTable* plugins_dependencies;  ///< Dependencies between plugins.
  nvtis_t* plugins;                  ///< Plugin meta-information.
  GHashTable* preferences;           ///< Server preference.
  GPtrArray* rules;                  ///< Server rules.
  int rules_size;                    ///< Number of rules.
} server_t;

// FIX for omp.c access to server info (rules, prefs, ...)
/*@-exportlocal@*/
extern server_t server;
/*@=exportlocal@*/

#endif
