/* OpenVAS Manager
 * $Id$
 * Description: LSC credentials encryption support
 *
 * Authors:
 * Werner Koch <wk@gnupg.org>
 *
 * Copyright:
 * Copyright (C) 2013 Greenbone Networks GmbH
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

#ifndef _OPENVASMD_LSC_CRYPT_H
#define _OPENVASMD_LSC_CRYPT_H

#include <glib.h>

/* (Defined in openvasmd.c) */
extern int disable_encrypted_credentials;


struct lsc_crypt_ctx_s;
typedef struct lsc_crypt_ctx_s *lsc_crypt_ctx_t;

lsc_crypt_ctx_t lsc_crypt_new ();
void lsc_crypt_release (lsc_crypt_ctx_t);

int lsc_crypt_create_key ();

void lsc_crypt_flush (lsc_crypt_ctx_t);

char *lsc_crypt_encrypt (lsc_crypt_ctx_t,
                         const char *, ...) G_GNUC_NULL_TERMINATED;

const char *lsc_crypt_get_password (lsc_crypt_ctx_t, const char *);
const char *lsc_crypt_get_private_key (lsc_crypt_ctx_t, const char *);


#endif /* _OPENVASMD_LSC_CRYPT_H */
