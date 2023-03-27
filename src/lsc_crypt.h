/* Copyright (C) 2013-2022 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * @file lsc_crypt.h
 * @brief LSC credentials encryption support
 */

#ifndef _GVMD_LSC_CRYPT_H
#define _GVMD_LSC_CRYPT_H

#include <glib.h>

/* (Defined in gvmd.c) */
extern int disable_encrypted_credentials;


struct lsc_crypt_ctx_s;
typedef struct lsc_crypt_ctx_s *lsc_crypt_ctx_t;

lsc_crypt_ctx_t lsc_crypt_new ();
void lsc_crypt_release (lsc_crypt_ctx_t);

int lsc_crypt_create_key ();

void lsc_crypt_flush (lsc_crypt_ctx_t);

char *lsc_crypt_encrypt (lsc_crypt_ctx_t,
                         const char *, ...) G_GNUC_NULL_TERMINATED;

const char *lsc_crypt_decrypt (lsc_crypt_ctx_t, const char *, const char *);
const char *lsc_crypt_get_password (lsc_crypt_ctx_t, const char *);
const char *lsc_crypt_get_private_key (lsc_crypt_ctx_t, const char *);


#endif /* not _GVMD_LSC_CRYPT_H */
