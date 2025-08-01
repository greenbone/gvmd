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
 * @file
 * @brief LSC credentials encryption support
 */

#ifndef _GVMD_LSC_CRYPT_H
#define _GVMD_LSC_CRYPT_H

#include <glib.h>

/// @brief Default length for RSA encryption keys
#define DEFAULT_ENCRYPTION_RSA_KEY_LENGTH 4096

/**
 * @brief The name of the old encryption key.
 *
 * Note that the code will use the "=" prefix flag to indicate an
 * exact search.  Thus when creating the key it should not have a
 * comment or email address part.
 */
#define OLD_ENCRYPTION_KEY_UID "GVM Credential Encryption"

/**
 * @brief Template for the name of the encryption key.
 *
 * It must contain a single %s that will be replaced with the current
 * date and time.
 *
 * Note that the code will use the "=" prefix flag to indicate an
 * exact search.  Thus when creating the key it should not have a
 * comment or email address part.
 */
#define ENCRYPTION_KEY_UID_TEMPLATE "GVM Credential Encryption - %s"

/* (Defined in gvmd.c) */
extern int disable_encrypted_credentials;


struct lsc_crypt_ctx_s;
typedef struct lsc_crypt_ctx_s *lsc_crypt_ctx_t;

int lsc_crypt_enckey_parms_init (const char *, int);

lsc_crypt_ctx_t lsc_crypt_new (const char*);
void lsc_crypt_release (lsc_crypt_ctx_t);

int lsc_crypt_create_key ();

void lsc_crypt_flush (lsc_crypt_ctx_t);

gboolean lsc_crypt_enckey_exists (lsc_crypt_ctx_t);

int lsc_crypt_create_enckey (lsc_crypt_ctx_t ctx);

char *lsc_crypt_encrypt_hashtable (lsc_crypt_ctx_t, GHashTable*);

char *lsc_crypt_encrypt (lsc_crypt_ctx_t,
                         const char *, ...) G_GNUC_NULL_TERMINATED;

const char *lsc_crypt_decrypt (lsc_crypt_ctx_t, const char *, const char *);
const char *lsc_crypt_get_password (lsc_crypt_ctx_t, const char *);
const char *lsc_crypt_get_private_key (lsc_crypt_ctx_t, const char *);


#endif /* not _GVMD_LSC_CRYPT_H */
