/* Copyright (C) 2022 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GVMD_MANAGE_AUTHENTICATION_H
#define _GVMD_MANAGE_AUTHENTICATION_H

#if ENABLE_JWT_AUTH
#include <glib.h>
#include <gvm/auth/gvm_auth.h>
#endif /* ENABLE_JWT_AUTH */

enum manage_authentication_rc
{
  GMA_SUCCESS,
  GMA_HASH_VALID_BUT_DATED,
  GMA_HASH_INVALID,
  GMA_ERR,
};

enum manage_authentication_rc
manage_authentication_setup (const char *pepper, unsigned int pepper_size,
                             unsigned int count, char *prefix);
char *
manage_authentication_hash (const char *password);

enum manage_authentication_rc
manage_authentication_verify (const char *hash, const char *password);

#if ENABLE_JWT_AUTH

int
load_authentication_config ();

int
get_access_token_lifetime ();

gvm_jwt_decode_secret_t
get_jwt_decode_secret ();

gvm_jwt_encode_secret_t
get_jwt_encode_secret ();

#endif /* ENABLE_JWT_AUTH */

#endif /* _GVMD_MANAGE_AUTHENTICATION_H */
