/* Copyright (C) 2009-2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: Credentials.
 *
 * Non-SQL credential management code for the GVM management layer.
 */

#ifndef _GVMD_MANAGE_CREDENTIALS_H
#define _GVMD_MANAGE_CREDENTIALS_H

#include "iterator.h"
#include "manage_get.h"
#include "manage_resources_types.h"

/**
 * @brief Represents a credential.
 */
struct credential_data
{
  char *credential_id;
  char *name;
  char *comment;
  char *login;
  char *password;
  char *key_phrase;
  char *key_private;
  char *key_public;
  char *certificate;
  char *community;
  char *auth_algorithm;
  char *privacy_password;
  char *privacy_algorithm;
  char *kdc;
  array_t *kdcs;
  char *realm;
  char *type;
  char *allow_insecure;
#if ENABLE_CREDENTIAL_STORES
  char *credential_store_id;
  char *vault_id;
  char *host_identifier;
  char *privacy_host_identifier;
#endif
  gboolean key_present;
} ;
typedef struct credential_data credential_data_t;

typedef enum
{
  CREDENTIAL_OK = 0,

  CREDENTIAL_INTERNAL_ERROR,
  CREDENTIAL_PERMISSION_DENIED,

  CREDENTIAL_NOT_FOUND,
  CREDENTIAL_NAME_REQUIRED,
  CREDENTIAL_NAME_ALREADY_EXISTS,
  CREDENTIAL_CREDENTIAL_ID_REQUIRED,

  CREDENTIAL_INVALID_LOGIN,

  CREDENTIAL_UNSUPPORTED_TYPE,
  CREDENTIAL_TYPE_UNDETERMINED,
  CREDENTIAL_AUTOGENERATION_NOT_SUPPORTED,

  CREDENTIAL_LOGIN_REQUIRED,
  CREDENTIAL_PASSWORD_REQUIRED,
  CREDENTIAL_PRIVATE_KEY_REQUIRED,
  CREDENTIAL_PUBLIC_KEY_REQUIRED,
  CREDENTIAL_CERTIFICATE_REQUIRED,

  CREDENTIAL_INVALID_PRIVATE_KEY_OR_PASSPHRASE,
  CREDENTIAL_INVALID_PUBLIC_KEY,
  CREDENTIAL_INVALID_CERTIFICATE,

  CREDENTIAL_SNMP_AUTHENTICATION_REQUIRED,
  CREDENTIAL_SNMP_AUTH_ALGORITHM_REQUIRED,
  CREDENTIAL_SNMP_PRIVACY_ALGORITHM_REQUIRED,
  CREDENTIAL_INVALID_SNMP_AUTH_ALGORITHM,
  CREDENTIAL_INVALID_SNMP_PRIVACY_ALGORITHM,

  CREDENTIAL_KDC_REQUIRED,
  CREDENTIAL_INVALID_KDC,
  CREDENTIAL_REALM_REQUIRED,
  CREDENTIAL_INVALID_REALM,

  CREDENTIAL_CREDENTIAL_STORE_ID_REQUIRED,
  CREDENTIAL_CREDENTIAL_STORE_NOT_FOUND,
  CREDENTIAL_CREDENTIAL_STORE_UNAVAILABLE,
  CREDENTIAL_VAULT_ID_REQUIRED,
  CREDENTIAL_HOST_IDENTIFIER_REQUIRED,
  CREDENTIAL_MIXED_CREDENTIAL_SOURCES
} credential_return_t;

credential_return_t
create_credential (const credential_data_t *,
                   credential_t *);

credential_return_t
modify_credential (const credential_data_t *);

credential_return_t
copy_credential (const char *,
                 const char *,
                 const char *,
                 credential_t *);

void
credential_data_reset (credential_data_t *);

int
check_certificate_x509 (const char *);

#endif /* _GVMD_MANAGE_CREDENTIALS_H */
