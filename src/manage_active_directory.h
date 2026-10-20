
/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM GMP layer: Active Directory headers.
 *
 * Header for GMP Active Directory handlers
 */
#if ENABLE_AD_INTEGRATION

#ifndef _GVMD_MANAGE_ACTIVE_DIRECTORY_H
#define _GVMD_MANAGE_ACTIVE_DIRECTORY_H

#include "gmp_base.h"
#include "glib.h"

typedef struct
{
  char *host;
  char *port;
  char *bind_dn;
  char *bind_password;
  char *tls_mode;
  char *base_dn;
  char *ca_certificate;
} ad_credential_data_t;

typedef enum
{
  VERIFY_AD_CREDENTIAL_OK,
  VERIFY_AD_CREDENTIAL_INVALID_INPUT,
  VERIFY_AD_CREDENTIAL_PERMISSION_DENIED,
  VERIFY_AD_CREDENTIAL_NOT_FOUND,
  VERIFY_AD_CREDENTIAL_INVALID_TYPE,
  VERIFY_AD_CREDENTIAL_INVALID_STORED_CONFIGURATION,
  VERIFY_AD_CREDENTIAL_HOST_REQUIRED,
  VERIFY_AD_CREDENTIAL_BIND_DN_REQUIRED,
  VERIFY_AD_CREDENTIAL_BIND_PASSWORD_REQUIRED,
  VERIFY_AD_CREDENTIAL_BASE_DN_REQUIRED,
  VERIFY_AD_CREDENTIAL_TLS_MODE_REQUIRED,
  VERIFY_AD_CREDENTIAL_INVALID_TLS_MODE,
  VERIFY_AD_CREDENTIAL_INVALID_PORT,
  VERIFY_AD_CREDENTIAL_INVALID_CA_CERTIFICATE,
  VERIFY_AD_CREDENTIAL_CONNECTION_FAILED,
  VERIFY_AD_CREDENTIAL_BIND_FAILED,
  VERIFY_AD_CREDENTIAL_FEATURE_DISABLED,
  VERIFY_AD_CREDENTIAL_INTERNAL_ERROR
} verify_ad_return_t;


gboolean
valid_ad_ca_certificate (const char *);

gboolean
valid_ad_port (const char *);

verify_ad_return_t
verify_active_directory_credential (const gchar *,
                                    const ad_credential_data_t *);

void
ad_credential_data_reset (ad_credential_data_t *);

#endif /* _GVMD_MANAGE_ACTIVE_DIRECTORY_H */

#endif /* ENABLE_AD_INTEGRATION */
