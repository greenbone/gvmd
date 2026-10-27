/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: Active Directory.
 *
 * Non-SQL Active Directory management code for the GVM management layer.
 */

#if ENABLE_AD_INTEGRATION

#include "manage_acl.h"
#include "manage_active_directory.h"
#include "manage_runtime_flags.h"
#include "manage_sql.h"
#include "manage_sql_resources.h"
#include "manage_sql_credentials.h"
#include "manage_credentials.h"
#include "lsc_user.h"

#include <gnutls/x509.h> /* for gnutls_x509_crt_... */

#include <gvm/ad_connector/ad_connector.h>
#include <gvm/util/tlsutils.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

#define AD_NETWORK_TIMEOUT_SECONDS_DEFAULT 10
#define AD_OPERATION_TIMEOUT_SECONDS_DEFAULT 30

/**
 * @brief Reset the AD connector data structure.
 *
 * @param[in,out] ad  Pointer to the AD connector data structure to reset.
 *
 * This function frees all dynamically allocated fields within the
 * ad_credential_data_t structure and sets them to NULL.
 */
void
ad_credential_data_reset (ad_credential_data_t *ad)
{
  if (ad == NULL)
    return;

  g_free (ad->host);
  g_free (ad->port);
  g_free (ad->bind_dn);
  g_free (ad->bind_password);
  g_free (ad->base_dn);
  g_free (ad->tls_mode);
  g_free (ad->ca_certificate);

  memset (ad, 0, sizeof (*ad));
}

/**
 * @brief Validate an Active Directory port.
 *
 * @param text The port as a string.
 *
 * @return TRUE if the port is valid or NULL, FALSE otherwise.
 */
gboolean
valid_ad_port (const char *text)
{
  char *end;
  guint64 port;

  if (text == NULL)
    return TRUE;  /* use the connector default. */

  if (!g_ascii_isdigit ((guchar) text[0]))
    return FALSE;

  port = g_ascii_strtoull (text, &end, 10);
  return *end == '\0' && port >= 1 && port <= 65535;
}

/**
 * @brief Validate an Active Directory CA certificate.
 *
 * @param pem The CA certificate in PEM format.
 *
 * @return TRUE if the certificate is valid, FALSE otherwise.
 */
gboolean
valid_ad_ca_certificate (const char *pem)
{
  gnutls_x509_crt_t *certs = NULL;
  unsigned int count = 0;
  gnutls_datum_t input;
  gsize length;
  gboolean valid;
  int ret;

  if (pem == NULL || *pem == '\0')
    return FALSE;

  length = strlen (pem);
  if (length > G_MAXUINT)
    return FALSE;

  input.data = (unsigned char *) pem;
  input.size = (unsigned int) length;

  ret = gnutls_x509_crt_list_import2 (&certs, &count, &input,
                                      GNUTLS_X509_FMT_PEM, 0);

  valid = (ret == GNUTLS_E_SUCCESS && count > 0);
  gvm_x509_cert_list_free (certs, count);
  return valid;
}

/**
 * @brief Validate the supplied Active Directory connection data.
 *
 * @param ad  The Active Directory connection data to validate.
 *
 * @return A verify_ad_return_t indicating the result of the validation.
 */
static verify_ad_return_t
validate_supplied_ad_connection_data (const ad_credential_data_t *ad)
{
  if (!ad || !ad->host || !*ad->host)
    return VERIFY_AD_CREDENTIAL_HOST_REQUIRED;
  if (!ad->bind_dn || !*ad->bind_dn)
    return VERIFY_AD_CREDENTIAL_BIND_DN_REQUIRED;
  if (!ad->base_dn || !*ad->base_dn)
    return VERIFY_AD_CREDENTIAL_BASE_DN_REQUIRED;
  if (!ad->bind_password || !*ad->bind_password)
    return VERIFY_AD_CREDENTIAL_BIND_PASSWORD_REQUIRED;
  if (!ad->tls_mode || !*ad->tls_mode)
    return VERIFY_AD_CREDENTIAL_TLS_MODE_REQUIRED;

  if (!valid_ad_port (ad->port))
    return VERIFY_AD_CREDENTIAL_INVALID_PORT;

  if (!g_str_equal (ad->tls_mode, "ldaps")
      && !g_str_equal (ad->tls_mode, "starttls"))
    return VERIFY_AD_CREDENTIAL_INVALID_TLS_MODE;

  if (ad->ca_certificate
      && !valid_ad_ca_certificate (ad->ca_certificate))
    return VERIFY_AD_CREDENTIAL_INVALID_CA_CERTIFICATE;

  return VERIFY_AD_CREDENTIAL_OK;
}

/**
 * @brief Configure an Active Directory connector with
 *        the provided connection data.
 *
 * @param connector                  The Active Directory connector.
 * @param ad                         The Active Directory connection data.
 * @param network_timeout_seconds    The network timeout in seconds.
 * @param operation_timeout_seconds  The operation timeout in seconds.
 *
 * @return An ad_connector_return_t indicating the result of the configuration.
 */
static ad_connector_return_t
configure_ad_connector (ad_connector_t connector,
                        const ad_credential_data_t *ad,
                        gint network_timeout_seconds,
                        gint operation_timeout_seconds)
{
  ad_connector_return_t rc;
  ad_connector_tls_mode_t tls_mode;
  gint port = 0;

  if (!connector || !ad || !ad->tls_mode || !valid_ad_port (ad->port))
    return AD_CONNECTOR_INVALID_VALUE;

  if (g_str_equal (ad->tls_mode, "ldaps"))
    tls_mode = AD_CONNECTOR_TLS_LDAPS;
  else if (g_str_equal (ad->tls_mode, "starttls"))
    tls_mode = AD_CONNECTOR_TLS_STARTTLS;
  else
    return AD_CONNECTOR_INVALID_VALUE;

  if (ad->port)
    port = (gint) g_ascii_strtoull (ad->port, NULL, 10);

  rc = ad_connector_builder (connector, AD_CONNECTOR_OPT_HOST, ad->host);
  if (rc != AD_CONNECTOR_OK)
    return rc;
  rc = ad_connector_builder (connector, AD_CONNECTOR_OPT_PORT, &port);
  if (rc != AD_CONNECTOR_OK)
    return rc;
  rc = ad_connector_builder (connector, AD_CONNECTOR_OPT_TLS_MODE, &tls_mode);
  if (rc != AD_CONNECTOR_OK)
    return rc;
  rc = ad_connector_builder (connector, AD_CONNECTOR_OPT_BIND_DN,
                             ad->bind_dn);
  if (rc != AD_CONNECTOR_OK)
    return rc;
  rc = ad_connector_builder (connector, AD_CONNECTOR_OPT_NETWORK_TIMEOUT,
                             &network_timeout_seconds);
  if (rc != AD_CONNECTOR_OK)
    return rc;
  rc = ad_connector_builder (connector, AD_CONNECTOR_OPT_OPERATION_TIMEOUT,
                             &operation_timeout_seconds);
  if (rc != AD_CONNECTOR_OK)
    return rc;

  if (ad->ca_certificate)
    return ad_connector_builder (connector,
                                 AD_CONNECTOR_OPT_CA_CERT,
                                 ad->ca_certificate);

  return AD_CONNECTOR_OK;
}

/**
 * @brief Check if any Active Directory connection fields are present.
 *
 * @param ad  The Active Directory connection data to check.
 *
 * @return TRUE if any fields are present, FALSE otherwise.
 */
static gboolean
ad_fields_present (const ad_credential_data_t *ad)
{
  return ad
         && (ad->host
             || ad->port
             || ad->bind_dn
             || ad->bind_password
             || ad->tls_mode
             || ad->base_dn
             || ad->ca_certificate);
}

/**
 * @brief Verify an Active Directory credential.
 *
 * @param credential_id  The ID of the credential to verify.
 * @param fields         The Active Directory connection data to verify.
 *
 * @return A verify_ad_return_t indicating the result of the verification.
 */
verify_ad_return_t
verify_active_directory_credential (const gchar *credential_id,
                                    const ad_credential_data_t *fields)
{
  ad_credential_data_t saved = { 0 };
  const ad_credential_data_t *ad = fields;
  credential_t credential = 0;
  ad_connector_t connector = NULL;
  ad_connector_return_t connector_result;
  verify_ad_return_t result = VERIFY_AD_CREDENTIAL_INTERNAL_ERROR;
  gchar *type = NULL;
  gboolean supplied = ad_fields_present (fields);

  if ((credential_id && supplied)
      ||(!credential_id && !supplied)
      || (credential_id && !*credential_id))
    return VERIFY_AD_CREDENTIAL_INVALID_INPUT;

  if (!feature_enabled (FEATURE_ID_AD_INTEGRATION))
    return VERIFY_AD_CREDENTIAL_FEATURE_DISABLED;

  if (!acl_user_may ("verify_active_directory_credential"))
    return VERIFY_AD_CREDENTIAL_PERMISSION_DENIED;

  if (supplied)
    {
      result = validate_supplied_ad_connection_data (fields);
      if (result != VERIFY_AD_CREDENTIAL_OK)
        goto cleanup;
    }
  else
    {
      if (find_credential_with_permission (credential_id,
                                           &credential,
                                           "get_credentials"))
        {
          g_warning ("%s: Failed to find credential", __func__);
          goto cleanup;
        }

      if (!credential)
        {
          result = VERIFY_AD_CREDENTIAL_NOT_FOUND;
          goto cleanup;
        }

      type = credential_type (credential);
      if (!type)
        goto cleanup;
      if (strcmp (type, "ad") != 0)
        {
          result = VERIFY_AD_CREDENTIAL_INVALID_TYPE;
          goto cleanup;
        }

      saved.host = credential_value (credential, "ad_host");
      saved.port = credential_value (credential, "ad_port");
      saved.bind_dn = credential_value (credential, "ad_bind_dn");
      saved.bind_password
        = credential_encrypted_value (credential, "password");
      saved.base_dn = credential_value (credential, "ad_base_dn");
      saved.tls_mode = credential_value (credential, "ad_tls_mode");
      saved.ca_certificate
        = credential_value (credential, "ad_ca_certificate");
      ad = &saved;

      result = validate_supplied_ad_connection_data (ad);
      if (result != VERIFY_AD_CREDENTIAL_OK)
        {
          result = VERIFY_AD_CREDENTIAL_INVALID_STORED_CONFIGURATION;
          goto cleanup;
        }
    }

  connector = ad_connector_new ();
  if (!connector)
    goto cleanup;

  connector_result = configure_ad_connector (connector,
                                             ad,
                                             AD_NETWORK_TIMEOUT_SECONDS_DEFAULT,
                                             AD_OPERATION_TIMEOUT_SECONDS_DEFAULT);
  if (connector_result != AD_CONNECTOR_OK)
    {
      result = !supplied && connector_result == AD_CONNECTOR_INVALID_VALUE
                 ? VERIFY_AD_CREDENTIAL_INVALID_STORED_CONFIGURATION
                 : VERIFY_AD_CREDENTIAL_INTERNAL_ERROR;
      goto cleanup;
    }

  connector_result = ad_connector_connect (connector, ad->bind_password);
  switch (connector_result)
    {
    case AD_CONNECTOR_OK:
      result = VERIFY_AD_CREDENTIAL_OK;
      break;
    case AD_CONNECTOR_BIND_ERROR:
      result = VERIFY_AD_CREDENTIAL_BIND_FAILED;
      break;
    case AD_CONNECTOR_CONNECTION_ERROR:
      result = VERIFY_AD_CREDENTIAL_CONNECTION_FAILED;
      break;
    case AD_CONNECTOR_INVALID_VALUE:
      result = supplied
                 ? VERIFY_AD_CREDENTIAL_INTERNAL_ERROR
                 : VERIFY_AD_CREDENTIAL_INVALID_STORED_CONFIGURATION;
      break;
    default:
      result = VERIFY_AD_CREDENTIAL_INTERNAL_ERROR;
      break;
    }

cleanup:
  ad_connector_free (connector);
  g_free (type);
  ad_credential_data_reset (&saved);
  return result;
}

#endif /* ENABLE_AD_INTEGRATION */
