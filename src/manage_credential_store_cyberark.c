/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file manage_credential_store_cyberark.c
 * @brief GVM manage layer: CyberArk credential store.
 *
 * Management headers of the CyberArk credential store.
 */

#include "manage_credential_stores.h"
#include "manage_credential_store_cyberark.h"
#include <gvm/util/fileutils.h>
#include <gvm/http/httputils.h>
#include <gvm/util/tlsutils.h>
#include <gnutls/gnutls.h>

static verify_credential_store_return_t
verify_and_prepare_cyberark_connection_data (const char *host,
                                             const char *path,
                                             GHashTable *preferences,
                                             const char **app_id,
                                             gchar **client_key_pem,
                                             gchar **client_cert_pem,
                                             gchar **server_ca_cert_pem,
                                             gchar **message)
{
  credential_store_preference_data_t *app_id_preference;
  credential_store_preference_data_t *pkcs12_preference;
  credential_store_preference_data_t *ca_cert_preference;
  *client_key_pem = *client_cert_pem = *server_ca_cert_pem = *message = NULL;

  if (host == NULL || strcmp (host, "") == 0)
    {
      *message = g_strdup ("host must not be empty");
      return VERIFY_CREDENTIAL_STORE_HOST_ERROR;
    }
  if (path == NULL || strcmp (path, "") == 0)
    {
      *message = g_strdup ("path must not be empty");
      return VERIFY_CREDENTIAL_STORE_PATH_ERROR;
    }
  app_id_preference = g_hash_table_lookup (preferences, "app_id");
  if (credential_store_preference_is_set (app_id_preference) == FALSE)
    {
      *message = g_strdup ("'app_id' is missing or empty");
      return VERIFY_CREDENTIAL_STORE_PREFERENCE_ERROR;
    }
  *app_id = app_id_preference->value;

  pkcs12_preference = g_hash_table_lookup (preferences, "client_pkcs12_file");
  if (credential_store_preference_is_set (pkcs12_preference))
    {
      credential_store_preference_data_t *passphrase_preference;
      const char *passphrase;
      int ret;

      passphrase_preference 
        = g_hash_table_lookup (preferences,
                               pkcs12_preference->passphrase_name);
      if (credential_store_preference_is_set (passphrase_preference))
        passphrase = passphrase_preference->value;
      else
        passphrase = NULL;

      gchar* extra;
      ret = eval_pkcs12_credential_store_preference (pkcs12_preference,
                                                     passphrase,
                                                     client_key_pem,
                                                     client_cert_pem,
                                                     &extra,
                                                     NULL,
                                                     message);

      if (ret)
        return VERIFY_CREDENTIAL_STORE_PREFERENCE_ERROR;
    }
  else
    {
      credential_store_preference_data_t *key_preference, *cert_preference;
      credential_store_preference_data_t *passphrase_preference;
      const char *passphrase;
      int ret;

      key_preference = g_hash_table_lookup (preferences, "client_key");
      cert_preference = g_hash_table_lookup (preferences, "client_cert");

      if (credential_store_preference_is_set (key_preference) == FALSE
          || credential_store_preference_is_set (cert_preference) == FALSE)
        {
          *message = g_strdup ("either 'client_pkcs12_file'"
                               " or both 'client_key' and 'client_cert'"
                               " are required");

          g_free (server_ca_cert_pem);
          return VERIFY_CREDENTIAL_STORE_PREFERENCE_ERROR;
        }

      passphrase_preference 
        = g_hash_table_lookup (preferences,
                               key_preference->passphrase_name);
      if (credential_store_preference_is_set (passphrase_preference))
        passphrase = passphrase_preference->value;
      else
        passphrase = NULL;

      ret = eval_privkey_credential_store_preference (key_preference,
                                                      passphrase,
                                                      client_key_pem,
                                                      message);

      if (ret)
        return VERIFY_CREDENTIAL_STORE_PREFERENCE_ERROR;

      ret = eval_certs_credential_store_preference (cert_preference,
                                                    client_cert_pem,
                                                    message);

      if (ret)
        return VERIFY_CREDENTIAL_STORE_PREFERENCE_ERROR;
    }

  ca_cert_preference = g_hash_table_lookup (preferences, "server_ca_cert");
  if (credential_store_preference_is_set (ca_cert_preference))
    {
      int ret;

      ret = eval_certs_credential_store_preference (ca_cert_preference,
                                                    server_ca_cert_pem,
                                                    message);

      if (ret)
        {
          g_free (client_key_pem);
          g_free (client_cert_pem);
          return VERIFY_CREDENTIAL_STORE_PREFERENCE_ERROR;
        }
    }

  return VERIFY_CREDENTIAL_STORE_OK;
}

verify_credential_store_return_t
verify_cyberark_credential_store (const char *host,
                                  const char *path,
                                  GHashTable *preferences,
                                  gchar **message)
{
  const char *app_id;
  gchar *client_key_pem, *client_cert_pem, *server_ca_cert_pem;
  verify_credential_store_return_t ret;

  ret = verify_and_prepare_cyberark_connection_data (host,
                                                     path,
                                                     preferences,
                                                     &app_id,
                                                     &client_key_pem,
                                                     &client_cert_pem,
                                                     &server_ca_cert_pem,
                                                     message);
  if (ret)
    {
      g_free (client_key_pem);
      g_free (client_cert_pem);
      g_free (server_ca_cert_pem);
      return ret;
    }

  // TODO: Send HTTP request to API and check response

  g_free (client_key_pem);
  g_free (client_cert_pem);
  g_free (server_ca_cert_pem);

  return VERIFY_CREDENTIAL_STORE_OK;
}
