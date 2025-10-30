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

#include "manage_credential_store_cyberark.h"
#include "manage_sql.h"
#include "manage_sql_credential_stores.h"
#include "manage_credential_stores.h"

#include <gnutls/gnutls.h>
#include <gvm/cyberark/cyberark.h>
#include <gvm/util/fileutils.h>
#include <gvm/util/tlsutils.h>

static verify_credential_store_return_t
verify_and_prepare_cyberark_connection_data (
  const char *host, const char *path, GHashTable *preferences,
  const char **app_id, gchar **client_key_pem, gchar **client_cert_pem,
  gchar **server_ca_cert_pem, gchar **message)
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

      passphrase_preference =
        g_hash_table_lookup (preferences, pkcs12_preference->passphrase_name);
      if (credential_store_preference_is_set (passphrase_preference))
        passphrase = passphrase_preference->value;
      else
        passphrase = NULL;

      gchar *extra;
      ret = eval_pkcs12_credential_store_preference (
        pkcs12_preference, passphrase, client_key_pem, client_cert_pem, &extra,
        NULL, message);

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

          return VERIFY_CREDENTIAL_STORE_PREFERENCE_ERROR;
        }

      passphrase_preference =
        g_hash_table_lookup (preferences, key_preference->passphrase_name);
      if (credential_store_preference_is_set (passphrase_preference))
        passphrase = passphrase_preference->value;
      else
        passphrase = NULL;

      ret = eval_privkey_credential_store_preference (
        key_preference, passphrase, client_key_pem, message);

      if (ret)
        return VERIFY_CREDENTIAL_STORE_PREFERENCE_ERROR;

      ret = eval_certs_credential_store_preference (cert_preference,
                                                    client_cert_pem, message);

      if (ret)
        return VERIFY_CREDENTIAL_STORE_PREFERENCE_ERROR;
    }

  ca_cert_preference = g_hash_table_lookup (preferences, "server_ca_cert");
  if (credential_store_preference_is_set (ca_cert_preference))
    {
      int ret;

      ret = eval_certs_credential_store_preference (
        ca_cert_preference, server_ca_cert_pem, message);

      if (ret)
        {
          return VERIFY_CREDENTIAL_STORE_PREFERENCE_ERROR;
        }
    }

  return VERIFY_CREDENTIAL_STORE_OK;
}

/**
 * @brief Verifies the connection of a CyberArk credential store.
 *
 * @param[in]  host         The host of the CyberArk credential store.
 * @param[in]  path         The path of the CyberArk credential store.
 * @param[in]  preferences  The preferences of the CyberArk credential store.
 * @param[out] message      Error message output.
 *
 * @return A verify_credential_store_return_t return code.
 */
verify_credential_store_return_t
verify_cyberark_credential_store (const char *host, const char *path,
                                  GHashTable *preferences, gchar **message)
{
  const char *app_id;
  gchar *client_key_pem, *client_cert_pem, *server_ca_cert_pem;
  verify_credential_store_return_t rc;

  rc = verify_and_prepare_cyberark_connection_data (
    host, path, preferences, &app_id, &client_key_pem, &client_cert_pem,
    &server_ca_cert_pem, message);
  if (rc)
    {
      g_free (client_key_pem);
      g_free (client_cert_pem);
      g_free (server_ca_cert_pem);
      return rc;
    }

  cyberark_connector_t connector = cyberark_connector_new ();

  cyberark_connector_builder (connector, CYBERARK_HOST, host);
  cyberark_connector_builder (connector, CYBERARK_PATH, path);
  cyberark_connector_builder (connector, CYBERARK_CA_CERT, server_ca_cert_pem);
  cyberark_connector_builder (connector, CYBERARK_KEY, client_key_pem);
  cyberark_connector_builder (connector, CYBERARK_CERT, client_cert_pem);
  cyberark_connector_builder (connector, CYBERARK_PROTOCOL, "https");
  cyberark_connector_builder (connector, CYBERARK_APP_ID, app_id);

  int ret =
    cyberark_verify_connection (connector, "dummy-safe", NULL, "dummy-object");

  if (ret < 0)
    {
      cyberark_connector_free (connector);
      g_free (client_key_pem);
      g_free (client_cert_pem);
      g_free (server_ca_cert_pem);
      return VERIFY_CREDENTIAL_STORE_INTERNAL_ERROR;
    }
  else if (ret > 0)
    {
      cyberark_connector_free (connector);
      g_free (client_key_pem);
      g_free (client_cert_pem);
      g_free (server_ca_cert_pem);
      return VERIFY_CREDENTIAL_STORE_CONNECTION_FAILED;
    }

  cyberark_connector_free (connector);

  g_free (client_key_pem);
  g_free (client_cert_pem);
  g_free (server_ca_cert_pem);

  return VERIFY_CREDENTIAL_STORE_OK;
}

/**
 * @brief Retrieves login and password from CyberArk credential store.
 *
 * @param[in]  cred_store_uuid  The UUID of the credential store.
 * @param[in]  vault_id         The vault ID in CyberArk.
 * @param[in]  host_identifier  The host identifier in CyberArk.
 * @param[out] login            The retrieved login.
 * @param[out] password         The retrieved password.
 *
 * @return 0 on success, -1 on error.
 */
int
cyberark_login_password_credential_data (const gchar* cred_store_uuid,
                                         const gchar* vault_id,
                                         const gchar* host_identifier,
                                         gchar **login,
                                         gchar **password)
{
  credential_store_t credential_store;
  GHashTable *preferences;
  gchar *host, *path;
  const char *app_id;
  gchar *client_key_pem, *client_cert_pem, *server_ca_cert_pem;
  cyberark_connector_t connector;
  gchar *message = NULL;
  int ret;

  if (find_resource_with_permission ("credential_store",
                                     cred_store_uuid,
                                     &credential_store,
                                     "get_credential_stores",
                                     0))
    {
      g_warning ("%s: Error getting credential store '%s'",
                 __func__, cred_store_uuid);
      return -1;
    }
  if (credential_store == 0)
    {
      g_warning ("%s: Credential store '%s' not found",
                 __func__, cred_store_uuid);
      return -1;
    }
  host = credential_store_host (credential_store);
  path = credential_store_path (credential_store);
  preferences = credential_store_get_preferences_hashtable (credential_store);

  ret = verify_and_prepare_cyberark_connection_data (host,
                                                     path,
                                                     preferences,
                                                     &app_id,
                                                     &client_key_pem,
                                                     &client_cert_pem,
                                                     &server_ca_cert_pem,
                                                     &message);
  if (ret)
    {
      g_warning ("%s: Error preparing connection data for"
                 " credential store '%s': %s",
                 __func__, cred_store_uuid,
                 message ? message : "unknown error");
      g_free (client_key_pem);
      g_free (client_cert_pem);
      g_free (server_ca_cert_pem);
      g_free (host);
      g_free (path);
      g_free (message);
      g_hash_table_destroy (preferences);
      return -1;
    }

  connector = cyberark_connector_new();

  cyberark_connector_builder (connector, CYBERARK_HOST, host);
  cyberark_connector_builder (connector, CYBERARK_PATH, path);
  cyberark_connector_builder (connector, CYBERARK_CA_CERT, server_ca_cert_pem);
  cyberark_connector_builder (connector, CYBERARK_KEY, client_key_pem);
  cyberark_connector_builder (connector, CYBERARK_CERT, client_cert_pem);
  cyberark_connector_builder (connector, CYBERARK_PROTOCOL, "https");
  cyberark_connector_builder (connector, CYBERARK_APP_ID, app_id);

  cyberark_object_t credential_object = cyberark_get_object (connector,
                                                             vault_id,
                                                             NULL,
                                                             host_identifier);

  if (credential_object == NULL)
    {
      cyberark_connector_free (connector);
      g_hash_table_destroy (preferences);
      g_free (client_key_pem);
      g_free (client_cert_pem);
      g_free (server_ca_cert_pem);
      g_free (host);
      g_free (path);
      g_warning ("%s: Error getting credential object from"
                 " CyberArk credential store '%s'",
                 __func__, cred_store_uuid);
      return -1;
    }

  if (login)
    *login = g_strdup (credential_object->username);

  if (password)
    *password = g_strdup (credential_object->content);

  cyberark_object_free (credential_object);

  cyberark_connector_free (connector);
  g_hash_table_destroy (preferences);
  g_free (client_key_pem);
  g_free (client_cert_pem);
  g_free (server_ca_cert_pem);
  g_free (host);
  g_free (path);

  if (ret)
    {
      g_warning ("%s: Error getting credential from CyberArk"
                 " credential store '%s'",
                 __func__, cred_store_uuid);
      return -1;
    }
  return 0;
}