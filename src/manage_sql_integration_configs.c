/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief SQL backend implementation for integration config management in GVMD.
 *
 */
#include "manage_sql_integration_configs.h"

#include "manage_runtime_flags.h"
#include "manage_sql_resources.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

static const gchar *OIDC_CLIENT_SECRET_TYPE = "oidc_client_secret";

/**
 * @brief Creates a new Security Intelligence integration configuration.
 *
 * @param[in] owner   Owner of configuration data.
 */
static void
create_security_intelligence_config (user_t owner)
{
  sql_ps ("INSERT INTO integration_configs (uuid, name, comment, owner,"
          " creation_time, modification_time, service_url,"
          " service_cacert, oidc_url, oidc_client_id, oidc_client_secret) "
          "VALUES ($1, $2, $3, "
          "  $4, m_now(), m_now(), $5, $6, $7, $8, $9) "
          " ON CONFLICT (uuid) DO NOTHING",
          SQL_STR_PARAM (INTEGRATION_CONFIG_SECURITY_INTELLIGENCE_UUID),
          SQL_STR_PARAM ("Security Intelligence Integration Configuration"),
          SQL_STR_PARAM (""),
          SQL_RESOURCE_PARAM (owner),
          SQL_STR_PARAM (""),
          SQL_STR_PARAM (""),
          SQL_STR_PARAM (""),
          SQL_STR_PARAM (""),
          SQL_STR_PARAM (""),
          NULL);
}

/**
 * @brief Updates an existing integration configuration.
 *
 * @param[in] config   Integration configuration data.
 * @param[in] secret   OIDC client secret (encrypted).
 *
 * @return INTEGRATION_CONFIG_SUCCESS on success,
 *         INTEGRATION_CONFIG_INVALID_DATA if the input is invalid.
 */
static integration_config_response_t
modify_integration_config_row (integration_config_data_t config,
                               const gchar *secret)
{
  if (!config || str_blank (config->uuid))
    return INTEGRATION_CONFIG_INVALID_DATA;

  sql_ps ("UPDATE integration_configs SET"
          " modification_time = m_now(),"
          " service_url = $1,"
          " service_cacert = $2,"
          " oidc_url = $3,"
          " oidc_client_id = $4,"
          " oidc_client_secret = $5"
          " WHERE uuid = $6;",
          SQL_STR_PARAM (config->service_url),
          SQL_STR_PARAM (config->service_cacert),
          SQL_STR_PARAM (config->oidc_url),
          SQL_STR_PARAM (config->oidc_client_id),
          SQL_STR_PARAM (secret),
          SQL_STR_PARAM (config->uuid),
          NULL);

  return INTEGRATION_CONFIG_SUCCESS;
}

/**
 * @brief Checks whether all mutable integration config fields are empty.
 *
 * @param[in] config Integration configuration data.
 *
 * @return TRUE if all configurable fields are empty or unset, FALSE otherwise.
 */
static gboolean
integration_config_is_all_empty (integration_config_data_t config)
{
  if (!config)
    return TRUE;

  return str_blank (config->service_url)
         && str_blank (config->service_cacert)
         && str_blank (config->oidc_url)
         && str_blank (config->oidc_client_id)
         && str_blank (config->oidc_client_secret);
}

/**
 * @brief Validate required integration configuration fields.
 *
 * @param[in] data  Integration configuration data to validate.
 *
 * @return Validation result indicating success or the first detected error.
 */
static integration_config_response_t
integration_config_data_validate (integration_config_data_t data)
{
  if (data == NULL)
    return INTEGRATION_CONFIG_INVALID_DATA;
  if (str_blank (data->service_url))
    return INTEGRATION_CONFIG_MISSING_SERVICE_URL;

  if (str_blank (data->oidc_url))
    return INTEGRATION_CONFIG_MISSING_OIDC_URL;

  if (str_blank (data->oidc_client_id))
    return INTEGRATION_CONFIG_MISSING_OIDC_CLIENT_ID;

  if (str_blank (data->oidc_client_secret))
    return INTEGRATION_CONFIG_MISSING_OIDC_CLIENT_SECRET;

  return INTEGRATION_CONFIG_SUCCESS;
}

/**
 * @brief Create, update, or delete an integration configuration.
 *
 * @param[in] config  Integration configuration data.
 *
 * @return Result of the create, update, or delete operation.
 */
integration_config_response_t
modify_integration_config (integration_config_data_t config)
{
  integration_config_response_t response;
  lsc_crypt_ctx_t crypt_ctx = NULL;
  gchar *secret = NULL;
  char *encryption_key_uid = NULL;
  integration_config_t row_id;
  char *owner_uuid = NULL;
  user_t owner = 0;
  setting_value (SETTING_UUID_INTEGRATION_CONFIG_OWNER, &owner_uuid);
  if (owner_uuid == NULL)
    {
      return INTEGRATION_CONFIG_INVALID_OWNER;
    }
  if (strcmp (owner_uuid, current_credentials.uuid) != 0)
    {
      g_free (owner_uuid);
      return INTEGRATION_CONFIG_INVALID_OWNER;
    }

  find_resource_no_acl ("user", owner_uuid, &owner);
  g_free (owner_uuid);

  if (owner == 0)
    {
      return INTEGRATION_CONFIG_INVALID_OWNER;
    }

  if (!config || str_blank (config->uuid))
    return INTEGRATION_CONFIG_INVALID_DATA;

  if (find_resource ("integration_config", config->uuid, &row_id))
    return INTEGRATION_CONFIG_INTERNAL_ERROR;
  if (row_id == 0)
    return INTEGRATION_CONFIG_NOT_FOUND;

  if (integration_config_is_all_empty (config))
    return modify_integration_config_row (config, "");

  response = integration_config_data_validate (config);
  if (response != INTEGRATION_CONFIG_SUCCESS)
    return response;

  sql_begin_immediate ();

  encryption_key_uid = current_encryption_key_uid (TRUE);
  crypt_ctx = lsc_crypt_new (encryption_key_uid);
  free (encryption_key_uid);
  encryption_key_uid = NULL;

  secret = lsc_crypt_encrypt (crypt_ctx,
                              OIDC_CLIENT_SECRET_TYPE,
                              config->oidc_client_secret,
                              NULL);

  if (!secret)
    {
      sql_rollback ();
      lsc_crypt_release (crypt_ctx);
      return INTEGRATION_CONFIG_INVALID_DATA;
    }

  response = modify_integration_config_row (config, secret);

  g_free (secret);
  lsc_crypt_release (crypt_ctx);

  if (response != INTEGRATION_CONFIG_SUCCESS)
    {
      sql_rollback ();
      return response;
    }

  sql_commit ();
  return response;
}

/**
 * @brief Count number of integration_config in the database based on filter.
 *
 * @param get GET parameters to use for filtering.
 * @return Count of matching agents.
 */
int
integration_config_count (const get_data_t *get)
{
  static const char *extra_columns[] =
    INTEGRATION_CONFIG_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = INTEGRATION_CONFIG_ITERATOR_COLUMNS;

  return count ("integration_config", get, columns, NULL, extra_columns, 0, 0,
                0, TRUE);
}

/**
 * @brief Ensure the default security intelligence integration config exists.
 *
 * Checks whether the security intelligence export feature is enabled and whether
 * a valid integration config owner is configured. If the owner exists, creates
 * the security intelligence integration config for that user.
 */
void
check_db_integration_configs ()
{
  if (!feature_enabled (FEATURE_ID_SECURITY_INTELLIGENCE_EXPORT))
    return;

  char *owner_uuid = NULL;
  user_t owner;
  setting_value (SETTING_UUID_INTEGRATION_CONFIG_OWNER, &owner_uuid);
  if (!owner_uuid || str_blank (owner_uuid))
    return;

  find_resource_no_acl ("user", owner_uuid, &owner);
  if (owner == 0)
    {
      g_warning ("%s: integration user is not found", __func__);
      return;
    }
  create_security_intelligence_config (owner);
}

/**
 * @brief Check if an integration config is writable.
 *
 * @param config Resource identifier.
 * @return Always returns 1 (writable).
 */
int
integration_config_writable (integration_config_t config)
{
  (void) config;
  return 1;
}

/**
 * @brief Check if an integration config is currently in use.
 *
 * @param config Resource identifier.
 * @return 1 if the config is in use, 0 otherwise.
 */
int
integration_config_in_use (integration_config_t config)
{
  (void) config;
  return 0;
}

/**
 * @brief Initialize an iterator for integration configuration retrieval.
 *
 * @param[in,out] iterator  Iterator to initialize.
 * @param[in]     get       Get request data with optional filter criteria.
 *
 * @return 0 on success, 1 if the resource was not found, 2 if the filter
 *         was not found, or -1 on error.
 */
int
init_integration_config_iterator (iterator_t *iterator, get_data_t *get)
{
  g_return_val_if_fail (iterator, -1);
  g_return_val_if_fail (get, -1);

  static column_t columns[] = INTEGRATION_CONFIG_ITERATOR_COLUMNS;
  static const char *filter_columns[] =
    INTEGRATION_CONFIG_ITERATOR_FILTER_COLUMNS;

  gchar *quoted = NULL;
  gchar *where_clause = NULL;

  if (get->id)
    {
      quoted = sql_quote (get->id);
      where_clause = g_strdup_printf ("uuid = '%s'", quoted);
    }

  int ret = init_get_iterator (iterator, "integration_config", get, columns,
                               NULL, // no trash columns
                               filter_columns,
                               0,    // no trashcan
                               NULL, // no joins
                               where_clause, 0);

  g_free (where_clause);
  g_free (quoted);

  return ret;
}

/**
 * @brief Initialize an iterator for a single integration configuration.
 *
 * @param[in,out] iterator  Iterator to initialize.
 * @param[in]     uuid      UUID of the integration configuration.
 *
 * @return 0 on success, 1 if the resource was not found, 2 if the filter
 *         was not found, or -1 on error.
 */
int
init_integration_config_iterator_one (iterator_t *iterator, const gchar *uuid)
{
  g_return_val_if_fail (iterator, -1);
  g_return_val_if_fail (uuid, -1);

  get_data_t get;

  memset (&get, '\0', sizeof (get));
  get.id = g_strdup (uuid);
  get.filter = "owner=any";
  return init_integration_config_iterator (iterator, &get);
}

/**
 * @brief Get the decrypted OIDC client secret from an integration config iterator.
 *
 * @param[in,out] iterator  Iterator positioned on an integration config row.
 *
 * @return Decrypted OIDC client secret, or NULL if unavailable.
 */
const gchar *
integration_config_iterator_encrypted_oidc_client_secret (iterator_t *iterator)
{
  const gchar *secret = NULL;
  const gchar *unencrypted =
    integration_config_iterator_oidc_client_secret (iterator);
  if (!unencrypted)
    return NULL;

  /* Initialize encryption context. */
  if (!iterator->crypt_ctx)
    {
      char *encryption_key_uid = current_encryption_key_uid (TRUE);
      iterator->crypt_ctx = lsc_crypt_new (encryption_key_uid);
      free (encryption_key_uid);
    }

  return lsc_crypt_decrypt (iterator->crypt_ctx, secret,
                            OIDC_CLIENT_SECRET_TYPE);
}

/**
 * @brief Retrieve service_url from iterator.
 */
const char *
integration_config_iterator_service_url (iterator_t *iterator)
{
  return iterator_string (iterator, GET_ITERATOR_COLUMN_COUNT);
}

/**
 * @brief Retrieve service_url from iterator.
 */
const char *
integration_config_iterator_service_cacert (iterator_t *iterator)
{
  return iterator_string (iterator, GET_ITERATOR_COLUMN_COUNT + 1);
}

/**
 * @brief Retrieve oidc_url from iterator.
 */
const char *
integration_config_iterator_oidc_url (iterator_t *iterator)
{
  return iterator_string (iterator, GET_ITERATOR_COLUMN_COUNT + 2);
}

/**
 * @brief Retrieve oidc_client_id from iterator.
 */
const char *
integration_config_iterator_oidc_client_id (iterator_t *iterator)
{
  return iterator_string (iterator, GET_ITERATOR_COLUMN_COUNT + 3);
}

/**
 * @brief Retrieve oidc_client_secret from iterator.
 */
const char *
integration_config_iterator_oidc_client_secret (iterator_t *iterator)
{
  return iterator_string (iterator, GET_ITERATOR_COLUMN_COUNT + 4);
}