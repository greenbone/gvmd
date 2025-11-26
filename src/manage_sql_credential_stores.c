/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file manage_credential_stores.h
 * @brief SQL functions and iterator definitions for credential stores.
 *
 * This header provides iterator macros and function declarations used
 * for managing credential stores in the SQL layer of GVMD, including support
 * for trashcan handling and restoration.
 */

#include "gmp_base.h" // for log_event
#include "manage_acl.h"
#include "manage_credential_store_cyberark.h"
#include "manage_sql_credential_stores.h"
#include <gnutls/x509.h>
#include <gnutls/pkcs12.h>
#include <gvm/util/tlsutils.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Count the number of credential stores based on filter criteria.
 *
 * @param[in] get  Pointer to the get_data_t structure containing
 *                 filters and options.
 *
 * @return The number of matching credential stores.
 */
int
credential_store_count (const get_data_t *get)
{
  static const char *filter_columns[]
    = CREDENTIAL_STORE_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = CREDENTIAL_STORE_ITERATOR_COLUMNS;


  return count ("credential_store", get, columns, NULL, filter_columns, 0,
                NULL, 0, TRUE);
}

/**
 * @brief Initialize an iterator for retrieving credential stores.
 *
 * @param[in,out] iterator  Pointer to the iterator to initialize.
 * @param[in]     get       Pointer to the get_data_t structure containing
 *                          filters and options.
 *
 * @return 0 on success, non-zero on failure.
 */
int
init_credential_store_iterator (iterator_t *iterator, get_data_t *get)
{
  static const char *filter_columns[]
    = CREDENTIAL_STORE_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = CREDENTIAL_STORE_ITERATOR_COLUMNS;

  return init_get_iterator (iterator, "credential_store", get, columns, NULL,
                            filter_columns, 0, NULL, NULL, TRUE);
}

/**
 * @brief Get the host from a credential store iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Host, or NULL if iteration is complete.
 */
DEF_ACCESS (credential_store_iterator_version, GET_ITERATOR_COLUMN_COUNT);

/**
 * @brief Get whether a store is active from a credential store iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return 1 if active, 0 if not or iteration is complete.
 */
int
credential_store_iterator_active (iterator_t *iterator)
{
  if (iterator->done)
    return 0;
  return iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 1);
}

/**
 * @brief Get the host from a credential store iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Host, or NULL if iteration is complete.
 */
DEF_ACCESS (credential_store_iterator_host, GET_ITERATOR_COLUMN_COUNT + 2);

/**
 * @brief Get the path from a credential store iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Path, or NULL if iteration is complete.
 */
DEF_ACCESS (credential_store_iterator_path, GET_ITERATOR_COLUMN_COUNT + 3);

/**
 * @brief Get the port from a credential store iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Port, 0 if not set or -1 if iteration is complete.
 */
int
credential_store_iterator_port (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 4);
  return ret;
}

/**
 * @brief Initialize an iterator for retrieving credential store preferences.
 *
 * @param[in,out] iterator  Pointer to the iterator to initialize.
 * @param[in]     credential_store    The credential store to get data of.
 */
void
init_credential_store_preference_iterator (
    iterator_t *iterator, credential_store_t credential_store)
{
  init_iterator (iterator,
                 "SELECT name, secret, type, pattern, value, default_value,"
                 "       passphrase_name"
                 " FROM credential_store_preferences"
                 " WHERE credential_store = %llu"
                 " ORDER BY name",
                 credential_store);
}

/**
 * @brief Create a credential preference structure from an iterator.
 *
 * @param[in]  iterator  The iterator to get data from.
 *
 * @return The newly allocated preference.
 */
credential_store_preference_data_t *
credential_store_preference_from_iterator (iterator_t *iterator)
{
  return credential_store_preference_new (
    credential_store_preference_iterator_name (iterator),
    credential_store_preference_iterator_secret (iterator),
    credential_store_preference_iterator_type (iterator),
    credential_store_preference_iterator_pattern (iterator),
    credential_store_preference_iterator_decrypted_value (iterator),
    credential_store_preference_iterator_default_value (iterator),
    credential_store_preference_iterator_passphrase_name (iterator)
  );
}

/**
 * @brief Get the name from a credential store preference iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Name, or NULL if iteration is complete.
 */
DEF_ACCESS (credential_store_preference_iterator_name, 0);

/**
 * @brief Get whether the preference is secret from a credential store iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return TRUE if preference is secret, FALSE if not or iteration is complete.
 */
gboolean
credential_store_preference_iterator_secret (iterator_t *iterator)
{
  if (iterator->done)
    return FALSE;
  return iterator_int (iterator, 1) ? TRUE : FALSE;
}

/**
 * @brief Get the type from a credential store preference iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Type, or NULL if iteration is complete.
 */
credential_store_preference_type_t
credential_store_preference_iterator_type (iterator_t *iterator)
{
  if (iterator->done)
    return CREDENTIAL_STORE_PREFERENCE_TYPE_UNKNOWN;
  return iterator_int (iterator, 2);
}

/**
 * @brief Get the type from a credential store preference iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Type, or NULL if iteration is complete.
 */
const char *
credential_store_preference_iterator_type_name (iterator_t *iterator)
{
  credential_store_preference_type_t type;
  if (iterator->done)
    type = CREDENTIAL_STORE_PREFERENCE_TYPE_UNKNOWN;
  else
    type = iterator_int (iterator, 2);
  return credential_store_preference_type_name (type);
}

/**
 * @brief Get the pattern from a credential store preference iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Pattern, or NULL if iteration is complete.
 */
DEF_ACCESS (credential_store_preference_iterator_pattern, 3);

/**
 * @brief Get the value from a credential store preference iterator.
 *
 * This function will return NULL for encrypted preferences.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Value, or NULL if value is a secret or iteration is complete.
 */
const char *
credential_store_preference_iterator_value (iterator_t *iterator)
{
  if (iterator->done
      || credential_store_preference_iterator_secret (iterator))
    return NULL;
  return iterator_string (iterator, 4);
}

/**
 * @brief Get the decrypted value from a credential store preference iterator.
 *
 * This function will also return the value for non-encrypted preferences.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Value, or NULL if iteration is complete.
 */
const char *
credential_store_preference_iterator_decrypted_value (iterator_t *iterator)
{
  if (iterator->done)
    return NULL;
  else if (credential_store_preference_iterator_secret (iterator))
    {
      const char *encrypted;
      if (iterator->crypt_ctx == NULL)
        {
          char *encryption_key_uid = current_encryption_key_uid (TRUE);
          iterator->crypt_ctx = lsc_crypt_new (encryption_key_uid);
          free (encryption_key_uid);
        }
      encrypted = iterator_string (iterator, 4);
      if (encrypted == NULL)
        return NULL;
      else if (strcmp (encrypted, "") == 0)
        return "";
      else
        return lsc_crypt_decrypt (iterator->crypt_ctx, encrypted, "secret");
    }
  return iterator_string (iterator, 4);
}

/**
 * @brief Get the value from a credential store preference iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Value, or NULL if iteration is complete.
 */
const char *
credential_store_preference_iterator_default_value (iterator_t *iterator)
{
  if (iterator->done
      || credential_store_preference_iterator_secret (iterator))
    return NULL;
  return iterator_string (iterator, 5);
}

/**
 * @brief Get the passphrase name from a credential store preference iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Name of the passphrase preference, or NULL if none is set or
 *         iteration is complete.
 */
DEF_ACCESS (credential_store_preference_iterator_passphrase_name, 6);

/**
 * @brief Initialize an iterator for retrieving credential store selectors.
 *
 * @param[in,out] iterator  Pointer to the iterator to initialize.
 * @param[in]     credential_store    The credential store to get data of.
 */
void
init_credential_store_selector_iterator (iterator_t *iterator,
                                         credential_store_t credential_store)
{
  init_iterator (iterator,
                 "SELECT id, name, pattern, default_value"
                 " FROM credential_store_selectors"
                 " WHERE credential_store = %llu",
                 credential_store);
}

/**
 * @brief Create a credential selector structure from an iterator.
 *
 * @param[in]  iterator  The iterator to get data from.
 *
 * @return The newly allocated selector.
 */
credential_store_selector_data_t *
credential_store_selector_from_iterator (iterator_t *iterator,
                                         gboolean include_credential_types)
{
  credential_store_selector_data_t *selector;
  selector = credential_store_selector_new (
    credential_store_selector_iterator_name (iterator),
    credential_store_selector_iterator_pattern (iterator),
    credential_store_selector_iterator_default_value (iterator),
    credential_store_selector_iterator_resource_id (iterator)
  );

  if (include_credential_types)
    {
      iterator_t types_iter;
      init_credential_store_selector_type_iterator (&types_iter,
                                                    selector->rowid);
      while (next (&types_iter))
        {
          const char *type
            = credential_store_selector_type_iterator_type (&types_iter);
          credential_store_selector_add_credential_type (selector, type);
        }
      cleanup_iterator (&types_iter);
    }
  return selector;
}

/**
 * @brief Initialize an iterator for retrieving credential store selectors,
 *        limite to a given credential type.
 *
 * @param[in,out] iterator  Pointer to the iterator to initialize.
 * @param[in]     credential_store    The credential store to get data of.
 * @param[in]     credential_type     Credential type to limit selectors to.
 */
void
init_credential_store_selector_iterator_for_type (iterator_t *iterator,
                                                  credential_store_t
                                                    credential_store,
                                                  const char *credential_type)
{
  gchar *quoted_credential_type = sql_quote (credential_type);
  init_iterator (iterator,
                 "SELECT id, name, pattern, default_value"
                 " FROM credential_store_selectors"
                 " WHERE credential_store = %llu"
                 "  AND id IN (SELECT selector"
                 "             FROM credential_store_selector_types"
                 "             WHERE credential_type = '%s')",
                 credential_store,
                 quoted_credential_type);
  g_free (quoted_credential_type);
}

/**
 * @brief Get the resource rowid from a credential store selector iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Resource rowid, or 0 if iteration is complete.
 */
resource_t
credential_store_selector_iterator_resource_id (iterator_t *iterator)
{
  if (iterator->done)
    return 0;
  return iterator_int64 (iterator, 0);
}

/**
 * @brief Get the name from a credential store selector iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Name, or NULL if iteration is complete.
 */
DEF_ACCESS (credential_store_selector_iterator_name, 1);

/**
 * @brief Get the pattern from a credential store selector iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Pattern, or NULL if iteration is complete.
 */
DEF_ACCESS (credential_store_selector_iterator_pattern, 2);

/**
 * @brief Get the default value from a credential store selector iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Default value, or NULL if iteration is complete.
 */
DEF_ACCESS (credential_store_selector_iterator_default_value, 3);

/**
 * @brief Initialize an iterator for retrieving the credential types
 *        supported by a credential store selector.
 *
 * @param[in,out] iterator  Pointer to the iterator to initialize.
 * @param[in]     selector  The credential store selector to get types of of.
 */
void
init_credential_store_selector_type_iterator (iterator_t *iterator,
                                              resource_t selector)
{
  init_iterator (iterator,
                 "SELECT credential_type FROM credential_store_selector_types"
                 " WHERE selector = %llu",
                 selector);
}

/**
 * @brief Get the type from a credential store selector type iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Credential type, or NULL if iteration is complete.
 */
DEF_ACCESS (credential_store_selector_type_iterator_type, 0);

/**
 * @brief Return whether a credential_store is in use.
 *
 * @param[in]  credential_store  Credential Store row id.
 *
 * @return 1 if in use, else 0.
 */
int
credential_store_in_use (credential_store_t credential_store)
{
  return 1;
}

/**
 * @brief Return whether a credential_store is writable.
 *
 * @param[in]  credential_store  Credential Store row id.
 *
 * @return 1 if writable, else 0.
 */
int
credential_store_writable (credential_store_t credential_store)
{
  return 1;
}

/**
 * @brief Get the "active" status of a credential store.
 *
 * @param[in]  credential_store  The credential store to check.
 *
 * @return TRUE if active, FALSE if not.
 */
gboolean
credential_store_active (credential_store_t credential_store)
{
  return sql_int ("SELECT active FROM credential_stores WHERE id = %llu",
                  credential_store);
}

/**
 * @brief Get the host of a credential store.
 *
 * @param[in]  credential_store  The credential store to check.
 *
 * @return The host of the credential store. Caller must freed.
 */
char *
credential_store_host (credential_store_t credential_store)
{
  return sql_string ("SELECT host FROM credential_stores WHERE id = %llu",
                     credential_store);
}

/**
 * @brief Get the path of a credential store.
 *
 * @param[in]  credential_store  The credential store to check.
 *
 * @return The path of the credential store. Caller must freed.
 */
char *
credential_store_path (credential_store_t credential_store)
{
  return sql_string ("SELECT path FROM credential_stores WHERE id = %llu",
                     credential_store);
}

/**
 * @brief Return the port of a credential store.
 *
 * @param[in]  credential_store  Credential store.
 *
 * @return Credential store port, -1 if not found;
 */
int
credential_store_port (credential_store_t credential_store)
{
  int port;
  char *str;
  str = sql_string ("SELECT port FROM credential_stores WHERE id = %llu;",
                    credential_store);
  if (!str)
    return -1;
  port = atoi (str);
  g_free (str);
  return port;
}


/**
 * @brief Check if a host is valid for a credential store type.
 *
 * @param[in]  host                 The host string to check.
 * @param[in]  credential_store_id  The credential type to check.
 * @param[out] message              Output of error message if check fails.
 *
 * @return TRUE if host is valid, FALSE if not.
 */
static gboolean
credential_store_host_valid (const char *host,
                             const char *credential_store_id,
                             gchar **message)
{
  if (strcmp (host, "") == 0)
    {
      sql_rollback ();
      *message = g_strdup ("host must not be empty");
      return FALSE;
    }
  return TRUE;
}

/**
 * @brief Check if a path is valid for a credential store type.
 *
 * @param[in]  path                 The path string to check.
 * @param[in]  credential_store_id  The credential type to check.
 * @param[out] message              Output of error message if check fails.
 *
 * @return TRUE if path is valid, FALSE if not.
 */
static gboolean
credential_store_path_valid (const char *path,
                             const char *credential_store_id,
                             gchar **message)
{
  if (strcmp (path, "") == 0)
    {
      sql_rollback ();
      *message = g_strdup ("path must not be empty");
      return FALSE;
    }
  return TRUE;
}


/**
 * @brief Check if binary data of a credential store preference value is valid.
 *
 * @param[in]  name       Name of the preference
 * @param[in]  bin_value  The value as a gnutls datum
 * @param[in]  type       The data type of the value
 * @param[in]  passphrase Optional passphrase if value is an encrypted key.
 * @param[out] message    Message output in case the the data is invalid.
 *
 * @return TRUE if data is valid, FALSE otherwise.
 */
static gboolean
credential_store_preference_binary_value_is_valid (
  const char *name,
  gnutls_datum_t *bin_value,
  credential_store_preference_type_t type,
  const char *passphrase,
  gchar **message)
{
  int ret;
  switch (type)
  {
    case CREDENTIAL_STORE_PREFERENCE_TYPE_X509_CERTS:
      {
        gnutls_x509_crt_t *certs = NULL;
        unsigned int cert_count = 0;
        gnutls_x509_crt_fmt_t cert_format;

        cert_format = gvm_x509_format_from_data ((const char*)bin_value->data,
                                                 bin_value->size);
        ret = gnutls_x509_crt_list_import2 (&certs, &cert_count,
                                            bin_value, cert_format, 0);
        for (int i = 0; i < cert_count; i++)
          {
            gnutls_x509_crt_deinit (certs[i]);
          }
        gnutls_free (certs);
        if (ret != GNUTLS_E_SUCCESS)
          {
            *message = g_strdup_printf("'%s' is not a valid x509"
                                      " certificate chain: %s",
                                      name, gnutls_strerror (ret));
            return FALSE;
          }
        return TRUE;
      }
    case CREDENTIAL_STORE_PREFERENCE_TYPE_X509_PRIVKEY:
      {
        gboolean use_passphrase = passphrase && strcmp (passphrase, "")
                                  ? TRUE : FALSE;
        gnutls_x509_privkey_t key;
        gnutls_x509_crt_fmt_t key_format;

        key_format = gvm_x509_format_from_data ((const char*)bin_value->data,
                                                bin_value->size);
        gnutls_x509_privkey_init (&key);
        if (use_passphrase)
          ret = gnutls_x509_privkey_import2 (key, bin_value, key_format,
                                             passphrase, 0);
        else
          ret = gnutls_x509_privkey_import (key, bin_value, key_format);
        gnutls_x509_privkey_deinit (key);
        if (ret == GNUTLS_E_DECRYPTION_FAILED)
          {
            *message = g_strdup_printf("Private key '%s'"
                                       " could not be decrypted",
                                       name);
            return FALSE;
          }
        else if (ret != GNUTLS_E_SUCCESS)
          {
            *message = g_strdup_printf("'%s' is not a valid x509"
                                        " private key: %s",
                                        name, gnutls_strerror (ret));
            return FALSE;
          }
        return TRUE;
      }
    case CREDENTIAL_STORE_PREFERENCE_TYPE_PKCS12_FILE:
      {
        gboolean use_passphrase = passphrase && strcmp (passphrase, "")
                                  ? TRUE : FALSE;
        gnutls_x509_crt_fmt_t key_format;
        gnutls_pkcs12_t pkcs12;
        gnutls_x509_privkey_t privkey;
        gnutls_x509_crt_t *certs = NULL;
        unsigned int cert_count = 0;

        key_format = gvm_x509_format_from_data ((const char*)bin_value->data,
                                                bin_value->size);
        gnutls_pkcs12_init (&pkcs12);
        ret = gnutls_pkcs12_import (pkcs12, bin_value, key_format, 0);
        if (ret != GNUTLS_E_SUCCESS)
          {
            *message = g_strdup_printf("'%s' is not a valid PKCS12 file: %s",
                                        name, gnutls_strerror (ret));
            gnutls_pkcs12_deinit (pkcs12);
            return FALSE;
          }

        gnutls_x509_privkey_init (&privkey);
        ret = gnutls_pkcs12_simple_parse (pkcs12,
                                          use_passphrase ? passphrase : NULL,
                                          &privkey,
                                          &certs,
                                          &cert_count,
                                          NULL,
                                          NULL,
                                          NULL,
                                          0);
        for (int i = 0; i < cert_count; i++)
          {
            gnutls_x509_crt_deinit (certs[i]);
          }
        gnutls_x509_privkey_deinit (privkey);
        gnutls_pkcs12_deinit (pkcs12);

        if (ret != GNUTLS_E_SUCCESS)
          {
            *message = g_strdup_printf("could not get key and certificates"
                                       " from PKCS12 file '%s': %s",
                                        name, gnutls_strerror (ret));
            return FALSE;
          }
        return TRUE;
      }
    default:
      return TRUE;
  }
}

/**
 * @brief Check if a credential store preference value is valid.
 *
 * @param[in]  name       Name of the preference (for error messages).
 * @param[in]  value      Value to check the validity of.
 * @param[in]  type       Data type of the preference to check.
 * @param[in]  pattern    Pattern for validating string type preferences.
 * @param[in]  passphrase Passphrase if preference is an encrypted key or NULL.
 * @param[out] message    Output of error message if check fails.
 *
 * @return TRUE if preference is valid, FALSE if not.
 */
static gboolean
credential_store_preference_value_valid (const char *name,
                                         const char* value,
                                         credential_store_preference_type_t
                                           type,
                                         const char *pattern,
                                         const char *passphrase,
                                         gchar **message)
{
  switch (type)
  {
    case CREDENTIAL_STORE_PREFERENCE_TYPE_STRING:
      {
        if (pattern && strcmp (pattern, ""))
          {
            gboolean ret;
            GError *error = NULL;
            GRegex *string_regex = g_regex_new (pattern, 0, 0, &error);
            if (error)
              {
                g_warning ("%s: Preference %s has invalid pattern: %s",
                           __func__, name, error->message);
                g_error_free (error);
                *message = g_strdup_printf("internal error:"
                                           " invalid pattern for '%s'", name);
                return FALSE;
              }
            ret = g_regex_match (string_regex, "value", 0, NULL);
            g_regex_unref (string_regex);
            if (ret == FALSE)
              {
                *message = g_strdup_printf("'%s' does not match the"
                                           " expected pattern",
                                           name);
              }
            return ret;
          }
        return TRUE;
      }
    case CREDENTIAL_STORE_PREFERENCE_TYPE_INTEGER:
      {
        static GRegex *integer_regex = NULL;
        if (integer_regex == NULL)
          integer_regex = g_regex_new ("^-?[0-9]+$", 0, 0, NULL);

        if (g_regex_match (integer_regex, "value", 0, NULL) == 0)
          {
            *message = g_strdup_printf("'%s' must be an integer", name);
            return FALSE;
          }
        return TRUE;
      }
    case CREDENTIAL_STORE_PREFERENCE_TYPE_FLOAT:
      {
        static GRegex *float_regex = NULL;
        if (float_regex == NULL)
          float_regex = g_regex_new ("^-?[0-9]+(?:\\.[0-9]*)?$", 0, 0, NULL);

        if (g_regex_match (float_regex, "value", 0, NULL) == 0)
          {
            *message = g_strdup_printf("'%s' must be a floating point number",
                                       name);
            return FALSE;
          }
        return TRUE;
      }
    case CREDENTIAL_STORE_PREFERENCE_TYPE_BASE64:
    case CREDENTIAL_STORE_PREFERENCE_TYPE_X509_CERTS:
    case CREDENTIAL_STORE_PREFERENCE_TYPE_X509_PRIVKEY:
    case CREDENTIAL_STORE_PREFERENCE_TYPE_PKCS12_FILE:
      {
        int ret;
        gnutls_datum_t encoded, decoded;

        // Allow setting empty value
        if (strcmp (value, "") == 0)
          return TRUE;

        encoded.data = (unsigned char*) value;
        encoded.size = strlen (value);
        decoded.data = NULL;
        decoded.size = 0;

        ret = gnutls_base64_decode2 (&encoded, &decoded);
        if (ret != GNUTLS_E_SUCCESS)
          {
            *message = g_strdup_printf("'%s' is not valid Base64", name);
            gnutls_free (decoded.data);
            return FALSE;
          }
        ret = credential_store_preference_binary_value_is_valid (name,
                                                                 &decoded,
                                                                 type,
                                                                 passphrase,
                                                                 message);
        gnutls_free (decoded.data);
        return ret;
      }
    default:
      *message = g_strdup_printf("internal error: '%s' has unknown or"
                                 " invalid type %d", name, type);
      return FALSE;
  }
}

/**
 * @brief  Set a credential store preference.
 *
 * @param[in]  credential_store  Credential store to set the preference of.
 * @param[in]  pref_name         Name of the preference to set.
 * @param[in]  value             Preference value to set or NULL for default.
 */
static void
credential_store_set_preference (credential_store_t credential_store,
                                 const char *pref_name,
                                 const char *value,
                                 lsc_crypt_ctx_t crypt_ctx)
{
  gchar *quoted_pref_name = sql_quote (pref_name);
  if (value == NULL)
    sql ("UPDATE credential_store_preferences SET value = default_value"
         " WHERE credential_store = %llu AND name = ''",
         credential_store, pref_name);
  else if (sql_int ("SELECT secret FROM credential_store_preferences"
                    " WHERE credential_store = %llu AND name = '%s'",
                    credential_store, quoted_pref_name))
    {
      gchar *encrypted = lsc_crypt_encrypt (crypt_ctx, "secret", value, NULL);
      sql ("UPDATE credential_store_preferences SET value = '%s'"
           " WHERE credential_store = %llu AND name = '%s'",
           encrypted, credential_store, quoted_pref_name);
      g_free (encrypted);
    }
  else
    {
      gchar *quoted_value = sql_quote (value);
      sql ("UPDATE credential_store_preferences SET value = '%s'"
           " WHERE credential_store = %llu AND name = '%s'",
           quoted_value, credential_store, quoted_pref_name);
      g_free (quoted_value);
    }

  g_free (quoted_pref_name);
}

/**
 * @brief Collect the preferences of a credential store in a hashtable.
 *
 * @param[in]  credential_store  Credential store to get the preferences of.
 *
 * @return  The hashtable of preferences.
 */
GHashTable*
credential_store_get_preferences_hashtable (credential_store_t credential_store)
{
  GHashTable *preferences;
  iterator_t db_prefs_iter;

  preferences = g_hash_table_new_full (g_str_hash,
                                       g_str_equal,
                                       NULL,
                                       (GDestroyNotify)
                                         credential_store_preference_free);

  init_credential_store_preference_iterator (&db_prefs_iter, credential_store);
  while (next (&db_prefs_iter))
    {
      credential_store_preference_data_t *preference;
      preference = credential_store_preference_from_iterator (&db_prefs_iter);
      g_hash_table_replace (preferences,
                            g_strdup (preference->name),
                            preference);
    }
  cleanup_iterator (&db_prefs_iter);

  return preferences;
}

/**
 * @brief Update the preferences of a credential store.
 *
 * @param[in]  preference_values  Collection of preference values to update.
 * @param[in]  credential_store   Credential store the preferences belong to.
 * @param[out] message            Output of error message if check fails.
 *
 * @return 0 on success, -1 on error.
 */
static int
credential_store_update_preferences (GHashTable *preference_values,
                                     credential_store_t credential_store,
                                     gchar **message)
{

  GHashTable *old_preferences;
  GHashTableIter hash_table_iter;
  gchar *name, *value;
  char *encryption_key_uid;
  lsc_crypt_ctx_t crypt_ctx;

  old_preferences = credential_store_get_preferences_hashtable (credential_store);

  encryption_key_uid = current_encryption_key_uid (TRUE);
  crypt_ctx = lsc_crypt_new (encryption_key_uid);
  free (encryption_key_uid);

  g_hash_table_iter_init (&hash_table_iter, preference_values);
  while (g_hash_table_iter_next (&hash_table_iter,
                                 (gpointer*) &name,
                                 (gpointer*) &value))
    {
      credential_store_preference_data_t *preference;
      const char *passphrase;
      preference = g_hash_table_lookup (old_preferences, name);

      if (preference == NULL)
        {
          *message = g_strdup_printf ("'%s' is not a valid preference name"
                                      " for this credential store",
                                      name);
          g_hash_table_destroy (old_preferences);
          lsc_crypt_release (crypt_ctx);
          return -1;
        }

      if (preference->passphrase_name
          && strcmp (preference->passphrase_name, ""))
        {
          passphrase = g_hash_table_lookup (preference_values,
                                            preference->passphrase_name);
          if (passphrase == NULL)
            {
              credential_store_preference_data_t *passphrase_preference
                = g_hash_table_lookup (old_preferences,
                                       preference->passphrase_name);
              if (credential_store_preference_is_set (passphrase_preference))
                passphrase = passphrase_preference->value;
              else
                passphrase = NULL;
            }
        }
      else
        passphrase = NULL;

      if (value != NULL
            && credential_store_preference_value_valid (name,
                                                        value,
                                                        preference->type,
                                                        preference->pattern,
                                                        passphrase,
                                                        message) == FALSE)
        {
          g_hash_table_destroy (old_preferences);
          lsc_crypt_release (crypt_ctx);
          return -1;
        }

      credential_store_set_preference (credential_store,
                                       name,
                                       value,
                                       crypt_ctx);
    }

  lsc_crypt_release (crypt_ctx);
  g_hash_table_destroy (old_preferences);
  return 0;
}

/**
 * @brief Modify an existing credential store.
 *
 * @param[in]  credential_store_id  UUID of the credential store to modify.
 * @param[in]  active       Active status to set or NULL to keep old one.
 * @param[in]  host         Host to set or NULL to keep old one.
 * @param[in]  path         Path to set or NULL to keep old one.
 * @param[in]  port         Port to set or NULL to keep old one.
 * @param[in]  comment      Comment to set or NULL to keep old one.
 * @param[in]  preference_values  Preference values to set.
 * @param[out] message      Output for error message.
 */
modify_credential_store_return_t
modify_credential_store (const char *credential_store_id,
                         const char *active,
                         const char *host,
                         const char *path,
                         const char *port,
                         const char *comment,
                         GHashTable *preference_values,
                         gchar **message)
{
  *message = NULL;
  credential_store_t credential_store;

  if (credential_store_id == NULL || strcmp (credential_store_id, "") == 0)
    return MODIFY_CREDENTIAL_STORE_MISSING_ID;

  sql_begin_immediate ();
  if (acl_user_may ("modify_credential_store") == 0)
    {
      sql_rollback ();
      return MODIFY_CREDENTIAL_STORE_PERMISSION_DENIED;
    }

  if (find_resource_with_permission ("credential_store",
                                     credential_store_id,
                                     &credential_store,
                                     "get_credential_stores",
                                     0))
    {
      g_warning ("%s: Error getting credential store '%s'",
                 __func__, credential_store_id);
      sql_rollback ();
      return MODIFY_CREDENTIAL_STORE_INTERNAL_ERROR;
    }
  if (credential_store == 0)
    {
      sql_rollback ();
      return MODIFY_CREDENTIAL_STORE_NOT_FOUND;
    }

  if (host)
    {
      gchar *quoted_host;
      if (credential_store_host_valid (host, credential_store_id, message)
          == FALSE)
        {
          sql_rollback ();
          return MODIFY_CREDENTIAL_STORE_INVALID_HOST;
        }
      quoted_host = sql_quote (host);
      sql ("UPDATE credential_stores SET host = '%s' WHERE id = %llu",
           quoted_host, credential_store);
      g_free (quoted_host);
    }

  if (port)
    {
      if (strcmp (port, "") == 0)
        {
          sql ("UPDATE credential_stores SET port = NULL WHERE id = %llu",
               credential_store);
        }
      else
        {
          int iport = strtol (port, NULL, 10);
          if (iport <= 0 || iport > 65535)
            {
              sql_rollback ();
              return MODIFY_CREDENTIAL_STORE_INVALID_PORT;
            }
          sql ("UPDATE credential_stores SET port = '%d' WHERE id = %llu",
               iport, credential_store);
        }
    }

  if (path)
    {
      gchar *quoted_path;
      if (credential_store_path_valid (path, credential_store_id, message)
          == FALSE)
        {
          sql_rollback ();
          return MODIFY_CREDENTIAL_STORE_INVALID_PATH;
        }
      quoted_path = sql_quote (path);
      sql ("UPDATE credential_stores SET path = '%s' WHERE id = %llu",
           quoted_path, credential_store);
      g_free (quoted_path);
    }

  if (comment)
    {
      gchar *quoted_comment = sql_quote (comment);
      sql ("UPDATE credential_stores SET comment = '%s' WHERE id = %llu",
           quoted_comment, credential_store);
      g_free (quoted_comment);
    }

  if (active)
    {
      sql ("UPDATE credential_stores SET active = %d WHERE id = %llu",
           !!(strcmp (active, "") && strcmp (active, "0")),
           credential_store);
    }

  if (preference_values)
    {
      if (credential_store_update_preferences (preference_values,
                                               credential_store,
                                               message))
        {
          sql_rollback ();
          return MODIFY_CREDENTIAL_STORE_INVALID_PREFERENCE;
        }
    }

  sql_commit ();
  return MODIFY_CREDENTIAL_STORE_OK;
}

/**
 * @brief Create or update the base data of a credential store.
 *
 * If the credential store already exists, fields that can be modified by
 * users will only be overwritten by defaults if the current values are no
 * longer valid.
 *
 * @param[in]  credential_store_id  UUID of the credential store
 * @param[in]  name     Name of the credential store
 * @param[in]  host     Default host of the credential store
 * @param[in]  path     Default path of the credential store
 * @param[in]  version  Version of the credential store
 * @param[in]  owner    Owner if credential store is created
 * @param[out] credential_store   Output of the credential store row id
 * @param[out] created            Output if credential store was created
 *
 * @return 0 success, -1 failure.
 */
static int
create_or_update_credential_store_base (const char *credential_store_id,
                                        const char *name,
                                        const char *host,
                                        const char *path,
                                        const char *version,
                                        user_t owner,
                                        credential_store_t *credential_store,
                                        gboolean *created)
{
  if (find_resource_no_acl ("credential_store",
                            credential_store_id,
                            credential_store))
    {
      g_warning ("%s: Error getting credential store '%s'",
                 __func__, credential_store_id);
      sql_rollback ();
      return -1;
    }

  if (*credential_store == 0)
    {
      *created = TRUE;
      gchar *quoted_credential_store_id, *quoted_name, *quoted_version;
      gchar *quoted_host, *quoted_path;
      quoted_credential_store_id = sql_quote (credential_store_id);
      quoted_name = sql_quote (name);
      quoted_version = sql_quote (version);
      quoted_host = sql_quote (host);
      quoted_path = sql_quote (path);

      sql_int64 (credential_store,
                 "INSERT INTO credential_stores"
                 " (uuid, owner, name, comment, version,"
                 "  creation_time, modification_time,"
                 "  active, host, path)"
                 " VALUES"
                 " ('%s', %llu, '%s', '', '%s',"
                 "  m_now (), m_now (),"
                 "  0, '%s', '%s')"
                 " RETURNING id;",
                 quoted_credential_store_id,
                 owner,
                 quoted_name,
                 quoted_version,
                 quoted_host,
                 quoted_path);

      g_free (quoted_credential_store_id);
      g_free (quoted_name);
      g_free (quoted_version);
      g_free (quoted_host);
      g_free (quoted_path);
    }
  else
    {
      *created = FALSE;
      gchar *quoted_name = sql_quote (name);
      gchar *quoted_version = sql_quote (version);

      sql ("UPDATE credential_stores"
           " SET name = '%s', version = '%s',"
           " modification_time = m_now ()"
           " WHERE id = %llu;",
           quoted_name, quoted_version, *credential_store);
      g_free (quoted_name);
    }

  return 0;
}

/**
 * @brief Create or update a credential store preference
 *
 * To set the value of a preference to one given by a user, use
 *  credential_store_set_preference.
 *
 * If the preference already exists, the value will only be overwritten
 *  by the default if the current value is no longer valid.
 *
 * @param[in]  credential_store_id  UUID of the credential store (for messages).
 * @param[in]  credential_store     Rowid of the credential store.
 * @param[in]  new_preference       The new preference data to set
 * @param[in]  old_preference       The old preference data
 * @param[in]  passphrase           Optional passphrase for encrypted keys.
 */
static void
create_or_update_credential_store_preference (
  const char *credential_store_id,
  credential_store_t credential_store,
  credential_store_preference_data_t *new_preference,
  credential_store_preference_data_t *old_preference,
  const char *passphrase)
{
  gchar *message = NULL;
  credential_store_preference_data_t *reset_preference = NULL;
  gchar *quoted_name, *quoted_pattern, *quoted_value, *quoted_default_value;
  gchar *quoted_passphrase_name;
  quoted_name = sql_quote (new_preference->name);
  quoted_pattern = sql_quote (new_preference->pattern);
  quoted_value = sql_quote (new_preference->value);

  if (new_preference->secret
      && new_preference->default_value
      && strcmp (new_preference->default_value, ""))
    {
      g_warning ("%s: Secret '%s' of credential store %s"
                 " should have no default value",
                 __func__, new_preference->name, credential_store_id);
      quoted_default_value = g_strdup ("");
    }
  else
    quoted_default_value = sql_quote (new_preference->default_value);

  quoted_passphrase_name = sql_quote (new_preference->passphrase_name
                                      ? new_preference->passphrase_name
                                      : "");

  sql ("INSERT INTO credential_store_preferences"
       " (credential_store, name, secret, type, pattern, value, default_value,"
       "  passphrase_name)"
       " VALUES (%llu, '%s', %d, %d, '%s', '%s', '%s', '%s')"
       " ON CONFLICT (credential_store, name) DO UPDATE"
       " SET secret = EXCLUDED.secret,"
       "     type = EXCLUDED.type,"
       "     pattern = EXCLUDED.pattern,"
       "     default_value = EXCLUDED.default_value,"
       "     passphrase_name = EXCLUDED.passphrase_name",
       credential_store,
       quoted_name,
       new_preference->secret,
       new_preference->type,
       quoted_pattern,
       quoted_default_value,
       quoted_default_value,
       quoted_passphrase_name);

  g_free (quoted_name);
  g_free (quoted_pattern);
  g_free (quoted_value);
  g_free (quoted_default_value);

  if (old_preference == NULL)
    return;

  if (credential_store_preference_value_valid (new_preference->name,
                                               old_preference->value,
                                               new_preference->type,
                                               new_preference->pattern,
                                               passphrase,
                                               &message)
      == FALSE)
    {
      g_info ("Value of preference '%s' of credential store '%s'"
              " is no longer valid (%s)"
              " and is reset to the default.",
              new_preference->name, credential_store_id, message);

      reset_preference = new_preference;
    }
  else if (old_preference->secret != new_preference->secret)
    {
      if (new_preference->secret)
        g_info ("Value of preference '%s' of credential store '%s'"
                " is now encrypted.",
                new_preference->name, credential_store_id);
      else
        g_info ("Value of preference '%s' of credential store '%s'"
                " is now no longer encrypted.",
                new_preference->name, credential_store_id);

      reset_preference = old_preference;
    }

  if (reset_preference)
    {
      lsc_crypt_ctx_t crypt_ctx;
      char *encryption_key_uid = current_encryption_key_uid (TRUE);
      crypt_ctx = lsc_crypt_new (encryption_key_uid);
      free (encryption_key_uid);

      credential_store_set_preference (credential_store,
                                       reset_preference->name,
                                       reset_preference->value,
                                       crypt_ctx);
      lsc_crypt_release (crypt_ctx);
    }

}

/**
 * @brief Create or update a credential store selector.
 *
 * @param[in]  credential_store     Rowid of the credential store
 * @param[in]  new_selector         The new selector data to set
 */
static void
create_or_update_credential_store_selector (credential_store_t
                                              credential_store,
                                            credential_store_selector_data_t
                                              *new_selector)
{
  gchar *quoted_name, *quoted_pattern, *quoted_default_value;
  quoted_name = sql_quote (new_selector->name);
  quoted_pattern = sql_quote (new_selector->pattern);
  quoted_default_value = sql_quote (new_selector->default_value);
  resource_t selector;
  GList *current_item;

  sql ("INSERT INTO credential_store_selectors"
       " (credential_store, name, pattern, default_value)"
       " VALUES (%llu, '%s', '%s', '%s')"
       " ON CONFLICT (credential_store, name) DO UPDATE"
       " SET pattern = EXCLUDED.pattern,"
       "     default_value = EXCLUDED.default_value",
       credential_store, quoted_name, quoted_pattern, quoted_default_value);

  selector = sql_int64_0 ("SELECT id FROM credential_store_selectors"
                          " WHERE credential_store = %llu"
                          "   AND name = '%s'",
                          credential_store, quoted_name);

  sql ("DELETE FROM credential_store_selector_types"
       " WHERE selector = %llu", selector);
  current_item = new_selector->credential_types;
  while (current_item)
    {
      gchar *quoted_type = sql_quote (current_item->data);
      sql ("INSERT INTO credential_store_selector_types"
           " VALUES (%llu, '%s')",
           selector, quoted_type);
      g_free (quoted_type);
      current_item = current_item->next;
    }

  g_free (quoted_name);
  g_free (quoted_pattern);
  g_free (quoted_default_value);
}

/**
 * @brief Create a new credential store or update an existing one.
 *
 * For modifications by users, use modify_credential_store.
 *
 * @param[in]  credential_store_id  UUID of the credential store
 * @param[in]  name     Name of the credential store
 * @param[in]  host     Default host of the credential store
 * @param[in]  path     Default path of the credential store
 * @param[in]  version  Version of the credential store
 * @param[in]  preferences  List of preferences of the credential store
 * @param[in]  selectors    List of selectors of the credential store
 * @param[in]  owner    Owner of the credential store if it is newly created
 *
 * @return 0 success, -1 error.
 */
int
create_or_update_credential_store (const char *credential_store_id,
                                   const char *name,
                                   const char *host,
                                   const char *path,
                                   const char *version,
                                   GList *preferences,
                                   GList *selectors,
                                   user_t owner)
{
  gboolean created = FALSE;
  credential_store_t credential_store = 0;
  GList *current_list_item;
  GHashTable *old_preferences;

  sql_begin_immediate ();

  // Update data in the base "credential_store" table
  if (create_or_update_credential_store_base (credential_store_id,
                                              name,
                                              host,
                                              path,
                                              version,
                                              owner,
                                              &credential_store,
                                              &created))
    {
      sql_rollback ();
      return -1;
    }

  // Update preferences
  old_preferences
    = credential_store_get_preferences_hashtable (credential_store);
  current_list_item = preferences;
  while (current_list_item)
    {
      credential_store_preference_data_t *new_preference, *old_preference;
      const char *passphrase;

      new_preference = current_list_item->data;
      old_preference = g_hash_table_lookup (old_preferences,
                                            new_preference->name);

      if (new_preference->passphrase_name
          && strcmp (new_preference->passphrase_name, ""))
        {
          // New secrets should be empty by default, so only old preferences
          // have to be checked for an existing passphrase.
          credential_store_preference_data_t *passphrase_preference
            = g_hash_table_lookup (old_preferences,
                                   new_preference->passphrase_name);
          if (passphrase_preference)
            passphrase = passphrase_preference->value;
          else
            passphrase = NULL;
        }
      else
        passphrase = NULL;

      create_or_update_credential_store_preference (credential_store_id,
                                                    credential_store,
                                                    new_preference,
                                                    old_preference,
                                                    passphrase);

      current_list_item = current_list_item->next;
    }
  g_hash_table_destroy (old_preferences);

  // Update selectors
  current_list_item = selectors;
  while (current_list_item)
    {
      credential_store_selector_data_t *new_selector;
      new_selector = current_list_item->data;
      create_or_update_credential_store_selector (credential_store,
                                                  new_selector);
      current_list_item = current_list_item->next;
    }

  log_event ("credential_store",
             "Credential Store",
             credential_store_id,
             created ? "created" : "modified");

  return 0;
}

/**
 * @brief Verifies the connection of a credential store.
 *
 * @param[in]  credential_store_id  The UUID of the credential store to verify.
 * @param[out] message              Error message output.
 *
 * @return A verify_credential_store_return_t return code.
 */
verify_credential_store_return_t
verify_credential_store (const char *credential_store_id,
                         gchar **message)
{
  credential_store_t credential_store;
  gchar *host, *path;
  int port;
  credential_store_verify_func_t verify_func;
  GHashTable *preferences;
  int ret;

  if (credential_store_id == NULL || strcmp (credential_store_id, "") == 0)
    return VERIFY_CREDENTIAL_STORE_MISSING_ID;

  if (acl_user_may ("verify_credential_store") == 0)
    {
      return VERIFY_CREDENTIAL_STORE_PERMISSION_DENIED;
    }

  if (find_resource_with_permission ("credential_store",
                                     credential_store_id,
                                     &credential_store,
                                     "get_credential_stores",
                                     0))
    {
      g_warning ("%s: Error getting credential store '%s'",
                 __func__, credential_store_id);
      return VERIFY_CREDENTIAL_STORE_INTERNAL_ERROR;
    }

  if (credential_store == 0)
    return VERIFY_CREDENTIAL_STORE_NOT_FOUND;

  if (strcmp (credential_store_id, CREDENTIAL_STORE_UUID_CYBERARK) == 0)
    verify_func = verify_cyberark_credential_store;
  else
    {
      g_warning ("%s: Error getting connector for credential store '%s'",
                 __func__, credential_store_id);
      return VERIFY_CREDENTIAL_STORE_CONNECTOR_ERROR;
    }

  host = credential_store_host (credential_store);
  path = credential_store_path (credential_store);
  port = credential_store_port (credential_store);
  preferences = credential_store_get_preferences_hashtable (credential_store);

  ret = verify_func (host, path, port, preferences, message);

  free (host);
  g_hash_table_destroy (preferences);

  return ret;
}

/**
 * @brief Find a credential store given a UUID.
 *
 * This does not do any permission checks.
 *
 * @param[in]   uuid              UUID of the credential store.
 * @param[out]  credential_store  Credential store return,
 *                                 0 if no such credential store.
 *
 * @return FALSE on success (including if no such store), TRUE on error.
 */
gboolean
find_credential_store_no_acl (const char *uuid,
                              credential_store_t *credential_store)
{
  gchar *quoted_uuid;

  quoted_uuid = sql_quote (uuid);
  switch (sql_int64 (credential_store,
                     "SELECT id FROM credential_stores WHERE uuid = '%s';",
                     quoted_uuid))
    {
      case 0:
        break;
      case 1:        /* Too few rows in result of query. */
        *credential_store = 0;
        break;
      default:       /* Programming error. */
        assert (0);
      case -1:
        g_free (quoted_uuid);
        return TRUE;
        break;
    }

  g_free (quoted_uuid);
  return FALSE;
}