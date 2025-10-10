/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file manage_credential_stores.c
 * @brief GVM manage layer: Credential stores.
 *
 * General management headers of credential stores.
 */

#include "manage_credential_stores.h"
#include <gvm/util/tlsutils.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Get a name string for a given credential store preference data type.
 *
 * @param[in]  type  The type to get the name of.
 *
 * @return The name string.
 */
const char *
credential_store_preference_type_name (credential_store_preference_type_t type)
{
  switch (type)
    {
      case CREDENTIAL_STORE_PREFERENCE_TYPE_STRING:
        return "string";
      case CREDENTIAL_STORE_PREFERENCE_TYPE_INTEGER:
        return "integer";
      case CREDENTIAL_STORE_PREFERENCE_TYPE_FLOAT:
        return "float";
      case CREDENTIAL_STORE_PREFERENCE_TYPE_BASE64:
        return "base64";
      case CREDENTIAL_STORE_PREFERENCE_TYPE_X509_CERTS:
        return "x509_certs";
      case CREDENTIAL_STORE_PREFERENCE_TYPE_X509_PRIVKEY:
        return "x509_privkey";
      case CREDENTIAL_STORE_PREFERENCE_TYPE_PKCS12_FILE:
        return "pkcs12_file";
      default:
        return "unknown";
    }
}

/**
 * @brief Create a new credential store preference data structure.
 * 
 * @param[in]  name           Name of the preference
 * @param[in]  secret         Whether the preference is an encrypted secret
 * @param[in]  type           The data type of the preference
 * @param[in]  pattern        The regex pattern for string preferences
 * @param[in]  value          The current value of the preference
 * @param[in]  default_value  The default value of the preference
 * 
 * @return The newly allocated preference data structure.
 */
credential_store_preference_data_t *
credential_store_preference_new (const char *name,
                                 gboolean secret,
                                 credential_store_preference_type_t type,
                                 const char *pattern,
                                 const char *value,
                                 const char *default_value,
                                 const char *passphrase_name)
{
  credential_store_preference_data_t *new_pref
    = g_malloc0 (sizeof (credential_store_preference_data_t));

  new_pref->name = name ? g_strdup (name) : NULL;
  new_pref->secret = secret;
  new_pref->type = type;
  new_pref->pattern = pattern ? g_strdup (pattern) : NULL;
  new_pref->value = value ? g_strdup (value) : NULL;
  new_pref->default_value = default_value ? g_strdup (default_value) : NULL;
  new_pref->passphrase_name 
    = passphrase_name ? g_strdup (passphrase_name) : NULL;

  return new_pref;
}

/**
 * @brief Free a credential store preference data structure and its fields.
 * 
 * @param[in]  preference  The preference struct to free.
 */
void
credential_store_preference_free (credential_store_preference_data_t *preference)
{
  g_free (preference->name);
  g_free (preference->pattern);
  g_free (preference->value);
  g_free (preference->default_value);
  g_free (preference->passphrase_name);
  g_free (preference);
}

/**
 * @brief Check if the preference has a non-empty value.
 * 
 * @param[in]  preference  The preference to check.
 * 
 * @return TRUE if the prefrence has a non-empty value, FALSE otherwise.
 */
gboolean
credential_store_preference_is_set
  (credential_store_preference_data_t *preference)
{
  if (preference
      && preference->value
      && strcmp (preference->value, ""))
    return TRUE;
  else
    return FALSE;
}

/**
 * @brief Create a new credential store selector data structure.
 * 
 * @param[in]  name           Name of the selector
 * @param[in]  pattern        The regex pattern for selector strings
 * @param[in]  default_value  The default value of the selector
 * 
 * @return The newly allocated preference data structure.
 */
credential_store_selector_data_t *
credential_store_selector_new (const char *name,
                               const char *pattern,
                               const char *default_value,
                               resource_t rowid)
{
  credential_store_selector_data_t *new_selector
    = g_malloc0 (sizeof (credential_store_selector_data_t));

  new_selector->name = name ? g_strdup (name) : NULL;
  new_selector->pattern = pattern ? g_strdup (pattern) : NULL;
  new_selector->default_value = default_value ? g_strdup (default_value) : NULL;
  new_selector->rowid = rowid;
  new_selector->credential_types = NULL;

  return new_selector;
}

/**
 * @brief Add a credential type to a credential store selector data structure.
 * 
 * @param[in]  selector             The selector to add to
 * @param[in]  new_credential_type  The credential type to add
 */
void
credential_store_selector_add_credential_type (credential_store_selector_data_t
                                                 *selector,
                                               const char *new_credential_type)
{
  selector->credential_types = g_list_append (selector->credential_types,
                                              g_strdup (new_credential_type));
}

/**
 * @brief Free a credentials store selector data structure
 * 
 * @param[in]  selector  The selector data to free.
 */
void
credential_store_selector_free (credential_store_selector_data_t *selector)
{
  g_free (selector->name);
  g_free (selector->pattern);
  g_free (selector->default_value);
  g_list_free_full (selector->credential_types, g_free);
  g_free (selector);
}

/**
 * @brief Evaluate a PKCS12 credential store prefrerence, extracting
 *        the key and certificate data as PEM strings.
 *
 * Output parameters for unused parts of the PKCS12 file can be NULL
 *  to only extract required data.
 * If all output parameters are NULL the function will still check if
 *  the data preference can be decoded, parsed and decrypted.
 *
 * @param[in]  preference       The preference to evaluate
 * @param[in]  passphrase       Optional Passphrase to decrypt PKCS12 file
 * @param[out] privkey_out      Optional private key output
 * @param[out] cert_chain_out   Optional certificate chain output
 * @param[out] extra_certs_out  Optional extra certificates output
 * @param[out] crl_out          Optional certififcate revocation list output
 * @param[out] message          Error message output
 *
 * @return 0 if valid, -1 on error or if invalid
 */
int
eval_pkcs12_credential_store_preference (credential_store_preference_data_t
                                          *preference,
                                         const char *passphrase,
                                         gchar **privkey_out,
                                         gchar **cert_chain_out,
                                         gchar **extra_certs_out,
                                         gchar **crl_out,
                                         gchar **message)
{
  int ret;
  gnutls_datum_t decoded_data = { .data = NULL, .size = 0 };
  gnutls_x509_crt_fmt_t crt_format;
  gnutls_pkcs12_t pkcs12;

  ret = gvm_base64_to_gnutls_datum (preference->value, &decoded_data);
  if (ret)
    {
      if (message)
        *message = g_strdup_printf ("could not decode '%s': %s",
                                    preference->name,
                                    gnutls_strerror (ret));
      return -1;
    }

  crt_format = gvm_x509_format_from_data ((const char*) decoded_data.data,
                                          decoded_data.size);
  
  gnutls_pkcs12_init (&pkcs12);
  ret = gnutls_pkcs12_import (pkcs12, &decoded_data, crt_format, 0);
  if (ret)
    {
      if (message)
        *message = g_strdup_printf ("could not import '%s': %s",
                                    preference->name,
                                    gnutls_strerror (ret));
      gnutls_pkcs12_deinit (pkcs12);
      return -1;
    }

  ret = gvm_pkcs12_to_pem (pkcs12, passphrase,
                           privkey_out, cert_chain_out,
                           extra_certs_out, crl_out);
  gnutls_pkcs12_deinit (pkcs12);

  if (ret)
    {
      if (message)
        *message = g_strdup_printf ("could not convert '%s' to PEM",
                                    preference->name);
      return -1;
    }
  return 0;
}

/**
 * @brief Evaluate a private key credential store prefrerence, extracting
 *        the key as a decrypted PEM string.
 *
 * If the PEM output parameter is NULL the function will still check if
 *  the data preference can be decoded, parsed and decrypted.
 *
 * @param[in]  preference       The preference to evaluate
 * @param[in]  passphrase       Optional Passphrase to decrypt PKCS12 file
 * @param[out] privkey_out      Optional private key output
 * @param[out] message          Error message output
 *
 * @return 0 if valid, -1 on error or if invalid
 */
int
eval_privkey_credential_store_preference (credential_store_preference_data_t
                                           *preference,
                                          const char *passphrase,
                                          gchar **privkey_out,
                                          gchar **message)
{
  int ret;
  gnutls_datum_t decoded_data = { .data = NULL, .size = 0 };
  gnutls_x509_crt_fmt_t crt_format;
  gnutls_x509_privkey_t privkey;

  ret = gvm_base64_to_gnutls_datum (preference->value, &decoded_data);
  if (ret)
    {
      if (message)
        *message = g_strdup_printf ("could not decode '%s': %s",
                                    preference->name,
                                    gnutls_strerror (ret));
      return -1;
    }

  crt_format = gvm_x509_format_from_data ((const char*) decoded_data.data,
                                          decoded_data.size);
  
  gnutls_x509_privkey_init (&privkey);
  ret = gnutls_x509_privkey_import2 (privkey, &decoded_data, crt_format,
                                     passphrase, 0);
  if (ret)
    {
      if (message)
        *message = g_strdup_printf ("could not import '%s': %s",
                                    preference->name,
                                    gnutls_strerror (ret));
      gnutls_x509_privkey_deinit (privkey);
      return -1;
    }

  if (privkey_out)
    {
      *privkey_out = gvm_x509_privkey_to_pem (privkey);

      if (privkey_out && *privkey_out == NULL)
        {
          gnutls_x509_privkey_deinit (privkey);

          if (message)
            *message = g_strdup_printf ("could not convert '%s' to PEM",
                                        preference->name);
          return -1;
        }
    }

  gnutls_x509_privkey_deinit (privkey);
  return 0;
}

/**
 * @brief Evaluate a certificate list credential store prefrerence, extracting
 *        the certificate data as PEM strings.
 *
 * If the cert output parameter is NULL the function will still check if
 *  the data preference can be decoded and parsed.
 *
 * @param[in]  preference       The preference to evaluate
 * @param[in]  passphrase       Optional Passphrase to decrypt PKCS12 file
 * @param[out] certs_out        Optional certificate list output
 * @param[out] message          Error message output
 *
 * @return 0 if valid, -1 on error or if invalid
 */
int
eval_certs_credential_store_preference (credential_store_preference_data_t
                                          *preference,
                                        gchar **certs_out,
                                        gchar **message)
{
  int ret;
  gnutls_datum_t decoded_data = { .data = NULL, .size = 0 };
  gnutls_x509_crt_fmt_t crt_format;
  gnutls_x509_crt_t *certs = NULL;
  unsigned int certs_count = 0;

  ret = gvm_base64_to_gnutls_datum (preference->value, &decoded_data);
  if (ret)
    {
      if (message)
        *message = g_strdup_printf ("could not decode '%s': %s",
                                    preference->name,
                                    gnutls_strerror (ret));
      return -1;
    }

  crt_format = gvm_x509_format_from_data ((const char*) decoded_data.data,
                                          decoded_data.size);

  ret = gnutls_x509_crt_list_import2 (&certs, &certs_count,
                                      &decoded_data, crt_format, 0);
  if (ret)
    {
      if (message)
        *message = g_strdup_printf ("could not import '%s': %s",
                                    preference->name,
                                    gnutls_strerror (ret));
      return -1;
    }

  if (certs_out)
    {
      *certs_out = gvm_x509_cert_list_to_pem (certs, certs_count);
      if (*certs_out == NULL)
        {
          gvm_x509_cert_list_free (certs, certs_count);
          if (message)
            *message = g_strdup_printf ("could not convert '%s' to PEM",
                                        preference->name);
          return -1;
        }
    }

  return 0;
}
