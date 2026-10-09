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

#include "manage_acl.h"
#include "manage_credentials.h"
#include "manage_runtime_flags.h"
#include "manage_sql.h"
#include "manage_sql_credential_stores.h"
#include "manage_sql_resources.h"
#include "manage_sql_credentials.h"
#include "lsc_user.h"

#include <ctype.h>
#include <gnutls/x509.h> /* for gnutls_x509_crt_... */

#include <gvm/base/hosts.h>
#include <gvm/util/fileutils.h>
#include <gvm/util/gpgmeutils.h>
#include <gvm/util/serverutils.h>
#include <gvm/util/sshutils.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Length of password generated in create_credential.
 */
#define PASSWORD_LENGTH 10

typedef enum
{
  CREDENTIAL_TYPE_UP,
  CREDENTIAL_TYPE_PW,
  CREDENTIAL_TYPE_USK,
  CREDENTIAL_TYPE_CC,
  CREDENTIAL_TYPE_PGP,
  CREDENTIAL_TYPE_SMIME,
  CREDENTIAL_TYPE_SNMP,
  CREDENTIAL_TYPE_KRB5,

#if ENABLE_CREDENTIAL_STORES
  CREDENTIAL_TYPE_CS_UP,
  CREDENTIAL_TYPE_CS_PW,
  CREDENTIAL_TYPE_CS_USK,
  CREDENTIAL_TYPE_CS_CC,
  CREDENTIAL_TYPE_CS_PGP,
  CREDENTIAL_TYPE_CS_SMIME,
  CREDENTIAL_TYPE_CS_SNMP,
  CREDENTIAL_TYPE_CS_KRB5
#endif
} credential_type_t;

/**
 * @brief Reset the credential data structure.
 *
 * @param[in,out] data  Pointer to the credential data structure to reset.
 *
 * This function frees all dynamically allocated fields within the
 * credential_data_t structure and sets them to NULL.
 */
void
credential_data_reset (credential_data_t *data)
{
  if (data == NULL)
    return;

  g_free (data->credential_id);
  g_free (data->name);
  g_free (data->comment);
  g_free (data->login);
  g_free (data->password);
  g_free (data->key_phrase);
  g_free (data->key_private);
  g_free (data->key_public);
  g_free (data->certificate);
  g_free (data->community);
  g_free (data->auth_algorithm);
  g_free (data->privacy_password);
  g_free (data->privacy_algorithm);
  g_free (data->kdc);
  array_free (data->kdcs);
  g_free (data->realm);
  g_free (data->type);
  g_free (data->allow_insecure);

#if ENABLE_CREDENTIAL_STORES
  g_free (data->credential_store_id);
  g_free (data->vault_id);
  g_free (data->host_identifier);
  g_free (data->privacy_host_identifier);
#endif

  memset (data, 0, sizeof (*data));
}

/**
 * @brief Resolve the explicit credential type, including whether
 *        it uses a credential store.
 *
 * @param[in]  type       Credential type.
 * @param[out] resolved  Pointer to store the resolved credential type.
 *
 * @return CREDENTIAL_OK if the type was successfully resolved,
 *         A credential_return_t error code otherwise.
 */
static credential_return_t
credential_type_from_string (const gchar *type,
                             credential_type_t *resolved)
{
  if (resolved == NULL)
    return CREDENTIAL_INTERNAL_ERROR;

  if (type == NULL)
    return CREDENTIAL_UNSUPPORTED_TYPE;

  if (g_str_equal (type, "up"))
    *resolved = CREDENTIAL_TYPE_UP;
  else if (g_str_equal (type, "usk"))
    *resolved = CREDENTIAL_TYPE_USK;
  else if (g_str_equal (type, "snmp"))
    *resolved = CREDENTIAL_TYPE_SNMP;
  else if (g_str_equal (type, "krb5"))
    *resolved = CREDENTIAL_TYPE_KRB5;
  else if (g_str_equal (type, "cc"))
    *resolved = CREDENTIAL_TYPE_CC;
  else if (g_str_equal (type, "pw"))
    *resolved = CREDENTIAL_TYPE_PW;
  else if (g_str_equal (type, "pgp"))
    *resolved = CREDENTIAL_TYPE_PGP;
  else if (g_str_equal (type, "smime"))
    *resolved = CREDENTIAL_TYPE_SMIME;

#if ENABLE_CREDENTIAL_STORES
  else if (g_str_equal (type, "cs_up"))
    *resolved = CREDENTIAL_TYPE_CS_UP;
  else if (g_str_equal (type, "cs_usk"))
    *resolved = CREDENTIAL_TYPE_CS_USK;
  else if (g_str_equal (type, "cs_snmp"))
    *resolved = CREDENTIAL_TYPE_CS_SNMP;
  else if (g_str_equal (type, "cs_krb5"))
    *resolved = CREDENTIAL_TYPE_CS_KRB5;
  else if (g_str_equal (type, "cs_cc"))
    *resolved = CREDENTIAL_TYPE_CS_CC;
  else if (g_str_equal (type, "cs_pw"))
    *resolved = CREDENTIAL_TYPE_CS_PW;
  else if (g_str_equal (type, "cs_pgp"))
    *resolved = CREDENTIAL_TYPE_CS_PGP;
  else if (g_str_equal (type, "cs_smime"))
    *resolved = CREDENTIAL_TYPE_CS_SMIME;
#endif
  else
    return CREDENTIAL_UNSUPPORTED_TYPE;

  return CREDENTIAL_OK;
}

/**
 * @brief Check that a string represents a valid public key or certificate.
 *
 * @param[in]  key_str     Key string.
 * @param[in]  key_types   GArray of the data types to check for.
 * @param[in]  protocol    The GPG protocol to check.
 *
 * @return 0 if valid, 1 otherwise.
 */
static int
try_gpgme_import (const char *key_str, GArray *key_types,
                  gpgme_protocol_t protocol)
{
  int ret = 0;
  gpgme_ctx_t ctx;
  char gpg_temp_dir[] = "/tmp/gvmd-gpg-XXXXXX";

  if (mkdtemp (gpg_temp_dir) == NULL)
    {
      g_warning ("%s: mkdtemp failed", __func__);
      return -1;
    }

  gpgme_new (&ctx);
  gpgme_ctx_set_engine_info (ctx, protocol, NULL, gpg_temp_dir);
  gpgme_set_protocol (ctx, protocol);

  ret = gvm_gpg_import_many_types_from_string (ctx, key_str, -1, key_types);

  gpgme_release (ctx);
  gvm_file_remove_recurse (gpg_temp_dir);

  return ret != 0;
}

/**
 * @brief Check that a string represents a valid Public Key.
 *
 * @param[in]  key_str  Public Key string.
 *
 * @return 0 if valid, 1 otherwise.
 */
static int
check_public_key (const char *key_str)
{
  int ret;
  const gpgme_data_type_t types_ptr[1] = {GPGME_DATA_TYPE_PGP_KEY};
  GArray *key_types = g_array_new (FALSE, FALSE, sizeof (gpgme_data_type_t));

  g_array_append_vals (key_types, types_ptr, 1);
  ret = try_gpgme_import (key_str, key_types, GPGME_PROTOCOL_OPENPGP);
  g_array_free (key_types, TRUE);

  return ret;
}

/**
 * @brief Check that a string represents a valid S/MIME Certificate.
 *
 * @param[in]  cert_str     Certificate string.
 *
 * @return 0 if valid, 1 otherwise.
 */
static int
check_certificate_smime (const char *cert_str)
{
  int ret;
  const gpgme_data_type_t types_ptr[2] = {GPGME_DATA_TYPE_X509_CERT,
                                          GPGME_DATA_TYPE_CMS_OTHER};
  GArray *key_types = g_array_new (FALSE, FALSE, sizeof (gpgme_data_type_t));

  g_array_append_vals (key_types, types_ptr, 2);
  ret = try_gpgme_import (cert_str, key_types, GPGME_PROTOCOL_CMS);
  g_array_free (key_types, TRUE);

  return ret;
}

/**
 * @brief Check that a string represents a valid x509 Certificate.
 *
 * @param[in]  cert_str     Certificate string.
 *
 * @return 0 if valid, 1 otherwise.
 */
int
check_certificate_x509 (const char *cert_str)
{
  gnutls_x509_crt_t crt;
  gnutls_datum_t data;
  int ret = 0;

  assert (cert_str);
  if (gnutls_x509_crt_init (&crt))
    return 1;
  data.size = strlen (cert_str);
  data.data = (void *) g_strdup (cert_str);
  if (gnutls_x509_crt_import (crt, &data, GNUTLS_X509_FMT_PEM))
    {
      gnutls_x509_crt_deinit (crt);
      g_free (data.data);
      return 1;
    }

  if (time (NULL) > gnutls_x509_crt_get_expiration_time (crt))
    {
      g_warning ("Certificate expiration time passed");
      ret = 1;
    }
  if (time (NULL) < gnutls_x509_crt_get_activation_time (crt))
    {
      g_warning ("Certificate activation time in the future");
      ret = 1;
    }
  g_free (data.data);
  gnutls_x509_crt_deinit (crt);
  return ret;
}

/**
 * @brief Copy a credential from an existing one.
 *
 * @param[in]  name                 Name of new Credential. NULL to copy
 *                                  from existing.
 * @param[in]  comment              Comment on new Credential. NULL to copy
 *                                  from existing.
 * @param[in]  credential_id        UUID of existing Credential.
 * @param[out] new_credential       New Credential.
 *
 * @return A credential_return_t return code.
 */
credential_return_t
copy_credential (const char *name,
                 const char *comment,
                 const char *credential_id,
                 credential_t *new_credential)
{
  credential_return_t result;
  int ret;

  if (new_credential == NULL)
    return CREDENTIAL_INTERNAL_ERROR;

  *new_credential = 0;

  if (credential_id == NULL || credential_id[0] == '\0')
    return CREDENTIAL_NOT_FOUND;

  assert (current_credentials.uuid);

  sql_begin_immediate ();

  ret = copy_credential_rows (name,
                              comment,
                              credential_id,
                              new_credential);

  switch (ret)
    {
      case 0:
        result = CREDENTIAL_OK;
        break;

      case 1:
        result = CREDENTIAL_NAME_ALREADY_EXISTS;
        break;

      case 2:
        result = CREDENTIAL_NOT_FOUND;
        break;

      case 99:
        result = CREDENTIAL_PERMISSION_DENIED;
        break;

      case -1:
      default:
        result = CREDENTIAL_INTERNAL_ERROR;
        break;
    }

  if (result == CREDENTIAL_OK)
    sql_commit ();
  else
    {
      *new_credential = 0;
      sql_rollback ();
    }

  return result;
}

/**
 * @brief Check that a string represents a valid certificate.
 *
 * The type of certificate accepted depends on the credential_type.
 *
 * @param[in]  cert_str         Certificate string.
 * @param[in]  credential_type  The credential type to assume.
 *
 * @return 0 if valid, 1 otherwise.
 */
static int
check_certificate (const char *cert_str, const char *credential_type)
{
  if (credential_type && strcmp (credential_type, "smime") == 0)
    return check_certificate_smime (cert_str);
  else
    return check_certificate_x509 (cert_str);
}

/**
 * @brief Validate the format and resolvability of a Kerberos KDC input string.
 *
 * @param[in] kdc_input  A comma or newline-separated list of KDC hostnames or IPs.
 *
 * @return TRUE if all KDC entries are valid hosts, FALSE otherwise.
 */
static gboolean
validate_credential_kdc_format (const char *kdc_input)
{
  if (!kdc_input || !*kdc_input)
    return FALSE;

  gchar *input_copy = g_strdup (kdc_input);
  for (gchar *p = input_copy; *p; ++p)
    {
      if (*p == '\n')
        *p = ',';
    }

  gchar **parts = g_strsplit (input_copy, ",", 0);
  g_free (input_copy);

  for (gchar **ptr = parts; *ptr != NULL; ptr++)
    {
      const gchar *entry = *ptr;

      // reject empty strings
      if (!*entry)
        {
          g_strfreev (parts);
          return FALSE;
        }

      // validate whitespace in the KDC entry
      for (const gchar *c = entry; *c; ++c)
        {
          if (g_ascii_isspace (*c))
            {
              g_strfreev (parts);
              return FALSE;
            }
        }

      // validate host or IP
      if (gvm_get_host_type (entry) == -1)
        {
          g_strfreev (parts);
          return FALSE;
        }
    }

  g_strfreev (parts);
  return TRUE;
}

/**
 * @brief Validate the format and resolvability of a list of Kerberos KDCs.
 *
 * This function checks that each entry in the provided kdcs array:
 * - does not contain any whitespace,
 * - can be resolved via gvm_get_host_type(),
 * and if all entries are valid, it joins them into a single comma-separated string.
 *
 * @param[in]  kdcs        A pointer to an array of KDC strings (hostnames or IPs).
 * @param[out] joined_out  A location to store the resulting joined string
 *                         if validation succeeds.
 *                         The caller is responsible for freeing
 *                         the returned string using g_free().
 *
 * @return TRUE if all KDC entries are valid and @p joined_out is set; FALSE otherwise.
 */
static gboolean
validate_credential_kdcs_format (array_t *kdcs, gchar **joined_out)
{
  if (!kdcs || kdcs->len == 0 || !joined_out)
    return FALSE;

  GString *joined = g_string_new ("");

  for (size_t i = 0; i < kdcs->len; ++i)
    {
      const char *kdc_val = g_ptr_array_index (kdcs, i);

      // reject whitespace
      for (const char *c = kdc_val; *c; ++c)
        {
          if (g_ascii_isspace (*c))
            {
              g_string_free (joined, TRUE);
              return FALSE;
            }
        }

      // reject unresolvable host
      if (gvm_get_host_type (kdc_val) == -1)
        {
          g_string_free (joined, TRUE);
          return FALSE;
        }

      if (i > 0)
        g_string_append_c (joined, ',');

      g_string_append (joined, kdc_val);
    }

  *joined_out = g_string_free (joined, FALSE);
  return TRUE;
}

/**
 * @brief Validate the format of a Kerberos realm string.
 *
 * This function checks whether the given @p realm is non-empty and does not
 * contain any whitespace characters.
 *
 * @param[in] realm  A string representing the Kerberos realm.
 *
 * @return TRUE if the realm is valid; FALSE otherwise.
 */
gboolean
validate_credential_realm_format (const char *realm)
{
  if (!realm || !*realm)
    return FALSE;

  for (const char *c = realm; *c; ++c)
    {
      if (g_ascii_isspace (*c))
        return FALSE;
    }

  return TRUE;
}

/**
 * @brief Infer the credential type based on the provided credential data.
 *
 * @param[in]   data  Credential data to infer the type from.
 * @param[out]  type  Pointer to store the resolved credential type.
 *
 * @return A credential_return_t return code.
*/
static credential_return_t
resolve_inferred_credential_type (const credential_data_t *data,
                                  credential_type_t *type)
{
  if (data->community
      || (data->login
          && data->password
          && data->auth_algorithm))
    {
      *type = CREDENTIAL_TYPE_SNMP;
      return CREDENTIAL_OK;
    }
  else if (data->certificate && data->key_private)
    {
      *type = CREDENTIAL_TYPE_CC;
      return CREDENTIAL_OK;
    }
  else if (data->login && data->key_private)
    {
      *type = CREDENTIAL_TYPE_USK;
      return CREDENTIAL_OK;
    }
  else if (data->login
           && data->password
           && (data->realm
               || data->kdc
               || (data->kdcs && data->kdcs->len)))
    {
      *type = CREDENTIAL_TYPE_KRB5;
      return CREDENTIAL_OK;
    }
  else if (data->login && data->password)
    {
      *type = CREDENTIAL_TYPE_UP;
      return CREDENTIAL_OK;
    }
  else if (data->login
           && data->key_private == NULL
           && data->password == NULL)
    {
      *type = CREDENTIAL_TYPE_USK; /* auto-generate */
      return CREDENTIAL_OK;
    }

    g_warning ("%s: Failed to resolve type of new credential", __func__);
    return CREDENTIAL_TYPE_UNDETERMINED;
}

/**
 * @brief Resolve an explicit or inferred credential type.
 *
 * @param[in]   data  Credential data.
 * @param[out]  type_info  Pointer to store the resolved credential type.
 *
 * @return A credential_return_t return code.
 */
static credential_return_t
resolve_credential_type (const credential_data_t *data,
                         credential_type_t *type)
{
  if (data == NULL)
    return CREDENTIAL_INTERNAL_ERROR;

  if (data->type && data->type[0] != '\0')
    return credential_type_from_string (data->type, type);

  return resolve_inferred_credential_type (data, type);
}

/**
 * @brief Validate the security settings for an SNMP credential.
 *
 * @param[in] auth_algorithm    The authentication algorithm.
 * @param[in] privacy_algorithm The privacy algorithm.
 * @param[in] privacy_value     The privacy value.
 *
 * @return A credential_return_t return code.
 */
static credential_return_t
validate_snmp_security (const gchar *auth_algorithm,
                        const gchar *privacy_algorithm,
                        const gchar *privacy_value)
{
  if (auth_algorithm
      && auth_algorithm[0] != '\0'
      && !g_str_equal (auth_algorithm, "md5")
      && !g_str_equal (auth_algorithm, "sha1"))
    return CREDENTIAL_INVALID_SNMP_AUTH_ALGORITHM;

  if (privacy_algorithm
      && privacy_algorithm[0] != '\0'
      && !g_str_equal (privacy_algorithm, "aes")
      && !g_str_equal (privacy_algorithm, "des"))
    return CREDENTIAL_INVALID_SNMP_PRIVACY_ALGORITHM;

  if (privacy_value
      && privacy_value[0] != '\0'
      && (privacy_algorithm == NULL || privacy_algorithm[0] == '\0'))
    return CREDENTIAL_SNMP_PRIVACY_ALGORITHM_REQUIRED;

  return CREDENTIAL_OK;
}

/**
 * @brief Test if a username is valid to use in a credential.
 *
 * Valid usernames may only contain alphanumeric characters and a few
 *  special ones to avoid problems with installer package generation.
 *
 * @param[in]  username  The username string to test.
 *
 * @return Whether the username is valid.
 */
static gboolean
validate_credential_username (const gchar *username)
{
  const guchar *s;

  if (username == NULL)
    return FALSE;

  for (s = (const guchar *) username; *s; s++)
    if (!g_ascii_isalnum (*s)
        && strchr ("-_\\.@", *s) == NULL)
      return FALSE;

  return TRUE;
}

/**
 * @brief Generate a random password of length PASSWORD_LENGTH.
 *
 * @note This code is copied as-is from the old `create_credential`
 * function in manage_sql.c and might need to be improved to use a
 * cryptographically secure random source instead of `g_rand_new()`.
 *
 * @param[out]  password  Buffer to store the generated password.
 *                        Must be at least PASSWORD_LENGTH bytes long.
 */
static void
generate_credential_password (gchar password[PASSWORD_LENGTH])
{
  GRand *rand;

  rand = g_rand_new ();

  for (size_t i = 0; i < PASSWORD_LENGTH - 1; i++)
    {
      password[i] = (gchar) g_rand_int_range (rand, '0', 'z');

      if (password[i] == '\\')
        password[i] = '{';
    }
  password[PASSWORD_LENGTH - 1] = '\0';
  g_rand_free (rand);
}

/**
 * @brief Store a password for a given credential.
 *
 * @param  credential  The credential row ID.
 * @param  password    The password to store.
 *
 * @return  CREDENTIAL_OK on success, or an error code on failure.
 */
static credential_return_t
store_credential_password (credential_t credential,
                           const char *password)
{
  lsc_crypt_ctx_t crypt_ctx = NULL;

  if (password == NULL)
    return CREDENTIAL_INTERNAL_ERROR;

  if (!disable_encrypted_credentials)
    {
      gchar *encrypted_blob;
      char *encryption_key_uid;

      encryption_key_uid= current_encryption_key_uid (TRUE);
      crypt_ctx = lsc_crypt_new (encryption_key_uid);
      free (encryption_key_uid);

      encrypted_blob = lsc_crypt_encrypt (crypt_ctx,
                                          "password", password,
                                          NULL);

      if (encrypted_blob == NULL)
        {
          lsc_crypt_release (crypt_ctx);
          return CREDENTIAL_INTERNAL_ERROR;
        }
      if (set_credential_data (credential, "secret", encrypted_blob)
          || set_credential_data (credential, "password", NULL)
          || set_credential_data (credential, "private_key", NULL))
        {
          g_free (encrypted_blob);
          lsc_crypt_release (crypt_ctx);
          return CREDENTIAL_INTERNAL_ERROR;
        }

      g_free (encrypted_blob);
      lsc_crypt_release (crypt_ctx);
    }
  else
    {
      if (set_credential_data (credential, "secret", NULL)
          || set_credential_data (credential, "password", password)
          || set_credential_data (credential, "private_key", NULL))
        {
          return CREDENTIAL_INTERNAL_ERROR;
        }
    }
  return CREDENTIAL_OK;
}

/**
 * @brief Create a new username/password credential.
 *
 * @param[in]   data            Credential data.
 * @param[out]  new_credential  Pointer to store the created credential.
 *
 * @return A credential_return_t return code.
 */
static credential_return_t
create_username_password_credential (const credential_data_t *data,
                                     credential_t *new_credential)
{
  credential_return_t ret;
  gchar generated_password[PASSWORD_LENGTH] = { 0 };
  const gchar *password;

  if (data == NULL || new_credential == NULL)
    return CREDENTIAL_INTERNAL_ERROR;

  *new_credential = 0;

  if (data->login == NULL || data->login[0] == '\0')
    return CREDENTIAL_LOGIN_REQUIRED;

  if (!validate_credential_username (data->login))
    return CREDENTIAL_INVALID_LOGIN;

  password = data->password;
  if (password == NULL)
    {
      generate_credential_password (generated_password);
      password = generated_password;
    }

  ret = insert_credential_base (data, "up", new_credential);
  if (ret != CREDENTIAL_OK)
    goto fail;

  if (set_credential_data (*new_credential, "username", data->login))
    {
      ret = CREDENTIAL_INTERNAL_ERROR;
      goto fail;
    }

  ret = store_credential_password (*new_credential, password);
  if (ret != CREDENTIAL_OK)
    goto fail;

  return CREDENTIAL_OK;

fail:
  *new_credential = 0;
  return ret;
}

/**
 * @brief Validate the fields related to the Kerberos 5 credential.
 *
 * @param[in] data  Credential data.
 * @param[out] kdc_value  The KDC value extracted from the credential data.
 *
 * @return A credential_return_t return code.
 */
static credential_return_t
validate_kerberos_fields (const credential_data_t *data,
                          gchar **kdc_value)
{
  *kdc_value = NULL;

  if (data->realm == NULL)
    return CREDENTIAL_REALM_REQUIRED;

  if (!validate_credential_realm_format (data->realm))
    return CREDENTIAL_INVALID_REALM;

  if (data->kdcs && data->kdcs->len > 0)
    {
      if (!validate_credential_kdcs_format (data->kdcs, kdc_value))
        return CREDENTIAL_INVALID_KDC;
    }
  else if (data->kdc)
    {
      if (!validate_credential_kdc_format (data->kdc))
        return CREDENTIAL_INVALID_KDC;

      *kdc_value = g_strdup (data->kdc);
    }
  else
    {
      return CREDENTIAL_KDC_REQUIRED;
    }

  return CREDENTIAL_OK;
}

/**
 * @brief Create a new Kerberos credential.
 *
 * @param[in]   data            Credential data.
 * @param[out]  new_credential  Pointer to store the created credential.
 *
 * @return A credential_return_t return code.
 */
static credential_return_t
create_kerberos_credential (const credential_data_t *data,
                            credential_t *new_credential)
{
  credential_return_t ret;
  gchar *kdc_value = NULL;

  if (data == NULL || new_credential == NULL)
    return CREDENTIAL_INTERNAL_ERROR;

  *new_credential = 0;

  if (data->login == NULL || data->login[0] == '\0')
    return CREDENTIAL_LOGIN_REQUIRED;

  if (!validate_credential_username (data->login))
    return CREDENTIAL_INVALID_LOGIN;

  if (data->password == NULL)
    return CREDENTIAL_PASSWORD_REQUIRED;

  ret = validate_kerberos_fields (data, &kdc_value);
  if (ret != CREDENTIAL_OK)
    goto cleanup;

  ret = insert_credential_base (data, "krb5", new_credential);
  if (ret != CREDENTIAL_OK)
    goto cleanup;

  if (set_credential_data (*new_credential, "username", data->login))
    {
      ret = CREDENTIAL_INTERNAL_ERROR;
      goto cleanup;
    }

  ret = store_credential_password (*new_credential, data->password);
  if (ret != CREDENTIAL_OK)
    goto cleanup;

  if (set_credential_data (*new_credential, "kdc", kdc_value)
      || set_credential_data (*new_credential, "realm", data->realm))
    {
      ret = CREDENTIAL_INTERNAL_ERROR;
      goto cleanup;
    }

cleanup:
  g_free (kdc_value);

  if (ret != CREDENTIAL_OK)
    *new_credential = 0;

  return ret;
}

/**
 * Store an SNMP secret in the credential.
 *
 * @param new_credential The credential to store the secret in.
 * @param community The SNMP community string.
 * @param password The SNMP password.
 * @param privacy_password The SNMP privacy password.
 *
 * @return CREDENTIAL_OK on success, or an appropriate error code on failure.
 */
static credential_return_t
store_credential_snmp_secret (credential_t new_credential,
                              const gchar *community,
                              const gchar *password,
                              const gchar *privacy_password)
{
  lsc_crypt_ctx_t crypt_ctx = NULL;

  if (!disable_encrypted_credentials)
   {
      gchar *encrypted_blob;
      gchar *encryption_key_uid;

      encryption_key_uid = current_encryption_key_uid (TRUE);
      crypt_ctx = lsc_crypt_new (encryption_key_uid);
      free (encryption_key_uid);

      encrypted_blob = lsc_crypt_encrypt (
        crypt_ctx,
        "community", community,
        "password", password,
        "privacy_password", privacy_password,
        NULL);

      if (encrypted_blob == NULL)
        {
          lsc_crypt_release (crypt_ctx);
          return CREDENTIAL_INTERNAL_ERROR;
        }

      if (set_credential_data (new_credential, "secret", encrypted_blob)
          || set_credential_data (new_credential, "community", NULL)
          || set_credential_data (new_credential, "password", NULL)
          || set_credential_data (new_credential, "privacy_password", NULL))
        {
          g_free (encrypted_blob);
          lsc_crypt_release (crypt_ctx);
          return CREDENTIAL_INTERNAL_ERROR;
        }

      g_free (encrypted_blob);
      lsc_crypt_release (crypt_ctx);
    }
  else
    {
      if (set_credential_data (new_credential, "secret", NULL)
          || set_credential_data (new_credential, "community", community)
          || set_credential_data (new_credential, "password", password)
          || set_credential_data (new_credential, "privacy_password",
                                  privacy_password))
        {
          return CREDENTIAL_INTERNAL_ERROR;
        }
    }
  return CREDENTIAL_OK;
}

/**
 * @brief Validate a local SNMP credential.
 *
 * @param[in] data  Credential data.
 *
 * @return A credential_return_t return code.
 */
static credential_return_t
validate_local_snmp (const credential_data_t *data)
{
  gboolean has_community;
  gboolean has_login;
  gboolean has_password_value;
  gboolean has_auth_algorithm;
  gboolean has_privacy_algorithm;
  gboolean has_privacy_password;
  gboolean uses_snmp_v3;

  has_community = data->community && data->community[0];
  has_login = data->login && data->login[0];
  has_password_value = data->password && data->password[0];
  has_auth_algorithm = data->auth_algorithm && data->auth_algorithm[0];
  has_privacy_algorithm = data->privacy_algorithm && data->privacy_algorithm[0];
  has_privacy_password = data->privacy_password && data->privacy_password[0];

  if (!has_community && (!has_login || !has_password_value))
    return CREDENTIAL_SNMP_AUTHENTICATION_REQUIRED;

  uses_snmp_v3 = has_login
                 || has_password_value
                 || has_auth_algorithm
                 || has_privacy_password
                 || has_privacy_algorithm;

  if (uses_snmp_v3 && !has_auth_algorithm)
    return CREDENTIAL_SNMP_AUTH_ALGORITHM_REQUIRED;

  return validate_snmp_security (data->auth_algorithm,
                                 data->privacy_algorithm,
                                 data->privacy_password);
}

/**
 * Create an SNMP credential.
 *
 * @param data  The credential data.
 * @param new_credential  The newly created credential.
 * @return CREDENTIAL_OK on success, or an error code on failure.
 */
static credential_return_t
create_snmp_credential (const credential_data_t *data,
                        credential_t *new_credential)
{
  credential_return_t ret;

  if (data == NULL || new_credential == NULL)
    return CREDENTIAL_INTERNAL_ERROR;

  *new_credential = 0;

  ret = validate_local_snmp (data);
  if (ret != CREDENTIAL_OK)
    return ret;

  if (data->login && data->login[0] != '\0'
      && !validate_credential_username (data->login))
    return CREDENTIAL_INVALID_LOGIN;

  ret = insert_credential_base (data, "snmp", new_credential);
  if (ret != CREDENTIAL_OK)
    goto cleanup;

  if (data->login && data->login[0] != '\0'
      && set_credential_data (*new_credential, "username", data->login))
    {
      ret = CREDENTIAL_INTERNAL_ERROR;
      goto cleanup;
    }

  if (data->auth_algorithm
      && data->auth_algorithm[0] != '\0'
      && set_credential_data (*new_credential,
                              "auth_algorithm",
                              data->auth_algorithm))
    {
      ret = CREDENTIAL_INTERNAL_ERROR;
      goto cleanup;
    }

  if (data->privacy_algorithm
      && data->privacy_algorithm[0] != '\0'
      && set_credential_data (*new_credential,
                              "privacy_algorithm",
                              data->privacy_algorithm))
    {
      ret = CREDENTIAL_INTERNAL_ERROR;
      goto cleanup;
    }

  ret = store_credential_snmp_secret (*new_credential,
                                      data->community,
                                      data->password,
                                      data->privacy_password
                                      ? data->privacy_password
                                      : "");
cleanup:
  if (ret != CREDENTIAL_OK)
    *new_credential = 0;
  return ret;
}

/**
 * @brief Store a private key for a given credential.
 *
 * @param credential         The credential to associate the private key with.
 * @param private_key        The private key to store.
 * @param passphrase         The passphrase for the private key.
 * @param verify_public_key  Whether to verify the generated public
 *                           key against the private key.
 *
 * @return CREDENTIAL_OK on success, or an error code on failure.
 */
static credential_return_t
store_credential_private_key (credential_t credential,
                              const char *private_key,
                              const char *passphrase,
                              gboolean verify_public_key)
{
  lsc_crypt_ctx_t crypt_ctx = NULL;

  if (private_key == NULL || private_key[0] == '\0')
    return CREDENTIAL_INVALID_PRIVATE_KEY_OR_PASSPHRASE;

  if (verify_public_key)
    {
      gchar *truncated_key_private = NULL;
      gchar *generated_key_public = NULL;

      truncated_key_private = truncate_private_key (private_key);

      generated_key_public =
        gvm_ssh_public_from_private (truncated_key_private
                                       ? truncated_key_private
                                       : private_key,
                                     passphrase);

      g_free (truncated_key_private);

      if (generated_key_public == NULL)
        return CREDENTIAL_INVALID_PRIVATE_KEY_OR_PASSPHRASE;

      g_free (generated_key_public);
    }

  if (!disable_encrypted_credentials)
    {
      gchar *encrypted_blob;
      char *encryption_key_uid;

      encryption_key_uid= current_encryption_key_uid (TRUE);
      crypt_ctx = lsc_crypt_new (encryption_key_uid);
      free (encryption_key_uid);

      encrypted_blob = lsc_crypt_encrypt (
        crypt_ctx,
        "password", passphrase,
        "private_key", private_key,
        NULL);

      if (encrypted_blob == NULL)
        {
          lsc_crypt_release (crypt_ctx);
          return CREDENTIAL_INTERNAL_ERROR;
        }
      if (set_credential_data (credential, "secret", encrypted_blob)
          || set_credential_data (credential, "password", NULL)
          || set_credential_data (credential, "private_key", NULL))
        {
          g_free (encrypted_blob);
          lsc_crypt_release (crypt_ctx);
          return CREDENTIAL_INTERNAL_ERROR;
        }

      g_free (encrypted_blob);
      lsc_crypt_release (crypt_ctx);
    }
  else
    {
      if (set_credential_data (credential, "secret", NULL)
          || set_credential_data (credential, "password", passphrase)
          || set_credential_data (credential, "private_key", private_key))
        {
          return CREDENTIAL_INTERNAL_ERROR;
        }
    }
  return CREDENTIAL_OK;
}

/**
 * @brief Create an SSH credential.
 *
 * @param data The credential data.
 * @param new_credential The newly created credential.
 * @return CREDENTIAL_OK on success, or an error code on failure.
 */
static credential_return_t
create_ssh_credential (const credential_data_t *data,
                       credential_t *new_credential)
{
  credential_return_t ret;
  const gchar *private_key;
  const gchar *passphrase;
  gchar generated_passphrase[PASSWORD_LENGTH] = {0};
  gchar *generated_private_key = NULL;
  gboolean private_key_supplied;

  if (data == NULL || new_credential == NULL)
    return CREDENTIAL_INTERNAL_ERROR;

  *new_credential = 0;

  if (data->login == NULL || data->login[0] == '\0')
    return CREDENTIAL_LOGIN_REQUIRED;

  if (!validate_credential_username (data->login))
    return CREDENTIAL_INVALID_LOGIN;

  private_key_supplied = data->key_private != NULL;
  private_key = data->key_private;

  if (private_key_supplied)
    {
       passphrase = data->key_phrase ? data->key_phrase : "";

      if (check_private_key (private_key, passphrase))
        {
          ret = CREDENTIAL_INVALID_PRIVATE_KEY_OR_PASSPHRASE;
          goto cleanup;
        }
    }
  else
    {
      if (data->key_phrase != NULL)
        return CREDENTIAL_PRIVATE_KEY_REQUIRED;

      generate_credential_password (generated_passphrase);

      if (lsc_user_keys_create (generated_passphrase,
                                &generated_private_key))
        {
          ret = CREDENTIAL_INTERNAL_ERROR;
          goto cleanup;
        }

      private_key = generated_private_key;
      passphrase = generated_passphrase;
    }

  ret = insert_credential_base (data, "usk", new_credential);
  if (ret != CREDENTIAL_OK)
    goto cleanup;

  if (set_credential_data (*new_credential,
                           "username",
                           data->login))
    {
      ret = CREDENTIAL_INTERNAL_ERROR;
      goto cleanup;
    }

  ret = store_credential_private_key (*new_credential,
                                      private_key,
                                      passphrase,
                                      private_key_supplied);

cleanup:
  if (ret != CREDENTIAL_OK)
    *new_credential = 0;

  g_free (generated_private_key);
  return ret;
}

/**
 * @brief Create a CC (Client Certificate) credential.
 *
 * @param data The credential data.
 * @param new_credential The newly created credential.
 *
 * @return CREDENTIAL_OK on success, or an error code on failure.
 */
static credential_return_t
create_cc_credential (const credential_data_t *data,
                      credential_t *new_credential)
{
  credential_return_t ret;
  gchar *certificate = NULL;
  const gchar *passphrase;

  if (data == NULL || new_credential == NULL)
    return CREDENTIAL_INTERNAL_ERROR;

  *new_credential = 0;

  if (data->key_private == NULL)
    return CREDENTIAL_PRIVATE_KEY_REQUIRED;

  if (data->certificate == NULL)
    return CREDENTIAL_CERTIFICATE_REQUIRED;

  passphrase = data->key_phrase ? data->key_phrase : "";

  if (check_private_key (data->key_private, passphrase))
    return CREDENTIAL_INVALID_PRIVATE_KEY_OR_PASSPHRASE;

  if (check_certificate (data->certificate, "cc"))
    return CREDENTIAL_INVALID_CERTIFICATE;

  certificate = truncate_certificate (data->certificate);
  if (certificate == NULL)
    return CREDENTIAL_INVALID_CERTIFICATE;

  ret = insert_credential_base (data, "cc", new_credential);
  if (ret != CREDENTIAL_OK)
    goto cleanup;

  if (set_credential_data (*new_credential,
                           "certificate",
                           certificate))
    {
      ret = CREDENTIAL_INTERNAL_ERROR;
      goto cleanup;
    }

  ret = store_credential_private_key (*new_credential,
                                      data->key_private,
                                      passphrase,
                                      TRUE);

cleanup:
  g_free (certificate);

  if (ret != CREDENTIAL_OK)
    *new_credential = 0;

  return ret;
}

/**
 * @brief Create an S/MIME credential.
 *
 * @param data  The credential data.
 * @param new_credential  The newly created credential.
 *
 * @return CREDENTIAL_OK on success, or an error code on failure.
 */
static credential_return_t
create_smime_credential (const credential_data_t *data,
                         credential_t *new_credential)
{
  credential_return_t ret;
  gchar *certificate = NULL;

  if (data == NULL || new_credential == NULL)
    return CREDENTIAL_INTERNAL_ERROR;

  *new_credential = 0;

  if (data->certificate == NULL)
    return CREDENTIAL_CERTIFICATE_REQUIRED;

  if (check_certificate (data->certificate, "smime"))
    return CREDENTIAL_INVALID_CERTIFICATE;

  certificate = truncate_certificate (data->certificate);
  if (certificate == NULL)
    return CREDENTIAL_INVALID_CERTIFICATE;

  ret = insert_credential_base (data, "smime", new_credential);
  if (ret != CREDENTIAL_OK)
    goto cleanup;

  if (set_credential_data (*new_credential, "certificate", certificate))
    {
      ret = CREDENTIAL_INTERNAL_ERROR;
      goto cleanup;
    }

cleanup:
  g_free (certificate);

  if (ret != CREDENTIAL_OK)
    *new_credential = 0;

  return ret;
}

/**
 * @brief Create a PGP credential.
 *
 * @param data  The credential data.
 * @param new_credential  The newly created credential.
 *
 * @return CREDENTIAL_OK on success, or an error code on failure.
 */
static credential_return_t
create_pgp_credential (const credential_data_t *data,
                       credential_t *new_credential)
{
  credential_return_t ret;

  if (data == NULL || new_credential == NULL)
    return CREDENTIAL_INTERNAL_ERROR;

  *new_credential = 0;

  if (data->key_public == NULL)
    return CREDENTIAL_PUBLIC_KEY_REQUIRED;

  if (check_public_key (data->key_public))
    return CREDENTIAL_INVALID_PUBLIC_KEY;

  ret = insert_credential_base (data, "pgp", new_credential);
  if (ret != CREDENTIAL_OK)
    goto fail;

  if (set_credential_data (*new_credential, "public_key", data->key_public))
    {
      ret = CREDENTIAL_INTERNAL_ERROR;
      goto fail;
    }

  return CREDENTIAL_OK;

fail:
  *new_credential = 0;
  return ret;
}

/**
 * @brief Create a password credential.
 *
 * @param data The credential data.
 * @param new_credential The newly created credential.
 *
 * @return CREDENTIAL_OK on success, or an error code on failure.
 */
static credential_return_t
create_password_credential (const credential_data_t *data,
                            credential_t *new_credential)
{
  credential_return_t ret;
  gchar generated_password[PASSWORD_LENGTH] = { 0 };
  const gchar *password;

  if (data == NULL || new_credential == NULL)
    return CREDENTIAL_INTERNAL_ERROR;

  *new_credential = 0;

  password = data->password;

  if (password == NULL)
    {
      generate_credential_password (generated_password);
      password = generated_password;
    }

  ret = insert_credential_base (data, "pw", new_credential);
  if (ret != CREDENTIAL_OK)
    goto fail;

  ret = store_credential_password (*new_credential, password);
  if (ret != CREDENTIAL_OK)
    goto fail;

  return CREDENTIAL_OK;

fail:
  *new_credential = 0;
  return ret;
}

#if ENABLE_CREDENTIAL_STORES
/**
 * @brief Validate the fields related to the credential store.
 *
 * @param[in] data  Credential data.
 *
 * @return A credential_return_t return code.
 */
static credential_return_t
validate_credential_store_fields (const credential_data_t *data)
{
  credential_store_t store;

  if (!feature_enabled (FEATURE_ID_CREDENTIAL_STORES))
    return CREDENTIAL_CREDENTIAL_STORE_UNAVAILABLE;

  if (data->credential_store_id == NULL)
    {
      if (get_default_credential_store_id () == NULL)
        return CREDENTIAL_CREDENTIAL_STORE_ID_REQUIRED;
    }
  else if (find_credential_store_no_acl (data->credential_store_id, &store)
           || store == 0)
    {
      return CREDENTIAL_CREDENTIAL_STORE_NOT_FOUND;
    }

  if (data->vault_id == NULL || data->vault_id[0] == '\0')
    return CREDENTIAL_VAULT_ID_REQUIRED;

  if (data->host_identifier == NULL || data->host_identifier[0] == '\0')
    return CREDENTIAL_HOST_IDENTIFIER_REQUIRED;

  return CREDENTIAL_OK;
}

/**
 * @brief Validate an SNMP credential for storage in a credential store.
 *
 * @param[in] data  Credential data.
 *
 * @return A credential_return_t return code.
 */
static credential_return_t
validate_store_snmp_fields (const credential_data_t *data)
{
  if (data->auth_algorithm == NULL
      || data->auth_algorithm[0] == '\0')
    return CREDENTIAL_SNMP_AUTH_ALGORITHM_REQUIRED;

  return validate_snmp_security (data->auth_algorithm,
                                 data->privacy_algorithm,
                                 data->privacy_host_identifier);
}

/**
 * @brief Store credential store specific data in the credential.
 *
 * @param[in] credential  The credential object.
 * @param[in] data  Credential data.
 *
 * @return A credential_return_t return code indicating success or failure.
 */
static credential_return_t
store_credential_store_data (credential_t credential,
                             const credential_data_t *data)
{
  const gchar *store_id;

  store_id = data->credential_store_id
               ? data->credential_store_id
               : get_default_credential_store_id ();

  if (set_credential_data (credential, "credential_store_id", store_id)
      || set_credential_data (credential, "vault_id", data->vault_id)
      || set_credential_data (credential, "host_identifier",
                              data->host_identifier))
    {
      return CREDENTIAL_INTERNAL_ERROR;
    }

return CREDENTIAL_OK;
}

/**
 * @brief Create a new credential store credential
 *
 * @param[in] data  Credential data.
 * @param[in] type  Type of the credential.
 * @param[out] new_credential  Pointer to the newly created credential.
 *
 * @return A credential_return_t return code indicating success or failure.
 */
static credential_return_t
create_credential_store_credential (const credential_data_t *data,
                                    credential_type_t type,
                                    credential_t *new_credential)
{
  credential_return_t ret;
  gchar *kdc_value = NULL;
  const gchar *database_type;

  if (!feature_enabled (FEATURE_ID_CREDENTIAL_STORES))
    return CREDENTIAL_CREDENTIAL_STORE_UNAVAILABLE;

  if (data == NULL || new_credential == NULL)
    return CREDENTIAL_INTERNAL_ERROR;

  *new_credential = 0;

  ret = validate_credential_store_fields (data);
  if (ret != CREDENTIAL_OK)
    return ret;

  switch (type)
    {
    case CREDENTIAL_TYPE_CS_UP:
      database_type = "cs_up";
      break;
    case CREDENTIAL_TYPE_CS_PW:
      database_type = "cs_pw";
      break;
    case CREDENTIAL_TYPE_CS_USK:
      database_type = "cs_usk";
      break;
    case CREDENTIAL_TYPE_CS_CC:
      database_type = "cs_cc";
      break;
    case CREDENTIAL_TYPE_CS_PGP:
      database_type = "cs_pgp";
      break;
    case CREDENTIAL_TYPE_CS_SMIME:
      database_type = "cs_smime";
      break;
    case CREDENTIAL_TYPE_CS_SNMP:
      ret = validate_store_snmp_fields (data);
      if (ret != CREDENTIAL_OK)
        goto cleanup;
      database_type = "cs_snmp";
      break;
    case CREDENTIAL_TYPE_CS_KRB5:
      ret = validate_kerberos_fields (data, &kdc_value);
      if (ret != CREDENTIAL_OK)
        goto cleanup;
      database_type = "cs_krb5";
      break;

    default:
      ret = CREDENTIAL_UNSUPPORTED_TYPE;
      goto cleanup;
    }

  ret = insert_credential_base (data, database_type, new_credential);
  if (ret != CREDENTIAL_OK)
    goto cleanup;

  ret = store_credential_store_data (*new_credential, data);
  if (ret != CREDENTIAL_OK)
    goto cleanup;

 switch (type)
    {
      case CREDENTIAL_TYPE_CS_SNMP:
        if (set_credential_data (*new_credential,
                                 "auth_algorithm",
                                 data->auth_algorithm)
            || set_credential_data (*new_credential,
                                    "privacy_algorithm",
                                    data->privacy_algorithm)
            || set_credential_data (*new_credential,
                                    "privacy_host_identifier",
                                    data->privacy_host_identifier))
          {
            ret = CREDENTIAL_INTERNAL_ERROR;
            goto cleanup;
          }
        break;

      case CREDENTIAL_TYPE_CS_KRB5:
        if (set_credential_data (*new_credential,
                                 "kdc",
                                 kdc_value)
            || set_credential_data (*new_credential,
                                    "realm",
                                    data->realm))
          {
            ret = CREDENTIAL_INTERNAL_ERROR;
            goto cleanup;
          }
        break;

      default:
        break;
    }

  ret = CREDENTIAL_OK;

cleanup:
  g_free (kdc_value);

  if (ret != CREDENTIAL_OK)
    *new_credential = 0;

  return ret;
}
#endif /* ENABLE_CREDENTIAL_STORES */

/**
 * @brief Create a new credential for a specific type.
 *
 * @param[in]   data            Credential data.
 * @param[in]   type            Credential type.
 * @param[out]  new_credential  Pointer to store the created credential.
 *
 * @return A credential_return_t return code.
 */
static credential_return_t
create_credential_for_type (const credential_data_t *data,
                            credential_type_t type,
                            credential_t *new_credential)
{
  switch (type)
    {
      case CREDENTIAL_TYPE_UP:
        return create_username_password_credential (data, new_credential);
      case CREDENTIAL_TYPE_USK:
        return create_ssh_credential (data, new_credential);
      case CREDENTIAL_TYPE_SNMP:
        return create_snmp_credential (data, new_credential);
      case CREDENTIAL_TYPE_KRB5:
        return create_kerberos_credential (data, new_credential);
      case CREDENTIAL_TYPE_CC:
        return create_cc_credential (data, new_credential);
      case CREDENTIAL_TYPE_SMIME:
        return create_smime_credential (data, new_credential);
      case CREDENTIAL_TYPE_PGP:
        return create_pgp_credential (data, new_credential);
      case CREDENTIAL_TYPE_PW:
        return create_password_credential (data, new_credential);
#if ENABLE_CREDENTIAL_STORES
      case CREDENTIAL_TYPE_CS_UP:
      case CREDENTIAL_TYPE_CS_USK:
      case CREDENTIAL_TYPE_CS_SNMP:
      case CREDENTIAL_TYPE_CS_KRB5:
      case CREDENTIAL_TYPE_CS_CC:
      case CREDENTIAL_TYPE_CS_SMIME:
      case CREDENTIAL_TYPE_CS_PGP:
      case CREDENTIAL_TYPE_CS_PW:
        return create_credential_store_credential (data, type, new_credential);
#endif
      default:
        return CREDENTIAL_UNSUPPORTED_TYPE;
    }
}

/**
 * @brief Create a new credential.
 *
 * @param[in]   data        Credential data.
 * @param[out]  credential  Pointer to store the created credential.
 *
 * @return A credential_return_t return code.
 */
credential_return_t
create_credential (const credential_data_t *data,
                   credential_t *credential)
{
  credential_type_t type;
  credential_t new_credential = 0;
  credential_return_t ret;

  if (credential)
    *credential = 0;

  if (data == NULL || data->name == NULL || data->name[0] == '\0')
    return CREDENTIAL_NAME_REQUIRED;

  assert (current_credentials.uuid);

  sql_begin_immediate ();

  if (!acl_user_may ("create_credential"))
    {
      ret = CREDENTIAL_PERMISSION_DENIED;
      goto rollback;
    }

  if (resource_with_name_exists (data->name, "credential", 0))
    {
      ret = CREDENTIAL_NAME_ALREADY_EXISTS;
      goto rollback;
    }

  ret = resolve_credential_type (data, &type);
  if (ret != CREDENTIAL_OK)
    goto rollback;

  ret = create_credential_for_type (data, type, &new_credential);
  if (ret != CREDENTIAL_OK)
    goto rollback;

  if (credential)
    *credential = new_credential;

  sql_commit ();
  return CREDENTIAL_OK;

rollback:
  sql_rollback ();
  return ret;
}

/**
 * @brief Modify the login of an existing credential.
 *
 * @param[in]   login       New login.
 * @param[in]   credential  Credential row ID.
 * @param[out]  changed     Pointer to store whether the credential
 *                          was changed.
 *
 * @return A credential_return_t return code.
 */
static credential_return_t
modify_credential_login (const gchar *login,
                         credential_t credential,
                         gboolean *changed)
{
  if (login == NULL)
    return CREDENTIAL_OK;

  if (login[0] == '\0'
      || !validate_credential_username (login))
    return CREDENTIAL_INVALID_LOGIN;

  if (set_credential_data (credential, "username", login))
    return CREDENTIAL_INTERNAL_ERROR;

  *changed = TRUE;
  return CREDENTIAL_OK;
}

/**
 * @brief Modify an existing username/password credential.
 *
 * @param[in]   data            Credential data.
 * @param[in]   credential      Credential row ID.
 *
 * @return A credential_return_t return code.
 */
static credential_return_t
modify_username_password_credential (const credential_data_t *data,
                                     credential_t credential)
{
  credential_return_t ret;
  gboolean changed = FALSE;

  if (data == NULL || credential == 0)
    return CREDENTIAL_INTERNAL_ERROR;

  ret = modify_credential_login (data->login, credential, &changed);
  if (ret != CREDENTIAL_OK)
    return ret;

  if (data->password != NULL)
    {
      ret = store_credential_password (credential, data->password);
      if (ret != CREDENTIAL_OK)
        return ret;

      changed = TRUE;
    }

  if (changed)
    update_credential_modification_time (credential);

  return CREDENTIAL_OK;
}

/**
 * @brief Modify an existing SSH credential.
 *
 * @param[in]   data        Credential data.
 * @param[in]   credential  Credential row ID.
 *
 * @return A credential_return_t return code.
 */
static credential_return_t
modify_ssh_credential (const credential_data_t *data,
                       credential_t credential)
{
  credential_return_t ret = CREDENTIAL_OK;
  iterator_t iterator;
  const gchar *private_key;
  const gchar *passphrase;
  gchar *normalized_private_key = NULL;
  gchar *generated_public_key = NULL;
  gboolean changed = FALSE;

  if (data == NULL || credential == 0)
    return CREDENTIAL_INTERNAL_ERROR;

  ret = modify_credential_login (data->login, credential, &changed);
  if (ret != CREDENTIAL_OK)
    return ret;

  if (data->key_private != NULL || data->key_phrase != NULL)
    {
      init_credential_iterator_one (&iterator, credential);
      if (!next (&iterator))
      {
        cleanup_iterator (&iterator);
        return CREDENTIAL_INTERNAL_ERROR;
      }

      if (data->key_private != NULL)
       {
          if (data->key_private[0] == '\0')
            {
              cleanup_iterator (&iterator);
              return CREDENTIAL_INVALID_PRIVATE_KEY_OR_PASSPHRASE;
            }

            normalized_private_key = truncate_private_key (data->key_private);
            private_key = normalized_private_key
                            ? normalized_private_key
                            : data->key_private;
       }
      else
        private_key = credential_iterator_private_key (&iterator);

      passphrase = data->key_phrase != NULL
                    ? data->key_phrase
                    : credential_iterator_password (&iterator);

      if (private_key == NULL || private_key[0] == '\0'
          || check_private_key (private_key, passphrase))
      {
        cleanup_iterator (&iterator);
        ret =  CREDENTIAL_INVALID_PRIVATE_KEY_OR_PASSPHRASE;
        goto cleanup;
      }

      if (data->key_private != NULL)
        {
            generated_public_key =
              gvm_ssh_public_from_private (private_key, passphrase);

            if (generated_public_key == NULL)
            {
              cleanup_iterator (&iterator);
              ret = CREDENTIAL_INVALID_PRIVATE_KEY_OR_PASSPHRASE;
              goto cleanup;
            }
        }

      ret = store_credential_private_key (credential,
                                          private_key,
                                          passphrase,
                                          FALSE);
      cleanup_iterator (&iterator);

      if (ret != CREDENTIAL_OK)
        goto cleanup;

      changed = TRUE;
    }

cleanup:
  g_free (normalized_private_key);
  g_free (generated_public_key);

  if (ret == CREDENTIAL_OK && changed)
    update_credential_modification_time (credential);

  return ret;
}

/**
 * @brief Clear the private key, passphrase, and secret for a credential.
 *
 * @param[in]   credential  Credential row ID.
 *
 * @return A credential_return_t return code.
 */
static credential_return_t
clear_credential_private_key (credential_t credential)
{
  if (set_credential_data (credential, "secret", NULL)
      || set_credential_data (credential, "password", NULL)
      || set_credential_data (credential, "private_key", NULL))
    return CREDENTIAL_INTERNAL_ERROR;

  return CREDENTIAL_OK;
}

/**
 * @brief Modify the certificate for a credential.
 *
 * @param[in]   certificate  The new certificate.
 * @param[in]   credential   Credential row ID.
 * @param[in]   credential_type  The type of the credential.
 * @param[out]  changed      Indicates if the credential was changed.
 *
 * @return A credential_return_t return code.
 */
static credential_return_t
modify_credential_certificate (const gchar *certificate,
                               credential_t credential,
                               const gchar *credential_type,
                               gboolean *changed)
{
  gchar *normalized = NULL;
  credential_return_t ret = CREDENTIAL_OK;

  if (certificate == NULL)
    return CREDENTIAL_OK;

  if (certificate[0] != '\0')
    {
      if (check_certificate (certificate, credential_type))
        return CREDENTIAL_INVALID_CERTIFICATE;

      normalized = truncate_certificate (certificate);
      if (normalized == NULL)
        return CREDENTIAL_INVALID_CERTIFICATE;
    }

  if (set_credential_data (credential, "certificate", normalized))
    ret = CREDENTIAL_INTERNAL_ERROR;
  else
    *changed = TRUE;

  g_free (normalized);
  return ret;
}

/**
 * @brief Modify a credential for the CC type.
 *
 * @param[in]   data        Credential data.
 * @param[in]   credential  Credential row ID.
 *
 * @return A credential_return_t return code.
 */
static credential_return_t
modify_cc_credential (const credential_data_t *data,
                     credential_t credential)
{
  credential_return_t ret;
  iterator_t iterator;
  const gchar *effective_private_key = NULL;
  const gchar *effective_passphrase = NULL;
  gboolean changed = FALSE;

  if (data == NULL || credential == 0)
    return CREDENTIAL_INTERNAL_ERROR;

  ret = modify_credential_certificate (data->certificate,
                                       credential,
                                       "cc",
                                       &changed);
  if (ret != CREDENTIAL_OK)
    return ret;

  if (data->key_private != NULL || data->key_phrase != NULL)
   {
      init_credential_iterator_one (&iterator, credential);

      if (!next (&iterator))
        {
          cleanup_iterator (&iterator);
          return CREDENTIAL_INTERNAL_ERROR;
        }

      effective_private_key = data->key_private != NULL
                                ? data->key_private
                                : credential_iterator_private_key (&iterator);

      effective_passphrase = data->key_phrase != NULL
                              ? data->key_phrase
                              : credential_iterator_password (&iterator);

      if (effective_private_key == NULL)
        {
          ret = CREDENTIAL_INVALID_PRIVATE_KEY_OR_PASSPHRASE;
        }
      else if (effective_private_key[0] == '\0')
        {
          ret = clear_credential_private_key (credential);
        }
      else if (check_private_key (effective_private_key,
                                  effective_passphrase))
        {
          ret = CREDENTIAL_INVALID_PRIVATE_KEY_OR_PASSPHRASE;
        }
      else
        {
          /* Skip public-key derivation for a passphrase-only update
             for consistency with legacy code */
          ret = store_credential_private_key (credential,
                                              effective_private_key,
                                              effective_passphrase,
                                              data->key_private != NULL);
        }

      cleanup_iterator (&iterator);

      if (ret != CREDENTIAL_OK)
        return ret;

      changed = TRUE;
   }

  if (changed)
    update_credential_modification_time (credential);

  return CREDENTIAL_OK;
}

/**
 * @brief Modify a PGP credential.
 *
 * @param data  The credential data.
 * @param credential  The credential row ID.
 *
 * @return CREDENTIAL_OK on success, or an error code on failure.
 */
static credential_return_t
modify_pgp_credential (const credential_data_t *data,
                       credential_t credential)
{
  const gchar *public_key;

  if (data == NULL || credential == 0)
    return CREDENTIAL_INTERNAL_ERROR;

  public_key = data->key_public;

  if (public_key == NULL)
    return CREDENTIAL_OK;

  if (public_key[0] != '\0' && check_public_key (public_key))
    return CREDENTIAL_INVALID_PUBLIC_KEY;

  if (set_credential_data (credential,
                           "public_key",
                           public_key[0] ? public_key : NULL))
    return CREDENTIAL_INTERNAL_ERROR;

  update_credential_modification_time (credential);
  return CREDENTIAL_OK;
}

/**
 * @brief Modify an S/MIME credential.
 *
 * @param data  The credential data.
 * @param credential  The credential row ID.
 *
 * @return CREDENTIAL_OK on success, or an error code on failure.
 */
static credential_return_t
modify_smime_credential (const credential_data_t *data,
                         credential_t credential)
{
  credential_return_t ret;
  gboolean changed = FALSE;

  if (data == NULL || credential == 0)
    return CREDENTIAL_INTERNAL_ERROR;

  ret = modify_credential_certificate (data->certificate,
                                       credential,
                                       "smime",
                                       &changed);
  if (ret != CREDENTIAL_OK)
    return ret;

  if (changed)
    update_credential_modification_time (credential);

  return CREDENTIAL_OK;
}

/**
 * @brief Modify a password credential.
 *
 * @param data  The credential data.
 * @param credential  The credential row ID.
 *
 * @return CREDENTIAL_OK on success, or an error code on failure.
 */
static credential_return_t
modify_password_credential (const credential_data_t *data,
                           credential_t credential)
{
  credential_return_t ret;

  if (data == NULL || credential == 0)
    return CREDENTIAL_INTERNAL_ERROR;

  if (data->password == NULL)
    return CREDENTIAL_OK;

  ret = store_credential_password (credential, data->password);
  if (ret != CREDENTIAL_OK)
    return ret;

  update_credential_modification_time (credential);
  return CREDENTIAL_OK;
}

/**
 * @brief Modify the local SNMP security fields of a credential.
 *
 * @param data              The credential data.
 * @param credential        The credential row ID.
 * @param [in,out] changed  Set to TRUE when this helper successfully
 *                          modifies a field. The caller must initialize it.
 *
 * @return CREDENTIAL_OK on success, or an error code on failure.
 */
static credential_return_t
modify_local_snmp_security_fields (const credential_data_t *data,
                                   credential_t credential,
                                   gboolean *changed)
{
  credential_return_t ret = CREDENTIAL_OK;
  iterator_t iterator;
  const gchar *community, *password;
  const gchar *privacy_algorithm, *privacy_password;
  gboolean secret_changed, privacy_changed;

  if (data == NULL || credential == 0 || changed == NULL)
    return CREDENTIAL_INTERNAL_ERROR;

  secret_changed = data->community != NULL
                   || data->password != NULL
                   || data->privacy_password != NULL;

  privacy_changed = data->privacy_algorithm != NULL
                    || data->privacy_password != NULL;

  if (!secret_changed && !privacy_changed)
    return CREDENTIAL_OK;

  init_credential_iterator_one (&iterator, credential);

  if (!next (&iterator))
    {
      ret = CREDENTIAL_INTERNAL_ERROR;
      goto cleanup;
    }

  community = data->community != NULL
    ? data->community
    : credential_iterator_community (&iterator);

  password = data->password != NULL
    ? data->password
    : credential_iterator_password (&iterator);

  privacy_password = data->privacy_password != NULL
    ? data->privacy_password
    : credential_iterator_privacy_password (&iterator);

  privacy_algorithm = data->privacy_algorithm != NULL
    ? data->privacy_algorithm
    : credential_iterator_privacy_algorithm (&iterator);

  if (privacy_changed)
    {
      ret = validate_snmp_security (NULL,
                                    privacy_algorithm,
                                    privacy_password);
      if (ret != CREDENTIAL_OK)
        goto cleanup;
    }

  if (data->privacy_algorithm != NULL)
    {
      if (set_credential_data (credential,
                               "privacy_algorithm",
                               data->privacy_algorithm))
        {
          ret = CREDENTIAL_INTERNAL_ERROR;
          goto cleanup;
        }

      *changed = TRUE;
    }

  if (secret_changed)
    {
      ret = store_credential_snmp_secret (credential,
                                          community,
                                          password,
                                          privacy_password);
      if (ret != CREDENTIAL_OK)
        goto cleanup;

      *changed = TRUE;
    }

cleanup:
  cleanup_iterator (&iterator);
  return ret;
}

/**
 * @brief Modify an SNMP credential.
 *
 * @param data  The credential data.
 * @param credential  The credential row ID.
 *
 * @return CREDENTIAL_OK on success, or an error code on failure.
 */
static credential_return_t
modify_snmp_credential (const credential_data_t *data,
                        credential_t credential)
{
  credential_return_t ret = CREDENTIAL_OK;
  gboolean changed = FALSE;

  if (data == NULL || credential == 0)
    return CREDENTIAL_INTERNAL_ERROR;

  if (data->auth_algorithm != NULL
      && !g_str_equal (data->auth_algorithm, "md5")
      && !g_str_equal (data->auth_algorithm, "sha1"))
    return CREDENTIAL_INVALID_SNMP_AUTH_ALGORITHM;

  ret = modify_credential_login (data->login, credential, &changed);
  if (ret != CREDENTIAL_OK)
    return ret;

  ret = modify_local_snmp_security_fields (data,
                                           credential,
                                           &changed);
  if (ret != CREDENTIAL_OK)
    return ret;

  if (data->auth_algorithm != NULL)
    {
      if (set_credential_data (credential, "auth_algorithm",
                               data->auth_algorithm))
        return CREDENTIAL_INTERNAL_ERROR;

      changed = TRUE;
    }

  if (changed)
    update_credential_modification_time (credential);

return ret;
}

/**
 * @brief Modify the Kerberos fields of a credential.
 *
 * @param[in]   data        Credential data.
 * @param[in]   credential  Credential row ID.
 * @param[in,out]  changed  Set to TRUE when this helper
 *                          successfully modifies a field.
 *                          The caller must initialize it.
 *
 * @return A credential_return_t return code.
 */
static credential_return_t
modify_kerberos_fields (const credential_data_t *data,
                        credential_t credential,
                        gboolean *changed)
{
  gchar *joined_kdcs = NULL;

  if (data == NULL || credential == 0 || changed == NULL)
    return CREDENTIAL_INTERNAL_ERROR;

  if (data->realm != NULL)
    {
      if (!validate_credential_realm_format (data->realm))
        return CREDENTIAL_INVALID_REALM;

      if (set_credential_data (credential, "realm", data->realm))
        return CREDENTIAL_INTERNAL_ERROR;

      *changed = TRUE;
    }

  if (data->kdcs != NULL)
    {
      if (!validate_credential_kdcs_format (data->kdcs, &joined_kdcs))
        {
          g_free (joined_kdcs);
          return CREDENTIAL_INVALID_KDC;
        }

      if (set_credential_data (credential, "kdc", joined_kdcs))
        {
          g_free (joined_kdcs);
          return CREDENTIAL_INTERNAL_ERROR;
        }

      *changed = TRUE;
      g_free (joined_kdcs);
    }
  else if (data->kdc != NULL)
    {
      if (!validate_credential_kdc_format (data->kdc))
        return CREDENTIAL_INVALID_KDC;

      if (set_credential_data (credential, "kdc", data->kdc))
        return CREDENTIAL_INTERNAL_ERROR;

      *changed = TRUE;
    }

  return CREDENTIAL_OK;
}

/**
 * @brief Modify a Kerberos credential.
 *
 * @param[in]   data        Credential data.
 * @param[in]   credential  Credential row ID.
 *
 * @return A credential_return_t return code.
 */
static credential_return_t
modify_kerberos_credential (const credential_data_t *data,
                           credential_t credential)
{
  credential_return_t ret = CREDENTIAL_OK;
  gboolean changed = FALSE;

  if (data == NULL || credential == 0)
    return CREDENTIAL_INTERNAL_ERROR;

  ret = modify_credential_login (data->login, credential, &changed);
  if (ret != CREDENTIAL_OK)
    return ret;

  if (data->password != NULL)
    {
      ret = store_credential_password (credential, data->password);
      if (ret != CREDENTIAL_OK)
        goto cleanup;

      changed = TRUE;
    }

  ret = modify_kerberos_fields (data, credential, &changed);
  if (ret != CREDENTIAL_OK)
    goto cleanup;

cleanup:
  if (ret == CREDENTIAL_OK && changed)
    update_credential_modification_time (credential);

  return ret;
}

/**
 * @brief Modify the common fields of a credential.
 *
 * @param[in]   data        Credential data.
 * @param[in]   credential  Credential row ID.
 *
 * @return A credential_return_t return code.
 */
static credential_return_t
modify_credential_common_fields (const credential_data_t *data,
                                credential_t credential)
{
  int allow_insecure;

  if (data == NULL || credential == 0)
    return CREDENTIAL_INTERNAL_ERROR;

  if (data->name != NULL)
  {
    /* An empty name was NULL in legacy code and was rejected. */
    if (data->name[0] == '\0')
      return CREDENTIAL_NAME_REQUIRED;

    if (resource_with_name_exists (data->name,
                                   "credential",
                                   credential))

      return CREDENTIAL_NAME_ALREADY_EXISTS;

    if (set_credential_name (credential, data->name))
      return CREDENTIAL_INTERNAL_ERROR;
  }

  if (data->comment != NULL)
    if (set_credential_comment (credential, data->comment))
      return CREDENTIAL_INTERNAL_ERROR;

  if (data->allow_insecure != NULL)
  {
    allow_insecure =
      data->allow_insecure[0] != '\0'
      && !g_str_equal (data->allow_insecure, "0");

    if (set_credential_allow_insecure (credential, allow_insecure))
      return CREDENTIAL_INTERNAL_ERROR;
  }

  return CREDENTIAL_OK;
}

#if ENABLE_CREDENTIAL_STORES
/**
 * @brief Check if the credential data has any local secret fields.
 *
 * @param[in]   data  Credential data.
 *
 * @return TRUE if any local secret fields are present, FALSE otherwise.
 */
static gboolean
credential_data_has_local_secret_fields (const credential_data_t *data)
{
  if (data == NULL)
    return FALSE;

  return data->login != NULL
         || data->password != NULL
         || data->key_phrase != NULL
         || data->key_private != NULL
         || data->key_public != NULL
         || data->certificate != NULL
         || data->community != NULL
         || data->privacy_password != NULL;
}

/**
 * @brief Check if the credential data has any external credential
 *        store fields.
 *
 * @param[in]   data  Credential data.
 *
 * @return TRUE if any external credential store fields are present,
 *         FALSE otherwise.
 */
static gboolean
credential_data_has_store_fields (const credential_data_t *data)
{
  if (data == NULL)
    return FALSE;

  return data->credential_store_id != NULL
         || data->vault_id != NULL
         || data->host_identifier != NULL
         || data->privacy_host_identifier != NULL;
}

/**
 * @brief Modify the SNMP fields of a credential stored in an external credential store.
 *
 * @param[in]   data        Credential data.
 * @param[in]   credential  Credential row ID.
 * @param [in,out] changed  Set to TRUE when this helper successfully
 *                          modifies a field. The caller must initialize it.
 *
 * @return A credential_return_t return code.
 */
static credential_return_t
modify_credential_store_snmp_fields (const credential_data_t *data,
                                     credential_t credential,
                                     gboolean *changed)
{
  if (data == NULL || credential == 0 || changed == NULL)
    return CREDENTIAL_INTERNAL_ERROR;

  credential_return_t ret;
  iterator_t iterator;
  const gchar *effective_algorithm;
  const gchar *effective_identifier;

  if (data->auth_algorithm != NULL)
    {
      if (!g_str_equal (data->auth_algorithm, "md5")
          && !g_str_equal (data->auth_algorithm, "sha1"))
        return CREDENTIAL_INVALID_SNMP_AUTH_ALGORITHM;

      if (set_credential_data (credential,
                               "auth_algorithm",
                               data->auth_algorithm))
        return CREDENTIAL_INTERNAL_ERROR;

      *changed = TRUE;
    }

  if (data->privacy_algorithm == NULL
      && data->privacy_host_identifier == NULL)
    return CREDENTIAL_OK;

  init_credential_iterator_one (&iterator, credential);
  if (!next (&iterator))
    {
      cleanup_iterator (&iterator);
      return CREDENTIAL_INTERNAL_ERROR;
    }

  effective_algorithm =
    data->privacy_algorithm != NULL
      ? data->privacy_algorithm
      : credential_iterator_privacy_algorithm (&iterator);

  effective_identifier =
    data->privacy_host_identifier != NULL
      ? data->privacy_host_identifier
      : credential_iterator_privacy_host_identifier (&iterator);

  ret = validate_snmp_security (NULL,
                                effective_algorithm,
                                effective_identifier);

  cleanup_iterator (&iterator);

  if (ret != CREDENTIAL_OK)
    return ret;

  if (data->privacy_algorithm != NULL)
    {
      if (set_credential_data (credential,
                               "privacy_algorithm",
                               data->privacy_algorithm))
        return CREDENTIAL_INTERNAL_ERROR;

      *changed = TRUE;
    }

  if (data->privacy_host_identifier != NULL)
    {
      if (set_credential_data (credential,
                               "privacy_host_identifier",
                               data->privacy_host_identifier[0] != '\0'
                                 ? data->privacy_host_identifier
                                 : NULL))
        return CREDENTIAL_INTERNAL_ERROR;

      *changed = TRUE;
    }

  return CREDENTIAL_OK;
}

/**
 * @brief Modify a credential backed by an external credential store.
 *
 * @param[in]   data        Credential data.
 * @param[in]   type        Credential type.
 * @param[in]   credential  Credential row ID.
 *
 * @return A credential_return_t return code.
 */
static credential_return_t
modify_credential_store_credential (const credential_data_t *data,
                                    credential_type_t type,
                                    credential_t credential)
{
  credential_return_t ret = CREDENTIAL_OK;
  credential_store_t store;
  gboolean changed = FALSE;

  if (data == NULL || credential == 0)
    return CREDENTIAL_INTERNAL_ERROR;

  if (!feature_enabled (FEATURE_ID_CREDENTIAL_STORES))
    return CREDENTIAL_CREDENTIAL_STORE_UNAVAILABLE;

  if (data->credential_store_id != NULL)
    {
      if (find_credential_store_no_acl (data->credential_store_id, &store)
          || store == 0)
        return CREDENTIAL_CREDENTIAL_STORE_NOT_FOUND;

      if (set_credential_data (credential,
                               "credential_store_id",
                               data->credential_store_id))
        return CREDENTIAL_INTERNAL_ERROR;

      changed = TRUE;
    }

  if (data->vault_id != NULL)
    {
      if (data->vault_id[0] == '\0')
        return CREDENTIAL_VAULT_ID_REQUIRED;

      if (set_credential_data (credential,
                               "vault_id",
                               data->vault_id))
        return CREDENTIAL_INTERNAL_ERROR;

      changed = TRUE;
    }

  if (data->host_identifier != NULL)
    {
      if (data->host_identifier[0] == '\0')
        return CREDENTIAL_HOST_IDENTIFIER_REQUIRED;

      if (set_credential_data (credential,
                               "host_identifier",
                               data->host_identifier))
        return CREDENTIAL_INTERNAL_ERROR;

      changed = TRUE;
    }

   switch (type)
    {
      case CREDENTIAL_TYPE_CS_SNMP:
        ret = modify_credential_store_snmp_fields (data,
                                                   credential,
                                                   &changed);
        break;
      case CREDENTIAL_TYPE_CS_KRB5:
        ret = modify_kerberos_fields (data,
                                      credential,
                                      &changed);
        break;
      case CREDENTIAL_TYPE_CS_UP:
      case CREDENTIAL_TYPE_CS_USK:
      case CREDENTIAL_TYPE_CS_CC:
      case CREDENTIAL_TYPE_CS_SMIME:
      case CREDENTIAL_TYPE_CS_PGP:
      case CREDENTIAL_TYPE_CS_PW:
        break;

      default:
        ret = CREDENTIAL_UNSUPPORTED_TYPE;
        break;
    }

  if (ret == CREDENTIAL_OK && changed)
    update_credential_modification_time (credential);

  return ret;
}
#endif /* ENABLE_CREDENTIAL_STORES */

/**
 * @brief Modify a credential for a specific type.
 *
 * @param[in]   data            Credential data.
 * @param[in]   credential      Credential row ID.
 * @param[in]   type            Credential type.
 *
 * @return A credential_return_t return code.
 */
static credential_return_t
modify_credential_for_type (const credential_data_t *data,
                            credential_t credential,
                            credential_type_t type)
{
  credential_return_t ret;

  ret = modify_credential_common_fields (data, credential);
  if (ret != CREDENTIAL_OK)
    return ret;

  switch (type)
    {
      case CREDENTIAL_TYPE_UP:
        return modify_username_password_credential (data, credential);
      case CREDENTIAL_TYPE_USK:
        return modify_ssh_credential (data, credential);
      case CREDENTIAL_TYPE_SNMP:
        return modify_snmp_credential (data, credential);
      case CREDENTIAL_TYPE_KRB5:
        return modify_kerberos_credential (data, credential);
      case CREDENTIAL_TYPE_CC:
        return modify_cc_credential (data, credential);
      case CREDENTIAL_TYPE_SMIME:
        return modify_smime_credential (data, credential);
      case CREDENTIAL_TYPE_PGP:
        return modify_pgp_credential (data, credential);
      case CREDENTIAL_TYPE_PW:
        return modify_password_credential (data, credential);
#if ENABLE_CREDENTIAL_STORES
      case CREDENTIAL_TYPE_CS_UP:
      case CREDENTIAL_TYPE_CS_USK:
      case CREDENTIAL_TYPE_CS_SNMP:
      case CREDENTIAL_TYPE_CS_KRB5:
      case CREDENTIAL_TYPE_CS_CC:
      case CREDENTIAL_TYPE_CS_SMIME:
      case CREDENTIAL_TYPE_CS_PGP:
      case CREDENTIAL_TYPE_CS_PW:
        return modify_credential_store_credential (data, type, credential);
#endif
      default:
        return CREDENTIAL_UNSUPPORTED_TYPE;
    }
}

/**
 * @brief Modify a credential.
 *
 * @param[in]   data  Credential data.
 *
 * @return A credential_return_t return code.
 */
credential_return_t
modify_credential (const credential_data_t *data)
{
  credential_type_t enum_type;
  credential_t credential = 0;
  credential_return_t ret;
  gchar *db_type = NULL;

  if (data == NULL)
    return CREDENTIAL_INTERNAL_ERROR;

  if (data->credential_id == NULL)
    return CREDENTIAL_CREDENTIAL_ID_REQUIRED;

  assert (current_credentials.uuid);

  sql_begin_immediate ();

  if (!acl_user_may ("modify_credential"))
    {
      ret = CREDENTIAL_PERMISSION_DENIED;
      goto rollback;
    }

  if (find_credential_with_permission (data->credential_id,
                                       &credential,
                                       "modify_credential"))
    {
      ret = CREDENTIAL_INTERNAL_ERROR;
      goto rollback;
    }

  if (credential == 0)
    {
      ret = CREDENTIAL_NOT_FOUND;
      goto rollback;
    }

  db_type = credential_type (credential);
  ret = credential_type_from_string (db_type, &enum_type);
  g_free (db_type);

  if (ret != CREDENTIAL_OK)
    goto rollback;

#if ENABLE_CREDENTIAL_STORES
  if (credential_data_has_store_fields (data)
      && credential_data_has_local_secret_fields (data))
    {
      ret = CREDENTIAL_MIXED_CREDENTIAL_SOURCES;
      goto rollback;
    }
#endif

  ret = modify_credential_for_type (data, credential, enum_type);
  if (ret != CREDENTIAL_OK)
    goto rollback;

  sql_commit ();
  return CREDENTIAL_OK;

rollback:
  sql_rollback ();
  return ret;
}
