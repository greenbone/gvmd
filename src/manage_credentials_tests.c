/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_credentials.c"

#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>

#if ENABLE_AD_INTEGRATION
#include <gvm/ad_connector/ad_connector.h>
#endif

static int saved_disable_encrypted_credentials;
static int copy_rows_result;
static int check_private_key_result;
static gchar *saved_current_credentials_uuid;
static gchar copy_test_user_uuid[] = "test-user";
static const gchar *copy_rows_name;
static const gchar *copy_rows_comment;
static const gchar *copy_rows_credential_id;
static int ad_test_enabled = TRUE;
static int fail_gpgme_new;
static const gchar *retained_ad_host;
static const gchar *retained_ad_port;
static const gchar *retained_ad_tls_mode;
#if ENABLE_AD_INTEGRATION
static gchar *previous_ad_hosts_env;
static gchar *previous_ad_ports_env;
#endif
static int credential_permission_allowed;
static int transaction_active;
static int transaction_begins;
static int transaction_commits;
static int transaction_rollbacks;
static int common_writes;
static int pending_common_writes;
static int pending_ad_writes;
static int ad_connector_calls;

/* Mocks */
credential_return_t
__wrap_insert_credential_base (const credential_data_t *data,
                               const gchar *type,
                               credential_t *credential)
{
  mock (data, type, credential);

  *credential = 123;
  return CREDENTIAL_OK;
}

int
__wrap_set_credential_data (credential_t credential,
                            const char *type,
                            const char *value)
{
  if (transaction_active)
    pending_ad_writes++;
  mock (credential, type, value);
  return 0;
}

void
__wrap_update_credential_modification_time (credential_t credential)
{
  mock (credential);
}

int
__wrap_check_private_key (const char *private_key, const char *passphrase)
{
  mock (private_key, passphrase);
  return check_private_key_result;
}

char *
__wrap_gvm_ssh_public_from_private (const char *private_key,
                                   const char *passphrase)
{
  mock (private_key, passphrase);
  return g_strdup ("ssh-ed25519 test-public-key");
}

int
__wrap_copy_credential_rows (const char *name,
                             const char *comment,
                             const char *credential_id,
                             credential_t *new_credential)
{
  copy_rows_name = name;
  copy_rows_comment = comment;
  copy_rows_credential_id = credential_id;

  if (copy_rows_result == 0)
    *new_credential = 123;

  return copy_rows_result;
}

void
__wrap_init_credential_iterator_one (iterator_t *iterator,
                                     credential_t credential)
{
  (void) credential;
  (void) iterator;
}

gboolean
__wrap_next (iterator_t *iterator)
{
  (void) iterator;
  return TRUE;
}

void
__wrap_cleanup_iterator (iterator_t *iterator)
{
  (void) iterator;
}

int
__wrap_feature_enabled (feature_id_t feature)
{
  return feature == FEATURE_ID_AD_INTEGRATION
           ? ad_test_enabled : FALSE;
}

gpgme_error_t __real_gpgme_new (gpgme_ctx_t *ctx);

gpgme_error_t
__wrap_gpgme_new (gpgme_ctx_t *ctx)
{
  if (fail_gpgme_new)
    return gpg_err_make (GPG_ERR_SOURCE_ANY, GPG_ERR_NOT_OPERATIONAL);

  return __real_gpgme_new (ctx);
}

void
__wrap_sql_begin_immediate (void)
{
  transaction_active = TRUE;
  transaction_begins++;
}

void
__wrap_sql_commit (void)
{
  transaction_active = FALSE;
  transaction_commits++;
}

void
__wrap_sql_rollback (void)
{
  transaction_active = FALSE;
  transaction_rollbacks++;
  pending_common_writes = 0;
  pending_ad_writes = 0;
}

int
__wrap_acl_user_may (const char *permission)
{
  (void) permission;
  return credential_permission_allowed;
}

gboolean
__wrap_find_credential_with_permission (const char *uuid,
                                        credential_t *credential,
                                        const char *permission)
{
  (void) uuid;
  (void) permission;
  *credential = 42;
  return FALSE;
}

char *
__wrap_credential_type (credential_t credential)
{
  (void) credential;
  return g_strdup ("ad");
}

gchar *
__wrap_credential_value (credential_t credential, const char *name)
{
  assert_that (credential, is_equal_to (42));
  if (g_str_equal (name, "ad_host"))
    return g_strdup (retained_ad_host);
  if (g_str_equal (name, "ad_port"))
    return g_strdup (retained_ad_port);
  if (g_str_equal (name, "ad_tls_mode"))
    return g_strdup (retained_ad_tls_mode);
  fail_test ("Unexpected retained credential field");
  return NULL;
}

int
__wrap_resource_with_name_exists (const char *name, const char *type,
                                  resource_t resource)
{
  (void) name;
  (void) type;
  (void) resource;
  return FALSE;
}

int
__wrap_set_credential_name (credential_t credential, const char *name)
{
  (void) credential;
  (void) name;
  assert_that (transaction_active, is_equal_to (TRUE));
  common_writes++;
  pending_common_writes++;
  return 0;
}

int
__wrap_set_credential_comment (credential_t credential, const char *comment)
{
  return __wrap_set_credential_name (credential, comment);
}

int
__wrap_set_credential_allow_insecure (credential_t credential, int value)
{
  (void) value;
  return __wrap_set_credential_name (credential, NULL);
}

#if ENABLE_AD_INTEGRATION
ad_connector_t
__wrap_ad_connector_new (void)
{
  ad_connector_calls++;
  fail_test ("Credential creation/modification must not create a connector");
  return NULL;
}
#endif

static void
expect_no_storage_calls (void)
{
  never_expect (__wrap_insert_credential_base);
  never_expect (__wrap_set_credential_data);
  never_expect (__wrap_update_credential_modification_time);
}

#if ENABLE_AD_INTEGRATION

/**
 * @brief Construct valid creation data without allocating owned strings.
 *
 * @return Credential data borrowing string literals; callers may replace fields.
 */
static credential_data_t
valid_ad_test_data (void)
{
  return (credential_data_t) {
    .name = "test",
    .ad_credential_data = {
      .host = "dc.example.com",
      .bind_dn = "user@domain",
      .base_dn = "DC=example,DC=com",
      .bind_password = "password",
      .tls_mode = "ldaps",
    },
  };
}
#endif

Describe (manage_credentials);
BeforeEach (manage_credentials)
{
  saved_disable_encrypted_credentials = disable_encrypted_credentials;
  disable_encrypted_credentials = TRUE;

  saved_current_credentials_uuid = current_credentials.uuid;
  current_credentials.uuid = copy_test_user_uuid;

  copy_rows_result = 0;
  copy_rows_name = NULL;
  copy_rows_comment = NULL;
  copy_rows_credential_id = NULL;

  check_private_key_result = 0;
  ad_test_enabled = TRUE;
  credential_permission_allowed = TRUE;
  retained_ad_host = "dc.example.com";
  retained_ad_port = "636";
  retained_ad_tls_mode = "ldaps";
  transaction_active = FALSE;
  transaction_begins = transaction_commits = transaction_rollbacks = 0;
  common_writes = pending_common_writes = pending_ad_writes = 0;
  ad_connector_calls = 0;
#if ENABLE_AD_INTEGRATION
  previous_ad_hosts_env = g_strdup (g_getenv ("GVMD_AD_ALLOWED_HOSTS"));
  previous_ad_ports_env = g_strdup (g_getenv ("GVMD_AD_ALLOWED_PORTS"));
  g_setenv ("GVMD_AD_ALLOWED_HOSTS", "", TRUE);
  g_setenv ("GVMD_AD_ALLOWED_PORTS", "389,636,3268,3269", TRUE);
  load_active_directory_config ();
#endif
}

AfterEach (manage_credentials)
{
  disable_encrypted_credentials = saved_disable_encrypted_credentials;
  current_credentials.uuid = saved_current_credentials_uuid;
#if ENABLE_AD_INTEGRATION
  assert_that (ad_connector_calls, is_equal_to (0));
  if (previous_ad_hosts_env)
    g_setenv ("GVMD_AD_ALLOWED_HOSTS", previous_ad_hosts_env, TRUE);
  else
    g_unsetenv ("GVMD_AD_ALLOWED_HOSTS");
  if (previous_ad_ports_env)
    g_setenv ("GVMD_AD_ALLOWED_PORTS", previous_ad_ports_env, TRUE);
  else
    g_unsetenv ("GVMD_AD_ALLOWED_PORTS");
  g_clear_pointer (&previous_ad_hosts_env, g_free);
  g_clear_pointer (&previous_ad_ports_env, g_free);
  load_active_directory_config ();
#endif
}

/* Test suite. */

/* Username and password credential */
Ensure (manage_credentials, create_up_requires_login)
{
  credential_data_t data = {.name = "test"};
  credential_t credential = 42;

  expect_no_storage_calls ();

  assert_that (create_username_password_credential (&data, &credential),
               is_equal_to (CREDENTIAL_LOGIN_REQUIRED));
  assert_that (credential,
               is_equal_to (0));
}

/* SSH credential */
Ensure (manage_credentials, create_ssh_rejects_phrase_without_private_key)
{
  credential_data_t data = {
    .name = "test",
    .login = "user",
    .key_phrase = "phrase",
  };
  credential_t credential = 42;

  expect_no_storage_calls ();

  assert_that (create_ssh_credential (&data, &credential),
               is_equal_to (CREDENTIAL_PRIVATE_KEY_REQUIRED));
  assert_that (credential,
               is_equal_to (0));
}

/* SNMP credential. */
Ensure (manage_credentials, create_snmp_requires_authentication)
{
  credential_data_t data = {.name = "test"};
  credential_t credential = 42;

  expect_no_storage_calls ();

  assert_that (create_snmp_credential (&data, &credential),
               is_equal_to (CREDENTIAL_SNMP_AUTHENTICATION_REQUIRED));
  assert_that (credential,
               is_equal_to (0));
}

Ensure (manage_credentials, create_snmp_v3_requires_auth_algorithm)
{
  credential_data_t data = {
    .name = "test",
    .login = "user",
    .password = "password",
  };
  credential_t credential = 42;

  expect_no_storage_calls ();

  assert_that (create_snmp_credential (&data, &credential),
               is_equal_to (CREDENTIAL_SNMP_AUTH_ALGORITHM_REQUIRED));
  assert_that (credential,
               is_equal_to (0));
}

Ensure (manage_credentials,
        create_snmp_requires_privacy_algorithm_for_privacy_password)
{
  credential_data_t data = {
    .name = "test",
    .community = "public",
    .auth_algorithm = "sha1",
    .privacy_password = "privacy-password",
  };
  credential_t credential = 42;

  expect_no_storage_calls ();

  assert_that (create_snmp_credential (&data, &credential),
               is_equal_to (CREDENTIAL_SNMP_PRIVACY_ALGORITHM_REQUIRED));
  assert_that (credential,
               is_equal_to (0));
}

/* Kerberos credential. */
Ensure (manage_credentials, create_kerberos_requires_password)
{
  credential_data_t data = {
    .name = "test",
    .login = "user",
  };
  credential_t credential = 42;

  expect_no_storage_calls ();

  assert_that (create_kerberos_credential (&data, &credential),
               is_equal_to (CREDENTIAL_PASSWORD_REQUIRED));
  assert_that (credential,
               is_equal_to (0));
}

Ensure (manage_credentials, create_kerberos_requires_realm)
{
  credential_data_t data = {
    .name = "test",
    .login = "user",
    .password = "password",
    .kdc = "127.0.0.1",
  };
  credential_t credential = 42;

  expect_no_storage_calls ();

  assert_that (create_kerberos_credential (&data, &credential),
               is_equal_to (CREDENTIAL_REALM_REQUIRED));
  assert_that (credential,
               is_equal_to (0));
}

Ensure (manage_credentials, create_kerberos_requires_kdc)
{
  credential_data_t data = {
    .name = "test",
    .login = "user",
    .password = "password",
    .realm = "EXAMPLE.COM",
  };
  credential_t credential = 42;

  expect_no_storage_calls ();

  assert_that (create_kerberos_credential (&data, &credential),
               is_equal_to (CREDENTIAL_KDC_REQUIRED));
  assert_that (credential,
               is_equal_to (0));
}

/* Client certificate credential. */
Ensure (manage_credentials, create_cc_requires_private_key_and_certificate)
{
  credential_data_t data = {.name = "test"};
  credential_t credential = 42;

  assert_that (create_cc_credential (&data, &credential),
               is_equal_to (CREDENTIAL_PRIVATE_KEY_REQUIRED));
  assert_that (credential,
               is_equal_to (0));

  data.key_private = "private-key";
  credential = 42;

  expect_no_storage_calls ();

  assert_that (create_cc_credential (&data, &credential),
               is_equal_to (CREDENTIAL_CERTIFICATE_REQUIRED));
  assert_that (credential,
               is_equal_to (0));
}

/* S/MIME credential. */
Ensure (manage_credentials, create_smime_rejects_invalid_certificate)
{
  credential_data_t data = {
    .name = "test",
    .certificate = "not a certificate",
  };
  credential_t credential = 42;

  expect_no_storage_calls ();

  assert_that (create_smime_credential (&data, &credential),
               is_equal_to (CREDENTIAL_INVALID_CERTIFICATE));
  assert_that (credential,
               is_equal_to (0));
}

/* PGP credential. */
Ensure (manage_credentials, create_pgp_rejects_invalid_public_key)
{
  credential_data_t data = {
    .name = "test",
    .key_public = "not a PGP key",
  };
  credential_t credential = 42;

  expect_no_storage_calls ();

  assert_that (create_pgp_credential (&data, &credential),
               is_equal_to (CREDENTIAL_INVALID_PUBLIC_KEY));
  assert_that (credential,
               is_equal_to (0));
}

Ensure (manage_credentials, try_gpgme_import_initialises_gpgme)
{
  const gpgme_data_type_t types_ptr[1] = {GPGME_DATA_TYPE_PGP_KEY};
  GArray *key_types = g_array_new (FALSE, FALSE, sizeof (gpgme_data_type_t));
  int ret;

  g_array_append_vals (key_types, types_ptr, 1);

  ret = try_gpgme_import ("not a PGP key", key_types, GPGME_PROTOCOL_OPENPGP);

  g_array_free (key_types, TRUE);

  assert_that (ret, is_not_equal_to (-1));
}

Ensure (manage_credentials, try_gpgme_import_rejects_failed_gpgme_new)
{
  const gpgme_data_type_t types_ptr[1] = {GPGME_DATA_TYPE_PGP_KEY};
  GArray *key_types = g_array_new (FALSE, FALSE, sizeof (gpgme_data_type_t));
  int ret;

  g_array_append_vals (key_types, types_ptr, 1);

  fail_gpgme_new = 1;
  ret = try_gpgme_import ("not a PGP key", key_types, GPGME_PROTOCOL_OPENPGP);
  fail_gpgme_new = 0;

  g_array_free (key_types, TRUE);

  assert_that (ret, is_equal_to (-1));
}

/* Password credential. */
Ensure (manage_credentials, create_password_stores_supplied_password)
{
  credential_data_t data = {
    .name = "test",
    .password = "test-password",
  };
  credential_t credential = 0;

  expect (__wrap_insert_credential_base,
          when (type, is_equal_to_string ("pw")));

  expect (__wrap_set_credential_data,
          when (credential, is_equal_to (123)),
          when (type, is_equal_to_string ("secret")),
          when (value, is_null));

  expect (__wrap_set_credential_data,
          when (credential, is_equal_to (123)),
          when (type, is_equal_to_string ("password")),
          when (value, is_equal_to_string ("test-password")));

  expect (__wrap_set_credential_data,
          when (credential, is_equal_to (123)),
          when (type, is_equal_to_string ("private_key")),
          when (value, is_null));

  assert_that (create_password_credential (&data, &credential),
               is_equal_to (CREDENTIAL_OK));
  assert_that (credential,
               is_equal_to (123));
}

/* Copy credential. */
Ensure (manage_credentials, copy_credential_forwards_overrides)
{
  credential_t credential = 0;

  assert_that (copy_credential ("copy-name", "copy-comment", "source-id", &credential),
               is_equal_to (CREDENTIAL_OK));
  assert_that (credential, is_equal_to (123));
  assert_that (copy_rows_name, is_equal_to_string ("copy-name"));
  assert_that (copy_rows_comment, is_equal_to_string ("copy-comment"));
  assert_that (copy_rows_credential_id, is_equal_to_string ("source-id"));
}

Ensure (manage_credentials, copy_credential_forwards_null_overrides)
{
  credential_t credential = 0;

  assert_that (copy_credential (NULL, NULL, "source-id", &credential),
               is_equal_to (CREDENTIAL_OK));
  assert_that (credential, is_equal_to (123));
  assert_that (copy_rows_name, is_null);
  assert_that (copy_rows_comment, is_null);
  assert_that (copy_rows_credential_id, is_equal_to_string ("source-id"));
}

Ensure (manage_credentials, copy_credential_maps_row_errors)
{
  const int row_results[] = {1, 2, 99, -1, 7};
  const credential_return_t expected[] = {
    CREDENTIAL_NAME_ALREADY_EXISTS,
    CREDENTIAL_NOT_FOUND,
    CREDENTIAL_PERMISSION_DENIED,
    CREDENTIAL_INTERNAL_ERROR,
    CREDENTIAL_INTERNAL_ERROR,
  };

  for (guint i = 0; i < G_N_ELEMENTS (row_results); i++)
    {
      credential_t credential = 42;
      copy_rows_result = row_results[i];

      assert_that (copy_credential (NULL, NULL, "source-id", &credential),
                   is_equal_to (expected[i]));
      assert_that (credential, is_equal_to (0));
    }
}

/* Credential modification. */
Ensure (manage_credentials, modify_up_updates_login_and_password)
{
  credential_data_t data = {
    .login = "new-user",
    .password = "new-password",
  };

  expect (__wrap_set_credential_data,
          when (credential, is_equal_to (42)),
          when (type, is_equal_to_string ("username")),
          when (value, is_equal_to_string ("new-user")));
  expect (__wrap_set_credential_data,
          when (credential, is_equal_to (42)),
          when (type, is_equal_to_string ("secret")),
          when (value, is_null));
  expect (__wrap_set_credential_data,
          when (credential, is_equal_to (42)),
          when (type, is_equal_to_string ("password")),
          when (value, is_equal_to_string ("new-password")));
  expect (__wrap_set_credential_data,
          when (credential, is_equal_to (42)),
          when (type, is_equal_to_string ("private_key")),
          when (value, is_null));
  expect (__wrap_update_credential_modification_time,
          when (credential, is_equal_to (42)));

  assert_that (modify_username_password_credential (&data, 42),
               is_equal_to (CREDENTIAL_OK));
}

Ensure (manage_credentials, modify_password_updates_password)
{
  credential_data_t data = {
    .password = "new-password",
  };

  expect (__wrap_set_credential_data,
          when (credential, is_equal_to (42)),
          when (type, is_equal_to_string ("secret")),
          when (value, is_null));
  expect (__wrap_set_credential_data,
          when (credential, is_equal_to (42)),
          when (type, is_equal_to_string ("password")),
          when (value, is_equal_to_string ("new-password")));
  expect (__wrap_set_credential_data,
          when (credential, is_equal_to (42)),
          when (type, is_equal_to_string ("private_key")),
          when (value, is_null));
  expect (__wrap_update_credential_modification_time,
          when (credential, is_equal_to (42)));

  assert_that (modify_password_credential (&data, 42),
               is_equal_to (CREDENTIAL_OK));
}

Ensure (manage_credentials, modify_ssh_updates_login)
{
  credential_data_t data = {
    .login = "new-user",
  };

  expect (__wrap_set_credential_data,
          when (credential, is_equal_to (42)),
          when (type, is_equal_to_string ("username")),
          when (value, is_equal_to_string ("new-user")));
  expect (__wrap_update_credential_modification_time,
          when (credential, is_equal_to (42)));

  assert_that (modify_ssh_credential (&data, 42),
               is_equal_to (CREDENTIAL_OK));
}

Ensure (manage_credentials, modify_ssh_updates_supplied_key_and_passphrase)
{
  credential_data_t data = {
    .key_private = "test-private-key",
    .key_phrase = "test-passphrase",
  };

  expect (__wrap_check_private_key,
          when (private_key, is_equal_to_string ("test-private-key")),
          when (passphrase, is_equal_to_string ("test-passphrase")));
  expect (__wrap_gvm_ssh_public_from_private,
          when (private_key, is_equal_to_string ("test-private-key")),
          when (passphrase, is_equal_to_string ("test-passphrase")));
  expect (__wrap_set_credential_data,
          when (credential, is_equal_to (42)),
          when (type, is_equal_to_string ("secret")),
          when (value, is_null));
  expect (__wrap_set_credential_data,
          when (credential, is_equal_to (42)),
          when (type, is_equal_to_string ("password")),
          when (value, is_equal_to_string ("test-passphrase")));
  expect (__wrap_set_credential_data,
          when (credential, is_equal_to (42)),
          when (type, is_equal_to_string ("private_key")),
          when (value, is_equal_to_string ("test-private-key")));
  expect (__wrap_update_credential_modification_time,
          when (credential, is_equal_to (42)));

  assert_that (modify_ssh_credential (&data, 42),
               is_equal_to (CREDENTIAL_OK));
}

Ensure (manage_credentials, create_ssh_rejects_public_key_without_private_key)
{
  credential_data_t data = {
    .name = "test",
    .login = "user",
    .key_public = "public-key",
  };
  credential_t credential = 42;

  expect_no_storage_calls ();

  assert_that (create_ssh_credential (&data, &credential),
               is_equal_to (CREDENTIAL_PRIVATE_KEY_REQUIRED));
  assert_that (credential, is_equal_to (0));
}

Ensure (manage_credentials, modify_snmp_updates_login_and_auth_algorithm)
{
  credential_data_t data = {
    .login = "new-user",
    .auth_algorithm = "sha1",
  };

  expect (__wrap_set_credential_data,
          when (credential, is_equal_to (42)),
          when (type, is_equal_to_string ("username")),
          when (value, is_equal_to_string ("new-user")));
  expect (__wrap_set_credential_data,
          when (credential, is_equal_to (42)),
          when (type, is_equal_to_string ("auth_algorithm")),
          when (value, is_equal_to_string ("sha1")));
  expect (__wrap_update_credential_modification_time,
          when (credential, is_equal_to (42)));

  assert_that (modify_snmp_credential (&data, 42),
               is_equal_to (CREDENTIAL_OK));
}

Ensure (manage_credentials, modify_snmp_rejects_invalid_auth_algorithm)
{
  credential_data_t data = {
    .auth_algorithm = "invalid",
  };

  expect_no_storage_calls ();

  assert_that (modify_snmp_credential (&data, 42),
               is_equal_to (CREDENTIAL_INVALID_SNMP_AUTH_ALGORITHM));
}

Ensure (manage_credentials, modify_kerberos_updates_supplied_fields)
{
  credential_data_t data = {
    .login = "new-user",
    .password = "new-password",
    .realm = "EXAMPLE.COM",
    .kdc = "127.0.0.1",
  };

  expect (__wrap_set_credential_data,
          when (credential, is_equal_to (42)),
          when (type, is_equal_to_string ("username")),
          when (value, is_equal_to_string ("new-user")));
  expect (__wrap_set_credential_data,
          when (credential, is_equal_to (42)),
          when (type, is_equal_to_string ("secret")),
          when (value, is_null));
  expect (__wrap_set_credential_data,
          when (credential, is_equal_to (42)),
          when (type, is_equal_to_string ("password")),
          when (value, is_equal_to_string ("new-password")));
  expect (__wrap_set_credential_data,
          when (credential, is_equal_to (42)),
          when (type, is_equal_to_string ("private_key")),
          when (value, is_null));
  expect (__wrap_set_credential_data,
          when (credential, is_equal_to (42)),
          when (type, is_equal_to_string ("realm")),
          when (value, is_equal_to_string ("EXAMPLE.COM")));
  expect (__wrap_set_credential_data,
          when (credential, is_equal_to (42)),
          when (type, is_equal_to_string ("kdc")),
          when (value, is_equal_to_string ("127.0.0.1")));
  expect (__wrap_update_credential_modification_time,
          when (credential, is_equal_to (42)));

  assert_that (modify_kerberos_credential (&data, 42),
               is_equal_to (CREDENTIAL_OK));
}

Ensure (manage_credentials, modify_kerberos_rejects_invalid_realm)
{
  credential_data_t data = {
    .realm = "not a realm",
  };

  expect_no_storage_calls ();

  assert_that (modify_kerberos_credential (&data, 42),
               is_equal_to (CREDENTIAL_INVALID_REALM));
}

Ensure (manage_credentials, modify_cc_ignores_absent_key_and_certificate)
{
  credential_data_t data = { 0 };

  expect_no_storage_calls ();

  assert_that (modify_cc_credential (&data, 42),
               is_equal_to (CREDENTIAL_OK));
}

Ensure (manage_credentials, modify_cc_rejects_invalid_certificate)
{
  credential_data_t data = {
    .certificate = "not a certificate",
  };

  expect_no_storage_calls ();

  assert_that (modify_cc_credential (&data, 42),
               is_equal_to (CREDENTIAL_INVALID_CERTIFICATE));
}

Ensure (manage_credentials, modify_cc_clears_empty_certificate)
{
  credential_data_t data = {
    .certificate = "",
  };

  expect (__wrap_set_credential_data,
          when (credential, is_equal_to (42)),
          when (type, is_equal_to_string ("certificate")),
          when (value, is_null));
  expect (__wrap_update_credential_modification_time,
          when (credential, is_equal_to (42)));

  assert_that (modify_cc_credential (&data, 42),
               is_equal_to (CREDENTIAL_OK));
}

Ensure (manage_credentials, modify_cc_rejects_invalid_private_key)
{
  credential_data_t data = {
    .key_private = "not a private key",
    .key_phrase = "",
  };

  check_private_key_result = 1;

  expect (__wrap_check_private_key,
          when (private_key, is_equal_to_string ("not a private key")),
          when (passphrase, is_equal_to_string ("")));

  never_expect (__wrap_set_credential_data);
  never_expect (__wrap_update_credential_modification_time);

  assert_that (modify_cc_credential (&data, 42),
               is_equal_to (CREDENTIAL_INVALID_PRIVATE_KEY_OR_PASSPHRASE));
}

Ensure (manage_credentials, modify_cc_clears_empty_private_key)
{
  credential_data_t data = {
    .key_private = "",
    .key_phrase = "",
  };

  expect (__wrap_set_credential_data,
          when (credential, is_equal_to (42)),
          when (type, is_equal_to_string ("secret")),
          when (value, is_null));
  expect (__wrap_set_credential_data,
          when (credential, is_equal_to (42)),
          when (type, is_equal_to_string ("password")),
          when (value, is_null));
  expect (__wrap_set_credential_data,
          when (credential, is_equal_to (42)),
          when (type, is_equal_to_string ("private_key")),
          when (value, is_null));
  expect (__wrap_update_credential_modification_time,
          when (credential, is_equal_to (42)));

  assert_that (modify_cc_credential (&data, 42),
               is_equal_to (CREDENTIAL_OK));
}

Ensure (manage_credentials, modify_smime_rejects_invalid_certificate)
{
  credential_data_t data = {
    .certificate = "not a certificate",
  };

  expect_no_storage_calls ();

  assert_that (modify_smime_credential (&data, 42),
               is_equal_to (CREDENTIAL_INVALID_CERTIFICATE));
}

Ensure (manage_credentials, modify_smime_clears_empty_certificate)
{
  credential_data_t data = {
    .certificate = "",
  };

  expect (__wrap_set_credential_data,
          when (credential, is_equal_to (42)),
          when (type, is_equal_to_string ("certificate")),
          when (value, is_null));
  expect (__wrap_update_credential_modification_time,
          when (credential, is_equal_to (42)));

  assert_that (modify_smime_credential (&data, 42),
               is_equal_to (CREDENTIAL_OK));
}

Ensure (manage_credentials, modify_pgp_rejects_invalid_public_key)
{
  credential_data_t data = {
    .key_public = "not a PGP key",
  };

  expect_no_storage_calls ();

  assert_that (modify_pgp_credential (&data, 42),
               is_equal_to (CREDENTIAL_INVALID_PUBLIC_KEY));
}

Ensure (manage_credentials, modify_pgp_ignores_absent_public_key)
{
  credential_data_t data = { 0 };

  expect_no_storage_calls ();

  assert_that (modify_pgp_credential (&data, 42),
               is_equal_to (CREDENTIAL_OK));
}

Ensure (manage_credentials, modify_pgp_clears_empty_public_key)
{
  credential_data_t data = {
    .key_public = "",
  };

  expect (__wrap_set_credential_data,
          when (credential, is_equal_to (42)),
          when (type, is_equal_to_string ("public_key")),
          when (value, is_null));
  expect (__wrap_update_credential_modification_time,
          when (credential, is_equal_to (42)));

  assert_that (modify_pgp_credential (&data, 42),
               is_equal_to (CREDENTIAL_OK));
}

#if ENABLE_AD_INTEGRATION
Ensure (manage_credentials, create_ad_unavailable_when_feature_disabled)
{
  credential_t credential = 42;
  credential_data_t data = valid_ad_test_data ();
  ad_test_enabled = FALSE;

  expect_no_storage_calls ();

  assert_that (create_active_directory_credential (&data, &credential),
               is_equal_to (CREDENTIAL_AD_INTEGRATION_UNAVAILABLE));
  assert_that (credential, is_equal_to (0));
}

Ensure (manage_credentials, create_ad_requires_host)
{
  credential_t credential = 42;
  credential_data_t data = valid_ad_test_data ();
  data.ad_credential_data.host = NULL;
  ad_test_enabled = TRUE;

  expect_no_storage_calls ();

  assert_that (create_active_directory_credential (&data, &credential),
               is_equal_to (CREDENTIAL_AD_HOST_REQUIRED));
  assert_that (credential, is_equal_to (0));
}

Ensure (manage_credentials, create_ad_rejects_empty_host)
{
  credential_t credential = 42;
  credential_data_t data = valid_ad_test_data ();
  data.ad_credential_data.host = "";

  expect_no_storage_calls ();

  assert_that (create_active_directory_credential (&data, &credential),
               is_equal_to (CREDENTIAL_AD_HOST_REQUIRED));
  assert_that (credential, is_equal_to (0));
}

Ensure (manage_credentials, create_ad_requires_bind_dn)
{
  credential_t credential = 42;
  credential_data_t data = valid_ad_test_data ();
  data.ad_credential_data.bind_dn = NULL;

  expect_no_storage_calls ();

  assert_that (create_active_directory_credential (&data, &credential),
               is_equal_to (CREDENTIAL_AD_BIND_DN_REQUIRED));
  assert_that (credential, is_equal_to (0));
}

Ensure (manage_credentials, create_ad_rejects_empty_bind_dn)
{
  credential_t credential = 42;
  credential_data_t data = valid_ad_test_data ();
  data.ad_credential_data.bind_dn = "";

  expect_no_storage_calls ();

  assert_that (create_active_directory_credential (&data, &credential),
               is_equal_to (CREDENTIAL_AD_BIND_DN_REQUIRED));
  assert_that (credential, is_equal_to (0));
}

Ensure (manage_credentials, create_ad_requires_base_dn)
{
  credential_t credential = 42;
  credential_data_t data = valid_ad_test_data ();
  data.ad_credential_data.base_dn = NULL;

  expect_no_storage_calls ();

  assert_that (create_active_directory_credential (&data, &credential),
               is_equal_to (CREDENTIAL_AD_BASE_DN_REQUIRED));
  assert_that (credential, is_equal_to (0));
}

Ensure (manage_credentials, create_ad_rejects_empty_base_dn)
{
  credential_t credential = 42;
  credential_data_t data = valid_ad_test_data ();
  data.ad_credential_data.base_dn = "";

  expect_no_storage_calls ();

  assert_that (create_active_directory_credential (&data, &credential),
               is_equal_to (CREDENTIAL_AD_BASE_DN_REQUIRED));
  assert_that (credential, is_equal_to (0));
}

Ensure (manage_credentials, create_ad_requires_bind_password)
{
  credential_t credential = 42;
  credential_data_t data = valid_ad_test_data ();
  data.ad_credential_data.bind_password = NULL;

  expect_no_storage_calls ();

  assert_that (create_active_directory_credential (&data, &credential),
               is_equal_to (CREDENTIAL_AD_BIND_PASSWORD_REQUIRED));
  assert_that (credential, is_equal_to (0));
}

Ensure (manage_credentials, create_ad_rejects_empty_bind_password)
{
  credential_t credential = 42;
  credential_data_t data = valid_ad_test_data ();
  data.ad_credential_data.bind_password = "";

  expect_no_storage_calls ();

  assert_that (create_active_directory_credential (&data, &credential),
               is_equal_to (CREDENTIAL_AD_BIND_PASSWORD_REQUIRED));
  assert_that (credential, is_equal_to (0));
}

Ensure (manage_credentials, create_ad_rejects_empty_port)
{
  credential_t credential = 42;
  credential_data_t data = valid_ad_test_data ();
  data.ad_credential_data.port = "";

  expect_no_storage_calls ();

  assert_that (create_active_directory_credential (&data, &credential),
               is_equal_to (CREDENTIAL_AD_INVALID_PORT));
  assert_that (credential, is_equal_to (0));
}

Ensure (manage_credentials, create_ad_rejects_zero_port)
{
  credential_t credential = 42;
  credential_data_t data = valid_ad_test_data ();
  data.ad_credential_data.port = "0";

  expect_no_storage_calls ();

  assert_that (create_active_directory_credential (&data, &credential),
               is_equal_to (CREDENTIAL_AD_INVALID_PORT));
  assert_that (credential, is_equal_to (0));
}

Ensure (manage_credentials, create_ad_rejects_port_above_maximum)
{
  credential_t credential = 42;
  credential_data_t data = valid_ad_test_data ();
  data.ad_credential_data.port = "65536";

  expect_no_storage_calls ();

  assert_that (create_active_directory_credential (&data, &credential),
               is_equal_to (CREDENTIAL_AD_INVALID_PORT));
  assert_that (credential, is_equal_to (0));
}

Ensure (manage_credentials, create_ad_rejects_negative_port)
{
  credential_t credential = 42;
  credential_data_t data = valid_ad_test_data ();
  data.ad_credential_data.port = "-1";

  expect_no_storage_calls ();

  assert_that (create_active_directory_credential (&data, &credential),
               is_equal_to (CREDENTIAL_AD_INVALID_PORT));
  assert_that (credential, is_equal_to (0));
}

Ensure (manage_credentials, create_ad_requires_tls_mode)
{
  credential_t credential = 42;
  credential_data_t data = valid_ad_test_data ();
  data.ad_credential_data.tls_mode = NULL;

  expect_no_storage_calls ();

  assert_that (create_active_directory_credential (&data, &credential),
               is_equal_to (CREDENTIAL_AD_TLS_MODE_REQUIRED));
  assert_that (credential, is_equal_to (0));
}

Ensure (manage_credentials, create_ad_rejects_empty_tls_mode)
{
  credential_t credential = 42;
  credential_data_t data = valid_ad_test_data ();
  data.ad_credential_data.tls_mode = "";

  expect_no_storage_calls ();

  assert_that (create_active_directory_credential (&data, &credential),
               is_equal_to (CREDENTIAL_AD_TLS_MODE_REQUIRED));
  assert_that (credential, is_equal_to (0));
}

Ensure (manage_credentials, create_ad_rejects_plain_ldap)
{
  credential_t credential = 42;
  credential_data_t data = valid_ad_test_data ();
  data.ad_credential_data.tls_mode = "ldap";

  expect_no_storage_calls ();

  assert_that (create_active_directory_credential (&data, &credential),
               is_equal_to (CREDENTIAL_AD_INVALID_TLS_MODE));
  assert_that (credential, is_equal_to (0));
}

Ensure (manage_credentials, create_ad_rejects_empty_ca_certificate)
{
  credential_t credential = 42;
  credential_data_t data = valid_ad_test_data ();
  data.ad_credential_data.ca_certificate = "";

  expect_no_storage_calls ();

  assert_that (create_active_directory_credential (&data, &credential),
               is_equal_to (CREDENTIAL_AD_INVALID_CA_CERTIFICATE));
  assert_that (credential, is_equal_to (0));
}

Ensure (manage_credentials, create_ad_rejects_invalid_ca_certificate)
{
  credential_t credential = 42;
  credential_data_t data = valid_ad_test_data ();
  data.ad_credential_data.ca_certificate = "invalid";

  expect_no_storage_calls ();

  assert_that (create_active_directory_credential (&data, &credential),
               is_equal_to (CREDENTIAL_AD_INVALID_CA_CERTIFICATE));
  assert_that (credential, is_equal_to (0));
}

Ensure (manage_credentials, create_ad_stores_valid_data)
{
  credential_t credential = 0;
  credential_data_t data = valid_ad_test_data ();
  data.ad_credential_data.port = "636";
  data.ad_credential_data.tls_mode = "ldaps";
  ad_test_enabled = TRUE;

  expect (__wrap_insert_credential_base,
          when (type, is_equal_to_string ("ad")));

  expect (__wrap_set_credential_data,
          when (credential, is_equal_to (123)),
          when (type, is_equal_to_string ("ad_host")),
          when (value, is_equal_to_string ("dc.example.com")));

  expect (__wrap_set_credential_data,
          when (credential, is_equal_to (123)),
          when (type, is_equal_to_string ("ad_bind_dn")),
          when (value, is_equal_to_string ("user@domain")));

  expect (__wrap_set_credential_data,
          when (credential, is_equal_to (123)),
          when (type, is_equal_to_string ("ad_base_dn")),
          when (value, is_equal_to_string ("DC=example,DC=com")));

  expect (__wrap_set_credential_data,
          when (credential, is_equal_to (123)),
          when (type, is_equal_to_string ("ad_port")),
          when (value, is_equal_to_string ("636")));

  expect (__wrap_set_credential_data,
          when (credential, is_equal_to (123)),
          when (type, is_equal_to_string ("ad_tls_mode")),
          when (value, is_equal_to_string ("ldaps")));

  expect (__wrap_set_credential_data,
          when (credential, is_equal_to (123)),
          when (type, is_equal_to_string ("ad_ca_certificate")),
          when (value, is_null));

  expect (__wrap_set_credential_data,
          when (credential, is_equal_to (123)),
          when (type, is_equal_to_string ("secret")),
          when (value, is_null));

  expect (__wrap_set_credential_data,
          when (credential, is_equal_to (123)),
          when (type, is_equal_to_string ("password")),
          when (value, is_equal_to_string ("password")));

  expect (__wrap_set_credential_data,
          when (credential, is_equal_to (123)),
          when (type, is_equal_to_string ("private_key")),
          when (value, is_null));

  assert_that (create_active_directory_credential (&data, &credential),
               is_equal_to (CREDENTIAL_OK));
  assert_that (credential, is_equal_to (123));
}

Ensure (manage_credentials, create_ad_rejects_policy_and_host_before_storage)
{
  credential_data_t data = valid_ad_test_data ();
  credential_t credential = 42;
  const gchar *bad_hosts[] = { "dc.example.com:636", "*.example.com",
                              "192.0.2.0/24", " dc.example.com", "\t" };

  expect_no_storage_calls ();
  g_setenv ("GVMD_AD_ALLOWED_HOSTS", "other.invalid", TRUE);
  load_active_directory_config ();
  assert_that (create_active_directory_credential (&data, &credential),
               is_equal_to (CREDENTIAL_AD_DESTINATION_NOT_ALLOWED));
  assert_that (credential, is_equal_to (0));
  for (guint i = 0; i < G_N_ELEMENTS (bad_hosts); i++)
    {
      data.ad_credential_data.host = (gchar *) bad_hosts[i];
      assert_that (create_active_directory_credential (&data, &credential),
                   is_equal_to (CREDENTIAL_AD_INVALID_HOST));
    }
  data = valid_ad_test_data ();
  data.ad_credential_data.port = "invalid";
  assert_that (create_active_directory_credential (&data, &credential),
               is_equal_to (CREDENTIAL_AD_INVALID_PORT));
  g_setenv ("GVMD_AD_ALLOWED_HOSTS", "", TRUE);
  g_setenv ("GVMD_AD_ALLOWED_PORTS", "389", TRUE);
  load_active_directory_config ();
  data.ad_credential_data.port = NULL;
  assert_that (create_active_directory_credential (&data, &credential),
               is_equal_to (CREDENTIAL_AD_DESTINATION_NOT_ALLOWED));
  data.ad_credential_data.port = "1389";
  assert_that (create_active_directory_credential (&data, &credential),
               is_equal_to (CREDENTIAL_AD_DESTINATION_NOT_ALLOWED));
}

Ensure (manage_credentials, create_ad_empty_lists_store_nonstandard_original_values)
{
  credential_data_t data = valid_ad_test_data ();
  credential_t credential = 0;
  const gchar *fields[] = {
    "ad_host", "ad_bind_dn", "ad_base_dn", "ad_port", "ad_tls_mode",
    "ad_ca_certificate", "secret", "password", "private_key"
  };
  const gchar *values[] = {
    "UNRESOLVABLE.invalid.", " \t ", "\t", "001389", "ldaps",
    NULL, NULL, " password\t ", NULL
  };

  g_setenv ("GVMD_AD_ALLOWED_HOSTS", " \t ", TRUE);
  g_setenv ("GVMD_AD_ALLOWED_PORTS", "", TRUE);
  load_active_directory_config ();
  data.ad_credential_data.host = (gchar *) values[0];
  data.ad_credential_data.bind_dn = (gchar *) values[1];
  data.ad_credential_data.base_dn = (gchar *) values[2];
  data.ad_credential_data.port = (gchar *) values[3];
  data.ad_credential_data.bind_password = (gchar *) values[7];
  expect (__wrap_insert_credential_base,
          when (type, is_equal_to_string ("ad")));
  for (guint i = 0; i < G_N_ELEMENTS (fields); i++)
    expect (__wrap_set_credential_data,
            when (credential, is_equal_to (123)),
            when (type, is_equal_to_string (fields[i])),
            when (value, values[i] ? is_equal_to_string (values[i]) : is_null));
  assert_that (create_active_directory_credential (&data, &credential),
               is_equal_to (CREDENTIAL_OK));
  assert_that (credential, is_equal_to (123));
}

Ensure (manage_credentials, ad_whitespace_and_creation_syntax_precede_policy)
{
  credential_data_t data = valid_ad_test_data ();
  credential_t credential = 42;
  const gchar *whitespace[] = { " ", "\t", " \t " };

  expect_no_storage_calls ();
  g_setenv ("GVMD_AD_ALLOWED_HOSTS", "other.invalid", TRUE);
  load_active_directory_config ();
  for (guint i = 0; i < G_N_ELEMENTS (whitespace); i++)
    {
      credential_data_t update = { 0 };
      data.ad_credential_data.host = (gchar *) whitespace[i];
      update.ad_credential_data.host = (gchar *) whitespace[i];
      assert_that (create_active_directory_credential (&data, &credential),
                   is_equal_to (CREDENTIAL_AD_INVALID_HOST));
      assert_that (modify_active_directory_credential (&update, 42),
                   is_equal_to (CREDENTIAL_AD_INVALID_HOST));
      data.ad_credential_data.host = "dc.example.com";
      data.ad_credential_data.port = (gchar *) whitespace[i];
      update.ad_credential_data.host = NULL;
      update.ad_credential_data.port = (gchar *) whitespace[i];
      assert_that (create_active_directory_credential (&data, &credential),
                   is_equal_to (CREDENTIAL_AD_INVALID_PORT));
      assert_that (modify_active_directory_credential (&update, 42),
                   is_equal_to (CREDENTIAL_AD_INVALID_PORT));
      data.ad_credential_data.port = NULL;
    }

  /* Multiple invalid fields preserve the existing create validation order. */
  data.ad_credential_data.host = "\tdc.example.com";
  data.ad_credential_data.bind_dn = "";
  data.ad_credential_data.port = "636\t";
  data.ad_credential_data.tls_mode = "ldaps ";
  data.ad_credential_data.ca_certificate = "invalid";
  assert_that (create_active_directory_credential (&data, &credential),
               is_equal_to (CREDENTIAL_AD_BIND_DN_REQUIRED));
  data.ad_credential_data.bind_dn = " \t ";
  assert_that (create_active_directory_credential (&data, &credential),
               is_equal_to (CREDENTIAL_AD_INVALID_PORT));
  data.ad_credential_data.port = "636";
  assert_that (create_active_directory_credential (&data, &credential),
               is_equal_to (CREDENTIAL_AD_INVALID_HOST));
  data.ad_credential_data.host = "dc.example.com";
  assert_that (create_active_directory_credential (&data, &credential),
               is_equal_to (CREDENTIAL_AD_INVALID_TLS_MODE));
  data.ad_credential_data.tls_mode = "ldaps";
  assert_that (create_active_directory_credential (&data, &credential),
               is_equal_to (CREDENTIAL_AD_INVALID_CA_CERTIFICATE));
  assert_that (credential, is_equal_to (0));
}

Ensure (manage_credentials, modify_ad_empty_lists_preserve_nonstandard_and_whitespace)
{
  credential_data_t data = {
    .ad_credential_data = {
      .host = "UNRESOLVABLE.invalid.",
      .port = "001389",
      .bind_dn = " \t ",
      .base_dn = "\t",
    },
  };

  g_setenv ("GVMD_AD_ALLOWED_HOSTS", "", TRUE);
  g_setenv ("GVMD_AD_ALLOWED_PORTS", " \t ", TRUE);
  load_active_directory_config ();
  expect (__wrap_set_credential_data,
          when (type, is_equal_to_string ("ad_host")),
          when (value, is_equal_to_string ("UNRESOLVABLE.invalid.")));
  expect (__wrap_set_credential_data,
          when (type, is_equal_to_string ("ad_bind_dn")),
          when (value, is_equal_to_string (" \t ")));
  expect (__wrap_set_credential_data,
          when (type, is_equal_to_string ("ad_base_dn")),
          when (value, is_equal_to_string ("\t")));
  expect (__wrap_set_credential_data,
          when (type, is_equal_to_string ("ad_port")),
          when (value, is_equal_to_string ("001389")));
  expect (__wrap_update_credential_modification_time);
  assert_that (modify_active_directory_credential (&data, 42),
               is_equal_to (CREDENTIAL_OK));
}

Ensure (manage_credentials, modify_ad_checks_merged_destination_before_writes)
{
  const struct
  {
    const gchar *host;
    const gchar *port;
    const gchar *tls_mode;
    const gchar *saved_host;
    const gchar *saved_port;
    const gchar *allowed_ports;
  } cases[] = {
    { "other.invalid", NULL, NULL, "dc.example.com", "636", "636" },
    { NULL, "1389", NULL, "dc.example.com", "636", "636" },
    { NULL, NULL, "starttls", "dc.example.com", NULL, "636" },
    { NULL, "", NULL, "dc.example.com", "1389", "1389" },
    { NULL, NULL, NULL, "other.invalid", "636", "636" },
    { NULL, NULL, NULL, "dc.example.com", "1389", "636" },
  };

  expect_no_storage_calls ();
  g_setenv ("GVMD_AD_ALLOWED_HOSTS", "dc.example.com", TRUE);
  for (guint i = 0; i < G_N_ELEMENTS (cases); i++)
    {
      credential_data_t data = { 0 };
      data.ad_credential_data.host = (gchar *) cases[i].host;
      data.ad_credential_data.port = (gchar *) cases[i].port;
      data.ad_credential_data.tls_mode = (gchar *) cases[i].tls_mode;
      retained_ad_host = cases[i].saved_host;
      retained_ad_port = cases[i].saved_port;
      g_setenv ("GVMD_AD_ALLOWED_PORTS", cases[i].allowed_ports, TRUE);
      load_active_directory_config ();
      assert_that (modify_active_directory_credential (&data, 42),
                   is_equal_to (CREDENTIAL_AD_DESTINATION_NOT_ALLOWED));
    }
}

Ensure (manage_credentials, modify_ad_accepts_merged_defaults_and_original_values)
{
  const struct
  {
    const gchar *field;
    const gchar *value;
    const gchar *saved_port;
    const gchar *allowed_ports;
  } cases[] = {
    { "ad_host", "DC.Example.COM.", "636", "636" },
    { "ad_port", "0003268", "636", "3268" },
    { "ad_tls_mode", "starttls", NULL, "389" },
    { "ad_port", "", "1389", "636" },
  };

  g_setenv ("GVMD_AD_ALLOWED_HOSTS", "dc.example.com", TRUE);
  for (guint i = 0; i < G_N_ELEMENTS (cases); i++)
    {
      credential_data_t data = { 0 };
      if (g_str_equal (cases[i].field, "ad_host"))
        data.ad_credential_data.host = (gchar *) cases[i].value;
      else if (g_str_equal (cases[i].field, "ad_port"))
        data.ad_credential_data.port = (gchar *) cases[i].value;
      else
        data.ad_credential_data.tls_mode = (gchar *) cases[i].value;
      retained_ad_port = cases[i].saved_port;
      g_setenv ("GVMD_AD_ALLOWED_PORTS", cases[i].allowed_ports, TRUE);
      load_active_directory_config ();
      expect (__wrap_set_credential_data,
              when (type, is_equal_to_string (cases[i].field)),
              when (value, *cases[i].value
                             ? is_equal_to_string (cases[i].value) : is_null));
      expect (__wrap_update_credential_modification_time);
      assert_that (modify_active_directory_credential (&data, 42),
                   is_equal_to (CREDENTIAL_OK));
    }
}

Ensure (manage_credentials, modify_ad_syntax_precedes_policy_without_partial_writes)
{
  credential_data_t data = { 0 };

  expect_no_storage_calls ();
  g_setenv ("GVMD_AD_ALLOWED_HOSTS", "other.invalid", TRUE);
  load_active_directory_config ();
  data.ad_credential_data.host = "dc.example.com";
  data.ad_credential_data.bind_dn = "new-user";
  data.ad_credential_data.port = "0";
  assert_that (modify_active_directory_credential (&data, 42),
               is_equal_to (CREDENTIAL_AD_INVALID_PORT));
  data.ad_credential_data.port = NULL;
  data.ad_credential_data.host = " dc.example.com";
  assert_that (modify_active_directory_credential (&data, 42),
               is_equal_to (CREDENTIAL_AD_INVALID_HOST));
  data.ad_credential_data.host = NULL;
  retained_ad_host = "*.example.com";
  assert_that (modify_active_directory_credential (&data, 42),
               is_equal_to (CREDENTIAL_AD_INVALID_HOST));
  retained_ad_host = "dc.example.com";
  retained_ad_port = "invalid";
  assert_that (modify_active_directory_credential (&data, 42),
               is_equal_to (CREDENTIAL_AD_INVALID_PORT));
}

Ensure (manage_credentials, modify_ad_denial_rolls_back_common_fields)
{
  credential_data_t data = {
    .credential_id = "credential-id",
    .name = "new-name",
    .comment = "new-comment",
    .allow_insecure = "1",
    .ad_credential_data = { .bind_dn = "new-user", .port = "1389" },
  };

  expect_no_storage_calls ();
  assert_that (modify_credential (&data),
               is_equal_to (CREDENTIAL_AD_DESTINATION_NOT_ALLOWED));
  assert_that (common_writes, is_equal_to (3));
  assert_that (transaction_begins, is_equal_to (1));
  assert_that (transaction_rollbacks, is_equal_to (1));
  assert_that (transaction_commits, is_equal_to (0));
  assert_that (pending_common_writes, is_equal_to (0));
  assert_that (pending_ad_writes, is_equal_to (0));
  assert_that (transaction_active, is_equal_to (FALSE));

  /* A common-field-only update must also recheck the retained endpoint. */
  data.ad_credential_data = (ad_credential_data_t) { 0 };
  retained_ad_host = "other.invalid";
  g_setenv ("GVMD_AD_ALLOWED_HOSTS", "dc.example.com", TRUE);
  load_active_directory_config ();
  assert_that (modify_credential (&data),
               is_equal_to (CREDENTIAL_AD_DESTINATION_NOT_ALLOWED));
  assert_that (common_writes, is_equal_to (6));
  assert_that (transaction_rollbacks, is_equal_to (2));
  assert_that (transaction_commits, is_equal_to (0));
  assert_that (pending_common_writes, is_equal_to (0));
  assert_that (pending_ad_writes, is_equal_to (0));
}

Ensure (manage_credentials, modify_ad_merged_defaults_and_syntax_roll_back)
{
  const struct {
    const gchar *port;
    const gchar *tls_mode;
    const gchar *saved_host;
    const gchar *saved_port;
    const gchar *saved_tls_mode;
    const gchar *allowed_ports;
    credential_return_t result;
  } cases[] = {
    { "", "starttls", "dc.example.com", "1389", "ldaps", "636",
      CREDENTIAL_AD_DESTINATION_NOT_ALLOWED },
    { "", "ldaps", "dc.example.com", "1389", "starttls", "389",
      CREDENTIAL_AD_DESTINATION_NOT_ALLOWED },
    { NULL, NULL, "dc.example.com", "636\t", "ldaps", "636",
      CREDENTIAL_AD_INVALID_PORT },
    { NULL, NULL, "dc.example.com", NULL, NULL, "636",
      CREDENTIAL_AD_INVALID_TLS_MODE },
    { NULL, NULL, NULL, "636", "ldaps", "636",
      CREDENTIAL_AD_HOST_REQUIRED },
  };

  expect_no_storage_calls ();
  for (guint i = 0; i < G_N_ELEMENTS (cases); i++)
    {
      credential_data_t data = {
        .credential_id = "credential-id",
        .name = "new-name",
        .comment = "new-comment",
        .allow_insecure = "1",
        .ad_credential_data = {
          .port = (gchar *) cases[i].port,
          .tls_mode = (gchar *) cases[i].tls_mode,
          .bind_dn = "new-user",
        },
      };

      retained_ad_host = cases[i].saved_host;
      retained_ad_port = cases[i].saved_port;
      retained_ad_tls_mode = cases[i].saved_tls_mode;
      g_setenv ("GVMD_AD_ALLOWED_PORTS", cases[i].allowed_ports, TRUE);
      load_active_directory_config ();
      assert_that (modify_credential (&data), is_equal_to (cases[i].result));
      assert_that (common_writes, is_equal_to (3 * (i + 1)));
      assert_that (transaction_begins, is_equal_to (i + 1));
      assert_that (transaction_rollbacks, is_equal_to (i + 1));
      assert_that (transaction_commits, is_equal_to (0));
      assert_that (pending_common_writes, is_equal_to (0));
      assert_that (pending_ad_writes, is_equal_to (0));
      assert_that (transaction_active, is_equal_to (FALSE));
    }
}

Ensure (manage_credentials, modify_ad_allowed_update_commits_common_and_ad_fields)
{
  credential_data_t data = {
    .credential_id = "credential-id",
    .comment = "new-comment",
    .ad_credential_data = { .port = "", .tls_mode = "starttls" },
  };

  retained_ad_port = "1389";
  g_setenv ("GVMD_AD_ALLOWED_PORTS", "389", TRUE);
  load_active_directory_config ();
  expect (__wrap_set_credential_data,
          when (type, is_equal_to_string ("ad_port")), when (value, is_null));
  expect (__wrap_set_credential_data,
          when (type, is_equal_to_string ("ad_tls_mode")),
          when (value, is_equal_to_string ("starttls")));
  expect (__wrap_update_credential_modification_time);
  assert_that (modify_credential (&data), is_equal_to (CREDENTIAL_OK));
  assert_that (common_writes, is_equal_to (1));
  assert_that (pending_common_writes, is_equal_to (1));
  assert_that (pending_ad_writes, is_equal_to (2));
  assert_that (transaction_commits, is_equal_to (1));
  assert_that (transaction_rollbacks, is_equal_to (0));
}

Ensure (manage_credentials, ad_command_permissions_precede_policy)
{
  credential_data_t data = valid_ad_test_data ();
  credential_t credential = 42;

  data.type = "ad";
  data.credential_id = "credential-id";
  data.ad_credential_data.host = "invalid:636";
  credential_permission_allowed = FALSE;
  expect_no_storage_calls ();
  assert_that (create_credential (&data, &credential),
               is_equal_to (CREDENTIAL_PERMISSION_DENIED));
  assert_that (modify_credential (&data),
               is_equal_to (CREDENTIAL_PERMISSION_DENIED));
  assert_that (transaction_rollbacks, is_equal_to (2));
  assert_that (common_writes, is_equal_to (0));
  assert_that (transaction_commits, is_equal_to (0));
}

Ensure (manage_credentials, modify_ad_unavailable_when_feature_disabled)
{
  credential_data_t data = { 0 };
  ad_test_enabled = FALSE;

  expect_no_storage_calls ();

  assert_that (modify_active_directory_credential (&data, 42),
               is_equal_to (CREDENTIAL_AD_INTEGRATION_UNAVAILABLE));
}

Ensure (manage_credentials, modify_ad_ignores_absent_fields)
{
  credential_data_t data = { 0 };
  ad_test_enabled = TRUE;

  expect_no_storage_calls ();

  assert_that (modify_active_directory_credential (&data, 42),
               is_equal_to (CREDENTIAL_OK));
}

Ensure (manage_credentials, modify_ad_rejects_empty_host)
{
  credential_data_t data = { 0 };
  data.ad_credential_data.host = "";
  ad_test_enabled = TRUE;

  expect_no_storage_calls ();

  assert_that (modify_active_directory_credential (&data, 42),
               is_equal_to (CREDENTIAL_AD_HOST_REQUIRED));
}

Ensure (manage_credentials, modify_ad_rejects_empty_bind_dn)
{
  credential_data_t data = { 0 };
  data.ad_credential_data.bind_dn = "";
  ad_test_enabled = TRUE;

  expect_no_storage_calls ();

  assert_that (modify_active_directory_credential (&data, 42),
               is_equal_to (CREDENTIAL_AD_BIND_DN_REQUIRED));
}

Ensure (manage_credentials, modify_ad_rejects_empty_base_dn)
{
  credential_data_t data = { 0 };
  data.ad_credential_data.base_dn = "";
  ad_test_enabled = TRUE;

  expect_no_storage_calls ();

  assert_that (modify_active_directory_credential (&data, 42),
               is_equal_to (CREDENTIAL_AD_BASE_DN_REQUIRED));
}

Ensure (manage_credentials, modify_ad_rejects_empty_bind_password)
{
  credential_data_t data = { 0 };
  data.ad_credential_data.bind_password = "";
  ad_test_enabled = TRUE;

  expect_no_storage_calls ();

  assert_that (modify_active_directory_credential (&data, 42),
               is_equal_to (CREDENTIAL_AD_BIND_PASSWORD_REQUIRED));
}

Ensure (manage_credentials, modify_ad_rejects_invalid_port)
{
  credential_data_t data = { 0 };
  data.ad_credential_data.port = "0";
  ad_test_enabled = TRUE;

  expect_no_storage_calls ();

  assert_that (modify_active_directory_credential (&data, 42),
               is_equal_to (CREDENTIAL_AD_INVALID_PORT));
}

Ensure (manage_credentials, modify_ad_clears_empty_port)
{
  credential_data_t data = { 0 };
  data.ad_credential_data.port = "";
  ad_test_enabled = TRUE;

  expect (__wrap_set_credential_data,
          when (credential, is_equal_to (42)),
          when (type, is_equal_to_string ("ad_port")),
          when (value, is_null));
  expect (__wrap_update_credential_modification_time,
          when (credential, is_equal_to (42)));

  assert_that (modify_active_directory_credential (&data, 42),
               is_equal_to (CREDENTIAL_OK));
}

Ensure (manage_credentials, modify_ad_rejects_invalid_tls_mode)
{
  credential_data_t data = { 0 };
  data.ad_credential_data.tls_mode = "ldap";
  ad_test_enabled = TRUE;

  expect_no_storage_calls ();

  assert_that (modify_active_directory_credential (&data, 42),
               is_equal_to (CREDENTIAL_AD_INVALID_TLS_MODE));
}

Ensure (manage_credentials, modify_ad_clears_empty_ca_certificate)
{
  credential_data_t data = { 0 };
  data.ad_credential_data.ca_certificate = "";
  ad_test_enabled = TRUE;

  expect (__wrap_set_credential_data,
          when (credential, is_equal_to (42)),
          when (type, is_equal_to_string ("ad_ca_certificate")),
          when (value, is_null));
  expect (__wrap_update_credential_modification_time,
          when (credential, is_equal_to (42)));

  assert_that (modify_active_directory_credential (&data, 42),
               is_equal_to (CREDENTIAL_OK));
}

Ensure (manage_credentials, modify_ad_rejects_invalid_ca_certificate)
{
  credential_data_t data = { 0 };
  data.ad_credential_data.ca_certificate = "invalid";
  ad_test_enabled = TRUE;

  expect_no_storage_calls ();

  assert_that (modify_active_directory_credential (&data, 42),
               is_equal_to (CREDENTIAL_AD_INVALID_CA_CERTIFICATE));
}

Ensure (manage_credentials, modify_ad_updates_host_port_tls_and_password)
{
  credential_data_t data = { 0 };
  data.ad_credential_data.host = "dc-new.example.com";
  data.ad_credential_data.port = "636";
  data.ad_credential_data.tls_mode = "ldaps";
  data.ad_credential_data.bind_password = "new-password";
  ad_test_enabled = TRUE;

  expect (__wrap_set_credential_data,
          when (credential, is_equal_to (42)),
          when (type, is_equal_to_string ("ad_host")),
          when (value, is_equal_to_string ("dc-new.example.com")));

  expect (__wrap_set_credential_data,
          when (credential, is_equal_to (42)),
          when (type, is_equal_to_string ("ad_port")),
          when (value, is_equal_to_string ("636")));

  expect (__wrap_set_credential_data,
          when (credential, is_equal_to (42)),
          when (type, is_equal_to_string ("ad_tls_mode")),
          when (value, is_equal_to_string ("ldaps")));

  expect (__wrap_set_credential_data,
          when (credential, is_equal_to (42)),
          when (type, is_equal_to_string ("secret")),
          when (value, is_null));

  expect (__wrap_set_credential_data,
          when (credential, is_equal_to (42)),
          when (type, is_equal_to_string ("password")),
          when (value, is_equal_to_string ("new-password")));

  expect (__wrap_set_credential_data,
          when (credential, is_equal_to (42)),
          when (type, is_equal_to_string ("private_key")),
          when (value, is_null));

  expect (__wrap_update_credential_modification_time,
          when (credential, is_equal_to (42)));

  assert_that (modify_active_directory_credential (&data, 42),
               is_equal_to (CREDENTIAL_OK));
}
#endif

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, manage_credentials,
                         create_up_requires_login);
  add_test_with_context (suite, manage_credentials,
                         create_ssh_rejects_phrase_without_private_key);
  add_test_with_context (suite, manage_credentials,
                         create_snmp_requires_authentication);
  add_test_with_context (suite, manage_credentials,
                         create_snmp_v3_requires_auth_algorithm);
  add_test_with_context (suite, manage_credentials,
                         create_snmp_requires_privacy_algorithm_for_privacy_password);
  add_test_with_context (suite, manage_credentials,
                         create_kerberos_requires_password);
  add_test_with_context (suite, manage_credentials,
                         create_kerberos_requires_realm);
  add_test_with_context (suite, manage_credentials,
                         create_kerberos_requires_kdc);
  add_test_with_context (suite, manage_credentials,
                         create_cc_requires_private_key_and_certificate);
  add_test_with_context (suite, manage_credentials,
                         create_smime_rejects_invalid_certificate);
  add_test_with_context (suite, manage_credentials,
                         create_pgp_rejects_invalid_public_key);
  add_test_with_context (suite, manage_credentials,
                         try_gpgme_import_initialises_gpgme);
  add_test_with_context (suite, manage_credentials,
                         try_gpgme_import_rejects_failed_gpgme_new);
  add_test_with_context (suite, manage_credentials,
                         create_password_stores_supplied_password);

  add_test_with_context (suite, manage_credentials,
                         copy_credential_forwards_overrides);
  add_test_with_context (suite, manage_credentials,
                         copy_credential_forwards_null_overrides);
  add_test_with_context (suite, manage_credentials,
                         copy_credential_maps_row_errors);

  add_test_with_context (suite, manage_credentials,
                         modify_up_updates_login_and_password);
  add_test_with_context (suite, manage_credentials,
                         modify_password_updates_password);
  add_test_with_context (suite, manage_credentials,
                         modify_ssh_updates_login);
  add_test_with_context (suite, manage_credentials,
                         modify_ssh_updates_supplied_key_and_passphrase);
  add_test_with_context (suite, manage_credentials,
                         create_ssh_rejects_public_key_without_private_key);
  add_test_with_context (suite, manage_credentials,
                         modify_snmp_updates_login_and_auth_algorithm);
  add_test_with_context (suite, manage_credentials,
                         modify_snmp_rejects_invalid_auth_algorithm);
  add_test_with_context (suite, manage_credentials,
                         modify_kerberos_updates_supplied_fields);
  add_test_with_context (suite, manage_credentials,
                         modify_kerberos_rejects_invalid_realm);
  add_test_with_context (suite, manage_credentials,
                         modify_cc_ignores_absent_key_and_certificate);
  add_test_with_context (suite, manage_credentials,
                         modify_cc_rejects_invalid_certificate);
  add_test_with_context (suite, manage_credentials,
                         modify_cc_clears_empty_certificate);
  add_test_with_context (suite, manage_credentials,
                         modify_cc_rejects_invalid_private_key);
  add_test_with_context (suite, manage_credentials,
                         modify_cc_clears_empty_private_key);
  add_test_with_context (suite, manage_credentials,
                         modify_smime_rejects_invalid_certificate);
  add_test_with_context (suite, manage_credentials,
                         modify_smime_clears_empty_certificate);
  add_test_with_context (suite, manage_credentials,
                         modify_pgp_rejects_invalid_public_key);
  add_test_with_context (suite, manage_credentials,
                         modify_pgp_ignores_absent_public_key);
  add_test_with_context (suite, manage_credentials,
                         modify_pgp_clears_empty_public_key);

#if ENABLE_AD_INTEGRATION
  add_test_with_context (suite, manage_credentials,
                         create_ad_rejects_policy_and_host_before_storage);
  add_test_with_context (suite, manage_credentials,
                         create_ad_empty_lists_store_nonstandard_original_values);
  add_test_with_context (suite, manage_credentials,
                         ad_whitespace_and_creation_syntax_precede_policy);
  add_test_with_context (suite, manage_credentials,
                         modify_ad_empty_lists_preserve_nonstandard_and_whitespace);
  add_test_with_context (suite, manage_credentials,
                         modify_ad_merged_defaults_and_syntax_roll_back);
  add_test_with_context (suite, manage_credentials,
                         modify_ad_checks_merged_destination_before_writes);
  add_test_with_context (suite, manage_credentials,
                         modify_ad_accepts_merged_defaults_and_original_values);
  add_test_with_context (suite, manage_credentials,
                         modify_ad_syntax_precedes_policy_without_partial_writes);
  add_test_with_context (suite, manage_credentials,
                         modify_ad_denial_rolls_back_common_fields);
  add_test_with_context (suite, manage_credentials,
                         modify_ad_allowed_update_commits_common_and_ad_fields);
  add_test_with_context (suite, manage_credentials,
                         ad_command_permissions_precede_policy);
  add_test_with_context (suite, manage_credentials,
                         create_ad_unavailable_when_feature_disabled);
  add_test_with_context (suite, manage_credentials,
                         create_ad_requires_host);
  add_test_with_context (suite, manage_credentials,
                         create_ad_rejects_empty_host);
  add_test_with_context (suite, manage_credentials,
                         create_ad_requires_bind_dn);
  add_test_with_context (suite, manage_credentials,
                         create_ad_rejects_empty_bind_dn);
  add_test_with_context (suite, manage_credentials,
                         create_ad_requires_base_dn);
  add_test_with_context (suite, manage_credentials,
                         create_ad_rejects_empty_base_dn);
  add_test_with_context (suite, manage_credentials,
                         create_ad_requires_bind_password);
  add_test_with_context (suite, manage_credentials,
                         create_ad_rejects_empty_bind_password);
  add_test_with_context (suite, manage_credentials,
                         create_ad_rejects_empty_port);
  add_test_with_context (suite, manage_credentials,
                         create_ad_rejects_zero_port);
  add_test_with_context (suite, manage_credentials,
                         create_ad_rejects_port_above_maximum);
  add_test_with_context (suite, manage_credentials,
                         create_ad_rejects_negative_port);
  add_test_with_context (suite, manage_credentials,
                        create_ad_requires_tls_mode);
  add_test_with_context (suite, manage_credentials,
                         create_ad_rejects_empty_tls_mode);
  add_test_with_context (suite, manage_credentials,
                         create_ad_rejects_plain_ldap);
  add_test_with_context (suite, manage_credentials,
                         create_ad_rejects_empty_ca_certificate);
  add_test_with_context (suite, manage_credentials,
                         create_ad_rejects_invalid_ca_certificate);
  add_test_with_context (suite, manage_credentials,
                         create_ad_stores_valid_data);

  add_test_with_context (suite, manage_credentials,
                         modify_ad_unavailable_when_feature_disabled);
  add_test_with_context (suite, manage_credentials,
                         modify_ad_ignores_absent_fields);
  add_test_with_context (suite, manage_credentials,
                         modify_ad_rejects_empty_host);
  add_test_with_context (suite, manage_credentials,
                         modify_ad_rejects_empty_bind_dn);
  add_test_with_context (suite, manage_credentials,
                         modify_ad_rejects_empty_base_dn);
  add_test_with_context (suite, manage_credentials,
                         modify_ad_rejects_empty_bind_password);
  add_test_with_context (suite, manage_credentials,
                         modify_ad_rejects_invalid_port);
  add_test_with_context (suite, manage_credentials,
                         modify_ad_clears_empty_port);
  add_test_with_context (suite, manage_credentials,
                         modify_ad_rejects_invalid_tls_mode);
  add_test_with_context (suite, manage_credentials,
                         modify_ad_clears_empty_ca_certificate);
  add_test_with_context (suite, manage_credentials,
                         modify_ad_rejects_invalid_ca_certificate);
  add_test_with_context (suite, manage_credentials,
                         modify_ad_updates_host_port_tls_and_password);
#endif

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
