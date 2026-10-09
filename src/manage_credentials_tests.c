/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_credentials.c"

#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>

static int saved_disable_encrypted_credentials;
static int copy_rows_result;
static int check_private_key_result;
static gchar *saved_current_credentials_uuid;
static gchar copy_test_user_uuid[] = "test-user";
static const gchar *copy_rows_name;
static const gchar *copy_rows_comment;
static const gchar *copy_rows_credential_id;

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

void __wrap_sql_begin_immediate (void) {}
void __wrap_sql_commit (void) {}
void __wrap_sql_rollback (void) {}

static void
expect_no_storage_calls (void)
{
  never_expect (__wrap_insert_credential_base);
  never_expect (__wrap_set_credential_data);
  never_expect (__wrap_update_credential_modification_time);
}

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
}

AfterEach (manage_credentials)
{
  disable_encrypted_credentials = saved_disable_encrypted_credentials;
  current_credentials.uuid = saved_current_credentials_uuid;
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
  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
