/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>

#if ENABLE_AD_INTEGRATION

#include "manage_active_directory.c"

static int feature_is_enabled;
static const gchar *saved_credential_type;
static const gchar *saved_host;
static const gchar *saved_port;
static const gchar *saved_bind_dn;
static const gchar *saved_bind_password;
static const gchar *saved_base_dn;
static const gchar *saved_tls_mode;
static const gchar *saved_ca_certificate;

static ad_connector_t test_connector = GINT_TO_POINTER (1);
static ad_connector_return_t connector_connect_result;
static gchar *connected_password;

static int builder_calls;
static ad_connector_opt_t builder_options[32];
static const gchar *builder_host;
static const gchar *builder_bind_dn;
static const gchar *builder_ca_certificate;
static gint builder_port;
static gint builder_network_timeout;
static gint builder_operation_timeout;
static ad_connector_tls_mode_t builder_tls_mode;
static gboolean builder_failure_enabled;
static ad_connector_opt_t builder_failure_option;
static ad_connector_return_t builder_failure_result;

int
__wrap_feature_enabled (feature_id_t feature)
{
  assert_that (feature, is_equal_to (FEATURE_ID_AD_INTEGRATION));
  return feature_is_enabled;
}

int
__wrap_acl_user_may (const char *permission)
{
  assert_that (permission,
               is_equal_to_string ("verify_active_directory_credential"));
  return TRUE;
}

gboolean
__wrap_find_credential_with_permission (const char *uuid,
                                        credential_t *credential,
                                        const char *permission)
{
  assert_that (uuid, is_equal_to_string ("credential-id"));
  assert_that (permission, is_equal_to_string ("get_credentials"));
  *credential = 42;
  return FALSE;
}

char *
__wrap_credential_type (credential_t credential)
{
  assert_that (credential, is_equal_to (42));
  return g_strdup (saved_credential_type);
}

gchar *
__wrap_credential_value (credential_t credential, const char *name)
{
  assert_that (credential, is_equal_to (42));

  if (g_str_equal (name, "ad_host"))
    return g_strdup (saved_host);
  if (g_str_equal (name, "ad_port"))
    return g_strdup (saved_port);
  if (g_str_equal (name, "ad_bind_dn"))
    return g_strdup (saved_bind_dn);
  if (g_str_equal (name, "ad_base_dn"))
    return g_strdup (saved_base_dn);
  if (g_str_equal (name, "ad_tls_mode"))
    return g_strdup (saved_tls_mode);
  if (g_str_equal (name, "ad_ca_certificate"))
    return g_strdup (saved_ca_certificate);

  fail_test ("Unexpected credential value requested");
  return NULL;
}

gchar *
__wrap_credential_encrypted_value (credential_t credential, const char *name)
{
  assert_that (credential, is_equal_to (42));
  assert_that (name, is_equal_to_string ("password"));
  return g_strdup (saved_bind_password);
}

ad_connector_t
__wrap_ad_connector_new (void)
{
  return test_connector;
}

void
__wrap_ad_connector_free (ad_connector_t connector)
{
  (void) connector;
}

ad_connector_return_t
__wrap_ad_connector_builder (ad_connector_t connector,
                             ad_connector_opt_t option,
                             const void *value)
{
  assert_that (connector, is_equal_to (test_connector));
  builder_options[builder_calls++] = option;

  switch (option)
    {
    case AD_CONNECTOR_OPT_HOST:
      builder_host = value;
      break;
    case AD_CONNECTOR_OPT_PORT:
      builder_port = *((const gint *) value);
      break;
    case AD_CONNECTOR_OPT_TLS_MODE:
      builder_tls_mode = *((const ad_connector_tls_mode_t *) value);
      break;
    case AD_CONNECTOR_OPT_CA_CERT:
      builder_ca_certificate = value;
      break;
    case AD_CONNECTOR_OPT_BIND_DN:
      builder_bind_dn = value;
      break;
    case AD_CONNECTOR_OPT_NETWORK_TIMEOUT:
      builder_network_timeout = *((const gint *) value);
      break;
    case AD_CONNECTOR_OPT_OPERATION_TIMEOUT:
      builder_operation_timeout = *((const gint *) value);
      break;
    default:
      fail_test ("Unexpected connector option");
    }

  if (builder_failure_enabled && option == builder_failure_option)
    return builder_failure_result;

  return AD_CONNECTOR_OK;
}

ad_connector_return_t
__wrap_ad_connector_connect (ad_connector_t connector,
                             const gchar *bind_password)
{
  assert_that (connector, is_equal_to (test_connector));
  g_free (connected_password);
  connected_password = g_strdup (bind_password);
  return connector_connect_result;
}

static ad_credential_data_t
valid_ad_data (void)
{
  return (ad_credential_data_t) {
    .host = "dc.example.com",
    .port = "636",
    .bind_dn = "user@example.com",
    .bind_password = "password",
    .base_dn = "DC=example,DC=com",
    .tls_mode = "ldaps",
  };
}

static void
reset_test_state (void)
{
  feature_is_enabled = TRUE;
  saved_credential_type = "ad";
  saved_host = "dc.example.com";
  saved_port = "636";
  saved_bind_dn = "user@example.com";
  saved_bind_password = "password";
  saved_base_dn = "DC=example,DC=com";
  saved_tls_mode = "ldaps";
  saved_ca_certificate = NULL;

  test_connector = GINT_TO_POINTER (1);
  connector_connect_result = AD_CONNECTOR_OK;
  g_clear_pointer (&connected_password, g_free);

  builder_calls = 0;
  memset (builder_options, 0, sizeof (builder_options));
  builder_host = NULL;
  builder_bind_dn = NULL;
  builder_ca_certificate = NULL;
  builder_port = -1;
  builder_network_timeout = -1;
  builder_operation_timeout = -1;
  builder_tls_mode = AD_CONNECTOR_TLS_LDAPS;
  builder_failure_enabled = FALSE;
  builder_failure_option = AD_CONNECTOR_OPT_HOST;
  builder_failure_result = AD_CONNECTOR_OK;
}

Describe (manage_active_directory);
BeforeEach (manage_active_directory)
{
  reset_test_state ();
}

AfterEach (manage_active_directory)
{
  g_clear_pointer (&connected_password, g_free);
}

/* Test suite. */

Ensure (manage_active_directory, validation_accepts_valid_connection_data)
{
  ad_credential_data_t data = valid_ad_data ();

  assert_that (validate_supplied_ad_connection_data (&data),
               is_equal_to (VERIFY_AD_CREDENTIAL_OK));

  data.port = NULL;
  data.tls_mode = "starttls";
  assert_that (validate_supplied_ad_connection_data (&data),
               is_equal_to (VERIFY_AD_CREDENTIAL_OK));
}

Ensure (manage_active_directory, validation_reports_invalid_fields)
{
  ad_credential_data_t data = valid_ad_data ();

  data.host = NULL;
  assert_that (validate_supplied_ad_connection_data (&data),
               is_equal_to (VERIFY_AD_CREDENTIAL_HOST_REQUIRED));
  data = valid_ad_data ();
  data.bind_dn = "";
  assert_that (validate_supplied_ad_connection_data (&data),
               is_equal_to (VERIFY_AD_CREDENTIAL_BIND_DN_REQUIRED));
  data = valid_ad_data ();
  data.base_dn = NULL;
  assert_that (validate_supplied_ad_connection_data (&data),
               is_equal_to (VERIFY_AD_CREDENTIAL_BASE_DN_REQUIRED));
  data = valid_ad_data ();
  data.bind_password = "";
  assert_that (validate_supplied_ad_connection_data (&data),
               is_equal_to (VERIFY_AD_CREDENTIAL_BIND_PASSWORD_REQUIRED));
  data = valid_ad_data ();
  data.tls_mode = NULL;
  assert_that (validate_supplied_ad_connection_data (&data),
               is_equal_to (VERIFY_AD_CREDENTIAL_TLS_MODE_REQUIRED));
  data = valid_ad_data ();
  data.port = "65536";
  assert_that (validate_supplied_ad_connection_data (&data),
               is_equal_to (VERIFY_AD_CREDENTIAL_INVALID_PORT));
  data = valid_ad_data ();
  data.tls_mode = "ldap";
  assert_that (validate_supplied_ad_connection_data (&data),
               is_equal_to (VERIFY_AD_CREDENTIAL_INVALID_TLS_MODE));
  data = valid_ad_data ();
  data.ca_certificate = "not-a-certificate";
  assert_that (validate_supplied_ad_connection_data (&data),
               is_equal_to (VERIFY_AD_CREDENTIAL_INVALID_CA_CERTIFICATE));
}

Ensure (manage_active_directory, configure_sets_connector_options)
{
  ad_credential_data_t data = valid_ad_data ();
  data.ca_certificate = "certificate";

  assert_that (configure_ad_connector (test_connector, &data, 12, 34),
               is_equal_to (AD_CONNECTOR_OK));
  assert_that (builder_calls, is_equal_to (7));
  assert_that (builder_options[0], is_equal_to (AD_CONNECTOR_OPT_HOST));
  assert_that (builder_options[1], is_equal_to (AD_CONNECTOR_OPT_PORT));
  assert_that (builder_options[2], is_equal_to (AD_CONNECTOR_OPT_TLS_MODE));
  assert_that (builder_options[3], is_equal_to (AD_CONNECTOR_OPT_BIND_DN));
  assert_that (builder_options[4],
               is_equal_to (AD_CONNECTOR_OPT_NETWORK_TIMEOUT));
  assert_that (builder_options[5],
               is_equal_to (AD_CONNECTOR_OPT_OPERATION_TIMEOUT));
  assert_that (builder_options[6], is_equal_to (AD_CONNECTOR_OPT_CA_CERT));
  assert_that (builder_host, is_equal_to_string (data.host));
  assert_that (builder_port, is_equal_to (636));
  assert_that (builder_tls_mode, is_equal_to (AD_CONNECTOR_TLS_LDAPS));
  assert_that (builder_bind_dn, is_equal_to_string (data.bind_dn));
  assert_that (builder_network_timeout, is_equal_to (12));
  assert_that (builder_operation_timeout, is_equal_to (34));
  assert_that (builder_ca_certificate,
               is_equal_to_string (data.ca_certificate));
}

Ensure (manage_active_directory, configure_rejects_and_propagates_errors)
{
  ad_credential_data_t data = valid_ad_data ();
  data.port = "invalid";

  assert_that (configure_ad_connector (test_connector, &data, 12, 34),
               is_equal_to (AD_CONNECTOR_INVALID_VALUE));
  assert_that (builder_calls, is_equal_to (0));

  data = valid_ad_data ();
  builder_failure_enabled = TRUE;
  builder_failure_option = AD_CONNECTOR_OPT_TLS_MODE;
  builder_failure_result = AD_CONNECTOR_CONNECTION_ERROR;

  assert_that (configure_ad_connector (test_connector, &data, 12, 34),
               is_equal_to (AD_CONNECTOR_CONNECTION_ERROR));
  assert_that (builder_calls, is_equal_to (3));
}

Ensure (manage_active_directory, verify_rejects_invalid_invocations)
{
  ad_credential_data_t data = valid_ad_data ();

  assert_that (verify_active_directory_credential (NULL, NULL),
               is_equal_to (VERIFY_AD_CREDENTIAL_INVALID_INPUT));
  assert_that (verify_active_directory_credential ("", NULL),
               is_equal_to (VERIFY_AD_CREDENTIAL_INVALID_INPUT));
  assert_that (verify_active_directory_credential ("credential-id", &data),
               is_equal_to (VERIFY_AD_CREDENTIAL_INVALID_INPUT));
}

Ensure (manage_active_directory, verify_enforces_feature_flag)
{
  ad_credential_data_t data = valid_ad_data ();

  feature_is_enabled = FALSE;
  assert_that (verify_active_directory_credential (NULL, &data),
               is_equal_to (VERIFY_AD_CREDENTIAL_FEATURE_DISABLED));
}

Ensure (manage_active_directory, verify_maps_inline_connection_results)
{
  ad_credential_data_t data = valid_ad_data ();

  data.host = NULL;
  assert_that (verify_active_directory_credential (NULL, &data),
               is_equal_to (VERIFY_AD_CREDENTIAL_HOST_REQUIRED));

  data = valid_ad_data ();
  connector_connect_result = AD_CONNECTOR_OK;
  assert_that (verify_active_directory_credential (NULL, &data),
               is_equal_to (VERIFY_AD_CREDENTIAL_OK));
  assert_that (connected_password, is_equal_to_string ("password"));
  assert_that (builder_network_timeout,
               is_equal_to (AD_NETWORK_TIMEOUT_SECONDS_DEFAULT));
  assert_that (builder_operation_timeout,
               is_equal_to (AD_OPERATION_TIMEOUT_SECONDS_DEFAULT));

  connector_connect_result = AD_CONNECTOR_BIND_ERROR;
  assert_that (verify_active_directory_credential (NULL, &data),
               is_equal_to (VERIFY_AD_CREDENTIAL_BIND_FAILED));

  connector_connect_result = AD_CONNECTOR_CONNECTION_ERROR;
  assert_that (verify_active_directory_credential (NULL, &data),
               is_equal_to (VERIFY_AD_CREDENTIAL_CONNECTION_FAILED));
}

Ensure (manage_active_directory, verify_handles_saved_credentials)
{
  saved_credential_type = "up";
  assert_that (verify_active_directory_credential ("credential-id", NULL),
               is_equal_to (VERIFY_AD_CREDENTIAL_INVALID_TYPE));

  reset_test_state ();
  saved_port = "invalid";
  assert_that (verify_active_directory_credential ("credential-id", NULL),
               is_equal_to (
                 VERIFY_AD_CREDENTIAL_INVALID_STORED_CONFIGURATION));

  reset_test_state ();
  saved_bind_password = NULL;
  assert_that (verify_active_directory_credential ("credential-id", NULL),
               is_equal_to (
                 VERIFY_AD_CREDENTIAL_INVALID_STORED_CONFIGURATION));

  reset_test_state ();
  assert_that (verify_active_directory_credential ("credential-id", NULL),
               is_equal_to (VERIFY_AD_CREDENTIAL_OK));
  assert_that (connected_password, is_equal_to_string ("password"));
}


int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, manage_active_directory,
                         validation_accepts_valid_connection_data);
  add_test_with_context (suite, manage_active_directory,
                         validation_reports_invalid_fields);
  add_test_with_context (suite, manage_active_directory,
                         configure_sets_connector_options);
  add_test_with_context (suite, manage_active_directory,
                         configure_rejects_and_propagates_errors);
  add_test_with_context (suite, manage_active_directory,
                         verify_rejects_invalid_invocations);
  add_test_with_context (suite, manage_active_directory,
                         verify_enforces_feature_flag);
  add_test_with_context (suite, manage_active_directory,
                         verify_maps_inline_connection_results);
  add_test_with_context (suite, manage_active_directory,
                         verify_handles_saved_credentials);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}

#endif /* ENABLE_AD_INTEGRATION */
