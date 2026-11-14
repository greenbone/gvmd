/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>

#if ENABLE_AD_INTEGRATION

#include "gvmd_config.h"

#include <netdb.h>

static GKeyFile *test_config;

/* Executable-level interposition also catches calls from shared gvm-libs;
 * linker --wrap alone would only catch references from linked object files.
 * All connectors in this suite are mocked, so no resolver call is legitimate. */
static guint dns_calls;

/**
 * @brief Reject forward resolution in this database/network-free suite.
 *
 * @param[in] node     Borrowed node name (not inspected or retained).
 * @param[in] service  Borrowed service name (not inspected or retained).
 * @param[in] hints    Borrowed resolver hints (not inspected or retained).
 * @param[out] result  Optional output, cleared without allocating addresses.
 *
 * @return EAI_FAIL; report any lookup as a failed test, never access the network.
 */
int
getaddrinfo (const char *node, const char *service, const struct addrinfo *hints,
             struct addrinfo **result)
{
  (void) node;
  (void) service;
  (void) hints;
  if (result)
    *result = NULL;
  dns_calls++;
  fail_test ("AD policy validation must not resolve names");
  return EAI_FAIL;
}

/**
 * @brief Reject reverse resolution in this database/network-free suite.
 *
 * @param[in] address         Borrowed address (not inspected or retained).
 * @param[in] address_length  Address length (unused).
 * @param[out] host           Host buffer (not written).
 * @param[in] host_length     Host buffer length (unused).
 * @param[out] service        Service buffer (not written).
 * @param[in] service_length  Service buffer length (unused).
 * @param[in] flags           Resolver flags (unused).
 *
 * @return EAI_FAIL; report any lookup as a failed test, never access the network.
 */
int
getnameinfo (const struct sockaddr *address, socklen_t address_length,
             char *host, socklen_t host_length, char *service,
             socklen_t service_length, int flags)
{
  (void) address;
  (void) address_length;
  (void) host;
  (void) host_length;
  (void) service;
  (void) service_length;
  (void) flags;
  dns_calls++;
  fail_test ("AD policy validation must not reverse-resolve addresses");
  return EAI_FAIL;
}

/**
 * @brief Return the isolated configuration used by the loader tests.
 *
 * @return Borrowed configuration, or NULL when testing a missing configuration.
 */
static GKeyFile *
test_get_gvmd_config (void)
{
  return test_config;
}

/* Supply an isolated parsed file without changing the shared config cache. */
#define get_gvmd_config test_get_gvmd_config
#include "manage_active_directory.c"
#undef get_gvmd_config

static gchar *previous_allowed_hosts_env;
static gchar *previous_allowed_ports_env;
static guint warning_handler;
static guint policy_warning_count;
static gchar *last_policy_warning;

/**
 * @brief Capture AD parser/shared-getter warnings in the same log domain.
 *
 * @param[in] domain   Log domain passed by GLib.
 * @param[in] level    Message log level.
 * @param[in] message  Non-NULL message text, copied for policy warnings.
 * @param[in] data     Handler data, forwarded to the default handler.
 *
 * @return Nothing.
 */
static void
capture_policy_warning (const gchar *domain, GLogLevelFlags level,
                        const gchar *message, gpointer data)
{
  if (strstr (message, "active_directory.allowed_"))
    {
      policy_warning_count++;
      g_free (last_policy_warning);
      last_policy_warning = g_strdup (message);
    }
  else
    g_log_default_handler (domain, level, message, data);
}

/**
 * @brief Replace the isolated configuration with parsed test data.
 *
 * @param[in] contents  Non-NULL key-file text, not modified or retained.
 *
 * @return Nothing. Assert that the supplied text parses successfully.
 */
static void
set_test_ad_config (const gchar *contents)
{
  g_clear_pointer (&test_config, g_key_file_unref);
  test_config = g_key_file_new ();
  assert_that (g_key_file_load_from_data (test_config, contents, -1,
                                         G_KEY_FILE_NONE, NULL),
               is_equal_to (TRUE));
}

/**
 * @brief Assert that the loaded port policy contains the built-in defaults.
 *
 * @return Nothing. Failed comparisons are reported as test assertions.
 */
static void
assert_default_ad_ports (void)
{
  assert_that (ad_allowed_ports->len, is_equal_to (4));
  assert_that (g_array_index (ad_allowed_ports, guint, 0), is_equal_to (389));
  assert_that (g_array_index (ad_allowed_ports, guint, 1), is_equal_to (636));
  assert_that (g_array_index (ad_allowed_ports, guint, 2), is_equal_to (3268));
  assert_that (g_array_index (ad_allowed_ports, guint, 3), is_equal_to (3269));
}

static int feature_is_enabled;
static int permission_allowed;
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
static guint connector_new_calls;
static guint connector_connect_calls;

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
  return permission_allowed;
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
  connector_new_calls++;
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
  connector_connect_calls++;
  assert_that (connector, is_equal_to (test_connector));
  g_free (connected_password);
  connected_password = g_strdup (bind_password);
  return connector_connect_result;
}

/**
 * @brief Construct valid inline data without allocating owned strings.
 *
 * @return Connection data borrowing string literals; callers may replace fields.
 */
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
  permission_allowed = TRUE;
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
  connector_new_calls = 0;
  connector_connect_calls = 0;
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
  dns_calls = 0;
  previous_allowed_hosts_env = g_strdup (g_getenv ("GVMD_AD_ALLOWED_HOSTS"));
  previous_allowed_ports_env = g_strdup (g_getenv ("GVMD_AD_ALLOWED_PORTS"));
  g_unsetenv ("GVMD_AD_ALLOWED_HOSTS");
  g_unsetenv ("GVMD_AD_ALLOWED_PORTS");
  test_config = g_key_file_new ();
  policy_warning_count = 0;
  warning_handler = g_log_set_handler (G_LOG_DOMAIN, G_LOG_LEVEL_WARNING,
                                       capture_policy_warning, NULL);
  load_active_directory_config ();
}

AfterEach (manage_active_directory)
{
  assert_that (dns_calls, is_equal_to (0));
  g_clear_pointer (&connected_password, g_free);
  g_clear_pointer (&ad_allowed_hosts, g_ptr_array_unref);
  g_clear_pointer (&ad_allowed_ports, g_array_unref);
  g_clear_pointer (&test_config, g_key_file_unref);
  g_log_remove_handler (G_LOG_DOMAIN, warning_handler);
  g_clear_pointer (&last_policy_warning, g_free);
  if (previous_allowed_hosts_env)
    g_setenv ("GVMD_AD_ALLOWED_HOSTS", previous_allowed_hosts_env, TRUE);
  else
    g_unsetenv ("GVMD_AD_ALLOWED_HOSTS");
  if (previous_allowed_ports_env)
    g_setenv ("GVMD_AD_ALLOWED_PORTS", previous_allowed_ports_env, TRUE);
  else
    g_unsetenv ("GVMD_AD_ALLOWED_PORTS");
  g_clear_pointer (&previous_allowed_hosts_env, g_free);
  g_clear_pointer (&previous_allowed_ports_env, g_free);
}

/* Test suite. */

/**
 * @brief Assert that checking has not created, configured or connected AD.
 *
 * @return Nothing. Any connector use is reported as a failed assertion.
 */
static void
assert_no_ad_connector_calls (void)
{
  assert_that (connector_new_calls, is_equal_to (0));
  assert_that (builder_calls, is_equal_to (0));
  assert_that (connector_connect_calls, is_equal_to (0));
}

Ensure (manage_active_directory, effective_port_defaults_and_explicit_values)
{
  guint port = 42;
  const gchar *explicit[] = { "1", "65535", "000389", "3268", "3269" };
  const guint expected[] = { 1, 65535, 389, 3268, 3269 };

  assert_that (active_directory_effective_port (NULL, "starttls", &port),
               is_equal_to (AD_DESTINATION_OK));
  assert_that (port, is_equal_to (389));
  assert_that (active_directory_effective_port (NULL, "ldaps", &port),
               is_equal_to (AD_DESTINATION_OK));
  assert_that (port, is_equal_to (636));
  for (guint i = 0; i < G_N_ELEMENTS (explicit); i++)
    {
      assert_that (active_directory_effective_port (explicit[i], "ldaps", &port),
                   is_equal_to (AD_DESTINATION_OK));
      assert_that (port, is_equal_to (expected[i]));
      assert_that (active_directory_effective_port (explicit[i], "starttls",
                                                    &port),
                   is_equal_to (AD_DESTINATION_OK));
      assert_that (port, is_equal_to (expected[i]));
    }
  assert_no_ad_connector_calls ();
}

Ensure (manage_active_directory, checker_matches_names_without_rewriting_input)
{
  gchar host[] = "DC.Example.COM.";
  guint port = 42;

  set_test_ad_config ("[active_directory]\n"
                      "allowed_hosts = dc.example.com,unresolvable.invalid\n"
                      "allowed_ports = 389\n");
  load_active_directory_config ();
  assert_that (check_active_directory_destination (host, NULL, "starttls", &port),
               is_equal_to (AD_DESTINATION_OK));
  assert_that (port, is_equal_to (389));
  assert_that (host, is_equal_to_string ("DC.Example.COM."));
  assert_that (check_active_directory_destination ("UNRESOLVABLE.invalid.",
                                                   "000389", "ldaps", NULL),
               is_equal_to (AD_DESTINATION_OK));
  assert_that (check_active_directory_destination ("alias.example.com", "389",
                                                   "starttls", NULL),
               is_equal_to (AD_DESTINATION_NOT_ALLOWED));
  assert_that (check_active_directory_destination ("192.0.2.1", "389",
                                                   "starttls", NULL),
               is_equal_to (AD_DESTINATION_NOT_ALLOWED));
  assert_no_ad_connector_calls ();
}

Ensure (manage_active_directory, checker_matches_only_same_family_addresses)
{
  set_test_ad_config ("[active_directory]\n"
                      "allowed_hosts = 192.0.2.1,2001:db8::1\n"
                      "allowed_ports = \n");
  load_active_directory_config ();
  assert_that (check_active_directory_destination ("192.0.2.1", "1389",
                                                   "starttls", NULL),
               is_equal_to (AD_DESTINATION_OK));
  assert_that (check_active_directory_destination ("2001:0DB8:0:0:0:0:0:1",
                                                   "1389", "ldaps", NULL),
               is_equal_to (AD_DESTINATION_OK));
  assert_that (check_active_directory_destination ("::ffff:192.0.2.1", "1389",
                                                   "ldaps", NULL),
               is_equal_to (AD_DESTINATION_NOT_ALLOWED));
  assert_that (check_active_directory_destination ("192.0.2.2", "1389",
                                                   "ldaps", NULL),
               is_equal_to (AD_DESTINATION_NOT_ALLOWED));
  assert_that (check_active_directory_destination ("2001:db8::2", "1389",
                                                   "ldaps", NULL),
               is_equal_to (AD_DESTINATION_NOT_ALLOWED));
  assert_that (check_active_directory_destination ("dc.example.com", "1389",
                                                   "ldaps", NULL),
               is_equal_to (AD_DESTINATION_NOT_ALLOWED));

  g_setenv ("GVMD_AD_ALLOWED_HOSTS", "::ffff:192.0.2.1", TRUE);
  load_active_directory_config ();
  assert_that (check_active_directory_destination ("::ffff:c000:201", "1389",
                                                   "ldaps", NULL),
               is_equal_to (AD_DESTINATION_OK));
  assert_that (check_active_directory_destination ("192.0.2.1", "1389",
                                                   "ldaps", NULL),
               is_equal_to (AD_DESTINATION_NOT_ALLOWED));
  assert_no_ad_connector_calls ();
}

Ensure (manage_active_directory, checker_empty_lists_still_validate_syntax)
{
  const gchar *invalid_hosts[] = {
    NULL, "", " ", "\t", " dc.example.com", "dc.example.com ",
    "dc.example.com\t", "*.example.com", "192.0.2.0/24", "192.0.2.1-10",
    "2001:db8::/64", "ldap://dc.example.com", "dc.example.com:389",
    "dc.example.com,other.invalid", "[::1]", "fe80::1%eth0", "dc.example.com.."
  };
  const gchar *invalid_ports[] = {
    "", " ", "\t", " 389", "389 ", "389\t", "0", "65536",
    "18446744073709551616", "999999999999999999999999999999999999",
    "+389", "-389", "ldap", "0x185", "389-636", "389junk"
  };
  const gchar *invalid_tls[] = { NULL, "", "ldap", "LDAPS", " starttls" };
  guint port = 42;

  set_test_ad_config ("[active_directory]\nallowed_hosts = \nallowed_ports = \n");
  load_active_directory_config ();
  assert_that (check_active_directory_destination ("unresolvable.invalid",
                                                   "1389", "starttls", NULL),
               is_equal_to (AD_DESTINATION_OK));
  assert_that (check_active_directory_destination ("::1", "1", "ldaps", NULL),
               is_equal_to (AD_DESTINATION_OK));
  assert_that (check_active_directory_destination ("192.0.2.1", "65535",
                                                   "ldaps", NULL),
               is_equal_to (AD_DESTINATION_OK));
  for (guint i = 0; i < G_N_ELEMENTS (invalid_hosts); i++)
    assert_that (check_active_directory_destination (invalid_hosts[i], "389",
                                                     "starttls", &port),
                 is_equal_to (AD_DESTINATION_INVALID_HOST));
  for (guint i = 0; i < G_N_ELEMENTS (invalid_ports); i++)
    {
      assert_that (valid_ad_port (invalid_ports[i]), is_equal_to (FALSE));
      assert_that (check_active_directory_destination ("dc.example.com",
                                                       invalid_ports[i],
                                                       "ldaps", &port),
                   is_equal_to (AD_DESTINATION_INVALID_PORT));
    }
  for (guint i = 0; i < G_N_ELEMENTS (invalid_tls); i++)
    {
      assert_that (check_active_directory_destination ("dc.example.com", NULL,
                                                       invalid_tls[i], &port),
                   is_equal_to (AD_DESTINATION_INVALID_TLS_MODE));
      assert_that (active_directory_effective_port ("3269", invalid_tls[i],
                                                    &port),
                   is_equal_to (AD_DESTINATION_INVALID_TLS_MODE));
    }
  assert_that (port, is_equal_to (42));
  assert_that (policy_warning_count, is_equal_to (0));
  assert_no_ad_connector_calls ();
}

Ensure (manage_active_directory, checker_syntax_precedes_policy_denial)
{
  guint port = 42;

  set_test_ad_config ("[active_directory]\n"
                      "allowed_hosts = allowed.invalid\nallowed_ports = 1389\n");
  load_active_directory_config ();
  assert_that (check_active_directory_destination ("*.invalid", "bad", "ldap",
                                                   &port),
               is_equal_to (AD_DESTINATION_INVALID_HOST));
  assert_that (check_active_directory_destination ("denied.invalid", "bad",
                                                   "ldap", &port),
               is_equal_to (AD_DESTINATION_INVALID_PORT));
  assert_that (check_active_directory_destination ("denied.invalid", "389",
                                                   "ldap", &port),
               is_equal_to (AD_DESTINATION_INVALID_TLS_MODE));
  assert_that (check_active_directory_destination ("denied.invalid", "389",
                                                   "ldaps", &port),
               is_equal_to (AD_DESTINATION_NOT_ALLOWED));
  assert_that (port, is_equal_to (42));
  assert_no_ad_connector_calls ();
}

Ensure (manage_active_directory, checker_defaults_and_denial_never_fall_back)
{
  guint port = 42;

  load_active_directory_config ();
  assert_that (check_active_directory_destination ("dc.invalid", NULL,
                                                   "starttls", &port),
               is_equal_to (AD_DESTINATION_OK));
  assert_that (port, is_equal_to (389));
  assert_that (check_active_directory_destination ("dc.invalid", NULL, "ldaps",
                                                   &port),
               is_equal_to (AD_DESTINATION_OK));
  assert_that (port, is_equal_to (636));
  assert_that (check_active_directory_destination ("dc.invalid", "0003268",
                                                   "ldaps", &port),
               is_equal_to (AD_DESTINATION_OK));
  assert_that (port, is_equal_to (3268));
  assert_that (check_active_directory_destination ("dc.invalid", "3269",
                                                   "starttls", &port),
               is_equal_to (AD_DESTINATION_OK));
  assert_that (port, is_equal_to (3269));
  assert_that (check_active_directory_destination ("dc.invalid", "1389",
                                                   "ldaps", &port),
               is_equal_to (AD_DESTINATION_NOT_ALLOWED));
  assert_that (port, is_equal_to (3269));

  g_setenv ("GVMD_AD_ALLOWED_PORTS", "636,3268,3269", TRUE);
  load_active_directory_config ();
  assert_that (check_active_directory_destination ("dc.invalid", NULL,
                                                   "starttls", &port),
               is_equal_to (AD_DESTINATION_NOT_ALLOWED));
  assert_that (port, is_equal_to (3269));
  g_setenv ("GVMD_AD_ALLOWED_PORTS", "389,3268,3269", TRUE);
  load_active_directory_config ();
  assert_that (check_active_directory_destination ("dc.invalid", NULL,
                                                   "ldaps", &port),
               is_equal_to (AD_DESTINATION_NOT_ALLOWED));
  assert_that (check_active_directory_destination ("dc.invalid", "636",
                                                   "starttls", &port),
               is_equal_to (AD_DESTINATION_NOT_ALLOWED));
  assert_that (port, is_equal_to (3269));
  assert_no_ad_connector_calls ();
}

Ensure (manage_active_directory, checker_reads_immutable_loaded_policy)
{
  set_test_ad_config ("[active_directory]\n"
                      "allowed_hosts = allowed.invalid\nallowed_ports = 1389\n");
  load_active_directory_config ();
  g_setenv ("GVMD_AD_ALLOWED_HOSTS", "denied.invalid", TRUE);
  g_setenv ("GVMD_AD_ALLOWED_PORTS", "636", TRUE);
  set_test_ad_config ("[active_directory]\nallowed_hosts = \nallowed_ports = \n");
  feature_is_enabled = FALSE;
  assert_that (check_active_directory_destination ("allowed.invalid", "1389",
                                                   "ldaps", NULL),
               is_equal_to (AD_DESTINATION_OK));
  assert_that (check_active_directory_destination ("denied.invalid", "1389",
                                                   "ldaps", NULL),
               is_equal_to (AD_DESTINATION_NOT_ALLOWED));
  assert_that (check_active_directory_destination ("allowed.invalid", "636",
                                                   "ldaps", NULL),
               is_equal_to (AD_DESTINATION_NOT_ALLOWED));
  assert_that (ad_allowed_hosts->len, is_equal_to (1));
  assert_that (ad_allowed_ports->len, is_equal_to (1));
  assert_that (policy_warning_count, is_equal_to (0));
  assert_no_ad_connector_calls ();
}

Ensure (manage_active_directory, loader_defaults_for_missing_configuration)
{
  g_clear_pointer (&test_config, g_key_file_unref);
  load_active_directory_config ();
  assert_that (ad_allowed_hosts->len, is_equal_to (0));
  assert_default_ad_ports ();

  set_test_ad_config ("[unrelated]\nvalue = 1\n");
  load_active_directory_config ();
  assert_that (ad_allowed_hosts->len, is_equal_to (0));
  assert_default_ad_ports ();

  set_test_ad_config ("[active_directory]\nother = value\n");
  load_active_directory_config ();
  assert_that (ad_allowed_hosts->len, is_equal_to (0));
  assert_default_ad_ports ();
  assert_that (check_active_directory_destination ("outside.invalid", NULL,
                                                   "starttls", NULL),
               is_equal_to (AD_DESTINATION_OK));
  assert_that (check_active_directory_destination ("outside.invalid", NULL,
                                                   "ldaps", NULL),
               is_equal_to (AD_DESTINATION_OK));
  assert_that (check_active_directory_destination ("outside.invalid", "1389",
                                                   "ldaps", NULL),
               is_equal_to (AD_DESTINATION_NOT_ALLOWED));
  assert_that (policy_warning_count, is_equal_to (0));
}

Ensure (manage_active_directory, loader_resolves_options_independently)
{
  ad_policy_host_t *host;

  set_test_ad_config ("[active_directory]\n"
                      "allowed_hosts = file.example.com\n"
                      "allowed_ports = 1389\n");
  g_setenv ("GVMD_AD_ALLOWED_HOSTS", "ENV.example.com.", TRUE);
  load_active_directory_config ();
  assert_that (ad_allowed_hosts->len, is_equal_to (1));
  host = g_ptr_array_index (ad_allowed_hosts, 0);
  assert_that (host->value.name, is_equal_to_string ("env.example.com"));
  assert_that (ad_allowed_ports->len, is_equal_to (1));
  assert_that (g_array_index (ad_allowed_ports, guint, 0), is_equal_to (1389));

  g_unsetenv ("GVMD_AD_ALLOWED_HOSTS");
  g_setenv ("GVMD_AD_ALLOWED_PORTS", "1636", TRUE);
  load_active_directory_config ();
  host = g_ptr_array_index (ad_allowed_hosts, 0);
  assert_that (host->value.name, is_equal_to_string ("file.example.com"));
  assert_that (ad_allowed_ports->len, is_equal_to (1));
  assert_that (g_array_index (ad_allowed_ports, guint, 0), is_equal_to (1636));

  g_clear_pointer (&test_config, g_key_file_unref);
  g_setenv ("GVMD_AD_ALLOWED_HOSTS", "env-only.invalid", TRUE);
  load_active_directory_config ();
  host = g_ptr_array_index (ad_allowed_hosts, 0);
  assert_that (host->value.name, is_equal_to_string ("env-only.invalid"));
  assert_that (g_array_index (ad_allowed_ports, guint, 0), is_equal_to (1636));
  assert_that (policy_warning_count, is_equal_to (0));
}

Ensure (manage_active_directory, loader_accepts_explicit_empty_lists)
{
  set_test_ad_config ("[active_directory]\n"
                      "allowed_hosts = \nallowed_ports = \n");
  load_active_directory_config ();
  assert_that (ad_allowed_hosts->len, is_equal_to (0));
  assert_that (ad_allowed_ports->len, is_equal_to (0));

  set_test_ad_config ("[active_directory]\n"
                      "allowed_hosts = \\s\\t\\s\n"
                      "allowed_ports = \\s\\t\\s\n");
  load_active_directory_config ();
  assert_that (ad_allowed_hosts->len, is_equal_to (0));
  assert_that (ad_allowed_ports->len, is_equal_to (0));

  set_test_ad_config ("[active_directory]\n"
                      "allowed_hosts = file.example.com\n"
                      "allowed_ports = 1389\n");
  g_setenv ("GVMD_AD_ALLOWED_HOSTS", "", TRUE);
  g_setenv ("GVMD_AD_ALLOWED_PORTS", " \t\n ", TRUE);
  load_active_directory_config ();
  assert_that (ad_allowed_hosts->len, is_equal_to (0));
  assert_that (ad_allowed_ports->len, is_equal_to (0));

  g_setenv ("GVMD_AD_ALLOWED_HOSTS", " \t\n ", TRUE);
  g_setenv ("GVMD_AD_ALLOWED_PORTS", "", TRUE);
  load_active_directory_config ();
  assert_that (ad_allowed_hosts->len, is_equal_to (0));
  assert_that (ad_allowed_ports->len, is_equal_to (0));
  assert_that (policy_warning_count, is_equal_to (0));
}

Ensure (manage_active_directory, loader_normalizes_and_deduplicates)
{
  ad_policy_host_t *host;
  struct in_addr ipv4;
  struct in6_addr ipv6;

  g_setenv ("GVMD_AD_ALLOWED_HOSTS",
            " DC.Example.COM. , dc.example.com, 192.0.2.1,192.0.2.1,"
            "2001:db8::1,2001:0db8:0:0:0:0:0:1,::ffff:192.0.2.1,"
            "unresolvable.invalid ", TRUE);
  g_setenv ("GVMD_AD_ALLOWED_PORTS", " 000389 , 389,1,65535, 1389 ", TRUE);
  load_active_directory_config ();
  assert_that (ad_allowed_hosts->len, is_equal_to (5));
  host = g_ptr_array_index (ad_allowed_hosts, 0);
  assert_that (host->type, is_equal_to (HOST_TYPE_NAME));
  assert_that (host->value.name, is_equal_to_string ("dc.example.com"));
  host = g_ptr_array_index (ad_allowed_hosts, 1);
  assert_that (host->type, is_equal_to (HOST_TYPE_IPV4));
  assert_that (inet_pton (AF_INET, "192.0.2.1", &ipv4), is_equal_to (1));
  assert_that (host->value.ipv4.s_addr, is_equal_to (ipv4.s_addr));
  host = g_ptr_array_index (ad_allowed_hosts, 2);
  assert_that (host->type, is_equal_to (HOST_TYPE_IPV6));
  assert_that (inet_pton (AF_INET6, "2001:db8::1", &ipv6), is_equal_to (1));
  assert_that (memcmp (host->value.ipv6.s6_addr, ipv6.s6_addr,
                       sizeof (ipv6.s6_addr)), is_equal_to (0));
  assert_that (ad_policy_hosts_equal (g_ptr_array_index (ad_allowed_hosts, 1),
                                     g_ptr_array_index (ad_allowed_hosts, 3)),
               is_equal_to (FALSE));
  host = g_ptr_array_index (ad_allowed_hosts, 4);
  assert_that (host->value.name, is_equal_to_string ("unresolvable.invalid"));
  assert_that (ad_allowed_ports->len, is_equal_to (4));
  assert_that (g_array_index (ad_allowed_ports, guint, 0), is_equal_to (389));
  assert_that (g_array_index (ad_allowed_ports, guint, 1), is_equal_to (1));
  assert_that (g_array_index (ad_allowed_ports, guint, 2), is_equal_to (65535));
  assert_that (g_array_index (ad_allowed_ports, guint, 3), is_equal_to (1389));
  assert_that (policy_warning_count, is_equal_to (0));
}

Ensure (manage_active_directory, loader_discards_invalid_selected_host_lists)
{
  const gchar *invalid[] = {
    ",dc.example.com", "dc.example.com,", "dc.example.com,,other.invalid",
    "dc.example.com, \t ,other.invalid", "dc.example.com;other.invalid",
    "dc.example.com,*.example.com", "192.0.2.0/24", "192.0.2.1-10",
    "2001:db8::/64", "ldap://dc.example.com", "dc.example.com:389",
    "[::1]", "fe80::1%eth0", "dc.example.com.."
  };

  set_test_ad_config ("[active_directory]\n"
                      "allowed_hosts = file.example.com\n"
                      "allowed_ports = 1389\n");
  for (guint i = 0; i < G_N_ELEMENTS (invalid); i++)
    {
      g_setenv ("GVMD_AD_ALLOWED_HOSTS", invalid[i], TRUE);
      load_active_directory_config ();
      /* Invalid env denies all, without retrying the valid file restriction. */
      assert_that (ad_allowed_hosts, is_null);
      assert_that (ad_allowed_ports->len, is_equal_to (1));
      assert_that (g_array_index (ad_allowed_ports, guint, 0),
                   is_equal_to (1389));
      assert_that (policy_warning_count, is_equal_to (i + 1));
      assert_that (strstr (last_policy_warning, "allowed_hosts"), is_not_null);
      assert_that (check_active_directory_destination ("outside.invalid", "1389",
                                                       "ldaps", NULL),
                   is_equal_to (AD_DESTINATION_NOT_ALLOWED));
      assert_that (check_active_directory_destination ("file.example.com", "1389",
                                                       "ldaps", NULL),
                   is_equal_to (AD_DESTINATION_NOT_ALLOWED));
      assert_that (check_active_directory_destination ("outside.invalid", "636",
                                                       "ldaps", NULL),
                   is_equal_to (AD_DESTINATION_NOT_ALLOWED));
    }
}

Ensure (manage_active_directory, loader_discards_invalid_selected_port_lists)
{
  const gchar *invalid[] = {
    ",389", "389,", "389,,636", "389, \t ,636", "389;636", "389,0",
    "65536", "18446744073709551616", "+389", "-389", "ldap", "0x185",
    "389-636", "389junk"
  };

  set_test_ad_config ("[active_directory]\n"
                      "allowed_hosts = file.example.com\n"
                      "allowed_ports = 1389\n");
  for (guint i = 0; i < G_N_ELEMENTS (invalid); i++)
    {
      g_setenv ("GVMD_AD_ALLOWED_PORTS", invalid[i], TRUE);
      load_active_directory_config ();
      assert_that (ad_allowed_hosts->len, is_equal_to (1));
      assert_that (ad_allowed_ports, is_null);
      assert_that (policy_warning_count, is_equal_to (i + 1));
      assert_that (strstr (last_policy_warning, "allowed_ports"), is_not_null);
      assert_that (check_active_directory_destination ("file.example.com", "636",
                                                       "ldaps", NULL),
                   is_equal_to (AD_DESTINATION_NOT_ALLOWED));
      assert_that (check_active_directory_destination ("file.example.com", "1389",
                                                       "ldaps", NULL),
                   is_equal_to (AD_DESTINATION_NOT_ALLOWED));
      assert_that (check_active_directory_destination ("outside.invalid", "636",
                                                       "ldaps", NULL),
                   is_equal_to (AD_DESTINATION_NOT_ALLOWED));
    }
}

Ensure (manage_active_directory, loader_handles_file_errors_independently)
{
  ad_policy_host_t *host;

  set_test_ad_config ("[active_directory]\n"
                      "allowed_hosts = dc.example.com,\n"
                      "allowed_ports = 1389\n");
  load_active_directory_config ();
  assert_that (ad_allowed_hosts, is_null);
  assert_that (g_array_index (ad_allowed_ports, guint, 0), is_equal_to (1389));
  assert_that (policy_warning_count, is_equal_to (1));
  assert_that (check_active_directory_destination ("dc.example.com", "1389",
                                                   "ldaps", NULL),
               is_equal_to (AD_DESTINATION_NOT_ALLOWED));

  set_test_ad_config ("[active_directory]\n"
                      "allowed_hosts = dc.example.com\n"
                      "allowed_ports = 389,0\n");
  load_active_directory_config ();
  host = g_ptr_array_index (ad_allowed_hosts, 0);
  assert_that (host->value.name, is_equal_to_string ("dc.example.com"));
  assert_that (ad_allowed_ports, is_null);
  assert_that (policy_warning_count, is_equal_to (2));
  assert_that (check_active_directory_destination ("dc.example.com", "389",
                                                   "starttls", NULL),
               is_equal_to (AD_DESTINATION_NOT_ALLOWED));

  /* Invalid string escapes pass general file parsing but fail string reads. */
  set_test_ad_config ("[active_directory]\n"
                      "allowed_hosts = hidden\\q\n"
                      "allowed_ports = 1389\n");
  load_active_directory_config ();
  assert_that (ad_allowed_hosts, is_null);
  assert_that (g_array_index (ad_allowed_ports, guint, 0), is_equal_to (1389));
  assert_that (policy_warning_count, is_equal_to (3));
  assert_that (last_policy_warning, is_equal_to_string (
    "gvmd_get_env_or_config_string: active_directory.allowed_hosts: "
    "could not read string"));
  assert_that (strstr (last_policy_warning, "hidden"), is_null);
  assert_that (check_active_directory_destination ("dc.example.com", "1389",
                                                   "ldaps", NULL),
               is_equal_to (AD_DESTINATION_NOT_ALLOWED));

  set_test_ad_config ("[active_directory]\n"
                      "allowed_hosts = dc.example.com\n"
                      "allowed_ports = hidden\\q\n");
  load_active_directory_config ();
  assert_that (ad_allowed_hosts->len, is_equal_to (1));
  assert_that (ad_allowed_ports, is_null);
  assert_that (policy_warning_count, is_equal_to (4));
  assert_that (last_policy_warning, is_equal_to_string (
    "gvmd_get_env_or_config_string: active_directory.allowed_ports: "
    "could not read string"));
  assert_that (check_active_directory_destination ("dc.example.com", NULL,
                                                   "ldaps", NULL),
               is_equal_to (AD_DESTINATION_NOT_ALLOWED));
  assert_no_ad_connector_calls ();
}

Ensure (manage_active_directory, loader_ignores_overridden_file_lists)
{
  set_test_ad_config ("[active_directory]\n"
                      "allowed_hosts = hidden\\q\n"
                      "allowed_ports = hidden\\q\n");
  g_setenv ("GVMD_AD_ALLOWED_HOSTS", "env.example.com", TRUE);
  g_setenv ("GVMD_AD_ALLOWED_PORTS", "1389", TRUE);
  load_active_directory_config ();
  assert_that (ad_allowed_hosts->len, is_equal_to (1));
  assert_that (ad_allowed_ports->len, is_equal_to (1));
  assert_that (g_array_index (ad_allowed_ports, guint, 0), is_equal_to (1389));
  assert_that (check_active_directory_destination ("env.example.com", "1389",
                                                   "ldaps", NULL),
               is_equal_to (AD_DESTINATION_OK));
  g_setenv ("GVMD_AD_ALLOWED_HOSTS", "", TRUE);
  g_setenv ("GVMD_AD_ALLOWED_PORTS", " \t ", TRUE);
  load_active_directory_config ();
  assert_that (check_active_directory_destination ("outside.invalid", "1636",
                                                   "ldaps", NULL),
               is_equal_to (AD_DESTINATION_OK));
  assert_that (policy_warning_count, is_equal_to (0));
}

Ensure (manage_active_directory, loader_reinitializes_when_runtime_disabled)
{
  g_setenv ("GVMD_AD_ALLOWED_HOSTS", "dc.example.com", TRUE);
  g_setenv ("GVMD_AD_ALLOWED_PORTS", "1389", TRUE);
  load_active_directory_config ();
  assert_that (ad_allowed_hosts->len, is_equal_to (1));
  assert_that (ad_allowed_ports->len, is_equal_to (1));

  feature_is_enabled = FALSE;
  g_setenv ("GVMD_AD_ALLOWED_HOSTS", "dc.example.com,", TRUE);
  g_unsetenv ("GVMD_AD_ALLOWED_PORTS");
  /* Changing the source does not mutate the already-published policy. */
  assert_that (ad_allowed_hosts->len, is_equal_to (1));
  assert_that (g_array_index (ad_allowed_ports, guint, 0), is_equal_to (1389));
  load_active_directory_config ();
  assert_that (ad_allowed_hosts, is_null);
  assert_default_ad_ports ();
  assert_that (policy_warning_count, is_equal_to (1));
  assert_that (builder_calls, is_equal_to (0));
  assert_that (check_active_directory_destination ("dc.example.com", "636",
                                                   "ldaps", NULL),
               is_equal_to (AD_DESTINATION_NOT_ALLOWED));

  g_setenv ("GVMD_AD_ALLOWED_HOSTS", "", TRUE);
  g_setenv ("GVMD_AD_ALLOWED_PORTS", "", TRUE);
  /* A repaired source cannot change the failed snapshot without a reload. */
  assert_that (check_active_directory_destination ("dc.example.com", "636",
                                                   "ldaps", NULL),
               is_equal_to (AD_DESTINATION_NOT_ALLOWED));
  load_active_directory_config ();
  assert_that (ad_allowed_hosts->len, is_equal_to (0));
  assert_that (ad_allowed_ports->len, is_equal_to (0));
  assert_that (check_active_directory_destination ("dc.example.com", "1389",
                                                   "ldaps", NULL),
               is_equal_to (AD_DESTINATION_OK));
}

Ensure (manage_active_directory, failed_policy_preserves_syntax_and_denies_commands)
{
  const gchar *configs[] = {
    "[active_directory]\nallowed_hosts = dc.example.com,\nallowed_ports = \n",
    "[active_directory]\nallowed_hosts = \nallowed_ports = 636,0\n",
    "[active_directory]\nallowed_hosts = hidden\\q\nallowed_ports = \n",
    "[active_directory]\nallowed_hosts = \nallowed_ports = hidden\\q\n",
    "[active_directory]\nallowed_hosts = hidden\\q\nallowed_ports = hidden\\q\n",
    "[active_directory]\nallowed_hosts = hidden\377\nallowed_ports = \n",
    "[active_directory]\nallowed_hosts = \nallowed_ports = hidden\377\n",
  };

  for (guint i = 0; i < G_N_ELEMENTS (configs); i++)
    {
      ad_credential_data_t data = valid_ad_data ();
      guint port = 42;

      reset_test_state ();
      set_test_ad_config (configs[i]);
      load_active_directory_config ();
      assert_that (check_active_directory_destination ("*.invalid", "bad", "ldap",
                                                       &port),
                   is_equal_to (AD_DESTINATION_INVALID_HOST));
      assert_that (check_active_directory_destination (data.host, "bad", "ldap",
                                                       &port),
                   is_equal_to (AD_DESTINATION_INVALID_PORT));
      assert_that (check_active_directory_destination (data.host, "636", "ldap",
                                                       &port),
                   is_equal_to (AD_DESTINATION_INVALID_TLS_MODE));
      assert_that (check_active_directory_destination (data.host, "636", "ldaps",
                                                       &port),
                   is_equal_to (AD_DESTINATION_NOT_ALLOWED));
      assert_that (port, is_equal_to (42));
      assert_that (verify_active_directory_credential (NULL, &data),
                   is_equal_to (VERIFY_AD_CREDENTIAL_DESTINATION_NOT_ALLOWED));
      assert_that (verify_active_directory_credential ("credential-id", NULL),
                   is_equal_to (VERIFY_AD_CREDENTIAL_DESTINATION_NOT_ALLOWED));
      data.port = NULL;
      saved_port = NULL;
      assert_that (verify_active_directory_credential (NULL, &data),
                   is_equal_to (VERIFY_AD_CREDENTIAL_DESTINATION_NOT_ALLOWED));
      assert_that (verify_active_directory_credential ("credential-id", NULL),
                   is_equal_to (VERIFY_AD_CREDENTIAL_DESTINATION_NOT_ALLOWED));
      data.port = "bad";
      saved_port = "bad";
      assert_that (verify_active_directory_credential (NULL, &data),
                   is_equal_to (VERIFY_AD_CREDENTIAL_INVALID_PORT));
      assert_that (verify_active_directory_credential ("credential-id", NULL),
                   is_equal_to (VERIFY_AD_CREDENTIAL_INVALID_STORED_CONFIGURATION));
      permission_allowed = FALSE;
      assert_that (verify_active_directory_credential (NULL, &data),
                   is_equal_to (VERIFY_AD_CREDENTIAL_PERMISSION_DENIED));
      assert_no_ad_connector_calls ();
    }

  /* Uninitialized also denies, and checking must not lazily repair it. */
  g_clear_pointer (&ad_allowed_hosts, g_ptr_array_unref);
  g_clear_pointer (&ad_allowed_ports, g_array_unref);
  set_test_ad_config ("[active_directory]\nallowed_hosts = \nallowed_ports = \n");
  assert_that (check_active_directory_destination ("dc.example.com", "636",
                                                   "ldaps", NULL),
               is_equal_to (AD_DESTINATION_NOT_ALLOWED));
  assert_that (ad_allowed_hosts, is_null);
  assert_that (ad_allowed_ports, is_null);
}

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
  const gchar *invalid_ports[] = {
    "", " ", " 389", "389 ", "0", "65536", "18446744073709551616",
    "+389", "-389", "ldap", "0x185", "389-636", "389junk", "invalid"
  };
  const gchar *invalid_modes[] = { NULL, "", "ldap", "LDAPS", " starttls" };

  assert_that (configure_ad_connector (NULL, &data, 12, 34),
               is_equal_to (AD_CONNECTOR_INVALID_VALUE));
  assert_that (configure_ad_connector (test_connector, NULL, 12, 34),
               is_equal_to (AD_CONNECTOR_INVALID_VALUE));
  for (guint i = 0; i < G_N_ELEMENTS (invalid_ports); i++)
    {
      data.port = (gchar *) invalid_ports[i];
      assert_that (configure_ad_connector (test_connector, &data, 12, 34),
                   is_equal_to (AD_CONNECTOR_INVALID_VALUE));
      assert_no_ad_connector_calls ();
    }
  for (guint i = 0; i < G_N_ELEMENTS (invalid_modes); i++)
    {
      data.tls_mode = (gchar *) invalid_modes[i];
      data.port = NULL;
      assert_that (configure_ad_connector (test_connector, &data, 12, 34),
                   is_equal_to (AD_CONNECTOR_INVALID_VALUE));
      data.port = "636";
      assert_that (configure_ad_connector (test_connector, &data, 12, 34),
                   is_equal_to (AD_CONNECTOR_INVALID_VALUE));
      assert_no_ad_connector_calls ();
    }

  data = valid_ad_data ();
  builder_failure_enabled = TRUE;
  builder_failure_option = AD_CONNECTOR_OPT_TLS_MODE;
  builder_failure_result = AD_CONNECTOR_CONNECTION_ERROR;

  assert_that (configure_ad_connector (test_connector, &data, 12, 34),
               is_equal_to (AD_CONNECTOR_CONNECTION_ERROR));
  assert_that (builder_calls, is_equal_to (3));
}

Ensure (manage_active_directory, configure_uses_effective_ports_without_policy)
{
  ad_credential_data_t data = valid_ad_data ();
  const gchar *ports[] = { NULL, NULL, "0003268", "3269", "1389" };
  const gchar *modes[] = { "starttls", "ldaps", "ldaps", "starttls", "ldaps" };
  const guint expected[] = { 389, 636, 3268, 3269, 1389 };

  set_test_ad_config ("[active_directory]\n"
                      "allowed_hosts = other.invalid\nallowed_ports = 1\n");
  load_active_directory_config ();
  for (guint i = 0; i < G_N_ELEMENTS (ports); i++)
    {
      guint effective_port;

      reset_test_state ();
      data.port = (gchar *) ports[i];
      data.tls_mode = (gchar *) modes[i];
      assert_that (active_directory_effective_port (data.port, data.tls_mode,
                                                    &effective_port),
                   is_equal_to (AD_DESTINATION_OK));
      assert_that (configure_ad_connector (test_connector, &data, 12, 34),
                   is_equal_to (AD_CONNECTOR_OK));
      assert_that (builder_calls, is_equal_to (6));
      assert_that (builder_port, is_equal_to (expected[i]));
      assert_that (builder_port, is_equal_to (effective_port));
      assert_that (builder_tls_mode,
           is_equal_to (g_str_equal (data.tls_mode, "ldaps")
                  ? AD_CONNECTOR_TLS_LDAPS
                  : AD_CONNECTOR_TLS_STARTTLS));
      assert_that (builder_host, is_equal_to_string (data.host));
      assert_that (connector_new_calls, is_equal_to (0));
      assert_that (connector_connect_calls, is_equal_to (0));
    }
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
  permission_allowed = FALSE;
  data.host = " invalid host ";
  data.port = "bad";
  assert_that (verify_active_directory_credential (NULL, &data),
               is_equal_to (VERIFY_AD_CREDENTIAL_FEATURE_DISABLED));
  assert_that (verify_active_directory_credential ("credential-id", NULL),
               is_equal_to (VERIFY_AD_CREDENTIAL_FEATURE_DISABLED));
  assert_no_ad_connector_calls ();
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
               is_equal_to (VERIFY_AD_CREDENTIAL_CONNECTION_FAILED));

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


Ensure (manage_active_directory, verify_denies_inline_and_stored_before_connector)
{
  ad_credential_data_t data = valid_ad_data ();

  set_test_ad_config ("[active_directory]\nallowed_hosts = other.invalid\n"
                      "allowed_ports = 636\n");
  load_active_directory_config ();
  assert_that (verify_active_directory_credential (NULL, &data),
               is_equal_to (VERIFY_AD_CREDENTIAL_DESTINATION_NOT_ALLOWED));
  assert_that (verify_active_directory_credential ("credential-id", NULL),
               is_equal_to (VERIFY_AD_CREDENTIAL_DESTINATION_NOT_ALLOWED));

  set_test_ad_config ("[active_directory]\nallowed_hosts = dc.example.com\n"
                      "allowed_ports = 389\n");
  load_active_directory_config ();
  assert_that (verify_active_directory_credential (NULL, &data),
               is_equal_to (VERIFY_AD_CREDENTIAL_DESTINATION_NOT_ALLOWED));
  assert_that (verify_active_directory_credential ("credential-id", NULL),
               is_equal_to (VERIFY_AD_CREDENTIAL_DESTINATION_NOT_ALLOWED));
  assert_that (connector_new_calls, is_equal_to (0));
  assert_that (builder_calls, is_equal_to (0));
  assert_that (connector_connect_calls, is_equal_to (0));
}

Ensure (manage_active_directory, verify_syntax_and_permissions_precede_policy)
{
  ad_credential_data_t data = valid_ad_data ();
  const gchar *bad_hosts[] = { "dc.example.com:636", "*.example.com",
                              "192.0.2.1/24", " dc.example.com", "\t", "" };

  set_test_ad_config ("[active_directory]\nallowed_hosts = other.invalid\n"
                      "allowed_ports = 1\n");
  load_active_directory_config ();
  for (guint i = 0; i < G_N_ELEMENTS (bad_hosts); i++)
    {
      data.host = (gchar *) bad_hosts[i];
      assert_that (verify_active_directory_credential (NULL, &data),
                   is_equal_to (*bad_hosts[i] ? VERIFY_AD_CREDENTIAL_INVALID_HOST
                                             : VERIFY_AD_CREDENTIAL_HOST_REQUIRED));
      saved_host = bad_hosts[i];
      assert_that (verify_active_directory_credential ("credential-id", NULL),
                   is_equal_to (VERIFY_AD_CREDENTIAL_INVALID_STORED_CONFIGURATION));
    }
  data.port = "invalid";
  assert_that (verify_active_directory_credential (NULL, &data),
               is_equal_to (VERIFY_AD_CREDENTIAL_HOST_REQUIRED));
  data = valid_ad_data ();
  data.port = "invalid";
  assert_that (verify_active_directory_credential (NULL, &data),
               is_equal_to (VERIFY_AD_CREDENTIAL_INVALID_PORT));
  saved_host = "dc.example.com";
  saved_port = "";
  assert_that (verify_active_directory_credential ("credential-id", NULL),
               is_equal_to (VERIFY_AD_CREDENTIAL_INVALID_STORED_CONFIGURATION));
  permission_allowed = FALSE;
  assert_that (verify_active_directory_credential (NULL, &data),
               is_equal_to (VERIFY_AD_CREDENTIAL_PERMISSION_DENIED));
  assert_that (verify_active_directory_credential ("credential-id", NULL),
               is_equal_to (VERIFY_AD_CREDENTIAL_PERMISSION_DENIED));
  assert_that (connector_new_calls, is_equal_to (0));
  assert_that (connector_connect_calls, is_equal_to (0));
}

Ensure (manage_active_directory, verify_configures_checked_defaults_and_ports)
{
  ad_credential_data_t data = valid_ad_data ();
  const gchar *ports[] = { NULL, NULL, "0003268", "3269", "1389" };
  const gchar *modes[] = { "starttls", "ldaps", "ldaps", "starttls", "ldaps" };
  const guint numbers[] = { 389, 636, 3268, 3269, 1389 };

  set_test_ad_config ("[active_directory]\nallowed_hosts = dc.example.com\n"
                      "allowed_ports = 389,636,3268,3269,1389\n");
  load_active_directory_config ();
  for (guint i = 0; i < G_N_ELEMENTS (ports); i++)
    {
      reset_test_state ();
      data.host = "DC.Example.COM.";
      data.port = (gchar *) ports[i];
      data.tls_mode = (gchar *) modes[i];
      assert_that (verify_active_directory_credential (NULL, &data),
                   is_equal_to (VERIFY_AD_CREDENTIAL_OK));
      assert_that (builder_port, is_equal_to (numbers[i]));
      assert_that (builder_host, is_equal_to_string ("DC.Example.COM."));
      reset_test_state ();
      saved_port = ports[i];
      saved_tls_mode = modes[i];
      assert_that (verify_active_directory_credential ("credential-id", NULL),
                   is_equal_to (VERIFY_AD_CREDENTIAL_OK));
      assert_that (builder_port, is_equal_to (numbers[i]));
    }
}

Ensure (manage_active_directory, verify_denied_default_never_retries)
{
  ad_credential_data_t data = valid_ad_data ();
  const gchar *modes[] = { "starttls", "ldaps" };

  set_test_ad_config ("[active_directory]\nallowed_ports = 3269\n");
  load_active_directory_config ();
  data.port = NULL;
  saved_port = NULL;
  for (guint i = 0; i < G_N_ELEMENTS (modes); i++)
    {
      data.tls_mode = (gchar *) modes[i];
      saved_tls_mode = modes[i];
      assert_that (verify_active_directory_credential (NULL, &data),
                   is_equal_to (VERIFY_AD_CREDENTIAL_DESTINATION_NOT_ALLOWED));
      assert_that (verify_active_directory_credential ("credential-id", NULL),
                   is_equal_to (VERIFY_AD_CREDENTIAL_DESTINATION_NOT_ALLOWED));
      assert_no_ad_connector_calls ();
    }
}

Ensure (manage_active_directory, verify_empty_lists_allow_nonstandard_not_invalid_ports)
{
  ad_credential_data_t data = valid_ad_data ();

  /* Empty overrides replace restrictive file values, not the built-in ports. */
  set_test_ad_config ("[active_directory]\nallowed_hosts = other.invalid\n"
                      "allowed_ports = 636\n");
  g_setenv ("GVMD_AD_ALLOWED_HOSTS", " \t ", TRUE);
  g_setenv ("GVMD_AD_ALLOWED_PORTS", "", TRUE);
  load_active_directory_config ();
  data.host = "UNRESOLVABLE.invalid.";
  data.port = "001389";
  assert_that (verify_active_directory_credential (NULL, &data),
               is_equal_to (VERIFY_AD_CREDENTIAL_OK));
  assert_that (builder_host, is_equal_to_string (data.host));
  assert_that (builder_port, is_equal_to (1389));

  reset_test_state ();
  saved_host = "unresolvable.invalid";
  saved_port = "1389";
  assert_that (verify_active_directory_credential ("credential-id", NULL),
               is_equal_to (VERIFY_AD_CREDENTIAL_OK));
  assert_that (builder_port, is_equal_to (1389));

  reset_test_state ();
  data.port = "\t1389";
  saved_port = "\t1389";
  assert_that (verify_active_directory_credential (NULL, &data),
               is_equal_to (VERIFY_AD_CREDENTIAL_INVALID_PORT));
  assert_that (verify_active_directory_credential ("credential-id", NULL),
               is_equal_to (VERIFY_AD_CREDENTIAL_INVALID_STORED_CONFIGURATION));
  assert_that (policy_warning_count, is_equal_to (0));
  assert_no_ad_connector_calls ();
}

Ensure (manage_active_directory, verify_preserves_whitespace_and_structural_precedence)
{
  ad_credential_data_t data = valid_ad_data ();

  /* Non-host fields retain their existing nonempty, untrimmed semantics. */
  data.bind_dn = " \t ";
  data.base_dn = "\t";
  data.bind_password = " password\t ";
  assert_that (verify_active_directory_credential (NULL, &data),
               is_equal_to (VERIFY_AD_CREDENTIAL_OK));
  assert_that (builder_bind_dn, is_equal_to_string (" \t "));
  assert_that (connected_password, is_equal_to_string (" password\t "));
  assert_that (data.base_dn, is_equal_to_string ("\t"));

  reset_test_state ();
  set_test_ad_config ("[active_directory]\nallowed_hosts = other.invalid\n"
                      "allowed_ports = 1\n");
  load_active_directory_config ();
  data.host = "\tdc.example.com";
  data.port = "636\t";
  data.tls_mode = "ldaps ";
  data.ca_certificate = "not-a-certificate";
  data.bind_dn = "";
  assert_that (verify_active_directory_credential (NULL, &data),
               is_equal_to (VERIFY_AD_CREDENTIAL_BIND_DN_REQUIRED));
  data.bind_dn = " \t ";
  assert_that (verify_active_directory_credential (NULL, &data),
               is_equal_to (VERIFY_AD_CREDENTIAL_INVALID_PORT));
  data.port = "636";
  assert_that (verify_active_directory_credential (NULL, &data),
               is_equal_to (VERIFY_AD_CREDENTIAL_INVALID_HOST));
  data.host = "dc.example.com";
  assert_that (verify_active_directory_credential (NULL, &data),
               is_equal_to (VERIFY_AD_CREDENTIAL_INVALID_TLS_MODE));
  data.tls_mode = "ldaps";
  assert_that (verify_active_directory_credential (NULL, &data),
               is_equal_to (VERIFY_AD_CREDENTIAL_INVALID_CA_CERTIFICATE));
  saved_ca_certificate = "not-a-certificate";
  assert_that (verify_active_directory_credential ("credential-id", NULL),
               is_equal_to (VERIFY_AD_CREDENTIAL_INVALID_STORED_CONFIGURATION));
  assert_no_ad_connector_calls ();
}

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, manage_active_directory,
                         failed_policy_preserves_syntax_and_denies_commands);
  add_test_with_context (suite, manage_active_directory,
                         verify_empty_lists_allow_nonstandard_not_invalid_ports);
  add_test_with_context (suite, manage_active_directory,
                         verify_preserves_whitespace_and_structural_precedence);
  add_test_with_context (suite, manage_active_directory,
                         verify_denies_inline_and_stored_before_connector);
  add_test_with_context (suite, manage_active_directory,
                         verify_syntax_and_permissions_precede_policy);
  add_test_with_context (suite, manage_active_directory,
                         verify_configures_checked_defaults_and_ports);
  add_test_with_context (suite, manage_active_directory,
                         verify_denied_default_never_retries);
  add_test_with_context (suite, manage_active_directory,
                         effective_port_defaults_and_explicit_values);
  add_test_with_context (suite, manage_active_directory,
                         checker_matches_names_without_rewriting_input);
  add_test_with_context (suite, manage_active_directory,
                         checker_matches_only_same_family_addresses);
  add_test_with_context (suite, manage_active_directory,
                         checker_empty_lists_still_validate_syntax);
  add_test_with_context (suite, manage_active_directory,
                         checker_syntax_precedes_policy_denial);
  add_test_with_context (suite, manage_active_directory,
                         checker_defaults_and_denial_never_fall_back);
  add_test_with_context (suite, manage_active_directory,
                         checker_reads_immutable_loaded_policy);
  add_test_with_context (suite, manage_active_directory,
                         configure_uses_effective_ports_without_policy);
  add_test_with_context (suite, manage_active_directory,
                         loader_defaults_for_missing_configuration);
  add_test_with_context (suite, manage_active_directory,
                         loader_resolves_options_independently);
  add_test_with_context (suite, manage_active_directory,
                         loader_accepts_explicit_empty_lists);
  add_test_with_context (suite, manage_active_directory,
                         loader_normalizes_and_deduplicates);
  add_test_with_context (suite, manage_active_directory,
                         loader_discards_invalid_selected_host_lists);
  add_test_with_context (suite, manage_active_directory,
                         loader_discards_invalid_selected_port_lists);
  add_test_with_context (suite, manage_active_directory,
                         loader_handles_file_errors_independently);
  add_test_with_context (suite, manage_active_directory,
                         loader_ignores_overridden_file_lists);
  add_test_with_context (suite, manage_active_directory,
                         loader_reinitializes_when_runtime_disabled);
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
