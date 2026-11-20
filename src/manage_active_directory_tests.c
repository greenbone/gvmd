/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <cgreen/cgreen.h>

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
static gchar *previous_network_timeout_env;
static gchar *previous_operation_timeout_env;
static guint timeout_warning_count;
static gchar *last_timeout_warning;
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
  else if (strstr (message, "active_directory.network_timeout_seconds")
           || strstr (message, "active_directory.operation_timeout_seconds"))
    {
      timeout_warning_count++;
      g_free (last_timeout_warning);
      last_timeout_warning = g_strdup (message);
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
static const gchar *expected_permission;
static guint config_command_checks;
static gboolean enrichment_permissions;
static gboolean credential_lookup_failed;
static credential_t saved_credential;
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
static ad_connector_return_t connector_search_result;
static ad_object_type_t search_object_type;
static const gchar *search_account_control;
static const gchar *search_hostname;
static guint collected_objects_freed;
static gchar *connected_password;
static guint connector_new_calls;
static guint connector_connect_calls;
static gchar *requested_attributes;
static gboolean requested_include_disabled_computers;

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
  if (g_str_equal (permission, "get_configs"))
    config_command_checks++;
  if (enrichment_permissions)
    {
      assert_that (g_str_equal (permission, "get_active_directory_objects")
                   || g_str_equal (permission, "get_targets")
                   || g_str_equal (permission, "get_tasks")
                   || g_str_equal (permission, "get_configs"),
                   is_true);
      return permission_allowed;
    }
  assert_that (permission,
               is_equal_to_string (expected_permission));
  return permission_allowed;
}

#define TEST_TARGET 42
#define TEST_CONFIG 200

typedef struct
{
  gboolean readable;
  gboolean target_trashed;
  gboolean config_trashed;
  const gchar *config_uuid;
  gboolean config_readable;
  gboolean config_error;
} task_details_row_t;

static const task_details_row_t *task_details_rows;
static guint task_details_count;
static gint task_details_index;
static iterator_t *task_details_iterator;
static guint config_permission_checks;
static guint task_iterator_cleanups;
static iterator_t *target_candidate_iterator;
static const gchar *target_candidate_hosts;
static const gchar *target_candidate_exclusions;
static gboolean target_candidate_readable;
static gboolean target_candidate_available;

int
__wrap_init_ad_target_candidate_iterator_by_hostname (iterator_t *iterator,
                                                      const get_data_t *get,
                                                      GHashTable *hostnames)
{
  assert_that (get->trash, is_equal_to (0));
  assert_that (g_hash_table_contains (hostnames, "host.example.com"), is_true);
  target_candidate_iterator = iterator;
  target_candidate_available = target_candidate_readable;
  iterator->done = FALSE;
  return 0;
}

void
__wrap_init_target_task_details_iterator (iterator_t *iterator, target_t target)
{
  assert_that (target, is_equal_to (TEST_TARGET));
  task_details_iterator = iterator;
  task_details_index = -1;
  iterator->done = FALSE;
}

gboolean
__wrap_next (iterator_t *iterator)
{
  if (iterator == target_candidate_iterator)
    {
      iterator->done = !target_candidate_available;
      target_candidate_available = FALSE;
      return !iterator->done;
    }
  if (iterator == task_details_iterator)
    {
      task_details_index++;
      iterator->done = task_details_index >= (gint) task_details_count;
      return !iterator->done;
    }
  fail_test ("Unexpected iterator");
  return FALSE;
}

void
__wrap_cleanup_iterator (iterator_t *iterator)
{
  if (iterator == target_candidate_iterator)
    target_candidate_iterator = NULL;
  else if (iterator == task_details_iterator)
    {
      task_iterator_cleanups++;
      task_details_iterator = NULL;
    }
  else
    fail_test ("Unexpected iterator");
}

const char *
__wrap_target_task_details_iterator_name (iterator_t *iterator)
{
  return "Task name";
}

const char *
__wrap_target_task_details_iterator_uuid (iterator_t *iterator)
{
  return "task-id";
}

int
__wrap_target_task_details_iterator_readable (iterator_t *iterator)
{
  return task_details_rows[task_details_index].readable;
}

int
__wrap_target_task_details_iterator_target_in_trash (iterator_t *iterator)
{
  return task_details_rows[task_details_index].target_trashed;
}

int
__wrap_target_task_details_iterator_config_in_trash (iterator_t *iterator)
{
  return task_details_rows[task_details_index].config_trashed;
}

const char *
__wrap_target_task_details_iterator_config_uuid (iterator_t *iterator)
{
  return task_details_rows[task_details_index].config_uuid;
}

const char *
__wrap_target_task_details_iterator_config_name (iterator_t *iterator)
{
  return "Configuration name";
}

resource_t
__wrap_get_iterator_resource (iterator_t *iterator)
{
  assert_that (iterator, is_equal_to (target_candidate_iterator));
  return TEST_TARGET;
}

const char *
__wrap_get_iterator_uuid (iterator_t *iterator)
{
  assert_that (iterator, is_equal_to (target_candidate_iterator));
  return "target-id";
}

const char *
__wrap_get_iterator_name (iterator_t *iterator)
{
  assert_that (iterator, is_equal_to (target_candidate_iterator));
  return "Target name";
}

const char *
__wrap_target_iterator_hosts (iterator_t *iterator)
{
  return target_candidate_hosts;
}

const char *
__wrap_target_iterator_exclude_hosts (iterator_t *iterator)
{
  return target_candidate_exclusions;
}

gboolean
__wrap_find_config_with_permission (const char *uuid, config_t *config,
                                    const char *permission)
{
  assert_that (uuid, is_equal_to_string ("config-id"));
  assert_that (permission, is_equal_to_string ("get_configs"));
  config_permission_checks++;
  *config = task_details_rows[task_details_index].config_readable
              ? TEST_CONFIG
              : 0;
  return task_details_rows[task_details_index].config_error;
}

gboolean
__wrap_find_credential_with_permission (const char *uuid,
                                        credential_t *credential,
                                        const char *permission)
{
  assert_that (uuid, is_equal_to_string ("credential-id"));
  assert_that (permission, is_equal_to_string ("get_credentials"));
  *credential = saved_credential;
  return credential_lookup_failed;
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
  if (builder_calls >= (int) G_N_ELEMENTS (builder_options))
    {
      fail_test ("Too many AD connector builder calls");
      return AD_CONNECTOR_INVALID_VALUE;
    }
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

static void
count_collected_object_free (gpointer object)
{
  collected_objects_freed++;
  ad_directory_object_free (object);
}

static void
add_object_attribute (ad_object_t *object, const gchar *name,
                      const gchar *first, const gchar *second)
{
  GPtrArray *values = g_ptr_array_new_with_free_func (g_free);

  if (!object->attributes)
    object->attributes = g_hash_table_new_full (
      g_str_hash, g_str_equal, g_free, (GDestroyNotify) g_ptr_array_unref);
  g_ptr_array_add (values, g_strdup (first));
  if (second)
    g_ptr_array_add (values, g_strdup (second));
  g_hash_table_insert (object->attributes, g_strdup (name), values);
}

ad_connector_return_t
__real_ad_search_config_builder (ad_search_config_t, ad_search_config_opt_t,
                                 const void *);

ad_connector_return_t
__wrap_ad_search_config_builder (ad_search_config_t config,
                                 ad_search_config_opt_t option,
                                 const void *value)
{
  if (option == AD_SEARCH_CONFIG_OPT_EXTRA_ATTRIBUTES)
    {
      g_free (requested_attributes);
      requested_attributes = g_strdup (value);
    }
  else if (option == AD_SEARCH_CONFIG_OPT_INCLUDE_DISABLED_COMPUTERS)
    requested_include_disabled_computers = *((const gboolean *) value);
  return __real_ad_search_config_builder (config, option, value);
}

ad_connector_return_t
__wrap_ad_connector_search_objects (ad_connector_t connector,
                                    const ad_search_config_t config,
                                    ad_object_callback_t callback,
                                    gpointer user_data,
                                    ad_object_search_result_t *result)
{
  get_ad_objects_result_t *search_results = user_data;
  ad_object_t *object = g_new0 (ad_object_t, 1);

  object->type = search_object_type;
  object->name = g_strdup ("hosts");
  object->distinguished_name = g_strdup ("OU=hosts,DC=example,DC=com");
  object->parent_dn = g_strdup ("DC=example,DC=com");

  if (search_hostname)
    add_object_attribute (object, "dNSHostName", search_hostname, NULL);
  if (search_account_control)
    add_object_attribute (object, "userAccountControl",
                          search_account_control, NULL);

  assert_that (connector, is_equal_to (test_connector));
  assert_that (config, is_non_null);
  g_ptr_array_set_free_func (search_results->objects,
                             count_collected_object_free);
  assert_that (callback (object, user_data),
               is_equal_to (AD_OBJECT_CALLBACK_CONTINUE));
  result->emitted = 1;
  result->truncated = TRUE;
  return connector_search_result;
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

/**
 * @brief Clear recorded connector and search calls without changing fixtures.
 */
static void
reset_connector_observations (void)
{
  connector_new_calls = 0;
  connector_connect_calls = 0;
  collected_objects_freed = 0;
  g_clear_pointer (&connected_password, g_free);
  g_clear_pointer (&requested_attributes, g_free);
  requested_include_disabled_computers = FALSE;

  builder_calls = 0;
  memset (builder_options, 0, sizeof (builder_options));
  builder_host = NULL;
  builder_bind_dn = NULL;
  builder_ca_certificate = NULL;
  builder_port = -1;
  builder_network_timeout = -1;
  builder_operation_timeout = -1;
  builder_tls_mode = (ad_connector_tls_mode_t) -1;

  config_permission_checks = 0;
  config_command_checks = 0;
  task_iterator_cleanups = 0;
}

static void
reset_test_state (void)
{
  feature_is_enabled = TRUE;
  permission_allowed = TRUE;
  enrichment_permissions = FALSE;
  expected_permission = "verify_active_directory_credential";
  credential_lookup_failed = FALSE;
  saved_credential = 42;
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
  connector_search_result = AD_CONNECTOR_OK;
  search_object_type = AD_OBJECT_TYPE_OU;
  search_account_control = NULL;
  search_hostname = NULL;
  target_candidate_iterator = NULL;
  target_candidate_hosts = NULL;
  target_candidate_exclusions = NULL;
  target_candidate_readable = FALSE;
  task_details_iterator = NULL;
  task_details_rows = NULL;
  task_details_count = 0;
  reset_connector_observations ();

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
  previous_network_timeout_env =
    g_strdup (g_getenv ("GVMD_AD_NETWORK_TIMEOUT_SECONDS"));
  previous_operation_timeout_env =
    g_strdup (g_getenv ("GVMD_AD_OPERATION_TIMEOUT_SECONDS"));
  g_unsetenv ("GVMD_AD_NETWORK_TIMEOUT_SECONDS");
  g_unsetenv ("GVMD_AD_OPERATION_TIMEOUT_SECONDS");
  test_config = g_key_file_new ();
  policy_warning_count = 0;
  timeout_warning_count = 0;
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
  g_clear_pointer (&last_timeout_warning, g_free);
  if (previous_allowed_hosts_env)
    g_setenv ("GVMD_AD_ALLOWED_HOSTS", previous_allowed_hosts_env, TRUE);
  else
    g_unsetenv ("GVMD_AD_ALLOWED_HOSTS");
  if (previous_allowed_ports_env)
    g_setenv ("GVMD_AD_ALLOWED_PORTS", previous_allowed_ports_env, TRUE);
  else
    g_unsetenv ("GVMD_AD_ALLOWED_PORTS");
  if (previous_network_timeout_env)
    g_setenv ("GVMD_AD_NETWORK_TIMEOUT_SECONDS", previous_network_timeout_env,
              TRUE);
  else
    g_unsetenv ("GVMD_AD_NETWORK_TIMEOUT_SECONDS");
  if (previous_operation_timeout_env)
    g_setenv ("GVMD_AD_OPERATION_TIMEOUT_SECONDS",
              previous_operation_timeout_env, TRUE);
  else
    g_unsetenv ("GVMD_AD_OPERATION_TIMEOUT_SECONDS");
  g_clear_pointer (&previous_network_timeout_env, g_free);
  g_clear_pointer (&previous_operation_timeout_env, g_free);
  g_clear_pointer (&previous_allowed_hosts_env, g_free);
  g_clear_pointer (&previous_allowed_ports_env, g_free);
  g_clear_pointer (&requested_attributes, g_free);
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

static ad_object_t *
new_test_object (ad_object_type_t type)
{
  ad_object_t *object = g_new0 (ad_object_t, 1);

  object->type = type;
  object->name = g_strdup ("host");
  object->distinguished_name = g_strdup ("CN=host,DC=example,DC=com");
  return object;
}

Ensure (manage_active_directory, object_map_owns_all_selected_values)
{
  ad_object_t *source = new_test_object (AD_OBJECT_TYPE_COMPUTER);
  gchar *name = source->name;
  ad_directory_object_t *copy;
  GPtrArray *values, *original_values;
  gchar *original_value;

  add_object_attribute (source, "DNSHOSTNAME", "host.example.com", NULL);
  add_object_attribute (source, "servicePrincipalName", "HOST/host",
                         "HOST/host.example.com");
  add_object_attribute (source, "description", "computer", NULL);
  add_object_attribute (source, "memberOf", "CN=group,DC=example,DC=com", NULL);
  add_object_attribute (source, "unrequested", "ignored", NULL);
  original_values = g_hash_table_lookup (source->attributes,
                                         "servicePrincipalName");
  original_value = g_ptr_array_index (original_values, 0);
  copy = ad_directory_object_from_search_object (source);

  assert_that (copy->name, is_equal_to (name));
  assert_that (copy->name, is_equal_to_string ("host"));
  assert_that (copy->parent_dn, is_null);
  assert_that (g_hash_table_size (copy->attributes), is_equal_to (3));
  assert_that (ad_object_attribute_value (copy, "dNSHostName"),
               is_equal_to_string ("host.example.com"));
  assert_that (ad_object_attribute_value (copy, "operatingSystem"),
               is_null);
  assert_that (ad_object_attribute_value (copy, "memberOf"), is_null);
  values = g_hash_table_lookup (copy->attributes, "serviceprincipalname");
  assert_that (values, is_equal_to (original_values));
  assert_that (g_ptr_array_index (values, 0), is_equal_to (original_value));
  assert_that (values->len, is_equal_to (2));
  assert_that (g_ptr_array_index (values, 0), is_equal_to_string ("HOST/host"));
  assert_that (g_ptr_array_index (values, 1),
               is_equal_to_string ("HOST/host.example.com"));
  ad_directory_object_free (copy);
}

Ensure (manage_active_directory, object_map_selects_actual_object_type)
{
  ad_object_t *source = new_test_object (AD_OBJECT_TYPE_GROUP);
  ad_directory_object_t *copy;

  add_object_attribute (source, "cn", "group", NULL);
  add_object_attribute (source, "ou", "hosts", NULL);
  add_object_attribute (source, "dNSHostName", "host.example.com", NULL);
  add_object_attribute (source, "displayName", "Test group", NULL);
  add_object_attribute (source, "memberOf", "CN=parent,DC=example,DC=com", NULL);
  copy = ad_directory_object_from_search_object (source);
  assert_that (g_hash_table_size (copy->attributes), is_equal_to (2));
  assert_that (ad_object_attribute_value (copy, "displayName"),
               is_equal_to_string ("Test group"));
  assert_that (ad_object_attribute_value (copy, "memberOf"), is_null);
  assert_that (ad_object_attribute_value (copy, "ou"), is_null);
  assert_that (ad_object_attribute_value (copy, "dNSHostName"),
               is_null);
  ad_directory_object_free (copy);

  source = new_test_object (AD_OBJECT_TYPE_OU);
  add_object_attribute (source, "cn", "group", NULL);
  add_object_attribute (source, "ou", "hosts", NULL);
  add_object_attribute (source, "memberOf", "CN=parent,DC=example,DC=com", NULL);
  copy = ad_directory_object_from_search_object (source);
  assert_that (g_hash_table_size (copy->attributes), is_equal_to (2));
  assert_that (ad_object_attribute_value (copy, "ou"),
               is_equal_to_string ("hosts"));
  assert_that (ad_object_attribute_value (copy, "memberOf"), is_null);
  ad_directory_object_free (copy);

  source = new_test_object (AD_OBJECT_TYPE_CONTAINER);
  add_object_attribute (source, "cn", "Computers", NULL);
  add_object_attribute (source, "ou", "ignored", NULL);
  add_object_attribute (source, "description", "Default container", NULL);
  copy = ad_directory_object_from_search_object (source);
  assert_that (g_hash_table_size (copy->attributes), is_equal_to (2));
  assert_that (ad_object_attribute_value (copy, "cn"),
               is_equal_to_string ("Computers"));
  assert_that (ad_object_attribute_value (copy, "description"),
               is_equal_to_string ("Default container"));
  assert_that (ad_object_attribute_value (copy, "ou"), is_null);
  ad_directory_object_free (copy);
}

Ensure (manage_active_directory, collection_counts_non_computer_types)
{
  GPtrArray *objects = g_ptr_array_new_with_free_func (
    (GDestroyNotify) ad_directory_object_free);
  get_ad_objects_result_t result = { .objects = objects };
  ad_object_t *source;

  source = new_test_object (AD_OBJECT_TYPE_OU);
  assert_that (collect_ad_object (source, &result),
               is_equal_to (AD_OBJECT_CALLBACK_CONTINUE));
  source = new_test_object (AD_OBJECT_TYPE_CONTAINER);
  assert_that (collect_ad_object (source, &result),
               is_equal_to (AD_OBJECT_CALLBACK_CONTINUE));
  source = new_test_object (AD_OBJECT_TYPE_GROUP);
  assert_that (collect_ad_object (source, &result),
               is_equal_to (AD_OBJECT_CALLBACK_CONTINUE));

  assert_that (objects->len, is_equal_to (3));
  assert_that (result.counts.ou, is_equal_to (1));
  assert_that (result.counts.container, is_equal_to (1));
  assert_that (result.counts.group, is_equal_to (1));
  assert_that (result.counts.computer_total, is_equal_to (0));
  g_ptr_array_unref (objects);
}

Ensure (manage_active_directory, collection_accepts_large_attributes)
{
  ad_object_t *source = new_test_object (AD_OBJECT_TYPE_COMPUTER);
  GPtrArray *objects = g_ptr_array_new_with_free_func (
    (GDestroyNotify) ad_directory_object_free);
  get_ad_objects_result_t result = { .objects = objects };
  const gsize length = 2 * 1024 * 1024 + 1;
  gchar *text = g_strnfill (length, 'a');
  GPtrArray *values, *retained_values;
  ad_directory_object_t *retained;

  add_object_attribute (source, "servicePrincipalName", text, NULL);
  values = g_hash_table_lookup (source->attributes, "servicePrincipalName");
  for (guint index = values->len; index < 1025; index++)
    g_ptr_array_add (values, g_strdup (""));
  g_free (text);

  assert_that (collect_ad_object (source, &result),
               is_equal_to (AD_OBJECT_CALLBACK_CONTINUE));
  assert_that (objects->len, is_equal_to (1));
  retained = g_ptr_array_index (objects, 0);
  retained_values = g_hash_table_lookup (retained->attributes,
                                         "serviceprincipalname");
  assert_that (retained_values, is_equal_to (values));
  assert_that (retained_values->len, is_equal_to (1025));
  assert_that (strlen (g_ptr_array_index (retained_values, 0)),
               is_equal_to (length));

  source = new_test_object (AD_OBJECT_TYPE_COMPUTER);
  add_object_attribute (source, "userAccountControl", "514", NULL);
  assert_that (collect_ad_object (source, &result),
               is_equal_to (AD_OBJECT_CALLBACK_CONTINUE));
  assert_that (objects->len, is_equal_to (2));
  assert_that (result.counts.computer_total, is_equal_to (2));
  assert_that (result.counts.computer_disabled, is_equal_to (1));
  g_ptr_array_unref (objects);
}

Ensure (manage_active_directory, search_transfers_owned_collection)
{
  get_ad_objects_params_t params = {
    .credential_id = "credential-id",
    .scope = AD_CONNECTOR_SEARCH_SCOPE_SUBTREE,
    .object_types = AD_OBJECT_TYPE_OU,
    .max_results = 1
  };
  get_ad_objects_result_t result = { 0 };
  ad_directory_object_t *object;

  expected_permission = "get_active_directory_objects";
  assert_that (get_active_directory_objects (&params, &result),
               is_equal_to (GET_AD_OBJECTS_OK));
  assert_that (builder_network_timeout,
               is_equal_to (AD_NETWORK_TIMEOUT_SECONDS_DEFAULT));
  assert_that (builder_operation_timeout,
               is_equal_to (AD_OPERATION_TIMEOUT_SECONDS_DEFAULT));
  assert_that (collected_objects_freed, is_equal_to (0));
  assert_that (result.objects, is_non_null);
  assert_that (result.objects->len, is_equal_to (1));
  assert_that (result.truncated, is_true);
  object = g_ptr_array_index (result.objects, 0);
  assert_that (object->name, is_equal_to_string ("hosts"));
  assert_that (object->distinguished_name,
               is_equal_to_string ("OU=hosts,DC=example,DC=com"));
  get_ad_objects_result_reset (&result);
}

static guint rejected_values_freed;

static void
count_rejected_value_free (gpointer value)
{
  rejected_values_freed++;
  g_free (value);
}

Ensure (manage_active_directory, collection_frees_rejected_objects)
{
  GPtrArray *objects = g_ptr_array_new_with_free_func (
    (GDestroyNotify) ad_directory_object_free);
  get_ad_objects_result_t result = { .objects = objects };
  ad_object_t *source;
  GPtrArray *values;

  rejected_values_freed = 0;

  source = new_test_object (AD_OBJECT_TYPE_COMPUTER);
  add_object_attribute (source, "description", "rejected", NULL);
  values = g_hash_table_lookup (source->attributes, "description");
  g_ptr_array_set_free_func (values, count_rejected_value_free);
  g_clear_pointer (&source->name, g_free);
  assert_that (collect_ad_object (source, &result),
               is_equal_to (AD_OBJECT_CALLBACK_ERROR));
  assert_that (objects->len, is_equal_to (0));
  assert_that (result.counts.ou, is_equal_to (0));
  assert_that (result.counts.group, is_equal_to (0));
  assert_that (result.counts.computer_total, is_equal_to (0));
  assert_that (result.counts.computer_disabled, is_equal_to (0));
  assert_that (rejected_values_freed, is_equal_to (1));

  source = new_test_object (AD_OBJECT_TYPE_COMPUTER);
  add_object_attribute (source, "description", "rejected", NULL);
  values = g_hash_table_lookup (source->attributes, "description");
  g_ptr_array_set_free_func (values, count_rejected_value_free);
  g_clear_pointer (&source->distinguished_name, g_free);
  assert_that (collect_ad_object (source, &result),
               is_equal_to (AD_OBJECT_CALLBACK_ERROR));
  assert_that (objects->len, is_equal_to (0));
  assert_that (result.counts.ou, is_equal_to (0));
  assert_that (result.counts.group, is_equal_to (0));
  assert_that (result.counts.computer_total, is_equal_to (0));
  assert_that (result.counts.computer_disabled, is_equal_to (0));
  assert_that (rejected_values_freed, is_equal_to (2));

  source = new_test_object (AD_OBJECT_TYPE_COMPUTER);
  add_object_attribute (source, "description", "rejected", NULL);
  values = g_hash_table_lookup (source->attributes, "description");
  g_ptr_array_set_free_func (values, count_rejected_value_free);
  source->type = AD_OBJECT_TYPE_ALL;
  assert_that (collect_ad_object (source, &result),
               is_equal_to (AD_OBJECT_CALLBACK_ERROR));
  assert_that (objects->len, is_equal_to (0));
  assert_that (result.counts.ou, is_equal_to (0));
  assert_that (result.counts.group, is_equal_to (0));
  assert_that (result.counts.computer_total, is_equal_to (0));
  assert_that (result.counts.computer_disabled, is_equal_to (0));
  assert_that (rejected_values_freed, is_equal_to (3));
  g_ptr_array_unref (objects);
}

Ensure (manage_active_directory, search_discards_partial_collection_on_failure)
{
  get_ad_objects_params_t params = {
    .credential_id = "credential-id",
    .scope = AD_CONNECTOR_SEARCH_SCOPE_SUBTREE,
    .object_types = AD_OBJECT_TYPE_OU,
    .max_results = 1
  };
  get_ad_objects_result_t result = { 0 };

  expected_permission = "get_active_directory_objects";
  connector_search_result = AD_CONNECTOR_RESULT_ERROR;
  assert_that (get_active_directory_objects (&params, &result),
               is_equal_to (GET_AD_OBJECTS_RESULT_FAILED));
  assert_that (collected_objects_freed, is_equal_to (1));
  assert_that (result.objects, is_null);
  assert_that (result.truncated, is_false);
  get_ad_objects_result_reset (&result);
}

static void
assert_search_succeeds (get_ad_objects_params_t *params)
{
  get_ad_objects_result_t result = { 0 };

  reset_connector_observations ();
  assert_that (get_active_directory_objects (params, &result),
               is_equal_to (GET_AD_OBJECTS_OK));
  get_ad_objects_result_reset (&result);
}

static void
assert_search_rejects_invalid_input (get_ad_objects_params_t *params)
{
  get_ad_objects_result_t result = { 0 };

  reset_connector_observations ();
  assert_that (get_active_directory_objects (params, &result),
               is_equal_to (GET_AD_OBJECTS_INVALID_INPUT));
  assert_that (result.objects, is_null);
  assert_that (connector_connect_calls, is_equal_to (0));
  assert_that (connected_password, is_null);
}

static void
assert_search_rejected_before_connector (get_ad_objects_return_t expected)
{
  get_ad_objects_params_t params = {
    .credential_id = "credential-id",
    .scope = AD_CONNECTOR_SEARCH_SCOPE_SUBTREE,
    .object_types = AD_OBJECT_TYPE_OU,
    .max_results = 1
  };
  get_ad_objects_result_t result = { 0 };

  expected_permission = "get_active_directory_objects";
  assert_that (get_active_directory_objects (&params, &result),
               is_equal_to (expected));
  assert_that (result.objects, is_null);
  assert_that (result.truncated, is_false);
  assert_no_ad_connector_calls ();
}

Ensure (manage_active_directory, search_enforces_feature_and_permission)
{
  get_ad_objects_params_t params = {
    .credential_id = "credential-id",
    .scope = AD_CONNECTOR_SEARCH_SCOPE_SUBTREE,
    .object_types = AD_OBJECT_TYPE_OU,
    .max_results = 1
  };
  get_ad_objects_result_t result = { 0 };

  expected_permission = "get_active_directory_objects";
  feature_is_enabled = FALSE;
  permission_allowed = FALSE;
  assert_that (get_active_directory_objects (&params, &result),
               is_equal_to (GET_AD_OBJECTS_FEATURE_DISABLED));
  feature_is_enabled = TRUE;
  assert_that (get_active_directory_objects (&params, &result),
               is_equal_to (GET_AD_OBJECTS_PERMISSION_DENIED));
  assert_that (result.objects, is_null);
  assert_no_ad_connector_calls ();
}

Ensure (manage_active_directory, search_maps_connection_failures_to_generic_error)
{
  const ad_connector_return_t failures[] = {
    AD_CONNECTOR_BIND_ERROR,
    AD_CONNECTOR_CONNECTION_ERROR,
    AD_CONNECTOR_INVALID_VALUE
  };
  get_ad_objects_params_t params = {
    .credential_id = "credential-id",
    .scope = AD_CONNECTOR_SEARCH_SCOPE_SUBTREE,
    .object_types = AD_OBJECT_TYPE_OU,
    .max_results = 1
  };

  for (guint i = 0; i < G_N_ELEMENTS (failures); i++)
    {
      get_ad_objects_result_t result = { 0 };

      reset_test_state ();
      expected_permission = "get_active_directory_objects";
      connector_connect_result = failures[i];
      assert_that (get_active_directory_objects (&params, &result),
                   is_equal_to (GET_AD_OBJECTS_CONNECTION_FAILED));
      assert_that (connector_new_calls, is_equal_to (1));
      assert_that (connector_connect_calls, is_equal_to (1));
      assert_that (result.objects, is_null);
      assert_that (result.truncated, is_false);
      assert_that (collected_objects_freed, is_equal_to (0));
      get_ad_objects_result_reset (&result);
    }
}

Ensure (manage_active_directory, search_checks_allowed_destination_and_port)
{
  const gchar *ports[] = { NULL, NULL, "0003268", "3269" };
  const gchar *modes[] = { "starttls", "ldaps", "ldaps", "starttls" };
  const guint expected_ports[] = { 389, 636, 3268, 3269 };
  get_ad_objects_params_t params = {
    .credential_id = "credential-id",
    .scope = AD_CONNECTOR_SEARCH_SCOPE_SUBTREE,
    .object_types = AD_OBJECT_TYPE_OU,
    .max_results = 1
  };

  set_test_ad_config ("[active_directory]\nallowed_hosts = dc.example.com\n"
                      "allowed_ports = 389,636,3268,3269\n");
  load_active_directory_config ();
  for (guint i = 0; i < G_N_ELEMENTS (ports); i++)
    {
      reset_test_state ();
      expected_permission = "get_active_directory_objects";
      saved_host = "DC.Example.COM.";
      saved_port = ports[i];
      saved_tls_mode = modes[i];
      assert_search_succeeds (&params);
      assert_that (builder_port, is_equal_to (expected_ports[i]));
      assert_that (connector_new_calls, is_equal_to (1));
      assert_that (connector_connect_calls, is_equal_to (1));
      assert_that (connected_password, is_equal_to_string ("password"));
    }
}

Ensure (manage_active_directory, search_rejects_disallowed_destination)
{
  const gchar *configs[] = {
    "[active_directory]\nallowed_hosts = other.invalid\nallowed_ports = 636\n",
    "[active_directory]\nallowed_hosts = dc.example.com\nallowed_ports = 389\n"
  };

  for (guint i = 0; i < G_N_ELEMENTS (configs); i++)
    {
      reset_test_state ();
      set_test_ad_config (configs[i]);
      load_active_directory_config ();
      assert_search_rejected_before_connector (
        GET_AD_OBJECTS_DESTINATION_NOT_ALLOWED);
    }
}

Ensure (manage_active_directory, search_rejects_disallowed_default_ports)
{
  const gchar *modes[] = { "starttls", "ldaps" };

  set_test_ad_config ("[active_directory]\nallowed_ports = 3269\n");
  load_active_directory_config ();
  for (guint i = 0; i < G_N_ELEMENTS (modes); i++)
    {
      reset_test_state ();
      saved_port = NULL;
      saved_tls_mode = modes[i];
      assert_search_rejected_before_connector (
        GET_AD_OBJECTS_DESTINATION_NOT_ALLOWED);
    }
}

Ensure (manage_active_directory, search_rejects_failed_or_uninitialized_policy)
{
  const gchar *configs[] = {
    "[active_directory]\nallowed_hosts = dc.example.com,\n",
    "[active_directory]\nallowed_ports = 636,0\n"
  };

  for (guint i = 0; i < G_N_ELEMENTS (configs); i++)
    {
      reset_test_state ();
      set_test_ad_config (configs[i]);
      load_active_directory_config ();
      assert_search_rejected_before_connector (
        GET_AD_OBJECTS_DESTINATION_NOT_ALLOWED);
    }

  g_clear_pointer (&ad_allowed_hosts, g_ptr_array_unref);
  g_clear_pointer (&ad_allowed_ports, g_array_unref);
  assert_search_rejected_before_connector (
    GET_AD_OBJECTS_DESTINATION_NOT_ALLOWED);
}

Ensure (manage_active_directory, search_validates_stored_fields_before_policy)
{
  const gchar **fields[] = {
    &saved_host, &saved_host, &saved_port, &saved_tls_mode,
    &saved_bind_dn, &saved_bind_password, &saved_ca_certificate
  };
  const gchar *invalid[] = {
    NULL, " invalid host ", "bad", "ldap", "", NULL, "not-a-certificate"
  };

  set_test_ad_config ("[active_directory]\nallowed_hosts = other.invalid\n");
  load_active_directory_config ();
  for (guint i = 0; i < G_N_ELEMENTS (fields); i++)
    {
      reset_test_state ();
      *fields[i] = invalid[i];
      assert_search_rejected_before_connector (
        GET_AD_OBJECTS_INVALID_STORED_CONFIGURATION);
    }
}

Ensure (manage_active_directory, search_accepts_base_within_credential)
{
  get_ad_objects_params_t params = {
    .credential_id = "credential-id",
    .scope = AD_CONNECTOR_SEARCH_SCOPE_SUBTREE,
    .object_types = AD_OBJECT_TYPE_OU,
    .max_results = 1
  };
  expected_permission = "get_active_directory_objects";
  saved_base_dn = "OU=Allowed,DC=example,DC=com";

  params.base_dn = NULL;
  assert_search_succeeds (&params);
  params.base_dn = "OU=Allowed,DC=example,DC=com";
  assert_search_succeeds (&params);
  params.base_dn = "OU=Child,OU=Allowed,DC=example,DC=com";
  assert_search_succeeds (&params);
  params.base_dn = "CN=Host,OU=Child,OU=Allowed,DC=example,DC=com";
  assert_search_succeeds (&params);
}

Ensure (manage_active_directory, search_rejects_base_outside_credential)
{
  get_ad_objects_params_t params = {
    .credential_id = "credential-id",
    .scope = AD_CONNECTOR_SEARCH_SCOPE_SUBTREE,
    .object_types = AD_OBJECT_TYPE_OU,
    .max_results = 1
  };
  expected_permission = "get_active_directory_objects";
  saved_base_dn = "OU=Allowed,DC=example,DC=com";

  params.base_dn = "";
  assert_search_rejects_invalid_input (&params);
  params.base_dn = "not-a-dn";
  assert_search_rejects_invalid_input (&params);
  params.base_dn = "DC=example,DC=com";
  assert_search_rejects_invalid_input (&params);
  params.base_dn = "OU=Other,DC=example,DC=com";
  assert_search_rejects_invalid_input (&params);
  params.base_dn = "OU=Allowed,DC=example,DC=org";
  assert_search_rejects_invalid_input (&params);
  params.base_dn = "OU=Fake\\,OU=Allowed,DC=example,DC=com";
  assert_search_rejects_invalid_input (&params);
}

Ensure (manage_active_directory, search_rejects_invalid_stored_base)
{
  get_ad_objects_params_t params = {
    .credential_id = "credential-id",
    .scope = AD_CONNECTOR_SEARCH_SCOPE_SUBTREE,
    .object_types = AD_OBJECT_TYPE_OU,
    .max_results = 1
  };
  expected_permission = "get_active_directory_objects";

  const gchar *missing_bases[] = { NULL, "" };
  for (guint i = 0; i < G_N_ELEMENTS (missing_bases); i++)
    for (guint supplied = 0; supplied < 2; supplied++)
      {
        get_ad_objects_result_t result = { 0 };

        saved_base_dn = missing_bases[i];
        params.base_dn = supplied ? "OU=Child,DC=example,DC=com" : NULL;
        assert_that (get_active_directory_objects (&params, &result),
                     is_equal_to (GET_AD_OBJECTS_INVALID_STORED_CONFIGURATION));
        assert_that (result.objects, is_null);
        assert_no_ad_connector_calls ();
      }

  saved_base_dn = "not-a-dn";
  params.base_dn = NULL;
  assert_search_rejects_invalid_input (&params);
  params.base_dn = "OU=Child,DC=example,DC=com";
  assert_search_rejects_invalid_input (&params);
}

Ensure (manage_active_directory, search_params_accept_valid_boundaries)
{
  get_ad_objects_params_t params = {
    .credential_id = "credential-id",
    .scope = AD_CONNECTOR_SEARCH_SCOPE_BASE,
    .object_types = AD_OBJECT_TYPE_OU,
    .max_results = 1
  };
  assert_that (valid_ad_object_search_params (&params), is_true);
  params.max_results = GET_AD_OBJECTS_MAX_RESULTS;
  assert_that (valid_ad_object_search_params (&params), is_true);
  params.object_types = AD_OBJECT_TYPE_COMPUTER;
  assert_that (valid_ad_object_search_params (&params), is_true);
  params.object_types = AD_OBJECT_TYPE_CONTAINER;
  assert_that (valid_ad_object_search_params (&params), is_true);
  params.object_types = AD_OBJECT_TYPE_OU | AD_OBJECT_TYPE_COMPUTER;
  assert_that (valid_ad_object_search_params (&params), is_true);
  params.object_types = AD_OBJECT_TYPE_GROUP;
  assert_that (valid_ad_object_search_params (&params), is_true);
  params.object_types = AD_OBJECT_TYPE_OU | AD_OBJECT_TYPE_GROUP;
  assert_that (valid_ad_object_search_params (&params), is_true);
  params.object_types = AD_OBJECT_TYPE_COMPUTER | AD_OBJECT_TYPE_GROUP;
  assert_that (valid_ad_object_search_params (&params), is_true);
  params.object_types = AD_OBJECT_TYPE_ALL;
  assert_that (valid_ad_object_search_params (&params), is_true);
  params.object_types = AD_OBJECT_TYPE_OU;
  params.scope = AD_CONNECTOR_SEARCH_SCOPE_ONELEVEL;
  assert_that (valid_ad_object_search_params (&params), is_true);
  params.scope = AD_CONNECTOR_SEARCH_SCOPE_SUBTREE;
  assert_that (valid_ad_object_search_params (&params), is_true);
  params.targets = TRUE;
  assert_that (valid_ad_object_search_params (&params), is_true);
  params.tasks = TRUE;
  assert_that (valid_ad_object_search_params (&params), is_true);
}

Ensure (manage_active_directory, search_params_reject_invalid_values)
{
  get_ad_objects_params_t params = {
    .credential_id = "credential-id",
    .scope = AD_CONNECTOR_SEARCH_SCOPE_BASE,
    .object_types = AD_OBJECT_TYPE_COMPUTER,
    .max_results = 1
  };

  assert_that (valid_ad_object_search_params (NULL), is_false);
  params.credential_id = NULL;
  assert_that (valid_ad_object_search_params (&params), is_false);
  params.credential_id = "";
  assert_that (valid_ad_object_search_params (&params), is_false);
  params.credential_id = "credential-id";

  params.max_results = 0;
  assert_that (valid_ad_object_search_params (&params), is_false);
  params.max_results = GET_AD_OBJECTS_MAX_RESULTS + 1;
  assert_that (valid_ad_object_search_params (&params), is_false);
  params.max_results = 1;

  params.scope = (ad_connector_search_scope_t) -1;
  assert_that (valid_ad_object_search_params (&params), is_false);
  params.scope = AD_CONNECTOR_SEARCH_SCOPE_BASE;

  params.object_types = 0;
  assert_that (valid_ad_object_search_params (&params), is_false);
  params.object_types = (ad_object_type_t) (AD_OBJECT_TYPE_ALL | (1 << 8));
  assert_that (valid_ad_object_search_params (&params), is_false);
  params.object_types = AD_OBJECT_TYPE_COMPUTER;

  params.tasks = TRUE;
  assert_that (valid_ad_object_search_params (&params), is_false);
}

Ensure (manage_active_directory, configure_search_accepts_valid_options)
{
  ad_search_config_t config = ad_search_config_new ();
  const gchar *credential_base_dn = "DC=example,DC=com";
  get_ad_objects_params_t params = {
    .scope = AD_CONNECTOR_SEARCH_SCOPE_ONELEVEL,
    .object_types = AD_OBJECT_TYPE_OU | AD_OBJECT_TYPE_COMPUTER,
    .max_results = GET_AD_OBJECTS_MAX_RESULTS,
    .include_disabled_computers = TRUE
  };

  assert_that (config, is_non_null);
  assert_that (configure_ad_search (config, &params, credential_base_dn),
               is_equal_to (AD_CONNECTOR_OK));
  assert_that (requested_include_disabled_computers, is_true);
  assert_that (requested_attributes, is_equal_to_string (
    "description,cn,objectcategory,ou,dnshostname,samaccountname,operatingsystem,"
    "useraccountcontrol"));

  ad_search_config_free (config);
  config = ad_search_config_new ();
  params.base_dn = "OU=hosts,DC=example,DC=com";
  params.scope = AD_CONNECTOR_SEARCH_SCOPE_SUBTREE;
  params.object_types = AD_OBJECT_TYPE_ALL;
  params.max_results = 1;
  params.include_disabled_computers = FALSE;
  assert_that (configure_ad_search (config, &params, credential_base_dn),
               is_equal_to (AD_CONNECTOR_OK));
  assert_that (requested_include_disabled_computers, is_false);
  assert_that (requested_attributes, is_equal_to_string (
    "description,cn,objectcategory,ou,dnshostname,samaccountname,operatingsystem,"
    "useraccountcontrol,displayname,"
    "grouptype"));

  ad_search_config_free (config);
  config = ad_search_config_new ();
  params.base_dn = NULL;
  params.object_types = AD_OBJECT_TYPE_GROUP;
  assert_that (configure_ad_search (config, &params, credential_base_dn),
               is_equal_to (AD_CONNECTOR_OK));
  assert_that (requested_attributes, is_equal_to_string (
    "description,cn,objectcategory,samaccountname,displayname,grouptype"));
  ad_search_config_free (config);

  config = ad_search_config_new ();
  params.object_types = AD_OBJECT_TYPE_CONTAINER;
  assert_that (configure_ad_search (config, &params, credential_base_dn),
               is_equal_to (AD_CONNECTOR_OK));
  assert_that (requested_attributes,
               is_equal_to_string ("description,cn,objectcategory"));
  ad_search_config_free (config);

  config = ad_search_config_new ();
  params.object_types = AD_OBJECT_TYPE_COMPUTER;
  params.details = TRUE;
  assert_that (configure_ad_search (config, &params, credential_base_dn),
               is_equal_to (AD_CONNECTOR_OK));
  assert_that (requested_attributes, is_equal_to_string (
    "description,cn,objectcategory,dnshostname,samaccountname,operatingsystem,"
    "useraccountcontrol,operatingsystemversion,serviceprincipalname"));
  ad_search_config_free (config);
}

Ensure (manage_active_directory,
        configure_search_accepts_group_within_credential_base)
{
  ad_search_config_t config = ad_search_config_new ();
  get_ad_objects_params_t params = {
    .base_dn = "OU=Computers,DC=example,DC=com",
    .group_dn = "CN=Servers,OU=Groups,DC=example,DC=com",
    .scope = AD_CONNECTOR_SEARCH_SCOPE_SUBTREE,
    .object_types = AD_OBJECT_TYPE_COMPUTER,
    .max_results = 100
  };

  assert_that (configure_ad_search (config, &params,
                                    "DC=example,DC=com"),
               is_equal_to (AD_CONNECTOR_OK));

  ad_search_config_free (config);
}

Ensure (manage_active_directory,
        configure_search_rejects_group_outside_credential_base)
{
  ad_search_config_t config = ad_search_config_new ();
  get_ad_objects_params_t params = {
    .group_dn = "CN=Servers,DC=other,DC=com",
    .scope = AD_CONNECTOR_SEARCH_SCOPE_SUBTREE,
    .object_types = AD_OBJECT_TYPE_COMPUTER,
    .max_results = 100
  };

  assert_that (configure_ad_search (config, &params,
                                    "DC=example,DC=com"),
               is_equal_to (AD_CONNECTOR_INVALID_VALUE));

  ad_search_config_free (config);
}

Ensure (manage_active_directory, configure_search_propagates_invalid_values)
{
  ad_search_config_t config = ad_search_config_new ();
  const gchar *credential_base_dn = "DC=example,DC=com";
  get_ad_objects_params_t params = {
    .scope = AD_CONNECTOR_SEARCH_SCOPE_BASE,
    .object_types = AD_OBJECT_TYPE_COMPUTER,
    .max_results = 10
  };
  assert_that (configure_ad_search (NULL, &params, credential_base_dn),
               is_equal_to (AD_CONNECTOR_INVALID_VALUE));
  assert_that (configure_ad_search (config, NULL, credential_base_dn),
               is_equal_to (AD_CONNECTOR_INVALID_VALUE));
  assert_that (configure_ad_search (config, &params, NULL),
               is_equal_to (AD_CONNECTOR_INVALID_VALUE));

  params.scope = (ad_connector_search_scope_t) -1;
  assert_that (configure_ad_search (config, &params, credential_base_dn),
               is_equal_to (AD_CONNECTOR_INVALID_VALUE));

  ad_search_config_free (config);
  config = ad_search_config_new ();
  params.scope = AD_CONNECTOR_SEARCH_SCOPE_BASE;
  params.object_types = 0;
  assert_that (configure_ad_search (config, &params, credential_base_dn),
               is_equal_to (AD_CONNECTOR_INVALID_VALUE));

  ad_search_config_free (config);
  config = ad_search_config_new ();
  params.object_types = AD_OBJECT_TYPE_COMPUTER;
  params.group_dn = "not-a-dn";
  assert_that (configure_ad_search (config, &params, credential_base_dn),
               is_equal_to (AD_CONNECTOR_INVALID_VALUE));
  ad_search_config_free (config);
}

Ensure (manage_active_directory, load_reads_owned_credential_fields)
{
  ad_credential_data_t data = { 0 };

  saved_ca_certificate = "certificate";
  assert_that (load_ad_credential ("credential-id", &data),
               is_equal_to (AD_CREDENTIAL_LOAD_OK));
  assert_that (data.host, is_equal_to_string (saved_host));
  assert_that (data.port, is_equal_to_string (saved_port));
  assert_that (data.bind_dn, is_equal_to_string (saved_bind_dn));
  assert_that (data.bind_password, is_equal_to_string (saved_bind_password));
  assert_that (data.base_dn, is_equal_to_string (saved_base_dn));
  assert_that (data.tls_mode, is_equal_to_string (saved_tls_mode));
  assert_that (data.ca_certificate,
               is_equal_to_string (saved_ca_certificate));
  ad_credential_data_reset (&data);
}

Ensure (manage_active_directory, load_leaves_field_validation_to_caller)
{
  ad_credential_data_t data = { 0 };

  saved_bind_password = NULL;
  assert_that (load_ad_credential ("credential-id", &data),
               is_equal_to (AD_CREDENTIAL_LOAD_OK));
  assert_that (data.bind_password, is_null);
  assert_that (data.ca_certificate, is_null);
  assert_that (data.host, is_equal_to_string (saved_host));
  ad_credential_data_reset (&data);
}

Ensure (manage_active_directory, load_reports_lookup_and_type_failures)
{
  ad_credential_data_t data = { 0 };

  credential_lookup_failed = TRUE;
  assert_that (load_ad_credential ("credential-id", &data),
               is_equal_to (AD_CREDENTIAL_LOAD_INTERNAL_ERROR));

  credential_lookup_failed = FALSE;
  saved_credential = 0;
  assert_that (load_ad_credential ("credential-id", &data),
               is_equal_to (AD_CREDENTIAL_LOAD_NOT_FOUND));

  saved_credential = 42;
  saved_credential_type = NULL;
  assert_that (load_ad_credential ("credential-id", &data),
               is_equal_to (AD_CREDENTIAL_LOAD_INTERNAL_ERROR));

  saved_credential_type = "up";
  assert_that (load_ad_credential ("credential-id", &data),
               is_equal_to (AD_CREDENTIAL_LOAD_INVALID_TYPE));
  assert_that (data.host, is_null);
  assert_that (data.bind_password, is_null);
  ad_credential_data_reset (&data);
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
  assert_that (builder_options[2],
               is_equal_to (builder_failure_option));
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
  assert_no_ad_connector_calls ();
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
  assert_no_ad_connector_calls ();
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

static void
assert_disabled_account_control (const gchar *value, gboolean disabled)
{
  ad_object_t *source = new_test_object (AD_OBJECT_TYPE_COMPUTER);
  ad_directory_object_t *object;

  if (value)
    add_object_attribute (source, "userAccountControl", value, NULL);
  object = ad_directory_object_from_search_object (source);
  assert_that (ad_directory_object_is_disabled (object), is_equal_to (disabled));
  ad_directory_object_free (object);
}

Ensure (manage_active_directory, account_control_detects_disabled_accounts)
{
  assert_disabled_account_control (NULL, FALSE);
  assert_disabled_account_control ("", FALSE);
  assert_disabled_account_control ("512", FALSE);
  assert_disabled_account_control ("514", TRUE);
  assert_disabled_account_control ("000514", TRUE);
  assert_disabled_account_control ("4294967295", TRUE);
  assert_disabled_account_control ("+514", FALSE);
  assert_disabled_account_control (" 514", FALSE);
  assert_disabled_account_control ("514x", FALSE);
  assert_disabled_account_control ("4294967296", FALSE);
}

static void
assert_account_control_case (get_ad_objects_params_t *params,
                             const gchar *account_control,
                             guint disabled)
{
  get_ad_objects_result_t result = { 0 };

  search_account_control = account_control;
  reset_connector_observations ();
  assert_that (get_active_directory_objects (params, &result),
               is_equal_to (GET_AD_OBJECTS_OK));
  assert_that (result.counts.computer_total, is_equal_to (1));
  assert_that (result.counts.computer_disabled, is_equal_to (disabled));
  assert_that (result.objects->len, is_equal_to (1));
  assert_that (ad_directory_object_is_disabled (
                 g_ptr_array_index (result.objects, 0)),
               is_equal_to (disabled));
  get_ad_objects_result_reset (&result);
}

Ensure (manage_active_directory, search_retains_and_counts_disabled_accounts)
{
  get_ad_objects_params_t params = {
    .credential_id = "credential-id",
    .scope = AD_CONNECTOR_SEARCH_SCOPE_ONELEVEL,
    .object_types = AD_OBJECT_TYPE_COMPUTER,
    .max_results = 1,
    .include_disabled_computers = TRUE
  };

  expected_permission = "get_active_directory_objects";
  search_object_type = AD_OBJECT_TYPE_COMPUTER;
  assert_account_control_case (&params, "512", 0);
  assert_account_control_case (&params, "514", 1);
}

static void
set_task_details_rows (const task_details_row_t *rows, guint count)
{
  task_details_rows = rows;
  task_details_count = count;
}

static void
assert_task_match (const ad_task_match_t *match, const gchar *config_uuid)
{
  assert_that (match->resource.uuid, is_equal_to_string ("task-id"));
  assert_that (match->resource.name, is_equal_to_string ("Task name"));
  if (!config_uuid)
    {
      assert_that (match->config, is_null);
      return;
    }
  assert_that (match->config, is_non_null);
  assert_that (match->config->uuid, is_equal_to_string (config_uuid));
  assert_that (match->config->name, is_equal_to_string ("Configuration name"));
}

Ensure (manage_active_directory, target_tasks_preserve_resource_permissions)
{
  const task_details_row_t rows[] = {
    { .readable = FALSE },
    { .readable = TRUE, .target_trashed = TRUE },
    { .readable = TRUE, .config_trashed = TRUE },
    { .readable = TRUE, .config_uuid = "config-id" },
    { .readable = TRUE },
    { .readable = TRUE, .config_uuid = "config-id",
      .config_readable = TRUE }
  };
  GPtrArray *matches = NULL;

  expected_permission = "get_configs";
  set_task_details_rows (rows, G_N_ELEMENTS (rows));
  assert_that (load_ad_target_tasks (TEST_TARGET, &matches),
               is_equal_to (GET_AD_OBJECTS_OK));
  assert_that (matches->len, is_equal_to (4));
  /* Trashed, unreadable and missing configurations are omitted. */
  assert_task_match (g_ptr_array_index (matches, 0), NULL);
  assert_task_match (g_ptr_array_index (matches, 1), NULL);
  assert_task_match (g_ptr_array_index (matches, 2), NULL);
  assert_task_match (g_ptr_array_index (matches, 3), "config-id");
  assert_that (config_permission_checks, is_equal_to (2));
  assert_that (config_command_checks, is_equal_to (1));
  assert_that (task_iterator_cleanups, is_equal_to (1));
  g_ptr_array_unref (matches);
}

Ensure (manage_active_directory, target_tasks_respect_config_command_permission)
{
  const task_details_row_t rows[] = {
    { .readable = TRUE, .config_uuid = "config-id",
      .config_readable = TRUE },
    { .readable = TRUE, .config_uuid = "config-id",
      .config_readable = TRUE }
  };
  GPtrArray *matches = NULL;

  expected_permission = "get_configs";
  permission_allowed = FALSE;
  set_task_details_rows (rows, G_N_ELEMENTS (rows));
  assert_that (load_ad_target_tasks (TEST_TARGET, &matches),
               is_equal_to (GET_AD_OBJECTS_OK));
  assert_that (matches->len, is_equal_to (2));
  assert_task_match (g_ptr_array_index (matches, 0), NULL);
  assert_task_match (g_ptr_array_index (matches, 1), NULL);
  assert_that (config_permission_checks, is_equal_to (0));
  assert_that (config_command_checks, is_equal_to (1));
  assert_that (task_iterator_cleanups, is_equal_to (1));
  g_ptr_array_unref (matches);
}

static void
assert_target_tasks_error (const task_details_row_t *row,
                           guint config_checks)
{
  GPtrArray *matches = NULL;

  reset_connector_observations ();
  set_task_details_rows (row, 1);
  assert_that (load_ad_target_tasks (TEST_TARGET, &matches),
               is_equal_to (GET_AD_OBJECTS_INTERNAL_ERROR));
  assert_that (matches, is_null);
  assert_that (config_permission_checks, is_equal_to (config_checks));
  assert_that (task_iterator_cleanups, is_equal_to (1));
}

Ensure (manage_active_directory, target_tasks_report_lookup_errors)
{
  task_details_row_t row = {
    .readable = TRUE,
    .config_uuid = "config-id",
    .config_readable = TRUE
  };

  expected_permission = "get_configs";
  row.config_error = TRUE;
  assert_target_tasks_error (&row, 1);
}

Ensure (manage_active_directory, hostname_normalization_accepts_only_names)
{
  gchar *hostname = normalize_ad_hostname (" HOST.Example.COM. ");

  assert_that (hostname, is_equal_to_string ("host.example.com"));
  g_free (hostname);
  assert_that (normalize_ad_hostname (NULL), is_null);
  assert_that (normalize_ad_hostname (""), is_null);
  assert_that (normalize_ad_hostname ("host.."), is_null);
  assert_that (normalize_ad_hostname ("192.0.2.1"), is_null);
  assert_that (normalize_ad_hostname ("::1"), is_null);
}

Ensure (manage_active_directory, hosts_string_normalization_keeps_other_hosts)
{
  gchar *hosts = normalize_ad_hosts_string (
    "Host.Example.COM.,192.0.2.001\n192.0.2.1-5");

  assert_that (hosts,
               is_equal_to_string ("host.example.com, 192.0.2.1, 192.0.2.1-5"));
  g_free (hosts);
}

static ad_directory_object_t *
new_enrichment_computer (const gchar *hostname)
{
  ad_object_t *source = new_test_object (AD_OBJECT_TYPE_COMPUTER);

  add_object_attribute (source, "dNSHostName", hostname, NULL);
  return ad_directory_object_from_search_object (source);
}

static GPtrArray *
new_enrichment_objects (const gchar *first, const gchar *second)
{
  GPtrArray *objects = g_ptr_array_new_with_free_func (
    (GDestroyNotify) ad_directory_object_free);

  g_ptr_array_add (objects, new_enrichment_computer (first));
  if (second)
    g_ptr_array_add (objects, new_enrichment_computer (second));
  return objects;
}

static void
set_enrichment_target (const gchar *hosts, const gchar *exclusions)
{
  enrichment_permissions = TRUE;
  target_candidate_hosts = hosts;
  target_candidate_exclusions = exclusions;
  target_candidate_readable = TRUE;
}

Ensure (manage_active_directory, enrichment_matches_exact_hostname)
{
  GPtrArray *objects = new_enrichment_objects (" HOST.EXAMPLE.COM. ", NULL);
  ad_directory_object_t *computer = g_ptr_array_index (objects, 0);
  ad_target_match_t *target;

  set_enrichment_target ("host.example.com.,other.example.com", "");
  assert_that (match_ad_objects_to_targets (objects, TRUE),
               is_equal_to (GET_AD_OBJECTS_OK));
  assert_that (computer->target_matches, is_non_null);
  assert_that (computer->target_matches->len, is_equal_to (1));
  target = g_ptr_array_index (computer->target_matches, 0);
  assert_that (target->resource.uuid, is_equal_to_string ("target-id"));
  assert_that (target->resource.name, is_equal_to_string ("Target name"));
  assert_that (target->tasks, is_non_null);
  assert_that (target->tasks->len, is_equal_to (0));
  g_ptr_array_unref (objects);
}

static void
assert_no_target_match (const gchar *hosts, const gchar *exclusions,
                        gboolean readable)
{
  GPtrArray *objects = new_enrichment_objects ("host.example.com", NULL);
  ad_directory_object_t *computer = g_ptr_array_index (objects, 0);

  reset_connector_observations ();
  set_enrichment_target (hosts, exclusions);
  target_candidate_readable = readable;
  assert_that (match_ad_objects_to_targets (objects, TRUE),
               is_equal_to (GET_AD_OBJECTS_OK));
  assert_that (computer->target_matches, is_non_null);
  assert_that (computer->target_matches->len, is_equal_to (0));
  assert_that (task_iterator_cleanups, is_equal_to (0));
  g_ptr_array_unref (objects);
}

Ensure (manage_active_directory, enrichment_skips_non_matching_targets)
{
  assert_no_target_match ("prefixhost.example.com,host.example.com.other", "",
                          TRUE);
  assert_no_target_match ("host.example.com,other.example.com",
                          "host.example.com", TRUE);
  assert_no_target_match ("host.example.com", "host.example.com.", TRUE);
  assert_no_target_match ("host.example.com", "", FALSE);
}

Ensure (manage_active_directory, enrichment_matches_computers_sharing_hostname)
{
  const task_details_row_t row = {
    .readable = TRUE, .config_uuid = "config-id",
    .config_readable = TRUE
  };
  GPtrArray *objects =
    new_enrichment_objects ("host.example.com", "HOST.EXAMPLE.COM");
  ad_directory_object_t *first = g_ptr_array_index (objects, 0);
  ad_directory_object_t *second = g_ptr_array_index (objects, 1);
  ad_target_match_t *target;

  set_enrichment_target ("host.example.com", "");
  set_task_details_rows (&row, 1);
  assert_that (match_ad_objects_to_targets (objects, TRUE),
               is_equal_to (GET_AD_OBJECTS_OK));

  assert_that (first->target_matches->len, is_equal_to (1));
  target = g_ptr_array_index (first->target_matches, 0);
  assert_that (target->resource.uuid, is_equal_to_string ("target-id"));
  assert_that (target->tasks->len, is_equal_to (1));
  assert_task_match (g_ptr_array_index (target->tasks, 0), "config-id");

  assert_that (second->target_matches->len, is_equal_to (1));
  target = g_ptr_array_index (second->target_matches, 0);
  assert_that (target->resource.uuid, is_equal_to_string ("target-id"));
  assert_that (target->tasks->len, is_equal_to (1));
  assert_task_match (g_ptr_array_index (target->tasks, 0), "config-id");

  assert_that (task_iterator_cleanups, is_equal_to (1));
  g_ptr_array_unref (objects);
}

Ensure (manage_active_directory, search_enriches_targets_and_readable_tasks)
{
  get_ad_objects_params_t params = {
    .credential_id = "credential-id",
    .scope = AD_CONNECTOR_SEARCH_SCOPE_SUBTREE,
    .object_types = AD_OBJECT_TYPE_COMPUTER,
    .max_results = 1,
    .targets = TRUE,
    .tasks = TRUE
  };
  const task_details_row_t rows[] = {
    { .readable = FALSE },
    { .readable = TRUE, .config_uuid = "config-id" },
    { .readable = TRUE, .config_uuid = "config-id",
      .config_readable = TRUE }
  };
  get_ad_objects_result_t result = { 0 };
  ad_directory_object_t *computer;
  ad_target_match_t *target;

  set_enrichment_target ("host.example.com", "");
  set_task_details_rows (rows, G_N_ELEMENTS (rows));
  search_object_type = AD_OBJECT_TYPE_COMPUTER;
  search_hostname = "HOST.EXAMPLE.COM";
  assert_that (get_active_directory_objects (&params, &result),
               is_equal_to (GET_AD_OBJECTS_OK));
  assert_that (result.objects, is_non_null);
  assert_that (result.objects->len, is_equal_to (1));
  computer = g_ptr_array_index (result.objects, 0);
  assert_that (computer->target_matches, is_non_null);
  assert_that (computer->target_matches->len, is_equal_to (1));
  target = g_ptr_array_index (computer->target_matches, 0);
  assert_that (target->resource.uuid, is_equal_to_string ("target-id"));
  assert_that (target->tasks, is_non_null);
  assert_that (target->tasks->len, is_equal_to (2));
  assert_task_match (g_ptr_array_index (target->tasks, 0), NULL);
  assert_task_match (g_ptr_array_index (target->tasks, 1), "config-id");
  assert_that (config_permission_checks, is_equal_to (2));
  get_ad_objects_result_reset (&result);
}

Ensure (manage_active_directory,
        loader_defaults_for_missing_timeout_configuration)
{
  /* Exercise the NULL configuration path. */
  g_clear_pointer (&test_config, g_key_file_unref);
  load_active_directory_config ();
  assert_that (ad_network_timeout_seconds, is_equal_to (10));
  assert_that (ad_operation_timeout_seconds, is_equal_to (30));

  set_test_ad_config ("[unrelated]\nvalue = 1\n");
  load_active_directory_config ();
  assert_that (ad_network_timeout_seconds, is_equal_to (10));
  assert_that (ad_operation_timeout_seconds, is_equal_to (30));

  set_test_ad_config ("[active_directory]\nother = value\n");
  load_active_directory_config ();
  assert_that (ad_network_timeout_seconds, is_equal_to (10));
  assert_that (ad_operation_timeout_seconds, is_equal_to (30));
  assert_that (timeout_warning_count, is_equal_to (0));
}

Ensure (manage_active_directory, loader_resolves_timeouts_independently)
{
  set_test_ad_config ("[active_directory]\nnetwork_timeout_seconds = 12\n"
                      "operation_timeout_seconds = 34\n");
  load_active_directory_config ();
  assert_that (ad_network_timeout_seconds, is_equal_to (12));
  assert_that (ad_operation_timeout_seconds, is_equal_to (34));

  g_setenv ("GVMD_AD_NETWORK_TIMEOUT_SECONDS", "60", TRUE);
  load_active_directory_config ();
  assert_that (ad_network_timeout_seconds, is_equal_to (60));
  assert_that (ad_operation_timeout_seconds, is_equal_to (34));

  g_unsetenv ("GVMD_AD_NETWORK_TIMEOUT_SECONDS");
  g_setenv ("GVMD_AD_OPERATION_TIMEOUT_SECONDS", "180", TRUE);
  load_active_directory_config ();
  assert_that (ad_network_timeout_seconds, is_equal_to (12));
  assert_that (ad_operation_timeout_seconds, is_equal_to (180));

  g_clear_pointer (&test_config, g_key_file_unref);
  g_setenv ("GVMD_AD_NETWORK_TIMEOUT_SECONDS", "60", TRUE);
  load_active_directory_config ();
  assert_that (ad_network_timeout_seconds, is_equal_to (60));
  assert_that (ad_operation_timeout_seconds, is_equal_to (180));
  assert_that (timeout_warning_count, is_equal_to (0));
}

Ensure (manage_active_directory, loader_invalid_timeouts_use_defaults)
{
  const gchar *invalid[] = {
    "", "0", "-1", "+1", "1second", "1.5", "999999999999999999999999999999"};

  for (guint i = 0; i < G_N_ELEMENTS (invalid); i++)
    {
      guint warnings;

      set_test_ad_config ("[active_directory]\n");
      g_key_file_set_value (test_config, "active_directory",
                            "network_timeout_seconds", invalid[i]);
      g_key_file_set_value (test_config, "active_directory",
                            "operation_timeout_seconds", invalid[i]);
      warnings = timeout_warning_count;
      load_active_directory_config ();
      assert_that (ad_network_timeout_seconds, is_equal_to (10));
      assert_that (ad_operation_timeout_seconds, is_equal_to (30));
      assert_that (timeout_warning_count, is_equal_to (warnings + 2));

      set_test_ad_config ("[active_directory]\nnetwork_timeout_seconds = 12\n"
                          "operation_timeout_seconds = 34\n");
      g_setenv ("GVMD_AD_NETWORK_TIMEOUT_SECONDS", invalid[i], TRUE);
      g_setenv ("GVMD_AD_OPERATION_TIMEOUT_SECONDS", invalid[i], TRUE);
      warnings = timeout_warning_count;
      load_active_directory_config ();
      assert_that (ad_network_timeout_seconds, is_equal_to (10));
      assert_that (ad_operation_timeout_seconds, is_equal_to (30));
      assert_that (timeout_warning_count, is_equal_to (warnings + 2));
      g_unsetenv ("GVMD_AD_NETWORK_TIMEOUT_SECONDS");
      g_unsetenv ("GVMD_AD_OPERATION_TIMEOUT_SECONDS");
    }
  assert_that (policy_warning_count, is_equal_to (0));
}

Ensure (manage_active_directory, loader_checks_timeout_boundaries)
{
  guint warnings = timeout_warning_count;

  set_test_ad_config ("[active_directory]\nnetwork_timeout_seconds = 1\n"
                      "operation_timeout_seconds = 1\n");
  load_active_directory_config ();
  assert_that (ad_network_timeout_seconds, is_equal_to (1));
  assert_that (ad_operation_timeout_seconds, is_equal_to (1));
  assert_that (timeout_warning_count, is_equal_to (warnings));

  set_test_ad_config ("[active_directory]\nnetwork_timeout_seconds = 120\n"
                      "operation_timeout_seconds = 300\n");
  load_active_directory_config ();
  assert_that (ad_network_timeout_seconds, is_equal_to (120));
  assert_that (ad_operation_timeout_seconds, is_equal_to (300));
  assert_that (timeout_warning_count, is_equal_to (warnings));

  set_test_ad_config ("[active_directory]\nnetwork_timeout_seconds = 121\n"
                      "operation_timeout_seconds = 301\n");
  warnings = timeout_warning_count;
  load_active_directory_config ();
  assert_that (ad_network_timeout_seconds, is_equal_to (10));
  assert_that (ad_operation_timeout_seconds, is_equal_to (30));
  assert_that (timeout_warning_count, is_equal_to (warnings + 2));
}

Ensure (manage_active_directory,
        loader_unreadable_timeouts_warn_and_use_defaults)
{
  guint warnings = timeout_warning_count;

  set_test_ad_config ("[active_directory]\nnetwork_timeout_seconds = \\q\n"
                      "operation_timeout_seconds = 34\n");
  load_active_directory_config ();
  assert_that (ad_network_timeout_seconds, is_equal_to (10));
  assert_that (ad_operation_timeout_seconds, is_equal_to (34));
  assert_that (timeout_warning_count, is_equal_to (warnings + 1));
  assert_that (strstr (last_timeout_warning,
                        "active_directory.network_timeout_seconds"),
               is_non_null);
  assert_that (strstr (last_timeout_warning, "could not read"), is_non_null);

  warnings = timeout_warning_count;
  set_test_ad_config ("[active_directory]\nnetwork_timeout_seconds = 12\n"
                      "operation_timeout_seconds = \\q\n");
  load_active_directory_config ();
  assert_that (ad_network_timeout_seconds, is_equal_to (12));
  assert_that (ad_operation_timeout_seconds, is_equal_to (30));
  assert_that (timeout_warning_count, is_equal_to (warnings + 1));
  assert_that (strstr (last_timeout_warning,
                        "active_directory.operation_timeout_seconds"),
               is_non_null);
  assert_that (strstr (last_timeout_warning, "could not read"), is_non_null);

  set_test_ad_config ("[active_directory]\nnetwork_timeout_seconds = \\q\n"
                      "operation_timeout_seconds = \\q\n");
  g_setenv ("GVMD_AD_NETWORK_TIMEOUT_SECONDS", "12", TRUE);
  g_setenv ("GVMD_AD_OPERATION_TIMEOUT_SECONDS", "34", TRUE);
  warnings = timeout_warning_count;
  load_active_directory_config ();
  assert_that (ad_network_timeout_seconds, is_equal_to (12));
  assert_that (ad_operation_timeout_seconds, is_equal_to (34));
  assert_that (timeout_warning_count, is_equal_to (warnings));
  assert_that (policy_warning_count, is_equal_to (0));
}

Ensure (manage_active_directory, configured_timeouts_are_applied)
{
  ad_credential_data_t data = valid_ad_data ();
  get_ad_objects_params_t params = {.credential_id = "credential-id",
                                    .scope = AD_CONNECTOR_SEARCH_SCOPE_ONELEVEL,
                                    .object_types = AD_OBJECT_TYPE_OU,
                                    .max_results =
                                      GET_AD_OBJECTS_DEFAULT_MAX_RESULTS};
  get_ad_objects_result_t result = {0};

  set_test_ad_config ("[active_directory]\nnetwork_timeout_seconds = 12\n"
                      "operation_timeout_seconds = 34\n");
  load_active_directory_config ();
  assert_that (verify_active_directory_credential (NULL, &data),
               is_equal_to (VERIFY_AD_CREDENTIAL_OK));
  assert_that (builder_network_timeout, is_equal_to (12));
  assert_that (builder_operation_timeout, is_equal_to (34));

  reset_test_state ();
  expected_permission = "get_active_directory_objects";
  assert_that (get_active_directory_objects (&params, &result),
               is_equal_to (GET_AD_OBJECTS_OK));
  assert_that (builder_network_timeout, is_equal_to (12));
  assert_that (builder_operation_timeout, is_equal_to (34));
  get_ad_objects_result_reset (&result);
}

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, manage_active_directory,
                         search_enforces_feature_and_permission);

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
                         account_control_detects_disabled_accounts);
  add_test_with_context (suite, manage_active_directory,
                         search_retains_and_counts_disabled_accounts);
  add_test_with_context (suite, manage_active_directory,
                         target_tasks_preserve_resource_permissions);
  add_test_with_context (suite, manage_active_directory,
                         target_tasks_respect_config_command_permission);
  add_test_with_context (suite, manage_active_directory,
                         target_tasks_report_lookup_errors);
  add_test_with_context (suite, manage_active_directory,
                         hostname_normalization_accepts_only_names);
  add_test_with_context (suite, manage_active_directory,
                         hosts_string_normalization_keeps_other_hosts);
  add_test_with_context (suite, manage_active_directory,
                         enrichment_matches_exact_hostname);
  add_test_with_context (suite, manage_active_directory,
                         enrichment_skips_non_matching_targets);
  add_test_with_context (suite, manage_active_directory,
                         enrichment_matches_computers_sharing_hostname);
  add_test_with_context (suite, manage_active_directory,
                         search_enriches_targets_and_readable_tasks);
  add_test_with_context (suite, manage_active_directory,
                         object_map_owns_all_selected_values);
  add_test_with_context (suite, manage_active_directory,
                         object_map_selects_actual_object_type);
  add_test_with_context (suite, manage_active_directory,
                         collection_counts_non_computer_types);
  add_test_with_context (suite, manage_active_directory,
                         collection_accepts_large_attributes);
  add_test_with_context (suite, manage_active_directory,
                         collection_frees_rejected_objects);
  add_test_with_context (suite, manage_active_directory,
                         search_transfers_owned_collection);
  add_test_with_context (suite, manage_active_directory,
                         search_discards_partial_collection_on_failure);
  add_test_with_context (suite, manage_active_directory,
                         search_maps_connection_failures_to_generic_error);
  add_test_with_context (suite, manage_active_directory,
                         search_checks_allowed_destination_and_port);
  add_test_with_context (suite, manage_active_directory,
                         search_rejects_disallowed_destination);
  add_test_with_context (suite, manage_active_directory,
                         search_rejects_disallowed_default_ports);
  add_test_with_context (suite, manage_active_directory,
                         search_rejects_failed_or_uninitialized_policy);
  add_test_with_context (suite, manage_active_directory,
                         search_validates_stored_fields_before_policy);
  add_test_with_context (suite, manage_active_directory,
                         search_accepts_base_within_credential);
  add_test_with_context (suite, manage_active_directory,
                         search_rejects_base_outside_credential);
  add_test_with_context (suite, manage_active_directory,
                         search_rejects_invalid_stored_base);
  add_test_with_context (suite, manage_active_directory,
                         search_params_accept_valid_boundaries);
  add_test_with_context (suite, manage_active_directory,
                         search_params_reject_invalid_values);
  add_test_with_context (suite, manage_active_directory,
                         configure_search_accepts_valid_options);
  add_test_with_context (
    suite, manage_active_directory,
    configure_search_accepts_group_within_credential_base);
  add_test_with_context (
    suite, manage_active_directory,
    configure_search_rejects_group_outside_credential_base);
  add_test_with_context (suite, manage_active_directory,
                         configure_search_propagates_invalid_values);
  add_test_with_context (suite, manage_active_directory,
                         load_reads_owned_credential_fields);
  add_test_with_context (suite, manage_active_directory,
                         load_leaves_field_validation_to_caller);
  add_test_with_context (suite, manage_active_directory,
                         load_reports_lookup_and_type_failures);
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

  add_test_with_context (suite, manage_active_directory,
                         loader_defaults_for_missing_timeout_configuration);
  add_test_with_context (suite, manage_active_directory,
                         loader_resolves_timeouts_independently);
  add_test_with_context (suite, manage_active_directory,
                         loader_invalid_timeouts_use_defaults);
  add_test_with_context (suite, manage_active_directory,
                         loader_checks_timeout_boundaries);
  add_test_with_context (suite, manage_active_directory,
                         loader_unreadable_timeouts_warn_and_use_defaults);
  add_test_with_context (suite, manage_active_directory,
                         configured_timeouts_are_applied);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}

#endif /* ENABLE_AD_INTEGRATION */
