/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>

#if ENABLE_AD_INTEGRATION

#include "manage_active_directory.c"

static int feature_is_enabled;
static const gchar *expected_permission;
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
static guint collected_objects_freed;
static gchar *connected_password;
static gchar *requested_attributes;
static gboolean requested_include_disabled_computers;

static int builder_calls;
static ad_connector_opt_t builder_last_option;
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
               is_equal_to_string (expected_permission));
  return TRUE;
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
  builder_calls++;
  builder_last_option = option;

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

static void
count_collected_object_free (gpointer object)
{
  collected_objects_freed++;
  ad_directory_object_free (object);
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

  if (search_account_control)
    {
      GPtrArray *values = g_ptr_array_new_with_free_func (g_free);

      object->attributes = g_hash_table_new_full (
        g_str_hash, g_str_equal, g_free, (GDestroyNotify) g_ptr_array_unref);
      g_ptr_array_add (values, g_strdup (search_account_control));
      g_hash_table_insert (object->attributes,
                           g_strdup ("useraccountcontrol"), values);
    }

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
  collected_objects_freed = 0;
  g_clear_pointer (&connected_password, g_free);
  g_clear_pointer (&requested_attributes, g_free);

  builder_calls = 0;
  builder_last_option = (ad_connector_opt_t) -1;
  builder_host = NULL;
  builder_bind_dn = NULL;
  builder_ca_certificate = NULL;
  builder_port = -1;
  builder_network_timeout = -1;
  builder_operation_timeout = -1;
  builder_tls_mode = (ad_connector_tls_mode_t) -1;
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
  g_clear_pointer (&requested_attributes, g_free);
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

/* Test suite. */

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

  builder_calls = 0;
  assert_that (get_active_directory_objects (params, &result),
               is_equal_to (GET_AD_OBJECTS_OK));
  get_ad_objects_result_reset (&result);
}

static void
assert_search_rejects_invalid_input (get_ad_objects_params_t *params)
{
  get_ad_objects_result_t result = { 0 };

  builder_calls = 0;
  assert_that (get_active_directory_objects (params, &result),
               is_equal_to (GET_AD_OBJECTS_INVALID_INPUT));
  assert_that (result.objects, is_null);
  assert_that (connected_password, is_null);
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

  saved_base_dn = NULL;
  params.base_dn = NULL;
  assert_search_rejects_invalid_input (&params);
  params.base_dn = "OU=Child,DC=example,DC=com";
  assert_search_rejects_invalid_input (&params);

  saved_base_dn = "";
  params.base_dn = NULL;
  assert_search_rejects_invalid_input (&params);
  params.base_dn = "OU=Child,DC=example,DC=com";
  assert_search_rejects_invalid_input (&params);

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
  assert_that (builder_calls, is_greater_than (0));
  assert_that (builder_last_option,
               is_equal_to (builder_failure_option));
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
  builder_calls = 0;
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

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, manage_active_directory,
                         account_control_detects_disabled_accounts);
  add_test_with_context (suite, manage_active_directory,
                         search_retains_and_counts_disabled_accounts);
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

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}

#endif /* ENABLE_AD_INTEGRATION */
