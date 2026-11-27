/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "gmp.c"

#include <cgreen/cgreen.h>
#include <glib/gstdio.h>
#include <unistd.h>

Describe (gmp);

static const gchar *report_export_uuid = "a3d1e516-d3e7-4f2a-b45f-b7be6f4b2f71";
static const gchar *report_uuid_value = "13a70b2e-c4d4-43ae-9492-6d2a09d1f2ca";
static const gchar *report_format_uuid_value =
  "5057e5cc-b825-11e4-9d0e-28d24461215b";
static const guchar report_export_contents[] = {
  0x00, 0x01, 0x02, 0x7f, 0x80, 0xff, '<', '&', '>', '\n', 0x00};

static GString *captured_output;
static gchar *report_export_path;
static int report_export_delete_count;
static int mock_missing_report_export;
static gboolean mock_ad_response;
static credential_return_t mock_credential_result;
static int credential_command_calls;
static int credential_failure_logs;
#if ENABLE_AD_INTEGRATION
static verify_ad_return_t mock_verify_result;
static get_ad_objects_return_t mock_search_result;
static guint search_command_calls;
static guint mock_ad_max_results_limit;
static const get_ad_objects_params_t *expected_search_params;
static ad_directory_object_t *mock_search_object;
static const gchar *expected_ad_host;
static const gchar *expected_ad_port;
static gboolean expected_stored_ad;
#endif

BeforeEach (gmp)
{
  captured_output = g_string_new ("");
  report_export_path = NULL;
  report_export_delete_count = 0;
  mock_missing_report_export = 0;
  mock_ad_response = FALSE;
  mock_credential_result = CREDENTIAL_OK;
  credential_command_calls = 0;
  credential_failure_logs = 0;
#if ENABLE_AD_INTEGRATION
  mock_search_result = GET_AD_OBJECTS_OK;
  mock_verify_result = VERIFY_AD_CREDENTIAL_OK;
  search_command_calls = 0;
  mock_ad_max_results_limit = AD_MAX_RESULTS_LIMIT_DEFAULT;
  expected_ad_host = NULL;
  expected_ad_port = NULL;
  expected_stored_ad = FALSE;
  mock_search_object = NULL;
  expected_search_params = NULL;
#endif
}

AfterEach (gmp)
{
#if ENABLE_AD_INTEGRATION
  ad_directory_object_free (mock_search_object);
#endif
  if (report_export_path)
    g_unlink (report_export_path);
  g_free (report_export_path);
  g_string_free (captured_output, TRUE);
}

static int
dummy_client_writer (const char *message, void *data)
{
  return 0;
}

static int
string_client_writer (const char *message, void *data)
{
  g_string_append (data, message);
  return 0;
}

static int
capture_client_writer (const char *message, void *data)
{
  (void) data;
  g_string_append (captured_output, message);
  return 0;
}

credential_return_t __real_create_credential (const credential_data_t *,
                                             credential_t *);
credential_return_t __real_modify_credential (const credential_data_t *);
void __real_log_event_fail (const char *, const char *, const char *,
                            const char *);

#if ENABLE_AD_INTEGRATION
/**
 * @brief Assert that the real GMP parser preserves the response fixture fields.
 *
 * @param[in] ad  Borrowed parsed connection data, owned by the command handler.
 *
 * @return Nothing. Field mismatches are reported as failed test assertions.
 */
static void
assert_ad_response_data (const ad_credential_data_t *ad)
{
  if (expected_ad_host)
    assert_that (ad->host, is_equal_to_string (expected_ad_host));
  else
    assert_that (ad->host, is_null);
  if (expected_ad_port)
    assert_that (ad->port, is_equal_to_string (expected_ad_port));
  else
    assert_that (ad->port, is_null);
  if (expected_stored_ad)
    assert_that (ad->bind_password, is_null);
  else
    {
      assert_that (ad->tls_mode, is_equal_to_string ("starttls"));
      assert_that (ad->bind_password, is_equal_to_string ("test-secret"));
    }
}
#endif

credential_return_t
__wrap_create_credential (const credential_data_t *data,
                          credential_t *credential)
{
  if (!mock_ad_response)
    return __real_create_credential (data, credential);
  credential_command_calls++;
  assert_that (data->name, is_equal_to_string ("AD response test"));
  assert_that (data->type, is_equal_to_string ("ad"));
#if ENABLE_AD_INTEGRATION
  assert_ad_response_data (&data->ad_credential_data);
#endif
  return mock_credential_result;
}

credential_return_t
__wrap_modify_credential (const credential_data_t *data)
{
  if (!mock_ad_response)
    return __real_modify_credential (data);
  credential_command_calls++;
  assert_that (data->credential_id,
               is_equal_to_string ("response-credential"));
#if ENABLE_AD_INTEGRATION
  assert_ad_response_data (&data->ad_credential_data);
#endif
  return mock_credential_result;
}

void
__wrap_log_event_fail (const char *type, const char *name, const char *id,
                       const char *action)
{
  if (!mock_ad_response)
    {
      __real_log_event_fail (type, name, id, action);
      return;
    }
  assert_that (type, is_equal_to_string ("credential"));
  credential_failure_logs++;
}

#if ENABLE_AD_INTEGRATION
/**
 * @brief Assert that the GMP parser preserves all expected search options.
 *
 * @param[in] params    Parsed search parameters, borrowed from the handler.
 * @param[in] expected  Expected search parameters for this request.
 */
static void
assert_ad_search_params (const get_ad_objects_params_t *params,
                         const get_ad_objects_params_t *expected)
{
  assert_that (params->scope, is_equal_to (expected->scope));
  assert_that (params->max_results, is_equal_to (expected->max_results));
  assert_that (params->object_types, is_equal_to (expected->object_types));
  assert_that (params->include_disabled_computers,
               is_equal_to (expected->include_disabled_computers));
  assert_that (params->targets, is_equal_to (expected->targets));
  assert_that (params->tasks, is_equal_to (expected->tasks));
  assert_that (params->details, is_equal_to (expected->details));
  if (expected->base_dn)
    assert_that (params->base_dn, is_equal_to_string (expected->base_dn));
  else
    assert_that (params->base_dn, is_null);
  if (expected->group_dn)
    assert_that (params->group_dn, is_equal_to_string (expected->group_dn));
  else
    assert_that (params->group_dn, is_null);
}

guint
__wrap_active_directory_max_results_limit (void)
{
  return mock_ad_max_results_limit;
}

get_ad_objects_return_t
__wrap_get_active_directory_objects (const get_ad_objects_params_t *params,
                                     get_ad_objects_result_t *result)
{
  assert_that (mock_ad_response, is_true);
  assert_that (params->credential_id,
               is_equal_to_string ("response-credential"));
  if (expected_search_params)
    assert_ad_search_params (params, expected_search_params);
  assert_that (result->objects, is_null);
  search_command_calls++;
  if (mock_search_result == GET_AD_OBJECTS_OK)
    {
      result->objects = g_ptr_array_new_with_free_func (
        (GDestroyNotify) ad_directory_object_free);
      if (mock_search_object)
        {
          g_ptr_array_add (result->objects, mock_search_object);
          mock_search_object = NULL;
          result->counts.computer_total = 1;
        }
    }
  return mock_search_result;
}

verify_ad_return_t
__wrap_verify_active_directory_credential (const gchar *credential_id,
                                           const ad_credential_data_t *ad)
{
  assert_that (mock_ad_response, is_true);
  credential_command_calls++;
  if (expected_stored_ad)
    assert_that (credential_id, is_equal_to_string ("response-credential"));
  else
    assert_that (credential_id, is_null);
  assert_ad_response_data (ad);
  return mock_verify_result;
}

/**
 * @brief Parse an AD request, check its exact response and verify parser reset.
 *
 * @param[in] request   Complete request XML.
 * @param[in] expected  Expected complete response XML.
 */
static void
assert_ad_request_xml (const gchar *request, const gchar *expected)
{
  const GMarkupParser parser = {
    .start_element = gmp_xml_handle_start_element,
    .end_element = gmp_xml_handle_end_element,
    .text = gmp_xml_handle_text
  };
  gmp_parser_t gmp_parser = { 0 };
  GMarkupParseContext *context;
  GError *error = NULL;

  g_string_truncate (captured_output, 0);
  gmp_parser.client_writer = capture_client_writer;
  client_state = CLIENT_AUTHENTIC;
  context = g_markup_parse_context_new (&parser, 0, &gmp_parser, NULL);
  assert_that (g_markup_parse_context_parse (context, request, -1, &error),
               is_true);
  assert_that (g_markup_parse_context_end_parse (context, &error), is_true);
  assert_that (error, is_null);
  assert_that (client_state, is_equal_to (CLIENT_AUTHENTIC));
  assert_that (captured_output->str, is_equal_to_string (expected));
  g_markup_parse_context_free (context);

  g_string_truncate (captured_output, 0);
  gmp_xml_handle_start_element (NULL, "get_version", NULL, NULL, &gmp_parser,
                                &error);
  gmp_xml_handle_end_element (NULL, "get_version", &gmp_parser, &error);
  assert_that (error, is_null);
  assert_that (client_state, is_equal_to (CLIENT_AUTHENTIC));
  assert_that (captured_output->str,
               contains_string ("<get_version_response status=\"200\""));
}

/**
 * @brief Check an AD command's status response and parser reset.
 *
 * @param[in] command  Command name.
 * @param[in] request  Complete request XML.
 * @param[in] status   Expected exact GMP status.
 * @param[in] text     Expected exact status text.
 */
static void
assert_ad_request_response (const gchar *command, const gchar *request,
                            const gchar *status, const gchar *text)
{
  gchar *expected = g_markup_printf_escaped (
    "<%s_response status=\"%s\" status_text=\"%s\"/>", command, status, text);

  assert_ad_request_xml (request, expected);
  g_free (expected);
}

/**
 * @brief Build and check a credential creation, modification or verification request.
 *
 * Management results and failure logging are mocked; no policy, SQL or network
 * operation is performed.
 *
 * @param[in] command  Command name.
 * @param[in] host     Host text, or NULL to omit the element.
 * @param[in] port     Port text, or NULL to omit the element.
 * @param[in] stored   Whether verification uses a stored credential ID.
 * @param[in] status   Expected exact GMP status.
 * @param[in] text     Expected exact status text.
 */
static void
assert_ad_credential_command_response (const gchar *command, const gchar *host,
                                       const gchar *port, gboolean stored,
                                       const gchar *status, const gchar *text)
{
  GString *xml = g_string_new ("");
  gboolean verify = !strcmp (command, "verify_active_directory_credential");

  mock_ad_response = TRUE;
  expected_ad_host = host;
  expected_ad_port = port;
  expected_stored_ad = stored;
  credential_command_calls = 0;
  credential_failure_logs = 0;
  g_string_append_printf (xml, "<%s%s>", command,
                          stored || !strcmp (command, "modify_credential")
                            ? " credential_id=\"response-credential\"" : "");
  if (!verify)
    g_string_append (xml, "<name>AD response test</name><type>ad</type>");
  if (host)
    g_string_append_printf (xml, "<host>%s</host>", host);
  if (port)
    g_string_append_printf (xml, "<port>%s</port>", port);
  if (!stored)
    g_string_append (xml, "<tls_mode>starttls</tls_mode>"
                         "<bind_dn>cn=test</bind_dn><base_dn>dc=example</base_dn>"
                         "<bind_password>test-secret</bind_password>");
  g_string_append_printf (xml, "</%s>", command);

  assert_ad_request_response (command, xml->str, status, text);
  assert_that (credential_command_calls, is_equal_to (1));
  assert_that (credential_failure_logs, is_equal_to (verify ? 0 : 1));
  g_string_free (xml, TRUE);
  mock_ad_response = FALSE;
}

/**
 * @brief Check an AD search response using a saved credential request.
 *
 * @param[in] status  Expected exact GMP status.
 * @param[in] text    Expected exact status text.
 */
static void
assert_ad_search_response (const gchar *status, const gchar *text)
{
  const gchar *request = "<get_active_directory_objects "
                         "credential_id=\"response-credential\"/>";

  mock_ad_response = TRUE;
  search_command_calls = 0;
  credential_failure_logs = 0;
  assert_ad_request_response ("get_active_directory_objects", request,
                              status, text);
  assert_that (search_command_calls, is_equal_to (1));
  assert_that (credential_failure_logs, is_equal_to (0));
  mock_ad_response = FALSE;
}

/**
 * @brief Free a target match created for the AD search fixture.
 *
 * @param[in] data  Target match to free, including its optional task array.
 */
static void
free_ad_search_target (gpointer data)
{
  ad_target_match_t *target = data;

  g_free (target->resource.uuid);
  g_free (target->resource.name);
  g_clear_pointer (&target->tasks, g_ptr_array_unref);
  g_free (target);
}

/**
 * @brief Prepare a computer result for the mocked AD search.
 *
 * The search mock transfers ownership of the fixture to the command handler.
 *
 * @param[in] with_target  Whether to attach a target match.
 * @param[in] empty_tasks  Give the target an empty task array instead of NULL.
 *                        Only used when with_target is true.
 */
static void
set_ad_search_computer (gboolean with_target, gboolean empty_tasks)
{
  mock_search_object = g_new0 (ad_directory_object_t, 1);
  mock_search_object->type = AD_OBJECT_TYPE_COMPUTER;
  mock_search_object->name = g_strdup ("computer");
  mock_search_object->distinguished_name = g_strdup ("CN=computer,DC=example");
  if (with_target)
    {
      ad_target_match_t *target = g_new0 (ad_target_match_t, 1);

      target->resource.uuid = g_strdup ("target-id");
      target->resource.name = g_strdup ("AD target");
      if (empty_tasks)
        target->tasks = g_ptr_array_new ();
      mock_search_object->target_matches
        = g_ptr_array_new_with_free_func (free_ad_search_target);
      g_ptr_array_add (mock_search_object->target_matches, target);
    }
}

/**
 * @brief Check target and task collection XML using the prepared search fixture.
 *
 * @param[in] targets               Whether to request target matches.
 * @param[in] tasks                 Whether to request tasks for each target.
 * @param[in] expected_collections  Expected collection XML within the computer.
 */
static void
assert_ad_search_collections (gboolean targets, gboolean tasks,
                              const gchar *expected_collections)
{
  gchar *request = g_strdup_printf (
    "<get_active_directory_objects credential_id=\"response-credential\" "
    "include_disabled_computers=\"0\" targets=\"%d\" tasks=\"%d\"/>",
    targets, tasks);
  gchar *expected = g_strdup_printf (
    "<get_active_directory_objects_response status=\"200\" status_text=\"OK\">"
    "<objects truncated=\"0\"><count><ou>0</ou><container>0</container>"
    "<group>0</group><computer><total>1</total></computer></count>"
    "<object type=\"computer\"><name>computer</name>"
    "<distinguished_name>CN=computer,DC=example</distinguished_name>"
    "<parent_dn></parent_dn><description></description>%s</object>"
    "</objects></get_active_directory_objects_response>", expected_collections);

  mock_ad_response = TRUE;
  mock_search_result = GET_AD_OBJECTS_OK;
  search_command_calls = 0;
  assert_ad_request_xml (request, expected);
  assert_that (search_command_calls, is_equal_to (1));
  mock_ad_response = FALSE;
  g_free (expected);
  g_free (request);
}

Ensure (gmp, search_omits_unrequested_collections)
{
  set_ad_search_computer (TRUE, TRUE);
  assert_ad_search_collections (FALSE, FALSE, "");

  set_ad_search_computer (TRUE, TRUE);
  assert_ad_search_collections (
    TRUE, FALSE,
    "<targets><target id=\"target-id\"><name>AD target</name></target></targets>");
}

Ensure (gmp, search_emits_requested_empty_collections)
{
  set_ad_search_computer (FALSE, FALSE);
  assert_ad_search_collections (TRUE, TRUE, "<targets/>");

  set_ad_search_computer (FALSE, FALSE);
  mock_search_object->target_matches
    = g_ptr_array_new_with_free_func (free_ad_search_target);
  assert_ad_search_collections (TRUE, TRUE, "<targets/>");

  set_ad_search_computer (TRUE, FALSE);
  assert_ad_search_collections (
    TRUE, TRUE,
    "<targets><target id=\"target-id\"><name>AD target</name>"
    "<tasks/></target></targets>");

  set_ad_search_computer (TRUE, TRUE);
  assert_ad_search_collections (
    TRUE, TRUE,
    "<targets><target id=\"target-id\"><name>AD target</name>"
    "<tasks/></target></targets>");
}

/**
 * @brief Check parsed search options and authenticated parser recovery.
 *
 * The management mock checks the parameters and returns an empty successful
 * result without LDAP access.
 *
 * @param[in] attributes  Request attributes following credential_id.
 * @param[in] children    Child elements within the search request.
 * @param[in] expected    Expected parsed search parameters.
 */
static void
assert_ad_search_options (const gchar *attributes, const gchar *children,
                          const get_ad_objects_params_t *expected)
{
  gchar *request = g_strdup_printf (
    "<get_active_directory_objects credential_id=\"response-credential\" %s>"
    "%s</get_active_directory_objects>", attributes, children);
  gchar *response = g_strdup_printf (
    "<get_active_directory_objects_response status=\"200\" status_text=\"OK\">"
    "<objects truncated=\"0\"><count><ou>0</ou><container>0</container>"
    "<group>0</group><computer><total>0</total>%s</computer></count>"
    "</objects></get_active_directory_objects_response>",
    expected->include_disabled_computers ? "<disabled>0</disabled>" : "");

  mock_ad_response = TRUE;
  mock_search_result = GET_AD_OBJECTS_OK;
  search_command_calls = 0;
  expected_search_params = expected;
  assert_ad_request_xml (request, response);
  assert_that (search_command_calls, is_equal_to (1));
  expected_search_params = NULL;
  mock_ad_response = FALSE;
  g_free (response);
  g_free (request);
}

Ensure (gmp, search_request_defaults)
{
  const get_ad_objects_params_t expected = {
    .scope = AD_CONNECTOR_SEARCH_SCOPE_ONELEVEL,
    .object_types = AD_OBJECT_TYPE_DEFAULT,
    .max_results = AD_MAX_RESULTS_LIMIT_DEFAULT,
    .include_disabled_computers = TRUE
  };

  assert_ad_search_options ("", "", &expected);
}

Ensure (gmp, search_request_valid_options)
{
  const struct
  {
    const gchar *attributes;
    const gchar *children;
    get_ad_objects_params_t expected;
  } cases[] = {
    { "scope=\"base\" max_results=\"1\" include_disabled_computers=\"0\" "
      "targets=\"0\" tasks=\"0\" details=\"0\"", "",
      { .scope = AD_CONNECTOR_SEARCH_SCOPE_BASE,
        .object_types = AD_OBJECT_TYPE_DEFAULT, .max_results = 1 } },
    { "scope=\"onelevel\" max_results=\"1000\" "
      "include_disabled_computers=\"1\" "
      "targets=\"1\" tasks=\"1\" details=\"1\"", "",
      { .scope = AD_CONNECTOR_SEARCH_SCOPE_ONELEVEL,
        .object_types = AD_OBJECT_TYPE_DEFAULT, .max_results = 1000,
        .include_disabled_computers = TRUE, .targets = TRUE,
        .tasks = TRUE, .details = TRUE } },
    { "scope=\"subtree\" targets=\"1\" tasks=\"0\"", "",
      { .scope = AD_CONNECTOR_SEARCH_SCOPE_SUBTREE,
        .object_types = AD_OBJECT_TYPE_DEFAULT,
        .max_results = AD_MAX_RESULTS_LIMIT_DEFAULT,
        .include_disabled_computers = TRUE, .targets = TRUE } },
    { "max_results=\"0001\"", "",
      { .scope = AD_CONNECTOR_SEARCH_SCOPE_ONELEVEL,
        .object_types = AD_OBJECT_TYPE_DEFAULT, .max_results = 1,
        .include_disabled_computers = TRUE } },
    { "", "<base_dn> </base_dn>",
      { .base_dn = " ", .scope = AD_CONNECTOR_SEARCH_SCOPE_ONELEVEL,
        .object_types = AD_OBJECT_TYPE_DEFAULT,
        .max_results = AD_MAX_RESULTS_LIMIT_DEFAULT,
        .include_disabled_computers = TRUE } },
    { "", "<object_types><object_type>ou</object_type>"
            "<object_type>container</object_type>"
            "<object_type>ou</object_type></object_types>",
      { .scope = AD_CONNECTOR_SEARCH_SCOPE_ONELEVEL,
        .object_types = AD_OBJECT_TYPE_OU | AD_OBJECT_TYPE_CONTAINER,
        .max_results = AD_MAX_RESULTS_LIMIT_DEFAULT,
        .include_disabled_computers = TRUE } },
    { "", "<object_types><unknown>ignored</unknown>"
            "<object_type>computer</object_type></object_types>",
      { .scope = AD_CONNECTOR_SEARCH_SCOPE_ONELEVEL,
        .object_types = AD_OBJECT_TYPE_COMPUTER,
        .max_results = AD_MAX_RESULTS_LIMIT_DEFAULT,
        .include_disabled_computers = TRUE } },
    { "", "<base_dn>OU=Hosts,DC=example</base_dn>"
            "<group_dn>CN=Group,DC=example</group_dn>"
            "<object_types><object_type>ou</object_type>"
            "<object_type>container</object_type>"
            "<object_type>computer</object_type>"
            "<object_type>group</object_type></object_types>",
      { .base_dn = "OU=Hosts,DC=example", .group_dn = "CN=Group,DC=example",
        .scope = AD_CONNECTOR_SEARCH_SCOPE_ONELEVEL,
        .object_types = AD_OBJECT_TYPE_OU | AD_OBJECT_TYPE_CONTAINER
                        | AD_OBJECT_TYPE_COMPUTER | AD_OBJECT_TYPE_GROUP,
        .max_results = AD_MAX_RESULTS_LIMIT_DEFAULT,
        .include_disabled_computers = TRUE } }
  };

  for (guint i = 0; i < G_N_ELEMENTS (cases); i++)
    assert_ad_search_options (cases[i].attributes, cases[i].children,
                              &cases[i].expected);
}

/**
 * @brief Reject invalid XML request fields before management is invoked.
 *
 * @param[in] request  Complete request XML.
 * @param[in] message  Expected syntax error status text.
 */
static void
assert_ad_search_rejected (const gchar *request, const gchar *message)
{
  mock_ad_response = TRUE;
  mock_search_result = GET_AD_OBJECTS_CONNECTION_FAILED;
  search_command_calls = 0;
  assert_ad_request_response ("get_active_directory_objects", request,
                              "400", message);
  assert_that (search_command_calls, is_equal_to (0));
  mock_ad_response = FALSE;
}

Ensure (gmp, search_request_rejects_invalid_options)
{
  const struct
  {
    const gchar *attributes;
    const gchar *children;
    const gchar *message;
  } cases[] = {
    { "scope=\"invalid\"", "", "Invalid scope" },
    { "max_results=\"\"", "", "Invalid max_results" },
    { "max_results=\"0\"", "", "Invalid max_results" },
    { "max_results=\"1001\"", "", "Invalid max_results" },
    { "max_results=\"1x\"", "", "Invalid max_results" },
    { "max_results=\"18446744073709551616\"", "", "Invalid max_results" },
    { "include_disabled_computers=\"2\"", "",
      "Invalid include_disabled_computers" },
    { "targets=\"2\"", "", "Invalid targets" },
    { "tasks=\"2\"", "", "Invalid tasks" },
    { "tasks=\"1\"", "", "tasks requires targets=1" },
    { "targets=\"0\" tasks=\"1\"", "", "tasks requires targets=1" },
    { "details=\"2\"", "", "Invalid details" },
    { "", "<base_dn/>", "Empty base_dn element" },
    { "", "<base_dn><name>DC=example</name></base_dn>",
      "Invalid base_dn element" },
    { "", "<group_dn/>", "Empty group_dn element" },
    { "", "<group_dn><name>CN=Group</name></group_dn>",
      "Invalid group_dn element" },
    { "", "<object_types/>", "Invalid object_types element" },
    { "", "<object_types><object_type/></object_types>",
      "Invalid object_types element" },
    { "", "<object_types><object_type>invalid</object_type></object_types>",
      "Invalid object_types element" },
    { "", "<object_types><object_type>computer</object_type>"
          "<object_type>invalid</object_type></object_types>",
      "Invalid object_types element" },
    { "", "<object_types><object_type><name>computer</name>"
          "</object_type></object_types>",
      "Invalid object_types element" }
  };

  assert_ad_search_rejected ("<get_active_directory_objects/>",
                             "Missing or empty credential_id attribute");
  assert_ad_search_rejected (
    "<get_active_directory_objects credential_id=\"\"/>",
    "Missing or empty credential_id attribute");

  for (guint i = 0; i < G_N_ELEMENTS (cases); i++)
    {
      gchar *request = g_strdup_printf (
        "<get_active_directory_objects "
        "credential_id=\"response-credential\" %s>"
        "%s</get_active_directory_objects>",
        cases[i].attributes, cases[i].children);

      assert_ad_search_rejected (request, cases[i].message);
      g_free (request);
    }
}

Ensure (gmp, search_request_uses_configured_result_limit)
{
  const get_ad_objects_params_t expected = {
    .scope = AD_CONNECTOR_SEARCH_SCOPE_ONELEVEL,
    .object_types = AD_OBJECT_TYPE_DEFAULT,
    .max_results = 50,
    .include_disabled_computers = TRUE
  };

  mock_ad_max_results_limit = 50;
  assert_ad_search_options ("", "", &expected);
  assert_ad_search_options ("max_results=\"50\"", "", &expected);
  assert_ad_search_rejected (
    "<get_active_directory_objects credential_id=\"response-credential\" "
    "max_results=\"51\"/>",
    "Invalid max_results");
}

Ensure (gmp, search_ad_error_responses)
{
  mock_search_result = GET_AD_OBJECTS_CONNECTION_FAILED;
  assert_ad_search_response ("503", "Could not connect to Active Directory");

  mock_search_result = GET_AD_OBJECTS_DESTINATION_NOT_ALLOWED;
  assert_ad_search_response ("400",
                             "Active Directory destination is not allowed.");

  mock_search_result = GET_AD_OBJECTS_INVALID_STORED_CONFIGURATION;
  assert_ad_search_response ("400",
                             "Stored Active Directory credential configuration"
                             " is invalid");
}

Ensure (gmp, create_ad_host_and_port_denial_responses)
{
  mock_credential_result = CREDENTIAL_AD_DESTINATION_NOT_ALLOWED;
  assert_ad_credential_command_response ("create_credential", "denied.invalid", "389",
                              FALSE, "400",
                              "Active Directory destination is not allowed.");
  assert_ad_credential_command_response ("create_credential", "allowed.invalid", "1389",
                              FALSE, "400",
                              "Active Directory destination is not allowed.");
}

Ensure (gmp, modify_ad_host_and_port_denial_responses)
{
  mock_credential_result = CREDENTIAL_AD_DESTINATION_NOT_ALLOWED;
  assert_ad_credential_command_response ("modify_credential", "denied.invalid", "389",
                              FALSE, "400",
                              "Active Directory destination is not allowed.");
  assert_ad_credential_command_response ("modify_credential", "allowed.invalid", "1389",
                              FALSE, "400",
                              "Active Directory destination is not allowed.");
}

Ensure (gmp, verify_inline_ad_host_and_port_denial_responses)
{
  mock_verify_result = VERIFY_AD_CREDENTIAL_DESTINATION_NOT_ALLOWED;
  assert_ad_credential_command_response ("verify_active_directory_credential",
                              "denied.invalid", "389", FALSE, "400",
                              "Active Directory destination is not allowed.");
  assert_ad_credential_command_response ("verify_active_directory_credential",
                              "allowed.invalid", "1389", FALSE, "400",
                              "Active Directory destination is not allowed.");
}

Ensure (gmp, verify_stored_ad_destination_denial_response)
{
  mock_verify_result = VERIFY_AD_CREDENTIAL_DESTINATION_NOT_ALLOWED;
  assert_ad_credential_command_response ("verify_active_directory_credential",
                              NULL, NULL, TRUE, "400",
                              "Active Directory destination is not allowed.");
}

Ensure (gmp, malformed_ad_host_responses)
{
  mock_credential_result = CREDENTIAL_AD_INVALID_HOST;
  mock_verify_result = VERIFY_AD_CREDENTIAL_INVALID_HOST;
  assert_ad_credential_command_response ("create_credential", "bad/host", "389", FALSE,
                              "400", "Invalid AD host");
  assert_ad_credential_command_response ("modify_credential", "bad/host", "389", FALSE,
                              "400", "Invalid AD host");
  assert_ad_credential_command_response ("verify_active_directory_credential", "bad/host",
                              "389", FALSE, "400", "Invalid AD host");
}

Ensure (gmp, ad_whitespace_fields_and_disabled_responses)
{
  mock_credential_result = CREDENTIAL_AD_INVALID_HOST;
  mock_verify_result = VERIFY_AD_CREDENTIAL_INVALID_HOST;
  assert_ad_credential_command_response ("create_credential", "\tdc.example.com ", NULL,
                              FALSE, "400", "Invalid AD host");
  assert_ad_credential_command_response ("modify_credential", " \t ", "", FALSE,
                              "400", "Invalid AD host");
  assert_ad_credential_command_response ("verify_active_directory_credential", " \t ",
                              NULL, FALSE, "400", "Invalid AD host");
  mock_verify_result = VERIFY_AD_CREDENTIAL_INVALID_PORT;
  assert_ad_credential_command_response ("verify_active_directory_credential",
                              "dc.example.com", "389\t", FALSE,
                              "400", "Invalid AD port");

  mock_credential_result = CREDENTIAL_AD_INTEGRATION_UNAVAILABLE;
  mock_verify_result = VERIFY_AD_CREDENTIAL_FEATURE_DISABLED;
  assert_ad_credential_command_response ("create_credential", "denied.invalid", "1389",
                              FALSE, "400", "AD integration feature is disabled");
  assert_ad_credential_command_response ("modify_credential", NULL, "", FALSE,
                              "400", "AD integration feature is disabled");
  assert_ad_credential_command_response ("verify_active_directory_credential",
                              "denied.invalid", "1389", FALSE, "400",
                              "Active Directory integration is disabled");
  assert_ad_credential_command_response ("verify_active_directory_credential", NULL, NULL,
                              TRUE, "400",
                              "Active Directory integration is disabled");
}

Ensure (gmp, existing_ad_credential_error_responses_are_unchanged)
{
  const struct {
    credential_return_t result;
    const gchar *text;
  } cases[] = {
    { CREDENTIAL_AD_HOST_REQUIRED, "AD host is required" },
    { CREDENTIAL_AD_INVALID_PORT, "Invalid AD port" },
    { CREDENTIAL_AD_TLS_MODE_REQUIRED, "AD TLS mode is required" },
    { CREDENTIAL_AD_INVALID_TLS_MODE, "Invalid AD TLS mode" },
    { CREDENTIAL_AD_INVALID_CA_CERTIFICATE, "Invalid AD CA certificate" },
    { CREDENTIAL_PERMISSION_DENIED, "Permission denied" }
  };

  for (guint i = 0; i < G_N_ELEMENTS (cases); i++)
    {
      mock_credential_result = cases[i].result;
      assert_ad_credential_command_response ("create_credential", NULL, NULL, FALSE,
                                  "400", cases[i].text);
      assert_ad_credential_command_response ("modify_credential", "", NULL, FALSE,
                                  "400", cases[i].text);
    }
}

Ensure (gmp, existing_ad_verification_error_responses_are_unchanged)
{
  const struct {
    verify_ad_return_t result;
    const gchar *status;
    const gchar *text;
  } cases[] = {
    { VERIFY_AD_CREDENTIAL_HOST_REQUIRED, "400", "AD host is required" },
    { VERIFY_AD_CREDENTIAL_INVALID_PORT, "400", "Invalid AD port" },
    { VERIFY_AD_CREDENTIAL_TLS_MODE_REQUIRED, "400", "AD TLS mode is required" },
    { VERIFY_AD_CREDENTIAL_INVALID_TLS_MODE, "400", "Invalid AD TLS mode" },
    { VERIFY_AD_CREDENTIAL_INVALID_CA_CERTIFICATE, "400",
      "Invalid AD CA certificate" },
    { VERIFY_AD_CREDENTIAL_PERMISSION_DENIED, "403",
      "Access to resource forbidden" },
    { VERIFY_AD_CREDENTIAL_CONNECTION_FAILED, "503",
      "Could not connect to Active Directory" }
  };

  for (guint i = 0; i < G_N_ELEMENTS (cases); i++)
    {
      mock_verify_result = cases[i].result;
      assert_ad_credential_command_response ("verify_active_directory_credential", "",
                                  NULL, FALSE, cases[i].status, cases[i].text);
    }
  mock_verify_result = VERIFY_AD_CREDENTIAL_INVALID_STORED_CONFIGURATION;
  assert_ad_credential_command_response ("verify_active_directory_credential", NULL, NULL,
                              TRUE, "400",
                              "Stored Active Directory credential configuration"
                              " is invalid");
}
#endif

int
__wrap_modify_permission (const char *permission_id, const char *name,
                          const char *comment, const char *resource_id,
                          const char *resource_type, const char *subject_type,
                          const char *subject_id)
{
  return 1;
}

int
__wrap_acl_user_may (const char *permission)
{
  (void) permission;
  return 0;
}

int __real_init_get (gchar *, get_data_t *, const gchar *, int *);
int __real_init_report_export_iterator (iterator_t *, get_data_t *);

int
__wrap_init_get (gchar *command, get_data_t *get, const gchar *setting_name,
                 int *first)
{
  if (mock_missing_report_export && !strcmp (command, "get_report_exports"))
    {
      *first = 1;
      return 0;
    }
  return __real_init_get (command, get, setting_name, first);
}

int
__wrap_init_report_export_iterator (iterator_t *iterator, get_data_t *get)
{
  if (mock_missing_report_export)
    {
      assert_that (get->id, is_equal_to_string (report_export_uuid));
      return 1;
    }
  return __real_init_report_export_iterator (iterator, get);
}

gboolean
__wrap_find_report_export_with_permission (const char *uuid,
                                           report_export_t *report_export,
                                           const char *permission)
{
  assert_that (uuid, is_equal_to_string (report_export_uuid));
  assert_that (permission, is_equal_to_string ("get_report_exports"));
  *report_export = 42;
  return FALSE;
}

int
__wrap_load_report_export_data (report_export_t report_export,
                                report_export_data_t data)
{
  assert_that (report_export, is_equal_to (42));

  data->row_id = report_export;
  data->uuid = g_strdup (report_export_uuid);
  data->report = 101;
  data->report_format = 102;
  data->export_type = REPORT_EXPORT_TYPE_SCAN;
  data->status = REPORT_EXPORT_STATUS_DONE;
  data->progress = REPORT_EXPORT_PROGRESS_COMPLETED;
  data->file_path = g_strdup (report_export_path);
  data->file_size = sizeof (report_export_contents);
  data->content_type = g_strdup ("application/octet-stream");
  data->extension = g_strdup ("bin");
  return 0;
}

char *
__wrap_report_uuid (report_t report)
{
  assert_that (report, is_equal_to (101));
  return g_strdup (report_uuid_value);
}

char *
__wrap_report_format_uuid (report_format_t report_format)
{
  assert_that (report_format, is_equal_to (102));
  return g_strdup (report_format_uuid_value);
}

int
__wrap_manage_delete_report_export (report_export_t report_export,
                                    const gchar *file_path)
{
  (void) report_export;
  (void) file_path;
  report_export_delete_count++;
  return 0;
}

static void
create_report_export_file (void)
{
  gssize offset = 0;
  int fd;

  fd = g_file_open_tmp ("gvmd-report-export-XXXXXX", &report_export_path, NULL);
  assert_that (fd, is_greater_than (-1));

  while (offset < (gssize) sizeof (report_export_contents))
    {
      gssize written;

      written = write (fd, report_export_contents + offset,
                       sizeof (report_export_contents) - offset);
      assert_that (written, is_greater_than (0));
      offset += written;
    }

  assert_that (close (fd), is_equal_to (0));
}

static void
run_completed_report_export_download (gmp_parser_t *gmp_parser, GError **error)
{
  const gchar *attribute_names[] = { "report_export_id", NULL };
  const gchar *attribute_values[] = { report_export_uuid, NULL };

  client_state = CLIENT_AUTHENTIC;
  gmp_xml_handle_start_element (NULL, "download_report_export", attribute_names,
                                attribute_values, gmp_parser, error);
  gmp_xml_handle_end_element (NULL, "download_report_export", gmp_parser,
                              error);
}

static void
assert_download_response (const gchar *response)
{
  GMarkupParseContext *context;
  GMarkupParser validation_parser = { 0 };
  const gchar *content_start;
  const gchar *content_end;
  guchar *decoded;
  gsize decoded_size;
  gchar *encoded;
  GError *error = NULL;

  assert_that (response, contains_string ("status=\"200\""));
  assert_that (response, contains_string ("<type>scan</type>"));
  assert_that (response, contains_string ("<status>done</status>"));
  assert_that (response,
               contains_string ("<progress>completed</progress>"));
  assert_that (response, contains_string ("<file_size>11</file_size>"));
  assert_that (response,
               contains_string ("<content_type>application/octet-stream"
                                "</content_type>"));
  assert_that (response, contains_string ("<extension>bin</extension>"));
  assert_that (response, contains_string (report_uuid_value));
  assert_that (response, contains_string (report_format_uuid_value));

  context = g_markup_parse_context_new (&validation_parser, 0, NULL, NULL);
  assert_that (g_markup_parse_context_parse (context, response,
                                             strlen (response), &error),
               is_true);
  assert_that (g_markup_parse_context_end_parse (context, &error), is_true);
  assert_that (error, is_null);
  g_markup_parse_context_free (context);

  content_start = strstr (response, "<content>");
  assert_that (content_start, is_not_null);
  content_start += strlen ("<content>");
  content_end = strstr (content_start, "</content>");
  assert_that (content_end, is_not_null);
  encoded = g_strndup (content_start, content_end - content_start);
  decoded = g_base64_decode (encoded, &decoded_size);
  assert_that (decoded_size, is_equal_to (sizeof (report_export_contents)));
  assert_that (
    memcmp (decoded, report_export_contents, sizeof (report_export_contents)),
    is_equal_to (0));
  g_free (decoded);
  g_free (encoded);
}

Ensure (gmp, completed_download_report_export_is_repeatable)
{
  gmp_parser_t gmp_parser = { 0 };
  gchar *first_response;
  GError *error = NULL;

  create_report_export_file ();
  gmp_parser.client_writer = capture_client_writer;

  run_completed_report_export_download (&gmp_parser, &error);

  assert_that (error, is_null);
  assert_that (client_state, is_equal_to (CLIENT_AUTHENTIC));
  assert_that (report_export_delete_count, is_equal_to (0));
  assert_that (g_file_test (report_export_path, G_FILE_TEST_EXISTS), is_true);
  assert_download_response (captured_output->str);
  first_response = g_strdup (captured_output->str);

  g_string_truncate (captured_output, 0);
  run_completed_report_export_download (&gmp_parser, &error);

  assert_that (error, is_null);
  assert_that (client_state, is_equal_to (CLIENT_AUTHENTIC));
  assert_that (report_export_delete_count, is_equal_to (0));
  assert_that (g_file_test (report_export_path, G_FILE_TEST_EXISTS), is_true);
  assert_that (captured_output->str, is_equal_to_string (first_response));
  assert_download_response (captured_output->str);
  g_free (first_response);

  g_string_truncate (captured_output, 0);
  gmp_xml_handle_start_element (NULL, "get_version", NULL, NULL, &gmp_parser,
                                &error);
  gmp_xml_handle_end_element (NULL, "get_version", &gmp_parser, &error);

  assert_that (error, is_null);
  assert_that (client_state, is_equal_to (CLIENT_AUTHENTIC));
  assert_that (captured_output->str,
               contains_string ("<get_version_response status=\"200\""));
}

Ensure (gmp, missing_report_export_returns_not_found)
{
  const gchar *attribute_names[] = { "report_export_id", NULL };
  const gchar *attribute_values[] = { report_export_uuid, NULL };
  gmp_parser_t gmp_parser = { 0 };
  GError *error = NULL;

  mock_missing_report_export = 1;
  gmp_parser.client_writer = capture_client_writer;
  client_state = CLIENT_AUTHENTIC;
  gmp_xml_handle_start_element (NULL, "get_report_exports", attribute_names,
                                attribute_values, &gmp_parser, &error);
  gmp_xml_handle_end_element (NULL, "get_report_exports", &gmp_parser, &error);

  assert_that (error, is_null);
  assert_that (client_state, is_equal_to (CLIENT_AUTHENTIC));
  assert_that (captured_output->str,
               contains_string ("<get_report_exports_response status=\"404\""));
  assert_that (captured_output->str, contains_string (report_export_uuid));

  g_string_truncate (captured_output, 0);
  gmp_xml_handle_start_element (NULL, "get_version", NULL, NULL, &gmp_parser,
                                &error);
  gmp_xml_handle_end_element (NULL, "get_version", &gmp_parser, &error);
  assert_that (error, is_null);
  assert_that (client_state, is_equal_to (CLIENT_AUTHENTIC));
  assert_that (captured_output->str,
               contains_string ("<get_version_response status=\"200\""));
}

static void
assert_report_export_command_restores_authenticated_state (const char *command)
{
  const gchar *attribute_names[] = { NULL };
  const gchar *attribute_values[] = { NULL };
  gmp_parser_t gmp_parser = { 0 };
  GError *error = NULL;

  gmp_parser.client_writer = dummy_client_writer;
  client_state = CLIENT_AUTHENTIC;

  gmp_xml_handle_start_element (NULL, command, attribute_names,
                                attribute_values, &gmp_parser, &error);
  gmp_xml_handle_end_element (NULL, command, &gmp_parser, &error);

  assert_that (error, is_null);
  assert_that (client_state, is_equal_to (CLIENT_AUTHENTIC));

  gmp_xml_handle_start_element (NULL, "get_version", NULL, NULL,
                                &gmp_parser, &error);

  assert_that (error, is_null);
  assert_that (client_state, is_equal_to (CLIENT_GET_VERSION_AUTHENTIC));
}

Ensure (gmp, cancel_report_export_restores_authenticated_state)
{
  assert_report_export_command_restores_authenticated_state
    ("cancel_report_export");
}

Ensure (gmp, create_report_config_restores_authenticated_state)
{
  gmp_parser_t gmp_parser = { 0 };
  GError *error = NULL;

  gmp_parser.client_writer = dummy_client_writer;
  client_state = CLIENT_CREATE_REPORT_CONFIG;
  create_report_config_start (&gmp_parser, NULL, NULL);

  gmp_xml_handle_end_element (NULL, "create_report_config", &gmp_parser,
                              &error);

  assert_that (error, is_null);
  assert_that (client_state, is_equal_to (CLIENT_AUTHENTIC));
}

Ensure (gmp, download_report_export_restores_authenticated_state)
{
  assert_report_export_command_restores_authenticated_state
    ("download_report_export");
}

Ensure (gmp, export_audit_report_restores_authenticated_state)
{
  assert_report_export_command_restores_authenticated_state
    ("export_audit_report");
}

Ensure (gmp, export_delta_audit_report_restores_authenticated_state)
{
  assert_report_export_command_restores_authenticated_state
    ("export_delta_audit_report");
}

Ensure (gmp, export_delta_scan_report_restores_authenticated_state)
{
  assert_report_export_command_restores_authenticated_state
    ("export_delta_scan_report");
}

Ensure (gmp, export_scan_report_restores_authenticated_state)
{
  assert_report_export_command_restores_authenticated_state
    ("export_scan_report");
}

Ensure (gmp, modify_report_config_restores_authenticated_state)
{
  gmp_parser_t gmp_parser = { 0 };
  GError *error = NULL;

  gmp_parser.client_writer = dummy_client_writer;
  client_state = CLIENT_MODIFY_REPORT_CONFIG;
  modify_report_config_start (&gmp_parser, NULL, NULL);

  gmp_xml_handle_end_element (NULL, "modify_report_config", &gmp_parser,
                              &error);

  assert_that (error, is_null);
  assert_that (client_state, is_equal_to (CLIENT_AUTHENTIC));
}

#if ENABLE_WEB_APPLICATION_SCANNING
Ensure (gmp, modify_web_application_target_restores_authenticated_state)
{
  const gchar *attribute_names[] = { NULL };
  const gchar *attribute_values[] = { NULL };
  gmp_parser_t gmp_parser = { 0 };
  GError *error = NULL;

  gmp_parser.client_writer = capture_client_writer;
  client_state = CLIENT_AUTHENTIC;
  gmp_xml_handle_start_element (NULL, "modify_web_application_target",
                                attribute_names, attribute_values, &gmp_parser,
                                &error);
  gmp_xml_handle_start_element (NULL, "name", attribute_names,
                                attribute_values, &gmp_parser, &error);
  gmp_xml_handle_end_element (NULL, "name", &gmp_parser, &error);
  assert_that (client_state, is_equal_to (CLIENT_MODIFY_WEB_APPLICATION_TARGET));
  gmp_xml_handle_end_element (NULL, "modify_web_application_target", &gmp_parser,
                              &error);

  assert_that (error, is_null);
  assert_that (captured_output->str,
               contains_string ("<modify_web_application_target_response "
                                "status=\"400\""));
  assert_that (client_state, is_equal_to (CLIENT_AUTHENTIC));

  g_string_truncate (captured_output, 0);
  gmp_xml_handle_start_element (NULL, "get_version", NULL, NULL, &gmp_parser,
                                &error);
  gmp_xml_handle_end_element (NULL, "get_version", &gmp_parser, &error);
  assert_that (error, is_null);
  assert_that (client_state, is_equal_to (CLIENT_AUTHENTIC));
  assert_that (captured_output->str,
               contains_string ("<get_version_response status=\"200\""));
}
#endif

#if ENABLE_CONTAINER_SCANNING
Ensure (gmp, modify_oci_image_target_restores_authenticated_state)
{
  const gchar *attribute_names[] = { NULL };
  const gchar *attribute_values[] = { NULL };
  gmp_parser_t gmp_parser = { 0 };
  GError *error = NULL;

  gmp_parser.client_writer = capture_client_writer;
  client_state = CLIENT_AUTHENTIC;
  gmp_xml_handle_start_element (NULL, "modify_oci_image_target", attribute_names,
                                attribute_values, &gmp_parser, &error);
  gmp_xml_handle_start_element (NULL, "name", attribute_names,
                                attribute_values, &gmp_parser, &error);
  gmp_xml_handle_end_element (NULL, "name", &gmp_parser, &error);
  assert_that (client_state, is_equal_to (CLIENT_MODIFY_OCI_IMAGE_TARGET));
  gmp_xml_handle_end_element (NULL, "modify_oci_image_target", &gmp_parser,
                              &error);

  assert_that (error, is_null);
  assert_that (captured_output->str,
               contains_string ("<modify_oci_image_target_response "
                                "status=\"400\""));
  assert_that (client_state, is_equal_to (CLIENT_AUTHENTIC));

  g_string_truncate (captured_output, 0);
  gmp_xml_handle_start_element (NULL, "get_version", NULL, NULL, &gmp_parser,
                                &error);
  gmp_xml_handle_end_element (NULL, "get_version", &gmp_parser, &error);
  assert_that (error, is_null);
  assert_that (client_state, is_equal_to (CLIENT_AUTHENTIC));
  assert_that (captured_output->str,
               contains_string ("<get_version_response status=\"200\""));
}
#endif

static void
assert_move_task_error_restores_authenticated_state (
  const gchar **attribute_names, const gchar **attribute_values)
{
  gmp_parser_t gmp_parser = { 0 };
  GError *error = NULL;

  gmp_parser.client_writer = dummy_client_writer;
  client_state = CLIENT_AUTHENTIC;

  gmp_xml_handle_start_element (NULL, "move_task", attribute_names,
                                attribute_values, &gmp_parser, &error);
  gmp_xml_handle_end_element (NULL, "move_task", &gmp_parser, &error);

  assert_that (error, is_null);
  assert_that (client_state, is_equal_to (CLIENT_AUTHENTIC));

  gmp_xml_handle_start_element (NULL, "get_version", NULL, NULL,
                                &gmp_parser, &error);

  assert_that (error, is_null);
  assert_that (client_state, is_equal_to (CLIENT_GET_VERSION_AUTHENTIC));
}

Ensure (gmp, modify_permission_not_found_returns_not_found_response)
{
  const gchar *attribute_names[] = { "permission_id", NULL };
  const gchar *attribute_values[] = { "missing-permission", NULL };
  gmp_parser_t gmp_parser = { 0 };
  GError *error = NULL;
  GString *response;

  response = g_string_new ("");
  gmp_parser.client_writer = string_client_writer;
  gmp_parser.client_writer_data = response;
  client_state = CLIENT_AUTHENTIC;

  gmp_xml_handle_start_element (NULL, "modify_permission", attribute_names,
                                attribute_values, &gmp_parser, &error);
  gmp_xml_handle_end_element (NULL, "modify_permission", &gmp_parser,
                              &error);

  assert_that (error, is_null);
  assert_that (response->str, contains_string
               ("<modify_permission_response status=\"404\""));
  assert_that (response->str, contains_string
               ("Failed to find permission 'missing-permission'"));
  assert_that (client_state, is_equal_to (CLIENT_AUTHENTIC));

  g_string_free (response, TRUE);
}

Ensure (gmp, move_task_without_task_id_restores_authenticated_state)
{
  const gchar *attribute_names[] = { "slave_id", NULL };
  const gchar *attribute_values[] = { "slave", NULL };

  assert_move_task_error_restores_authenticated_state (attribute_names,
                                                        attribute_values);
}

Ensure (gmp, move_task_without_slave_id_restores_authenticated_state)
{
  const gchar *attribute_names[] = { "task_id", NULL };
  const gchar *attribute_values[] = { "task", NULL };

  assert_move_task_error_restores_authenticated_state (attribute_names,
                                                        attribute_values);
}

Ensure (gmp, move_task_with_empty_task_id_restores_authenticated_state)
{
  const gchar *attribute_names[] = { "task_id", "slave_id", NULL };
  const gchar *attribute_values[] = { "", "slave", NULL };

  assert_move_task_error_restores_authenticated_state (attribute_names,
                                                        attribute_values);
}

#if ENABLE_AGENTS
Ensure (gmp, scan_config_xml_decodes_excluded_path_backslash_pairs)
{
  const struct
  {
    const gchar *xml_path;
    const gchar *expected;
  } paths[] = {
    {"C:\\\\ProgramData\\\\Example\\\\Cache",
     "C:\\ProgramData\\Example\\Cache"},
    {"C:\\ProgramData\\Example\\Cache", "C:\\ProgramData\\Example\\Cache"},
    {"C:\\\\Cache\\\\", "C:\\Cache\\"},
    {"\\\\\\\\server\\\\share", "\\\\server\\share"},
    {"/opt/private", "/opt/private"},
    {"/var/lib/example/cache", "/var/lib/example/cache"},
    {"/tmp/\\n&<cache>", "/tmp/\\n&<cache>"},
  };

  for (guint i = 0; i < G_N_ELEMENTS (paths); ++i)
    {
      gchar *xml = g_markup_printf_escaped (
        "<config_defaults><agent_defaults>"
        "<file_search><excluded_paths is_list=\"1\"><item>%s</item>"
        "</excluded_paths></file_search>"
        "</agent_defaults></config_defaults>",
        paths[i].xml_path);
      entity_t root = NULL;
      assert_that (parse_entity (xml, &root), is_equal_to (0));
      g_free (xml);
      agent_controller_scan_agent_config_t cfg =
        agent_controller_scan_agent_config_new ();
      assert_that (build_scan_agent_config_from_entity (root, cfg),
                   is_equal_to (0));
      free_entity (root);

      GPtrArray *excluded_paths =
        cfg->agent_defaults->file_search.excluded_paths;
      assert_that (excluded_paths, is_not_null);
      assert_that (excluded_paths->len, is_equal_to (1));
      assert_that (g_ptr_array_index (excluded_paths, 0),
                   is_equal_to_string (paths[i].expected));

      gchar *payload = agent_controller_convert_scan_agent_config_string (cfg);
      assert_that (payload, is_not_null);
      if (i == 0)
        assert_that (payload, contains_string (
                                "\"C:\\\\ProgramData\\\\Example\\\\Cache\""));
      cJSON *json = cJSON_Parse (payload);
      assert_that (json, is_not_null);
      cJSON *defaults = cJSON_GetObjectItem (json, "agent_defaults");
      cJSON *file_search = cJSON_GetObjectItem (defaults, "file_search");
      cJSON *array = cJSON_GetObjectItem (file_search, "excluded_paths");
      assert_that (cJSON_GetArraySize (array), is_equal_to (1));
      cJSON *item = cJSON_GetArrayItem (array, 0);
      assert_that (item, is_not_null);
      assert_that (item->valuestring, is_equal_to_string (paths[i].expected));
      cJSON_Delete (json);
      cJSON_free (payload);
      agent_controller_scan_agent_config_free (cfg);
    }
}
#endif

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

#if ENABLE_AGENTS
  add_test_with_context
    (suite, gmp, scan_config_xml_decodes_excluded_path_backslash_pairs);
#endif

#if ENABLE_AD_INTEGRATION
  add_test_with_context
    (suite, gmp, create_ad_host_and_port_denial_responses);
  add_test_with_context
    (suite, gmp, modify_ad_host_and_port_denial_responses);
  add_test_with_context
    (suite, gmp, verify_inline_ad_host_and_port_denial_responses);
  add_test_with_context
    (suite, gmp, verify_stored_ad_destination_denial_response);
  add_test_with_context (suite, gmp, malformed_ad_host_responses);
  add_test_with_context (suite, gmp, ad_whitespace_fields_and_disabled_responses);
  add_test_with_context
    (suite, gmp, existing_ad_credential_error_responses_are_unchanged);
  add_test_with_context
    (suite, gmp, existing_ad_verification_error_responses_are_unchanged);
  add_test_with_context (suite, gmp, search_request_defaults);
  add_test_with_context (suite, gmp,
                         search_request_uses_configured_result_limit);
  add_test_with_context (suite, gmp, search_request_valid_options);
  add_test_with_context (suite, gmp, search_request_rejects_invalid_options);
  add_test_with_context (suite, gmp, search_ad_error_responses);
  add_test_with_context (suite, gmp, search_omits_unrequested_collections);
  add_test_with_context (suite, gmp, search_emits_requested_empty_collections);
#endif
  add_test_with_context
    (suite, gmp, completed_download_report_export_is_repeatable);
  add_test_with_context
    (suite, gmp, cancel_report_export_restores_authenticated_state);
  add_test_with_context
    (suite, gmp, create_report_config_restores_authenticated_state);
  add_test_with_context
    (suite, gmp, download_report_export_restores_authenticated_state);
  add_test_with_context
    (suite, gmp, export_audit_report_restores_authenticated_state);
  add_test_with_context
    (suite, gmp, export_delta_audit_report_restores_authenticated_state);
  add_test_with_context
    (suite, gmp, export_delta_scan_report_restores_authenticated_state);
  add_test_with_context
    (suite, gmp, export_scan_report_restores_authenticated_state);
  add_test_with_context
    (suite, gmp, missing_report_export_returns_not_found);
  add_test_with_context
    (suite, gmp, modify_permission_not_found_returns_not_found_response);
  add_test_with_context
    (suite, gmp, modify_report_config_restores_authenticated_state);
#if ENABLE_WEB_APPLICATION_SCANNING
  add_test_with_context
    (suite, gmp, modify_web_application_target_restores_authenticated_state);
#endif
#if ENABLE_CONTAINER_SCANNING
  add_test_with_context
    (suite, gmp, modify_oci_image_target_restores_authenticated_state);
#endif
  add_test_with_context
    (suite, gmp, move_task_with_empty_task_id_restores_authenticated_state);
  add_test_with_context
    (suite, gmp, move_task_without_slave_id_restores_authenticated_state);
  add_test_with_context
    (suite, gmp, move_task_without_task_id_restores_authenticated_state);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
