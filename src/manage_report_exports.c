/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: Report export to OSI.
 *
 * Implements report export from the GVM management layer to OSI.
 */

#include "manage_report_exports.h"

#include "gmp_base.h"
#include "manage.h"
#include "manage_filters.h"
#include "manage_settings.h"

#include <auth/gvm_auth.h>
#include <glib/gstdio.h>
#include <security_intelligence/security_intelligence.h>
#include <unistd.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Generate an OAuth2 access token.
 *
 * @param[in] config Integration config for report export.
 *
 * @return Raw access token without the "Bearer" prefix.
 *         Must be freed by the caller.
 */
static gchar *
generate_access_token (integration_config_data_t config)
{
  gvm_oauth2_new_err_t new_err = GVM_OAUTH2_NEW_ERR_INTERNAL_ERROR;
  gvm_oauth2_get_token_err_t token_err =
    GVM_OAUTH2_GET_TOKEN_ERR_INTERNAL_ERROR;
  gvm_oauth2_token_provider_t token_provider;
  char *access_token;
  gchar *token;

  token_provider =
    gvm_oauth2_token_provider_new (
      config->oidc_url,
      config->oidc_client_id,
      config->oidc_client_secret,
      "",
      30,
      &new_err);

  if (!token_provider)
    {
      g_debug ("%s: failed to initialize token provider, error: %d",
               __func__,
               new_err);
      return NULL;
    }

  access_token =
    gvm_oauth2_get_token (token_provider, &token_err);

  if (!access_token)
    {
      g_debug ("%s: failed to retrieve access token, error: %d",
               __func__,
               token_err);
      gvm_oauth2_token_provider_free (token_provider);
      return NULL;
    }

  token = g_strdup (access_token);

  gvm_auth_str_free (access_token);
  gvm_oauth2_token_provider_free (token_provider);

  return token;
}

/**
 * @brief Generate and assign an OAuth2 access token to a connector.
 *
 * @param[in,out] conn   Security Intelligence connector.
 * @param[in]     config Integration config for report export.
 *
 * @return TRUE on success, FALSE on failure.
 */
static gboolean
refresh_connector_access_token (security_intelligence_connector_t conn,
                                integration_config_data_t config)
{
  gchar *bearer_token;

  bearer_token = generate_access_token (config);
  if (!bearer_token)
    return FALSE;

  if (security_intelligence_connector_builder (
        conn,
        SECURITY_INTELLIGENCE_BEARER_TOKEN,
        bearer_token)
      != SECURITY_INTELLIGENCE_OK)
    {
      g_free (bearer_token);
      return FALSE;
    }

  g_free (bearer_token);
  return TRUE;
}

/**
 * @brief Initialize GET data for report result generation.
 *
 * @param[out] get          GET data to initialize.
 * @param[in] first_result  Zero-based result offset.
 * @param[in] max_results   Maximum number of results, or -1 for all results.
 *
 * @return 0 on success, -1 on invalid input or allocation failure.
 */
static int
init_report_export_get_data (get_data_t *get,
                             int first_result,
                             int max_results)
{
  if (!get || first_result < 0 || max_results == 0)
    return -1;

  memset (get, 0, sizeof (*get));

  get->details = 1;
  get->ignore_max_rows_per_page = 1;

  if (max_results < 0)
    {
      get->filter = g_strdup (
        "first=1 rows=-1 levels=chmlgf min_qod=0 "
        "sort=host apply_overrides=1");
    }
  else
    {
      get->filter = g_strdup_printf (
        "first=%d rows=%d levels=chmlgf min_qod=0 "
        "sort=host apply_overrides=1",
        first_result + 1,
        max_results);
    }

  return get->filter ? 0 : -1;
}

/**
 * @brief Initialize GET data for the outer GET_REPORTS response.
 *
 * This filter describes the outer report resource response. It is separate
 * from the result filter used inside the generated scan report.
 *
 * @param[out] get GET data to initialize.
 *
 * @return 0 on success, -1 on invalid input or allocation failure.
 */
static int
init_report_response_get_data (get_data_t *get)
{
  if (!get)
    return -1;

  memset (get, 0, sizeof (*get));

  get->details = 1;
  get->ignore_max_rows_per_page = 1;
  get->filter = g_strdup (
    "first=1 rows=1 sort=name apply_overrides=1 min_qod=0");

  return get->filter ? 0 : -1;
}

/**
 * @brief Cleanup GET data initialized by an export helper.
 *
 * @param[in,out] get GET data to clean up.
 */
static void
cleanup_report_export_get_data (get_data_t *get)
{
  if (!get)
    return;

  g_free (get->id);
  get->id = NULL;

  g_free (get->filter);
  get->filter = NULL;

  g_free (get->filter_replacement);
  get->filter_replacement = NULL;

  g_free (get->filt_id);
  get->filt_id = NULL;
}

/**
 * @brief Get the owner UUID and username for a report.
 *
 * @param[in]  report          Report.
 * @param[out] owner_uuid      Owner UUID. Must be freed by the caller.
 * @param[out] owner_username  Owner username. Must be freed by the caller.
 *
 * @return 0 on success, -1 if the owner cannot be resolved.
 */
static int
report_export_owner (report_t report,
                     gchar **owner_uuid,
                     gchar **owner_username)
{
  if (report == 0 || owner_uuid == NULL || owner_username == NULL)
    return -1;

  *owner_uuid = NULL;
  *owner_username = NULL;

  *owner_uuid = sql_string_ps (
    "SELECT users.uuid"
    " FROM reports"
    " JOIN users ON users.id = reports.owner"
    " WHERE reports.id = $1",
    SQL_RESOURCE_PARAM (report),
    NULL);

  if (*owner_uuid == NULL)
    return -1;

  *owner_username = sql_string_ps (
    "SELECT users.name"
    " FROM reports"
    " JOIN users ON users.id = reports.owner"
    " WHERE reports.id = $1",
    SQL_RESOURCE_PARAM (report),
    NULL);

  if (*owner_username == NULL)
    {
      g_free (*owner_uuid);
      *owner_uuid = NULL;
      return -1;
    }

  return 0;
}

/**
 * @brief Build the opening GET_REPORTS response and outer report metadata.
 *
 * It does not close the outer report or the response element.
 *
 * @param[in] report      Report.
 * @param[in] report_uuid Report UUID.
 *
 * @return Newly allocated XML buffer, or NULL on error.
 */
static GString *
build_get_reports_prefix_xml (report_t report,
                              const gchar *report_uuid)
{
  get_data_t report_get;
  iterator_t reports;
  report_t iterated_report = 0;
  GString *prefix = NULL;
  task_t task = 0;
  int iterator_initialized = 0;
  int ret;

  if (report == 0 || report_uuid == NULL)
    return NULL;

  memset (&report_get, 0, sizeof (report_get));

  report_get.id = g_strdup (report_uuid);
  report_get.details = 1;
  report_get.ignore_max_rows_per_page = 1;

  if (!report_get.id)
    goto cleanup;

  ret = init_report_iterator (&reports, &report_get);
  if (ret)
    {
      g_warning ("%s: Failed to initialize report iterator for %s: %d",
                 __func__,
                 report_uuid,
                 ret);
      goto cleanup;
    }

  iterator_initialized = 1;

  if (!next_report (&reports, &iterated_report)
      || iterated_report != report)
    {
      g_warning ("%s: Failed to iterate report %s",
                 __func__,
                 report_uuid);
      goto cleanup;
    }

  prefix = g_string_new ("");
  if (!prefix)
    goto cleanup;

  buffer_xml_append_printf (
    prefix,
    "<get_reports_response status=\"200\" status_text=\"OK\">"
    "<report"
    " id=\"%s\""
    " format_id=\"\""
    " config_id=\"\""
    " extension=\"\""
    " content_type=\"application/xml\">",
    report_iterator_uuid (&reports)
      ? report_iterator_uuid (&reports)
      : report_uuid);

  /*
   * Standard resource elements. This should remain aligned with
   * handle_get_reports().
   */
  buffer_xml_append_printf (
    prefix,
    "<owner><name>%s</name></owner>"
    "<name>%s</name>"
    "<comment>%s</comment>",
    get_iterator_owner_name (&reports)
      ? get_iterator_owner_name (&reports)
      : "",
    get_iterator_name (&reports)
      ? get_iterator_name (&reports)
      : "",
    get_iterator_comment (&reports)
      ? get_iterator_comment (&reports)
      : "");

  buffer_xml_append_printf (
    prefix,
    "<creation_time>%s</creation_time>",
    iso_if_time (get_iterator_creation_time (&reports)));

  buffer_xml_append_printf (
    prefix,
    "<modification_time>%s</modification_time>"
    "<writable>0</writable>"
    "<in_use>0</in_use>",
    iso_if_time (get_iterator_modification_time (&reports)));

  if (report_task (report, &task) == 0 && task)
    {
      gchar *task_uuid_value = NULL;
      gchar *task_name_value = NULL;

      task_uuid (task, &task_uuid_value);
      task_name_value = task_name (task);

      buffer_xml_append_printf (
        prefix,
        "<task id=\"%s\">"
        "<name>%s</name>"
        "</task>",
        task_uuid_value ? task_uuid_value : "",
        task_name_value ? task_name_value : "");

      g_free (task_uuid_value);
      g_free (task_name_value);
    }

cleanup:
  if (iterator_initialized)
    cleanup_iterator (&reports);

  cleanup_report_export_get_data (&report_get);
  return prefix;
}

/**
 * @brief Add a default filter keyword when it is missing.
 *
 * @param[in] filter        Existing cleaned filter.
 * @param[in] keyword       Keyword name.
 * @param[in] default_value Default keyword value.
 *
 * @return Newly allocated filter. The input filter is always freed.
 */
static gchar *
report_filter_add_default (gchar *filter,
                           const gchar *keyword,
                           int default_value)
{
  gchar *value;
  gchar *new_filter;

  if (!filter || !keyword)
    {
      g_free (filter);
      return NULL;
    }

  value = filter_term_value (filter, keyword);
  if (value)
    {
      g_free (value);
      return filter;
    }

  new_filter = g_strdup_printf (
    "%s=%d %s",
    keyword,
    default_value,
    filter);

  g_free (filter);
  return new_filter;
}

/**
 * @brief Build the GET_REPORTS response footer.
 *
 * @param[in] get       Outer report GET data.
 * @param[in] count     Number of reports in this response.
 * @param[in] filtered  Number of matching reports.
 * @param[in] full      Full report count represented by the response.
 *
 * @return Newly allocated XML buffer, or NULL on error.
 */
static GString *
build_get_reports_footer_xml (get_data_t *get,
                              int count,
                              int filtered,
                              int full)
{
  gchar *source_filter = NULL;
  gchar *clean_filter = NULL;
  gchar *sort_field = NULL;
  GString *footer = NULL;
  int first = 1;
  int max = 1;
  int sort_order = 1;

  if (!get)
    return NULL;

  if (get->filt_id
      && strcmp (get->filt_id, FILT_ID_NONE))
    {
      if (get->filter_replacement)
        source_filter = g_strdup (get->filter_replacement);
      else
        source_filter = filter_term (get->filt_id);

      if (!source_filter)
        return NULL;
    }
  else
    {
      source_filter = g_strdup (get->filter ? get->filter : "");
    }

  if (!source_filter)
    return NULL;

  manage_filter_controls (
    source_filter,
    &first,
    &max,
    &sort_field,
    &sort_order);

  max = manage_max_rows (
    max,
    get->ignore_max_rows_per_page);

  clean_filter = manage_clean_filter (
    source_filter,
    get->ignore_max_rows_per_page);

  g_free (source_filter);
  source_filter = NULL;

  if (!clean_filter)
    goto cleanup;

  clean_filter = report_filter_add_default (
    clean_filter,
    "min_qod",
    0);

  if (!clean_filter)
    goto cleanup;

  clean_filter = report_filter_add_default (
    clean_filter,
    "apply_overrides",
    1);

  if (!clean_filter)
    goto cleanup;

  footer = g_string_new ("");
  if (!footer)
    goto cleanup;

  buffer_get_filter_xml (
    footer,
    "report",
    get,
    clean_filter,
    NULL);

  buffer_xml_append_printf (
    footer,
    "<sort>"
    "<field>%s<order>%s</order></field>"
    "</sort>"
    "<reports start=\"%i\" max=\"%i\"/>",
    sort_field ? sort_field : "",
    sort_order ? "ascending" : "descending",
    first,
    max);

  buffer_xml_append_printf (
    footer,
    "<report_count>"
    "%i"
    "<filtered>%i</filtered>"
    "<page>%i</page>"
    "</report_count>",
    full,
    filtered,
    count);

  g_string_append (
    footer,
    "</get_reports_response>");

cleanup:
  g_free (source_filter);
  g_free (clean_filter);
  g_free (sort_field);

  return footer;
}

/**
 * @brief Get the next report page index.
 *
 * @param[in] pages Existing remote report pages.
 *
 * @return Next zero-based page index.
 */
static int
next_report_page_index (
  security_intelligence_managed_report_page_list_t pages)
{
  int max_index = -1;

  if (!pages)
    return 0;

  for (int i = 0; i < pages->count; ++i)
    {
      if (pages->pages[i]
          && pages->pages[i]->index > max_index)
        {
          max_index = pages->pages[i]->index;
        }
    }

  return max_index + 1;
}

/**
 * @brief Generate and upload one report page.
 *
 * @param[in]  conn         Security Intelligence connector.
 * @param[in]  report       Local report.
 * @param[in]  report_uuid  Report UUID.
 * @param[in]  page_index   Zero-based page index.
 * @param[out] errors       Optional Security Intelligence errors.
 *
 * @return TRUE on success, FALSE on failure.
 */
static gboolean
upload_report_page (security_intelligence_connector_t conn,
                    report_t report,
                    const gchar *report_uuid,
                    int page_index,
                    GPtrArray **errors)
{
  get_data_t result_get;
  get_data_t response_get;
  GError *error = NULL;
  gchar *xml_path = NULL;
  gchar *report_xml = NULL;
  GString *prefix_xml = NULL;
  GString *footer_xml = NULL;
  GString *response_xml = NULL;
  gsize report_xml_len = 0;
  int fd = -1;
  int first_result;
  gboolean result_get_initialized = FALSE;
  gboolean response_get_initialized = FALSE;
  gboolean success = FALSE;

  memset (&result_get, 0, sizeof (result_get));
  memset (&response_get, 0, sizeof (response_get));

  first_result =
    page_index * SECURITY_INTELLIGENCE_REPORT_PAGE_SIZE;

  if (init_report_export_get_data (
    &result_get,
    first_result,
    SECURITY_INTELLIGENCE_REPORT_PAGE_SIZE))
    {
      g_warning ("%s: Failed to initialize result GET data for page %d",
                 __func__,
                 page_index);
      goto cleanup;
    }

  result_get_initialized = TRUE;

  if (init_report_response_get_data (&response_get))
    {
      g_warning ("%s: Failed to initialize response GET data for page %d",
                 __func__,
                 page_index);
      goto cleanup;
    }

  response_get_initialized = TRUE;

  fd = g_file_open_tmp (
    "gvmd-report-export-XXXXXX.xml",
    &xml_path,
    &error);

  if (fd == -1)
    {
      g_warning ("%s: Failed to create temporary file: %s",
                 __func__,
                 error ? error->message : "unknown error");
      g_clear_error (&error);
      goto cleanup;
    }

  close (fd);
  fd = -1;

  if (manage_report_xml_page (
    report,
    &result_get,
    xml_path))
    {
      g_warning ("%s: Failed to generate XML for report %lld, page %d",
                 __func__,
                 report,
                 page_index);
      goto cleanup;
    }

  if (!g_file_get_contents (
    xml_path,
    &report_xml,
    &report_xml_len,
    &error))
    {
      g_warning ("%s: Failed to read generated XML for report %s,"
                 " page %d: %s",
                 __func__,
                 report_uuid,
                 page_index,
                 error ? error->message : "unknown error");
      g_clear_error (&error);
      goto cleanup;
    }

  prefix_xml = build_get_reports_prefix_xml (
    report,
    report_uuid);

  if (!prefix_xml)
    {
      g_warning ("%s: Failed to build GET_REPORTS prefix for report %s,"
                 " page %d",
                 __func__,
                 report_uuid,
                 page_index);
      goto cleanup;
    }

  /*
   * Each uploaded page represents one outer report resource.
   */
  footer_xml = build_get_reports_footer_xml (
    &response_get,
    1,
    1,
    1);

  if (!footer_xml)
    {
      g_warning ("%s: Failed to build GET_REPORTS footer for report %s,"
                 " page %d",
                 __func__,
                 report_uuid,
                 page_index);
      goto cleanup;
    }

  response_xml = g_string_sized_new (
    prefix_xml->len
    + report_xml_len
    + strlen ("</report></report>")
    + footer_xml->len);

  /*
   * Outer response and outer report metadata
   */
  g_string_append_len (
    response_xml,
    prefix_xml->str,
    prefix_xml->len);

  /*
   * Inner scan report generated by manage_report_xml_page()
   */
  g_string_append_len (
    response_xml,
    report_xml,
    report_xml_len);

  /*
   * Close the inner scan report and then the outer report resource.
   */
  g_string_append (
    response_xml,
    "</report></report>");

  /*
   * Append filters, sorting, report counts, and close
   * get_reports_response.
   */
  g_string_append_len (
    response_xml,
    footer_xml->str,
    footer_xml->len);

  if (security_intelligence_add_report_page (
        conn,
        report_uuid,
        page_index,
        (const guint8 *) response_xml->str,
        response_xml->len,
        errors)
      != SECURITY_INTELLIGENCE_RESP_OK)
    {
      g_warning ("%s: Failed to upload report %s page %d",
                 __func__,
                 report_uuid,
                 page_index);
      goto cleanup;
    }

  success = TRUE;

cleanup:
  if (fd != -1)
    close (fd);

  if (xml_path)
    {
      g_unlink (xml_path);
      g_free (xml_path);
    }

  if (response_xml)
    g_string_free (response_xml, TRUE);

  if (footer_xml)
    g_string_free (footer_xml, TRUE);

  if (prefix_xml)
    g_string_free (prefix_xml, TRUE);

  g_free (report_xml);

  if (response_get_initialized)
    cleanup_report_export_get_data (&response_get);

  if (result_get_initialized)
    cleanup_report_export_get_data (&result_get);

  return success;
}

/**
 * @brief Export a single report to Security Intelligence.
 *
 * Handles both new exports and retries. Existing remote pages are preserved,
 * and uploading continues from the next page index.
 *
 * @param[in] report Local report.
 * @param[in] config Security Intelligence integration configuration.
 *
 * @return EXPORT_REPORT_RESULT_SUCCESS on success,
 *         EXPORT_REPORT_RESULT_TIMEOUT when a request times out,
 *         EXPORT_REPORT_RESULT_TOKEN_GENERATION_FAILED when an access token
 *         cannot be generated,
 *         EXPORT_REPORT_RESULT_FAILURE on any other failure.
 */
export_report_result_t
export_report_security_intelligence (report_t report,
                                     integration_config_data_t config)
{
  export_report_result_t result = EXPORT_REPORT_RESULT_FAILURE;
  security_intelligence_connector_t conn = NULL;
  security_intelligence_managed_report_t remote_report = NULL;
  security_intelligence_managed_report_page_list_t remote_pages = NULL;
  GPtrArray *errors = NULL;
  get_data_t count_get;
  gboolean count_get_initialized = FALSE;
  gchar *report_id = NULL;
  gchar *owner_uuid = NULL;
  gchar *owner_username = NULL;
  int result_count = 0;
  int total_pages;
  int next_page;

  memset (&count_get, 0, sizeof (count_get));

  g_debug ("%s: Exporting report %lld",
           __func__,
           report);

  report_id = report_uuid (report);
  if (!report_id)
    {
      g_warning ("%s: Failed to get UUID for report %lld",
                 __func__,
                 report);
      goto cleanup;
    }

  if (report_export_owner (
    report,
    &owner_uuid,
    &owner_username))
    {
      g_warning ("%s: Failed to resolve owner for report %s",
                 __func__,
                 report_id);
      goto cleanup;
    }

  /*
   * This function runs in a dedicated forked export process. Therefore,
   * restoration of a previous user context is not required.
   */
  current_credentials.uuid = owner_uuid;
  current_credentials.username = owner_username;

  manage_session_init (current_credentials.uuid);

  g_debug ("%s: Exporting report %s as user %s",
           __func__,
           report_id,
           owner_username);

  conn = security_intelligence_connector_new ();
  if (!conn)
    {
      g_warning ("%s: Failed to create Security Intelligence connector",
                 __func__);
      goto cleanup;
    }

  if (security_intelligence_connector_builder (
        conn,
        SECURITY_INTELLIGENCE_URL,
        config->service_url)
      != SECURITY_INTELLIGENCE_OK)
    {
      g_warning ("%s: Failed to configure Security Intelligence URL",
                 __func__);
      goto cleanup;
    }

  if (config->service_cacert
      && security_intelligence_connector_builder (
        conn,
        SECURITY_INTELLIGENCE_CA_CERT,
        config->service_cacert)
      != SECURITY_INTELLIGENCE_OK)
    {
      g_warning ("%s: Failed to configure Security Intelligence CA",
                 __func__);
      goto cleanup;
    }

  if (!refresh_connector_access_token (conn, config))
    {
      result = EXPORT_REPORT_RESULT_TOKEN_GENERATION_FAILED;
      goto cleanup;
    }

  remote_report =
    security_intelligence_get_report (
      conn,
      report_id,
      &errors);

  if (!remote_report)
    {
      if (errors)
        {
          g_ptr_array_free (errors, TRUE);
          errors = NULL;
        }

      g_debug ("%s: Remote report %s not found, creating it",
               __func__,
               report_id);

      if (security_intelligence_create_report (
            conn,
            report_id,
            &remote_report,
            &errors)
          != SECURITY_INTELLIGENCE_RESP_OK)
        {
          g_warning ("%s: Failed to create remote report %s",
                     __func__,
                     report_id);
          goto cleanup;
        }
    }

  if (!remote_report)
    {
      g_warning ("%s: Missing remote report after creation",
                 __func__);
      goto cleanup;
    }

  if (remote_report->upload_status
      == SECURITY_INTELLIGENCE_REPORT_UPLOAD_STATUS_COMPLETED)
    {
      g_debug ("%s: Report %s is already completed",
               __func__,
               report_id);
      result = EXPORT_REPORT_RESULT_SUCCESS;
      goto cleanup;
    }

  if (remote_report->upload_status
      != SECURITY_INTELLIGENCE_REPORT_UPLOAD_STATUS_STARTED)
    {
      if (security_intelligence_update_report_status (
            conn,
            report_id,
            SECURITY_INTELLIGENCE_REPORT_UPLOAD_STATUS_STARTED,
            &errors)
          != SECURITY_INTELLIGENCE_RESP_OK)
        {
          g_warning ("%s: Failed to mark report %s as started",
                     __func__,
                     report_id);
          goto cleanup;
        }
    }

  /*
   * Use the same result filter for counting and page generation.
   */
  if (init_report_export_get_data (
    &count_get,
    0,
    -1))
    {
      g_warning ("%s: Failed to initialize report count GET data",
                 __func__);
      goto cleanup;
    }

  count_get_initialized = TRUE;

  if (manage_report_result_count (
    report,
    &count_get,
    &result_count))
    {
      g_warning ("%s: Failed to count results for report %s",
                 __func__,
                 report_id);
      goto cleanup;
    }

  cleanup_report_export_get_data (&count_get);
  count_get_initialized = FALSE;

  /*
   * Generate one page for an empty report so that report-level metadata is
   * still uploaded.
   */
  total_pages =
    result_count > 0
      ? (result_count
         + SECURITY_INTELLIGENCE_REPORT_PAGE_SIZE
         - 1)
        / SECURITY_INTELLIGENCE_REPORT_PAGE_SIZE
      : 1;

  remote_pages =
    security_intelligence_get_report_pages (
      conn,
      report_id,
      &errors);

  if (!remote_pages)
    {
      g_warning ("%s: Failed to get pages for report %s",
                 __func__,
                 report_id);
      goto cleanup;
    }

  next_page = next_report_page_index (remote_pages);

  if (next_page > total_pages)
    {
      g_warning (
        "%s: Remote report %s has %d pages, but only %d are expected",
        __func__,
        report_id,
        next_page,
        total_pages);
      goto cleanup;
    }

  g_debug (
    "%s: Report %s has %d results and %d pages;"
    " continuing from page %d",
    __func__,
    report_id,
    result_count,
    total_pages,
    next_page);

  for (int page_index = next_page;
       page_index < total_pages;
       ++page_index)
    {
      g_debug ("%s: Uploading report %s page %d of %d",
               __func__,
               report_id,
               page_index + 1,
               total_pages);

      if (!upload_report_page (
        conn,
        report,
        report_id,
        page_index,
        &errors))
        {
          goto cleanup;
        }
    }

  if (security_intelligence_update_report_status (
        conn,
        report_id,
        SECURITY_INTELLIGENCE_REPORT_UPLOAD_STATUS_COMPLETED,
        &errors)
      != SECURITY_INTELLIGENCE_RESP_OK)
    {
      g_warning ("%s: Failed to complete remote report %s",
                 __func__,
                 report_id);
      goto cleanup;
    }

  result = EXPORT_REPORT_RESULT_SUCCESS;

cleanup:
  if (result != EXPORT_REPORT_RESULT_SUCCESS && errors)
    {
      for (guint i = 0; i < errors->len; ++i)
        {
          const gchar *message;

          message = g_ptr_array_index (errors, i);

          g_warning ("%s: Security Intelligence error: %s",
                     __func__,
                     message ? message : "unknown error");
        }
    }

  if (count_get_initialized)
    cleanup_report_export_get_data (&count_get);

  if (errors)
    g_ptr_array_free (errors, TRUE);

  security_intelligence_managed_report_page_list_free (remote_pages);
  security_intelligence_managed_report_free (remote_report);
  security_intelligence_connector_free (conn);

  g_free (owner_uuid);
  g_free (owner_username);
  g_free (report_id);

  return result;
}
