/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Implementation of web application scanner management
 *        functions for GVMD.
 */

#if ENABLE_WEB_APPLICATION_SCANNING

#include "debug_utils.h"
#include "manage_assets.h"
#include "manage_web_application_scanner.h"
#include "manage_report_exports.h"
#include "manage_runtime_flags.h"
#include "manage_sql.h"
#include "manage_sql_web_application_targets.h"
#include "manage_openvas.h"
#include "manage_osp.h"
#include <sys/types.h>
#include <bsd/unistd.h>
#include <unistd.h>

#include <gvm/base/gvm_sentry.h>
#include <gvm/web_application_scanner/web_application_scanner.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

#define WEB_APPLICATION_SCAN_PREFIX "api/v1"

/**
 * @brief Create a new connection to a web application scanner.
 *
 * @param[in]   scanner      Scanner.
 * @param[in]   scan_id      scan uuid.
 *
 * @return New connection if success, NULL otherwise.
 *         The connection has to be freed by the caller.
 */
http_scanner_connector_t
web_application_scanner_connect (scanner_t scanner, const char *scan_id)
{
  http_scanner_connector_t connection;

  connection = http_scanner_connect (scanner, scan_id);

  if (connection)
    http_scanner_connector_builder (connection,
                                    HTTP_SCANNER_SCAN_PREFIX,
                                    WEB_APPLICATION_SCAN_PREFIX);
  else
    g_warning ("%s: Could not connect to web application scanner", __func__);

  return connection;
}

/**
 * @brief Get a severity string from result type.
 *
 * @param[in]  type     Result type.
 *
 * @return A severity string, NULL if unknown type.
 */
char *
web_application_nvt_severity (const char *type)
{
  char *severity = NULL;

  if ((strcasecmp (type, "alarm") == 0 || strcasecmp (type, "Alarm") == 0))
    severity = g_strdup (G_STRINGIFY (SEVERITY_MAX));
  else if (strcasecmp (type, "Log Message") == 0
           || strcasecmp (type, "log") == 0)
    severity = g_strdup (G_STRINGIFY (SEVERITY_LOG));
  else if (strcasecmp (type, "Error Message") == 0
           || strcasecmp (type, "error") == 0)
    severity = g_strdup (G_STRINGIFY (SEVERITY_ERROR));
  else
    g_warning ("Invalid result nvt type %s", type);
  return severity;
}

/**
 * @brief Get the credential of a web application target as
 *        scan_credential_t.
 *
 * @param[in]  target  The web application target to get the credential from.
 *
 * @return  Pointer to a newly allocated scan_credential_t.
 */
scan_credential_t *
web_application_scanner_target_credential (web_application_target_t target)
{
  credential_t credential;
  credential = web_application_target_credential (target);
  if (credential)
    {
      iterator_t iter;
      scan_credential_t *scan_credential;

      init_credential_iterator_one (&iter, credential);
      if (!next (&iter))
        {
          g_warning ("%s: Credential not found.", __func__);
          cleanup_iterator (&iter);
          return NULL;
        }
      if (strcmp (credential_iterator_type (&iter), "up"))
        {
          g_warning ("%s: Credential not a user/pass pair.", __func__);
          cleanup_iterator (&iter);
          return NULL;
        }

      scan_credential
        = scan_credential_new ("up", "generic", NULL);

      scan_credential_set_auth_data (
        scan_credential,
        "username",
        credential_iterator_login (&iter)
      );

      scan_credential_set_auth_data (
        scan_credential,
        "password",
        credential_iterator_password (&iter)
      );

      cleanup_iterator (&iter);
      return scan_credential;
    }
  g_warning ("%s: No credential assigned to target.", __func__);
  return NULL;
}

/**
 * @brief Generate the hash value for the fields of the result and
 * check if web application scanner result for report already exists
 *
 * @param[in]  report      Report.
 * @param[in]  task        Task.
 * @param[in]  r_entity    entity of the result.
 * @param[out] entity_hash_value  The generated hash value of r_entity.
 *
 * @return     "1" if web application scanner result already exists, else "0"
 */
static int
check_web_application_scanner_result_exists (report_t report,
                                             task_t task,
                                             http_scanner_result_t res,
                                             char **entity_hash_value,
                                             GHashTable *hashed_results)
{
  GString *result_string;
  int return_value = 0;
  result_string = g_string_new ("");
  g_string_append_printf (result_string, "host:%s\n"
                          "hostname:%s\n"
                          "type:%s\n"
                          "description:%s\n"
                          "port:%s\n"
                          "oid:%s",res->ip_address, res->hostname,
                          res->type, res->message, res->port, res->oid);

 *entity_hash_value = get_md5_hash_from_string (result_string->str);
  if (g_hash_table_contains (hashed_results, *entity_hash_value))
    {
      return_value = 1;
    }
  else
    {
      g_hash_table_insert (hashed_results,
                           g_strdup(*entity_hash_value),
                           GINT_TO_POINTER(1));
      if (sql_int ("SELECT EXISTS"
                   " (SELECT * FROM results"
                   "  WHERE report = %llu and hash_value = '%s');",
                   report, *entity_hash_value))
        {
          const char *desc, *type, *severity = NULL, *host = NULL;
          const char *hostname, *port = NULL;
          gchar *quoted_desc, *quoted_type, *quoted_host;
          gchar *quoted_hostname, *quoted_port;
          double severity_double = 0.0;
          int qod_int = QOD_DEFAULT;

          host = res->ip_address;
          hostname = res->hostname;
          type = convert_http_scanner_type_to_osp_type(res->type);
          desc = res->message;
          severity = web_application_nvt_severity (type);
          port = res->port;

          if (!severity)
            {
              g_debug ("%s: Result without severity", __func__);
              g_string_free (result_string, TRUE);
              return 0;
            }
          else
            {
              severity_double = strtod (severity, NULL);
            }

          quoted_host = sql_quote (host ?: "");
          quoted_hostname = sql_quote (hostname ?: "");
          quoted_type = sql_quote (type ?: "");
          quoted_desc = sql_quote (desc ?: "");
          quoted_port = sql_quote (port ?: "");

          if (sql_int ("SELECT EXISTS"
                       " (SELECT * FROM results"
                       "   WHERE report = %llu and hash_value = '%s'"
                       "    and host = '%s' and hostname = '%s'"
                       "    and type = '%s' and description = '%s'"
                       "    and port = '%s' and severity = %1.1f::real"
                       "    and qod = %d"
                       " );",
                       report, *entity_hash_value,
                       quoted_host, quoted_hostname,
                       quoted_type, quoted_desc,
                       quoted_port, severity_double,
                       qod_int))
            {
              g_info ("Captured duplicate result, report: %llu hash_value: %s",
                      report, *entity_hash_value);
              g_debug ("Entity string: %s", result_string->str);
              return_value = 1;
            }

          g_free (quoted_host);
          g_free (quoted_hostname);
          g_free (quoted_type);
          g_free (quoted_desc);
          g_free (quoted_port);
        }
    }
  if (return_value)
    {
      g_debug ("Captured duplicate result, report: %llu hash_value: %s",
                report, *entity_hash_value);
      g_debug ("Entity string: %s", result_string->str);
    }
  g_string_free (result_string, TRUE);
  return return_value;
}

/**
 * @brief Add a container image scan result to a report.
 *
 * @param[in]      res           The container image scan result.
 * @param[in,out]  results_aux   Auxiliary data, a pointer to struct
 *                               report_aux.
 */
static void
add_web_application_scan_result (http_scanner_result_t res,
                                 gpointer *results_aux)
{

  struct report_aux *rep_aux = *results_aux;
  result_t result;
  char *type, *host, *hostname, *test_id;
  char *port = NULL, *desc = NULL;

  type = res->type;
  test_id = res->oid;
  host = res->ip_address;
  hostname = res->hostname ?: "";
  port = res->port;
  desc = res->message;

  if (host)
    manage_report_host_add (rep_aux->report, host, 0, 0);

  if (strcmp (type, "host_detail") == 0)
    {
      gchar *hash_value = NULL;
      if (!check_host_detail_exists (rep_aux->report, host,
                                     res->detail_source_type,
                                     res->detail_source_name,
                                     res->detail_source_description,
                                     res->detail_name,
                                     res->detail_value,
                                     &hash_value,
                                     rep_aux->hash_hostdetails))
        {
          insert_report_host_detail (rep_aux->report, host,
                                     res->detail_source_type,
                                     res->detail_source_name,
                                     res->detail_source_description,
                                     res->detail_name,
                                     res->detail_value,
                                     hash_value);
        }
      g_free (hash_value);
    }
  else if (host && desc && strcmp (type, "host_start") == 0)
    {
      set_scan_host_start_time_ctime (rep_aux->report, host, desc);
    }
  else if (host && desc && strcmp (type, "host_end") == 0)
    {
      set_scan_host_end_time_ctime (rep_aux->report, host, desc);
    }
  else
    {
      char *nvt_id = NULL, *severity_str = NULL;
      char *hash_value, *result_type;
      int qod_int;

      nvt_id = g_strdup (test_id);
      result_type = convert_http_scanner_type_to_osp_type (type);
      severity_str = web_application_nvt_severity (result_type);
      qod_int = QOD_DEFAULT;

      if (!check_web_application_scanner_result_exists (rep_aux->report,
                                                        rep_aux->task,
                                                        res, &hash_value,
                                                        rep_aux->hash_results))
        {
          result = make_osp_result (rep_aux->task,
                                    host ?: "",
                                    hostname ?: "",
                                    nvt_id ?: NULL,
                                    result_type ?: "",
                                    desc ?: "",
                                    port ?: "",
                                    severity_str ?: NULL,
                                    qod_int,
                                    NULL,
                                    hash_value);
          g_array_append_val (rep_aux->results_array, result);
        }
      g_free (hash_value);
      g_free (severity_str);
      g_free (result_type);
      g_free (nvt_id);
    }

  return;
}

/**
 * @brief Parse container image scan results.
 *
 * @param[in]  task        Task.
 * @param[in]  report      Report.
 * @param[in]  results     container image scan results.
 */
static void
parse_web_application_scan_report (task_t task,
                                   report_t report,
                                   GSList *results,
                                   time_t start_time,
                                   time_t end_time)
{
  GArray *results_array = NULL;
  GHashTable *hashed_scanner_results = NULL;
  GHashTable *hashed_host_details = NULL;
  struct report_aux *rep_aux;

  assert (task);
  assert (report);

  sql_begin_immediate ();

  /* Set the report's start and end times. */
  if (start_time)
    set_scan_start_time_epoch (report, start_time);

  if (end_time)
    set_scan_end_time_epoch (report, end_time);

  if (results == NULL)
    {
      sql_commit ();
      return;
    }

  hashed_scanner_results = g_hash_table_new_full (g_str_hash,
                                          g_str_equal,
                                          g_free,
                                          NULL);
  hashed_host_details = g_hash_table_new_full (g_str_hash,
                                               g_str_equal,
                                               g_free,
                                               NULL);

  results_array = g_array_new(TRUE, TRUE, sizeof(result_t));
  rep_aux = g_malloc0 (sizeof (struct report_aux));
  rep_aux->report = report;
  rep_aux->task = task;
  rep_aux->results_array = results_array;
  rep_aux->hash_results = hashed_scanner_results;
  rep_aux->hash_hostdetails = hashed_host_details;

  g_slist_foreach(results,
                  (GFunc) add_web_application_scan_result,
                  &rep_aux);

  if (results_array->len > 0)
    {
      sql ("UPDATE reports SET modification_time = m_now() WHERE id = %llu;",
           report);
      report_add_results_array (report, results_array);
    }

  sql_commit ();
  if (results_array && results_array->len > 0)
    g_array_free (results_array, TRUE);

  g_hash_table_destroy (hashed_scanner_results);
  g_hash_table_destroy (hashed_host_details);
  g_free (rep_aux);
}

/**
 * @brief Prepare a report for resuming a container image scan.
 *
 * @param[in]  task     The task of the scan.
 * @param[in]  scan_id  The scan uuid.
 * @param[out] error    Error return.
 *
 * @return 0 scan finished or still running,
 *         1 scan must be started,
 *         -1 error
 */
int
prepare_web_application_scan_for_resume (task_t task, const char *scan_id,
                                         char **error)
{
  http_scanner_connector_t connection;
  int ret;

  assert (task);
  assert (scan_id);
  assert (global_current_report);
  assert (error);

  connection = web_application_scanner_connect (task_scanner (task), scan_id);
  if (connection == NULL)
    {
      *error = g_strdup ("Could not connect to web application Scanner");
      return -1;
    }

  g_debug ("%s: Preparing scan %s for resume", __func__, scan_id);

  ret = prepare_http_scanner_scan_for_resume (connection, error);

  if (ret == 1)
    trim_partial_report (global_current_report);

  http_scanner_connector_free (connection);

  return ret;
}

/**
 * @brief Launch web application scanning task.
 *
 * @param[in]   task              The task.
 * @param[in]   web_application_target  The web application target.
 * @param[in]   scan_id           The scan uuid.
 * @param[in]   from              0 start from beginning,
 *                                1 continue from stopped,
 *                                2 continue if stopped else start from
 *                                  beginning.
 * @param[out]  error             Error return.
 *
 * @return 0 on success, -1 if error.
 */
static int
launch_web_application_task (task_t task,
                             web_application_target_t web_application_target,
                             const char *scan_id,
                             int from,
                             char **error)
{
  http_scanner_connector_t connection;
  char *urls_str, *finished_urls_str, *exclude_urls_str;
  web_scanner_target_t *web_scanner_target;
  scan_credential_t *target_credential;
  GHashTable *scanner_options;
  http_scanner_resp_t response;
  int ret;

  connection = NULL;
  finished_urls_str = NULL;

  /* Prepare the report */
  if (from)
    {
      ret = prepare_web_application_scan_for_resume (task, scan_id, error);
      if (ret == 0)
        return 0;
      else if (ret == -1)
        return -1;
      finished_urls_str = report_finished_hosts_str (global_current_report);
    }

  urls_str = web_application_target_urls (web_application_target);
  exclude_urls_str = web_application_target_exclude_urls (web_application_target);

  GString *target_exclude_urls
    = g_string_new (exclude_urls_str ? exclude_urls_str : "");

  if (finished_urls_str != NULL && strlen (finished_urls_str) > 0)
    {
      g_string_append_printf (target_exclude_urls,
                              "%s%s",
                              exclude_urls_str
                                && strlen (exclude_urls_str) > 0 ? "," : "",
                              finished_urls_str);
    }

  web_scanner_target = web_scanner_target_new (scan_id, urls_str,
                                               target_exclude_urls->str);

  g_string_free (target_exclude_urls, TRUE);
  free (exclude_urls_str);
  free (finished_urls_str);
  free (urls_str);

  target_credential = web_application_scanner_target_credential (web_application_target);

  if (target_credential)
      web_scanner_target_add_credential (web_scanner_target, target_credential);
  else
    g_warning ("%s: No credential assigned to target.", __func__);

  /* Setup scanner preferences. */
  scanner_options
    = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);

  /* No scanner preferences for now. An empty list is sent */

  connection = web_application_scanner_connect (task_scanner (task), scan_id);
  if (!connection)
    {
      if (error)
        *error = g_strdup ("Could not connect to Scanner");
      web_scanner_target_free (web_scanner_target);
      g_hash_table_destroy (scanner_options);
      return -1;
    }

  gchar *scan_config = NULL;
  scan_config =
    web_scanner_build_scan_config_json (web_scanner_target,
                                        scanner_options,
                                        NULL);  /* vts are sent as an empty list for now */

  response = http_scanner_create_scan (connection, scan_config);

  if (response->code != 201)
    {
      g_warning ("%s: Failed to create scan: %ld", __func__, response->code);
      web_scanner_target_free (web_scanner_target);
      g_hash_table_destroy (scanner_options);
      http_scanner_response_cleanup (response);
      return -1;
    }

  http_scanner_response_cleanup (response);
  response = http_scanner_start_scan (connection);

  if (response->code != 204)
    {
      g_warning ("%s: Failed to start scan: %ld", __func__, response->code);
      web_scanner_target_free (web_scanner_target);
      g_hash_table_destroy (scanner_options);
      http_scanner_response_cleanup (response);
      return -1;
    }

  web_scanner_target_free (web_scanner_target);
  g_hash_table_destroy (scanner_options);
  http_scanner_response_cleanup (response);
  http_scanner_connector_free (connection);

  return 0;
}

/**
 * @brief Handle a container image scan, until success or failure.
 *
 * @param[in]   task      The task.
 * @param[in]   report    The report.
 * @param[in]   scan_id   The UUID of the scan on the scanner.
 *
 * @return 0 if success, -1 if error, -2 if scan was stopped,
 *         -3 if the scan was interrupted, -4 already stopped.
 */
static int
handle_web_application_scan (task_t task,
                             report_t report,
                             const char *scan_id)
{
  scanner_t scanner;
  http_scanner_connector_t connector;
  http_scanner_resp_t response = NULL;
  int rc;

  scanner = task_scanner (task);
  connector = web_application_scanner_connect (scanner, scan_id);

  if (connector == NULL)
    {
      g_warning ("%s: Could not connect to web application scanner", __func__);
      return -1;
    }

  gboolean started, queued_status_updated;
  int retry, connection_retry;

  if (connector == NULL)
    {
      g_warning ("%s: Could not connect to web application scanner", __func__);
      return -1;
    }

  task_status_t task_status = task_run_status (task);
  started = (task_status == TASK_STATUS_RUNNING);
  queued_status_updated = started || (task_status == TASK_STATUS_QUEUED);
  connection_retry = get_scanner_connection_retry ();

  retry = connection_retry;
  rc = -1;
  while (retry >= 0)
    {
      int run_status;

      run_status = task_run_status (task);
      if (run_status == TASK_STATUS_STOPPED
          || run_status == TASK_STATUS_STOP_REQUESTED)
        {
          rc = -4;
          break;
        }

      rc = update_http_scanner_scan (connector, task, report,
                                     parse_web_application_scan_report, &retry,
                                     &queued_status_updated, &started);

      if (rc <= 0)
        break;

      if (rc != 1)
        {
          retry = connection_retry;
          gvm_sleep (5);
        }
    }

  http_scanner_response_cleanup (response);
  http_scanner_connector_free (connector);

  return rc;
}

/**
 * @brief Handle the start of a web application scan.
 *
 * @param[in]   task      The task.
 * @param[in]   target    The web application target.
 * @param[in]   report_id The UUID of the report on the scanner.
 * @param[in]   from      0 start from beginning, 1 continue from stopped,
 *                         2 continue if stopped else start from beginning.
 *
 * @return 0 if success, -1 if error.
 */

int
handle_web_application_scan_start (task_t task,
                                   web_application_target_t target,
                                   char *report_id,
                                   int from)
{
  int rc;
  char *error = NULL;

  rc = launch_web_application_task (task, target, report_id, from, &error);

  if (rc < 0)
    {
      result_t result;

      g_warning ("web application scanner start_scan %s: %s", report_id, error);
      result = make_osp_result (task, "", "", "",
                                threat_message_type ("Error"),
                                error, "", "", QOD_DEFAULT, NULL, NULL);
      report_add_result (global_current_report, result);

      set_task_run_status (task, TASK_STATUS_DONE);
      set_report_scan_run_status (global_current_report, TASK_STATUS_DONE);

      set_task_end_time_epoch (task, time (NULL));
      set_scan_end_time_epoch (global_current_report, time (NULL));

      g_free (error);
      return -1;
    }

  return 0;
}

/**
 * @brief Handle the end of a web application scan.
 *
 * @param[in]   task              The task.
 * @param[in]   handle_progress_rc The return code from handling the scan
 *                                 progress.
 *
 * @return The input return code.
 */
int
handle_web_application_scan_end (task_t task, int handle_progress_rc)
{
  if (handle_progress_rc >= 0)
    {
      set_task_run_status (task, TASK_STATUS_PROCESSING);
      set_report_scan_run_status (global_current_report,
                                  TASK_STATUS_PROCESSING);

      set_task_run_status (task, TASK_STATUS_DONE);
      set_report_scan_run_status (global_current_report, TASK_STATUS_DONE);
      if (feature_enabled (FEATURE_ID_SECURITY_INTELLIGENCE_EXPORT))
        {
          queue_report_for_export (global_current_report);
        }
    }
  else if (handle_progress_rc == -1 || handle_progress_rc == -2)
    {
      set_task_run_status (task, TASK_STATUS_STOPPED);
      set_report_scan_run_status (global_current_report, TASK_STATUS_STOPPED);
    }
  else if (handle_progress_rc == -3)
    {
      set_task_run_status (task, TASK_STATUS_INTERRUPTED);
      set_report_scan_run_status (global_current_report,
                                  TASK_STATUS_INTERRUPTED);
    }

  set_task_end_time_epoch (task, time (NULL));
  set_scan_end_time_epoch (global_current_report, time (NULL));
  global_current_report = 0;
  current_scanner_task = (task_t) 0;

  return handle_progress_rc;
}

/**
 * @brief Fork a child to handle a web application scan's
 *        fetching and inserting.
 *
 * @param[in]   task                     The task.
 * @param[in]   web_application_target   The web application target.
 * @param[in]   from                     0 start from beginning,
 *                                       1 continue from stopped,
 *                                       2 continue if stopped else
 *                                         start from beginning.
 * @param[out]  report_id_return         UUID of the report.
 *
 * @return Parent returns with 0 if success, -1 if failure. Child process
 *         doesn't return and simply exits.
 */
static int
fork_web_application_scan_handler (task_t task,
                                   web_application_target_t web_application_target,
                                   int from,
                                   char **report_id_return)
{
  char *report_id;
  int rc;

  assert (task);
  assert (web_application_target);

  if (report_id_return)
    *report_id_return = NULL;

  if (run_osp_scan_get_report (task, from, &report_id))
    return -1;

  current_scanner_task = task;
  set_task_run_status (task, TASK_STATUS_REQUESTED);

  switch (fork ())
    {
      case 0:
        init_sentry ();
        break;
      case -1:
        /* Parent, failed to fork. */
        global_current_report = 0;
        g_warning ("%s: Failed to fork: %s",
                   __func__,
                   strerror (errno));
        set_task_interrupted (task,
                              "Error forking scan handler."
                              "  Interrupting scan.");
        set_report_scan_run_status (global_current_report,
                                    TASK_STATUS_INTERRUPTED);
        global_current_report = (report_t) 0;
        current_scanner_task = 0;
        g_free (report_id);
        return -9;
      default:
        /* Parent, successfully forked. */
        global_current_report = 0;
        current_scanner_task = 0;
        if (report_id_return)
          *report_id_return = report_id;
        else
          g_free (report_id);
        return 0;
    }

  /* Child: Re-open DB after fork and periodically check scan progress.
   * If progress == 100%: Parse the report results and other info then exit(0).
   * Else, exit(1) in error cases like connection to scanner failure.
   */
  reinit_manage_process ();
  manage_session_init (current_credentials.uuid);

  if (handle_web_application_scan_start (task, web_application_target, report_id, from))
    {
      g_free (report_id);
      gvm_close_sentry ();
      exit (-1);
    }

  setproctitle ("web application scanner: Handling scan %s", report_id);

  g_info ("%s: Handling web application scan %s", __func__, report_id);

  rc = handle_web_application_scan (task, global_current_report, report_id);

  g_free (report_id);

  rc = handle_web_application_scan_end (task, rc);

  gvm_close_sentry ();
  exit (rc);
}

/**
 * @brief Start a task on web application scanner.
 *
 * @param[in]   task       The task.
 * @param[in]   from       0 start from beginning, 1 continue from stopped,
 *                         2 continue if stopped else start from beginning.
 * @param[out]  report_id  The report ID.
 *
 * @return 0 success, 99 permission denied, -1 error.
 */
int
run_web_application_task (task_t task, int from, char **report_id)
{
  if (!feature_enabled (FEATURE_ID_WEB_APPLICATION_SCANNING))
    {
      g_warning ("%s: web application scanning runtime flag is disabled", __func__);
      return -1;
    }
  web_application_target_t web_application_target;

  web_application_target = task_web_application_target (task);
  if (web_application_target)
    {
      char *uuid;
      web_application_target_t found;

      uuid = web_application_target_uuid (web_application_target);
      if (find_web_application_target_with_permission (uuid,
                                                       &found,
                                                       "get_web_application_targets"))
        {
          g_warning ("%s: Failed to find web application target %s", __func__, uuid);
          g_free (uuid);
          return -1;
        }
      g_free (uuid);
      if (found == 0)
        return 99;
    }

  if (fork_web_application_scan_handler (task,
                                         web_application_target,
                                         from,
                                         report_id))
    {
      g_warning ("Couldn't fork web application scan handler");
      return -1;
    }
  return 0;
}

/**
 * @brief Stop a web application scanning task.
 *
 * @param[in]   task  The task.
 *
 * @return 0 on success, else -1.
 */
int
stop_web_application_task (task_t task)
{
  if (!feature_enabled (FEATURE_ID_WEB_APPLICATION_SCANNING))
    {
      g_warning ("%s: web application scanning runtime flag is disabled", __func__);
      return -1;
    }
  int ret = 0;
  report_t scan_report;
  char *scan_id;
  task_t previous_task;
  report_t previous_report;

  scanner_t scanner;
  http_scanner_resp_t response;
  http_scanner_connector_t connector = NULL;

  scan_report = task_running_report (task);
  if (!scan_report)
    return 0;

  previous_task = current_scanner_task;
  previous_report = global_current_report;

  scan_id = report_uuid (scan_report);
  if (!scan_id)
    {
      ret = -1;
      g_warning ("%s: Failed to get scan ID from report %lld",
                 __func__, scan_report);
      goto end_stop_task;
    }
  scanner = task_scanner (task);
  connector = web_application_scanner_connect (scanner, scan_id);
  if (!connector)
    {
      ret = -1;
      g_warning ("%s: Could not connect to web application scanner", __func__);
      goto end_stop_task;
    }

  current_scanner_task = task;
  global_current_report = task_running_report (task);
  set_task_run_status (task, TASK_STATUS_STOP_REQUESTED);
  response = http_scanner_stop_scan (connector);
  if (response->code < 0)
    {
      ret = -1;
      http_scanner_response_cleanup (response);
      g_free (scan_id);
      goto end_stop_task;
    }
  http_scanner_response_cleanup (response);

  ret = delete_http_scanner_scan_with_retry (connector, scan_id);
  g_free (scan_id);

end_stop_task:
  http_scanner_connector_free (connector);
  set_task_end_time_epoch (task, time (NULL));
  set_task_run_status (task, TASK_STATUS_STOPPED);
  if (scan_report)
    {
      set_scan_end_time_epoch (scan_report, time (NULL));
      set_report_scan_run_status (scan_report, TASK_STATUS_STOPPED);
    }
  current_scanner_task = previous_task;
  global_current_report = previous_report;

  return ret;
}

#endif
