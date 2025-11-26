/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Implementation of container image scanner management
 *        functions for GVMD.
 */

#if ENABLE_CONTAINER_SCANNING

#include "debug_utils.h"
#include "manage_container_image_scanner.h"
#include "manage_sql.h"
#include "manage_sql_oci_image_targets.h"
#include "manage.h"
#include "manage_openvas.h"
#include "manage_osp.h"
#include <sys/types.h>
#include <bsd/unistd.h>
#include <unistd.h>

#include <gvm/base/gvm_sentry.h>
#include <gvm/container_image_scanner/container_image_scanner.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

#define CONTAINER_SCANNER_SCAN_PREFIX "container-image-scanner"

/**
 * @brief Create a new connection to a container image scanner.
 *
 * @param[in]   scanner      Scanner.
 * @param[in]   scan_id      scan uuid.
 *
 * @return New connection if success, NULL otherwise.
 *         The connection has to be freed by the caller.
 */
http_scanner_connector_t
container_image_scanner_connect (scanner_t scanner, const char *scan_id)
{
  http_scanner_connector_t connection;

  connection = http_scanner_connect (scanner, scan_id);
  if (connection)
      http_scanner_connector_builder (connection,
                                      HTTP_SCANNER_SCAN_PREFIX,
                                      CONTAINER_SCANNER_SCAN_PREFIX);
  else
    g_warning ("%s: Could not connect to container image scanner", __func__);

  return connection;
}

/**
 * @brief Get the credential of a OCI image target as
 *        container_image_credential_t.
 *
 * @param[in]  target  The OCI image target to get the credential from.
 *
 * @return  Pointer to a newly allocated container_image_credential_t.
 */
container_image_credential_t *
container_image_target_credential (oci_image_target_t target)
{
  credential_t credential;
  credential = oci_image_target_credential (target);
  if (credential)
    {
      iterator_t iter;
      container_image_credential_t *container_image_credential;

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

      container_image_credential
        = container_image_credential_new ("up", "generic");

      container_image_credential_set_auth_data (
        container_image_credential,
        "username",
        credential_iterator_login (&iter)
      );
      
      container_image_credential_set_auth_data (
        container_image_credential,
        "password",
        credential_iterator_password (&iter)
      );

      cleanup_iterator (&iter);
      return container_image_credential;
    }
  g_warning ("%s: No credential assigned to target.", __func__);
  return NULL;
}

/**
 * @brief Add a container image scan result to a report.
 *
 * @param[in]      res           The container image scan result.
 * @param[in,out]  results_aux   Auxiliary data, a pointer to struct
 *                               report_aux.
 */
static void
add_container_image_scan_result (http_scanner_result_t res, 
                                 gpointer *results_aux)
{

  struct report_aux *rep_aux = *results_aux;
  result_t result;
  char *type, *host, *hostname, *test_id;
  char *port = NULL, *desc = NULL;
  char *nvt_id = NULL, *severity_str = NULL;
  int qod_int;

  type = convert_http_scanner_type_to_osp_type (res->type);
  test_id = res->oid;
  host = res->ip_address;
  hostname = res->hostname;
  port = res->port;

  nvt_id = g_strdup (test_id);
  severity_str = nvt_severity (test_id, type);
  desc = res->message;
  qod_int = get_http_scanner_nvti_qod (test_id);

  char *hash_value;
  if (!check_http_scanner_result_exists (rep_aux->report, rep_aux->task, res,
                                         &hash_value, rep_aux->hash_results))
    {
      result = make_osp_result (rep_aux->task,
                                host ?: "",
                                hostname ?: "",
                                nvt_id ?: "",
                                type ?: "",
                                desc ?: "",
                                port ?: "",
                                severity_str ?: NULL,
                                qod_int,
                                NULL,
                                hash_value);
      g_array_append_val (rep_aux->results_array, result);
    }

  g_free (hash_value);
  g_free (nvt_id);
  g_free (type);

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
parse_container_image_scan_report (task_t task,
                                   report_t report,
                                   GSList *results,
                                   time_t start_time,
                                   time_t end_time)
{
  gboolean has_results = FALSE;
  GArray *results_array = NULL;
  GHashTable *hashed_results = NULL;
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
 
  hashed_results = g_hash_table_new_full (g_str_hash,
                                          g_str_equal,
                                          g_free,
                                          NULL);

  has_results = TRUE;

  results_array = g_array_new(TRUE, TRUE, sizeof(result_t));
  rep_aux = g_malloc0 (sizeof (struct report_aux));
  rep_aux->report = report;
  rep_aux->task = task;
  rep_aux->results_array = results_array;
  rep_aux->hash_results = hashed_results;
  rep_aux->hash_hostdetails = NULL;

  g_slist_foreach(results, 
                  (GFunc) add_container_image_scan_result,
                  &rep_aux);

  if (has_results)
    {
      sql ("UPDATE reports SET modification_time = m_now() WHERE id = %llu;",
           report);
      report_add_results_array (report, results_array);
    }

  sql_commit ();
  if (results_array && has_results)
    g_array_free (results_array, TRUE);

  g_hash_table_destroy (hashed_results);
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
prepare_container_image_scan_for_resume (task_t task, const char *scan_id,
                                         char **error)
{
  http_scanner_connector_t connection;
  int ret;

  assert (task);
  assert (scan_id);
  assert (global_current_report);
  assert (error);

  connection = container_image_scanner_connect (task_scanner (task), scan_id);
  if (connection == NULL)
    {
      *error = g_strdup ("Could not connect to container image Scanner");
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
 * @brief Get the boolean string for scanner preferences.
 *
 * @param[in]  value  The preference value.
 *
 * @return "true", "false" or a copy of the original value.
 */
char *
get_bool_string (const char *preference_value)
{
  if (strcmp (preference_value, "no") == 0
      || strcmp (preference_value, "0") == 0)
    return g_strdup("false");
  else if (strcmp (preference_value, "yes") == 0
           || strcmp (preference_value, "1") == 0)
    return g_strdup("true");
  else
    return g_strdup (preference_value);
}

/*
* @brief Get the value of a named scanner preference from a list of preferences.
*
* @param[in]  name        The name of the scanner preferences.
* @param[in]  scan_prefs  The list of preferences.
*
* @return     The value of the preference.
*/
static gchar *
get_preference_from_list (char *name, GSList *scan_prefs)
{
  gchar *value = NULL;
  GSList *point = scan_prefs;

  while (point)
    {
      http_scanner_param_t *param;
      char *p_name;

      param = point->data;
      p_name = http_scanner_param_id (param);

      if (p_name && strcmp (p_name, name) == 0)
        {
          value = g_strdup (http_scanner_param_default (param));
          break;
        }
      point = g_slist_next (point);
    }
  return value;
}

/*
* @brief Add container image scan preferences to the scanner options.
*        Task preferences override default scanner preferences.
*
* @param[in]  scanner_options  The scanner preferences table to add to.
* @param[in]  task             The task.
*
* @return     0 on success, -1 if error.
*/
static int
add_container_image_scan_preferences (http_scanner_connector_t connector,
                                      GHashTable *scanner_options,
                                      task_t task)
{
  GSList *scan_prefs = NULL;
  gchar *accept_invalid_certs, *registry_allow_insecure;
  int err = 0;

  accept_invalid_certs = task_preference_value (task, "accept_invalid_certs");

  if (accept_invalid_certs)
    g_hash_table_insert (scanner_options, g_strdup ("accept_invalid_certs"),
                         get_bool_string(accept_invalid_certs));

  registry_allow_insecure = task_preference_value (task, "registry_allow_insecure");

  if (registry_allow_insecure)
    g_hash_table_insert (scanner_options, g_strdup ("registry_allow_insecure"),
                         get_bool_string (registry_allow_insecure));


  if (!accept_invalid_certs || !registry_allow_insecure)
    err = http_scanner_parsed_scans_preferences (connector, &scan_prefs);

  if (err < 0)
    {
      if (scan_prefs)
        g_slist_free_full (scan_prefs, (GDestroyNotify) http_scanner_param_free);
      g_free (accept_invalid_certs);
      g_free (registry_allow_insecure);
      return err;
    };

  if (scan_prefs && !accept_invalid_certs)
    {
      accept_invalid_certs = get_preference_from_list ("accept_invalid_certs", scan_prefs);
      if (accept_invalid_certs)
        g_hash_table_insert (scanner_options, g_strdup ("accept_invalid_certs"),
                             get_bool_string (accept_invalid_certs));
    }

  if (scan_prefs && !registry_allow_insecure)
    {
      registry_allow_insecure = get_preference_from_list ("registry_allow_insecure", scan_prefs);
      if (registry_allow_insecure)
        g_hash_table_insert (scanner_options, g_strdup ("registry_allow_insecure"),
                             get_bool_string (registry_allow_insecure));
    }

  g_slist_free_full (scan_prefs, (GDestroyNotify) http_scanner_param_free);
  g_free (accept_invalid_certs);
  g_free (registry_allow_insecure);

  return err;
}

/**
 * @brief Launch container image scanning task.
 *
 * @param[in]   task              The task.
 * @param[in]   oci_image_target  The OCI image target.
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
launch_container_image_task (task_t task,
                             oci_image_target_t oci_image_target,
                             const char *scan_id,
                             int from,
                             char **error)
{
  http_scanner_connector_t connection;
  char *oci_image_references_str;
  container_image_target_t *container_image_target;
  container_image_credential_t *credential;
  gchar *max_checks, *max_hosts, *hosts_ordering;
  GHashTable *scanner_options;
  http_scanner_resp_t response;
  int ret;

  connection = NULL;

  /* Prepare the report */
  if (from)
    {
      ret = prepare_container_image_scan_for_resume (task, scan_id, error);
      if (ret == 0)
        return 0;
      else if (ret == -1)
        return -1;
    }

  oci_image_references_str
    = oci_image_target_image_references (oci_image_target);

  container_image_target 
      = container_image_target_new (scan_id, oci_image_references_str);

  credential = container_image_target_credential (oci_image_target);

  if (credential)
      container_image_target_add_credential (container_image_target, credential);
  else
    g_warning ("%s: No credential assigned to target.", __func__);

  /* Setup scanner preferences */
  scanner_options
    = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);

  /* Setup user-specific scanner preference */
  add_user_scan_preferences (scanner_options);

  /* Setup general task preferences */
  max_checks = task_preference_value (task, "max_checks");
  g_hash_table_insert (scanner_options, g_strdup ("max_checks"),
                       max_checks ? max_checks : g_strdup (MAX_CHECKS_DEFAULT));

  max_hosts = task_preference_value (task, "max_hosts");
  g_hash_table_insert (scanner_options, g_strdup ("max_hosts"),
                       max_hosts ? max_hosts : g_strdup (MAX_HOSTS_DEFAULT));

  hosts_ordering = task_hosts_ordering (task);
  if (hosts_ordering)
    g_hash_table_insert (scanner_options, g_strdup ("hosts_ordering"),
                         hosts_ordering);

  connection = container_image_scanner_connect (task_scanner (task), scan_id);
  if (!connection)
    {
      if (error)
        *error = g_strdup ("Could not connect to Scanner");
      container_image_target_free (container_image_target);
      g_hash_table_destroy (scanner_options);
      return -1;
    }

  /* Setup container image scanner preferences */
  if (add_container_image_scan_preferences (connection,
                                            scanner_options,
                                            task) < 0)
    {
      if (error)
        *error = g_strdup ("Could not get scan preferences from scanner");
      container_image_target_free (container_image_target);
      g_hash_table_destroy (scanner_options);
      return -1;
    }

  gchar *scan_config = NULL;
  scan_config =
    container_image_build_scan_config_json (container_image_target,
                                            scanner_options);

  response = http_scanner_create_scan (connection, scan_config);

  if (response->code != 201)
    {
      g_warning ("%s: Failed to create scan: %ld", __func__, response->code);
      container_image_target_free (container_image_target);
      g_hash_table_destroy (scanner_options);
      http_scanner_response_cleanup (response);
      return -1;
    }

  http_scanner_response_cleanup (response);
  response = http_scanner_start_scan (connection);

  if (response->code != 204)
    {
      g_warning ("%s: Failed to start scan: %ld", __func__, response->code);
      container_image_target_free (container_image_target);
      g_hash_table_destroy (scanner_options);
      http_scanner_response_cleanup (response);
      return -1;
    }

  container_image_target_free (container_image_target);
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
handle_container_image_scan (task_t task,
                             report_t report,
                             const char *scan_id)
{
  scanner_t scanner;
  http_scanner_connector_t connector;
  int ret;
  
  scanner = task_scanner (task);
  connector = container_image_scanner_connect (scanner, scan_id);

  if (connector == NULL)
    {
      g_warning ("%s: Could not connect to container image scanner", __func__);
      return -1;
    }

  ret = handle_http_scanner_scan (connector, task, report,
                                  parse_container_image_scan_report);

  http_scanner_connector_free (connector);

  return ret;
}

/**
 * @brief Fork a child to handle a container image scan's
 *        fetching and inserting.
 *
 * @param[in]   task               The task.
 * @param[in]   oci_image_target   The OCI image target.
 * @param[in]   from               0 start from beginning,
 *                                 1 continue from stopped,
 *                                 2 continue if stopped else
 *                                   start from beginning.
 * @param[out]  report_id_return   UUID of the report.
 *
 * @return Parent returns with 0 if success, -1 if failure. Child process
 *         doesn't return and simply exits.
 */
static int
fork_container_image_scan_handler (task_t task,
                                   oci_image_target_t oci_image_target,
                                   int from,
                                   char **report_id_return)
{
  char *report_id, *error = NULL;
  int rc;

  assert (task);
  assert (oci_image_target);

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

  rc = launch_container_image_task (task, oci_image_target, report_id, from,
                                    &error);

  if (rc < 0)
    {
      result_t result;

      g_warning ("container image scanner start_scan %s: %s", report_id, error);
      result = make_osp_result (task, "", "", "",
                                threat_message_type ("Error"),
                                error, "", "", QOD_DEFAULT, NULL, NULL);
      report_add_result (global_current_report, result);
      set_task_run_status (task, TASK_STATUS_DONE);
      set_report_scan_run_status (global_current_report, TASK_STATUS_DONE);
      set_task_end_time_epoch (task, time (NULL));
      set_scan_end_time_epoch (global_current_report, time (NULL));

      g_free (error);
      g_free (report_id);
      gvm_close_sentry ();
      exit (-1);
    }

  setproctitle ("container image scanner: Handling scan %s", report_id);

  g_info ("%s: Handling container image scan %s", __func__, report_id);

  rc = handle_container_image_scan (task, global_current_report, report_id);

  g_free (report_id);

  if (rc >= 0)
    {
      set_task_run_status (task, TASK_STATUS_PROCESSING);
      set_report_scan_run_status (global_current_report,
                                  TASK_STATUS_PROCESSING);
      set_task_run_status (task, TASK_STATUS_DONE);
      set_report_scan_run_status (global_current_report, TASK_STATUS_DONE);
    }
  else if (rc == -1 || rc == -2)
    {
      set_task_run_status (task, TASK_STATUS_STOPPED);
      set_report_scan_run_status (global_current_report, TASK_STATUS_STOPPED);
    }
  else if (rc == -3)
    {
      set_task_run_status (task, TASK_STATUS_INTERRUPTED);
      set_report_scan_run_status (global_current_report,
                                  TASK_STATUS_INTERRUPTED);
    }

  set_task_end_time_epoch (task, time (NULL));
  set_scan_end_time_epoch (global_current_report, time (NULL));
  global_current_report = 0;
  current_scanner_task = (task_t) 0;
  gvm_close_sentry ();
  exit (rc);
}

/**
 * @brief Start a task on a container image scanner.
 *
 * @param[in]   task       The task.
 * @param[in]   from       0 start from beginning, 1 continue from stopped,
 *                         2 continue if stopped else start from beginning.
 * @param[out]  report_id  The report ID.
 *
 * @return 0 success, 99 permission denied, -1 error.
 */
int
run_container_image_task (task_t task, int from, char **report_id)
{
  oci_image_target_t oci_image_target;

  oci_image_target = task_oci_image_target (task);
  if (oci_image_target)
    {
      char *uuid;
      oci_image_target_t found;

      uuid = oci_image_target_uuid (oci_image_target);
      if (find_oci_image_target_with_permission (uuid,
                                                 &found,
                                                 "get_oci_image_targets"))
        {
          g_warning ("%s: Failed to find OCI image target %s", __func__, uuid);
          g_free (uuid);
          return -1;
        }
      g_free (uuid);
      if (found == 0)
        return 99;
    }

  if (fork_container_image_scan_handler (task,
                                         oci_image_target, 
                                         from,
                                         report_id))
    {
      g_warning ("Couldn't fork container image scan handler");
      return -1;
    }
  return 0;
}

/**
 * @brief Stop a container scanning task.
 *
 * @param[in]   task  The task.
 *
 * @return 0 on success, else -1.
 */
int
stop_container_image_task (task_t task)
{
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
      goto end_stop_openvasd;
    }
  scanner = task_scanner (task);
  connector = container_image_scanner_connect (scanner, scan_id);
  if (!connector)
    {
      ret = -1;
      goto end_stop_openvasd;
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
      goto end_stop_openvasd;
    }
  http_scanner_response_cleanup (response);
  response = http_scanner_delete_scan (connector);
  http_scanner_response_cleanup (response);
  g_free (scan_id);
end_stop_openvasd:
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
