/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Headers for Greenbone Vulnerability Manager OpenVASD scan handling.
 */

#if ENABLE_OPENVASD

#include "manage_openvasd.h"

#include "ipc.h"
#include "manage_assets.h"
#include "manage_report_exports.h"
#include "manage_runtime_flags.h"
#include "manage_scan_queue.h"
#include "manage_sql.h"
#include "manage_sql_nvts.h"
#include "manage_sql_targets.h"
#include "manage_openvas.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Prepare a report for resuming an OSP scan
 *
 * @param[in]  task     The task of the scan.
 * @param[in]  scan_id  The scan uuid.
 * @param[out] error    Error return.
 *
 * @return 0 scan finished or still running,
 *         1 scan must be started,
 *         -1 error
 */
static int
prepare_openvasd_scan_for_resume (task_t task, const char *scan_id,
                                  char **error)
{
  http_scanner_connector_t connection;
  int ret;

  assert (task);
  assert (scan_id);
  assert (global_current_report);
  assert (error);

  connection = http_scanner_connect (task_scanner (task), scan_id);
  if (!connection)
    {
      *error = g_strdup ("Could not connect to openvasd Scanner");
      return -1;
    }

  g_debug ("%s: Preparing scan %s for resume", __func__, scan_id);

  ret = prepare_http_scanner_scan_for_resume (connection, error);

  if (ret == 1)
    trim_partial_report (global_current_report);

  return ret;
}

/**
 * @brief Launch an OpenVAS via openvasd task.
 *
 * @param[in]   task           The task.
 * @param[in]   target         The target.
 * @param[in]   scan_id        The scan uuid.
 * @param[in]   from           0 start from beginning, 1 continue from stopped,
 *                             2 continue if stopped else start from beginning.
 * @param[out]  error          Error return.
 * @param[out]  discovery_out  Returns TRUE if all OIDs are labeled
 *                             as discovery in the used scan config.
 *
 * @return An http code on success, -1 if error.
 */
static int
launch_openvasd_openvas_task (task_t task, target_t target, const char *scan_id,
                         int from, char **error, gboolean *discovery_out)
{
  http_scanner_connector_t connection;
  char *hosts_str, *ports_str, *exclude_hosts_str, *finished_hosts_str;
  gchar *clean_hosts, *clean_exclude_hosts, *clean_finished_hosts_str;
  int alive_test, reverse_lookup_only, reverse_lookup_unify;
  int arp = 0, icmp = 0, tcp_ack = 0, tcp_syn = 0, consider_alive = 0;
  openvasd_target_t *openvasd_target;
  GSList *openvasd_targets, *vts;
  GHashTable *vts_hash_table;
  gchar *max_checks, *max_hosts;
  GHashTable *scanner_options;
  http_scanner_resp_t response;
  int ret, empty;
  config_t config;
  iterator_t scanner_prefs_iter, families, prefs;

  connection = NULL;
  config = task_config (task);

  alive_test = 0;
  reverse_lookup_unify = 0;
  reverse_lookup_only = 0;

  /* Prepare the report */
  if (from)
    {
      ret = prepare_openvasd_scan_for_resume (task, scan_id, error);
      if (ret == 0)
        return 0;
      else if (ret == -1)
        return -1;
      finished_hosts_str = report_finished_hosts_str (global_current_report);
      clean_finished_hosts_str = clean_hosts_string (finished_hosts_str);
    }
  else
    {
      finished_hosts_str = NULL;
      clean_finished_hosts_str = NULL;
    }

  /* Set up target(s) */
  hosts_str = target_hosts (target);
  ports_str = target_port_range (target);
  exclude_hosts_str = target_exclude_hosts (target);

  clean_hosts = clean_hosts_string (hosts_str);
  clean_exclude_hosts = clean_hosts_string (exclude_hosts_str);

  alive_test = 0;
  if (target_alive_tests (target) > 0)
    alive_test = target_alive_tests (target);

  if (target_reverse_lookup_only (target) != NULL)
    reverse_lookup_only = atoi (target_reverse_lookup_only (target));

  if (target_reverse_lookup_unify (target) != NULL)
    reverse_lookup_unify = atoi (target_reverse_lookup_unify (target));

  if (finished_hosts_str)
    {
      gchar *new_exclude_hosts;

      new_exclude_hosts = g_strdup_printf ("%s,%s",
                                           clean_exclude_hosts,
                                           clean_finished_hosts_str);
      free (clean_exclude_hosts);
      clean_exclude_hosts = new_exclude_hosts;
    }

  openvasd_target = openvasd_target_new (scan_id, clean_hosts, ports_str,
                                         clean_exclude_hosts,
                                         reverse_lookup_unify,
                                         reverse_lookup_only);
  if (finished_hosts_str)
    openvasd_target_set_finished_hosts (openvasd_target, finished_hosts_str);

  if (alive_test & ALIVE_TEST_ARP)
    arp = 1;
  if (alive_test & ALIVE_TEST_ICMP)
    icmp = 1;
  if (alive_test & ALIVE_TEST_TCP_ACK_SERVICE)
    tcp_ack = 1;
  if (alive_test & ALIVE_TEST_TCP_SYN_SERVICE)
    tcp_syn = 1;
  if (alive_test & ALIVE_TEST_CONSIDER_ALIVE)
    consider_alive = 1;

  openvasd_target_add_alive_test_methods (openvasd_target, icmp, tcp_syn,
                                          tcp_ack, arp, consider_alive);

  free (hosts_str);
  free (ports_str);
  free (exclude_hosts_str);
  free (finished_hosts_str);
  g_free (clean_hosts);
  g_free (clean_exclude_hosts);
  g_free (clean_finished_hosts_str);
  openvasd_targets = g_slist_append (NULL, openvasd_target);

#if ENABLE_CREDENTIAL_STORES == 0

  openvasd_credential_t *ssh_credential, *smb_credential, *esxi_credential;
  openvasd_credential_t *snmp_credential;

  ssh_credential = (openvasd_credential_t *) target_osp_ssh_credential_db (target);
  if (ssh_credential)
    openvasd_target_add_credential (openvasd_target, ssh_credential);

  smb_credential = (openvasd_credential_t *) target_osp_smb_credential_db (target);
  if (smb_credential)
    openvasd_target_add_credential (openvasd_target, smb_credential);

  esxi_credential =
    (openvasd_credential_t *) target_osp_esxi_credential_db (target);
  if (esxi_credential)
    openvasd_target_add_credential (openvasd_target, esxi_credential);

  snmp_credential =
    (openvasd_credential_t *) target_osp_snmp_credential_db (target);
  if (snmp_credential)
    openvasd_target_add_credential (openvasd_target, snmp_credential);

#endif

  /* Initialize vts table for vulnerability tests and their preferences */
  vts = NULL;
  vts_hash_table
    = g_hash_table_new_full (g_str_hash, g_str_equal, g_free,
                             /* Value is freed in vts list. */
                             NULL);

  /*  Setup of vulnerability tests (without preferences) */
  init_family_iterator (&families, 0, NULL, 1);
  GSList *oids = NULL;
  empty = 1;
  while (next (&families))
    {
      const char *family = family_iterator_name (&families);
      if (family)
        {
          iterator_t nvts;
          init_nvt_iterator (&nvts, 0, config, family, NULL, 1, NULL);
          while (next (&nvts))
            {
              const char *oid;
              openvasd_vt_single_t *new_vt;

              empty = 0;
              oid = nvt_iterator_oid (&nvts);
              new_vt = openvasd_vt_single_new (oid);
              oids = g_slist_prepend (oids, g_strdup (oid));

              vts = g_slist_prepend (vts, new_vt);
              g_hash_table_replace (vts_hash_table, g_strdup (oid), new_vt);
            }
          cleanup_iterator (&nvts);
        }
    }
  cleanup_iterator (&families);

  /* check oids are discovery or not */
  *discovery_out = nvts_oids_all_discovery_cached (oids);
  /* clean up oids list */
  g_slist_free_full (oids, g_free);

  if (empty) {
    if (error)
      *error = g_strdup ("Exiting because VT list is empty "
                         "(e.g. feed not synced yet)");
    g_slist_free_full (openvasd_targets, (GDestroyNotify) openvasd_target_free);
    // Credentials are freed with target
    g_slist_free_full (vts, (GDestroyNotify) openvasd_vt_single_free);
    return -1;
  }

  /* Setup general scanner preferences */
  scanner_options
    = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
  init_preference_iterator (&scanner_prefs_iter, config, "SERVER_PREFS");
  while (next (&scanner_prefs_iter))
    {
      const char *name, *value;
      name = preference_iterator_name (&scanner_prefs_iter);
      value = preference_iterator_value (&scanner_prefs_iter);
      if (name && value && !g_str_has_prefix (name, "timeout."))
        {
          const char *openvasd_value;

          // Workaround for boolean scanner preferences
          if (strcmp (value, "no") == 0)
            openvasd_value = "0";
          else if (strcmp (value, "yes") == 0)
            openvasd_value = "1";
          else
            openvasd_value = value;
          g_hash_table_replace (scanner_options, g_strdup (name),
                                g_strdup (openvasd_value));
        }
      /* Timeouts are stored as SERVER_PREFS, but are actually
         script preferences. This prefs is converted into a
         script preference to be sent to the scanner. */
      else if (name && value && g_str_has_prefix (name, "timeout."))
        {
          char **oid = NULL;
          openvasd_vt_single_t *openvasd_vt = NULL;

          oid = g_strsplit (name, ".", 2);
          openvasd_vt = g_hash_table_lookup (vts_hash_table, oid[1]);
          if (openvasd_vt)
            openvasd_vt_single_add_value (openvasd_vt, "0", value);
          g_strfreev (oid);
        }
    }
  cleanup_iterator (&scanner_prefs_iter);

  /* Setup user-specific scanner preference */
  add_user_scan_preferences (scanner_options);

  /* Setup general task preferences */
  max_checks = task_preference_value (task, "max_checks");
  g_hash_table_insert (scanner_options, g_strdup ("max_checks"),
                       max_checks ? max_checks : g_strdup (MAX_CHECKS_DEFAULT));

  max_hosts = task_preference_value (task, "max_hosts");
  g_hash_table_insert (scanner_options, g_strdup ("max_hosts"),
                       max_hosts ? max_hosts : g_strdup (MAX_HOSTS_DEFAULT));

  /* Setup VT preferences */
  init_preference_iterator (&prefs, config, "PLUGINS_PREFS");
  while (next (&prefs))
    {
      const char *full_name, *value;
      openvasd_vt_single_t *openvasd_vt;
      gchar **split_name;

      full_name = preference_iterator_name (&prefs);
      value = preference_iterator_value (&prefs);
      split_name = g_strsplit (full_name, ":", 4);

      openvasd_vt = NULL;
      if (split_name && split_name[0] && split_name[1] && split_name[2])
        {
          const char *oid = split_name[0];
          const char *pref_id = split_name[1];
          const char *type = split_name[2];
          gchar *openvasd_value = NULL;

          if (strcmp (type, "checkbox") == 0)
            {
              if (strcmp (value, "yes") == 0)
                openvasd_value = g_strdup ("1");
              else
                openvasd_value = g_strdup ("0");
            }
          else if (strcmp (type, "radio") == 0)
            {
              gchar** split_value;
              split_value = g_strsplit (value, ";", 2);
              openvasd_value = g_strdup (split_value[0]);
              g_strfreev (split_value);
            }
          else if (strcmp (type, "file") == 0)
            openvasd_value = g_base64_encode ((guchar*) value, strlen (value));

          openvasd_vt = g_hash_table_lookup (vts_hash_table, oid);
          if (openvasd_vt)
            openvasd_vt_single_add_value (openvasd_vt, pref_id,
                                     openvasd_value ? openvasd_value : value);
          g_free (openvasd_value);
        }

      g_strfreev (split_name);
    }
  cleanup_iterator (&prefs);
  g_hash_table_destroy (vts_hash_table);

  /* Start the scan */
  connection = http_scanner_connect (task_scanner (task), scan_id);
  if (!connection)
    {
      if (error)
        *error = g_strdup ("Could not connect to Scanner");
      g_slist_free_full (openvasd_targets,
                         (GDestroyNotify) openvasd_target_free);
      // Credentials are freed with target
      g_slist_free_full (vts, (GDestroyNotify) openvasd_vt_single_free);
      g_hash_table_destroy (scanner_options);
      return -1;
    }

  gchar *scan_config = NULL;
  scan_config =
    openvasd_build_scan_config_json(openvasd_target, scanner_options, vts);

  response = http_scanner_create_scan (connection, scan_config);
  if (response->code == 201)
    {
      http_scanner_response_cleanup (response);
      response = http_scanner_start_scan (connection);
    }
  else
    g_warning ("%s: Failed to create scan: %ld", __func__, response->code);

  openvasd_target_free(openvasd_target);
  // Credentials are freed with target
  g_slist_free_full (vts, (GDestroyNotify) openvasd_vt_single_free);
  g_hash_table_destroy (scanner_options);
  ret = response->code;
  http_scanner_response_cleanup (response);

  return ret;
}

/**
 * @brief Handle the start of an OpenVASD scan.
 *
 * @param[in]  task        The task of the OpenVASD scan
 * @param[in]  target      The target of the scan task
 * @param[in]  scan_id     UUID of the scan / report
 * @param[in]  start_from  0 start from beginning, 1 continue from stopped,
 *                         2 continue if stopped else start from beginning.
 * @param[in]  wait_until_active  Whether to wait until scan is queued or
 *                                running
 * @param[out] discovery_out  Discovery flag for scan config.
 *
 * @return 0 success, -1 if error.
 */
int
handle_openvasd_scan_start (task_t task, target_t target, const char *scan_id,
                            int start_from, gboolean wait_until_active,
                            gboolean *discovery_out)
{
  char *error = NULL;
  int rc;

  rc = launch_openvasd_openvas_task (task, target, scan_id, start_from, &error,
                                     discovery_out);
  if (rc < 0)
    {
      result_t result;

      g_warning ("openvasd start_scan %s: %s", scan_id, error);
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

  if (wait_until_active)
    {
      report_t report = global_current_report;
      scanner_t scanner = task_scanner (task);
      http_scanner_connector_t connector = http_scanner_connect (scanner,
                                                                 scan_id);
      if (connector == NULL)
        {
          g_warning ("%s: Could not connect to container image scanner",
                     __func__);
          return -1;
        }

      http_scanner_resp_t response = NULL;
      gboolean started = FALSE;
      gboolean queued_status_updated = FALSE;
      int connection_retry = get_scanner_connection_retry ();

      int retry = connection_retry;
      rc = -1;
      while (retry >= 0)
        {
          int run_status, sem_op_ret;

          run_status = task_run_status (task);
          if (run_status == TASK_STATUS_STOPPED
              || run_status == TASK_STATUS_STOP_REQUESTED)
            {
              rc = -4;
              break;
            }

          sem_op_ret = scan_semaphore_update_start (TRUE, task, report);
          if (sem_op_ret == 1)
            continue;
          else if (sem_op_ret)
            {
              response = http_scanner_delete_scan (connector);
              rc = -3;
              break;
            }

          rc = update_http_scanner_scan (connector, task, report,
                                         parse_http_scanner_report, &retry,
                                         &queued_status_updated, &started);

          // Exit loop on error or if scan finished
          if (rc <= 0)
            break;

          if (scan_semaphore_update_end (TRUE, task, report))
            {
              response = http_scanner_delete_scan (connector);
              rc = -3;
              break;
            }

          // Exit loop if scan is queued or started
          if (rc == 2)
            break;
        }

      http_scanner_connector_free (connector);
      http_scanner_response_cleanup (response);
    }
  else
    rc = 0;

  return rc < 0 ? -1 : 0;
}

/**
 * @brief Handle an ongoing openvasd scan, until success or failure.
 *
 * @param[in]   task        The task.
 * @param[in]   report      The report.
 * @param[in]   scan_id     The UUID of the scan on the scanner.
 * @param[in]   yield_time  Time after which to yield if there are more
 * .                        queued scans than the maximum active count or
 *                          0 for non-queued scans running until the end.
 *
 * @return 0 if success, -1 if error, -2 if scan was stopped,
 *         -3 if the scan was interrupted, -4 already stopped.
 */
int
handle_openvasd_scan (task_t task, report_t report, const char *scan_id,
                      time_t yield_time)
{
  scanner_t scanner;
  http_scanner_connector_t connector;
  http_scanner_resp_t response = NULL;
  int rc;

  scanner = task_scanner (task);
  connector = http_scanner_connect (scanner, scan_id);

  if (!connector)
    {
      g_warning ("%s: Could not connect to openvasd scanner", __func__);
      return -1;
    }

  gboolean started, queued_status_updated;
  int retry, connection_retry, max_active_scans;

  if (connector == NULL)
    {
      g_warning ("%s: Could not connect to http scanner", __func__);
      return -1;
    }

  if (yield_time)
    {
      max_active_scans = get_max_active_scan_handlers ();
    }

  task_status_t task_status = task_run_status (task);
  started = (task_status == TASK_STATUS_RUNNING);
  queued_status_updated = started || (task_status == TASK_STATUS_QUEUED);
  connection_retry = get_scanner_connection_retry ();

  retry = connection_retry;
  rc = -1;
  while (retry >= 0)
    {
      int run_status, sem_op_ret;

      run_status = task_run_status (task);
      if (run_status == TASK_STATUS_STOPPED
          || run_status == TASK_STATUS_STOP_REQUESTED)
        {
          rc = -4;
          break;
        }

      sem_op_ret = scan_semaphore_update_start (TRUE, task, report);
      if (sem_op_ret == 1)
        continue;
      else if (sem_op_ret)
        {
          response = http_scanner_delete_scan (connector);
          rc = -3;
          break;
        }

      rc = update_http_scanner_scan (connector, task, report,
                                     parse_http_scanner_report, &retry,
                                     &queued_status_updated, &started);

      int ret = scan_semaphore_update_end (TRUE, task, report);

      if (rc <= 0)
        break;

      if (ret)
        {
          response = http_scanner_delete_scan (connector);
          rc = -3;
          break;
        }

      if (yield_time
          && time (NULL) >= yield_time
          && scan_queue_length () > max_active_scans)
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
 * @brief Handle the end of an OpenVASD scan.
 *
 * @param[in]  task                 The task of the scan
 * @param[in]  handle_progress_rc   Return code from handle_openvasd_scan_start
 * @param[in] discovery             Discovery flag for scan config.
 *
 * @return The given handle_openvasd_scan_start return code.
 */
int
handle_openvasd_scan_end (task_t task, int handle_progress_rc, gboolean discovery)
{
  if (handle_progress_rc == 0)
   {
      set_task_run_status (task, TASK_STATUS_PROCESSING);
      set_report_scan_run_status (global_current_report,
                                  TASK_STATUS_PROCESSING);

      // add semaphores check
      hosts_set_identifiers (global_current_report);
      hosts_set_max_severity (global_current_report, NULL, NULL);
      hosts_set_details (global_current_report);

      asset_snapshots_target (global_current_report, task, discovery);
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

#endif /* ENABLE_OPENVASD */
