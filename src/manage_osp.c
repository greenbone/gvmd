/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file scan_handler.c
 * @brief Headers for Greenbone Vulnerability Manager OSP scan handling.
 */

#include "ipc.h"
#include "manage_osp.h"
#include "manage_scan_queue.h"
#include "manage_sql.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Frees an osp_connect_data_t struct and its fields.
 * 
 * @param[in] conn_data  Connection data struct to free.
 */
void
osp_connect_data_free (osp_connect_data_t *conn_data)
{
  g_free (conn_data->host);
  g_free (conn_data->ca_pub);
  g_free (conn_data->key_pub);
  g_free (conn_data->key_priv);
  g_free (conn_data);
}

/**
 * @brief Get OSP connection data from a scanner.
 * 
 * If a relay is defined in the scanners table, the struct will contain the
 *  relay host and port and .
 *
 * @param[in]  scanner  The scanner to get the data from.
 *
 * @return New allocated connection data struct. Caller should free it with
 *         osp_connect_data_free
 */
osp_connect_data_t *
osp_connect_data_from_scanner (scanner_t scanner)
{
  gboolean has_relay;
  osp_connect_data_t *conn_data = g_malloc0 (sizeof (osp_connect_data_t));

  has_relay = scanner_has_relay (scanner);
  conn_data->use_relay_mapper = has_relay == FALSE;
  conn_data->host = scanner_host (scanner, has_relay);

  if (conn_data->host && *(conn_data->host) == '/')
    {
      conn_data->port = 0;
      conn_data->ca_pub = NULL;
      conn_data->key_pub = NULL;
      conn_data->key_priv = NULL;
    }
  else
    {
      conn_data->port = scanner_port (scanner, has_relay);
      conn_data->ca_pub = scanner_ca_pub (scanner);
      conn_data->key_pub = scanner_key_pub (scanner);
      conn_data->key_priv = scanner_key_priv (scanner);
    }

  return conn_data;
}


/**
 * @brief Get OSP connection data from a scanner iterator.
 * 
 * Fields are expected to be cleaned up by the iterator.
 *
 * @param[in]  iterator  The scanner iterator to get the data from.
 * @param[out] conn_data Struct to add data to connect to the scanner to.
 */
void
osp_connect_data_from_scanner_iterator (iterator_t *iterator,
                                        osp_connect_data_t *conn_data)
{
  gboolean has_relay;
  
  assert (iterator);

  has_relay = strcmp (scanner_iterator_relay_host (iterator) ?: "", "");
  conn_data->use_relay_mapper = (has_relay == FALSE);
  conn_data->host = has_relay ? (char*)(scanner_iterator_relay_host (iterator))
                              : (char*)(scanner_iterator_host (iterator));

  if (conn_data->host && *(conn_data->host) == '/')
    {
      conn_data->port = 0;
      conn_data->ca_pub = NULL;
      conn_data->key_priv = NULL;
      conn_data->key_pub = NULL;
    }
  else
    {
      conn_data->port = has_relay ? scanner_iterator_relay_port (iterator)
                                  : scanner_iterator_port (iterator);

      conn_data->ca_pub = (char*) scanner_iterator_ca_pub (iterator);
      conn_data->key_priv = (char*) scanner_iterator_key_priv (iterator);
      conn_data->key_pub = (char*) scanner_iterator_key_pub (iterator);
    }
}

/**
 * @brief Create a new connection to an OSP scanner using the relay mapper.
 *
 * @param[in] conn_data Original data used to look up the relay and connect
 *                      to the scanner.
 *
 * @return New connection if success, NULL otherwise.
 */
static osp_connection_t *
osp_scanner_mapped_relay_connect (osp_connect_data_t *conn_data)
{
  int ret, new_port;
  gchar *new_host, *new_ca_pub;
  osp_connection_t *connection;

  new_host = NULL;
  new_ca_pub = NULL;
  new_port = 0;

  ret = slave_get_relay (conn_data->host,
                         conn_data->port,
                         conn_data->ca_pub,
                         "OSP",
                         &new_host,
                         &new_port,
                         &new_ca_pub);

  switch (ret)
    {
      case 0:
        break;
      case 1:
        g_warning ("No relay found for Scanner at %s:%d",
                   conn_data->host, conn_data->port);
        return NULL;
      default:
        g_warning ("%s: Error getting relay for Scanner at %s:%d",
                   __func__, conn_data->host, conn_data->port);
        return NULL;
    }

  connection
    = osp_connection_new (new_host, new_port, new_ca_pub,
                          conn_data->key_pub, conn_data->key_priv);

  if (connection == NULL)
    {
      if (new_port)
        g_warning ("Could not connect to relay at %s:%d"
                    " for Scanner at %s:%d",
                    new_host, new_port, conn_data->host, conn_data->port);
      else
        g_warning ("Could not connect to relay at %s"
                    " for Scanner at %s:%d",
                    new_host, conn_data->host, conn_data->port);
    }

  g_free (new_host);
  g_free (new_ca_pub);

  return connection;
}

/**
 * @brief Create a new connection to an OSP scanner using the scanner data.
 *
 * @param[in]  conn_data Data used to connect to the scanner.
 *
 * @return New connection if success, NULL otherwise.
 */
osp_connection_t *
osp_connect_with_data (osp_connect_data_t *conn_data)
{
  osp_connection_t *connection;
  int is_unix_socket = (conn_data->host && *(conn_data->host) == '/') ? 1 : 0;

  if (is_unix_socket == 0
      && conn_data->use_relay_mapper
      && get_relay_mapper_path ())
    {
      connection
        = osp_scanner_mapped_relay_connect (conn_data);
    }
  else
    {
      connection = osp_connection_new (conn_data->host,
                                       conn_data->port,
                                       conn_data->ca_pub,
                                       conn_data->key_pub,
                                       conn_data->key_priv);

      if (connection == NULL)
        {
          if (is_unix_socket)
            g_warning ("Could not connect to Scanner at %s",
                       conn_data->host);
          else
            g_warning ("Could not connect to Scanner at %s:%d",
                       conn_data->host, conn_data->port);
        }
    }
  return connection;
}

/**
 * @brief Create a new connection to an OSP scanner.
 *
 * @param[in]   scanner     Scanner.
 *
 * @return New connection if success, NULL otherwise.
 */
osp_connection_t *
osp_scanner_connect (scanner_t scanner)
{
  osp_connect_data_t *conn_data;
  osp_connection_t *connection;

  assert (scanner);
  conn_data = osp_connect_data_from_scanner (scanner);
  connection = osp_connect_with_data (conn_data);
  osp_connect_data_free (conn_data);
  return connection;
}


/**
 * @brief Delete an OSP scan.
 *
 * @param[in]   report_id   Report ID.
 * @param[in]   conn_data   Data used to connect to the scanner.
 */
static void
delete_osp_scan (const char *report_id, osp_connect_data_t *conn_data)
{
  osp_connection_t *connection;

  connection = osp_connect_with_data (conn_data);
  if (!connection)
    {
      return;
    }
  osp_delete_scan (connection, report_id);
  osp_connection_close (connection);
}

/**
 * @brief Get an OSP scan's report.
 *
 * @param[in]   scan_id     Scan ID.
 * @param[in]   conn_data   Data used to connect to the scanner.
 * @param[in]   details     1 for detailed report, 0 otherwise.
 * @param[in]   pop_results 1 to pop results, 0 to leave results intact.
 * @param[out]  report_xml  Scan report.
 *
 * @return -1 on connection error, -2 on fail to find scan,
 *         progress value between 0 and 100 on success.
 */
static int
get_osp_scan_report (const char *scan_id, osp_connect_data_t *conn_data,
                     int details, int pop_results,
                     char **report_xml)
{
  osp_connection_t *connection;
  int progress;
  char *error = NULL;

  connection = osp_connect_with_data (conn_data);
  if (!connection)
    {
      return -1;
    }
  progress = osp_get_scan_pop (connection, scan_id, report_xml, details,
                               pop_results, &error);
  if (progress > 100 || progress < 0)
    {
      if (g_strrstr (error, "Failed to find scan") != NULL)
        progress = -2; // Scan already deleted
      else
        progress = -1; // connection error. Should retry.
      g_warning ("OSP get_scan %s: %s", scan_id, error);
      g_free (error);

    }

  osp_connection_close (connection);
  return progress;
}


/**
 * @brief Get an OSP scan's status.
 *
 * @param[in]   scan_id     Scan ID.
 * @param[in]   conn_data   Data used to connect to the scanner.
 *
 * @return 0 in success, -1 otherwise.
 */
static osp_scan_status_t
get_osp_scan_status (const char *scan_id, osp_connect_data_t *conn_data)
{
  osp_connection_t *connection;
  char *error = NULL;
  osp_get_scan_status_opts_t get_scan_opts;
  osp_scan_status_t status = OSP_SCAN_STATUS_ERROR;

  connection = osp_connect_with_data (conn_data);
  if (!connection)
    {
      return status;
    }

  get_scan_opts.scan_id = scan_id;
  status = osp_get_scan_status_ext (connection, get_scan_opts, &error);
  if (status == OSP_SCAN_STATUS_ERROR)
    {
      g_warning ("OSP %s %s: %s", __func__, scan_id, error);
      g_free (error);
      return status;
    }

  osp_connection_close (connection);
  return status;
}

/**
 * @brief Handles the semaphore for the start of an OSP scan update.
 *
 * @param[in]  add_result_on_error  Whether to create an OSP result on error.
 * @param[in]  task   The current task (for error result).
 * @param[in]  report The current report (for error result).
 *
 * @return 0 success, -1 error.
 */
static int
osp_scan_semaphore_update_start (int add_result_on_error,
                                 task_t task, report_t report)
{
  if (get_max_concurrent_scan_updates () == 0)
    return 0;
  
  int sem_op_ret = semaphore_op (SEMAPHORE_SCAN_UPDATE, -1, 5);
  if (sem_op_ret == 1)
    return 1;
  else if (sem_op_ret)
    {
      g_warning ("%s: error waiting for scan update semaphore",
                __func__);
      if (add_result_on_error)
        {
          result_t result = make_osp_result
            (task, "", "", "",
              threat_message_type ("Error"),
              "Error waiting for scan update semaphore", "", "",
              QOD_DEFAULT, NULL, NULL);
          report_add_result (report, result);
        }
      return -1;
    }
  return 0;
}

/**
 * @brief Handles the semaphore for the end of an OSP scan update.
 *
 * @param[in]  add_result_on_error  Whether to create an OSP result on error.
 * @param[in]  task   The current task (for error result).
 * @param[in]  report The current report (for error result).
 *
 * @return 0 success, -1 error.
 */
static int
osp_scan_semaphore_update_end (int add_result_on_error,
                               task_t task, report_t report)
{
  if (get_max_concurrent_scan_updates () == 0)
    return 0;

  if (semaphore_op (SEMAPHORE_SCAN_UPDATE, +1, 0))
    {
      g_warning ("%s: error signaling scan update semaphore",
                __func__);
      if (add_result_on_error)
        {
          result_t result = make_osp_result
            (task, "", "", "",
              threat_message_type ("Error"),
              "Error signaling scan update semaphore", "", "",
              QOD_DEFAULT, NULL, NULL);
          report_add_result (report, result);
        }
      return -1;
    }
  return 0;
}

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
prepare_osp_scan_for_resume (task_t task, const char *scan_id, char **error)
{
  osp_connection_t *connection;
  osp_get_scan_status_opts_t status_opts;
  osp_scan_status_t status;

  assert (task);
  assert (scan_id);
  assert (global_current_report);
  assert (error);

  status_opts.scan_id = scan_id;

  connection = osp_scanner_connect (task_scanner (task));
  if (!connection)
    {
      *error = g_strdup ("Could not connect to Scanner");
      return -1;
    }
  status = osp_get_scan_status_ext (connection, status_opts, error);

  /* Reset connection. */
  osp_connection_close (connection);
  connection = osp_scanner_connect (task_scanner (task));
  if (!connection)
    {
      *error = g_strdup ("Could not connect to Scanner");
      return -1;
    }

  if (status == OSP_SCAN_STATUS_ERROR)
    {
      if (g_str_has_prefix (*error, "Failed to find scan"))
        {
          g_debug ("%s: Scan %s not found", __func__, scan_id);
          g_free (*error);
          *error = NULL;
          osp_connection_close (connection);
          trim_partial_report (global_current_report);
          return 1;
        }
      else
        {
          g_warning ("%s: Error getting status of scan %s: %s",
                     __func__, scan_id, *error);
          osp_connection_close (connection);
          return -1;
        }
    }
  else if (status == OSP_SCAN_STATUS_RUNNING
           || status == OSP_SCAN_STATUS_QUEUED)
    {
      g_debug ("%s: Scan %s queued or running", __func__, scan_id);
      /* It would be possible to simply continue getting the results
       * from the scanner, but gvmd may have crashed while receiving
       * or storing the results, so some may be missing. */
      if (osp_stop_scan (connection, scan_id, error))
        {
          osp_connection_close (connection);
          return -1;
        }
      if (osp_delete_scan (connection, scan_id))
        {
          *error = g_strdup ("Failed to delete old report");
          osp_connection_close (connection);
          return -1;
        }
      osp_connection_close (connection);
      trim_partial_report (global_current_report);
      return 1;
    }
  else if (status == OSP_SCAN_STATUS_FINISHED)
    {
      /* OSP can't stop an already finished/interrupted scan,
       * but it must be delete to be resumed. */
      g_debug ("%s: Scan %s finished", __func__, scan_id);
      if (osp_delete_scan (connection, scan_id))
        {
          *error = g_strdup ("Failed to delete old report");
          osp_connection_close (connection);
          return -1;
        }
      osp_connection_close (connection);
      trim_partial_report (global_current_report);
      return 1;
    }
  else if (status == OSP_SCAN_STATUS_STOPPED
           || status == OSP_SCAN_STATUS_INTERRUPTED)
    {
      g_debug ("%s: Scan %s stopped or interrupted",
               __func__, scan_id);
      if (osp_delete_scan (connection, scan_id))
        {
          *error = g_strdup ("Failed to delete old report");
          osp_connection_close (connection);
          return -1;
        }
      osp_connection_close (connection);
      trim_partial_report (global_current_report);
      return 1;
    }

  g_warning ("%s: Unexpected scanner status %d", __func__, status);
  *error = g_strdup_printf ("Unexpected scanner status %d", status);
  osp_connection_close (connection);
  return -1;
}

/**
 * @brief Launch an OpenVAS via OSP task.
 *
 * @param[in]   task        The task.
 * @param[in]   target      The target.
 * @param[in]   scan_id     The scan uuid.
 * @param[in]   from        0 start from beginning, 1 continue from stopped,
 *                          2 continue if stopped else start from beginning.
 * @param[out]  error       Error return.
 *
 * @return 0 success, -1 if error.
 */
static int
launch_osp_openvas_task (task_t task, target_t target, const char *scan_id,
                         int from, char **error)
{
  osp_connection_t *connection;
  char *hosts_str, *ports_str, *exclude_hosts_str, *finished_hosts_str;
  gchar *clean_hosts, *clean_exclude_hosts, *clean_finished_hosts_str;
  int alive_test, reverse_lookup_only, reverse_lookup_unify;
  osp_target_t *osp_target;
  GSList *osp_targets, *vts;
  GHashTable *vts_hash_table;
  osp_credential_t *ssh_credential, *smb_credential, *esxi_credential;
  osp_credential_t *snmp_credential, *krb5_credential;
  gchar *max_checks, *max_hosts, *hosts_ordering;
  GHashTable *scanner_options;
  int ret, empty;
  config_t config;
  iterator_t scanner_prefs_iter, families, prefs;
  osp_start_scan_opts_t start_scan_opts;

  config = task_config (task);

  connection = NULL;

  alive_test = 0;
  reverse_lookup_unify = 0;
  reverse_lookup_only = 0;

  /* Prepare the report */
  if (from)
    {
      ret = prepare_osp_scan_for_resume (task, scan_id, error);
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

  osp_target = osp_target_new (clean_hosts, ports_str, clean_exclude_hosts,
                               alive_test, reverse_lookup_unify,
                               reverse_lookup_only);
  if (finished_hosts_str)
    osp_target_set_finished_hosts (osp_target, finished_hosts_str);

  free (hosts_str);
  free (ports_str);
  free (exclude_hosts_str);
  free (finished_hosts_str);
  g_free (clean_hosts);
  g_free (clean_exclude_hosts);
  g_free (clean_finished_hosts_str);
  osp_targets = g_slist_append (NULL, osp_target);

  ssh_credential = target_osp_ssh_credential (target);
  if (ssh_credential)
    osp_target_add_credential (osp_target, ssh_credential);

  smb_credential = target_osp_smb_credential (target);
  if (smb_credential)
    osp_target_add_credential (osp_target, smb_credential);

  esxi_credential = target_osp_esxi_credential (target);
  if (esxi_credential)
    osp_target_add_credential (osp_target, esxi_credential);

  snmp_credential = target_osp_snmp_credential (target);
  if (snmp_credential)
    osp_target_add_credential (osp_target, snmp_credential);

  krb5_credential = target_osp_krb5_credential (target);
  if (krb5_credential)
    osp_target_add_credential (osp_target, krb5_credential);

  /* Initialize vts table for vulnerability tests and their preferences */
  vts = NULL;
  vts_hash_table
    = g_hash_table_new_full (g_str_hash, g_str_equal, g_free,
                             /* Value is freed in vts list. */
                             NULL);

  /*  Setup of vulnerability tests (without preferences) */
  init_family_iterator (&families, 0, NULL, 1);
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
              osp_vt_single_t *new_vt;

              empty = 0;
              oid = nvt_iterator_oid (&nvts);
              new_vt = osp_vt_single_new (oid);

              vts = g_slist_prepend (vts, new_vt);
              g_hash_table_replace (vts_hash_table, g_strdup (oid), new_vt);
            }
          cleanup_iterator (&nvts);
        }
    }
  cleanup_iterator (&families);

  if (empty) {
    if (error)
      *error = g_strdup ("Exiting because VT list is empty (e.g. feed not synced yet)");
    g_slist_free_full (osp_targets, (GDestroyNotify) osp_target_free);
    // Credentials are freed with target
    g_slist_free_full (vts, (GDestroyNotify) osp_vt_single_free);
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
          const char *osp_value;

          // Workaround for boolean scanner preferences
          if (strcmp (value, "yes") == 0)
            osp_value = "1";
          else if (strcmp (value, "no") == 0)
            osp_value = "0";
          else
            osp_value = value;
          g_hash_table_replace (scanner_options, g_strdup (name),
                                g_strdup (osp_value));
        }
      else if (name && value && g_str_has_prefix (name, "timeout."))
        {
          /* Timeouts used to be stored as SERVER_PREFS, but were
           * converted into a script preference to be sent to the scanner. */
          g_warning ("%s: Timeout preference using obsolete format: %s",
                     __func__, name);
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

  hosts_ordering = task_hosts_ordering (task);
  if (hosts_ordering)
    g_hash_table_insert (scanner_options, g_strdup ("hosts_ordering"),
                         hosts_ordering);

  /* Setup VT preferences */
  init_preference_iterator (&prefs, config, "PLUGINS_PREFS");
  while (next (&prefs))
    {
      const char *full_name, *value;
      osp_vt_single_t *osp_vt;
      gchar **split_name;

      full_name = preference_iterator_name (&prefs);
      value = preference_iterator_value (&prefs);
      split_name = g_strsplit (full_name, ":", 4);

      osp_vt = NULL;
      if (split_name && split_name[0] && split_name[1] && split_name[2])
        {
          const char *oid = split_name[0];
          const char *pref_id = split_name[1];
          const char *type = split_name[2];
          gchar *osp_value = NULL;

          if (strcmp (type, "checkbox") == 0)
            {
              if (strcmp (value, "yes") == 0)
                osp_value = g_strdup ("1");
              else
                osp_value = g_strdup ("0");
            }
          else if (strcmp (type, "radio") == 0)
            {
              gchar** split_value;
              split_value = g_strsplit (value, ";", 2);
              osp_value = g_strdup (split_value[0]);
              g_strfreev (split_value);
            }
          else if (strcmp (type, "file") == 0)
            osp_value = g_base64_encode ((guchar*) value, strlen (value));

          osp_vt = g_hash_table_lookup (vts_hash_table, oid);
          if (osp_vt)
            osp_vt_single_add_value (osp_vt, pref_id,
                                     osp_value ? osp_value : value);
          g_free (osp_value);
        }

      g_strfreev (split_name);
    }
  cleanup_iterator (&prefs);
  g_hash_table_destroy (vts_hash_table);

  /* Start the scan */
  connection = osp_scanner_connect (task_scanner (task));
  if (!connection)
    {
      if (error)
        *error = g_strdup ("Could not connect to Scanner");
      g_slist_free_full (osp_targets, (GDestroyNotify) osp_target_free);
      // Credentials are freed with target
      g_slist_free_full (vts, (GDestroyNotify) osp_vt_single_free);
      g_hash_table_destroy (scanner_options);
      return -1;
    }

  start_scan_opts.targets = osp_targets;
  start_scan_opts.vt_groups = NULL;
  start_scan_opts.vts = vts;
  start_scan_opts.scanner_params = scanner_options;
  start_scan_opts.scan_id = scan_id;

  ret = osp_start_scan_ext (connection,
                            start_scan_opts,
                            error);

  osp_connection_close (connection);
  g_slist_free_full (osp_targets, (GDestroyNotify) osp_target_free);
  // Credentials are freed with target
  g_slist_free_full (vts, (GDestroyNotify) osp_vt_single_free);
  g_hash_table_destroy (scanner_options);
  return ret;
}

/**
 * @brief Get the last stopped report or a new one for an OSP scan.
 *
 * @param[in]   task      The task.
 * @param[in]   from      0 start from beginning, 1 continue from stopped,
 *                        2 continue if stopped else start from beginning.
 * @param[out]  report_id UUID of the report.
 *
 * @return 0 success, -1 error
 */
int
run_osp_scan_get_report (task_t task, int from, char **report_id)
{
  report_t resume_report;

  resume_report = 0;
  *report_id = NULL;

  if (from && task_last_resumable_report (task, &resume_report))
    {
      g_warning ("%s: error getting report to resume", __func__);
      return -1;
    }

  if (resume_report)
    {
      // Report to resume found
      if (global_current_report)
        {
           g_warning ("%s: global_current_report already set", __func__);
          return -1;
        }
      global_current_report = resume_report;
      *report_id = report_uuid (resume_report);

      /* Ensure the report is marked as requested. */
      set_report_scan_run_status (resume_report, TASK_STATUS_REQUESTED);

      /* Clear the end times of the task and partial report. */
      set_task_start_time_epoch (task,
                                 scan_start_time_epoch (resume_report));
      set_task_end_time (task, NULL);
      set_scan_end_time (resume_report, NULL);
    }
  else if (from == 1)
    // No report to resume and starting a new one is not allowed
    return -1;

  // Try starting a new report
  if (resume_report == 0
      && create_current_report (task, report_id, TASK_STATUS_REQUESTED))
    {
      g_debug ("   %s: failed to create report", __func__);
      return -1;
    }

  return 0;
}

/**
 * @brief Update the status and results of an OSP scan.
 * 
 * @param[in]  task       The task of the OSP scan
 * @param[in]  report     Row id of the scan report
 * @param[in]  scan_id    UUID of the scan report
 * @param[in]  conn_data   Data used to connect to the scanner.
 * @param[in,out]  queued_status_updated  Whether the "queued" status was set.
 * @param[in,out]  started                Whether the scan was started.
 * 
 * @return 0 if scan finished, 1 if caller should retry if appropriate,
 *         2 if scan is running or queued by the scanner,
 *         -1 if error, -2 if scan was stopped,
 *         -3 if the scan was interrupted, -4 already stopped.
 */
static int
update_osp_scan (task_t task, report_t report, const char *scan_id,
                 osp_connect_data_t *conn_data, int *retry_ptr,
                 int *queued_status_updated, int *started)
{
  int progress;
  osp_scan_status_t osp_scan_status;

  /* Get only the progress, without results and details. */
  progress = get_osp_scan_report (scan_id, conn_data, 0, 0, NULL);

  if (progress < 0 || progress > 100)
    {
      if (*retry_ptr > 0 && progress == -1)
        {
          (*retry_ptr)--;
          g_warning ("Connection lost with the scanner at %s. "
                      "Trying again in 1 second.", conn_data->host);
          gvm_sleep (1);
          if (osp_scan_semaphore_update_end (TRUE, task, report))
            {
              delete_osp_scan (scan_id, conn_data);
              return -3;
            }
          return 1;
        }
      else if (progress == -2)
        {
          osp_scan_semaphore_update_end (FALSE, task, report);
          return -2;
        }
      result_t result = make_osp_result
                          (task, "", "", "",
                          threat_message_type ("Error"),
                          "Erroneous scan progress value", "", "",
                          QOD_DEFAULT, NULL, NULL);
      report_add_result (report, result);
      osp_scan_semaphore_update_end (FALSE, task, report);
      delete_osp_scan (scan_id, conn_data);
      return -1;
    }
  else
    {
      /* Get the full OSP report. */
      char *report_xml = NULL;
      progress = get_osp_scan_report (scan_id, conn_data,
                                      1, 1, &report_xml);
      if (progress < 0 || progress > 100)
        {
          if ((*retry_ptr) > 0 && progress == -1)
            {
              (*retry_ptr)--;
              g_warning ("Connection lost with the scanner at %s. "
                          "Trying again in 1 second.", conn_data->host);
              if (osp_scan_semaphore_update_end (TRUE, task, report))
                {
                  delete_osp_scan (scan_id, conn_data);
                  return -3;
                }
              gvm_sleep (1);
              return 1;
            }
          else if (progress == -2)
            {
              osp_scan_semaphore_update_end (FALSE, task, report);
              return -2;
            }
          g_free (report_xml);
          result_t result = make_osp_result
                              (task, "", "", "",
                              threat_message_type ("Error"),
                              "Erroneous scan progress value", "", "",
                              QOD_DEFAULT, NULL, NULL);
          report_add_result (report, result);
          osp_scan_semaphore_update_end (FALSE, task, report);
          return -1;
        }
      else
        {
          set_report_slave_progress (report, progress);
          parse_osp_report (task, report, report_xml);
          g_free (report_xml);

          osp_scan_status = get_osp_scan_status (scan_id, conn_data);

          if (osp_scan_status == OSP_SCAN_STATUS_QUEUED)
            {
              if (*queued_status_updated == FALSE)
                {
                  set_task_run_status (task, TASK_STATUS_QUEUED);
                  set_report_scan_run_status (global_current_report,
                                              TASK_STATUS_QUEUED);
                  *queued_status_updated = TRUE;
                  return 2;
                }
            }
          else if (osp_scan_status == OSP_SCAN_STATUS_INTERRUPTED)
            {
              result_t result = make_osp_result
                (task, "", "", "",
                  threat_message_type ("Error"),
                  "Task interrupted unexpectedly", "", "",
                  QOD_DEFAULT, NULL, NULL);
              report_add_result (report, result);
              delete_osp_scan (scan_id, conn_data);
              osp_scan_semaphore_update_end (FALSE, task, report);
              return -3;
            }
          else if (progress >= 0 && progress < 100
                   && osp_scan_status == OSP_SCAN_STATUS_STOPPED)
            {
              if (*retry_ptr > 0)
                {
                  (*retry_ptr)--;
                  g_warning ("Connection lost with the scanner at %s. "
                              "Trying again in 1 second.", conn_data->host);
                  if (osp_scan_semaphore_update_end (TRUE, task, report))
                    {
                      delete_osp_scan (scan_id, conn_data);
                      return -3;
                    }
                  gvm_sleep (1);
                  return 1;
                }

              result_t result = make_osp_result
                (task, "", "", "",
                  threat_message_type ("Error"),
                  "Scan stopped unexpectedly by the server", "", "",
                  QOD_DEFAULT, NULL, NULL);
              report_add_result (report, result);
              delete_osp_scan (scan_id, conn_data);
              osp_scan_semaphore_update_end (FALSE, task, report);
              return -1;
            }
          else if (progress == 100
                   && osp_scan_status == OSP_SCAN_STATUS_FINISHED)
            {
              delete_osp_scan (scan_id, conn_data);
              osp_scan_semaphore_update_end (FALSE, task, report);
              if (*started == FALSE)
                {
                  set_task_run_status (task, TASK_STATUS_RUNNING);
                  set_report_scan_run_status (global_current_report,
                                              TASK_STATUS_RUNNING);
                }
              return 0;
            }
          else if (osp_scan_status == OSP_SCAN_STATUS_RUNNING
                    && *started == FALSE)
            {
              set_task_run_status (task, TASK_STATUS_RUNNING);
              set_report_scan_run_status (global_current_report,
                                          TASK_STATUS_RUNNING);
              *started = TRUE;
              return 2;
            }
        }
    }
  return 2;
}

/**
 * @brief Handle the start of an OSP scan.
 * 
 * @param[in]  task       The task of the OSP scan
 * @param[in]  target     The target of the scan task
 * @param[in]  scan_id    UUID of the scan / report
 * @param[in]  start_from 0 start from beginning, 1 continue from stopped,
 *                        2 continue if stopped else start from beginning.
 * @param[in]  wait_until_active  Whether to wait until scan is queued or
 *                                running
 *
 * @return 0 success, -1 if error.
 */
int
handle_osp_scan_start (task_t task, target_t target, const char *scan_id,
                       int start_from, gboolean wait_until_active)
{
  char *error = NULL;
  int rc;

  rc = launch_osp_openvas_task (task, target, scan_id, start_from, &error);
  if (rc)
    {
      result_t result;

      g_warning ("OSP start_scan %s: %s", scan_id, error);
      result = make_osp_result (task, "", "", "",
                                threat_message_type ("Error"),
                                error, "", "", QOD_DEFAULT, NULL, NULL);
      report_add_result (global_current_report, result);
      set_task_run_status (task, TASK_STATUS_DONE);
      set_report_scan_run_status (global_current_report, TASK_STATUS_DONE);
      set_task_end_time_epoch (task, time (NULL));
      set_scan_end_time_epoch (global_current_report, time (NULL));

      g_free (error);

      return (-1);
    }

  if (wait_until_active)
    {
      gboolean started, queued_status_updated;
      scanner_t scanner;
      osp_connect_data_t *conn_data;
      int connection_retry, retry;
      report_t report;

      started = FALSE;
      queued_status_updated = FALSE;
      report = global_current_report;
      scanner = task_scanner (task);
      conn_data = osp_connect_data_from_scanner (scanner);

      connection_retry = get_scanner_connection_retry ();
      retry = connection_retry;
      rc = -1;
      while (retry >= 0)
        {
          int sem_op_ret, run_status;

          run_status = task_run_status (task);
          if (run_status == TASK_STATUS_STOPPED
              || run_status == TASK_STATUS_STOP_REQUESTED)
            {
              rc = -4;
              break;
            }

          sem_op_ret = osp_scan_semaphore_update_start (TRUE, task, report);
          if (sem_op_ret == 1)
            continue;
          else if (sem_op_ret)
            {
              delete_osp_scan (scan_id, conn_data);
              rc = -3;
              break;
            }

          rc = update_osp_scan (task, report, scan_id, conn_data,
                                &retry, &queued_status_updated, &started);

          // Exit loop on error or if scan finished
          if (rc <= 0)
            break;

          if (osp_scan_semaphore_update_end (TRUE, task, report))
            {
              delete_osp_scan (scan_id, conn_data);
              rc = -3;
              break;
            }
          
          // Exit loop if scan is queued or started
          if (rc == 2)
            break;

          retry = connection_retry;
          gvm_sleep (5);
        }

      osp_connect_data_free (conn_data);
    }
  else
    rc = 0;

  return rc < 0 ? -1 : 0;
}

/**
 * @brief Handle an ongoing OSP scan, until success or failure.
 *
 * @param[in]   task      The task.
 * @param[in]   report    The report.
 * @param[in]   scan_id   The UUID of the scan on the scanner.
 * @param[in]   yield_time  Time after which to yield if there are more
 * .                        queued scans than the maximum active count or
 *                          0 for non-queued scans running until the end.
 *
 * @return 0 if success, -1 if error, -2 if scan was stopped,
 *         -3 if the scan was interrupted, -4 already stopped.
 */
int
handle_osp_scan (task_t task, report_t report, const char *scan_id,
                 time_t yield_time)
{
  int max_active_scans;
  task_status_t task_status;
  int rc;
  scanner_t scanner;
  osp_connect_data_t *conn_data;
  gboolean started, queued_status_updated;
  int retry, connection_retry;

  if (yield_time)
    {
      max_active_scans = get_max_active_scan_handlers ();
    }

  scanner = task_scanner (task);
  conn_data = osp_connect_data_from_scanner (scanner);

  task_status = task_run_status (task);
  started = (task_status == TASK_STATUS_RUNNING);
  queued_status_updated = started || (task_status == TASK_STATUS_QUEUED);
  connection_retry = get_scanner_connection_retry ();

  retry = connection_retry;
  rc = -1;
  while (retry >= 0)
    {
      int sem_op_ret, run_status;

      run_status = task_run_status (task);
      if (run_status == TASK_STATUS_STOPPED
          || run_status == TASK_STATUS_STOP_REQUESTED)
        {
          rc = -4;
          break;
        }

      sem_op_ret = osp_scan_semaphore_update_start (TRUE, task, report);
      if (sem_op_ret == 1)
        continue;
      else if (sem_op_ret)
        {
          delete_osp_scan (scan_id, conn_data);
          rc = -3;
          break;
        }

      rc = update_osp_scan (task, report, scan_id, conn_data,
                            &retry, &queued_status_updated, &started);

      // Exit loop on error or if scan finished
      if (rc <= 0)
        break;

      if (osp_scan_semaphore_update_end (TRUE, task, report))
        {
          delete_osp_scan (scan_id, conn_data);
          rc = -3;
          break;
        }

      if (yield_time 
          && time (NULL) >= yield_time
          && scan_queue_length () > max_active_scans)
        break;

      retry = connection_retry;
      gvm_sleep (5);
    }

  osp_connect_data_free (conn_data);
  return rc;
}

/**
 * @brief Handle the end of an OSP scan.
 * 
 * @param[in]  task                 The task of the scan
 * @param[in]  handle_progress_rc   Return code from handle_osp_scan
 * 
 * @return The given handle_osp_scan return code.
 */
int
handle_osp_scan_end (task_t task, int handle_progress_rc)
{
  if (handle_progress_rc == 0)
    {
      int max_concurrent_scan_updates = get_max_concurrent_scan_updates ();
      set_task_run_status (task, TASK_STATUS_PROCESSING);
      set_report_scan_run_status (global_current_report,
                                  TASK_STATUS_PROCESSING);

      if (max_concurrent_scan_updates)
        semaphore_op (SEMAPHORE_SCAN_UPDATE, -1, 0);
      hosts_set_identifiers (global_current_report);
      if (max_concurrent_scan_updates)
        semaphore_op (SEMAPHORE_SCAN_UPDATE, +1, 0);

      if (max_concurrent_scan_updates)
        semaphore_op (SEMAPHORE_SCAN_UPDATE, -1, 0);
      hosts_set_max_severity (global_current_report, NULL, NULL);
      if (max_concurrent_scan_updates)
        semaphore_op (SEMAPHORE_SCAN_UPDATE, +1, 0);

      if (max_concurrent_scan_updates)
        semaphore_op (SEMAPHORE_SCAN_UPDATE, -1, 0);
      hosts_set_details (global_current_report);
      if (max_concurrent_scan_updates)
        semaphore_op (SEMAPHORE_SCAN_UPDATE, +1, 0);

      set_task_run_status (task, TASK_STATUS_DONE);
      set_report_scan_run_status (global_current_report, TASK_STATUS_DONE);
    }
  else if (handle_progress_rc == -1 || handle_progress_rc == -2)
    {
      set_task_run_status (task, TASK_STATUS_STOPPED);
      set_report_scan_run_status (global_current_report, TASK_STATUS_STOPPED);
    }
  else if (handle_progress_rc == -3)
    {
      set_task_run_status (task, TASK_STATUS_INTERRUPTED);
      set_report_scan_run_status (global_current_report, TASK_STATUS_INTERRUPTED);
    }

  set_task_end_time_epoch (task, time (NULL));
  set_scan_end_time_epoch (global_current_report, time (NULL));
  global_current_report = 0;
  current_scanner_task = (task_t) 0;

  return handle_progress_rc;
}
