/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Implementation of HTTP scanner management functions for GVMD.
 *
 * This file provides the implementation for connecting to an HTTP-based
 * scanner and managing connector properties.
 */
#if ENABLE_HTTP_SCANNER
#include "manage_http_scanner.h"
#include "manage_sql.h"
#include "manage_scan_queue.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Create a new connection to a HTTP scanner.
 *
 * @param[in]   scanner     Scanner.
 * @param[in]   scan_id     scan uuid for creating http scan.
 *
 * @return New connection if success, NULL otherwise.
 */
http_scanner_connector_t
http_scanner_connect (scanner_t scanner, const char *scan_id)
{
  gboolean has_relay;
  int port;
  http_scanner_connector_t connection;
  char *host, *ca_pub, *key_pub, *key_priv;
  const char *protocol;

  assert (scanner);
  has_relay = scanner_has_relay (scanner);
  host = scanner_host (scanner, has_relay);
  port = scanner_port (scanner, has_relay);
  ca_pub = scanner_ca_pub (scanner);
  key_pub = scanner_key_pub (scanner);
  key_priv = scanner_key_priv (scanner);

  gboolean is_socket_path = host && *host != '\0' && g_path_is_absolute (host);

  if (!host || *host == '\0' || (!is_socket_path && port <= 0))
    {
      g_warning ("%s: Invalid scanner host or port", __func__);
      g_free (host);
      g_free (ca_pub);
      g_free (key_pub);
      g_free (key_priv);
      return NULL;
    }

  connection = http_scanner_connector_new ();

  if (is_socket_path)
    {
      g_debug ("%s: Using Unix domain socket: %s", __func__, host);
      http_scanner_connector_builder (connection, HTTP_SCANNER_UNIX_SOCKET_PATH, host);
    }
  else
    {
      /* Determine protocol based on certificates presence */
      protocol = (ca_pub && key_pub && key_priv) ? "https" : "http";

      http_scanner_connector_builder (connection, HTTP_SCANNER_HOST, host);
      http_scanner_connector_builder (connection, HTTP_SCANNER_PROTOCOL, protocol);
      http_scanner_connector_builder (connection, HTTP_SCANNER_PORT,
                                      (void *) &port);
    }

  if (ca_pub)
    http_scanner_connector_builder (connection, HTTP_SCANNER_CA_CERT, ca_pub);
  if (key_priv)
    http_scanner_connector_builder (connection, HTTP_SCANNER_KEY, key_priv);
  if (key_pub)
    http_scanner_connector_builder (connection, HTTP_SCANNER_CERT, key_pub);

  if (scan_id && scan_id[0] != '\0')
    http_scanner_connector_builder (connection, HTTP_SCANNER_SCAN_ID, scan_id);

  g_free (host);
  g_free (ca_pub);
  g_free (key_pub);
  g_free (key_priv);

  return connection;
}

/**
 * @brief Prepare a report for resuming an HTTP scanner scan
 *
 * @param[in]  connector  The connector to the scanner.
 * @param[out] error    Error return.
 *
 * @return 0 scan finished or still running,
 *         1 scan must be started,
 *         -1 error
 */
int
prepare_http_scanner_scan_for_resume (http_scanner_connector_t connector,
                                      char **error)

{
  http_scanner_scan_status_t status;

  assert (error);

  if (connector == NULL)
    {
      *error = g_strdup ("Could not connect to http scanner");
      return -1;
    }

  status = http_scanner_parsed_scan_status (connector);

  if (status->status == HTTP_SCANNER_SCAN_STATUS_ERROR)
    {
      if (status->response_code == 404)
        {
          g_debug ("%s: Scan not found", __func__);
          return 1;
        }
      g_warning ("%s: Error getting scan status: %ld", __func__,
                 status->response_code);
      return -1;
    }
  else if (status->status == HTTP_SCANNER_SCAN_STATUS_RUNNING
           || status->status == HTTP_SCANNER_SCAN_STATUS_REQUESTED)
    {
      http_scanner_resp_t response;

      g_debug ("%s: Scan queued or running", __func__);
      /* It would be possible to simply continue getting the results
       * from the scanner, but gvmd may have crashed while receiving
       * or storing the results, so some may be missing. */
      response = http_scanner_stop_scan (connector);
      if (response->code != 204)
        {
          *error = g_strdup_printf ("Failed to stop old report: %ld",
                                    response->code);
          http_scanner_response_cleanup (response);
          return -1;
        }
      http_scanner_response_cleanup (response);
      response = http_scanner_delete_scan (connector);
      if (response->code != 204)
        {
          *error = g_strdup_printf ("Failed to delete old report: %ld",
                                    response->code);
          http_scanner_response_cleanup (response);
          return -1;
        }
      http_scanner_response_cleanup (response);
      return 1;
    }
  else if (status->status == HTTP_SCANNER_SCAN_STATUS_SUCCEEDED)
    {
      http_scanner_resp_t response;

      /* OSP can't stop an already finished/interrupted scan,
       * but it must be delete to be resumed. */
      g_debug ("%s: Scan finished", __func__);
      response = http_scanner_delete_scan (connector);
      if (response->code != 204)
        {
          *error = g_strdup_printf ("Failed to delete old report: %ld",
                             response->code);
          http_scanner_response_cleanup (response);
          return -1;
        }
      http_scanner_response_cleanup (response);
      return 1;
    }
  else if (status->status == HTTP_SCANNER_SCAN_STATUS_STOPPED
           || status->status == HTTP_SCANNER_SCAN_STATUS_FAILED)
    {
      http_scanner_resp_t response;

      g_debug ("%s: Scan stopped or interrupted", __func__);
      response = http_scanner_delete_scan (connector);
      if (response->code != 204)
        {
          *error = g_strdup_printf ("Failed to delete old report: %ld",
                                    response->code);
          http_scanner_response_cleanup (response);
          return -1;
        }
      http_scanner_response_cleanup (response);
      return 1;
    }

  g_warning ("%s: Unexpected scanner status %d", __func__, status->status);
  *error = g_strdup_printf ("Unexpected scanner status %d", status->status);

  return -1;
}

/**
 * @brief Update the status and results of an HTTP scanner scan.
 *
 * @param[in]      connector  The connector to the scanner.
 * @param[in]      task       The task of the HTTP scanner scan
 * @param[in]      report     Row id of the scan report
 * @param[in]      parse_report_callback  Callback to parse and insert results.
 * @param[in,out]  retry_ptr              How many times to retry.
 * @param[in,out]  queued_status_updated  Whether the "queued" status was set.
 * @param[in,out]  started                Whether the scan was started.
 *
 * @return 0 if scan finished, 1 if caller should retry if appropriate,
 *         2 if scan is running or queued by the scanner,
 *         -1 if error, -2 if scan was stopped,
 *         -3 if the scan was interrupted, -4 already stopped.
 */
int
update_http_scanner_scan (http_scanner_connector_t connector, task_t task,
                          report_t report,
                          void (*parse_report_callback)
                            (task_t, report_t, GSList *, time_t, time_t),
                          int *retry_ptr, int *queued_status_updated,
                          int *started)
{
  http_scanner_resp_t response = NULL;
  int progress = http_scanner_get_scan_progress (connector);

  if (progress < 0 || progress > 100)
    {
      if (*retry_ptr > 0 && progress == -1)
        {
          (*retry_ptr)--;
          g_warning ("Connection lost with the scanner."
                      "Trying again in 1 second.");
          gvm_sleep (1);
          return 1;
        }
      else if (progress == -2)
        {
          return -2;
        }
      result_t result = make_osp_result
                          (task, "", "", "",
                          threat_message_type ("Error"),
                          "Erroneous scan progress value", "", "",
                          QOD_DEFAULT, NULL, NULL);
      report_add_result (report, result);
      response = http_scanner_delete_scan (connector);
      http_scanner_response_cleanup (response);
      return -1;
    }
  else
    {
      /* Get the full report. */
      progress = http_scanner_get_scan_progress (connector);

      if (progress < 0 || progress > 100)
        {
          if (*retry_ptr > 0 && progress == -1)
            {
              (*retry_ptr)--;
              g_warning ("Connection lost with the scanner. "
                          "Trying again in 1 second.");
              gvm_sleep (1);
              return 1;
            }
          else if (progress == -2)
            {
              return -2;
            }
          result_t result = make_osp_result
                              (task, "", "", "",
                              threat_message_type ("Error"),
                              "Erroneous scan progress value", "", "",
                              QOD_DEFAULT, NULL, NULL);
          report_add_result (report, result);
          return -1;
        }
      else
        {
          GSList *results = NULL;
          static unsigned long result_start = 0;
          static unsigned long result_end = -1; // get up to the end
          http_scanner_status_t current_status;
          time_t start_time, end_time;
          http_scanner_scan_status_t scan_status;

          if (progress > 0)
            set_report_slave_progress (report, progress);

          scan_status
            = http_scanner_parsed_scan_status (connector);
          start_time = scan_status->start_time;
          end_time = scan_status->end_time;
          current_status = scan_status->status;
          progress = scan_status->progress;
          g_free (scan_status);

          gvm_sleep (1);

          http_scanner_parsed_results (connector, result_start,
                                        result_end, &results);

          result_start += g_slist_length (results);

          parse_report_callback (task, report, results, start_time,
                                  end_time);
          if (results != NULL)
            {
              g_slist_free_full (results,
                                  (GDestroyNotify) http_scanner_result_free);
            }
          if (current_status == HTTP_SCANNER_SCAN_STATUS_STORED)
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
          else if (current_status == HTTP_SCANNER_SCAN_STATUS_FAILED
                   || current_status == HTTP_SCANNER_SCAN_STATUS_ERROR)
            {
              result_t result = make_osp_result
                (task, "", "", "",
                  threat_message_type ("Error"),
                  "Task interrupted unexpectedly", "", "",
                  QOD_DEFAULT, NULL, NULL);
              report_add_result (report, result);
              response = http_scanner_delete_scan (connector);
              http_scanner_response_cleanup (response);
              return -3;
            }
          else if (progress >= 0 && progress < 100
                   && current_status == HTTP_SCANNER_SCAN_STATUS_STOPPED)
            {
              if (*retry_ptr > 0)
                {
                  (*retry_ptr)--;
                  g_warning ("Connection lost with the scanner. "
                              "Trying again in 1 second.");
                  gvm_sleep (1);
                  return 1;
                }

              result_t result = make_osp_result
                (task, "", "", "",
                  threat_message_type ("Error"),
                  "Scan stopped unexpectedly by the server", "", "",
                  QOD_DEFAULT, NULL, NULL);
              report_add_result (report, result);
              response = http_scanner_delete_scan (connector);
              http_scanner_response_cleanup (response);
              return -1;
            }
          else if (progress == 100
                   && current_status == HTTP_SCANNER_SCAN_STATUS_SUCCEEDED)
            {
              response = http_scanner_delete_scan (connector);
              http_scanner_response_cleanup (response);
              return 0;
            }
          else if (current_status == HTTP_SCANNER_SCAN_STATUS_RUNNING
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
 * @brief Delete a scan on the HTTP scanner with retries.
 *        On retries, it will attempt to stop the scan
 *        before deleting it.
 *
 * @param[in]   connector  The connector to the scanner.
 * @param[in]   scan_id    The scan ID to delete.
 *
 * @return 0 if success, -1 if error.
 */
int
delete_http_scanner_scan_with_retry (http_scanner_connector_t connector,
                                     const char *scan_id)
{
  int delete_retry;
  http_scanner_resp_t response;
  int ret = 0;

  if (connector == NULL)
    {
      g_warning ("%s: Could not connect to http scanner", __func__);
      return -1;
    }

  delete_retry = get_scanner_connection_retry ();
  while (delete_retry >= 0)
    {
      response = http_scanner_delete_scan (connector);
      if (response->code == 204)
        {
          break;
        }
      else if (response->code == 406)
        {
          if (delete_retry > 0)
            {
              g_warning ("%s: Scan %s is still running and cannot be deleted yet,"
                         " retrying stop and delete.",
                         __func__, scan_id);

              http_scanner_resp_t stop_response = http_scanner_stop_scan (connector);
              if (stop_response->code != 204)
                {
                  g_warning ("%s: Failed to stop scan %s: %ld",
                             __func__, scan_id, stop_response->code);
                }
              http_scanner_response_cleanup (stop_response);
              gvm_sleep (3);

              delete_retry--;
              continue;
            }
          else
            {
              g_warning ("%s: Scan %s is not deleted, no more retries left",
                         __func__, scan_id);
              break;
            }
        }
      else
        {
          g_warning ("%s: Failed to delete scan %s: %ld",
                     __func__, scan_id, response->code);
          ret = -1;
          break;
        }
    }
  http_scanner_response_cleanup (response);
  return ret;
}

#endif /* ENABLE_HTTP_SCANNER */
