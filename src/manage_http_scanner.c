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

  /* Determine protocol based on certificate presence */
  if (ca_pub && key_pub && key_priv)
    protocol = "https";
  else
    protocol = "http";

  connection = http_scanner_connector_new ();

  http_scanner_connector_builder (connection, HTTP_SCANNER_HOST, host);
  http_scanner_connector_builder (connection, HTTP_SCANNER_CA_CERT, ca_pub);
  http_scanner_connector_builder (connection, HTTP_SCANNER_KEY, key_priv);
  http_scanner_connector_builder (connection, HTTP_SCANNER_CERT, key_pub);
  http_scanner_connector_builder (connection, HTTP_SCANNER_PROTOCOL, protocol);
  http_scanner_connector_builder (connection, HTTP_SCANNER_PORT,
                                  (void *) &port);

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
 * @brief Handle an ongoing scan on HTTP scanner, until success or failure.
 *
 * @param[in]   connector  The connector to the scanner.
 * @param[in]   task       The task.
 * @param[in]   report     The report.
 * @param[in]   parse_report_callback  Callback to parse and insert results.
 *
 * @return 0 if success, -1 if error, -2 if scan was stopped,
 *         -3 if the scan was interrupted, -4 already stopped.
 */
int
handle_http_scanner_scan (http_scanner_connector_t connector,
                          task_t task, report_t report,
                          void (*parse_report_callback)
                            (task_t, report_t, GSList *, time_t, time_t))
{
  int rc;
  gboolean started, queued_status_updated;
  int retry, connection_retry;
  http_scanner_resp_t response;

  if (connector == NULL)
    {
      g_warning ("%s: Could not connect to http scanner", __func__);
      return -1;
    }

  response = NULL;
  started = FALSE;
  queued_status_updated = FALSE;
  connection_retry = get_scanner_connection_retry ();

  retry = connection_retry;
  rc = -1;
  while (retry >= 0)
    {
      int run_status, progress;

      run_status = task_run_status (task);
      if (run_status == TASK_STATUS_STOPPED
          || run_status == TASK_STATUS_STOP_REQUESTED)
        {
          rc = -4;
          break;
        }

      progress = http_scanner_get_scan_progress (connector);

      if (progress < 0 || progress > 100)
        {
          if (retry > 0 && progress == -1)
            {
              retry--;
              g_warning ("Connection lost with the scanner."
                         "Trying again in 1 second.");
              gvm_sleep (1);
              continue;
            }
          else if (progress == -2)
            {
              rc = -2;
              break;
            }
          result_t result = make_osp_result
                             (task, "", "", "",
                              threat_message_type ("Error"),
                              "Erroneous scan progress value", "", "",
                              QOD_DEFAULT, NULL, NULL);
          report_add_result (report, result);
          response = http_scanner_delete_scan(connector);
          rc = -1;
          break;
        }
      else
        {
          /* Get the full report. */
          progress = http_scanner_get_scan_progress (connector);

          if (progress < 0 || progress > 100)
            {
              if (retry > 0 && progress == -1)
                {
                  retry--;
                  g_warning ("Connection lost with the scanner. "
                             "Trying again in 1 second.");
                  gvm_sleep (1);
                  continue;
                }
              else if (progress == -2)
                {
                  rc = -2;
                  break;
                }
              result_t result = make_osp_result
                                 (task, "", "", "",
                                  threat_message_type ("Error"),
                                  "Erroneous scan progress value", "", "",
                                  QOD_DEFAULT, NULL, NULL);
              report_add_result (report, result);
              rc = -1;
              break;
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
                  if (queued_status_updated == FALSE)
                    {
                      set_task_run_status (task, TASK_STATUS_QUEUED);
                      set_report_scan_run_status (global_current_report,
                                                  TASK_STATUS_QUEUED);
                      queued_status_updated = TRUE;
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
                  rc = -3;
                  break;
                }
              else if (progress >= 0 && progress < 100
                  && current_status == HTTP_SCANNER_SCAN_STATUS_STOPPED)
                {
                  if (retry > 0)
                    {
                      retry--;
                      g_warning ("Connection lost with the scanner. "
                                 "Trying again in 1 second.");
                      gvm_sleep (1);
                      continue;
                    }

                  result_t result = make_osp_result
                    (task, "", "", "",
                     threat_message_type ("Error"),
                     "Scan stopped unexpectedly by the server", "", "",
                     QOD_DEFAULT, NULL, NULL);
                  report_add_result (report, result);
                  response = http_scanner_delete_scan (connector);
                  rc = -1;
                  break;
                }
              else if (progress == 100
                       && current_status == HTTP_SCANNER_SCAN_STATUS_SUCCEEDED)
                {
                  response = http_scanner_delete_scan (connector);
                  rc = response->code;
                  break;
                }
              else if (current_status == HTTP_SCANNER_SCAN_STATUS_RUNNING
                       && started == FALSE)
                {
                  set_task_run_status (task, TASK_STATUS_RUNNING);
                  set_report_scan_run_status (global_current_report,
                                              TASK_STATUS_RUNNING);
                  started = TRUE;
                }
            }
        }

      retry = connection_retry;
      gvm_sleep (5);
    }
  http_scanner_response_cleanup (response);
  return rc;
}

#endif /* ENABLE_HTTP_SCANNER */
