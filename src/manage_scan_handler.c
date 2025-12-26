/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Greenbone Vulnerability Manager scan handler.
 */

#include "utils.h"
#include "manage_osp.h"
#include "manage_sql.h"
#include "manage_sql_scan_queue.h"
#include "manage_scan_handler.h"
#include <gvm/base/gvm_sentry.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md   scan"

/**
 * @brief Handle a OSP scan in the gvmd scan queue.
 *
 * @param[in]  scan_id    UUID of the scan / report to handle.
 * @param[in]  report     Row id of the report.
 * @param[in]  task       Row id of the task.
 * @param[in]  start_from 0 start from beginning, 1 continue from stopped,
 *                        2 continue if stopped else start from beginning.
 *
 * @return 0 scan finished, 2 scan running,
 *         -1 if error, -2 if scan was stopped,
 *         -3 if the scan was interrupted, -4 already stopped.
 */
static int
handle_queued_osp_scan (const char *scan_id, report_t report,
                        task_t task, int start_from)
{
  task_status_t status = task_run_status (task);
  gboolean discovery_scan = FALSE;

  switch (status)
    {
      case TASK_STATUS_REQUESTED:
        {
          int rc;
          target_t target = task_target (task);
          rc = handle_osp_scan_start (task, target, scan_id, start_from,
                                      TRUE, &discovery_scan);
          /* Set discovery flag to the report */
          report_set_discovery (report, discovery_scan);
          return (rc == 0) ? 2 : rc;
        }
      default:
        {
          time_t yield_time = time (NULL) + get_scan_handler_active_time ();
          int ret = handle_osp_scan (task, report, scan_id, yield_time);
          return ret;
        }
    }

}

/**
 * @brief Handle a scan in the gvmd scan queue.
 *
 * @param[in]  scan_id    UUID of the scan / report to handle.
 * @param[in]  report     Report.
 * @param[in]  task       Task.
 * @param[in]  scanner    Scanner.
 * @param[in]  start_from 0 start from beginning, 1 continue from stopped,
 *                        2 continue if stopped else start from beginning.
 *
 * @return 0 scan finished, 2 scan running,
 *         -1 if error, -2 if scan was stopped,
 *         -3 if the scan was interrupted, -4 already stopped.
 */
static int
handle_queued_scan (const char *scan_id, report_t report, task_t task,
                    scanner_t scanner, int start_from)
{
  scanner_type_t current_scanner_type = scanner_type (scanner);
  switch (current_scanner_type)
    {
      case SCANNER_TYPE_OPENVAS:
      case SCANNER_TYPE_OSP_SENSOR:
        return handle_queued_osp_scan (scan_id, report, task, start_from);
      default:
        {
          g_warning ("%s: Scanner type not supported by queue: %d",
                     __func__, current_scanner_type);
          set_task_interrupted (task,
                                "Internal error:"
                                " Scanner type not supported by queue");
          set_report_scan_run_status (report, TASK_STATUS_INTERRUPTED);
          return -1;
        }
    }
}

/**
 * @brief Handle a scan defined a by a queue entry.
 *
 * @param[in]  report_id  UUID of the scan / report to handle.
 * @param[in]  report     Row id of the report.
 * @param[in]  task       Row id of the task.
 * @param[in]  owner      Owner of the report.
 * @param[in]  start_from 0 start from beginning, 1 continue from stopped,
 *                        2 continue if stopped else start from beginning.
 *
 * @return 0 success, -1 error.
 */
static int
handle_scan_queue_entry (const char *report_id, report_t report, task_t task,
                         user_t owner, int start_from)
{
  int rc = -1;
  gchar *owner_uuid = NULL, *owner_name = NULL;
  scanner_t scanner;

  g_debug ("Handling scan %s (%llu) for task %llu",
           report_id, report, task);

  owner_uuid = user_uuid (owner);
  owner_name = owner_uuid ? user_name (owner_uuid) : NULL;
  current_credentials.uuid = owner_uuid;
  current_credentials.username = owner_name;
  manage_session_init (current_credentials.uuid);
  current_scanner_task = task;
  global_current_report = report;

  scanner = task_scanner (task);
  if (scanner == 0)
    {
      g_warning ("%s: scanner not found", __func__);
      set_task_interrupted (task,
                            "Internal error getting scanner in queue handler");
      set_report_scan_run_status (report, TASK_STATUS_INTERRUPTED);
    }

  rc = handle_queued_scan (report_id, report, task, scanner, start_from);

  if (rc == 2)
    {
      g_debug ("Requeued scan %s (%llu) for task %llu",
               report_id, report, task);
      global_current_report = 0;
      current_scanner_task = 0;
      scan_queue_move_to_end (report);
    }
  else
    {
      g_debug ("Scan %s (%llu) for task %llu ended with return code %d",
               report_id, report, task, rc);

      scan_queue_remove (report);
      global_current_report = 0;
      current_scanner_task = 0;

      if (rc == 0)
        {
          gchar *in_assets;
          int in_assets_int;

          in_assets = task_preference_value (task, "in_assets");
          in_assets_int = atoi (in_assets);
          g_free (in_assets);

          report_set_processing_required (report, 1, in_assets_int);
        }
    }

  return 0;
}

/**
 * @brief Fork a new handler process for a given scan queue entry.
 *
 * @param[in]  report_id  UUID of the scan to handle.
 * @param[in]  report     Row id of the report.
 * @param[in]  task       Row id of the task.
 * @param[in]  owner      Owner of the report.
 * @param[in]  start_from 0 start from beginning, 1 continue from stopped,
 *                        2 continue if stopped else start from beginning.
 *
 * @return The PID of the new handler process or -1 on error.
 */
pid_t
fork_scan_handler (const char *report_id, report_t report, task_t task,
                   user_t owner, int start_from)
{
  int pipe_fds[2];
  int nbytes;
  pid_t child_pid;
  pid_t grandchild_pid;
  struct sigaction action;
  int ret;

  if (pipe (pipe_fds))
    {
      g_warning ("%s: Failed to create pipe: %s",
                 __func__, strerror (errno));
      return -1;
    }

  child_pid = fork ();
  (void) handle_scan_queue_entry;

  switch (child_pid)
    {
      case 0:
        {
          // Child
          close (pipe_fds[0]); // Close input side of pipe
          grandchild_pid = fork ();
          switch (grandchild_pid)
            {
              case 0:
                // Grandchild
                close (pipe_fds[1]);
                reinit_manage_process ();

                // Reset SIGCHLD handler to default so the process can
                // use common functions to wait for its own child processes.
                memset (&action, '\0', sizeof (action));
                sigemptyset (&action.sa_mask);
                action.sa_handler = SIG_DFL;
                action.sa_flags = 0;
                if (sigaction (SIGCHLD, &action, NULL) == -1)
                  {
                    g_critical ("%s: failed to set SIGCHLD handler: %s",
                                __func__,
                                strerror (errno));
                    gvm_close_sentry ();
                    exit (EXIT_FAILURE);
                  }

                handle_scan_queue_entry (report_id, report, task, owner,
                                         start_from);
                exit (EXIT_SUCCESS);
              case -1:
                // Child on error
                close (pipe_fds[1]);
                g_warning ("%s: fork failed: %s", __func__, strerror (errno));
                exit (EXIT_FAILURE);
              default:
                // Child on success
                ret = write (pipe_fds[1],
                             &grandchild_pid,
                             sizeof (grandchild_pid));
                if (ret < sizeof (grandchild_pid))
                  {
                    if (ret <= -1)
                      g_warning ("%s: Failed to write PID to pipe: %s",
                                 __func__, strerror (errno));
                    else
                      g_warning ("%s: Failed to write PID to pipe: %s"
                                 " (%d of %zu bytes sent)",
                                 __func__, strerror (errno),
                                 ret, sizeof (grandchild_pid));
                  }
                close (pipe_fds[1]); // Close output side of pipe
                sql_close_fork ();
                if (ret < sizeof (grandchild_pid))
                  exit (EXIT_FAILURE);
                else
                  exit (EXIT_SUCCESS);
            }
        }
      case -1:
        {
          // Parent on error
          close (pipe_fds[0]);
          close (pipe_fds[1]);
          g_warning ("%s: fork failed: %s", __func__, strerror (errno));
          return -1;
        }
      default:
        {
          // Parent on success
          int status;

          close (pipe_fds[1]); // Close output side of pipe

          // Get PID of grandchild from pipe
          grandchild_pid = 0;
          nbytes = read (pipe_fds[0], &grandchild_pid, sizeof (grandchild_pid));
          g_debug ("%s: Received pid: %d (%d bytes)",
                   __func__, grandchild_pid, nbytes);

          if (nbytes != sizeof (grandchild_pid))
            {
              if (nbytes == -1)
                g_warning ("%s: Could not read handler PID from pipe: %s",
                           __func__, strerror (errno));
              else
                g_warning ("%s: Could not read handler PID from pipe:"
                           " received %d bytes, expected %zu",
                           __func__, nbytes, sizeof (grandchild_pid));

              close (pipe_fds[0]); // Close input side of pipe
              return -1;
            }

          close (pipe_fds[0]); // Close input side of pipe

          /*  Wait to prevent zombie, then return. */
          while (waitpid (child_pid, &status, 0) < 0)
            {
              if (errno == ECHILD)
                {
                  g_warning ("%s: Failed to get child exit status",
                             __func__);
                  return -1;
                }
              if (errno == EINTR)
                continue;
              g_warning ("%s: waitpid: %s",
                         __func__,
                         strerror (errno));
              return -1;
            }

          return grandchild_pid;
        }
    }
  return -1;
}
