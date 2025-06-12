/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file scan_handler.c
 * @brief Greenbone Vulnerability Manager scan handler.
 */

#include "utils.h"
#include "manage_sql.h"
#include "manage_sql_scan_queue.h"
#include "manage_scan_handler.h"
#include <unistd.h>
#include <sys/wait.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md   scan"

/**
 * @brief Handle a scan defined a by a queue entry.
 * 
 * @param[in]  report_id  UUID of the scan to handle.
 * @param[in]  report     Row id of the scan to handle.
 * @param[in]  task       Row id of the scan to handle.
 * @param[in]  owner      Owner of the report.
 *
 * @return 0 success, -1 error.
 */
static int
handle_scan_queue_entry (const char *report_id, report_t report, task_t task,
                         user_t owner)
{
  time_t loop_end_time, last_loop_check;
  gchar *owner_uuid = NULL, *owner_name = NULL;
  int max_active_scan_handlers = get_max_active_scan_handlers ();
  gboolean scan_active, may_continue_loop;
  g_debug ("Handling scan in pid: %d | task: %llu | report: %llu",
             getpid (), task, report);

  owner_uuid = user_uuid (owner);
  owner_name = owner_uuid ? user_name (owner_uuid) : NULL;
  current_credentials.uuid = owner_uuid;
  current_credentials.username = owner_name;
  manage_session_init (current_credentials.uuid);
  // TODO: Use these when real scan handling is introduced
  // current_scanner_task = task;
  // global_current_report = report;

  loop_end_time = time (NULL) + get_scan_handler_active_time ();
  last_loop_check = 0;

  srand (getpid());

  scan_active = may_continue_loop = TRUE;
  while (scan_active && may_continue_loop)
    {
      // TODO: Replace with actual scan handling
      g_debug ("Scan handler in pid %d running", getpid ());
      gvm_sleep (1);
      scan_active = rand () % 10;

      last_loop_check = time (NULL);
      if (last_loop_check >= loop_end_time
          && scan_queue_length () > max_active_scan_handlers)
        may_continue_loop = FALSE;
    }

  if (scan_active)
    {
      g_debug ("Scan handler in pid %d requeued", getpid ());
      scan_queue_move_to_end (report);
    }
  else
    {
      g_debug ("Scan handler in pid %d finished", getpid ());
      scan_queue_remove (report);
    }

  return 0;
}

/**
 * @brief Fork a new handler process for a given scan queue entry.
 * 
 * @param[in]  report_id  UUID of the scan to handle.
 * @param[in]  report     Row id of the scan to handle.
 * @param[in]  task       Row id of the scan to handle.
 * @param[in]  owner      Owner of the report.
 *
 * @return The PID of the new handler process or -1 on error.
 */
pid_t
fork_scan_handler (const char *report_id, report_t report, task_t task,
                   user_t owner)
{
  int pipe_fds[2];
  int nbytes;
  pid_t child_pid;
  pid_t grandchild_pid;

  pipe (pipe_fds);

  child_pid = fork();
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
                handle_scan_queue_entry (report_id, report, task, owner);
                exit (EXIT_SUCCESS);
              case -1:
                // Child on error
                close(pipe_fds[1]);
                g_warning ("%s: fork failed: %s", __func__, strerror (errno));
                exit (EXIT_FAILURE);
              default:
                // Child on success
                write (pipe_fds[1], &grandchild_pid, sizeof(grandchild_pid));
                close(pipe_fds[1]); // Close output side of pipe
                sql_close_fork ();
                exit(EXIT_SUCCESS);
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

          close(pipe_fds[1]); // Close output side of pipe

          // Get PID of grandchild from pipe
          grandchild_pid = 0;
          nbytes = read(pipe_fds[0], &grandchild_pid, sizeof(grandchild_pid));
          g_debug ("%s: Received pid: %d (%d bytes)",
                   __func__, grandchild_pid, nbytes);

          if (nbytes != sizeof (grandchild_pid))
            {
              if (nbytes == -1)
                g_warning ("%s: Could not read handler PID from pipe: %s",
                           __func__, strerror (errno));
              else
                g_warning ("%s: Could not read handler PID from pipe:"
                           " received %d bytes, expected %zd",
                           __func__, nbytes, sizeof(grandchild_pid));
          
              close(pipe_fds[0]); // Close input side of pipe
              return -1;
            }
          
          close(pipe_fds[0]); // Close input side of pipe
          
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
