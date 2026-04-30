#include "manage.h"
#include "manage_schedules.h"
#include "manage_sql.h"
#include "debug_utils.h"

#include <bsd/unistd.h>
#include <sys/wait.h>

#include <gvm/base/gvm_sentry.h>
#include <gvm/gmp/gmp.h>

/**
 * @brief Default for schedule_timeout in minutes.
 */
#define SCHEDULE_TIMEOUT_DEFAULT 60

/**
 * @brief Number of minutes before overdue tasks timeout.
 */
static int schedule_timeout = SCHEDULE_TIMEOUT_DEFAULT;

/**
 * @brief Get the current schedule timeout.
 *
 * @return The schedule timeout in minutes.
 */
int
get_schedule_timeout ()
{
  return schedule_timeout;
}

/**
 * @brief Set the schedule timeout.
 *
 * @param new_timeout The new schedule timeout in minutes.
 */
void
set_schedule_timeout (int new_timeout)
{
  if (new_timeout < 0)
    schedule_timeout = -1;
  else
    schedule_timeout = new_timeout;
}

/**
 * @brief Task info, for scheduler.
 */
typedef struct
{
  gchar *owner_uuid;   ///< UUID of owner.
  gchar *owner_name;   ///< Name of owner.
  gchar *task_uuid;    ///< UUID of task.
} scheduled_task_t;

/**
 * @brief Create a schedule task structure.
 *
 * @param[in] task_uuid   UUID of task.
 * @param[in] owner_uuid  UUID of owner.
 * @param[in] owner_name  Name of owner.
 *
 * @return Scheduled task structure.
 */
static scheduled_task_t *
scheduled_task_new (const gchar* task_uuid, const gchar* owner_uuid,
                    const gchar* owner_name)
{
  scheduled_task_t *scheduled_task;

  scheduled_task = g_malloc (sizeof (*scheduled_task));
  scheduled_task->task_uuid = g_strdup (task_uuid);
  scheduled_task->owner_uuid = g_strdup (owner_uuid);
  scheduled_task->owner_name = g_strdup (owner_name);

  return scheduled_task;
}

/**
 * @brief Set UUID of user that scheduled the current task.
 *
 * @param[in] scheduled_task  Scheduled task.
 */
static void
scheduled_task_free (scheduled_task_t *scheduled_task)
{
  g_free (scheduled_task->task_uuid);
  g_free (scheduled_task->owner_uuid);
  g_free (scheduled_task->owner_name);
  g_free (scheduled_task);
}

/**
 * @brief Stop a task, for the scheduler.
 *
 * @param[in]  scheduled_task   Scheduled task.
 * @param[in]  fork_connection  Function that forks a child which is connected
 *                              to the Manager.  Must return PID in parent, 0
 *                              in child, or -1 on error.
 * @param[in]  sigmask_current  Sigmask to restore in child.
 *
 * @return 0 success, -1 error.  Child does not return.
 */
static int
scheduled_task_stop (scheduled_task_t *scheduled_task,
                     manage_connection_forker_t fork_connection,
                     sigset_t *sigmask_current)
{
  gvm_connection_t connection;
  gmp_authenticate_info_opts_t auth_opts;

  /* TODO As with starts above, this should retry if the stop failed. */

  /* Run the callback to fork a child connected to the Manager. */

  switch (fork_connection (&connection, scheduled_task->owner_uuid))
    {
      case 0:
        /* Child.  Break, stop task, exit. */
        break;

      case -1:
        /* Parent on error. */
        g_warning ("%s: stop fork failed", __func__);
        return -1;

      default:
        /* Parent.  Continue to next task. */
        return 0;
    }

  /* Stop the task. */

  setproctitle ("scheduler: stopping %s",
            scheduled_task->task_uuid);

  auth_opts = gmp_authenticate_info_opts_defaults;
  auth_opts.username = scheduled_task->owner_name;
  if (gmp_authenticate_info_ext_c (&connection, auth_opts))
    {
      scheduled_task_free (scheduled_task);
      gvm_connection_free (&connection);
      gvm_close_sentry ();
      exit (EXIT_FAILURE);
    }

  if (gmp_stop_task_c (&connection, scheduled_task->task_uuid))
    {
      scheduled_task_free (scheduled_task);
      gvm_connection_free (&connection);
      gvm_close_sentry ();
      exit (EXIT_FAILURE);
    }

  scheduled_task_free (scheduled_task);
  gvm_connection_free (&connection);
  gvm_close_sentry ();
  exit (EXIT_SUCCESS);
}

/**
 * @brief Start a task, for the scheduler.
 *
 * @param[in]  scheduled_task   Scheduled task.
 * @param[in]  fork_connection  Function that forks a child which is connected
 *                              to the Manager.  Must return PID in parent, 0
 *                              in child, or -1 on error.
 * @param[in]  sigmask_current  Sigmask to restore in child.
 *
 * @return 0 success, -1 error.  Child does not return.
 */
static int
scheduled_task_start (scheduled_task_t *scheduled_task,
                      manage_connection_forker_t fork_connection,
                      sigset_t *sigmask_current)
{
  int pid;
  gvm_connection_t connection;
  gmp_authenticate_info_opts_t auth_opts;

  /* Fork a child to start the task and wait for the response, so that the
   * parent can return to the main loop.  Only the parent returns. */

  pid = fork ();
  switch (pid)
    {
      case 0:
        /* Child.  Carry on to start the task, reopen the database (required
         * after fork). */

        /* Restore the sigmask that was blanked for pselect. */
        pthread_sigmask (SIG_SETMASK, sigmask_current, NULL);

        init_sentry ();
        reinit_manage_process ();
        manage_session_init (current_credentials.uuid);
        break;

      case -1:
        /* Parent on error. */
        g_warning ("%s: fork failed", __func__);
        return -1;

      default:
        /* Parent.  Continue to next task. */
        g_debug ("%s: %i forked %i", __func__, getpid (), pid);
        return 0;
    }

  /* Run the callback to fork a child connected to the Manager. */

  pid = fork_connection (&connection, scheduled_task->owner_uuid);
  switch (pid)
    {
      case 0:
        /* Child.  Break, start task, exit. */
        break;

      case -1:
        /* Parent on error. */
        g_warning ("%s: fork_connection failed", __func__);
        reschedule_task (scheduled_task->task_uuid);
        scheduled_task_free (scheduled_task);
        gvm_close_sentry ();
        exit (EXIT_FAILURE);
        break;

      default:
        {
          int status;

          /* Parent.  Wait for child, to check return. */

          setproctitle ("scheduler: waiting for %i", pid);

          g_debug ("%s: %i fork_connectioned %i",
                   __func__, getpid (), pid);

          if (signal (SIGCHLD, SIG_DFL) == SIG_ERR)
            g_warning ("%s: failed to set SIGCHLD", __func__);
          while (waitpid (pid, &status, 0) < 0)
            {
              if (errno == ECHILD)
                {
                  g_warning ("%s: Failed to get child exit,"
                             " so task '%s' may not have been scheduled",
                             __func__,
                             scheduled_task->task_uuid);
                  scheduled_task_free (scheduled_task);
                  gvm_close_sentry ();
                  exit (EXIT_FAILURE);
                }
              if (errno == EINTR)
                continue;
              g_warning ("%s: waitpid: %s",
                         __func__,
                         strerror (errno));
              g_warning ("%s: As a result, task '%s' may not have been"
                         " scheduled",
                         __func__,
                         scheduled_task->task_uuid);
              scheduled_task_free (scheduled_task);
              gvm_close_sentry ();
              exit (EXIT_FAILURE);
            }
          if (WIFEXITED (status))
            switch (WEXITSTATUS (status))
              {
                case EXIT_SUCCESS:
                  {
                    schedule_t schedule;
                    int periods;
                    const gchar *task_uuid;

                    /* Child succeeded, so task successfully started. */

                    task_uuid = scheduled_task->task_uuid;
                    schedule = task_schedule_uuid (task_uuid);
                    if (schedule
                        && schedule_period (schedule) == 0
                        && schedule_duration (schedule) == 0
                        /* Check next time too, in case the user changed
                         * the schedule after this task was added to the
                         * "starts" list. */
                        && task_schedule_next_time_uuid (task_uuid) == 0)
                      /* A once-off schedule without a duration, remove
                       * it from the task.  If it has a duration it
                       * will be removed by manage_schedule via
                       * clear_duration_schedules, after the duration. */
                      set_task_schedule_uuid (task_uuid, 0, -1);
                    else if ((periods = task_schedule_periods_uuid
                                         (task_uuid)))
                      {
                        /* A task restricted to a certain number of
                         * scheduled runs. */
                        if (periods > 1)
                          {
                            set_task_schedule_periods (task_uuid,
                                                       periods - 1);
                          }
                        else if (periods == 1
                                 && schedule_duration (schedule) == 0)
                          {
                            /* Last run of a task restricted to a certain
                             * number of scheduled runs. */
                            set_task_schedule_uuid (task_uuid, 0, 1);
                          }
                        else if (periods == 1)
                          /* Flag that the task has started, for
                           * update_duration_schedule_periods. */
                          set_task_schedule_next_time_uuid (task_uuid, 0);
                      }
                  }
                  scheduled_task_free (scheduled_task);
                  gvm_close_sentry ();
                  exit (EXIT_SUCCESS);

                case EXIT_FAILURE:
                default:
                  break;
              }

          /* Child failed, reset task schedule time and exit. */

          g_warning ("%s: child failed", __func__);
          reschedule_task (scheduled_task->task_uuid);
          scheduled_task_free (scheduled_task);
          gvm_close_sentry ();
          exit (EXIT_FAILURE);
        }
    }

  /* Start the task. */

  setproctitle ("scheduler: starting %s", scheduled_task->task_uuid);

  auth_opts = gmp_authenticate_info_opts_defaults;
  auth_opts.username = scheduled_task->owner_name;
  if (gmp_authenticate_info_ext_c (&connection, auth_opts))
    {
      g_warning ("%s: gmp_authenticate failed", __func__);
      scheduled_task_free (scheduled_task);
      gvm_connection_free (&connection);
      gvm_close_sentry ();
      exit (EXIT_FAILURE);
    }

  if (gmp_resume_task_report_c (&connection,
                                scheduled_task->task_uuid,
                                NULL))
    {
      gmp_start_task_opts_t opts;

      opts = gmp_start_task_opts_defaults;
      opts.task_id = scheduled_task->task_uuid;

      switch (gmp_start_task_ext_c (&connection, opts))
        {
          case 0:
            break;

          case 99:
            g_warning ("%s: user denied permission to start task", __func__);
            scheduled_task_free (scheduled_task);
            gvm_connection_free (&connection);
            gvm_close_sentry ();
            /* Return success, so that parent stops trying to start the task. */
            exit (EXIT_SUCCESS);

          default:
            g_warning ("%s: gmp_start_task and gmp_resume_task failed", __func__);
            scheduled_task_free (scheduled_task);
            gvm_connection_free (&connection);
            gvm_close_sentry ();
            exit (EXIT_FAILURE);
        }
    }

  scheduled_task_free (scheduled_task);
  gvm_connection_free (&connection);
  gvm_close_sentry ();
  exit (EXIT_SUCCESS);
}

/**
 * @brief Schedule any actions that are due.
 *
 * In gvmd, periodically called from the main daemon loop.
 *
 * @param[in]  fork_connection  Function that forks a child which is connected
 *                              to the Manager.  Must return PID in parent, 0
 *                              in child, or -1 on error.
 * @param[in]  run_tasks        Whether to run scheduled tasks.
 * @param[in]  sigmask_current  Sigmask to restore in child.
 *
 * @return 0 success, 1 failed to get lock, -1 error.
 */
int
manage_schedule (manage_connection_forker_t fork_connection,
                 gboolean run_tasks,
                 sigset_t *sigmask_current)
{
  iterator_t schedules;
  GSList *starts, *stops;
  int ret;
  task_t previous_start_task, previous_stop_task;

  starts = NULL;
  stops = NULL;
  previous_start_task = 0;
  previous_stop_task = 0;

  auto_delete_reports ();

  ret = manage_update_nvti_cache ();
  if (ret)
    {
      if (ret == -1)
        {
          g_warning ("%s: manage_update_nvti_cache error"
                     " (Perhaps the db went down?)",
                     __func__);
          /* Just ignore, in case the db went down temporarily. */
          return 0;
        }

      return ret;
    }

  if (run_tasks == 0)
    return 0;

  /* Assemble "starts" and "stops" list containing task uuid, owner name and
   * owner UUID for each (scheduled) task to start or stop. */

  ret = init_task_schedule_iterator (&schedules);
  if (ret)
    {
      if (ret == -1)
        {
          g_warning ("%s: iterator init error"
                     " (Perhaps the db went down?)",
                     __func__);
          /* Just ignore, in case the db went down temporarily. */
          return 0;
        }

      return ret;
    }
  /* This iterator runs in a transaction. */
  while (next (&schedules))
    if (task_schedule_iterator_start_due (&schedules))
      {
        const char *icalendar, *zone;
        int timed_out;

        /* Check if task schedule is timed out before updating next due time */
        timed_out = task_schedule_iterator_timed_out (&schedules);

        /* Update the task schedule info to prevent multiple schedules. */

        icalendar = task_schedule_iterator_icalendar (&schedules);
        zone = task_schedule_iterator_timezone (&schedules);

        g_debug ("%s: start due for %llu, setting next_time",
                 __func__,
                 task_schedule_iterator_task (&schedules));
        set_task_schedule_next_time
         (task_schedule_iterator_task (&schedules),
          icalendar_next_time_from_string (icalendar, time(NULL), zone, 0));

        /* Skip this task if it was already added to the starts list
         * to avoid conflicts between multiple users with permissions. */

        if (previous_start_task == task_schedule_iterator_task (&schedules))
          continue;

        if (timed_out)
          {
            g_message (" %s: Task timed out: %s",
                       __func__,
                       task_schedule_iterator_task_uuid (&schedules));
            continue;
          }

        previous_start_task = task_schedule_iterator_task (&schedules);

        /* Add task UUID and owner name and UUID to the list. */

        starts = g_slist_prepend
                  (starts,
                   scheduled_task_new
                    (task_schedule_iterator_task_uuid (&schedules),
                     task_schedule_iterator_owner_uuid (&schedules),
                     task_schedule_iterator_owner_name (&schedules)));
      }
    else if (task_schedule_iterator_stop_due (&schedules))
      {
        /* Skip this task if it was already added to the stops list
         * to avoid conflicts between multiple users with permissions. */

        if (previous_stop_task == task_schedule_iterator_task (&schedules))
          continue;
        previous_stop_task = task_schedule_iterator_task (&schedules);

        /* Add task UUID and owner name and UUID to the list. */

        stops = g_slist_prepend
                 (stops,
                  scheduled_task_new
                   (task_schedule_iterator_task_uuid (&schedules),
                    task_schedule_iterator_owner_uuid (&schedules),
                    task_schedule_iterator_owner_name (&schedules)));
      }
  cleanup_task_schedule_iterator (&schedules);

  /* Start tasks in forked processes, now that the SQL statement is closed. */

  while (starts)
    {
      scheduled_task_t *scheduled_task;
      GSList *head;

      scheduled_task = starts->data;

      head = starts;
      starts = starts->next;
      g_slist_free_1 (head);

      if (scheduled_task_start (scheduled_task,
                                fork_connection,
                                sigmask_current))
        /* Error.  Reschedule and continue to next task. */
        reschedule_task (scheduled_task->task_uuid);
      scheduled_task_free (scheduled_task);
    }

  /* Stop tasks in forked processes, now that the SQL statement is closed. */

  while (stops)
    {
      scheduled_task_t *scheduled_task;
      GSList *head;

      scheduled_task = stops->data;
      head = stops;
      stops = stops->next;
      g_slist_free_1 (head);

      if (scheduled_task_stop (scheduled_task,
                               fork_connection,
                               sigmask_current))
        {
          /* Error.  Exit. */
          scheduled_task_free (scheduled_task);
          while (stops)
            {
              scheduled_task_free (stops->data);
              stops = g_slist_delete_link (stops, stops);
            }
          return -1;
        }
      scheduled_task_free (scheduled_task);
    }

  clear_duration_schedules (0);
  update_duration_schedule_periods (0);

  return 0;
}
