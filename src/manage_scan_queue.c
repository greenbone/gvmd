/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Greenbone Vulnerability Manager scan queue.
 */

#include "utils.h"
#include "manage_scan_queue.h"
#include "manage_scan_handler.h"
#include "manage_sql.h"
#include "manage_sql_scan_queue.h"


#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md   scan"

/**
 * @brief Option whether to use the scan queue for scanners that support it.
 */
static gboolean use_scan_queue = 0;

/**
 * @brief Minimum active time in seconds for queued scan handlers.
 *
 * Handlers will keep getting results of running scans for this time before
 *  exiting, allowing the next queued scan handler to run.
 * 
 * Note that handlers can remain active for longer in some situations like
 *  waiting for scanner responses, especially when starting a scan, or
 *  post-processing that is not delegated to a dedicated process.
 */
static int scan_handler_active_time = 0;

/**
 * @brief Maximum number of scan handlers that can be active at the same time.
 */
static int max_active_scan_handlers = DEFAULT_MAX_ACTIVE_SCAN_HANDLERS;

/**
 * @brief Sets a new value for the option whether to use the scan queue.
 * 
 * @param[in]  new_use_scan_queue  The new value to set.
 */
void
set_use_scan_queue (gboolean new_use_scan_queue)
{
  use_scan_queue = new_use_scan_queue ? 1 : 0;
}

/**
 * @brief Gets whether to use the scan queue.
 * 
 * @return The current value of the option.
 */
gboolean
get_use_scan_queue ()
{
  return use_scan_queue;
}

/**
 * @brief Sets a new minimum active time for scan handlers.
 * 
 * @param[in]  new_active_time  The new value to set.
 */
void
set_scan_handler_active_time (int new_active_time)
{
  scan_handler_active_time = new_active_time >= 0 ? new_active_time : 0;
}

/**
 * @brief Gets the minimum active time for scan handlers.
 * 
 * @return The current value of the option.
 */
int
get_scan_handler_active_time ()
{
  return scan_handler_active_time;
}

/**
 * @brief Sets a new maxmimum number of concurrently active scan handlers
 *         handled by the queue.
 * 
 * @param[in]  new_max  The new value to set.
 */
void
set_max_active_scan_handlers (int new_max)
{
  max_active_scan_handlers = (new_max > 0) ? new_max : 0;
}

/**
 * @brief Gets the maxmimum number of concurrently active scan handlers
 *         handled by the queue.
 * 
 * @return The current value of the option.
 */
int
get_max_active_scan_handlers ()
{
  return max_active_scan_handlers;
}

/**
 * @brief Handle scans in the scan queue.
 */
void
manage_handle_scan_queue ()
{
  iterator_t queue_iterator;
  int active_count = 0;
  
  if (use_scan_queue == 0)
    return;

  init_scan_queue_iterator (&queue_iterator);
  
  while (next (&queue_iterator))
    {
      pid_t handler_pid;
      report_t report;
      
      if (max_active_scan_handlers && active_count >= max_active_scan_handlers)
        {
          g_debug ("%s: one or more scans are waiting", __func__);
          break;
        }

      handler_pid = scan_queue_iterator_handler_pid (&queue_iterator);
      report = scan_queue_iterator_report (&queue_iterator);

      if (handler_pid)
        {
          if (kill (handler_pid, 0))
            {
              g_debug ("%s: %d no longer running", __func__, handler_pid);
              scan_queue_move_to_end (report);
            }
          else
            {
              active_count ++;
              g_debug ("%s: %d still active", __func__, handler_pid);
            }
        }
      else
        {
          pid_t new_handler_pid;
          const char *report_id
            = scan_queue_iterator_report_uuid (&queue_iterator);
          task_t task
            = scan_queue_iterator_task (&queue_iterator);
          user_t owner
            = scan_queue_iterator_owner (&queue_iterator);
          int start_from
            = scan_queue_iterator_start_from (&queue_iterator);
            
          new_handler_pid = fork_scan_handler (report_id, report, task, owner,
                                               start_from);
          if (new_handler_pid >= 0)
            {
              active_count ++;
              scan_queue_set_handler_pid (report, new_handler_pid);
            }
          else
            {
              scan_queue_move_to_end (report);
            }
        }
      
    }
  
}
