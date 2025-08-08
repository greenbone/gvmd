/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Greenbone Vulnerability Manager scan queue SQL.
 */

#include "manage_get.h"
#include "manage_sql_scan_queue.h"
#include "sql.h"
#include "time.h"

/**
 * @brief Remove all entries from the scan queue.
 */
void
scan_queue_clear ()
{
  sql ("TRUNCATE scan_queue;");
}

/**
 * @brief Add a scan to the queue.
 * 
 * @param[in]  report  The report of the scan to add.
 */
void
scan_queue_add (report_t report)
{
  struct timespec ts;
  
  clock_gettime (CLOCK_REALTIME, &ts);
  
  sql ("INSERT INTO scan_queue"
       " (report, queued_time_secs, queued_time_nano, handler_pid)"
       " VALUES (%llu, %ld, %ld, 0)",
       report, ts.tv_sec, ts.tv_nsec);
}

/**
 * @brief Move a scan to end of the queue and reset the pid to 0.
 * 
 * @param[in]  report  The report of the scan to move.
 */
void
scan_queue_move_to_end (report_t report)
{
  struct timespec ts;
  clock_gettime (CLOCK_REALTIME, &ts);
  sql ("UPDATE scan_queue"
       " SET queued_time_secs = %d,"
       "     queued_time_nano = %d,"
       "     handler_pid = 0"
       " WHERE report = %llu;",
       ts.tv_sec, ts.tv_nsec, report);
}

/**
 * @brief Set the pid of a scan.
 * 
 * @param[in]  report  The report of the scan to update.
 * @param[in]  pid     The pid to set.
 */
void
scan_queue_set_handler_pid (report_t report, pid_t pid)
{
  sql ("UPDATE scan_queue"
       " SET handler_pid = %d"
       " WHERE report = %llu;",
       pid, report);
}

/**
 * @brief Remove a scan from the queue.
 * 
 * @param[in]  report  The report of the scan to remove.
 */
void
scan_queue_remove (report_t report)
{
  sql ("DELETE FROM scan_queue WHERE report = %llu", report);
}

/**
 * @brief Gets the length of the gvmd scan queue.
 *
 * @return  The number of scans in the queue.
 */
int
scan_queue_length ()
{
  return sql_int ("SELECT count(*) FROM scan_queue");
}

/**
 * Initialize a scan queue iterator, with the reports and task sorted so
 *  the ones queued first are also returned first.
 * 
 * @param[in]  iterator The iterator to Initialize.
 */
void
init_scan_queue_iterator (iterator_t *iterator)
{
  init_iterator (iterator,
                 "SELECT report, handler_pid, start_from,"
                 " reports.uuid, reports.task, reports.owner"
                 " FROM scan_queue LEFT JOIN reports ON reports.id = report"
                 " ORDER BY queued_time_secs ASC, queued_time_nano ASC;");
}

/**
 * @brief Get the report row id from a scan queue iterator.
 * 
 * @return The report row id or 0 if iteration is finished.
 */
report_t
scan_queue_iterator_report (iterator_t* iterator)
{
  if (iterator->done)
    return 0;
  return iterator_int64 (iterator, 0);
}

/**
 * @brief Get the PID of the current handler from a scan queue iterator or
 *        0 if there is no active handler.
 * 
 * @return The handler PID or 0 if iteration is finished.
 */
pid_t
scan_queue_iterator_handler_pid (iterator_t *iterator)
{
  if (iterator->done)
    return 0;
  return iterator_int (iterator, 1);
}

/**
 * @brief Get where to start the scan from.
 * 
 * @return 0 start from beginning, 1 continue from stopped,
 *         2 continue if stopped else start from beginning.
 */
int
scan_queue_iterator_start_from (iterator_t* iterator)
{
  if (iterator->done)
    return 0;
  return iterator_int (iterator, 2);
}

/**
 * @brief Get the report UUID from a scan queue iterator.
 * 
 * @return The report UUID or NULL if iteration is finished.
 */
DEF_ACCESS (scan_queue_iterator_report_uuid, 3);

/**
 * @brief Get the task row id from a scan queue iterator.
 * 
 * @return The task row id or 0 if iteration is finished.
 */
task_t
scan_queue_iterator_task (iterator_t* iterator)
{
  if (iterator->done)
    return 0;
  return iterator_int64 (iterator, 4);
}

/**
 * @brief Get the report's owner row id from a scan queue iterator.
 * 
 * @return The owner row id or 0 if iteration is finished.
 */
user_t
scan_queue_iterator_owner (iterator_t* iterator)
{
  if (iterator->done)
    return 0;
  return iterator_int64 (iterator, 5);
}
