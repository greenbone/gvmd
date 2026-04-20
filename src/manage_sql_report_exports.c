/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "gvmd_config.h"
#include "manage_report_exports.h"
#include "manage_settings.h"
#include "manage_sql.h"


static int report_export_max_retries = 10;

void
init_report_exports_from_config ()
{
  GKeyFile *kf = get_gvmd_config ();
  if (kf == NULL)
    {
      return;
    }

  gboolean has_max_retries = FALSE;
  int max_retries = 0;

  gvmd_config_get_int (kf, "report_export", "max_retries", &has_max_retries,
                       &max_retries);

  if (has_max_retries)
    {
      report_export_max_retries = max_retries;
      g_warning("max_retries: %d", report_export_max_retries);
    }
}

/**
 * @brief Checks if the automatic export to security intelligence is enabled
 *        by the owner of the given report
 *
 * @param  report  The report to check
 *
 * @return TRUE if enabled, FALSE otherwise
 */
gboolean
export_enabled_for_report_owner (report_t report)
{
  return !!sql_int_ps (
    "SELECT s.value FROM reports AS r"
    " INNER JOIN settings AS s ON r.owner = s.owner"
    " WHERE r.id = $1"
    " AND s.uuid = $2",
    SQL_INT_PARAM (report),
    SQL_STR_PARAM (SETTING_UUID_SECURITY_INTELLIGENCE_EXPORT), NULL);
}

/**
 * @brief Queue the given report for automatic export to security intelligence
 *
 * @param  report  The report to queue
 *
 * @return 0 on success, -1 on failure
 */
int
queue_report_for_export (const report_t report)
{
  init_report_exports_from_config();

  if (!export_enabled_for_report_owner (report))
    return -1;

  sql_ps ("INSERT INTO report_exports (report_id, status, retry_count,"
          "                            reason, next_retry_time,"
          "                            creation_time, modification_time)"
          " VALUES ($1, 'report_export_requested', 0, 'Queued',"
          "         m_now(), m_now(), m_now())",
          SQL_INT_PARAM (report), NULL);

  return 0;
}

/**
 * @brief Update report export status with a reason
 *
 * @param  report   The report ID that is in export queue
 * @param  status   The new status
 * @param  reason   The reason for the status
 */
void
set_report_export_status_and_reason (report_t report, const gchar *status,
                                     const gchar *reason)
{
  sql_ps ("UPDATE report_exports"
          "   SET status = $1, reason = $2"
          " WHERE report_id = $3",
          SQL_STR_PARAM (status),
          SQL_STR_PARAM (reason),
          SQL_INT_PARAM (report),
          NULL);
}

/**
 * @brief Update report export next retry time
 *
 * @param  report           The report ID that is in export queue
 * @param  next_retry_time  The new next retry time
 */
void
set_report_export_next_retry_time (report_t report, time_t next_retry_time)
{
  sql_ps ("UPDATE report_exports"
          "   SET next_retry_time = $1"
          " WHERE report_id = $2",
          SQL_INT_PARAM (next_retry_time), SQL_INT_PARAM (report), NULL);
}

/**
 * @brief Update report export retry count
 *
 * @param  report           The report ID that is in export queue
 * @param  retry_count      The new retry count
 */
void
set_report_export_retry_count (report_t report, int retry_count)
{
  sql_ps ("UPDATE report_exports"
          "   SET retry_count = $1"
          " WHERE report_id = $2",
          SQL_INT_PARAM (retry_count), SQL_INT_PARAM (report), NULL);
}

/**
 * @brief Initialize report export iterator to fetch
 *        all exports that are due now
 *
 * @param[out] iterator iterator to initialize
 *
 * @return 0 on success
 */
int
init_report_export_iterator_due_exports (iterator_t *iterator)
{
  int max_retry_count = 0;
  gvmd_config_resolve_int ("GVMD_REPORT_EXPORT_MAX_RETRIES", TRUE,
                           report_export_max_retries, &max_retry_count);

  init_ps_iterator (iterator,
                    "SELECT id, report_id, status, reason,"
                    "    retry_count, next_retry_time,"
                    "    creation_time, modification_time"
                    " FROM report_exports"
                    " WHERE   next_retry_time < m_now()"
                    " AND     retry_count < $1"
                    " AND     status IN ('report_export_requested',"
                    "                    'report_export_failed')",
                    SQL_INT_PARAM (max_retry_count), NULL);

  return 0;
}

/**
 * @brief Get the report id from a report export iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Report id, or 0 if iteration is complete. Freed by
 *         cleanup_iterator.
 */
report_t
report_export_iterator_report_id (iterator_t *iterator)
{
  if (iterator->done)
    return 0;
  return iterator_int64 (iterator, 1);
}

/**
 * @brief Get the status from a report export iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Status, or 0 if iteration is complete. Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (report_export_iterator_status, 2);

/**
 * @brief Get the reason from a report export iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Reason, or 0 if iteration is complete. Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (report_export_iterator_reason, 3);

/**
 * @brief Get the retry count from a report export iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Retry count, or 0 if iteration is complete. Freed by
 *         cleanup_iterator.
 */
int
report_export_iterator_retry_count (iterator_t *iterator)
{
  if (iterator->done)
    return 0;
  return iterator_int (iterator, 4);
}

/**
 * @brief Get the next retry time from a report export iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Next retry time, or 0 if iteration is complete. Freed by
 *         cleanup_iterator.
 */
time_t
report_export_iterator_next_retry_time (iterator_t *iterator)
{
  if (iterator->done)
    return 0;
  return iterator_int64 (iterator, 5);
}

/**
 * @brief Get the creation time from a report export iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Creation time, or 0 if iteration is complete. Freed by
 *         cleanup_iterator.
 */
time_t
report_export_iterator_creation_time (iterator_t *iterator)
{
  if (iterator->done)
    return 0;
  return iterator_int64 (iterator, 6);
}

/**
 * @brief Get the modification time from a report export iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Modification time, or 0 if iteration is complete. Freed by
 *         cleanup_iterator.
 */
time_t
report_export_iterator_modification_time (iterator_t *iterator)
{
  if (iterator->done)
    return 0;
  return iterator_int64 (iterator, 7);
}
