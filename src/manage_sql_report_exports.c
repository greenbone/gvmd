/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM SQL management layer: Report exports.
 */

#include "manage_sql_report_exports.h"

#include "manage_sql.h"

#undef G_LOG_DOMAIN

/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief SQL joins used by report export iterators.
 */
#define REPORT_EXPORT_ITERATOR_JOIN_CLAUSE                                \
  " LEFT JOIN"                                                            \
  " (SELECT id AS report_id,"                                             \
  "         uuid AS report_uuid"                                          \
  "    FROM reports)"                                                     \
  " AS report_data"                                                       \
  " ON report_data.report_id = report_exports.report"                     \
  " LEFT JOIN"                                                            \
  " (SELECT id AS delta_report_id,"                                       \
  "         uuid AS delta_report_uuid"                                    \
  "    FROM reports)"                                                     \
  " AS delta_report_data"                                                 \
  " ON delta_report_data.delta_report_id = report_exports.delta_report"   \
  " LEFT JOIN"                                                            \
  " (SELECT id AS report_format_id,"                                      \
  "         uuid AS report_format_uuid,"                                  \
  "         name AS report_format_name"                                   \
  "    FROM report_formats)"                                              \
  " AS report_format_data"                                                \
  " ON report_format_data.report_format_id"                               \
  "    = report_exports.report_format"                                    \
  " LEFT JOIN"                                                            \
  " (SELECT id AS report_config_id,"                                      \
  "         uuid AS report_config_uuid,"                                  \
  "         name AS report_config_name"                                   \
  "    FROM report_configs)"                                              \
  " AS report_config_data"                                                \
  " ON report_config_data.report_config_id"                               \
  "    = report_exports.report_config"

/**
 * @brief Initialize a SQL-based report export iterator.
 *
 * @param[out] iterator     Iterator to initialize.
 * @param[in]  get          GET parameters.
 * @param[in]  where_clause Optional additional SQL condition.
 *
 * @return 0 on success, -1 on failure.
 */
static int
init_report_export_iterator_with_where (iterator_t *iterator,
                                        get_data_t *get,
                                        const gchar *where_clause)
{
  static column_t columns[] = REPORT_EXPORT_ITERATOR_COLUMNS;
  static const char *filter_columns[]
    = REPORT_EXPORT_ITERATOR_FILTER_COLUMNS;

  g_return_val_if_fail (iterator, -1);
  g_return_val_if_fail (get, -1);

  return init_get_iterator (
    iterator,
    "report_export",
    get,
    columns,
    NULL, /* No trash columns. */
    filter_columns,
    0, /* No trashcan. */
    REPORT_EXPORT_ITERATOR_JOIN_CLAUSE,
    where_clause,
    0);
}

/**
 * @brief Initialize an iterator for a report export row ID.
 *
 * @param[out] iterator      Iterator to initialize.
 * @param[in]  report_export Report export row ID.
 *
 * @return 0 on success, -1 on failure.
 */
static int
init_report_export_iterator_by_id (iterator_t *iterator,
                                   report_export_t report_export)
{
  get_data_t get = {0};
  gchar *where_clause;
  int ret;

  g_return_val_if_fail (iterator, -1);

  if (report_export == 0)
    return -1;

  where_clause = g_strdup_printf (
    " AND report_exports.id = %lld",
    report_export);

  ret = init_report_export_iterator_with_where (
    iterator,
    &get,
    where_clause);

  g_free (where_clause);

  return ret;
}

/**
 * @brief Initialize a SQL-based report export iterator.
 *
 * @param[out] iterator  Iterator to initialize.
 * @param[in]  get       GET parameters containing filtering criteria.
 *
 * @return 0 on success, -1 on failure.
 */
int
init_report_export_iterator (iterator_t *iterator, get_data_t *get)
{
  gchar *quoted = NULL;
  gchar *where_clause = NULL;
  int ret;

  g_return_val_if_fail (iterator, -1);
  g_return_val_if_fail (get, -1);

  if (get->id)
    {
      quoted = sql_quote (get->id);

      where_clause = g_strdup_printf (
        "report_exports.uuid = '%s'",
        quoted);
    }

  ret = init_report_export_iterator_with_where (iterator,
                                                get,
                                                where_clause);

  g_free (where_clause);
  g_free (quoted);

  return ret;
}

/**
 * @brief Find the latest report export with the same request parameters.
 *
 * @param[in]  report              Report to export.
 * @param[in]  delta_report        Optional delta report.
 * @param[in]  report_format       Report format.
 * @param[in]  report_config       Optional report configuration.
 * @param[in]  export_type         Report export type.
 * @param[in]  filter              Optional report filter.
 * @param[in]  ignore_pagination   Whether pagination is ignored.
 * @param[in]  lean                Whether lean report data is requested.
 * @param[in]  notes_details       Whether note details are requested.
 * @param[in]  overrides_details   Whether override details are requested.
 * @param[in]  result_tags         Whether result tags are requested.
 * @param[out] report_export       Matching report export, or 0 if not found.
 * @param[out] status              Status of the matching export.
 *
 * @return 0 on success, including when no matching row exists, or -1 on
 *         invalid arguments.
 */
static int
find_matching_report_export (
  report_t report,
  report_t delta_report,
  report_format_t report_format,
  report_config_t report_config,
  report_export_type_t export_type,
  const gchar *filter,
  gboolean ignore_pagination,
  gboolean lean,
  gboolean notes_details,
  gboolean overrides_details,
  gboolean result_tags,
  report_export_t *report_export,
  report_export_status_t *status)
{
  const gchar *normalized_filter;
  iterator_t iterator;

  if (report == 0
      || report_format == 0
      || report_export == NULL
      || status == NULL)
    return -1;

  *report_export = 0;
  *status = REPORT_EXPORT_STATUS_EXPIRED;

  normalized_filter = filter ? filter : "";

  init_ps_iterator (
    &iterator,
    "SELECT id, status"
    "  FROM report_exports"
    " WHERE owner ="
    "       (SELECT id"
    "          FROM users"
    "         WHERE uuid = $1)"
    "   AND report = $2"
    "   AND COALESCE (delta_report, 0) = $3"
    "   AND report_format = $4"
    "   AND COALESCE (report_config, 0) = $5"
    "   AND export_type = $6"
    "   AND COALESCE (filter, '') = $7"
    "   AND ignore_pagination = $8"
    "   AND lean = $9"
    "   AND notes_details = $10"
    "   AND overrides_details = $11"
    "   AND result_tags = $12"
    " ORDER BY creation_time DESC"
    " LIMIT 1",
    SQL_STR_PARAM (current_credentials.uuid),
    SQL_RESOURCE_PARAM (report),
    SQL_RESOURCE_PARAM (delta_report),
    SQL_RESOURCE_PARAM (report_format),
    SQL_RESOURCE_PARAM (report_config),
    SQL_INT_PARAM (export_type),
    SQL_STR_PARAM (normalized_filter),
    SQL_INT_PARAM (ignore_pagination),
    SQL_INT_PARAM (lean),
    SQL_INT_PARAM (notes_details),
    SQL_INT_PARAM (overrides_details),
    SQL_INT_PARAM (result_tags),
    NULL);

  if (next (&iterator))
    {
      *report_export =
        (report_export_t) iterator_int64 (&iterator, 0);

      *status =
        (report_export_status_t) iterator_int (&iterator, 1);
    }

  cleanup_iterator (&iterator);

  if (*report_export
      && report_export_status_valid (*status) == FALSE)
    {
      *report_export = 0;
      return -1;
    }

  return 0;
}

/**
 * @brief Queue a report export or reuse an identical export.
 *
 * Pending and running exports are reused. Failed, canceled,
 * cancel-requested and expired exports are replaced by a new export.
 *
 * @param[in]  report              Report to export.
 * @param[in]  delta_report        Optional delta report.
 * @param[in]  report_format       Report format to use.
 * @param[in]  report_config       Optional report configuration.
 * @param[in]  export_type         Type of report export.
 * @param[in]  name                Report export name.
 * @param[in]  comment             Optional report export comment.
 * @param[in]  filter              Optional report filter.
 * @param[in]  ignore_pagination   Whether to ignore pagination.
 * @param[in]  lean                Whether to generate lean report data.
 * @param[in]  notes_details       Whether to include note details.
 * @param[in]  overrides_details   Whether to include override details.
 * @param[in]  result_tags         Whether to include result tags.
 * @param[out] report_export       Existing or newly created report export.
 * @param[out] status              Current status of the returned export.
 * @param[out] created             TRUE if a new row was inserted.
 *
 * @return 0 on success or -1 on failure.
 */
int
create_report_export (report_t report,
                      report_t delta_report,
                      report_format_t report_format,
                      report_config_t report_config,
                      report_export_type_t export_type,
                      const gchar *name,
                      const gchar *comment,
                      const gchar *filter,
                      gboolean ignore_pagination,
                      gboolean lean,
                      gboolean notes_details,
                      gboolean overrides_details,
                      gboolean result_tags,
                      report_export_t *report_export,
                      report_export_status_t *status,
                      gboolean *created)
{
  const gchar *normalized_filter;
  report_export_status_t existing_status;
  report_export_t existing_report_export;
  report_export_t new_report_export;
  int ret;

  if (report == 0
      || report_format == 0
      || name == NULL
      || report_export == NULL
      || status == NULL
      || created == NULL)
    return -1;

  *report_export = 0;
  *status = REPORT_EXPORT_STATUS_PENDING;
  *created = FALSE;

  normalized_filter = filter ? filter : "";

  existing_report_export = 0;
  existing_status = REPORT_EXPORT_STATUS_EXPIRED;

  ret = find_matching_report_export (
    report,
    delta_report,
    report_format,
    report_config,
    export_type,
    normalized_filter,
    ignore_pagination,
    lean,
    notes_details,
    overrides_details,
    result_tags,
    &existing_report_export,
    &existing_status);

  if (ret)
    return -1;

  if (existing_report_export)
    {
      switch (existing_status)
        {
        case REPORT_EXPORT_STATUS_PENDING:
        case REPORT_EXPORT_STATUS_RUNNING:
          *report_export = existing_report_export;
          *status = existing_status;
          *created = FALSE;
          return 0;

        case REPORT_EXPORT_STATUS_ERROR:
        case REPORT_EXPORT_STATUS_CANCEL_REQUESTED:
        case REPORT_EXPORT_STATUS_CANCELED:
        case REPORT_EXPORT_STATUS_EXPIRED:
        case REPORT_EXPORT_STATUS_DONE:
          /*
           * Do not reuse this export. Continue and create a new row.
           */
          break;

        default:
          return -1;
        }
    }

  sql_ps (
    "INSERT INTO report_exports"
    " (uuid,"
    "  owner,"
    "  name,"
    "  comment,"
    "  report,"
    "  delta_report,"
    "  report_format,"
    "  report_config,"
    "  export_type,"
    "  status,"
    "  progress,"
    "  filter,"
    "  ignore_pagination,"
    "  lean,"
    "  notes_details,"
    "  overrides_details,"
    "  result_tags,"
    "  attempt_count,"
    "  creation_time,"
    "  modification_time)"
    " VALUES"
    " (make_uuid (),"
    "  (SELECT id FROM users WHERE uuid = $1),"
    "  $2,"
    "  $3,"
    "  $4,"
    "  NULLIF ($5, 0),"
    "  $6,"
    "  NULLIF ($7, 0),"
    "  $8,"
    "  $9,"
    "  $10,"
    "  $11,"
    "  $12,"
    "  $13,"
    "  $14,"
    "  $15,"
    "  $16,"
    "  0,"
    "  m_now (),"
    "  m_now ());",
    SQL_STR_PARAM (current_credentials.uuid),
    SQL_STR_PARAM (name),
    SQL_STR_PARAM (comment),
    SQL_INT_PARAM (report),
    SQL_INT_PARAM (delta_report),
    SQL_INT_PARAM (report_format),
    SQL_INT_PARAM (report_config),
    SQL_INT_PARAM (export_type),
    SQL_INT_PARAM (REPORT_EXPORT_STATUS_PENDING),
    SQL_INT_PARAM (REPORT_EXPORT_PROGRESS_QUEUED),
    SQL_STR_PARAM (normalized_filter),
    SQL_INT_PARAM (ignore_pagination),
    SQL_INT_PARAM (lean),
    SQL_INT_PARAM (notes_details),
    SQL_INT_PARAM (overrides_details),
    SQL_INT_PARAM (result_tags),
    NULL);

  new_report_export = sql_last_insert_id ();

  if (new_report_export == 0)
    return -1;

  *report_export = new_report_export;
  *status = REPORT_EXPORT_STATUS_PENDING;
  *created = TRUE;

  return 0;
}

/**
 * @brief Get the status of a report export.
 *
 * @param[in]  report_export  Report export.
 * @param[out] status         Current report export status.
 *
 * @return 0 on success, -1 if the export does not exist, the stored status
 *         is invalid, or the arguments are invalid.
 */
int
get_report_export_status (report_export_t report_export,
                          report_export_status_t *status)
{
  int value;

  if (report_export == 0 || status == NULL)
    return -1;

  if (sql_int_ps (
        "SELECT count (*)"
        "  FROM report_exports"
        " WHERE id = $1",
        SQL_RESOURCE_PARAM (report_export),
        NULL)
      == 0)
    return -1;

  value = sql_int_ps (
    "SELECT status"
    "  FROM report_exports"
    " WHERE id = $1",
    SQL_RESOURCE_PARAM (report_export),
    NULL);

  if (report_export_status_valid ((report_export_status_t) value) == FALSE)
    return -1;

  *status = (report_export_status_t) value;

  return 0;
}

/**
 * @brief Get the status and progress of a report export.
 *
 * @param[in]  report_export  Report export.
 * @param[out] status         Current report export status.
 * @param[out] progress       Current report export progress.
 *
 * @return 0 on success, -1 if the export does not exist or arguments are
 *         invalid.
 */
int
get_report_export_status_and_progress (
  report_export_t report_export,
  report_export_status_t *status,
  report_export_progress_t *progress)
{
  iterator_t iterator;
  int status_value;
  int progress_value;

  if (report_export == 0 || status == NULL || progress == NULL)
    return -1;

  init_ps_iterator (
    &iterator,
    "SELECT status, progress"
    "  FROM report_exports"
    " WHERE id = $1",
    SQL_RESOURCE_PARAM (report_export),
    NULL);

  if (next (&iterator) == FALSE)
    {
      cleanup_iterator (&iterator);
      return -1;
    }

  status_value = iterator_int (&iterator, 0);
  progress_value = iterator_int (&iterator, 1);

  cleanup_iterator (&iterator);

  if (status_value < REPORT_EXPORT_STATUS_PENDING
      || status_value > REPORT_EXPORT_STATUS_EXPIRED)
    return -1;

  if (progress_value < REPORT_EXPORT_PROGRESS_QUEUED
      || progress_value > REPORT_EXPORT_PROGRESS_COMPLETED)
    return -1;

  *status = (report_export_status_t) status_value;
  *progress = (report_export_progress_t) progress_value;

  return 0;
}

/**
 * @brief Get the worker process ID handling a report export.
 *
 * @param[in]  report_export  Report export.
 * @param[out] worker_pid     PID of the worker process.
 *
 * @return 0 on success, -1 if the export does not exist or arguments are
 *         invalid.
 */
int
get_report_export_worker_pid (report_export_t report_export,
                              int *worker_pid)
{
  if (report_export == 0 || worker_pid == NULL)
    return -1;

  *worker_pid = sql_int_ps (
    "SELECT COALESCE (worker_pid, 0)"
    "  FROM report_exports"
    " WHERE id = $1",
    SQL_RESOURCE_PARAM (report_export),
    NULL);

  return 0;
}

/**
 * @brief Update report export status.
 *
 * @param[in] report_export  Report export.
 * @param[in] status         New status.
 */
void
set_report_export_status (report_export_t report_export,
                          report_export_status_t status)
{
  sql_ps (
    "UPDATE report_exports"
    "   SET status = $1,"
    "       modification_time = m_now ()"
    " WHERE id = $2",
    SQL_INT_PARAM (status),
    SQL_RESOURCE_PARAM (report_export),
    NULL);
}

/**
 * @brief Update report export progress.
 *
 * @param[in] report_export  Report export.
 * @param[in] progress       New progress stage.
 */
void
set_report_export_progress (report_export_t report_export,
                            report_export_progress_t progress)
{
  sql_ps (
    "UPDATE report_exports"
    "   SET progress = $1,"
    "       modification_time = m_now ()"
    " WHERE id = $2",
    SQL_INT_PARAM (progress),
    SQL_RESOURCE_PARAM (report_export),
    NULL);
}

/**
 * @brief Mark a report export as running.
 *
 * @param[in] report_export  Report export.
 * @param[in] worker_pid     Worker process ID.
 */
void
start_report_export (report_export_t report_export,
                     int worker_pid)
{
  sql_ps (
    "UPDATE report_exports"
    "   SET status = $1,"
    "       progress = $2,"
    "       worker_pid = $3,"
    "       start_time = m_now (),"
    "       end_time = NULL,"
    "       attempt_count = attempt_count + 1,"
    "       error_message = NULL,"
    "       modification_time = m_now ()"
    " WHERE id = $4",
    SQL_INT_PARAM (REPORT_EXPORT_STATUS_RUNNING),
    SQL_INT_PARAM (REPORT_EXPORT_PROGRESS_PREPARING),
    SQL_INT_PARAM (worker_pid),
    SQL_RESOURCE_PARAM (report_export),
    NULL);
}

/**
 * @brief Mark a report export as completed.
 *
 * @param[in] report_export  Report export.
 * @param[in] file_path      Path of generated file.
 * @param[in] file_size      Size of generated file.
 * @param[in] content_type   Content type of generated file.
 * @param[in] extension      File extension.
 */
void
complete_report_export (report_export_t report_export,
                        const gchar *file_path,
                        long long file_size,
                        const gchar *content_type,
                        const gchar *extension)
{
  sql_ps (
    "UPDATE report_exports"
    "   SET status = $1,"
    "       progress = $2,"
    "       worker_pid = NULL,"
    "       file_path = $3,"
    "       file_size = $4,"
    "       content_type = $5,"
    "       extension = $6,"
    "       error_message = NULL,"
    "       end_time = m_now (),"
    "       modification_time = m_now ()"
    " WHERE id = $7",
    SQL_INT_PARAM (REPORT_EXPORT_STATUS_DONE),
    SQL_INT_PARAM (REPORT_EXPORT_PROGRESS_COMPLETED),
    SQL_STR_PARAM (file_path),
    SQL_RESOURCE_PARAM (file_size),
    SQL_STR_PARAM (content_type),
    SQL_STR_PARAM (extension),
    SQL_RESOURCE_PARAM (report_export),
    NULL);
}

/**
 * @brief Mark a report export as failed.
 *
 * @param[in] report_export  Report export.
 * @param[in] error_message  Error description.
 */
void
fail_report_export (report_export_t report_export,
                    const gchar *error_message)
{
  sql_ps (
    "UPDATE report_exports"
    "   SET status = $1,"
    "       error_message = $2,"
    "       worker_pid = NULL,"
    "       end_time = m_now (),"
    "       modification_time = m_now ()"
    " WHERE id = $3",
    SQL_INT_PARAM (REPORT_EXPORT_STATUS_ERROR),
    SQL_STR_PARAM (error_message),
    SQL_RESOURCE_PARAM (report_export),
    NULL);
}

/**
 * @brief Request cancellation of a report export.
 *
 * @param[in] report_export  Report export.
 */
void
request_report_export_cancel (report_export_t report_export)
{
  sql_ps (
    "UPDATE report_exports"
    "   SET status = $1,"
    "       modification_time = m_now ()"
    " WHERE id = $2"
    "   AND status IN ($3, $4)",
    SQL_INT_PARAM (REPORT_EXPORT_STATUS_CANCEL_REQUESTED),
    SQL_RESOURCE_PARAM (report_export),
    SQL_INT_PARAM (REPORT_EXPORT_STATUS_PENDING),
    SQL_INT_PARAM (REPORT_EXPORT_STATUS_RUNNING),
    NULL);
}

/**
 * @brief Mark a report export as canceled.
 *
 * @param[in] report_export  Report export.
 */
void
cancel_report_export (report_export_t report_export)
{
  sql_ps (
    "UPDATE report_exports"
    "   SET status = $1,"
    "       worker_pid = NULL,"
    "       end_time = m_now (),"
    "       modification_time = m_now ()"
    " WHERE id = $2",
    SQL_INT_PARAM (REPORT_EXPORT_STATUS_CANCELED),
    SQL_RESOURCE_PARAM (report_export),
    NULL);
}

/**
 * @brief Reset a report export for another processing attempt.
 *
 * @param[in] report_export  Report export.
 */
void
reset_report_export (report_export_t report_export)
{
  sql_ps (
    "UPDATE report_exports"
    "   SET status = $1,"
    "       progress = $2,"
    "       worker_pid = NULL,"
    "       start_time = NULL,"
    "       end_time = NULL,"
    "       error_message = NULL,"
    "       modification_time = m_now ()"
    " WHERE id = $3",
    SQL_INT_PARAM (REPORT_EXPORT_STATUS_PENDING),
    SQL_INT_PARAM (REPORT_EXPORT_PROGRESS_QUEUED),
    SQL_RESOURCE_PARAM (report_export),
    NULL);
}

/**
 * @brief Count the number of report exports currently being processed.
 *
 * @return Number of report exports with a non-null worker PID and a status
 *         of running or cancel-requested.
 */
int
report_export_worker_pid_count ()
{
  return sql_int_ps (
    "SELECT count(*)"
    " FROM report_exports"
    " WHERE worker_pid IS NOT NULL"
    "   AND status IN ($1, $2)",
    SQL_INT_PARAM (REPORT_EXPORT_STATUS_RUNNING),
    SQL_INT_PARAM (REPORT_EXPORT_STATUS_CANCEL_REQUESTED),
    NULL);
}

/**
 * @brief Get the export type of a report export.
 *
 * @param[in]  report_export  Report export.
 * @param[out] export_type    Current report export type.
 *
 * @return 0 on success, -1 if the export does not exist, the stored type
 *         is invalid, or the arguments are invalid.
 */
int
get_report_export_type (report_export_t report_export,
                        report_export_type_t *export_type)
{
  int value;

  if (report_export == 0 || export_type == NULL)
    return -1;

  if (sql_int_ps (
        "SELECT count (*)"
        "  FROM report_exports"
        " WHERE id = $1",
        SQL_RESOURCE_PARAM (report_export),
        NULL)
      == 0)
    return -1;

  value = sql_int_ps (
    "SELECT export_type"
    "  FROM report_exports"
    " WHERE id = $1",
    SQL_RESOURCE_PARAM (report_export),
    NULL);

  if (report_export_type_valid ((report_export_type_t) value) == FALSE)
    return -1;

  *export_type = (report_export_type_t) value;

  return 0;
}

/**
 * @brief Initialize an iterator over pending report exports.
 *
 * @param[out] iterator      Iterator to initialize.
 * @param[in]  get           GET parameters.
 * @param[in]  max_attempts  Maximum allowed processing attempts.
 *
 * @return 0 on success, -1 on failure.
 */
int
init_report_export_iterator_pending (iterator_t *iterator,
                                     get_data_t *get,
                                     int max_attempts)
{
  gchar *where_clause;
  int ret;

  g_return_val_if_fail (iterator, -1);
  g_return_val_if_fail (get, -1);

  where_clause = g_strdup_printf (
    " AND report_exports.status = %d"
    " AND report_exports.attempt_count < %d",
    REPORT_EXPORT_STATUS_PENDING,
    max_attempts);

  ret = init_report_export_iterator_with_where (iterator,
                                                get,
                                                where_clause);

  g_free (where_clause);

  return ret;
}

/**
 * @brief Initialize an iterator over stale running report exports.
 *
 * @param[out] iterator   Iterator to initialize.
 * @param[in]  get        GET parameters.
 * @param[in]  threshold  Modification-time threshold.
 *
 * @return 0 on success, -1 on failure.
 */
int
init_report_export_iterator_stale (iterator_t *iterator,
                                   get_data_t *get,
                                   time_t threshold)
{
  gchar *where_clause;
  int ret;

  g_return_val_if_fail (iterator, -1);
  g_return_val_if_fail (get, -1);

  where_clause = g_strdup_printf (
    "AND report_exports.status = %d"
    " AND report_exports.modification_time < %lld",
    REPORT_EXPORT_STATUS_RUNNING,
    (long long) threshold);

  ret = init_report_export_iterator_with_where (iterator,
                                                get,
                                                where_clause);

  g_free (where_clause);

  return ret;
}

/**
 * @brief Load report export data.
 *
 * @param[in]  report_export  Report export to load.
 * @param[out] data           Report export data to fill.
 *
 * @return 0 on success, 1 if not found, and -1 on failure.
 */
int
load_report_export_data (report_export_t report_export,
                         report_export_data_t data)
{
  iterator_t iterator;

  if (report_export == 0 || data == NULL)
    return -1;

  if (init_report_export_iterator_by_id (&iterator, report_export))
    return -1;

  if (next (&iterator) == FALSE)
    {
      cleanup_iterator (&iterator);
      return 1;
    }

  data->row_id = report_export;

  data->uuid = g_strdup (
    get_iterator_uuid (&iterator));
  data->name = g_strdup (
    get_iterator_name (&iterator));
  data->comment = g_strdup (
    get_iterator_comment (&iterator));

  data->owner = get_iterator_owner (&iterator);

  data->report = report_export_iterator_report (&iterator);
  data->delta_report =
    report_export_iterator_delta_report (&iterator);

  data->report_format =
    report_export_iterator_report_format (&iterator);
  data->report_config =
    report_export_iterator_report_config (&iterator);

  data->export_type =
    report_export_iterator_export_type (&iterator);
  data->status =
    report_export_iterator_status (&iterator);
  data->progress =
    report_export_iterator_progress (&iterator);

  data->filter = g_strdup (
    report_export_iterator_filter (&iterator));

  data->ignore_pagination =
    report_export_iterator_ignore_pagination (&iterator);
  data->lean =
    report_export_iterator_lean (&iterator);
  data->worker_pid =
    report_export_iterator_worker_pid (&iterator);

  data->notes_details =
    report_export_iterator_notes_details (&iterator);
  data->overrides_details =
    report_export_iterator_overrides_details (&iterator);
  data->result_tags =
    report_export_iterator_result_tags (&iterator);

  data->file_path = g_strdup (
    report_export_iterator_file_path (&iterator));
  data->file_size =
    report_export_iterator_file_size (&iterator);
  data->content_type = g_strdup (
    report_export_iterator_content_type (&iterator));
  data->extension = g_strdup (
    report_export_iterator_extension (&iterator));
  data->error_message = g_strdup (
    report_export_iterator_error_message (&iterator));

  data->attempt_count =
    report_export_iterator_attempt_count (&iterator);

  data->creation_time =
    get_iterator_creation_time (&iterator);
  data->start_time =
    report_export_iterator_start_time (&iterator);
  data->end_time =
    report_export_iterator_end_time (&iterator);
  data->modification_time =
    get_iterator_modification_time (&iterator);

  cleanup_iterator (&iterator);

  if (data->uuid == NULL
      || data->report == 0
      || data->report_format == 0
      || report_export_type_valid (data->export_type) == FALSE
      || report_export_status_valid (data->status) == FALSE
      || report_export_progress_valid (data->progress) == FALSE)
    return -1;

  return 0;
}

/**
 * @brief Retrieve report of the current report export.
 *
 * @param[in] iterator  Iterator pointing to the current report export.
 *
 * @return The report associated with the current report export.
 */
report_t
report_export_iterator_report (iterator_t *iterator)
{
  if (iterator->done)
    return 0;

  return iterator_int64 (iterator, GET_ITERATOR_COLUMN_COUNT);
}

/**
 * @brief Retrieve delta report of the current report export.
 *
 * @param[in] iterator  Iterator pointing to the current report export.
 *
 * @return The delta report associated with the current report export.
 */
report_t
report_export_iterator_delta_report (iterator_t *iterator)
{
  if (iterator->done)
    return 0;

  return iterator_int64 (iterator, GET_ITERATOR_COLUMN_COUNT + 1);
}

/**
 * @brief Retrieve report format of the current report export.
 *
 * @param[in] iterator  Iterator pointing to the current report export.
 *
 * @return The report format associated with the current report export.
 */
report_format_t
report_export_iterator_report_format (iterator_t *iterator)
{
  if (iterator->done)
    return 0;

  return iterator_int64 (iterator, GET_ITERATOR_COLUMN_COUNT + 2);
}

/**
 * @brief Retrieve report config of the current report export.
 *
 * @param[in] iterator  Iterator pointing to the current report export.
 *
 * @return The report config associated with the current report export.
 */
report_config_t
report_export_iterator_report_config (iterator_t *iterator)
{
  if (iterator->done)
    return 0;

  return iterator_int64 (iterator, GET_ITERATOR_COLUMN_COUNT + 3);
}

/**
 * @brief Retrieve export type of the current report export.
 *
 * @param[in] iterator  Iterator pointing to the current report export.
 *
 * @return The export type of the current report export.
 */
report_export_type_t
report_export_iterator_export_type (iterator_t *iterator)
{
  if (iterator->done)
    return REPORT_EXPORT_TYPE_SCAN;

  return iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 4);
}

/**
 * @brief Retrieve status of the current report export.
 *
 * @param[in] iterator  Iterator pointing to the current report export.
 *
 * @return The status of the current report export.
 */
report_export_status_t
report_export_iterator_status (iterator_t *iterator)
{
  if (iterator->done)
    return REPORT_EXPORT_STATUS_PENDING;

  return iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 5);
}

/**
 * @brief Retrieve progress of the current report export.
 *
 * @param[in] iterator  Iterator pointing to the current report export.
 *
 * @return The progress of the current report export.
 */
report_export_progress_t
report_export_iterator_progress (iterator_t *iterator)
{
  if (iterator->done)
    return REPORT_EXPORT_PROGRESS_QUEUED;

  return iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 6);
}

/**
 * @brief Retrieve filter of the current report export.
 *
 * @param[in] iterator  Iterator pointing to the current report export.
 *
 * @return The filter associated with the current report export.
 */
DEF_ACCESS (report_export_iterator_filter, GET_ITERATOR_COLUMN_COUNT + 7);

/**
 * @brief Retrieve ignore-pagination flag of the current report export.
 *
 * @param[in] iterator  Iterator pointing to the current report export.
 *
 * @return The ignore-pagination flag.
 */
int
report_export_iterator_ignore_pagination (iterator_t *iterator)
{
  if (iterator->done)
    return 0;

  return iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 8);
}

/**
 * @brief Retrieve lean flag of the current report export.
 *
 * @param[in] iterator  Iterator pointing to the current report export.
 *
 * @return The lean flag.
 */
int
report_export_iterator_lean (iterator_t *iterator)
{
  if (iterator->done)
    return 0;

  return iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 9);
}

/**
 * @brief Retrieve worker PID of the current report export.
 *
 * @param[in] iterator  Iterator pointing to the current report export.
 *
 * @return The worker PID.
 */
int
report_export_iterator_worker_pid (iterator_t *iterator)
{
  if (iterator->done)
    return 0;

  return iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 10);
}

/**
 * @brief Retrieve notes-details flag of the current report export.
 *
 * @param[in] iterator  Iterator pointing to the current report export.
 *
 * @return The notes-details flag.
 */
int
report_export_iterator_notes_details (iterator_t *iterator)
{
  if (iterator->done)
    return 0;

  return iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 11);
}

/**
 * @brief Retrieve overrides-details flag of the current report export.
 *
 * @param[in] iterator  Iterator pointing to the current report export.
 *
 * @return The overrides-details flag.
 */
int
report_export_iterator_overrides_details (iterator_t *iterator)
{
  if (iterator->done)
    return 0;

  return iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 12);
}

/**
 * @brief Retrieve result-tags flag of the current report export.
 *
 * @param[in] iterator  Iterator pointing to the current report export.
 *
 * @return The result-tags flag.
 */
int
report_export_iterator_result_tags (iterator_t *iterator)
{
  if (iterator->done)
    return 0;

  return iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 13);
}

/**
 * @brief Retrieve file path of the current report export.
 *
 * @param[in] iterator  Iterator pointing to the current report export.
 *
 * @return The generated file path.
 */
DEF_ACCESS (report_export_iterator_file_path,
            GET_ITERATOR_COLUMN_COUNT + 14);

/**
 * @brief Retrieve file size of the current report export.
 *
 * @param[in] iterator  Iterator pointing to the current report export.
 *
 * @return The generated file size.
 */
long long
report_export_iterator_file_size (iterator_t *iterator)
{
  if (iterator->done)
    return 0;

  return iterator_int64 (iterator, GET_ITERATOR_COLUMN_COUNT + 15);
}

/**
 * @brief Retrieve content type of the current report export.
 *
 * @param[in] iterator  Iterator pointing to the current report export.
 *
 * @return The generated file content type.
 */
DEF_ACCESS (report_export_iterator_content_type,
            GET_ITERATOR_COLUMN_COUNT + 16);

/**
 * @brief Retrieve extension of the current report export.
 *
 * @param[in] iterator  Iterator pointing to the current report export.
 *
 * @return The generated file extension.
 */
DEF_ACCESS (report_export_iterator_extension,
            GET_ITERATOR_COLUMN_COUNT + 17);

/**
 * @brief Retrieve error message of the current report export.
 *
 * @param[in] iterator  Iterator pointing to the current report export.
 *
 * @return The report export error message.
 */
DEF_ACCESS (report_export_iterator_error_message,
            GET_ITERATOR_COLUMN_COUNT + 18);

/**
 * @brief Retrieve attempt count of the current report export.
 *
 * @param[in] iterator  Iterator pointing to the current report export.
 *
 * @return The processing attempt count.
 */
int
report_export_iterator_attempt_count (iterator_t *iterator)
{
  if (iterator->done)
    return 0;

  return iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 19);
}

/**
 * @brief Retrieve start time of the current report export.
 *
 * @param[in] iterator  Iterator pointing to the current report export.
 *
 * @return The processing start time.
 */
time_t
report_export_iterator_start_time (iterator_t *iterator)
{
  if (iterator->done)
    return 0;

  return iterator_int64 (iterator, GET_ITERATOR_COLUMN_COUNT + 20);
}

/**
 * @brief Retrieve end time of the current report export.
 *
 * @param[in] iterator  Iterator pointing to the current report export.
 *
 * @return The processing end time.
 */
time_t
report_export_iterator_end_time (iterator_t *iterator)
{
  if (iterator->done)
    return 0;

  return iterator_int64 (iterator, GET_ITERATOR_COLUMN_COUNT + 21);
}

/**
 * @brief Retrieve report UUID of the current report export.
 *
 * @param[in] iterator  Iterator pointing to the current report export.
 *
 * @return The UUID of the associated report.
 */
DEF_ACCESS (report_export_iterator_report_uuid,
            GET_ITERATOR_COLUMN_COUNT + 22);

/**
 * @brief Retrieve delta report UUID of the current report export.
 *
 * @param[in] iterator  Iterator pointing to the current report export.
 *
 * @return The UUID of the associated delta report.
 */
DEF_ACCESS (report_export_iterator_delta_report_uuid,
            GET_ITERATOR_COLUMN_COUNT + 23);

/**
 * @brief Retrieve report format UUID of the current report export.
 *
 * @param[in] iterator  Iterator pointing to the current report export.
 *
 * @return The UUID of the associated report format.
 */
DEF_ACCESS (report_export_iterator_report_format_uuid,
            GET_ITERATOR_COLUMN_COUNT + 24);

/**
 * @brief Retrieve report format name of the current report export.
 *
 * @param[in] iterator  Iterator pointing to the current report export.
 *
 * @return The name of the associated report format.
 */
DEF_ACCESS (report_export_iterator_report_format_name,
            GET_ITERATOR_COLUMN_COUNT + 25);

/**
 * @brief Retrieve report config UUID of the current report export.
 *
 * @param[in] iterator  Iterator pointing to the current report export.
 *
 * @return The UUID of the associated report config.
 */
DEF_ACCESS (report_export_iterator_report_config_uuid,
            GET_ITERATOR_COLUMN_COUNT + 26);

/**
 * @brief Retrieve report config name of the current report export.
 *
 * @param[in] iterator  Iterator pointing to the current report export.
 *
 * @return The name of the associated report config.
 */
DEF_ACCESS (report_export_iterator_report_config_name,
            GET_ITERATOR_COLUMN_COUNT + 27);

/**
 * @brief Count report exports matching GET filter criteria.
 *
 * @param[in] get  GET parameters containing filtering criteria.
 *
 * @return Number of matching report exports.
 */
int
report_export_count (const get_data_t *get)
{
  static const char *extra_columns[] =
    REPORT_EXPORT_ITERATOR_FILTER_COLUMNS;

  static column_t columns[] =
    REPORT_EXPORT_ITERATOR_COLUMNS;

  return count ("report_export",
                get,
                columns,
                NULL,
                extra_columns,
                0,
                NULL,
                0,
                TRUE);
}

/**
 * @brief Initialize an iterator over active report exports.
 *
 * Active exports are exports that were running or had cancellation requested.
 *
 * @param[out] iterator  Iterator to initialize.
 *
 * @return 0 on success, -1 on failure.
 */
int
init_report_export_iterator_active (iterator_t *iterator)
{
  g_return_val_if_fail (iterator, -1);

  init_iterator (
    iterator,
    "SELECT id,"
    "       status,"
    "       attempt_count"
    "  FROM report_exports"
    " WHERE status IN (%d, %d)",
    REPORT_EXPORT_STATUS_RUNNING,
    REPORT_EXPORT_STATUS_CANCEL_REQUESTED);

  return 0;
}
