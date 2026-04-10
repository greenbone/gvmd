/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM SQL layer: Report errors.
 *
 * SQL handlers for report error XML.
 */

#include "manage_sql_report_errors.h"

#include "manage_sql_assets.h"

/**
 * @brief Initialise a report errors iterator.
 *
 * @param[in]  iterator  Iterator.
 * @param[in]  report   The report.
 */
void
init_report_errors_iterator (iterator_t *iterator, report_t report)
{
  if (report)
    init_iterator (iterator,
                   "SELECT results.host, results.port, results.nvt,"
                   " results.description,"
                   " coalesce((SELECT name FROM nvts"
                   "           WHERE nvts.oid = results.nvt), ''),"
                   " coalesce((SELECT cvss_base FROM nvts"
                   "           WHERE nvts.oid = results.nvt), ''),"
                   " results.nvt_version, results.severity,"
                   " results.id"
                   " FROM results"
                   " WHERE results.severity = %0.1f"
                   "  AND results.report = %llu",
                   SEVERITY_ERROR, report);
}

/**
 * @brief Get the host from a report error messages iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The host of the report error message.  Caller must use only before
 *         calling cleanup_iterator.
 */
DEF_ACCESS (report_errors_iterator_host, 0);

/**
 * @brief Get the port from a report error messages iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The port of the report error message.  Caller must use only before
 *         calling cleanup_iterator.
 */
DEF_ACCESS (report_errors_iterator_port, 1);

/**
 * @brief Get the nvt oid from a report error messages iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The nvt of the report error message.  Caller must use only before
 *         calling cleanup_iterator.
 */
DEF_ACCESS (report_errors_iterator_nvt_oid, 2);

/**
 * @brief Get the description from a report error messages iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The description of the report error message.  Caller must use only
 * before calling cleanup_iterator.
 */
DEF_ACCESS (report_errors_iterator_desc, 3);

/**
 * @brief Get the nvt name from a report error messages iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The nvt of the report error message.  Caller must use only before
 *         calling cleanup_iterator.
 */
DEF_ACCESS (report_errors_iterator_nvt_name, 4);

/**
 * @brief Get the nvt cvss base from a report error messages iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The nvt cvss base of the report error message.  Caller must use only
 *         before calling cleanup_iterator.
 */
DEF_ACCESS (report_errors_iterator_nvt_cvss, 5);

/**
 * @brief Get the nvt cvss base from a report error messages iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The nvt version at scan time of the report error message.
 *         Caller must use only before calling cleanup_iterator.
 */
DEF_ACCESS (report_errors_iterator_scan_nvt_version, 6);

/**
 * @brief Get the nvt cvss base from a report error messages iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The severity at scan time of the report error message.
 *         Caller must use only before calling cleanup_iterator.
 */
DEF_ACCESS (report_errors_iterator_severity, 7);

/**
 * @brief Write report error message to file stream.
 *
 * @param[in]   stream      Stream to write to.
 * @param[in]   errors      Pointer to report error messages iterator.
 * @param[in]   asset_id    Asset ID.
 */
#define PRINT_REPORT_ERROR(stream, errors, asset_id)                       \
  do                                                                       \
    {                                                                      \
      PRINT (stream,                                                       \
             "<error>"                                                     \
             "<host>"                                                      \
             "%s"                                                          \
             "<asset asset_id=\"%s\"/>"                                    \
             "</host>"                                                     \
             "<port>%s</port>"                                             \
             "<description>%s</description>"                               \
             "<nvt oid=\"%s\">"                                            \
             "<type>nvt</type>"                                            \
             "<name>%s</name>"                                             \
             "<cvss_base>%s</cvss_base>"                                   \
             "</nvt>"                                                      \
             "<scan_nvt_version>%s</scan_nvt_version>"                     \
             "<severity>%s</severity>"                                     \
             "</error>",                                                   \
             report_errors_iterator_host (errors) ?: "",                   \
             asset_id ? asset_id : "",                                     \
             report_errors_iterator_port (errors),                         \
             report_errors_iterator_desc (errors),                         \
             report_errors_iterator_nvt_oid (errors),                      \
             report_errors_iterator_nvt_name (errors),                     \
             report_errors_iterator_nvt_cvss (errors),                     \
             report_errors_iterator_scan_nvt_version (errors),             \
             report_errors_iterator_severity (errors));                    \
    }                                                                      \
  while (0)

/**
 * @brief Get the result from a report error messages iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Result.
 */
static result_t
report_errors_iterator_result (iterator_t *iterator)
{
  if (iterator->done)
    return 0;
  return iterator_int64 (iterator, 8);
}

/**
 * @brief Count a report's total number of error messages.
 *
 * @param[in]  report  Report.
 *
 * @return Error Messages count.
 */
int
report_error_count (report_t report)
{
  return sql_int ("SELECT count (id) FROM results"
                  " WHERE report = %llu and type = 'Error Message';",
                  report);
}

/**
 * @brief Print the XML for a report's error messages to a file stream.
 *
 * @param[in]  report   The report.
 * @param[in]  stream   File stream to write to.
 *
 * @return 0 on success, -1 error.
 */
int
print_report_errors_xml (report_t report, FILE *stream)
{
  iterator_t errors;

  init_report_errors_iterator
    (&errors, report);

  PRINT (stream, "<errors><count>%i</count>", report_error_count (report));
  while (next (&errors))
    {
      char *asset_id;

      asset_id = result_host_asset_id (report_errors_iterator_host (&errors),
                                       report_errors_iterator_result (&errors));
      PRINT_REPORT_ERROR (stream, &errors, asset_id);
      free (asset_id);
    }
  cleanup_iterator (&errors);
  PRINT (stream, "</errors>");

  return 0;
}

/**
 * @brief Print report error XML, returning either full details or only the count.
 *
 * @param[in]  report   The report.
 * @param[in]  stream   File stream to write to.
 * @param[in]  details  Boolean flag whether to include full details
 *
 * @return 0 on success, -1 error.
 */
int
print_report_errors_xml_summary_or_details (report_t report, FILE *stream,
                                            int details)
{
  if (details == 0)
    {
      PRINT (stream, "<errors><count>%i</count></errors>",
             report_error_count (report));
      return 0;
    }

  return print_report_errors_xml (report, stream);
}
