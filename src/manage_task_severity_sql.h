/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef GVMD_MANAGE_TASK_SEVERITY_SQL_H
#define GVMD_MANAGE_TASK_SEVERITY_SQL_H

/* clang-format off */

/*
 * Keep the version-specific definitions testable as production SQL.  The
 * report lookup is a FROM subquery so report_severity is not evaluated when a
 * task has no completed report.
 */

#define TASK_SEVERITY_SQL_V277                                      \
  "CREATE OR REPLACE FUNCTION task_severity (integer,"             \
  "                                          integer,"             \
  "                                          integer)"             \
  " RETURNS double precision AS $$"                               \
  "  SELECT CASE"                                                  \
  "         WHEN (SELECT target = 0 "                               \
  "               AND agent_group = 0 "                            \
  "               AND oci_image_target = 0 "                       \
  "               AND web_application_target = 0 "                 \
  "               FROM tasks WHERE id = $1)"                       \
  "         THEN CAST (NULL AS double precision)"                  \
  "         ELSE"                                                  \
  "         (SELECT report_severity (last_report.id, $2, $3)"      \
  "          FROM (SELECT id FROM reports"                          \
  "                WHERE task = $1"                                \
  "                AND scan_run_status = %u"                       \
  "                ORDER BY creation_time DESC"                    \
  "                LIMIT 1 OFFSET 0) AS last_report)"              \
  "         END;"                                                  \
  "$$ LANGUAGE SQL;"

#define TASK_SEVERITY_SQL_V262                                      \
  "CREATE OR REPLACE FUNCTION task_severity (integer,"             \
  "                                          integer,"             \
  "                                          integer)"             \
  " RETURNS double precision AS $$"                               \
  "  SELECT CASE"                                                  \
  "         WHEN (SELECT target = 0 "                               \
  "               AND agent_group = 0 "                            \
  "               AND oci_image_target = 0 "                       \
  "               FROM tasks WHERE id = $1)"                       \
  "         THEN CAST (NULL AS double precision)"                  \
  "         ELSE"                                                  \
  "         (SELECT report_severity (last_report.id, $2, $3)"      \
  "          FROM (SELECT id FROM reports"                          \
  "                WHERE task = $1"                                \
  "                AND scan_run_status = %u"                       \
  "                ORDER BY creation_time DESC"                    \
  "                LIMIT 1 OFFSET 0) AS last_report)"              \
  "         END;"                                                  \
  "$$ LANGUAGE SQL;"

#define TASK_SEVERITY_SQL_V245                                      \
  "CREATE OR REPLACE FUNCTION task_severity (integer,"             \
  "                                          integer,"             \
  "                                          integer)"             \
  " RETURNS double precision AS $$"                               \
  "  SELECT CASE"                                                  \
  "         WHEN (SELECT target = 0 "                               \
  "               FROM tasks WHERE id = $1)"                       \
  "         THEN CAST (NULL AS double precision)"                  \
  "         ELSE"                                                  \
  "         (SELECT report_severity (last_report.id, $2, $3)"      \
  "          FROM (SELECT id FROM reports"                          \
  "                WHERE task = $1"                                \
  "                AND scan_run_status = %u"                       \
  "                ORDER BY creation_time DESC"                    \
  "                LIMIT 1 OFFSET 0) AS last_report)"              \
  "         END;"                                                  \
  "$$ LANGUAGE SQL;"

#define TASK_SEVERITY_SQL_V189                                      \
  "CREATE OR REPLACE FUNCTION task_severity (integer,"             \
  "                                          integer,"             \
  "                                          integer)"             \
  " RETURNS double precision AS $$"                               \
  "  SELECT CASE"                                                  \
  "         WHEN (SELECT target = 0"                               \
  "               FROM tasks WHERE id = $1)"                       \
  "         THEN CAST (NULL AS double precision)"                  \
  "         ELSE"                                                  \
  "         (SELECT report_severity (last_report.id, $2, $3)"      \
  "          FROM (SELECT id FROM reports"                          \
  "                WHERE task = $1"                                \
  "                AND scan_run_status = %u"                       \
  "                ORDER BY date DESC"                             \
  "                LIMIT 1 OFFSET 0) AS last_report)"              \
  "         END;"                                                  \
  "$$ LANGUAGE SQL;"

/* clang-format on */

#endif /* not GVMD_MANAGE_TASK_SEVERITY_SQL_H */
