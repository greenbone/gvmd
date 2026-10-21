/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef GVMD_MANAGE_REPORT_SEVERITY_SQL_H
#define GVMD_MANAGE_REPORT_SEVERITY_SQL_H

/* clang-format off */

/**
 * @brief Common overrides SQL for SQL functions.
 */
#define OVERRIDES_SQL(severity_sql)                         \
 " coalesce"                                                \
 "  ((SELECT overrides.new_severity"                        \
 "    FROM overrides"                                       \
 "    WHERE overrides.result_nvt = results.result_nvt"      \
 "    AND ((overrides.owner IS NULL)"                       \
 "         OR (overrides.owner"                             \
 "             = gvmd_user ()))"                            \
 "    AND ((overrides.end_time = 0)"                        \
 "         OR (overrides.end_time >= m_now ()))"            \
 "    AND (overrides.task = results.task"                   \
 "         OR overrides.task = 0)"                          \
 "    AND (overrides.result = results.id"                   \
 "         OR overrides.result = 0)"                        \
 "    AND (overrides.hosts is NULL"                         \
 "         OR overrides.hosts = ''"                         \
 "         OR oci_digest_list_contains (overrides.hosts,"   \
 "                                      results.host)"      \
 "         OR hosts_contains (overrides.hosts,"             \
 "                            results.host))"               \
 "    AND (overrides.port is NULL"                          \
 "         OR overrides.port = ''"                          \
 "         OR overrides.port = results.port)"               \
 "    AND severity_matches_ov"                              \
 "         (" severity_sql ", overrides.severity)"          \
 "    ORDER BY overrides.result DESC,"                      \
 "             overrides.task DESC,"                        \
 "             overrides.port DESC,"                        \
 "             overrides.severity ASC,"                     \
 "             overrides.creation_time DESC"                \
 "    LIMIT 1),"                                            \
 "   " severity_sql ")"

#define REPORT_SEVERITY_CACHED_SQL                           \
 "CREATE OR REPLACE FUNCTION report_severity_cached"         \
 "         (report integer, overrides integer, min_qod integer)" \
 " RETURNS double precision AS $$"                          \
 "  SELECT max(severity)::double precision"                 \
 "  FROM report_counts"                                     \
 "  WHERE report = $1"                                      \
 "  AND \"user\" = gvmd_user ()"                         \
 "  AND override = $2"                                      \
 "  AND min_qod = $3"                                       \
 "  AND (end_time = 0 or end_time >= m_now ());"            \
 "$$ LANGUAGE SQL STABLE;"

#define REPORT_SEVERITY_DYNAMIC_SQL                          \
 "CREATE OR REPLACE FUNCTION report_severity_dynamic"        \
 "         (report integer, overrides integer, min_qod integer)" \
 " RETURNS double precision AS $$"                          \
 "  SELECT CASE"                                            \
 "         WHEN dynamic_severity () AND $2::boolean"        \
 "         THEN (SELECT max"                                \
 "                       (" OVERRIDES_SQL                    \
                           ("current_severity (results.severity," \
                            "                  results.nvt)") ")" \
 "               FROM results"                              \
 "               WHERE results.report = $1"                 \
 "                 AND results.qod >= $3)"                  \
 "         WHEN dynamic_severity ()"                        \
 "         THEN (SELECT max (CASE"                          \
 "                           WHEN results.type IS NULL"      \
 "                           THEN 0::real"                  \
 "                           ELSE current_severity"          \
 "                                 (results.severity, results.nvt)" \
 "                           END)"                           \
 "               FROM results"                              \
 "               WHERE results.report = $1"                 \
 "                 AND results.qod >= $3)"                  \
 "         WHEN $2::boolean"                                \
 "         THEN (SELECT max (" OVERRIDES_SQL ("results.severity") ")" \
 "               FROM results"                              \
 "               WHERE results.report = $1"                 \
 "                 AND results.qod >= $3)"                  \
 "         ELSE (SELECT max (CASE"                          \
 "                           WHEN results.type IS NULL"      \
 "                           THEN 0::real"                  \
 "                           ELSE results.severity"          \
 "                           END)"                           \
 "               FROM results"                              \
 "               WHERE results.report = $1"                 \
 "                 AND results.qod >= $3)"                  \
 "         END;"                                            \
 "$$ LANGUAGE SQL STABLE;"

#define REPORT_SEVERITY_SQL                                  \
 "CREATE OR REPLACE FUNCTION report_severity (report integer," \
 "                                            overrides integer," \
 "                                            min_qod integer)" \
 " RETURNS double precision AS $$"                          \
 "  SELECT coalesce (report_severity_cached ($1, $2, $3),"  \
 "                   report_severity_dynamic ($1, $2, $3));" \
 "$$ LANGUAGE SQL STABLE;"

/* clang-format on */

#endif /* not GVMD_MANAGE_REPORT_SEVERITY_SQL_H */
