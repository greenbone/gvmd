/* OpenVAS Manager
 * $Id$
 * Description: Manager Manage library: PostgreSQL specific Manage facilities.
 *
 * Authors:
 * Matthew Mundell <matthew.mundell@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2014 Greenbone Networks GmbH
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * or, at your option, any later version as published by the Free
 * Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "sql.h"
#include "manage.h"
#include "manage_sql.h"


/* Session. */

/**
 * @brief Setup session.
 *
 * @param[in]  uuid  User UUID.
 */
void
manage_session_init (const char *uuid)
{
  sql ("CREATE TEMPORARY TABLE IF NOT EXISTS current_credentials"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL);");
  sql ("DELETE FROM current_credentials;");
  sql ("INSERT INTO current_credentials (uuid) VALUES ('%s');", uuid);
}


/* Helpers. */

/**
 * @brief Check whether database is empty.
 *
 * @param[in]  1 if empty, else 0;
 */
int
manage_db_empty ()
{
  return sql_int ("SELECT EXISTS (SELECT * FROM information_schema.tables"
                  "               WHERE table_catalog = 'tasks'"
                  "               AND table_schema = 'public'"
                  "               AND table_name = 'meta')"
                  "        ::integer;")
         == 0;
}


/* SQL functions. */

/**
 * @brief Move data from a table to a new table, heeding column rename.
 *
 * @param[in]  old_table  Existing table.
 * @param[in]  new_table  New empty table with renamed column.
 * @param[in]  old_name   Name of column in old table.
 * @param[in]  new_name   Name of column in new table.
 */
void
sql_rename_column (const char *old_table, const char *new_table,
                   const char *old_name, const char *new_name)
{
  return;
}

/**
 * @brief Create functions.
 *
 * @return 0 success, -1 error.
 */
int
manage_create_sql_functions ()
{
#if 0
  can duplicate with pl/pgsql probably
    resource_exists (only used in migrator (given table type, will need exec))

  can duplicate
    clean_hosts  (only used in migrator)
    current_offset (only used in migrator (maybe with SHOW TIMEZONE and hairy date stuff))

  duplicated below
    common_cve
    hosts_contains
    report_severity         (pg does not cache when recalculating)
    report_severity_count   (pg does not cache when recalculating)
    resource_name
    run_status_name
    severity_in_level
    severity_to_level
    task_severity
    task_trend              (pg does not cache when recalculating)
    task_threat_level
    user_can_everything

  duplicated with pl/pgsql below
    iso_time
    report_progress
    severity_matches_ov
    severity_to_type
    uniquify (given table type, will need exec)

  server side below
    max_hosts
    next_time
#endif

  /* Functions in C. */

  sql ("SET role dba;");

  sql ("CREATE OR REPLACE FUNCTION max_hosts (text, text)"
       " RETURNS integer"
       " AS '%s/openvasmd/pg/libmanage-pg-server', 'sql_max_hosts'"
       " LANGUAGE C;",
       OPENVAS_STATE_DIR);

  sql ("CREATE OR REPLACE FUNCTION level_max_severity (text, text)"
       " RETURNS double precision"
       " AS '%s/openvasmd/pg/libmanage-pg-server', 'sql_level_max_severity'"
       " LANGUAGE C;",
       OPENVAS_STATE_DIR);

  sql ("CREATE OR REPLACE FUNCTION level_min_severity (text, text)"
       " RETURNS double precision"
       " AS '%s/openvasmd/pg/libmanage-pg-server', 'sql_level_min_severity'"
       " LANGUAGE C;",
       OPENVAS_STATE_DIR);

  sql ("CREATE OR REPLACE FUNCTION next_time (integer, integer, integer)"
       " RETURNS integer"
       " AS '%s/openvasmd/pg/libmanage-pg-server', 'sql_next_time'"
       " LANGUAGE C;",
       OPENVAS_STATE_DIR);

  sql ("RESET role;");

  /* Functions in SQL. */

  sql ("CREATE OR REPLACE FUNCTION t () RETURNS boolean AS $$"
       "  SELECT true;"
       "$$ LANGUAGE SQL;");

  sql ("CREATE OR REPLACE FUNCTION m_now () RETURNS integer AS $$"
       "  SELECT extract (epoch FROM now ())::integer;"
       "$$ LANGUAGE SQL;");

  if (sql_int ("SELECT count (*) FROM pg_available_extensions"
               " WHERE name = 'uuid-ossp' AND installed_version IS NOT NULL;")
      == 0)
    {
      g_warning ("%s: PostgreSQL extension uuid-ossp required", __FUNCTION__);
      return -1;
    }

  sql ("CREATE OR REPLACE FUNCTION common_cve (text, text)"
       " RETURNS boolean AS $$"
       /* Check if two CVE lists contain a common CVE. */
       "  SELECT EXISTS (SELECT trim (unnest (string_to_array ($1, ',')))"
       "                 INTERSECT"
       "                 SELECT trim (unnest (string_to_array ($2, ','))));"
       "$$ LANGUAGE SQL;");

  sql ("CREATE OR REPLACE FUNCTION hosts_contains (text, text)"
       " RETURNS boolean AS $$"
       /* Check if a host list contains a host. */
       "  SELECT trim ($2)"
       "         IN (SELECT trim (unnest (string_to_array ($1, ','))));"
       "$$ LANGUAGE SQL;");

  sql ("CREATE OR REPLACE FUNCTION make_uuid () RETURNS text AS $$"
       "  SELECT uuid_generate_v4 ()::text AS result;"
       "$$ LANGUAGE SQL;");

  sql ("CREATE OR REPLACE FUNCTION tag (text, text) RETURNS text AS $$"
       /* Extract a tag from an OTP tag list. */
       "  SELECT split_part (unnest, '=', 2)"
       "  FROM unnest (string_to_array ($1, '|'))"
       "  WHERE split_part (unnest, '=', 1) = $2;"
       "$$ LANGUAGE SQL;");

  if (sql_int ("SELECT EXISTS (SELECT * FROM information_schema.tables"
               "               WHERE table_catalog = 'tasks'"
               "               AND table_schema = 'public'"
               "               AND table_name = 'meta')"
               " ::integer;"))
    {
      sql ("CREATE OR REPLACE FUNCTION report_active (integer)"
           " RETURNS boolean AS $$"
           /* Check whether a report is active. */
           "  SELECT CASE"
           "         WHEN (SELECT scan_run_status FROM reports"
           "               WHERE reports.id = $1)"
           "               IN (SELECT unnest (ARRAY [%i, %i, %i, %i, %i, %i,"
           "                                         %i]))"
           "         THEN true"
           "         ELSE false"
           "         END;"
           "$$ LANGUAGE SQL;",
           TASK_STATUS_REQUESTED,
           TASK_STATUS_RUNNING,
           TASK_STATUS_DELETE_REQUESTED,
           TASK_STATUS_DELETE_ULTIMATE_REQUESTED,
           TASK_STATUS_STOP_REQUESTED,
           TASK_STATUS_STOP_REQUESTED_GIVEUP,
           TASK_STATUS_STOPPED);

      sql ("CREATE OR REPLACE FUNCTION report_progress (integer)"
           " RETURNS integer AS $$"
           /* TODO Calculate the progress of a report. */
           "  SELECT CASE"
           "         WHEN $1 = 0"
           "         THEN -1"
           "         WHEN (SELECT slave_task_uuid FROM reports WHERE id = $1)"
           "              != ''"
           "         THEN (SELECT slave_progress FROM reports WHERE id = $1)"
           "         WHEN report_active ($1)"
           "         THEN report_progress_active ($1)"
           "         ELSE -1"
           "         END;"
           "$$ LANGUAGE SQL;");
    }

  sql ("CREATE OR REPLACE FUNCTION dynamic_severity ()"
       " RETURNS boolean AS $$"
       /* Get Dynamic Severity user setting. */
       "  SELECT CAST (value AS integer) = 1 FROM settings"
       "  WHERE name = 'Dynamic Severity'"
       "  AND ((owner IS NULL)"
       "       OR (owner = (SELECT id FROM users"
       "                    WHERE users.uuid"
       "                          = (SELECT uuid"
       "                             FROM current_credentials))))"
       "  ORDER BY coalesce (owner, 0) DESC LIMIT 1;"
       "$$ LANGUAGE SQL;");

#define OVERRIDES_SQL(severity_sql)                         \
 " coalesce"                                                \
 "  ((SELECT overrides.new_severity"                        \
 "    FROM overrides"                                       \
 "    WHERE overrides.nvt = results.nvt"                    \
 "    AND ((overrides.owner IS NULL)"                       \
 "         OR (overrides.owner ="                           \
 "             (SELECT id FROM users"                       \
 "              WHERE users.uuid"                           \
 "                    = (SELECT uuid"                       \
 "                       FROM current_credentials))))"      \
 "    AND ((overrides.end_time = 0)"                        \
 "         OR (overrides.end_time >= m_now ()))"            \
 "    AND (overrides.task = results.task"                   \
 "         OR overrides.task = 0)"                          \
 "    AND (overrides.result = results.id"                   \
 "         OR overrides.result = 0)"                        \
 "    AND (overrides.hosts is NULL"                         \
 "         OR overrides.hosts = ''"                         \
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

  sql ("CREATE OR REPLACE FUNCTION report_severity (report integer,"
       "                                            overrides integer)"
       " RETURNS double precision AS $$"
       /* Calculate the severity of a report. */
       "  WITH max_severity AS (SELECT max(severity) AS max"
       "                        FROM report_counts"
       // FIX should have user like report_counts_cache_exists?  c version too?
       "                        WHERE report = $1"
       "                        AND override = $2"
       "                        AND (end_time = 0 or end_time >= m_now ()))"
       "  SELECT CASE"
       "         WHEN EXISTS (SELECT max FROM max_severity)"
       "              AND (SELECT max FROM max_severity) IS NOT NULL"
       "         THEN (SELECT max::double precision FROM max_severity)"
       "         WHEN dynamic_severity () AND $2::boolean"
       /*        Dynamic severity, overrides on. */
       "         THEN (SELECT max"
       "                       (" OVERRIDES_SQL
                                   ("CASE"
                                    " WHEN results.severity"
                                    "      > " G_STRINGIFY (SEVERITY_LOG)
                                    " THEN (SELECT CAST (cvss_base AS REAL)"
                                    "       FROM nvts"
                                    "       WHERE nvts.oid = results.nvt)"
                                    " ELSE results.severity END") ")"
       "               FROM results"
       "               WHERE results.report = $1)"
       "         WHEN dynamic_severity ()"
       /*        Dynamic severity, overrides off. */
       "         THEN (SELECT max (CASE"
       "                           WHEN results.type IS NULL"
       "                           THEN 0::real"
       "                           ELSE (CASE"
       "                                 WHEN results.severity"
       "                                      > " G_STRINGIFY (SEVERITY_LOG)
       "                                 THEN (SELECT CAST (cvss_base AS REAL)"
       "                                       FROM nvts"
       "                                       WHERE nvts.oid = results.nvt)"
       "                                 ELSE results.severity"
       "                                 END)"
       "                           END)"
       "               FROM results"
       "               WHERE results.report = $1)"
       "         WHEN $2::boolean"
       /*        Overrides on. */
       "         THEN (SELECT max (" OVERRIDES_SQL ("results.severity") ")"
       "               FROM results"
       "               WHERE results.report = $1)"
       /*        Overrides off. */
       "         ELSE (SELECT max (CASE"
       "                           WHEN results.type IS NULL"
       "                           THEN 0::real"
       "                           ELSE results.severity"
       "                           END)"
       "               FROM results"
       "               WHERE results.report = $1)"
       "         END;"
       "$$ LANGUAGE SQL;");

  sql ("CREATE OR REPLACE FUNCTION severity_class ()"
       " RETURNS text AS $$"
       /* Get the user's severity class setting. */
       "  SELECT value FROM settings"
       "  WHERE name = 'Severity Class'"
       "  AND ((owner IS NULL)"
       "       OR (owner = (SELECT id FROM users"
       "                    WHERE users.uuid = (SELECT uuid"
       "                                        FROM current_credentials))))"
       "  ORDER BY owner DESC LIMIT 1;"
       "$$ LANGUAGE SQL;");

  sql ("CREATE OR REPLACE FUNCTION"
       " report_severity_count (report integer, overrides integer, level text)"
       " RETURNS bigint AS $$"
       /* Calculate the severity of a report. */
       "  WITH severity_count AS (SELECT sum (count) AS total"
       "                          FROM report_counts"
       "                          WHERE report = $1"
       "                          AND override = $2"
       "                          AND (end_time = 0 or end_time >= m_now ())"
       "                          AND (severity"
       "                               BETWEEN level_min_severity"
       "                                        ($3, severity_class ())"
       "                                       AND level_max_severity"
       "                                            ($3, severity_class ())))"
       "  SELECT CASE"
       "         WHEN EXISTS (SELECT total FROM severity_count)"
       "              AND (SELECT total FROM severity_count) IS NOT NULL"
       "         THEN (SELECT total FROM severity_count)"
       "         WHEN dynamic_severity () AND $2::boolean"
       /*        Dynamic severity, overrides on. */
       "         THEN (SELECT count (*)"
       "               FROM results"
       "               WHERE results.report = $1"
       "               AND (" OVERRIDES_SQL
                               ("CASE"
                                " WHEN results.severity"
                                "      > " G_STRINGIFY (SEVERITY_LOG)
                                " THEN (SELECT CAST (cvss_base AS REAL)"
                                "       FROM nvts"
                                "       WHERE nvts.oid = results.nvt)"
                                " ELSE results.severity END")
       "                    BETWEEN level_min_severity"
       "                             ($3, severity_class ())"
       "                            AND level_max_severity"
       "                                 ($3, severity_class ())))"
       "         WHEN dynamic_severity ()"
       /*        Dynamic severity, overrides off. */
       "         THEN (SELECT count (*)"
       "               FROM results"
       "               WHERE results.report = $1"
       "               AND ((CASE"
       "                     WHEN results.type IS NULL"
       "                     THEN 0::real"
       "                     ELSE (CASE"
       "                           WHEN results.severity"
       "                                > " G_STRINGIFY (SEVERITY_LOG)
       "                           THEN (SELECT CAST (cvss_base AS REAL)"
       "                                 FROM nvts"
       "                                 WHERE nvts.oid = results.nvt)"
       "                           ELSE results.severity"
       "                           END)"
       "                     END)"
       "                    BETWEEN level_min_severity ($3, severity_class ())"
       "                            AND level_max_severity"
       "                                 ($3, severity_class ())))"
       "         WHEN $2::boolean"
       /*        Overrides on. */
       "         THEN (SELECT count (*)"
       "               FROM results"
       "               WHERE results.report = $1"
       "               AND (" OVERRIDES_SQL ("results.severity")
       "                    BETWEEN level_min_severity ($3, severity_class ())"
       "                            AND level_max_severity"
       "                                 ($3, severity_class ())))"
       /*        Overrides off. */
       "         ELSE (SELECT count (*)"
       "               FROM results"
       "               WHERE results.report = $1"
       "               AND ((CASE"
       "                     WHEN results.type IS NULL"
       "                     THEN 0::real"
       "                     ELSE results.severity"
       "                     END)"
       "                    BETWEEN level_min_severity ($3, severity_class ())"
       "                            AND level_max_severity"
       "                                 ($3, severity_class ())))"
       "         END;"
       "$$ LANGUAGE SQL;");

  sql ("CREATE OR REPLACE FUNCTION task_last_report (integer)"
       " RETURNS integer AS $$"
       /* Get the report from the most recently completed invocation of task. */
       "  SELECT id FROM reports WHERE task = $1 AND scan_run_status = %u"
       "  ORDER BY date DESC LIMIT 1;"
       "$$ LANGUAGE SQL;",
       TASK_STATUS_DONE);

  sql ("CREATE OR REPLACE FUNCTION task_second_last_report (integer)"
       " RETURNS integer AS $$"
       /* Get report from second most recently completed invocation of task. */
       "  SELECT id FROM reports WHERE task = $1 AND scan_run_status = %u"
       "  ORDER BY date DESC LIMIT 1 OFFSET 1;"
       "$$ LANGUAGE SQL;",
       TASK_STATUS_DONE);

  sql ("CREATE OR REPLACE FUNCTION task_severity (integer, integer)"
       " RETURNS double precision AS $$"
       /* Calculate the severity of a task. */
       "  SELECT CASE"
       "         WHEN (SELECT target IS NULL FROM tasks WHERE id = $1)"
       "         THEN CAST (0.0 AS double precision)"
       "         WHEN dynamic_severity () AND CAST ($2 AS boolean)"
       /*        Dynamic severity, overrides on. */
       "         THEN (SELECT"
       "                round"
       "                 (max (" OVERRIDES_SQL
                                  ("CASE"
                                   " WHEN results.severity"
                                   "      > " G_STRINGIFY (SEVERITY_LOG)
                                   " THEN (SELECT CAST (cvss_base AS REAL)"
                                   "       FROM nvts"
                                   "       WHERE nvts.oid = results.nvt)"
                                   " ELSE results.severity END") ")::numeric,"
       "                  2)"
       "               FROM results"
       "               WHERE results.report = (SELECT id FROM reports"
       "                                       WHERE reports.task = $1"
       "                                       AND reports.scan_run_status = %u"
       "                                       ORDER BY reports.date DESC"
       "                                                LIMIT 1 OFFSET 0))"
       "         WHEN dynamic_severity ()"
       /*        Dynamic severity, overrides off. */
       "         THEN (SELECT round (max (CASE"
       "                                  WHEN results.severity"
       "                                       > " G_STRINGIFY (SEVERITY_LOG)
       "                                  THEN (SELECT CAST (cvss_base AS REAL)"
       "                                        FROM nvts"
       "                                        WHERE nvts.oid = results.nvt)"
       "                                  ELSE results.severity END)::numeric,"
       "                             2)"
       "               FROM results"
       "               WHERE results.report = (SELECT id FROM reports"
       "                                       WHERE reports.task = $1"
       "                                       AND reports.scan_run_status = %u"
       "                                       ORDER BY reports.date DESC"
       "                                                LIMIT 1 OFFSET 0))"
       "         WHEN CAST ($2 AS boolean)"
       /*        Overrides on. */
       "         THEN (SELECT round"
       "                       (max (" OVERRIDES_SQL ("results.severity") ")"
       "                              ::numeric,"
       "                        2)"
       "               FROM results"
       "               WHERE results.report = (SELECT id FROM reports"
       "                                       WHERE reports.task = $1"
       "                                       AND reports.scan_run_status = %u"
       "                                       ORDER BY reports.date DESC"
       "                                       LIMIT 1 OFFSET 0))"
       /*        Overrides off. */
       // FIX need rounding in sqlite?
       "         ELSE (SELECT round (max (results.severity)::numeric, 2)"
       "               FROM results"
       "               WHERE results.report = (SELECT id FROM reports"
       "                                       WHERE reports.task = $1"
       "                                       AND reports.scan_run_status = %u"
       "                                       ORDER BY reports.date DESC"
       "                                                LIMIT 1 OFFSET 0))"
       "         END;"
       "$$ LANGUAGE SQL;",
       TASK_STATUS_DONE,
       TASK_STATUS_DONE,
       TASK_STATUS_DONE,
       TASK_STATUS_DONE);

  sql ("CREATE OR REPLACE FUNCTION task_threat_level (integer, integer)"
       " RETURNS text AS $$"
       /* Calculate the threat level of a task. */
       "  SELECT severity_to_level (task_severity ($1, $2), 0);"
       "$$ LANGUAGE SQL;");

  sql ("CREATE OR REPLACE FUNCTION run_status_name (integer)"
       " RETURNS text AS $$"
       /* Get the name of a task run status. */
       "  SELECT CASE"
       "         WHEN $1 = %i"
       "              OR $1 = %i"
       "         THEN 'Delete Requested'"
       "         WHEN $1 = %i OR $1 = %i"
       "         THEN 'Ultimate Delete Requested'"
       "         WHEN $1 = %i"
       "         THEN 'Done'"
       "         WHEN $1 = %i"
       "         THEN 'New'"
       "         WHEN $1 = %i"
       "         THEN 'Requested'"
       "         WHEN $1 = %i"
       "         THEN 'Running'"
       "         WHEN $1 = %i OR $1 = %i OR $1 = %i"
       "         THEN 'Stop Requested'"
       "         WHEN $1 = %i"
       "         THEN 'Stopped'"
       "         ELSE 'Internal Error'"
       "         END;"
       "$$ LANGUAGE SQL;",
       TASK_STATUS_DELETE_REQUESTED,
       TASK_STATUS_DELETE_WAITING,
       TASK_STATUS_DELETE_ULTIMATE_REQUESTED,
       TASK_STATUS_DELETE_ULTIMATE_WAITING,
       TASK_STATUS_DONE,
       TASK_STATUS_NEW,
       TASK_STATUS_REQUESTED,
       TASK_STATUS_RUNNING,
       TASK_STATUS_STOP_REQUESTED_GIVEUP,
       TASK_STATUS_STOP_REQUESTED,
       TASK_STATUS_STOP_WAITING,
       TASK_STATUS_STOPPED);

  if (sql_int ("SELECT EXISTS (SELECT * FROM information_schema.tables"
               "               WHERE table_catalog = 'tasks'"
               "               AND table_schema = 'public'"
               "               AND table_name = 'permissions')"
               " ::integer;"))
    sql ("CREATE OR REPLACE FUNCTION user_can_everything (text)"
         " RETURNS boolean AS $$"
         /* Test whether a user may perform any operation.
          *
          * This must match user_can_everything in manage_acl.c. */
         "  SELECT count(*) > 0 FROM permissions"
         "  WHERE resource = 0"
         "  AND ((subject_type = 'user'"
         "        AND subject"
         "            = (SELECT id FROM users"
         "               WHERE users.uuid = $1))"
         "       OR (subject_type = 'group'"
         "           AND subject"
         "               IN (SELECT DISTINCT \"group\""
         "                   FROM group_users"
         "                   WHERE \"user\"  = (SELECT id"
         "                                     FROM users"
         "                                     WHERE users.uuid"
         "                                           = $1)))"
         "       OR (subject_type = 'role'"
         "           AND subject"
         "               IN (SELECT DISTINCT role"
         "                   FROM role_users"
         "                   WHERE \"user\"  = (SELECT id"
         "                                     FROM users"
         "                                     WHERE users.uuid"
         "                                           = $1))))"
         "  AND name = 'Everything';"
         "$$ LANGUAGE SQL;");

  sql ("CREATE OR REPLACE FUNCTION group_concat_pair (text, text, text)"
       " RETURNS text AS $$"
       "  SELECT CASE"
       "         WHEN $1 IS NULL OR $1 = ''"
       "         THEN $2"
       "         ELSE $1 || $3 || $2"
       "         END;"
       "$$ LANGUAGE SQL;");

  sql ("DROP AGGREGATE IF EXISTS group_concat (text, text);");

  sql ("CREATE AGGREGATE group_concat (text, text)"
       " (sfunc       = group_concat_pair,"
       "  stype       = text,"
       "  initcond    = '');");

  if (sql_int ("SELECT EXISTS (SELECT * FROM information_schema.tables"
               "               WHERE table_catalog = 'tasks'"
               "               AND table_schema = 'public'"
               "               AND table_name = 'meta')"
               " ::integer;"))
    {
      sql ("CREATE OR REPLACE FUNCTION resource_name (text, text, integer)"
           " RETURNS text AS $$"
           /* Get the name of a resource by its type and ID. */
           // FIX check valid_db_resource_type (type)
           "  SELECT CASE"
           "         WHEN $1 = 'note'"
           "              AND $3 = " G_STRINGIFY (LOCATION_TABLE)
           "         THEN (SELECT 'Note for: '"
           "                      || (SELECT name"
           "                          FROM nvts"
           "                          WHERE nvts.uuid = notes.nvt)"
           "               FROM notes"
           "               WHERE uuid = $2)"
           "         WHEN $1 = 'note'"
           "         THEN (SELECT 'Note for: '"
           "                      || (SELECT name"
           "                          FROM nvts"
           "                          WHERE nvts.uuid = notes_trash.nvt)"
           "               FROM notes_trash"
           "               WHERE uuid = $2)"
           "         WHEN $1 = 'override'"
           "              AND $3 = " G_STRINGIFY (LOCATION_TABLE)
           "         THEN (SELECT 'Override for: '"
           "                      || (SELECT name"
           "                          FROM nvts"
           "                          WHERE nvts.uuid = overrides.nvt)"
           "               FROM overrides"
           "               WHERE uuid = $2)"
           "         WHEN $1 = 'override'"
           "         THEN (SELECT 'Override for: '"
           "                      || (SELECT name"
           "                          FROM nvts"
           "                          WHERE nvts.uuid = overrides_trash.nvt)"
           "               FROM overrides_trash"
           "               WHERE uuid = $2)"
           "         WHEN $1 = 'report'"
           "         THEN (SELECT (SELECT name FROM tasks WHERE id = task)"
           "               || ' - '"
           "               || (SELECT"
           "                     CASE (SELECT end_time FROM tasks"
           "                           WHERE id = task)"
           "                     WHEN 0 THEN 'N/A'"
           "                     ELSE (SELECT end_time::text"
           "                           FROM tasks WHERE id = task)"
           "                   END)"
           "               FROM reports"
           "               WHERE uuid = $2)"
           "         WHEN $1 = 'result'"
           "         THEN (SELECT (SELECT name FROM tasks WHERE id = task)"
           "               || ' - '"
           "               || (SELECT name FROM nvts WHERE oid = nvt)"
           "               || ' - '"
           "               || (SELECT"
           "                     CASE (SELECT end_time FROM tasks"
           "                           WHERE id = task)"
           "                     WHEN 0 THEN 'N/A'"
           "                     ELSE (SELECT end_time::text"
           "                           FROM tasks WHERE id = task)"
           "                   END)"
           "               FROM results"
           "               WHERE uuid = $2)"
           "         WHEN $1 = 'target'"
           "              AND $3 = " G_STRINGIFY (LOCATION_TABLE)
           "         THEN (SELECT name"
           "               FROM targets"
           "               WHERE uuid = $2)"
           "         WHEN $1 = 'target'"
           "         THEN (SELECT name"
           "               FROM targets_trash"
           "               WHERE uuid = $2)"
           "         WHEN $1 = 'port_list'"
           "              AND $3 = " G_STRINGIFY (LOCATION_TABLE)
           "         THEN (SELECT name"
           "               FROM port_lists"
           "               WHERE uuid = $2)"
           "         WHEN $1 = 'port_list'"
           "         THEN (SELECT name"
           "               FROM port_lists_trash"
           "               WHERE uuid = $2)"
           // FIX more
           "         ELSE 'ERROR'"
           "         END;"
           "$$ LANGUAGE SQL;");

      sql ("CREATE OR REPLACE FUNCTION severity_in_level (double precision,"
           "                                              text)"
           " RETURNS boolean AS $$"
           "  SELECT CASE (SELECT value FROM settings"
           "               WHERE name = 'Severity Class'"
           "               AND ((owner IS NULL)"
           "                    OR (owner = (SELECT id FROM users"
           "                                 WHERE users.uuid"
           "                                       = (SELECT uuid"
           "                                          FROM current_credentials))))"
           // FIX coalesce else null first
           "               ORDER BY owner DESC LIMIT 1)"
           "         WHEN 'classic'"
           "         THEN (CASE $2"
           "               WHEN 'high'"
           "               THEN $1 > 5"
           "                    AND $1 <= 10"
           "               WHEN 'medium'"
           "               THEN $1 > 2"
           "                    AND $1 <= 5"
           "               WHEN 'low'"
           "               THEN $1 > 0"
           "                    AND $1 <= 2"
           "               WHEN 'none'"
           "               THEN $1 = 0"
           "               ELSE 0::boolean"
           "               END)"
           "         WHEN 'pci-dss'"
           "         THEN (CASE $2"
           "               WHEN 'high'"
           "               THEN $1 >= 4.3"
           "               WHEN 'none'"
           "               THEN $1 = 0"
           "               ELSE 0::boolean"
           "               END)"
           "         ELSE " /* NIST/BSI */
           "              (CASE $2"
           "               WHEN 'high'"
           "               THEN $1 >= 7"
           "                    AND $1 <= 10"
           "               WHEN 'medium'"
           "               THEN $1 >= 4"
           "                    AND $1 < 7"
           "               WHEN 'low'"
           "               THEN $1 > 0"
           "                    AND $1 < 4"
           "               WHEN 'none'"
           "               THEN $1 = 0"
           "               ELSE 0::boolean"
           "               END)"
           "         END;"
           "$$ LANGUAGE SQL;");

      sql ("CREATE OR REPLACE FUNCTION severity_to_level (text, integer)"
           " RETURNS text AS $$"
           "  SELECT CASE"
           "         WHEN $1::double precision = " G_STRINGIFY (SEVERITY_LOG)
           "         THEN 'Log'"
           "         WHEN $1::double precision = " G_STRINGIFY (SEVERITY_FP)
           "         THEN 'False Positive'"
           "         WHEN $1::double precision = " G_STRINGIFY (SEVERITY_DEBUG)
           "         THEN 'Debug'"
           "         WHEN $1::double precision = " G_STRINGIFY (SEVERITY_ERROR)
           "         THEN 'Error'"
           "         WHEN $1::double precision > 0.0"
           "              AND $1::double precision <= 10.0"
           "         THEN (SELECT CASE"
           "                      WHEN $2 = 1"
           "                      THEN 'Alarm'"
           "                      WHEN severity_in_level ($1::double precision,"
           "                                              'high')"
           "                      THEN 'High'"
           "                      WHEN severity_in_level ($1::double precision,"
           "                                              'medium')"
           "                      THEN 'Medium'"
           "                      WHEN severity_in_level ($1::double precision,"
           "                                              'low')"
           "                      THEN 'Low'"
           "                      ELSE 'Log'"
           "                      END)"
           "         ELSE 'Internal Error'"
           "         END;"
           "$$ LANGUAGE SQL;");

      sql ("CREATE OR REPLACE FUNCTION severity_to_level (double precision,"
           "                                              integer)"
           " RETURNS text AS $$"
           "  SELECT CASE"
           "         WHEN $1 = " G_STRINGIFY (SEVERITY_LOG)
           "         THEN 'Log'"
           "         WHEN $1 = " G_STRINGIFY (SEVERITY_FP)
           "         THEN 'False Positive'"
           "         WHEN $1 = " G_STRINGIFY (SEVERITY_DEBUG)
           "         THEN 'Debug'"
           "         WHEN $1 = " G_STRINGIFY (SEVERITY_ERROR)
           "         THEN 'Error'"
           "         WHEN $1 > 0.0 AND $1 <= 10.0"
           "         THEN (SELECT CASE"
           "                      WHEN $2 = 1"
           "                      THEN 'Alarm'"
           "                      WHEN severity_in_level ($1, 'high')"
           "                      THEN 'High'"
           "                      WHEN severity_in_level ($1, 'medium')"
           "                      THEN 'Medium'"
           "                      WHEN severity_in_level ($1, 'low')"
           "                      THEN 'Low'"
           "                      ELSE 'Log'"
           "                      END)"
           "         ELSE 'Internal Error'"
           "         END;"
           "$$ LANGUAGE SQL;");
    }

  sql ("CREATE OR REPLACE FUNCTION lower (integer)"
       " RETURNS integer AS $$"
       "  SELECT $1;"
       "$$ LANGUAGE SQL;");

  /* Functions in pl/pgsql. */

  sql ("CREATE OR REPLACE FUNCTION task_trend (integer, integer)"
       " RETURNS text AS $$"
       /* Calculate the trend of a task. */
       " DECLARE"
       "   last_report integer;"
       "   second_last_report integer;"
       "   severity_a double precision;"
       "   severity_b double precision;"
       "   high_a bigint;"
       "   high_b bigint;"
       "   medium_a bigint;"
       "   medium_b bigint;"
       "   low_a bigint;"
       "   low_b bigint;"
       "   threat_a integer;"
       "   threat_b integer;"
       " BEGIN"
       "   CASE"
       /*  Ensure there are enough reports. */
       "   WHEN (SELECT count(*) <= 1 FROM reports"
       "         WHERE task = $1"
       "         AND scan_run_status = %u)"
       "   THEN RETURN ''::text;"
       /*  Get trend only for authenticated users. */
       "   WHEN NOT EXISTS (SELECT uuid FROM current_credentials)"
       "        OR (SELECT uuid = '' FROM current_credentials)"
       "   THEN RETURN ''::text;"
       /*  Skip running and container tasks. */
       "   WHEN (SELECT run_status = %u OR target = 0"
       "         FROM tasks WHERE id = $1)"
       "   THEN RETURN ''::text;"
       "   ELSE"
       "   END CASE;"
       /*  Check if the severity score changed. */
       "   last_report := task_last_report ($1);"
       "   second_last_report := task_second_last_report ($1);"
       "   severity_a := report_severity (last_report, $2);"
       "   severity_b := report_severity (second_last_report, $2);"
       "   IF severity_a > severity_b THEN"
       "     RETURN 'up'::text;"
       "   ELSIF severity_b > severity_a THEN"
       "     RETURN 'down'::text;"
       "   END IF;"
       /*  Calculate trend. */
       "   high_a := report_severity_count (last_report, $2, 'high');"
       "   high_b := report_severity_count (second_last_report, $2, 'high');"
       "   medium_a := report_severity_count (last_report, $2, 'medium');"
       "   medium_b := report_severity_count (second_last_report, $2, 'medium');"
       "   low_a := report_severity_count (last_report, $2, 'low');"
       "   low_b := report_severity_count (second_last_report, $2, 'low');"
       "   IF high_a > 0 THEN"
       "     threat_a := 4;"
       "   ELSIF medium_a > 0 THEN"
       "     threat_a := 3;"
       "   ELSIF low_a > 0 THEN"
       "     threat_a := 2;"
       "   ELSE"
       "     threat_a := 1;"
       "   END IF;"
       "   IF high_b > 0 THEN"
       "     threat_b := 4;"
       "   ELSIF medium_b > 0 THEN"
       "     threat_b := 3;"
       "   ELSIF low_b > 0 THEN"
       "     threat_b := 2;"
       "   ELSE"
       "     threat_b := 1;"
       "   END IF;"
       /*  Check if the threat level changed. */
       "   IF threat_a > threat_b THEN"
       "     RETURN 'up'::text;"
       "   ELSIF threat_b > threat_a THEN"
       "     RETURN 'down'::text;"
       "   END IF;"
       /*  Check if the threat count changed. */
       "   IF high_a > 0 THEN"
       "     IF high_a > high_b THEN"
       "       RETURN 'more'::text;"
       "     ELSIF high_a < high_b THEN"
       "       RETURN 'less'::text;"
       "     END IF;"
       "     RETURN 'same'::text;"
       "   END IF;"
       "   IF medium_a > 0 THEN"
       "     IF medium_a > medium_b THEN"
       "       RETURN 'more'::text;"
       "     ELSIF medium_a < medium_b THEN"
       "       RETURN 'less'::text;"
       "     END IF;"
       "     RETURN 'same'::text;"
       "   END IF;"
       "   IF low_a > 0 THEN"
       "     IF low_a > low_b THEN"
       "       RETURN 'more'::text;"
       "     ELSIF low_a < low_b THEN"
       "       RETURN 'less'::text;"
       "     END IF;"
       "     RETURN 'same'::text;"
       "   END IF;"
       "   RETURN 'same'::text;"
       " END;"
       "$$ LANGUAGE plpgsql;",
       TASK_STATUS_DONE,
       TASK_STATUS_RUNNING);

  sql ("CREATE OR REPLACE FUNCTION report_progress_active (integer)"
       " RETURNS integer AS $$"
       /* Calculate the progress of an active report. */
       " DECLARE"
       "   report_task integer;"
       "   task_target integer;"
       "   target_hosts text;"
       "   target_exclude_hosts text;"
       "   progress integer;"
       "   total integer;"
       "   maximum_hosts integer;"
       "   total_progress integer;"
       "   report_host record;"
       " BEGIN"
       "   total := 0;"
       "   report_task := (SELECT task FROM reports WHERE id = $1);"
       "   task_target := (SELECT target FROM tasks WHERE id = report_task);"
       "   IF task_target IS NULL THEN"
       "     target_hosts := NULL;"
       "     target_exclude_hosts := NULL;"
       "   ELSIF (SELECT target_location = " G_STRINGIFY (LOCATION_TRASH)
       "          FROM tasks WHERE id = report_task)"
       "   THEN"
       "     target_hosts := (SELECT hosts FROM targets_trash"
       "                      WHERE id = task_target);"
       "     target_exclude_hosts := (SELECT exclude_hosts FROM targets_trash"
       "                              WHERE id = task_target);"
       "   ELSE"
       "     target_hosts := (SELECT hosts FROM targets"
       "                      WHERE id = task_target);"
       "     target_exclude_hosts := (SELECT exclude_hosts FROM targets"
       "                              WHERE id = task_target);"
       "   END IF;"
       "   IF target_hosts IS NULL THEN"
       "     RETURN 0;"
       "   END IF;"
       "   maximum_hosts := max_hosts (target_hosts, target_exclude_hosts);"
       "   IF maximum_hosts = 0 THEN"
       "     RETURN 0;"
       "   END IF;"
       "   FOR report_host IN SELECT current_port, max_port"
       "                      FROM report_hosts WHERE report = $1"
       "   LOOP"
       "     IF report_host.max_port IS NOT NULL"
       "        AND report_host.max_port != 0"
       "     THEN"
       "       progress := (report_host.current_port * 100)"
       "                   / report_host.max_port;"
       "     ELSIF report_host.current_port IS NULL"
       "           OR report_host.current_port = 0"
       "     THEN"
       "       progress := 0;"
       "     ELSE"
       "       progress := 100;"
       "     END IF;"
       "     total := total + progress;"
       "   END LOOP;"
       "   total_progress := total / maximum_hosts;"
       "   IF total_progress = 0 THEN"
       "     RETURN 1;"
       "   ELSIF total_progress = 100 THEN"
       "     RETURN 99;"
       "   END IF;"
       "   RETURN total_progress;"
       " END;"
       "$$ LANGUAGE plpgsql;");

  sql ("CREATE OR REPLACE FUNCTION order_message_type (text)"
       " RETURNS integer AS $$"
       " BEGIN"
       "   IF $1 = 'Security Hole' THEN"
       "     RETURN 1;"
       "   ELSIF $1 = 'Security Warning' THEN"
       "     RETURN 2;"
       "   ELSIF $1 = 'Security Note' THEN"
       "     RETURN 3;"
       "   ELSIF $1 = 'Log Message' THEN"
       "     RETURN 4;"
       "   ELSIF $1 = 'Debug Message' THEN"
       "     RETURN 5;"
       "   ELSIF $1 = 'Error Message' THEN"
       "     RETURN 6;"
       "   ELSE"
       "     RETURN 7;"
       "   END IF;"
       " END;"
       "$$ LANGUAGE plpgsql;");

  sql ("CREATE OR REPLACE FUNCTION order_port (text)"
       " RETURNS integer AS $$"
       " BEGIN"
       // FIX
       "   RETURN 0;"
       " END;"
       "$$ LANGUAGE plpgsql;");

  sql ("CREATE OR REPLACE FUNCTION severity_to_type (double precision)"
       " RETURNS text AS $$"
       " BEGIN"
       "   IF $1 = " G_STRINGIFY (SEVERITY_LOG) " THEN"
       "     RETURN 'Log Message';"
       "   ELSIF $1 = " G_STRINGIFY (SEVERITY_FP) " THEN"
       "     RETURN 'False Positive';"
       "   ELSIF $1 = " G_STRINGIFY (SEVERITY_DEBUG) " THEN"
       "     RETURN 'Debug Message';"
       "   ELSIF $1 = " G_STRINGIFY (SEVERITY_ERROR) " THEN"
       "     RETURN 'Error Message';"
       "   ELSIF $1 > 0.0 AND $1 <= 10.0 THEN"
       "     RETURN 'Alarm';"
       "   ELSE"
       "     RAISE EXCEPTION 'Invalid severity score given: %', $1;"
       "   END IF;"
       " END;"
       "$$ LANGUAGE plpgsql;");

  sql ("CREATE OR REPLACE FUNCTION severity_matches_ov (double precision,"
       "                                                double precision)"
       " RETURNS boolean AS $$"
       " BEGIN"
       "   IF $1 IS NULL THEN"
       "     RAISE EXCEPTION 'First parameter of severity_matches_ov is NULL';"
       "   END IF;"
       "   RETURN CASE"
       "          WHEN $2 IS NULL"   // FIX SQLite also has "OR $2 = ''".
       "          THEN true"
       "          WHEN $1 <= 0.0"
       "          THEN $1 = $2"
       "          ELSE $1 >= $2"
       "          END;"
       " END;"
       "$$ LANGUAGE plpgsql;");

  sql ("CREATE OR REPLACE FUNCTION iso_time (seconds integer)"
       " RETURNS text AS $$"
       " DECLARE"
       "   user_zone text;"
       "   user_offset interval;"
       " BEGIN"
       "   user_zone := (SELECT timezone FROM users"
       "                 WHERE uuid = (SELECT uuid"
       "                               FROM current_credentials));"
       "   user_offset := age (now () AT TIME ZONE user_zone,"
       "                       now () AT TIME ZONE 'UTC');"
       "   RETURN CASE"
       "          WHEN $1 = 0"
       "          THEN ''"
       "          WHEN user_zone IS NULL"
       "          THEN to_char (to_timestamp ($1) AT TIME ZONE 'UTC',"
       "                        'FMIYYY-MM-DD')"
       "               || to_char (to_timestamp ($1) AT TIME ZONE 'UTC',"
       "                           'FMTHH24:MI:SSZ')"
       "          ELSE to_char (to_timestamp ($1) AT TIME ZONE user_zone,"
       "                        'FMIYYY-MM-DD')"
       "               || to_char (to_timestamp ($1) AT TIME ZONE user_zone,"
       "                           'FMTHH24:MI:SS')"
       "               || '+'"
       "               || to_char (extract (hours FROM user_offset)::integer,"
       "                           'FM00')"
       "               || ':'"
       "               || to_char (extract (minutes FROM user_offset)::integer,"
       "                           'FM00')"
       "          END;"
       " END;"
       "$$ LANGUAGE plpgsql;");

  sql ("CREATE OR REPLACE FUNCTION uniquify (type text, proposed_name text,"
       "                                     owner integer, suffix text)"
       " RETURNS text AS $$"
       " DECLARE"
       "   number integer := 1;"
       "   candidate text := '';"
       "   separator text := ' ';"
       "   unique_candidate boolean;"
       " BEGIN"
       "   IF type = 'user' THEN separator := '_'; END IF;"
       "   candidate := proposed_name || suffix || separator || number::text;"
       "   LOOP"
       "     EXECUTE 'SELECT count (*) = 0 FROM ' || type || 's"
       "              WHERE name = $1"
       "              AND ((owner IS NULL) OR (owner = $2))'"
       "       INTO unique_candidate"
       "       USING candidate, owner;"
       "     EXIT WHEN unique_candidate;"
       "     number := number + 1;"
       "     candidate := proposed_name || suffix || separator || number::text;"
       "   END LOOP;"
       "   RETURN candidate;"
       " END;"
       "$$ LANGUAGE plpgsql;");

  return 0;
}


/* SQL collations. */

/**
 * @brief Create collations.
 *
 * @return 0 success, -1 error.
 */
int
manage_create_sql_collations ()
{
  return 0;
}


/* Creation. */

/**
 * @brief Create all tables.
 */
void
create_tables ()
{
  sql ("CREATE TABLE IF NOT EXISTS current_credentials"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL);");

  sql ("CREATE TABLE IF NOT EXISTS meta"
       " (id SERIAL PRIMARY KEY,"
       "  name text UNIQUE NOT NULL,"
       "  value text);");

  sql ("CREATE TABLE IF NOT EXISTS users"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  name text NOT NULL,"
       "  comment text,"
       "  password text,"
       "  timezone text,"
       "  hosts text,"
       "  hosts_allow integer,"
       "  ifaces text,"
       "  ifaces_allow integer,"
       "  method text,"
       "  creation_time integer,"
       "  modification_time integer);");

  sql ("CREATE TABLE IF NOT EXISTS agents"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  name text NOT NULL,"
       "  comment text,"
       "  installer text,"
       "  installer_64 text,"
       "  installer_filename text,"
       "  installer_signature_64 text,"
       "  installer_trust integer,"
       "  installer_trust_time integer,"
       "  howto_install text,"
       "  howto_use text,"
       "  creation_time integer,"
       "  modification_time integer);");

  sql ("CREATE TABLE IF NOT EXISTS agents_trash"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  name text NOT NULL,"
       "  comment text,"
       "  installer text,"
       "  installer_64 text,"
       "  installer_filename text,"
       "  installer_signature_64 text,"
       "  installer_trust integer,"
       "  installer_trust_time integer,"
       "  howto_install text,"
       "  howto_use text,"
       "  creation_time integer,"
       "  modification_time integer);");

  sql ("CREATE TABLE IF NOT EXISTS alerts"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  name text NOT NULL,"
       "  comment text,"
       "  event integer,"
       "  condition integer,"
       "  method integer,"
       "  filter integer,"
       "  creation_time integer,"
       "  modification_time integer);");

  sql ("CREATE TABLE IF NOT EXISTS alerts_trash"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  name text NOT NULL,"
       "  comment text,"
       "  event integer,"
       "  condition integer,"
       "  method integer,"
       "  filter integer,"
       "  filter_location integer,"
       "  creation_time integer,"
       "  modification_time integer);");

  sql ("CREATE TABLE IF NOT EXISTS alert_condition_data"
       " (id SERIAL PRIMARY KEY,"
       "  alert integer REFERENCES alerts (id) ON DELETE RESTRICT,"
       "  name text,"
       "  data text);");

  sql ("CREATE TABLE IF NOT EXISTS alert_condition_data_trash"
       " (id SERIAL PRIMARY KEY,"
       "  alert integer REFERENCES alerts_trash (id) ON DELETE RESTRICT,"
       "  name text,"
       "  data text);");

  sql ("CREATE TABLE IF NOT EXISTS alert_event_data"
       " (id SERIAL PRIMARY KEY,"
       "  alert integer REFERENCES alerts (id) ON DELETE RESTRICT,"
       "  name text,"
       "  data text);");

  sql ("CREATE TABLE IF NOT EXISTS alert_event_data_trash"
       " (id SERIAL PRIMARY KEY,"
       "  alert integer REFERENCES alerts_trash (id) ON DELETE RESTRICT,"
       "  name text,"
       "  data text);");

  sql ("CREATE TABLE IF NOT EXISTS alert_method_data"
       " (id SERIAL PRIMARY KEY,"
       "  alert integer REFERENCES alerts (id) ON DELETE RESTRICT,"
       "  name text,"
       "  data text);");

  sql ("CREATE TABLE IF NOT EXISTS alert_method_data_trash"
       " (id SERIAL PRIMARY KEY,"
       "  alert integer REFERENCES alerts_trash (id) ON DELETE RESTRICT,"
       "  name text,"
       "  data text);");

  sql ("CREATE TABLE IF NOT EXISTS filters"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  name text NOT NULL,"
       "  comment text,"
       "  type text,"
       "  term text,"
       "  creation_time integer,"
       "  modification_time integer);");

  sql ("CREATE TABLE IF NOT EXISTS filters_trash"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  name text NOT NULL,"
       "  comment text,"
       "  type text,"
       "  term text,"
       "  creation_time integer,"
       "  modification_time integer);");

  sql ("CREATE TABLE IF NOT EXISTS groups"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  name text NOT NULL,"
       "  comment text,"
       "  creation_time integer,"
       "  modification_time integer);");

  sql ("CREATE TABLE IF NOT EXISTS groups_trash"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  name text NOT NULL,"
       "  comment text,"
       "  creation_time integer,"
       "  modification_time integer);");

  sql ("CREATE TABLE IF NOT EXISTS group_users"
       " (id SERIAL PRIMARY KEY,"
       "  \"group\" integer REFERENCES groups (id) ON DELETE RESTRICT,"
       "  \"user\" integer REFERENCES users (id) ON DELETE RESTRICT);");

  sql ("CREATE TABLE IF NOT EXISTS group_users_trash"
       " (id SERIAL PRIMARY KEY,"
       "  \"group\" integer REFERENCES groups_trash (id) ON DELETE RESTRICT,"
       "  \"user\" integer REFERENCES users (id) ON DELETE RESTRICT);");

  sql ("CREATE TABLE IF NOT EXISTS roles"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  name text NOT NULL,"
       "  comment text,"
       "  creation_time integer,"
       "  modification_time integer);");

  sql ("CREATE TABLE IF NOT EXISTS roles_trash"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  name text NOT NULL,"
       "  comment text,"
       "  creation_time integer,"
       "  modification_time integer);");

  sql ("CREATE TABLE IF NOT EXISTS role_users"
       " (id SERIAL PRIMARY KEY,"
       "  role integer REFERENCES roles (id) ON DELETE RESTRICT,"
       "  \"user\" integer REFERENCES users (id) ON DELETE RESTRICT);");

  sql ("CREATE TABLE IF NOT EXISTS role_users_trash"
       " (id SERIAL PRIMARY KEY,"
       "  role integer REFERENCES roles (id) ON DELETE RESTRICT,"
       "  \"user\" integer REFERENCES users (id) ON DELETE RESTRICT);");

  sql ("CREATE TABLE IF NOT EXISTS nvt_selectors"
       " (id SERIAL PRIMARY KEY,"
       "  name text,"
       "  exclude integer,"
       "  type integer,"
       "  family_or_nvt text,"
       "  family text);");

  sql ("CREATE TABLE IF NOT EXISTS port_lists"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  name text NOT NULL,"
       "  comment text,"
       "  creation_time integer,"
       "  modification_time integer);");

  sql ("CREATE TABLE IF NOT EXISTS port_lists_trash"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  name text NOT NULL,"
       "  comment text,"
       "  creation_time integer,"
       "  modification_time integer);");

  sql ("CREATE TABLE IF NOT EXISTS port_ranges"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  port_list integer REFERENCES port_lists (id) ON DELETE RESTRICT,"
       "  type integer,"
       "  start integer,"
       "  \"end\" integer,"
       "  comment text,"
       "  exclude integer);");

  sql ("CREATE TABLE IF NOT EXISTS port_ranges_trash"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  port_list integer REFERENCES port_lists_trash (id) ON DELETE RESTRICT,"
       "  type integer,"
       "  start integer,"
       "  \"end\" integer,"
       "  comment text,"
       "  exclude integer);");

  sql ("CREATE TABLE IF NOT EXISTS port_names"
       " (id SERIAL PRIMARY KEY,"
       "  number integer,"
       "  protocol text,"
       "  name text,"
       "  UNIQUE (number, protocol));");

  sql ("CREATE TABLE IF NOT EXISTS lsc_credentials"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  name text NOT NULL,"
       "  login text,"
       "  password text,"
       "  comment text,"
       "  private_key text,"
       "  creation_time integer,"
       "  modification_time integer);");

  sql ("CREATE TABLE IF NOT EXISTS lsc_credentials_trash"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  name text NOT NULL,"
       "  login text,"
       "  password text,"
       "  comment text,"
       "  private_key text,"
       "  creation_time integer,"
       "  modification_time integer);");

  sql ("CREATE TABLE IF NOT EXISTS targets"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  name text NOT NULL,"
       "  hosts text,"
       "  exclude_hosts text,"
       "  reverse_lookup_only integer,"
       "  reverse_lookup_unify integer,"
       "  comment text,"
       "  lsc_credential integer," // REFERENCES lsc_credentials (id) ON DELETE RESTRICT,"
       "  ssh_port text,"
       "  smb_lsc_credential integer," // REFERENCES lsc_credentials (id) ON DELETE RESTRICT,"
       "  port_range integer REFERENCES port_lists (id) ON DELETE RESTRICT,"
       "  alive_test integer,"
       "  creation_time integer,"
       "  modification_time integer);");

  sql ("CREATE TABLE IF NOT EXISTS targets_trash"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  name text NOT NULL,"
       "  hosts text,"
       "  exclude_hosts text,"
       "  reverse_lookup_only integer,"
       "  reverse_lookup_unify integer,"
       "  comment text,"
       "  lsc_credential integer," // REFERENCES lsc_credentials (id) ON DELETE RESTRICT,"
       "  ssh_port text,"
       "  smb_lsc_credential integer," // REFERENCES lsc_credentials (id) ON DELETE RESTRICT,"
       "  port_range integer REFERENCES port_lists (id) ON DELETE RESTRICT,"
       "  ssh_location integer,"
       "  smb_location integer,"
       "  port_list_location integer,"
       "  alive_test integer,"
       "  creation_time integer,"
       "  modification_time integer);");

  sql ("CREATE TABLE IF NOT EXISTS configs"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  name text NOT NULL,"
       "  nvt_selector text,"  /* REFERENCES nvt_selectors (name) */
       "  comment text,"
       "  family_count integer,"
       "  nvt_count integer,"
       "  families_growing integer,"
       "  nvts_growing integer,"
       "  type integer,"
       "  creation_time integer,"
       "  modification_time integer);");

  sql ("CREATE TABLE IF NOT EXISTS configs_trash"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  name text NOT NULL,"
       "  nvt_selector text,"  /* REFERENCES nvt_selectors (name) */
       "  comment text,"
       "  family_count integer,"
       "  nvt_count integer,"
       "  families_growing integer,"
       "  nvts_growing integer,"
       "  type integer,"
       "  creation_time integer,"
       "  modification_time integer);");

  sql ("CREATE TABLE IF NOT EXISTS config_preferences"
       " (id SERIAL PRIMARY KEY,"
       "  config integer REFERENCES configs (id) ON DELETE RESTRICT,"
       "  type text,"
       "  name text,"
       "  value text);");

  sql ("CREATE TABLE IF NOT EXISTS config_preferences_trash"
       " (id SERIAL PRIMARY KEY,"
       "  config integer REFERENCES configs_trash (id) ON DELETE RESTRICT,"
       "  type text,"
       "  name text,"
       "  value text);");

  sql ("CREATE TABLE IF NOT EXISTS schedules"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  name text NOT NULL,"
       "  comment text,"
       "  first_time integer,"
       "  period integer,"
       "  period_months integer,"
       "  duration integer,"
       "  timezone text,"
       "  initial_offset integer,"
       "  creation_time integer,"
       "  modification_time integer);");

  sql ("CREATE TABLE IF NOT EXISTS schedules_trash"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  name text NOT NULL,"
       "  comment text,"
       "  first_time integer,"
       "  period integer,"
       "  period_months integer,"
       "  duration integer,"
       "  timezone text,"
       "  initial_offset integer,"
       "  creation_time integer,"
       "  modification_time integer);");

  sql ("CREATE TABLE IF NOT EXISTS slaves"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  name text NOT NULL,"
       "  comment text,"
       "  host text,"
       "  port text,"
       "  login text,"
       "  password text,"
       "  creation_time integer,"
       "  modification_time integer);");

  sql ("CREATE TABLE IF NOT EXISTS slaves_trash"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  name text NOT NULL,"
       "  comment text,"
       "  host text,"
       "  port text,"
       "  login text,"
       "  password text,"
       "  creation_time integer,"
       "  modification_time integer);");

  sql ("CREATE TABLE IF NOT EXISTS scanners"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  name text,"
       "  comment text,"
       "  host text,"
       "  port integer,"
       "  type integer,"
       "  ca_pub text,"
       "  key_pub text,"
       "  key_priv text,"
       "  creation_time integer,"
       "  modification_time integer);");

  sql ("CREATE TABLE IF NOT EXISTS scanners_trash"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  name text,"
       "  comment text,"
       "  host text,"
       "  port integer,"
       "  type integer,"
       "  ca_pub text,"
       "  key_pub text,"
       "  key_priv text,"
       "  creation_time integer,"
       "  modification_time integer);");

  sql ("CREATE TABLE IF NOT EXISTS tasks"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  name text,"
       "  hidden integer,"
       "  comment text,"
       "  description text,"
       "  run_status integer,"
       "  start_time integer,"
       "  end_time integer,"
       "  config integer REFERENCES configs (id) ON DELETE RESTRICT,"
       "  target integer REFERENCES targets (id) ON DELETE RESTRICT,"
       "  schedule integer," // REFERENCES schedules (id) ON DELETE RESTRICT,"
       "  schedule_next_time integer,"
       "  slave integer," // REFERENCES slaves (id) ON DELETE RESTRICT,"
       "  scanner integer," // REFERENCES scanner (id) ON DELETE RESTRICT,"
       "  config_location integer,"
       "  target_location integer,"
       "  schedule_location integer,"
       "  slave_location integer,"
       "  upload_result_count integer,"
       "  hosts_ordering text,"
       "  alterable integer,"
       "  creation_time integer,"
       "  modification_time integer);");

  sql ("CREATE TABLE IF NOT EXISTS task_files"
       " (id SERIAL PRIMARY KEY,"
       "  task integer REFERENCES tasks (id) ON DELETE RESTRICT,"
       "  name text,"
       "  content text);");

  sql ("CREATE TABLE IF NOT EXISTS task_alerts"
       " (id SERIAL PRIMARY KEY,"
       "  task integer REFERENCES tasks (id) ON DELETE RESTRICT,"
       "  alert integer REFERENCES alerts (id) ON DELETE RESTRICT,"
       "  alert_location integer);");

  sql ("CREATE TABLE IF NOT EXISTS task_preferences"
       " (id SERIAL PRIMARY KEY,"
       "  task integer REFERENCES tasks (id) ON DELETE RESTRICT,"
       "  name text,"
       "  value text);");

  sql ("CREATE TABLE IF NOT EXISTS reports"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  hidden integer,"
       "  task integer REFERENCES tasks (id) ON DELETE RESTRICT,"
       "  date integer,"
       "  start_time integer,"
       "  end_time integer,"
       "  nbefile text,"
       "  comment text,"
       "  scan_run_status integer,"
       "  slave_progress integer,"
       "  slave_task_uuid text,"
       "  slave_uuid text,"
       "  slave_name text,"
       "  slave_host text,"
       "  slave_port integer,"
       "  source_iface text);");

  sql ("CREATE TABLE IF NOT EXISTS report_counts"
       " (id SERIAL PRIMARY KEY,"
       "  report integer REFERENCES reports (id) ON DELETE RESTRICT,"
       "  \"user\" integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  severity decimal,"
       "  count integer,"
       "  override integer,"
       "  end_time integer);");

  sql ("CREATE TABLE IF NOT EXISTS results"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  task integer REFERENCES tasks (id) ON DELETE RESTRICT,"
       "  host text,"
       "  port text,"
       "  nvt text,"
       "  type text,"
       "  description text,"
       "  report integer REFERENCES reports (id) ON DELETE RESTRICT,"
       "  nvt_version text,"
       "  severity real,"
       "  qod integer,"
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  date integer);");

  sql ("CREATE TABLE IF NOT EXISTS report_formats"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  name text NOT NULL,"
       "  extension text,"
       "  content_type text,"
       "  summary text,"
       "  description text,"
       "  signature text,"
       "  trust integer,"
       "  trust_time integer,"
       "  flags integer,"
       "  creation_time integer,"
       "  modification_time integer);");

  sql ("CREATE TABLE IF NOT EXISTS report_formats_trash"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  name text NOT NULL,"
       "  extension text,"
       "  content_type text,"
       "  summary text,"
       "  description text,"
       "  signature text,"
       "  trust integer,"
       "  trust_time integer,"
       "  flags integer,"
       "  original_uuid text,"
       "  creation_time integer,"
       "  modification_time integer);");

  sql ("CREATE TABLE IF NOT EXISTS report_format_params"
       " (id SERIAL PRIMARY KEY,"
       "  report_format integer REFERENCES report_formats (id) ON DELETE RESTRICT,"
       "  name text,"
       "  type integer,"
       "  value text,"
       "  type_min bigint,"
       "  type_max bigint,"
       "  type_regex text,"
       "  fallback text);");

  sql ("CREATE TABLE IF NOT EXISTS report_format_params_trash"
       " (id SERIAL PRIMARY KEY,"
       "  report_format integer REFERENCES report_formats (id) ON DELETE RESTRICT,"
       "  name text,"
       "  type integer,"
       "  value text,"
       "  type_min bigint,"
       "  type_max bigint,"
       "  type_regex text,"
       "  fallback text);");

  sql ("CREATE TABLE IF NOT EXISTS report_format_param_options"
       " (id SERIAL PRIMARY KEY,"
       "  report_format_param integer REFERENCES report_format_params (id) ON DELETE RESTRICT,"
       "  value text);");

  sql ("CREATE TABLE IF NOT EXISTS report_format_param_options_trash"
       " (id SERIAL PRIMARY KEY,"
       "  report_format_param integer REFERENCES report_format_params (id) ON DELETE RESTRICT,"
       "  value text);");

  sql ("CREATE TABLE IF NOT EXISTS report_hosts"
       " (id SERIAL PRIMARY KEY,"
       "  report integer REFERENCES reports (id) ON DELETE RESTRICT,"
       "  host text,"
       "  start_time integer,"
       "  end_time integer,"
       "  attack_state integer,"
       "  current_port integer,"
       "  max_port integer);");

  sql ("CREATE TABLE IF NOT EXISTS report_host_details"
       " (id SERIAL PRIMARY KEY,"
       "  report_host integer REFERENCES report_hosts (id) ON DELETE RESTRICT,"
       "  source_type text,"
       "  source_name text,"
       "  source_description text,"
       "  name text,"
       "  value text);");

  sql ("CREATE TABLE IF NOT EXISTS report_results"
       " (id SERIAL PRIMARY KEY,"
       "  report integer REFERENCES reports (id) ON DELETE RESTRICT,"
       "  result integer REFERENCES results (id) ON DELETE RESTRICT);");

  sql ("CREATE TABLE IF NOT EXISTS nvt_preferences"
       " (id SERIAL PRIMARY KEY,"
       "  name text UNIQUE NOT NULL,"
       "  value text);");

  sql ("CREATE TABLE IF NOT EXISTS nvts"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  oid text UNIQUE NOT NULL,"
       "  version text,"
       "  name text,"
       "  comment text,"
       "  summary text,"
       "  copyright text,"
       "  cve text,"
       "  bid text,"
       "  xref text,"
       "  tag text,"
       "  category text,"
       "  family text,"
       "  cvss_base text,"
       "  creation_time integer,"
       "  modification_time integer);");

  sql ("CREATE TABLE IF NOT EXISTS nvt_cves"
       " (id SERIAL PRIMARY KEY,"
       "  nvt integer REFERENCES nvts (id) ON DELETE RESTRICT,"
       "  oid text,"
       "  cve_name text);");

  sql ("CREATE TABLE IF NOT EXISTS notes"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  nvt text NOT NULL,"
       "  creation_time integer,"
       "  modification_time integer,"
       "  text text,"
       "  hosts text,"
       "  port text,"
       "  severity double precision,"
       "  task integer," // REFERENCES tasks (id) ON DELETE RESTRICT,"
       "  result integer," // REFERENCES results (id) ON DELETE RESTRICT,"
       "  end_time integer);");

  sql ("CREATE TABLE IF NOT EXISTS notes_trash"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  nvt text NOT NULL,"
       "  creation_time integer,"
       "  modification_time integer,"
       "  text text,"
       "  hosts text,"
       "  port text,"
       "  severity double precision,"
       "  task integer," // REFERENCES tasks (id) ON DELETE RESTRICT,"
       "  result integer," // REFERENCES results (id) ON DELETE RESTRICT,"
       "  end_time integer);");

  sql ("CREATE TABLE IF NOT EXISTS overrides"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  nvt text NOT NULL,"
       "  creation_time integer,"
       "  modification_time integer,"
       "  text text,"
       "  hosts text,"
       "  new_severity double precision,"
       "  port text,"
       "  severity double precision,"
       "  task integer," // REFERENCES tasks (id) ON DELETE RESTRICT,"
       "  result integer," // REFERENCES results (id) ON DELETE RESTRICT,"
       "  end_time integer);");

  sql ("CREATE TABLE IF NOT EXISTS overrides_trash"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  nvt text NOT NULL,"
       "  creation_time integer,"
       "  modification_time integer,"
       "  text text,"
       "  hosts text,"
       "  new_severity double precision,"
       "  port text,"
       "  severity double precision,"
       "  task integer," // REFERENCES tasks (id) ON DELETE RESTRICT,"
       "  result integer," // REFERENCES results (id) ON DELETE RESTRICT,"
       "  end_time integer);");

  sql ("CREATE TABLE IF NOT EXISTS permissions"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  name text NOT NULL,"
       "  comment text,"
       "  resource_type text,"
       "  resource integer,"
       "  resource_uuid text,"
       "  resource_location integer,"
       "  subject_type text,"
       "  subject integer,"
       "  subject_location integer,"
       "  creation_time integer,"
       "  modification_time integer);");

  sql ("CREATE TABLE IF NOT EXISTS permissions_trash"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  name text NOT NULL,"
       "  comment text,"
       "  resource_type text,"
       "  resource integer,"
       "  resource_uuid text,"
       "  resource_location integer,"
       "  subject_type text,"
       "  subject integer,"
       "  subject_location integer,"
       "  creation_time integer,"
       "  modification_time integer);");

  sql ("CREATE TABLE IF NOT EXISTS settings"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text NOT NULL,"     /* Note: not UNIQUE. */
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  name text NOT NULL,"
       "  comment text,"
       "  value text);");

  sql ("CREATE TABLE IF NOT EXISTS tags"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  name text NOT NULL,"
       "  comment text,"
       "  resource_type text,"
       "  resource integer,"
       "  resource_uuid text,"
       "  resource_location integer,"
       "  active integer,"
       "  value text,"
       "  creation_time integer,"
       "  modification_time integer);");

  sql ("CREATE TABLE IF NOT EXISTS tags_trash"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  name text NOT NULL,"
       "  comment text,"
       "  resource_type text,"
       "  resource integer,"
       "  resource_uuid text,"
       "  resource_location integer,"
       "  active integer,"
       "  value text,"
       "  creation_time integer,"
       "  modification_time integer);");
}


/* Migrator helper. */

/**
 * @brief Dummy for SQLite3 compatibility.
 *
 * @param[in]  stmt      Statement.
 * @param[in]  position  Column position.
 *
 * @return 0 success, -1 error.
 */
int
manage_create_migrate_51_to_52_convert ()
{
  return 0;
}
