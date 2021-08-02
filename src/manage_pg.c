/* Copyright (C) 2014-2021 Greenbone Networks GmbH
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @file  manage_pg.c
 * @brief GVM management layer: PostgreSQL specific facilities
 *
 * This file contains the parts of the GVM management layer that need
 * to be coded for each backend.  This is the PostgreSQL version.
 */

#include <strings.h> /* for strcasecmp() */
#include <assert.h>  /* for assert() */

#include "sql.h"
#include "manage_sql.h"
#include "manage_utils.h"
#include "manage_acl.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Database superuser role
 */
#define DB_SUPERUSER_ROLE "dba"


/* Headers */
int
check_db_extensions ();


/* Session. */

/**
 * @brief Setup session.
 *
 * @param[in]  uuid  User UUID.
 */
void
manage_session_init (const char *uuid)
{
  sql ("SET SESSION \"gvmd.user.id\" = %llu;",
       sql_int64_0 ("SELECT id FROM users WHERE uuid = '%s';",
                    uuid));
  sql ("SET SESSION \"gvmd.tz_override\" = '';");
}

/**
 * @brief Setup session timezone.
 *
 * @param[in]  zone  Timezone.
 */
void
manage_session_set_timezone (const char *zone)
{
  sql ("SET SESSION TIME ZONE '%s';", zone);
  return;
}


/* Helpers. */

/**
 * @brief Check whether database is empty.
 *
 * @return 1 if empty, else 0.
 */
int
manage_db_empty ()
{
  return sql_int ("SELECT EXISTS (SELECT * FROM information_schema.tables"
                  "               WHERE table_catalog = '%s'"
                  "               AND table_schema = 'public'"
                  "               AND table_name = 'meta')"
                  "        ::integer;",
                  sql_database ())
         == 0;
}


/* SCAP. */

/**
 * @brief Check if CERT db exists.
 *
 * @return 1 if exists, else 0.
 */
int
manage_cert_db_exists ()
{
  if (sql_int ("SELECT exists (SELECT schema_name"
               "               FROM information_schema.schemata"
               "               WHERE schema_name = 'cert');"))
    return 1;
  return 0;
}

/**
 * @brief Check if SCAP db exists.
 *
 * @return 1 if exists, else 0.
 */
int
manage_scap_db_exists ()
{
  if (sql_int ("SELECT exists (SELECT schema_name"
               "               FROM information_schema.schemata"
               "               WHERE schema_name = 'scap');"))
    return 1;
  return 0;
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
 * @brief Common overrides SQL for SQL functions.
 */
#define OVERRIDES_SQL(severity_sql)                         \
 " coalesce"                                                \
 "  ((SELECT overrides.new_severity"                        \
 "    FROM overrides"                                       \
 "    WHERE overrides.result_nvt = results.result_nvt"      \
 "    AND ((overrides.owner IS NULL)"                       \
 "         OR (overrides.owner"                             \
 "             = gvmd_user ()))"        \
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

/**
 * @brief Create functions.
 *
 * @return 0 success, -1 error.
 */
int
manage_create_sql_functions ()
{
  static int created = 0;
  int current_db_version = manage_db_version ();

  if (created)
    return 0;

  if (check_db_extensions ())
    return -1;

  /* Functions in C. */

  sql ("SET ROLE \"%s\";", DB_SUPERUSER_ROLE);

  sql ("CREATE OR REPLACE FUNCTION hosts_contains (text, text)"
       " RETURNS boolean"
       " AS '%s/libgvm-pg-server', 'sql_hosts_contains'"
       " LANGUAGE C"
       " IMMUTABLE;",
       GVM_LIB_INSTALL_DIR);

  sql ("CREATE OR REPLACE FUNCTION max_hosts (text, text)"
       " RETURNS integer"
       " AS '%s/libgvm-pg-server', 'sql_max_hosts'"
       " LANGUAGE C;",
       GVM_LIB_INSTALL_DIR);

  /*
   * This database function is a duplicate of 'level_max_severity' from manage_utils.c
   * These two functions must stay in sync.
   */
  sql ("CREATE OR REPLACE FUNCTION level_max_severity (lvl text, cls text)"
       "RETURNS double precision AS $$"
       "DECLARE"
       "  v double precision;"
       "BEGIN"
       "  CASE"
       "    WHEN lower (lvl) = 'log' THEN"
       "      v := " G_STRINGIFY (SEVERITY_LOG) ";"
       "    WHEN lower (lvl) = 'false positive' THEN"
       "      v := " G_STRINGIFY (SEVERITY_FP) ";"
       "    WHEN lower (lvl) = 'error' THEN"
       "      v :=  " G_STRINGIFY (SEVERITY_ERROR) ";"
       "    ELSE"
       "      CASE"
       "        WHEN lower (lvl) = 'high' THEN"
       "          v := 10.0;"
       "        WHEN lower (lvl) = 'medium' THEN"
       "          v := 6.9;"
       "        WHEN lower (lvl) = 'low' THEN"
       "          v := 3.9;"
       "        ELSE"
       "          v := " G_STRINGIFY (SEVERITY_UNDEFINED) ";"
       "        END CASE;"
       "    END CASE;"
       "  return v;"
       "END;"
       "$$ LANGUAGE plpgsql;");

  /*
   * This database function is a duplicate of 'level_min_severity' from manage_utils.c
   * These two functions must stay in sync.
   */
  sql ("CREATE OR REPLACE FUNCTION level_min_severity(lvl text, cls text)"
       "RETURNS double precision AS $$"
       "DECLARE"
       "  v double precision;"
       "BEGIN"
       "  CASE"
       "    WHEN lower (lvl) = 'log' THEN"
       "      v := " G_STRINGIFY (SEVERITY_LOG) ";"
       "    WHEN lower (lvl) = 'false positive' THEN"
       "      v := " G_STRINGIFY (SEVERITY_FP) ";"
       "    WHEN lower (lvl) = 'error' THEN"
       "      v :=  " G_STRINGIFY (SEVERITY_ERROR) ";"
       "    ELSE"
       "      CASE"
       "        WHEN lower (lvl) = 'high' THEN"
       "          v := 7.0;"
       "        WHEN lower (lvl) = 'medium' THEN"
       "          v := 4.0;"
       "        WHEN lower (lvl) = 'low' THEN"
       "          v := 0.1;"
       "        ELSE"
       "          v := " G_STRINGIFY (SEVERITY_UNDEFINED) ";"
       "        END CASE;"
       "    END CASE;"
       "  return v;"
       "END;"
       "$$ LANGUAGE plpgsql;");

  sql ("CREATE OR REPLACE FUNCTION next_time_ical (text, text)"
       " RETURNS integer"
       " AS '%s/libgvm-pg-server', 'sql_next_time_ical'"
       " LANGUAGE C;",
       GVM_LIB_INSTALL_DIR);

  sql ("CREATE OR REPLACE FUNCTION next_time_ical (text, text, integer)"
       " RETURNS integer"
       " AS '%s/libgvm-pg-server', 'sql_next_time_ical'"
       " LANGUAGE C;",
       GVM_LIB_INSTALL_DIR);

  sql ("CREATE OR REPLACE FUNCTION severity_matches_ov (a double precision,"
       "                                                b double precision)"
       "RETURNS BOOLEAN AS $$"
       "BEGIN"
       " RETURN CASE WHEN a IS NULL THEN false"
       "        WHEN b IS NULL THEN true"
       " ELSE CASE WHEN a::float8 <= 0 THEN a::float8 = b::float8"
       "      ELSE a::float8 >= b::float8"
       "      END"
       " END;"
       "END;"
       "$$ LANGUAGE plpgsql IMMUTABLE;");

  sql ("CREATE OR REPLACE FUNCTION regexp (text, text)"
       " RETURNS boolean"
       " AS '%s/libgvm-pg-server', 'sql_regexp'"
       " LANGUAGE C;",
       GVM_LIB_INSTALL_DIR);

  if (sql_int ("SELECT count(*) FROM pg_operator"
               " WHERE oprname = '?~#';")
      == 0)
    {
      sql ("CREATE OPERATOR ?~#"
          " (PROCEDURE = regexp, LEFTARG = text, RIGHTARG = text);");
    }

  sql ("RESET role;");

  /* Functions in pl/pgsql. */

  /* Helper function for quoting the individual parts of multi-part
   *  identifiers like "scap", "cpes" and "id" in "scap.cpes.id" where
   *  necessary.
   */
  sql ("CREATE OR REPLACE FUNCTION quote_ident_split (ident_name text)"
       " RETURNS text AS $$"
       " DECLARE quoted text := '';"
       " BEGIN"
       // Split original dot-separated input into rows
       "   WITH split AS"
       "   (SELECT (unnest(string_to_array(ident_name, '.'))) AS part)"
       // For each row trim outer quote marks and quote the result.
       //  then recombine the rows into a single, dot-separated string again.
       "   SELECT string_agg(quote_ident(trim(part, '\"')), '.') FROM split"
       "   INTO quoted;"
       "   RETURN quoted;"
       " END;"
       " $$ LANGUAGE plpgsql;");

  /* Helper function for quoting comma-separated lists of
   *  identifiers like "config.name, config.type"
   */
  sql ("CREATE OR REPLACE FUNCTION quote_ident_list (ident_name text)"
       " RETURNS text AS $$"
       " DECLARE quoted text := '';"
       " BEGIN"
       // Split original comma-separated input into rows
       "   WITH split AS"
       "   (SELECT (unnest(string_to_array(ident_name, ','))) AS ident)"
       // For each row trim outer whitespace and quote the result.
       //  then recombine the rows into a single, comma-separated string again.
       "   SELECT string_agg(quote_ident_split(trim(ident, ' ')), ', ')"
       "   FROM split"
       "   INTO quoted;"
       "   RETURN quoted;"
       " END;"
       " $$ LANGUAGE plpgsql;");

  /* Wrapping the "LOCK TABLE ... NOWAIT" like this will prevent
   *  error messages in the PostgreSQL log if the lock is not available.
   */
  sql ("CREATE OR REPLACE FUNCTION try_exclusive_lock (regclass)"
       " RETURNS integer AS $$"
       " BEGIN"
       "   EXECUTE 'LOCK TABLE '"
       "           || quote_ident_split($1::text)"
       "           || ' IN ACCESS EXCLUSIVE MODE NOWAIT;';"
       "   RETURN 1;"
       " EXCEPTION WHEN lock_not_available THEN"
       "   RETURN 0;"
       " END;"
       "$$ language 'plpgsql';");

  if (sql_int ("SELECT EXISTS (SELECT * FROM information_schema.tables"
               "               WHERE table_catalog = '%s'"
               "               AND table_schema = 'public'"
               "               AND table_name = 'meta')"
               " ::integer;",
               sql_database ()))
    {
      sql ("CREATE OR REPLACE FUNCTION resource_name (text, text, integer)"
           " RETURNS text AS $$"
           /* Get the name of a resource by its type and ID. */
           " DECLARE"
           "   execute_name text;"
           " BEGIN"
           "   CASE"
           "   WHEN $1 = 'note'"
           "        AND $3 = "  G_STRINGIFY (LOCATION_TABLE)
           "   THEN RETURN (SELECT 'Note for: '"
           "                       || (SELECT name"
           "                           FROM nvts"
           "                           WHERE nvts.uuid = notes.nvt)"
           "                FROM notes"
           "                WHERE uuid = $2);"
           "   WHEN $1 = 'note'"
           "   THEN RETURN (SELECT 'Note for: '"
           "                       || (SELECT name"
           "                           FROM nvts"
           "                           WHERE nvts.uuid = notes_trash.nvt)"
           "                FROM notes_trash"
           "                WHERE uuid = $2);"
           "   WHEN $1 = 'override'"
           "        AND $3 = " G_STRINGIFY (LOCATION_TABLE)
           "   THEN RETURN (SELECT 'Override for: '"
           "                       || (SELECT name"
           "                           FROM nvts"
           "                           WHERE nvts.uuid = overrides.nvt)"
           "                FROM overrides"
           "                WHERE uuid = $2);"
           "   WHEN $1 = 'override'"
           "   THEN RETURN (SELECT 'Override for: '"
           "                       || (SELECT name"
           "                           FROM nvts"
           "                           WHERE nvts.uuid = overrides_trash.nvt)"
           "                FROM overrides_trash"
           "                WHERE uuid = $2);"
           "   WHEN $1 = 'report'"
           "   THEN RETURN (SELECT (SELECT name FROM tasks WHERE id = task)"
           "                || ' - '"
           "                || (SELECT"
           "                      CASE (SELECT end_time FROM tasks"
           "                            WHERE id = task)"
           "                      WHEN 0 THEN 'N/A'"
           "                      ELSE (SELECT end_time::text"
           "                            FROM tasks WHERE id = task)"
           "                    END)"
           "                FROM reports"
           "                WHERE uuid = $2);"
           "   WHEN $1 = 'result'"
           "   THEN RETURN (SELECT (SELECT name FROM tasks WHERE id = task)"
           "                || ' - '"
           "                || (SELECT name FROM nvts WHERE oid = nvt)"
           "                || ' - '"
           "                || (SELECT"
           "                      CASE (SELECT end_time FROM tasks"
           "                            WHERE id = task)"
           "                      WHEN 0 THEN 'N/A'"
           "                      ELSE (SELECT end_time::text"
           "                            FROM tasks WHERE id = task)"
           "                    END)"
           "                FROM results"
           "                WHERE uuid = $2);"
           "   WHEN $1 = 'task'"
           "   THEN RETURN (SELECT name FROM tasks WHERE uuid = $2);"
           "   WHEN $3 = " G_STRINGIFY (LOCATION_TABLE)
           "   THEN EXECUTE 'SELECT name FROM '"
           "                || quote_ident_split($1 || 's')"
           "                || ' WHERE uuid = $1'"
           "        INTO execute_name"
           "        USING $2;"
           "        RETURN execute_name;"
           "   WHEN $1 NOT IN ('nvt', 'cpe', 'cve', 'ovaldef', 'cert_bund_adv',"
           "                   'dfn_cert_adv', 'report', 'result', 'user')"
           "   THEN EXECUTE 'SELECT name FROM '"
           "                || quote_ident_split ($1 || 's_trash')"
           "                || ' WHERE uuid = $1'"
           "        INTO execute_name"
           "        USING $2;"
           "        RETURN execute_name;"
           "   ELSE RETURN NULL;"
           "   END CASE;"
           " END;"
           "$$ LANGUAGE plpgsql;");

      created = 1;
    }

  sql ("CREATE OR REPLACE FUNCTION order_inet (text)"
       " RETURNS text AS $$"
       " BEGIN"
       "   IF $1 ~ '^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$' THEN"
       "     RETURN chr (1)" /* Make IPs sort before hostnames. */
       "            || to_char (split_part ($1, '.', 1)::integer, 'fm000')"
       "            || '.'"
       "            || to_char (split_part ($1, '.', 2)::integer, 'fm000')"
       "            || '.'"
       "            || to_char (split_part ($1, '.', 3)::integer, 'fm000')"
       "            || '.'"
       "            || to_char (split_part ($1, '.', 4)::integer, 'fm000');"
       "   ELSE"
       "     RETURN $1;"
       "   END IF;"
       " END;"
       "$$ LANGUAGE plpgsql"
       " IMMUTABLE;");

  sql ("CREATE OR REPLACE FUNCTION order_port (text)"
       " RETURNS integer AS $$"
       " BEGIN"
       "   IF $1 ~ '^[0-9]+' THEN"
       "     RETURN CAST (substring ($1, '^[0-9]+') as integer);"
       "   ELSIF $1 ~ '^[^0-9]* \\([0-9]+/' THEN"
       "     RETURN CAST (substring ($1, '^[^0-9]* \\(([0-9]+)/') as integer);"
       "   ELSE"
       "     RETURN 0;"
       "   END IF;"
       " END;"
       "$$ LANGUAGE plpgsql"
       " IMMUTABLE;");

  sql ("CREATE OR REPLACE FUNCTION order_role (text)"
       " RETURNS text AS $$"
       " BEGIN"
       "   IF $1 = 'Admin' THEN"
       "     RETURN ' !';"
       "   ELSE"
       "     RETURN $1;"
       "   END IF;"
       " END;"
       "$$ LANGUAGE plpgsql"
       " IMMUTABLE;");

  sql ("CREATE OR REPLACE FUNCTION order_threat (text)"
       " RETURNS integer AS $$"
       " BEGIN"
       "   IF $1 = 'High' THEN"
       "     RETURN 1;"
       "   ELSIF $1 = 'Medium' THEN"
       "     RETURN 2;"
       "   ELSIF $1 = 'Low' THEN"
       "     RETURN 3;"
       "   ELSIF $1 = 'Log' THEN"
       "     RETURN 4;"
       "   ELSIF $1 = 'False Positive' THEN"
       "     RETURN 5;"
       "   ELSIF $1 = 'None' THEN"
       "     RETURN 6;"
       "   ELSE"
       "     RETURN 7;"
       "   END IF;"
       " END;"
       "$$ LANGUAGE plpgsql"
       " IMMUTABLE;");

  sql ("CREATE OR REPLACE FUNCTION severity_to_type (double precision)"
       " RETURNS text AS $$"
       " BEGIN"
       "   IF $1 IS NULL THEN"
       "     RETURN NULL;"
       "   ELSIF $1 = " G_STRINGIFY (SEVERITY_LOG) " THEN"
       "     RETURN 'Log Message';"
       "   ELSIF $1 = " G_STRINGIFY (SEVERITY_FP) " THEN"
       "     RETURN 'False Positive';"
       "   ELSIF $1 = " G_STRINGIFY (SEVERITY_ERROR) " THEN"
       "     RETURN 'Error Message';"
       "   ELSIF $1 > 0.0 AND $1 <= 10.0 THEN"
       "     RETURN 'Alarm';"
       "   ELSE"
       "     RAISE EXCEPTION 'Invalid severity score given: %%', $1;"
       "   END IF;"
       " END;"
       "$$ LANGUAGE plpgsql"
       " IMMUTABLE;");

  sql ("DROP FUNCTION IF EXISTS iso_time (seconds integer);");

  sql ("CREATE OR REPLACE FUNCTION iso_time (seconds bigint, user_zone text)"
       " RETURNS text AS $$"
       " DECLARE"
       "   user_offset interval;"
       " BEGIN"
       "   BEGIN"
       "     user_offset := age (now () AT TIME ZONE user_zone,"
       "                         now () AT TIME ZONE 'UTC');"
       "   EXCEPTION WHEN invalid_parameter_value THEN"
       "     user_zone = 'UTC';"
       "     user_offset = 0;"
       "   END;"
       "   RETURN CASE"
       "          WHEN $1 IS NULL OR $1 = 0"
       "          THEN ''"
       "          WHEN user_zone IS NULL"
       "            OR EXTRACT (EPOCH FROM user_offset) = 0"
       "          THEN to_char (to_timestamp ($1) AT TIME ZONE 'UTC',"
       "                        'FMYYYY-MM-DD')"
       "               || to_char (to_timestamp ($1) AT TIME ZONE 'UTC',"
       "                           'FMTHH24:MI:SSZ')"
       "          ELSE to_char (to_timestamp ($1) AT TIME ZONE user_zone,"
       "                        'FMYYYY-MM-DD')"
       "               || to_char (to_timestamp ($1) AT TIME ZONE user_zone,"
       "                           'FMTHH24:MI:SS')"
       "               || CASE WHEN (extract (epoch FROM user_offset) > 0)"
       "                       THEN '+' ELSE '' END"
       "               || to_char (extract (hours FROM user_offset)::integer,"
       "                           'FM00')"
       "               || ':'"
       "               || to_char (abs (extract (minutes FROM user_offset)"
       "                                ::integer),"
       "                           'FM00')"
       "          END;"
       " END;"
       "$$ LANGUAGE plpgsql;");

  sql ("CREATE OR REPLACE FUNCTION iso_time (seconds bigint)"
       " RETURNS text AS $$"
       " DECLARE"
       "   user_zone text;"
       " BEGIN"
       "   user_zone :="
       "     coalesce ((SELECT current_setting ('gvmd.tz_override')),"
       "               (SELECT timezone FROM users"
       "                WHERE id = gvmd_user ()));"
       " RETURN iso_time (seconds, user_zone);"
       " END;"
       "$$ LANGUAGE plpgsql;");

  sql ("DROP FUNCTION IF EXISTS iso_time (integer);");

  sql ("CREATE OR REPLACE FUNCTION certificate_iso_time (bigint)"
       " RETURNS text AS $$"
       " BEGIN"
       "   RETURN CASE"
       "     WHEN ($1 = 0) THEN 'unlimited'"
       "     WHEN ($1 = -1) THEN 'unknown'"
       "     ELSE iso_time($1)"
       "     END;"
       " END;"
       "$$ LANGUAGE plpgsql;");

  sql ("DROP FUNCTION IF EXISTS days_from_now (seconds integer);");

  sql ("CREATE OR REPLACE FUNCTION days_from_now (seconds bigint)"
       " RETURNS integer AS $$"
       " DECLARE"
       "   diff interval;"
       " BEGIN"
       "   diff := age (to_timestamp (seconds), now ());"
       "   RETURN CASE"
       "          WHEN seconds = 0"
       "          THEN -2"
       "          WHEN diff < interval '0 seconds'"
       "          THEN -1"
       "          ELSE date_part ('day', diff)"
       "          END;"
       " END;"
       "$$ LANGUAGE plpgsql"
       " STABLE;");

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
       "     EXECUTE 'SELECT count (*) = 0 FROM '"
       "             || quote_ident_split(type || 's')"
       "             || ' WHERE name = $1"
       "              AND (($2 IS NULL) OR (owner IS NULL) OR (owner = $2))'"
       "       INTO unique_candidate"
       "       USING candidate, owner;"
       "     EXIT WHEN unique_candidate;"
       "     number := number + 1;"
       "     candidate := proposed_name || suffix || separator || number::text;"
       "   END LOOP;"
       "   RETURN candidate;"
       " END;"
       "$$ LANGUAGE plpgsql;");

  sql ("CREATE OR REPLACE FUNCTION create_index (schema_name text,"
       "                                         index_name text,"
       "                                         table_name text,"
       "                                         columns text)"
       " RETURNS void AS $$"
       " BEGIN"
       "   IF (SELECT count(*) = 0 FROM pg_indexes"
       "       WHERE schemaname = lower (schema_name)"
       "       AND tablename = lower (table_name)"
       "       AND indexname = lower (index_name))"
       "   THEN"
       "     EXECUTE 'CREATE INDEX ' || quote_ident(index_name)"
       "             || ' ON ' || quote_ident_split(table_name)"
       "             || ' (' || quote_ident_list(columns) || ');';"
       "   END IF;"
       " END;"
       "$$ LANGUAGE plpgsql;");

  sql ("CREATE OR REPLACE FUNCTION create_index (index_name text,"
       "                                         table_name text,"
       "                                         columns text)"
       " RETURNS void AS $$"
       " BEGIN"
       "   PERFORM create_index ('public', index_name, table_name, columns);"
       " END;"
       "$$ LANGUAGE plpgsql;");

  sql ("CREATE OR REPLACE FUNCTION user_has_super_on_resource (arg_type text, arg_id integer)"
       " RETURNS boolean AS $$"
       /* Test whether a user has super permissions on a resource.
        *
        * This must match user_has_super_on_resource in manage_acl.c. */
       " DECLARE"
       "   owns boolean;"
       " BEGIN"
       "   EXECUTE"
       "   'SELECT"
       "    EXISTS (SELECT * FROM permissions"
       "            WHERE name = ''Super''"
       /*                Super on everyone. */
       "            AND ((resource = 0)"
       /*                Super on other_user. */
       "                 OR ((resource_type = ''user'')"
       "                     AND (resource = (SELECT '"
       "                                      || quote_ident_split($1 || 's')"
       "                                      || '.owner'"
       "                                      || ' FROM '"
       "                                      || quote_ident_split($1 || 's')"
       "                                      || ' WHERE id = $2)))"
       /*                Super on other_user's role. */
       "                 OR ((resource_type = ''role'')"
       "                     AND (resource"
       "                          IN (SELECT DISTINCT role"
       "                              FROM role_users"
       "                              WHERE \"user\""
       "                                    = (SELECT '"
       "                                       || quote_ident_split($1 || 's')"
       "                                       || '.owner'"
       "                                       || ' FROM '"
       "                                       || quote_ident_split($1 || 's')"
       "                                       || ' WHERE id = $2))))"
       /*                Super on other_user's group. */
       "                 OR ((resource_type = ''group'')"
       "                     AND (resource"
       "                          IN (SELECT DISTINCT \"group\""
       "                              FROM group_users"
       "                              WHERE \"user\""
       "                                    = (SELECT '"
       "                                       || quote_ident_split($1 || 's')"
       "                                       || '.owner'"
       "                                       || ' FROM '"
       "                                       || quote_ident_split($1 || 's')"
       "                                       || ' WHERE id = $2)))))"
       "            AND subject_location = " G_STRINGIFY (LOCATION_TABLE)
       "            AND ((subject_type = ''user''"
       "                  AND subject = gvmd_user ())"
       "                 OR (subject_type = ''group''"
       "                     AND subject"
       "                         IN (SELECT DISTINCT \"group\""
       "                             FROM group_users"
       "                             WHERE \"user\" = gvmd_user ()))"
       "                 OR (subject_type = ''role''"
       "                     AND subject"
       "                         IN (SELECT DISTINCT role"
       "                             FROM role_users"
       "                             WHERE \"user\" = gvmd_user ()))))'"
       "   USING arg_type, arg_id"
       "   INTO owns;"
       "   RETURN owns;"
       " END;"
       "$$ LANGUAGE plpgsql;");

  sql ("CREATE OR REPLACE FUNCTION user_owns (arg_type text, arg_id integer)"
       " RETURNS boolean AS $$"
       /* Test whether a user owns a resource.
        *
        * This must match user_owns in manage_acl.c. */
       " DECLARE"
       "   owns boolean;"
       " BEGIN"
       "   CASE"
       "   WHEN arg_type = 'nvt'"
       "        OR arg_type = 'cve'"
       "        OR arg_type = 'cpe'"
       "        OR arg_type = 'ovaldef'"
       "        OR arg_type = 'cert_bund_adv'"
       "        OR arg_type = 'dfn_cert_adv'"
       "   THEN RETURN true;"
       "   WHEN user_has_super_on_resource (arg_type, arg_id)"
       "   THEN RETURN true;"
       "   WHEN arg_type = 'result'"
       "   THEN CASE"
       "        WHEN EXISTS (SELECT * FROM results, reports"
       "                     WHERE results.id = arg_id"
       "                     AND results.report = reports.id"
       "                     AND ((reports.owner IS NULL)"
       "                          OR (reports.owner = gvmd_user ())))"
       "        THEN RETURN true;"
       "        ELSE RETURN false;"
       "        END CASE;"
       "   WHEN arg_type = 'task'"
       "   THEN CASE"
       "        WHEN EXISTS (SELECT * FROM tasks"
       "                     WHERE id = arg_id"
       "                     AND hidden < 2"
       "                     AND ((owner IS NULL)"
       "                          OR (owner = gvmd_user ())))"
       "        THEN RETURN true;"
       "        ELSE RETURN false;"
       "        END CASE;"
       "   ELSE EXECUTE"
       "        'SELECT"
       "         EXISTS (SELECT *"
       "                 FROM ' || quote_ident_split ($1 || 's') || '"
       "                 WHERE id = $2"
       "                 AND ((owner IS NULL)"
       "                      OR (owner = gvmd_user ())))'"
       "        USING arg_type, arg_id"
       "        INTO owns;"
       "        RETURN owns;"
       "   END CASE;"
       " END;"
       "$$ LANGUAGE plpgsql;");

  sql ("CREATE OR REPLACE FUNCTION user_has_access_uuid (arg_type text,"
       "                                                 arg_uuid text,"
       "                                                 arg_permission text,"
       "                                                 arg_trash integer)"
       " RETURNS boolean AS $$"
       " DECLARE"
       "  resource bigint;"
       "  task_uuid text;"
       "  is_get boolean;"
       "  user_id bigint;"
       "  ret boolean;"
       " BEGIN"
       "  EXECUTE"
       "    'SELECT id FROM ' || quote_ident_split($1 || 's') || '"
       "     WHERE uuid = $2'"
       "    USING arg_type, arg_uuid"
       "    INTO resource;"
       "  ret = user_owns (arg_type, resource::integer);"
       "  IF (ret)"
       "  THEN"
       "    RETURN ret;"
       "  END IF;"
       "  CASE"
       "  WHEN arg_type = 'result'"
       "  THEN"
       "    task_uuid = (SELECT uuid FROM tasks"
       "                WHERE id = (SELECT task FROM results"
       "                             WHERE uuid = arg_uuid));"
       "  WHEN arg_type = 'report'"
       "  THEN"
       "    task_uuid = (SELECT uuid FROM tasks"
       "                WHERE id = (SELECT task FROM reports"
       "                             WHERE uuid = arg_uuid));"
       "  ELSE"
       "    task_uuid = null;"
       "  END CASE;"
       "  is_get = substr (arg_permission, 0, 4) = 'get';"
       "  user_id = gvmd_user ();"
       "  ret = (SELECT count(*) FROM permissions"
       "          WHERE resource_uuid = coalesce (task_uuid, arg_uuid)"
       "            AND subject_location = " G_STRINGIFY (LOCATION_TABLE)
       "            AND ((subject_type = 'user'"
       "                  AND subject = user_id)"
       "                 OR (subject_type = 'group'"
       "                     AND subject"
       "                         IN (SELECT DISTINCT \"group\""
       "                             FROM group_users"
       "                             WHERE \"user\" = user_id))"
       "                 OR (subject_type = 'role'"
       "                     AND subject"
       "                         IN (SELECT DISTINCT role"
       "                             FROM role_users"
       "                             WHERE \"user\" = user_id)))"
       "            AND (is_get OR name = arg_permission)) > 0;"
       "  RETURN ret;"
       " END;"
       "$$ LANGUAGE plpgsql"
       " STABLE COST 1000;");

  /* Functions in SQL. */

  if (sql_int ("SELECT (EXISTS (SELECT * FROM information_schema.tables"
               "                WHERE table_catalog = '%s'"
               "                AND table_schema = 'public'"
               "                AND table_name = 'nvts')"
               "        AND EXISTS (SELECT * FROM information_schema.tables"
               "                    WHERE table_catalog = '%s'"
               "                    AND table_schema = 'public'"
               "                    AND table_name = 'nvt_preferences'))"
               " ::integer;",
               sql_database (),
               sql_database ()))
    {
      char *quoted_collation;
      if (get_vt_verification_collation ())
        {
          gchar *string_quoted_collation;
          string_quoted_collation
            = sql_quote (get_vt_verification_collation ());
          quoted_collation = sql_string ("SELECT quote_ident('%s')",
                                         string_quoted_collation);
          g_free (string_quoted_collation);
        }
      else
        {
          char *encoding;
          encoding = sql_string ("SHOW server_encoding;");

          if (g_str_match_string ("UTF-8", encoding, 0)
              || g_str_match_string ("UTF8", encoding, 0))
            quoted_collation = strdup ("ucs_basic");
          else
            // quote C collation because this seems to be required
            // without quoting it an error is raised
            // other collations don't need quoting
            quoted_collation = strdup ("\"C\"");

          free (encoding);
        }

      g_debug ("Using vt verification collation %s", quoted_collation);

      sql ("CREATE OR REPLACE FUNCTION vts_verification_str ()"
           " RETURNS text AS $$"
           " WITH pref_str AS ("
           "   SELECT name,"
           "          substring(name, '^(.*?):') AS oid,"
           "          substring (name, '^.*?:([^:]+):') AS pref_id,"
           "          (substring (name, '^.*?:([^:]+):')"
           "           || substring (name,"
           "                         '^[^:]*:[^:]*:[^:]*:(.*)')"
           "           || value) AS pref"
           "   FROM nvt_preferences"
           "  ),"
           "  nvt_str AS ("
           "   SELECT (SELECT nvts.oid"
           "             || max(modification_time)"
           "             || coalesce (string_agg"
           "                            (pref_str.pref, ''"
           "                             ORDER BY (pref_id"
           "                                       COLLATE %s)),"
           "                          ''))"
           "          AS vt_string"
           "   FROM nvts"
           "   LEFT JOIN pref_str ON nvts.oid = pref_str.oid"
           "   GROUP BY nvts.oid"
           "   ORDER BY (nvts.oid COLLATE %s) ASC"
           "  )"
           " SELECT coalesce (string_agg (nvt_str.vt_string, ''), '')"
           "   FROM nvt_str"
           "$$ LANGUAGE SQL"
           " STABLE;",
           quoted_collation,
           quoted_collation);

      g_free (quoted_collation);
    }

  sql ("CREATE OR REPLACE FUNCTION t () RETURNS boolean AS $$"
       "  SELECT true;"
       "$$ LANGUAGE SQL"
       " IMMUTABLE;");

  sql ("CREATE OR REPLACE FUNCTION m_now () RETURNS integer AS $$"
       "  SELECT extract (epoch FROM now ())::integer;"
       "$$ LANGUAGE SQL"
       " STABLE;");

  sql ("CREATE OR REPLACE FUNCTION gvmd_user ()"
       " RETURNS integer AS $$"
       "  SELECT current_setting ('gvmd.user.id')::integer;"
       "$$ LANGUAGE SQL;");

  sql ("CREATE OR REPLACE FUNCTION common_cve (text, text)"
       " RETURNS boolean AS $$"
       /* Check if two CVE lists contain a common CVE. */
       "  SELECT EXISTS (SELECT trim (unnest (string_to_array ($1, ',')))"
       "                 INTERSECT"
       "                 SELECT trim (unnest (string_to_array ($2, ','))));"
       "$$ LANGUAGE SQL;");

  if (sql_int ("SELECT EXISTS (SELECT * FROM information_schema.tables"
               "               WHERE table_catalog = '%s'"
               "               AND table_schema = 'scap'"
               "               AND table_name = 'cpes')"
               " ::integer;",
               sql_database ()))
    {
      sql ("CREATE OR REPLACE FUNCTION cpe_title (text)"
           " RETURNS text AS $$"
           "  SELECT title FROM scap.cpes WHERE uuid = $1;"
           "$$ LANGUAGE SQL;");
    }
  else
    {
      sql ("CREATE OR REPLACE FUNCTION cpe_title (text)"
           " RETURNS text AS $$"
           "  SELECT null::text;"
           "$$ LANGUAGE SQL;");
    }

  sql ("CREATE OR REPLACE FUNCTION make_uuid () RETURNS text AS $$"
       "  SELECT uuid_generate_v4 ()::text AS result;"
       "$$ LANGUAGE SQL;");

  if (sql_int ("SELECT EXISTS (SELECT * FROM information_schema.tables"
               "               WHERE table_catalog = '%s'"
               "               AND table_schema = 'public'"
               "               AND table_name = 'meta')"
               " ::integer;",
               sql_database ()))
    {
      sql ("CREATE OR REPLACE FUNCTION report_active (integer)"
           " RETURNS boolean AS $$"
           /* Check whether a report is active. */
           "  SELECT CASE"
           "         WHEN (SELECT scan_run_status FROM reports"
           "               WHERE reports.id = $1)"
           "               IN (SELECT unnest (ARRAY [%i, %i, %i, %i, %i,"
           "                                         %i, %i, %i]))"
           "         THEN true"
           "         ELSE false"
           "         END;"
           "$$ LANGUAGE SQL;",
           TASK_STATUS_REQUESTED,
           TASK_STATUS_RUNNING,
           TASK_STATUS_DELETE_REQUESTED,
           TASK_STATUS_DELETE_ULTIMATE_REQUESTED,
           TASK_STATUS_STOP_REQUESTED,
           TASK_STATUS_STOPPED,
           TASK_STATUS_INTERRUPTED,
           TASK_STATUS_QUEUED);

      sql ("CREATE OR REPLACE FUNCTION report_progress (integer)"
           " RETURNS integer AS $$"
           /* Get the progress of a report. */
           "  SELECT CASE"
           "         WHEN $1 = 0"
           "         THEN -1"
           "         WHEN report_active ($1)"
           "         THEN (SELECT slave_progress FROM reports WHERE id = $1)"
           "         ELSE -1"
           "         END;"
           "$$ LANGUAGE SQL;");

      sql ("CREATE OR REPLACE FUNCTION dynamic_severity ()"
           " RETURNS boolean AS $$"
           /* Get Dynamic Severity user setting. */
           "  SELECT CAST (value AS integer) = 1 FROM settings"
           "  WHERE name = 'Dynamic Severity'"
           "  AND ((owner IS NULL)"
           "       OR (owner = gvmd_user ()))"
           "  ORDER BY coalesce (owner, 0) DESC LIMIT 1;"
           "$$ LANGUAGE SQL;");

      sql ("CREATE OR REPLACE FUNCTION current_severity (real, text)"
           " RETURNS double precision AS $$"
           "  SELECT coalesce ((CASE WHEN $1 > " G_STRINGIFY (SEVERITY_LOG)
           "                    THEN (SELECT CAST (cvss_base"
           "                                       AS double precision)"
           "                          FROM nvts"
           "                          WHERE nvts.oid = $2)"
           "                    ELSE $1"
           "                    END),"
           "                   $1);"
           "$$ LANGUAGE SQL;");

      /* result_nvt column (in OVERRIDES_SQL) was added in version 189 */
      if (current_db_version >= 189)
        sql ("CREATE OR REPLACE FUNCTION report_severity (report integer,"
             "                                            overrides integer,"
             "                                            min_qod integer)"
             " RETURNS double precision AS $$"
             /* Calculate the severity of a report. */
             "  WITH max_severity"
             "       AS (SELECT max(severity) AS max"
             "           FROM report_counts"
             "           WHERE report = $1"
             "           AND \"user\" = gvmd_user ()"
             "           AND override = $2"
             "           AND min_qod = $3"
             "           AND (end_time = 0 or end_time >= m_now ()))"
             "  SELECT CASE"
             "         WHEN EXISTS (SELECT max FROM max_severity)"
             "              AND (SELECT max FROM max_severity) IS NOT NULL"
             "         THEN (SELECT max::double precision FROM max_severity)"
             "         WHEN dynamic_severity () AND $2::boolean"
             /*        Dynamic severity, overrides on. */
             "         THEN (SELECT max"
             "                       (" OVERRIDES_SQL
                                         ("current_severity (results.severity,"
                                          "                  results.nvt)") ")"
             "               FROM results"
             "               WHERE results.report = $1"
             "                 AND results.qod >= $3)"
             "         WHEN dynamic_severity ()"
             /*        Dynamic severity, overrides off. */
             "         THEN (SELECT max (CASE"
             "                           WHEN results.type IS NULL"
             "                           THEN 0::real"
             "                           ELSE current_severity"
             "                                 (results.severity, results.nvt)"
             "                           END)"
             "               FROM results"
             "               WHERE results.report = $1"
             "                 AND results.qod >= $3)"
             "         WHEN $2::boolean"
             /*        Overrides on. */
             "         THEN (SELECT max (" OVERRIDES_SQL ("results.severity") ")"
             "               FROM results"
             "               WHERE results.report = $1"
             "                 AND results.qod >= $3)"
             /*        Overrides off. */
             "         ELSE (SELECT max (CASE"
             "                           WHEN results.type IS NULL"
             "                           THEN 0::real"
             "                           ELSE results.severity"
             "                           END)"
             "               FROM results"
             "               WHERE results.report = $1"
             "                 AND results.qod >= $3)"
             "         END;"
             "$$ LANGUAGE SQL;");

      sql ("CREATE OR REPLACE FUNCTION report_host_count (report integer)"
            " RETURNS bigint AS $$"
            "  SELECT count (DISTINCT id) FROM report_hosts"
            "  WHERE report_hosts.report = $1;"
            "$$ LANGUAGE SQL;");

      sql ("CREATE OR REPLACE FUNCTION report_result_host_count (report integer,"
            "                                                    min_qod integer)"
            " RETURNS bigint AS $$"
            "  SELECT count (DISTINCT id) FROM report_hosts"
            "  WHERE report_hosts.report = $1"
            "    AND EXISTS (SELECT * FROM results"
            "                WHERE results.host = report_hosts.host"
            "                  AND results.qod >= $2)"
            "$$ LANGUAGE SQL;");

      sql ("CREATE OR REPLACE FUNCTION severity_class ()"
           " RETURNS text AS $$"
           /* Get the user's severity class setting. */
           "  SELECT value FROM settings"
           "  WHERE name = 'Severity Class'"
           "  AND ((owner IS NULL)"
           "       OR (owner = gvmd_user ()))"
           "  ORDER BY coalesce (owner, 0) DESC LIMIT 1;"
           "$$ LANGUAGE SQL;");

      /* result_nvt column (in OVERRIDES_SQL) was added in version 189 */
      if (current_db_version >= 189)
        sql ("CREATE OR REPLACE FUNCTION"
             " report_severity_count (report integer, overrides integer,"
             "                        min_qod integer, level text)"
             " RETURNS bigint AS $$"
             /* Calculate the severity of a report. */
             "  WITH severity_count"
             "       AS (SELECT sum (count) AS total"
             "           FROM report_counts"
             "           WHERE report = $1"
             "           AND \"user\" = gvmd_user ()"
             "           AND override = $2"
             "           AND min_qod = $3"
             "           AND (end_time = 0"
             "                or end_time >= m_now ())"
             "           AND (severity"
             "                BETWEEN level_min_severity"
             "                         ($4, severity_class ())"
             "                        AND level_max_severity"
             "                             ($4, severity_class ())))"
             "  SELECT CASE"
             "         WHEN EXISTS (SELECT total FROM severity_count)"
             "              AND (SELECT total FROM severity_count) IS NOT NULL"
             "         THEN (SELECT total FROM severity_count)"
             "         WHEN dynamic_severity () AND $2::boolean"
             /*        Dynamic severity, overrides on. */
             "         THEN (SELECT count (*)"
             "               FROM results"
             "               WHERE results.report = $1"
             "               AND results.qod >= $3"
             "               AND (" OVERRIDES_SQL
                                     ("current_severity (results.severity,"
                                      "                  results.nvt)")
             "                    BETWEEN level_min_severity"
             "                             ($4, severity_class ())"
             "                            AND level_max_severity"
             "                                 ($4, severity_class ())))"
             "         WHEN dynamic_severity ()"
             /*        Dynamic severity, overrides off. */
             "         THEN (SELECT count (*)"
             "               FROM results"
             "               WHERE results.report = $1"
             "               AND results.qod >= $3"
             "               AND ((CASE"
             "                     WHEN results.type IS NULL"
             "                     THEN 0::real"
             "                     ELSE current_severity (results.severity,"
             "                                            results.nvt)"
             "                     END)"
             "                    BETWEEN level_min_severity ($4, severity_class ())"
             "                            AND level_max_severity"
             "                                 ($4, severity_class ())))"
             "         WHEN $2::boolean"
             /*        Overrides on. */
             "         THEN (SELECT count (*)"
             "               FROM results"
             "               WHERE results.report = $1"
             "               AND results.qod >= $3"
             "               AND (" OVERRIDES_SQL ("results.severity")
             "                    BETWEEN level_min_severity ($4, severity_class ())"
             "                            AND level_max_severity"
             "                                 ($4, severity_class ())))"
             /*        Overrides off. */
             "         ELSE (SELECT count (*)"
             "               FROM results"
             "               WHERE results.report = $1"
             "               AND results.qod >= $3"
             "               AND ((CASE"
             "                     WHEN results.type IS NULL"
             "                     THEN 0::real"
             "                     ELSE results.severity"
             "                     END)"
             "                    BETWEEN level_min_severity ($4, severity_class ())"
             "                            AND level_max_severity"
             "                                 ($4, severity_class ())))"
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

      /* result_nvt column (in OVERRIDES_SQL) was added in version 189. */
      if (current_db_version >= 189)
        sql ("CREATE OR REPLACE FUNCTION task_severity (integer,"  // task
             "                                          integer,"  // overrides
             "                                          integer)"  // min_qod
             " RETURNS double precision AS $$"
             /* Calculate the severity of a task. */
             "  SELECT CASE"
             "         WHEN (SELECT target = 0"
             "               FROM tasks WHERE id = $1)"
             "         THEN CAST (NULL AS double precision)"
             "         ELSE"
             "         (SELECT report_severity ((SELECT id FROM reports"
             "                                   WHERE task = $1"
             "                                   AND scan_run_status = %u"
             "                                   ORDER BY date DESC"
             "                                   LIMIT 1 OFFSET 0), $2, $3))"
             "         END;"
             "$$ LANGUAGE SQL;",
             TASK_STATUS_DONE);

      sql ("CREATE OR REPLACE FUNCTION task_trend (integer, integer, integer)"
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
           "   WHEN gvmd_user () = 0"
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
           "   severity_a := report_severity (last_report, $2, $3);"
           "   severity_b := report_severity (second_last_report, $2, $3);"
           "   IF severity_a > severity_b THEN"
           "     RETURN 'up'::text;"
           "   ELSIF severity_b > severity_a THEN"
           "     RETURN 'down'::text;"
           "   END IF;"
           /*  Calculate trend. */
           "   high_a := report_severity_count (last_report, $2, $3,"
           "                                    'high');"
           "   high_b := report_severity_count (second_last_report, $2, $3,"
           "                                    'high');"
           "   medium_a := report_severity_count (last_report, $2, $3,"
           "                                      'medium');"
           "   medium_b := report_severity_count (second_last_report, $2, $3,"
           "                                      'medium');"
           "   low_a := report_severity_count (last_report, $2, $3,"
           "                                   'low');"
           "   low_b := report_severity_count (second_last_report, $2, $3,"
           "                                   'low');"
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
    }

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
       "         WHEN $1 = %i OR $1 = %i"
       "         THEN 'Stop Requested'"
       "         WHEN $1 = %i"
       "         THEN 'Stopped'"
       "         WHEN $1 = %i"
       "         THEN 'Queued'"
       "         ELSE 'Interrupted'"
       "         END;"
       "$$ LANGUAGE SQL"
       " IMMUTABLE;",
       TASK_STATUS_DELETE_REQUESTED,
       TASK_STATUS_DELETE_WAITING,
       TASK_STATUS_DELETE_ULTIMATE_REQUESTED,
       TASK_STATUS_DELETE_ULTIMATE_WAITING,
       TASK_STATUS_DONE,
       TASK_STATUS_NEW,
       TASK_STATUS_REQUESTED,
       TASK_STATUS_RUNNING,
       TASK_STATUS_STOP_REQUESTED,
       TASK_STATUS_STOP_WAITING,
       TASK_STATUS_STOPPED,
       TASK_STATUS_QUEUED);

  if (sql_int ("SELECT EXISTS (SELECT * FROM information_schema.tables"
               "               WHERE table_catalog = '%s'"
               "               AND table_schema = 'public'"
               "               AND table_name = 'permissions')"
               " ::integer;",
               sql_database ()))
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
       "$$ LANGUAGE SQL"
       " IMMUTABLE;");

  sql ("DROP AGGREGATE IF EXISTS group_concat (text, text);");

  sql ("CREATE AGGREGATE group_concat (text, text)"
       " (sfunc       = group_concat_pair,"
       "  stype       = text,"
       "  initcond    = '');");

  if (sql_int ("SELECT EXISTS (SELECT * FROM information_schema.tables"
               "               WHERE table_catalog = '%s'"
               "               AND table_schema = 'public'"
               "               AND table_name = 'meta')"
               " ::integer;",
               sql_database ()))
    {
      sql ("CREATE OR REPLACE FUNCTION severity_in_level (double precision,"
           "                                              text)"
           " RETURNS boolean AS $$"
           "  (SELECT CASE lower ($2)"
           "         WHEN 'high'"
           "         THEN $1 >= 7"
           "              AND $1 <= 10"
           "         WHEN 'medium'"
           "         THEN $1 >= 4"
           "              AND $1 < 7"
           "         WHEN 'low'"
           "         THEN $1 > 0"
           "              AND $1 < 4"
           "         WHEN 'none'"
           "         THEN $1 = 0"
           "         WHEN 'log'"
           "         THEN $1 = 0"
           "         WHEN 'false'"
           "         THEN $1 = -1"
           "         ELSE 0::boolean"
           "         END);"
           "$$ LANGUAGE SQL"
           " STABLE;");

      sql ("CREATE OR REPLACE FUNCTION severity_in_levels (double precision,"
           "                                               VARIADIC text[])"
           " RETURNS boolean AS $$"
           "  (SELECT true = ANY (SELECT severity_in_level ($1, severity)"
           "                      FROM unnest ($2) AS severity));"
           "$$ LANGUAGE SQL"
           " STABLE;");

      sql ("CREATE OR REPLACE FUNCTION severity_to_level (text, integer)"
           " RETURNS text AS $$"
           "  SELECT CASE"
           "         WHEN $1::double precision = " G_STRINGIFY (SEVERITY_LOG)
           "         THEN 'Log'"
           "         WHEN $1::double precision = " G_STRINGIFY (SEVERITY_FP)
           "         THEN 'False Positive'"
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
           "$$ LANGUAGE SQL"
           " IMMUTABLE;");

      sql ("CREATE OR REPLACE FUNCTION severity_to_level (double precision,"
           "                                              integer)"
           " RETURNS text AS $$"
           "  SELECT CASE"
           "         WHEN $1 = " G_STRINGIFY (SEVERITY_LOG)
           "         THEN 'Log'"
           "         WHEN $1 = " G_STRINGIFY (SEVERITY_FP)
           "         THEN 'False Positive'"
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
           "$$ LANGUAGE SQL"
           " IMMUTABLE;");

      /* result_nvt column (in task_severity) was added in version 189. */
      if (current_db_version >= 189)
        sql ("CREATE OR REPLACE FUNCTION task_threat_level (integer, integer,"
             "                                              integer)"
             " RETURNS text AS $$"
             /* Calculate the threat level of a task. */
             "  SELECT severity_to_level (task_severity ($1, $2, $3), 0);"
             "$$ LANGUAGE SQL"
             " STABLE;");
    }

  if (sql_int ("SELECT (EXISTS (SELECT * FROM information_schema.tables"
               "               WHERE table_catalog = '%s'"
               "               AND table_schema = 'public'"
               "               AND table_name = 'credentials_data')"
               "   AND EXISTS (SELECT * FROM information_schema.tables"
               "               WHERE table_catalog = '%s'"
               "               AND table_schema = 'public'"
               "               AND table_name = 'credentials_trash_data'))"
               " ::integer;",
               sql_database (), sql_database ()))
    {
      sql ("CREATE OR REPLACE FUNCTION credential_value (integer, integer, text)"
           " RETURNS text AS $$"
           "  SELECT CASE"
           "         WHEN $2 != 0"
           "         THEN"
           "           (SELECT value FROM credentials_trash_data"
           "            WHERE credential = $1 AND type = $3)"
           "         ELSE"
           "           (SELECT value FROM credentials_data"
           "            WHERE credential = $1 AND type = $3)"
           "         END;"
           "$$ LANGUAGE SQL;");
    }

  if (sql_int ("SELECT (EXISTS (SELECT * FROM information_schema.tables"
               "               WHERE table_catalog = '%s'"
               "               AND table_schema = 'public'"
               "               AND table_name = 'targets_login_data')"
               "   AND EXISTS (SELECT * FROM information_schema.tables"
               "               WHERE table_catalog = '%s'"
               "               AND table_schema = 'public'"
               "               AND table_name = 'targets_trash_login_data'))"
               " ::integer;",
               sql_database (), sql_database ()))
    {
      sql ("CREATE OR REPLACE FUNCTION target_credential (integer, integer, text)"
          " RETURNS integer AS $$"
          "  SELECT CASE"
          "         WHEN $2 != 0"
          "         THEN"
          "           (SELECT credential FROM targets_trash_login_data"
          "            WHERE target = $1 AND type = $3)"
          "         ELSE"
          "           (SELECT credential FROM targets_login_data"
          "             WHERE target = $1 AND type = $3)"
          "         END;"
          "$$ LANGUAGE SQL;");

      sql ("CREATE OR REPLACE FUNCTION trash_target_credential_location (integer, text)"
          " RETURNS integer AS $$"
          "  SELECT credential_location FROM targets_trash_login_data"
          "   WHERE target = $1 AND type = $2"
          "$$ LANGUAGE SQL;");

      sql ("CREATE OR REPLACE FUNCTION target_login_port (integer, integer, text)"
          " RETURNS integer AS $$"
          "  SELECT CASE"
          "         WHEN $2 != 0"
          "         THEN"
          "           (SELECT port FROM targets_trash_login_data"
          "            WHERE target = $1 AND type = $3)"
          "         ELSE"
          "           (SELECT port FROM targets_login_data"
          "            WHERE target = $1 AND type = $3)"
          "         END;"
          "$$ LANGUAGE SQL;");
    }

  sql ("CREATE OR REPLACE FUNCTION lower (integer)"
       " RETURNS integer AS $$"
       "  SELECT $1;"
       "$$ LANGUAGE SQL"
       " IMMUTABLE;");

  if (sql_int ("SELECT (EXISTS (SELECT * FROM information_schema.tables"
               "               WHERE table_catalog = '%s'"
               "               AND table_schema = 'public'"
               "               AND table_name = 'permissions_get_tasks'))"
               " ::integer;",
               sql_database ()))
    {
      sql ("DROP FUNCTION IF EXISTS"
           " vuln_results (text, bigint, bigint, text, integer);");
      sql ("CREATE OR REPLACE FUNCTION"
           " vuln_results (text, bigint, bigint, text)"
           " RETURNS bigint AS $$"
           " SELECT count(*) FROM results"
           " WHERE results.nvt = $1"
           "   AND ($2 IS NULL OR results.task = $2)"
           "   AND ($3 IS NULL OR results.report = $3)"
           "   AND ($4 IS NULL OR results.host = $4)"
           "   AND (results.severity != " G_STRINGIFY (SEVERITY_ERROR) ")"
           "   AND (SELECT has_permission FROM permissions_get_tasks"
           "         WHERE \"user\" = gvmd_user ()"
           "           AND task = results.task)"
           "$$ LANGUAGE SQL;");

      sql ("DROP FUNCTION IF EXISTS"
           " vuln_results_exist (text, bigint, bigint, text, integer);");
      sql ("CREATE OR REPLACE FUNCTION"
           " vuln_results_exist (text, bigint, bigint, text)"
           " RETURNS boolean AS $$"
           " SELECT EXISTS"
           "  (SELECT * FROM results"
           "   WHERE results.nvt = $1"
           "   AND ($2 IS NULL OR results.task = $2)"
           "   AND ($3 IS NULL OR results.report = $3)"
           "   AND ($4 IS NULL OR results.host = $4)"
           "   AND (results.severity != " G_STRINGIFY (SEVERITY_ERROR) ")"
           "   AND (SELECT has_permission FROM permissions_get_tasks"
           "        WHERE \"user\" = gvmd_user ()"
           "        AND task = results.task))"
           "$$ LANGUAGE SQL;");
    }

  return 0;
}


/* Creation. */

/**
 * @brief Create result indexes.
 */
void
manage_create_result_indexes ()
{
  sql ("SELECT create_index ('results_by_host_and_qod', 'results',"
       "                     'host, qod');");
  sql ("SELECT create_index ('results_by_report', 'results', 'report');");
  sql ("SELECT create_index ('results_by_nvt', 'results', 'nvt');");
  sql ("SELECT create_index ('results_by_task', 'results', 'task');");
  sql ("SELECT create_index ('results_by_date', 'results', 'date');");
}

/**
 * @brief Create or replace the vulns view.
 */
void
create_view_vulns ()
{
  sql ("DROP VIEW IF EXISTS vulns;");

  if (sql_int ("SELECT EXISTS (SELECT * FROM information_schema.tables"
               "               WHERE table_catalog = '%s'"
               "               AND table_schema = 'scap'"
               "               AND table_name = 'ovaldefs')"
               " ::integer;",
               sql_database ()))
    sql ("CREATE OR REPLACE VIEW vulns AS"
         " WITH used_nvts"
         " AS (SELECT DISTINCT nvt FROM results"
         "     WHERE (results.severity != " G_STRINGIFY (SEVERITY_ERROR) "))"
         " SELECT id, uuid, name, creation_time, modification_time,"
         "        cvss_base::double precision AS severity, qod, 'nvt' AS type"
         " FROM nvts"
         " WHERE uuid in (SELECT * FROM used_nvts)"
         " UNION SELECT id, uuid, name, creation_time, modification_time,"
         "       severity, "
         G_STRINGIFY (QOD_DEFAULT) " AS qod,"
         "       'cve' AS type"
         " FROM cves"
         " WHERE uuid in (SELECT * FROM used_nvts)"
         " UNION SELECT id, uuid, name, creation_time, modification_time,"
         "       severity, "
         G_STRINGIFY (QOD_DEFAULT) " AS qod,"
         "       'ovaldef' AS type"
         " FROM ovaldefs"
         " WHERE uuid in (SELECT * FROM used_nvts)");
  else
    sql ("CREATE OR REPLACE VIEW vulns AS"
         " WITH used_nvts"
         " AS (SELECT DISTINCT nvt FROM results"
         "     WHERE (results.severity != " G_STRINGIFY (SEVERITY_ERROR) "))"
         " SELECT id, uuid, name, creation_time, modification_time,"
         "        cvss_base::double precision AS severity, qod, 'nvt' AS type"
         " FROM nvts"
         " WHERE uuid in (SELECT * FROM used_nvts)");
}

#undef VULNS_RESULTS_WHERE

/**
 * @brief Create all tables.
 */
void
create_tables ()
{
  gchar *owned_clause;

  sql ("CREATE TABLE IF NOT EXISTS meta"
       " (id SERIAL PRIMARY KEY,"
       "  name text UNIQUE NOT NULL,"
       "  value text);");

  sql ("CREATE TABLE IF NOT EXISTS users"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  name text UNIQUE NOT NULL,"
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

  sql ("CREATE TABLE IF NOT EXISTS auth_cache"
       " (id SERIAL PRIMARY KEY,"
       "  username text NOT NULL,"
       "  hash text,"
       "  method integer,"
       "  creation_time integer);");

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
       "  active integer,"
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
       "  active integer,"
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

  sql ("CREATE TABLE IF NOT EXISTS credentials"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  name text NOT NULL,"
       "  comment text,"
       "  creation_time integer,"
       "  modification_time integer,"
       "  type text,"
       "  allow_insecure integer);");

  sql ("CREATE TABLE IF NOT EXISTS credentials_trash"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  name text NOT NULL,"
       "  comment text,"
       "  creation_time integer,"
       "  modification_time integer,"
       "  type text,"
       "  allow_insecure integer);");

  sql ("CREATE TABLE IF NOT EXISTS credentials_data"
       " (id SERIAL PRIMARY KEY,"
       "  credential INTEGER REFERENCES credentials (id) ON DELETE RESTRICT,"
       "  type TEXT,"
       "  value TEXT);");

  sql ("CREATE TABLE IF NOT EXISTS credentials_trash_data"
       " (id SERIAL PRIMARY KEY,"
       "  credential INTEGER REFERENCES credentials_trash (id) ON DELETE RESTRICT,"
       "  type TEXT,"
       "  value TEXT);");

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

  sql ("CREATE TABLE IF NOT EXISTS hosts"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  name text NOT NULL,"
       "  comment text,"
       "  creation_time integer,"
       "  modification_time integer);");

  sql ("CREATE TABLE IF NOT EXISTS host_identifiers"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  host integer REFERENCES hosts (id) ON DELETE RESTRICT,"
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  name text NOT NULL,"
       "  comment text,"
       "  value text NOT NULL,"
       "  source_type text NOT NULL,"
       "  source_id text NOT NULL,"
       "  source_data text NOT NULL,"
       "  creation_time integer,"
       "  modification_time integer);");

  sql ("CREATE TABLE IF NOT EXISTS oss"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  name text NOT NULL,"
       "  comment text,"
       "  creation_time integer,"
       "  modification_time integer);");

  sql ("CREATE TABLE IF NOT EXISTS host_oss"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  host integer REFERENCES hosts (id) ON DELETE RESTRICT,"
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  name text NOT NULL,"
       "  comment text,"
       "  os integer REFERENCES oss (id) ON DELETE RESTRICT,"
       "  source_type text NOT NULL,"
       "  source_id text NOT NULL,"
       "  source_data text NOT NULL,"
       "  creation_time integer,"
       "  modification_time integer);");

  sql ("CREATE TABLE IF NOT EXISTS host_max_severities"
       " (id SERIAL PRIMARY KEY,"
       "  host integer REFERENCES hosts (id) ON DELETE RESTRICT,"
       "  severity real,"
       "  source_type text NOT NULL,"
       "  source_id text NOT NULL,"
       "  creation_time integer);");

  sql ("CREATE TABLE IF NOT EXISTS host_details"
       " (id SERIAL PRIMARY KEY,"
       "  host integer REFERENCES hosts (id) ON DELETE RESTRICT,"
       /* The report that the host detail came from. */
       "  source_type text NOT NULL,"
       "  source_id text NOT NULL,"
       /* The original source of the host detail, from the scanner. */
       "  detail_source_type text,"
       "  detail_source_name text,"
       "  detail_source_description text,"
       "  name text,"
       "  value text);");

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
       "  role integer REFERENCES roles_trash (id) ON DELETE RESTRICT,"
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
       "  predefined integer,"
       "  creation_time integer,"
       "  modification_time integer);");

  sql ("CREATE TABLE IF NOT EXISTS port_lists_trash"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  name text NOT NULL,"
       "  comment text,"
       "  predefined integer,"
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
       "  port_list integer REFERENCES port_lists (id) ON DELETE RESTRICT,"
       "  alive_test integer,"
       "  creation_time integer,"
       "  modification_time integer,"
       "  allow_simultaneous_ips integer DEFAULT 1);");

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
       "  port_list integer," // REFERENCES port_lists (id) ON DELETE RESTRICT,"
       "  port_list_location integer,"
       "  alive_test integer,"
       "  creation_time integer,"
       "  modification_time integer,"
       "  allow_simultaneous_ips integer DEFAULT 1);");

  sql ("CREATE TABLE IF NOT EXISTS targets_login_data"
       " (id SERIAL PRIMARY KEY,"
       "  target INTEGER REFERENCES targets (id) ON DELETE RESTRICT,"
       "  type TEXT,"
       "  credential INTEGER REFERENCES credentials (id) ON DELETE RESTRICT,"
       "  port INTEGER);");

  sql ("CREATE TABLE IF NOT EXISTS targets_trash_login_data"
       " (id SERIAL PRIMARY KEY,"
       "  target INTEGER REFERENCES targets_trash (id) ON DELETE RESTRICT,"
       "  type TEXT,"
       "  credential INTEGER,"//REFERENCES credentials (id) ON DELETE RESTRICT,"
       "  port INTEGER,"
       "  credential_location INTEGER);");

  sql ("CREATE TABLE IF NOT EXISTS tickets"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  name text NOT NULL," /* NVT name.  Aka Vulnerability. */
       "  comment text,"
       "  nvt text,"
       "  task integer," // REFERENCES tasks (id) ON DELETE RESTRICT,"
       "  report integer," // REFERENCES reports (id) ON DELETE RESTRICT,"
       "  severity real,"
       "  host text,"
       "  location text,"
       "  solution_type text,"
       "  assigned_to integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  status integer,"
       "  open_time integer,"
       "  open_note text,"
       "  fixed_time integer,"
       "  fixed_note text,"
       "  fix_verified_time integer,"
       "  fix_verified_report integer," // REFERENCES reports (id) ON DELETE RESTRICT,"
       "  closed_time integer,"
       "  closed_note text,"
       "  creation_time integer,"
       "  modification_time integer);");

  sql ("CREATE TABLE IF NOT EXISTS ticket_results"
       " (id SERIAL PRIMARY KEY,"
       "  ticket integer REFERENCES tickets (id) ON DELETE RESTRICT,"
       "  result integer,"    // REFERENCES results (id) ON DELETE RESTRICT
       "  result_location integer,"
       "  result_uuid text,"
       "  report integer);"); // REFERENCES reports (id) ON DELETE RESTRICT

  sql ("CREATE TABLE IF NOT EXISTS tickets_trash"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  name text NOT NULL," /* NVT name.  Aka Vulnerability. */
       "  comment text,"
       "  nvt text,"
       "  task integer," // REFERENCES tasks (id) ON DELETE RESTRICT,"
       "  report integer," // REFERENCES reports (id) ON DELETE RESTRICT,"
       "  severity real,"
       "  host text,"
       "  location text,"
       "  solution_type text,"
       "  assigned_to integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  status integer,"
       "  open_time integer,"
       "  open_note text,"
       "  fixed_time integer,"
       "  fixed_note text,"
       "  fix_verified_time integer,"
       "  fix_verified_report integer," // REFERENCES reports (id) ON DELETE RESTRICT,"
       "  closed_time integer,"
       "  closed_note text,"
       "  creation_time integer,"
       "  modification_time integer);");

  sql ("CREATE TABLE IF NOT EXISTS ticket_results_trash"
       " (id SERIAL PRIMARY KEY,"
       "  ticket integer REFERENCES tickets_trash (id) ON DELETE RESTRICT,"
       "  result integer,"    // REFERENCES results_trash (id) ON DELETE RESTRICT
       "  result_location integer,"
       "  result_uuid text,"
       "  report integer);"); // REFERENCES reports_trash (id) ON DELETE RESTRICT

  sql ("CREATE TABLE IF NOT EXISTS tls_certificates"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  name text,"
       "  comment text,"
       "  creation_time bigint,"
       "  modification_time bigint,"
       "  certificate text,"
       "  subject_dn text,"
       "  issuer_dn text,"
       "  activation_time bigint,"
       "  expiration_time bigint,"
       "  md5_fingerprint text,"
       "  trust integer,"
       "  certificate_format text,"
       "  sha256_fingerprint text,"
       "  serial text);");

  sql ("CREATE TABLE IF NOT EXISTS tls_certificate_locations"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  host_ip text,"
       "  port text);");

  sql ("CREATE TABLE IF NOT EXISTS tls_certificate_origins"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  origin_type text,"
       "  origin_id text,"
       "  origin_data text);");

  sql ("CREATE TABLE IF NOT EXISTS tls_certificate_sources"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  tls_certificate integer REFERENCES tls_certificates (id),"
       "  location integer REFERENCES tls_certificate_locations (id),"
       "  origin integer REFERENCES tls_certificate_origins (id),"
       "  timestamp bigint,"
       "  tls_versions text);");

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
       "  credential integer REFERENCES credentials (id) ON DELETE RESTRICT,"
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
       "  scanner integer REFERENCES scanners (id) ON DELETE RESTRICT,"
       "  predefined integer,"
       "  creation_time integer,"
       "  modification_time integer,"
       "  usage_type text);");

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
       "  scanner integer," /* REFERENCES scanners (id) */
       "  predefined integer,"
       "  creation_time integer,"
       "  modification_time integer,"
       "  scanner_location integer,"
       "  usage_type text);");

  sql ("CREATE TABLE IF NOT EXISTS config_preferences"
       " (id SERIAL PRIMARY KEY,"
       "  config integer REFERENCES configs (id) ON DELETE RESTRICT,"
       "  type text,"
       "  name text,"
       "  value text,"
       "  default_value text,"
       "  hr_name text);");

  sql ("CREATE TABLE IF NOT EXISTS config_preferences_trash"
       " (id SERIAL PRIMARY KEY,"
       "  config integer REFERENCES configs_trash (id) ON DELETE RESTRICT,"
       "  type text,"
       "  name text,"
       "  value text,"
       "  default_value text,"
       "  hr_name text);");

  sql ("CREATE TABLE IF NOT EXISTS schedules"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  name text NOT NULL,"
       "  comment text,"
       "  first_time integer,"
       "  period integer,"
       "  period_months integer,"
       "  byday integer,"
       "  duration integer,"
       "  timezone text,"
       "  creation_time integer,"
       "  modification_time integer,"
       "  icalendar text);");

  sql ("CREATE TABLE IF NOT EXISTS schedules_trash"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  name text NOT NULL,"
       "  comment text,"
       "  first_time integer,"
       "  period integer,"
       "  period_months integer,"
       "  byday integer,"
       "  duration integer,"
       "  timezone text,"
       "  creation_time integer,"
       "  modification_time integer,"
       "  icalendar text);");

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
       "  credential integer,"
       "  credential_location integer,"
       "  creation_time integer,"
       "  modification_time integer);");

  sql ("CREATE TABLE IF NOT EXISTS tasks"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  name text,"
       "  hidden integer,"
       "  comment text,"
       "  run_status integer,"
       "  start_time integer,"
       "  end_time integer,"
       "  config integer," // REFERENCES configs (id) ON DELETE RESTRICT,"
       "  target integer," // REFERENCES targets (id) ON DELETE RESTRICT,"
       "  schedule integer," // REFERENCES schedules (id) ON DELETE RESTRICT,"
       "  schedule_next_time integer,"
       "  schedule_periods integer,"
       "  scanner integer," // REFERENCES scanner (id) ON DELETE RESTRICT,"
       "  config_location integer,"
       "  target_location integer,"
       "  schedule_location integer,"
       "  scanner_location integer,"
       "  upload_result_count integer,"
       "  hosts_ordering text,"
       "  alterable integer,"
       "  creation_time integer,"
       "  modification_time integer,"
       "  usage_type text);");

  sql ("CREATE TABLE IF NOT EXISTS task_files"
       " (id SERIAL PRIMARY KEY,"
       "  task integer REFERENCES tasks (id) ON DELETE RESTRICT,"
       "  name text,"
       "  content text);");

  sql ("CREATE TABLE IF NOT EXISTS task_alerts"
       " (id SERIAL PRIMARY KEY,"
       "  task integer REFERENCES tasks (id) ON DELETE RESTRICT,"
       "  alert integer," // REFERENCES alerts (id) ON DELETE RESTRICT,"
       "  alert_location integer);");

  sql ("CREATE TABLE IF NOT EXISTS task_preferences"
       " (id SERIAL PRIMARY KEY,"
       "  task integer REFERENCES tasks (id) ON DELETE RESTRICT,"
       "  name text,"
       "  value text);");

  sql ("CREATE TABLE IF NOT EXISTS permissions_get_tasks"
       " (\"user\" integer REFERENCES users ON DELETE CASCADE,"
       "  task integer REFERENCES tasks ON DELETE CASCADE,"
       "  has_permission boolean,"
       "  UNIQUE (\"user\", task));");

  sql ("CREATE TABLE IF NOT EXISTS reports"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  task integer REFERENCES tasks (id) ON DELETE RESTRICT,"
       "  date integer,"
       "  start_time integer,"
       "  end_time integer,"
       "  comment text,"
       "  scan_run_status integer,"
       "  slave_progress integer,"
       "  source_iface text,"
       "  flags integer);");

  sql ("CREATE TABLE IF NOT EXISTS report_counts"
       " (id SERIAL PRIMARY KEY,"
       "  report integer REFERENCES reports (id) ON DELETE RESTRICT,"
       "  \"user\" integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  severity decimal,"
       "  count integer,"
       "  override integer,"
       "  end_time integer,"
       "  min_qod integer);");

  sql ("CREATE TABLE IF NOT EXISTS results"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  task integer REFERENCES tasks (id) ON DELETE RESTRICT,"
       "  host text,"
       "  port text,"
       "  nvt text,"
       "  result_nvt integer," // REFERENCES result_nvts (id),"
       "  type text,"
       "  description text,"
       "  report integer REFERENCES reports (id) ON DELETE RESTRICT,"
       "  nvt_version text,"
       "  severity real,"
       "  qod integer,"
       "  qod_type text,"
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  date integer,"
       "  hostname text,"
       "  path text);");

  sql ("CREATE TABLE IF NOT EXISTS results_trash"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  task integer REFERENCES tasks (id) ON DELETE RESTRICT,"
       "  host text,"
       "  port text,"
       "  nvt text,"
       "  result_nvt integer," // REFERENCES result_nvts (id),"
       "  type text,"
       "  description text,"
       "  report integer REFERENCES reports (id) ON DELETE RESTRICT,"
       "  nvt_version text,"
       "  severity real,"
       "  qod integer,"
       "  qod_type text,"
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  date integer,"
       "  hostname text,"
       "  path text);");

  /* All the NVTs that have ever been encountered in results and overrides.
   *
   * This gives the textual NVT oids an integer ID, so that they can be
   * compared faster when calculating overridden severity. */
  sql ("CREATE TABLE IF NOT EXISTS result_nvts"
       " (id SERIAL PRIMARY KEY,"
       "  nvt text UNIQUE NOT NULL);");

  /* A record of all the reports that contain each result_nvt.  In other words,
   * all the reports that contain each NVT.
   *
   * This is used when counting the results of a report, to reduce the number
   * of overrides that are considered for each result. */
  sql ("CREATE TABLE IF NOT EXISTS result_nvt_reports"
       " (result_nvt INTEGER,"
       "  report INTEGER);");

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
       "  predefined integer,"
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
       "  predefined integer,"
       /* The UUID that the report format had before it was deleted.
        *
        * Regular report formats are given a new UUID when they are moved to
        * the trash, because it's possible to import the same report format
        * again, and delete it a second time.  The trash UUIDs must be unique.
        *
        * Feed ("predefined") report formats are not given a new UUID because
        * they are not created if they already exist in the trash. */
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
       "  report_format integer REFERENCES report_formats_trash (id) ON DELETE RESTRICT,"
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
       "  report_format_param integer REFERENCES report_format_params_trash (id) ON DELETE RESTRICT,"
       "  value text);");

  sql ("CREATE TABLE IF NOT EXISTS report_hosts"
       " (id SERIAL PRIMARY KEY,"
       "  report integer REFERENCES reports (id) ON DELETE RESTRICT,"
       "  host text,"
       "  start_time integer,"
       "  end_time integer,"
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

  sql ("CREATE TABLE IF NOT EXISTS vt_refs"
       " (id SERIAL PRIMARY KEY,"
       "  vt_oid text NOT NULL,"
       "  type text NOT NULL,"
       "  ref_id text NOT NULL,"
       "  ref_text text);");

  sql ("CREATE TABLE IF NOT EXISTS vt_severities"
       " (id SERIAL PRIMARY KEY,"
       "  vt_oid text NOT NULL,"
       "  type text NOT NULL,"
       "  origin text,"
       "  date integer,"
       "  score double precision,"
       "  value text);");

  sql ("CREATE TABLE IF NOT EXISTS nvt_preferences"
       " (id SERIAL PRIMARY KEY,"
       "  name text UNIQUE NOT NULL,"
       "  value text);");

  sql ("CREATE TABLE IF NOT EXISTS nvts"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  oid text UNIQUE NOT NULL,"
       "  name text,"
       "  comment text,"
       "  summary text,"
       "  insight text,"
       "  affected text,"
       "  impact text,"
       "  cve text,"
       "  tag text,"
       "  category text,"
       "  family text,"
       "  cvss_base text,"
       "  creation_time integer,"
       "  modification_time integer,"
       "  solution text,"
       "  solution_type text,"
       "  solution_method text,"
       "  detection text,"
       "  qod integer,"
       "  qod_type text);");

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
       "  result_nvt integer," // REFERENCES result_nvts (id),"
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
       "  result_nvt integer," // REFERENCES result_nvts (id),"
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
       "  value text,"
       "  UNIQUE (uuid, owner));");

  sql ("CREATE TABLE IF NOT EXISTS tags"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  name text NOT NULL,"
       "  comment text,"
       "  resource_type text,"
       "  active integer,"
       "  value text,"
       "  creation_time integer,"
       "  modification_time integer);");

  sql ("CREATE TABLE IF NOT EXISTS tag_resources"
       " (tag integer REFERENCES tags (id),"
       "  resource_type text,"
       "  resource integer,"
       "  resource_uuid text,"
       "  resource_location integer);");

  sql ("CREATE TABLE IF NOT EXISTS tags_trash"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  name text NOT NULL,"
       "  comment text,"
       "  resource_type text,"
       "  active integer,"
       "  value text,"
       "  creation_time integer,"
       "  modification_time integer);");

  sql ("CREATE TABLE IF NOT EXISTS tag_resources_trash"
       " (tag integer REFERENCES tags_trash (id),"
       "  resource_type text,"
       "  resource integer,"
       "  resource_uuid text,"
       "  resource_location integer);");

  /* Create result views. */

  /* Create functions, so that current_severity is created for
   * result_new_severities. */
  manage_create_sql_functions ();

  owned_clause = acl_where_owned_for_get ("override", "users.id", NULL, NULL);

  sql ("CREATE OR REPLACE VIEW result_overrides AS"
       " SELECT users.id AS user,"
       "        results.id as result,"
       "        overrides.id AS override,"
       "        overrides.severity AS ov_old_severity,"
       "        overrides.new_severity AS ov_new_severity"
       " FROM users, results, overrides"
       " WHERE overrides.result_nvt = results.result_nvt"
       " AND (overrides.result = 0 OR overrides.result = results.id)"
       " AND %s"
       " AND ((overrides.end_time = 0)"
       "      OR (overrides.end_time >= m_now ()))"
       " AND (overrides.task ="
       "      (SELECT reports.task FROM reports"
       "       WHERE results.report = reports.id)"
       "      OR overrides.task = 0)"
       " AND (overrides.result = results.id"
       "      OR overrides.result = 0)"
       " AND (overrides.hosts is NULL"
       "      OR overrides.hosts = ''"
       "      OR hosts_contains (overrides.hosts, results.host))"
       " AND (overrides.port is NULL"
       "      OR overrides.port = ''"
       "      OR overrides.port = results.port)"
       " ORDER BY overrides.result DESC, overrides.task DESC,"
       " overrides.port DESC, overrides.severity ASC,"
       " overrides.creation_time DESC",
       owned_clause);

  g_free (owned_clause);

  sql ("CREATE OR REPLACE VIEW result_new_severities_dynamic AS"
       "  SELECT results.id as result, users.id as user, 1 AS dynamic, 1 AS override,"
       "         coalesce ((SELECT ov_new_severity FROM result_overrides"
       "                    WHERE result = results.id"
       "                    AND result_overrides.user = users.id"
       "                    AND severity_matches_ov"
       "                         (current_severity (results.severity,"
       "                                            results.nvt),"
       "                          ov_old_severity)"
       "                    LIMIT 1),"
       "                   current_severity (results.severity, results.nvt))"
       "         AS new_severity"
       "  FROM results, users;");

  sql ("CREATE OR REPLACE VIEW result_new_severities_static AS"
       "  SELECT results.id as result, users.id as user, 0 AS dynamic, 1 AS override,"
       "         coalesce ((SELECT ov_new_severity FROM result_overrides"
       "                    WHERE result = results.id"
       "                    AND result_overrides.user = users.id"
       "                    AND severity_matches_ov"
       "                         (results.severity,"
       "                          ov_old_severity)"
       "                    LIMIT 1),"
       "                   results.severity)"
       "         AS new_severity"
       "  FROM results, users;");

  sql ("CREATE OR REPLACE VIEW result_new_severities AS"
       "  SELECT results.id as result, users.id as user, dynamic, 1 AS override,"
       "    CASE WHEN dynamic != 0 THEN"
       "      coalesce ((SELECT ov_new_severity FROM result_overrides"
       "                 WHERE result = results.id"
       "                   AND result_overrides.user = users.id"
       "                   AND severity_matches_ov"
       "                         (current_severity (results.severity,"
       "                                            results.nvt),"
       "                          ov_old_severity)"
       "                 LIMIT 1),"
       "                current_severity (results.severity, results.nvt))"
       "    ELSE"
       "      coalesce ((SELECT ov_new_severity FROM result_overrides"
       "                 WHERE result = results.id"
       "                   AND result_overrides.user = users.id"
       "                   AND severity_matches_ov"
       "                         (results.severity,"
       "                          ov_old_severity)"
       "                 LIMIT 1),"
       "                results.severity)"
       "    END AS new_severity"
       "  FROM results, users,"
       "  (SELECT 0 AS dynamic UNION SELECT 1 AS dynamic) AS dynamic_opts;");

  sql ("CREATE OR REPLACE VIEW tls_certificate_source_origins AS"
       " SELECT sources.id AS source_id, tls_certificate,"
       "        origin_id, origin_type, origin_data"
       "  FROM tls_certificate_sources AS sources"
       "  JOIN tls_certificate_origins AS origins"
       "    ON sources.origin = origins.id;");

  create_view_vulns ();

  /* Create indexes. */

  sql ("SELECT create_index ('host_details_by_host',"
       "                     'host_details', 'host');");

  sql ("SELECT create_index ('host_identifiers_by_host',"
       "                     'host_identifiers', 'host');");
  sql ("SELECT create_index ('host_identifiers_by_value',"
       "                     'host_identifiers', 'value');");

  sql ("SELECT create_index ('host_max_severities_by_host',"
       "                     'host_max_severities', 'host');");
  sql ("SELECT create_index ('host_oss_by_host',"
       "                     'host_oss', 'host');");

  sql ("SELECT create_index ('nvt_selectors_by_family_or_nvt',"
       "                     'nvt_selectors',"
       "                     'type, family_or_nvt');");
  sql ("SELECT create_index ('nvt_selectors_by_name',"
       "                     'nvt_selectors',"
       "                     'name');");
  sql ("SELECT create_index ('nvts_by_creation_time',"
       "                     'nvts',"
       "                     'creation_time');");
  sql ("SELECT create_index ('nvts_by_family', 'nvts', 'family');");
  sql ("SELECT create_index ('nvts_by_name', 'nvts', 'name');");
  sql ("SELECT create_index ('nvts_by_modification_time',"
       "                     'nvts', 'modification_time');");
  sql ("SELECT create_index ('nvts_by_cvss_base',"
       "                     'nvts', 'cvss_base');");
  sql ("SELECT create_index ('nvts_by_solution_type',"
       "                     'nvts', 'solution_type');");

  sql ("SELECT create_index ('permissions_by_name',"
       "                     'permissions', 'name');");
  sql ("SELECT create_index ('permissions_by_resource',"
       "                     'permissions', 'resource');");

  sql ("SELECT create_index ('report_counts_by_report_and_override',"
       "                     'report_counts', 'report, override');");

  sql ("SELECT create_index ('reports_by_task',"
       "                     'reports', 'task');");

  sql ("SELECT create_index ('tag_resources_by_resource',"
       "                     'tag_resources',"
       "                     'resource_type, resource, resource_location');");
  sql ("SELECT create_index ('tag_resources_by_resource_uuid',"
       "                     'tag_resources',"
       "                     'resource_type, resource_uuid');");
  sql ("SELECT create_index ('tag_resources_by_tag',"
       "                     'tag_resources', 'tag');");

  sql ("SELECT create_index ('tag_resources_trash_by_tag',"
       "                     'tag_resources_trash', 'tag');");

  sql ("SELECT create_index ('tls_certificate_locations_by_host_ip',"
       "                     'tls_certificate_locations', 'host_ip')");

  sql ("SELECT create_index ('tls_certificate_origins_by_origin_id_and_type',"
       "                     'tls_certificate_origins',"
       "                     'origin_id, origin_type')");

  sql ("SELECT create_index ('vt_refs_by_vt_oid',"
       "                     'vt_refs', 'vt_oid');");

  sql ("SELECT create_index ('vt_severities_by_vt_oid',"
       "                     'vt_severities', 'vt_oid');");

  /* Previously this included the value column but that can be bigger than 8191,
   * the maximum size that Postgres can handle.  For example, this can happen
   * for "ports".  Mostly value is short, like a CPE for the "App" detail,
   * which is what the index is for. */
  sql ("SELECT create_index"
       "        ('report_host_details_by_report_host_and_name',"
       "         'report_host_details',"
       "         'report_host, name');");
  sql ("SELECT create_index"
       "        ('report_hosts_by_report_and_host',"
       "         'report_hosts',"
       "         'report, host');");

  manage_create_result_indexes ();

  sql ("SELECT create_index"
       "        ('result_nvt_reports_by_report',"
       "         'result_nvt_reports',"
       "         'report');");
}

/**
 * @brief Ensure sequences for automatic ids are in a consistent state.
 *
 * Caller must organise a transaction.
 */
void
check_db_sequences ()
{
  iterator_t sequence_tables;
  init_iterator(&sequence_tables,
                "WITH table_columns AS ("
                " SELECT table_name, column_name FROM information_schema.columns"
                "  WHERE table_schema = 'public')"
                " SELECT *, pg_get_serial_sequence (table_name, column_name) FROM table_columns"
                "  WHERE pg_get_serial_sequence (table_name, column_name) IS NOT NULL;");

  while (next (&sequence_tables))
    {
      const char* table = iterator_string (&sequence_tables, 0);
      const char* column = iterator_string (&sequence_tables, 1);
      const char* sequence = iterator_string (&sequence_tables, 2);
      resource_t old_start, new_start;

      sql_int64 (&old_start,
                 "SELECT last_value + 1 FROM %s;",
                 sequence);

      sql_int64 (&new_start,
                 "SELECT coalesce (max (%s), 0) + 1 FROM %s;",
                 column, table);

      if (old_start < new_start)
        sql ("ALTER SEQUENCE %s RESTART WITH %llu;", sequence, new_start);
    }

  cleanup_iterator (&sequence_tables);
}

/**
 * @brief Check if an extension is available and can be installed.
 * 
 * @param[in]  name  Name of the extension to check.
 *
 * @return TRUE extension is available, FALSE otherwise.
 */
static gboolean
db_extension_available (const char *name)
{
  if (sql_int ("SELECT count(*) FROM pg_available_extensions"
               " WHERE name = '%s'",
               name))
    {
      g_debug ("%s: Extension '%s' is available.",
                 __func__, name);
      return TRUE;
    }
  else
    {
      g_message ("%s: Extension '%s' is not available.",
                 __func__, name);
      return FALSE;
    }
}

/**
 * @brief Ensure all extensions are installed.
 *
 * @return 0 success, 1 extension missing.
 */
int
check_db_extensions ()
{
  if (db_extension_available ("uuid-ossp")
      && db_extension_available ("pgcrypto"))
    {
      g_debug ("%s: All required extensions are available.", __func__);

      // Switch to superuser role and try to install extensions.
      sql ("SET ROLE \"%s\";", DB_SUPERUSER_ROLE);
      
      sql ("CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\"");
      sql ("CREATE EXTENSION IF NOT EXISTS \"pgcrypto\"");

      sql ("RESET ROLE;");
      return 0;
    }
  else
    {
      g_warning ("%s: A required extension is not available.", __func__);
      return 1;
    }
}

/* SecInfo. */

/**
 * @brief Attach external databases.
 */
void
manage_attach_databases ()
{
  if (manage_scap_loaded ())
    sql ("SELECT set_config ('search_path',"
         "                   current_setting ('search_path') || ',scap',"
         "                   false);");

  if (manage_cert_loaded ())
    sql ("SELECT set_config ('search_path',"
         "                   current_setting ('search_path') || ',cert',"
         "                   false);");
}

/**
 * @brief Attach external databases.
 *
 * @param[in]  name  Database name.
 */
void
manage_db_remove (const gchar *name)
{
  if (strcasecmp (name, "cert") == 0)
    sql ("DROP SCHEMA IF EXISTS cert CASCADE;");
  else if (strcasecmp (name, "scap") == 0)
    sql ("DROP SCHEMA IF EXISTS scap CASCADE;");
  else
    assert (0);
}

/**
 * @brief Init external database.
 *
 * @param[in]  name  Name.  "cert" or "scap".
 *
 * @return 0 success, -1 error.
 */
int
manage_db_init (const gchar *name)
{
  if (strcasecmp (name, "cert") == 0)
    {
      sql ("DROP SCHEMA IF EXISTS cert CASCADE;");
      sql ("CREATE SCHEMA cert;");

      sql ("SELECT set_config ('search_path',"
           "                   current_setting ('search_path') || ',cert',"
           "                   false);");

      /* Create tables and indexes. */

      sql ("CREATE TABLE cert.meta"
           " (id SERIAL PRIMARY KEY,"
           "  name text UNIQUE,"
           "  value text);");

      sql ("CREATE TABLE cert.cert_bund_advs"
           " (id SERIAL PRIMARY KEY,"
           "  uuid text UNIQUE,"
           "  name text UNIQUE,"
           "  comment TEXT,"
           "  creation_time integer,"
           "  modification_time integer,"
           "  title TEXT,"
           "  summary TEXT,"
           "  cve_refs INTEGER,"
           "  severity DOUBLE PRECISION);");
      sql ("CREATE UNIQUE INDEX cert_bund_advs_idx"
           " ON cert.cert_bund_advs (name);");
      sql ("CREATE INDEX cert_bund_advs_by_creation_time"
           " ON cert.cert_bund_advs (creation_time);");

      sql ("CREATE TABLE cert.cert_bund_cves"
           " (adv_id INTEGER,"
           "  cve_name VARCHAR(20));");
      sql ("CREATE INDEX cert_bund_cves_adv_idx"
           " ON cert.cert_bund_cves (adv_id);");
      sql ("CREATE INDEX cert_bund_cves_cve_idx"
           " ON cert.cert_bund_cves (cve_name);");

      sql ("CREATE TABLE cert.dfn_cert_advs"
           " (id SERIAL PRIMARY KEY,"
           "  uuid text UNIQUE,"
           "  name text UNIQUE,"
           "  comment TEXT,"
           "  creation_time integer,"
           "  modification_time integer,"
           "  title TEXT,"
           "  summary TEXT,"
           "  cve_refs INTEGER,"
           "  severity DOUBLE PRECISION);");
      sql ("CREATE UNIQUE INDEX dfn_cert_advs_idx"
           " ON cert.dfn_cert_advs (name);");
      sql ("CREATE INDEX dfn_cert_advs_by_creation_time"
           " ON cert.dfn_cert_advs (creation_time);");

      sql ("CREATE TABLE cert.dfn_cert_cves"
           " (adv_id INTEGER,"
           "  cve_name text);");
      sql ("CREATE INDEX dfn_cert_cves_adv_idx"
           " ON cert.dfn_cert_cves (adv_id);");
      sql ("CREATE INDEX dfn_cert_cves_cve_idx"
           " ON cert.dfn_cert_cves (cve_name);");

      /* Create deletion triggers. */

      sql ("CREATE OR REPLACE FUNCTION cert.cert_delete_bund_adv ()"
           " RETURNS TRIGGER AS $$"
           " BEGIN"
           "   DELETE FROM cert_bund_cves where adv_id = old.id;"
           "   RETURN old;"
           " END;"
           "$$ LANGUAGE plpgsql;");

      sql ("CREATE TRIGGER bund_delete"
           " AFTER DELETE ON cert.cert_bund_advs"
           " FOR EACH ROW EXECUTE PROCEDURE cert.cert_delete_bund_adv ();");

      sql ("CREATE OR REPLACE FUNCTION cert.cert_delete_cve ()"
           " RETURNS TRIGGER AS $$"
           " BEGIN"
           "   DELETE FROM dfn_cert_cves where adv_id = old.id;"
           "   RETURN old;"
           " END;"
           "$$ LANGUAGE plpgsql;");

      sql ("CREATE TRIGGER cve_delete"
           " AFTER DELETE ON cert.dfn_cert_advs"
           " FOR EACH ROW EXECUTE PROCEDURE cert.cert_delete_cve ();");

      /* Init tables. */

      sql ("INSERT INTO cert.meta (name, value)"
           " VALUES ('database_version', '%i');",
           GVMD_CERT_DATABASE_VERSION);
      sql ("INSERT INTO cert.meta (name, value)"
           " VALUES ('last_update', '0');");
    }
  else if (strcasecmp (name, "scap") == 0)
    {
      sql ("CREATE OR REPLACE FUNCTION drop_scap2 () RETURNS void AS $$"
           " BEGIN"
           "   IF EXISTS (SELECT schema_name FROM information_schema.schemata"
           "              WHERE schema_name = 'scap2')"
           "   THEN"
           "     DROP SCHEMA IF EXISTS scap2 CASCADE;"
           "   END IF;"
           " END;"
           " $$ LANGUAGE plpgsql;");

      sql ("SELECT set_config ('search_path',"
           "                   'scap2,' || current_setting ('search_path'),"
           "                   false);");

      sql ("SELECT drop_scap2 ();");
      sql ("DROP FUNCTION IF EXISTS drop_scap2 ();");

      sql ("CREATE SCHEMA scap2;");

      /* Create tables. */

      sql ("CREATE TABLE scap2.meta"
           " (id SERIAL PRIMARY KEY,"
           "  name text UNIQUE,"
           "  value text);");

      sql ("CREATE TABLE scap2.cves"
           " (id SERIAL PRIMARY KEY,"
           "  uuid text,"
           "  name text,"
           "  comment text,"
           "  description text,"
           "  creation_time integer,"
           "  modification_time integer,"
           "  cvss_vector text,"
           "  products text,"
           "  severity DOUBLE PRECISION DEFAULT 0);");

      sql ("CREATE TABLE scap2.cpes"
           " (id SERIAL PRIMARY KEY,"
           "  uuid text,"
           "  name text,"
           "  comment text,"
           "  creation_time integer,"
           "  modification_time integer,"
           "  title text,"
           "  status text,"
           "  deprecated_by_id INTEGER,"
           "  severity DOUBLE PRECISION DEFAULT 0,"
           "  cve_refs INTEGER DEFAULT 0,"
           "  nvd_id text);");

      sql ("CREATE TABLE scap2.affected_products"
           " (cve INTEGER,"
           "  cpe INTEGER);");

      sql ("CREATE TABLE scap2.ovaldefs"
           " (id SERIAL PRIMARY KEY,"
           "  uuid text,"
           "  name text,"                   /* OVAL identifier. */
           "  comment text,"
           "  creation_time integer,"
           "  modification_time integer,"
           "  version INTEGER,"
           "  deprecated INTEGER,"
           "  def_class TEXT,"              /* Enum. */
           "  title TEXT,"
           "  description TEXT,"
           "  xml_file TEXT,"
           "  status TEXT,"
           "  severity DOUBLE PRECISION DEFAULT 0,"
           "  cve_refs INTEGER DEFAULT 0);");

      sql ("CREATE TABLE scap2.ovalfiles"
           " (id SERIAL PRIMARY KEY,"
           "  xml_file TEXT);");

      sql ("CREATE TABLE scap2.affected_ovaldefs"
           " (cve INTEGER,"
           "  ovaldef INTEGER);");

      /* Init tables. */

      sql ("INSERT INTO scap2.meta (name, value)"
           " VALUES ('database_version', '%i');",
           GVMD_SCAP_DATABASE_VERSION);
      sql ("INSERT INTO scap2.meta (name, value)"
           " VALUES ('last_update', '0');");
    }
  else
    {
      assert (0);
      return -1;
    }

  return 0;
}

/**
 * @brief Init external database.
 *
 * @param[in]  name  Name.  Currently only "scap".
 *
 * @return 0 success, -1 error.
 */
int
manage_db_add_constraints (const gchar *name)
{
  if (strcasecmp (name, "scap") == 0)
    {
      sql ("ALTER TABLE scap2.cves"
           " ADD UNIQUE (uuid);");

      sql ("ALTER TABLE scap2.cpes"
           " ADD UNIQUE (uuid);");

      sql ("ALTER TABLE scap2.affected_products"
           " ALTER cve SET NOT NULL,"
           " ALTER cpe SET NOT NULL,"
           " ADD UNIQUE (cve, cpe),"
           " ADD FOREIGN KEY(cve) REFERENCES cves(id),"
           " ADD FOREIGN KEY(cpe) REFERENCES cpes(id);");

      sql ("ALTER TABLE scap2.ovaldefs"
           " ADD UNIQUE (uuid);");

      sql ("ALTER TABLE scap2.ovalfiles"
           " ADD UNIQUE (xml_file);");

      sql ("ALTER TABLE scap2.affected_ovaldefs"
           " ALTER cve SET NOT NULL,"
           " ALTER ovaldef SET NOT NULL,"
           " ADD FOREIGN KEY(cve) REFERENCES cves(id),"
           " ADD FOREIGN KEY(ovaldef) REFERENCES ovaldefs(id);");
    }
  else
    {
      assert (0);
      return -1;
    }

  return 0;
}

/**
 * @brief Init external database.
 *
 * @param[in]  name  Name.  Currently only "scap".
 *
 * @return 0 success, -1 error.
 */
int
manage_db_init_indexes (const gchar *name)
{
  if (strcasecmp (name, "scap") == 0)
    {
      sql ("CREATE UNIQUE INDEX cve_idx"
           " ON scap2.cves (name);");
      sql ("CREATE INDEX cves_by_creation_time_idx"
           " ON scap2.cves (creation_time);");
      sql ("CREATE INDEX cves_by_modification_time_idx"
           " ON scap2.cves (modification_time);");
      sql ("CREATE INDEX cves_by_severity"
           " ON scap2.cves (severity);");

      sql ("CREATE UNIQUE INDEX cpe_idx"
           " ON scap2.cpes (name);");
      sql ("CREATE INDEX cpes_by_creation_time_idx"
           " ON scap2.cpes (creation_time);");
      sql ("CREATE INDEX cpes_by_modification_time_idx"
           " ON scap2.cpes (modification_time);");
      sql ("CREATE INDEX cpes_by_severity"
           " ON scap2.cpes (severity);");
      sql ("CREATE INDEX cpes_by_uuid"
           " ON scap2.cpes (uuid);");

      sql ("CREATE INDEX afp_cpe_idx"
           " ON scap2.affected_products (cpe);");
      sql ("CREATE INDEX afp_cve_idx"
           " ON scap2.affected_products (cve);");

      sql ("CREATE INDEX ovaldefs_idx"
           " ON scap2.ovaldefs (name);");
      sql ("CREATE INDEX ovaldefs_by_creation_time"
           " ON scap2.ovaldefs (creation_time);");

      sql ("CREATE UNIQUE INDEX ovalfiles_idx"
           " ON scap2.ovalfiles (xml_file);");

      sql ("CREATE INDEX aff_ovaldefs_def_idx"
           " ON scap2.affected_ovaldefs (ovaldef);");
      sql ("CREATE INDEX aff_ovaldefs_cve_idx"
           " ON scap2.affected_ovaldefs (cve);");
    }
  else
    {
      assert (0);
      return -1;
    }

  return 0;
}

/**
 * @brief Check whether CERT is available.
 *
 * @return 1 if CERT database is loaded, else 0.
 */
int
manage_cert_loaded ()
{
  return !!sql_int ("SELECT EXISTS (SELECT * FROM information_schema.tables"
                    "               WHERE table_catalog = '%s'"
                    "               AND table_schema = 'cert'"
                    "               AND table_name = 'dfn_cert_advs')"
                    " ::integer;",
                    sql_database ());
}

/**
 * @brief Check whether SCAP is available.
 *
 * @return 1 if SCAP database is loaded, else 0.
 */
int
manage_scap_loaded ()
{
  return !!sql_int ("SELECT EXISTS (SELECT * FROM information_schema.tables"
                    "               WHERE table_catalog = '%s'"
                    "               AND table_schema = 'scap'"
                    "               AND table_name = 'cves')"
                    " ::integer;",
                    sql_database ());
}
