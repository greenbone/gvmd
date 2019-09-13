/* Copyright (C) 2014-2019 Greenbone Networks GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
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
       "  uuid text UNIQUE NOT NULL,"
       "  tz_override text);");
  sql ("DELETE FROM current_credentials;");
  if (uuid)
    sql ("INSERT INTO current_credentials (uuid) VALUES ('%s');", uuid);
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

/**
 * @brief Database specific setup for CERT update.
 *
 * @return 0 success, -1 error.
 */
int
manage_update_cert_db_init ()
{
  sql ("CREATE OR REPLACE FUNCTION merge_dfn_cert_adv"
       "                            (uuid_arg TEXT,"
       "                             creation_time_arg INTEGER,"
       "                             modification_time_arg INTEGER,"
       "                             title_arg TEXT,"
       "                             summary_arg TEXT,"
       "                             cve_refs_arg INTEGER)"
       " RETURNS VOID AS $$"
       " BEGIN"
       "   LOOP"
       "     UPDATE cert.dfn_cert_advs"
       "     SET name = uuid_arg,"
       "         comment = '',"
       "         creation_time = creation_time_arg,"
       "         modification_time = modification_time_arg,"
       "         title = title_arg,"
       "         summary = summary_arg,"
       "         cve_refs = cve_refs_arg"
       "     WHERE uuid = uuid_arg;"
       "     IF found THEN"
       "       RETURN;"
       "     END IF;"
       "     BEGIN"
       "       INSERT INTO cert.dfn_cert_advs"
       "                    (uuid, name, comment, creation_time,"
       "                     modification_time, title, summary, cve_refs)"
       "       VALUES (uuid_arg, uuid_arg, '', creation_time_arg,"
       "               modification_time_arg, title_arg, summary_arg,"
       "               cve_refs_arg);"
       "       RETURN;"
       "     EXCEPTION WHEN unique_violation THEN"
       "       NULL;"  /* Try again. */
       "     END;"
       "   END LOOP;"
       " END;"
       "$$ LANGUAGE plpgsql;");

  sql ("CREATE OR REPLACE FUNCTION merge_bund_adv"
       "                            (uuid_arg TEXT,"
       "                             creation_time_arg INTEGER,"
       "                             modification_time_arg INTEGER,"
       "                             title_arg TEXT,"
       "                             summary_arg TEXT,"
       "                             cve_refs_arg INTEGER)"
       " RETURNS VOID AS $$"
       " BEGIN"
       "   LOOP"
       "     UPDATE cert.cert_bund_advs"
       "     SET name = uuid_arg,"
       "         comment = '',"
       "         creation_time = creation_time_arg,"
       "         modification_time = modification_time_arg,"
       "         title = title_arg,"
       "         summary = summary_arg,"
       "         cve_refs = cve_refs_arg"
       "     WHERE uuid = uuid_arg;"
       "     IF found THEN"
       "       RETURN;"
       "     END IF;"
       "     BEGIN"
       "       INSERT INTO cert.cert_bund_advs"
       "                    (uuid, name, comment, creation_time,"
       "                     modification_time, title, summary, cve_refs)"
       "       VALUES (uuid_arg, uuid_arg, '', creation_time_arg,"
       "               modification_time_arg, title_arg, summary_arg,"
       "               cve_refs_arg);"
       "       RETURN;"
       "     EXCEPTION WHEN unique_violation THEN"
       "       NULL;"  /* Try again. */
       "     END;"
       "   END LOOP;"
       " END;"
       "$$ LANGUAGE plpgsql;");

  return 0;
}

/**
 * @brief Database specific cleanup after CERT update.
 */
void
manage_update_cert_db_cleanup ()
{
  sql ("DROP FUNCTION merge_dfn_cert_adv (uuid_arg TEXT,"
       "                                  creation_time_arg INTEGER,"
       "                                  modification_time_arg INTEGER,"
       "                                  title_arg TEXT,"
       "                                  summary_arg TEXT,"
       "                                  cve_refs_arg INTEGER);");

  sql ("DROP FUNCTION merge_bund_adv (uuid_arg TEXT,"
       "                              creation_time_arg INTEGER,"
       "                              modification_time_arg INTEGER,"
       "                              title_arg TEXT,"
       "                              summary_arg TEXT,"
       "                              cve_refs_arg INTEGER);");
}

/**
 * @brief Database specific setup for SCAP update.
 *
 * @return 0 success, -1 error.
 */
int
manage_update_scap_db_init ()
{
  sql ("CREATE OR REPLACE FUNCTION merge_cpe"
       "                            (name_arg TEXT,"
       "                             title_arg TEXT, creation_time_arg INTEGER,"
       "                             modification_time_arg INTEGER,"
       "                             status_arg TEXT,"
       "                             deprecated_by_id_arg INTEGER,"
       "                             nvd_id_arg TEXT)"
       " RETURNS VOID AS $$"
       " BEGIN"
       "   LOOP"
       "     UPDATE scap.cpes"
       "     SET name = name_arg, title = title_arg,"
       "         creation_time = creation_time_arg,"
       "         modification_time = modification_time_arg,"
       "         status = status_arg,"
       "         deprecated_by_id = deprecated_by_id_arg,"
       "         nvd_id = nvd_id_arg"
       "     WHERE uuid = name_arg;"
       "     IF found THEN"
       "       RETURN;"
       "     END IF;"
       "     BEGIN"
       "       INSERT INTO scap.cpes"
       "                    (uuid, name, title, creation_time,"
       "                     modification_time, status, deprecated_by_id,"
       "                     nvd_id)"
       "       VALUES (name_arg, name_arg, title_arg, creation_time_arg,"
       "               modification_time_arg, status_arg, deprecated_by_id_arg,"
       "               nvd_id_arg);"
       "       RETURN;"
       "     EXCEPTION WHEN unique_violation THEN"
       "       NULL;"  /* Try again. */
       "     END;"
       "   END LOOP;"
       " END;"
       "$$ LANGUAGE plpgsql;");

  sql ("CREATE OR REPLACE FUNCTION merge_cve"
       "                            (uuid_arg TEXT,"
       "                             name_arg TEXT,"
       "                             creation_time_arg INTEGER,"
       "                             modification_time_arg INTEGER,"
       "                             cvss_arg FLOAT,"
       "                             description_arg TEXT,"
       "                             vector_arg TEXT,"
       "                             complexity_arg TEXT,"
       "                             authentication_arg TEXT,"
       "                             confidentiality_impact_arg TEXT,"
       "                             integrity_impact_arg TEXT,"
       "                             availability_impact_arg TEXT,"
       "                             products_arg TEXT)"
       " RETURNS VOID AS $$"
       " BEGIN"
       "   LOOP"
       "     UPDATE scap.cves"
       "     SET name = name_arg,"
       "         creation_time = creation_time_arg,"
       "         modification_time = modification_time_arg,"
       "         cvss = cvss_arg,"
       "         description = description_arg,"
       "         vector = vector_arg,"
       "         complexity = complexity_arg,"
       "         authentication = authentication_arg,"
       "         confidentiality_impact = confidentiality_impact_arg,"
       "         integrity_impact = integrity_impact_arg,"
       "         availability_impact = availability_impact_arg,"
       "         products = products_arg"
       "     WHERE uuid = uuid_arg;"
       "     IF found THEN"
       "       RETURN;"
       "     END IF;"
       "     BEGIN"
       "       INSERT INTO scap.cves"
       "                    (uuid, name, creation_time, modification_time,"
       "                     cvss, description, vector, complexity,"
       "                     authentication, confidentiality_impact,"
       "                     integrity_impact, availability_impact, products)"
       "       VALUES (uuid_arg, name_arg, creation_time_arg,"
       "               modification_time_arg, cvss_arg, description_arg,"
       "               vector_arg, complexity_arg, authentication_arg,"
       "               confidentiality_impact_arg, integrity_impact_arg,"
       "               availability_impact_arg, products_arg);"
       "       RETURN;"
       "     EXCEPTION WHEN unique_violation THEN"
       "       NULL;"  /* Try again. */
       "     END;"
       "   END LOOP;"
       " END;"
       "$$ LANGUAGE plpgsql;");

  sql ("CREATE OR REPLACE FUNCTION merge_cpe_name"
       "                            (uuid_arg TEXT, name_arg TEXT,"
       "                             published_arg INTEGER,"
       "                             modified_arg INTEGER)"
       " RETURNS VOID AS $$"
       " BEGIN"
       "   LOOP"
       "     UPDATE scap.cpes"
       "     SET name = name_arg"
       "     WHERE uuid = uuid_arg;"
       "     IF found THEN"
       "       RETURN;"
       "     END IF;"
       "     BEGIN"
       "       INSERT INTO scap.cpes"
       "                    (uuid, name, creation_time, modification_time)"
       "       VALUES (uuid_arg, name_arg, published_arg, modified_arg);"
       "       RETURN;"
       "     EXCEPTION WHEN unique_violation THEN"
       "       NULL;"  /* Try again. */
       "     END;"
       "   END LOOP;"
       " END;"
       "$$ LANGUAGE plpgsql;");

  sql ("CREATE OR REPLACE FUNCTION merge_affected_product"
       "                            (cve_arg INTEGER, cpe_arg INTEGER)"
       " RETURNS VOID AS $$"
       " BEGIN"
       "   LOOP"
       "     UPDATE scap.affected_products"
       "     SET cve = cve_arg, cpe = cpe_arg"
       "     WHERE cve = cve_arg AND cpe = cpe_arg;"
       "     IF found THEN"
       "       RETURN;"
       "     END IF;"
       "     BEGIN"
       "       INSERT INTO scap.affected_products"
       "                    (cve, cpe)"
       "       VALUES (cve_arg, cpe_arg);"
       "       RETURN;"
       "     EXCEPTION WHEN unique_violation THEN"
       "       NULL;"  /* Try again. */
       "     END;"
       "   END LOOP;"
       " END;"
       "$$ LANGUAGE plpgsql;");

  sql ("CREATE OR REPLACE FUNCTION merge_ovaldef"
       "                            (uuid_arg TEXT,"
       "                             name_arg TEXT,"
       "                             comment_arg TEXT,"
       "                             creation_time_arg INTEGER,"
       "                             modification_time_arg INTEGER,"
       "                             version_arg INTEGER,"
       "                             deprecated_arg INTEGER,"
       "                             def_class_arg TEXT,"
       "                             title_arg TEXT,"
       "                             description_arg TEXT,"
       "                             xml_file_arg TEXT,"
       "                             status_arg TEXT,"
       "                             cve_refs_arg INTEGER)"
       " RETURNS VOID AS $$"
       " BEGIN"
       "   LOOP"
       "     UPDATE scap.ovaldefs"
       "     SET name = name_arg,"
       "         comment = comment_arg,"
       "         creation_time = creation_time_arg,"
       "         modification_time = modification_time_arg,"
       "         version = version_arg,"
       "         deprecated = deprecated_arg,"
       "         def_class = def_class_arg,"
       "         title = title_arg,"
       "         description = description_arg,"
       "         xml_file = xml_file_arg,"
       "         status = status_arg,"
       "         max_cvss = 0.0,"
       "         cve_refs = cve_refs_arg"
       "     WHERE uuid = uuid_arg;"
       "     IF found THEN"
       "       RETURN;"
       "     END IF;"
       "     BEGIN"
       "       INSERT INTO scap.ovaldefs"
       "                    (uuid, name, comment, creation_time,"
       "                     modification_time, version, deprecated, def_class,"
       "                     title, description, xml_file, status,"
       "                     max_cvss, cve_refs)"
       "       VALUES (uuid_arg, name_arg, comment_arg, creation_time_arg,"
       "               modification_time_arg, version_arg, deprecated_arg,"
       "               def_class_arg, title_arg, description_arg, xml_file_arg,"
       "               status_arg, 0.0, cve_refs_arg);"
       "       RETURN;"
       "     EXCEPTION WHEN unique_violation THEN"
       "       NULL;"  /* Try again. */
       "     END;"
       "   END LOOP;"
       " END;"
       "$$ LANGUAGE plpgsql;");

  return 0;
}

/**
 * @brief Database specific cleanup after SCAP update.
 */
void
manage_update_scap_db_cleanup ()
{
  sql ("DROP FUNCTION merge_cpe (name_arg TEXT, title_arg TEXT,"
       "                         creation_time_arg INTEGER,"
       "                         modification_time_arg INTEGER,"
       "                         status_arg TEXT, deprecated_by_id_arg INTEGER,"
       "                         nvd_id_arg TEXT);");

  sql ("DROP FUNCTION merge_cve (uuid_arg TEXT,"
       "                         name_arg TEXT,"
       "                         creation_time_arg INTEGER,"
       "                         modification_time_arg INTEGER,"
       "                         cvss_arg FLOAT,"
       "                         description_arg TEXT,"
       "                         vector_arg TEXT,"
       "                         complexity_arg TEXT,"
       "                         authentication_arg TEXT,"
       "                         confidentiality_impact_arg TEXT,"
       "                         integrity_impact_arg TEXT,"
       "                         availability_impact_arg TEXT,"
       "                         products_arg TEXT);");

  sql ("DROP FUNCTION merge_cpe_name (uuid_arg TEXT,"
       "                              name_arg TEXT,"
       "                              modified_arg INTEGER,"
       "                              published_arg INTEGER);");

  sql ("DROP FUNCTION merge_affected_product (cve_arg INTEGER,"
       "                                      cpe_arg INTEGER);");

  sql ("DROP FUNCTION merge_ovaldef (uuid_arg TEXT,"
       "                             name_arg TEXT,"
       "                             comment_arg TEXT,"
       "                             creation_time_arg INTEGER,"
       "                             modification_time_arg INTEGER,"
       "                             version_arg INTEGER,"
       "                             deprecated_arg INTEGER,"
       "                             def_class_arg TEXT,"
       "                             title_arg TEXT,"
       "                             description_arg TEXT,"
       "                             xml_file_arg TEXT,"
       "                             status_arg TEXT,"
       "                             cve_refs_arg INTEGER);");
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

  if (sql_int ("SELECT count (*) FROM pg_available_extensions"
               " WHERE name = 'uuid-ossp' AND installed_version IS NOT NULL;")
      == 0)
    {
      g_warning ("%s: PostgreSQL extension uuid-ossp required", __FUNCTION__);
      return -1;
    }

  /* Functions in C. */

  sql ("SET role dba;");

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

  sql ("CREATE OR REPLACE FUNCTION level_max_severity (text, text)"
       " RETURNS double precision"
       " AS '%s/libgvm-pg-server', 'sql_level_max_severity'"
       " LANGUAGE C;",
       GVM_LIB_INSTALL_DIR);

  sql ("CREATE OR REPLACE FUNCTION level_min_severity (text, text)"
       " RETURNS double precision"
       " AS '%s/libgvm-pg-server', 'sql_level_min_severity'"
       " LANGUAGE C;",
       GVM_LIB_INSTALL_DIR);

  sql ("CREATE OR REPLACE FUNCTION next_time (integer, integer, integer, integer)"
       " RETURNS integer"
       " AS '%s/libgvm-pg-server', 'sql_next_time'"
       " LANGUAGE C;",
       GVM_LIB_INSTALL_DIR);

  sql ("CREATE OR REPLACE FUNCTION next_time (integer, integer, integer, integer, text)"
       " RETURNS integer"
       " AS '%s/libgvm-pg-server', 'sql_next_time'"
       " LANGUAGE C;",
       GVM_LIB_INSTALL_DIR);

  sql ("CREATE OR REPLACE FUNCTION next_time (integer, integer, integer, integer, text, integer)"
       " RETURNS integer"
       " AS '%s/libgvm-pg-server', 'sql_next_time'"
       " LANGUAGE C;",
       GVM_LIB_INSTALL_DIR);

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

  sql ("CREATE OR REPLACE FUNCTION severity_matches_ov (double precision,"
       "                                                double precision)"
       " RETURNS boolean"
       " AS '%s/libgvm-pg-server', 'sql_severity_matches_ov'"
       " LANGUAGE C"
       " IMMUTABLE;",
       GVM_LIB_INSTALL_DIR);

  sql ("CREATE OR REPLACE FUNCTION valid_db_resource_type (text)"
       " RETURNS boolean"
       " AS '%s/libgvm-pg-server', 'sql_valid_db_resource_type'"
       " LANGUAGE C;",
       GVM_LIB_INSTALL_DIR);

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

  /* Wrapping the "LOCK TABLE ... NOWAIT" like this will prevent
   *  error messages in the PostgreSQL log if the lock is not available.
   */
  sql ("CREATE OR REPLACE FUNCTION try_exclusive_lock (regclass)"
       " RETURNS integer AS $$"
       " BEGIN"
       "   EXECUTE 'LOCK TABLE \"'"
       "           || $1"
       "           || '\" IN ACCESS EXCLUSIVE MODE NOWAIT;';"
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
           "   WHEN NOT valid_db_resource_type ($1)"
           "   THEN RAISE EXCEPTION 'Invalid resource type argument: %', $1;"
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
           "   THEN EXECUTE 'SELECT name FROM ' || $1 || 's"
           "                 WHERE uuid = $1'"
           "        INTO execute_name"
           "        USING $2;"
           "        RETURN execute_name;"
           "   WHEN $1 NOT IN ('nvt', 'cpe', 'cve', 'ovaldef', 'cert_bund_adv',"
           "                   'dfn_cert_adv', 'report', 'result', 'user')"
           "   THEN EXECUTE 'SELECT name FROM ' || $1 || 's_trash"
           "                 WHERE uuid = $1'"
           "        INTO execute_name"
           "        USING $2;"
           "        RETURN execute_name;"
           "   ELSE RETURN NULL;"
           "   END CASE;"
           " END;"
           "$$ LANGUAGE plpgsql;");

      created = 1;
    }

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
       "   dead_hosts integer;"
       " BEGIN"
       "   total := 0;"
       "   dead_hosts := 0;"
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
       "     IF report_host.max_port = -1 THEN"
       "       progress := 0;"
       "       dead_hosts := dead_hosts + 1;"
       "     ELSEIF report_host.max_port IS NOT NULL"
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
       "   IF (maximum_hosts - dead_hosts) > 0 THEN"
       "     total_progress := total / (maximum_hosts - dead_hosts);"
       "   ELSE"
       "     total_progress := 0;"
       "   END IF;"
       "   IF total_progress = 0 THEN"
       "     RETURN 1;"
       "   ELSIF total_progress = 100 THEN"
       "     RETURN 99;"
       "   END IF;"
       "   RETURN total_progress;"
       " END;"
       "$$ LANGUAGE plpgsql;");

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
       "   ELSIF $1 = 'Debug' THEN"
       "     RETURN 5;"
       "   ELSIF $1 = 'False Positive' THEN"
       "     RETURN 6;"
       "   ELSIF $1 = 'None' THEN"
       "     RETURN 7;"
       "   ELSE"
       "     RETURN 8;"
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
       "$$ LANGUAGE plpgsql"
       " IMMUTABLE;");

  sql ("DROP FUNCTION IF EXISTS iso_time (seconds integer);");

  sql ("CREATE OR REPLACE FUNCTION iso_time (seconds bigint)"
       " RETURNS text AS $$"
       " DECLARE"
       "   user_zone text;"
       "   user_offset interval;"
       " BEGIN"
       "   user_zone :="
       "     coalesce ((SELECT tz_override FROM current_credentials),"
       "               (SELECT timezone FROM users"
       "                WHERE uuid = (SELECT uuid"
       "                              FROM current_credentials)));"
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
       "     EXECUTE 'SELECT count (*) = 0 FROM ' || type || 's"
       "              WHERE name = $1"
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
       "     EXECUTE 'CREATE INDEX ' || index_name"
       "             || ' ON ' || table_name || ' (' || columns || ');';"
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
       "                     AND (resource = (SELECT ' || $1 || 's.owner"
       "                                      FROM ' || $1 || 's"
       "                                      WHERE id = $2)))"
       /*                Super on other_user's role. */
       "                 OR ((resource_type = ''role'')"
       "                     AND (resource"
       "                          IN (SELECT DISTINCT role"
       "                              FROM role_users"
       "                              WHERE \"user\""
       "                                    = (SELECT ' || $1 || 's.owner"
       "                                       FROM ' || $1 || 's"
       "                                       WHERE id = $2))))"
       /*                Super on other_user's group. */
       "                 OR ((resource_type = ''group'')"
       "                     AND (resource"
       "                          IN (SELECT DISTINCT \"group\""
       "                              FROM group_users"
       "                              WHERE \"user\""
       "                                    = (SELECT ' || $1 || 's.owner"
       "                                       FROM ' || $1 || 's"
       "                                       WHERE id = $2)))))"
       "            AND subject_location = " G_STRINGIFY (LOCATION_TABLE)
       "            AND ((subject_type = ''user''"
       "                  AND subject"
       "                      = (SELECT id FROM users"
       "                         WHERE users.uuid"
       "                               = (SELECT uuid"
       "                                  FROM current_credentials)))"
       "                 OR (subject_type = ''group''"
       "                     AND subject"
       "                         IN (SELECT DISTINCT \"group\""
       "                             FROM group_users"
       "                             WHERE"
       "                             \"user\""
       "                             = (SELECT id"
       "                                FROM users"
       "                                WHERE users.uuid"
       "                                      = (SELECT uuid"
       "                                         FROM current_credentials))))"
       "                 OR (subject_type = ''role''"
       "                     AND subject"
       "                         IN (SELECT DISTINCT role"
       "                             FROM role_users"
       "                             WHERE"
       "                             \"user\""
       "                             = (SELECT id"
       "                                FROM users"
       "                                WHERE users.uuid"
       "                                      = (SELECT uuid"
       "                                         FROM current_credentials))))))'"
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
       "                          OR (reports.owner"
       "                              = (SELECT id FROM users"
       "                                 WHERE users.uuid"
       "                                       = (SELECT uuid"
       "                                          FROM current_credentials)))))"
       "        THEN RETURN true;"
       "        ELSE RETURN false;"
       "        END CASE;"
       "   WHEN arg_type = 'task'"
       "   THEN CASE"
       "        WHEN EXISTS (SELECT * FROM tasks"
       "                     WHERE id = arg_id"
       "                     AND hidden < 2"
       "                     AND ((owner IS NULL)"
       "                          OR (owner"
       "                              = (SELECT id FROM users"
       "                                 WHERE users.uuid"
       "                                       = (SELECT uuid"
       "                                          FROM current_credentials)))))"
       "        THEN RETURN true;"
       "        ELSE RETURN false;"
       "        END CASE;"
       "   ELSE"
       "     EXECUTE"
       "     'SELECT EXISTS (SELECT * FROM ' || $1 || 's"
       "      WHERE id = $2"
       "      AND ((owner IS NULL)"
       "           OR (owner = (SELECT id FROM users"
       "                        WHERE users.uuid = (SELECT uuid"
       "                                            FROM current_credentials))))'"
       "     USING arg_type, arg_id"
       "     INTO owns;"
       "     RETURN owns;"
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
       "    'SELECT id FROM ' || $1 || 's WHERE uuid = $2'"
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
       "  user_id = (SELECT id FROM users"
       "              WHERE uuid = (SELECT uuid FROM current_credentials));"
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
       "$$ LANGUAGE plpgsql;");

  /* Functions in SQL. */

  sql ("CREATE OR REPLACE FUNCTION t () RETURNS boolean AS $$"
       "  SELECT true;"
       "$$ LANGUAGE SQL"
       " IMMUTABLE;");

  sql ("CREATE OR REPLACE FUNCTION m_now () RETURNS integer AS $$"
       "  SELECT extract (epoch FROM now ())::integer;"
       "$$ LANGUAGE SQL"
       " STABLE;");

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
           "               IN (SELECT unnest (ARRAY [%i, %i, %i, %i, %i, %i,"
           "                                         %i, %i]))"
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
           TASK_STATUS_STOPPED,
           TASK_STATUS_INTERRUPTED);

      sql ("CREATE OR REPLACE FUNCTION report_progress (integer)"
           " RETURNS integer AS $$"
           /* Calculate the progress of a report. */
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
             "  WITH max_severity AS (SELECT max(severity) AS max"
             "                        FROM report_counts"
             // FIX should have user like report_counts_cache_exists?  c version too?
             "                        WHERE report = $1"
             "                        AND override = $2"
             "                        AND min_qod = $3"
             "                        AND (end_time = 0 or end_time >= m_now ()))"
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
           "       OR (owner = (SELECT id FROM users"
           "                    WHERE users.uuid = (SELECT uuid"
           "                                        FROM current_credentials))))"
           "  ORDER BY coalesce (owner, 0) DESC LIMIT 1;"
           "$$ LANGUAGE SQL;");

      /* result_nvt column (in OVERRIDES_SQL) was added in version 189 */
      if (current_db_version >= 189)
        sql ("CREATE OR REPLACE FUNCTION"
             " report_severity_count (report integer, overrides integer,"
             "                        min_qod integer, level text)"
             " RETURNS bigint AS $$"
             /* Calculate the severity of a report. */
             "  WITH severity_count AS (SELECT sum (count) AS total"
             "                          FROM report_counts"
             "                          WHERE report = $1"
             "                          AND override = $2"
             "                          AND min_qod = $3"
             "                          AND (end_time = 0"
             "                               or end_time >= m_now ())"
             "                          AND (severity"
             "                               BETWEEN level_min_severity"
             "                                        ($4, severity_class ())"
             "                                       AND level_max_severity"
             "                                            ($4, severity_class ())))"
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
        sql ("CREATE OR REPLACE FUNCTION task_severity (integer, integer,"
             "                                          integer)"
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
       "         WHEN $1 = %i OR $1 = %i OR $1 = %i"
       "         THEN 'Stop Requested'"
       "         WHEN $1 = %i"
       "         THEN 'Stopped'"
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
       TASK_STATUS_STOP_REQUESTED_GIVEUP,
       TASK_STATUS_STOP_REQUESTED,
       TASK_STATUS_STOP_WAITING,
       TASK_STATUS_STOPPED);

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
           "  SELECT CASE (SELECT value FROM settings"
           "               WHERE name = 'Severity Class'"
           "               AND ((owner IS NULL)"
           "                    OR (owner = (SELECT id FROM users"
           "                                 WHERE users.uuid"
           "                                       = (SELECT uuid"
           "                                          FROM current_credentials))))"
           "               ORDER BY coalesce (owner, 0) DESC LIMIT 1)"
           "         WHEN 'pci-dss'"
           "         THEN (CASE lower ($2)"
           "               WHEN 'high'"
           "               THEN $1 >= 4.0"
           "               WHEN 'none'"
           "               THEN $1 >= 0.0 AND $1 < 4.0"
           "               WHEN 'log'"
           "               THEN $1 >= 0.0 AND $1 < 4.0"
           "               ELSE 0::boolean"
           "               END)"
           "         ELSE " /* NIST/BSI */
           "              (CASE lower ($2)"
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
           "               WHEN 'log'"
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
           "         WHERE \"user\" = (SELECT id FROM users"
           "                           WHERE uuid ="
           "                            (SELECT uuid FROM current_credentials))"
           "           AND task = results.task)"
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
 * @brief Results WHERE SQL for creating views in create_tabes.
 */
#define VULNS_RESULTS_WHERE                                           \
  " WHERE uuid IN"                                                    \
  "   (SELECT nvt FROM results"                                       \
  "     WHERE (results.severity != " G_STRINGIFY (SEVERITY_ERROR) "))"

/**
 * @brief Create all tables.
 */
void
create_tables ()
{
  gchar *owned_clause;

  sql ("DROP TABLE IF EXISTS current_credentials");
  sql ("CREATE TABLE IF NOT EXISTS current_credentials"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  tz_override text);");

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

  sql ("CREATE TABLE IF NOT EXISTS agents"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  name text NOT NULL,"
       "  comment text,"
       "  installer bytea,"
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
       "  installer bytea,"
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
       "  port_list integer," // REFERENCES port_lists (id) ON DELETE RESTRICT,"
       "  port_list_location integer,"
       "  alive_test integer,"
       "  creation_time integer,"
       "  modification_time integer);");

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
       "  initial_offset integer,"
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
       "  initial_offset integer,"
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
       "  slave_task_uuid text,"
       "  slave_uuid text,"
       "  slave_name text,"
       "  slave_host text,"
       "  slave_port integer,"
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

  sql ("CREATE TABLE IF NOT EXISTS resources_predefined"
       " (id SERIAL PRIMARY KEY,"
       "  resource_type text,"
       "  resource integer);");

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
       "  hostname text);");

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
       "  hostname text);");

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
       "  value text);");

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

  owned_clause = acl_where_owned_for_get ("override", "users.id", NULL);

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

  sql ("CREATE OR REPLACE VIEW result_new_severities AS"
       "  SELECT results.id as result, users.id as user, dynamic, override,"
       "    CASE WHEN dynamic != 0 THEN"
       "      CASE WHEN override != 0 THEN"
       "        coalesce ((SELECT ov_new_severity FROM result_overrides"
       "                   WHERE result = results.id"
       "                     AND result_overrides.user = users.id"
       "                     AND severity_matches_ov"
       "                           (current_severity (results.severity,"
       "                                              results.nvt),"
       "                            ov_old_severity)"
       "                   LIMIT 1),"
       "                  current_severity (results.severity, results.nvt))"
       "      ELSE"
       "        current_severity (results.severity, results.nvt)"
       "      END"
       "    ELSE"
       "      CASE WHEN override != 0 THEN"
       "        coalesce ((SELECT ov_new_severity FROM result_overrides"
       "                   WHERE result = results.id"
       "                     AND result_overrides.user = users.id"
       "                     AND severity_matches_ov"
       "                           (results.severity,"
       "                            ov_old_severity)"
       "                   LIMIT 1),"
       "                  results.severity)"
       "      ELSE"
       "        results.severity"
       "      END"
       "    END AS new_severity"
       "  FROM results, users,"
       "  (SELECT 0 AS override UNION SELECT 1 AS override) AS override_opts,"
       "  (SELECT 0 AS dynamic UNION SELECT 1 AS dynamic) AS dynamic_opts;");

  sql ("CREATE OR REPLACE VIEW results_autofp AS"
       " SELECT results.id as result, autofp_selection,"
       "        (CASE autofp_selection"
       "         WHEN 1 THEN"
       "          (CASE WHEN"
       "           (((SELECT family FROM nvts WHERE oid = results.nvt)"
       "             IN (" LSC_FAMILY_LIST "))"
       "            OR EXISTS"
       "              (SELECT id FROM nvts"
       "               WHERE oid = results.nvt"
       "               AND"
       "                (cve = ''"
       "                 OR cve NOT IN (SELECT cve FROM nvts"
       "                                WHERE oid"
       "                                      IN (SELECT source_name"
       "                                          FROM report_host_details"
       "                                          WHERE report_host"
       "                                                = (SELECT id"
       "                                                   FROM report_hosts"
       "                                                   WHERE report = %llu"
       "                                                   AND host"
       "                                                       = results.host)"
       "                                          AND name = 'EXIT_CODE'"
       "                                          AND value = 'EXIT_NOTVULN')"
       "                                AND family IN (" LSC_FAMILY_LIST ")))))"
       "           THEN NULL"
       "           WHEN severity = " G_STRINGIFY (SEVERITY_ERROR) " THEN NULL"
       "           ELSE 1 END)"
       "         WHEN 2 THEN"
       "          (CASE WHEN"
       "            (((SELECT family FROM nvts WHERE oid = results.nvt)"
       "              IN (" LSC_FAMILY_LIST "))"
       "             OR EXISTS"
       "             (SELECT id FROM nvts AS outer_nvts"
       "              WHERE oid = results.nvt"
       "              AND"
       "              (cve = ''"
       "               OR NOT EXISTS"
       "                  (SELECT cve FROM nvts"
       "                   WHERE oid IN (SELECT source_name"
       "                                 FROM report_host_details"
       "                                 WHERE report_host"
       "                                 = (SELECT id"
       "                                    FROM report_hosts"
       "                                    WHERE report = results.report"
       "                                    AND host = results.host)"
       "                                 AND name = 'EXIT_CODE'"
       "                                 AND value = 'EXIT_NOTVULN')"
       "                   AND family IN (" LSC_FAMILY_LIST ")"
       /* The CVE of the result NVT is outer_nvts.cve.  The CVE of the
        * NVT that has registered the "closed" host detail is nvts.cve.
        * Either can be a list of CVEs. */
       "                   AND common_cve (nvts.cve, outer_nvts.cve)))))"
       "           THEN NULL"
       "           WHEN severity = " G_STRINGIFY (SEVERITY_ERROR) " THEN NULL"
       "           ELSE 1 END)"
       "         ELSE 0 END) AS autofp"
       " FROM results,"
       "  (SELECT 0 AS autofp_selection"
       "   UNION SELECT 1 AS autofp_selection"
       "   UNION SELECT 2 AS autofp_selection) AS autofp_opts;");

  sql ("CREATE OR REPLACE VIEW tls_certificate_source_origins AS"
       " SELECT sources.id AS source_id, tls_certificate,"
       "        origin_id, origin_type, origin_data"
       "  FROM tls_certificate_sources AS sources"
       "  JOIN tls_certificate_origins AS origins"
       "    ON sources.origin = origins.id;");

  sql ("DROP VIEW IF EXISTS vulns;");
  if (sql_int ("SELECT EXISTS (SELECT * FROM information_schema.tables"
               "               WHERE table_catalog = '%s'"
               "               AND table_schema = 'scap'"
               "               AND table_name = 'ovaldefs')"
               " ::integer;",
               sql_database ()))
    sql ("CREATE OR REPLACE VIEW vulns AS"
         " SELECT id, uuid, name, creation_time, modification_time,"
         "        cast (cvss_base AS double precision) AS severity, qod,"
         "        'nvt' AS type"
         " FROM nvts"
         VULNS_RESULTS_WHERE
         " UNION SELECT id, uuid, name, creation_time, modification_time,"
         "       cvss AS severity, " G_STRINGIFY (QOD_DEFAULT) " AS qod,"
         "       'cve' AS type"
         " FROM cves"
         VULNS_RESULTS_WHERE
         " UNION SELECT id, uuid, name, creation_time, modification_time,"
         "       max_cvss AS severity, " G_STRINGIFY (QOD_DEFAULT) " AS qod,"
         "       'ovaldef' AS type"
         " FROM ovaldefs"
         VULNS_RESULTS_WHERE);
  else
    sql ("CREATE OR REPLACE VIEW vulns AS"
         " SELECT id, uuid, name, creation_time, modification_time,"
         "        cast (cvss_base AS double precision) AS severity, qod,"
         "        'nvt' AS type"
         " FROM nvts"
         VULNS_RESULTS_WHERE);

#undef VULNS_RESULTS_WHERE

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


#if 0
  /* TODO The value column can be bigger than 8191, the maximum size that
   *      Postgres can handle.  For example, this can happen for "ports".
   *      Mostly value is short, like a CPE for the "App" detail, which is
   *      what the index is for. */
  sql ("SELECT create_index"
       "        ('report_host_details_by_report_host_and_name_and_value',"
       "         'report_host_details',"
       "         'report_host, name, value');");
#else
  sql ("SELECT create_index"
       "        ('report_host_details_by_report_host_and_name',"
       "         'report_host_details',"
       "         'report_host, name');");
#endif
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
           "  max_cvss FLOAT);");
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
           "  max_cvss FLOAT);");
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
           " VALUES ('database_version', '6');");
      sql ("INSERT INTO cert.meta (name, value)"
           " VALUES ('last_update', '0');");
    }
  else if (strcasecmp (name, "scap") == 0)
    {
      sql ("CREATE OR REPLACE FUNCTION drop_scap () RETURNS void AS $$"
           " BEGIN"
           "   IF EXISTS (SELECT schema_name FROM information_schema.schemata"
           "              WHERE schema_name = 'scap')"
           "   THEN"
           "     DROP SCHEMA IF EXISTS scap CASCADE;"
           "   END IF;"
           " END;"
           " $$ LANGUAGE plpgsql;");

      sql ("SELECT drop_scap ();");
      sql ("DROP FUNCTION drop_scap ();");
      sql ("CREATE SCHEMA scap;");

      sql ("SELECT set_config ('search_path',"
           "                   current_setting ('search_path') || ',scap',"
           "                   false);");

      /* Create tables and indexes. */

      sql ("CREATE TABLE scap.meta"
           " (id SERIAL PRIMARY KEY,"
           "  name text UNIQUE,"
           "  value text);");

      sql ("CREATE TABLE scap.cves"
           " (id SERIAL PRIMARY KEY,"
           "  uuid text UNIQUE,"
           "  name text,"
           "  comment text,"
           "  description text,"
           "  creation_time integer,"
           "  modification_time integer,"
           "  vector text,"
           "  complexity text,"
           "  authentication text,"
           "  confidentiality_impact text,"
           "  integrity_impact text,"
           "  availability_impact text,"
           "  products text,"
           "  cvss FLOAT DEFAULT 0);");
      sql ("CREATE UNIQUE INDEX cve_idx"
           " ON cves (name);");
      sql ("CREATE INDEX cves_by_creation_time_idx"
           " ON cves (creation_time);");
      sql ("CREATE INDEX cves_by_modification_time_idx"
           " ON cves (modification_time);");
      sql ("CREATE INDEX cves_by_cvss"
           " ON cves (cvss);");

      sql ("CREATE TABLE scap.cpes"
           " (id SERIAL PRIMARY KEY,"
           "  uuid text UNIQUE,"
           "  name text,"
           "  comment text,"
           "  creation_time integer,"
           "  modification_time integer,"
           "  title text,"
           "  status text,"
           "  deprecated_by_id INTEGER,"
           "  max_cvss FLOAT DEFAULT 0,"
           "  cve_refs INTEGER DEFAULT 0,"
           "  nvd_id text);");
      sql ("CREATE UNIQUE INDEX cpe_idx"
           " ON cpes (name);");
      sql ("CREATE INDEX cpes_by_creation_time_idx"
           " ON cpes (creation_time);");
      sql ("CREATE INDEX cpes_by_modification_time_idx"
           " ON cpes (modification_time);");
      sql ("CREATE INDEX cpes_by_cvss"
           " ON cpes (max_cvss);");

      sql ("CREATE TABLE scap.affected_products"
           " (cve INTEGER NOT NULL,"
           "  cpe INTEGER NOT NULL,"
           "  FOREIGN KEY(cve) REFERENCES cves(id),"
           "  FOREIGN KEY(cpe) REFERENCES cpes(id));");
      sql ("CREATE INDEX afp_cpe_idx"
           " ON affected_products (cpe);");
      sql ("CREATE INDEX afp_cve_idx"
           " ON affected_products (cve);");

      sql ("CREATE TABLE scap.ovaldefs"
           " (id SERIAL PRIMARY KEY,"
           "  uuid text UNIQUE,"
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
           "  max_cvss FLOAT DEFAULT 0,"
           "  cve_refs INTEGER DEFAULT 0);");
      sql ("CREATE INDEX ovaldefs_idx"
           " ON ovaldefs (name);");
      sql ("CREATE INDEX ovaldefs_by_creation_time"
           " ON ovaldefs (creation_time);");

      sql ("CREATE TABLE scap.ovalfiles"
           " (id SERIAL PRIMARY KEY,"
           "  xml_file TEXT UNIQUE);");
      sql ("CREATE UNIQUE INDEX ovalfiles_idx"
           " ON ovalfiles (xml_file);");

      sql ("CREATE TABLE scap.affected_ovaldefs"
           " (cve INTEGER NOT NULL,"
           "  ovaldef INTEGER NOT NULL,"
           "  FOREIGN KEY(cve) REFERENCES cves(id),"
           "  FOREIGN KEY(ovaldef) REFERENCES ovaldefs(id));");
      sql ("CREATE INDEX aff_ovaldefs_def_idx"
           " ON affected_ovaldefs (ovaldef);");
      sql ("CREATE INDEX aff_ovaldefs_cve_idx"
           " ON affected_ovaldefs (cve);");

      /* Create deletion triggers. */

      sql ("CREATE OR REPLACE FUNCTION scap_delete_affected ()"
           " RETURNS TRIGGER AS $$"
           " BEGIN"
           "   DELETE FROM affected_products where cve = old.id;"
           "   DELETE FROM affected_ovaldefs where cve = old.id;"
           "   RETURN old;"
           " END;"
           "$$ LANGUAGE plpgsql;");

      sql ("CREATE TRIGGER cves_delete AFTER DELETE ON cves"
	   " FOR EACH ROW EXECUTE PROCEDURE scap_delete_affected ();");

      sql ("CREATE OR REPLACE FUNCTION scap_update_cpes ()"
           " RETURNS TRIGGER AS $$"
           " BEGIN"
           "   UPDATE cpes SET max_cvss = 0.0 WHERE id = old.cpe;"
           "   UPDATE cpes SET cve_refs = cve_refs -1 WHERE id = old.cpe;"
           "   RETURN old;"
           " END;"
           "$$ LANGUAGE plpgsql;");

      sql ("CREATE TRIGGER affected_delete AFTER DELETE ON affected_products"
           " FOR EACH ROW EXECUTE PROCEDURE scap_update_cpes ();");

      sql ("CREATE OR REPLACE FUNCTION scap_delete_oval ()"
           " RETURNS TRIGGER AS $$"
           " BEGIN"
           "   DELETE FROM ovaldefs WHERE ovaldefs.xml_file = old.xml_file;"
           "   RETURN old;"
           " END;"
           "$$ LANGUAGE plpgsql;");

      sql ("CREATE TRIGGER ovalfiles_delete AFTER DELETE ON ovalfiles"
           " FOR EACH ROW EXECUTE PROCEDURE scap_delete_oval ();");

      sql ("CREATE OR REPLACE FUNCTION scap_update_oval ()"
           " RETURNS TRIGGER AS $$"
           " BEGIN"
           "   UPDATE ovaldefs SET max_cvss = 0.0 WHERE id = old.ovaldef;"
           "   RETURN old;"
           " END;"
           "$$ LANGUAGE plpgsql;");

      sql ("CREATE TRIGGER affected_ovaldefs_delete"
           " AFTER DELETE ON affected_ovaldefs"
	   " FOR EACH ROW EXECUTE PROCEDURE scap_update_oval ();");

      /* Init tables. */

      sql ("INSERT INTO scap.meta (name, value)"
           " VALUES ('database_version', '15');");
      sql ("INSERT INTO scap.meta (name, value)"
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
 * @brief Dummy function.
 *
 * @param[in]  name  Dummy arg.
 */
void
manage_db_check_mode (const gchar *name)
{
  return;
}

/**
 * @brief Dummy function.
 *
 * @param[in]  name  Dummy arg.
 *
 * @return 0.
 */
int
manage_db_check (const gchar *name)
{
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
