/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * @brief PostgreSQL integration tests for report_severity.
 */

#include "manage_report_severity_sql.h"

#include <libpq-fe.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TEST_SKIPPED 77

static PGconn *connection;
static int failures;

static int
execute (const char *sql)
{
  PGresult *result = PQexec (connection, sql);
  ExecStatusType status = PQresultStatus (result);

  if (status != PGRES_COMMAND_OK && status != PGRES_TUPLES_OK)
    {
      fprintf (stderr, "SQL failed:\n%s\n%s", sql, PQerrorMessage (connection));
      failures++;
      PQclear (result);
      return 0;
    }

  PQclear (result);
  return 1;
}

static void
expect_value (const char *description, const char *sql, const char *expected)
{
  PGresult *result = PQexec (connection, sql);

  if (PQresultStatus (result) != PGRES_TUPLES_OK || PQntuples (result) != 1
      || PQnfields (result) != 1)
    {
      fprintf (stderr, "%s: query failed: %s", description,
               PQerrorMessage (connection));
      failures++;
    }
  else if (PQgetisnull (result, 0, 0))
    {
      fprintf (stderr, "%s: expected %s, got NULL\n", description, expected);
      failures++;
    }
  else if (strcmp (PQgetvalue (result, 0, 0), expected))
    {
      fprintf (stderr, "%s: expected %s, got %s\n", description, expected,
               PQgetvalue (result, 0, 0));
      failures++;
    }

  PQclear (result);
}

static void
expect_null (const char *description, const char *sql)
{
  PGresult *result = PQexec (connection, sql);

  if (PQresultStatus (result) != PGRES_TUPLES_OK || PQntuples (result) != 1
      || PQnfields (result) != 1)
    {
      fprintf (stderr, "%s: query failed: %s", description,
               PQerrorMessage (connection));
      failures++;
    }
  else if (PQgetisnull (result, 0, 0) == 0)
    {
      fprintf (stderr, "%s: expected NULL, got %s\n", description,
               PQgetvalue (result, 0, 0));
      failures++;
    }

  PQclear (result);
}

static int
create_fixture ()
{
  char schema_sql[256];

  snprintf (schema_sql, sizeof (schema_sql),
            "CREATE SCHEMA report_severity_test_%ld;"
            "SET LOCAL search_path TO report_severity_test_%ld;",
            (long) getpid (), (long) getpid ());

  return execute ("BEGIN;") && execute (schema_sql)
         && execute ("CREATE TABLE report_counts"
                     " (report integer, \"user\" integer, override integer,"
                     "  min_qod integer, end_time bigint, severity real);")
         && execute ("CREATE TABLE results"
                     " (id integer, report integer, task integer,"
                     "  result_nvt text, severity real, nvt text, type text,"
                     "  qod integer, host text, port text);")
         && execute ("CREATE TABLE overrides"
                     " (new_severity real, result_nvt text, owner integer,"
                     "  end_time bigint, task integer, result integer,"
                     "  hosts text, port text, severity text,"
                     "  creation_time bigint);")
         && execute ("CREATE TABLE test_control (dynamic boolean);"
                     "INSERT INTO test_control VALUES (false);")
         && execute ("CREATE FUNCTION gvmd_user () RETURNS integer"
                     " AS $$ SELECT 42; $$ LANGUAGE SQL STABLE;")
         && execute ("CREATE FUNCTION m_now () RETURNS bigint"
                     " AS $$ SELECT 1000; $$ LANGUAGE SQL STABLE;")
         && execute ("CREATE FUNCTION dynamic_severity () RETURNS boolean"
                     " AS $$ SELECT dynamic FROM test_control; $$"
                     " LANGUAGE SQL STABLE;")
         && execute ("CREATE FUNCTION current_severity (real, text)"
                     " RETURNS double precision"
                     " AS $$ SELECT $1 + 10; $$ LANGUAGE SQL STABLE;")
         && execute ("CREATE FUNCTION oci_digest_list_contains (text, text)"
                     " RETURNS boolean AS $$ SELECT false; $$"
                     " LANGUAGE SQL STABLE;")
         && execute ("CREATE FUNCTION hosts_contains (text, text)"
                     " RETURNS boolean AS $$ SELECT false; $$"
                     " LANGUAGE SQL STABLE;")
         && execute ("CREATE FUNCTION severity_matches_ov"
                     " (double precision, text)"
                     " RETURNS boolean AS $$ SELECT $2 = 'match'; $$"
                     " LANGUAGE SQL STABLE;")
         && execute (REPORT_SEVERITY_CACHED_SQL)
         && execute (REPORT_SEVERITY_DYNAMIC_SQL)
         && execute (REPORT_SEVERITY_SQL);
}

static int
load_fixture_data ()
{
  return execute ("INSERT INTO report_counts VALUES"
                  " (1, 42, 0, 70, 0, 7.1),"
                  " (1, 42, 0, 70, 1100, 8.2),"
                  " (1, 99, 0, 70, 0, 9.9),"
                  " (1, 42, 1, 70, 0, 9.8),"
                  " (1, 42, 0, 80, 0, 9.7),"
                  " (1, 42, 0, 70, 999, 9.6),"
                  " (11, 42, 0, 70, 0, NULL),"
                  " (12, 42, 0, 70, 999, 9.9),"
                  " (14, 99, 0, 70, 0, 9.9),"
                  " (14, 42, 1, 70, 0, 9.8),"
                  " (14, 42, 0, 80, 0, 9.7);")
         && execute (
           "INSERT INTO results VALUES"
           " (100, 10, 1, 'n1', 5, 'n1', 'Alarm', 70, 'host', 'port'),"
           " (101, 10, 1, 'n2', 9, 'n2', 'Alarm', 60, 'host', 'port'),"
           " (110, 11, 1, 'n1', 6, 'n1', 'Alarm', 70, 'host', 'port'),"
           " (120, 12, 1, 'n1', 7, 'n1', 'Alarm', 70, 'host', 'port'),"
           " (130, 13, 1, 'n1', 9, 'n1', NULL, 70, 'host', 'port'),"
           " (140, 14, 1, 'n1', 4, 'n1', 'Alarm', 70, 'host', 'port');")
         && execute ("INSERT INTO overrides VALUES"
                     " (8, 'n1', 42, 0, 1, 100, NULL, NULL, 'match', 1);");
}

static void
test_metadata ()
{
  expect_value ("all split functions are installed and STABLE",
                "SELECT count(*)::text FROM pg_proc JOIN pg_namespace"
                " ON pg_namespace.oid = pg_proc.pronamespace"
                " WHERE pg_namespace.nspname = current_schema ()"
                " AND proname IN ('report_severity_cached',"
                "                 'report_severity_dynamic', 'report_severity')"
                " AND provolatile = 's';",
                "3");
}

static void
test_cached_severity ()
{
  expect_value ("valid cache rows are used and mismatched keys are ignored",
                "SELECT round (report_severity (1, 0, 70)::numeric, 1)::text;",
                "8.2");
  expect_value ("wrong user, override and min-QoD keys fall back",
                "SELECT report_severity (14, 0, 70)::text;", "4");
  expect_value ("a NULL cache value falls back",
                "SELECT report_severity (11, 0, 70)::text;", "6");
  expect_value ("an expired cache value falls back",
                "SELECT report_severity (12, 0, 70)::text;", "7");
}

static void
test_dynamic_severity_branches ()
{
  expect_value ("static severity without overrides",
                "SELECT report_severity (10, 0, 70)::text;", "5");
  expect_value ("static severity with overrides",
                "SELECT report_severity (10, 1, 70)::text;", "8");
  expect_value ("minimum QoD is applied",
                "SELECT report_severity (10, 0, 60)::text;", "9");
  expect_value ("a NULL result type has zero severity",
                "SELECT report_severity (13, 0, 70)::text;", "0");
  expect_null ("empty results stay NULL",
               "SELECT report_severity (99, 0, 70)::text;");

  execute ("UPDATE test_control SET dynamic = true;");
  expect_value ("dynamic severity without overrides",
                "SELECT report_severity (10, 0, 70)::text;", "15");
  expect_value ("dynamic severity with overrides",
                "SELECT report_severity (10, 1, 70)::text;", "8");
  expect_value ("a NULL result type remains zero in dynamic mode",
                "SELECT report_severity (13, 0, 70)::text;", "0");
}

static void
test_dynamic_function_is_lazy ()
{
  PGresult *result;

  execute ("CREATE OR REPLACE FUNCTION report_severity_dynamic"
           " (report integer, overrides integer, min_qod integer)"
           " RETURNS double precision AS $$"
           " BEGIN RAISE EXCEPTION 'dynamic branch invoked'; END;"
           " $$ LANGUAGE plpgsql STABLE;");

  expect_value ("a cache hit does not invoke the dynamic function",
                "SELECT round (report_severity (1, 0, 70)::numeric, 1)::text;",
                "8.2");

  execute ("SAVEPOINT dynamic_branch;");
  result = PQexec (connection, "SELECT report_severity (10, 0, 70);");
  if (PQresultStatus (result) != PGRES_FATAL_ERROR
      || strstr (PQresultErrorMessage (result), "dynamic branch invoked")
           == NULL)
    {
      fprintf (stderr, "a cache miss did not invoke the dynamic function\n");
      failures++;
    }
  PQclear (result);
  execute ("ROLLBACK TO SAVEPOINT dynamic_branch;");
}

int
main ()
{
  const char *connection_uri = getenv ("GVMD_TEST_DATABASE_URI");

  if (connection_uri == NULL || connection_uri[0] == '\0')
    {
      fprintf (stderr, "GVMD_TEST_DATABASE_URI is not set; skipping test\n");
      return TEST_SKIPPED;
    }

  connection = PQconnectdb (connection_uri);
  if (PQstatus (connection) != CONNECTION_OK)
    {
      fprintf (stderr, "Could not connect to PostgreSQL: %s",
               PQerrorMessage (connection));
      PQfinish (connection);
      return EXIT_FAILURE;
    }

  if (create_fixture () && load_fixture_data ())
    {
      test_metadata ();
      test_cached_severity ();
      test_dynamic_severity_branches ();
      test_dynamic_function_is_lazy ();
    }

  PQexec (connection, "ROLLBACK;");
  PQfinish (connection);

  return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
