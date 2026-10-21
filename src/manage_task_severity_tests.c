/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * @brief PostgreSQL integration tests for task_severity.
 */

#include "manage_task_severity_sql.h"

#include <libpq-fe.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TEST_SKIPPED 77
#define TEST_TASK_STATUS_DONE 1U

typedef struct
{
  const char *name;
  const char *sql;
  int latest_report;
} task_severity_variant_t;

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
expect_value (const char *variant, const char *description, const char *sql,
              const char *expected)
{
  PGresult *result = PQexec (connection, sql);

  if (PQresultStatus (result) != PGRES_TUPLES_OK || PQntuples (result) != 1
      || PQnfields (result) != 1)
    {
      fprintf (stderr, "%s: %s: query failed: %s", variant, description,
               PQerrorMessage (connection));
      failures++;
    }
  else if (PQgetisnull (result, 0, 0))
    {
      fprintf (stderr, "%s: %s: expected %s, got NULL\n", variant, description,
               expected);
      failures++;
    }
  else if (strcmp (PQgetvalue (result, 0, 0), expected))
    {
      fprintf (stderr, "%s: %s: expected %s, got %s\n", variant, description,
               expected, PQgetvalue (result, 0, 0));
      failures++;
    }

  PQclear (result);
}

static void
expect_null (const char *variant, const char *description, const char *sql)
{
  PGresult *result = PQexec (connection, sql);

  if (PQresultStatus (result) != PGRES_TUPLES_OK || PQntuples (result) != 1
      || PQnfields (result) != 1)
    {
      fprintf (stderr, "%s: %s: query failed: %s", variant, description,
               PQerrorMessage (connection));
      failures++;
    }
  else if (PQgetisnull (result, 0, 0) == 0)
    {
      fprintf (stderr, "%s: %s: expected NULL, got %s\n", variant, description,
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
            "CREATE SCHEMA task_severity_test_%ld;"
            "SET LOCAL search_path TO task_severity_test_%ld;",
            (long) getpid (), (long) getpid ());

  return execute ("BEGIN;") && execute (schema_sql)
         && execute ("CREATE TABLE tasks"
                     " (id integer PRIMARY KEY, target integer,"
                     "  agent_group integer, oci_image_target integer,"
                     "  web_application_target integer);")
         && execute ("CREATE TABLE reports"
                     " (id integer PRIMARY KEY, task integer,"
                     "  scan_run_status integer, creation_time integer,"
                     "  date integer);")
         && execute ("CREATE TABLE test_calls"
                     " (report integer, overrides integer, min_qod integer);")
         && execute ("CREATE FUNCTION report_severity"
                     " (report integer, overrides integer, min_qod integer)"
                     " RETURNS double precision AS $$"
                     " BEGIN"
                     "   IF report IS NULL THEN"
                     "     RAISE EXCEPTION 'report_severity called with NULL';"
                     "   END IF;"
                     "   INSERT INTO test_calls VALUES"
                     "     (report, overrides, min_qod);"
                     "   RETURN report * 10000 + overrides * 100 + min_qod;"
                     " END;"
                     " $$ LANGUAGE plpgsql;");
}

static int
load_fixture_data ()
{
  return execute ("INSERT INTO tasks VALUES"
                  " (1, 1, 0, 0, 0),"
                  " (2, 1, 0, 0, 0),"
                  " (3, 1, 0, 0, 0),"
                  " (4, 0, 0, 0, 0);")
         && execute ("INSERT INTO reports VALUES"
                     " (20, 2, 0, 100, 100),"
                     " (30, 3, 1, 300, 100),"
                     " (31, 3, 1, 200, 400),"
                     " (32, 3, 0, 500, 500),"
                     " (40, 4, 1, 600, 600);");
}

static void
reset_calls ()
{
  execute ("TRUNCATE test_calls;");
}

static void
test_variant (const task_severity_variant_t *variant)
{
  char create_sql[4096];
  char expected[32];

  snprintf (create_sql, sizeof (create_sql), variant->sql,
            TEST_TASK_STATUS_DONE);
  if (execute (create_sql) == 0)
    return;

  reset_calls ();
  expect_null (variant->name, "a task without reports stays NULL",
               "SELECT task_severity (1, 2, 73)::text;");
  expect_value (variant->name, "no-report lookup skips report_severity",
                "SELECT count(*)::text FROM test_calls;", "0");

  reset_calls ();
  expect_null (variant->name, "a non-completed report stays NULL",
               "SELECT task_severity (2, 2, 73)::text;");
  expect_value (variant->name, "non-completed reports skip report_severity",
                "SELECT count(*)::text FROM test_calls;", "0");

  reset_calls ();
  expect_null (variant->name, "a targetless task stays NULL",
               "SELECT task_severity (4, 2, 73)::text;");
  expect_value (variant->name, "targetless tasks skip report_severity",
                "SELECT count(*)::text FROM test_calls;", "0");

  reset_calls ();
  expect_null (variant->name, "a missing task stays NULL",
               "SELECT task_severity (999, 2, 73)::text;");
  expect_value (variant->name, "missing tasks skip report_severity",
                "SELECT count(*)::text FROM test_calls;", "0");

  reset_calls ();
  snprintf (expected, sizeof (expected), "%d",
            variant->latest_report * 10000 + 2 * 100 + 73);
  expect_value (variant->name,
                "the latest completed report and arguments are preserved",
                "SELECT task_severity (3, 2, 73)::text;", expected);
  expect_value (variant->name, "report_severity is called exactly once",
                "SELECT count(*)::text FROM test_calls;", "1");
}

int
main ()
{
  const char *connection_uri = getenv ("GVMD_TEST_DATABASE_URI");
  const task_severity_variant_t variants[] = {
    {"database version 277", TASK_SEVERITY_SQL_V277, 30},
    {"database version 262", TASK_SEVERITY_SQL_V262, 30},
    {"database version 245", TASK_SEVERITY_SQL_V245, 30},
    {"database version 189", TASK_SEVERITY_SQL_V189, 31},
  };
  size_t index;

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
    for (index = 0; index < sizeof (variants) / sizeof (variants[0]); index++)
      test_variant (&variants[index]);

  PQexec (connection, "ROLLBACK;");
  PQfinish (connection);

  return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
