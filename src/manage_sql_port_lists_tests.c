/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_sql_port_lists.c"

#include <cgreen/cgreen.h>
#include <stdarg.h>

#define PORT_LIST 41
#define PORT_RANGE 51

typedef struct
{
  gboolean in_use;
  gboolean predefined;
  gboolean transaction_open;
  int commit_count;
  int rollback_count;
  int metadata_writes;
  int range_inserts;
  int range_deletes;
} port_list_model_t;

static port_list_model_t model;

static gchar *
query_string (const char *format, va_list args)
{
  return g_strdup_vprintf (format, args);
}

void
__wrap_sql_begin_immediate (void)
{
  model.transaction_open = TRUE;
}

void
__wrap_sql_commit (void)
{
  model.commit_count++;
  model.transaction_open = FALSE;
}

void
__wrap_sql_rollback (void)
{
  model.rollback_count++;
  model.transaction_open = FALSE;
}

int
__wrap_acl_user_may (const char *permission)
{
  (void) permission;
  return 1;
}

int
__wrap_acl_user_owns_uuid (const char *type, const char *uuid, int trash)
{
  (void) type;
  (void) uuid;
  (void) trash;
  return 1;
}

gboolean
__wrap_find_resource_with_permission (const char *type, const char *uuid,
                                      resource_t *resource,
                                      const char *permission, int trash)
{
  (void) permission;
  (void) trash;

  *resource = 0;
  if (strcmp (type, "port_list") == 0
      && strcmp (uuid, "port-list") == 0)
    *resource = PORT_LIST;
  return FALSE;
}

gboolean
__wrap_resource_with_name_exists (const char *name, const char *type,
                                  resource_t exclude)
{
  (void) name;
  (void) type;
  (void) exclude;
  return FALSE;
}

gchar *
__wrap_sql_quote (const char *value)
{
  return g_strdup (value);
}

int
__wrap_sql_int (const char *format, ...)
{
  va_list args;
  gchar *query;
  int result = 0;

  va_start (args, format);
  query = query_string (format, args);
  va_end (args);

  if (strstr (query, "SELECT predefined FROM port_lists"))
    result = model.predefined;
  else if (strstr (query, "SELECT count (*) FROM port_ranges WHERE uuid"))
    result = 1;
  else if (strstr (query, "FROM targets")
           && strstr (query, "WHERE port_list"))
    result = model.in_use;

  g_free (query);
  return result;
}

int
__wrap_sql_int64 (long long int *result, const char *format, ...)
{
  va_list args;
  gchar *query;

  va_start (args, format);
  query = query_string (format, args);
  va_end (args);

  if (strstr (query, "SELECT id FROM port_lists WHERE uuid"))
    *result = PORT_LIST;
  else if (strstr (query, "SELECT id FROM port_ranges WHERE uuid"))
    *result = PORT_RANGE;
  else if (strstr (query, "SELECT port_list FROM port_ranges WHERE id"))
    *result = PORT_LIST;
  else
    {
      g_free (query);
      return 1;
    }

  g_free (query);
  return 0;
}

char *
__wrap_sql_string (const char *format, ...)
{
  va_list args;
  gchar *query;
  char *result = NULL;

  va_start (args, format);
  query = query_string (format, args);
  va_end (args);

  if (strstr (query, "SELECT uuid FROM port_lists")
      && strstr (query, "SELECT port_list FROM port_ranges"))
    result = g_strdup ("port-list");

  g_free (query);
  return result;
}

void
__wrap_sql (const char *format, ...)
{
  va_list args;
  gchar *query;

  va_start (args, format);
  query = query_string (format, args);
  va_end (args);

  if (strstr (query, "UPDATE port_lists SET"))
    model.metadata_writes++;
  else if (strstr (query, "INSERT INTO port_ranges"))
    model.range_inserts++;
  else if (strstr (query, "DELETE FROM port_ranges WHERE id"))
    model.range_deletes++;

  g_free (query);
}

Describe (manage_sql_port_lists);
BeforeEach (manage_sql_port_lists)
{
  memset (&model, 0, sizeof (model));
  model.in_use = TRUE;
  current_credentials.uuid = "user-id";
}
AfterEach (manage_sql_port_lists)
{
  current_credentials.uuid = NULL;
}

Ensure (manage_sql_port_lists, reports_metadata_writability)
{
  assert_that (port_list_writable (PORT_LIST), is_equal_to (1));

  model.in_use = FALSE;
  assert_that (port_list_writable (PORT_LIST), is_equal_to (1));

  model.predefined = TRUE;
  assert_that (port_list_writable (PORT_LIST), is_equal_to (0));
}

Ensure (manage_sql_port_lists, modifies_metadata_while_referenced)
{
  int ret;

  ret = modify_port_list ("port-list", "Renamed list", "Updated comment");

  assert_that (ret, is_equal_to (0));
  assert_that (model.metadata_writes, is_equal_to (1));
  assert_that (model.commit_count, is_equal_to (1));
  assert_that (model.transaction_open, is_false);
}

Ensure (manage_sql_port_lists, rejects_range_creation_while_referenced)
{
  int ret;

  ret = create_port_range ("port-list", "TCP", "80", "80", NULL, NULL);

  assert_that (ret, is_equal_to (5));
  assert_that (model.range_inserts, is_equal_to (0));
  assert_that (model.rollback_count, is_equal_to (1));
  assert_that (model.transaction_open, is_false);
}

Ensure (manage_sql_port_lists, creates_range_while_unreferenced)
{
  int ret;

  model.in_use = FALSE;
  ret = create_port_range ("port-list", "TCP", "80", "80", NULL, NULL);

  assert_that (ret, is_equal_to (0));
  assert_that (model.range_inserts, is_equal_to (1));
  assert_that (model.commit_count, is_equal_to (1));
}

Ensure (manage_sql_port_lists, rejects_range_deletion_while_referenced)
{
  int ret;

  ret = delete_port_range ("port-range", 0);

  assert_that (ret, is_equal_to (1));
  assert_that (model.range_deletes, is_equal_to (0));
  assert_that (model.rollback_count, is_equal_to (1));
  assert_that (model.transaction_open, is_false);
}

Ensure (manage_sql_port_lists, deletes_range_while_unreferenced)
{
  int ret;

  model.in_use = FALSE;
  ret = delete_port_range ("port-range", 0);

  assert_that (ret, is_equal_to (0));
  assert_that (model.range_deletes, is_equal_to (1));
  assert_that (model.commit_count, is_equal_to (1));
}

Ensure (manage_sql_port_lists, preserves_resource_deletion_protection)
{
  int ret;

  ret = delete_port_list ("port-list", 0);

  assert_that (ret, is_equal_to (1));
  assert_that (model.rollback_count, is_equal_to (1));
  assert_that (model.transaction_open, is_false);
}

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();
  add_test_with_context (suite, manage_sql_port_lists,
                         reports_metadata_writability);
  add_test_with_context (suite, manage_sql_port_lists,
                         modifies_metadata_while_referenced);
  add_test_with_context (suite, manage_sql_port_lists,
                         rejects_range_creation_while_referenced);
  add_test_with_context (suite, manage_sql_port_lists,
                         creates_range_while_unreferenced);
  add_test_with_context (suite, manage_sql_port_lists,
                         rejects_range_deletion_while_referenced);
  add_test_with_context (suite, manage_sql_port_lists,
                         deletes_range_while_unreferenced);
  add_test_with_context (suite, manage_sql_port_lists,
                         preserves_resource_deletion_protection);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);
  return ret;
}
