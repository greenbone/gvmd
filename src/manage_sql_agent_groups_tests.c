/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_sql_agent_groups.c"

#include <cgreen/cgreen.h>

Describe (manage_sql_agent_groups);

static int commit_count;
static int delete_membership_count;
static int copy_init_count;
static int copy_append_count;
static int copy_commit_count;

BeforeEach (manage_sql_agent_groups)
{
  commit_count = 0;
  delete_membership_count = 0;
  copy_init_count = 0;
  copy_append_count = 0;
  copy_commit_count = 0;
}

AfterEach (manage_sql_agent_groups)
{
}

int
__wrap_sql_int_ps (const char *statement, ...)
{
  (void) statement;
  return 0;
}

int
__wrap_sql_int (const char *statement, ...)
{
  (void) statement;
  return 0;
}

void
__wrap_sql_begin_immediate ()
{
}

void
__wrap_sql_ps (const char *statement, ...)
{
  (void) statement;
}

void
__wrap_sql (const char *statement, ...)
{
  if (g_str_has_prefix (statement, "DELETE FROM agent_group_agents "))
    delete_membership_count++;
}

void
__wrap_sql_commit ()
{
  commit_count++;
}

int
__wrap_sql_int64 (long long int *value, const char *statement, ...)
{
  (void) statement;
  *value = 7;
  return 0;
}

char *
__wrap_scanner_uuid (scanner_t scanner)
{
  assert_that (scanner, is_equal_to (7));
  return g_strdup ("scanner-uuid");
}

int
__wrap_acl_user_has_access_uuid (const char *type, const char *uuid,
                                 const char *permission, int trash)
{
  (void) type;
  (void) uuid;
  (void) permission;
  (void) trash;
  return 1;
}

int
__wrap_agent_id_by_uuid_and_scanner (const gchar *uuid, scanner_t scanner,
                                     agent_t *agent)
{
  assert_that (uuid,
               is_equal_to_string ("48c1b767-b699-45a4-a8bb-3325f2865913"));
  assert_that (scanner, is_equal_to (7));
  *agent = 11;
  return 0;
}

gboolean
__wrap_agent_authorized (const gchar *uuid, scanner_t scanner)
{
  (void) uuid;
  (void) scanner;
  return TRUE;
}

void
__wrap_db_copy_buffer_init (db_copy_buffer_t *buffer, int size,
                            const gchar *statement)
{
  (void) buffer;
  (void) size;
  (void) statement;
  copy_init_count++;
}

int
__wrap_db_copy_buffer_append_printf (db_copy_buffer_t *buffer,
                                     const char *format, ...)
{
  (void) buffer;
  (void) format;
  copy_append_count++;
  return 0;
}

int
__wrap_db_copy_buffer_commit (db_copy_buffer_t *buffer, gboolean finalize)
{
  (void) buffer;
  (void) finalize;
  copy_commit_count++;
  return 0;
}

void
__wrap_db_copy_buffer_cleanup (db_copy_buffer_t *buffer)
{
  (void) buffer;
}

static agent_group_data_t
test_group_data ()
{
  agent_group_data_t data = agent_group_data_new ();

  data->name = g_strdup ("group");
  data->comment = g_strdup ("");
  data->scheduler_cron_time = g_strdup ("0 1 * * *");
  return data;
}

Ensure (manage_sql_agent_groups, omitted_agents_preserves_membership)
{
  agent_group_data_t data = test_group_data ();

  assert_that (modify_agent_group (3, data, NULL),
               is_equal_to (AGENT_GROUP_RESP_SUCCESS));
  assert_that (delete_membership_count, is_equal_to (0));
  assert_that (copy_init_count, is_equal_to (0));
  assert_that (commit_count, is_equal_to (1));

  agent_group_data_free (data);
}

Ensure (manage_sql_agent_groups, empty_agents_clears_without_copy)
{
  agent_group_data_t data = test_group_data ();
  agent_uuid_list_t agent_uuids = agent_uuid_list_new (0);

  assert_that (modify_agent_group (3, data, agent_uuids),
               is_equal_to (AGENT_GROUP_RESP_SUCCESS));
  assert_that (delete_membership_count, is_equal_to (1));
  assert_that (copy_init_count, is_equal_to (0));
  assert_that (commit_count, is_equal_to (1));

  agent_uuid_list_free (agent_uuids);
  agent_group_data_free (data);
}

Ensure (manage_sql_agent_groups, non_empty_agents_replaces_with_copy)
{
  agent_group_data_t data = test_group_data ();
  agent_uuid_list_t agent_uuids = agent_uuid_list_new (1);

  agent_uuids->agent_uuids[0] =
    g_strdup ("48c1b767-b699-45a4-a8bb-3325f2865913");

  assert_that (modify_agent_group (3, data, agent_uuids),
               is_equal_to (AGENT_GROUP_RESP_SUCCESS));
  assert_that (delete_membership_count, is_equal_to (1));
  assert_that (copy_init_count, is_equal_to (1));
  assert_that (copy_append_count, is_equal_to (1));
  assert_that (copy_commit_count, is_equal_to (1));
  assert_that (commit_count, is_equal_to (1));

  agent_uuid_list_free (agent_uuids);
  agent_group_data_free (data);
}

Ensure (manage_sql_agent_groups,
        empty_membership_snapshot_remains_explicit_for_rollback)
{
  agent_uuid_list_t agent_uuids = NULL;

  assert_that (get_agent_group_agent_uuids (3, &agent_uuids),
               is_equal_to (AGENT_GROUP_RESP_SUCCESS));
  assert_that (agent_uuids, is_not_null);
  assert_that (agent_uuids->count, is_equal_to (0));

  agent_uuid_list_free (agent_uuids);
}

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite = create_test_suite ();

  add_test_with_context (suite, manage_sql_agent_groups,
                         omitted_agents_preserves_membership);
  add_test_with_context (suite, manage_sql_agent_groups,
                         empty_agents_clears_without_copy);
  add_test_with_context (suite, manage_sql_agent_groups,
                         non_empty_agents_replaces_with_copy);
  add_test_with_context (
    suite, manage_sql_agent_groups,
    empty_membership_snapshot_remains_explicit_for_rollback);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);
  return ret;
}
