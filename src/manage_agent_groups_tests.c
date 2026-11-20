/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_agent_groups.c"

#include <cgreen/cgreen.h>

Describe (manage_agent_groups);
BeforeEach (manage_agent_groups)
{
}
AfterEach (manage_agent_groups)
{
}

static agent_uuid_list_t
uuid_list (const gchar *uuid)
{
  agent_uuid_list_t list = agent_uuid_list_new (uuid ? 1 : 0);

  if (uuid)
    list->agent_uuids[0] = g_strdup (uuid);

  return list;
}

Ensure (manage_agent_groups, clear_syncs_formerly_assigned_agents)
{
  agent_uuid_list_t old_agents =
    uuid_list ("48c1b767-b699-45a4-a8bb-3325f2865913");
  agent_uuid_list_t replacement_agents = uuid_list (NULL);
  agent_uuid_list_t sync_agents =
    agent_uuid_list_union (old_agents, replacement_agents);

  assert_that (sync_agents, is_not_null);
  assert_that (sync_agents->count, is_equal_to (1));
  assert_that (sync_agents->agent_uuids[0],
               is_equal_to_string ("48c1b767-b699-45a4-a8bb-3325f2865913"));

  agent_uuid_list_free (sync_agents);
  agent_uuid_list_free (replacement_agents);
  agent_uuid_list_free (old_agents);
}

Ensure (manage_agent_groups, replacement_syncs_removed_and_added_agents)
{
  agent_uuid_list_t old_agents =
    uuid_list ("48c1b767-b699-45a4-a8bb-3325f2865913");
  agent_uuid_list_t replacement_agents =
    uuid_list ("2a233e68-06af-4b0e-92ae-4741d3bbff79");
  agent_uuid_list_t sync_agents =
    agent_uuid_list_union (old_agents, replacement_agents);

  assert_that (sync_agents, is_not_null);
  assert_that (sync_agents->count, is_equal_to (2));
  assert_that (sync_agents->agent_uuids[0],
               is_equal_to_string ("48c1b767-b699-45a4-a8bb-3325f2865913"));
  assert_that (sync_agents->agent_uuids[1],
               is_equal_to_string ("2a233e68-06af-4b0e-92ae-4741d3bbff79"));

  agent_uuid_list_free (sync_agents);
  agent_uuid_list_free (replacement_agents);
  agent_uuid_list_free (old_agents);
}

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite = create_test_suite ();

  add_test_with_context (suite, manage_agent_groups,
                         clear_syncs_formerly_assigned_agents);
  add_test_with_context (suite, manage_agent_groups,
                         replacement_syncs_removed_and_added_agents);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);
  return ret;
}
