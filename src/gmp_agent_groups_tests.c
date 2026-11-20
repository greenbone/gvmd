/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "gmp_agent_groups.c"

#include <cgreen/cgreen.h>
#include <gvm/util/xmlutils.h>

Describe (gmp_agent_groups);
BeforeEach (gmp_agent_groups)
{
}
AfterEach (gmp_agent_groups)
{
}

static agent_uuid_list_t
parse_membership_update (const gchar *xml)
{
  agent_uuid_list_t agent_uuids = NULL;
  const gchar *invalid_uuid = NULL;
  entity_t root = NULL;

  assert_that (parse_entity (xml, &root), is_equal_to (0));
  assert_that (
    parse_agent_group_membership_update (root, &agent_uuids, &invalid_uuid),
    is_true);
  assert_that (invalid_uuid, is_null);
  free_entity (root);

  return agent_uuids;
}

Ensure (gmp_agent_groups, omitted_agents_preserves_membership)
{
  agent_uuid_list_t agent_uuids =
    parse_membership_update ("<modify_agent_group/>");

  assert_that (agent_uuids, is_null);
}

Ensure (gmp_agent_groups, empty_agents_clears_membership)
{
  agent_uuid_list_t agent_uuids =
    parse_membership_update ("<modify_agent_group><agents/>"
                             "</modify_agent_group>");

  assert_that (agent_uuids, is_not_null);
  assert_that (agent_uuids->count, is_equal_to (0));

  agent_uuid_list_free (agent_uuids);
}

Ensure (gmp_agent_groups, non_empty_agents_replaces_membership)
{
  agent_uuid_list_t agent_uuids = parse_membership_update (
    "<modify_agent_group><agents>"
    "<agent id=\"48c1b767-b699-45a4-a8bb-3325f2865913\"/>"
    "<agent id=\"2a233e68-06af-4b0e-92ae-4741d3bbff79\"/>"
    "</agents></modify_agent_group>");

  assert_that (agent_uuids, is_not_null);
  assert_that (agent_uuids->count, is_equal_to (2));
  assert_that (agent_uuids->agent_uuids[0],
               is_equal_to_string ("48c1b767-b699-45a4-a8bb-3325f2865913"));
  assert_that (agent_uuids->agent_uuids[1],
               is_equal_to_string ("2a233e68-06af-4b0e-92ae-4741d3bbff79"));

  agent_uuid_list_free (agent_uuids);
}

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite = create_test_suite ();

  add_test_with_context (suite, gmp_agent_groups,
                         omitted_agents_preserves_membership);
  add_test_with_context (suite, gmp_agent_groups,
                         empty_agents_clears_membership);
  add_test_with_context (suite, gmp_agent_groups,
                         non_empty_agents_replaces_membership);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);
  return ret;
}
