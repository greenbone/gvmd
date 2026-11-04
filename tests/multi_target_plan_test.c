/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "../src/multi_target_plan.h"
#include <assert.h>

int
main (void)
{
  const char *ids[] = {
    "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
  };
  const char *duplicate[] = {ids[0], ids[0]};
  const char *case_duplicate[] = {ids[0], "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA"};
  const char *invalid[] = {"<target id=evil>"};
  multi_target_host_t hosts[6] = {
    {ids[0], "1"}, {ids[0], "2"}, {ids[0], "3"},
    {ids[1], "4"}, {ids[1], "5"}, {ids[1], "6"}
  };
  size_t groups[6], group_count;
  assert (multi_target_validate_ids (ids, 2) == MULTI_TARGET_OK);
  assert (multi_target_validate_ids (ids, 0) == MULTI_TARGET_EMPTY);
  assert (multi_target_validate_ids (duplicate, 2)
          == MULTI_TARGET_DUPLICATE);
  assert (multi_target_validate_ids (case_duplicate, 2)
          == MULTI_TARGET_DUPLICATE);
  assert (multi_target_validate_ids (invalid, 1)
          == MULTI_TARGET_INVALID_ID);
  assert (multi_target_partition_hosts (hosts, 6, groups, &group_count)
          == MULTI_TARGET_OK);
  assert (group_count == 2);
  assert (groups[0] == groups[1] && groups[1] == groups[2]);
  assert (groups[3] == groups[4] && groups[4] == groups[5]);
  assert (groups[0] != groups[3]);
  hosts[2].source_target_id = "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA";
  assert (multi_target_partition_hosts (hosts, 6, groups, &group_count)
          == MULTI_TARGET_OK);
  assert (group_count == 2);
  assert (groups[2] == groups[0]);
  hosts[2].host = "";
  assert (multi_target_partition_hosts (hosts, 6, groups, &group_count)
          == MULTI_TARGET_INVALID_HOST);
  return 0;
}
