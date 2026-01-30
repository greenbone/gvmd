/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_asset_keys.c"

#include <cgreen/cgreen.h>

Describe (manage_asset_keys);

BeforeEach (manage_asset_keys)
{
}

AfterEach (manage_asset_keys)
{
}

static asset_target_obs_t
obs (const char *ip, const char *hostname, const char *mac)
{
  asset_target_obs_t o;
  o.ip = ip;
  o.hostname = hostname;
  o.mac = mac;
  return o;
}

static asset_candidate_t
candidate_new (const char *key, unsigned match_mask, time_t last_seen)
{
  asset_candidate_t c;
  memset (&c, 0, sizeof (c));
  c.asset_key = key;
  c.match_mask = match_mask;
  c.last_seen = last_seen;
  return c;
}

static void
assert_merge_indices_equal (const asset_merge_decision_t *d,
                            const size_t *expected,
                            size_t expected_len)
{
  assert_that (d->merge_indices_len, is_equal_to (expected_len));

  for (size_t i = 0; i < expected_len; i++)
  assert_that (d->merge_indices[i], is_equal_to (expected[i]));
}

Ensure (manage_asset_keys, returns_new_key_if_observed_is_null)
{
  asset_candidate_t candidates[] = {
    candidate_new ("k1", MATCH_MAC, 10),
  };

  asset_merge_decision_t d =
    asset_keys_target_merge_decide (NULL, candidates, 1);

  assert_true (d.needs_new_key);
  assert_that (d.selected_key, is_null);
  assert_that (d.merge_indices_len, is_equal_to (0));
  asset_merge_decision_free (&d);
}

Ensure (manage_asset_keys, returns_new_key_if_observed_has_no_properties)
{
  asset_target_obs_t o = obs ("", "", "");

  asset_candidate_t candidates[] = {
    candidate_new ("k1", MATCH_MAC, 10),
  };

  asset_merge_decision_t d =
    asset_keys_target_merge_decide (&o, candidates, 1);

  assert_true (d.needs_new_key);
  assert_that (d.selected_key, is_null);
  assert_that (d.merge_indices_len, is_equal_to (0));
  asset_merge_decision_free (&d);
}

Ensure (manage_asset_keys, returns_new_key_if_no_candidates)
{
  asset_target_obs_t o = obs ("1.2.3.4", NULL, NULL);

  asset_merge_decision_t d =
    asset_keys_target_merge_decide (&o, NULL, 0);

  assert_true (d.needs_new_key);
  assert_that (d.selected_key, is_null);
  assert_that (d.merge_indices_len, is_equal_to (0));
  asset_merge_decision_free (&d);
}

Ensure (manage_asset_keys, returns_new_key_if_candidates_do_not_match)
{
  asset_target_obs_t o = obs ("1.2.3.4", "h", "m");

  asset_candidate_t candidates[] = {
    candidate_new ("k1", 0, 100),
    candidate_new ("k2", 0, 200),
  };

  asset_merge_decision_t d =
    asset_keys_target_merge_decide (&o, candidates, 2);

  assert_true (d.needs_new_key);
  assert_that (d.selected_key, is_null);
  assert_that (d.merge_indices_len, is_equal_to (0));
  asset_merge_decision_free (&d);
}

Ensure (manage_asset_keys, ignores_empty_asset_keys)
{
  asset_target_obs_t o = obs ("1.2.3.4", "h", "m");

  asset_candidate_t candidates[] = {
    candidate_new ("", MATCH_MAC, 999),
    candidate_new (NULL, MATCH_MAC, 999),
    candidate_new ("k3", MATCH_IP, 10),
  };

  asset_merge_decision_t d =
    asset_keys_target_merge_decide (&o, candidates, 3);

  assert_false (d.needs_new_key);
  assert_string_equal (d.selected_key, "k3");
  assert_that (d.selected_index, is_equal_to (2));
  assert_that (d.merge_indices_len, is_equal_to (0));
  asset_merge_decision_free (&d);
}

Ensure (manage_asset_keys, prefers_higher_score_mac_over_weak)
{
  asset_target_obs_t o = obs ("1.2.3.4", "h", "m");

  asset_candidate_t candidates[] = {
    candidate_new ("weak", MATCH_IP | MATCH_HOSTNAME, 999),
    candidate_new ("strong", MATCH_MAC, 1),
  };

  asset_merge_decision_t d =
    asset_keys_target_merge_decide (&o, candidates, 2);

  assert_false (d.needs_new_key);
  assert_string_equal (d.selected_key, "strong");
  assert_that (d.selected_index, is_equal_to (1));

  size_t expected[] = {0};
  assert_merge_indices_equal (&d, expected, 1);

  asset_merge_decision_free (&d);
}

Ensure (manage_asset_keys, decide_by_last_seen_when_score_equal)
{
  asset_target_obs_t o = obs ("1.2.3.4", "h", "m");

  asset_candidate_t candidates[] = {
    candidate_new ("older", MATCH_IP, 10),
    candidate_new ("newer", MATCH_IP, 20),
  };

  asset_merge_decision_t d =
    asset_keys_target_merge_decide (&o, candidates, 2);

  assert_false (d.needs_new_key);
  assert_string_equal (d.selected_key, "newer");
  assert_that (d.selected_index, is_equal_to (1));

  size_t expected[] = {0};
  assert_merge_indices_equal (&d, expected, 1);

  asset_merge_decision_free (&d);
}

Ensure (manage_asset_keys, merges_all_other_matching_candidates)
{
  asset_target_obs_t o = obs ("1.2.3.4", "h", "m");

  asset_candidate_t candidates[] = {
    candidate_new ("best", MATCH_MAC, 100),
    candidate_new ("also_match_ip", MATCH_IP, 200),
    candidate_new ("also_match_host", MATCH_HOSTNAME, 300),
    candidate_new ("no_match", 0, 999),
    candidate_new ("", MATCH_IP, 999),
  };

  asset_merge_decision_t d =
    asset_keys_target_merge_decide (&o, candidates, 5);

  assert_false (d.needs_new_key);
  assert_string_equal (d.selected_key, "best");
  assert_that (d.selected_index, is_equal_to (0));

  size_t expected[] = {1, 2};
  assert_merge_indices_equal (&d, expected, 2);

  asset_merge_decision_free (&d);
}

Ensure (manage_asset_keys, cleanup_asset_merge_decision)
{
  asset_target_obs_t o = obs ("1.2.3.4", "h", "m");

  asset_candidate_t candidates[] = {
    candidate_new ("best", MATCH_MAC, 100),
    candidate_new ("also_match_ip", MATCH_IP, 200),
    candidate_new ("also_match_host", MATCH_HOSTNAME, 300),
    candidate_new ("no_match", 0, 999),
    candidate_new ("", MATCH_IP, 999),
  };

  asset_merge_decision_t d =
    asset_keys_target_merge_decide (&o, candidates, 5);

  asset_merge_decision_free (&d);

  assert_that (d.merge_indices, is_null);
  assert_that (d.merge_indices_len, is_equal_to (0));
  assert_that (d.merge_indices_len, is_equal_to (0));
  assert_that (d.selected_key, is_null);
  assert_that (d.selected_index, is_equal_to (0));
  assert_that (d.needs_new_key, is_equal_to (0));
}

Ensure (manage_asset_keys, cleanup_asset_merge_decision_null_is_safe)
{
  asset_merge_decision_t *d = NULL;

  asset_merge_decision_free (d);

  assert_that (d, is_null);
}

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite = create_test_suite ();

  add_test_with_context (suite, manage_asset_keys,
                         returns_new_key_if_observed_is_null);
  add_test_with_context (suite, manage_asset_keys,
                         returns_new_key_if_observed_has_no_properties);
  add_test_with_context (suite, manage_asset_keys,
                         returns_new_key_if_no_candidates);
  add_test_with_context (suite, manage_asset_keys,
                         returns_new_key_if_candidates_do_not_match);
  add_test_with_context (suite, manage_asset_keys, ignores_empty_asset_keys);
  add_test_with_context (suite, manage_asset_keys,
                         prefers_higher_score_mac_over_weak);
  add_test_with_context (suite, manage_asset_keys,
                         decide_by_last_seen_when_score_equal);
  add_test_with_context (suite, manage_asset_keys,
                         merges_all_other_matching_candidates);
  add_test_with_context (suite, manage_asset_keys,
                         cleanup_asset_merge_decision);
  add_test_with_context (suite, manage_asset_keys,
                         cleanup_asset_merge_decision_null_is_safe);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);
  return ret;
}