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
candidate_new (const char *key, unsigned match_mask, time_t last_seen,
               const char *ip, const char *hostname, const char *mac)
{
  asset_candidate_t c;
  memset (&c, 0, sizeof (c));
  c.asset_key = key;
  c.match_mask = match_mask;
  c.last_seen = last_seen;
  c.ip = ip;
  c.hostname = hostname;
  c.mac = mac;

  return c;
}

static void
assert_merge_indices_equal (const asset_merge_decision_t *d,
                            const size_t *expected,
                            size_t expected_len)
{
  if (expected_len == 0)
    {
      assert_that (d->merge_indices, is_null);
      return;
    }

  assert_that (d->merge_indices, is_not_null);
  assert_that (d->merge_indices->len, is_equal_to (expected_len));

  for (size_t i = 0; i < expected_len; i++)
    {
      size_t got = g_array_index (d->merge_indices, size_t, i);
      assert_that (got, is_equal_to (expected[i]));
    }
}

Ensure (manage_asset_keys, returns_new_key_if_observed_is_null)
{
  asset_candidate_t candidates[] = {
    candidate_new ("k1", MATCH_MAC, 10, NULL, NULL, "m"),
  };

  asset_merge_decision_t d;
  asset_keys_target_merge_decide (NULL, candidates, 1, &d);

  assert_true (d.needs_new_key);
  assert_that (d.selected_key, is_null);
  assert_that (d.merge_indices, is_null);

  asset_merge_decision_reset (&d);
}

Ensure (manage_asset_keys, returns_new_key_if_observed_has_no_properties)
{
  asset_target_obs_t o = obs ("", "", "");

  asset_candidate_t candidates[] = {
    candidate_new ("k1", MATCH_MAC, 10, NULL, NULL, "m"),
  };

  asset_merge_decision_t d;
  asset_keys_target_merge_decide (&o, candidates, 1, &d);

  assert_true (d.needs_new_key);
  assert_that (d.selected_key, is_null);
  assert_that (d.merge_indices, is_null);

  asset_merge_decision_reset (&d);
}

Ensure (manage_asset_keys, returns_new_key_if_no_candidates)
{
  asset_target_obs_t o = obs ("1.2.3.4", NULL, NULL);

  asset_merge_decision_t d;
  asset_keys_target_merge_decide (&o, NULL, 0, &d);

  assert_true (d.needs_new_key);
  assert_that (d.selected_key, is_null);
  assert_that (d.merge_indices, is_null);

  asset_merge_decision_reset (&d);
}

Ensure (manage_asset_keys, returns_new_key_if_candidates_do_not_match)
{
  asset_target_obs_t o = obs ("1.2.3.4", "h", "m");

  asset_candidate_t candidates[] = {
    candidate_new ("k1", 0, 100, "1.2.3.4", "h", "m"),
    candidate_new ("k2", 0, 200, "1.2.3.4", "h", "m"),
  };

  asset_merge_decision_t d;
  asset_keys_target_merge_decide (&o, candidates, 2, &d);

  assert_true (d.needs_new_key);
  assert_that (d.selected_key, is_null);
  assert_that (d.merge_indices, is_null);

  asset_merge_decision_reset (&d);
}

Ensure (manage_asset_keys, ignores_empty_asset_keys)
{
  asset_target_obs_t o = obs ("1.2.3.4", "h", "m");

  asset_candidate_t candidates[] = {
    candidate_new ("", MATCH_MAC, 999, NULL, NULL, "m"),
    candidate_new (NULL, MATCH_MAC, 999, NULL, NULL, "m"),
    candidate_new ("k3", MATCH_IP, 10, "1.2.3.4", NULL, NULL),
  };

  asset_merge_decision_t d;
  asset_keys_target_merge_decide (&o, candidates, 3, &d);

  assert_false (d.needs_new_key);
  assert_string_equal (d.selected_key, "k3");
  assert_that (d.selected_index, is_equal_to (2));
  assert_merge_indices_equal (&d, NULL, 0);

  asset_merge_decision_reset (&d);
}

Ensure (manage_asset_keys, prefers_higher_score_mac_over_weak)
{
  asset_target_obs_t o = obs ("1.2.3.4", "h", "m");

  asset_candidate_t candidates[] = {
    candidate_new ("weak", MATCH_IP | MATCH_HOSTNAME, 999, "1.2.3.4", "h",
                   NULL),
    candidate_new ("strong", MATCH_MAC, 1, NULL, NULL, "m"),
  };

  asset_merge_decision_t d;
  asset_keys_target_merge_decide (&o, candidates, 2, &d);

  assert_false (d.needs_new_key);
  assert_string_equal (d.selected_key, "strong");
  assert_that (d.selected_index, is_equal_to (1));

  size_t expected[] = {0};
  assert_merge_indices_equal (&d, expected, 1);

  asset_merge_decision_reset (&d);
}

Ensure (manage_asset_keys, decide_by_last_seen_when_score_equal)
{
  asset_target_obs_t o = obs ("1.2.3.4", "h", "m");

  asset_candidate_t candidates[] = {
    candidate_new ("older", MATCH_IP, 10, "1.2.3.4", NULL, NULL),
    candidate_new ("newer", MATCH_IP, 20, "1.2.3.4", NULL, NULL),
  };

  asset_merge_decision_t d;
  asset_keys_target_merge_decide (&o, candidates, 2, &d);

  assert_false (d.needs_new_key);
  assert_string_equal (d.selected_key, "newer");
  assert_that (d.selected_index, is_equal_to (1));

  size_t expected[] = {0};
  assert_merge_indices_equal (&d, expected, 1);

  asset_merge_decision_reset (&d);
}

Ensure (manage_asset_keys, merges_all_other_matching_candidates)
{
  asset_target_obs_t o = obs ("1.2.3.4", "h", "m");

  asset_candidate_t candidates[] = {
    candidate_new ("best", MATCH_MAC, 100, NULL, NULL, "m"),
    candidate_new ("also_match_ip", MATCH_IP, 200, "1.2.3.4", NULL, NULL),
    candidate_new ("also_match_host", MATCH_HOSTNAME, 300, NULL, "h", NULL),
    candidate_new ("no_match", 0, 999, "9.9.9.9", NULL, NULL),
    candidate_new ("", MATCH_IP, 999, "1.2.3.4", NULL, NULL),
  };

  asset_merge_decision_t d;
  asset_keys_target_merge_decide (&o, candidates, 5, &d);

  assert_false (d.needs_new_key);
  assert_string_equal (d.selected_key, "best");
  assert_that (d.selected_index, is_equal_to (0));

  size_t expected[] = {1, 2};
  assert_merge_indices_equal (&d, expected, 2);

  asset_merge_decision_reset (&d);
}

Ensure (manage_asset_keys, cleanup_asset_merge_decision)
{
  asset_target_obs_t o = obs ("1.2.3.4", "h", "m");

  asset_candidate_t candidates[] = {
    candidate_new ("best", MATCH_MAC, 100, NULL, NULL, "m"),
    candidate_new ("also_match_ip", MATCH_IP, 200, "1.2.3.4", NULL, NULL),
    candidate_new ("also_match_host", MATCH_HOSTNAME, 300, NULL, "h", NULL),
  };

  asset_merge_decision_t d;
  asset_keys_target_merge_decide (&o, candidates, 3, &d);

  asset_merge_decision_reset (&d);

  assert_that (d.merge_indices, is_null);
  assert_that (d.selected_key, is_null);
  assert_that (d.selected_index, is_equal_to (0));
  assert_that (d.needs_new_key, is_equal_to (0));
}

Ensure (manage_asset_keys, cleanup_asset_merge_decision_null_is_safe)
{
  asset_merge_decision_t *d = NULL;

  asset_merge_decision_reset (d);

  assert_that (d, is_null);
}

Ensure (manage_asset_keys, subset_returns_false_on_null_inputs)
{
  asset_target_obs_t o = obs ("1.2.3.4", "h", "m");

  asset_candidate_t c = candidate_new ("k", MATCH_IP, 1, "1.2.3.4", NULL, NULL);
  asset_candidate_t s = candidate_new ("k2", MATCH_MAC, 1, NULL, NULL, "m");

  assert_false (candidate_props_subset_of_selected_and_obs (NULL, &s, &o));
  assert_false (candidate_props_subset_of_selected_and_obs (&c, NULL, &o));
  assert_false (candidate_props_subset_of_selected_and_obs (&c, &s, NULL));
}

Ensure (manage_asset_keys, subset_mac_matches_selected_returns_true)
{
  asset_target_obs_t o = obs (NULL, NULL, "obs-mac");

  asset_candidate_t selected =
    candidate_new ("sel", MATCH_MAC, 1, NULL, NULL, "aa:bb:cc");
  asset_candidate_t cand =
    candidate_new ("c", MATCH_MAC, 1, NULL, NULL, "aa:bb:cc");

  assert_true (
    candidate_props_subset_of_selected_and_obs (&cand, &selected, &o));
}

Ensure (manage_asset_keys, subset_mac_matches_obs_returns_true)
{
  asset_target_obs_t o = obs (NULL, NULL, "aa:bb:cc");

  asset_candidate_t selected =
    candidate_new ("sel", MATCH_MAC, 1, NULL, NULL, "different");
  asset_candidate_t cand =
    candidate_new ("c", MATCH_MAC, 1, NULL, NULL, "aa:bb:cc");

  assert_true (
    candidate_props_subset_of_selected_and_obs (&cand, &selected, &o));
}

Ensure (manage_asset_keys, subset_mac_mismatch_returns_false)
{
  asset_target_obs_t o = obs (NULL, NULL, "obs-mac");

  asset_candidate_t selected =
    candidate_new ("sel", MATCH_MAC, 1, NULL, NULL, "sel-mac");
  asset_candidate_t cand =
    candidate_new ("c", MATCH_MAC, 1, NULL, NULL, "cand-mac");

  assert_false (
    candidate_props_subset_of_selected_and_obs (&cand, &selected, &o));
}

Ensure (manage_asset_keys, subset_hostname_matches_selected_returns_true)
{
  asset_target_obs_t o = obs (NULL, "obs-host", NULL);

  asset_candidate_t selected =
    candidate_new ("sel", MATCH_HOSTNAME, 1, NULL, "hostA", NULL);
  asset_candidate_t cand =
    candidate_new ("c", MATCH_HOSTNAME, 1, NULL, "hostA", NULL);

  assert_true (
    candidate_props_subset_of_selected_and_obs (&cand, &selected, &o));
}

Ensure (manage_asset_keys, subset_hostname_matches_obs_returns_true)
{
  asset_target_obs_t o = obs (NULL, "hostB", NULL);

  asset_candidate_t selected =
    candidate_new ("sel", MATCH_HOSTNAME, 1, NULL, "different", NULL);
  asset_candidate_t cand =
    candidate_new ("c", MATCH_HOSTNAME, 1, NULL, "hostB", NULL);

  assert_true (
    candidate_props_subset_of_selected_and_obs (&cand, &selected, &o));
}

Ensure (manage_asset_keys, subset_hostname_mismatch_returns_false)
{
  asset_target_obs_t o = obs (NULL, "obs-host", NULL);

  asset_candidate_t selected =
    candidate_new ("sel", MATCH_HOSTNAME, 1, NULL, "sel-host", NULL);
  asset_candidate_t cand =
    candidate_new ("c", MATCH_HOSTNAME, 1, NULL, "cand-host", NULL);

  assert_false (
    candidate_props_subset_of_selected_and_obs (&cand, &selected, &o));
}

Ensure (manage_asset_keys, subset_ip_matches_selected_returns_true)
{
  asset_target_obs_t o = obs ("9.9.9.9", NULL, NULL);

  asset_candidate_t selected =
    candidate_new ("sel", MATCH_IP, 1, "1.2.3.4", NULL, NULL);
  asset_candidate_t cand =
    candidate_new ("c", MATCH_IP, 1, "1.2.3.4", NULL, NULL);

  assert_true (
    candidate_props_subset_of_selected_and_obs (&cand, &selected, &o));
}

Ensure (manage_asset_keys, subset_ip_matches_obs_returns_true)
{
  asset_target_obs_t o = obs ("1.2.3.4", NULL, NULL);

  asset_candidate_t selected =
    candidate_new ("sel", MATCH_IP, 1, "9.9.9.9", NULL, NULL);
  asset_candidate_t cand =
    candidate_new ("c", MATCH_IP, 1, "1.2.3.4", NULL, NULL);

  assert_true (
    candidate_props_subset_of_selected_and_obs (&cand, &selected, &o));
}

Ensure (manage_asset_keys, subset_ip_mismatch_returns_false)
{
  asset_target_obs_t o = obs ("9.9.9.9", NULL, NULL);

  asset_candidate_t selected =
    candidate_new ("sel", MATCH_IP, 1, "1.1.1.1", NULL, NULL);
  asset_candidate_t cand =
    candidate_new ("c", MATCH_IP, 1, "2.2.2.2", NULL, NULL);

  assert_false (
    candidate_props_subset_of_selected_and_obs (&cand, &selected, &o));
}

Ensure (manage_asset_keys, subset_multiple_properties_all_covered_returns_true)
{
  asset_target_obs_t o = obs ("1.2.3.4", "hostB", "macC");

  asset_candidate_t selected =
    candidate_new ("sel", MATCH_MAC, 1, "9.9.9.9", "hostA", "macA");
  asset_candidate_t cand =
    candidate_new ("c", MATCH_MAC | MATCH_HOSTNAME | MATCH_IP, 1,
                   "1.2.3.4", "hostB", "macA");

  assert_true (
    candidate_props_subset_of_selected_and_obs (&cand, &selected, &o));
}

Ensure (manage_asset_keys,
        subset_multiple_properties_one_mismatch_returns_false)
{
  asset_target_obs_t o = obs ("1.2.3.4", "hostB", "macC");

  asset_candidate_t selected =
    candidate_new ("sel", MATCH_MAC, 1, "9.9.9.9", "hostA", "macA");
  asset_candidate_t cand =
    candidate_new ("c", MATCH_MAC | MATCH_HOSTNAME | MATCH_IP, 1,
                   "1.2.3.4", "hostX", "macA");

  assert_false (
    candidate_props_subset_of_selected_and_obs (&cand, &selected, &o));
}

Ensure (manage_asset_keys, subset_ignores_empty_string_properties)
{
  asset_target_obs_t o = obs ("1.2.3.4", "hostB", "macC");

  asset_candidate_t selected =
    candidate_new ("sel", MATCH_MAC, 1, "9.9.9.9", "hostA", "macA");
  asset_candidate_t cand =
    candidate_new ("c", MATCH_MAC | MATCH_HOSTNAME | MATCH_IP, 1,
                   "", "", "");

  assert_true (
    candidate_props_subset_of_selected_and_obs (&cand, &selected, &o));
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
  add_test_with_context (suite, manage_asset_keys,
                         subset_returns_false_on_null_inputs);
  add_test_with_context (suite, manage_asset_keys,
                         subset_mac_matches_selected_returns_true);
  add_test_with_context (suite, manage_asset_keys,
                         subset_mac_matches_obs_returns_true);
  add_test_with_context (suite, manage_asset_keys,
                         subset_mac_mismatch_returns_false);
  add_test_with_context (suite, manage_asset_keys,
                         subset_hostname_matches_selected_returns_true);
  add_test_with_context (suite, manage_asset_keys,
                         subset_hostname_matches_obs_returns_true);
  add_test_with_context (suite, manage_asset_keys,
                         subset_hostname_mismatch_returns_false);
  add_test_with_context (suite, manage_asset_keys,
                         subset_ip_matches_selected_returns_true);
  add_test_with_context (suite, manage_asset_keys,
                         subset_ip_matches_obs_returns_true);
  add_test_with_context (suite, manage_asset_keys,
                         subset_ip_mismatch_returns_false);
  add_test_with_context (suite, manage_asset_keys,
                         subset_multiple_properties_all_covered_returns_true);
  add_test_with_context (suite, manage_asset_keys,
                         subset_multiple_properties_one_mismatch_returns_false);
  add_test_with_context (suite, manage_asset_keys,
                         subset_ignores_empty_string_properties);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);
  return ret;
}