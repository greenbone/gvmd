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

/**
 * @brief Add an IP identifier to a test observation.
 *
 * @param[in,out] obs  Observation.
 * @param[in]     ip   IP value.
 */
static void
obs_add_ip (asset_target_obs_t *obs, const char *ip)
{
  asset_identifier_map_add (obs->identifiers, ASSET_IDENTIFIER_TYPE_IP, ip);
}

/**
 * @brief Add a hostname identifier to a test observation.
 *
 * @param[in,out] obs       Observation.
 * @param[in]     hostname  Hostname value.
 */
static void
obs_add_hostname (asset_target_obs_t *obs, const char *hostname)
{
  asset_identifier_map_add (obs->identifiers,
                            ASSET_IDENTIFIER_TYPE_HOSTNAME,
                            hostname);
}

/**
 * @brief Add a MAC identifier to a test observation.
 *
 * @param[in,out] obs  Observation.
 * @param[in]     mac  MAC value.
 */
static void
obs_add_mac (asset_target_obs_t *obs, const char *mac)
{
  asset_identifier_map_add (obs->identifiers, ASSET_IDENTIFIER_TYPE_MAC, mac);
}

/**
 * @brief Create a test candidate.
 *
 * @param[in] key        Asset key.
 * @param[in] last_seen  Last seen timestamp.
 *
 * @return Initialized candidate. Must be freed with asset_candidate_free.
 */
static asset_candidate_t *
candidate_new_test (const char *key, time_t last_seen)
{
  asset_candidate_t *candidate;

  candidate = asset_candidate_new (key);
  if (!candidate)
    return NULL;

  candidate->last_seen = last_seen;

  return candidate;
}

/**
 * @brief Add an IP identifier to a test candidate.
 *
 * @param[in,out] candidate  Candidate.
 * @param[in]     ip         IP value.
 */
static void
candidate_add_ip (asset_candidate_t *candidate, const char *ip)
{
  asset_identifier_map_add (candidate->identifiers,
                            ASSET_IDENTIFIER_TYPE_IP,
                            ip);
}

/**
 * @brief Add a hostname identifier to a test candidate.
 *
 * @param[in,out] candidate  Candidate.
 * @param[in]     hostname   Hostname value.
 */
static void
candidate_add_hostname (asset_candidate_t *candidate, const char *hostname)
{
  asset_identifier_map_add (candidate->identifiers,
                            ASSET_IDENTIFIER_TYPE_HOSTNAME,
                            hostname);
}

/**
 * @brief Add a MAC identifier to a test candidate.
 *
 * @param[in,out] candidate  Candidate.
 * @param[in]     mac        MAC value.
 */
static void
candidate_add_mac (asset_candidate_t *candidate, const char *mac)
{
  asset_identifier_map_add (candidate->identifiers,
                            ASSET_IDENTIFIER_TYPE_MAC,
                            mac);
}

/**
 * @brief Copy candidate pointers into a flat array.
 *
 * The returned array is a shallow copy. The original candidates must stay alive
 * while the array is used.
 *
 * @param[in] candidates      Candidate pointer array.
 * @param[in] candidates_len  Number of candidates.
 *
 * @return Flat candidate array. Must be freed with g_free.
 */
static asset_candidate_t *
candidate_array_from_ptrs (asset_candidate_t **candidates,
                           size_t candidates_len)
{
  asset_candidate_t *array;

  array = g_malloc0 (candidates_len * sizeof (*array));

  for (size_t i = 0; i < candidates_len; i++)
    array[i] = *candidates[i];

  return array;
}

/**
 * @brief Free test candidates.
 *
 * @param[in] candidates      Candidate pointer array.
 * @param[in] candidates_len  Number of candidates.
 */
static void
candidate_ptrs_free (asset_candidate_t **candidates, size_t candidates_len)
{
  for (size_t i = 0; i < candidates_len; i++)
    asset_candidate_free (candidates[i]);
}

/**
 * @brief Assert merge indices match an expected list.
 *
 * @param[in] d             Decision.
 * @param[in] expected      Expected indices.
 * @param[in] expected_len  Number of expected indices.
 */
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
  asset_candidate_t *c1 = candidate_new_test ("k1", 10);
  candidate_add_mac (c1, "m");

  asset_candidate_t *ptrs[] = {c1};
  asset_candidate_t *candidates = candidate_array_from_ptrs (ptrs, 1);

  asset_merge_decision_t d;
  asset_keys_target_merge_decide (NULL, candidates, 1, &d);

  assert_true (d.needs_new_key);
  assert_that (d.selected_key, is_null);
  assert_that (d.merge_indices, is_null);

  asset_merge_decision_reset (&d);
  g_free (candidates);
  candidate_ptrs_free (ptrs, 1);
}

Ensure (manage_asset_keys, returns_new_key_if_observed_has_no_identifiers)
{
  asset_target_obs_t *o = asset_target_obs_new ();

  asset_candidate_t *c1 = candidate_new_test ("k1", 10);
  candidate_add_mac (c1, "m");

  asset_candidate_t *ptrs[] = {c1};
  asset_candidate_t *candidates = candidate_array_from_ptrs (ptrs, 1);

  asset_merge_decision_t d;
  asset_keys_target_merge_decide (o, candidates, 1, &d);

  assert_true (d.needs_new_key);
  assert_that (d.selected_key, is_null);
  assert_that (d.merge_indices, is_null);

  asset_merge_decision_reset (&d);
  asset_target_obs_free (o);
  g_free (candidates);
  candidate_ptrs_free (ptrs, 1);
}

Ensure (manage_asset_keys, returns_new_key_if_no_candidates)
{
  asset_target_obs_t *o = asset_target_obs_new ();
  obs_add_ip (o, "1.2.3.4");

  asset_merge_decision_t d;
  asset_keys_target_merge_decide (o, NULL, 0, &d);

  assert_true (d.needs_new_key);
  assert_that (d.selected_key, is_null);
  assert_that (d.merge_indices, is_null);

  asset_merge_decision_reset (&d);
  asset_target_obs_free (o);
}

Ensure (manage_asset_keys, returns_new_key_if_candidates_do_not_match)
{
  asset_target_obs_t *o = asset_target_obs_new ();
  obs_add_ip (o, "1.2.3.4");
  obs_add_hostname (o, "h");
  obs_add_mac (o, "m");

  asset_candidate_t *c1 = candidate_new_test ("k1", 100);
  candidate_add_ip (c1, "9.9.9.9");

  asset_candidate_t *c2 = candidate_new_test ("k2", 200);
  candidate_add_mac (c2, "other-mac");

  asset_candidate_t *ptrs[] = {c1, c2};
  asset_candidate_t *candidates = candidate_array_from_ptrs (ptrs, 2);

  asset_merge_decision_t d;
  asset_keys_target_merge_decide (o, candidates, 2, &d);

  assert_true (d.needs_new_key);
  assert_that (d.selected_key, is_null);
  assert_that (d.merge_indices, is_null);

  asset_merge_decision_reset (&d);
  asset_target_obs_free (o);
  g_free (candidates);
  candidate_ptrs_free (ptrs, 2);
}

Ensure (manage_asset_keys, ignores_empty_asset_keys)
{
  asset_target_obs_t *o = asset_target_obs_new ();
  obs_add_ip (o, "1.2.3.4");

  asset_candidate_t empty_key;
  memset (&empty_key, 0, sizeof (empty_key));
  empty_key.asset_key = "";
  empty_key.identifiers = asset_identifier_map_new ();
  asset_identifier_map_add (empty_key.identifiers,
                            ASSET_IDENTIFIER_TYPE_IP,
                            "1.2.3.4");

  asset_candidate_t null_key;
  memset (&null_key, 0, sizeof (null_key));
  null_key.asset_key = NULL;
  null_key.identifiers = asset_identifier_map_new ();
  asset_identifier_map_add (null_key.identifiers,
                            ASSET_IDENTIFIER_TYPE_IP,
                            "1.2.3.4");

  asset_candidate_t *valid = candidate_new_test ("k3", 10);
  candidate_add_ip (valid, "1.2.3.4");

  asset_candidate_t candidates[] = {empty_key, null_key, *valid};

  asset_merge_decision_t d;
  asset_keys_target_merge_decide (o, candidates, 3, &d);

  assert_false (d.needs_new_key);
  assert_string_equal (d.selected_key, "k3");
  assert_that (d.selected_index, is_equal_to (2));
  assert_merge_indices_equal (&d, NULL, 0);

  asset_merge_decision_reset (&d);
  asset_target_obs_free (o);
  g_hash_table_destroy (empty_key.identifiers);
  g_hash_table_destroy (null_key.identifiers);
  asset_candidate_free (valid);
}

Ensure (manage_asset_keys,
        creates_new_key_when_no_candidate_contains_all_observed_identifiers)
{
  asset_target_obs_t *o = asset_target_obs_new ();
  obs_add_ip (o, "1.2.3.4");
  obs_add_hostname (o, "h");
  obs_add_mac (o, "m");

  asset_candidate_t *ip_and_hostname =
    candidate_new_test ("ip_and_hostname", 999);
  candidate_add_ip (ip_and_hostname, "1.2.3.4");
  candidate_add_hostname (ip_and_hostname, "h");

  asset_candidate_t *mac_only = candidate_new_test ("mac_only", 1);
  candidate_add_mac (mac_only, "m");

  asset_candidate_t *ptrs[] = {ip_and_hostname, mac_only};
  asset_candidate_t *candidates = candidate_array_from_ptrs (ptrs, 2);

  asset_merge_decision_t d;
  asset_keys_target_merge_decide (o, candidates, 2, &d);

  assert_true (d.needs_new_key);
  assert_that (d.selected_key, is_null);
  assert_that (d.selected_index, is_equal_to (0));

  /*
   * Both candidates are subsets of the observation, so both should be merged
   * into the new asset key.
   */
  size_t expected[] = {0, 1};
  assert_merge_indices_equal (&d, expected, 2);

  asset_merge_decision_reset (&d);
  asset_target_obs_free (o);
  g_free (candidates);
  candidate_ptrs_free (ptrs, 2);
}

Ensure (manage_asset_keys, decide_by_last_seen_when_score_equal)
{
  asset_target_obs_t *o = asset_target_obs_new ();
  obs_add_ip (o, "1.2.3.4");

  asset_candidate_t *older = candidate_new_test ("older", 10);
  candidate_add_ip (older, "1.2.3.4");

  asset_candidate_t *newer = candidate_new_test ("newer", 20);
  candidate_add_ip (newer, "1.2.3.4");

  asset_candidate_t *ptrs[] = {older, newer};
  asset_candidate_t *candidates = candidate_array_from_ptrs (ptrs, 2);

  asset_merge_decision_t d;
  asset_keys_target_merge_decide (o, candidates, 2, &d);

  assert_false (d.needs_new_key);
  assert_string_equal (d.selected_key, "newer");
  assert_that (d.selected_index, is_equal_to (1));

  asset_merge_decision_reset (&d);
  asset_target_obs_free (o);
  g_free (candidates);
  candidate_ptrs_free (ptrs, 2);
}

Ensure (manage_asset_keys,
        reuses_existing_key_when_candidate_contains_observation)
{
  asset_target_obs_t *o = asset_target_obs_new ();
  obs_add_ip (o, "A");
  obs_add_ip (o, "B");

  asset_candidate_t *candidate = candidate_new_test ("old", 10);
  candidate_add_ip (candidate, "A");
  candidate_add_ip (candidate, "B");
  candidate_add_ip (candidate, "C");

  asset_candidate_t *ptrs[] = {candidate};
  asset_candidate_t *candidates = candidate_array_from_ptrs (ptrs, 1);

  asset_merge_decision_t d;
  asset_keys_target_merge_decide (o, candidates, 1, &d);

  assert_false (d.needs_new_key);
  assert_string_equal (d.selected_key, "old");
  assert_that (d.selected_index, is_equal_to (0));
  assert_merge_indices_equal (&d, NULL, 0);

  asset_merge_decision_reset (&d);
  asset_target_obs_free (o);
  g_free (candidates);
  candidate_ptrs_free (ptrs, 1);
}

Ensure (manage_asset_keys,
        creates_new_key_and_merges_candidate_when_observation_contains_candidate)
{
  asset_target_obs_t *o = asset_target_obs_new ();
  obs_add_ip (o, "A");
  obs_add_ip (o, "B");
  obs_add_ip (o, "C");

  asset_candidate_t *candidate = candidate_new_test ("old", 10);
  candidate_add_ip (candidate, "A");
  candidate_add_ip (candidate, "B");

  asset_candidate_t *ptrs[] = {candidate};
  asset_candidate_t *candidates = candidate_array_from_ptrs (ptrs, 1);

  asset_merge_decision_t d;
  asset_keys_target_merge_decide (o, candidates, 1, &d);

  assert_true (d.needs_new_key);
  assert_that (d.selected_key, is_null);

  size_t expected[] = {0};
  assert_merge_indices_equal (&d, expected, 1);

  asset_merge_decision_reset (&d);
  asset_target_obs_free (o);
  g_free (candidates);
  candidate_ptrs_free (ptrs, 1);
}

Ensure (manage_asset_keys,
        creates_new_key_without_merge_when_sets_overlap_but_neither_contains_other)
{
  asset_target_obs_t *o = asset_target_obs_new ();
  obs_add_ip (o, "A");
  obs_add_ip (o, "C");

  asset_candidate_t *candidate = candidate_new_test ("old", 10);
  candidate_add_ip (candidate, "A");
  candidate_add_ip (candidate, "B");

  asset_candidate_t *ptrs[] = {candidate};
  asset_candidate_t *candidates = candidate_array_from_ptrs (ptrs, 1);

  asset_merge_decision_t d;
  asset_keys_target_merge_decide (o, candidates, 1, &d);

  assert_true (d.needs_new_key);
  assert_that (d.selected_key, is_null);
  assert_merge_indices_equal (&d, NULL, 0);

  asset_merge_decision_reset (&d);
  asset_target_obs_free (o);
  g_free (candidates);
  candidate_ptrs_free (ptrs, 1);
}

Ensure (manage_asset_keys,
        creates_new_key_and_merges_multiple_subset_candidates)
{
  asset_target_obs_t *o = asset_target_obs_new ();
  obs_add_ip (o, "A");
  obs_add_ip (o, "B");
  obs_add_hostname (o, "host");

  asset_candidate_t *c1 = candidate_new_test ("old-ip-a", 10);
  candidate_add_ip (c1, "A");

  asset_candidate_t *c2 = candidate_new_test ("old-host", 20);
  candidate_add_hostname (c2, "host");

  asset_candidate_t *c3 = candidate_new_test ("not-subset", 30);
  candidate_add_ip (c3, "A");
  candidate_add_ip (c3, "X");

  asset_candidate_t *ptrs[] = {c1, c2, c3};
  asset_candidate_t *candidates = candidate_array_from_ptrs (ptrs, 3);

  asset_merge_decision_t d;
  asset_keys_target_merge_decide (o, candidates, 3, &d);

  assert_true (d.needs_new_key);
  assert_that (d.selected_key, is_null);

  size_t expected[] = {0, 1};
  assert_merge_indices_equal (&d, expected, 2);

  asset_merge_decision_reset (&d);
  asset_target_obs_free (o);
  g_free (candidates);
  candidate_ptrs_free (ptrs, 3);
}

Ensure (manage_asset_keys,
        candidate_with_empty_identifier_map_is_subset_and_can_be_merged)
{
  asset_target_obs_t *o = asset_target_obs_new ();
  obs_add_ip (o, "A");

  asset_candidate_t *candidate = candidate_new_test ("empty", 10);

  asset_candidate_t *ptrs[] = {candidate};
  asset_candidate_t *candidates = candidate_array_from_ptrs (ptrs, 1);

  asset_merge_decision_t d;
  asset_keys_target_merge_decide (o, candidates, 1, &d);

  assert_true (d.needs_new_key);

  size_t expected[] = {0};
  assert_merge_indices_equal (&d, expected, 1);

  asset_merge_decision_reset (&d);
  asset_target_obs_free (o);
  g_free (candidates);
  candidate_ptrs_free (ptrs, 1);
}

Ensure (manage_asset_keys, duplicate_identifiers_are_stored_once)
{
  GHashTable *map;
  GHashTable *values;

  map = asset_identifier_map_new ();

  asset_identifier_map_add (map, ASSET_IDENTIFIER_TYPE_IP, "1.2.3.4");
  asset_identifier_map_add (map, ASSET_IDENTIFIER_TYPE_IP, "1.2.3.4");

  values = g_hash_table_lookup (map,
                                GINT_TO_POINTER (ASSET_IDENTIFIER_TYPE_IP));

  assert_that (values, is_not_null);
  assert_that (g_hash_table_size (values), is_equal_to (1));

  g_hash_table_destroy (map);
}

Ensure (manage_asset_keys, cleanup_asset_merge_decision)
{
  asset_target_obs_t *o = asset_target_obs_new ();
  obs_add_ip (o, "A");
  obs_add_ip (o, "B");

  asset_candidate_t *candidate = candidate_new_test ("old", 10);
  candidate_add_ip (candidate, "A");

  asset_candidate_t *ptrs[] = {candidate};
  asset_candidate_t *candidates = candidate_array_from_ptrs (ptrs, 1);

  asset_merge_decision_t d;
  asset_keys_target_merge_decide (o, candidates, 1, &d);

  asset_merge_decision_reset (&d);

  assert_that (d.merge_indices, is_null);
  assert_that (d.selected_key, is_null);
  assert_that (d.selected_index, is_equal_to (0));
  assert_that (d.needs_new_key, is_equal_to (0));

  asset_target_obs_free (o);
  g_free (candidates);
  candidate_ptrs_free (ptrs, 1);
}

Ensure (manage_asset_keys, cleanup_asset_merge_decision_null_is_safe)
{
  asset_merge_decision_t *d = NULL;

  asset_merge_decision_reset (d);

  assert_that (d, is_null);
}

Ensure (manage_asset_keys, asset_candidate_new_returns_null_for_empty_key)
{
  assert_that (asset_candidate_new (NULL), is_null);
  assert_that (asset_candidate_new (""), is_null);
}

Ensure (manage_asset_keys,
        reuses_existing_key_and_merges_equivalent_candidate)
{
  asset_target_obs_t *o = asset_target_obs_new ();
  obs_add_ip (o, "192.168.178.64");
  obs_add_hostname (o, "gateway.fritz.box");
  obs_add_mac (o, "08:00:27:06:62:DB");

  asset_candidate_t *older = candidate_new_test ("old-key", 10);
  candidate_add_ip (older, "192.168.178.64");
  candidate_add_hostname (older, "gateway.fritz.box");
  candidate_add_mac (older, "08:00:27:06:62:DB");

  asset_candidate_t *newer = candidate_new_test ("selected-key", 20);
  candidate_add_ip (newer, "192.168.178.64");
  candidate_add_hostname (newer, "gateway.fritz.box");
  candidate_add_mac (newer, "08:00:27:06:62:DB");

  asset_candidate_t *ptrs[] = {older, newer};
  asset_candidate_t *candidates = candidate_array_from_ptrs (ptrs, 2);

  asset_merge_decision_t d;
  asset_keys_target_merge_decide (o, candidates, 2, &d);

  assert_false (d.needs_new_key);
  assert_string_equal (d.selected_key, "selected-key");
  assert_that (d.selected_index, is_equal_to (1));

  size_t expected[] = {0};
  assert_merge_indices_equal (&d, expected, 1);

  asset_merge_decision_reset (&d);
  asset_target_obs_free (o);
  g_free (candidates);
  candidate_ptrs_free (ptrs, 2);
}

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite = create_test_suite ();

  add_test_with_context (suite, manage_asset_keys,
                         returns_new_key_if_observed_is_null);
  add_test_with_context (suite, manage_asset_keys,
                         returns_new_key_if_observed_has_no_identifiers);
  add_test_with_context (suite, manage_asset_keys,
                         returns_new_key_if_no_candidates);
  add_test_with_context (suite, manage_asset_keys,
                         returns_new_key_if_candidates_do_not_match);
  add_test_with_context (suite, manage_asset_keys,
                         ignores_empty_asset_keys);
  add_test_with_context (suite, manage_asset_keys,
                         creates_new_key_when_no_candidate_contains_all_observed_identifiers);
  add_test_with_context (suite, manage_asset_keys,
                         decide_by_last_seen_when_score_equal);
  add_test_with_context (suite, manage_asset_keys,
                         reuses_existing_key_when_candidate_contains_observation);
  add_test_with_context (suite, manage_asset_keys,
                         creates_new_key_and_merges_candidate_when_observation_contains_candidate);
  add_test_with_context (suite, manage_asset_keys,
                         creates_new_key_without_merge_when_sets_overlap_but_neither_contains_other);
  add_test_with_context (suite, manage_asset_keys,
                         creates_new_key_and_merges_multiple_subset_candidates);
  add_test_with_context (suite, manage_asset_keys,
                         candidate_with_empty_identifier_map_is_subset_and_can_be_merged);
  add_test_with_context (suite, manage_asset_keys,
                         duplicate_identifiers_are_stored_once);
  add_test_with_context (suite, manage_asset_keys,
                         cleanup_asset_merge_decision);
  add_test_with_context (suite, manage_asset_keys,
                         cleanup_asset_merge_decision_null_is_safe);
  add_test_with_context (suite, manage_asset_keys,
                         asset_candidate_new_returns_null_for_empty_key);
  add_test_with_context (suite, manage_asset_keys,
                         reuses_existing_key_and_merges_equivalent_candidate);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);
  return ret;
}
