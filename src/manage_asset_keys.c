/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Manage asset_key merging for target assets.
 *
 * Functions for deciding and applying asset_key merges for asset snapshots of
 * type ASSET_TYPE_TARGET.
 */

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

#include "manage_asset_keys.h"

#include <stdlib.h>
#include <string.h>

/**
 * @brief Score weights.
 *
 * For target assets:
 * - Hostname, MAC and IP are treated as weak
 * identifiers because none of them is guaranteed to uniquely identify a target
 * machine.
 *
 * SCORE_STRONG is kept for consistency with the scoring model and for future
 * identifier types that may be considered strong.
 */
#define SCORE_STRONG 1.0f
#define SCORE_WEAK   0.4f

/**
 * @brief Free one identifier value set.
 *
 * @param[in] value_set  GHashTable used as set of strings.
 */
static void
asset_identifier_value_set_free (gpointer value_set)
{
  if (value_set)
    g_hash_table_destroy (value_set);
}

/**
 * @brief Create an identifier map.
 *
 * The returned hash table maps integer identifier types to string sets.
 *
 * Key:   GINT_TO_POINTER(identifier_type)
 * Value: GHashTable* used as a set of gchar* identifier values.
 *
 * @return New identifier map.
 */
GHashTable *
asset_identifier_map_new ()
{
  return g_hash_table_new_full (g_direct_hash,
                                g_direct_equal,
                                NULL,
                                asset_identifier_value_set_free);
}

/**
 * @brief Get or create the string set for an identifier type.
 *
 * @param[in,out] identifiers      Identifier map.
 * @param[in]     identifier_type  Identifier type.
 *
 * @return String set for the identifier type, or NULL on error.
 */
GHashTable *
asset_identifier_map_ensure_values (GHashTable *identifiers,
                                    int identifier_type)
{
  gpointer key;
  GHashTable *values;

  if (!identifiers)
    return NULL;

  key = GINT_TO_POINTER (identifier_type);
  values = g_hash_table_lookup (identifiers, key);

  if (!values)
    {
      values = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
      g_hash_table_insert (identifiers, key, values);
    }

  return values;
}

/**
 * @brief Add an identifier value to an identifier map.
 *
 * Duplicate values for the same identifier type are ignored.
 *
 * @param[in,out] identifiers       Identifier map.
 * @param[in]     identifier_type   Identifier type.
 * @param[in]     identifier_value  Identifier value.
 */
void
asset_identifier_map_add (GHashTable *identifiers,
                          int identifier_type,
                          const char *identifier_value)
{
  GHashTable *values;

  if (!identifiers || !identifier_value || !*identifier_value)
    return;

  values = asset_identifier_map_ensure_values (identifiers, identifier_type);
  if (!values)
    return;

  if (g_hash_table_contains (values, identifier_value))
    return;

  g_hash_table_add (values, g_strdup (identifier_value));
}

/**
 * @brief Create a new target observation.
 *
 * @return New target observation, or NULL on allocation failure.
 */
asset_target_obs_t *
asset_target_obs_new ()
{
  asset_target_obs_t *obs;

  obs = g_malloc0 (sizeof (*obs));
  obs->identifiers = asset_identifier_map_new ();

  return obs;
}

/**
 * @brief Free all identifiers inside a target observation.
 *
 * @param[in,out] obs  Observation to reset.
 */
void
asset_target_obs_free (asset_target_obs_t *obs)
{
  if (!obs)
    return;

  if (obs->identifiers)
    g_hash_table_destroy (obs->identifiers);

  obs->identifiers = NULL;
}

/**
 * @brief Create a new empty asset candidate.
 *
 * @param[in] asset_key  Asset key for the candidate.
 *
 * @return New candidate, or NULL if @p asset_key is empty.
 */
asset_candidate_t *
asset_candidate_new (const char *asset_key)
{
  asset_candidate_t *candidate;

  if (!asset_key || !*asset_key)
    return NULL;

  candidate = g_malloc0 (sizeof (*candidate));
  candidate->asset_key = g_strdup (asset_key);
  candidate->last_seen = 0;
  candidate->identifiers = asset_identifier_map_new ();

  return candidate;
}

/**
 * @brief Free one asset candidate.
 *
 * @param[in] candidate  Candidate to free.
 */
void
asset_candidate_free (asset_candidate_t *candidate)
{
  if (!candidate)
    return;

  g_free ((gchar *) candidate->asset_key);

  if (candidate->identifiers)
    g_hash_table_destroy (candidate->identifiers);

  g_free (candidate);
}

/**
 * @brief Count values in one set.
 *
 * @param[in] values  GHashTable used as set of strings.
 *
 * @return Number of values.
 */
static guint
identifier_value_set_size (GHashTable *values)
{
  if (!values)
    return 0;

  return g_hash_table_size (values);
}

/**
 * @brief Count all identifier values in a map.
 *
 * @param[in] identifiers  Identifier map.
 *
 * @return Total number of identifier values.
 */
static guint
asset_identifier_map_value_count (GHashTable *identifiers)
{
  GHashTableIter iter;
  gpointer key, value;
  guint count = 0;

  if (!identifiers)
    return 0;

  g_hash_table_iter_init (&iter, identifiers);
  while (g_hash_table_iter_next (&iter, &key, &value))
    count += identifier_value_set_size ((GHashTable *) value);

  return count;
}

/**
 * @brief Check whether an identifier map has at least one value.
 *
 * @param[in] identifiers  Identifier map.
 *
 * @return TRUE if there is at least one identifier value, else FALSE.
 */
static gboolean
asset_identifier_map_has_any (GHashTable *identifiers)
{
  return asset_identifier_map_value_count (identifiers) > 0;
}

/**
 * @brief Count intersection size for one identifier type.
 *
 * @param[in] a                First identifier map.
 * @param[in] b                Second identifier map.
 * @param[in] identifier_type  Identifier type to compare.
 *
 * @return Number of shared values for @p identifier_type.
 */
static guint
asset_identifier_map_intersection_count_for_type (GHashTable *a,
                                                  GHashTable *b,
                                                  int identifier_type)
{
  GHashTable *a_values;
  GHashTable *b_values;
  GHashTableIter iter;
  gpointer key, value;
  guint count = 0;

  if (!a || !b)
    return 0;

  a_values = g_hash_table_lookup (a, GINT_TO_POINTER (identifier_type));
  b_values = g_hash_table_lookup (b, GINT_TO_POINTER (identifier_type));

  if (!a_values || !b_values)
    return 0;

  g_hash_table_iter_init (&iter, a_values);
  while (g_hash_table_iter_next (&iter, &key, &value))
    {
      const char *identifier_value = key;

      if (g_hash_table_contains (b_values, identifier_value))
        count++;
    }

  return count;
}

/**
 * @brief Check whether all values of one set exist in another set.
 *
 * @param[in] a_values  Candidate subset.
 * @param[in] b_values  Candidate superset.
 *
 * @return TRUE if @p a_values is a subset of @p b_values, else FALSE.
 */
static gboolean
identifier_value_set_is_subset (GHashTable *a_values,
                                GHashTable *b_values)
{
  GHashTableIter iter;
  gpointer key, value;

  if (!a_values || g_hash_table_size (a_values) == 0)
    return TRUE;

  if (!b_values)
    return FALSE;

  g_hash_table_iter_init (&iter, a_values);
  while (g_hash_table_iter_next (&iter, &key, &value))
    {
      const char *identifier_value = key;

      if (!g_hash_table_contains (b_values, identifier_value))
        return FALSE;
    }

  return TRUE;
}

/**
 * @brief Check whether one identifier map is a subset of another.
 *
 * Every identifier value in @p a must also exist in @p b under the same
 * identifier type.
 *
 * @param[in] a  Candidate subset.
 * @param[in] b  Candidate superset.
 *
 * @return TRUE if @p a is a subset of @p b, else FALSE.
 */
static gboolean
asset_identifier_map_is_subset (GHashTable *a,
                                GHashTable *b)
{
  GHashTableIter iter;
  gpointer key, value;

  if (!a || asset_identifier_map_value_count (a) == 0)
    return TRUE;

  if (!b)
    return FALSE;

  g_hash_table_iter_init (&iter, a);
  while (g_hash_table_iter_next (&iter, &key, &value))
    {
      GHashTable *a_values = value;
      GHashTable *b_values = g_hash_table_lookup (b, key);

      if (!identifier_value_set_is_subset (a_values, b_values))
        return FALSE;
    }

  return TRUE;
}

/**
 * @brief Compute candidate score for an observation.
 *
 * Scores by number of matching identifiers. MAC matches are strong, hostname
 * and IP matches are weak.
 *
 * @param[in] candidate  Asset candidate.
 * @param[in] obs        Current observation.
 *
 * @return Candidate score.
 */
static float
candidate_score (const asset_candidate_t *candidate,
                 const asset_target_obs_t *obs)
{
  float score = 0.0f;

  if (!candidate || !obs)
    return 0.0f;

  score += (float) asset_identifier_map_intersection_count_for_type (
    candidate->identifiers,
    obs->identifiers,
    ASSET_IDENTIFIER_TYPE_MAC) * SCORE_WEAK;

  score += (float) asset_identifier_map_intersection_count_for_type (
    candidate->identifiers,
    obs->identifiers,
    ASSET_IDENTIFIER_TYPE_HOSTNAME) * SCORE_WEAK;

  score += (float) asset_identifier_map_intersection_count_for_type (
    candidate->identifiers,
    obs->identifiers,
    ASSET_IDENTIFIER_TYPE_IP) * SCORE_WEAK;

  return score;
}

/**
 * @brief Check whether an observation has at least one usable identifier.
 *
 * @param[in] obs  Observed target identifiers.
 *
 * @return TRUE if the observation has any identifier, else FALSE.
 */
static gboolean
obs_has_any_identifier (const asset_target_obs_t *obs)
{
  if (!obs)
    return FALSE;

  return asset_identifier_map_has_any (obs->identifiers);
}

/**
 * @brief Initialize a merge decision with default values.
 *
 * @param[in,out] out  Decision object to initialize.
 */
static void
asset_merge_decision_init (asset_merge_decision_t *out)
{
  memset (out, 0, sizeof (*out));
  out->needs_new_key = 1;
  out->selected_key = NULL;
  out->selected_index = 0;
  out->merge_indices = NULL;
}

/**
 * @brief Decide the asset_key for a target observation.
 *
 * Rules:
 * - If an existing candidate contains all observed identifiers, reuse the best
 *   matching candidate key.
 * - Else if the observation contains one or more existing candidates, caller
 *   should create a new key and merge those candidate keys into it.
 * - Else create a new key and do not merge.
 *
 * @param[in]     obs             Observed identifiers (ip/hostname/mac).
 * @param[in]     candidates      Candidate asset_keys.
 * @param[in]     candidates_len  Number of entries in @p candidates.
 * @param[in,out] out             Output decision.
 */
void
asset_keys_target_merge_decide (const asset_target_obs_t *obs,
                                const asset_candidate_t *candidates,
                                size_t candidates_len,
                                asset_merge_decision_t *out)
{
  float best_score = -1.0f;
  time_t best_last_seen = (time_t) 0;
  size_t best_idx = 0;
  gboolean found_containing_candidate = FALSE;
  gboolean found_subset_candidate = FALSE;

  if (!out)
    return;

  asset_merge_decision_init (out);

  if (!obs_has_any_identifier (obs))
    return;

  if (!candidates || candidates_len == 0)
    return;

  /*
   * An existing candidate contains all identifiers from the new observation.
   * Reuse the existing candidate asset_key.
   */
  for (size_t i = 0; i < candidates_len; i++)
    {
      const asset_candidate_t *candidate = &candidates[i];
      float score;

      if (!candidate->asset_key || !*candidate->asset_key)
        continue;

      if (!asset_identifier_map_is_subset (obs->identifiers,
                                           candidate->identifiers))
        continue;

      score = candidate_score (candidate, obs);

      if (!found_containing_candidate
          || score > best_score
          || (score == best_score && candidate->last_seen > best_last_seen))
        {
          found_containing_candidate = TRUE;
          best_score = score;
          best_last_seen = candidate->last_seen;
          best_idx = i;
        }
    }

  if (found_containing_candidate)
    {
      out->needs_new_key = 0;
      out->selected_index = best_idx;
      out->selected_key = candidates[best_idx].asset_key;
      return;
    }

  /*
   * The new observation contains one or more old candidates.
   * Caller creates a new key and merges those candidates into it.
   */
  out->merge_indices =
    g_array_sized_new (FALSE, FALSE, sizeof (size_t), candidates_len);

  for (size_t i = 0; i < candidates_len; i++)
    {
      const asset_candidate_t *candidate = &candidates[i];

      if (!candidate->asset_key || !*candidate->asset_key)
        continue;

      if (asset_identifier_map_is_subset (candidate->identifiers,
                                          obs->identifiers))
        {
          found_subset_candidate = TRUE;
          g_array_append_val (out->merge_indices, i);
        }
    }

  if (found_subset_candidate)
    {
      out->needs_new_key = 1;
      out->selected_key = NULL;
      out->selected_index = 0;
      return;
    }

  /*
   * There is no full match. Create a new key and do not merge.
   */
  if (out->merge_indices)
    {
      g_array_free (out->merge_indices, TRUE);
      out->merge_indices = NULL;
    }

  out->needs_new_key = 1;
  out->selected_key = NULL;
  out->selected_index = 0;
}

/**
 * @brief Free heap-allocated fields inside a merge decision.
 *
 * @param[in,out] d  Decision to free/reset.
 */
void
asset_merge_decision_reset (asset_merge_decision_t *d)
{
  if (!d)
    return;

  if (d->merge_indices)
    g_array_free (d->merge_indices, TRUE);

  d->merge_indices = NULL;
  d->selected_key = NULL;
  d->selected_index = 0;
  d->needs_new_key = 0;
}
