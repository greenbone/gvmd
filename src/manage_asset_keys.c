/* Copyright (C) 2020-2022 Greenbone AG
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
 * - MAC is treated as strong
 * - hostname and IP are treated as weak
 */
#define SCORE_STRONG 1.0f
#define SCORE_WEAK   0.4f

/**
 * @brief Compute candidate score for an observation using match_mask.
 * @param [in] c Asset candidate
 * @return score of the candidate @param c
 */
static float
candidate_score (const asset_candidate_t *c)
{
  float s = 0.0f;

  if (c->match_mask & MATCH_MAC)
    s += SCORE_STRONG;

  if (c->match_mask & MATCH_HOSTNAME)
    s += SCORE_WEAK;

  if (c->match_mask & MATCH_IP)
    s += SCORE_WEAK;

  return s;
}

/**
 * @brief Check whether an observation has at least one usable property.
 * @param [in] obs Opserved Target
 * @return 1 if has any property else 0.
 */
static int
obs_has_any_property (const asset_target_obs_t *obs)
{
  if (!obs)
    return 0;

  return ((obs->mac && *obs->mac) ||
          (obs->hostname && *obs->hostname) ||
          (obs->ip && *obs->ip));
}

/**
 * @brief Decide the asset_key for a target observation and which candidates to
 *        merge into it.
 *
 * @param[in] obs             Observed identifiers (ip/hostname/mac).
 * @param[in] candidates      Candidate asset_keys provided by SQL layer.
 * @param[in] candidates_len  Number of candidates.
 *
 * @return A merge decision. Caller must call asset_merge_decision_free() on the
 *         returned decision to release merge_indices.
 */
asset_merge_decision_t
asset_keys_target_merge_decide (const asset_target_obs_t *obs,
                           const asset_candidate_t *candidates,
                           size_t candidates_len)
{
  asset_merge_decision_t out;

  memset (&out, 0, sizeof (out));

  /* assume new key unless we find a suitable candidate */
  out.needs_new_key = 1;
  out.selected_key = NULL;
  out.selected_index = 0;
  out.merge_indices = NULL;
  out.merge_indices_len = 0;

  if (!obs_has_any_property (obs))
    return out;

  /* No candidates then new key */
  if (!candidates || candidates_len == 0)
    return out;

  /* Pick best candidate: score desc, last_seen desc */
  float best_score = -1.0f;
  time_t best_last_seen = (time_t) 0;
  size_t best_idx = (size_t) 0;
  int found = 0;

  for (size_t i = 0; i < candidates_len; i++)
    {
      const asset_candidate_t *c = &candidates[i];

      /* ignore empty keys */
      if (!c->asset_key || !*c->asset_key)
        continue;

      float s = candidate_score (c);

      /* score==0 means no matching observed properties */
      if (s <= 0.0f)
        continue;

      if (!found ||
          s > best_score ||
          (s == best_score && c->last_seen > best_last_seen))
        {
          best_score = s;
          best_last_seen = c->last_seen;
          best_idx = i;
          found = 1;
        }
    }

  if (!found)
    return out; /* keep needs_new_key=1 */

  out.needs_new_key = 0;
  out.selected_index = best_idx;
  out.selected_key = candidates[best_idx].asset_key;

  size_t *indices = (size_t *) malloc (candidates_len * sizeof (size_t));
  if (!indices)
    {
      out.merge_indices = NULL;
      out.merge_indices_len = 0;
      return out;
    }

  size_t n = 0;
  for (size_t i = 0; i < candidates_len; i++)
    {
      if (i == best_idx)
        continue;

      const asset_candidate_t *c = &candidates[i];

      if (!c->asset_key || !*c->asset_key)
        continue;

      if (candidate_score (c) > 0.0f)
        indices[n++] = i;
    }

  if (n == 0)
    {
      free (indices);
      out.merge_indices = NULL;
      out.merge_indices_len = 0;
      return out;
    }

  out.merge_indices = indices;
  out.merge_indices_len = n;

  return out;
}

/**
 * @brief Free heap-allocated fields inside a merge decision.
 *
 * @param[in,out] d  Decision to free/reset.
 */
void
asset_merge_decision_free (asset_merge_decision_t *d)
{
  if (!d)
    return;

  free (d->merge_indices);
  d->merge_indices = NULL;
  d->merge_indices_len = 0;
  d->selected_key = NULL;
  d->selected_index = 0;
  d->needs_new_key = 0;
}