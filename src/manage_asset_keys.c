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
 * @brief Check whether all properties of @p cand are covered by selected and obs.
 *
 * @param[in] cand      Candidate being considered for merging into selected.
 * @param[in] selected  The selected candidate.
 * @param[in] obs       The current observation.
 *
 * @return TRUE if @p cand can be merged into @p selected, else FALSE.
 */
static gboolean
candidate_props_subset_of_selected_and_obs (const asset_candidate_t *cand,
                                            const asset_candidate_t *selected,
                                            const asset_target_obs_t *obs)
{
  if (!cand || !selected || !obs)
    return FALSE;

  /* MAC */
  if (cand->mac && *cand->mac)
    {
      gboolean ok = FALSE;

      if (selected->mac && *selected->mac &&
          g_strcmp0 (cand->mac, selected->mac) == 0)
        ok = TRUE;

      if (!ok && obs->mac && *obs->mac &&
          g_strcmp0 (cand->mac, obs->mac) == 0)
        ok = TRUE;

      if (!ok)
        return FALSE;
    }

  /* HOSTNAME */
  if (cand->hostname && *cand->hostname)
    {
      gboolean ok = FALSE;

      if (selected->hostname && *selected->hostname &&
          g_strcmp0 (cand->hostname, selected->hostname) == 0)
        ok = TRUE;

      if (!ok && obs->hostname && *obs->hostname &&
          g_strcmp0 (cand->hostname, obs->hostname) == 0)
        ok = TRUE;

      if (!ok)
        return FALSE;
    }

  /* IP */
  if (cand->ip && *cand->ip)
    {
      gboolean ok = FALSE;

      if (selected->ip && *selected->ip &&
          g_strcmp0 (cand->ip, selected->ip) == 0)
        ok = TRUE;

      if (!ok && obs->ip && *obs->ip &&
          g_strcmp0 (cand->ip, obs->ip) == 0)
        ok = TRUE;

      if (!ok)
        return FALSE;
    }

  return TRUE;
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
 * @brief Decide the asset_key for a target observation and which candidates to merge.
 *
 * Selection:
 * - choose the best candidate by score (MAC strong, hostname/IP weak)
 * - pick by last_seen
 *
 * @param[in]  obs             Observed identifiers (ip/hostname/mac).
 * @param[in]  candidates      Candidate asset_keys.
 * @param[in]  candidates_len  Number of entries in @p candidates.
 * @param[in,out] out          Output decision.
 */
void
asset_keys_target_merge_decide (const asset_target_obs_t *obs,
                                const asset_candidate_t *candidates,
                                size_t candidates_len,
                                asset_merge_decision_t *out)
{
  if (!out)
    return;

  asset_merge_decision_init (out);

  if (!obs_has_any_property (obs))
    return;

  if (!candidates || candidates_len == 0)
    return;

  float best_score = -1.0f;
  time_t best_last_seen = (time_t) 0;
  size_t best_idx = 0;
  gboolean found = FALSE;

  for (size_t i = 0; i < candidates_len; i++)
    {
      const asset_candidate_t *c = &candidates[i];

      if (!c->asset_key || !*c->asset_key)
        continue;

      float s = candidate_score (c);
      if (s <= 0.0f)
        continue;

      if (!found ||
          s > best_score ||
          (s == best_score && c->last_seen > best_last_seen))
        {
          best_score = s;
          best_last_seen = c->last_seen;
          best_idx = i;
          found = TRUE;
        }
    }

  if (!found)
    return;

  out->needs_new_key = 0;
  out->selected_index = best_idx;
  out->selected_key = candidates[best_idx].asset_key;

  const asset_candidate_t *selected = &candidates[best_idx];

  out->merge_indices =
    g_array_sized_new (FALSE, FALSE, sizeof (size_t), candidates_len);

  for (size_t i = 0; i < candidates_len; i++)
    {
      if (i == best_idx)
        continue;

      const asset_candidate_t *c = &candidates[i];

      if (!c->asset_key || !*c->asset_key)
        continue;

      if (candidate_props_subset_of_selected_and_obs (c, selected, obs))
        g_array_append_val (out->merge_indices, i);
    }

  if (out->merge_indices->len == 0)
    {
      g_array_free (out->merge_indices, TRUE);
      out->merge_indices = NULL;
    }
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