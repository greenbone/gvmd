/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Manage asset key merging for target assets.
 *
 * Provides functions to decide and apply asset key merges for asset snapshots
 * of type ASSET_TYPE_TARGET.
 */

#ifndef _GVMD_MANAGE_ASSET_KEYS_H
#define _GVMD_MANAGE_ASSET_KEYS_H

#include <glib.h>
#include <stddef.h>

/**
 * @brief Match flags indicating which observed properties match a candidate
 *        asset_key.
 */
#define MATCH_IP       (1u << 0)  ///< Candidate matches the observed IP address.
#define MATCH_HOSTNAME (1u << 1)  ///< Candidate matches the observed hostname.
#define MATCH_MAC      (1u << 2)  ///< Candidate matches the observed MAC address.

/**
 * @brief Types of asset identifiers represented in asset snapshot identifiers.
 */
typedef enum
{
 ASSET_IDENTIFIER_TYPE_IP = 0,
 ASSET_IDENTIFIER_TYPE_HOSTNAME = 1,
 ASSET_IDENTIFIER_TYPE_MAC = 2,
 ASSET_IDENTIFIER_TYPE_AGENT_ID = 3,
 ASSET_IDENTIFIER_TYPE_CONTAINER_DIGEST = 4,
} asset_identifier_type_t;

/**
 * @brief Observed target identifiers for a single asset snapshot row.
 */
typedef struct
{
 /**
  * Map of identifier type to string set.
  *
  * Key:   GINT_TO_POINTER (ASSET_IDENTIFIER_TYPE_*)
  * Value: GHashTable* used as a set of gchar* identifier values.
  */
 GHashTable *identifiers;
} asset_target_obs_t;

/**
 * @brief Candidate existing asset identified by an asset_key.
 */
typedef struct
{
 const char *asset_key; ///< Existing asset_key for this candidate.
 time_t last_seen;      ///< Last seen timestamp for this asset_key.
 unsigned match_mask;   ///< Bitmask of MATCH_* flags for this candidate.

 /**
  * Map of identifier type to string set.
  *
  * Key:   GINT_TO_POINTER (ASSET_IDENTIFIER_TYPE_*)
  * Value: GHashTable* used as a set of gchar* identifier values.
  */
 GHashTable *identifiers;
} asset_candidate_t;

/**
 * @brief Merge decision returned by the target merge algorithm.
 */
typedef struct
{
    int needs_new_key; ///< 1 if caller must generate a new asset_key.
    const char* selected_key; ///< Chosen asset_key (borrowed, may be NULL).
    size_t selected_index; ///< Index of chosen candidate in candidates[].

    GArray* merge_indices; ///< Indices into candidates[] to merge.
    ///  Element type: size_t
} asset_merge_decision_t;

void
asset_keys_target_merge_decide (const asset_target_obs_t*,
                                const asset_candidate_t*,
                                size_t,
                                asset_merge_decision_t*);

void
asset_merge_decision_reset (asset_merge_decision_t* );

GHashTable *
asset_identifier_map_new ();

GHashTable *
asset_identifier_map_ensure_values (GHashTable *,int);

void
asset_identifier_map_add (GHashTable *, int, const char *);

asset_target_obs_t *
asset_target_obs_new ();

void
asset_target_obs_free (asset_target_obs_t *);

asset_candidate_t *
asset_candidate_new (const char *);

void
asset_candidate_free (asset_candidate_t *);

#endif /* _GVMD_MANAGE_ASSET_KEYS_H */
