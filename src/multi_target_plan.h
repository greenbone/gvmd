/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef CREDENTIAL_MULTI_TARGET_PLAN_H
#define CREDENTIAL_MULTI_TARGET_PLAN_H

#include <stddef.h>

#define MULTI_TARGET_MAX_TARGETS 32

typedef enum
{
  MULTI_TARGET_OK = 0,
  MULTI_TARGET_EMPTY,
  MULTI_TARGET_TOO_MANY,
  MULTI_TARGET_INVALID_ID,
  MULTI_TARGET_DUPLICATE,
  MULTI_TARGET_INVALID_HOST
} multi_target_result_t;

/* An expanded, concrete host belonging to one selected source target. */
typedef struct
{
  const char *source_target_id;
  const char *host;
} multi_target_host_t;

/* Validate ordered target UUIDs before looking up target permissions/settings.
 * This is only the input boundary; it does not launch or aggregate child scans. */
multi_target_result_t multi_target_validate_ids (const char *const *ids,
                                                  size_t count);

/* Assign one scan unit per source target, retaining all its concrete hosts.
 * Units are numbered in first-seen order. The caller owns the inputs and
 * provides count slots in group_for_host. Credential-specific partitions
 * refine these units when asset overrides are enabled. */
multi_target_result_t multi_target_partition_hosts (
  const multi_target_host_t *hosts, size_t count, size_t *group_for_host,
  size_t *group_count);

#endif
