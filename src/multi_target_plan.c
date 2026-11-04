/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "multi_target_plan.h"
#include <ctype.h>
#include <string.h>

static int
is_hex (char c)
{
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
         || (c >= 'A' && c <= 'F');
}

static int
is_uuid (const char *id)
{
  size_t i;
  if (id == NULL || strlen (id) != 36)
    return 0;
  for (i = 0; i < 36; ++i)
    if (i == 8 || i == 13 || i == 18 || i == 23)
      {
        if (id[i] != '-')
          return 0;
      }
    else if (!is_hex (id[i]))
      return 0;
  return 1;
}

static int
same_uuid (const char *left, const char *right)
{
  size_t i;
  for (i = 0; i < 36; ++i)
    if (tolower ((unsigned char) left[i])
        != tolower ((unsigned char) right[i]))
      return 0;
  return 1;
}

multi_target_result_t
multi_target_validate_ids (const char *const *ids, size_t count)
{
  size_t i, j;
  if (ids == NULL || count == 0)
    return MULTI_TARGET_EMPTY;
  if (count > MULTI_TARGET_MAX_TARGETS)
    return MULTI_TARGET_TOO_MANY;
  for (i = 0; i < count; ++i)
    {
      if (!is_uuid (ids[i]))
        return MULTI_TARGET_INVALID_ID;
      for (j = 0; j < i; ++j)
        if (same_uuid (ids[i], ids[j]))
          return MULTI_TARGET_DUPLICATE;
    }
  return MULTI_TARGET_OK;
}

multi_target_result_t
multi_target_partition_hosts (const multi_target_host_t *hosts, size_t count,
                              size_t *group_for_host, size_t *group_count)
{
  size_t i, j, groups = 0;
  if (hosts == NULL || count == 0 || group_for_host == NULL
      || group_count == NULL)
    return MULTI_TARGET_EMPTY;

  for (i = 0; i < count; ++i)
    {
      if (!is_uuid (hosts[i].source_target_id))
        return MULTI_TARGET_INVALID_ID;
      if (hosts[i].host == NULL || hosts[i].host[0] == '\0')
        return MULTI_TARGET_INVALID_HOST;

      for (j = 0; j < i; ++j)
        if (same_uuid (hosts[i].source_target_id,
                       hosts[j].source_target_id))
          break;
      if (j < i)
        group_for_host[i] = group_for_host[j];
      else
        group_for_host[i] = groups++;
    }

  *group_count = groups;
  return MULTI_TARGET_OK;
}
