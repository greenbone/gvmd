/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_sql_targets.h"
#include "sql.h"

/**
 * @file
 * @brief GVM management layer: Targets SQL
 *
 * The Targets SQL for the GVM management layer.
 */

/**
 * @brief Return the UUID of a target.
 *
 * @param[in]  target  Target.
 *
 * @return Newly allocated UUID if available, else NULL.
 */
char*
target_uuid (target_t target)
{
  return sql_string ("SELECT uuid FROM targets WHERE id = %llu;",
                     target);
}

/**
 * @brief Return the UUID of a trashcan target.
 *
 * @param[in]  target  Target.
 *
 * @return Newly allocated UUID if available, else NULL.
 */
char*
trash_target_uuid (target_t target)
{
  return sql_string ("SELECT uuid FROM targets_trash WHERE id = %llu;",
                     target);
}

/**
 * @brief Return the name of a target.
 *
 * @param[in]  target  Target.
 *
 * @return Newly allocated name if available, else NULL.
 */
char*
target_name (target_t target)
{
  return sql_string ("SELECT name FROM targets WHERE id = %llu;",
                     target);
}

/**
 * @brief Return the name of a trashcan target.
 *
 * @param[in]  target  Target.
 *
 * @return Newly allocated name if available, else NULL.
 */
char*
trash_target_name (target_t target)
{
  return sql_string ("SELECT name FROM targets_trash WHERE id = %llu;",
                     target);
}

/**
 * @brief Return the comment of a target.
 *
 * @param[in]  target  Target.
 *
 * @return Newly allocated name if available, else NULL.
 */
char*
target_comment (target_t target)
{
  return sql_string ("SELECT comment FROM targets WHERE id = %llu;",
                     target);
}

/**
 * @brief Return the comment of a trashcan target.
 *
 * @param[in]  target  Target.
 *
 * @return Newly allocated name if available, else NULL.
 */
char*
trash_target_comment (target_t target)
{
  return sql_string ("SELECT comment FROM targets_trash WHERE id = %llu;",
                     target);
}

/**
 * @brief Return the hosts associated with a target.
 *
 * @param[in]  target  Target.
 *
 * @return Newly allocated comma separated list of hosts if available,
 *         else NULL.
 */
char*
target_hosts (target_t target)
{
  return sql_string ("SELECT hosts FROM targets WHERE id = %llu;",
                     target);
}

/**
 * @brief Return the excluded hosts associated with a target.
 *
 * @param[in]  target  Target.
 *
 * @return Newly allocated comma separated list of excluded hosts if available,
 *         else NULL.
 */
char*
target_exclude_hosts (target_t target)
{
  return sql_string ("SELECT exclude_hosts FROM targets WHERE id = %llu;",
                     target);
}

/**
 * @brief Return the reverse_lookup_only value of a target.
 *
 * @param[in]  target  Target.
 *
 * @return Reverse lookup only value if available, else NULL.
 */
char*
target_reverse_lookup_only (target_t target)
{
  return sql_string ("SELECT reverse_lookup_only FROM targets"
                     " WHERE id = %llu;", target);
}

/**
 * @brief Return the reverse_lookup_unify value of a target.
 *
 * @param[in]  target  Target.
 *
 * @return Reverse lookup unify value if available, else NULL.
 */
char*
target_reverse_lookup_unify (target_t target)
{
  return sql_string ("SELECT reverse_lookup_unify FROM targets"
                     " WHERE id = %llu;", target);
}

/**
 * @brief Return the allow_simultaneous_ips value of a target.
 *
 * @param[in]  target  Target.
 *
 * @return The allow_simultaneous_ips value if available, else NULL.
 */
char*
target_allow_simultaneous_ips (target_t target)
{
  return sql_string ("SELECT allow_simultaneous_ips FROM targets"
                     " WHERE id = %llu;", target);
}
