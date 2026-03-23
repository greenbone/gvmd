/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_sql_settings.h"
#include "manage_acl.h"
#include "sql.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @file
 * @brief GVM management layer: Settings SQL
 *
 * The Settings SQL for the GVM management layer.
 */

/**
 * @brief Return the uuid of a resource filter from settings.
 *
 * @param[in]  resource  Resource (eg. Filters, Targets, CPE).
 *
 * @return resource filter uuid in settings if it exists, "" otherwise.
 */
char *
setting_filter (const char *resource)
{
  return sql_string ("SELECT value FROM settings WHERE name = '%s Filter'"
                     " AND " ACL_GLOBAL_OR_USER_OWNS () ""
                     " ORDER BY coalesce (owner, 0) DESC;",
                     resource,
                     current_credentials.uuid);
}

/**
 * @brief Return the user's timezone.
 *
 * @return User Severity Class in settings if it exists, else NULL.
 */
char *
setting_timezone ()
{
  return sql_string ("SELECT timezone FROM users WHERE uuid = '%s'",
                     current_credentials.uuid);
}
