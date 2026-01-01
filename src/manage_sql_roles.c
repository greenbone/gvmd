/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_roles.h"
#include "manage_acl.h"
#include "manage_sql.h"
#include "sql.h"

/**
 * @file
 * @brief GVM management layer: Roles SQL
 *
 * The Roles SQL for the GVM management layer.
 */

/**
 * @brief List roles.
 *
 * @param[in]  log_config  Log configuration.
 * @param[in]  database    Location of manage database.
 * @param[in]  verbose     Whether to print UUID.
 *
 * @return 0 success, -1 error.
 */
int
manage_get_roles (GSList *log_config, const db_conn_info_t *database,
                  int verbose)
{
  iterator_t roles;
  int ret;

  g_info ("   Getting roles.");

  ret = manage_option_setup (log_config, database,
                             0 /* avoid_db_check_inserts */);
  if (ret)
    return ret;

  init_iterator (&roles, "SELECT name, uuid FROM roles;");
  while (next (&roles))
    if (verbose)
      printf ("%s %s\n", iterator_string (&roles, 0), iterator_string (&roles, 1));
    else
      printf ("%s\n", iterator_string (&roles, 0));

  cleanup_iterator (&roles);

  manage_option_cleanup ();

  return 0;
}
