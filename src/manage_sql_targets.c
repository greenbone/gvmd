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

/**
 * @brief Get a login port from a target.
 *
 * @param[in]  target         The target.
 * @param[in]  type           The credential type (e.g. "ssh" or "smb").
 *
 * @return  0 on success, -1 on error, 1 credential not found, 99 permission
 *          denied.
 */
static int
target_login_port (target_t target, const char* type)
{
  gchar *quoted_type;
  int port;

  if (target == 0 || type == NULL)
    return 0;

  quoted_type = sql_quote (type);

  if (sql_int ("SELECT NOT EXISTS"
               " (SELECT * FROM targets_login_data"
               "  WHERE target = %llu and type = '%s');",
               target, quoted_type))
    {
      g_free (quoted_type);
      return 0;
    }

  port = sql_int ("SELECT port FROM targets_login_data"
                  " WHERE target = %llu AND type = '%s';",
                  target, quoted_type);

  g_free (quoted_type);

  return port;
}

/**
 * @brief Return the SSH LSC port of a target.
 *
 * @param[in]  target  Target.
 *
 * @return Newly allocated port if available, else NULL.
 */
char*
target_ssh_port (target_t target)
{
  int port = target_login_port (target, "ssh");
  return port ? g_strdup_printf ("%d", port) : NULL;
}

/**
 * @brief Get a credential from a target.
 *
 * @param[in]  target         The target.
 * @param[in]  type           The credential type (e.g. "ssh" or "smb").
 *
 * @return  0 on success, -1 on error, 1 credential not found, 99 permission
 *          denied.
 */
credential_t
target_credential (target_t target, const char* type)
{
  gchar *quoted_type;
  credential_t credential;

  if (target == 0 || type == NULL)
    return 0;

  quoted_type = sql_quote (type);

  if (sql_int ("SELECT NOT EXISTS"
               " (SELECT * FROM targets_login_data"
               "  WHERE target = %llu and type = '%s');",
               target, quoted_type))
    {
      g_free (quoted_type);
      return 0;
    }

  sql_int64 (&credential,
             "SELECT credential FROM targets_login_data"
             " WHERE target = %llu AND type = '%s';",
             target, quoted_type);

  g_free (quoted_type);

  return credential;
}

/**
 * @brief Return the SSH credential associated with a target, if any.
 *
 * @param[in]  target  Target.
 *
 * @return SSH credential if any, else 0.
 */
credential_t
target_ssh_credential (target_t target)
{
  return target_credential (target, "ssh");
}

/**
 * @brief Return the SMB credential associated with a target, if any.
 *
 * @param[in]  target  Target.
 *
 * @return SMB credential if any, else 0.
 */
credential_t
target_smb_credential (target_t target)
{
  return target_credential (target, "smb");
}

/**
 * @brief Return the ESXi credential associated with a target, if any.
 *
 * @param[in]  target  Target.
 *
 * @return ESXi credential if any, else 0.
 */
credential_t
target_esxi_credential (target_t target)
{
  return target_credential (target, "esxi");
}

/**
 * @brief Return the ELEVATE credential associated with a target, if any.
 *
 * @param[in]  target  Target.
 *
 * @return ELEVATE credential if any, else 0.
 */
credential_t
target_ssh_elevate_credential (target_t target)
{
  return target_credential (target, "elevate");
}

/**
 * @brief Return the Kerberos 5 credential associated with a target, if any.
 *
 * @param[in]  target  Target.
 *
 * @return Kerberos 5 credential if any, else 0.
 */
credential_t
target_krb5_credential (target_t target)
{
  return target_credential (target, "krb5");
}
