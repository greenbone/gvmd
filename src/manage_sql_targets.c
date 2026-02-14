/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_sql_targets.h"
#include "manage_acl.h"
#include "manage_sql_assets.h"
#include "manage_sql_permissions.h"
#include "manage_sql_port_lists.h"
#include "manage_sql_resources.h"
#include "sql.h"

#include <assert.h>
#include <ctype.h>

/**
 * @file
 * @brief GVM management layer: Targets SQL
 *
 * The Targets SQL for the GVM management layer.
 */

/**
 * @brief Find a target for a specific permission, given a UUID.
 *
 * @param[in]   uuid        UUID of target.
 * @param[out]  target      Target return, 0 if successfully failed to find target.
 * @param[in]   permission  Permission.
 *
 * @return FALSE on success (including if failed to find target), TRUE on error.
 */
gboolean
find_target_with_permission (const char* uuid, target_t* target,
                             const char *permission)
{
  return find_resource_with_permission ("target", uuid, target, permission, 0);
}

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

/**
 * @brief Create a target from an existing target.
 *
 * @param[in]  name        Name of new target.  NULL to copy from existing.
 * @param[in]  comment     Comment on new target.  NULL to copy from existing.
 * @param[in]  target_id   UUID of existing target.
 * @param[out] new_target  New target.
 *
 * @return 0 success, 1 target exists already, 2 failed to find existing
 *         target, 99 permission denied, -1 error.
 */
int
copy_target (const char* name, const char* comment, const char *target_id,
             target_t* new_target)
{
  int ret;
  target_t old_target;

  assert (new_target);

  ret = copy_resource ("target", name, comment, target_id,
                       "hosts, exclude_hosts, port_list, reverse_lookup_only,"
                       " reverse_lookup_unify, alive_test,"
                       " allow_simultaneous_ips",
                       1, new_target, &old_target);
  if (ret)
    return ret;

  sql ("INSERT INTO targets_login_data (target, type, credential, port)"
       " SELECT %llu, type, credential, port"
       "   FROM targets_login_data"
       "  WHERE target = %llu;",
       *new_target, old_target);

  return 0;
}

/**
 * @brief Delete a target.
 *
 * @param[in]  target_id  UUID of target.
 * @param[in]  ultimate   Whether to remove entirely, or to trashcan.
 *
 * @return 0 success, 1 fail because a task refers to the target, 2 failed
 *         to find target, 99 permission denied, -1 error.
 */
int
delete_target (const char *target_id, int ultimate)
{
  target_t target = 0;
  target_t trash_target;

  sql_begin_immediate ();

  if (acl_user_may ("delete_target") == 0)
    {
      sql_rollback ();
      return 99;
    }

  if (find_target_with_permission (target_id, &target, "delete_target"))
    {
      sql_rollback ();
      return -1;
    }

  if (target == 0)
    {
      if (find_trash ("target", target_id, &target))
        {
          sql_rollback ();
          return -1;
        }
      if (target == 0)
        {
          sql_rollback ();
          return 2;
        }
      if (ultimate == 0)
        {
          /* It's already in the trashcan. */
          sql_commit ();
          return 0;
        }

      /* Check if it's in use by a task in the trashcan. */
      if (sql_int ("SELECT count(*) FROM tasks"
                   " WHERE target = %llu"
                   " AND target_location = " G_STRINGIFY (LOCATION_TRASH) ";",
                   target))
        {
          sql_rollback ();
          return 1;
        }

      permissions_set_orphans ("target", target, LOCATION_TRASH);
      tags_remove_resource ("target", target, LOCATION_TRASH);

      sql ("DELETE FROM targets_trash_login_data WHERE target = %llu;", target);
      sql ("DELETE FROM targets_trash WHERE id = %llu;", target);
      sql_commit ();
      return 0;
    }

  if (ultimate == 0)
    {
      if (sql_int ("SELECT count(*) FROM tasks"
                   " WHERE target = %llu"
                   " AND target_location = " G_STRINGIFY (LOCATION_TABLE)
                   " AND hidden = 0;",
                   target))
        {
          sql_rollback ();
          return 1;
        }

      sql ("INSERT INTO targets_trash"
           " (uuid, owner, name, hosts, exclude_hosts, comment,"
           "  port_list, port_list_location,"
           "  reverse_lookup_only, reverse_lookup_unify, alive_test,"
           "  allow_simultaneous_ips,"
           "  creation_time, modification_time)"
           " SELECT uuid, owner, name, hosts, exclude_hosts, comment,"
           "        port_list, " G_STRINGIFY (LOCATION_TABLE) ","
           "        reverse_lookup_only, reverse_lookup_unify, alive_test,"
           "        allow_simultaneous_ips,"
           "        creation_time, modification_time"
           " FROM targets WHERE id = %llu;",
           target);

      trash_target = sql_last_insert_id ();

      /* Copy login data */
      sql ("INSERT INTO targets_trash_login_data"
           " (target, type, credential, port, credential_location)"
           " SELECT %llu, type, credential, port, "
           G_STRINGIFY (LOCATION_TABLE)
           "   FROM targets_login_data WHERE target = %llu;",
           trash_target, target);

      /* Update the location of the target in any trashcan tasks. */
      sql ("UPDATE tasks"
           " SET target = %llu,"
           "     target_location = " G_STRINGIFY (LOCATION_TRASH)
           " WHERE target = %llu"
           " AND target_location = " G_STRINGIFY (LOCATION_TABLE) ";",
           sql_last_insert_id (),
           target);

      permissions_set_locations ("target", target,
                                 sql_last_insert_id (),
                                 LOCATION_TRASH);
      tags_set_locations ("target", target,
                          sql_last_insert_id (),
                          LOCATION_TRASH);
    }
  else if (sql_int ("SELECT count(*) FROM tasks"
                    " WHERE target = %llu"
                    " AND target_location = " G_STRINGIFY (LOCATION_TABLE),
                    target))
    {
      sql_rollback ();
      return 1;
    }
  else
    {
      permissions_set_orphans ("target", target, LOCATION_TABLE);
      tags_remove_resource ("target", target, LOCATION_TABLE);
    }

  sql ("DELETE FROM targets_login_data WHERE target = %llu;", target);
  sql ("DELETE FROM targets WHERE id = %llu;", target);

  sql_commit ();
  return 0;
}

/**
 * @brief Validate a single port.
 *
 * @param[in]   port      A port.
 *
 * @return 0 success, 1 failed.
 */
static int
validate_port (const char *port)
{
  const char *first;

  while (*port && isblank (*port)) port++;
  if (*port == '\0')
    return 1;

  first = port;
  while (*first && isdigit (*first)) first++;
  if (first == port)
    return 1;

  while (*first && isblank (*first)) first++;
  if (*first == '\0')
    {
      long int number;
      number = strtol (port, NULL, 10);
      if (number <= 0)
        return 1;
      if (number > 65535)
        return 1;
      return 0;
    }
  return 1;
}

/**
 * @brief Convert alive test array to alive test bitfield.
 *
 * @param[in]  alive_tests NULL-terminated array of alive tests.
 *
 * @return Alive test bitfield, or -1 on error.
 */
static int
alive_test_from_array (GPtrArray *alive_tests)
{
  alive_test_t alive_test_bitfield = 0;

  if (alive_tests->len == 0)
    return 0;

  for (int i = 0; i < alive_tests->len; i++)
    {
      const char *item = g_ptr_array_index (alive_tests, i);
      if (strcasecmp (item, "Scan Config Default") == 0)
        {
          alive_test_bitfield = 0;
          break;
        }
      else if (strcasecmp (item, "Consider Alive") == 0)
        {
          alive_test_bitfield = ALIVE_TEST_CONSIDER_ALIVE;
          break;
        }
      else if (strcasecmp (item, "ARP") == 0
          || strcasecmp (item, "ARP Ping") == 0)
        alive_test_bitfield |= ALIVE_TEST_ARP;
      else if (strcmp (item, "ICMP") == 0
                || strcmp (item, "ICMP Ping") == 0)
        alive_test_bitfield |= ALIVE_TEST_ICMP;
      else if (strcmp (item, "TCP-ACK Service") == 0
                || strcmp (item, "TCP-ACK Service Ping") == 0)
        alive_test_bitfield |= ALIVE_TEST_TCP_ACK_SERVICE;
      else if (strcmp (item, "TCP-SYN Service") == 0
                || strcmp (item, "TCP-SYN Service Ping") == 0)
        alive_test_bitfield |= ALIVE_TEST_TCP_SYN_SERVICE;
      else
        {
          g_debug ("%s: Invalid alive_tests item: %s", __func__, item);
          alive_test_bitfield = -1;
          break;
        }
    }
  return alive_test_bitfield;
}

/**
 * @brief Convert legacy alive test name string to alive test bitfield.
 *
 * @param[in]  alive_tests  Name of alive test.
 *
 * @return Alive test, or -1 on error.
 */
static int
alive_test_from_string (const char* alive_tests)
{
  alive_test_t alive_test;
  if (alive_tests == NULL
      || strcmp (alive_tests, "") == 0
      || strcmp (alive_tests, "Scan Config Default") == 0)
    alive_test = 0;
  else if (strcmp (alive_tests, "ICMP, TCP-ACK Service & ARP Ping") == 0)
    alive_test = ALIVE_TEST_TCP_ACK_SERVICE | ALIVE_TEST_ICMP | ALIVE_TEST_ARP;
  else if (strcmp (alive_tests, "TCP-ACK Service & ARP Ping") == 0)
    alive_test = ALIVE_TEST_TCP_ACK_SERVICE | ALIVE_TEST_ARP;
  else if (strcmp (alive_tests, "ICMP & ARP Ping") == 0)
    alive_test = ALIVE_TEST_ICMP | ALIVE_TEST_ARP;
  else if (strcmp (alive_tests, "ICMP & TCP-ACK Service Ping") == 0)
    alive_test = ALIVE_TEST_ICMP | ALIVE_TEST_TCP_ACK_SERVICE;
  else if (strcmp (alive_tests, "ARP Ping") == 0)
    alive_test = ALIVE_TEST_ARP;
  else if (strcmp (alive_tests, "TCP-ACK Service Ping") == 0)
    alive_test = ALIVE_TEST_TCP_ACK_SERVICE;
  else if (strcmp (alive_tests, "TCP-SYN Service Ping") == 0)
    alive_test = ALIVE_TEST_TCP_SYN_SERVICE;
  else if (strcmp (alive_tests, "ICMP Ping") == 0)
    alive_test = ALIVE_TEST_ICMP;
  else if (strcmp (alive_tests, "Consider Alive") == 0)
    alive_test = ALIVE_TEST_CONSIDER_ALIVE;
  else
    return -1;
  return alive_test;
}

/**
 * @brief Set login data for a target.
 *
 * @param[in]  target         The target.
 * @param[in]  type           The credential type (e.g. "ssh" or "smb").
 * @param[in]  credential     The credential or 0 to remove.
 * @param[in]  port           The port to authenticate at with credential.
 *
 * @return  0 on success, -1 on error, 1 target not found, 99 permission denied.
 */
static int
set_target_login_data (target_t target, const char* type,
                       credential_t credential, int port)
{
  gchar *quoted_type;

  if (current_credentials.uuid
      && (acl_user_may ("modify_target") == 0))
    return 99;

  if (type == NULL)
    return -1;

  if (target == 0)
    return 1;

  quoted_type = sql_quote (type);

  if (sql_int ("SELECT count (*) FROM targets_login_data"
               " WHERE target = %llu AND type = '%s';",
               target, quoted_type))
    {
      if (credential == 0)
        {
          sql ("DELETE FROM targets_login_data"
               " WHERE target = '%llu' AND type = '%s';",
               target, quoted_type);
        }
      else
        {
          sql ("UPDATE targets_login_data"
               " SET credential = %llu, port = %d"
               " WHERE target = %llu AND type = '%s';",
               credential, port, target, quoted_type);
        }
    }
  else if (credential)
    {
      sql ("INSERT INTO targets_login_data (target, type, credential, port)"
            " VALUES (%llu, '%s', %llu, %i)",
            target, quoted_type, credential, port);
    }

  g_free (quoted_type);
  return 0;
}

/**
 * @brief Create a target.
 *
 * @param[in]   name            Name of target.
 * @param[in]   asset_hosts_filter  Asset host filter to select hosts.
 *                                  Overrides \p hosts and \p exclude_hosts.
 * @param[in]   hosts           Host list of target.
 * @param[in]   exclude_hosts   List of hosts to exclude from \p hosts.
 * @param[in]   comment         Comment on target.
 * @param[in]   port_list_id    Port list of target (overrides \p port_range).
 * @param[in]   port_range      Port range of target.
 * @param[in]   ssh_credential  SSH credential.
 * @param[in]   ssh_elevate_credential  SSH previlige escalation credential.
 * @param[in]   ssh_port        Port for SSH login.
 * @param[in]   smb_credential        SMB credential.
 * @param[in]   esxi_credential       ESXi credential.
 * @param[in]   snmp_credential       SNMP credential.
 * @param[in]   krb5_credential       Kerberos credential.
 * @param[in]   reverse_lookup_only   Scanner preference reverse_lookup_only.
 * @param[in]   reverse_lookup_unify  Scanner preference reverse_lookup_unify.
 * @param[in]   alive_tests             Alive tests array.
 * @param[in]   alive_test_str          Legacy alive tests string.
 * @param[in]   allow_simultaneous_ips  Scanner preference allow_simultaneous_ips.
 * @param[out]  target                  Created target.
 *
 * @return 0 success, 1 target exists already, 2 error in host specification,
 *         3 too many hosts, 4 error in port range, 5 error in SSH port,
 *         6 failed to find port list, 7 error in alive tests,
 *         8 invalid SSH credential type, 9 invalid SSH elevate credential type,
 *         10 invalid SMB credential type, 11 invalid ESXi credential type,
 *         12 invalid SNMP credential type, 13 port range or port list required,
 *         14 SSH elevate credential without an SSH credential,
 *         15 elevate credential must be different from the SSH credential,
 *         16 invalid Kerberos 5 credential type,
 *         30 cannot use both alive_tests string and sub-elements,
 *         99 permission denied, -1 error.
 */
int
create_target (const char* name, const char* asset_hosts_filter,
               const char* hosts, const char* exclude_hosts,
               const char* comment, const char* port_list_id,
               const char* port_range, credential_t ssh_credential,
               credential_t ssh_elevate_credential,
               const char* ssh_port, credential_t smb_credential,
               credential_t esxi_credential, credential_t snmp_credential,
               credential_t krb5_credential,
               const char *reverse_lookup_only,
               const char *reverse_lookup_unify,
               GPtrArray *alive_tests,
               const char *alive_test_str,
               const char *allow_simultaneous_ips,
               target_t* target)
{
  gchar *quoted_name, *quoted_hosts, *quoted_exclude_hosts, *quoted_comment;
  gchar *port_list_comment, *quoted_ssh_port, *clean, *clean_exclude;
  gchar *chosen_hosts;
  port_list_t port_list;
  int ret, alive_test, max;
  target_t new_target;

  assert (current_credentials.uuid);

  if (port_range && validate_port_range (port_range))
    return 4;

  if (ssh_port && validate_port (ssh_port))
    return 5;

  if (alive_tests && alive_tests->len
      && alive_test_str && strlen (alive_test_str))
    return 30;
  else if (alive_tests && alive_tests->len)
    alive_test = alive_test_from_array (alive_tests);
  else if (alive_test_str && strlen (alive_test_str))
    alive_test = alive_test_from_string (alive_test_str);
  else
    alive_test = 0;
  if (alive_test <= -1)
    return 7;

  if (ssh_elevate_credential && (!ssh_credential))
    return 14;

  if (ssh_credential && (ssh_elevate_credential == ssh_credential))
    return 15;

  sql_begin_immediate ();

  if (acl_user_may ("create_target") == 0)
    {
      sql_rollback ();
      return 99;
    }

  if (resource_with_name_exists (name, "target", 0))
    {
      sql_rollback ();
      return 1;
    }

  if (port_list_id)
    {
      if (find_port_list_with_permission (port_list_id, &port_list,
                                          "get_port_lists")
          || (port_list == 0))
        {
          sql_rollback ();
          return 6;
        }
    }
  else if (port_range == NULL)
    {
      sql_rollback ();
      return 13;
    }
  else
    {
      port_list_comment = g_strdup_printf ("Autogenerated for target %s.", name);
      ret = create_port_list_unique (name, port_list_comment, port_range,
                                     &port_list);
      g_free (port_list_comment);
      if (ret)
        {
          sql_rollback ();
          return ret;
        }
    }

  if (asset_hosts_filter)
    {
      iterator_t asset_hosts;
      int previous;
      get_data_t get;
      GString *buffer;

      memset (&get, 0, sizeof (get));
      get.filter = g_strdup (asset_hosts_filter);
      init_asset_host_iterator (&asset_hosts, &get);
      g_free (get.filter);
      previous = 0;
      buffer = g_string_new ("");
      while (next (&asset_hosts))
        {
          g_string_append_printf (buffer,
                                  "%s%s",
                                  previous ? ", " : "",
                                  get_iterator_name (&asset_hosts));
          previous = 1;
        }
      cleanup_iterator (&asset_hosts);
      chosen_hosts = g_string_free (buffer, FALSE);

      g_debug ("asset chosen_hosts: %s", chosen_hosts);
    }
  else
    {
      chosen_hosts = g_strdup (hosts);
      g_debug ("manual chosen_hosts: %s", chosen_hosts);
    }


  clean = clean_hosts (chosen_hosts, &max);
  g_free (chosen_hosts);
  if (exclude_hosts)
    clean_exclude = clean_hosts (exclude_hosts, NULL);
  else
    clean_exclude = g_strdup ("");

  max = manage_count_hosts (clean, clean_exclude);
  if (max <= 0)
    {
      g_free (clean);
      g_free (clean_exclude);
      sql_rollback ();
      return 2;
    }
  if (max > manage_max_hosts ())
    {
      g_free (clean);
      g_free (clean_exclude);
      sql_rollback ();
      return 3;
    }
  quoted_hosts = sql_quote (clean);
  quoted_exclude_hosts = sql_quote (clean_exclude);
  g_free (clean);
  g_free (clean_exclude);

  if (ssh_credential)
    quoted_ssh_port = sql_insert (ssh_port ? ssh_port : "22");
  else
    quoted_ssh_port = g_strdup ("NULL");

  if (reverse_lookup_only == NULL || strcmp (reverse_lookup_only, "0") == 0)
    reverse_lookup_only = "0";
  else
    reverse_lookup_only = "1";
  if (reverse_lookup_unify == NULL || strcmp (reverse_lookup_unify, "0") == 0)
    reverse_lookup_unify = "0";
  else
    reverse_lookup_unify = "1";
  if (allow_simultaneous_ips
      && strcmp (allow_simultaneous_ips, "0") == 0)
    allow_simultaneous_ips = "0";
  else
    allow_simultaneous_ips = "1";

  quoted_name = sql_quote (name ?: "");

  if (comment)
    quoted_comment = sql_quote (comment);
  else
    quoted_comment = sql_quote ("");

  sql ("INSERT INTO targets"
       " (uuid, name, owner, hosts, exclude_hosts, comment, "
       "  port_list, reverse_lookup_only, reverse_lookup_unify, alive_test,"
       "  allow_simultaneous_ips,"
       "  creation_time, modification_time)"
       " VALUES (make_uuid (), '%s',"
       " (SELECT id FROM users WHERE users.uuid = '%s'),"
       " '%s', '%s', '%s', %llu, '%s', '%s', %i,"
       " %s,"
       " m_now (), m_now ());",
        quoted_name, current_credentials.uuid,
        quoted_hosts, quoted_exclude_hosts, quoted_comment, port_list,
        reverse_lookup_only, reverse_lookup_unify, alive_test,
        allow_simultaneous_ips);

  new_target = sql_last_insert_id ();
  if (target)
    *target = new_target;

  g_free (quoted_comment);
  g_free (quoted_name);
  g_free (quoted_hosts);
  g_free (quoted_exclude_hosts);

  if (ssh_credential)
    {
      gchar *type = credential_type (ssh_credential);
      if (strcmp (type, "usk") && strcmp (type, "up")
#if ENABLE_CREDENTIAL_STORES
          && strcmp (type, "cs_usk") && strcmp (type, "cs_up")
#endif
          )
        {
          sql_rollback ();
          g_free (quoted_ssh_port);
          return 8;
        }
      g_free (type);

      sql ("INSERT INTO targets_login_data"
           " (target, type, credential, port)"
           " VALUES (%llu, 'ssh', %llu, %s);",
           new_target, ssh_credential, quoted_ssh_port);
    }
  g_free (quoted_ssh_port);

  if (ssh_elevate_credential)
    {
      gchar *type = credential_type (ssh_elevate_credential);
      if (strcmp (type, "up")
#if ENABLE_CREDENTIAL_STORES
          && strcmp (type, "cs_up")
#endif
         )
        {
          sql_rollback ();
          return 9;
        }
      g_free (type);

      sql ("INSERT INTO targets_login_data"
           " (target, type, credential, port)"
           " VALUES (%llu, 'elevate', %llu, %s);",
           new_target, ssh_elevate_credential, "0");
    }

  if (smb_credential)
    {
      gchar *type = credential_type (smb_credential);
      if (strcmp (type, "up")
#if ENABLE_CREDENTIAL_STORES
          && strcmp (type, "cs_up")
#endif
         )
        {
          sql_rollback ();
          return 10;
        }
      g_free (type);

      sql ("INSERT INTO targets_login_data"
           " (target, type, credential, port)"
           " VALUES (%llu, 'smb', %llu, %s);",
           new_target, smb_credential, "0");
    }

  if (esxi_credential)
    {
      gchar *type = credential_type (esxi_credential);
      if (strcmp (type, "up")
#if ENABLE_CREDENTIAL_STORES
          && strcmp (type, "cs_up")
#endif
        )
        {
          sql_rollback ();
          return 11;
        }
      g_free (type);

      sql ("INSERT INTO targets_login_data"
           " (target, type, credential, port)"
           " VALUES (%llu, 'esxi', %llu, %s);",
           new_target, esxi_credential, "0");
    }

  if (snmp_credential)
    {
      gchar *type = credential_type (snmp_credential);
      if (strcmp (type, "snmp")
#if ENABLE_CREDENTIAL_STORES
          && strcmp (type, "cs_snmp")
#endif
         )
        {
          sql_rollback ();
          return 12;
        }
      g_free (type);

      sql ("INSERT INTO targets_login_data"
           " (target, type, credential, port)"
           " VALUES (%llu, 'snmp', %llu, %s);",
           new_target, snmp_credential, "0");
    }

  if (krb5_credential)
    {
      gchar *type = credential_type (krb5_credential);
      if (strcmp (type, "krb5")
#if ENABLE_CREDENTIAL_STORES
          && strcmp (type, "cs_krb5")
#endif
         )
        {
          sql_rollback ();
          g_free (type);
          return 16;
        }
      g_free (type);

      sql ("INSERT INTO targets_login_data"
           " (target, type, credential, port)"
           " VALUES (%llu, 'krb5', %llu, %s);",
           new_target, krb5_credential, "0");
    }

  sql_commit ();

  return 0;
}

/**
 * @brief Modify a target.
 *
 * @param[in]   target_id       UUID of target.
 * @param[in]   name            Name of target.
 * @param[in]   hosts           Host list of target.
 * @param[in]   exclude_hosts   List of hosts to exclude from \p hosts.
 * @param[in]   comment         Comment on target.
 * @param[in]   port_list_id    Port list of target (overrides \p port_range).
 * @param[in]   ssh_credential_id  SSH credential.
 * @param[in]   ssh_elevate_credential_id  SSH previlige escalation credential.
 * @param[in]   ssh_port        Port for SSH login.
 * @param[in]   smb_credential_id  SMB credential.
 * @param[in]   esxi_credential_id  ESXi credential.
 * @param[in]   snmp_credential_id  SNMP credential.
 * @param[in]   krb5_credential_id  Kerberos 5 credential.
 * @param[in]   reverse_lookup_only   Scanner preference reverse_lookup_only.
 * @param[in]   reverse_lookup_unify  Scanner preference reverse_lookup_unify.
 * @param[in]   alive_tests            Alive tests array.
 * @param[in]   alive_test_str         Alive test string.
 * @param[in]   allow_simultaneous_ips Scanner preference allow_simultaneous_ips.
 *
 * @return 0 success, 1 target exists already, 2 error in host specification,
 *         3 too many hosts, 4 error in port range, 5 error in SSH port,
 *         6 failed to find port list, 7 failed to find SSH cred, 8 failed to
 *         find SMB cred, 9 failed to find target, 10 error in alive tests,
 *         11 zero length name, 12 exclude hosts requires hosts
 *         13 hosts requires exclude hosts,
 *         14 hosts must be at least one character, 15 target is in use,
 *         16 failed to find ESXi cred, 17 failed to find SNMP cred,
 *         18 invalid SSH credential type, 19 invalid SMB credential type,
 *         20 invalid ESXi credential type, 21 invalid SNMP credential type,
 *         22 failed to find SSH elevate cred, 23 invalid SSH elevate
 *         credential type, 24 SSH elevate credential without SSH credential,
 *         25 SSH elevate credential equals SSH credential,
 *         26 failed to find Kerberos 5 credential,
 *         27 invalid Kerberos 5 credential type,
 *         28 cannot use both SMB and Kerberos 5 credential,
 *         30 cannot use both alive_tests string and sub-elements,
 *         99 permission denied, -1 error.
 */
int
modify_target (const char *target_id, const char *name, const char *hosts,
               const char *exclude_hosts, const char *comment,
               const char *port_list_id, const char *ssh_credential_id,
               const char *ssh_elevate_credential_id,
               const char *ssh_port, const char *smb_credential_id,
               const char *esxi_credential_id, const char* snmp_credential_id,
               const char *krb5_credential_id,
               const char *reverse_lookup_only,
               const char *reverse_lookup_unify,
               GPtrArray *alive_tests,
               const char *alive_test_str,
               const char *allow_simultaneous_ips)
{
  target_t target;
  credential_t ssh_credential = 0;
  credential_t ssh_elevate_credential = 0;
  credential_t smb_credential;
  credential_t krb5_credential;

  assert (target_id);

  sql_begin_immediate ();

  assert (current_credentials.uuid);

  if (acl_user_may ("modify_target") == 0)
    {
      sql_rollback ();
      return 99;
    }

  if (hosts && (exclude_hosts == NULL))
    {
      sql_rollback ();
      return 13;
    }

  target = 0;
  if (find_target_with_permission (target_id, &target, "modify_target"))
    {
      sql_rollback ();
      return -1;
    }

  if (target == 0)
    {
      sql_rollback ();
      return 9;
    }

  if (name)
    {
      gchar *quoted_name;

      if (strlen (name) == 0)
        {
          sql_rollback ();
          return 11;
        }
      if (resource_with_name_exists (name, "target", target))
        {
          sql_rollback ();
          return 1;
        }

      quoted_name = sql_quote (name);
      sql ("UPDATE targets SET"
           " name = '%s',"
           " modification_time = m_now ()"
           " WHERE id = %llu;",
           quoted_name,
           target);

      g_free (quoted_name);
    }

  if (comment)
    {
      gchar *quoted_comment;
      quoted_comment = sql_quote (comment);
      sql ("UPDATE targets SET"
           " comment = '%s',"
           " modification_time = m_now ()"
           " WHERE id = %llu;",
           quoted_comment,
           target);
      g_free (quoted_comment);
    }

  if (allow_simultaneous_ips)
    {
      if (target_in_use (target))
        {
          sql_rollback ();
          return 15;
        }

      sql ("UPDATE targets SET"
           " allow_simultaneous_ips = '%i',"
           " modification_time = m_now ()"
           " WHERE id = %llu;",
           strcmp (allow_simultaneous_ips, "0") ? 1 : 0,
           target);
    }

  if (alive_tests && alive_tests->len
      && alive_test_str && strlen (alive_test_str))
    return 30;
  else if (alive_tests && alive_tests->len)
    {
      int alive_test;

      alive_test = alive_test_from_array (alive_tests);
      if (alive_test <= -1)
        {
          sql_rollback ();
          return 10;
        }
      sql ("UPDATE targets SET"
           " alive_test = '%i',"
           " modification_time = m_now ()"
           " WHERE id = %llu;",
           alive_test,
           target);
    }
  else if (alive_test_str && strlen (alive_test_str))
    {
      int alive_test;

      alive_test = alive_test_from_string (alive_test_str);
      if (alive_test <= -1)
        {
          sql_rollback ();
          return 10;
        }
      sql ("UPDATE targets SET"
           " alive_test = '%i',"
           " modification_time = m_now ()"
           " WHERE id = %llu;",
           alive_test,
           target);
    }

  if (port_list_id)
    {
      port_list_t port_list;

      if (target_in_use (target))
        {
          sql_rollback ();
          return 15;
        }

      port_list = 0;
      if (find_port_list_with_permission (port_list_id, &port_list,
                                          "get_port_lists"))
        {
          sql_rollback ();
          return -1;
        }

      if (port_list == 0)
        {
          sql_rollback ();
          return 6;
        }

      sql ("UPDATE targets SET"
           " port_list = %llu,"
           " modification_time = m_now ()"
           " WHERE id = %llu;",
           port_list,
           target);
    }

  if (ssh_credential_id)
    {
      if (target_in_use (target))
        {
          sql_rollback ();
          return 15;
        }

      ssh_credential = 0;
      if (strcmp (ssh_credential_id, "0"))
        {
          int port_int;
          gchar *type;

          if (find_credential_with_permission (ssh_credential_id,
                                               &ssh_credential,
                                               "get_credentials"))
            {
              sql_rollback ();
              return -1;
            }

          if (ssh_credential == 0)
            {
              sql_rollback ();
              return 7;
            }

          if (ssh_port && strcmp (ssh_port, "0") && strcmp (ssh_port, ""))
            {
              if (validate_port (ssh_port))
                {
                  sql_rollback ();
                  return 5;
                }
              port_int = atoi (ssh_port);
            }
          else
            port_int = 22;

          type = credential_type (ssh_credential);
          if (strcmp (type, "up") && strcmp (type, "usk")
#if ENABLE_CREDENTIAL_STORES
              && strcmp (type, "cs_up") && strcmp (type, "cs_usk")
#endif
          )
            {
              sql_rollback ();
              return 18;
            }
          g_free (type);

          set_target_login_data (target, "ssh", ssh_credential, port_int);
        }
      else
        set_target_login_data (target, "ssh", 0, 0);
    }

  if (ssh_elevate_credential_id)
    {
      if (target_in_use (target))
        {
          sql_rollback ();
          return 15;
        }

      ssh_elevate_credential = 0;
      if (strcmp (ssh_elevate_credential_id, "0"))
        {
          gchar *type;
          if (find_credential_with_permission (ssh_elevate_credential_id,
                                               &ssh_elevate_credential,
                                               "get_credentials"))
            {
              sql_rollback ();
              return -1;
            }

          if (ssh_elevate_credential == 0)
            {
              sql_rollback ();
              return 22;
            }

          type = credential_type (ssh_elevate_credential);
          if (strcmp (type, "up")
#if ENABLE_CREDENTIAL_STORES
              && strcmp (type, "cs_up")
#endif
            )
            {
              sql_rollback ();
              return 23;
            }
          g_free (type);

          set_target_login_data (target, "elevate", ssh_elevate_credential, 0);
        }
      else
        set_target_login_data (target, "elevate", 0, 0);
    }

  if (smb_credential_id)
    {
      if (target_in_use (target))
        {
          sql_rollback ();
          return 15;
        }

      smb_credential = 0;
      if (strcmp (smb_credential_id, "0"))
        {
          gchar *type;
          if (find_credential_with_permission (smb_credential_id,
                                               &smb_credential,
                                               "get_credentials"))
            {
              sql_rollback ();
              return -1;
            }

          if (smb_credential == 0)
            {
              sql_rollback ();
              return 7;
            }

          type = credential_type (smb_credential);
          if (strcmp (type, "up")
#if ENABLE_CREDENTIAL_STORES
              && strcmp (type, "cs_up")
#endif
             )
            {
              sql_rollback ();
              return 19;
            }
          g_free (type);

          set_target_login_data (target, "smb", smb_credential, 0);
        }
      else
        set_target_login_data (target, "smb", 0, 0);
    }
  else
    smb_credential = target_smb_credential (target);

  if (esxi_credential_id)
    {
      credential_t esxi_credential;

      if (target_in_use (target))
        {
          sql_rollback ();
          return 15;
        }

      esxi_credential = 0;
      if (strcmp (esxi_credential_id, "0"))
        {
          gchar *type;
          if (find_credential_with_permission (esxi_credential_id,
                                               &esxi_credential,
                                               "get_credentials"))
            {
              sql_rollback ();
              return -1;
            }

          if (esxi_credential == 0)
            {
              sql_rollback ();
              return 16;
            }

          type = credential_type (esxi_credential);
          if (strcmp (type, "up")
#if ENABLE_CREDENTIAL_STORES
              && strcmp (type, "cs_up")
#endif
             )
            {
              sql_rollback ();
              return 20;
            }
          g_free (type);

          set_target_login_data (target, "esxi", esxi_credential, 0);
        }
      else
        set_target_login_data (target, "esxi", 0, 0);
    }

  if (snmp_credential_id)
    {
      credential_t snmp_credential;

      if (target_in_use (target))
        {
          sql_rollback ();
          return 15;
        }

      snmp_credential = 0;
      if (strcmp (snmp_credential_id, "0"))
        {
          gchar *type;
          if (find_credential_with_permission (snmp_credential_id,
                                               &snmp_credential,
                                               "get_credentials"))
            {
              sql_rollback ();
              return -1;
            }

          if (snmp_credential == 0)
            {
              sql_rollback ();
              return 17;
            }

          type = credential_type (snmp_credential);
          if (strcmp (type, "snmp")
#if ENABLE_CREDENTIAL_STORES
              && strcmp (type, "cs_snmp")
#endif
             )
            {
              sql_rollback ();
              return 21;
            }
          g_free (type);

          set_target_login_data (target, "snmp", snmp_credential, 0);
        }
      else
        set_target_login_data (target, "snmp", 0, 0);
    }

  if (ssh_credential_id || ssh_elevate_credential_id)
    {
      if (!ssh_credential_id)
        ssh_credential = target_ssh_credential (target);
      if (!ssh_elevate_credential_id)
        ssh_elevate_credential = target_ssh_elevate_credential (target);

      if (ssh_elevate_credential && !ssh_credential)
        {
          sql_rollback ();
          return 24;
        }
      if (ssh_credential && (ssh_credential == ssh_elevate_credential))
        {
          sql_rollback ();
          return 25;
        }
    }

  if (krb5_credential_id)
    {
      if (target_in_use (target))
        {
          sql_rollback ();
          return 15;
        }

      krb5_credential = 0;
      if (strcmp (krb5_credential_id, "0"))
        {
          gchar *type;
          if (find_credential_with_permission (krb5_credential_id,
                                               &krb5_credential,
                                               "get_credentials"))
            {
              sql_rollback ();
              return -1;
            }

          if (krb5_credential == 0)
            {
              sql_rollback ();
              return 26;
            }

          type = credential_type (krb5_credential);
          if (strcmp (type, "krb5"))
            {
              sql_rollback ();
              g_free (type);
              return 27;
            }
          g_free (type);

          set_target_login_data (target, "krb5", krb5_credential, 0);
        }
      else
        set_target_login_data (target, "krb5", 0, 0);
    }
  else
    krb5_credential = target_krb5_credential (target);

  if (smb_credential && krb5_credential)
    {
      sql_rollback ();
      return 28;
    }

  if (exclude_hosts)
    {
      gchar *quoted_exclude_hosts, *quoted_hosts, *clean, *clean_exclude;
      int max;

      if (target_in_use (target))
        {
          sql_rollback ();
          return 15;
        }

      if (hosts == NULL)
        {
          sql_rollback ();
          return 12;
        }

      if (strlen (hosts) == 0)
        {
          sql_rollback ();
          return 14;
        }

      clean = clean_hosts (hosts, &max);
      clean_exclude = clean_hosts (exclude_hosts, NULL);

      max = manage_count_hosts (clean, clean_exclude);
      if (max <= 0)
        {
          g_free (clean);
          g_free (clean_exclude);
          sql_rollback ();
          return 2;
        }

      if (max > manage_max_hosts ())
        {
          g_free (clean);
          g_free (clean_exclude);
          sql_rollback ();
          return 3;
        }
      quoted_hosts = sql_quote (clean);
      quoted_exclude_hosts = sql_quote (clean_exclude);
      g_free (clean);
      g_free (clean_exclude);

      sql ("UPDATE targets SET"
           " hosts = '%s',"
           " exclude_hosts = '%s',"
           " modification_time = m_now ()"
           " WHERE id = %llu;",
           quoted_hosts,
           quoted_exclude_hosts,
           target);

      g_free (quoted_hosts);
      g_free (quoted_exclude_hosts);
    }

  if (reverse_lookup_only)
    {
      if (target_in_use (target))
        {
          sql_rollback ();
          return 15;
        }

      sql ("UPDATE targets SET"
           " reverse_lookup_only = '%i',"
           " modification_time = m_now ()"
           " WHERE id = %llu;",
           strcmp (reverse_lookup_only, "0") ? 1 : 0,
           target);
    }

  if (reverse_lookup_unify)
    {
      if (target_in_use (target))
        {
          sql_rollback ();
          return 15;
        }

      sql ("UPDATE targets SET"
           " reverse_lookup_unify = '%i',"
           " modification_time = m_now ()"
           " WHERE id = %llu;",
           strcmp (reverse_lookup_unify, "0") ? 1 : 0,
           target);
    }

  sql_commit ();

  return 0;
}
