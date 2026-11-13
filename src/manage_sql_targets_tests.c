/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_sql_targets.c"

#include <cgreen/cgreen.h>
#include <stdarg.h>

#define TARGET 1
#define PORT_LIST 41
#define OTHER_PORT_LIST 42
#define SSH_CREDENTIAL 51
#define ELEVATE_CREDENTIAL 52
#define SMB_CREDENTIAL 53
#define ESXI_CREDENTIAL 54
#define SNMP_CREDENTIAL 55
#define KRB5_CREDENTIAL 56

typedef struct
{
  gboolean in_use;
  gboolean transaction_open;
  int begin_count;
  int commit_count;
  int rollback_count;
  int in_use_queries;
  int protected_writes;
  gchar *name;
  gchar *comment;
  gchar *hosts;
  gchar *exclude_hosts;
  gchar *snapshot_name;
  gchar *snapshot_comment;
  int allow_simultaneous_ips;
  int reverse_lookup_only;
  int reverse_lookup_unify;
  port_list_t port_list;
  credential_t ssh_credential;
  credential_t elevate_credential;
  credential_t smb_credential;
  credential_t esxi_credential;
  credential_t snmp_credential;
  credential_t krb5_credential;
  int ssh_port;
} target_model_t;

static target_model_t model;

static void
replace_string (gchar **destination, const gchar *value)
{
  g_free (*destination);
  *destination = g_strdup (value);
}

static gchar *
query_string (const char *format, va_list args)
{
  return g_strdup_vprintf (format, args);
}

static credential_t
credential_for_query (const gchar *query)
{
  if (strstr (query, "type = 'ssh'"))
    return model.ssh_credential;
  if (strstr (query, "type = 'elevate'"))
    return model.elevate_credential;
  if (strstr (query, "type = 'smb'"))
    return model.smb_credential;
  if (strstr (query, "type = 'esxi'"))
    return model.esxi_credential;
  if (strstr (query, "type = 'snmp'"))
    return model.snmp_credential;
  if (strstr (query, "type = 'krb5'"))
    return model.krb5_credential;
  return 0;
}

static const gchar *
credential_uuid_for_id (credential_t credential)
{
  switch (credential)
    {
    case SSH_CREDENTIAL:
      return "ssh-credential";
    case ELEVATE_CREDENTIAL:
      return "elevate-credential";
    case SMB_CREDENTIAL:
      return "smb-credential";
    case ESXI_CREDENTIAL:
      return "esxi-credential";
    case SNMP_CREDENTIAL:
      return "snmp-credential";
    case KRB5_CREDENTIAL:
      return "krb5-credential";
    default:
      return NULL;
    }
}

static void
set_default_model (gboolean in_use)
{
  memset (&model, 0, sizeof (model));
  model.in_use = in_use;
  model.name = g_strdup ("Original target");
  model.comment = g_strdup ("Original comment");
  model.hosts = g_strdup ("192.0.2.1, 192.0.2.2");
  model.exclude_hosts = g_strdup ("192.0.2.2");
  model.allow_simultaneous_ips = 1;
  model.reverse_lookup_only = 1;
  model.reverse_lookup_unify = 0;
  model.port_list = PORT_LIST;
  model.ssh_credential = SSH_CREDENTIAL;
  model.elevate_credential = ELEVATE_CREDENTIAL;
  model.smb_credential = SMB_CREDENTIAL;
  model.esxi_credential = ESXI_CREDENTIAL;
  model.snmp_credential = SNMP_CREDENTIAL;
  model.ssh_port = 22;
}

static void
clear_model (void)
{
  g_free (model.name);
  g_free (model.comment);
  g_free (model.hosts);
  g_free (model.exclude_hosts);
  g_free (model.snapshot_name);
  g_free (model.snapshot_comment);
}

void
__wrap_sql_begin_immediate (void)
{
  model.begin_count++;
  model.transaction_open = TRUE;
  replace_string (&model.snapshot_name, model.name);
  replace_string (&model.snapshot_comment, model.comment);
}

void
__wrap_sql_commit (void)
{
  model.commit_count++;
  model.transaction_open = FALSE;
}

void
__wrap_sql_rollback (void)
{
  model.rollback_count++;
  model.transaction_open = FALSE;
  replace_string (&model.name, model.snapshot_name);
  replace_string (&model.comment, model.snapshot_comment);
}

int
__wrap_acl_user_may (const char *permission)
{
  (void) permission;
  return 1;
}

gboolean
__wrap_find_resource_with_permission (const char *type, const char *uuid,
                                      resource_t *resource,
                                      const char *permission, int trash)
{
  (void) permission;
  (void) trash;

  *resource = 0;
  if (strcmp (type, "target") == 0 && strcmp (uuid, "target-id") == 0)
    *resource = TARGET;
  else if (strcmp (type, "port_list") == 0
           && strcmp (uuid, "other-port-list") == 0)
    *resource = OTHER_PORT_LIST;
  return FALSE;
}

gboolean
__wrap_resource_with_name_exists (const char *name, const char *type,
                                  resource_t exclude)
{
  (void) name;
  (void) type;
  (void) exclude;
  return FALSE;
}

gchar *
__wrap_sql_quote (const char *value)
{
  return g_strdup (value);
}

int
__wrap_manage_max_hosts (void)
{
  return 4096;
}

int
__wrap_sql_int (const char *format, ...)
{
  va_list args;
  gchar *query;
  int result = 0;

  va_start (args, format);
  query = query_string (format, args);
  va_end (args);

  if (strstr (query, "SELECT count(*) FROM tasks"))
    {
      model.in_use_queries++;
      result = model.in_use;
    }
  else if (strstr (query, "SELECT allow_simultaneous_ips FROM targets"))
    result = model.allow_simultaneous_ips;
  else if (strstr (query, "SELECT NOT EXISTS")
           && strstr (query, "targets_login_data"))
    result = credential_for_query (query) == 0;
  else if (strstr (query, "SELECT port FROM targets_login_data"))
    result = model.ssh_port;

  g_free (query);
  return result;
}

int
__wrap_sql_int64 (long long int *result, const char *format, ...)
{
  va_list args;
  gchar *query;

  va_start (args, format);
  query = query_string (format, args);
  va_end (args);

  if (strstr (query, "SELECT port_list FROM targets"))
    *result = model.port_list;
  else if (strstr (query, "SELECT credential FROM targets_login_data"))
    *result = credential_for_query (query);
  else
    {
      g_free (query);
      return 1;
    }

  g_free (query);
  return 0;
}

char *
__wrap_sql_string (const char *format, ...)
{
  va_list args;
  gchar *query;
  const gchar *value = NULL;

  va_start (args, format);
  query = query_string (format, args);
  va_end (args);

  if (strstr (query, "SELECT hosts FROM targets"))
    value = model.hosts;
  else if (strstr (query, "SELECT exclude_hosts FROM targets"))
    value = model.exclude_hosts;
  else if (strstr (query, "SELECT reverse_lookup_only FROM targets"))
    value = model.reverse_lookup_only ? "1" : "0";
  else if (strstr (query, "SELECT reverse_lookup_unify FROM targets"))
    value = model.reverse_lookup_unify ? "1" : "0";
  else if (strstr (query, "SELECT uuid FROM port_lists"))
    value = model.port_list == PORT_LIST ? "port-list" : "other-port-list";
  else if (strstr (query, "SELECT uuid FROM credentials"))
    {
      long long credential = 0;
      sscanf (query, "SELECT uuid FROM credentials WHERE id = %lld;",
              &credential);
      value = credential_uuid_for_id (credential);
    }

  g_free (query);
  return value ? g_strdup (value) : NULL;
}

static gchar *
updated_string (const gchar *query, const gchar *column)
{
  gchar *start, *end;

  start = g_strstr_len (query, -1, column);
  if (start == NULL)
    return NULL;
  start += strlen (column);
  end = strchr (start, '\'');
  if (end == NULL)
    return NULL;
  return g_strndup (start, end - start);
}

void
__wrap_sql (const char *format, ...)
{
  va_list args;
  gchar *query, *value;

  va_start (args, format);
  query = query_string (format, args);
  va_end (args);

  value = updated_string (query, " name = '");
  if (value)
    {
      replace_string (&model.name, value);
      g_free (value);
    }

  value = updated_string (query, " comment = '");
  if (value)
    {
      replace_string (&model.comment, value);
      g_free (value);
    }

  if (strstr (query, " allow_simultaneous_ips = '"))
    {
      sscanf (strstr (query, " allow_simultaneous_ips = '") + 27, "%d",
              &model.allow_simultaneous_ips);
      model.protected_writes++;
    }
  else if (strstr (query, " port_list = "))
    {
      sscanf (strstr (query, " port_list = ") + 13, "%lld", &model.port_list);
      model.protected_writes++;
    }
  else if (strstr (query, " reverse_lookup_only = '"))
    {
      sscanf (strstr (query, " reverse_lookup_only = '") + 24, "%d",
              &model.reverse_lookup_only);
      model.protected_writes++;
    }
  else if (strstr (query, " reverse_lookup_unify = '"))
    {
      sscanf (strstr (query, " reverse_lookup_unify = '") + 25, "%d",
              &model.reverse_lookup_unify);
      model.protected_writes++;
    }
  else if (strstr (query, " hosts = '"))
    model.protected_writes++;
  else if (strstr (query, "targets_login_data"))
    model.protected_writes++;

  g_free (query);
}

Describe (manage_sql_targets);
BeforeEach (manage_sql_targets)
{
  set_default_model (TRUE);
  current_credentials.uuid = "user-id";
}
AfterEach (manage_sql_targets)
{
  clear_model ();
  current_credentials.uuid = NULL;
}

Ensure (manage_sql_targets, accepts_full_noop_for_in_use_target)
{
  int ret;

  ret = modify_target ("target-id", "Original target", "192.0.2.1, 192.0.2.2",
                       "192.0.2.2", "Updated comment", "port-list",
                       "ssh-credential", "elevate-credential", "0",
                       "smb-credential", "esxi-credential", "snmp-credential",
                       "0", "true", "0", NULL, "ICMP Ping", "true");

  assert_that (ret, is_equal_to (0));
  assert_that (model.comment, is_equal_to_string ("Updated comment"));
  assert_that (model.protected_writes, is_equal_to (0));
  assert_that (model.in_use_queries, is_equal_to (1));
  assert_that (model.commit_count, is_equal_to (1));
  assert_that (model.transaction_open, is_false);
}

Ensure (manage_sql_targets, accepts_unset_credentials_and_default_ssh_port)
{
  int ret;

  model.ssh_credential = 0;
  model.elevate_credential = 0;
  model.smb_credential = 0;
  model.esxi_credential = 0;
  model.snmp_credential = 0;

  ret =
    modify_target ("target-id", NULL, NULL, NULL, "Updated comment", NULL, "0",
                   "0", "0", "0", "0", "0", "0", NULL, NULL, NULL, NULL, NULL);

  assert_that (ret, is_equal_to (0));
  assert_that (model.comment, is_equal_to_string ("Updated comment"));
  assert_that (model.protected_writes, is_equal_to (0));
  assert_that (model.in_use_queries, is_equal_to (1));
}

static int
modify_with_change (int change)
{
  return modify_target (
    "target-id", "Renamed target", change == 8 ? "198.51.100.1" : NULL,
    change == 8 ? "" : NULL, "Changed comment",
    change == 1 ? "other-port-list" : NULL,
    change == 2 ? "ssh-credential" : NULL,
    change == 3 ? "other-elevate-credential" : NULL,
    change == 2 ? "2222" : NULL, change == 4 ? "other-smb-credential" : NULL,
    change == 5 ? "other-esxi-credential" : NULL,
    change == 6 ? "other-snmp-credential" : NULL,
    change == 7 ? "krb5-credential" : NULL, change == 9 ? "0" : NULL,
    change == 10 ? "1" : NULL, NULL, NULL, change == 0 ? "0" : NULL);
}

Ensure (manage_sql_targets, rejects_real_protected_changes_atomically)
{
  int change;

  for (change = 0; change <= 10; change++)
    {
      int ret = modify_with_change (change);

      assert_that (ret, is_equal_to (15));
      assert_that (model.name, is_equal_to_string ("Original target"));
      assert_that (model.comment, is_equal_to_string ("Original comment"));
      assert_that (model.protected_writes, is_equal_to (0));
      assert_that (model.in_use_queries, is_equal_to (1));
      assert_that (model.rollback_count, is_equal_to (1));
      assert_that (model.transaction_open, is_false);

      clear_model ();
      set_default_model (TRUE);
    }
}

Ensure (manage_sql_targets, preserves_omitted_fields_for_in_use_target)
{
  int ret;

  ret = modify_target ("target-id", NULL, NULL, NULL, "Updated comment", NULL,
                       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
                       NULL, NULL, NULL);

  assert_that (ret, is_equal_to (0));
  assert_that (model.comment, is_equal_to_string ("Updated comment"));
  assert_that (model.in_use_queries, is_equal_to (0));
  assert_that (model.protected_writes, is_equal_to (0));
}

Ensure (manage_sql_targets, preserves_updates_for_unused_target)
{
  int ret;

  model.in_use = FALSE;
  ret = modify_target ("target-id", "Renamed target", NULL, NULL,
                       "Updated comment", "other-port-list", NULL, NULL, NULL,
                       NULL, NULL, NULL, NULL, "0", "1", NULL, NULL, "0");

  assert_that (ret, is_equal_to (0));
  assert_that (model.name, is_equal_to_string ("Renamed target"));
  assert_that (model.comment, is_equal_to_string ("Updated comment"));
  assert_that (model.port_list, is_equal_to (OTHER_PORT_LIST));
  assert_that (model.allow_simultaneous_ips, is_equal_to (0));
  assert_that (model.reverse_lookup_only, is_equal_to (0));
  assert_that (model.reverse_lookup_unify, is_equal_to (1));
  assert_that (model.commit_count, is_equal_to (1));
}

Ensure (manage_sql_targets, preserves_errors_for_unused_target)
{
  int ret;

  model.in_use = FALSE;
  ret = modify_target ("target-id", "Renamed target", NULL, NULL,
                       "Updated comment", "missing-port-list", NULL, NULL, NULL,
                       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);

  assert_that (ret, is_equal_to (6));
  assert_that (model.name, is_equal_to_string ("Original target"));
  assert_that (model.comment, is_equal_to_string ("Original comment"));
  assert_that (model.rollback_count, is_equal_to (1));
  assert_that (model.transaction_open, is_false);
}

Ensure (manage_sql_targets, rolls_back_conflicting_alive_tests)
{
  GPtrArray *alive_tests;
  int ret;

  alive_tests = g_ptr_array_new ();
  g_ptr_array_add (alive_tests, "ICMP Ping");

  ret = modify_target ("target-id", "Renamed target", NULL, NULL,
                       "Updated comment", NULL, NULL, NULL, NULL, NULL, NULL,
                       NULL, NULL, NULL, NULL, alive_tests, "ICMP Ping", NULL);

  assert_that (ret, is_equal_to (30));
  assert_that (model.name, is_equal_to_string ("Original target"));
  assert_that (model.comment, is_equal_to_string ("Original comment"));
  assert_that (model.rollback_count, is_equal_to (1));
  assert_that (model.commit_count, is_equal_to (0));
  assert_that (model.transaction_open, is_false);

  g_ptr_array_free (alive_tests, TRUE);
}

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();
  add_test_with_context (suite, manage_sql_targets,
                         accepts_full_noop_for_in_use_target);
  add_test_with_context (suite, manage_sql_targets,
                         accepts_unset_credentials_and_default_ssh_port);
  add_test_with_context (suite, manage_sql_targets,
                         rejects_real_protected_changes_atomically);
  add_test_with_context (suite, manage_sql_targets,
                         preserves_omitted_fields_for_in_use_target);
  add_test_with_context (suite, manage_sql_targets,
                         preserves_updates_for_unused_target);
  add_test_with_context (suite, manage_sql_targets,
                         preserves_errors_for_unused_target);
  add_test_with_context (suite, manage_sql_targets,
                         rolls_back_conflicting_alive_tests);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);
  return ret;
}
