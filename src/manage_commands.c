/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file manage_commands.c
 * @brief GVM management layer: Generic command handling.
 *
 * Non-SQL generic command handling code for the GVM management layer.
 */

#define _GNU_SOURCE

#include <assert.h>
#include "manage_commands.h"
#include "manage_resources.h"

/**
 * @brief The GMP command list.
 */
command_t gmp_commands[]
 = {{"AUTHENTICATE", "Authenticate with the manager." },
#if ENABLE_AGENTS
    {"CREATE_AGENT_GROUP", "Create an agent group."},
#endif
    {"CREATE_ALERT", "Create an alert."},
    {"CREATE_ASSET", "Create an asset."},
    {"CREATE_CONFIG", "Create a config."},
    {"CREATE_CREDENTIAL", "Create a credential."},
    {"CREATE_FILTER", "Create a filter."},
    {"CREATE_GROUP", "Create a group."},
    {"CREATE_NOTE", "Create a note."},
    {"CREATE_OVERRIDE", "Create an override."},
    {"CREATE_PERMISSION", "Create a permission."},
    {"CREATE_PORT_LIST", "Create a port list."},
    {"CREATE_PORT_RANGE", "Create a port range in a port list."},
    {"CREATE_REPORT", "Create a report."},
    {"CREATE_REPORT_CONFIG", "Create a report config."},
    {"CREATE_REPORT_FORMAT", "Create a report format."},
    {"CREATE_ROLE", "Create a role."},
    {"CREATE_SCANNER", "Create a scanner."},
    {"CREATE_SCHEDULE", "Create a schedule."},
    {"CREATE_TAG", "Create a tag."},
    {"CREATE_TARGET", "Create a target."},
    {"CREATE_TASK", "Create a task."},
    {"CREATE_TICKET", "Create a ticket."},
    {"CREATE_TLS_CERTIFICATE", "Create a TLS certificate."},
    {"CREATE_USER", "Create a new user."},
#if ENABLE_AGENTS
    {"DELETE_AGENT_GROUP", "Delete an agent group."},
    {"DELETE_AGENTS", "Delete one or more agents."},
    {"DELETE_AGENT_INSTALLER", "Delete an agent installer."},
#endif /* ENABLE_AGENTS */
    {"DELETE_ALERT", "Delete an alert."},
    {"DELETE_ASSET", "Delete an asset."},
    {"DELETE_CONFIG", "Delete a config."},
    {"DELETE_CREDENTIAL", "Delete a credential."},
    {"DELETE_FILTER", "Delete a filter."},
    {"DELETE_GROUP", "Delete a group."},
    {"DELETE_NOTE", "Delete a note."},
    {"DELETE_OVERRIDE", "Delete an override."},
    {"DELETE_PERMISSION", "Delete a permission."},
    {"DELETE_PORT_LIST", "Delete a port list."},
    {"DELETE_PORT_RANGE", "Delete a port range."},
    {"DELETE_REPORT", "Delete a report."},
    {"DELETE_REPORT_CONFIG", "Delete a report config."},
    {"DELETE_REPORT_FORMAT", "Delete a report format."},
    {"DELETE_ROLE", "Delete a role."},
    {"DELETE_SCANNER", "Delete a scanner."},
    {"DELETE_SCHEDULE", "Delete a schedule."},
    {"DELETE_TAG", "Delete a tag."},
    {"DELETE_TARGET", "Delete a target."},
    {"DELETE_TASK", "Delete a task."},
    {"DELETE_TICKET", "Delete a ticket."},
    {"DELETE_TLS_CERTIFICATE", "Delete a TLS certificate."},
    {"DELETE_USER", "Delete an existing user."},
    {"DESCRIBE_AUTH", "Get details about the used authentication methods."},
    {"EMPTY_TRASHCAN", "Empty the trashcan."},
#if ENABLE_AGENTS
    {"GET_AGENT_GROUPS", "Get all agent groups."},
    {"GET_AGENTS", "Get all agents."},
    {"GET_AGENT_INSTALLERS", "Get all agent installers."},
    {"GET_AGENT_INSTALLER_FILE", "Get an agent installer file."},
#endif /* ENABLE_AGENTS */
    {"GET_AGGREGATES", "Get aggregates of resources."},
    {"GET_ALERTS", "Get all alerts."},
    {"GET_ASSETS", "Get all assets."},
    {"GET_CONFIGS", "Get all configs."},
    {"GET_CREDENTIALS", "Get all credentials."},
    {"GET_FEEDS", "Get details of one or all feeds this Manager uses."},
    {"GET_FILTERS", "Get all filters."},
    {"GET_GROUPS", "Get all groups."},
    {"GET_INFO", "Get raw information for a given item."},
    {"GET_LICENSE", "Get license information." },
    {"GET_NOTES", "Get all notes."},
    {"GET_NVTS", "Get one or all available NVTs."},
    {"GET_NVT_FAMILIES", "Get a list of all NVT families."},
    {"GET_OVERRIDES", "Get all overrides."},
    {"GET_PERMISSIONS", "Get all permissions."},
    {"GET_PORT_LISTS", "Get all port lists."},
    {"GET_PREFERENCES", "Get preferences for all available NVTs."},
    {"GET_REPORTS", "Get all reports."},
    {"GET_REPORT_CONFIGS", "Get all report configs."},
    {"GET_REPORT_FORMATS", "Get all report formats."},
    {"GET_RESULTS", "Get results."},
    {"GET_ROLES", "Get all roles."},
    {"GET_SCANNERS", "Get all scanners."},
    {"GET_SCHEDULES", "Get all schedules."},
    {"GET_SETTINGS", "Get all settings."},
    {"GET_SYSTEM_REPORTS", "Get all system reports."},
    {"GET_TAGS", "Get all tags."},
    {"GET_TARGETS", "Get all targets."},
    {"GET_TASKS", "Get all tasks."},
    {"GET_TICKETS", "Get all tickets."},
    {"GET_TLS_CERTIFICATES", "Get all TLS certificates."},
    {"GET_USERS", "Get all users."},
    {"GET_VERSION", "Get the Greenbone Management Protocol version."},
    {"GET_VULNS", "Get all vulnerabilities."},
    {"HELP", "Get this help text."},
#if ENABLE_AGENTS
    {"MODIFY_AGENT_GROUP", "Modify an agent group."},
    {"MODIFY_AGENTS", "Modify one or more existing agents."},
#endif /* ENABLE_AGENTS */
    {"MODIFY_ALERT", "Modify an existing alert."},
    {"MODIFY_ASSET", "Modify an existing asset."},
    {"MODIFY_AUTH", "Modify the authentication methods."},
    {"MODIFY_CONFIG", "Update an existing config."},
    {"MODIFY_CREDENTIAL", "Modify an existing credential."},
    {"MODIFY_FILTER", "Modify an existing filter."},
    {"MODIFY_GROUP", "Modify an existing group."},
    {"MODIFY_LICENSE", "Modify the existing license."},
    {"MODIFY_NOTE", "Modify an existing note."},
    {"MODIFY_OVERRIDE", "Modify an existing override."},
    {"MODIFY_PERMISSION", "Modify an existing permission."},
    {"MODIFY_PORT_LIST", "Modify an existing port list."},
    {"MODIFY_REPORT_CONFIG", "Modify an existing report config."},
    {"MODIFY_REPORT_FORMAT", "Modify an existing report format."},
    {"MODIFY_ROLE", "Modify an existing role."},
    {"MODIFY_SCANNER", "Modify an existing scanner."},
    {"MODIFY_SCHEDULE", "Modify an existing schedule."},
    {"MODIFY_SETTING", "Modify an existing setting."},
    {"MODIFY_TAG", "Modify an existing tag."},
    {"MODIFY_TARGET", "Modify an existing target."},
    {"MODIFY_TASK", "Update an existing task."},
    {"MODIFY_TICKET", "Modify an existing ticket."},
    {"MODIFY_TLS_CERTIFICATE", "Modify an existing TLS certificate."},
    {"MODIFY_USER", "Modify a user."},
    {"MOVE_TASK", "Assign task to another slave scanner, even while running."},
    {"RESTORE", "Restore a resource."},
    {"RESUME_TASK", "Resume a stopped task."},
    {"RUN_WIZARD", "Run a wizard."},
    {"START_TASK", "Manually start an existing task."},
    {"STOP_TASK", "Stop a running task."},
    {"SYNC_CONFIG", "Synchronize a config with a scanner."},
    {"TEST_ALERT", "Run an alert."},
    {"VERIFY_REPORT_FORMAT", "Verify a report format."},
    {"VERIFY_SCANNER", "Verify a scanner."},
    {NULL, NULL}};

/**
 * @brief Check whether a command name is valid.
 *
 * @param[in]  name  Command name.
 *
 * @return 1 yes, 0 no.
 */
int
valid_gmp_command (const char* name)
{
  command_t *command;
  command = gmp_commands;
  while (command[0].name)
    if (strcasecmp (command[0].name, name) == 0)
      return 1;
    else
      command++;
  return 0;
}

/**
 * @brief Get the type associated with a GMP command.
 *
 * @param[in]  name  Command name.
 *
 * @return Freshly allocated type name if any, else NULL.
 */
gchar *
gmp_command_type (const char* name)
{
  const char *under;
  under = strchr (name, '_');
  if (under && (strlen (under) > 1))
    {
      gchar *command;
      under++;
      command = g_strdup (under);
      if (command[strlen (command) - 1] == 's')
        command[strlen (command) - 1] = '\0';
      if (valid_type (command))
        return command;
      g_free (command);
    }
  return NULL;
}

/**
 * @brief Check whether a GMP command takes a resource.
 *
 * MODIFY_TARGET, for example, takes a target.
 *
 * @param[in]  name  Command name.
 *
 * @return 1 if takes resource, else 0.
 */
int
gmp_command_takes_resource (const char* name)
{
  assert (name);
  return strcasecmp (name, "AUTHENTICATE")
         && strcasestr (name, "CREATE_") != name
         && strcasestr (name, "DESCRIBE_") != name
         && strcasecmp (name, "EMPTY_TRASHCAN")
         && strcasecmp (name, "GET_VERSION")
         && strcasecmp (name, "HELP")
         && strcasecmp (name, "RUN_WIZARD")
         && strcasestr (name, "SYNC_") != name;
}
