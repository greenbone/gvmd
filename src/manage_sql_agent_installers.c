/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM SQL layer: Agent installers.
 *
 * SQL handlers of agent installers.
 */

#include "gmp_base.h"
#include "manage_sql.h"
#include "manage_sql_agent_installers.h"
#include "manage_acl.h"
#include <glib/gstdio.h>
#include <cjson/cJSON.h>
#include <gvm/util/json.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Get the time agent installers were last updated from the meta table
 *
 * @return The time of the last update
 */
time_t
get_meta_agent_installers_last_update ()
{
  return sql_int64_0 ("SELECT value FROM meta"
                      " WHERE name = 'agent_installers_last_update';");
}

/**
 * @brief Set the agent installers last update time to the current time.
 */
void
update_meta_agent_installers_last_update ()
{
  sql ("INSERT INTO meta (name, value)"
       " VALUES ('agent_installers_last_update', m_now())"
       " ON CONFLICT (name) DO UPDATE SET value = EXCLUDED.value;");
}

/**
 * @brief Copies agent installer data, applying sql_insert to all strings.
 *
 * The data should be freed with agent_installer_data_free after use.
 *
 * @param[in]  data  The agent installer data to copy.
 *
 * @return The modified copy of the agent installer data.
 */
static agent_installer_data_t*
agent_installer_data_copy_as_sql_inserts (agent_installer_data_t *data)
{
  agent_installer_data_t *new_data;
  new_data = g_malloc0 (sizeof (agent_installer_data_t));

  new_data->uuid = sql_insert (data->uuid);
  new_data->name = sql_insert (data->name);
  new_data->description = sql_insert (data->description);
  new_data->content_type = sql_insert (data->content_type);
  new_data->file_extension = sql_insert (data->file_extension);
  new_data->installer_path = sql_insert (data->installer_path);
  new_data->version = sql_insert (data->version);
  new_data->checksum = sql_insert (data->checksum);
  new_data->creation_time = data->creation_time;
  new_data->modification_time = data->modification_time;

  return new_data;
}

/**
 * @brief Grant 'Feed Import Roles' access to a agent installer.
 *
 * @param[in]  agent_installer_id  UUID of agent installer.
 */
static void
create_feed_agent_installer_permissions (const gchar *agent_installer_id)
{
  gchar *roles, **split, **point;

  setting_value (SETTING_UUID_FEED_IMPORT_ROLES, &roles);

  if (roles == NULL || strlen (roles) == 0)
    {
      g_debug ("%s: no 'Feed Import Roles', so not creating permissions",
               __func__);
      g_free (roles);
      return;
    }

  point = split = g_strsplit (roles, ",", 0);
  while (*point)
    {
      permission_t permission;

      if (create_permission_no_acl ("get_agent_installers",
                                    "Automatically created for agent installer"
                                    " from feed",
                                    NULL,
                                    agent_installer_id,
                                    "role",
                                    g_strstrip (*point),
                                    &permission))
        /* Keep going because we aren't strict about checking the value
         * of the setting, and because we don't adjust the setting when
         * roles are removed. */
        g_warning ("%s: failed to create permission for role '%s'",
                   __func__, g_strstrip (*point));

      point++;
    }
  g_strfreev (split);

  g_free (roles);
}

/**
 * @brief Create a new agent installer using an agent_installer_data_t struct.
 *
 * @param[in]  agent_installer_data  Structure containing the data
 *
 * @return 0 success, -1 error
 */
int
create_agent_installer_from_data (agent_installer_data_t *agent_installer_data)
{
  user_t owner;
  agent_installer_data_t *data_inserts;

  owner = sql_int64_0 ("SELECT id FROM users WHERE users.uuid = '%s'",
                       current_credentials.uuid);
  g_debug ("creating agent installer %s", agent_installer_data->uuid);

  sql_begin_immediate ();

  data_inserts
    = agent_installer_data_copy_as_sql_inserts (agent_installer_data);

  sql_int64_0 ("INSERT INTO agent_installers"
               " (uuid, name, owner,"
               "  creation_time, modification_time,"
               "  description, content_type, file_extension,"
               "  installer_path, version, checksum,"
               "  last_update)"
               " VALUES"
               " (%s, %s, %llu,"
               "  %ld, %ld,"
               "  %s, %s, %s,"
               "  %s, %s, %s,"
               "  m_now())"
               " RETURNING id;",
               data_inserts->uuid,
               data_inserts->name,
               owner,
               data_inserts->creation_time,
               data_inserts->modification_time,
               data_inserts->description,
               data_inserts->content_type,
               data_inserts->file_extension,
               data_inserts->installer_path,
               data_inserts->version,
               data_inserts->checksum);

  sql_commit ();

  agent_installer_data_free (data_inserts);

  log_event ("agent_installer",
             "Agent Installer",
             agent_installer_data->uuid,
             "created");

  /* Create permissions. */
  create_feed_agent_installer_permissions (agent_installer_data->uuid);

  return 0;
}

/**
 * @brief Overwrite agent installer data using an agent_installer_data_t.
 *
 * @param[in]  installer  Row-id of the installer to update
 * @param[in]  agent_installer_data  Structure containing the data
 *
 * @return 0 success, -1 error
 */
int
update_agent_installer_from_data (agent_installer_t installer,
                                  agent_installer_data_t *agent_installer_data)
{
  agent_installer_data_t *data_inserts;
  g_debug ("updating agent installer %s", agent_installer_data->uuid);

  sql_begin_immediate ();

  data_inserts
    = agent_installer_data_copy_as_sql_inserts (agent_installer_data);

  sql ("UPDATE agent_installers"
       " SET"
       "   name = %s,"
       "   creation_time = %ld,"
       "   modification_time = %ld,"
       "   description = %s,"
       "   content_type = %s,"
       "   file_extension = %s,"
       "   installer_path = %s,"
       "   version = %s,"
       "   checksum = %s,"
       "   last_update = m_now()"
       " WHERE id = %llu;",
       data_inserts->name,
       data_inserts->creation_time,
       data_inserts->modification_time,
       data_inserts->description,
       data_inserts->content_type,
       data_inserts->file_extension,
       data_inserts->installer_path,
       data_inserts->version,
       data_inserts->checksum,
       installer);

  sql_commit ();

  agent_installer_data_free (data_inserts);

  log_event ("agent_installer",
             "Agent Installer",
             agent_installer_data->uuid,
             "modified");
  return 0;
}

/**
 * @brief Find an agent installer given a UUID.
 *
 * This does not do any permission checks.
 *
 * @param[in]   uuid        UUID of resource.
 * @param[out]  installer   agent installer return, 0 if no such installer.
 *
 * @return FALSE on success (including if no such installer), TRUE on error.
 */
gboolean
find_agent_installer_no_acl (const char *uuid, agent_installer_t *installer)
{
  gchar *quoted_uuid;

  quoted_uuid = sql_quote (uuid);
  switch (sql_int64 (installer,
                     "SELECT id FROM agent_installers WHERE uuid = '%s';",
                     quoted_uuid))
    {
      case 0:
        break;
      case 1:        /* Too few rows in result of query. */
        *installer = 0;
        break;
      default:       /* Programming error. */
        assert (0);
      case -1:
        g_free (quoted_uuid);
        return TRUE;
        break;
    }

  g_free (quoted_uuid);
  return FALSE;
}

/* GET_AGENT_INSTALLERS */

/**
 * @brief Count the number of Agent Installers.
 *
 * @param[in]  get  GET params.
 *
 * @return Total number of Agent Installer filtered set.
 */
int
agent_installer_count (const get_data_t *get)
{
  static const char *filter_columns[] = AGENT_INSTALLER_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = AGENT_INSTALLER_ITERATOR_COLUMNS;
  return count ("agent_installer", get, columns, NULL, filter_columns,
                0, 0, 0, TRUE);
}

/**
 * @brief Gets the row id of an agent installer with a given UUID.
 *
 * @param[in]  agent_installer_id  The UUID of the agent installer.
 *
 * @return The row id.
 */
agent_installer_t
agent_installer_by_uuid (const char *agent_installer_id)
{
  agent_installer_t ret;
  gchar *quoted_agent_installer_id = sql_quote (agent_installer_id);
  ret = sql_int64_0 ("SELECT id FROM agent_installers"
                     " WHERE uuid = '%s'",
                     quoted_agent_installer_id);
  g_free (quoted_agent_installer_id);
  return ret;
}

/**
 * @brief Gets the last modification time of an agent installer.
 *
 * @param[in]  agent_installer  The id of the agent installer.
 *
 * @return The last modification time.
 */
time_t
agent_installer_modification_time (agent_installer_t agent_installer)
{
  return sql_int64_0 ("SELECT modification_time FROM agent_installers"
                      " WHERE id = %llu",
                      agent_installer);
}

/**
 * @brief Initialise a Agent Installer iterator, including observed
 *        Agent Installers.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  get         GET data.
 *
 * @return 0 success, 1 failed to find Agent Installer, 2 failed to find filter,
 *         -1 error.
 */
int
init_agent_installer_iterator (iterator_t* iterator, get_data_t *get)
{
  static const char *filter_columns[] = AGENT_INSTALLER_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = AGENT_INSTALLER_ITERATOR_COLUMNS;

  return init_get_iterator (iterator,
                            "agent_installer",
                            get,
                            columns,
                            NULL,
                            filter_columns,
                            0,
                            NULL,
                            NULL,
                            TRUE);
}

/**
 * @brief Get the description from an agent installer iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The description of the agent installer.
 *         Caller must only use before calling cleanup_iterator.
 */
DEF_ACCESS (agent_installer_iterator_description,
            GET_ITERATOR_COLUMN_COUNT);

/**
 * @brief Get the content type from an agent installer iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The content type of the agent installer.  Caller must only use before
 *         calling cleanup_iterator.
 */
DEF_ACCESS (agent_installer_iterator_content_type,
            GET_ITERATOR_COLUMN_COUNT + 1);

/**
 * @brief Get the file extension from an agent installer iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The file extension of the agent installer.
 *         Caller must only use before calling cleanup_iterator.
 */
DEF_ACCESS (agent_installer_iterator_file_extension,
            GET_ITERATOR_COLUMN_COUNT + 2);

/**
 * @brief Get the installer path from an agent installer iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The installer path of the agent installer.
 *         Caller must only use before calling cleanup_iterator.
 */
DEF_ACCESS (agent_installer_iterator_installer_path,
            GET_ITERATOR_COLUMN_COUNT + 3);

/**
 * @brief Get the version from an agent installer iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The version of the agent installer.
 *         Caller must only use before calling cleanup_iterator.
 */
DEF_ACCESS (agent_installer_iterator_version,
            GET_ITERATOR_COLUMN_COUNT + 4);

/**
 * @brief Get the checksum from an agent installer iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The checksum of the agent installer.
 *         Caller must only use before calling cleanup_iterator.
 */
DEF_ACCESS (agent_installer_iterator_checksum,
            GET_ITERATOR_COLUMN_COUNT + 5);

/**
 * @brief Get the last update time from an agent installer iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The last update time of the agent installer.
 *         Caller must only use before calling cleanup_iterator.
 */
time_t
agent_installer_iterator_last_update (iterator_t *iterator)
{
  if (iterator->done) return 0;
  return iterator_int64 (iterator,  GET_ITERATOR_COLUMN_COUNT + 6);
}

/**
 * @brief Return whether an agent installer is in use.
 *
 * @param[in]  agent_installer  Agent Installer.
 *
 * @return 1 if in use, else 0.
 */
int
agent_installer_in_use (agent_installer_t agent_installer)
{
  return 0;
}

/**
 * @brief Return whether an agent installer in the trashcan is in use.
 *
 * @param[in]  agent_installer  Agent Installer.
 *
 * @return 1 if in use, else 0.
 */
int
trash_agent_installer_in_use (agent_installer_t installer)
{
  return 0;
}

/**
 * @brief Return whether an agent installer is writable.
 *
 * @param[in]  target  Target.
 *
 * @return 1 if writable, else 0.
 */
int
agent_installer_writable (agent_installer_t installer)
{
  return 0;
}

/**
 * @brief Return whether a trashcan agent installer is writable.
 *
 * @param[in]  target  Target.
 *
 * @return 1 if writable, else 0.
 */
int
trash_agent_installer_writable (agent_installer_t installer)
{
  return 0;
}
