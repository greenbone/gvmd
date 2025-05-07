/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file manage_sql_agent_installers.c
 * @brief GVM SQL layer: Agent installers.
 *
 * SQL handlers of agent installers.
 */

#include "gmp_base.h"
#include "manage_sql.h"
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
 * @brief Delete an agent installer.
 *
 * @param[in]  agent_installer_id  UUID of agent installer.
 * @param[in]  ultimate      Whether to remove entirely, or to trashcan.
 *
 * @return 0 success, 99 permission denied, -1 error.
 */
int
delete_agent_installer (const char *agent_installer_id, int ultimate)
{
  agent_installer_t agent_installer = 0;

  sql_begin_immediate ();

  if (acl_user_may ("delete_agent_installer") == 0)
    {
      sql_rollback ();
      return 99;
    }

  if (find_resource_with_permission ("agent_installer", agent_installer_id,
                                     &agent_installer,
                                     "delete_agent_installer", 0))
    {
      sql_rollback ();
      return -1;
    }

  if (agent_installer == 0)
    {
      if (find_trash ("agent_installer", agent_installer_id, &agent_installer))
        {
          sql_rollback ();
          return -1;
        }
      if (agent_installer == 0)
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

      permissions_set_orphans ("agent_installer", agent_installer, LOCATION_TRASH);
      tags_remove_resource ("agent_installer", agent_installer, LOCATION_TRASH);

      sql ("DELETE FROM agent_installer_cpes_trash"
           " WHERE agent_installer = %llu;",
           agent_installer);
      sql ("DELETE FROM agent_installers_trash WHERE id = %llu;",
           agent_installer);
      sql_commit ();
      return 0;
    }

  if (ultimate == 0)
    {
      agent_installer_t trash_agent_installer;

      trash_agent_installer
        = sql_int64_0 ("INSERT INTO agent_installers_trash"
                       " (uuid, owner, name, comment,"
                       "  creation_time, modification_time,"
                       "  description, content_type, file_extension,"
                       "  installer_path, version, checksum,"
                       "  file_size, last_update)"
                       " SELECT uuid, owner, name, comment,"
                       "  creation_time, modification_time,"
                       "  description, content_type, file_extension,"
                       "  installer_path, version, checksum,"
                       "  file_size, last_update"
                       " FROM agent_installers WHERE id = %llu"
                       " RETURNING id;",
                       agent_installer);

      sql ("INSERT INTO agent_installer_cpes_trash"
           " (agent_installer, criteria,"
           "  version_start_incl, version_start_excl,"
           "  version_end_incl, version_end_excl)"
           " SELECT %llu, criteria,"
           "  version_start_incl, version_start_excl,"
           "  version_end_incl, version_end_excl"
           " FROM agent_installer_cpes WHERE agent_installer = %llu;",
           trash_agent_installer,
           agent_installer);

      permissions_set_locations ("agent_installer",
                                 agent_installer,
                                 trash_agent_installer,
                                 LOCATION_TRASH);
      tags_set_locations ("agent_installer",
                          agent_installer,
                          trash_agent_installer,
                          LOCATION_TRASH);
    }
  else
    {
      permissions_set_orphans ("agent_installer", agent_installer,
                               LOCATION_TABLE);
      tags_remove_resource ("agent_installer", agent_installer,
                            LOCATION_TABLE);
    }

  sql ("DELETE FROM agent_installer_cpes WHERE agent_installer = %llu;",
       agent_installer);
  sql ("DELETE FROM agent_installers WHERE id = %llu;", agent_installer);
  sql_commit ();
  return 0;
}

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
 * @brief Copies agent installer CPE data, applying sql_insert to all strings.
 *
 * @param[in]  data  The agent installer CPE data to copy.
 *
 * @return The modified copy of the agent installer CPE data.
 */
static agent_installer_cpe_data_t*
agent_installer_cpe_data_copy_as_sql_inserts (agent_installer_cpe_data_t *data)
{
  agent_installer_cpe_data_t *new_data;
  new_data = g_malloc0 (sizeof (agent_installer_cpe_data_t));

  new_data->criteria = sql_insert (data->criteria);
  new_data->version_start_incl = sql_insert (data->version_start_incl);
  new_data->version_start_excl = sql_insert (data->version_start_excl);
  new_data->version_end_incl = sql_insert (data->version_end_incl);
  new_data->version_end_excl = sql_insert (data->version_end_excl);

  return new_data;
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
  new_data->file_size = data->file_size;
  new_data->creation_time = data->creation_time;
  new_data->modification_time = data->modification_time;

  new_data->cpes
    = g_ptr_array_new_full (0, (GDestroyNotify) agent_installer_cpe_data_free);

  for (int i = 0; i < data->cpes->len; i++)
    {
      agent_installer_cpe_data_t *cpe_data_copy
        = agent_installer_cpe_data_copy_as_sql_inserts (data->cpes->pdata[i]);
      g_ptr_array_add (new_data->cpes, cpe_data_copy);
    }

  return new_data;
}

#undef GET_AGENT_INSTALLER_JSON_STR

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
  agent_installer_t installer;

  owner = sql_int64_0 ("SELECT id FROM users WHERE users.uuid = '%s'",
                       current_credentials.uuid);
  g_debug ("creating agent installer %s", agent_installer_data->uuid);

  sql_begin_immediate ();

  data_inserts
    = agent_installer_data_copy_as_sql_inserts (agent_installer_data);

  installer = sql_int64_0 ("INSERT INTO agent_installers"
                           " (uuid, name, owner,"
                           "  creation_time, modification_time,"
                           "  description, content_type, file_extension,"
                           "  installer_path, version, checksum, file_size,"
                           "  last_update)"
                           " VALUES"
                           " (%s, %s, %llu,"
                           "  %ld, %ld,"
                           "  %s, %s, %s,"
                           "  %s, %s, %s, %d,"
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
                           data_inserts->checksum,
                           data_inserts->file_size);

  for (int i = 0; i < data_inserts->cpes->len; i++)
    {
      agent_installer_cpe_data_t *cpe_data;
      cpe_data = g_ptr_array_index (data_inserts->cpes, i);

      sql ("INSERT INTO agent_installer_cpes"
           " (agent_installer, criteria,"
           "  version_start_incl, version_start_excl,"
           "  version_end_incl, version_end_excl)"
           " VALUES"
           " (%llu, %s, %s, %s, %s, %s);",
           installer,
           cpe_data->criteria,
           cpe_data->version_start_incl,
           cpe_data->version_start_excl,
           cpe_data->version_end_incl,
           cpe_data->version_end_excl);
    }

  sql_commit ();

  agent_installer_data_free (data_inserts);

  log_event ("agent_installer",
             "Agent Installer",
             agent_installer_data->uuid,
             "created");
  return 0;
}

/**
 * @brief Overwrite agent installer data using an agent_installer_data_t.
 *
 * @param[in]  installer  Row-id of the installer to update
 * @param[in]  trash      Whether the installer to update is in the trash
 * @param[in]  agent_installer_data  Structure containing the data
 *
 * @return 0 success, -1 error
 */
int
update_agent_installer_from_data (agent_installer_t installer,
                                  gboolean trash,
                                  agent_installer_data_t *agent_installer_data)
{
  agent_installer_data_t *data_inserts;
  g_debug ("updating agent installer %s%s",
           agent_installer_data->uuid, trash ? " in trashcan" : "");

  sql_begin_immediate ();

  data_inserts
    = agent_installer_data_copy_as_sql_inserts (agent_installer_data);

  sql ("UPDATE agent_installers%s"
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
       "   file_size = %d,"
       "   last_update = m_now()"
       " WHERE id = %llu;",
       trash ? "_trash" : "",
       data_inserts->name,
       data_inserts->creation_time,
       data_inserts->modification_time,
       data_inserts->description,
       data_inserts->content_type,
       data_inserts->file_extension,
       data_inserts->installer_path,
       data_inserts->version,
       data_inserts->checksum,
       data_inserts->file_size,
       installer);

  sql ("DELETE FROM agent_installer_cpes%s WHERE agent_installer = %llu;",
       trash ? "_trash" : "",
       installer);
  for (int i = 0; i < data_inserts->cpes->len; i++)
    {
      agent_installer_cpe_data_t *cpe_data;
      cpe_data = g_ptr_array_index (data_inserts->cpes, i);

      sql ("INSERT INTO agent_installer_cpes%s"
           " (agent_installer, criteria,"
           "  version_start_incl, version_start_excl,"
           "  version_end_incl, version_end_excl)"
           " VALUES"
           " (%llu, %s, %s, %s, %s, %s);",
           trash ? "_trash" : "",
           installer,
           cpe_data->criteria,
           cpe_data->version_start_incl,
           cpe_data->version_start_excl,
           cpe_data->version_end_incl,
           cpe_data->version_end_excl);
    }

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

/**
 * @brief Find a trash agent installer given a UUID.
 *
 * This does not do any permission checks.
 *
 * @param[in]   uuid       UUID of resource.
 * @param[out]  installer  agent installer return, 0 if no such installer.
 *
 * @return FALSE on success (including if no such installer), TRUE on error.
 */
gboolean
find_trash_agent_installer_no_acl (const char *uuid,
                                   agent_installer_t *installer)
{
  gchar *quoted_uuid;

  quoted_uuid = sql_quote (uuid);
  switch (sql_int64 (installer,
                     "SELECT id FROM agent_installers_trash WHERE uuid = '%s';",
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
 * @brief Filter columns for Agent Installer iterator.
 */
#define AGENT_INSTALLER_ITERATOR_FILTER_COLUMNS                             \
 { GET_ITERATOR_FILTER_COLUMNS, "description", "content_type",              \
   "file_extension", "version", "file_size", "last_update",                 \
   NULL }

/**
 * @brief Agent Installer iterator columns.
 */
#define AGENT_INSTALLER_ITERATOR_COLUMNS                                    \
 {                                                                          \
   { "id", NULL, KEYWORD_TYPE_INTEGER },                                    \
   { "uuid", NULL, KEYWORD_TYPE_STRING },                                   \
   { "name", NULL, KEYWORD_TYPE_STRING },                                   \
   { "comment", NULL, KEYWORD_TYPE_STRING },                                \
   { "creation_time", NULL, KEYWORD_TYPE_INTEGER },                         \
   { "modification_time", NULL, KEYWORD_TYPE_INTEGER },                     \
   { "creation_time", "created", KEYWORD_TYPE_INTEGER },                    \
   { "modification_time", "modified", KEYWORD_TYPE_INTEGER },               \
   {                                                                        \
     "(SELECT name FROM users WHERE users.id = agent_installers.owner)",    \
     "_owner",                                                              \
     KEYWORD_TYPE_STRING                                                    \
   },                                                                       \
   { "owner", NULL, KEYWORD_TYPE_INTEGER },                                 \
   { "description", NULL, KEYWORD_TYPE_STRING },                            \
   { "content_type", NULL, KEYWORD_TYPE_STRING },                           \
   { "file_extension", NULL, KEYWORD_TYPE_STRING },                         \
   { "installer_path", NULL, KEYWORD_TYPE_STRING },                         \
   { "version", NULL, KEYWORD_TYPE_STRING },                                \
   { "checksum", NULL, KEYWORD_TYPE_STRING },                               \
   { "file_size", NULL, KEYWORD_TYPE_INTEGER },                             \
   { "last_update", NULL, KEYWORD_TYPE_INTEGER },                           \
   { NULL, NULL, KEYWORD_TYPE_UNKNOWN }                                     \
 }

/**
 * @brief Agent Installer iterator columns for trash case.
 */
#define AGENT_INSTALLER_ITERATOR_TRASH_COLUMNS                                \
 {                                                                          \
   { "id", NULL, KEYWORD_TYPE_INTEGER },                                    \
   { "uuid", NULL, KEYWORD_TYPE_STRING },                                   \
   { "name", NULL, KEYWORD_TYPE_STRING },                                   \
   { "comment", NULL, KEYWORD_TYPE_STRING },                                \
   { "creation_time", NULL, KEYWORD_TYPE_INTEGER },                         \
   { "modification_time", NULL, KEYWORD_TYPE_INTEGER },                     \
   { "creation_time", "created", KEYWORD_TYPE_INTEGER },                    \
   { "modification_time", "modified", KEYWORD_TYPE_INTEGER },               \
   {                                                                        \
     "(SELECT name FROM users WHERE users.id = agent_installers_trash.owner)",\
     "_owner",                                                              \
     KEYWORD_TYPE_STRING                                                    \
   },                                                                       \
   { "owner", NULL, KEYWORD_TYPE_INTEGER },                                 \
   { "description", NULL, KEYWORD_TYPE_STRING },                            \
   { "content_type", NULL, KEYWORD_TYPE_STRING },                           \
   { "file_extension", NULL, KEYWORD_TYPE_STRING },                         \
   { "installer_path", NULL, KEYWORD_TYPE_STRING },                         \
   { "version", NULL, KEYWORD_TYPE_STRING },                                \
   { "checksum", NULL, KEYWORD_TYPE_STRING },                               \
   { "size", NULL, KEYWORD_TYPE_INTEGER },                                  \
   { "last_update", NULL, KEYWORD_TYPE_INTEGER },                           \
   { NULL, NULL, KEYWORD_TYPE_UNKNOWN }                                     \
 }

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
  static column_t trash_columns[] = AGENT_INSTALLER_ITERATOR_TRASH_COLUMNS;
  return count ("agent_installer", get, columns, trash_columns, filter_columns,
                0, 0, 0, TRUE);
}

/**
 * @brief Gets the row id of an agent installer with a given UUID.
 *
 * @param[in]  agent_installer_id  The UUID of the agent installer.
 * @param[in]  trash               Whether to get the installer from the trash.
 *
 * @return The row id.
 */
agent_installer_t
agent_installer_by_uuid (const char *agent_installer_id, int trash)
{
  agent_installer_t ret;
  gchar *quoted_agent_installer_id = sql_quote (agent_installer_id);
  ret = sql_int64_0 ("SELECT id FROM agent_installers%s"
                     " WHERE uuid = '%s'",
                     trash ? "_trash" : "",
                     quoted_agent_installer_id);
  g_free (quoted_agent_installer_id);
  return ret;
}

/**
 * @brief Gets the last modification time of an agent installer.
 *
 * @param[in]  agent_installer  The id of the agent installer.
 * @param[in]  trash            Whether to get the installer from the trash.
 *
 * @return The last modification time.
 */
time_t
agent_installer_modification_time (agent_installer_t agent_installer, int trash)
{
  return sql_int64_0 ("SELECT modification_time FROM agent_installers%s"
                      " WHERE id = %llu",
                      trash ? "_trash" : "",
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
  static column_t trash_columns[] = AGENT_INSTALLER_ITERATOR_TRASH_COLUMNS;

  return init_get_iterator (iterator,
                            "agent_installer",
                            get,
                            columns,
                            trash_columns,
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
 * @brief Get the file size from an agent installer iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The file size of the agent installer.
 *         Caller must only use before calling cleanup_iterator.
 */
int
agent_installer_iterator_file_size (iterator_t *iterator)
{
  if (iterator->done) return 0;
  return iterator_int (iterator,  GET_ITERATOR_COLUMN_COUNT + 6);
}

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
  return iterator_int64 (iterator,  GET_ITERATOR_COLUMN_COUNT + 7);
}

/**
 * @brief Initialise a Agent Installer CPE iterator.
 *
 * @param[in]  iterator         Iterator.
 * @param[in]  agent_installer  Agent installer to get CPEs of.
 * @param[in]  trash            Whether to get CPEs from an installer in trash.
 */
void
init_agent_installer_cpe_iterator (iterator_t* iterator,
                                  agent_installer_t agent_installer,
                                  int trash)
{
  init_iterator (iterator,
                 "SELECT criteria,"
                 " version_start_incl, version_start_excl,"
                 " version_end_incl, version_end_excl"
                 " FROM agent_installer_cpes%s"
                 " WHERE agent_installer = %llu",
                 trash ? "_trash" : "",
                 agent_installer);
}

/**
 * @brief Get the criteria from an agent installer CPE iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The criteria of the agent installer CPE.
 *         Caller must only use before calling cleanup_iterator.
 */
DEF_ACCESS (agent_installer_cpe_iterator_criteria, 0);

/**
 * @brief Get the inclusive version range start from an agent installer CPE
 * iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The inclusive version range start of the agent installer CPE.
 *         Caller must only use before calling cleanup_iterator.
 */
DEF_ACCESS (agent_installer_cpe_iterator_version_start_incl, 1);

/**
 * @brief Get the exclusive version range start from an agent installer CPE
 * iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The exclusive version range start of the agent installer CPE.
 *         Caller must only use before calling cleanup_iterator.
 */
DEF_ACCESS (agent_installer_cpe_iterator_version_start_excl, 2);

/**
 * @brief Get the inclusive version range end from an agent installer CPE
 * iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The exclusive version range end of the agent installer CPE.
 *         Caller must only use before calling cleanup_iterator.
 */
DEF_ACCESS (agent_installer_cpe_iterator_version_end_incl, 3);

/**
 * @brief Get the inclusive version range end from an agent installer CPE
 * iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The exclusive version range end of the agent installer CPE.
 *         Caller must only use before calling cleanup_iterator.
 */
DEF_ACCESS (agent_installer_cpe_iterator_version_end_excl, 4);

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
