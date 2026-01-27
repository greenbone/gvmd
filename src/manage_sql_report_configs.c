/* Copyright (C) 2024 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: Report configs SQL.
 *
 * SQL report config code for the GVM management layer.
 */

#include "debug_utils.h"
#include "manage_sql_report_configs.h"
#include "manage_acl.h"
#include "manage_sql_permissions.h"
#include "manage_sql_report_formats.h"
#include "sql.h"
#include "utils.h"
#include <glib.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"


/**
 * @brief Create Report Config from an existing Report Config.
 *
 * @param[in]  name                 Name of new Report Config. NULL to copy
 *                                  from existing.
 * @param[in]  source_uuid          UUID of existing Report Config.
 * @param[out] new_report_config    New Report Config.
 *
 * @return 0 success, 1 Report Config exists already, 2 failed to find existing
 *         Report Config, 99 permission denied, -1 error.
 */
int
copy_report_config (const char* name, const char* source_uuid,
                    report_config_t* new_report_config)
{
  report_format_t new, old;
  int ret;

  assert (current_credentials.uuid);

  sql_begin_immediate ();

  ret = copy_resource_lock ("report_config", name, NULL, source_uuid,
                            "report_format_id",
                            1, &new, &old);
  if (ret)
    {
      sql_rollback ();
      return ret;
    }

  /* Copy report config parameters. */

  sql ("INSERT INTO report_config_params "
       " (report_config, name, value)"
       " SELECT %llu, name, value"
       "  FROM report_config_params WHERE report_config = %llu;",
       new,
       old);

  sql_commit ();

  if (new_report_config) *new_report_config = new;
  return 0;
}

/**
 * @brief Validate a parameter for a report config against the report format.
 *
 * @param[in]  param          The parameter to validate
 * @param[in]  report_format  The report format the config param is based on
 * @param[out] error_message  Pointer for error message if validation fails
 *
 * @return 0 param is valid, 1 param is invalid
 */
static int
validate_report_config_param (report_config_param_data_t *param,
                              report_format_t report_format,
                              gchar **error_message)
{
  gchar *quoted_param_name = sql_quote (param->name);
  report_format_param_t format_param;

  format_param = sql_int64_0 ("SELECT id FROM report_format_params"
                              " WHERE report_format = %llu"
                              "   AND name = '%s'",
                              report_format,
                              quoted_param_name);

  if (format_param == 0)
    {
      if (error_message)
        *error_message = g_strdup_printf ("report format has no parameter"
                                          " named \"%s\"",
                                          param->name);
      g_free (quoted_param_name);
      return 1;
    }

  if (report_format_validate_param_value (report_format, format_param,
                                          param->name, param->value,
                                          error_message))
    {
      g_free (quoted_param_name);
      return 1;
    }

  g_free (quoted_param_name);
  return 0;
}

/**
 * @brief Add or replace a parameter to a new report config.
 *
 * @param[in]  report_config  The config the param is to be added to
 * @param[in]  param          The parameter to add
 */
static void
insert_report_config_param (report_config_t report_config,
                            report_config_param_data_t *param)
{
  gchar *quoted_name, *quoted_value;

  quoted_name = sql_quote (param->name ?: "");
  quoted_value = sql_quote (param->value ?: "");

  sql ("INSERT INTO report_config_params (report_config, name, value)"
       " VALUES (%llu, '%s', '%s')"
       " ON CONFLICT (report_config, name)"
       " DO UPDATE SET value = EXCLUDED.value",
       report_config, quoted_name, quoted_value);

  g_free (quoted_name);
  g_free (quoted_value);
}

/**
 * @brief Create a report config.
 *
 * @param[in]   name              Name of report config.
 * @param[in]   comment           Comment of report config.
 * @param[in]   report_format_id  UUID of report format.
 * @param[in]   params            Array of params.
 * @param[out]  report_config     Created report config.
 * @param[out]  error_message     Message for some errors like invalid params.
 *
 * @return 0 success,
 *         1 report config with same name already exists,
 *         2 report format not found,
 *         3 report format not configurable,
 *         4 param validation failed,
 *         99 permission denied,
 *         -1 internal error.
 */
int
create_report_config (const char *name, const char *comment,
                      const char *report_format_id,
                      array_t *params,
                      report_config_t *report_config,
                      gchar **error_message)
{
  gchar *quoted_name, *quoted_comment, *quoted_report_format_id;
  report_format_t report_format;
  sql_begin_immediate ();

  if (acl_user_may ("create_report_config") == 0)
    {
      sql_rollback ();
      return 99;
    }

  quoted_name = sql_quote (name ? name : "");
  if (sql_int ("SELECT count(*) FROM report_configs WHERE name = '%s'",
               quoted_name))
    {
      g_free (quoted_name);
      sql_rollback ();
      return 1;
    }

  report_format = 0;
  if (find_report_format_with_permission (report_format_id, &report_format,
                                          "get_report_formats"))
    {
      g_free (quoted_name);
      sql_rollback ();
      return -1;
    }

  if (report_format == 0)
    {
      g_free (quoted_name);
      sql_rollback ();
      return 2;
    }

  if (sql_int ("SELECT count(*) FROM report_format_params"
               " WHERE report_format = %llu", report_format) == 0)
    {
      g_free (quoted_name);
      sql_rollback ();
      return 3;
    }

  quoted_comment = sql_quote (comment ?: "");
  quoted_report_format_id = sql_quote (report_format_id ?: "");

  *report_config = sql_int64_0 ("INSERT INTO report_configs"
                                " (uuid, name, comment, report_format_id,"
                                "  owner, creation_time, modification_time)"
                                " SELECT make_uuid(), '%s', '%s', '%s',"
                                "   (SELECT id FROM users WHERE uuid='%s'),"
                                "   m_now(), m_now()"
                                " RETURNING id;",
                                quoted_name,
                                quoted_comment,
                                quoted_report_format_id,
                                current_credentials.uuid);

  g_free (quoted_name);
  g_free (quoted_comment);
  g_free (quoted_report_format_id);

  for (int i = 0; g_ptr_array_index (params, i); i++)
    {
      report_config_param_data_t *param;
      param = g_ptr_array_index (params, i);

      // Skip params that use default value
      if (param->use_default_value)
        continue;

      if (validate_report_config_param (param, report_format, error_message))
        {
          sql_rollback ();
          return 4;
        }
      insert_report_config_param (*report_config, param);
    }
  sql_commit ();
  return 0;
}

/* MODIFY_REPORT_CONFIG */

/**
 * @brief Modify a report config.
 *
 * @param[in]   report_config_id  UUID of report config to modify.
 * @param[in]   new_name          Name of report config.
 * @param[in]   new_comment       Comment of report config.
 * @param[in]   params            Array of params.
 * @param[out]  error_message     Message for some errors like invalid params.
 *
 * @return 0 success,
 *         1 report config not found,
 *         2 report config with same name already exists,
 *         3 cannot modify params of orphaned report config,
 *         4 param validation failed,
 *         99 permission denied,
 *         -1 internal error.
 */
int
modify_report_config (const char *report_config_id,
                      const char *new_name,
                      const char *new_comment,
                      array_t *params,
                      gchar **error_message)
{
  report_config_t report_config;

  sql_begin_immediate ();

  if (acl_user_may ("modify_report_config") == 0)
    {
      sql_rollback ();
      return 99;
    }

  report_config = 0;
  if (find_report_config_with_permission (report_config_id, &report_config,
                                          "modify_report_config"))
    {
      sql_rollback ();
      return -1;
    }

  if (report_config == 0)
    {
      sql_rollback ();
      return 1;
    }

  if (new_name)
    {
      gchar *quoted_name = sql_quote(new_name);

      if (sql_int ("SELECT count(*) FROM report_configs"
                   " WHERE name = '%s' AND id != %llu",
                   quoted_name, report_config))
        {
          g_free (quoted_name);
          sql_rollback ();
          return 2;
        }

      sql ("UPDATE report_configs SET name = '%s' WHERE id = %llu",
           quoted_name, report_config);
      g_free (quoted_name);
    }

  if (new_comment)
    {
      gchar *quoted_comment = sql_quote(new_comment);
      sql ("UPDATE report_configs SET comment = '%s' WHERE id = %llu",
           quoted_comment, report_config);
      g_free (quoted_comment);
    }

  if (params->len)
    {
      report_format_t report_format;
      report_format = sql_int64_0 ("SELECT id FROM report_formats"
                                   " WHERE uuid = (SELECT report_format_id"
                                   "               FROM report_configs"
                                   "               WHERE id = %llu)",
                                   report_config);
      if (report_format == 0)
        {
          sql_rollback ();
          return 3;
        }

      for (int i = 0; g_ptr_array_index (params, i); i++)
        {
          report_config_param_data_t *param;
          param = g_ptr_array_index (params, i);

          // Delete params meant to use default value
          if (param->use_default_value)
            {
              gchar *quoted_param_name = sql_quote (param->name);
              sql ("DELETE FROM report_config_params"
                   " WHERE report_config = %llu AND name = '%s'",
                   report_config, quoted_param_name);
              continue;
            }
          else
            {
              if (validate_report_config_param (param, report_format,
                                                error_message))
                {
                  sql_rollback ();
                  return 4;
                }
              insert_report_config_param (report_config, param);
            }
        }
    }

  sql ("UPDATE report_configs"
        " SET modification_time = m_now ()"
        " WHERE id = %llu",
        report_config);

  sql_commit ();
  return 0;
}


/* DELETE_REPORT_CONFIG and RESTORE */

/**
 * @brief Delete a report config.
 *
 * @param[in]  report_config_id  UUID of Report config.
 * @param[in]  ultimate          Whether to remove entirely, or to trashcan.
 *
 * @return 0 success, 1 report config in use, 2 failed to find report config,
 *         99 permission denied, -1 error.
 */
int
delete_report_config (const char *report_config_id, int ultimate)
{
  report_config_t report_config, trash_report_config;

  sql_begin_immediate ();

  if (acl_user_may ("delete_report_config") == 0)
    {
      sql_rollback ();
      return 99;
    }

  /* Look in the "real" table. */

  if (find_report_config_with_permission (report_config_id, &report_config,
                                          "delete_report_config"))
    {
      g_message("find failed");
      sql_rollback ();
      return -1;
    }

  if (report_config == 0)
    {
      /* Look in the trashcan. */

      if (find_trash ("report_config", report_config_id, &report_config))
        {
          g_message("find trash failed");
          sql_rollback ();
          return -1;
        }
      if (report_config == 0)
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

      /* Check if it's in use by a trash alert. */

      if (trash_report_config_in_use (report_config))
        {
          sql_rollback ();
          return 1;
        }

      /* Remove entirely. */

      permissions_set_orphans ("report_config", report_config, LOCATION_TRASH);
      tags_remove_resource ("report_config", report_config, LOCATION_TRASH);

      sql ("DELETE FROM report_config_params_trash WHERE report_config = %llu;",
           report_config);
      sql ("DELETE FROM report_configs_trash WHERE id = %llu;",
           report_config);

      sql_commit ();

      return 0;
    }

  if (ultimate)
    {
      permissions_set_orphans ("report_config", report_config, LOCATION_TABLE);
      tags_remove_resource ("report_config", report_config, LOCATION_TABLE);

      /* Check if it's in use by a trash or regular alert. */

      if (report_config_in_use (report_config))
        {
          sql_rollback ();
          return 1;
        }

      /* Remove from "real" tables. */

      sql ("DELETE FROM report_config_params WHERE report_config = %llu;",
           report_config);
      sql ("DELETE FROM report_configs WHERE id = %llu;",
           report_config);
    }
  else
    {
      /* Check if it's in use by a regular alert. */

      if (report_config_in_use (report_config))
        {
          sql_rollback ();
          return 1;
        }

      /* Move to trash. */

      sql ("INSERT INTO report_configs_trash"
           " (uuid, owner, name, comment, creation_time, modification_time,"
           "  report_format_id)"
           " SELECT"
           "  uuid, owner, name, comment, creation_time, modification_time,"
           "  report_format_id"
           " FROM report_configs"
           " WHERE id = %llu;",
           report_config);

      trash_report_config = sql_last_insert_id ();

      sql ("INSERT INTO report_config_params_trash"
           " (report_config, name, value)"
           " SELECT %llu, name, value"
           " FROM report_config_params"
           " WHERE report_config = %llu;",
           trash_report_config, report_config);

      permissions_set_locations ("report_config", report_config,
                                 trash_report_config, LOCATION_TRASH);
      tags_set_locations ("report_config", report_config,
                          trash_report_config, LOCATION_TRASH);

      /* Remove from "real" tables. */

      sql ("DELETE FROM report_config_params WHERE report_config = %llu",
           report_config);
      sql ("DELETE FROM report_configs WHERE id = %llu",
           report_config);
    }

  sql_commit ();

  return 0;
}

/**
 * @brief Delete all report configs owned by a user.
 *
 * @param[in]  user  The user.
 */
void
delete_report_configs_user (user_t user)
{
  sql ("DELETE FROM report_config_params"
       " WHERE report_config IN"
       "   (SELECT id FROM report_configs WHERE owner = %llu)",
       user);
  sql ("DELETE FROM report_configs WHERE owner = %llu;", user);

  sql ("DELETE FROM report_config_params_trash"
       " WHERE report_config IN"
       "   (SELECT id FROM report_configs_trash WHERE owner = %llu)",
       user);
  sql ("DELETE FROM report_configs_trash WHERE owner = %llu;", user);
}

/**
 * @brief Try restore a report config.
 *
 * If success, ends transaction for caller before exiting.
 *
 * @param[in]  report_config_id  UUID of resource.
 *
 * @return 0 success, 1 fail because resource is in use, 2 failed to find
 *         resource, 3 fail because resource with same name exists,
 *         4 fail because resource with same UUID exists, -1 error.
 */
int
restore_report_config (const char *report_config_id)
{
  report_config_t resource, report_config;

  if (find_trash ("report_config", report_config_id, &resource))
    {
      sql_rollback ();
      return -1;
    }

  if (resource == 0)
    return 2;

  if (sql_int ("SELECT count(*) FROM report_configs"
               " WHERE name ="
               " (SELECT name FROM report_configs_trash WHERE id = %llu)"
               " AND " ACL_USER_OWNS () ";",
               resource,
               current_credentials.uuid))
    {
      sql_rollback ();
      return 3;
    }

  if (sql_int ("SELECT count(*) FROM report_configs"
               " WHERE uuid = (SELECT uuid"
               "               FROM report_configs_trash"
               "               WHERE id = %llu);",
               resource))
    {
      sql_rollback ();
      return 4;
    }

  /* Move to "real" tables. */

  sql ("INSERT INTO report_configs"
       " (uuid, owner, name, comment, creation_time, modification_time,"
       "  report_format_id)"
       " SELECT"
       "  uuid, owner, name, comment, creation_time, modification_time,"
       "  report_format_id"
       " FROM report_configs_trash"
       " WHERE id = %llu;",
       resource);

  report_config = sql_last_insert_id ();

  sql ("INSERT INTO report_config_params"
       " (report_config, name, value)"
       " SELECT %llu, name, value"
       " FROM report_config_params_trash"
       " WHERE report_config = %llu;",
       report_config,
       resource);

  permissions_set_locations ("report_config", resource, report_config,
                             LOCATION_TABLE);
  tags_set_locations ("report_config", resource, report_config,
                      LOCATION_TABLE);

  /* Remove from trash tables. */

  sql ("DELETE FROM report_config_params_trash WHERE report_config = %llu;",
       resource);
  sql ("DELETE FROM report_configs_trash WHERE id = %llu;",
       resource);

  sql_commit ();
  return 0;
}


/* GET_REPORT_CONFIGS */

/**
 * @brief Filter columns for Report Config iterator.
 */
#define REPORT_CONFIG_ITERATOR_FILTER_COLUMNS                                 \
 { GET_ITERATOR_FILTER_COLUMNS, "report_format_id", "report_config",          \
   NULL }

/**
 * @brief Report Config iterator columns.
 */
#define REPORT_CONFIG_ITERATOR_COLUMNS                                      \
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
     "(SELECT name FROM users WHERE users.id = report_configs.owner)",      \
     "_owner",                                                              \
     KEYWORD_TYPE_STRING                                                    \
   },                                                                       \
   { "owner", NULL, KEYWORD_TYPE_INTEGER },                                 \
   { "report_format_id", NULL, KEYWORD_TYPE_STRING },                       \
   {                                                                        \
     "(SELECT name FROM report_formats"                                     \
     " WHERE report_formats.uuid = report_format_id)",                      \
     "report_format",                                                       \
     KEYWORD_TYPE_STRING,                                                   \
   },                                                                       \
   {                                                                        \
     "(SELECT id FROM report_formats"                                       \
     " WHERE report_formats.uuid = report_format_id)",                      \
     "report_format_rowid",                                                 \
     KEYWORD_TYPE_INTEGER,                                                  \
   },                                                                       \
   { NULL, NULL, KEYWORD_TYPE_UNKNOWN }                                     \
 }

/**
 * @brief Report Config iterator columns for trash case.
 */
#define REPORT_CONFIG_ITERATOR_TRASH_COLUMNS                                \
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
     "(SELECT name FROM users WHERE users.id = report_configs_trash.owner)",\
     "_owner",                                                              \
     KEYWORD_TYPE_STRING                                                    \
   },                                                                       \
   { "owner", NULL, KEYWORD_TYPE_INTEGER },                                 \
   { "report_format_id", NULL, KEYWORD_TYPE_STRING },                       \
   {                                                                        \
     "(SELECT name FROM report_formats"                                     \
     " WHERE report_formats.uuid = report_format_id)",                      \
     "report_format",                                                       \
     KEYWORD_TYPE_STRING,                                                   \
   },                                                                       \
   {                                                                        \
     "(SELECT id FROM report_formats"                                       \
     " WHERE report_formats.uuid = report_format_id)",                      \
     "report_format_rowid",                                                 \
     KEYWORD_TYPE_INTEGER,                                                  \
   },                                                                       \
 }

/**
 * @brief Count the number of Report Configs.
 *
 * @param[in]  get  GET params.
 *
 * @return Total number of Report Config filtered set.
 */
int
report_config_count (const get_data_t *get)
{
  static const char *filter_columns[] = REPORT_CONFIG_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = REPORT_CONFIG_ITERATOR_COLUMNS;
  static column_t trash_columns[] = REPORT_CONFIG_ITERATOR_TRASH_COLUMNS;
  return count ("report_config", get, columns, trash_columns, filter_columns,
                0, 0, 0, TRUE);
}

/**
 * @brief Initialise a Report Config iterator, including observed Report
 *        Configs.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  get         GET data.
 *
 * @return 0 success, 1 failed to find Report Config, 2 failed to find filter,
 *         -1 error.
 */
int
init_report_config_iterator (iterator_t* iterator, get_data_t *get)
{
  static const char *filter_columns[] = REPORT_CONFIG_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = REPORT_CONFIG_ITERATOR_COLUMNS;
  static column_t trash_columns[] = REPORT_CONFIG_ITERATOR_TRASH_COLUMNS;

  return init_get_iterator (iterator,
                            "report_config",
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
 * @brief Get the report format id from a report config iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Extension, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
const char *
report_config_iterator_report_format_id (iterator_t *iterator)
{
  if (iterator->done)
    return NULL;
  return iterator_string (iterator, GET_ITERATOR_COLUMN_COUNT);
}

/**
 * @brief Return the report format readable state from a report config iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Whether report format is readable.
 */
int
report_config_iterator_report_format_readable (iterator_t* iterator)
{
  const char *report_format_id;

  if (iterator->done) return 0;

  report_format_id
    = report_config_iterator_report_format_id (iterator);

  if (report_format_id)
    {
      int readable;
      readable = acl_user_has_access_uuid
                  ("filter", report_format_id, "get_report_formats", 0);
      return readable;
    }
  return 0;
}

/**
 * @brief Get the report format name from a report config iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Report format name, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
const char *
report_config_iterator_report_format_name (iterator_t *iterator)
{
  if (iterator->done)
    return NULL;
  return iterator_string (iterator, GET_ITERATOR_COLUMN_COUNT + 1);
}

/**
 * @brief Get the report format row id from a report config iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Report format, or 0 if iteration is complete or report format
 *         does not exist.
 */
report_format_t
report_config_iterator_report_format (iterator_t *iterator)
{
  if (iterator->done)
    return 0;
  return iterator_int64 (iterator, GET_ITERATOR_COLUMN_COUNT + 2);
}

/**
 * @brief Initialise an interator of Report Config params.
 *
 * @param[in]  iterator       Iterator.
 * @param[in]  report_config  The report config to get params of.
 * @param[in]  trash          Whether to get report config from trash.
 */
void
init_report_config_param_iterator (iterator_t *iterator,
                                   report_config_t report_config,
                                   int trash)
{
  report_format_t report_format;

  report_format = report_config_report_format (report_config);

  init_iterator (iterator,
                 "SELECT rcp.id, rfp.name, rfp.type,"
                 "       coalesce (rcp.value, rfp.value, rfp.fallback),"
                 "       coalesce (rfp.value, rfp.fallback),"
                 "       rfp.type_min, rfp.type_max, rfp.id,"
                 "       (rcp.id IS NULL)"
                 "  FROM report_format_params AS rfp"
                 "  LEFT JOIN report_config_params%s AS rcp"
                 "    ON rcp.name = rfp.name"
                 "   AND rcp.report_config = %llu"
                 " WHERE rfp.report_format = %llu",
                 trash ? "_trash" : "",
                 report_config, report_format);
}

/**
 * @brief Get the parameter row id from a report config param iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Param row id, or 0 if iteration is complete.
 */
report_config_param_t
report_config_param_iterator_rowid (iterator_t *iterator)
{
  if (iterator->done)
    return 0;
  return iterator_int64 (iterator, 0);
}

/**
 * @brief Get the parameter name from a report config param iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Name, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
const char*
report_config_param_iterator_name (iterator_t *iterator)
{
  if (iterator->done)
    return NULL;
  return iterator_string (iterator, 1);
}

/**
 * @brief Get the parameter type from a report config param iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Param type, or REPORT_FORMAT_PARAM_TYPE_ERROR
 *         if iteration is complete.
 */
report_format_param_type_t
report_config_param_iterator_type (iterator_t *iterator)
{
  if (iterator->done)
    return REPORT_FORMAT_PARAM_TYPE_ERROR;
  return iterator_int (iterator, 2);
}

/**
 * @brief Get the parameter type name from a report config param iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Param type name, or NULL if iteration is complete.
 */
const char*
report_config_param_iterator_type_name (iterator_t *iterator)
{
  if (iterator->done)
    return NULL;
  return report_format_param_type_name (iterator_int (iterator, 2));
}

/**
 * @brief Get the parameter value from a report config param iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Name, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
const char*
report_config_param_iterator_value (iterator_t *iterator)
{
  if (iterator->done)
    return NULL;
  return iterator_string (iterator, 3);
}

/**
 * @brief Get the parameter fallback value from a report config param iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Fallback value, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
const char*
report_config_param_iterator_fallback_value (iterator_t *iterator)
{
  if (iterator->done)
    return NULL;
  return iterator_string (iterator, 4);
}

/**
 * @brief Get the minimum value or length from a report config param iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Minimum value/length, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
long long int
report_config_param_iterator_type_min (iterator_t *iterator)
{
  if (iterator->done)
    return -1;
  return iterator_int64 (iterator, 5);
}

/**
 * @brief Get the maximum value or length from a report config param iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Maximum value/length, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
long long int
report_config_param_iterator_type_max (iterator_t *iterator)
{
  if (iterator->done)
    return -1;
  return iterator_int64 (iterator, 6);
}

/**
 * @brief Get the report format parameter row id from a
 *        report config param iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Report format param row id, or 0 if iteration is complete.
 */
report_format_param_t
report_config_param_iterator_format_param (iterator_t *iterator)
{
  if (iterator->done)
    return 0;
  return iterator_int64 (iterator, 7);
}

/**
 * @brief Get if a report format param is using the default fallback value.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return 1 if using fallback, or 0 if not or iteration is complete.
 */
int
report_config_param_iterator_using_default (iterator_t *iterator)
{
  if (iterator->done)
    return 0;
  return iterator_int (iterator, 8);
}

/* Misc. functions */

/**
 * @brief Return the name of a config config.
 *
 * @param[in]  report_config  Report config.
 *
 * @return Newly allocated UUID.
 */
char *
report_config_name (report_config_t report_config)
{
  return sql_string ("SELECT name FROM report_configs WHERE id = %llu;",
                     report_config);
}

/**
 * @brief Return the UUID of a config config.
 *
 * @param[in]  report_config  Report config.
 *
 * @return Newly allocated UUID.
 */
char *
report_config_uuid (report_config_t report_config)
{
  return sql_string ("SELECT uuid FROM report_configs WHERE id = %llu;",
                     report_config);
}

/**
 * @brief Return the report format of a report config.
 *
 * @param[in]  report_config  Report config.
 *
 * @return Newly allocated UUID.
 */
report_format_t
report_config_report_format (report_config_t report_config)
{
  return sql_int64_0 ("SELECT id FROM report_formats"
                      " WHERE uuid = (SELECT report_format_id"
                      "               FROM report_configs WHERE id = %llu);",
                      report_config);
}

/**
 * @brief Return whether a report config is referenced by an alert.
 *
 * @param[in]  report_config  Report Config.
 *
 * @return 1 if in use, else 0.
 */
int
report_config_in_use (report_config_t report_config)
{
  // TODO: Check for alerts using the report config
  return 0;
}

/**
 * @brief Return whether a report config in trash is referenced by an alert.
 *
 * @param[in]  report_config  Report Config.
 *
 * @return 1 if in use, else 0.
 */
int
trash_report_config_in_use (report_config_t report_config)
{
  // TODO: Check for alerts using the report config
  return 0;
}

/**
 * @brief Get filter columns.
 *
 * @return Constant array of filter columns.
 */
const char**
report_config_filter_columns ()
{
  static const char *columns[] = REPORT_CONFIG_ITERATOR_FILTER_COLUMNS;
  return columns;
}

/**
 * @brief Get select columns.
 *
 * @return Constant array of select columns.
 */
column_t*
report_config_select_columns ()
{
  static column_t columns[] = REPORT_CONFIG_ITERATOR_COLUMNS;
  return columns;
}
