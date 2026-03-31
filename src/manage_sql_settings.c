/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_sql_settings.h"
#include "manage_acl.h"
#include "manage_runtime_flags.h"
#include "manage_sql_configs.h"
#include "manage_sql_port_lists.h"
#include "manage_sql_report_formats.h"
#include "manage_sql_users.h"
#include "sql.h"

#include <ctype.h>

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

/**
 * @brief Return the Dynamic Severity user setting as an int.
 *
 * @return 1 if user's Dynamic Severity is "Yes", 0 if it is "No",
 *         or does not exist.
 */
int
setting_dynamic_severity_int ()
{
  return current_credentials.dynamic_severity;
}

/**
 * @brief Return the Auto Cache Rebuild user setting as an int.
 *
 * @return 1 if cache is rebuilt automatically, 0 if not.
 */
int
setting_auto_cache_rebuild_int ()
{
  return sql_int ("SELECT coalesce"
                  "        ((SELECT value FROM settings"
                  "          WHERE uuid = '" SETTING_UUID_AUTO_CACHE_REBUILD "'"
                  "          AND " ACL_USER_OWNS () ""
                  "          ORDER BY coalesce (owner, 0) DESC LIMIT 1),"
                  "         '1');",
                  current_credentials.uuid);
}

/**
 * @brief Get the value of a setting as a string.
 *
 * @param[in]   uuid   UUID of setting.
 * @param[out]  value  Freshly allocated value.
 *
 * @return 0 success, -1 error.
 */
int
setting_value_sql (const char *uuid, char **value)
{
  gchar *quoted_uuid;

  if (value == NULL || uuid == NULL)
    return -1;

  quoted_uuid = sql_quote (uuid);

  if (sql_int ("SELECT count (*)"
               " FROM settings"
               " WHERE uuid = '%s'"
               " AND " ACL_GLOBAL_OR_USER_OWNS () ";",
               quoted_uuid,
               current_credentials.uuid)
      == 0)
    {
      *value = NULL;
      g_free (quoted_uuid);
      return -1;
    }

  *value = sql_string
             ("SELECT value"
              " FROM settings"
              " WHERE uuid = '%s'"
              " AND " ACL_GLOBAL_OR_USER_OWNS ()
              /* Force the user's setting to come before the default. */
              " ORDER BY coalesce (owner, 0) DESC;",
              quoted_uuid,
              current_credentials.uuid);

  g_free (quoted_uuid);

  return 0;
}

/**
 * @brief Get the value of a setting.
 *
 * @param[in]   uuid   UUID of setting.
 * @param[out]  value  Value.
 *
 * @return 0 success, -1 error.
 */
int
setting_value_int_sql (const char *uuid, int *value)
{
  gchar *quoted_uuid;

  if (value == NULL || uuid == NULL)
    return -1;

  quoted_uuid = sql_quote (uuid);

  if (sql_int ("SELECT count (*)"
               " FROM settings"
               " WHERE uuid = '%s'"
               " AND " ACL_GLOBAL_OR_USER_OWNS () ";",
               quoted_uuid,
               current_credentials.uuid)
      == 0)
    {
      *value = -1;
      g_free (quoted_uuid);
      return -1;
    }

  *value = sql_int ("SELECT value"
                    " FROM settings"
                    " WHERE uuid = '%s'"
                    " AND " ACL_GLOBAL_OR_USER_OWNS ()
                    /* Force the user's setting to come before the default. */
                    " ORDER BY coalesce (owner, 0) DESC;",
                    quoted_uuid,
                    current_credentials.uuid);

  g_free (quoted_uuid);

  return 0;
}

/**
 * @brief Count number of settings.
 *
 * @param[in]  filter           Filter term.
 *
 * @return Total number of settings in filtered set.
 */
int
setting_count (const char *filter)
{
  static const char *filter_columns[] = SETTING_ITERATOR_FILTER_COLUMNS;
  static column_t select_columns[] = SETTING_ITERATOR_COLUMNS;
  gchar *clause;
  int ret;

  assert (current_credentials.uuid);

  clause = filter_clause ("setting", filter, filter_columns, select_columns,
                          NULL, 0, 0, NULL, NULL, NULL, NULL, NULL);

  ret = sql_int ("SELECT count (*)"
                 " FROM settings"
                 " WHERE"
                 " (owner = (SELECT id FROM users WHERE uuid = '%s')"
                 "  OR (owner IS NULL"
                 "      AND uuid"
                 "      NOT IN (SELECT uuid FROM settings"
                 "              WHERE owner = (SELECT id FROM users"
                 "                             WHERE uuid = '%s'))))"
                 "%s%s;",
                 current_credentials.uuid,
                 current_credentials.uuid,
                 clause ? " AND " : "",
                 clause ? clause : "");

  g_free (clause);

  return ret;
}

/**
 * @brief Initialise a setting iterator, including observed settings.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  uuid        UUID of setting to limit iteration to.  0 for all.
 * @param[in]  filter      Filter term.
 * @param[in]  first       First setting.
 * @param[in]  max         Maximum number of settings returned.
 * @param[in]  ascending   Whether to sort ascending or descending.
 * @param[in]  sort_field  Field to sort on, or NULL for "id".
 */
void
init_setting_iterator (iterator_t *iterator, const char *uuid,
                       const char *filter, int first, int max, int ascending,
                       const char *sort_field)
{
  static const char *filter_columns[] = SETTING_ITERATOR_FILTER_COLUMNS;
  static column_t select_columns[] = SETTING_ITERATOR_COLUMNS;
  gchar *clause, *columns, *quoted_uuid;

  assert (current_credentials.uuid);

  if (first < 0)
    first = 0;
  if (max < 1)
    max = -1;

  clause = filter_clause ("setting", filter, filter_columns, select_columns,
                          NULL, 0, 0, NULL, NULL, NULL, NULL, NULL);

  quoted_uuid = uuid ? sql_quote (uuid) : NULL;
  columns = columns_build_select (select_columns);

  if (quoted_uuid)
    init_iterator (iterator,
                   "SELECT %s"
                   " FROM settings"
                   " WHERE uuid = '%s'"
                   " AND (owner = (SELECT id FROM users WHERE uuid = '%s')"
                   "      OR (owner IS NULL"
                   "          AND uuid"
                   "          NOT IN (SELECT uuid FROM settings"
                   "                  WHERE owner = (SELECT id FROM users"
                   "                                 WHERE uuid = '%s'))))",
                   columns,
                   quoted_uuid,
                   current_credentials.uuid,
                   current_credentials.uuid);
  else
    init_iterator (iterator,
                   "SELECT %s"
                   " FROM settings"
                   " WHERE"
                   " (owner = (SELECT id FROM users WHERE uuid = '%s')"
                   "  OR (owner IS NULL"
                   "      AND uuid"
                   "      NOT IN (SELECT uuid FROM settings"
                   "              WHERE owner = (SELECT id FROM users"
                   "                             WHERE uuid = '%s'))))"
                   "%s%s"
                   " ORDER BY %s %s"
                   " LIMIT %s OFFSET %i;",
                   columns,
                   current_credentials.uuid,
                   current_credentials.uuid,
                   clause ? " AND " : "",
                   clause ? clause : "",
                   sort_field ? sort_field : "id",
                   ascending ? "ASC" : "DESC",
                   sql_select_limit (max),
                   first);

  g_free (quoted_uuid);
  g_free (columns);
  g_free (clause);
}

/**
 * @brief Get the UUID from a setting iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The UUID of the setting, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (setting_iterator_uuid, 1);

/**
 * @brief Get the name from a setting iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The name of the setting, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (setting_iterator_name, 2);

/**
 * @brief Get the comment from a setting iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The comment of the setting, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (setting_iterator_comment, 3);

/**
 * @brief Get the value from a setting iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The value of the setting, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (setting_iterator_value, 4);

/**
 * @brief Set the value of a setting.
 *
 * @param[in]  uuid      UUID of setting.
 * @param[in]  name      Setting name.  For Timezone and Password.
 * @param[in]  value_64  New setting value, base64 encoded.
 * @param[out] r_errdesc If not NULL the address of a variable to receive
 *                       a malloced string with the error description.  Will
 *                       always be set to NULL on success.
 *
 * @return 0 success, 1 failed to find setting, 2 syntax error in value,
 *         3 feature disabled, 99 permission denied, -1 on error.
 */
modify_setting_result_t
modify_setting (const gchar *uuid, const gchar *name,
                const gchar *value_64, gchar **r_errdesc)
{
  char *setting_name;

  assert (current_credentials.uuid);

  if (acl_user_may ("modify_setting") == 0)
    return MODIFY_SETTING_RESULT_PERMISSION_DENIED;

  if (r_errdesc)
    *r_errdesc = NULL;

  if (name && (strcmp (name, "Timezone") == 0))
    {
      gsize value_size;
      gchar *timezone;
      if (value_64 && strlen (value_64))
        {
          timezone = (gchar *) g_base64_decode (value_64, &value_size);
          if (g_utf8_validate (timezone, value_size, NULL) == FALSE)
            {
              if (r_errdesc)
                *r_errdesc = g_strdup ("Value cannot be decoded to"
                                       " valid UTF-8");
              g_free (timezone);
              return MODIFY_SETTING_RESULT_ERROR;
            }
          if (manage_timezone_supported (timezone) == FALSE)
            {
              g_free (timezone);
              return MODIFY_SETTING_RESULT_SYNTAX_ERROR;
            }
        }
      else
        {
          timezone = g_strdup ("");
          value_size = 0;
        }

      sql_ps ("UPDATE users SET timezone = $1, modification_time = m_now ()"
              " WHERE uuid = $2;",
              SQL_STR_PARAM (timezone),
              SQL_STR_PARAM (current_credentials.uuid), NULL);

      g_free (timezone);
      return MODIFY_SETTING_RESULT_OK;
    }

  if (name && (strcmp (name, "Password") == 0))
    {
      gsize value_size;
      gchar *value;
      int ret;

      assert (current_credentials.username);

      if (value_64 && strlen (value_64))
        {
          value = (gchar*) g_base64_decode (value_64, &value_size);
          if (g_utf8_validate (value, value_size, NULL) == FALSE)
            {
              if (r_errdesc)
                *r_errdesc = g_strdup ("Value cannot be decoded to"
                                       " valid UTF-8");
              g_free (value);
              return MODIFY_SETTING_RESULT_ERROR;
            }
        }
      else
        {
          value = g_strdup ("");
          value_size = 0;
        }

      ret = set_password (current_credentials.username,
                          current_credentials.uuid,
                          value,
                          r_errdesc);
      g_free (value);
      return ret;
    }

  if (uuid && (strcmp (uuid, SETTING_UUID_AUTO_CACHE_REBUILD) == 0
               || strcmp (uuid, SETTING_UUID_SECURITY_INTELLIGENCE_EXPORT) == 0
               || strcmp (uuid, SETTING_UUID_AUTO_REFRESH) == 0
               || strcmp (uuid, SETTING_UUID_DEFAULT_SEVERITY) == 0
               || strcmp (uuid, SETTING_UUID_DYNAMIC_SEVERITY) == 0
               || strcmp (uuid, SETTING_UUID_EXCERPT_SIZE) == 0
               || strcmp (uuid, SETTING_UUID_PREFERRED_LANG) == 0
               || strcmp (uuid, SETTING_UUID_ROWS_PER_PAGE) == 0
               || strcmp (uuid, SETTING_UUID_USER_INTERFACE_DATE_FORMAT) == 0
               || strcmp (uuid, SETTING_UUID_USER_INTERFACE_TIME_FORMAT) == 0))
    {
      gsize value_size;
      gchar *value;

      assert (current_credentials.username);

      if (sql_int_ps ("SELECT count(*) FROM settings"
                      " WHERE uuid = $1"
                      " AND " ACL_IS_GLOBAL () ";",
                      SQL_STR_PARAM (uuid), NULL)
          == 0)
        {
          return MODIFY_SETTING_RESULT_NOT_FOUND;
        }

      if (value_64 && strlen (value_64))
        {
          value = (gchar*) g_base64_decode (value_64, &value_size);
          if (g_utf8_validate (value, value_size, NULL) == FALSE)
            {
              if (r_errdesc)
                *r_errdesc = g_strdup ("Value cannot be decoded to"
                                       " valid UTF-8");
              g_free (value);
              return MODIFY_SETTING_RESULT_ERROR;
            }
        }
      else
        {
          value = g_strdup ("");
          value_size = 0;
        }

      if (strcmp (uuid, SETTING_UUID_ROWS_PER_PAGE) == 0)
        {
          const gchar *val;
          /* Rows Per Page. */
          val = value;
          while (*val && isdigit (*val)) val++;
          if (*val && strcmp (value, "-1"))
            {
              return MODIFY_SETTING_RESULT_SYNTAX_ERROR;
            }
        }

      if (strcmp (uuid, SETTING_UUID_PREFERRED_LANG) == 0)
        {
          GRegex *languages_regex;
          gboolean match;
          /*
           * regex: colon-separated lists of language or language and country
           *  codes (ISO 639-1, 639-2 and 3166-1 alpha-2)
           *  as used in the LANGUAGE env variable by gettext
           */
          languages_regex
            = g_regex_new ("^(Browser Language|"
                           "([a-z]{2,3})(_[A-Z]{2})?(@[[:alnum:]_\\-]+)?"
                           "(:([a-z]{2,3})(_[A-Z]{2})?(@[[:alnum:]_\\-]+)?)*)$",
                           0, 0, NULL);
          match = g_regex_match (languages_regex, value, 0, NULL);
          g_regex_unref (languages_regex);

          /* User Interface Language. */
          if (match)
            {
              // Valid languages string or "Browser Language":
              //  keep string as it is
            }
          /* Legacy full language names */
          else if (strcmp (value, "Chinese") == 0)
            {
              g_free (value);
              value = g_strdup ("zh_CN");
            }
          else if (strcmp (value, "English") == 0)
            {
              g_free (value);
              value = g_strdup ("en");
            }
          else if (strcmp (value, "German") == 0)
            {
              g_free (value);
              value = g_strdup ("de");
            }
          /* Invalid value */
          else
            {
              g_free (value);
              return MODIFY_SETTING_RESULT_SYNTAX_ERROR;
            }
        }

      if (strcmp (uuid, SETTING_UUID_DYNAMIC_SEVERITY) == 0)
        {
          /* Dynamic Severity */
          current_credentials.dynamic_severity = atoi (value);
          reports_clear_count_cache (current_credentials.uuid);
        }

      if (strcmp (uuid, SETTING_UUID_EXCERPT_SIZE) == 0)
        {
          /* Note/Override Excerpt Size */
          current_credentials.excerpt_size = atoi (value);
        }

      if (strcmp (uuid, SETTING_UUID_DEFAULT_SEVERITY) == 0)
        {
          double severity_dbl;
          /* Default Severity */
          if (sscanf (value, "%lf", &severity_dbl) != 1
              || severity_dbl < 0.0 || severity_dbl > 10.0)
            {
              g_free (value);
              return MODIFY_SETTING_RESULT_SYNTAX_ERROR;
            }
          else
            current_credentials.default_severity = severity_dbl;
        }

      if (strcmp (uuid, SETTING_UUID_AUTO_CACHE_REBUILD) == 0)
        {
          int value_int;
          /* Auto Cache Rebuild */
          if (sscanf (value, "%d", &value_int) != 1
              || (strcmp (value, "0") && strcmp (value, "1")))
            {
              g_free (value);
              return MODIFY_SETTING_RESULT_SYNTAX_ERROR;
            }
        }

      if (strcmp (uuid, SETTING_UUID_SECURITY_INTELLIGENCE_EXPORT) == 0)
        {
          if (!feature_enabled (FEATURE_ID_SECURITY_INTELLIGENCE_EXPORT))
            {
              g_free (value);

              g_warning("Export Reports to OPENVAS SECURITY INTELLIGENCE Feature"
                        "is disabled");
              return MODIFY_SETTING_RESULT_FEATURE_DISABLED;
            }

          int value_int;
          /* Export Reports SECURITY INTELLIGENCE */
          if (sscanf (value, "%d", &value_int) != 1
              || (strcmp (value, "0") && strcmp (value, "1")))
            {
              g_free (value);
              return MODIFY_SETTING_RESULT_SYNTAX_ERROR;
            }
        }

      if (strcmp (uuid, SETTING_UUID_USER_INTERFACE_TIME_FORMAT) == 0)
        {
          /* User Interface Time Format */
          if (strcmp (value, "12") && strcmp (value, "24")
              && strcmp (value, "system_default"))
            {
              g_free (value);
              return MODIFY_SETTING_RESULT_SYNTAX_ERROR;
            }
        }

      if (strcmp (uuid, SETTING_UUID_USER_INTERFACE_DATE_FORMAT) == 0)
        {
          /* User Interface Date Format */
          if (strcmp (value, "wmdy") && strcmp (value, "wdmy")
              && strcmp (value, "system_default"))
            {
              g_free (value);
              return MODIFY_SETTING_RESULT_SYNTAX_ERROR;
            }
        }

      if (sql_int_ps ("SELECT count(*) FROM settings"
                      " WHERE uuid = $1"
                      " AND owner = (SELECT id FROM users WHERE uuid = $2);",
                      SQL_STR_PARAM (uuid),
                      SQL_STR_PARAM (current_credentials.uuid), NULL))
        sql_ps ("UPDATE settings SET value = $1"
                " WHERE uuid = $2"
                " AND owner = (SELECT id FROM users WHERE uuid = $3);",
                SQL_STR_PARAM (value), SQL_STR_PARAM (uuid),
                SQL_STR_PARAM (current_credentials.uuid), NULL);
      else
        sql_ps ("INSERT INTO settings (uuid, owner, name, comment, value)"
                " VALUES"
                " ($1,"
                "  (SELECT id FROM users WHERE uuid = $2),"
                "  (SELECT name FROM settings"
                "   WHERE uuid = $1 AND " ACL_IS_GLOBAL ()
                "   LIMIT 1),"
                "  (SELECT comment FROM settings"
                "   WHERE uuid = $1 AND " ACL_IS_GLOBAL ()
                "   LIMIT 1),"
                "  $3);",
                SQL_STR_PARAM (uuid),
                SQL_STR_PARAM (current_credentials.uuid),
                SQL_STR_PARAM (value), NULL);

      g_free (value);
      return MODIFY_SETTING_RESULT_OK;
    }

  /* Export file name format */
  if (uuid
      && (strcmp (uuid, SETTING_UUID_FILE_DETAILS) == 0
          || strcmp (uuid, SETTING_UUID_FILE_LIST) == 0
          || strcmp (uuid, SETTING_UUID_FILE_REPORT) == 0))
    {
      gsize value_size;
      gchar *value;

      assert (current_credentials.uuid);
      if (strcmp (uuid, SETTING_UUID_FILE_DETAILS) == 0)
        setting_name = "Details Export File Name";
      else if (strcmp (uuid, SETTING_UUID_FILE_LIST) == 0)
        setting_name = "List Export File Name";
      else if (strcmp (uuid, SETTING_UUID_FILE_REPORT) == 0)
        setting_name = "Report Export File Name";
      else
        return MODIFY_SETTING_RESULT_ERROR;

      if (value_64 && strlen (value_64))
        {
          value = (gchar*) g_base64_decode (value_64, &value_size);
          if (g_utf8_validate (value, value_size, NULL) == FALSE)
            {
              if (r_errdesc)
                *r_errdesc = g_strdup ("Value cannot be decoded to"
                                       " valid UTF-8");
              g_free (value);
              return MODIFY_SETTING_RESULT_ERROR;
            }
        }
      else
        {
          value = g_strdup ("");
          value_size = 0;
        }

      if (strcmp (value, "") == 0)
        {
          g_free (value);
          return MODIFY_SETTING_RESULT_SYNTAX_ERROR;
        }

      if (sql_int_ps ("SELECT count(*) FROM settings"
                      " WHERE uuid = $1"
                      " AND owner = (SELECT id FROM users WHERE uuid = $2);",
                      SQL_STR_PARAM (uuid),
                      SQL_STR_PARAM (current_credentials.uuid), NULL))
        sql_ps ("UPDATE settings SET value = $1"
                " WHERE uuid = $2"
                " AND owner = (SELECT id FROM users WHERE uuid = $3);",
                SQL_STR_PARAM (value),
                SQL_STR_PARAM (uuid),
                SQL_STR_PARAM (current_credentials.uuid), NULL);
      else
        sql_ps ("INSERT INTO settings (uuid, owner, name, comment, value)"
                " VALUES"
                " ($1,"
                "  (SELECT id FROM users WHERE uuid = $2),"
                "  $3,"
                "  (SELECT comment FROM settings"
                "   WHERE uuid = $1 AND " ACL_IS_GLOBAL () "),"
                "  $4);",
                SQL_STR_PARAM (uuid),
                SQL_STR_PARAM (current_credentials.uuid),
                SQL_STR_PARAM (setting_name),
                SQL_STR_PARAM (value), NULL);

      g_free (value);
      return MODIFY_SETTING_RESULT_OK;
    }

  /* Resources filters, default resource selections and chart preferences. */

  setting_name = NULL;
  if (uuid)
    {
      /* Filters */
      if (strcmp (uuid, "b833a6f2-dcdc-4535-bfb0-a5154b5b5092") == 0)
        setting_name = g_strdup ("Alerts Filter");
#if ENABLE_AGENTS
      else if (strcmp (uuid, "391fc4f4-9f6c-4f0e-a689-37dd7d70d144") == 0)
        setting_name = g_strdup ("Agent Groups Filter");
      else if (strcmp (uuid, "c544a310-dc13-49c6-858e-f3160d75e221") == 0)
        setting_name = g_strdup ("Agents Filter");
      else if (strcmp (uuid, "a39a719a-e6bc-4d9f-a1e6-a53e5b014b05") == 0)
        setting_name = g_strdup ("Agent Installers Filter");
#endif
      else if (strcmp (uuid, "0f040d06-abf9-43a2-8f94-9de178b0e978") == 0)
        setting_name = g_strdup ("Assets Filter");
      else if (strcmp (uuid, "aaf1b63b-55a6-40ee-ae06-e8e50726f55a") == 0)
        setting_name = g_strdup ("Audits Filter");
      else if (strcmp (uuid, "45414da7-55f0-44c1-abbb-6b7d1126fbdf") == 0)
        setting_name = g_strdup ("Audit Reports Filter");
      else if (strcmp (uuid, "1a9fbd91-0182-44cd-bc88-a13a9b3b1bef") == 0)
        setting_name = g_strdup ("Configs Filter");
      else if (strcmp (uuid, "186a5ac8-fe5a-4fb1-aa22-44031fb339f3") == 0)
        setting_name = g_strdup ("Credentials Filter");
      else if (strcmp (uuid, "f9691163-976c-47e7-ad9a-38f2d5c81649") == 0)
        setting_name = g_strdup ("Filters Filter");
      else if (strcmp (uuid, "f722e5a4-88d8-475f-95b9-e4dcafbc075b") == 0)
        setting_name = g_strdup ("Groups Filter");
      else if (strcmp (uuid, "37562dfe-1f7e-4cae-a7c0-fa95e6f194c5") == 0)
        setting_name = g_strdup ("Hosts Filter");
      else if (strcmp (uuid, "96abcd5a-9b6d-456c-80b8-c3221bfa499d") == 0)
        setting_name = g_strdup ("Notes Filter");
#if ENABLE_CONTAINER_SCANNING
      else if (strcmp (uuid, "db61a364-de40-4552-b1bc-a518744f847a") == 0)
        setting_name = g_strdup ("OCI Image Targets Filter");
#endif
      else if (strcmp (uuid, "f608c3ec-ce73-4ff6-8e04-7532749783af") == 0)
        setting_name = g_strdup ("Operating Systems Filter");
      else if (strcmp (uuid, "eaaaebf1-01ef-4c49-b7bb-955461c78e0a") == 0)
        setting_name = g_strdup ("Overrides Filter");
      else if (strcmp (uuid, "ffb16b28-538c-11e3-b8f9-406186ea4fc5") == 0)
        setting_name = g_strdup ("Permissions Filter");
      else if (strcmp (uuid, "7d52d575-baeb-4d98-bb68-e1730dbc6236") == 0)
        setting_name = g_strdup ("Policies Filter");
      else if (strcmp (uuid, "a17e1497-b27d-4389-9860-2f3b01dff9b2") == 0)
        setting_name = g_strdup ("Port Lists Filter");
      else if (strcmp (uuid, "48ae588e-9085-41bc-abcb-3d6389cf7237") == 0)
        setting_name = g_strdup ("Reports Filter");
      else if (strcmp (uuid, "eca9738b-4339-4a3d-bd13-3c61173236ab") == 0)
        setting_name = g_strdup ("Report Configs Filter");
      else if (strcmp (uuid, "249c7a55-065c-47fb-b453-78e11a665565") == 0)
        setting_name = g_strdup ("Report Formats Filter");
      else if (strcmp (uuid, "739ab810-163d-11e3-9af6-406186ea4fc5") == 0)
        setting_name = g_strdup ("Results Filter");
      else if (strcmp (uuid, "f38e673a-bcd1-11e2-a19a-406186ea4fc5") == 0)
        setting_name = g_strdup ("Roles Filter");
      else if (strcmp (uuid, "ba00fe91-bdce-483c-b8df-2372e9774ad6") == 0)
        setting_name = g_strdup ("Scanners Filter");
      else if (strcmp (uuid, "a83e321b-d994-4ae8-beec-bfb5fe3e7336") == 0)
        setting_name = g_strdup ("Schedules Filter");
      else if (strcmp (uuid, "108eea3b-fc61-483c-9da9-046762f137a8") == 0)
        setting_name = g_strdup ("Tags Filter");
      else if (strcmp (uuid, "236e2e41-9771-4e7a-8124-c432045985e0") == 0)
        setting_name = g_strdup ("Targets Filter");
      else if (strcmp (uuid, "1c981851-8244-466c-92c4-865ffe05e721") == 0)
        setting_name = g_strdup ("Tasks Filter");
      else if (strcmp (uuid, "801544de-f06d-4377-bb77-bbb23369bad4") == 0)
        setting_name = g_strdup ("Tickets Filter");
      else if (strcmp (uuid, "34a176c1-0278-4c29-b84d-3d72117b2169") == 0)
        setting_name = g_strdup ("TLS Certificates Filter");
      else if (strcmp (uuid, "a33635be-7263-4549-bd80-c04d2dba89b4") == 0)
        setting_name = g_strdup ("Users Filter");
      else if (strcmp (uuid, "17c9d269-95e7-4bfa-b1b2-bc106a2175c7") == 0)
        setting_name = g_strdup ("Vulnerabilities Filter");
      else if (strcmp (uuid, "3414a107-ae46-4dea-872d-5c4479a48e8f") == 0)
        setting_name = g_strdup ("CPE Filter");
      else if (strcmp (uuid, "def63b5a-41ef-43f4-b9ef-03ef1665db5d") == 0)
        setting_name = g_strdup ("CVE Filter");
      else if (strcmp (uuid, "bef08b33-075c-4f8c-84f5-51f6137e40a3") == 0)
        setting_name = g_strdup ("NVT Filter");
      else if (strcmp (uuid, "e4cf514a-17e2-4ab9-9c90-336f15e24750") == 0)
        setting_name = g_strdup ("CERT-Bund Filter");
      else if (strcmp (uuid, "312350ed-bc06-44f3-8b3f-ab9eb828b80b") == 0)
        setting_name = g_strdup ("DFN-CERT Filter");
      else if (strcmp (uuid, "32b3d606-461b-4770-b3e1-b9ea3cf0f84c") == 0)
        setting_name = g_strdup ("Notes Filter");
      else if (strcmp (uuid, "956d13bd-3baa-4404-a138-5e7eb8f9630e") == 0)
        setting_name = g_strdup ("Overrides Filter");

      /* Content composer defaults */
      else if (strcmp (uuid, "b6b449ee-5d90-4ff0-af20-7e838c389d39") == 0)
        setting_name = g_strdup ("Report Composer Defaults");

      /* Default resource selections */
      else if (strcmp (uuid, "f9f5a546-8018-48d0-bef5-5ad4926ea899") == 0)
        setting_name = g_strdup ("Default Alert");

      else if (strcmp (uuid, "fe7ea321-e3e3-4cc6-9952-da836aae83ce") == 0)
        setting_name = g_strdup ("Default OpenVAS Scan Config");
      else if (strcmp (uuid, "fb19ac4b-614c-424c-b046-0bc32bf1be73") == 0)
        setting_name = g_strdup ("Default OSP Scan Config");

      else if (strcmp (uuid, "6fc56b72-c1cf-451c-a4c4-3a9dc784c3bd") == 0)
        setting_name = g_strdup ("Default SSH Credential");
      else if (strcmp (uuid, "a25c0cfe-f977-417b-b1da-47da370c03e8") == 0)
        setting_name = g_strdup ("Default SMB Credential");
      else if (strcmp (uuid, "83545bcf-0c49-4b4c-abbf-63baf82cc2a7") == 0)
        setting_name = g_strdup ("Default ESXi Credential");
      else if (strcmp (uuid, "024550b8-868e-4b3c-98bf-99bb732f6a0d") == 0)
        setting_name = g_strdup ("Default SNMP Credential");

      else if (strcmp (uuid, "d74a9ee8-7d35-4879-9485-ab23f1bd45bc") == 0)
        setting_name = g_strdup ("Default Port List");

      else if (strcmp (uuid, "f7d0f6ed-6f9e-45dc-8bd9-05cced84e80d") == 0)
        setting_name = g_strdup ("Default OpenVAS Scanner");
      else if (strcmp (uuid, "b20697c9-be0a-4cd4-8b4d-5fe7841ebb03") == 0)
        setting_name = g_strdup ("Default OSP Scanner");

      else if (strcmp (uuid, "353304fc-645e-11e6-ba7a-28d24461215b") == 0)
        setting_name = g_strdup ("Default Report Format");

      else if (strcmp (uuid, "778eedad-5550-4de0-abb6-1320d13b5e18") == 0)
        setting_name = g_strdup ("Default Schedule");

      else if (strcmp (uuid, "23409203-940a-4b4a-b70c-447475f18323") == 0)
        setting_name = g_strdup ("Default Target");

      /*
       * Main dashboard
       */
      else if (strcmp (uuid, "d97eca9f-0386-4e5d-88f2-0ed7f60c0646") == 0)
        setting_name = g_strdup ("Main Dashboard Configuration");

      /*
       * Scans dashboards
       */
      else if (strcmp (uuid, "c7584d7c-649f-4f8b-9ded-9e1dc20f24c8") == 0)
        setting_name = g_strdup ("Scans Dashboard Configuration");

      /* Tasks dashboard settings */
      else if (strcmp (uuid, "3d5db3c7-5208-4b47-8c28-48efc621b1e0") == 0)
        setting_name = g_strdup ("Tasks Top Dashboard Configuration");

      /* Reports dashboard settings */
      else if (strcmp (uuid, "e599bb6b-b95a-4bb2-a6bb-fe8ac69bc071") == 0)
        setting_name = g_strdup ("Reports Top Dashboard Configuration");

      /* Audit Reports dashboard settings */
      else if (strcmp (uuid, "8083d77b-05bb-4b17-ab39-c81175cb512c") == 0)
        setting_name = g_strdup ("Audit Reports Top Dashboard Configuration");
      /* Results dashboard settings */
      else if (strcmp (uuid, "0b8ae70d-d8fc-4418-8a72-e65ac8d2828e") == 0)
        setting_name = g_strdup ("Results Top Dashboard Configuration");

      /* Vulns dashboard settings */
      else if (strcmp (uuid, "43690dcb-3174-4d84-aa88-58c1936c7f5c") == 0)
        setting_name = g_strdup ("Vulnerabilities Top Dashboard Configuration");

      /* Notes dashboard settings */
      else if (strcmp (uuid, "ce7b121-c609-47b0-ab57-fd020a0336f4a") == 0)
        setting_name = g_strdup ("Notes Top Dashboard Configuration");

      /* Overrides dashboard settings */
      else if (strcmp (uuid, "054862fe-0781-4527-b1aa-2113bcd16ce7") == 0)
        setting_name = g_strdup ("Overrides Top Dashboard Configuration");

      /*
       * Assets dashboards
       */
      else if (strcmp (uuid, "0320e0db-bf30-4d4f-9379-b0a022d07cf7") == 0)
        setting_name = g_strdup ("Assets Dashboard Configuration");

      /* Hosts dashboard settings */
      else if (strcmp (uuid, "d3f5f2de-a85b-43f2-a817-b127457cc8ba") == 0)
        setting_name = g_strdup ("Hosts Top Dashboard Configuration");

      /* TLS Certificate dashboard settings */
      else if (strcmp (uuid, "9b62bf16-bf90-11e9-ad97-28d24461215b") == 0)
        setting_name = g_strdup ("TLS Certificates Top Dashboard Configuration");

      /* Operating Systems dashboard settings */
      else if (strcmp (uuid, "e93b51ed-5881-40e0-bc4f-7d3268a36177") == 0)
        setting_name = g_strdup ("OSs Top Dashboard Configuration");

      /*
       * SecInfo dashboards
       */
      else if (strcmp (uuid, "84ab32da-fe69-44d8-8a8f-70034cf28d4e") == 0)
        setting_name = g_strdup ("SecInfo Dashboard Configuration");

      /* NVTs dashboard settings */
      else if (strcmp (uuid, "f68d9369-1945-477b-968f-121c6029971b") == 0)
        setting_name = g_strdup ("NVTs Top Dashboard Configuration");

      /* CVEs dashboard settings */
      else if (strcmp (uuid, "815ddd2e-8654-46c7-a05b-d73224102240") == 0)
        setting_name = g_strdup ("CVEs Top Dashboard Configuration");

      /* CPEs dashboard settings */
      else if (strcmp (uuid, "9cff9b4d-b164-43ce-8687-f2360afc7500") == 0)
        setting_name = g_strdup ("CPEs Top Dashboard Configuration");

      /* CERT-Bund Advisories dashboard settings */
      else if (strcmp (uuid, "a6946f44-480f-4f37-8a73-28a4cd5310c4") == 0)
        setting_name = g_strdup ("CERT-Bund Advisories Top Dashboard"
                                 " Configuration");

      /* DFN-CERT Advisories */
      else if (strcmp (uuid, "9812ea49-682d-4f99-b3cc-eca051d1ce59") == 0)
        setting_name = g_strdup ("DFN-CERT Advisories Top Dashboard"
                                 " Configuration");

      /* All SecInfo */
      else if (strcmp (uuid, "4c7b1ea7-b7e6-4d12-9791-eb9f72b6f864") == 0)
        setting_name = g_strdup ("All SecInfo Top Dashboard Configuration");

      /*
       * Resilience / Remediation dashboards
       */

      /* Tickets */
      else if (strcmp (uuid, "70b0626f-a835-478e-8194-e09f97887a15") == 0)
        setting_name = g_strdup ("Tickets Top Dashboard Configuration");
    }

  if (setting_name)
    {
      gchar *value;
      gsize value_size;

      assert (current_credentials.username);

      if (value_64 && strlen (value_64))
        {
          value = (gchar *) g_base64_decode (value_64, &value_size);
          if (g_utf8_validate (value, value_size, NULL) == FALSE)
            {
              if (r_errdesc)
                *r_errdesc = g_strdup ("Value cannot be decoded to"
                                       " valid UTF-8");
              g_free (value);
              return MODIFY_SETTING_RESULT_ERROR;
            }
        }
      else
        {
          value = g_strdup ("");
          value_size = 0;
        }

      if (sql_int_ps ("SELECT count(*) FROM settings"
                      " WHERE uuid = $1"
                      " AND owner = (SELECT id FROM users WHERE uuid = $2);",
                      SQL_STR_PARAM (uuid),
                      SQL_STR_PARAM (current_credentials.uuid), NULL))
        sql_ps ("UPDATE settings SET value = $1"
                " WHERE uuid = $2"
                " AND owner = (SELECT id FROM users WHERE uuid = $3);",
                SQL_STR_PARAM (value), SQL_STR_PARAM (uuid),
                SQL_STR_PARAM (current_credentials.uuid), NULL);
      else
        sql_ps ("INSERT INTO settings (uuid, owner, name, comment, value)"
                " VALUES"
                " ($1,"
                "  (SELECT id FROM users WHERE uuid = $2),"
                "  $3,"
                "  (SELECT coalesce ((SELECT comment FROM settings"
                "                     WHERE uuid = $1"
                "                     AND " ACL_IS_GLOBAL () "),"
                "                    '')),"
                "  $4);",
                SQL_STR_PARAM (uuid), SQL_STR_PARAM (current_credentials.uuid),
                SQL_STR_PARAM (setting_name), SQL_STR_PARAM (value), NULL);

      g_free (value);
      return MODIFY_SETTING_RESULT_OK;
    }

  return MODIFY_SETTING_RESULT_NOT_FOUND;
}

/**
 * @brief Normalise the value of a setting.
 *
 * @param[in]  uuid   UUID of setting.
 * @param[in]  value  Value of setting, to verify.
 *
 * @return Normalised value.
 */
static gchar *
setting_normalise (const gchar *uuid, const gchar *value)
{
  if (value == NULL)
    return NULL;

  if (strcmp (uuid, SETTING_UUID_MAX_ROWS_PER_PAGE) == 0)
    {
      int max_rows;
      max_rows = atoi (value);
      if (max_rows < 0)
        return NULL;
      return g_strdup_printf ("%i", max_rows);
    }

  if (strcmp (uuid, SETTING_UUID_LSC_DEB_MAINTAINER) == 0)
    {
      return g_strstrip (g_strdup (value));
    }

  if (strcmp (uuid, SETTING_UUID_FEED_IMPORT_ROLES) == 0)
    {
      GString *normalised;
      gchar **split, **point;

      normalised = g_string_new ("");
      point = split = g_strsplit (value, ",", 0);

      while (*point)
        {
          g_string_append_printf (normalised,
                                  "%s%s",
                                  point == split ? "" : ",",
                                  g_strstrip (*point));
          point++;
        }

      g_strfreev (split);

      g_string_ascii_down (normalised);

      return g_string_free (normalised, FALSE);
    }

  if (strcmp (uuid, SETTING_UUID_SECINFO_SQL_BUFFER_THRESHOLD) == 0)
    {
      int threshold;
      threshold = atoi (value);
      if (threshold < 0)
        return NULL;
      return g_strdup_printf ("%i", threshold);
    }

  return g_strdup (value);
}

/**
 * @brief Verify the value of a setting.
 *
 * @param[in]  uuid   UUID of setting.
 * @param[in]  value  Value of setting, to verify.
 * @param[in]  user   User setting is to apply to, or NULL.
 *
 * @return 0 if valid, else 1.
 */
static int
setting_verify (const gchar *uuid, const gchar *value, const gchar *user)
{
  if (value == NULL)
    return 0;

  if (strcmp (uuid, SETTING_UUID_DEFAULT_CA_CERT) == 0)
    return 0;

  if (strcmp (uuid, SETTING_UUID_MAX_ROWS_PER_PAGE) == 0)
    {
      int max_rows;
      max_rows = atoi (value);
      if (user)
        {
          if (max_rows < -1)
            return 1;
        }
      else if (max_rows < 0)
        return 1;
    }

  if (strcmp (uuid, SETTING_UUID_LSC_DEB_MAINTAINER) == 0)
    {
      if (g_regex_match_simple
            ("^([[:alnum:]\\-_]*@[[:alnum:]\\-_][[:alnum:]\\-_.]*)?$",
            value, 0, 0) == FALSE)
        return 1;
    }

  if ((strcmp (uuid, SETTING_UUID_FEED_IMPORT_OWNER) == 0
     || (strcmp (uuid, SETTING_UUID_AGENT_OWNER) == 0 )
     || (strcmp (uuid, SETTING_UUID_INTEGRATION_CONFIG_OWNER) == 0 ))
    && strlen (value))
    {
      user_t value_user;
      gchar *quoted_uuid;

      quoted_uuid = sql_quote (value);
      switch (sql_int64 (&value_user,
                         "SELECT id FROM users WHERE uuid = '%s';",
                         quoted_uuid))
        {
          case 0:
            break;
          case 1:        /* Too few rows in result of query. */
            g_free (quoted_uuid);
            return 1;
          default:       /* Programming error. */
            assert (0);
          case -1:
            g_free (quoted_uuid);
            return 1;
        }
      g_free (quoted_uuid);
    }

  if (strcmp (uuid, SETTING_UUID_FEED_IMPORT_ROLES) == 0)
    {
      gchar **split, **point;

      point = split = g_strsplit (value, ",", 0);
      while (*point)
        {
          if (g_regex_match_simple ("^[-0123456789abcdefABCDEF]{36}$",
                                    g_strstrip (*point), 0, 0)
              == FALSE)
            {
              g_strfreev (split);
              return 1;
            }
          point++;
        }
      g_strfreev (split);
    }

  if (strcmp (uuid, SETTING_UUID_SECINFO_SQL_BUFFER_THRESHOLD) == 0)
    {
      int threshold;
      threshold = atoi (value);
      if (threshold < 0 || threshold > (INT_MAX / 1048576))
        return 1;
    }

  if (strcmp (uuid, SETTING_UUID_CVE_CPE_MATCHING_VERSION) == 0)
    {
      if (strcmp (value, "0") && strcmp (value, "1"))
        return 1;
    }

  return 0;
}

/**
 * @brief Get the description of a setting.
 *
 * @param[in]  uuid  UUID of setting.
 *
 * @return Setting description.
 */
static const gchar *
setting_description (const gchar *uuid)
{
  if (strcmp (uuid, SETTING_UUID_AGENT_OWNER) == 0)
    return "User who is given ownership of new Agents.";
  if (strcmp (uuid, SETTING_UUID_DEFAULT_CA_CERT) == 0)
    return "Default CA Certificate for Scanners";
  if (strcmp (uuid, SETTING_UUID_MAX_ROWS_PER_PAGE) == 0)
    return "The default maximum number of rows displayed in any listing.";
  if (strcmp (uuid, SETTING_UUID_LSC_DEB_MAINTAINER) == 0)
    return "Maintainer email address used in generated Debian LSC packages.";
  if (strcmp (uuid, SETTING_UUID_FEED_IMPORT_OWNER) == 0)
    return "User who is given ownership of new resources from feed.";
  if (strcmp (uuid, SETTING_UUID_FEED_IMPORT_ROLES) == 0)
    return "Roles given access to new resources from feed.";
  if (strcmp (uuid, SETTING_UUID_SECINFO_SQL_BUFFER_THRESHOLD) == 0)
    return "Buffer size threshold in MiB for running buffered SQL statements"
           " in SecInfo updates before the end of the file being processed.";
  if (strcmp (uuid, SETTING_UUID_CVE_CPE_MATCHING_VERSION) == 0)
    return "Version of the CVE-CPE matching used in CVE scans.";
  if (strcmp (uuid, SETTING_UUID_INTEGRATION_CONFIG_OWNER) == 0)
    return "User who is given ownership of integration configs.";

  return NULL;
}

/**
 * @brief Get the name of a setting.
 *
 * @param[in]  uuid  UUID of setting.
 *
 * @return Setting name.
 */
static const gchar *
setting_name (const gchar *uuid)
{
  if (strcmp (uuid, SETTING_UUID_AGENT_OWNER) == 0)
    return "Agent Owner";
  if (strcmp (uuid, SETTING_UUID_DEFAULT_CA_CERT) == 0)
    return "Default CA Cert";
  if (strcmp (uuid, SETTING_UUID_MAX_ROWS_PER_PAGE) == 0)
    return "Max Rows Per Page";
  if (strcmp (uuid, SETTING_UUID_LSC_DEB_MAINTAINER) == 0)
    return "Debian LSC Package Maintainer";
  if (strcmp (uuid, SETTING_UUID_FEED_IMPORT_OWNER) == 0)
    return "Feed Import Owner";
  if (strcmp (uuid, SETTING_UUID_FEED_IMPORT_ROLES) == 0)
    return "Feed Import Roles";
  if (strcmp (uuid, SETTING_UUID_SECINFO_SQL_BUFFER_THRESHOLD) == 0)
    return "SecInfo SQL Buffer Threshold";
  if (strcmp (uuid, SETTING_UUID_CVE_CPE_MATCHING_VERSION) == 0)
    return "CVE-CPE Matching Version";
  if (strcmp (uuid, SETTING_UUID_INTEGRATION_CONFIG_OWNER) == 0)
    return "Integration Configs Owner";

  return NULL;
}

/**
 * @brief Change value of a setting.
 *
 * @param[in]  log_config      Log configuration.
 * @param[in]  database        Location of manage database.
 * @param[in]  name            Name of user.
 * @param[in]  uuid            UUID of setting.
 * @param[in]  value           New value.
 *
 * @return 0 success, 1 failed to find user, 2 value out of range, 3 error in
 *         setting uuid, 4 modifying setting for a single user forbidden,
 *         5 syntax error in setting value, -1 error.
 */
int
manage_modify_setting (GSList *log_config, const db_conn_info_t *database,
                       const gchar *name, const gchar *uuid, const char *value)
{
  int ret;
  gchar *quoted_name, *quoted_description, *quoted_value, *normalised;

  g_info ("   Modifying setting.");

  if (strcmp (uuid, SETTING_UUID_AGENT_OWNER)
      && strcmp (uuid, SETTING_UUID_DEFAULT_CA_CERT)
      && strcmp (uuid, SETTING_UUID_MAX_ROWS_PER_PAGE)
      && strcmp (uuid, SETTING_UUID_LSC_DEB_MAINTAINER)
      && strcmp (uuid, SETTING_UUID_FEED_IMPORT_OWNER)
      && strcmp (uuid, SETTING_UUID_FEED_IMPORT_ROLES)
      && strcmp (uuid, SETTING_UUID_SECINFO_SQL_BUFFER_THRESHOLD)
      && strcmp (uuid, SETTING_UUID_CVE_CPE_MATCHING_VERSION)
      && strcmp (uuid, SETTING_UUID_INTEGRATION_CONFIG_OWNER))
    {
      fprintf (stderr, "Error in setting UUID.\n");
      return 3;
    }

  ret = manage_option_setup (log_config, database,
                             0 /* avoid_db_check_inserts */);
  if (ret)
    return ret;

  sql_begin_immediate ();

  if (setting_verify (uuid, value, name))
    {
      sql_rollback ();
      fprintf (stderr, "Syntax error in setting value.\n");
      manage_option_cleanup ();
      return 5;
    }

  if (name)
    {
      user_t user;

      if ((strcmp (uuid, SETTING_UUID_AGENT_OWNER) == 0)
          || (strcmp (uuid, SETTING_UUID_DEFAULT_CA_CERT) == 0)
          || (strcmp (uuid, SETTING_UUID_FEED_IMPORT_OWNER) == 0)
          || (strcmp (uuid, SETTING_UUID_FEED_IMPORT_ROLES) == 0)
          || (strcmp (uuid, SETTING_UUID_SECINFO_SQL_BUFFER_THRESHOLD) == 0)
          || (strcmp (uuid, SETTING_UUID_CVE_CPE_MATCHING_VERSION) == 0)
          || (strcmp (uuid, SETTING_UUID_INTEGRATION_CONFIG_OWNER) == 0))
        {
          sql_rollback ();
          fprintf (stderr,
                   "Modifying this setting for a single user is forbidden.\n");
          manage_option_cleanup ();
          return 4;
        }

      if (find_user_by_name (name, &user))
        {
          sql_rollback ();
          fprintf (stderr, "Internal error.\n");
          manage_option_cleanup ();
          return -1;
        }

      if (user == 0)
        {
          sql_rollback ();
          fprintf (stderr, "Failed to find user.\n");
          manage_option_cleanup ();
          return 1;
        }

      sql ("DELETE FROM settings"
           " WHERE uuid = '%s'"
           " AND owner = %llu;",
           uuid,
           user);

      normalised = setting_normalise (uuid, value);
      if (normalised)
        {
          quoted_value = sql_quote (normalised);
          g_free (normalised);
          quoted_name = sql_quote (setting_name (uuid));
          quoted_description = sql_quote (setting_description (uuid));
          sql ("INSERT INTO settings (uuid, owner, name, comment, value)"
               " VALUES ('%s', %llu, '%s', '%s', '%s');",
               uuid,
               user,
               quoted_name,
               quoted_description,
               quoted_value);
          g_free (quoted_value);
          g_free (quoted_name);
          g_free (quoted_description);
        }
    }
  else
    {
      sql ("DELETE FROM settings"
           " WHERE uuid = '%s'"
           " AND owner IS NULL;",
           uuid);

      normalised = setting_normalise (uuid, value);
      if (normalised)
        {
          quoted_value = sql_quote (normalised);
          g_free (normalised);
          quoted_name = sql_quote (setting_name (uuid));
          quoted_description = sql_quote (setting_description (uuid));
          sql ("INSERT INTO settings (uuid, owner, name, comment, value)"
               " VALUES ('%s', NULL, '%s', '%s', '%s');",
               uuid,
               quoted_name,
               quoted_description,
               quoted_value);
          g_free (quoted_value);
          g_free (quoted_name);
          g_free (quoted_description);

          if (strcmp (uuid, SETTING_UUID_FEED_IMPORT_OWNER) == 0)
            {
              migrate_predefined_configs ();
              migrate_predefined_port_lists ();
              if (migrate_predefined_report_formats ())
                {
                  sql_rollback ();
                  manage_option_cleanup ();
                  return -1;
                }
            }

          if (strcmp (uuid, SETTING_UUID_INTEGRATION_CONFIG_OWNER) == 0)
            {
              check_db_integration_configs ();
            }
        }
    }

  sql_commit ();
  manage_option_cleanup ();
  return 0;
}
