/* Copyright (C) 2019-2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "manage_sql_filters.h"
#include "manage.h"
#include "manage_acl.h"
#include "manage_filter_utils.h"
#include "manage_settings.h"
#include "manage_sql.h"

#include <ctype.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @file
 * @brief GVM management layer: Filters SQL
 *
 * The Filters SQL for the GVM management layer.
 */

/**
 * @brief Get info from a filter.
 *
 * It's up to the caller to ensure that max is adjusted for Max Rows Per Page
 * (by calling manage_max_rows).
 *
 * @param[in]   filter      Filter.
 * @param[out]  first       Number of first item.
 * @param[out]  max         Max number of rows.
 * @param[out]  sort_field  Sort field.
 * @param[out]  sort_order  Sort order.
 */
void
manage_filter_controls (const gchar *filter, int *first, int *max,
                        gchar **sort_field, int *sort_order)
{
  keyword_t **point;
  array_t *split;

  if (filter == NULL)
    {
      if (first)
        *first = 1;
      if (max)
        *max = -2;
      if (sort_field)
        *sort_field = g_strdup ("name");
      if (sort_order)
        *sort_order = 1;
      return;
    }

  split = split_filter (filter);
  point = (keyword_t**) split->pdata;
  if (first)
    {
      *first = 1;
      while (*point)
        {
          keyword_t *keyword;

          keyword = *point;
          if (keyword->column && (strcmp (keyword->column, "first") == 0))
            {
              *first = atoi (keyword->string);
              if (*first < 0)
                *first = 0;
              break;
            }
          point++;
        }
    }

  point = (keyword_t**) split->pdata;
  if (max)
    {
      *max = -2;
      while (*point)
        {
          keyword_t *keyword;

          keyword = *point;
          if (keyword->column && (strcmp (keyword->column, "rows") == 0))
            {
              *max = atoi (keyword->string);
              if (*max == -2)
                setting_value_int (SETTING_UUID_ROWS_PER_PAGE, max);
              else if (*max < 1)
                *max = -1;
              break;
            }
          point++;
        }
    }

  point = (keyword_t**) split->pdata;
  if (sort_field || sort_order)
    {
      if (sort_field) *sort_field = NULL;
      if (sort_order) *sort_order = 1;
      while (*point)
        {
          keyword_t *keyword;

          keyword = *point;
          if (keyword->column
              && (strcmp (keyword->column, "sort") == 0))
            {
              if (sort_field) *sort_field = g_strdup (keyword->string);
              if (sort_order) *sort_order = 1;
              break;
            }
          if (keyword->column
              && (strcmp (keyword->column, "sort-reverse") == 0))
            {
              if (sort_field) *sort_field = g_strdup (keyword->string);
              if (sort_order) *sort_order = 0;
              break;
            }
          point++;
        }
      if (sort_field && (*sort_field == NULL))
        *sort_field = g_strdup ("name");
    }

  filter_free (split);
  return;
}

/**
 * @brief Get an int column from a filter split.
 *
 * @param[in]  point   Filter split.
 * @param[in]  column  Name of column.
 * @param[out] val     Value of column.
 *
 * @return 0 success, 1 fail.
 */
static int
filter_control_int (keyword_t **point, const char *column, int *val)
{
  if (val)
    while (*point)
      {
        keyword_t *keyword;

        keyword = *point;
        if (keyword->column
            && (strcmp (keyword->column, column) == 0))
          {
            *val = atoi (keyword->string);
            return 0;
          }
        point++;
      }
  return 1;
}

/**
 * @brief Get a string column from a filter split.
 *
 * @param[in]  point   Filter split.
 * @param[in]  column  Name of column.
 * @param[out] string  Value of column, freshly allocated.
 *
 * @return 0 success, 1 fail.
 */
static int
filter_control_str (keyword_t **point, const char *column, gchar **string)
{
  if (string)
    while (*point)
      {
        keyword_t *keyword;

        keyword = *point;
        if (keyword->column
            && (strcmp (keyword->column, column) == 0))
          {
            *string = g_strdup (keyword->string);
            return 0;
          }
        point++;
      }
  return 1;
}

/**
 * @brief Get info from a result filter for a report.
 *
 * It's up to the caller to ensure that max is adjusted for Max Rows Per Page
 * (by calling manage_max_rows).
 *
 * @param[in]   filter      Filter.
 * @param[out]  first       Number of first item.
 * @param[out]  max         Max number of rows.
 * @param[out]  sort_field  Sort field.
 * @param[out]  sort_order  Sort order.
 * @param[out]  result_hosts_only  Whether to show only hosts with results.
 * @param[out]  min_qod        Minimum QoD base of included results.  All
 *                              results if NULL.
 * @param[out]  levels         String describing threat levels (message types)
 *                             to include in count (for example, "hmlg" for
 *                             High, Medium, Low and loG). All levels if NULL.
 * @param[out]  compliance_levels   String describing compliance levels
 *                             to include in count (for example, "yniu" for
 *                             "yes" (compliant), "n" for "no" (not compliant),
 *                             "i" for "incomplete" and "u" for "undefined"
 *                              (without compliance information).
 *                              All levels if NULL.
 * @param[out]  delta_states   String describing delta states to include in count
 *                             (for example, "sngc" Same, New, Gone and Changed).
 *                             All levels if NULL.
 * @param[out]  search_phrase      Phrase that results must include.  All results
 *                                 if NULL or "".
 * @param[out]  search_phrase_exact  Whether search phrase is exact.
 * @param[out]  notes              Whether to include notes.
 * @param[out]  overrides          Whether to include overrides.
 * @param[out]  apply_overrides    Whether to apply overrides.
 * @param[out]  zone               Timezone.
 */
void
manage_report_filter_controls (const gchar *filter, int *first, int *max,
                               gchar **sort_field, int *sort_order,
                               int *result_hosts_only, gchar **min_qod,
                               gchar **levels, gchar **compliance_levels,
                               gchar **delta_states, gchar **search_phrase,
                               int *search_phrase_exact, int *notes,
                               int *overrides, int *apply_overrides,
                               gchar **zone)
{
  keyword_t **point;
  array_t *split;
  int val;
  gchar *string;

  if (filter == NULL)
    return;

  split = split_filter (filter);

  point = (keyword_t**) split->pdata;
  if (first)
    {
      *first = 1;
      while (*point)
        {
          keyword_t *keyword;

          keyword = *point;
          if (keyword->column && (strcmp (keyword->column, "first") == 0))
            {
              *first = atoi (keyword->string);
              if (*first < 0)
                *first = 0;
              break;
            }
          point++;
        }
      /* Switch from 1 to 0 indexing. */

      (*first)--;
    }

  point = (keyword_t**) split->pdata;
  if (max)
    {
      *max = 100;
      while (*point)
        {
          keyword_t *keyword;

          keyword = *point;
          if (keyword->column && (strcmp (keyword->column, "rows") == 0))
            {
              *max = atoi (keyword->string);
              if (*max == -2)
                setting_value_int (SETTING_UUID_ROWS_PER_PAGE, max);
              else if (*max < 1)
                *max = -1;
              break;
            }
          point++;
        }
    }

  point = (keyword_t**) split->pdata;
  if (sort_field || sort_order)
    {
      if (sort_field) *sort_field = NULL;
      if (sort_order) *sort_order = 1;
      while (*point)
        {
          keyword_t *keyword;

          keyword = *point;
          if (keyword->column
              && (strcmp (keyword->column, "sort") == 0))
            {
              if (sort_field) *sort_field = g_strdup (keyword->string);
              if (sort_order) *sort_order = 1;
              break;
            }
          if (keyword->column
              && (strcmp (keyword->column, "sort-reverse") == 0))
            {
              if (sort_field) *sort_field = g_strdup (keyword->string);
              if (sort_order) *sort_order = 0;
              break;
            }
          point++;
        }
      if (sort_field && (*sort_field == NULL))
        *sort_field = g_strdup ("name"); /* NVT name. */
    }

  if (search_phrase)
    {
      GString *phrase;
      phrase = g_string_new ("");
      point = (keyword_t**) split->pdata;
      if (search_phrase_exact)
        *search_phrase_exact = 0;
      while (*point)
        {
          keyword_t *keyword;

          keyword = *point;
          if (keyword->column == NULL)
            {
              if (search_phrase_exact && keyword->equal)
                /* If one term is "exact" then the search is "exact", because
                 * for reports the filter terms are combined into a single
                 * search term. */
                *search_phrase_exact = 1;
              g_string_append_printf (phrase, "%s ", keyword->string);
            }
          point++;
        }
      *search_phrase = g_strchomp (g_string_free (phrase, FALSE));
    }

  if (result_hosts_only)
    {
      if (filter_control_int ((keyword_t **) split->pdata,
                              "result_hosts_only",
                              &val))
        *result_hosts_only = 1;
      else
        *result_hosts_only = val;
    }

  if (notes)
    {
      if (filter_control_int ((keyword_t **) split->pdata,
                              "notes",
                              &val))
        *notes = 1;
      else
        *notes = val;
    }

  if (overrides)
    {
      if (filter_control_int ((keyword_t **) split->pdata,
                              "overrides",
                              &val))
        *overrides = 1;
      else
        *overrides = val;
    }

  if (apply_overrides)
    {
      if (filter_control_int ((keyword_t **) split->pdata,
                              "apply_overrides",
                              &val))
        {
          if (filter_control_int ((keyword_t **) split->pdata,
                                  "overrides",
                                  &val))
            *apply_overrides = 1;
          else
            *apply_overrides = val;
        }
      else
        *apply_overrides = val;
    }

  if (compliance_levels)
    {
      if (filter_control_str ((keyword_t **) split->pdata,
                              "compliance_levels",
                              &string))
        *compliance_levels = NULL;
      else
        *compliance_levels = string;
    }

  if (delta_states)
    {
      if (filter_control_str ((keyword_t **) split->pdata,
                              "delta_states",
                              &string))
        *delta_states = NULL;
      else
        *delta_states = string;
    }

  if (levels)
    {
      if (filter_control_str ((keyword_t **) split->pdata,
                              "levels",
                              &string))
        *levels = NULL;
      else
        *levels = string;
    }

  if (min_qod)
    {
      if (filter_control_str ((keyword_t **) split->pdata,
                              "min_qod",
                              &string))
        *min_qod = NULL;
      else
        *min_qod = string;
    }

  if (zone)
    {
      if (filter_control_str ((keyword_t **) split->pdata,
                              "timezone",
                              &string))
        *zone = NULL;
      else
        *zone = string;
    }

  filter_free (split);
  return;
}

/**
 * @brief Append relation to filter.
 *
 * @param[in]  clean     Filter.
 * @param[in]  keyword   Keyword
 * @param[in]  relation  Relation char.
 * @param[in]  ignore_max_rows_per_page  Whether to ignore "Max Rows Per Page"
 */
static void
append_relation (GString *clean, keyword_t *keyword, const char relation,
                 int ignore_max_rows_per_page)
{
  if (strcmp (keyword->column, "rows") == 0)
    {
      int max;

      if (strcmp (keyword->string, "-2") == 0)
        setting_value_int (SETTING_UUID_ROWS_PER_PAGE, &max);
      else
        max = atoi (keyword->string);

      g_string_append_printf (clean,
                              " %s%c%i",
                              keyword->column,
                              relation,
                              manage_max_rows (max, ignore_max_rows_per_page));
    }
  else if (keyword->quoted)
    g_string_append_printf (clean,
                            " %s%c\"%s\"",
                            keyword->column,
                            relation,
                            keyword->string);
  else
    g_string_append_printf (clean,
                            " %s%c%s",
                            keyword->column,
                            relation,
                            keyword->string);
}

/**
 * @brief Clean a filter, removing a keyword in the process.
 *
 * @param[in]  filter  Filter.
 * @param[in]  column  Keyword to remove, or NULL.
 * @param[in]  ignore_max_rows_per_page  Whether to ignore "Max Rows Per Page"
 *
 * @return Cleaned filter.
 */
gchar *
manage_clean_filter_remove (const gchar *filter, const gchar *column,
                            int ignore_max_rows_per_page)
{
  GString *clean;
  keyword_t **point;
  array_t *split;

  if (filter == NULL)
    return g_strdup ("");

  clean = g_string_new ("");
  split = split_filter (filter);
  point = (keyword_t**) split->pdata;
  while (*point)
    {
      keyword_t *keyword;

      keyword = *point;
      if (keyword->column
          && column
          && strlen (column)
          && ((strcasecmp (keyword->column, column) == 0)
              || (keyword->column[0] == '_'
                  && strcasecmp (keyword->column + 1, column) == 0)))
        {
          /* Remove this keyword. */;
        }
      else if (keyword->column)
        switch (keyword->relation)
          {
            case KEYWORD_RELATION_COLUMN_EQUAL:
              append_relation (clean, keyword, '=', ignore_max_rows_per_page);
              break;
            case KEYWORD_RELATION_COLUMN_APPROX:
              append_relation (clean, keyword, '~', ignore_max_rows_per_page);
              break;
            case KEYWORD_RELATION_COLUMN_ABOVE:
              append_relation (clean, keyword, '>', ignore_max_rows_per_page);
              break;
            case KEYWORD_RELATION_COLUMN_BELOW:
              append_relation (clean, keyword, '<', ignore_max_rows_per_page);
              break;
            case KEYWORD_RELATION_COLUMN_REGEXP:
              append_relation (clean, keyword, ':', ignore_max_rows_per_page);
              break;

            case KEYWORD_RELATION_APPROX:
              if (keyword->quoted)
                g_string_append_printf (clean, " \"%s\"", keyword->string);
              else
                g_string_append_printf (clean, " %s", keyword->string);
              break;
          }
      else
        {
          const char *relation_symbol;
          if (keyword->equal)
            relation_symbol = "=";
          else if (keyword->approx)
            relation_symbol = "~";
          else
            relation_symbol = "";

          if (keyword->quoted)
            g_string_append_printf (clean, " %s\"%s\"",
                                    relation_symbol,
                                    keyword->string);
          else
            g_string_append_printf (clean, " %s%s",
                                    relation_symbol,
                                    keyword->string);
        }
      point++;
    }
  filter_free (split);
  return g_strstrip (g_string_free (clean, FALSE));
}

/**
 * @brief Clean a filter.
 *
 * @param[in]  filter  Filter.
 * @param[in]  ignore_max_rows_per_page  Whether to ignore "Max Rows Per Page"
 *
 * @return Cleaned filter.
 */
gchar *
manage_clean_filter (const gchar *filter, int ignore_max_rows_per_page)
{
  return manage_clean_filter_remove (filter, NULL, ignore_max_rows_per_page);
}

/**
 * @brief Return SQL join words for filter_clause.
 *
 * @param[in]  first         Whether keyword is first.
 * @param[in]  last_was_and  Whether last keyword was "and".
 * @param[in]  last_was_not  Whether last keyword was "not".
 *
 * @return SQL join words.
 */
const char *
get_join (int first, int last_was_and, int last_was_not)
{
  const char *pre;
  if (first)
    {
      if (last_was_not)
        pre = "NOT ";
      else
        pre = "";
    }
  else
    {
      if (last_was_and)
        {
          if (last_was_not)
            pre = " AND NOT ";
          else
            pre = " AND ";
        }
      else
        {
          if (last_was_not)
            pre = " OR NOT ";
          else
            pre = " OR ";
        }
    }
  return pre;
}

/**
 * @brief Return column list for SELECT statement.
 *
 * @param[in]  select_columns  SELECT columns.
 *
 * @return Column list for the SELECT statement.
 */
gchar *
columns_build_select (column_t *select_columns)
{
  if (select_columns == NULL)
    return g_strdup ("''");

  if ((*select_columns).select)
    {
      column_t *columns;
      GString *select;

      columns = select_columns;
      select = g_string_new ("");
      g_string_append (select, (*columns).select);
      if ((*columns).filter)
        g_string_append_printf (select, " AS %s", (*columns).filter);
      columns++;
      while ((*columns).select)
       {
         g_string_append_printf (select, ", %s", (*columns).select);
         if ((*columns).filter)
           g_string_append_printf (select, " AS %s", (*columns).filter);
         columns++;
       }
      return g_string_free (select, FALSE);
    }
  return g_strdup ("''");
}

/**
 * @brief Get the column expression for a filter column.
 *
 * @param[in]  select_columns  SELECT columns.
 * @param[in]  filter_column   Filter column.
 * @param[out] type            Type of returned column.
 *
 * @return Column for the SELECT statement.
 */
static gchar *
columns_select_column_single (column_t *select_columns,
                              const char *filter_column,
                              keyword_type_t* type)
{
  column_t *columns;
  if (type)
    *type = KEYWORD_TYPE_UNKNOWN;
  if (select_columns == NULL)
    return NULL;
  columns = select_columns;
  while ((*columns).select)
    {
      if ((*columns).filter
          && strcmp ((*columns).filter, filter_column) == 0)
        {
          if (type)
            *type = (*columns).type;
          return (*columns).select;
        }
      if ((*columns).filter
          && *((*columns).filter)
          && *((*columns).filter) == '_'
          && strcmp (((*columns).filter) + 1, filter_column) == 0)
        {
          if (type)
            *type = (*columns).type;
          return (*columns).select;
        }
      columns++;
    }
  columns = select_columns;
  while ((*columns).select)
    {
      if (strcmp ((*columns).select, filter_column) == 0)
        {
          if (type)
            *type = (*columns).type;
          return (*columns).select;
        }
      columns++;
    }
  return NULL;
}

/**
 * @brief Get the selection term for a filter column.
 *
 * @param[in]  select_columns  SELECT columns.
 * @param[in]  where_columns   WHERE "columns".
 * @param[in]  filter_column   Filter column.
 *
 * @return Column for the SELECT statement.
 */
gchar *
columns_select_column (column_t *select_columns,
                       column_t *where_columns,
                       const char *filter_column)
{
  gchar *column;
  column = columns_select_column_single (select_columns, filter_column, NULL);
  if (column)
    return column;
  return columns_select_column_single (where_columns, filter_column, NULL);
}

/**
 * @brief Get the selection term for a filter column.
 *
 * @param[in]  select_columns  SELECT columns.
 * @param[in]  where_columns   WHERE "columns".
 * @param[in]  filter_column   Filter column.
 * @param[out] type            Type of the returned column.
 *
 * @return Column for the SELECT statement.
 */
static gchar *
columns_select_column_with_type (column_t *select_columns,
                                 column_t *where_columns,
                                 const char *filter_column,
                                 keyword_type_t* type)
{
  gchar *column;
  column = columns_select_column_single (select_columns, filter_column, type);
  if (column)
    return column;
  return columns_select_column_single (where_columns, filter_column, type);
}

/**
 * @brief Check whether a keyword applies to a column.
 *
 * @param[in]  keyword  Keyword.
 * @param[in]  column   Column.
 *
 * @return 1 if applies, else 0.
 */
static int
keyword_applies_to_column (keyword_t *keyword, const char* column)
{
  if ((strcmp (column, "threat") == 0)
      && (strstr ("None", keyword->string) == NULL)
      && (strstr ("False Positive", keyword->string) == NULL)
      && (strstr ("Error", keyword->string) == NULL)
      && (strstr ("Alarm", keyword->string) == NULL)
#if CVSS3_RATINGS == 1
      && (strstr ("Critical", keyword->string) == NULL)
#endif
      && (strstr ("High", keyword->string) == NULL)
      && (strstr ("Medium", keyword->string) == NULL)
      && (strstr ("Low", keyword->string) == NULL)
      && (strstr ("Log", keyword->string) == NULL))
    return 0;
  if ((strcmp (column, "trend") == 0)
      && (strstr ("more", keyword->string) == NULL)
      && (strstr ("less", keyword->string) == NULL)
      && (strstr ("up", keyword->string) == NULL)
      && (strstr ("down", keyword->string) == NULL)
      && (strstr ("same", keyword->string) == NULL))
    return 0;
  if ((strcmp (column, "status") == 0)
      && (strstr ("Delete Requested", keyword->string) == NULL)
      && (strstr ("Ultimate Delete Requested", keyword->string) == NULL)
      && (strstr ("Done", keyword->string) == NULL)
      && (strstr ("New", keyword->string) == NULL)
      && (strstr ("Running", keyword->string) == NULL)
      && (strstr ("Queued", keyword->string) == NULL)
      && (strstr ("Stop Requested", keyword->string) == NULL)
      && (strstr ("Stopped", keyword->string) == NULL)
      && (strstr ("Interrupted", keyword->string) == NULL)
      && (strstr ("Processing", keyword->string) == NULL))
    return 0;
  return 1;
}

/**
 * @brief Append parts for a "tag" keyword to a filter clause.
 *
 * @param[in,out] clause      Buffer for the filter clause to append to.
 * @param[in]  keyword        The keyword to create the filter clause part for.
 * @param[in]  type           The resource type.
 * @param[in]  first_keyword  Whether keyword is first.
 * @param[in]  last_was_and   Whether last keyword was "and".
 * @param[in]  last_was_not   Whether last keyword was "not".
 */
static void
filter_clause_append_tag (GString *clause, keyword_t *keyword,
                          const char *type, int first_keyword,
                          int last_was_and, int last_was_not)
{
  gchar *quoted_keyword;
  gchar **tag_split, *tag_name, *tag_value;
  int value_given;

  quoted_keyword = sql_quote (keyword->string);
  tag_split = g_strsplit (quoted_keyword, "=", 2);
  tag_name = g_strdup (tag_split[0] ? tag_split[0] : "");

  if (tag_split[0] && tag_split[1])
    {
      tag_value = g_strdup (tag_split[1]);
      value_given = 1;
    }
  else
    {
      tag_value = g_strdup ("");
      value_given = 0;
    }

  if (keyword->relation == KEYWORD_RELATION_COLUMN_EQUAL
      || keyword->relation == KEYWORD_RELATION_COLUMN_ABOVE
      || keyword->relation == KEYWORD_RELATION_COLUMN_BELOW)
    {
      g_string_append_printf
         (clause,
          "%s"
          "(EXISTS"
          "  (SELECT * FROM tags"
          "   WHERE tags.name = '%s'"
          "   AND tags.active != 0"
          "   AND user_has_access_uuid (CAST ('tag' AS text),"
          "                             CAST (tags.uuid AS text),"
          "                             CAST ('get_tags' AS text),"
          "                             0)"
          "   AND EXISTS (SELECT * FROM tag_resources"
          "                WHERE tag_resources.resource_uuid"
          "                        = %ss.uuid"
          "                  AND tag_resources.resource_type"
          "                        = '%s'"
          "                  AND tag = tags.id)"
          "   %s%s%s))",
          get_join (first_keyword, last_was_and,
                    last_was_not),
          tag_name,
          type,
          type,
          (value_given
            ? "AND tags.value = '"
            : ""),
          value_given ? tag_value : "",
          (value_given
            ? "'"
            : ""));
    }
  else if (keyword->relation == KEYWORD_RELATION_COLUMN_APPROX)
    {
      g_string_append_printf
         (clause,
          "%s"
          "(EXISTS"
          "  (SELECT * FROM tags"
          "   WHERE tags.name %s '%%%%%s%%%%'"
          "   AND tags.active != 0"
          "   AND user_has_access_uuid (CAST ('tag' AS text),"
          "                             CAST (tags.uuid AS text),"
          "                             CAST ('get_tags' AS text),"
          "                             0)"
          "   AND EXISTS (SELECT * FROM tag_resources"
          "                WHERE tag_resources.resource_uuid"
          "                        = %ss.uuid"
          "                  AND tag_resources.resource_type"
          "                        = '%s'"
          "                  AND tag = tags.id)"
          "   AND tags.value %s '%%%%%s%%%%'))",
          get_join (first_keyword, last_was_and,
                    last_was_not),
          sql_ilike_op (),
          tag_name,
          type,
          type,
          sql_ilike_op (),
          tag_value);
    }
  else if (keyword->relation == KEYWORD_RELATION_COLUMN_REGEXP)
    {
      g_string_append_printf
         (clause,
          "%s"
          "(EXISTS"
          "  (SELECT * FROM tags"
          "   WHERE tags.name %s '%s'"
          "   AND tags.active != 0"
          "   AND user_has_access_uuid (CAST ('tag' AS text),"
          "                             CAST (tags.uuid AS text),"
          "                             CAST ('get_tags' AS text),"
          "                             0)"
          "   AND EXISTS (SELECT * FROM tag_resources"
          "                WHERE tag_resources.resource_uuid"
          "                        = %ss.uuid"
          "                  AND tag_resources.resource_type"
          "                        = '%s'"
          "                  AND tag = tags.id)"
          "   AND tags.value"
          "       %s '%s'))",
          get_join (first_keyword, last_was_and,
                    last_was_not),
          sql_regexp_op (),
          tag_name,
          type,
          type,
          sql_regexp_op (),
          tag_value);
    }

  g_free (quoted_keyword);
  g_strfreev(tag_split);
  g_free(tag_name);
  g_free(tag_value);
}

/**
 * @brief Append parts for a "tag_id" keyword to a filter clause.
 *
 * @param[in,out] clause      Buffer for the filter clause to append to.
 * @param[in]  keyword        The keyword to create the filter clause part for.
 * @param[in]  type           The resource type.
 * @param[in]  first_keyword  Whether keyword is first.
 * @param[in]  last_was_and   Whether last keyword was "and".
 * @param[in]  last_was_not   Whether last keyword was "not".
 */
static void
filter_clause_append_tag_id (GString *clause, keyword_t *keyword,
                             const char *type, int first_keyword,
                             int last_was_and, int last_was_not)
{
  gchar *quoted_keyword;

  quoted_keyword = sql_quote (keyword->string);

  if (keyword->relation == KEYWORD_RELATION_COLUMN_EQUAL
      || keyword->relation == KEYWORD_RELATION_COLUMN_ABOVE
      || keyword->relation == KEYWORD_RELATION_COLUMN_BELOW)
    {
      g_string_append_printf
         (clause,
          "%s"
          "(EXISTS"
          "  (SELECT * FROM tags"
          "   WHERE tags.uuid = '%s'"
          "   AND user_has_access_uuid (CAST ('tag' AS text),"
          "                             CAST (tags.uuid AS text),"
          "                             CAST ('get_tags' AS text),"
          "                             0)"
          "   AND EXISTS (SELECT * FROM tag_resources"
          "                WHERE tag_resources.resource_uuid"
          "                        = %ss.uuid"
          "                  AND tag_resources.resource_type"
          "                        = '%s'"
          "                  AND tag = tags.id)))",
          get_join (first_keyword, last_was_and,
                    last_was_not),
          quoted_keyword,
          type,
          type);
    }
  else if (keyword->relation == KEYWORD_RELATION_COLUMN_APPROX)
    {
      g_string_append_printf
         (clause,
          "%s"
          "(EXISTS"
          "  (SELECT * FROM tags"
          "   WHERE tags.uuid %s '%%%%%s%%%%'"
          "   AND tags.active != 0"
          "   AND user_has_access_uuid (CAST ('tag' AS text),"
          "                             CAST (tags.uuid AS text),"
          "                             CAST ('get_tags' AS text),"
          "                             0)"
          "   AND EXISTS (SELECT * FROM tag_resources"
          "                WHERE tag_resources.resource_uuid"
          "                        = %ss.uuid"
          "                  AND tag_resources.resource_type"
          "                        = '%s'"
          "                  AND tag = tags.id)))",
          get_join (first_keyword, last_was_and,
                    last_was_not),
          sql_ilike_op (),
          quoted_keyword,
          type,
          type);
    }
  else if (keyword->relation == KEYWORD_RELATION_COLUMN_REGEXP)
    {
      g_string_append_printf
         (clause,
          "%s"
          "(EXISTS"
          "  (SELECT * FROM tags"
          "   WHERE tags.uuid %s '%s'"
          "   AND tags.active != 0"
          "   AND user_has_access_uuid (CAST ('tag' AS text),"
          "                             CAST (tags.uuid AS text),"
          "                             CAST ('get_tags' AS text),"
          "                             0)"
          "   AND EXISTS (SELECT * FROM tag_resources"
          "                WHERE tag_resources.resource_uuid"
          "                        = %ss.uuid"
          "                  AND tag_resources.resource_type"
          "                        = '%s'"
          "                  AND tag = tags.id)))",
          get_join (first_keyword, last_was_and,
                    last_was_not),
          sql_regexp_op (),
          quoted_keyword,
          type,
          type);
    }

  g_free (quoted_keyword);
}

/**
 * @brief Return SQL WHERE clause for restricting a SELECT to a filter term.
 *
 * @param[in]  type     Resource type.
 * @param[in]  filter   Filter term.
 * @param[in]  filter_columns  Filter columns.
 * @param[in]  select_columns  SELECT columns.
 * @param[in]  where_columns   Columns in SQL that only appear in WHERE clause.
 * @param[in]  trash           Whether the trash table is being queried.
 * @param[in]  ignore_max_rows_per_page Whether to ignore "Max Rows Per Page".
 * @param[out] order_return  If given then order clause.
 * @param[out] first_return  If given then first row.
 * @param[out] max_return    If given then max rows.
 * @param[out] permissions   When given then permissions string vector.
 * @param[out] owner_filter  When given then value of owner keyword.
 *
 * @return WHERE clause for filter if one is required, else NULL.
 */
gchar *
filter_clause (const char* type, const char* filter,
               const char **filter_columns, column_t *select_columns,
               column_t *where_columns, int trash,
               int ignore_max_rows_per_page,
               gchar **order_return, int *first_return, int *max_return,
               array_t **permissions, gchar **owner_filter)
{
  GString *clause, *order;
  keyword_t **point;
  int first_keyword, first_order, last_was_and, last_was_not, last_was_re, skip;
  array_t *split;

  if (filter == NULL)
    filter = "";

  while (*filter && isspace (*filter)) filter++;

  if (permissions)
    *permissions = make_array ();

  if (owner_filter)
    *owner_filter = NULL;

  /* Add SQL to the clause for each keyword or phrase. */

  if (max_return)
    *max_return = -2;

  clause = g_string_new ("");
  order = g_string_new ("");
  /* NB This may add terms that are missing, like "sort". */
  split = split_filter (filter);
  point = (keyword_t**) split->pdata;
  first_keyword = 1;
  last_was_and = 0;
  last_was_not = 0;
  last_was_re = 0;
  first_order = 1;
  while (*point)
    {
      gchar *quoted_keyword;
      int index;
      keyword_t *keyword;

      skip = 0;

      keyword = *point;

      if ((keyword->column == NULL)
          && (strlen (keyword->string) == 0))
        {
          point++;
          continue;
        }

      if ((keyword->column == NULL)
          && (strcasecmp (keyword->string, "or") == 0))
        {
          point++;
          continue;
        }

      if ((keyword->column == NULL)
          && (strcasecmp (keyword->string, "and") == 0))
        {
          last_was_and = 1;
          point++;
          continue;
        }

      if ((keyword->column == NULL)
          && (strcasecmp (keyword->string, "not") == 0))
        {
          last_was_not = 1;
          point++;
          continue;
        }

      if ((keyword->column == NULL)
          && (strcasecmp (keyword->string, "re") == 0))
        {
          last_was_re = 1;
          point++;
          continue;
        }

      if ((keyword->column == NULL)
          && (strcasecmp (keyword->string, "regexp") == 0))
        {
          last_was_re = 1;
          point++;
          continue;
        }

      /* Check for ordering parts, like sort=name or sort-reverse=string. */

      if (keyword->column && (strcasecmp (keyword->column, "sort") == 0))
        {
          if (vector_find_filter (filter_columns, keyword->string) == 0)
            {
              point++;
              continue;
            }

          if (first_order)
            {
              if ((strcmp (type, "report") == 0)
                  && (strcmp (keyword->string, "status") == 0))
                g_string_append_printf
                 (order,
                  " ORDER BY"
                  "  (CASE WHEN (SELECT target = 0 FROM tasks"
                  "              WHERE tasks.id = task)"
                  "    THEN 'Container'"
                  "    ELSE run_status_name (scan_run_status)"
                  "         || (SELECT CAST (temp / 100 AS text)"
                  "                    || CAST (temp / 10 AS text)"
                  "                    || CAST (temp %% 10 as text)"
                  "             FROM (SELECT report_progress (id) AS temp)"
                  "                  AS temp_sub)"
                  "    END)"
                  " ASC");
              else if ((strcmp (type, "task") == 0)
                       && (strcmp (keyword->string, "status") == 0))
                g_string_append_printf
                 (order,
                  " ORDER BY"
                  "  (CASE WHEN target = 0"
                  "    THEN 'Container'"
                  "    ELSE run_status_name (run_status)"
                  "         || (SELECT CAST (temp / 100 AS text)"
                  "                    || CAST (temp / 10 AS text)"
                  "                    || CAST (temp %% 10 as text)"
                  "             FROM (SELECT report_progress (id) AS temp"
                  "                   FROM reports"
                  "                   WHERE task = tasks.id"
                  "                   ORDER BY creation_time DESC LIMIT 1)"
                  "                  AS temp_sub)"
                  "    END)"
                  " ASC");
              else if ((strcmp (type, "task") == 0)
                       && (strcmp (keyword->string, "threat") == 0))
                {
                  gchar *column;
                  column = columns_select_column (select_columns,
                                                  where_columns,
                                                  keyword->string);
                  assert (column);
                  g_string_append_printf (order,
                                          " ORDER BY order_threat (%s) ASC",
                                          column);
                }
              else if (strcmp (keyword->string, "severity") == 0
                       || strcmp (keyword->string, "original_severity") == 0
                       || strcmp (keyword->string, "cvss") == 0
                       || strcmp (keyword->string, "cvss_base") == 0
                       || strcmp (keyword->string, "max_cvss") == 0
                       || strcmp (keyword->string, "fp_per_host") == 0
                       || strcmp (keyword->string, "log_per_host") == 0
                       || strcmp (keyword->string, "low_per_host") == 0
                       || strcmp (keyword->string, "medium_per_host") == 0
                       || strcmp (keyword->string, "high_per_host") == 0
#if CVSS3_RATINGS == 1
                       || strcmp (keyword->string, "critical_per_host") == 0
#endif
                       )
                {
                  gchar *column;
                  column = columns_select_column (select_columns,
                                                  where_columns,
                                                  keyword->string);
                  g_string_append_printf (order,
                                          " ORDER BY CASE CAST (%s AS text)"
                                          " WHEN '' THEN '-Infinity'::real"
                                          " ELSE coalesce(%s::real,"
                                          "               '-Infinity'::real)"
                                          " END ASC",
                                          column,
                                          column);
                }
              else if (strcmp (keyword->string, "roles") == 0)
                {
                  gchar *column;
                  column = columns_select_column (select_columns,
                                                  where_columns,
                                                  keyword->string);
                  assert (column);
                  g_string_append_printf (order,
                                          " ORDER BY"
                                          " CASE WHEN %s %s 'Admin.*'"
                                          " THEN '0' || %s"
                                          " ELSE '1' || %s END ASC",
                                          column,
                                          sql_regexp_op (),
                                          column,
                                          column);
                }
              else if ((strcmp (keyword->string, "created") == 0)
                       || (strcmp (keyword->string, "modified") == 0)
                       || (strcmp (keyword->string, "published") == 0)
                       || (strcmp (keyword->string, "qod") == 0)
                       || (strcmp (keyword->string, "cves") == 0)
#if CVSS3_RATINGS == 1
                       || (strcmp (keyword->string, "critical") == 0)
#endif
                       || (strcmp (keyword->string, "high") == 0)
                       || (strcmp (keyword->string, "medium") == 0)
                       || (strcmp (keyword->string, "low") == 0)
                       || (strcmp (keyword->string, "log") == 0)
                       || (strcmp (keyword->string, "false_positive") == 0)
                       || (strcmp (keyword->string, "hosts") == 0)
                       || (strcmp (keyword->string, "result_hosts") == 0)
                       || (strcmp (keyword->string, "results") == 0)
                       || (strcmp (keyword->string, "latest_severity") == 0)
                       || (strcmp (keyword->string, "highest_severity") == 0)
                       || (strcmp (keyword->string, "average_severity") == 0))
                {
                  gchar *column;
                  column = columns_select_column (select_columns,
                                                  where_columns,
                                                  keyword->string);
                  assert (column);
                  g_string_append_printf (order,
                                          " ORDER BY %s ASC",
                                          column);
                }
              else if ((strcmp (keyword->string, "ips") == 0)
                       || (strcmp (keyword->string, "total") == 0)
                       || (strcmp (keyword->string, "tcp") == 0)
                       || (strcmp (keyword->string, "udp") == 0))
                {
                  gchar *column;
                  column = columns_select_column (select_columns,
                                                  where_columns,
                                                  keyword->string);
                  assert (column);
                  g_string_append_printf (order,
                                          " ORDER BY CAST (%s AS INTEGER) ASC",
                                          column);
                }
              else if (strcmp (keyword->string, "ip") == 0
                       || strcmp (keyword->string, "host") == 0)
                {
                  gchar *column;
                  column = columns_select_column (select_columns,
                                                  where_columns,
                                                  keyword->string);
                  assert (column);
                  g_string_append_printf (order,
                                          " ORDER BY order_inet (%s) ASC",
                                          column);
                }
              else if ((strcmp (type, "note")
                        && strcmp (type, "override"))
                       || (strcmp (keyword->string, "nvt")
                           && strcmp (keyword->string, "name")))
                {
                  gchar *column;
                  keyword_type_t column_type;
                  column = columns_select_column_with_type (select_columns,
                                                            where_columns,
                                                            keyword->string,
                                                            &column_type);
                  assert (column);
                  if (column_type == KEYWORD_TYPE_INTEGER)
                    g_string_append_printf (order,
                                            " ORDER BY"
                                            " cast (%s AS bigint) ASC",
                                            column);
                  else if (column_type == KEYWORD_TYPE_DOUBLE)
                    g_string_append_printf (order,
                                            " ORDER BY"
                                            " cast (%s AS real) ASC",
                                            column);
                  else
                    g_string_append_printf (order, " ORDER BY lower (%s) ASC",
                                            column);
                }
              else
                /* Special case for notes text sorting. */
                g_string_append_printf (order,
                                        " ORDER BY nvt ASC,"
                                        "          lower (%ss%s.text) ASC",
                                        type,
                                        trash ? "_trash" : "");
              first_order = 0;
            }
          else
            /* To help the client split_filter restricts the filter to one
             * sorting term, preventing this from happening. */
            g_string_append_printf (order, ", %s ASC",
                                    keyword->string);
          point++;
          continue;
        }
      else if (keyword->column
               && (strcasecmp (keyword->column, "sort-reverse") == 0))
        {
          if (vector_find_filter (filter_columns, keyword->string) == 0)
            {
              point++;
              continue;
            }

          if (first_order)
            {
              if ((strcmp (type, "report") == 0)
                  && (strcmp (keyword->string, "status") == 0))
                g_string_append_printf
                 (order,
                  " ORDER BY"
                  "  (CASE WHEN (SELECT target = 0 FROM tasks"
                  "              WHERE tasks.id = task)"
                  "    THEN 'Container'"
                  "    ELSE run_status_name (scan_run_status)"
                  "         || (SELECT CAST (temp / 100 AS text)"
                  "                    || CAST (temp / 10 AS text)"
                  "                    || CAST (temp %% 10 as text)"
                  "             FROM (SELECT report_progress (id) AS temp)"
                  "                  AS temp_sub)"
                  "    END)"
                  " DESC");
              else if ((strcmp (type, "task") == 0)
                       && (strcmp (keyword->string, "status") == 0))
                g_string_append_printf
                 (order,
                  " ORDER BY"
                  "  (CASE WHEN target = 0"
                  "    THEN 'Container'"
                  "    ELSE run_status_name (run_status)"
                  "         || (SELECT CAST (temp / 100 AS text)"
                  "                    || CAST (temp / 10 AS text)"
                  "                    || CAST (temp %% 10 as text)"
                  "             FROM (SELECT report_progress (id) AS temp"
                  "                   FROM reports"
                  "                   WHERE task = tasks.id"
                  "                   ORDER BY creation_time DESC LIMIT 1)"
                  "                  AS temp_sub)"
                  "    END)"
                  " DESC");
              else if ((strcmp (type, "task") == 0)
                       && (strcmp (keyword->string, "threat") == 0))
                {
                  gchar *column;
                  column = columns_select_column (select_columns,
                                                  where_columns,
                                                  keyword->string);
                  assert (column);
                  g_string_append_printf (order,
                                          " ORDER BY order_threat (%s) DESC",
                                          column);
                }
              else if (strcmp (keyword->string, "severity") == 0
                       || strcmp (keyword->string, "original_severity") == 0
                       || strcmp (keyword->string, "cvss") == 0
                       || strcmp (keyword->string, "cvss_base") == 0
                       || strcmp (keyword->string, "max_cvss") == 0
                       || strcmp (keyword->string, "fp_per_host") == 0
                       || strcmp (keyword->string, "log_per_host") == 0
                       || strcmp (keyword->string, "low_per_host") == 0
                       || strcmp (keyword->string, "medium_per_host") == 0
                       || strcmp (keyword->string, "high_per_host") == 0
#if CVSS3_RATINGS == 1
                       || strcmp (keyword->string, "critical_per_host") == 0
#endif
                      )
                {
                  gchar *column;
                  column = columns_select_column (select_columns,
                                                  where_columns,
                                                  keyword->string);
                  g_string_append_printf (order,
                                          " ORDER BY CASE CAST (%s AS text)"
                                          " WHEN '' THEN '-Infinity'::real"
                                          " ELSE coalesce(%s::real,"
                                          "               '-Infinity'::real)"
                                          " END DESC",
                                          column,
                                          column);
                }
              else if (strcmp (keyword->string, "roles") == 0)
                {
                  gchar *column;
                  column = columns_select_column (select_columns,
                                                  where_columns,
                                                  keyword->string);
                  assert (column);
                  g_string_append_printf (order,
                                          " ORDER BY"
                                          " CASE WHEN %s %s 'Admin.*'"
                                          " THEN '0' || %s"
                                          " ELSE '1' || %s END DESC",
                                          column,
                                          sql_regexp_op (),
                                          column,
                                          column);
                }
              else if ((strcmp (keyword->string, "created") == 0)
                       || (strcmp (keyword->string, "modified") == 0)
                       || (strcmp (keyword->string, "published") == 0)
                       || (strcmp (keyword->string, "qod") == 0)
                       || (strcmp (keyword->string, "cves") == 0)
#if CVSS3_RATINGS == 1
                       || (strcmp (keyword->string, "critical") == 0)
#endif
                       || (strcmp (keyword->string, "high") == 0)
                       || (strcmp (keyword->string, "medium") == 0)
                       || (strcmp (keyword->string, "low") == 0)
                       || (strcmp (keyword->string, "log") == 0)
                       || (strcmp (keyword->string, "false_positive") == 0)
                       || (strcmp (keyword->string, "hosts") == 0)
                       || (strcmp (keyword->string, "result_hosts") == 0)
                       || (strcmp (keyword->string, "results") == 0)
                       || (strcmp (keyword->string, "latest_severity") == 0)
                       || (strcmp (keyword->string, "highest_severity") == 0)
                       || (strcmp (keyword->string, "average_severity") == 0))
                {
                  gchar *column;
                  column = columns_select_column (select_columns,
                                                  where_columns,
                                                  keyword->string);
                  assert (column);
                  g_string_append_printf (order,
                                          " ORDER BY %s DESC",
                                          column);
                }
              else if ((strcmp (keyword->string, "ips") == 0)
                       || (strcmp (keyword->string, "total") == 0)
                       || (strcmp (keyword->string, "tcp") == 0)
                       || (strcmp (keyword->string, "udp") == 0))
                {
                  gchar *column;
                  column = columns_select_column (select_columns,
                                                  where_columns,
                                                  keyword->string);
                  assert (column);
                  g_string_append_printf (order,
                                          " ORDER BY CAST (%s AS INTEGER) DESC",
                                          column);
                }
              else if (strcmp (keyword->string, "ip") == 0
                       || strcmp (keyword->string, "host") == 0)
                {
                  gchar *column;
                  column = columns_select_column (select_columns,
                                                  where_columns,
                                                  keyword->string);
                  assert (column);
                  g_string_append_printf (order,
                                          " ORDER BY order_inet (%s) DESC",
                                          column);
                }
              else if ((strcmp (type, "note")
                        && strcmp (type, "override"))
                       || (strcmp (keyword->string, "nvt")
                           && strcmp (keyword->string, "name")))
                {
                  gchar *column;
                  keyword_type_t column_type;
                  column = columns_select_column_with_type (select_columns,
                                                            where_columns,
                                                            keyword->string,
                                                            &column_type);
                  assert (column);
                  if (column_type == KEYWORD_TYPE_INTEGER)
                    g_string_append_printf (order,
                                            " ORDER BY"
                                            " cast (%s AS bigint) DESC",
                                            column);
                  else if (column_type == KEYWORD_TYPE_DOUBLE)
                    g_string_append_printf (order,
                                            " ORDER BY"
                                            " cast (%s AS real) DESC",
                                            column);
                  else
                    g_string_append_printf (order, " ORDER BY lower (%s) DESC",
                                            column);
                }
              else
                /* Special case for notes text sorting. */
                g_string_append_printf (order,
                                        " ORDER BY nvt DESC,"
                                        "          lower (%ss%s.text) DESC",
                                        type,
                                        trash ? "_trash" : "");
              first_order = 0;
            }
          else
            /* To help the client split_filter restricts the filter to one
             * sorting term, preventing this from happening. */
            g_string_append_printf (order, ", %s DESC",
                                    keyword->string);
          point++;
          continue;
        }
      else if (keyword->column
               && (strcasecmp (keyword->column, "first") == 0))
        {
          if (first_return)
            {
              /* Subtract 1 to switch from 1 to 0 indexing. */
              *first_return = atoi (keyword->string) - 1;
              if (*first_return < 0)
                *first_return = 0;
            }

          point++;
          continue;
        }
      else if (keyword->column
               && (strcasecmp (keyword->column, "rows") == 0))
        {
          if (max_return)
            *max_return = atoi (keyword->string);

          point++;
          continue;
        }
      else if (keyword->column
               && (strcasecmp (keyword->column, "permission") == 0))
        {
          if (permissions)
            array_add (*permissions, g_strdup (keyword->string));

          point++;
          continue;
        }
      /* Add tag criteria to clause: tag name with optional value */
      else if (keyword->column
               && (strcasecmp (keyword->column, "tag") == 0))
        {
          quoted_keyword = NULL;

          filter_clause_append_tag (clause, keyword, type,
                                    first_keyword, last_was_and, last_was_not);

          first_keyword = 0;
          last_was_and = 0;
          last_was_not = 0;

          point++;
          continue;
        }
      /* Add criteria for tag_id to clause */
      else if (keyword->column
               && (strcasecmp (keyword->column, "tag_id") == 0))
        {
          quoted_keyword = NULL;

          filter_clause_append_tag_id (clause, keyword, type, first_keyword,
                                       last_was_and, last_was_not);

          first_keyword = 0;
          last_was_and = 0;
          last_was_not = 0;

          point++;
          continue;
        }

      /* Add SQL to the clause for each column name. */

      quoted_keyword = NULL;

      if (keyword->relation == KEYWORD_RELATION_COLUMN_EQUAL)
        {
          if (vector_find_filter (filter_columns, keyword->column) == 0)
            {
              last_was_and = 0;
              last_was_not = 0;
              point++;
              continue;
            }

          if (keyword->column
              && (strlen (keyword->column) > 3)
              && (strcmp (keyword->column + strlen (keyword->column) - 3, "_id")
                  == 0)
              && strcasecmp (keyword->column, "nvt_id")
              /* Tickets have a custom result_id column. */
              && strcasecmp (keyword->column, "result_id"))
            {
              gchar *type_term;

              type_term = g_strndup (keyword->column,
                                     strlen (keyword->column) - 3);
              if (valid_type (type_term) == 0)
                {
                  g_free (type_term);
                  last_was_and = 0;
                  last_was_not = 0;
                  point++;
                  continue;
                }

              quoted_keyword = sql_quote (keyword->string);
              if (strcmp (quoted_keyword, ""))
                g_string_append_printf (clause,
                                        "%s(((SELECT id FROM %ss"
                                        "     WHERE %ss.uuid = '%s')"
                                        "     = %ss.%s"
                                        "     OR %ss.%s IS NULL"
                                        "     OR %ss.%s = 0)",
                                        get_join (first_keyword,
                                                  last_was_and,
                                                  last_was_not),
                                        type_term,
                                        type_term,
                                        quoted_keyword,
                                        type,
                                        type_term,
                                        type,
                                        type_term,
                                        type,
                                        type_term);
              else
                g_string_append_printf (clause,
                                        "%s((%ss.%s IS NULL"
                                        "   OR %ss.%s = 0)",
                                        get_join (first_keyword,
                                                  last_was_and,
                                                  last_was_not),
                                        type,
                                        type_term,
                                        type,
                                        type_term);

              g_free (type_term);
            }
          else if (keyword->column && strcmp (keyword->column, "owner"))
            {
              gchar *column;
              keyword_type_t column_type;
              quoted_keyword = sql_quote (keyword->string);
              column = columns_select_column_with_type (select_columns,
                                                        where_columns,
                                                        keyword->column,
                                                        &column_type);
              assert (column);
              if (keyword->type == KEYWORD_TYPE_INTEGER
                  && (column_type == KEYWORD_TYPE_INTEGER
                      || column_type == KEYWORD_TYPE_DOUBLE))
                g_string_append_printf (clause,
                                        "%s(CAST (%s AS NUMERIC) = %i",
                                        get_join (first_keyword, last_was_and,
                                                  last_was_not),
                                        column,
                                        keyword->integer_value);
          else if (keyword->type == KEYWORD_TYPE_DOUBLE
                   && (column_type == KEYWORD_TYPE_DOUBLE
                       || column_type == KEYWORD_TYPE_INTEGER))
                g_string_append_printf (clause,
                                        "%s(CAST (%s AS REAL)"
                                        " = CAST (%f AS REAL)",
                                        get_join (first_keyword, last_was_and,
                                                  last_was_not),
                                        column,
                                        keyword->double_value);
              else if (strcmp (quoted_keyword, ""))
                g_string_append_printf (clause,
                                        "%s(CAST (%s AS TEXT) = '%s'",
                                        get_join (first_keyword, last_was_and,
                                                  last_was_not),
                                        column,
                                        quoted_keyword);
              else
                g_string_append_printf (clause,
                                        "%s((%s IS NULL OR CAST (%s AS TEXT) = '%s')",
                                        get_join (first_keyword, last_was_and,
                                                  last_was_not),
                                        column,
                                        column,
                                        quoted_keyword);
            }
          else
            {
              /* Skip term.  Owner filtering is done via where_owned. */
              skip = 1;
              if (owner_filter && (*owner_filter == NULL))
                *owner_filter = g_strdup (keyword->string);
            }
        }
      else if (keyword->relation == KEYWORD_RELATION_COLUMN_APPROX)
        {
          gchar *column;

          if (vector_find_filter (filter_columns, keyword->column) == 0)
            {
              last_was_and = 0;
              last_was_not = 0;
              point++;
              continue;
            }

          quoted_keyword = sql_quote (keyword->string);
          column = columns_select_column (select_columns,
                                          where_columns,
                                          keyword->column);
          assert (column);
          g_string_append_printf (clause,
                                  "%s(CAST (%s AS TEXT) %s '%%%%%s%%%%'",
                                  get_join (first_keyword, last_was_and,
                                            last_was_not),
                                  column,
                                  sql_ilike_op (),
                                  quoted_keyword);
        }
      else if (keyword->relation == KEYWORD_RELATION_COLUMN_ABOVE)
        {
          gchar *column;
          keyword_type_t column_type;

          if (vector_find_filter (filter_columns, keyword->column) == 0)
            {
              last_was_and = 0;
              last_was_not = 0;
              point++;
              continue;
            }

          quoted_keyword = sql_quote (keyword->string);
          column = columns_select_column_with_type (select_columns,
                                                    where_columns,
                                                    keyword->column,
                                                    &column_type);
          assert (column);
          if (keyword->type == KEYWORD_TYPE_INTEGER
              && (column_type == KEYWORD_TYPE_INTEGER
                  || column_type == KEYWORD_TYPE_DOUBLE))
            g_string_append_printf (clause,
                                    "%s(CAST (%s AS NUMERIC) > %i",
                                    get_join (first_keyword, last_was_and,
                                              last_was_not),
                                    column,
                                    keyword->integer_value);
          else if (keyword->type == KEYWORD_TYPE_DOUBLE
                   && (column_type == KEYWORD_TYPE_DOUBLE
                       || column_type == KEYWORD_TYPE_INTEGER))
            g_string_append_printf (clause,
                                    "%s(CAST (%s AS REAL)"
                                    " > CAST (%f AS REAL)",
                                    get_join (first_keyword, last_was_and,
                                              last_was_not),
                                    column,
                                    keyword->double_value);
          else
            g_string_append_printf (clause,
                                    "%s(CAST (%s AS TEXT) > '%s'",
                                    get_join (first_keyword, last_was_and,
                                              last_was_not),
                                    column,
                                    quoted_keyword);
        }
      else if (keyword->relation == KEYWORD_RELATION_COLUMN_BELOW)
        {
          gchar *column;
          keyword_type_t column_type;

          if (vector_find_filter (filter_columns, keyword->column) == 0)
            {
              last_was_and = 0;
              last_was_not = 0;
              point++;
              continue;
            }

          quoted_keyword = sql_quote (keyword->string);
          column = columns_select_column_with_type (select_columns,
                                                    where_columns,
                                                    keyword->column,
                                                    &column_type);
          assert (column);
          if (keyword->type == KEYWORD_TYPE_INTEGER
              && (column_type == KEYWORD_TYPE_INTEGER
                  || column_type == KEYWORD_TYPE_DOUBLE))
            g_string_append_printf (clause,
                                    "%s(CAST (%s AS NUMERIC) < %i",
                                    get_join (first_keyword, last_was_and,
                                              last_was_not),
                                    column,
                                    keyword->integer_value);
          else if (keyword->type == KEYWORD_TYPE_DOUBLE
                   && (column_type == KEYWORD_TYPE_DOUBLE
                       || column_type == KEYWORD_TYPE_INTEGER))
            g_string_append_printf (clause,
                                    "%s(CAST (%s AS REAL)"
                                    " < CAST (%f AS REAL)",
                                    get_join (first_keyword, last_was_and,
                                              last_was_not),
                                    column,
                                    keyword->double_value);
          else
            g_string_append_printf (clause,
                                    "%s(CAST (%s AS TEXT) < '%s'",
                                    get_join (first_keyword, last_was_and,
                                              last_was_not),
                                    column,
                                    quoted_keyword);
        }
      else if (keyword->relation == KEYWORD_RELATION_COLUMN_REGEXP)
        {
          gchar *column;

          if (vector_find_filter (filter_columns, keyword->column) == 0)
            {
              last_was_and = 0;
              last_was_not = 0;
              point++;
              continue;
            }

          quoted_keyword = sql_quote (keyword->string);
          column = columns_select_column (select_columns,
                                          where_columns,
                                          keyword->column);
          assert (column);
          g_string_append_printf (clause,
                                  "%s(CAST (%s AS TEXT) %s '%s'",
                                  get_join (first_keyword, last_was_and,
                                            last_was_not),
                                  column,
                                  sql_regexp_op (),
                                  quoted_keyword);
        }
      else if (keyword->equal)
        {
          const char *filter_column;

          /* Keyword like "=example". */

          g_string_append_printf (clause,
                                  "%s(",
                                  (first_keyword
                                    ? ""
                                    : (last_was_and ? " AND " : " OR ")));

          quoted_keyword = sql_quote (keyword->string);
          if (last_was_not)
            for (index = 0;
                 (filter_column = filter_columns[index]) != NULL;
                 index++)
              {
                gchar *select_column;
                keyword_type_t column_type;

                select_column = columns_select_column_with_type (select_columns,
                                                                 where_columns,
                                                                 filter_column,
                                                                 &column_type);
                assert (select_column);

                if (keyword->type == KEYWORD_TYPE_INTEGER
                    && (column_type == KEYWORD_TYPE_INTEGER
                        || column_type == KEYWORD_TYPE_DOUBLE))
                  g_string_append_printf (clause,
                                          "%s"
                                          "(%s IS NULL"
                                          " OR CAST (%s AS NUMERIC)"
                                          "    != %i)",
                                          (index ? " AND " : ""),
                                          select_column,
                                          select_column,
                                          keyword->integer_value);
                else if (keyword->type == KEYWORD_TYPE_DOUBLE
                         && (column_type == KEYWORD_TYPE_DOUBLE
                             || column_type == KEYWORD_TYPE_INTEGER))
                  g_string_append_printf (clause,
                                          "%s"
                                          "(%s IS NULL"
                                          " OR CAST (%s AS REAL)"
                                          "    != CAST (%f AS REAL))",
                                          (index ? " AND " : ""),
                                          select_column,
                                          select_column,
                                          keyword->double_value);
                else
                  g_string_append_printf (clause,
                                          "%s"
                                          "(%s IS NULL"
                                          " OR CAST (%s AS TEXT)"
                                          "    != '%s')",
                                          (index ? " AND " : ""),
                                          select_column,
                                          select_column,
                                          quoted_keyword);
              }
          else
            for (index = 0;
                 (filter_column = filter_columns[index]) != NULL;
                 index++)
              {
                gchar *select_column;
                keyword_type_t column_type;

                select_column = columns_select_column_with_type (select_columns,
                                                                 where_columns,
                                                                 filter_column,
                                                                 &column_type);
                assert (select_column);

                if (keyword->type == KEYWORD_TYPE_INTEGER
                    && (column_type == KEYWORD_TYPE_INTEGER
                        || column_type == KEYWORD_TYPE_DOUBLE))
                  g_string_append_printf (clause,
                                          "%sCAST (%s AS NUMERIC)"
                                          " = %i",
                                          (index ? " OR " : ""),
                                          select_column,
                                          keyword->integer_value);
                else if (keyword->type == KEYWORD_TYPE_DOUBLE
                         && (column_type == KEYWORD_TYPE_DOUBLE
                             || column_type == KEYWORD_TYPE_INTEGER))
                  g_string_append_printf (clause,
                                          "%sCAST (%s AS REAL)"
                                          " = CAST (%f AS REAL)",
                                          (index ? " OR " : ""),
                                          select_column,
                                          keyword->double_value);
                else
                  g_string_append_printf (clause,
                                          "%sCAST (%s AS TEXT)"
                                          " = '%s'",
                                          (index ? " OR " : ""),
                                          select_column,
                                          quoted_keyword);
              }
        }
      else
        {
          const char *filter_column;

          g_string_append_printf (clause,
                                  "%s(",
                                  (first_keyword
                                    ? ""
                                    : (last_was_and ? " AND " : " OR ")));

          quoted_keyword = sql_quote (keyword->string);
          if (last_was_not)
            for (index = 0;
                 (filter_column = filter_columns[index]) != NULL;
                 index++)
              {
                gchar *select_column;
                keyword_type_t column_type;
                int column_type_matches = 0;

                select_column = columns_select_column_with_type (select_columns,
                                                                 where_columns,
                                                                 filter_column,
                                                                 &column_type);

                if (column_type != KEYWORD_TYPE_INTEGER
                    && column_type != KEYWORD_TYPE_DOUBLE)
                  column_type_matches = 1;

                if (keyword_applies_to_column (keyword, filter_column)
                    && select_column && column_type_matches)
                  {
                    if (last_was_re)
                      g_string_append_printf (clause,
                                              "%s"
                                              "(%s IS NULL"
                                              " OR NOT (CAST (%s AS TEXT)"
                                              "         %s '%s'))",
                                              (index ? " AND " : ""),
                                              select_column,
                                              select_column,
                                              sql_regexp_op (),
                                              quoted_keyword);
                    else
                      g_string_append_printf (clause,
                                              "%s"
                                              "(%s IS NULL"
                                              " OR CAST (%s AS TEXT)"
                                              "    NOT %s '%%%s%%')",
                                              (index ? " AND " : ""),
                                              select_column,
                                              select_column,
                                              sql_ilike_op (),
                                              quoted_keyword);
                  }
                else
                  g_string_append_printf (clause,
                                          "%s t ()",
                                          (index ? " AND " : ""));
              }
          else
            for (index = 0;
                 (filter_column = filter_columns[index]) != NULL;
                 index++)
              {
                gchar *select_column;
                keyword_type_t column_type;
                int column_type_matches = 0;

                select_column = columns_select_column_with_type (select_columns,
                                                                 where_columns,
                                                                 filter_column,
                                                                 &column_type);
                if (column_type != KEYWORD_TYPE_INTEGER
                    && column_type != KEYWORD_TYPE_DOUBLE)
                  column_type_matches = 1;

                if (keyword_applies_to_column (keyword, filter_column)
                    && select_column && column_type_matches)
                  g_string_append_printf (clause,
                                          "%sCAST (%s AS TEXT)"
                                          " %s '%s%s%s'",
                                          (index ? " OR " : ""),
                                          select_column,
                                          last_was_re
                                           ? sql_regexp_op ()
                                           : sql_ilike_op (),
                                          last_was_re ? "" : "%%",
                                          quoted_keyword,
                                          last_was_re ? "" : "%%");
                else
                  g_string_append_printf (clause,
                                          "%snot t ()",
                                          (index ? " OR " : ""));
              }
        }

      if (skip == 0)
        {
          g_string_append (clause, ")");
          first_keyword = 0;
          last_was_and = 0;
          last_was_not = 0;
          last_was_re = 0;
        }
      g_free (quoted_keyword);
      point++;
    }
  filter_free (split);

  if (order_return)
    *order_return = g_string_free (order, FALSE);
  else
    g_string_free (order, TRUE);

  if (max_return)
    {
      if (*max_return == -2)
        setting_value_int (SETTING_UUID_ROWS_PER_PAGE, max_return);
      else if (*max_return < 1)
        *max_return = -1;

      *max_return = manage_max_rows (*max_return, ignore_max_rows_per_page);
    }

  if (strlen (clause->str))
    return g_string_free (clause, FALSE);
  g_string_free (clause, TRUE);
  return NULL;
}

/**
 * @brief Find a filter for a specific permission, given a UUID.
 *
 * @param[in]   uuid        UUID of filter.
 * @param[out]  filter      Filter return, 0 if successfully failed to find
 *                          filter.
 * @param[in]   permission  Permission.
 *
 * @return FALSE on success (including if failed to find filter), TRUE on error.
 */
gboolean
find_filter_with_permission (const char* uuid, filter_t* filter,
                             const char *permission)
{
  return find_resource_with_permission ("filter", uuid, filter, permission, 0);
}

/**
 * @brief Return the UUID of a filter.
 *
 * @param[in]  filter  Filter.
 *
 * @return Newly allocated UUID if available, else NULL.
 */
char*
filter_uuid (filter_t filter)
{
  return sql_string ("SELECT uuid FROM filters WHERE id = %llu;",
                     filter);
}

/**
 * @brief Return the UUID of a trashcan filter.
 *
 * @param[in]  filter  Filter.
 *
 * @return Newly allocated UUID if available, else NULL.
 */
char*
trash_filter_uuid (filter_t filter)
{
  return sql_string ("SELECT uuid FROM filters_trash WHERE id = %llu;",
                     filter);
}

/**
 * @brief Return the name of a filter.
 *
 * @param[in]  filter  Filter.
 *
 * @return name of filter.
 */
char*
filter_name (filter_t filter)
{
  return sql_string ("SELECT name FROM filters WHERE id = %llu;",
                     filter);
}

/**
 * @brief Return the name of a trashcan filter.
 *
 * @param[in]  filter  Filter.
 *
 * @return name of filter.
 */
char*
trash_filter_name (filter_t filter)
{
  return sql_string ("SELECT name FROM filters_trash WHERE id = %llu;",
                     filter);
}

/**
 * @brief Return the term of a filter.
 *
 * @param[in]  uuid  Filter UUID.
 *
 * @return Newly allocated term if available, else NULL.
 */
gchar*
filter_term_sql (const char *uuid)
{
  gchar *quoted_uuid, *ret;
  quoted_uuid = sql_quote (uuid);
  ret = sql_string ("SELECT term FROM filters WHERE uuid = '%s';",
                    quoted_uuid);
  g_free (quoted_uuid);
  return ret;
}

/**
 * @brief Create a filter.
 *
 * @param[in]   name            Name of filter.
 * @param[in]   comment         Comment on filter.
 * @param[in]   type            Type of resource.
 * @param[in]   term            Filter term.
 * @param[out]  filter          Created filter.
 *
 * @return 0 success, 1 filter exists already, 2 error in type, 99 permission
 *         denied.
 */
int
create_filter (const char *name, const char *comment, const char *type,
               const char *term, filter_t* filter)
{
  gchar *quoted_name, *quoted_comment, *quoted_term, *clean_term;
  const char *db_type;

  assert (current_credentials.uuid);

  if (type && strlen (type))
    {
      db_type = type_db_name (type);
      if ((db_type == NULL || !valid_type (db_type)) && !valid_subtype (type))
      {
        return 2;
      }
      type = valid_subtype (type) ? type : db_type;
    }

  sql_begin_immediate ();

  if (acl_user_may ("create_filter") == 0)
    {
      sql_rollback ();
      return 99;
    }

  if (resource_with_name_exists (name, "filter", 0))
    {
      sql_rollback ();
      return 1;
    }
  quoted_name = sql_quote (name ?: "");

  clean_term = manage_clean_filter (term ? term : "",
                                    0 /* ignore_max_rows_per_page */);
  quoted_term = sql_quote (clean_term);
  g_free (clean_term);

  if (comment)
    {
      quoted_comment = sql_quote (comment);
      sql ("INSERT INTO filters"
           " (uuid, name, owner, comment, type, term, creation_time,"
           "  modification_time)"
           " VALUES (make_uuid (), '%s',"
           " (SELECT id FROM users WHERE users.uuid = '%s'),"
           " '%s', %s%s%s, '%s', m_now (), m_now ());",
           quoted_name,
           current_credentials.uuid,
           quoted_comment,
           type ? "lower ('" : "",
           type ? type : "''",
           type ? "')" : "",
           quoted_term);
      g_free (quoted_comment);
    }
  else
    sql ("INSERT INTO filters"
         " (uuid, name, owner, comment, type, term, creation_time,"
         "  modification_time)"
         " VALUES (make_uuid (), '%s',"
         " (SELECT id FROM users WHERE users.uuid = '%s'),"
         " '', %s%s%s, '%s', m_now (), m_now ());",
         quoted_name,
         current_credentials.uuid,
         type ? "lower ('" : "",
         type ? type : "''",
         type ? "')" : "",
         quoted_term);

  if (filter)
    *filter = sql_last_insert_id ();

  g_free (quoted_name);
  g_free (quoted_term);

  sql_commit ();

  return 0;
}

/**
 * @brief Create a filter from an existing filter.
 *
 * @param[in]  name        Name of new filter.  NULL to copy from existing.
 * @param[in]  comment     Comment on new filter.  NULL to copy from existing.
 * @param[in]  filter_id   UUID of existing filter.
 * @param[out] new_filter  New filter.
 *
 * @return 0 success, 1 filter exists already, 2 failed to find existing
 *         filter, -1 error.
 */
int
copy_filter (const char* name, const char* comment, const char *filter_id,
             filter_t* new_filter)
{
  return copy_resource ("filter", name, comment, filter_id, "term, type",
                        1, new_filter, NULL);
}

/**
 * @brief Delete a filter.
 *
 * @param[in]  filter_id  UUID of filter.
 * @param[in]  ultimate   Whether to remove entirely, or to trashcan.
 *
 * @return 0 success, 1 fail because a task refers to the filter, 2 failed
 *         to find filter, 99 permission denied, -1 error.
 */
int
delete_filter (const char *filter_id, int ultimate)
{
  gchar *quoted_filter_id;
  filter_t filter = 0;

  sql_begin_immediate ();

  if (acl_user_may ("delete_filter") == 0)
    {
      sql_rollback ();
      return 99;
    }

  if (find_filter_with_permission (filter_id, &filter, "delete_filter"))
    {
      sql_rollback ();
      return -1;
    }

  if (filter == 0)
    {
      if (find_trash ("filter", filter_id, &filter))
        {
          sql_rollback ();
          return -1;
        }
      if (filter == 0)
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

      /* Check if it's in use by an alert in the trashcan. */
      if (sql_int ("SELECT count(*) FROM alerts_trash"
                   " WHERE filter = %llu"
                   " AND filter_location = " G_STRINGIFY (LOCATION_TRASH) ";",
                   filter))
        {
          sql_rollback ();
          return 1;
        }

      /* Check if it's in use by the condition of an alert in the trashcan. */
      if (sql_int ("SELECT count(*) FROM alert_condition_data_trash"
                   " WHERE name = 'filter_id'"
                   " AND data = (SELECT uuid FROM filters_trash"
                   "             WHERE id = %llu)"
                   " AND (SELECT condition = %i OR condition = %i"
                   "      FROM alerts_trash WHERE id = alert);",
                   filter,
                   ALERT_CONDITION_FILTER_COUNT_AT_LEAST,
                   ALERT_CONDITION_FILTER_COUNT_CHANGED))
        {
          sql_rollback ();
          return 1;
        }

      permissions_set_orphans ("filter", filter, LOCATION_TRASH);
      tags_remove_resource ("filter", filter, LOCATION_TRASH);

      sql ("DELETE FROM filters_trash WHERE id = %llu;", filter);
      sql_commit ();
      return 0;
    }

  /* Check if it's in use by an alert. */
  if (sql_int ("SELECT count(*) FROM alerts"
               " WHERE filter = %llu;",
               filter))
    {
      sql_rollback ();
      return 1;
    }

  /* Check if it's in use by the condition of an alert. */
  if (sql_int ("SELECT count(*) FROM alert_condition_data"
               " WHERE name = 'filter_id'"
               " AND data = (SELECT uuid FROM filters"
               "             WHERE id = %llu)"
               " AND (SELECT condition = %i OR condition = %i"
               "      FROM alerts WHERE id = alert);",
               filter,
               ALERT_CONDITION_FILTER_COUNT_AT_LEAST,
               ALERT_CONDITION_FILTER_COUNT_CHANGED))
    {
      sql_rollback ();
      return 1;
    }

  if (ultimate)
    {
      /* Check if it's in use by the condition of an alert in the trashcan. */
      if (sql_int ("SELECT count(*) FROM alert_condition_data_trash"
                   " WHERE name = 'filter_id'"
                   " AND data = (SELECT uuid FROM filters"
                   "             WHERE id = %llu)"
                   " AND (SELECT condition = %i OR condition = %i"
                   "      FROM alerts_trash WHERE id = alert);",
                   filter,
                   ALERT_CONDITION_FILTER_COUNT_AT_LEAST,
                   ALERT_CONDITION_FILTER_COUNT_CHANGED))
        {
          sql_rollback ();
          return 1;
        }
    }

  quoted_filter_id = sql_quote (filter_id);
  sql ("DELETE FROM settings WHERE name %s '%% Filter' AND value = '%s';",
       sql_ilike_op (),
       quoted_filter_id);
  g_free (quoted_filter_id);

  if (ultimate == 0)
    {
      sql ("INSERT INTO filters_trash"
           " (uuid, owner, name, comment, type, term, creation_time,"
           "  modification_time)"
           " SELECT uuid, owner, name, comment, type, term, creation_time,"
           "  modification_time"
           " FROM filters WHERE id = %llu;",
           filter);

      /* Update the location of the filter in any trashcan alerts. */
      sql ("UPDATE alerts_trash"
           " SET filter = %llu,"
           "     filter_location = " G_STRINGIFY (LOCATION_TRASH)
           " WHERE filter = %llu"
           " AND filter_location = " G_STRINGIFY (LOCATION_TABLE) ";",
           sql_last_insert_id (),
           filter);

      permissions_set_locations ("filter", filter,
                                 sql_last_insert_id (),
                                 LOCATION_TRASH);
      tags_set_locations ("filter", filter,
                          sql_last_insert_id (),
                          LOCATION_TRASH);
    }
  else
    {
      permissions_set_orphans ("filter", filter, LOCATION_TABLE);
      tags_remove_resource ("filter", filter, LOCATION_TABLE);
    }

  sql ("DELETE FROM filters WHERE id = %llu;", filter);

  sql_commit ();
  return 0;
}

/**
 * @brief Check whether a filter is in use.
 *
 * @param[in]  filter  Filter.
 *
 * @return 1 yes, 0 no.
 */
int
filter_in_use (filter_t filter)
{
  return !!sql_int ("SELECT count (*) FROM alerts"
                    /* Filter applied to results passed to alert's "generate". */
                    " WHERE filter = %llu"
                    /* Filter applied to check alert condition. */
                    "   OR (EXISTS (SELECT * FROM alert_condition_data"
                    "             WHERE name = 'filter_id'"
                    "             AND data = (SELECT uuid FROM filters"
                    "                          WHERE id = %llu)"
                    "             AND alert = alerts.id)"
                    "       AND (condition = %i OR condition = %i))",
                    filter,
                    filter,
                    ALERT_CONDITION_FILTER_COUNT_AT_LEAST,
                    ALERT_CONDITION_FILTER_COUNT_CHANGED);
}

/**
 * @brief Check whether a filter is in use for the output of any alert.
 *
 * @param[in]  filter  Filter.
 *
 * @return 1 yes, 0 no.
 */
static int
filter_in_use_for_output (filter_t filter)
{
  return !!sql_int ("SELECT count (*) FROM alerts"
                    " WHERE filter = %llu;",
                    filter);
}

/**
 * @brief Check whether a filter is in use by any result alert conditions.
 *
 * @param[in]  filter  Filter.
 *
 * @return 1 yes, 0 no.
 */
static int
filter_in_use_for_result_event (filter_t filter)
{
  return !!sql_int ("SELECT count (*) FROM alerts"
                    " WHERE event = %llu"
                    " AND (EXISTS (SELECT * FROM alert_condition_data"
                    "              WHERE name = 'filter_id'"
                    "              AND data = (SELECT uuid FROM filters"
                    "                          WHERE id = %llu)"
                    "              AND alert = alerts.id)"
                    " AND (condition = %i OR condition = %i))",
                    EVENT_TASK_RUN_STATUS_CHANGED,
                    filter,
                    ALERT_CONDITION_FILTER_COUNT_AT_LEAST,
                    ALERT_CONDITION_FILTER_COUNT_CHANGED);
}

/**
 * @brief Check whether a filter is in use by any secinfo alert conditions.
 *
 * @param[in]  filter  Filter.
 *
 * @return 1 yes, 0 no.
 */
static int
filter_in_use_for_secinfo_event (filter_t filter)
{
  return !!sql_int ("SELECT count (*) FROM alerts"
                    " WHERE (event = %llu OR event = %llu)"
                    " AND (EXISTS (SELECT * FROM alert_condition_data"
                    "              WHERE name = 'filter_id'"
                    "              AND data = (SELECT uuid FROM filters"
                    "                          WHERE id = %llu)"
                    "              AND alert = alerts.id)"
                    " AND (condition = %i OR condition = %i))",
                    EVENT_NEW_SECINFO,
                    EVENT_UPDATED_SECINFO,
                    filter,
                    ALERT_CONDITION_FILTER_COUNT_AT_LEAST,
                    ALERT_CONDITION_FILTER_COUNT_CHANGED);
}

/**
 * @brief Check whether a trashcan filter is in use.
 *
 * @param[in]  filter  Filter.
 *
 * @return 1 yes, 0 no.
 */
int
trash_filter_in_use (filter_t filter)
{
  return !!sql_int ("SELECT count (*) FROM alerts_trash"
                    " WHERE (filter = %llu"
                    "        AND filter_location = "
                                    G_STRINGIFY (LOCATION_TRASH) ")"
                    "   OR (EXISTS (SELECT *"
                    "               FROM alert_condition_data_trash"
                    "               WHERE name = 'filter_id'"
                    "                 AND data = (SELECT uuid"
                    "                             FROM filters_trash"
                    "                             WHERE id = %llu)"
                    "                 AND alert = alerts_trash.id)"
                    "       AND (condition = %i OR condition = %i))",
                    filter,
                    filter,
                    ALERT_CONDITION_FILTER_COUNT_AT_LEAST,
                    ALERT_CONDITION_FILTER_COUNT_CHANGED);
}

/**
 * @brief Check whether a filter is writable.
 *
 * @param[in]  filter  Filter.
 *
 * @return 1 yes, 0 no.
 */
int
filter_writable (filter_t filter)
{
  return 1;
}

/**
 * @brief Check whether a trashcan filter is writable.
 *
 * @param[in]  filter  Filter.
 *
 * @return 1 yes, 0 no.
 */
int
trash_filter_writable (filter_t filter)
{
  return 1;
}

/**
 * @brief Count number of filters.
 *
 * @param[in]  get  GET params.
 *
 * @return Total number of filters in filtered set.
 */
int
filter_count (const get_data_t *get)
{
  static const char *filter_columns[] = FILTER_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = FILTER_ITERATOR_COLUMNS;
  static column_t trash_columns[] = FILTER_ITERATOR_TRASH_COLUMNS;
  return count ("filter", get, columns, trash_columns, filter_columns,
                0, 0, 0, TRUE);
}

/**
 * @brief Initialise a filter iterator, including observed filters.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  get         GET data.
 *
 * @return 0 success, 1 failed to find filter, 2 failed to find filter (filt_id),
 *         -1 error.
 */
int
init_filter_iterator (iterator_t* iterator, get_data_t *get)
{
  static const char *filter_columns[] = FILTER_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = FILTER_ITERATOR_COLUMNS;
  static column_t trash_columns[] = FILTER_ITERATOR_TRASH_COLUMNS;

  return init_get_iterator (iterator,
                            "filter",
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
 * @brief Get the type from a filter iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The type of the filter, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.  "" for any type.
 */
const char*
filter_iterator_type (iterator_t* iterator)
{
  const char *ret;
  if (iterator->done) return NULL;
  ret = iterator_string (iterator, GET_ITERATOR_COLUMN_COUNT);
  return ret ? ret : "";
}

/**
 * @brief Get the term from a filter iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The term of the filter, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (filter_iterator_term, GET_ITERATOR_COLUMN_COUNT + 1);

/**
 * @brief Initialise a filter alert iterator.
 *
 * Iterates over all alerts that use the filter.
 *
 * @param[in]  iterator   Iterator.
 * @param[in]  filter     Filter.
 */
void
init_filter_alert_iterator (iterator_t* iterator, filter_t filter)
{
  gchar *available, *with_clause;
  get_data_t get;
  array_t *permissions;

  assert (filter);

  get.trash = 0;
  permissions = make_array ();
  array_add (permissions, g_strdup ("get_alerts"));
  available = acl_where_owned ("alert", &get, 1, "any", 0, permissions, 0,
                               &with_clause);
  array_free (permissions);

  init_iterator (iterator,
                 "%s"
                 " SELECT name, uuid, %s FROM alerts"
                 " WHERE filter = %llu"
                 " OR (EXISTS (SELECT * FROM alert_condition_data"
                 "             WHERE name = 'filter_id'"
                 "             AND data = (SELECT uuid FROM filters"
                 "                         WHERE id = %llu)"
                 "             AND alert = alerts.id)"
                 "     AND (condition = %i OR condition = %i))"
                 " ORDER BY name ASC;",
                 with_clause ? with_clause : "",
                 available,
                 filter,
                 filter,
                 ALERT_CONDITION_FILTER_COUNT_AT_LEAST,
                 ALERT_CONDITION_FILTER_COUNT_CHANGED);

  g_free (with_clause);
  g_free (available);
}

/**
 * @brief Get the name from a filter_alert iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The name of the host, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (filter_alert_iterator_name, 0);

/**
 * @brief Get the UUID from a filter_alert iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The UUID of the host, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (filter_alert_iterator_uuid, 1);

/**
 * @brief Get the read permission status from a GET iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return 1 if may read, else 0.
 */
int
filter_alert_iterator_readable (iterator_t* iterator)
{
  if (iterator->done) return 0;
  return iterator_int (iterator, 2);
}

/**
 * @brief Modify a filter.
 *
 * @param[in]   filter_id       UUID of filter.
 * @param[in]   name            Name of filter.
 * @param[in]   comment         Comment on filter.
 * @param[in]   term            Filter term.
 * @param[in]   type            Type of filter.
 *
 * @return 0 success, 1 failed to find filter, 2 filter with new name exists,
 *         3 error in type name, 4 filter_id required, 5 filter is in use so
 *         type must be "result", 6 filter is in use so type must be "info",
 *         99 permission denied, -1 internal error.
 */
int
modify_filter (const char *filter_id, const char *name, const char *comment,
               const char *term, const char *type)
{
  gchar *quoted_name, *quoted_comment, *quoted_term, *quoted_type, *clean_term;
  char *t_name, *t_comment, *t_term, *t_type;
  filter_t filter;
  const char *db_type;

  if (filter_id == NULL)
    return 4;

  sql_begin_immediate ();

  filter = 0;
  if (find_filter_with_permission (filter_id, &filter, "modify_filter"))
    {
      sql_rollback ();
      return -1;
    }

  if (filter == 0)
    {
      sql_rollback ();
      return 1;
    }

  db_type = type_db_name (type);
  if (db_type && !((strcmp (db_type, "") == 0) || valid_type (db_type)))
    {
      if (!valid_subtype (type))
        {
          sql_rollback ();
          return 3;
        }
    }

  if (type)
    {
      type = valid_subtype (type) ? type : db_type;
    }

  assert (current_credentials.uuid);

  if (acl_user_may ("modify_filter") == 0)
    {
      sql_rollback ();
      return 99;
    }

  /* If the filter is linked to an alert, check that the type is valid. */

  if ((filter_in_use_for_output (filter)
       || filter_in_use_for_result_event (filter))
      && type
      && strcasecmp (type, "result"))
    {
      sql_rollback ();
      return 5;
    }

  if (filter_in_use_for_secinfo_event (filter)
      && type
      && strcasecmp (type, "info"))
    {
      sql_rollback ();
      return 6;
    }

  /* Check whether a filter with the same name exists already. */
  if (name)
    {
      if (resource_with_name_exists (name, "filter", filter))
        {
          sql_rollback ();
          return 2;
        }
    }

  quoted_name = sql_quote(name ?: "");
  clean_term = manage_clean_filter (term ? term : "",
                                    0 /* ignore_max_rows_per_page */);
  quoted_term = sql_quote (clean_term);
  g_free (clean_term);
  quoted_comment = sql_quote (comment ? comment : "");
  quoted_type = sql_quote (type ? type : "");

  t_name = name ? g_strdup_printf (", name = '%s'", quoted_name) :
                  g_strdup ("");
  t_comment = comment ? g_strdup_printf (", comment = '%s'", quoted_comment) :
                        g_strdup ("");
  t_term = term ? g_strdup_printf (", term = '%s'", quoted_term) :
                  g_strdup ("");
  t_type = type ? g_strdup_printf (", type = lower ('%s')", quoted_type) :
                  g_strdup ("");

  sql ("UPDATE filters SET"
       " modification_time = m_now ()"
       " %s%s%s%s"
       " WHERE id = %llu;",
       t_name,
       t_comment,
       t_term,
       t_type,
       filter);

  g_free (t_name);
  g_free (t_comment);
  g_free (t_term);
  g_free (t_type);
  g_free (quoted_comment);
  g_free (quoted_name);
  g_free (quoted_term);
  g_free (quoted_type);

  sql_commit ();

  return 0;
}
