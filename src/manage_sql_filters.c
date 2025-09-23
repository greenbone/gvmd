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

#include "manage_filters.h"
#include "manage.h"
#include "manage_filter_utils.h"
#include "manage_settings.h"

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
