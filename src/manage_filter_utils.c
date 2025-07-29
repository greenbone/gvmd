/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: Filter utilities.
 *
 * Filter parser and handling utilities code for the GVM management layer.
 */

#define _XOPEN_SOURCE

#include <assert.h>
#include <ctype.h>
#include "manage_utils.h"
#include "manage_filter_utils.h"

/**
 * @brief Internal function for getting a filter term by UUID.
 */
filter_term_func filter_term_internal;

/**
 * @brief Flag to control the default sorting produced by split_filter.
 *
 * If this is true, and the filter does not specify a sort field, then
 * split_filter will not insert a default sort term, so that the random
 * (and fast) table order in the database will be used.
 */
int table_order_if_sort_not_specified = 0;


/**
 * @brief Get the symbol of a keyword relation.
 *
 * @param[in]  relation  Relation.
 *
 * @return Relation symbol.
 */
const char *
keyword_relation_symbol (keyword_relation_t relation)
{
  switch (relation)
    {
      case KEYWORD_RELATION_APPROX:        return "~";
      case KEYWORD_RELATION_COLUMN_ABOVE:  return ">";
      case KEYWORD_RELATION_COLUMN_APPROX: return "~";
      case KEYWORD_RELATION_COLUMN_EQUAL:  return "=";
      case KEYWORD_RELATION_COLUMN_BELOW:  return "<";
      case KEYWORD_RELATION_COLUMN_REGEXP: return ":";
      default:                             return "";
    }
}

/**
 * @brief Free a keyword.
 *
 * @param[in]  keyword  Filter keyword.
 */
static void
keyword_free (keyword_t* keyword)
{
  g_free (keyword->string);
  g_free (keyword->column);
}

/**
 * @brief Get whether a keyword is special (like "and").
 *
 * @param[in]  keyword  Keyword.
 *
 * @return 1 if special, else 0.
 */
int
keyword_special (keyword_t *keyword)
{
  if (keyword->string)
    return (strcmp (keyword->string, "and") == 0)
           || (strcmp (keyword->string, "or") == 0)
           || (strcmp (keyword->string, "not") == 0)
           || (strcmp (keyword->string, "re") == 0)
           || (strcmp (keyword->string, "regexp") == 0);
  return 0;
}

/**
 * @brief Parse a filter column relation.
 *
 * @param[in]  relation  Filter relation.
 *
 * @return keyword relation
 */
static keyword_relation_t
parse_column_relation (const char relation)
{
  switch (relation)
    {
      case '=': return KEYWORD_RELATION_COLUMN_EQUAL;
      case '~': return KEYWORD_RELATION_COLUMN_APPROX;
      case '>': return KEYWORD_RELATION_COLUMN_ABOVE;
      case '<': return KEYWORD_RELATION_COLUMN_BELOW;
      case ':': return KEYWORD_RELATION_COLUMN_REGEXP;
      default:  return KEYWORD_RELATION_COLUMN_APPROX;
    }
}

/**
 * @brief Parse a filter keyword.
 *
 * @param[in]  keyword  Filter keyword.
 */
static void
parse_keyword (keyword_t* keyword)
{
  gchar *string;
  int digits;

  if (keyword->column == NULL && keyword->equal == 0)
    {
      keyword->relation = KEYWORD_RELATION_APPROX;
      keyword->type = KEYWORD_TYPE_STRING;
      return;
    }

  /* Special values to substitute */

  if (keyword->column
      && (strcasecmp (keyword->column, "severity") == 0
          || strcasecmp (keyword->column, "new_severity") == 0))
    {
      if (strcasecmp (keyword->string, "Log") == 0)
        {
          keyword->double_value = SEVERITY_LOG;
          keyword->type = KEYWORD_TYPE_DOUBLE;
          return;
        }
      if (strcasecmp (keyword->string, "False Positive") == 0)
        {
          keyword->double_value = SEVERITY_FP;
          keyword->type = KEYWORD_TYPE_DOUBLE;
          return;
        }
      else if (strcasecmp (keyword->string, "Error") == 0)
        {
          keyword->double_value = SEVERITY_ERROR;
          keyword->type = KEYWORD_TYPE_DOUBLE;
          return;
        }
    }

  /* The type. */

  string = keyword->string;
  if (*string == '\0')
    {
      keyword->type = KEYWORD_TYPE_STRING;
      return;
    }
  if (*string && *string == '-' && strlen (string) > 1) string++;
  digits = 0;
  while (*string && isdigit (*string))
    {
      digits = 1;
      string++;
    }
  if (digits == 0)
    keyword->type = KEYWORD_TYPE_STRING;
  else if (*string)
    {
      struct tm date;
      gchar next;
      int parsed_integer;
      double parsed_double;
      char dummy[2];
      memset (&date, 0, sizeof (date));
      next = *(string + 1);
      if (next == '\0' && *string == 's')
        {
          time_t now;
          now = time (NULL);
          keyword->integer_value = now + atoi (keyword->string);
          keyword->type = KEYWORD_TYPE_INTEGER;
        }
      else if (next == '\0' && *string == 'm')
        {
          time_t now;
          now = time (NULL);
          keyword->integer_value = now + (atoi (keyword->string) * 60);
          keyword->type = KEYWORD_TYPE_INTEGER;
        }
      else if (next == '\0' && *string == 'h')
        {
          time_t now;
          now = time (NULL);
          keyword->integer_value = now + (atoi (keyword->string) * 3600);
          keyword->type = KEYWORD_TYPE_INTEGER;
        }
      else if (next == '\0' && *string == 'd')
        {
          time_t now;
          now = time (NULL);
          keyword->integer_value = now + (atoi (keyword->string) * 86400);
          keyword->type = KEYWORD_TYPE_INTEGER;
        }
      else if (next == '\0' && *string == 'w')
        {
          time_t now;
          now = time (NULL);
          keyword->integer_value = now + atoi (keyword->string) * 604800;
          keyword->type = KEYWORD_TYPE_INTEGER;
        }
      else if (next == '\0' && *string == 'M')
        {
          time_t now;
          now = time (NULL);
          keyword->integer_value = add_months (now, atoi (keyword->string));
          keyword->type = KEYWORD_TYPE_INTEGER;
        }
      else if (next == '\0' && *string == 'y')
        {
          time_t now;
          now = time (NULL);
          keyword->integer_value = add_months (now,
                                               atoi (keyword->string) * 12);
          keyword->type = KEYWORD_TYPE_INTEGER;
        }
      // Add cases for t%H:%M although it is incorrect sometimes it is easier
      // to call filter.lower on the frontend then it can happen that the
      // T indicator is lowered as well.
      else if (strptime (keyword->string, "%Y-%m-%dt%H:%M", &date))
        {
          keyword->integer_value = mktime (&date);
          keyword->type = KEYWORD_TYPE_INTEGER;
          g_debug ("Parsed Y-m-dtH:M %s to timestamp %d.",
                   keyword->string, keyword->integer_value);
        }
      else if (strptime (keyword->string, "%Y-%m-%dt%Hh%M", &date))
        {
          keyword->integer_value = mktime (&date);
          keyword->type = KEYWORD_TYPE_INTEGER;
          g_debug ("Parsed Y-m-dtHhM %s to timestamp %d.",
                   keyword->string, keyword->integer_value);
        }
      else if (strptime (keyword->string, "%Y-%m-%dT%H:%M", &date))
        {
          keyword->integer_value = mktime (&date);
          keyword->type = KEYWORD_TYPE_INTEGER;
          g_debug ("Parsed Y-m-dTH:M %s to timestamp %d.",
                   keyword->string, keyword->integer_value);
        }
      // Add T%Hh%M for downwards compatible filter
      else if (strptime (keyword->string, "%Y-%m-%dT%Hh%M", &date))
        {
          keyword->integer_value = mktime (&date);
          keyword->type = KEYWORD_TYPE_INTEGER;
          g_debug ("Parsed Y-m-dTHhM %s to timestamp %d.",
                   keyword->string, keyword->integer_value);
        }
      else if (memset (&date, 0, sizeof (date)),
               strptime (keyword->string, "%Y-%m-%d", &date))
        {
          keyword->integer_value = mktime (&date);
          keyword->type = KEYWORD_TYPE_INTEGER;
          g_debug ("Parsed Y-m-d %s to timestamp %d.",
                   keyword->string, keyword->integer_value);
        }
      else if (sscanf (keyword->string, "%d%1s", &parsed_integer, dummy) == 1)
        {
          keyword->integer_value = parsed_integer;
          keyword->type = KEYWORD_TYPE_INTEGER;
        }
      else if (sscanf (keyword->string, "%lf%1s", &parsed_double, dummy) == 1
               && parsed_double <= DBL_MAX)
        {
          keyword->double_value = parsed_double;
          keyword->type = KEYWORD_TYPE_DOUBLE;
        }
      else
        keyword->type = KEYWORD_TYPE_STRING;
    }
  else
    {
      keyword->integer_value = atoi (keyword->string);
      keyword->type = KEYWORD_TYPE_INTEGER;
    }
}

/**
 * @brief Cleans up keywords with special conditions and relations.
 *
 * @param[in]  keyword  Keyword to clean up.
 */
static void
cleanup_keyword (keyword_t *keyword)
{
  if (keyword->column == NULL)
    return;

  if (strcasecmp (keyword->column, "first") == 0)
    {
      /* "first" must be >= 1 */
      if (keyword->integer_value <= 0)
        {
          g_free (keyword->string);
          keyword->integer_value = 1;
          keyword->string = g_strdup ("1");
        }
      keyword->relation = KEYWORD_RELATION_COLUMN_EQUAL;
    }
  else if (strcasecmp (keyword->column, "rows") == 0)
    {
      /* rows must be >= 1 or a special value (-1 or -2) */
      if (keyword->integer_value == 0)
        {
          g_free (keyword->string);
          keyword->integer_value = 1;
          keyword->string = g_strdup ("1");
        }
      else if (keyword->integer_value < -2)
        {
          g_free (keyword->string);
          keyword->integer_value = -1;
          keyword->string = g_strdup ("-1");
        }
      keyword->relation = KEYWORD_RELATION_COLUMN_EQUAL;
    }
  else if (strcasecmp (keyword->column, "min_qod") == 0)
    {
      /* min_qod must be a percentage (between 0 and 100) */
      if (keyword->integer_value < 0)
        {
          g_free (keyword->string);
          keyword->integer_value = 0;
          keyword->string = g_strdup ("0");
        }
      else if (keyword->integer_value > 100)
        {
          g_free (keyword->string);
          keyword->integer_value = 100;
          keyword->string = g_strdup ("100");
        }
      keyword->relation = KEYWORD_RELATION_COLUMN_EQUAL;
    }
  else if (strcasecmp (keyword->column, "apply_overrides") == 0
           || strcasecmp (keyword->column, "overrides") == 0
           || strcasecmp (keyword->column, "notes") == 0
           || strcasecmp (keyword->column, "result_hosts_only") == 0)
    {
      /* Boolean options (0 or 1) */
      if (keyword->integer_value != 0 && keyword->integer_value != 1)
        {
          g_free (keyword->string);
          keyword->integer_value = 1;
          keyword->string = g_strdup ("1");
        }
      keyword->relation = KEYWORD_RELATION_COLUMN_EQUAL;
    }
  else if (strcasecmp (keyword->column, "delta_states") == 0
           || strcasecmp (keyword->column, "levels") == 0
           || strcasecmp (keyword->column, "sort") == 0
           || strcasecmp (keyword->column, "sort-reverse") == 0)
    {
      /* Text options */
      keyword->relation = KEYWORD_RELATION_COLUMN_EQUAL;
    }
}

/**
 * @brief Check whether a keyword has any effect in the filter.
 *
 * Some keywords are redundant, like a second sort= keyword.
 *
 * @param[in]  array    Array of existing keywords.
 * @param[in]  keyword  Keyword under consideration.
 *
 * @return 0 no, 1 yes.
 */
static int
keyword_applies (array_t *array, const keyword_t *keyword)
{
  if (keyword->column
      && ((strcmp (keyword->column, "sort") == 0)
          || (strcmp (keyword->column, "sort-reverse") == 0))
      && (keyword->relation == KEYWORD_RELATION_COLUMN_EQUAL))
    {
      int index;

      index = array->len;
      while (index--)
        {
          keyword_t *item;
          item = (keyword_t*) g_ptr_array_index (array, index);
          if (item->column
              && ((strcmp (item->column, "sort") == 0)
                  || (strcmp (item->column, "sort-reverse") == 0)))
            return 0;
        }
      return 1;
    }

  if (keyword->column
      && (strcmp (keyword->column, "first") == 0))
    {
      int index;

      index = array->len;
      while (index--)
        {
          keyword_t *item;
          item = (keyword_t*) g_ptr_array_index (array, index);
          if (item->column && (strcmp (item->column, "first") == 0))
            return 0;
        }
    }

  if (keyword->column
      && (strcmp (keyword->column, "rows") == 0))
    {
      int index;

      index = array->len;
      while (index--)
        {
          keyword_t *item;
          item = (keyword_t*) g_ptr_array_index (array, index);
          if (item->column && (strcmp (item->column, "rows") == 0))
            return 0;
        }
    }

  if (keyword->column
      && (strcmp (keyword->column, "apply_overrides") == 0))
    {
      int index;

      index = array->len;
      while (index--)
        {
          keyword_t *item;
          item = (keyword_t*) g_ptr_array_index (array, index);
          if (item->column && (strcmp (item->column, "apply_overrides") == 0))
            return 0;
        }
    }

  if (keyword->column
      && (strcmp (keyword->column, "delta_states") == 0))
    {
      int index;

      index = array->len;
      while (index--)
        {
          keyword_t *item;
          item = (keyword_t*) g_ptr_array_index (array, index);
          if (item->column && (strcmp (item->column, "delta_states") == 0))
            return 0;
        }
    }

  if (keyword->column
      && (strcmp (keyword->column, "levels") == 0))
    {
      int index;

      index = array->len;
      while (index--)
        {
          keyword_t *item;
          item = (keyword_t*) g_ptr_array_index (array, index);
          if (item->column && (strcmp (item->column, "levels") == 0))
            return 0;
        }
    }

  if (keyword->column
      && (strcmp (keyword->column, "min_qod") == 0))
    {
      int index;

      index = array->len;
      while (index--)
        {
          keyword_t *item;
          item = (keyword_t*) g_ptr_array_index (array, index);
          if (item->column && (strcmp (item->column, "min_qod") == 0))
            return 0;
        }
    }

  if (keyword->column
      && (strcmp (keyword->column, "notes") == 0))
    {
      int index;

      index = array->len;
      while (index--)
        {
          keyword_t *item;
          item = (keyword_t*) g_ptr_array_index (array, index);
          if (item->column && (strcmp (item->column, "notes") == 0))
            return 0;
        }
    }

  if (keyword->column
      && (strcmp (keyword->column, "overrides") == 0))
    {
      int index;

      index = array->len;
      while (index--)
        {
          keyword_t *item;
          item = (keyword_t*) g_ptr_array_index (array, index);
          if (item->column && (strcmp (item->column, "overrides") == 0))
            return 0;
        }
    }

  if (keyword->column
      && (strcmp (keyword->column, "result_hosts_only") == 0))
    {
      int index;

      index = array->len;
      while (index--)
        {
          keyword_t *item;
          item = (keyword_t*) g_ptr_array_index (array, index);
          if (item->column && (strcmp (item->column, "result_hosts_only") == 0))
            return 0;
        }
    }

  if (keyword->column
      && (strcmp (keyword->column, "timezone") == 0))
    {
      int index;

      index = array->len;
      while (index--)
        {
          keyword_t *item;
          item = (keyword_t*) g_ptr_array_index (array, index);
          if (item->column && (strcmp (item->column, "timezone") == 0))
            return 0;
        }
    }

  return 1;
}

/**
 * @brief Free a split filter.
 *
 * @param[in]  split  Split filter.
 */
void
filter_free (array_t *split)
{
  keyword_t **point;
  for (point = (keyword_t**) split->pdata; *point; point++)
    keyword_free (*point);
  array_free (split);
}

/**
 * @brief Ensure filter parts contains the special keywords.
 *
 * @param[in]  parts         Array of keyword strings.
 * @param[in]  given_filter  Filter term.
 */
static void
split_filter_add_specials (array_t *parts, const gchar* given_filter)
{
  int index, first, max, sort;
  keyword_t *keyword;

  index = parts->len;
  first = max = sort = 0;
  while (index--)
    {
      keyword_t *item;
      item = (keyword_t*) g_ptr_array_index (parts, index);
      if (item->column && (strcmp (item->column, "first") == 0))
        first = 1;
      else if (item->column && (strcmp (item->column, "rows") == 0))
        max = 1;
      else if (item->column
               && ((strcmp (item->column, "sort") == 0)
                   || (strcmp (item->column, "sort-reverse") == 0)))
        sort = 1;
    }

  if (first == 0)
    {
      keyword = g_malloc0 (sizeof (keyword_t));
      keyword->column = g_strdup ("first");
      keyword->string = g_strdup ("1");
      keyword->type = KEYWORD_TYPE_STRING;
      keyword->relation = KEYWORD_RELATION_COLUMN_EQUAL;
      array_add (parts, keyword);
    }

  if (max == 0)
    {
      keyword = g_malloc0 (sizeof (keyword_t));
      keyword->column = g_strdup ("rows");
      keyword->string = g_strdup ("-2");
      keyword->type = KEYWORD_TYPE_STRING;
      keyword->relation = KEYWORD_RELATION_COLUMN_EQUAL;
      array_add (parts, keyword);
    }

  if (table_order_if_sort_not_specified == 0 && sort == 0)
    {
      keyword = g_malloc0 (sizeof (keyword_t));
      keyword->column = g_strdup ("sort");
      keyword->string = g_strdup ("name");
      keyword->type = KEYWORD_TYPE_STRING;
      keyword->relation = KEYWORD_RELATION_COLUMN_EQUAL;
      array_add (parts, keyword);
    }
}

/**
 * @brief Split the filter term into parts.
 *
 * @param[in]  given_filter  Filter term.
 *
 * @return Array of strings, the parts.
 */
array_t *
split_filter (const gchar* given_filter)
{
  int in_quote, between;
  array_t *parts;
  const gchar *current_part, *filter;
  keyword_t *keyword;

  assert (given_filter);

  /* Collect the filter terms in an array. */

  filter = given_filter;
  parts = make_array ();
  in_quote = 0;
  between = 1;
  keyword = NULL;
  current_part = filter;  /* To silence compiler warning. */
  while (*filter)
    {
      switch (*filter)
        {
          case '=':
          case '~':
            if (between)
              {
                /* Empty index.  Start a part. */
                keyword = g_malloc0 (sizeof (keyword_t));
                if (*filter == '=')
                  keyword->equal = 1;
                else
                  keyword->approx = 1;
                current_part = filter + 1;
                between = 0;
                break;
              }
          case ':':
          case '>':
          case '<':
            if (between)
              {
                /* Empty index.  Start a part. */
                keyword = g_malloc0 (sizeof (keyword_t));
                current_part = filter;
                between = 0;
                break;
              }
            if (in_quote)
              break;
            /* End of an index. */
            if (keyword == NULL)
              {
                assert (0);
                break;
              }
            if (keyword->column)
              /* Already had an index char. */
              break;
            if (filter <= (current_part - 1))
              {
                assert (0);
                break;
              }
            keyword->column = g_strndup (current_part,
                                         filter - current_part);
            current_part = filter + 1;
            keyword->relation = parse_column_relation(*filter);
            break;

          case ' ':
          case '\t':
          case '\n':
          case '\r':
            if (in_quote || between)
              break;
            /* End of a part. */
            if (keyword == NULL)
              {
                assert (0);
                break;
              }
            keyword->string = g_strndup (current_part, filter - current_part);
            parse_keyword (keyword);
            cleanup_keyword (keyword);
            if (keyword_applies (parts, keyword))
              array_add (parts, keyword);
            keyword = NULL;
            between = 1;
            break;

          case '"':
            if (in_quote)
              {
                /* End of a quoted part. */
                if (keyword == NULL)
                  {
                    assert (0);
                    break;
                  }
                keyword->quoted = 1;
                keyword->string = g_strndup (current_part,
                                             filter - current_part);
                parse_keyword (keyword);
                cleanup_keyword (keyword);
                if (keyword_applies (parts, keyword))
                  array_add (parts, keyword);
                keyword = NULL;
                in_quote = 0;
                between = 1;
              }
            else if (between)
              {
                /* Start of a quoted part. */
                keyword = g_malloc0 (sizeof (keyword_t));
                in_quote = 1;
                current_part = filter + 1;
                between = 0;
              }
            else if (keyword->column && filter == current_part)
              {
                /* A quoted index. */
                in_quote = 1;
                current_part++;
              }
            else if ((keyword->equal || keyword->approx)
                     && filter == current_part)
              {
                /* A quoted exact term, like ="abc"
                 * or a prefixed approximate term, like ~"abc". */
                in_quote = 1;
                current_part++;
              }
            /* Else just a quote in a keyword, like ab"cd. */
            break;

          default:
            if (between)
              {
                /* Start of a part. */
                keyword = g_malloc0 (sizeof (keyword_t));
                current_part = filter;
                between = 0;
              }
            break;
        }
      filter++;
    }
  if (between == 0)
    {
      if (keyword == NULL)
        assert (0);
      else
        {
          keyword->quoted = in_quote;
          keyword->string = g_strdup (current_part);
          parse_keyword (keyword);
          cleanup_keyword (keyword);
          if (keyword_applies (parts, keyword))
            array_add (parts, keyword);
          keyword = NULL;
        }
    }
  assert (keyword == NULL);

  /* Make sure the special keywords appear in the array. */

  split_filter_add_specials (parts, given_filter);

  array_add (parts, NULL);

  return parts;
}

/**
 * @brief Return the term of a filter.
 *
 * @param[in]  uuid  Filter UUID.
 *
 * @return Newly allocated term if available, else NULL.
 */
gchar*
filter_term (const char *uuid)
{
  assert (filter_term_internal);
  return filter_term_internal (uuid);
}

/**
 * @brief Return the value of a column keyword of a filter term.
 *
 * @param[in]  term    Filter term.
 * @param[in]  column  Column name.
 *
 * @return Value of column keyword if one exists, else NULL.
 */
gchar*
filter_term_value (const char *term, const char *column)
{
  keyword_t **point;
  array_t *split;

  if (term == NULL)
    return NULL;

  split = split_filter (term);
  point = (keyword_t**) split->pdata;
  while (*point)
    {
      keyword_t *keyword;

      keyword = *point;
      if (keyword->column
          && ((strcasecmp (keyword->column, column) == 0)
              || (keyword->column[0] == '_'
                  && (strcasecmp (keyword->column + 1, column) == 0))))
        {
          gchar *ret = g_strdup (keyword->string);
          filter_free (split);
          return ret;
        }
      point++;
    }
  filter_free (split);
  return NULL;
}

/**
 * @brief Return the value of the apply_overrides keyword of a filter term.
 *
 * @param[in]  term    Filter term.
 *
 * @return Value of apply_overrides if it exists, else APPLY_OVERRIDES_DEFAULT.
 */
int
filter_term_apply_overrides (const char *term)
{
  if (term)
    {
      int ret;
      gchar *apply_overrides_str;

      apply_overrides_str = filter_term_value (term, "apply_overrides");
      ret = apply_overrides_str
              ? (strcmp (apply_overrides_str, "0") ? 1 : 0)
              : APPLY_OVERRIDES_DEFAULT;

      g_free (apply_overrides_str);
      return ret;
    }
  else
    return APPLY_OVERRIDES_DEFAULT;
}

/**
 * @brief Return the value of the min_qod keyword of a filter term.
 *
 * @param[in]  term    Filter term.
 *
 * @return Value of min_qod if it exists, else MIN_QOD_DEFAULT.
 */
int
filter_term_min_qod (const char *term)
{
  if (term)
    {
      int ret;
      gchar *min_qod_str;

      min_qod_str = filter_term_value (term, "min_qod");
      ret = (min_qod_str && strcmp (min_qod_str, ""))
              ? atoi (min_qod_str) : MIN_QOD_DEFAULT;

      g_free (min_qod_str);
      return ret;
    }
  else
    return MIN_QOD_DEFAULT;
}

/**
 * @brief Initialize the filter utility functions.
 */
void
init_manage_filter_utils_funcs (filter_term_func filter_term_f)
{
  filter_term_internal = filter_term_f;
}
