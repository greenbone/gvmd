/* Copyright (C) 2009-2022 Greenbone AG
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

/**
 * @file
 * @brief GVM management layer: SecInfo
 *
 * The SecInfo parts of the GVM management layer.
 */

/**
 * @brief Enable extra GNU functions.
 */
#define _GNU_SOURCE

#include "debug_utils.h"
#include "manage_sql.h"
#include "manage_sql_copy.h"
#include "manage_sql_secinfo.h"
#include "sql.h"
#include "utils.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <ftw.h>
#include <glib/gstdio.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <cjson/cJSON.h>
#include <gvm/base/gvm_sentry.h>
#include <bsd/unistd.h>
#include <gvm/util/compressutils.h>
#include <gvm/util/cpeutils.h>
#include <gvm/util/fileutils.h>
#include <gvm/util/jsonpull.h>
#include <gvm/util/xmlutils.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"


/* Static variables. */

/**
 * @brief Maximum number of rows in a CPEs INSERT.
 */
#define CPE_MAX_CHUNK_SIZE 10000

/**
 * @brief Query size for affected products updates.
 */
static int affected_products_query_size = AFFECTED_PRODUCTS_QUERY_SIZE_DEFAULT;

/**
 * @brief Commit size for updates.
 */
static int secinfo_commit_size = SECINFO_COMMIT_SIZE_DEFAULT;

/**
 * @brief Whether to prefer faster SQL with less checks for non-incremental
 *        SecInfo updates.
 */
static int secinfo_fast_init = SECINFO_FAST_INIT_DEFAULT;

/**
 * @brief Maximum number of rows in a EPSS INSERT.
 */
#define EPSS_MAX_CHUNK_SIZE 10000


/* Headers. */

void
manage_db_remove (const gchar *);

int
manage_db_init (const gchar *);

int
manage_db_init_indexes (const gchar *);

int
manage_db_add_constraints (const gchar *);

static int
sync_cert ();

static int
update_scap (gboolean);


/* Helpers. */

/**
 * @brief Get SQL quoted version of element's text.
 *
 * @param[in]  element  Element.
 *
 * @return Freshly allocated quoted text.
 */
static gchar *
sql_quote_element_text (element_t element)
{
  if (element)
    {
      gchar *quoted, *text;

      text = element_text (element);
      quoted = sql_quote (text);
      g_free (text);
      return quoted;
    }
  return g_strdup ("");
}

/**
 * @brief Get ISO time from element's text.
 *
 * @param[in]  element  Element.
 *
 * @return Seconds since epoch.  0 on error.
 */
static int
parse_iso_time_element_text (element_t element)
{
  if (element)
    {
      int ret;
      gchar *text;

      text = element_text (element);
      ret = parse_iso_time (text);
      g_free (text);
      return ret;
    }
  return 0;
}

/**
 * @brief Replace text in a string.
 *
 * @param[in]  string  String to replace in.
 * @param[in]  to      Replacement text.
 *
 * @return Freshly allocated string with replacements.
 */
static gchar *
string_replace (const gchar *string, const gchar *to, ...)
{
  va_list ap;
  const gchar *from;
  gchar *ret;

  ret = g_strdup (string);
  va_start (ap, to);
  while ((from = va_arg (ap, const gchar *)))
    {
      gchar **split;
      split = g_strsplit (ret, from, 0);
      g_free (ret);
      ret = g_strjoinv ("~", split);
      g_strfreev (split);
    }
  va_end (ap);
  return ret;
}

/**
 * @brief Increment transaction size, commit and reset at secinfo_commit_size.
 *
 * @param[in,out] current_size Pointer to current size to increment and compare.
 */
inline static void
increment_transaction_size (int* current_size)
{
  if (secinfo_commit_size && (++(*current_size) > secinfo_commit_size))
    {
      *current_size = 0;
      sql_commit ();
      sql_begin_immediate ();
    }
}

/* Helper: buffer structure for INSERTs. */

/**
 * @brief Get the SQL buffer size threshold converted from MiB to bytes.
 *
 * @return Number of bytes.
 */
int
setting_secinfo_sql_buffer_threshold_bytes ()
{
  int threshold;

  setting_value_int (SETTING_UUID_SECINFO_SQL_BUFFER_THRESHOLD, &threshold);

  return threshold * 1048576;
}

/**
 * @brief Buffer for INSERT statements.
 */
typedef struct
{
  array_t *statements;     ///< Buffered statements.
  GString *statement;      ///< Current statement.
  int statements_size;     ///< Sum of lengths of all statements buffered.
  int max_statements_size; ///< Auto-run at this statement_size, 0 for never.
  int current_chunk_size;  ///< Number of rows in current statement.
  int max_chunk_size;      ///< Max number of rows per INSERT.
  gchar *open_sql;         ///< SQL to open each statement.
  gchar *close_sql;        ///< SQL to close each statement.
} inserts_t;

static void
inserts_run (inserts_t *, gboolean);

/**
 * @brief Check size of current statement.
 *
 * @param[in]  inserts         Insert buffer.
 * @param[in]  max_chunk_size  Max chunk size per statement.
 * @param[in]  max_statements_size Automatically run at this statements size.
 * @param[in]  open_sql        SQL to to start each statement.
 * @param[in]  close_sql       SQL to append to the end of each statement.
 */
static void
inserts_init (inserts_t *inserts, int max_chunk_size, int max_statements_size,
              const gchar *open_sql, const gchar *close_sql)
{
  inserts->statements = make_array ();
  inserts->statement = NULL;
  inserts->statements_size = 0;
  inserts->max_statements_size = max_statements_size;
  inserts->current_chunk_size = 0;
  inserts->max_chunk_size = max_chunk_size;
  inserts->open_sql = open_sql ? g_strdup (open_sql) : NULL;
  inserts->close_sql = close_sql ? g_strdup (close_sql) : NULL;
}

/**
 * @brief Close the current statement.
 *
 * @param[in]  inserts  Insert buffer.
 */
static void
inserts_statement_close (inserts_t *inserts)
{
  if (inserts->statement)
    {
      if (inserts->close_sql)
        g_string_append (inserts->statement, inserts->close_sql);
      g_string_append (inserts->statement, ";");
    }
}

/**
 * @brief Check size of current statement.
 *
 * @param[in]  inserts  Insert buffer.
 *
 * @return Whether this is the first value in the statement.
 */
static int
inserts_check_size (inserts_t *inserts)
{
  int first;

  first = 0;

  if (inserts->statement
      && inserts->current_chunk_size >= inserts->max_chunk_size)
    {
      inserts_statement_close (inserts);
      array_add (inserts->statements, inserts->statement);
      inserts->statements_size += inserts->statement->len;
      inserts->statement = NULL;
      inserts->current_chunk_size = 0;

      if (inserts->max_statements_size
          && inserts-> statements_size >= inserts->max_statements_size)
        {
          inserts_run (inserts, FALSE);
        }
    }

  if (inserts->statement == NULL)
    {
      inserts->statement
        = g_string_new (inserts->open_sql ? inserts->open_sql : "");
      first = 1;
    }

  return first;
}

/**
 * @brief Free only the statements in an inserts buffer so it can be reused.
 *
 * @param[in]  inserts  Insert buffer.
 */
static void
inserts_free_statements (inserts_t *inserts)
{
  int index;

  for (index = 0; index < inserts->statements->len; index++)
    {
      g_string_free (g_ptr_array_index (inserts->statements, index), TRUE);
      inserts->statements->pdata[index] = NULL;
    }
  g_ptr_array_set_size (inserts->statements, 0);
  inserts->statements_size = 0;
}

/**
 * @brief Free all fields in an inserts buffer.
 *
 * @param[in]  inserts  Insert buffer.
 */
static void
inserts_free (inserts_t *inserts)
{
  int index;

  for (index = 0; index < inserts->statements->len; index++)
    g_string_free (g_ptr_array_index (inserts->statements, index), TRUE);
  g_ptr_array_free (inserts->statements, TRUE);
  g_free (inserts->open_sql);
  g_free (inserts->close_sql);
  bzero (inserts, sizeof (*inserts));
}

/**
 * @brief Run the INSERT SQL, freeing the buffers.
 *
 * @param[in]  inserts  Insert buffer.
 * @param[in]  finalize Whether to free the whole inserts buffer afterwards.
 */
static void
inserts_run (inserts_t *inserts, gboolean finalize)
{
  guint index;

  if (inserts->statement)
    {
      inserts_statement_close (inserts);
      array_add (inserts->statements, inserts->statement);
      inserts->statement = NULL;
      inserts->current_chunk_size = 0;
    }

  for (index = 0; index < inserts->statements->len; index++)
    {
      GString *statement;

      statement = g_ptr_array_index (inserts->statements, index);
      sql ("%s", statement->str);
    }

  if (finalize)
    inserts_free (inserts);
  else
    inserts_free_statements (inserts);
}

/**
 * @brief Get the string value for a specified key from a JSON object.
 *
 * @param[in]  object  JSON object
 * @param[in]  key     The key of the string in the JSON object.
 *
 * @return The string out of the JSON object with key "key", if any.
 *         NULL otherwise.
 */
static char*
json_object_item_string (cJSON *object, char *key)
{
  cJSON *value_json;

  value_json = cJSON_GetObjectItemCaseSensitive(object, key);
  if (cJSON_IsString(value_json))
    return value_json->valuestring;
  return NULL;
}

/**
 * @brief Get the double value for a specified key from a JSON object.
 *
 * @param[in]  object    JSON object
 * @param[in]  key       The key of the double value in the JSON object.
 * @param[in]  fallback  The fallback value if the double value is not
 *                       available.
 *
 * @return The double value out of the JSON object with key "key", if any.
 *         The fallback value otherwise.
 */
static double
json_object_item_double (cJSON *object, char *key, double fallback)
{
  cJSON *value_json;

  value_json = cJSON_GetObjectItemCaseSensitive(object, key);
  if (cJSON_IsNumber(value_json))
    return value_json->valuedouble;
  return fallback;
}

/**
 * @brief Get the boolean value for a specified key from a JSON object.
 *
 * @param[in]  object    JSON object
 * @param[in]  key       The key of the boolean value in the JSON object.
 * @param[in]  fallback  The fallback value if the boolean value is not
 *                       available.
 *
 * @return The boolean value out of the JSON object with key "key", if any.
 *         The fallback value otherwise.
 */
static int
json_object_item_boolean (cJSON *object, char *key, int fallback)
{
  cJSON *value_json;

  value_json = cJSON_GetObjectItemCaseSensitive(object, key);
  if (cJSON_IsTrue(value_json))
    return 1;
  else if (cJSON_IsFalse(value_json))
    return 0;
  return fallback;
}


/* CPE data. */

/**
 * @brief Gets the SELECT columns for CPE iterators and counts.
 *
 * @return The SELECT columns.
 */
static const column_t*
cpe_info_select_columns ()
{
  static column_t columns[] = CPE_INFO_ITERATOR_COLUMNS;
  return columns;
}

/**
 * @brief Gets the filter columns for CPE iterators and counts.
 *
 * @return The filter columns.
 */
static const char **
cpe_info_filter_columns ()
{
  static const char *filter_columns[] = CPE_INFO_ITERATOR_FILTER_COLUMNS;
  return filter_columns;
}

/**
 * @brief Count number of cpe.
 *
 * @param[in]  get  GET params.
 *
 * @return Total number of cpes in filtered set.
 */
int
cpe_info_count (const get_data_t *get)
{
  static const char *filter_columns[] = CPE_INFO_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = CPE_INFO_ITERATOR_COLUMNS;
  return count ("cpe", get, columns, NULL, filter_columns, 0, 0, 0, FALSE);
}

/**
 * @brief Initialise a info iterator.
 *
 * @param[in]  iterator        Iterator.
 * @param[in]  get             GET data.
 * @param[in]  name            Name of the info
 *
 * @return 0 success, 1 failed to find target, 2 failed to find filter,
 *         -1 error.
 */
int
init_cpe_info_iterator (iterator_t* iterator, get_data_t *get, const char *name)
{
  static const char *filter_columns[] = CPE_INFO_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = CPE_INFO_ITERATOR_COLUMNS;
  gchar *clause = NULL;
  int ret;

  if (get->id)
    {
      gchar *quoted = sql_quote (get->id);
      clause = g_strdup_printf (" AND uuid = '%s'", quoted);
      g_free (quoted);
      /* The entry is specified by ID, so filtering just gets in the way. */
      g_free (get->filter);
      get->filter = NULL;
    }
  else if (name)
    {
      gchar *quoted = sql_quote (name);
      clause = g_strdup_printf (" AND name = '%s'", quoted);
      g_free (quoted);
      /* The entry is specified by name, so filtering just gets in the way. */
      g_free (get->filter);
      get->filter = NULL;
    }
  ret = init_get_iterator (iterator,
                           "cpe",
                           get,
                           columns,
                           NULL,
                           filter_columns,
                           0,
                           NULL,
                           clause,
                           FALSE);
  g_free (clause);
  return ret;
}

/**
 * @brief Initialise a CPE info iterator not limited to a name.
 *
 * @param[in]  iterator        Iterator.
 * @param[in]  get             GET data.
 *
 * @return 0 success, 1 failed to find target, 2 failed to find filter,
 *         -1 error.
 */
int
init_cpe_info_iterator_all (iterator_t* iterator, get_data_t *get)
{
  return init_cpe_info_iterator (iterator, get, NULL);
}

/**
 * @brief Get the title from a CPE iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The Title of the CPE, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (cpe_info_iterator_title, GET_ITERATOR_COLUMN_COUNT);

/**
 * @brief Get the deprecation status from a CPE iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The deprecation status of the CPE, or NULL if iteration is complete.
 *         Freed by cleanup_iterator.
 */
DEF_ACCESS (cpe_info_iterator_deprecated, GET_ITERATOR_COLUMN_COUNT + 1);

/**
 * @brief Get the highest severity Score of all CVE's referencing this cpe.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The highest severity score of the CPE,
 *         or NULL if iteration is complete. Freed by cleanup_iterator.
 */
DEF_ACCESS (cpe_info_iterator_severity, GET_ITERATOR_COLUMN_COUNT + 2);

/**
 * @brief Get the Number of CVE's referencing this cpe from a CPE iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The Number of references to the CPE, or NULL if iteration is
 *         complete. Freed by cleanup_iterator.
 */
DEF_ACCESS (cpe_info_iterator_cve_refs, GET_ITERATOR_COLUMN_COUNT + 3);

/**
 * @brief Get the NVD assigned cpeNameId for this CPE.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The NVD ID of this CPE, or NULL if iteration is
 *         complete. Freed by cleanup_iterator.
 */
DEF_ACCESS (cpe_info_iterator_cpe_name_id, GET_ITERATOR_COLUMN_COUNT + 4);

/**
 * @brief Get the XML details / raw data for a given CPE ID.
 *
 * @param[in]  cpe_id  ID of the CPE to get the raw XML of.
 *
 * @return newly allocated XML details string
 */
char *
cpe_details_xml (const char *cpe_id) {
  gchar *quoted_cpe_id, *details_xml;
  quoted_cpe_id = sql_quote (cpe_id);
  details_xml = sql_string ("SELECT details_xml"
                            " FROM scap.cpe_details"
                            " WHERE cpe_id = '%s'",
                            cpe_id);
  g_free (quoted_cpe_id);
  return details_xml;
}

/**
 * @brief Initialise a CPE refrerences iterator.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  cpe         CPE to get references of.
 */
void
init_cpe_reference_iterator (iterator_t *iterator, const char *cpe)
{
  gchar *quoted_cpe;
  quoted_cpe = sql_quote (cpe);
  init_iterator (iterator,
                 "SELECT ref, type FROM cpe_refs"
                 " WHERE cpe = (SELECT id FROM cpes WHERE uuid = '%s');",
                 quoted_cpe);
  g_free (quoted_cpe);
}

/**
 * @brief Get the reference URL from CPE reference iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The reference URL, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (cpe_reference_iterator_href, 0);

/**
 * @brief Get the reference type from CPE reference iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The reference type, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (cpe_reference_iterator_type, 1);


/* CVE data. */

/**
 * @brief Gets the SELECT columns for CVE iterators and counts.
 *
 * @return The SELECT columns.
 */
static const column_t*
cve_info_select_columns ()
{
  static column_t columns[] = CVE_INFO_ITERATOR_COLUMNS;
  return columns;
}

/**
 * @brief Gets the filter columns for CVE iterators and counts.
 *
 * @return The filter columns.
 */
static const char **
cve_info_filter_columns ()
{
  static const char *filter_columns[] = CVE_INFO_ITERATOR_FILTER_COLUMNS;
  return filter_columns;
}

/**
 * @brief Initialise an iterator listing CPEs another CPE is deprecated_by.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  cpe         CPE to get which other CPEs it's deprecated by.
 */
void
init_cpe_deprecated_by_iterator (iterator_t *iterator, const char *cpe)
{
  gchar *quoted_cpe;
  assert (cpe);
  quoted_cpe = sql_quote (cpe);
  init_iterator (iterator,
                 "SELECT deprecated_by FROM cpes_deprecated_by"
                 " WHERE cpe = '%s'"
                 " ORDER BY deprecated_by;",
                 quoted_cpe);
  g_free (quoted_cpe);
}

DEF_ACCESS (cpe_deprecated_by_iterator_deprecated_by, 0);

/**
 * @brief Initialise an CVE iterator, for CVEs reported for a certain CPE.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  cve         CVE.
 * @param[in]  ascending   Whether to sort ascending or descending.
 * @param[in]  sort_field  Field to sort on, or NULL for "id".
 */
void
init_cpe_cve_iterator (iterator_t *iterator, const char *cve, int ascending,
                       const char *sort_field)
{
  gchar *quoted_cpe;
  assert (cve);
  quoted_cpe = sql_quote (cve);
  init_iterator (iterator,
                 "SELECT id, name, severity FROM cves"
                 " WHERE id IN"
                 " (SELECT cve FROM affected_products"
                 "  WHERE cpe ="
                 "  (SELECT id FROM cpes WHERE name = '%s'))"
                 " ORDER BY %s %s;",
                 quoted_cpe,
                 sort_field ? sort_field : "severity DESC, name",
                 ascending ? "ASC" : "DESC");
  g_free (quoted_cpe);
}

/**
 * @brief Get the name from a CVE iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The name of the CVE, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (cve_iterator_name, 1);

/**
 * @brief Get the severity score from a CVE iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The CVSS score of the CVE,
 *         or NULL if iteration is complete.  Freed by cleanup_iterator.
 */
DEF_ACCESS (cve_iterator_cvss_score, 2);

/**
 * @brief Get the CVSS score for a CVE.
 *
 * @param[in]  cve  CVE-ID of the CVE to get the score of.
 *
 * @return The CVSS score of the CVE.
 */
gchar *
cve_cvss_base (const gchar *cve)
{
  gchar *quoted_cve, *ret;
  quoted_cve = sql_quote (cve);
  ret = sql_string ("SELECT severity FROM cves WHERE name = '%s'",
                    quoted_cve);
  g_free (quoted_cve);
  return ret;
}

/**
 * @brief Count number of cve.
 *
 * @param[in]  get  GET params.
 *
 * @return Total number of cpes in filtered set.
 */
int
cve_info_count (const get_data_t *get)
{
  static const char *filter_columns[] = CVE_INFO_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = CVE_INFO_ITERATOR_COLUMNS;
  return count ("cve", get, columns, NULL, filter_columns, 0,
                " LEFT JOIN epss_scores ON cve = cves.uuid",
                0, FALSE);
}

/**
 * @brief Initialise a info iterator.
 *
 * @param[in]  iterator        Iterator.
 * @param[in]  get             GET data.
 * @param[in]  name            Name of the info
 *
 * @return 0 success, 1 failed to find target, 2 failed to find filter,
 *         -1 error.
 */
int
init_cve_info_iterator (iterator_t* iterator, get_data_t *get, const char *name)
{
  static const char *filter_columns[] = CVE_INFO_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = CVE_INFO_ITERATOR_COLUMNS;
  gchar *clause = NULL;
  int ret;

  if (get->id)
    {
      gchar *quoted = sql_quote (get->id);
      clause = g_strdup_printf (" AND uuid = '%s'", quoted);
      g_free (quoted);
      /* The entry is specified by ID, so filtering just gets in the way. */
      g_free (get->filter);
      get->filter = NULL;
    }
  else if (name)
    {
      gchar *quoted = sql_quote (name);
      clause = g_strdup_printf (" AND name = '%s'", quoted);
      g_free (quoted);
      /* The entry is specified by name, so filtering just gets in the way. */
      g_free (get->filter);
      get->filter = NULL;
    }
  ret = init_get_iterator (iterator,
                           "cve",
                           get,
                           columns,
                           NULL,
                           filter_columns,
                           0,
                           " LEFT JOIN epss_scores ON cve = cves.uuid",
                           clause,
                           FALSE);
  g_free (clause);
  return ret;
}

/**
 * @brief Initialise a CVE info iterator not limited to a name.
 *
 * @param[in]  iterator        Iterator.
 * @param[in]  get             GET data.
 *
 * @return 0 success, 1 failed to find target, 2 failed to find filter,
 *         -1 error.
 */
int
init_cve_info_iterator_all (iterator_t* iterator, get_data_t *get)
{
  return init_cve_info_iterator (iterator, get, NULL);
}

/**
 * @brief Get the CVSS attack vector for this CVE.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The CVSS attack vector of this CVE, or NULL if iteration is
 *         complete. Freed by cleanup_iterator.
 */
DEF_ACCESS (cve_info_iterator_vector, GET_ITERATOR_COLUMN_COUNT);

/**
 * @brief Get the CVSS attack complexity for this CVE.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The CVSS attack complexity of this CVE, or NULL if iteration is
 *         complete. Freed by cleanup_iterator.
 */
DEF_ACCESS (cve_info_iterator_complexity, GET_ITERATOR_COLUMN_COUNT + 1);

/**
 * @brief Get a space separated list of CPEs affected by this CVE.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return A space separated list of CPEs or NULL if iteration is
 *         complete. Freed by cleanup_iterator.
 */
DEF_ACCESS (cve_info_iterator_products, GET_ITERATOR_COLUMN_COUNT + 1);

/**
 * @brief Get the severity score for this CVE.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The severity score of this CVE, or NULL if iteration is complete.
 *         Freed by cleanup_iterator.
 */
DEF_ACCESS (cve_info_iterator_severity, GET_ITERATOR_COLUMN_COUNT + 2);

/**
 * @brief Get the Summary for this CVE.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The Summary of this CVE, or NULL if iteration is
 *         complete. Freed by cleanup_iterator.
 */
DEF_ACCESS (cve_info_iterator_description, GET_ITERATOR_COLUMN_COUNT + 3);

/**
 * @brief Get the EPSS score for this CVE.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The EPSS score of this CVE, or 0.0 if iteration is
 *         complete.
 */
double
cve_info_iterator_epss_score (iterator_t *iterator)
{
  if (iterator->done)
    return 0.0;
  return iterator_double (iterator, GET_ITERATOR_COLUMN_COUNT + 5);
}

/**
 * @brief Get the EPSS percentile for this CVE.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The EPSS percentile of this CVE, or 0.0 if iteration is
 *         complete.
 */
double
cve_info_iterator_epss_percentile (iterator_t *iterator)
{
  if (iterator->done)
    return 0.0;
  return iterator_double (iterator, GET_ITERATOR_COLUMN_COUNT + 6);
}


/* CERT-Bund data. */

/**
 * @brief Gets the SELECT columns for CERT-Bund advisory iterators and counts.
 *
 * @return The SELECT columns.
 */
static const column_t*
cert_bund_adv_info_select_columns ()
{
  static column_t columns[] = CERT_BUND_ADV_INFO_ITERATOR_COLUMNS;
  return columns;
}

/**
 * @brief Gets the filter columns for CERT-Bund advisory iterators and counts.
 *
 * @return The filter columns.
 */
static const char **
cert_bund_adv_info_filter_columns ()
{
  static const char *filter_columns[]
    = CERT_BUND_ADV_INFO_ITERATOR_FILTER_COLUMNS;
  return filter_columns;
}

/**
 * @brief Initialise an CERT-Bund advisory (cert_bund_adv) info iterator.
 *
 * @param[in]  iterator        Iterator.
 * @param[in]  get             GET data.
 * @param[in]  name            Name of the info
 *
 * @return 0 success, 1 failed to find target, 2 failed to find filter,
 *         -1 error.
 */
int
init_cert_bund_adv_info_iterator (iterator_t* iterator, get_data_t *get,
                                  const char *name)
{
  static const char *filter_columns[] =
      CERT_BUND_ADV_INFO_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = CERT_BUND_ADV_INFO_ITERATOR_COLUMNS;
  gchar *clause = NULL;
  int ret;

  if (get->id)
    {
      gchar *quoted = sql_quote (get->id);
      clause = g_strdup_printf (" AND uuid = '%s'", quoted);
      g_free (quoted);
      /* The entry is specified by ID, so filtering just gets in the way. */
      g_free (get->filter);
      get->filter = NULL;
    }
  else if (name)
    {
      gchar *quoted = sql_quote (name);
      clause = g_strdup_printf (" AND name = '%s'", quoted);
      g_free (quoted);
      /* The entry is specified by name, so filtering just gets in the way. */
      g_free (get->filter);
      get->filter = NULL;
    }
  ret = init_get_iterator (iterator,
                           "cert_bund_adv",
                           get,
                           columns,
                           NULL,
                           filter_columns,
                           0,
                           NULL,
                           clause,
                           FALSE);
  g_free (clause);
  return ret;
}

/**
 * @brief Initialise an CERT-Bund advisory (cert_bund_adv) info iterator not
 *        limited to a name.
 *
 * @param[in]  iterator        Iterator.
 * @param[in]  get             GET data.
 *
 * @return 0 success, 1 failed to find target, 2 failed to find filter,
 *         -1 error.
 */
int
init_cert_bund_adv_info_iterator_all (iterator_t* iterator, get_data_t *get)
{
  return init_cert_bund_adv_info_iterator (iterator, get, NULL);
}

/**
 * @brief Count number of cert_bund_adv.
 *
 * @param[in]  get  GET params.
 *
 * @return Total number of CERT-Bund advisories in filtered set.
 */
int
cert_bund_adv_info_count (const get_data_t *get)
{
  static const char *filter_columns[] =
                      CERT_BUND_ADV_INFO_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = CERT_BUND_ADV_INFO_ITERATOR_COLUMNS;
  return count ("cert_bund_adv", get, columns, NULL, filter_columns,
                0, 0, 0, FALSE);
}

/**
 * @brief Get the title from an CERT_BUND_ADV iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The title of the CERT-Bund advisory,
 *         or NULL if iteration is complete.
 *         Freed by cleanup_iterator.
 */
DEF_ACCESS (cert_bund_adv_info_iterator_title,
            GET_ITERATOR_COLUMN_COUNT);

/**
 * @brief Get the summary from an CERT_BUND_ADV iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The summary of the CERT-Bund advisory,
 *         or NULL if iteration is complete.
 *         Freed by cleanup_iterator.
 */
DEF_ACCESS (cert_bund_adv_info_iterator_summary,
            GET_ITERATOR_COLUMN_COUNT + 1);

/**
 * @brief Get the number of cves from an CERT_BUND_ADV iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The number of CVEs referenced in the CERT-Bund advisory,
 *         or NULL if iteration is complete.
 *         Freed by cleanup_iterator.
 */
DEF_ACCESS (cert_bund_adv_info_iterator_cve_refs,
            GET_ITERATOR_COLUMN_COUNT + 2);

/**
 * @brief Get the maximum severity score from an CERT_BUND_ADV iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The maximum severity score of the CVEs referenced
 *         in the CERT-Bund advisory, or NULL if iteration is complete.
 *         Freed by cleanup_iterator.
 */
DEF_ACCESS (cert_bund_adv_info_iterator_severity,
            GET_ITERATOR_COLUMN_COUNT + 3);

/**
 * @brief Initialise CVE iterator, for CVEs referenced by a CERT-Bund advisory.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  cve         Name of the CVE.
 * @param[in]  ascending   Whether to sort ascending or descending.
 * @param[in]  sort_field  Field to sort on, or NULL for "id".
 */
void
init_cve_cert_bund_adv_iterator (iterator_t *iterator, const char *cve,
                                int ascending, const char *sort_field)
{
  static column_t select_columns[] = CERT_BUND_ADV_INFO_ITERATOR_COLUMNS;
  gchar *columns;

  assert (cve);

  columns = columns_build_select (select_columns);
  init_iterator (iterator,
                 "SELECT %s"
                 " FROM cert_bund_advs"
                 " WHERE id IN (SELECT adv_id FROM cert_bund_cves"
                 "              WHERE cve_name = '%s')"
                 " ORDER BY %s %s;",
                 columns,
                 cve,
                 sort_field ? sort_field : "name",
                 ascending ? "ASC" : "DESC");
  g_free (columns);
}

/**
 * @brief Initialise an CERT-Bund iterator, for advisories relevant to a NVT.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  oid         OID of the NVT.
 */
void
init_nvt_cert_bund_adv_iterator (iterator_t *iterator, const char *oid)
{
  assert (oid);

  init_iterator (iterator,
                 "SELECT name"
                 " FROM cert_bund_advs"
                 " WHERE id IN (SELECT adv_id FROM cert_bund_cves"
                 "              WHERE cve_name IN (SELECT ref_id"
                 "                                 FROM vt_refs"
                 "                                 WHERE vt_oid = '%s'"
                 "                                   AND type = 'cve'))"
                 " ORDER BY name DESC;",
                 oid);
}

/**
 * @brief Get a column value from an iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Value of the column or NULL if iteration is complete.
 */
DEF_ACCESS (nvt_cert_bund_adv_iterator_name, 0);


/* DFN-CERT data. */

/**
 * @brief Gets the SELECT columns for DFN-CERT advisory iterators and counts.
 *
 * @return The SELECT columns.
 */
static const column_t*
dfn_cert_adv_info_select_columns ()
{
  static column_t columns[] = DFN_CERT_ADV_INFO_ITERATOR_COLUMNS;
  return columns;
}

/**
 * @brief Gets the filter columns for DFN-CERT advisory iterators and counts.
 *
 * @return The filter columns.
 */
static const char **
dfn_cert_adv_info_filter_columns ()
{
  static const char *filter_columns[]
    = DFN_CERT_ADV_INFO_ITERATOR_FILTER_COLUMNS;
  return filter_columns;
}

/**
 * @brief Initialise an DFN-CERT advisory (dfn_cert_adv) info iterator.
 *
 * @param[in]  iterator        Iterator.
 * @param[in]  get             GET data.
 * @param[in]  name            Name of the info
 *
 * @return 0 success, 1 failed to find target, 2 failed to find filter,
 *         -1 error.
 */
int
init_dfn_cert_adv_info_iterator (iterator_t* iterator, get_data_t *get,
                            const char *name)
{
  static const char *filter_columns[] =
      DFN_CERT_ADV_INFO_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = DFN_CERT_ADV_INFO_ITERATOR_COLUMNS;
  gchar *clause = NULL;
  int ret;

  if (get->id)
    {
      gchar *quoted = sql_quote (get->id);
      clause = g_strdup_printf (" AND uuid = '%s'", quoted);
      g_free (quoted);
      /* The entry is specified by ID, so filtering just gets in the way. */
      g_free (get->filter);
      get->filter = NULL;
    }
  else if (name)
    {
      gchar *quoted = sql_quote (name);
      clause = g_strdup_printf (" AND name = '%s'", quoted);
      g_free (quoted);
      /* The entry is specified by name, so filtering just gets in the way. */
      g_free (get->filter);
      get->filter = NULL;
    }
  ret = init_get_iterator (iterator,
                           "dfn_cert_adv",
                           get,
                           columns,
                           NULL,
                           filter_columns,
                           0,
                           NULL,
                           clause,
                           FALSE);
  g_free (clause);
  return ret;
}

/**
 * @brief Initialise an DFN-CERT advisory (dfn_cert_adv) info iterator
 *        not limited to a name.
 *
 * @param[in]  iterator        Iterator.
 * @param[in]  get             GET data.
 *
 * @return 0 success, 1 failed to find target, 2 failed to find filter,
 *         -1 error.
 */
int
init_dfn_cert_adv_info_iterator_all (iterator_t* iterator, get_data_t *get)
{
  return init_dfn_cert_adv_info_iterator (iterator, get, NULL);
}

/**
 * @brief Count number of dfn_cert_adv.
 *
 * @param[in]  get  GET params.
 *
 * @return Total number of DFN-CERT advisories in filtered set.
 */
int
dfn_cert_adv_info_count (const get_data_t *get)
{
  static const char *filter_columns[] =
                      DFN_CERT_ADV_INFO_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = DFN_CERT_ADV_INFO_ITERATOR_COLUMNS;
  return count ("dfn_cert_adv", get, columns, NULL, filter_columns,
                0, 0, 0, FALSE);
}

/**
 * @brief Get the title from an DFN_CERT_ADV iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The title of the DFN-CERT advisory,
 *         or NULL if iteration is complete.
 *         Freed by cleanup_iterator.
 */
DEF_ACCESS (dfn_cert_adv_info_iterator_title, GET_ITERATOR_COLUMN_COUNT);

/**
 * @brief Get the summary from an DFN_CERT_ADV iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The summary of the DFN-CERT advisory,
 *         or NULL if iteration is complete.
 *         Freed by cleanup_iterator.
 */
DEF_ACCESS (dfn_cert_adv_info_iterator_summary, GET_ITERATOR_COLUMN_COUNT + 1);

/**
 * @brief Get the number of cves from an DFN_CERT_ADV iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The number of CVEs referenced in the DFN-CERT advisory,
 *         or NULL if iteration is complete.
 *         Freed by cleanup_iterator.
 */
DEF_ACCESS (dfn_cert_adv_info_iterator_cve_refs, GET_ITERATOR_COLUMN_COUNT + 2);

/**
 * @brief Get the maximum severity score from an DFN_CERT_ADV iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The maximum score of the CVEs referenced
 *         in the DFN-CERT advisory, or NULL if iteration is complete.
 *         Freed by cleanup_iterator.
 */
DEF_ACCESS (dfn_cert_adv_info_iterator_severity, GET_ITERATOR_COLUMN_COUNT + 3);

/**
 * @brief Initialise CVE iterator, for CVEs referenced by a DFN-CERT advisory.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  cve         Name of the CVE.
 * @param[in]  ascending   Whether to sort ascending or descending.
 * @param[in]  sort_field  Field to sort on, or NULL for "id".
 */
void
init_cve_dfn_cert_adv_iterator (iterator_t *iterator, const char *cve,
                                int ascending, const char *sort_field)
{
  static column_t select_columns[] = DFN_CERT_ADV_INFO_ITERATOR_COLUMNS;
  gchar *columns;

  assert (cve);

  columns = columns_build_select (select_columns);
  init_iterator (iterator,
                 "SELECT %s"
                 " FROM dfn_cert_advs"
                 " WHERE id IN (SELECT adv_id FROM dfn_cert_cves"
                 "              WHERE cve_name = '%s')"
                 " ORDER BY %s %s;",
                 columns,
                 cve,
                 sort_field ? sort_field : "name",
                 ascending ? "ASC" : "DESC");
  g_free (columns);
}

/**
 * @brief Initialise an DFN-CERT iterator, for advisories relevant to a NVT.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  oid         OID of the NVT.
 */
void
init_nvt_dfn_cert_adv_iterator (iterator_t *iterator, const char *oid)
{
  assert (oid);

  init_iterator (iterator,
                 "SELECT name"
                 " FROM dfn_cert_advs"
                 " WHERE id IN (SELECT adv_id FROM dfn_cert_cves"
                 "              WHERE cve_name IN (SELECT ref_id"
                 "                                 FROM vt_refs"
                 "                                 WHERE vt_oid = '%s'"
                 "                                   AND type = 'cve'))"
                 " ORDER BY name DESC;",
                 oid);
}

/**
 * @brief Get a column value from an iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Value of the column or NULL if iteration is complete.
 */
DEF_ACCESS (nvt_dfn_cert_adv_iterator_name, 0);


/* All SecInfo data. */

/**
 * @brief Count number of SecInfo items created or modified after a given time.
 *
 * @param[in]  get            GET params.
 * @param[in]  type           The type of SecInfo to count.
 * @param[in]  count_time     Time SecInfo must be created or modified after.
 * @param[in]  get_modified   Whether to get the modification time.
 *
 * @return Total number of items in filtered set.
 */
int
secinfo_count_after (const get_data_t *get,
                     const char *type,
                     time_t count_time,
                     gboolean get_modified)
{
  const char **filter_columns;
  const column_t *columns;
  gchar *extra_where;
  int ret;

  if (strcmp (type, "cpe") == 0)
    {
      columns = cpe_info_select_columns ();
      filter_columns = cpe_info_filter_columns ();
    }
  else if (strcmp (type, "cve") == 0)
    {
      columns = cve_info_select_columns ();
      filter_columns = cve_info_filter_columns ();
    }
  else if (strcmp (type, "cert_bund_adv") == 0)
    {
      columns = cert_bund_adv_info_select_columns ();
      filter_columns = cert_bund_adv_info_filter_columns ();
    }
  else if (strcmp (type, "dfn_cert_adv") == 0)
    {
      columns = dfn_cert_adv_info_select_columns ();
      filter_columns = dfn_cert_adv_info_filter_columns ();
    }
  else
    {
      g_warning ("%s: Unexpected type %s", __func__, type);
      return 0;
    }

  if (get_modified)
    extra_where = g_strdup_printf (" AND modification_time > %ld"
                                   " AND creation_time <= %ld",
                                   count_time,
                                   count_time);
  else
    extra_where = g_strdup_printf (" AND creation_time > %ld",
                                   count_time);

  ret = count (type, get, (column_t*) columns, NULL, filter_columns,
               0, 0, extra_where, FALSE);

  g_free (extra_where);
  return ret;
}


/* CERT update: DFN-CERT. */

/**
 * @brief Update DFN-CERT info from a single XML feed file.
 *
 * @param[in]  xml_path          XML path.
 * @param[in]  last_cert_update  Time of last CERT update.
 * @param[in]  last_dfn_update   Time of last update to a DFN.
 *
 * @return 0 nothing to do, 1 updated, -1 error.
 */
static int
update_dfn_xml (const gchar *xml_path, int last_cert_update,
                int last_dfn_update)
{
  GError *error;
  element_t element, child;
  gchar *xml, *full_path;
  gsize xml_len;
  GStatBuf state;
  int updated_dfn_cert;
  int transaction_size = 0;

  updated_dfn_cert = 0;
  g_info ("%s: %s", __func__, xml_path);

  full_path = g_build_filename (GVM_CERT_DATA_DIR, xml_path, NULL);

  if (g_stat (full_path, &state))
    {
      g_warning ("%s: Failed to stat CERT file: %s",
                 __func__,
                 strerror (errno));
      return -1;
    }

  if ((state.st_mtime - (state.st_mtime % 60)) <= last_cert_update)
    {
      g_info ("Skipping %s, file is older than last revision",
              full_path);
      g_free (full_path);
      return 0;
    }

  g_info ("Updating %s", full_path);

  error = NULL;
  g_file_get_contents (full_path, &xml, &xml_len, &error);
  if (error)
    {
      g_warning ("%s: Failed to get contents: %s",
                 __func__,
                 error->message);
      g_error_free (error);
      g_free (full_path);
      return -1;
    }

  if (parse_element (xml, &element))
    {
      g_free (xml);
      g_warning ("%s: Failed to parse element", __func__);
      g_free (full_path);
      return -1;
    }
  g_free (xml);

  sql_begin_immediate ();
  child = element_first_child (element);
  while (child)
    {
      if (strcmp (element_name (child), "entry") == 0)
        {
          element_t updated;
          gchar *updated_text;

          updated = element_child (child, "updated");
          if (updated == NULL)
            {
              g_warning ("%s: UPDATED missing", __func__);
              element_free (element);
              goto fail;
            }

          updated_text = element_text (updated);
          if (parse_iso_time (updated_text) > last_dfn_update)
            {
              element_t refnum, published, summary, title, cve;
              gchar *quoted_refnum, *quoted_title, *quoted_summary;
              int cve_refs;

              refnum = element_child (child, "dfncert:refnum");
              if (refnum == NULL)
                {
                  g_warning ("%s: REFNUM missing", __func__);
                  element_free (element);
                  g_free (updated_text);
                  goto fail;
                }

              published = element_child (child, "published");
              if (published == NULL)
                {
                  g_warning ("%s: PUBLISHED missing", __func__);
                  element_free (element);
                  g_free (updated_text);
                  goto fail;
                }

              title = element_child (child, "title");
              if (title == NULL)
                {
                  g_warning ("%s: TITLE missing", __func__);
                  element_free (element);
                  g_free (updated_text);
                  goto fail;
                }

              summary = element_child (child, "summary");
              if (summary == NULL)
                {
                  g_warning ("%s: SUMMARY missing", __func__);
                  element_free (element);
                  g_free (updated_text);
                  goto fail;
                }

              cve_refs = 0;
              cve = element_first_child (child);
              while (cve)
                {
                  if (strcmp (element_name (cve), "cve") == 0)
                    cve_refs++;
                  cve = element_next (cve);
                }

              quoted_refnum = sql_quote_element_text (refnum);
              quoted_title = sql_quote_element_text (title);
              quoted_summary = sql_quote_element_text (summary);
              sql ("INSERT INTO cert.dfn_cert_advs"
                   " (uuid, name, comment, creation_time,"
                   "  modification_time, title, summary, cve_refs)"
                   " VALUES"
                   " ('%s', '%s', '', %i, %i, '%s', '%s', %i)"
                   " ON CONFLICT (uuid) DO UPDATE"
                   " SET name = EXCLUDED.uuid,"
                   "     comment = '',"
                   "     creation_time = EXCLUDED.creation_time,"
                   "     modification_time = EXCLUDED.modification_time,"
                   "     title = EXCLUDED.title,"
                   "     summary = EXCLUDED.summary,"
                   "     cve_refs = EXCLUDED.cve_refs;",
                   quoted_refnum,
                   quoted_refnum,
                   parse_iso_time_element_text (published),
                   parse_iso_time (updated_text),
                   quoted_title,
                   quoted_summary,
                   cve_refs);
              increment_transaction_size (&transaction_size);
              g_free (quoted_title);
              g_free (quoted_summary);

              cve = element_first_child (child);
              while (cve)
                {
                  if (strcmp (element_name (cve), "cve") == 0)
                    {
                      gchar **split, **point;
                      gchar *text, *start;

                      text = element_text (cve);
                      start = text;
                      while ((start = strstr (start, "CVE ")))
                        start[3] = '-';

                      split = g_strsplit (text, " ", 0);
                      g_free (text);
                      point = split;
                      while (*point)
                        {
                          if (g_str_has_prefix (*point, "CVE-")
                              && (strlen (*point) >= 13)
                              && atoi (*point + 4) > 0)
                            {
                              gchar *quoted_point;

                              quoted_point = sql_quote (*point);
                              /* There's no primary key, so just INSERT, even
                               * for Postgres. */
                              sql ("INSERT INTO dfn_cert_cves"
                                   " (adv_id, cve_name)"
                                   " VALUES"
                                   " ((SELECT id FROM dfn_cert_advs"
                                   "   WHERE name = '%s'),"
                                   "  '%s')",
                                   quoted_refnum,
                                   quoted_point);
                              increment_transaction_size (&transaction_size);
                              g_free (quoted_point);
                            }
                          point++;
                        }
                      g_strfreev (split);
                    }

                  cve = element_next (cve);
                }

              updated_dfn_cert = 1;
              g_free (quoted_refnum);
            }

          g_free (updated_text);
        }
      child = element_next (child);
    }

  element_free (element);
  g_free (full_path);
  sql_commit ();
  return updated_dfn_cert;

 fail:
  g_warning ("Update of DFN-CERT Advisories failed at file '%s'",
             full_path);
  g_free (full_path);
  sql_commit ();
  return -1;
}

/**
 * @brief Update DFN-CERTs.
 *
 * Assume that the databases are attached.
 *
 * @param[in]  last_cert_update  Time of last CERT update from meta.
 *
 * @return 0 nothing to do, 1 updated, -1 error.
 */
static int
update_dfn_cert_advisories (int last_cert_update)
{
  GError *error;
  int count, last_dfn_update, updated_dfn_cert;
  GDir *dir;
  const gchar *xml_path;

  error = NULL;
  dir = g_dir_open (GVM_CERT_DATA_DIR, 0, &error);
  if (dir == NULL)
    {
      g_warning ("%s: Failed to open directory '%s': %s",
                 __func__, GVM_CERT_DATA_DIR, error->message);
      g_error_free (error);
      return -1;
    }

  last_dfn_update = sql_int ("SELECT max (modification_time)"
                             " FROM cert.dfn_cert_advs;");

  g_debug ("%s: VS: " GVM_CERT_DATA_DIR "/dfn-cert-*.xml", __func__);
  count = 0;
  updated_dfn_cert = 0;
  while ((xml_path = g_dir_read_name (dir)))
    if (fnmatch ("dfn-cert-*.xml", xml_path, 0) == 0)
      {
        switch (update_dfn_xml (xml_path, last_cert_update, last_dfn_update))
          {
            case 0:
              break;
            case 1:
              updated_dfn_cert = 1;
              break;
            default:
              g_dir_close (dir);
              return -1;
          }
        count++;
      }

  if (count == 0)
    g_warning ("No DFN-CERT advisories found in %s", GVM_CERT_DATA_DIR);

  g_dir_close (dir);
  return updated_dfn_cert;
}


/* CERT update: CERT-BUND. */

/**
 * @brief Update CERT-Bund info from a single XML feed file.
 *
 * @param[in]  xml_path          XML path.
 * @param[in]  last_cert_update  Time of last CERT update.
 * @param[in]  last_bund_update   Time of last update to a DFN.
 *
 * @return 0 nothing to do, 1 updated, -1 error.
 */
static int
update_bund_xml (const gchar *xml_path, int last_cert_update,
                 int last_bund_update)
{
  GError *error;
  element_t element, child;
  gchar *xml, *full_path;
  gsize xml_len;
  GStatBuf state;
  int updated_cert_bund;
  int transaction_size = 0;

  updated_cert_bund = 0;
  full_path = g_build_filename (GVM_CERT_DATA_DIR, xml_path, NULL);

  if (g_stat (full_path, &state))
    {
      g_warning ("%s: Failed to stat CERT file: %s",
                 __func__,
                 strerror (errno));
      return -1;
    }

  if ((state.st_mtime - (state.st_mtime % 60)) <= last_cert_update)
    {
      g_info ("Skipping %s, file is older than last revision",
              full_path);
      g_free (full_path);
      return 0;
    }

  g_info ("Updating %s", full_path);

  error = NULL;
  g_file_get_contents (full_path, &xml, &xml_len, &error);
  if (error)
    {
      g_warning ("%s: Failed to get contents: %s",
                 __func__,
                 error->message);
      g_error_free (error);
      g_free (full_path);
      return -1;
    }

  if (parse_element (xml, &element))
    {
      g_free (xml);
      g_warning ("%s: Failed to parse element", __func__);
      g_free (full_path);
      return -1;
    }
  g_free (xml);

  sql_begin_immediate ();
  child = element_first_child (element);
  while (child)
    {
      if (strcmp (element_name (child), "Advisory") == 0)
        {
          element_t date;

          date = element_child (child, "Date");
          if (date == NULL)
            {
              g_warning ("%s: Date missing", __func__);
              element_free (element);
              goto fail;
            }
          if (parse_iso_time_element_text (date) > last_bund_update)
            {
              element_t refnum, description, title, cve, cve_list;
              gchar *quoted_refnum, *quoted_title, *quoted_summary;
              int cve_refs;
              GString *summary;

              refnum = element_child (child, "Ref_Num");
              if (refnum == NULL)
                {
                  g_warning ("%s: Ref_Num missing", __func__);
                  element_free (element);
                  goto fail;
                }

              title = element_child (child, "Title");
              if (title == NULL)
                {
                  g_warning ("%s: Title missing", __func__);
                  element_free (element);
                  goto fail;
                }

              summary = g_string_new ("");
              description = element_child (child, "Description");
              if (description)
                {
                  element_t delement;

                  delement = element_first_child (description);
                  while (delement)
                    {
                      if (strcmp (element_name (delement), "Element") == 0)
                        {
                          element_t text_block;
                          text_block = element_child (delement, "TextBlock");
                          if (text_block)
                            {
                              gchar *text;

                              text = element_text (text_block);
                              g_string_append (summary, text);
                              g_free (text);
                            }
                        }
                      delement = element_next (delement);
                    }
                }

              cve_refs = 0;
              cve_list = element_child (child, "CVEList");
              if (cve_list)
                {
                  cve = element_first_child (cve_list);
                  while (cve)
                    {
                      if (strcmp (element_name (cve), "CVE") == 0)
                        cve_refs++;
                      cve = element_next (cve);
                    }
                }

              quoted_refnum = sql_quote_element_text (refnum);
              quoted_title = sql_quote_element_text (title);
              quoted_summary = sql_quote (summary->str);
              g_string_free (summary, TRUE);
              sql ("INSERT INTO cert.cert_bund_advs"
                   " (uuid, name, comment, creation_time,"
                   "  modification_time, title, summary, cve_refs)"
                   " VALUES"
                   " ('%s', '%s', '', %i, %i, '%s', '%s', %i)"
                   " ON CONFLICT (uuid) DO UPDATE"
                   " SET name = EXCLUDED.uuid,"
                   "     comment = '',"
                   "     creation_time = EXCLUDED.creation_time,"
                   "     modification_time = EXCLUDED.modification_time,"
                   "     title = EXCLUDED.title,"
                   "     summary = EXCLUDED.summary,"
                   "     cve_refs = EXCLUDED.cve_refs;",
                   quoted_refnum,
                   quoted_refnum,
                   parse_iso_time_element_text (date),
                   parse_iso_time_element_text (date),
                   quoted_title,
                   quoted_summary,
                   cve_refs);
              increment_transaction_size (&transaction_size);
              g_free (quoted_title);
              g_free (quoted_summary);

              cve_list = element_child (child, "CVEList");
              if (cve_list)
                {
                  cve = element_first_child (cve_list);
                  while (cve)
                    {
                      if (strcmp (element_name (cve), "CVE") == 0)
                        {
                          gchar *cve_text;

                          cve_text = element_text (cve);

                          if (strlen (cve_text))
                            {
                              gchar *quoted_cve;
                              quoted_cve = sql_quote (cve_text);
                              /* There's no primary key, so just INSERT, even
                               * for Postgres. */
                              sql ("INSERT INTO cert_bund_cves"
                                   " (adv_id, cve_name)"
                                   " VALUES"
                                   " ((SELECT id FROM cert_bund_advs"
                                   "   WHERE name = '%s'),"
                                   "  '%s')",
                                   quoted_refnum,
                                   quoted_cve);
                              increment_transaction_size (&transaction_size);
                              g_free (quoted_cve);
                            }
                          g_free (cve_text);
                        }

                      cve = element_next (cve);
                    }
                }

              updated_cert_bund = 1;
              g_free (quoted_refnum);
            }
        }
      child = element_next (child);
    }

  element_free (element);
  g_free (full_path);
  sql_commit ();
  return updated_cert_bund;

 fail:
  g_warning ("Update of CERT-Bund Advisories failed at file '%s'",
             full_path);
  g_free (full_path);
  sql_commit ();
  return -1;
}

/**
 * @brief Update CERT-Bunds.
 *
 * Assume that the databases are attached.
 *
 * @param[in]  last_cert_update  Time of last CERT update from meta.
 *
 * @return 0 nothing to do, 1 updated, -1 error.
 */
static int
update_cert_bund_advisories (int last_cert_update)
{
  GError *error;
  int count, last_bund_update, updated_cert_bund;
  GDir *dir;
  const gchar *xml_path;

  error = NULL;
  dir = g_dir_open (GVM_CERT_DATA_DIR, 0, &error);
  if (dir == NULL)
    {
      g_warning ("%s: Failed to open directory '%s': %s",
                 __func__, GVM_CERT_DATA_DIR, error->message);
      g_error_free (error);
      return -1;
    }

  last_bund_update = sql_int ("SELECT max (modification_time)"
                              " FROM cert.cert_bund_advs;");

  count = 0;
  updated_cert_bund = 0;
  while ((xml_path = g_dir_read_name (dir)))
    if (fnmatch ("CB-K*.xml", xml_path, 0) == 0)
      {
        switch (update_bund_xml (xml_path, last_cert_update, last_bund_update))
          {
            case 0:
              break;
            case 1:
              updated_cert_bund = 1;
              break;
            default:
              g_dir_close (dir);
              return -1;
          }
        count++;
      }

  if (count == 0)
    g_warning ("No CERT-Bund advisories found in %s", GVM_CERT_DATA_DIR);

  g_dir_close (dir);
  return updated_cert_bund;
}


/* SCAP update: CPEs. */

/**
 * @brief Convert a CPE name from formatted string to URI and SQL quote it.
 *
 * @param[in]  name        Name.
 * @param[in]  quote_func  Function for quoting.
 *
 * @return URI converted uoted name.
 */
static gchar *
fs_to_uri_convert_and_quote_cpe_name (const char *name,
                                      gchar* (*quote_func)(const char*))
{
  gchar *name_converted, *name_decoded, *name_tilde, *quoted_name;

  name_converted = fs_cpe_to_uri_cpe (name);
  name_decoded = g_uri_unescape_string (name_converted, NULL);
  name_tilde = string_replace (name_decoded,
                               "~", "%7E", "%7e", NULL);
  g_free (name_decoded);
  g_free (name_converted);
  quoted_name = quote_func (name_tilde);
  g_free (name_tilde);
  return quoted_name;
}

/**
 * @brief Decode and SQL quote a CPE name.
 *
 * @param[in]  name  Name.
 *
 * @return Quoted name.
 */
static gchar *
decode_and_quote_cpe_name (const char *name)
{
  gchar *name_decoded, *name_tilde, *quoted_name;

  name_decoded = g_uri_unescape_string (name, NULL);
  name_tilde = string_replace (name_decoded,
                               "~", "%7E", "%7e", NULL);
  g_free (name_decoded);
  quoted_name = sql_quote (name_tilde);
  g_free (name_tilde);
  return quoted_name;
}

/**
 * @brief Insert a SCAP CPE from XML.
 *
 * @param[in]  inserts            Pointer to SQL buffer.
 * @param[in]  cpe_item           CPE item XML element.
 * @param[in]  item_metadata      Item's metadata element.
 * @param[in]  modification_time  Modification time of item.
 *
 * @return 0 success, -1 error.
 */
static int
insert_scap_cpe (inserts_t *inserts, element_t cpe_item, element_t item_metadata,
                 int modification_time)
{
  gchar *name, *status, *nvd_id;
  gchar *quoted_name, *quoted_title, *quoted_status, *quoted_nvd_id;
  element_t title;
  int first;

  assert (inserts);

  name = element_attribute (cpe_item, "name");
  if (name == NULL)
    {
      g_warning ("%s: name missing", __func__);
      return -1;
    }

  status = element_attribute (item_metadata, "status");
  if (status == NULL)
    {
      g_warning ("%s: status missing", __func__);
      g_free (name);
      return -1;
    }

  nvd_id = element_attribute (item_metadata, "nvd-id");
  if (nvd_id == NULL)
    {
      g_warning ("%s: nvd_id missing", __func__);
      g_free (name);
      g_free (status);
      return -1;
    }

  title = element_first_child (cpe_item);
  quoted_title = g_strdup ("");
  while (title)
    {
      if (strcmp (element_name (title), "title") == 0)
        {
          gchar *lang;

          lang = element_attribute (title, "xml:lang");
          if (lang && strcmp (lang, "en-US") == 0)
            {
              gchar *title_text;

              title_text = element_text (title);
              g_free (quoted_title);
              quoted_title = sql_quote (title_text);
              g_free (title_text);

              g_free (lang);
              break;
            }
          g_free (lang);
        }
      title = element_next (title);
    }

  quoted_name = decode_and_quote_cpe_name (name);
  g_free (name);
  quoted_status = sql_quote (status);
  g_free (status);
  quoted_nvd_id = sql_quote (nvd_id);
  g_free (nvd_id);

  first = inserts_check_size (inserts);

  g_string_append_printf (inserts->statement,
                          "%s ('%s', '%s', '%s', %i, %i, '%s', '%s')",
                          first ? "" : ",",
                          quoted_name,
                          quoted_name,
                          quoted_title,
                          modification_time,
                          modification_time,
                          quoted_status,
                          quoted_nvd_id);

  inserts->current_chunk_size++;

  g_free (quoted_title);
  g_free (quoted_name);
  g_free (quoted_status);
  g_free (quoted_nvd_id);

  return 0;
}

/**
 * @brief Insert a SCAP CPE.
 *
 * @param[in]  inserts            Pointer to SQL buffer.
 * @param[in]  cpe_item           CPE item XML element.
 *
 * @return 0 success, -1 error.
 */
static int
insert_scap_cpe_details (inserts_t *inserts, element_t cpe_item)
{
  gchar *name, *details_xml, *quoted_name, *quoted_details_xml;
  int first;

  assert (inserts);

  name = element_attribute (cpe_item, "name");
  if (name == NULL)
    {
      g_warning ("%s: name missing", __func__);
      return -1;
    }

  quoted_name = decode_and_quote_cpe_name (name);
  g_free (name);

  details_xml = element_to_string (cpe_item);
  quoted_details_xml = sql_quote (details_xml);
  g_free (details_xml);

  first = inserts_check_size (inserts);

  g_string_append_printf (inserts->statement,
                          "%s ('%s', '%s')",
                          first ? "" : ",",
                          quoted_name,
                          quoted_details_xml);

  g_free (quoted_name);
  g_free (quoted_details_xml);

  inserts->current_chunk_size++;

  return 0;
}

/**
 * @brief Try to skip to the products list in a CPEs JSON parser.
 *
 * @param[in]  parser      Parser to skip elements in.
 * @param[in]  event       Parser event structure.
 *
 * @return 0 success, -1 error.
 */
static int
scap_cpes_json_skip_to_products (gvm_json_pull_parser_t *parser,
                                 gvm_json_pull_event_t *event)
{
  gvm_json_pull_parser_next (parser, event);
  if (event->type == GVM_JSON_PULL_EVENT_ERROR)
    {
      g_warning ("%s: Parser error: %s", __func__, event->error_message);
      return -1;
    }
  else if (event->type != GVM_JSON_PULL_EVENT_OBJECT_START)
    {
      g_warning ("%s: CPEs file content is not a JSON object.", __func__);
      return -1;
    }

  gboolean products_found = FALSE;
  while (!products_found)
    {
      gvm_json_pull_parser_next (parser, event);
      gvm_json_path_elem_t *path_tail = g_queue_peek_tail (event->path);
      if (event->type == GVM_JSON_PULL_EVENT_ARRAY_START && path_tail &&
          path_tail->key && strcmp (path_tail->key, "products") == 0)
        {
          products_found = TRUE;
        }
      else if (event->type == GVM_JSON_PULL_EVENT_ERROR)
        {
          g_warning ("%s: Parser error: %s", __func__, event->error_message);
          return -1;
        }
      else if (event->type == GVM_JSON_PULL_EVENT_OBJECT_END)
        {
          g_warning ("%s: Unexpected json object end.", __func__);
          return -1;
        }
    }
  gvm_json_pull_parser_next (parser, event);

  return 0;
}

/**
 * @brief Insert a SCAP CPE from JSON.
 *
 * @param[in]  inserts      Pointer to SQL INSERT buffer for main CPE entries.
 * @param[in]  deprecated_by_inserts  Pointer to SQL buffer for deprecated_by.
 * @param[in]  copy_buffer  Pointer to SQL COPY buffer for main CPE entries.
 * @param[in]  cpe_rowid    Pointer to CPE rowid for COPY.
 * @param[in]  use_copy     Whether to insert CPEs with COPY statements.
 * @param[in]  product_item JSON object from the products list.
 *
 * @return 0 success, -1 error.
 */
static int
handle_json_cpe_item (inserts_t *inserts,
                      inserts_t *deprecated_by_inserts,
                      db_copy_buffer_t *copy_buffer,
                      resource_t *cpe_rowid,
                      gboolean use_copy,
                      cJSON *product_item)
{
  cJSON *cpe_item;
  char *name, *cpe_name_id, *last_modified, *title_text;
  gchar *quoted_name;
  cJSON *titles, *title;
  time_t modification_time;
  int deprecated;
  int first;

  assert (inserts);
  assert (copy_buffer);

  (*cpe_rowid)++;

  cpe_item = cJSON_GetObjectItemCaseSensitive (product_item, "cpe");
  if (! cJSON_IsObject (cpe_item))
    {
      g_warning ("%s: 'cpe' field in product missing or not an object",
                 __func__);
      return -1;
    }

  name = json_object_item_string (cpe_item, "cpeName");
  if (name == NULL)
    {
      g_warning ("%s: 'cpeName' field missing or not a string", __func__);
      return -1;
    }

  cpe_name_id = json_object_item_string (cpe_item, "cpeNameId");
  if (cpe_name_id == NULL)
    {
      g_warning ("%s: 'cpeNameId' field missing or not a string", __func__);
      return -1;
    }

  last_modified = json_object_item_string (cpe_item, "lastModified");
  if (last_modified == NULL)
    {
      g_warning ("%s: 'lastModified' field missing or not a string", __func__);
      return -1;
    }
  modification_time = parse_iso_time (last_modified);

  titles = cJSON_GetObjectItemCaseSensitive (cpe_item, "titles");
  if (! cJSON_IsArray (titles))
    {
      g_warning ("%s: 'titles' field missing or not an array", __func__);
      return -1;
    }

  title_text = NULL;
  cJSON_ArrayForEach (title, titles)
    {
      gchar *lang = json_object_item_string (title, "lang");
      if (lang && strcmp (lang, "en") == 0)
        {
          title_text = json_object_item_string (title, "title");
          break;
        }
    }

  deprecated = json_object_item_boolean (cpe_item, "deprecated", -1);
  if (deprecated == -1)
    {
      g_warning ("%s: 'deprecated' field missing or not a boolean", __func__);
      return -1;
    }

  quoted_name = fs_to_uri_convert_and_quote_cpe_name (name, sql_quote);
  if (deprecated)
    {
      cJSON *deprecated_by_array, *deprecated_by_item;
      gchar *quoted_deprecated_by_id;
      deprecated_by_array = cJSON_GetObjectItemCaseSensitive (cpe_item,
                                                              "deprecatedBy");
      if (! cJSON_IsArray (deprecated_by_array))
        {
          g_warning ("%s: 'deprecatedBy' field missing or not an array",
                     __func__);
          g_free (quoted_name);
          return -1;
        }
      else if (cJSON_GetArraySize (deprecated_by_array) == 0)
        {
          g_warning ("%s: 'deprecatedBy' array is empty",
                     __func__);
          g_free (quoted_name);
          return -1;
        }

      cJSON_ArrayForEach (deprecated_by_item, deprecated_by_array)
        {
          char *deprecated_by_id;
          deprecated_by_id = json_object_item_string (deprecated_by_item,
                                                      "cpeName");
          if (deprecated_by_id == NULL)
            {
              g_warning ("%s: 'cpeName' field in 'deprecatedBy' missing or not"
                         " a string",
                         __func__);
              g_free (quoted_name);
              return -1;
            }

          quoted_deprecated_by_id
            = fs_to_uri_convert_and_quote_cpe_name (deprecated_by_id,
                                                    sql_quote);

          first = inserts_check_size (deprecated_by_inserts);

          g_string_append_printf (deprecated_by_inserts->statement,
                                  "%s ('%s', '%s')",
                                  first ? "" : ",",
                                  quoted_name,
                                  quoted_deprecated_by_id);

          deprecated_by_inserts->current_chunk_size++;
          g_free (quoted_deprecated_by_id);
        }
    }

  if (use_copy)
    {
      int ret;
      gchar *copy_escaped_name, *copy_escaped_cpe_name_id, *copy_escaped_title;

      copy_escaped_name
        = fs_to_uri_convert_and_quote_cpe_name (name, sql_copy_escape);
      copy_escaped_cpe_name_id = sql_copy_escape (cpe_name_id);
      copy_escaped_title = sql_copy_escape (title_text ? title_text : "");

      ret = db_copy_buffer_append_printf
              (copy_buffer,
               "%llu\t%s\t%s\t%s\t%li\t%li\t%d\t%s\n",
               *cpe_rowid,
               copy_escaped_name,
               copy_escaped_name,
               copy_escaped_title,
               modification_time,
               modification_time,
               deprecated,
               copy_escaped_cpe_name_id);

      g_free (copy_escaped_name);
      g_free (copy_escaped_cpe_name_id);
      g_free (copy_escaped_title);

      if (ret)
        {
          g_free (quoted_name);
          return -1;
        }
    }
  else
    {
      gchar *quoted_title, *quoted_cpe_name_id;

      quoted_cpe_name_id = sql_quote (cpe_name_id);
      quoted_title = sql_quote (title_text ? title_text : "");

      first = inserts_check_size (inserts);
      g_string_append_printf (inserts->statement,
                              "%s ('%s', '%s', '%s', %li, %li, %d, '%s')",
                              first ? "" : ",",
                              quoted_name,
                              quoted_name,
                              quoted_title,
                              modification_time,
                              modification_time,
                              deprecated,
                              quoted_cpe_name_id);

      inserts->current_chunk_size++;
      g_free (quoted_title);
      g_free (quoted_cpe_name_id);
    }

  g_free (quoted_name);

  return 0;
}

/**
 * @brief Insert a SCAP CPE from JSON.
 *
 * @param[in]  inserts      Pointer to SQL INSERT buffer.
 * @param[in]  copy_buffer  Pointer to SQL COPY buffer for main CPE entries.
 * @param[in]  cpe_rowid    Pointer to CPE rowid for COPY.
 * @param[in]  use_copy     Whether to insert CPEs with COPY statements.
 * @param[in]  product_item JSON object from the products list.
 *
 * @return 0 success, -1 error.
 */
static int
handle_json_cpe_refs (inserts_t *inserts,
                      db_copy_buffer_t *copy_buffer,
                      gboolean use_copy,
                      resource_t *cpe_rowid,
                      cJSON *product_item)
{
  cJSON *cpe_item, *refs, *refs_item;
  gchar *name, *quoted_name;
  gchar* (*quote_func)(const char*);

  assert (inserts);

  (*cpe_rowid)++;

  cpe_item = cJSON_GetObjectItemCaseSensitive (product_item, "cpe");
  if (! cJSON_IsObject (cpe_item))
    {
      g_warning ("%s: 'cpe' field in product missing or not an object",
                 __func__);
      return -1;
    }

  name = json_object_item_string (cpe_item, "cpeName");
  if (name == NULL)
    {
      g_warning ("%s: 'cpeName' field missing or not a string", __func__);
      return -1;
    }

  refs = cJSON_GetObjectItemCaseSensitive (cpe_item, "refs");
  if (! cJSON_IsArray (refs))
    {
      g_debug ("%s: 'refs' field missing or not an array", __func__);
      return 0;
    }

  quote_func = use_copy ? sql_copy_escape : sql_quote;
  if (use_copy)
    quoted_name = NULL;
  else
    quoted_name = fs_to_uri_convert_and_quote_cpe_name (name, quote_func);

  cJSON_ArrayForEach (refs_item, refs)
    {
      int first;
      char *ref, *type;
      gchar *quoted_ref, *quoted_type;
      ref = json_object_item_string (refs_item, "ref");
      if (ref == NULL)
        {
          g_warning ("%s: 'ref' field missing or not a string", __func__);
          g_free (quoted_name);
          return -1;
        }
      type = json_object_item_string (refs_item, "type");
      quoted_ref = quote_func (ref ? ref : "");
      quoted_type = quote_func (type ? type : "");

      if (use_copy)
        {
          if (db_copy_buffer_append_printf (copy_buffer,
                                            "%llu\t%s\t%s\n",
                                            *cpe_rowid,
                                            quoted_ref,
                                            quoted_type))
            {
              g_free (quoted_ref);
              g_free (quoted_type);
              return -1;
            }
        }
      else
        {
          first = inserts_check_size (inserts);

          g_string_append_printf (inserts->statement,
                                  "%s ('%s', '%s', '%s')",
                                  first ? "" : ",",
                                  quoted_name,
                                  quoted_ref,
                                  quoted_type);

          inserts->current_chunk_size++;
        }

      g_free (quoted_ref);
      g_free (quoted_type);
    }
  g_free (quoted_name);

  return 0;
}

/**
 * @brief Update SCAP CPEs from a JSON file.
 *
 * @param[in]  path             Path to file.
 * @param[in]  use_copy         Whether to use COPY statements to load data.
 *
 * @return 0 success, -1 error.
 */
static int
update_scap_cpes_from_json_file (const gchar *path, gboolean use_copy)
{
  inserts_t inserts, deprecated_by_inserts;
  db_copy_buffer_t copy_buffer;
  resource_t cpe_rowid;
  gvm_json_pull_parser_t parser;
  gvm_json_pull_event_t event;
  FILE *cpe_file;

  int fd = open (path, O_RDONLY);

  if (fd < 0)
    {
      g_warning ("%s: Failed to open CPE file '%s': %s",
                 __func__, path, strerror(errno));
      return -1;
    }

  g_info ("Updating %s", path);

  cpe_file = gvm_gzip_open_file_reader_fd (fd);
  if (cpe_file == NULL)
    {
      g_warning ("%s: Failed to open CPE file: %s",
                 __func__,
                 strerror (errno));
      return -1;
    }

  gvm_json_pull_parser_init (&parser, cpe_file);
  gvm_json_pull_event_init (&event);
  if (scap_cpes_json_skip_to_products (&parser, &event))
    {
      gvm_json_pull_event_cleanup (&event);
      gvm_json_pull_parser_cleanup (&parser);
      fclose (cpe_file);
      return -1;
    }

  drop_indexes_cpe ();

  cpe_rowid = 0;
  sql_begin_immediate ();

  if (use_copy)
    {
      db_copy_buffer_init (&copy_buffer,
                           setting_secinfo_sql_buffer_threshold_bytes (),
                           "COPY scap2.cpes"
                           " (id, uuid, name, title, creation_time,"
                           "  modification_time, deprecated,"
                           "  cpe_name_id)"
                           " FROM STDIN;");
    }
  else
    {
      inserts_init (&inserts,
                    CPE_MAX_CHUNK_SIZE,
                    setting_secinfo_sql_buffer_threshold_bytes (),
                    "INSERT INTO scap2.cpes"
                    " (uuid, name, title, creation_time,"
                    "  modification_time, deprecated,"
                    "  cpe_name_id)"
                    " VALUES",
                    " ON CONFLICT (uuid) DO UPDATE"
                    " SET name = EXCLUDED.name,"
                    "     title = EXCLUDED.title,"
                    "     creation_time = EXCLUDED.creation_time,"
                    "     modification_time = EXCLUDED.modification_time,"
                    "     deprecated = EXCLUDED.deprecated,"
                    "     cpe_name_id = EXCLUDED.cpe_name_id");
    }

  inserts_init (&deprecated_by_inserts, 10,
                setting_secinfo_sql_buffer_threshold_bytes (),
                "INSERT INTO scap2.cpes_deprecated_by (cpe, deprecated_by)"
                " VALUES ",
                "");

  while (event.type == GVM_JSON_PULL_EVENT_OBJECT_START)
    {
      gchar *error_message;
      cJSON *entry = gvm_json_pull_expand_container (&parser, &error_message);
      if (error_message)
        {
          g_warning ("%s: Error expanding CVE item: %s", __func__, error_message);
          gvm_json_pull_event_cleanup (&event);
          gvm_json_pull_parser_cleanup (&parser);
          cJSON_Delete (entry);
          fclose (cpe_file);
          if (use_copy)
            db_copy_buffer_cleanup (&copy_buffer);
          else
            inserts_free (&inserts);
          inserts_free (&deprecated_by_inserts);
          sql_commit ();
          return -1;
        }
      if (handle_json_cpe_item (&inserts,
                                &deprecated_by_inserts,
                                &copy_buffer,
                                &cpe_rowid,
                                use_copy,
                                entry))
        {
          gvm_json_pull_event_cleanup (&event);
          gvm_json_pull_parser_cleanup (&parser);
          cJSON_Delete (entry);
          fclose (cpe_file);
          if (use_copy)
            db_copy_buffer_cleanup (&copy_buffer);
          else
            inserts_free (&inserts);
          inserts_free (&deprecated_by_inserts);
          sql_commit ();
          return -1;
        }
      cJSON_Delete (entry);
      gvm_json_pull_parser_next (&parser, &event);
    }
  if (use_copy)
    {
      sql ("SELECT setval('scap2.cpes_id_seq', %llu)", cpe_rowid);
      if (db_copy_buffer_commit (&copy_buffer, TRUE))
        {
          sql_commit ();
          gvm_json_pull_parser_cleanup (&parser);
          fclose (cpe_file);
          db_copy_buffer_cleanup (&copy_buffer);
          inserts_free (&deprecated_by_inserts);
          return -1;
        }
    }
  else
    inserts_run (&inserts, TRUE);

  inserts_run (&deprecated_by_inserts, TRUE);
  sql_commit ();
  gvm_json_pull_parser_cleanup (&parser);

  create_indexes_cpe ();

  // Reset and insert refs
  g_info ("Updating CPE refs...");

  fclose (cpe_file);
  fd = open (path, O_RDONLY);

  if (fd < 0)
    {
      g_warning ("%s: Failed to open CPE file '%s': %s",
                 __func__, path, strerror(errno));
      return -1;
    }

  cpe_file = gvm_gzip_open_file_reader_fd (fd);
  if (cpe_file == NULL)
    {
      g_warning ("%s: Failed to open CPE file: %s",
                 __func__,
                 strerror (errno));
      return -1;
    }
  gvm_json_pull_parser_init (&parser, cpe_file);

  if (scap_cpes_json_skip_to_products (&parser, &event))
    {
      gvm_json_pull_event_cleanup (&event);
      gvm_json_pull_parser_cleanup (&parser);
      fclose (cpe_file);
      return -1;
    }

  sql_begin_immediate ();
  cpe_rowid = 0;

  if (use_copy)
    {
      db_copy_buffer_init (&copy_buffer,
                           setting_secinfo_sql_buffer_threshold_bytes (),
                           "COPY scap2.cpe_refs (cpe, ref, type)"
                           " FROM STDIN");
    }
  else
    {
      inserts_init (&inserts, 10,
                    setting_secinfo_sql_buffer_threshold_bytes (),
                    "INSERT INTO scap2.cpe_refs (cpe, ref, type)"
                    " SELECT scap2.cpes.id, new_refs.ref, new_refs.type"
                    " FROM scap2.cpes JOIN (VALUES ",
                    ") AS new_refs (cpe_name, ref, type)"
                    " ON scap2.cpes.name = cpe_name;");
    }

  while (event.type == GVM_JSON_PULL_EVENT_OBJECT_START)
    {
      gchar *error_message;
      cJSON *entry = gvm_json_pull_expand_container (&parser, &error_message);
      if (error_message)
        {
          g_warning ("%s: Error expanding CVE item: %s", __func__, error_message);
          gvm_json_pull_event_cleanup (&event);
          gvm_json_pull_parser_cleanup (&parser);
          cJSON_Delete (entry);
          fclose (cpe_file);
          if (use_copy)
            db_copy_buffer_cleanup (&copy_buffer);
          else
            inserts_free (&inserts);
          sql_commit ();
          return -1;
        }
      if (handle_json_cpe_refs (&inserts, &copy_buffer, use_copy,
                                &cpe_rowid, entry))
        {
          gvm_json_pull_event_cleanup (&event);
          gvm_json_pull_parser_cleanup (&parser);
          cJSON_Delete (entry);
          fclose (cpe_file);
          if (use_copy)
            db_copy_buffer_cleanup (&copy_buffer);
          else
            inserts_free (&inserts);
          sql_commit ();
          return -1;
        }
      cJSON_Delete (entry);
      gvm_json_pull_parser_next (&parser, &event);
    }
  if (use_copy)
    {
      if (db_copy_buffer_commit (&copy_buffer, TRUE))
        {
          sql_commit ();
          gvm_json_pull_parser_cleanup (&parser);
          fclose (cpe_file);
          if (use_copy)
            db_copy_buffer_cleanup (&copy_buffer);
          else
            inserts_free (&inserts);
          return -1;
        }
    }
  else
    inserts_run (&inserts, TRUE);
  sql_commit ();
  gvm_json_pull_parser_cleanup (&parser);

  fclose (cpe_file);
  return 0;
}

/**
 * @brief Update SCAP CPEs from an XML file.
 *
 * @param[in]  path             Path to file.
 *
 * @return 0 success, -1 error.
 */
static int
update_scap_cpes_from_xml_file (const gchar *path)
{
  int ret;
  element_t cpe_item;
  inserts_t inserts;
  xml_file_iterator_t file_iterator;
  gchar *error_message = NULL;

  file_iterator = xml_file_iterator_new ();
  ret = xml_file_iterator_init_from_file_path (file_iterator, path, 1);
  switch (ret)
    {
      case 0:
        break;
      case 2:
        g_warning ("%s: Could not open file '%s' for XML file iterator: %s",
                   __func__, path, strerror(errno));
        xml_file_iterator_free (file_iterator);
        return -1;
      case 3:
        g_warning ("%s: Could not create parser context for XML file iterator",
                   __func__);
        xml_file_iterator_free (file_iterator);
        return -1;
      default:
        g_warning ("%s: Could not initialize XML file iterator",
                   __func__);
        xml_file_iterator_free (file_iterator);
        return -1;
    }

  sql_begin_immediate ();

  inserts_init (&inserts,
                CPE_MAX_CHUNK_SIZE,
                setting_secinfo_sql_buffer_threshold_bytes (),
                "INSERT INTO scap2.cpes"
                " (uuid, name, title, creation_time,"
                "  modification_time, status,"
                "  nvd_id)"
                " VALUES",
                " ON CONFLICT (uuid) DO UPDATE"
                " SET name = EXCLUDED.name,"
                "     title = EXCLUDED.title,"
                "     creation_time = EXCLUDED.creation_time,"
                "     modification_time = EXCLUDED.modification_time,"
                "     status = EXCLUDED.status,"
                "     nvd_id = EXCLUDED.nvd_id");

  cpe_item = xml_file_iterator_next (file_iterator, &error_message);
  if (error_message)
    {
      g_warning ("%s: could not get first CPE XML element: %s",
                 __func__, error_message);
      g_free (error_message);
      goto fail;
    }
  while (cpe_item)
    {
      gchar *modification_date;
      int modification_time;
      element_t item_metadata;

      if (strcmp (element_name (cpe_item), "cpe-item"))
        {
          element_free (cpe_item);
          cpe_item = xml_file_iterator_next (file_iterator, &error_message);
          if (error_message)
            {
              g_warning ("%s: could not get next CPE XML element: %s",
                        __func__, error_message);
              g_free (error_message);
              goto fail;
            }
          continue;
        }

      item_metadata = element_child (cpe_item, "meta:item-metadata");
      if (item_metadata == NULL)
        {
          g_warning ("%s: item-metadata missing", __func__);
          goto fail;
        }

      modification_date = element_attribute (item_metadata,
                                            "modification-date");
      if (modification_date == NULL)
        {
          g_warning ("%s: modification-date missing", __func__);
          goto fail;
        }

      modification_time = parse_iso_time (modification_date);
      g_free (modification_date);

      if (insert_scap_cpe (&inserts, cpe_item, item_metadata,
                           modification_time))
        goto fail;

      element_free (cpe_item);
      cpe_item = xml_file_iterator_next (file_iterator, &error_message);
      if (error_message)
        {
          g_warning ("%s: could not get next CPE XML element: %s",
                    __func__, error_message);
          g_free (error_message);
          error_message = NULL;
          goto fail;
        }
    }

  inserts_run (&inserts, TRUE);
  sql_commit ();
  sql_begin_immediate();

  if (xml_file_iterator_rewind (file_iterator))
    {
      g_warning ("%s: Could not create parser context for XML file iterator"
                 " for details.",
                 __func__);
      goto fail;
    }

  // Extract and save details XML.
  inserts_init (&inserts,
                CPE_MAX_CHUNK_SIZE,
                setting_secinfo_sql_buffer_threshold_bytes (),
                "INSERT INTO scap2.cpe_details"
                " (cpe_id, details_xml)"
                " VALUES",
                " ON CONFLICT (cpe_id) DO UPDATE"
                " SET details_xml = EXCLUDED.details_xml");
  cpe_item = xml_file_iterator_next (file_iterator, &error_message);
  if (error_message)
    {
      g_warning ("%s: could not get first CPE XML element for details: %s",
                __func__, error_message);
      g_free (error_message);
      error_message = NULL;
      goto fail;
    }
  while (cpe_item)
    {
      if (strcmp (element_name (cpe_item), "cpe-item"))
        {
          element_free (cpe_item);
          cpe_item = xml_file_iterator_next (file_iterator, &error_message);
          if (error_message)
            {
              g_warning ("%s: could not get next CPE XML element"
                         " for details: %s",
                         __func__, error_message);
              g_free (error_message);
              goto fail;
            }
          continue;
        }

      if (insert_scap_cpe_details (&inserts, cpe_item))
        goto fail;
      element_free (cpe_item);
      cpe_item = xml_file_iterator_next (file_iterator, &error_message);
      if (error_message)
        {
          g_warning ("%s: could not get next CPE XML element for details: %s",
                     __func__, error_message);
          g_free (error_message);
          goto fail;
        }
    }

  inserts_run (&inserts, TRUE);
  sql_commit();
  xml_file_iterator_free (file_iterator);

  return 0;

 fail:
  inserts_free (&inserts);
  g_warning ("Update of CPEs failed");
  sql_commit ();
  xml_file_iterator_free (file_iterator);
  return -1;
}

/**
 * @brief Update SCAP CPEs.
 *
 * @return 0 success, -1 error.
 */
static int
update_scap_cpes ()
{
  gchar *full_path;
  GStatBuf state;
  int ret;

  full_path = g_build_filename (GVM_SCAP_DATA_DIR,
                                "nvd-cpes.json.gz",
                                NULL);
  if (g_stat (full_path, &state))
    {
      g_free (full_path);
      full_path = g_build_filename (GVM_SCAP_DATA_DIR,
                                    "nvd-cpes.json",
                                    NULL);
    }

  if (g_stat (full_path, &state))
    {
      g_warning ("%s: No JSON CPE dictionary found at %s",
                 __func__,
                 full_path);
      g_free (full_path);

      full_path = g_build_filename (GVM_SCAP_DATA_DIR,
                                    "official-cpe-dictionary_v2.2.xml",
                                    NULL);

      if (g_stat (full_path, &state))
        {
          g_warning ("%s: No CPE dictionary found at %s",
                    __func__,
                    full_path);
          g_free (full_path);
          return -1;
        }

      ret = update_scap_cpes_from_xml_file (full_path);
      if (ret)
        return -1;

      return 0;
    }

  g_info ("Updating CPEs");

  ret = update_scap_cpes_from_json_file (full_path, secinfo_fast_init);

  g_free (full_path);

  if (ret)
    return -1;

  return 0;
}


/* SCAP update: CVEs. */

/**
 * @brief Get the ID of a CPE from a hashtable.
 *
 * @param[in]  hashed_cpes    CPEs.
 * @param[in]  product_tilde  UUID/Name.
 *
 * @return ID of CPE from hashtable.
 */
static int
hashed_cpes_cpe_id (GHashTable *hashed_cpes, const gchar *product_tilde)
{
  return GPOINTER_TO_INT (g_hash_table_lookup (hashed_cpes, product_tilde));
}

/**
 * @brief Insert products for a CVE.
 *
 * @param[in]  list              XML product list.
 * @param[in]  cve               CVE.
 * @param[in]  time_published    Time published.
 * @param[in]  time_modified     Time modified.
 * @param[in]  hashed_cpes       Hashed CPEs.
 * @param[in]  transaction_size  Statement counter for batching.
 */
static void
insert_cve_products (element_t list, resource_t cve,
                     int time_modified, int time_published,
                     GHashTable *hashed_cpes, int *transaction_size)
{
  element_t product_element;
  GHashTable *products;
  GHashTableIter products_iter;
  gchar *product_tilde;
  int first_product, first_affected;
  GString *sql_cpes, *sql_affected;

  if (list == NULL)
    return;

  product_element = element_first_child (list);

  if (product_element == NULL)
    return;

  sql_cpes = g_string_new ("INSERT INTO scap2.cpes"
                           " (uuid, name, creation_time,"
                           "  modification_time)"
                           " VALUES");
  sql_affected = g_string_new ("INSERT INTO scap2.affected_products"
                               " (cve, cpe)"
                               " VALUES");

  /* Collect unique product CPEs in the current CVE's XML.
   * Duplicates have to be avoided as they would cause errors from Postgres
   * ON CONFLICT DO UPDATE.
   */
  products = g_hash_table_new_full (g_str_hash, g_str_equal, free, NULL);
  while (product_element)
    {
      gchar *product_text, *product_decoded;
      if (strcmp (element_name (product_element), "product"))
        {
          product_element = element_next (product_element);
          continue;
        }

      product_text = element_text (product_element);
      if (strcmp (product_text, "") == 0)
        {
          free (product_text);
          product_element = element_next (product_element);
          continue;
        }

      product_decoded = g_uri_unescape_string (product_text, NULL);
      product_tilde = string_replace (product_decoded,
                                      "~", "%7E", "%7e",
                                      NULL);
      g_free (product_text);
      g_free (product_decoded);
      g_hash_table_insert (products, product_tilde, NULL);

      product_element = element_next (product_element);
    }

  /* Add new CPEs. */

  first_product = first_affected = 1;
  g_hash_table_iter_init (&products_iter, products);

  while (g_hash_table_iter_next (&products_iter,
                                 (gpointer*)(&product_tilde),
                                 NULL))
    {
      if (g_hash_table_contains (hashed_cpes, product_tilde) == 0)
        {
          gchar *quoted_product;
          quoted_product = sql_quote (product_tilde);
          g_string_append_printf
            (sql_cpes,
             "%s ('%s', '%s', %i, %i)",
             first_product ? "" : ",", quoted_product, quoted_product,
             time_published, time_modified);
          g_free (quoted_product);
          first_product = 0;
        }
    }

  if (first_product == 0)
    {
      /* Run the SQL for inserting new CPEs and add them to hashed_cpes
       * so they can be looked up quickly when adding affected_products.
       */
      iterator_t inserted_cpes;
      init_iterator (&inserted_cpes,
                     "%s"
                     " ON CONFLICT (uuid)"
                     " DO UPDATE SET name = EXCLUDED.name"
                     " RETURNING id, name;",
                     sql_cpes->str);

      while (next (&inserted_cpes))
        {
          int rowid = iterator_int (&inserted_cpes, 0);
          const char *name = iterator_string (&inserted_cpes, 1);
          g_hash_table_insert (hashed_cpes,
                               g_strdup (name),
                               GINT_TO_POINTER (rowid));
        }
      cleanup_iterator (&inserted_cpes);
      increment_transaction_size (transaction_size);
    }
    g_string_free (sql_cpes, TRUE);

  /**
   * Add the affected product references.
   */
  g_hash_table_iter_init (&products_iter, products);

  while (g_hash_table_iter_next (&products_iter,
                                 (gpointer*)(&product_tilde),
                                 NULL))
    {
      int cpe;

      cpe = hashed_cpes_cpe_id (hashed_cpes, product_tilde);
      g_string_append_printf
         (sql_affected,
          "%s (%llu, %i)",
          first_affected ? "" : ",", cve,
          cpe);
      first_affected = 0;
    }

  if (first_affected == 0)
    {
      sql ("%s"
           " ON CONFLICT DO NOTHING;",
           sql_affected->str);

      increment_transaction_size (transaction_size);
    }

  g_string_free (sql_affected, TRUE);
  g_hash_table_destroy (products);
}

/**
 * @brief Insert a CVE.
 *
 * @param[in]  entry             XML entry.
 * @param[in]  last_modified     XML last_modified element.
 * @param[in]  transaction_size  Statement counter for batching.
 * @param[in]  hashed_cpes       Hashed CPEs.
 *
 * @return 0 success, -1 error.
 */
static int
insert_cve_from_entry (element_t entry, element_t last_modified,
                       GHashTable *hashed_cpes, int *transaction_size)
{
  element_t published, summary, cvss, score, base_metrics, cvss_vector, list;
  double severity_dbl;
  gchar *quoted_id, *quoted_summary, *quoted_cvss_vector;
  gchar *quoted_software, *id;
  GString *software;
  gchar *software_unescaped, *software_tilde;
  int time_modified, time_published;
  resource_t cve;

  id = element_attribute (entry, "id");
  if (id == NULL)
    {
      g_warning ("%s: id missing",
                 __func__);
      return -1;
    }

  published = element_child (entry, "vuln:published-datetime");
  if (published == NULL)
    {
      g_warning ("%s: vuln:published-datetime missing for %s",
                 __func__, id);
      g_free (id);
      return -1;
    }

  gchar *base_metrics_element = "cvss:base_metrics";
  gchar *score_element = "cvss:score";
  gchar *cvss_vector_element = "cvss:vector-string";

  cvss = element_child (entry, "vuln:cvss4");
  if (cvss == NULL)
    {
      cvss = element_child (entry, "vuln:cvss3");
      if (cvss == NULL)
        {
          cvss = element_child (entry, "vuln:cvss");
        }
      else
        {
          base_metrics_element = "cvss3:base_metrics";
          score_element = "cvss3:base-score";
          cvss_vector_element = "cvss3:vector-string";
        }
    }
  else
    {
      base_metrics_element = "cvss4:base_metrics";
      score_element = "cvss4:base-score";
      cvss_vector_element = "cvss4:vector-string";
    }

  if (cvss == NULL)
    base_metrics = NULL;
  else
    base_metrics = element_child (cvss, base_metrics_element);

  if (base_metrics == NULL)
    {
      score = NULL;
      cvss_vector = NULL;
    }
  else
    {
      score = element_child (base_metrics, score_element);

      if (score == NULL)
        {
          g_warning ("%s: cvss:score missing for %s", __func__, id);
          g_free (id);
          return -1;
        }

      cvss_vector = element_child (base_metrics, cvss_vector_element);

      if (cvss_vector == NULL)
        {
          g_warning ("%s: cvss:access-vector missing for %s", __func__, id);
          g_free (id);
          return -1;
        }
    }

  if (score == NULL)
    severity_dbl = SEVERITY_MISSING;
  else
    severity_dbl = atof (element_text (score));

  summary = element_child (entry, "vuln:summary");
  if (summary == NULL)
    {
      g_warning ("%s: vuln:summary missing for %s", __func__, id);
      g_free (id);
      return -1;
    }

  software = g_string_new ("");
  list = element_child (entry, "vuln:vulnerable-software-list");
  if (list)
    {
      element_t product;
      product = element_first_child (list);
      while (product)
        {
          if (strcmp (element_name (product), "product") == 0)
            {
              gchar *product_text;

              product_text = element_text (product);
              g_string_append_printf (software, "%s ", product_text);
              g_free (product_text);
            }
          product = element_next (product);
        }
    }

  quoted_id = sql_quote (id);
  g_free (id);
  quoted_summary = sql_quote_element_text (summary);
  quoted_cvss_vector = sql_quote_element_text (cvss_vector);
  software_unescaped = g_uri_unescape_string (software->str, NULL);
  g_string_free (software, TRUE);
  software_tilde = string_replace (software_unescaped,
                                   "~", "%7E", "%7e", NULL);
  g_free (software_unescaped);
  quoted_software = sql_quote (software_tilde);
  g_free (software_tilde);
  time_modified = parse_iso_time_element_text (last_modified);
  time_published = parse_iso_time_element_text (published);
  cve = sql_int64_0
         ("INSERT INTO scap2.cves"
          " (uuid, name, creation_time, modification_time,"
          "  severity, description, cvss_vector, products)"
          " VALUES"
          " ('%s', '%s', %i, %i,"
          "  %0.1f, '%s', '%s', '%s')"
          " ON CONFLICT (uuid) DO UPDATE"
          " SET name = EXCLUDED.name,"
          "     creation_time = EXCLUDED.creation_time,"
          "     modification_time = EXCLUDED.modification_time,"
          "     severity = EXCLUDED.severity,"
          "     description = EXCLUDED.description,"
          "     cvss_vector = EXCLUDED.cvss_vector,"
          "     products = EXCLUDED.products"
          " RETURNING scap2.cves.id;",
          quoted_id,
          quoted_id,
          time_published,
          time_modified,
          severity_dbl,
          quoted_summary,
          quoted_cvss_vector,
          quoted_software);
  increment_transaction_size (transaction_size);
  g_free (quoted_summary);
  g_free (quoted_cvss_vector);
  g_free (quoted_software);

  insert_cve_products (list, cve, time_published, time_modified,
                       hashed_cpes, transaction_size);

  g_free (quoted_id);
  return 0;
}

/**
 * @brief Save the node of a cve match rule tree.
 *
 * @param[in]  cve_id     The id of the CVE to which the tree belongs.
 * @param[in]  operator   The operator for the match rules.
 * @param[in]  negate     Whether the operator is negated.
 *
 * @return The (database) id of the node.
 */
static resource_t
save_node (resource_t cve_id, const char *operator, gboolean negate)
{
  resource_t ret;
  gchar *quoted_operator = sql_quote (operator);

  ret = sql_int64_0
           ("INSERT INTO scap2.cpe_match_nodes"
            " (cve_id, operator, negate)"
            " VALUES"
            " (%llu, '%s', %d)"
            " RETURNING scap2.cpe_match_nodes.id;",
            cve_id,
            quoted_operator,
            negate ? 1 : 0);

  g_free (quoted_operator);
  return ret;
}

/**
 * @brief Set the root id for a node of a cve match rule tree.
 *
 * @param[in]  id       The id of the node for which the root id is to be set.
 * @param[in]  root_id  The id of the root of the tree this node belongs to.
 */
static void
set_root_id (long int id, long int root_id)
{
  sql ("UPDATE scap2.cpe_match_nodes set root_id = %i"
       " WHERE id = %i;",
       root_id,
       id);
}

/**
 * @brief Get all fields from a single item in the CVE references list.
 *
 * @param[in]  reference_item  The JSON item to get fields from
 * @param[in]  cve_id          CVE-ID string of the CVE being processed
 * @param[out] url             Return pointer for the URL field
 * @param[out] tags_str        Return pointer for tags aggregated into a string
 *
 * @return 0 on success, -1 on error.
 */
static int
get_cve_reference_fields (cJSON *reference_item,
                          const char *cve_id,
                          gchar **url,
                          gchar **tags_str)
{
  cJSON *tags;
  GString *tags_buffer;

  *tags_str = NULL;

  *url = json_object_item_string (reference_item, "url");
  if (*url == NULL)
    {
      g_warning ("%s: url missing in reference for %s.",
                 __func__, cve_id);
      return -1;
    }

  tags = cJSON_GetObjectItemCaseSensitive (reference_item, "tags");
  tags_buffer = g_string_new ("{");
  if (cJSON_IsArray (tags))
    {
      array_t *tags_array = make_array ();

      for (int i = 0; i < cJSON_GetArraySize (tags); i++)
        {
          cJSON *tag = cJSON_GetArrayItem (tags, i);
          if (!cJSON_IsString (tag))
            {
              g_warning ("%s: tag for %s is NULL or not a string.",
                          __func__, cve_id);
              return -1;
            }
          if ((strcmp (tag->valuestring, "(null)") == 0)
                || strlen (tag->valuestring) == 0)
            {
              g_warning ("%s: tag for %s is empty string or NULL.",
                          __func__, cve_id);
              return -1;
            }
          array_add (tags_array, tag->valuestring);
        }

      for (int i = 0; i < tags_array->len; i++)
        {
          gchar *tag = g_ptr_array_index (tags_array, i);
          gchar *quoted_tag = sql_quote (tag);

          g_string_append (tags_buffer, quoted_tag);

          if (i < tags_array->len - 1)
            g_string_append (tags_buffer, ",");

          g_free (quoted_tag);
        }
      g_ptr_array_free (tags_array, TRUE);
    }
  g_string_append (tags_buffer, "}");
  *tags_str = g_string_free (tags_buffer, FALSE);
  return 0;
}

/**
 * @brief Add a CVE reference to the database.
 *
 * If secinfo_fast_init is not 0, this will add the the reference to a COPY
 *  buffer, otherwise it will run an INSERT statement.
 *
 * The COPY buffer and urls hashtable can be NULL if secinfo_fast_init is 0.
 *
 * @param[in]  cve_db_id    Database rowid of the CVE being processed
 * @param[in]  url          URL of the reference to add
 * @param[in]  tags_str     Tags of the refrence aggregated into one string
 * @param[in]  cve_refs_buffer  COPY buffer for CVE references.
 * @param[in]  urls         Hashtable to de-duplicate URLs when using COPY.
 *
 * @return 0 on success, -1 on error
 */
static int
handle_cve_reference (resource_t cve_db_id,
                      const char *url,
                      const char *tags_str,
                      db_copy_buffer_t *cve_refs_buffer,
                      GHashTable *urls)
{
  if (secinfo_fast_init)
    {
      int ret = 0;

      if (! g_hash_table_contains (urls, url))
        {
          gchar *escaped_url = sql_copy_escape (url);
          gchar *escaped_tags = sql_copy_escape (tags_str);

          ret = db_copy_buffer_append_printf (cve_refs_buffer,
                                              "%llu\t%s\t%s\n",
                                              cve_db_id,
                                              escaped_url,
                                              escaped_tags);

          g_free (escaped_url);
          g_free (escaped_tags);
          if (ret == 0)
            g_hash_table_add (urls, (gpointer)url);
        }

      return ret;
    }
  else
    {
      gchar *quoted_url = sql_quote (url);

      sql ("INSERT INTO scap2.cve_references"
            " (cve_id, url, tags)"
            " VALUES"
            " (%llu, '%s', '%s')"
            " ON CONFLICT (cve_id, url) DO UPDATE"
            " SET tags = EXCLUDED.tags;",
            cve_db_id,
            quoted_url,
            tags_str);

      g_free (quoted_url);
      return 0;
    }
}

/**
 * @brief Handle the list of references of a CVE.
 *
 * @param[in]  cve_db_id            Database id of the CVE references belong to
 * @param[in]  cve_id               The CVE-ID string of the CVE.
 * @param[in]  references_array     JSON array containing the references.
 * @param[in]  cve_refs_buffer      COPY statement buffer for references.
 *
 * @return 0 on success, -1 on error.
 */
static int
handle_cve_references (resource_t cve_db_id, char *cve_id,
                       cJSON *references_array,
                       db_copy_buffer_t *cve_refs_buffer)
{
  int ret = 0;
  cJSON *reference_item;
  static GHashTable *urls = NULL;

  if (secinfo_fast_init && urls == NULL)
    urls = g_hash_table_new (g_str_hash, g_str_equal);

  cJSON_ArrayForEach (reference_item, references_array)
    {
      char *url_value;
      gchar *tags_str;

      if (get_cve_reference_fields (reference_item,
                                    cve_id,
                                    &url_value,
                                    &tags_str))
        {
          ret = -1;
          break;
        }

      if (handle_cve_reference (cve_db_id, url_value, tags_str,
                                cve_refs_buffer, urls))
        {
          g_free (tags_str);
          ret = -1;
          break;
        }

      g_free (tags_str);
    }

  if (urls)
    g_hash_table_remove_all (urls);

  return ret;
}

/**
 * @brief Get all fields from a configuration list item of a CVE.
 *
 * @param[in]  configuration_item  The JSON configuration item
 * @param[in]  cve_id       The CVE-ID string of the CVE being processed
 * @param[out] nodes_array     Return of the list of configuration nodes
 * @param[out] config_operator Return of the operator joining the config nodes
 * @param[out] negate          Return whether the node selection is negated
 *
 * @return 0 on success, -1 on error
 */
static int
get_cve_configuration_fields (cJSON* configuration_item,
                              const char *cve_id,
                              cJSON **nodes_array,
                              char **config_operator,
                              int *negate)
{
  *nodes_array = cJSON_GetObjectItemCaseSensitive (configuration_item,
                                                   "nodes");
  if (!cJSON_IsArray (*nodes_array))
    {
      g_warning ("%s: 'nodes' field missing or not an array for %s.",
                __func__, cve_id);
      return -1;
    }

  *config_operator = json_object_item_string (configuration_item,
                                              "operator");
  if (*config_operator)
    *negate = json_object_item_boolean (configuration_item, "negate", 0);

  return 0;
}

/**
 * @brief Get all fields from a configuration node of a CVE.
 *
 * @param[in]  configuration_item  The JSON configuration item
 * @param[in]  cve_id       The CVE-ID string of the CVE being processed
 * @param[out] nodes_array       Return of the list of configuration nodes
 * @param[out] config_operator   Return of the operator joining the config nodes
 * @param[out] negate            Return whether the node selection is negated
 * @param[out] cpe_matches_array Return of the CPE matches list
 *
 * @return 0 on success, -1 on error
 */
static int
get_cve_configuration_node_fields (cJSON* node_item,
                                   const char * cve_id,
                                   char **node_operator,
                                   int *negate,
                                   cJSON **cpe_matches_array)
{
  *node_operator = json_object_item_string (node_item, "operator");
  if (*node_operator == NULL)
    {
      g_warning ("%s: operator missing for %s.", __func__, cve_id);
      return -1;
    }

  *negate = json_object_item_boolean (node_item, "negate", 0);

  *cpe_matches_array = cJSON_GetObjectItemCaseSensitive (node_item,
                                                         "cpeMatch");
  if (*cpe_matches_array == NULL)
    {
      g_debug ("%s: cpeMatch missing for %s.",
               __func__, cve_id);
    }
  else if (!cJSON_IsArray (*cpe_matches_array))
    {
      g_warning ("%s: cpeMatch not an array for %s.",
                 __func__, cve_id);
      return -1;
    }

  return 0;
}

/**
 * @brief Get fields of a single CPE match in a CVE configuration node.
 *
 * @param[in]  cpe_match_item  The CPE match JSON item to the get fields of
 * @param[in]  cve_id          CVE-ID string of the CVE being processed
 * @param[out] vulnerable      Return whether the matching CPEs are vulnerable
 * @param[out] match_criteria_id Return of the MatchCriteriaId of the CPE match
 *
 * @return 0 on success, -1 on error
 */
static int
get_cve_configuration_node_cpe_match_fields (cJSON* cpe_match_item,
                                             const char * cve_id,
                                             int *vulnerable,
                                             char **match_criteria_id)
{
  *vulnerable = json_object_item_boolean (cpe_match_item,
                                          "vulnerable", -1);
  if (*vulnerable == -1)
    {
      g_warning ("%s: vulnerable missing in cpeMatch for %s.",
                  __func__, cve_id);
      return -1;
    }

  *match_criteria_id = json_object_item_string (cpe_match_item,
                                                "matchCriteriaId");
  if (*match_criteria_id == NULL)
    {
      g_warning ("%s: matchCriteriaId missing in cpeMatch for %s.",
                  __func__, cve_id);
      return -1;
    }

  return 0;
}

/**
 * @brief Add a root CPE configuration node to the database
 *
 * If the given operator is NULL, the configuration node is skipped.
 *
 * If secinfo_fast_init is not 0, this will add the the reference to a COPY
 *  buffer, otherwise it will run an INSERT statement and the COPY buffer
 *  can be NULL.
 *
 * @param[in]  cve_db_id  Database rowid of the CVE being processed
 * @param[in]  config_operator  Operator of the config item being processed
 * @param[in]  negate     Whether the nodes within the config items are negated
 * @param[in,out] node_id_ptr  Pointer to the config node database rowid
 * @param[in,out] node_id_ptr  Pointer to the root config node database rowid
 * @param[in]  cpe_match_nodes_buffer COPY buffer for CPE match nodes
 *
 * @return 0 on success, -1 on error.
 */
static int
handle_cve_configuration (resource_t cve_db_id,
                          const char *config_operator,
                          int negate,
                          resource_t *node_id_ptr,
                          resource_t *root_id_ptr,
                          db_copy_buffer_t *cpe_match_nodes_buffer)
{
  if (config_operator == NULL)
    return 0;

  if (secinfo_fast_init)
    {
      gchar *escaped_operator;
      (*node_id_ptr)++;
      *root_id_ptr = *node_id_ptr;

      escaped_operator = sql_copy_escape (config_operator);
      if (db_copy_buffer_append_printf (cpe_match_nodes_buffer,
                                        "%llu\t%llu\t%llu\t%s\t%d\n",
                                        *node_id_ptr,
                                        *root_id_ptr,
                                        cve_db_id,
                                        escaped_operator,
                                        negate))
        {
          g_free (escaped_operator);
          return -1;
        }
      g_free (escaped_operator);
      return 0;
    }
  else
    {
      *node_id_ptr = save_node (cve_db_id, config_operator, negate);
      set_root_id (*node_id_ptr, *node_id_ptr);
      *root_id_ptr = *node_id_ptr;
      return 0;
    }
}

/**
 * @brief Add a CPE configuration node to the database
 *
 * If the given operator is NULL, the configuration node is skipped.
 *
 * If secinfo_fast_init is not 0, this will add the the reference to a COPY
 *  buffer, otherwise it will run an INSERT statement and the COPY buffer
 *  can be NULL.
 *
 * @param[in]  cve_db_id  Database rowid of the CVE being processed
 * @param[in]  node_operator  Operator of the config node being processed
 * @param[in]  negate     Whether the nodes within the config items are negated
 * @param[in,out] node_id_ptr  Pointer to the config node database rowid
 * @param[in,out] node_id_ptr  Pointer to the root config node database rowid
 * @param[in]  cpe_match_nodes_buffer COPY buffer for CPE match nodes
 *
 * @return 0 on success, -1 on error
 */
static int
handle_cve_configuration_node (resource_t cve_db_id,
                               const char *node_operator,
                               int negate,
                               resource_t *node_id_ptr,
                               resource_t *root_id_ptr,
                               db_copy_buffer_t *cpe_match_nodes_buffer)
{
  if (secinfo_fast_init)
    {
      gchar *escaped_operator = sql_copy_escape (node_operator);

      (*node_id_ptr)++;
      if (*root_id_ptr < 0)
        *root_id_ptr = *node_id_ptr;

      if (db_copy_buffer_append_printf (cpe_match_nodes_buffer,
                                        "%llu\t%llu\t%llu\t%s\t%d\n",
                                        *node_id_ptr,
                                        *root_id_ptr,
                                        cve_db_id,
                                        escaped_operator,
                                        negate))
        {
          g_free (escaped_operator);
          return -1;
        }
      g_free (escaped_operator);
    }
  else
    {
      *node_id_ptr = save_node (cve_db_id, node_operator, negate);

      if (*node_id_ptr < 0)
        *node_id_ptr = *node_id_ptr;

      set_root_id (*node_id_ptr, *root_id_ptr);
    }

  return 0;
}

/**
 * @brief Add an affected product and its placeholder CPE to the database
 *
 * This uses COPY SQL buffers. Methods not using them have to add affected
 *  products a different way.
 *
 * @param[in]     cve_db_id       Database rowid of the CVE being processed
 * @param[in,out] cpe_db_id_ptr   Pointer to DB rowid for placeholder CPEs
 * @param[in]  match_cpe_name     CPE name of the product
 * @param[in]  match_cpe_name_id  CPE name ID of the product
 * @param[in]  hashed_cpes        Hashtable of CPE-IDs in the database
 * @param[in]  current_cve_cpes   Hashtable of CPE rowids for current CVE
 * @param[in]  cve_cpes_copy_buffer            COPY buffer for placeholder CPEs
 * @param[in]  affected_products_copy_buffer   COPY buffer for affected products
 */
static int
handle_cve_affected_product (resource_t cve_db_id,
                             resource_t *cpe_db_id_ptr,
                             const char *match_cpe_name,
                             const char *match_cpe_name_id,
                             GHashTable *hashed_cpes,
                             GHashTable *current_cve_cpes,
                             db_copy_buffer_t *cve_cpes_copy_buffer,
                             db_copy_buffer_t *affected_products_copy_buffer)
{
  resource_t affected_product_cpe_db_id;

  affected_product_cpe_db_id = GPOINTER_TO_INT (
    g_hash_table_lookup (hashed_cpes, match_cpe_name)
  );
  if (g_hash_table_contains (hashed_cpes, match_cpe_name) == 0)
    {
      (*cpe_db_id_ptr)++;
      affected_product_cpe_db_id = (*cpe_db_id_ptr);
      gchar *escaped_cpe_name, *escaped_cpe_name_id;

      escaped_cpe_name = sql_copy_escape (match_cpe_name);
      escaped_cpe_name_id = sql_copy_escape (match_cpe_name_id);

      g_hash_table_insert (hashed_cpes,
                           g_strdup (match_cpe_name),
                           GINT_TO_POINTER (*cpe_db_id_ptr));
      if (db_copy_buffer_append_printf (cve_cpes_copy_buffer,
                                        "%s\t%s\t%lld\t%lld\t0\t%s\n",
                                        escaped_cpe_name,
                                        escaped_cpe_name,
                                        0,
                                        0,
                                        escaped_cpe_name_id))
        {
          g_free (escaped_cpe_name);
          g_free (escaped_cpe_name_id);
          return -1;
        }
    }

  if (! g_hash_table_contains (current_cve_cpes,
                               GINT_TO_POINTER (affected_product_cpe_db_id)))
    {
      if (db_copy_buffer_append_printf (affected_products_copy_buffer,
                                        "%llu\t%llu\n",
                                        cve_db_id,
                                        affected_product_cpe_db_id))
        return -1;

      g_hash_table_add (current_cve_cpes,
                        GINT_TO_POINTER (affected_product_cpe_db_id));
    }
  return 0;
}

/**
 * @brief Add a CVE config node match criteria item to the database
 *
 * If secinfo_fast_init is not 0, the data will be inserted using COPY
 *  statements, otherwise INSERT and UPDATE statements will be used and the
 *  COPY buffers can be NULL.
 *
 * If secinfo_fast_init is not 0, placeholder CPEs and entries for the
 *  affected products table are also generated here, otherwise they have
 *  to be generated separately later.
 *
 * @param[in]  cve_db_id  Database rowid of the CVE being processed
 * @param[in]  node_id    Database rowid of the CVE config node being processed
 * @param[in,out] cpe_db_id_ptr Pointer to DB rowid for adding placeholder CPEs
 * @param[in]  match_criteria_id  MatchCriteriaId of the CPE match
 * @param[in]  vulnerable         Whether the matching CPEs are vulnerable
 * @param[in]  hashed_cpes        Hashtable of CPE-IDs in the database
 * @param[in]  current_cve_cpes   Hashtable of CPE rowids for current CVE
 * @param[in]  software           String buffer for the CVE products field
 * @param[in]  cpe_nodes_match_criteria_buffer COPY buffer for match criteria
 * @param[in]  cve_cpes_copy_buffer            COPY buffer for placeholder CPEs
 * @param[in]  affected_products_copy_buffer   COPY buffer for affected products
 *
 * @return 0 on success, -1 on error
 */
static int
handle_cve_cpe_nodes_match_criteria (resource_t cve_db_id,
                                     resource_t node_id,
                                     resource_t *cpe_db_id_ptr,
                                     const char *match_criteria_id,
                                     int vulnerable,
                                     GHashTable *hashed_cpes,
                                     GHashTable *current_cve_cpes,
                                     GString *software,
                                     db_copy_buffer_t *cpe_nodes_match_criteria_buffer,
                                     db_copy_buffer_t *cve_cpes_copy_buffer,
                                     db_copy_buffer_t *affected_products_copy_buffer)
{
  if (secinfo_fast_init)
    {
      gchar *escaped_match_criteria_id = sql_copy_escape (match_criteria_id);
      if (db_copy_buffer_append_printf (cpe_nodes_match_criteria_buffer,
                                        "%llu\t%d\t%s\n",
                                        node_id,
                                        vulnerable,
                                        escaped_match_criteria_id))
        {
          g_free (escaped_match_criteria_id);
          return -1;
        }
      g_free (escaped_match_criteria_id);
    }
  else
    {
      gchar *quoted_match_criteria_id = sql_quote (match_criteria_id);

      sql ("INSERT INTO scap2.cpe_nodes_match_criteria"
          " (node_id, vulnerable, match_criteria_id)"
          " VALUES"
          " (%llu, %d, '%s')",
          node_id,
          vulnerable ? 1 : 0,
          quoted_match_criteria_id);

      g_free (quoted_match_criteria_id);
    }

  if (vulnerable)
    {
      iterator_t cpe_matches;
      gchar *quoted_match_criteria_id
        = sql_quote (match_criteria_id);

      init_cpe_match_string_matches_iterator (
        &cpe_matches,
        quoted_match_criteria_id,
        "scap2"
      );
      g_free (quoted_match_criteria_id);

      while (next (&cpe_matches))
        {
          const char *match_cpe_name;
          match_cpe_name = cpe_matches_cpe_name (&cpe_matches);

          g_string_append_printf (software, "%s ", match_cpe_name);

          if (secinfo_fast_init)
            {
              const char *match_cpe_name_id;
              match_cpe_name_id = cpe_matches_cpe_name_id (&cpe_matches);

              if (handle_cve_affected_product (cve_db_id,
                                               cpe_db_id_ptr,
                                               match_cpe_name,
                                               match_cpe_name_id,
                                               hashed_cpes,
                                               current_cve_cpes,
                                               cve_cpes_copy_buffer,
                                               affected_products_copy_buffer))
                {
                  cleanup_iterator (&cpe_matches);
                  return -1;
                }
            }
        }
      cleanup_iterator (&cpe_matches);
    }
  return 0;
}

/**
 * @brief Handle the configurations of a CVE.
 *
 * If secinfo_fast_init is not 0, the data will be inserted using COPY
 *  statements, otherwise INSERT and UPDATE statements will be used and the
 *  COPY buffers can be NULL.
 *
 * @param[in]     cve_db_id     Database rowid of the configuration's CVE
 * @param[in,out] node_id_ptr   Pointer to latest configuration node DB rowid
 * @param[in,out] cpe_db_id_ptr Pointer to latest CPE DB rowid.
 * @param[in]  cve_id    CVE-ID string of the CVE
 * @param[in]  configurations_array  JSON array containing the configurations
 * @param[in]  hashed_cpes           Hashtable of CPE-IDs in the database
 * @param[in]  cpe_match_nodes_buffer          COPY buffer for CPE match nodes
 * @param[in]  cpe_nodes_match_criteria_buffer COPY buffer for match criteria
 * @param[in]  cve_cpes_copy_buffer            COPY buffer for placeholder CPEs
 * @param[in]  affected_products_copy_buffer   COPY buffer for affected products
 * @param[out] products_return  Return pointer for the products string.
 *
 * @return 0 on success, -1 on error.
 */
static int
handle_cve_configurations (resource_t cve_db_id,
                           resource_t *node_id_ptr,
                           resource_t *cpe_db_id_ptr,
                           char * cve_id,
                           cJSON* configurations_array,
                           GHashTable *hashed_cpes,
                           db_copy_buffer_t *cpe_match_nodes_buffer,
                           db_copy_buffer_t *cpe_nodes_match_criteria_buffer,
                           db_copy_buffer_t *cve_cpes_copy_buffer,
                           db_copy_buffer_t *affected_products_copy_buffer,
                           gchar **products_return)
{
  cJSON *configuration_item;
  if (products_return)
    *products_return = NULL;
  GString *software = g_string_new ("");
  GHashTable *current_cve_hashed_cpes
    = g_hash_table_new (g_direct_hash, g_direct_equal);

  cJSON_ArrayForEach (configuration_item, configurations_array)
    {
      cJSON *nodes_array, *node_item;
      resource_t root_id;
      char *config_operator;
      int negate;

      if (get_cve_configuration_fields (configuration_item,
                                        cve_id,
                                        &nodes_array,
                                        &config_operator,
                                        &negate))
        {
          g_string_free (software, TRUE);
          g_hash_table_destroy (current_cve_hashed_cpes);
          return -1;
        }

      root_id = -1;
      handle_cve_configuration (cve_db_id,
                                config_operator,
                                negate,
                                node_id_ptr,
                                &root_id,
                                cpe_match_nodes_buffer);

      cJSON_ArrayForEach(node_item, nodes_array)
        {
          char *node_operator;
          cJSON *cpe_matches_array;

          if (get_cve_configuration_node_fields (node_item,
                                                 cve_id,
                                                 &node_operator,
                                                 &negate,
                                                 &cpe_matches_array))
            {
              g_string_free (software, TRUE);
              g_hash_table_destroy (current_cve_hashed_cpes);
              return -1;
            }

          if (handle_cve_configuration_node (cve_db_id,
                                             node_operator,
                                             negate,
                                             node_id_ptr,
                                             &root_id,
                                             cpe_match_nodes_buffer))
            {
              g_string_free (software, TRUE);
              g_hash_table_destroy (current_cve_hashed_cpes);
              return -1;
            }

          cJSON *cpe_match_item;
          cJSON_ArrayForEach (cpe_match_item, cpe_matches_array)
            {
              char *match_criteria_id;
              int vulnerable;

              if (get_cve_configuration_node_cpe_match_fields
                    (cpe_match_item,
                     cve_id,
                     &vulnerable,
                     &match_criteria_id))
                {
                  g_string_free (software, TRUE);
                  g_hash_table_destroy (current_cve_hashed_cpes);
                  return -1;
                }

              if (handle_cve_cpe_nodes_match_criteria
                    (cve_db_id,
                     *node_id_ptr,
                     cpe_db_id_ptr,
                     match_criteria_id,
                     vulnerable,
                     hashed_cpes,
                     current_cve_hashed_cpes,
                     software,
                     cpe_nodes_match_criteria_buffer,
                     cve_cpes_copy_buffer,
                     affected_products_copy_buffer))
                {
                  g_string_free (software, TRUE);
                  g_hash_table_destroy (current_cve_hashed_cpes);
                  return -1;
                }
            }
        }
    }

  g_hash_table_destroy (current_cve_hashed_cpes);
  if (secinfo_fast_init)
    {
      if (products_return)
        *products_return = g_string_free (software, FALSE);
      else
        g_string_free (software, TRUE);
    }
  else
    {
      if (software->len > 0)
        {
          gchar *quoted_software = sql_quote (software->str);
          sql ("UPDATE scap2.cves"
              " SET products = '%s'"
              " WHERE id = %llu;",
              quoted_software, cve_db_id);
          g_free (quoted_software);
        }
      g_string_free (software, TRUE);
    }

 return 0;
}

/**
 * @brief Get the fields of a CVE item in a JSON vulnerabilities list.
 *
 * @param[in]  vuln_item            The JSON item from the vulnerabilities list
 * @param[out] cve_id               Return of the CVE-ID string
 * @param[out] published_time       Return of the "published" time
 * @param[out] modified_time        Return of the "modified" time
 * @param[out] vector               Return of the CVSS vector
 * @param[out] score_dbl            Return of the CVSS score as a double number
 * @param[out] description_value    Return of the description
 * @param[out] configurations_array Return of the configurations array
 * @param[out] references_array     Return of the references array
 *
 * @return 0 on success, -1 on error
 */
static int
get_cve_json_fields (cJSON *vuln_item,
                     gchar **cve_id,
                     time_t *published_time,
                     time_t *modified_time,
                     gchar **vector,
                     double *score_dbl,
                     gchar **description_value,
                     cJSON **configurations_array,
                     cJSON **references_array)
{
  cJSON *cve_json;
  char *published, *modified;

  cJSON *metrics_json = NULL;
  cJSON *best_cvss_metric_item = NULL;
  cJSON *descriptions_json = NULL;
  cJSON *description_item_json = NULL;
  gboolean cvss_metric_is_primary = FALSE;

  *cve_id = *vector = NULL;
  *published_time = *modified_time = 0;
  *score_dbl = SEVERITY_MISSING;
  *configurations_array = *references_array = NULL;

  cve_json = cJSON_GetObjectItemCaseSensitive (vuln_item, "cve");
  if (!cJSON_IsObject (cve_json))
    {
      g_warning ("%s: 'cve' field is missing or not an object.", __func__);
      return -1;
    }

  *cve_id = json_object_item_string (cve_json, "id");
  if (*cve_id == NULL)
    {
      g_warning ("%s: cve id missing.", __func__);
      return -1;
    }

  published = json_object_item_string (cve_json, "published");
  if (published == NULL)
    {
      g_warning("%s: publishedDate missing for %s.", __func__, *cve_id);
      return -1;
    }
  *published_time = parse_iso_time (published);

  modified = json_object_item_string (cve_json, "lastModified");
  if (modified == NULL)
    {
      g_warning ("%s: lastModifiedDate missing for %s.", __func__, *cve_id);
      return -1;
    }
  *modified_time = parse_iso_time (modified);

  // Get CVSS vector and score from "best" metric element
  metrics_json = cJSON_GetObjectItemCaseSensitive (cve_json, "metrics");
  if (!cJSON_IsObject (metrics_json))
    {
      g_warning ("%s: Metrics missing or not an object for %s.",
                 __func__, *cve_id);
      return -1;
    }

  const char *cvss_metric_keys[] = {
    "cvssMetricV40",
    "cvssMetricV31",
    "cvssMetricV30",
    "cvssMetricV2"};

  for (int i = 0; i < 4; i++)
    {
      cJSON *cvss_metric_array
        = cJSON_GetObjectItemCaseSensitive (metrics_json, cvss_metric_keys[i]);
      if (cJSON_IsArray (cvss_metric_array)
          && cJSON_GetArraySize (cvss_metric_array) > 0)
        {
          cJSON *cvss_metric_item;
          cJSON_ArrayForEach (cvss_metric_item, cvss_metric_array)
            {
              char *source_type
                = json_object_item_string (cvss_metric_item, "type");
              if (source_type == NULL)
                {
                  g_warning ("%s: type missing in CVSS metric for %s.",
                            __func__, *cve_id);
                  return -1;
                }
              if (strcmp (source_type, "Primary") == 0)
                cvss_metric_is_primary = TRUE;

              if (cvss_metric_is_primary)
                {
                  best_cvss_metric_item = cvss_metric_item;
                  break;
                }
              else if (best_cvss_metric_item == NULL)
                best_cvss_metric_item = cvss_metric_item;
            }

          if (cvss_metric_is_primary)
            break;
        }
    }

  if (best_cvss_metric_item)
    {
      cJSON *cvss_json
        = cJSON_GetObjectItemCaseSensitive (best_cvss_metric_item, "cvssData");
      if (!cJSON_IsObject (cvss_json))
        {
          g_warning ("%s: cvssData missing or not an object for %s.",
                      __func__, *cve_id);
          return -1;
        }

      *score_dbl = json_object_item_double (cvss_json,
                                           "baseScore",
                                           SEVERITY_MISSING);
      if (*score_dbl == SEVERITY_MISSING)
        {
          g_warning ("%s: baseScore missing for %s.", __func__, *cve_id);
          return -1;
        }

      *vector = json_object_item_string (cvss_json, "vectorString");
      if (*vector == NULL)
        {
          g_warning ("%s: vectorString missing for %s.", __func__, *cve_id);
          return -1;
        }
    }

  // Get description
  descriptions_json = cJSON_GetObjectItemCaseSensitive (cve_json,
                                                        "descriptions");
  if (!cJSON_IsArray (descriptions_json))
    {
      g_warning ("%s: descriptions for %s is missing or not an array.",
                 __func__, *cve_id);
      return -1;
    }
  cJSON_ArrayForEach (description_item_json, descriptions_json)
    {
      char *lang = json_object_item_string (description_item_json, "lang");
      if (lang != NULL && strcmp (lang, "en") == 0)
        *description_value = json_object_item_string (description_item_json,
                                                      "value");
    }

  // Get configurations
  *configurations_array = cJSON_GetObjectItemCaseSensitive (cve_json,
                                                           "configurations");
  if (!cJSON_IsArray (*configurations_array))
    {
      g_warning ("%s: configurations for %s is missing or not an array.",
                 __func__, *cve_id);
      return -1;
    }

  // Get references
  *references_array = cJSON_GetObjectItemCaseSensitive (cve_json, "references");
  if (!cJSON_IsArray (*references_array))
    {
      g_warning ("%s: references for %s is missing or not an array.",
                 __func__, *cve_id);
      return -1;
    }

  return 0;
}

/**
 * @brief Handle a complete CVE item using INSERT and UPDATE SQL statement.
 *        Gather some required data and load all match rules.
 *
 * @param[in]  item  The JSON object of the CVE item.
 *
 * @return 0 success, -1 error.
 */
static int
handle_json_cve_item_inserts (cJSON *vuln_item)
{
  char *cve_id, *vector, *description_value;
  time_t published_time, modified_time;
  double score_dbl;
  cJSON *configurations_array, *references_array;
  resource_t cve_db_id, node_id;

  if (get_cve_json_fields (vuln_item,
                           &cve_id,
                           &published_time,
                           &modified_time,
                           &vector,
                           &score_dbl,
                           &description_value,
                           &configurations_array,
                           &references_array))
    return -1;

  char *quoted_description = sql_quote (description_value);

  cve_db_id = sql_int64_0
         ("INSERT INTO scap2.cves"
          " (uuid, name, creation_time, modification_time,"
          "  severity, description, cvss_vector, products)"
          " VALUES"
          " ('%s', '%s', %i, %i,"
          "  %0.1f, '%s', '%s', '%s')"
          " ON CONFLICT (uuid) DO UPDATE"
          " SET name = EXCLUDED.name,"
          "     creation_time = EXCLUDED.creation_time,"
          "     modification_time = EXCLUDED.modification_time,"
          "     severity = EXCLUDED.severity,"
          "     description = EXCLUDED.description,"
          "     cvss_vector = EXCLUDED.cvss_vector,"
          "     products = EXCLUDED.products"
          " RETURNING scap2.cves.id;",
          cve_id,
          cve_id,
          published_time,
          modified_time,
          score_dbl,
          quoted_description,
          vector,
          "");

  g_free (quoted_description);

  if (handle_cve_configurations (cve_db_id, &node_id, 0 /*cpe_db_id*/,
                                 cve_id, configurations_array, NULL,
                                 NULL, NULL, NULL, NULL, NULL))
    return -1;

  if (handle_cve_references (cve_db_id, cve_id, references_array, NULL))
    return -1;

  return 0;
}

/**
 * @brief Handle a complete CVE item using COPY SQL statements.
 *        Gather some required data and load all match rules.
 *
 * @param[in]  item  The JSON object of the CVE item
 * @param[in,out] cve_db_id_ptr  Pointer to current CVE database rowid
 * @param[in,out] node_id_ptr    Pointer to current CVE config node DB rowid
 * @param[in,out] cpe_db_id_ptr  Pointer to current placeholder CPE DB rowid
 * @param[in]  hashed_cpes  Hashtable of all CPEs
 * @param[in]  cves_buffer                     COPY buffer for CVEs
 * @param[in]  cve_refs_buffer                 COPY buffer for CVE references
 * @param[in]  cpe_match_nodes_buffer          COPY buffer for config nodes
 * @param[in]  cpe_nodes_match_criteria_buffer COPY buffer for match criteria
 * @param[in]  cve_cpes_copy_buffer            COPY buffer for placeholder CPEs
 * @param[in]  affected_products_copy_buffer   COPY buffer for affected products
 *
 * @return 0 success, -1 error.
 */
static int
handle_json_cve_item_copy (cJSON *vuln_item,
                           resource_t *cve_db_id_ptr,
                           resource_t *node_id_ptr,
                           resource_t *cpe_db_id_ptr,
                           GHashTable *hashed_cpes,
                           db_copy_buffer_t *cves_buffer,
                           db_copy_buffer_t *cve_refs_buffer,
                           db_copy_buffer_t *cpe_match_nodes_buffer,
                           db_copy_buffer_t *cpe_nodes_match_criteria_buffer,
                           db_copy_buffer_t *cve_cpes_copy_buffer,
                           db_copy_buffer_t *affected_products_copy_buffer)
{
  char *cve_id, *vector, *description_value, *products_str;
  time_t published_time, modified_time;
  double score_dbl;
  cJSON *configurations_array, *references_array;
  gchar *escaped_cve_id, *escaped_vector, *escaped_description;
  gchar *escaped_products;

  (*cve_db_id_ptr)++;

  if (get_cve_json_fields (vuln_item,
                           &cve_id,
                           &published_time,
                           &modified_time,
                           &vector,
                           &score_dbl,
                           &description_value,
                           &configurations_array,
                           &references_array))
    return -1;

  if (handle_cve_references (*cve_db_id_ptr,
                             cve_id,
                             references_array,
                             cve_refs_buffer))
    return -1;

  if (handle_cve_configurations (*cve_db_id_ptr,
                                 node_id_ptr,
                                 cpe_db_id_ptr,
                                 cve_id,
                                 configurations_array,
                                 hashed_cpes,
                                 cpe_match_nodes_buffer,
                                 cpe_nodes_match_criteria_buffer,
                                 cve_cpes_copy_buffer,
                                 affected_products_copy_buffer,
                                 &products_str))
    return -1;

  escaped_cve_id = sql_copy_escape (cve_id);
  escaped_vector = sql_copy_escape (vector);
  escaped_description = sql_copy_escape (description_value);
  escaped_products = sql_copy_escape (products_str);

  if (db_copy_buffer_append_printf (cves_buffer,
                                    "%llu\t%s\t%s\t%i\t%i\t%0.1f\t%s\t%s\t%s\n",
                                    *cve_db_id_ptr,
                                    escaped_cve_id ?: "\\N",
                                    escaped_cve_id ?: "\\N",
                                    published_time,
                                    modified_time,
                                    score_dbl,
                                    escaped_description ?: "\\N",
                                    escaped_vector ?: "\\N",
                                    escaped_products))
    {
      g_free (escaped_cve_id);
      g_free (escaped_vector);
      g_free (escaped_description);
      g_free (escaped_products);
      g_free (products_str);
      return -1;
    }

  g_free (escaped_vector);
  g_free (escaped_description);
  g_free (escaped_cve_id);
  g_free (escaped_products);
  g_free (products_str);

  return 0;
}

/**
 * @brief Initialize all COPY buffers for updating the CVEs
 *
 * @param[in]  cves_buffer                     COPY buffer for CVEs
 * @param[in]  cve_refs_buffer                 COPY buffer for CVE references
 * @param[in]  cpe_match_nodes_buffer          COPY buffer for config nodes
 * @param[in]  cpe_nodes_match_criteria_buffer COPY buffer for match criteria
 * @param[in]  cve_cpes_copy_buffer            COPY buffer for placeholder CPEs
 * @param[in]  affected_products_copy_buffer   COPY buffer for affected products
 */
static void
init_cve_copy_buffers (db_copy_buffer_t *cves_buffer,
                       db_copy_buffer_t *cve_refs_buffer,
                       db_copy_buffer_t *cpe_match_nodes_buffer,
                       db_copy_buffer_t *cpe_nodes_match_criteria_buffer,
                       db_copy_buffer_t *cve_cpes_copy_buffer,
                       db_copy_buffer_t *affected_products_copy_buffer)
{
  int buffer_size = setting_secinfo_sql_buffer_threshold_bytes() / 6;
  db_copy_buffer_init
    (cves_buffer,
     buffer_size,
     "COPY scap2.cves ("
     "  id, uuid, name, creation_time, modification_time,"
     "  severity, description, cvss_vector, products"
     ") FROM STDIN;");
  db_copy_buffer_init
    (cve_refs_buffer,
     buffer_size,
     "COPY scap2.cve_references ("
     "  cve_id, url, tags"
     ") FROM STDIN;");
  db_copy_buffer_init
    (cpe_match_nodes_buffer,
     buffer_size,
     "COPY scap2.cpe_match_nodes ("
     "  id, root_id, cve_id, operator, negate"
     ") FROM STDIN;");
  db_copy_buffer_init
    (cpe_nodes_match_criteria_buffer,
     buffer_size,
     "COPY scap2.cpe_nodes_match_criteria ("
     "  node_id, vulnerable, match_criteria_id"
     ") FROM STDIN");
  db_copy_buffer_init
    (cve_cpes_copy_buffer,
     buffer_size,
     "COPY scap2.cpes ("
     "  uuid, name, creation_time, modification_time, deprecated, cpe_name_id"
     ") FROM STDIN");
  db_copy_buffer_init
    (affected_products_copy_buffer,
     buffer_size,
     "COPY scap2.affected_products ("
     "  cve, cpe"
     ") FROM STDIN");
}

/**
 * @brief Free fields of all COPY buffers for updating the CVEs
 *
 * @param[in]  cves_buffer                     COPY buffer for CVEs
 * @param[in]  cve_refs_buffer                 COPY buffer for CVE references
 * @param[in]  cpe_match_nodes_buffer          COPY buffer for config nodes
 * @param[in]  cpe_nodes_match_criteria_buffer COPY buffer for match criteria
 * @param[in]  cve_cpes_copy_buffer            COPY buffer for placeholder CPEs
 * @param[in]  affected_products_copy_buffer   COPY buffer for affected products
 */
static void
cleanup_cve_copy_buffers (db_copy_buffer_t *cves_buffer,
                          db_copy_buffer_t *cve_refs_buffer,
                          db_copy_buffer_t *cpe_match_nodes_buffer,
                          db_copy_buffer_t *cpe_nodes_match_criteria_buffer,
                          db_copy_buffer_t *cve_cpes_copy_buffer,
                          db_copy_buffer_t *affected_products_copy_buffer)
{
  db_copy_buffer_cleanup (cves_buffer);
  db_copy_buffer_cleanup (cve_refs_buffer);
  db_copy_buffer_cleanup (cpe_match_nodes_buffer);
  db_copy_buffer_cleanup (cpe_nodes_match_criteria_buffer);
  db_copy_buffer_cleanup (cve_cpes_copy_buffer);
  db_copy_buffer_cleanup (affected_products_copy_buffer);
}

/**
 * @brief Update CVE info from a single JSON feed file.
 *
 * @param[in]     cve_path        CVE json file path
 * @param[in]     hashed_cpes     Hashtable of all CPEs
 * @param[in,out] cve_db_id_ptr   Pointer to current CVE database rowid
 * @param[in,out] node_id_ptr     Pointer to current configuration node rowid
 * @param[in,out] cpe_db_id_ptr   Pointer to current placeholder CPE rowid
 *
 * @return 0 success, -1 error.
 */
static int
update_cve_json (const gchar *cve_path,
                 GHashTable *hashed_cpes,
                 resource_t *cve_db_id_ptr,
                 resource_t *node_id_ptr,
                 resource_t *cpe_db_id_ptr)
{
  cJSON *entry;
  FILE *cve_file;
  gchar *error_message = NULL;
  gvm_json_pull_event_t event;
  gvm_json_pull_parser_t parser;
  gchar *full_path;
  int transaction_size = 0;
  db_copy_buffer_t cves_copy_buffer;
  db_copy_buffer_t cve_refs_copy_buffer;
  db_copy_buffer_t cpe_match_nodes_copy_buffer;
  db_copy_buffer_t cpe_nodes_match_criteria_copy_buffer;
  db_copy_buffer_t cve_cpes_copy_buffer;
  db_copy_buffer_t affected_products_copy_buffer;

  full_path = g_build_filename (GVM_SCAP_DATA_DIR, cve_path, NULL);

  int fd = open (full_path, O_RDONLY);

  if (fd < 0)
    {
      g_warning ("%s: Failed to open CVE file: %s",
                 __func__,
                 strerror (errno));
      g_free (full_path);
      return -1;
    }

  g_info ("Updating %s", full_path);

  cve_file = gvm_gzip_open_file_reader_fd (fd);
  if (cve_file == NULL)
    {
      g_warning ("%s: Failed to open CVE file: %s",
                 __func__,
                 strerror (errno));
      g_free (full_path);
      return -1;
    }

  g_free (full_path);

  gvm_json_pull_parser_init (&parser, cve_file);
  gvm_json_pull_event_init (&event);
  gvm_json_pull_parser_next (&parser, &event);

  if (event.type == GVM_JSON_PULL_EVENT_OBJECT_START)
    {
      gboolean cve_items_found = FALSE;
      while (!cve_items_found)
        {
          gvm_json_pull_parser_next (&parser, &event);
          gvm_json_path_elem_t *path_tail = g_queue_peek_tail (event.path);
          if (event.type == GVM_JSON_PULL_EVENT_ARRAY_START && path_tail
              && path_tail->key && strcmp (path_tail->key, "vulnerabilities") == 0)
            {
              cve_items_found = TRUE;
            }
          else if (event.type == GVM_JSON_PULL_EVENT_ERROR)
            {
              g_warning ("%s: Parser error: %s", __func__, event.error_message);
              gvm_json_pull_event_cleanup (&event);
              gvm_json_pull_parser_cleanup (&parser);
              fclose (cve_file);
              return -1;
            }
          else if (event.type == GVM_JSON_PULL_EVENT_OBJECT_END)
            {
              g_warning ("%s: Unexpected json object end.", __func__);
              gvm_json_pull_event_cleanup (&event);
              gvm_json_pull_parser_cleanup (&parser);
              fclose (cve_file);
              return -1;
            }
        }
      gvm_json_pull_parser_next (&parser, &event);
      sql_begin_immediate ();
      drop_indexes_cve ();
      if (secinfo_fast_init)
        {
          init_cve_copy_buffers (&cves_copy_buffer,
                                 &cve_refs_copy_buffer,
                                 &cpe_match_nodes_copy_buffer,
                                 &cpe_nodes_match_criteria_copy_buffer,
                                 &cve_cpes_copy_buffer,
                                 &affected_products_copy_buffer);
        }

      while (event.type == GVM_JSON_PULL_EVENT_OBJECT_START)
        {
          entry = gvm_json_pull_expand_container (&parser, &error_message);
          if (error_message)
            {
              g_warning ("%s: Error expanding vulnerability item: %s", __func__, error_message);
              gvm_json_pull_event_cleanup (&event);
              gvm_json_pull_parser_cleanup (&parser);
              cJSON_Delete (entry);
              fclose (cve_file);
              sql_commit ();
              return -1;
            }
          if (secinfo_fast_init)
            {
              if (handle_json_cve_item_copy
                    (entry,
                     cve_db_id_ptr,
                     node_id_ptr,
                     cpe_db_id_ptr,
                     hashed_cpes,
                     &cves_copy_buffer,
                     &cve_refs_copy_buffer,
                     &cpe_match_nodes_copy_buffer,
                     &cpe_nodes_match_criteria_copy_buffer,
                     &cve_cpes_copy_buffer,
                     &affected_products_copy_buffer))
                {
                  gvm_json_pull_event_cleanup (&event);
                  gvm_json_pull_parser_cleanup (&parser);
                  cleanup_cve_copy_buffers
                    (&cves_copy_buffer,
                     &cve_refs_copy_buffer,
                     &cpe_match_nodes_copy_buffer,
                     &cpe_nodes_match_criteria_copy_buffer,
                     &cve_cpes_copy_buffer,
                     &affected_products_copy_buffer);
                  cJSON_Delete (entry);
                  fclose (cve_file);
                  sql_commit ();
                  return -1;
                }
            }
          else
            {
              if (handle_json_cve_item_inserts (entry))
                {
                  gvm_json_pull_event_cleanup (&event);
                  gvm_json_pull_parser_cleanup (&parser);
                  cJSON_Delete (entry);
                  fclose (cve_file);
                  sql_commit ();
                  return -1;
                }
            }
          increment_transaction_size (&transaction_size);
          cJSON_Delete (entry);
          gvm_json_pull_parser_next (&parser, &event);
        }
      if (secinfo_fast_init)
        {
          if (db_copy_buffer_commit (&cves_copy_buffer, TRUE)
              || db_copy_buffer_commit (&cve_refs_copy_buffer, TRUE)
              || db_copy_buffer_commit (&cpe_match_nodes_copy_buffer, TRUE)
              || db_copy_buffer_commit (&cpe_nodes_match_criteria_copy_buffer,
                                        TRUE)
              || db_copy_buffer_commit (&cve_cpes_copy_buffer, TRUE)
              || db_copy_buffer_commit (&affected_products_copy_buffer, TRUE))
            {
              cleanup_cve_copy_buffers (&cves_copy_buffer,
                                        &cve_refs_copy_buffer,
                                        &cpe_match_nodes_copy_buffer,
                                        &cpe_nodes_match_criteria_copy_buffer,
                                        &cve_cpes_copy_buffer,
                                        &affected_products_copy_buffer);
              gvm_json_pull_event_cleanup (&event);
              gvm_json_pull_parser_cleanup (&parser);
              fclose (cve_file);
              sql_commit ();
              return -1;
            }
        }
      create_indexes_cve ();

      sql ("SELECT setval('scap2.cves_id_seq', max(id))"
           " FROM scap2.cves;");
      sql ("SELECT setval('scap2.cpes_id_seq', max(id))"
           " FROM scap2.cpes;");
      sql ("SELECT setval('scap2.cpe_match_nodes_id_seq', max(id))"
           " FROM scap2.cpe_match_nodes;");
      sql_commit ();
    }
  else if (event.type == GVM_JSON_PULL_EVENT_ERROR)
    {
      g_warning ("%s: Parser error: %s", __func__, event.error_message);
      gvm_json_pull_event_cleanup (&event);
      gvm_json_pull_parser_cleanup (&parser);
      fclose (cve_file);
      return -1;
    }
  else
    {
      g_warning ("%s: File must contain a JSON object.", __func__);
      gvm_json_pull_event_cleanup (&event);
      gvm_json_pull_parser_cleanup (&parser);
      fclose (cve_file);
      return -1;
    }

  gvm_json_pull_event_cleanup (&event);
  gvm_json_pull_parser_cleanup (&parser);
  fclose (cve_file);
  return 0;
}

/**
 * @brief Update CVE info from a single XML feed file.
 *
 * @param[in]  xml_path          XML path.
 * @param[in]  hashed_cpes       Hashed CPEs.
 *
 * @return 0 success, -1 error.
 */
static int
update_cve_xml (const gchar *xml_path, GHashTable *hashed_cpes)
{
  gchar *error_message = NULL;
  xml_file_iterator_t iterator;
  element_t entry;
  gchar *full_path;
  GStatBuf state;
  int transaction_size = 0;
  int ret;

  full_path = g_build_filename (GVM_SCAP_DATA_DIR, xml_path, NULL);

  if (g_stat (full_path, &state))
    {
      g_warning ("%s: Failed to stat SCAP file: %s",
                 __func__,
                 strerror (errno));
      return -1;
    }

  g_info ("Updating %s", full_path);

  iterator = xml_file_iterator_new ();
  ret = xml_file_iterator_init_from_file_path (iterator, full_path, 1);
  switch (ret)
    {
      case 0:
        break;
      case 2:
        g_warning ("%s: Could not open file '%s' for XML file iterator: %s",
                   __func__, full_path, strerror(errno));
        xml_file_iterator_free (iterator);
        return -1;
      case 3:
        g_warning ("%s: Could not create parser context for XML file iterator",
                   __func__);
        xml_file_iterator_free (iterator);
        return -1;
      default:
        g_warning ("%s: Could not initialize XML file iterator",
                   __func__);
        xml_file_iterator_free (iterator);
        return -1;
    }

  sql_begin_immediate ();
  entry = xml_file_iterator_next (iterator, &error_message);
  while (entry)
    {
      if (strcmp (element_name (entry), "entry") == 0)
        {
          element_t last_modified;

          last_modified = element_child (entry, "vuln:last-modified-datetime");
          if (last_modified == NULL)
            {
              error_message = g_strdup ("vuln:last-modified-datetime missing");
              goto fail;
            }

          if (insert_cve_from_entry (entry, last_modified, hashed_cpes,
                                     &transaction_size))
            {
              g_warning ("%s: Insert of CVE into database failed. CVE skipped.", __func__);
            }
        }

      element_free (entry);
      entry = xml_file_iterator_next (iterator, &error_message);
    }

  if (error_message)
    goto fail;

  xml_file_iterator_free (iterator);
  g_free (full_path);
  sql_commit ();
  return 0;

 fail:
  xml_file_iterator_free (iterator);
  if (error_message)
    g_warning ("Update of CVEs failed at file '%s': %s",
              full_path, error_message);
  else
    g_warning ("Update of CVEs failed at file '%s'",
              full_path);
  g_free (full_path);
  g_free (error_message);
  sql_commit ();
  return -1;
}

/**
 * @brief Update SCAP CVEs.
 *
 * Assume that the databases are attached.
 *
 * @return 0 success, -1 error.
 */
static int
update_scap_cves ()
{
  GError *error;
  int count;
  GDir *dir;
  const gchar *cve_path;
  GHashTable *hashed_cpes;
  iterator_t cpes;
  resource_t cve_db_id = 0;
  resource_t node_id = 0;
  resource_t cpe_db_id = 0;

  g_info ("Updating CVEs");

  error = NULL;
  dir = g_dir_open (GVM_SCAP_DATA_DIR, 0, &error);
  if (dir == NULL)
    {
      g_warning ("%s: Failed to open directory '%s': %s",
                 __func__, GVM_SCAP_DATA_DIR, error->message);
      g_error_free (error);
      return -1;
    }

  hashed_cpes = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
  init_iterator (&cpes, "SELECT uuid, id FROM scap2.cpes;");
  while (next (&cpes))
    {
      long current_row_cpe_id = iterator_int64 (&cpes, 1);
      g_hash_table_insert (hashed_cpes,
                           (gpointer*) g_strdup (iterator_string (&cpes, 0)),
                           GINT_TO_POINTER (current_row_cpe_id));
      if (current_row_cpe_id > cpe_db_id)
        cpe_db_id = current_row_cpe_id;
    }

  gboolean read_json = FALSE;
  while ((cve_path = g_dir_read_name (dir)))
    {
      if (fnmatch ("nvdcve-2.0-*.json.gz", cve_path, 0) == 0 ||
          fnmatch ("nvdcve-2.0-*.json", cve_path, 0) == 0)
        {
          read_json = TRUE;
          break;
        }
    }
  g_dir_rewind (dir);

  count = 0;
  while ((cve_path = g_dir_read_name (dir)))
    {
      if ((fnmatch ("nvdcve-2.0-*.json.gz", cve_path, 0) == 0 ||
           fnmatch ("nvdcve-2.0-*.json", cve_path, 0) == 0)
          && read_json)
        {
          if (update_cve_json (cve_path, hashed_cpes,
                               &cve_db_id, &node_id, &cpe_db_id))
            {
              g_dir_close (dir);
              g_hash_table_destroy (hashed_cpes);
              cleanup_iterator (&cpes);
              return -1;
            }
          count++;
        }
      else if ((fnmatch ("nvdcve-2.0-*.xml", cve_path, 0) == 0) && !read_json)
        {
          if (update_cve_xml (cve_path, hashed_cpes))
            {
              g_dir_close (dir);
              g_hash_table_destroy (hashed_cpes);
              cleanup_iterator (&cpes);
              return -1;
            }
          count++;
        }
    }

  if (count == 0)
    g_warning ("No CVEs found in %s", GVM_SCAP_DATA_DIR);

  g_dir_close (dir);
  g_hash_table_destroy (hashed_cpes);
  cleanup_iterator (&cpes);
  return 0;
}

static void
exec_affected_products_sql (const char *cve_ids_str)
{
  sql ("INSERT INTO scap2.affected_products"
        "  SELECT DISTINCT scap2.cpe_match_nodes.cve_id, scap2.cpes.id"
        "    FROM scap2.cpe_match_nodes, scap2.cpe_nodes_match_criteria,"
        "         scap2.cpe_matches, scap2.cpes"
        "    WHERE scap2.cpe_match_nodes.cve_id IN (%s)"
        "      AND scap2.cpe_match_nodes.id ="
        "            scap2.cpe_nodes_match_criteria.node_id"
        "      AND scap2.cpe_nodes_match_criteria.vulnerable = 1"
        "      AND scap2.cpe_nodes_match_criteria.match_criteria_id ="
        "            scap2.cpe_matches.match_criteria_id"
        "      AND scap2.cpe_matches.cpe_name_id = scap2.cpes.cpe_name_id"
        "  ON CONFLICT DO NOTHING;",
        cve_ids_str);
}

/**
 * @brief Update SCAP affected products.
 *
 * Assume that the databases are attached.
 */
static void
update_scap_affected_products ()
{
  iterator_t cves_iter;
  GString *cve_ids_buffer;
  int count = 0;

  g_info ("Updating affected products ...");

  init_iterator (&cves_iter,
                 "SELECT DISTINCT cve_id FROM scap2.cpe_match_nodes");

  cve_ids_buffer = g_string_new ("");
  while (next (&cves_iter))
    {
      resource_t cve_id;
      cve_id = iterator_int64 (&cves_iter, 0);
      g_string_append_printf (cve_ids_buffer, "%s%llu",
                              cve_ids_buffer->len ? ", " : "",
                              cve_id);
      count ++;

      if (count % affected_products_query_size == 0)
        {
          exec_affected_products_sql (cve_ids_buffer->str);
          g_string_truncate (cve_ids_buffer, 0);
          g_debug ("%s: Products of %d CVEs processed", __func__, count);
        }
    }
  cleanup_iterator (&cves_iter);

  if (cve_ids_buffer->len)
    {
      exec_affected_products_sql (cve_ids_buffer->str);
      g_debug ("%s: Products of %d CVEs processed", __func__, count);
    }
  g_string_free (cve_ids_buffer, TRUE);

  g_info ("Updating affected products ... done");
}

/**
 * @brief Insert a SCAP CPE match string from JSON.
 *
 * @param[in]  inserts          Pointer to SQL buffer for match string entries.
 * @param[in]  matches_inserts  Pointer to SQL buffer for match string matches.
 * @param[in]  match_string_item   JSON object from the matchStrings list.
 *
 * @return 0 success, -1 error.
 */
static int
handle_json_cpe_match_string (inserts_t *inserts,
                              inserts_t *matches_inserts,
                              db_copy_buffer_t *copy_buffer,
                              db_copy_buffer_t *matches_copy_buffer,
                              gboolean use_copy,
                              cJSON *match_string_item)
{
  cJSON *match_string, *matches_array;
  char *criteria, *match_criteria_id, *status, *ver_str;
  gchar *quoted_version_start_incl, *quoted_version_start_excl;
  gchar *quoted_version_end_incl, *quoted_version_end_excl;
  gchar *quoted_criteria, *quoted_match_criteria_id, *quoted_status;
  int first;
  gchar* (*quote_func)(const char*) = use_copy ? sql_copy_escape : sql_quote;

  assert (inserts);
  assert (matches_inserts);

  match_string = cJSON_GetObjectItemCaseSensitive (match_string_item,
                                                   "matchString");
  if (!cJSON_IsObject (match_string))
    {
      g_warning ("%s: 'matchString' field is missing or not an object",
                 __func__);
      return -1;
    }

  criteria = json_object_item_string (match_string, "criteria");
  if (criteria == NULL)
    {
      g_warning ("%s: 'criteria' field missing or not a string", __func__);
      return -1;
    }

  match_criteria_id = json_object_item_string (match_string,
                                               "matchCriteriaId");
  if (match_criteria_id == NULL)
    {
      g_warning ("%s: 'matchCriteriaId' field missing or not a string",
                 __func__);
      return -1;
    }

  status = json_object_item_string (match_string, "status");
  if (status == NULL)
    {
      g_warning ("%s: 'status' field missing or not a string", __func__);
      return -1;
    }

  ver_str = json_object_item_string (match_string, "versionStartIncluding");
  if (use_copy)
    quoted_version_start_incl = ver_str
                                  ? sql_copy_escape (ver_str)
                                  : g_strdup ("\\N");
  else
    quoted_version_start_incl = sql_insert (ver_str);


  ver_str = json_object_item_string (match_string, "versionStartExcluding");
  if (use_copy)
    quoted_version_start_excl = ver_str
                                  ? sql_copy_escape (ver_str)
                                  : g_strdup ("\\N");
  else
    quoted_version_start_excl = sql_insert (ver_str);

  ver_str = json_object_item_string (match_string, "versionEndIncluding");
  if (use_copy)
    quoted_version_end_incl = ver_str
                                ? sql_copy_escape (ver_str)
                                : g_strdup ("\\N");
  else
    quoted_version_end_incl = sql_insert (ver_str);

  ver_str = json_object_item_string (match_string, "versionEndExcluding");
  if (use_copy)
    quoted_version_end_excl = ver_str
                                ? sql_copy_escape (ver_str)
                                : g_strdup ("\\N");
  else
    quoted_version_end_excl = sql_insert (ver_str);

  quoted_match_criteria_id = quote_func (match_criteria_id);
  quoted_criteria = fs_to_uri_convert_and_quote_cpe_name (criteria, quote_func);
  quoted_status = quote_func (status);

  if (use_copy)
    {
      if (db_copy_buffer_append_printf (copy_buffer,
                                        "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
                                        quoted_match_criteria_id,
                                        quoted_criteria,
                                        quoted_version_start_incl,
                                        quoted_version_start_excl,
                                        quoted_version_end_incl,
                                        quoted_version_end_excl,
                                        quoted_status))
        {
          g_free (quoted_match_criteria_id);
          g_free (quoted_criteria);
          g_free (quoted_version_start_incl);
          g_free (quoted_version_start_excl);
          g_free (quoted_version_end_incl);
          g_free (quoted_version_end_excl);
          g_free (quoted_status);
          return -1;
        }
    }
  else
    {
      first = inserts_check_size (inserts);

      g_string_append_printf (inserts->statement,
                              "%s ('%s', '%s', %s, %s, %s, %s, '%s')",
                              first ? "" : ",",
                              quoted_match_criteria_id,
                              quoted_criteria,
                              quoted_version_start_incl,
                              quoted_version_start_excl,
                              quoted_version_end_incl,
                              quoted_version_end_excl,
                              quoted_status);

      inserts->current_chunk_size++;
    }

  g_free (quoted_criteria);
  g_free (quoted_version_start_incl);
  g_free (quoted_version_start_excl);
  g_free (quoted_version_end_incl);
  g_free (quoted_version_end_excl);
  g_free (quoted_status);

  matches_array = cJSON_GetObjectItemCaseSensitive (match_string, "matches");

  if (cJSON_IsArray (matches_array) && cJSON_GetArraySize (matches_array) > 0)
    {
      cJSON *match_item;
      cJSON_ArrayForEach (match_item, matches_array)
        {
          char *cpe_name_id, *cpe_name;
          gchar *quoted_cpe_name_id, *quoted_cpe_name;

          cpe_name_id = json_object_item_string (match_item, "cpeNameId");
          if (cpe_name_id == NULL)
            {
              g_warning ("%s: 'cpeNameId' field missing or not a string",
                         __func__);
              g_free (quoted_match_criteria_id);
              return -1;
            }

          cpe_name = json_object_item_string (match_item, "cpeName");
          if (cpe_name == NULL)
            {
              g_warning ("%s: 'cpe_name' field missing or not a string",
                         __func__);
              g_free (quoted_match_criteria_id);
              return -1;
            }

          quoted_cpe_name_id = quote_func (cpe_name_id);
          quoted_cpe_name = fs_to_uri_convert_and_quote_cpe_name (cpe_name,
                                                                  quote_func);

          if (use_copy)
            {
              if (db_copy_buffer_append_printf (matches_copy_buffer,
                                                "%s\t%s\t%s\n",
                                                quoted_match_criteria_id,
                                                quoted_cpe_name_id,
                                                quoted_cpe_name))
                {
                  g_free (quoted_match_criteria_id);
                  g_free (quoted_cpe_name_id);
                  g_free (quoted_cpe_name);
                  return -1;
                }
            }
          else
            {
              first = inserts_check_size (matches_inserts);

              g_string_append_printf (matches_inserts->statement,
                                      "%s ('%s', '%s', '%s')",
                                      first ? "" : ",",
                                      quoted_match_criteria_id,
                                      quoted_cpe_name_id,
                                      quoted_cpe_name);

              matches_inserts->current_chunk_size++;
            }

          g_free (quoted_cpe_name_id);
          g_free (quoted_cpe_name);
        }
    }

  g_free (quoted_match_criteria_id);
  return 0;
}

/**
 * @brief Updates the CPE match strings in the SCAP database.
 *
 * @return 0 success, -1 error.
 */
static int
update_scap_cpe_match_strings ()
{
  gchar *current_json_path;
  FILE *cpe_match_strings_file;
  gvm_json_pull_event_t event;
  gvm_json_pull_parser_t parser;
  inserts_t inserts, matches_inserts;
  db_copy_buffer_t copy_buffer, matches_copy_buffer;
  gboolean use_copy = secinfo_fast_init;

  current_json_path = g_build_filename (GVM_SCAP_DATA_DIR,
                                        "nvd-cpe-matches.json.gz",
                                        NULL);
  int fd = open(current_json_path, O_RDONLY);

  if (fd < 0 && errno == ENOENT)
  {
    g_free (current_json_path);
    current_json_path = g_build_filename (GVM_SCAP_DATA_DIR,
                                          "nvd-cpe-matches.json",
                                          NULL);
    fd = open(current_json_path, O_RDONLY);
  }

  if (fd < 0)
    {
      int ret;
      if (errno == ENOENT)
        {
          g_info ("%s: CPE match strings file '%s' not found",
                  __func__, current_json_path);
          ret = 0;
        }
      else
        {
          g_warning ("%s: Failed to open CPE match strings file: %s",
                    __func__, strerror (errno));
          ret = -1;
        }
        g_free (current_json_path);
      return ret;
    }

  cpe_match_strings_file = gvm_gzip_open_file_reader_fd (fd);

  if (cpe_match_strings_file == NULL)
    {
      g_warning ("%s: Failed to convert file descriptor to FILE*: %s",
                 __func__,
                 strerror (errno));
      g_free (current_json_path);
      close (fd);
      return -1;
    }

  g_info ("Updating CPE match strings from %s", current_json_path);
  g_free (current_json_path);

  gvm_json_pull_event_init (&event);
  gvm_json_pull_parser_init (&parser, cpe_match_strings_file);

  gvm_json_pull_parser_next (&parser, &event);

  if (event.type == GVM_JSON_PULL_EVENT_OBJECT_START)
    {
      gboolean cpe_match_strings_found = FALSE;
      while (!cpe_match_strings_found)
        {
          gvm_json_pull_parser_next (&parser, &event);
	        gvm_json_path_elem_t *path_tail = g_queue_peek_tail (event.path);
	        if (event.type == GVM_JSON_PULL_EVENT_ARRAY_START
              && path_tail && strcmp (path_tail->key, "matchStrings") == 0)
            {
              cpe_match_strings_found = TRUE;
            }
          else if (event.type == GVM_JSON_PULL_EVENT_ERROR)
            {
              g_warning ("%s: Parser error: %s", __func__, event.error_message);
              gvm_json_pull_event_cleanup (&event);
              gvm_json_pull_parser_cleanup (&parser);
              fclose (cpe_match_strings_file);
              return -1;
            }
          else if (event.type == GVM_JSON_PULL_EVENT_OBJECT_END
                   && g_queue_is_empty (event.path))
            {
              g_warning ("%s: Unexpected json object end. Missing matchStrings field",
                         __func__);
              gvm_json_pull_event_cleanup (&event);
              gvm_json_pull_parser_cleanup (&parser);
              fclose (cpe_match_strings_file);
              return -1;
            }
        }

      sql_begin_immediate ();

      if (use_copy)
        {
          db_copy_buffer_init
            (&copy_buffer,
             setting_secinfo_sql_buffer_threshold_bytes () / 2,
             "COPY scap2.cpe_match_strings"
             "  (match_criteria_id, criteria, version_start_incl,"
             "   version_start_excl, version_end_incl, version_end_excl,"
             "   status)"
             " FROM STDIN");

          db_copy_buffer_init
            (&matches_copy_buffer,
             setting_secinfo_sql_buffer_threshold_bytes () / 2,
             "COPY scap2.cpe_matches"
             "  (match_criteria_id, cpe_name_id, cpe_name)"
             " FROM STDIN");
        }
      else
        {
          inserts_init
            (&inserts,
             CPE_MAX_CHUNK_SIZE,
             setting_secinfo_sql_buffer_threshold_bytes (),
             "INSERT INTO scap2.cpe_match_strings"
             "  (match_criteria_id, criteria, version_start_incl,"
             "   version_start_excl, version_end_incl, version_end_excl,"
             "   status)"
             "  VALUES ",
             " ON CONFLICT (match_criteria_id) DO UPDATE"
             " SET criteria = EXCLUDED.criteria,"
             "     version_start_incl = EXCLUDED.version_start_incl,"
             "     version_start_excl = EXCLUDED.version_start_excl,"
             "     version_end_incl = EXCLUDED.version_end_incl,"
             "     version_end_excl = EXCLUDED.version_end_excl,"
             "     status = EXCLUDED.status");

          inserts_init
            (&matches_inserts, 10,
             setting_secinfo_sql_buffer_threshold_bytes (),
             "INSERT INTO scap2.cpe_matches"
             "  (match_criteria_id, cpe_name_id, cpe_name)"
             "  VALUES ",
             "");
        }

      gvm_json_pull_parser_next (&parser, &event);
      while (event.type == GVM_JSON_PULL_EVENT_OBJECT_START)
        {
          gchar *error_message;
          cJSON *cpe_match_string_item
            = gvm_json_pull_expand_container (&parser, &error_message);
          if (error_message)
            {
              g_warning ("%s: Error expanding match string item: %s",
                         __func__, error_message);
              cJSON_Delete (cpe_match_string_item);
              if (use_copy)
                {
                  db_copy_buffer_cleanup (&copy_buffer);
                  db_copy_buffer_cleanup (&matches_copy_buffer);
                }
              else
                {
                  inserts_free (&inserts);
                  inserts_free (&matches_inserts);
                }
              sql_commit ();
              g_warning ("Update of CPE match strings failed");
              gvm_json_pull_event_cleanup (&event);
              gvm_json_pull_parser_cleanup (&parser);
              fclose (cpe_match_strings_file);
              return -1;
            }
          if (handle_json_cpe_match_string (&inserts,
                                            &matches_inserts,
                                            &copy_buffer,
                                            &matches_copy_buffer,
                                            use_copy,
                                            cpe_match_string_item))
            {
              cJSON_Delete (cpe_match_string_item);
              inserts_free (&inserts);
              inserts_free (&matches_inserts);
              if (use_copy)
                {
                  db_copy_buffer_cleanup (&copy_buffer);
                  db_copy_buffer_cleanup (&matches_copy_buffer);
                }
              else
                {
                  inserts_free (&inserts);
                  inserts_free (&matches_inserts);
                }
              sql_commit ();
              g_warning ("Update of CPE match strings failed");
              gvm_json_pull_event_cleanup (&event);
              gvm_json_pull_parser_cleanup (&parser);
              fclose (cpe_match_strings_file);
              return -1;
            }
          cJSON_Delete (cpe_match_string_item);
          gvm_json_pull_parser_next (&parser, &event);
	      }
    }
  else if (event.type == GVM_JSON_PULL_EVENT_ERROR)
    {
      g_warning ("%s: Parser error: %s", __func__, event.error_message);
      gvm_json_pull_event_cleanup (&event);
      gvm_json_pull_parser_cleanup (&parser);
      fclose (cpe_match_strings_file);
      return -1;
    }
  else
    {
      g_warning ("%s: CVE match strings file is not a JSON object.",
                 __func__);
      gvm_json_pull_event_cleanup (&event);
      gvm_json_pull_parser_cleanup (&parser);
      fclose (cpe_match_strings_file);
      return -1;
    }

  if (use_copy)
    {
      if (db_copy_buffer_commit (&copy_buffer, TRUE)
          || db_copy_buffer_commit (&matches_copy_buffer, TRUE))
        {
          db_copy_buffer_cleanup (&copy_buffer);
          db_copy_buffer_cleanup (&matches_copy_buffer);
          return -1;
        }
      sql ("SELECT setval('scap2.cpe_match_strings_id_seq', max(id))"
           " FROM scap2.cpe_match_strings;");
      sql ("SELECT setval('scap2.cpe_matches_id_seq', max(id))"
           " FROM scap2.cpe_matches;");
    }
  else
    {
      inserts_run (&inserts, TRUE);
      inserts_run (&matches_inserts, TRUE);
    }
  sql_commit ();
  gvm_json_pull_event_cleanup (&event);
  gvm_json_pull_parser_cleanup (&parser);
  fclose (cpe_match_strings_file);
  return 0;
}

/**
 * @brief Adds a EPSS score entry to an SQL inserts buffer.
 *
 * @param[in]  inserts      The SQL inserts buffer to add to.
 * @param[in]  cve          The CVE the epss score and percentile apply to.
 * @param[in]  epss         The EPSS score to add.
 * @param[in]  percentile   The EPSS percentile to add.
 */
static void
insert_epss_score_entry (inserts_t *inserts, const char *cve,
                         double epss, double percentile)
{
  gchar *quoted_cve;
  int first = inserts_check_size (inserts);

  quoted_cve = sql_quote (cve);
  g_string_append_printf (inserts->statement,
                          "%s ('%s', %lf, %.3lf)",
                          first ? "" : ",",
                          quoted_cve,
                          epss,
                          percentile * 100.0);
  g_free (quoted_cve);

  inserts->current_chunk_size++;
}

/**
 * @brief Checks a failure condition for validating EPSS JSON.
 */
#define EPSS_JSON_FAIL_IF(failure_condition, error_message)       \
if (failure_condition) {                                          \
  g_warning ("%s: %s", __func__, error_message);                  \
  goto fail_insert;                                                 \
}

/**
 * @brief Updates the base EPSS scores table in the SCAP database.
 *
 * @return 0 success, -1 error.
 */
static int
update_epss_scores ()
{
  gchar *current_json_path;
  gchar *error_message = NULL;
  FILE *epss_scores_file;
  cJSON *epss_entry;
  gvm_json_pull_event_t event;
  gvm_json_pull_parser_t parser;
  inserts_t inserts;

  current_json_path = g_build_filename (GVM_SCAP_DATA_DIR,
                                        "epss-scores-current.json.gz",
                                        NULL);
  int fd = open(current_json_path, O_RDONLY);

  if (fd < 0 && errno == ENOENT)
    {
      g_free (current_json_path);
      current_json_path = g_build_filename (GVM_SCAP_DATA_DIR,
                                            "epss-scores-current.json",
                                            NULL);
      fd = open(current_json_path, O_RDONLY);
    }

  if (fd < 0)
    {
      int ret;
      if (errno == ENOENT)
        {
          g_info ("%s: EPSS scores file '%s' not found",
                  __func__, current_json_path);
          ret = 0;
        }
      else
        {
          g_warning ("%s: Failed to open EPSS scores file: %s",
                    __func__, strerror (errno));
          ret = -1;
        }
      g_free (current_json_path);
      return ret;
    }

  epss_scores_file = gvm_gzip_open_file_reader_fd (fd);
  if (epss_scores_file == NULL)
    {
      g_warning ("%s: Failed to convert file descriptor to FILE*: %s",
                 __func__,
                 strerror (errno));
      g_free (current_json_path);
      close(fd);
      return -1;
    }

  g_info ("Updating EPSS scores from %s", current_json_path);
  g_free (current_json_path);

  gvm_json_pull_event_init (&event);
  gvm_json_pull_parser_init (&parser, epss_scores_file);

  gvm_json_pull_parser_next (&parser, &event);

  if (event.type == GVM_JSON_PULL_EVENT_OBJECT_START)
    {
      gboolean epss_scores_found = FALSE;
      while (!epss_scores_found)
        {
          gvm_json_pull_parser_next (&parser, &event);
          gvm_json_path_elem_t *path_tail = g_queue_peek_tail (event.path);
          if (event.type == GVM_JSON_PULL_EVENT_ARRAY_START
              && path_tail && strcmp (path_tail->key, "epss_scores") == 0)
            {
              epss_scores_found = TRUE;
            }
          else if (event.type == GVM_JSON_PULL_EVENT_ERROR)
            {
              g_warning ("%s: Parser error: %s", __func__, event.error_message);
              gvm_json_pull_event_cleanup (&event);
              gvm_json_pull_parser_cleanup (&parser);
              fclose (epss_scores_file);
              return -1;
            }
          else if (event.type == GVM_JSON_PULL_EVENT_OBJECT_END
                   && g_queue_is_empty (event.path))
            {
              g_warning ("%s: Unexpected json object end. Missing epss_scores field", __func__);
              gvm_json_pull_event_cleanup (&event);
              gvm_json_pull_parser_cleanup (&parser);
              fclose (epss_scores_file);
              return -1;
            }
        }

      sql_begin_immediate ();
      inserts_init (&inserts,
                    EPSS_MAX_CHUNK_SIZE,
                    setting_secinfo_sql_buffer_threshold_bytes (),
                    "INSERT INTO scap2.epss_scores"
                    "  (cve, epss, percentile)"
                    "  VALUES ",
                    " ON CONFLICT (cve) DO NOTHING");

      gvm_json_pull_parser_next (&parser, &event);
      while (event.type == GVM_JSON_PULL_EVENT_OBJECT_START)
        {
          cJSON *cve_json, *epss_json, *percentile_json;

          epss_entry = gvm_json_pull_expand_container (&parser, &error_message);

          if (error_message)
            {
              g_warning ("%s: Error expanding EPSS item: %s", __func__, error_message);
              g_free (error_message);
              goto fail_insert;
            }

          cve_json = cJSON_GetObjectItemCaseSensitive (epss_entry, "cve");
          epss_json = cJSON_GetObjectItemCaseSensitive (epss_entry, "epss");
          percentile_json = cJSON_GetObjectItemCaseSensitive (epss_entry, "percentile");

          EPSS_JSON_FAIL_IF (cve_json == NULL,
                            "Item missing mandatory 'cve' field");

          EPSS_JSON_FAIL_IF (epss_json == NULL,
                            "Item missing mandatory 'epss' field");

          EPSS_JSON_FAIL_IF (percentile_json == NULL,
                            "Item missing mandatory 'percentile' field");

          EPSS_JSON_FAIL_IF (! cJSON_IsString (cve_json),
                            "Field 'cve' in item is not a string");

          EPSS_JSON_FAIL_IF (! cJSON_IsNumber(epss_json),
                            "Field 'epss' in item is not a number");

          EPSS_JSON_FAIL_IF (! cJSON_IsNumber(percentile_json),
                            "Field 'percentile' in item is not a number");

          insert_epss_score_entry (&inserts,
                                   cve_json->valuestring,
                                   epss_json->valuedouble,
                                   percentile_json->valuedouble);

          gvm_json_pull_parser_next (&parser, &event);
          cJSON_Delete (epss_entry);
        }
    }
  else if (event.type == GVM_JSON_PULL_EVENT_ERROR)
    {
      g_warning ("%s: Parser error: %s", __func__, event.error_message);
      gvm_json_pull_event_cleanup (&event);
      gvm_json_pull_parser_cleanup (&parser);
      fclose (epss_scores_file);
      return -1;
    }
  else
    {
      g_warning ("%s: EPSS scores file is not a JSON object.", __func__);
      gvm_json_pull_event_cleanup (&event);
      gvm_json_pull_parser_cleanup (&parser);
      fclose (epss_scores_file);
      return -1;
    }

  inserts_run (&inserts, TRUE);
  sql_commit ();
  gvm_json_pull_event_cleanup (&event);
  gvm_json_pull_parser_cleanup (&parser);
  fclose (epss_scores_file);
  return 0;

fail_insert:
  inserts_free (&inserts);
  sql_rollback ();
  char *printed_item = cJSON_Print (epss_entry);
  g_message ("%s: invalid item: %s", __func__, printed_item);
  cJSON_Delete (epss_entry);
  free (printed_item);
  gvm_json_pull_event_cleanup (&event);
  gvm_json_pull_parser_cleanup (&parser);
  fclose (epss_scores_file);
  return -1;
}

/**
 * @brief Update EPSS data as supplement to SCAP CVEs.
 *
 * Assume that the databases are attached.
 *
 * @return 0 success, -1 error.
 */
static int
update_scap_epss ()
{
  if (update_epss_scores ())
    return -1;

  return 0;
}



/* CERT and SCAP update. */

/**
 * @brief Reinit a db.
 *
 * @param[in]  name  Name of db.
 *
 * @return 0 success, -1 error.
 */
static int
manage_db_reinit (const gchar *name)
{
  manage_db_remove (name);
  if (manage_db_init (name))
    {
      g_warning ("Could not reinitialize %s database", name);
      return -1;
    }
  return 0;
}

/**
 * @brief Sync a SecInfo DB.
 *
 * @param[in]  sigmask_current    Sigmask to restore in child.
 * @param[in]  update             Function to do the sync.
 * @param[in]  process_title      Process title.
 *
 * @return PID of the forked process handling the SecInfo sync, -1 on error.
 */
static pid_t
sync_secinfo (sigset_t *sigmask_current, int (*update) (void),
              const gchar *process_title)
{
  int pid;

  /* Fork a child to sync the db, so that the parent can return to the main
   * loop. */

  /* Use the default termination handlers for the child, because sync_secinfo
   * is called from the main process (via manage_schedule).  The signal
   * handlers inherited from the main process would not work because they
   * need the process to watch termination_signal. */
  pid = fork_with_handlers ();
  switch (pid)
    {
      case 0:
        /* Child.  Carry on to sync the db, reopen the database (required
         * after fork). */
        init_sentry ();

        /* Restore the sigmask that was blanked for pselect in the parent. */
        pthread_sigmask (SIG_SETMASK, sigmask_current, NULL);

        /* Cleanup so that exit works. */

        cleanup_manage_process (FALSE);

        /* Init. */

        reinit_manage_process ();
        manage_session_init (current_credentials.uuid);

        break;

      case -1:
        /* Parent on error.  Reschedule and continue to next task. */
        g_warning ("%s: fork failed", __func__);
        return -1;

      default:
        /* Parent.  Continue to next task. */
        return pid;

    }

  setproctitle ("%s", process_title);

  if (update () == 0)
    {
      check_alerts ();
    }

  gvm_close_sentry ();
  exit (EXIT_SUCCESS);
}

/**
 * @brief Get the feed timestamp.
 *
 * @param[in]  name  Feed type: SCAP or CERT.
 *
 * @return Timestamp from feed.  0 if missing.  -1 on error.
 */
static int
manage_feed_timestamp (const gchar *name)
{
  GError *error;
  gchar *timestamp;
  gsize len;
  time_t stamp;

  error = NULL;
  if (strcasecmp (name, "scap") == 0)
    g_file_get_contents (GVM_SCAP_DATA_DIR "/timestamp", &timestamp, &len,
                         &error);
  else
    g_file_get_contents (GVM_CERT_DATA_DIR "/timestamp", &timestamp, &len,
                         &error);
  if (error)
    {
      if (error->code == G_FILE_ERROR_NOENT)
        stamp = 0;
      else
        {
          g_warning ("%s: Failed to get %s feed timestamp: %s",
                     __func__,
                     name,
                     error->message);
          return -1;
        }
    }
  else
    {
      if (strlen (timestamp) < 8)
        {
          g_warning ("%s: %s feed timestamp too short: %s",
                     __func__,
                     name,
                     timestamp);
          g_free (timestamp);
          return -1;
        }

      timestamp[8] = '\0';
      stamp = parse_feed_timestamp (timestamp);
      g_free (timestamp);
      if (stamp == 0)
        return -1;
    }

 return stamp;
}

/**
 * @brief Gets the SCAP or CERT database version status.
 *
 * @param[in]  feed_type  The feed type to check. Must be "cert" or "scap".
 *
 * @return 0 feed current, 1 update needed, 2 database missing,
 *         3 missing "last_update", 4 inconsistent data, -1 error.
 */
int
secinfo_feed_version_status (const char *feed_type)
{
  int last_feed_update, last_db_update;

  if (strcmp (feed_type, "cert") == 0)
    {
      if (manage_cert_loaded () == 0)
        return 2;
    }
  else if (strcmp (feed_type, "scap") == 0)
    {
      if (manage_scap_loaded () == 0)
        return 2;
    }
  else
    {
      g_warning ("%s: Unexpected feed type: %s", __func__, feed_type);
      return -1;
    }

  last_feed_update = manage_feed_timestamp (feed_type);
  if (last_feed_update == -1)
    return -1;

  last_db_update = sql_int ("SELECT coalesce ((SELECT value FROM %s.meta"
                            "                  WHERE name = 'last_update'),"
                            "                 '-3');",
                            feed_type);
  if (last_db_update == -3)
    return 3;
  else if (last_db_update < 0)
    return 4;
  else
    {
      if (last_db_update == last_feed_update)
        {
          return 0;
        }

      if (last_db_update > last_feed_update)
        {
          g_warning ("%s: last %s database update later than last feed update",
                     __func__, feed_type);
          return -1;
        }
    }
  return 1;
}


/* CERT update. */

/**
 * @brief Ensure CERT db is at the right version, and in the right mode.
 *
 * @return 0 success, -1 error.
 */
int
check_cert_db_version ()
{
  int db_version = manage_cert_db_version ();

  if (db_version < GVMD_CERT_DATABASE_VERSION)
    {
      int ret;
      g_info ("Reinitialization of the CERT database necessary");

      ret = manage_db_reinit ("cert");
      if (ret)
        return ret;

      return sync_cert ();
    }
  else if (db_version > GVMD_CERT_DATABASE_VERSION)
    {
      g_warning ("%s: CERT database version %d is newer than"
                 " supported version %d",
                 __func__, db_version, GVMD_CERT_DATABASE_VERSION);
    }
  return 0;
}

/**
 * @brief Update timestamp in CERT db from feed timestamp.
 */
static void
update_cert_timestamp ()
{
  GError *error;
  gchar *timestamp;
  gsize len;
  time_t stamp;

  error = NULL;
  g_file_get_contents (GVM_CERT_DATA_DIR "/timestamp", &timestamp, &len,
                       &error);
  if (error)
    {
      if (error->code == G_FILE_ERROR_NOENT)
        stamp = 0;
      else
        {
          g_warning ("%s: Failed to get timestamp: %s",
                     __func__,
                     error->message);
          stamp = time(NULL);
        }
    }
  else
    {
      if (strlen (timestamp) < 8)
        {
          g_warning ("%s: Feed timestamp too short: %s",
                     __func__,
                     timestamp);
          g_free (timestamp);
          stamp = time(NULL);
        }
      else
        {
          timestamp[8] = '\0';
          g_debug ("%s: parsing: %s", __func__, timestamp);
          stamp = parse_feed_timestamp (timestamp);
          g_free (timestamp);
          if (stamp == 0)
            stamp = time(NULL);
        }
    }

  g_debug ("%s: setting last_update: %lld", __func__, (long long) stamp);
  sql ("UPDATE cert.meta SET value = '%lld' WHERE name = 'last_update';",
       (long long) stamp);
}

/**
 * @brief Update DFN-CERT Max CVSS.
 *
 * @param[in]  updated_dfn_cert  Whether CERT-Bund updated.
 * @param[in]  last_cert_update  Time of last CERT update.
 * @param[in]  last_scap_update  Time of last SCAP update.
 */
static void
update_cvss_dfn_cert (int updated_dfn_cert, int last_cert_update,
                      int last_scap_update)
{
  /* TODO greenbone-certdata-sync did retries. */

  if (updated_dfn_cert || (last_scap_update > last_cert_update))
    {
      g_info ("Updating Max CVSS for DFN-CERT");
      sql ("UPDATE cert.dfn_cert_advs"
           " SET severity = (SELECT max (severity)"
           "                  FROM scap.cves"
           "                  WHERE name"
           "                  IN (SELECT cve_name"
           "                      FROM cert.dfn_cert_cves"
           "                      WHERE adv_id = dfn_cert_advs.id)"
           "                  AND severity != 0);");

      g_info ("Updating DFN-CERT CVSS max succeeded.");
    }
  else
    g_info ("Updating DFN-CERT CVSS max succeeded (nothing to do).");
}

/**
 * @brief Update CERT-Bund Max CVSS.
 *
 * @param[in]  updated_cert_bund  Whether CERT-Bund updated.
 * @param[in]  last_cert_update  Time of last CERT update.
 * @param[in]  last_scap_update  Time of last SCAP update.
 */
static void
update_cvss_cert_bund (int updated_cert_bund, int last_cert_update,
                       int last_scap_update)
{
  /* TODO greenbone-certdata-sync did retries. */

  if (updated_cert_bund || (last_scap_update > last_cert_update))
    {
      g_info ("Updating Max CVSS for CERT-Bund");
      sql ("UPDATE cert.cert_bund_advs"
           " SET severity = (SELECT max (severity)"
           "                  FROM scap.cves"
           "                  WHERE name"
           "                     IN (SELECT cve_name"
           "                         FROM cert.cert_bund_cves"
           "                         WHERE adv_id = cert_bund_advs.id)"
           "                  AND severity != 0);");

      g_info ("Updating CERT-Bund CVSS max succeeded.");
    }
  else
    g_info ("Updating CERT-Bund CVSS max succeeded (nothing to do).");
}

/**
 * @brief Sync the CERT DB.
 *
 * @return 0 success, -1 error.
 */
static int
sync_cert ()
{
  int scap_db_version;
  int last_feed_update, last_cert_update, updated_dfn_cert;
  int updated_cert_bund;

  if (manage_cert_db_exists ())
    {
      if (check_cert_db_version ())
        return -1;
    }
  else
    {
      g_info ("Initializing CERT database");
      if (manage_db_init ("cert"))
        {
          g_warning ("%s: Could not initialize CERT database", __func__);
          return -1;
        }
    }

  last_cert_update = 0;
  if (manage_cert_loaded ())
    last_cert_update = sql_int ("SELECT coalesce ((SELECT value FROM cert.meta"
                                "                  WHERE name = 'last_update'),"
                                "                 '-1');");

  if (last_cert_update == -1)
    {
      g_warning ("%s: Inconsistent data. Resetting CERT database.",
                 __func__);
      if (manage_db_reinit ("cert"))
        {
          g_warning ("%s: could not reinitialize CERT database", __func__);
          return -1;
        }
      last_cert_update = 0;
    }

  last_feed_update = manage_feed_timestamp ("cert");
  if (last_feed_update == -1)
    return -1;

  if (last_cert_update >= last_feed_update)
    return -1;

  g_debug ("%s: sync", __func__);

  g_info ("%s: Updating data from feed", __func__);

  g_debug ("%s: update dfn", __func__);

  updated_dfn_cert = update_dfn_cert_advisories (last_cert_update);
  if (updated_dfn_cert == -1)
    goto fail;

  g_debug ("%s: update bund", __func__);

  updated_cert_bund = update_cert_bund_advisories (last_cert_update);
  if (updated_cert_bund == -1)
    goto fail;

  g_debug ("%s: update cvss", __func__);

  /* Update CERT data that depends on SCAP. */
  scap_db_version = manage_scap_db_version();

  if (scap_db_version == -1)
    g_info ("SCAP database does not exist (yet),"
            " skipping CERT severity score update");
  else if (scap_db_version < GVMD_SCAP_DATABASE_VERSION)
    g_info ("SCAP database has to be migrated,"
            " skipping CERT severity score update");
  else if (scap_db_version > GVMD_SCAP_DATABASE_VERSION)
    g_warning ("SCAP database is newer than supported version,"
               " skipping CERT severity score update");
  else
    {
      int last_scap_update;

      last_scap_update
        = sql_int ("SELECT coalesce ((SELECT value FROM scap.meta"
                   "                  WHERE name = 'last_update'),"
                   "                 '0');");
      g_debug ("%s: last_scap_update: %i", __func__, last_scap_update);
      g_debug ("%s: last_cert_update: %i", __func__, last_cert_update);

      update_cvss_dfn_cert (updated_dfn_cert,
                            last_cert_update,
                            last_scap_update);
      update_cvss_cert_bund (updated_cert_bund,
                             last_cert_update,
                             last_scap_update);
    }

  g_debug ("%s: update timestamp", __func__);

  update_cert_timestamp ();

  g_info ("%s: Updating CERT info succeeded.", __func__);

  return 0;

 fail:
  update_cert_timestamp ();
  return -1;
}

/**
 * @brief Sync the CERT DB.
 *
 * @param[in]  sigmask_current  Sigmask to restore in child.
 *
 * @return PID of the forked process handling the CERT sync, -1 on error.
 */
pid_t
manage_sync_cert (sigset_t *sigmask_current)
{
  return sync_secinfo (sigmask_current,
                       sync_cert,
                       "Syncing CERT");
}


/* SCAP update. */

/**
 * @brief Ensure SCAP db is at the right version, and in the right mode.
 *
 * @return 0 success, -1 error.
 */
int
check_scap_db_version ()
{
  int db_version = manage_scap_db_version ();

  if (db_version < GVMD_SCAP_DATABASE_VERSION)
    {
      g_info ("Reinitialization of the SCAP database necessary");
      manage_db_remove ("scap");
      return update_scap (TRUE);
    }
  else if (db_version > GVMD_SCAP_DATABASE_VERSION)
    {
      g_warning ("%s: SCAP database version %d is newer than"
                 " supported version %d",
                 __func__, db_version, GVMD_SCAP_DATABASE_VERSION);
    }
  return 0;
}

/**
 * @brief Update timestamp in SCAP db from feed timestamp.
 */
static void
update_scap_timestamp ()
{
  GError *error;
  gchar *timestamp;
  gsize len;
  time_t stamp;

  error = NULL;
  g_file_get_contents (GVM_SCAP_DATA_DIR "/timestamp", &timestamp, &len,
                       &error);
  if (error)
    {
      if (error->code == G_FILE_ERROR_NOENT)
        stamp = 0;
      else
        {
          g_warning ("%s: Failed to get timestamp: %s",
                     __func__,
                     error->message);
          stamp = time(NULL);
        }
    }
  else
    {
      if (strlen (timestamp) < 8)
        {
          g_warning ("%s: Feed timestamp too short: %s",
                     __func__,
                     timestamp);
          g_free (timestamp);
          stamp = time(NULL);
        }
      else
        {
          timestamp[8] = '\0';
          g_debug ("%s: parsing: %s", __func__, timestamp);
          stamp = parse_feed_timestamp (timestamp);
          g_free (timestamp);
          if (stamp == 0)
            stamp = time(NULL);
        }
    }

  g_debug ("%s: setting last_update: %lld", __func__, (long long) stamp);
  sql ("UPDATE scap2.meta SET value = '%lld' WHERE name = 'last_update';",
       (long long) stamp);
}

/**
 * @brief Update SCAP Max CVSS.
 */
static void
update_scap_cvss ()
{
  /* TODO greenbone-scapdata-sync did retries. */

  g_info ("Updating CVSS scores and CVE counts for CPEs");
  sql ("UPDATE scap2.cpes"
       " SET (severity, cve_refs)"
       "       = (WITH affected_cves"
       "          AS (SELECT cve FROM scap2.affected_products"
       "              WHERE cpe=cpes.id)"
       "          SELECT (SELECT max (severity) FROM scap2.cves"
       "                  WHERE id IN (SELECT cve FROM affected_cves)),"
       "                 (SELECT count (*) FROM affected_cves));");
}

/**
 * @brief Update SCAP placeholder CVES.
 */
static void
update_scap_placeholders ()
{
  /* TODO greenbone-scapdata-sync did retries. */

  g_info ("Updating placeholder CPEs");
  sql ("UPDATE scap2.cpes"
       " SET creation_time = (SELECT min (creation_time)"
       "                      FROM scap2.cves"
       "                      WHERE id IN (SELECT cve"
       "                                   FROM scap2.affected_products"
       "                                   WHERE cpe=cpes.id)),"
       "     modification_time = (SELECT min(creation_time)"
       "                          FROM scap2.cves"
       "                          WHERE id IN (SELECT cve"
       "                                       FROM scap2.affected_products"
       "                                       WHERE cpe=cpes.id))"
       " WHERE cpes.title IS NULL;");
}

/**
 * @brief Update extra data for VTs based on SCAP and SCAP supplement data.
 */
static void
update_vt_scap_extra_data ()
{
  g_info ("Assigning EPSS scores to VTs");

  sql ("UPDATE nvts"
       " SET epss_cve = NULL,"
       "     epss_score = NULL,"
       "     epss_percentile = NULL,"
       "     epss_severity = NULL,"
       "     max_epss_cve = NULL,"
       "     max_epss_score = NULL,"
       "     max_epss_percentile = NULL,"
       "     max_epss_severity = NULL;");

  sql ("WITH epss_candidates AS ("
       " SELECT vt_oid, cve, severity, epss, percentile,"
       "         rank() OVER (PARTITION BY vt_oid"
       "                      ORDER BY severity DESC,"
       "                      epss DESC,"
       "                      scap.cves.modification_time DESC) AS rank"
       "   FROM (SELECT * FROM vt_refs WHERE type='cve') AS vt_cves"
       "   JOIN scap.epss_scores ON ref_id = cve"
       "   LEFT JOIN scap.cves ON scap.cves.name = cve"
       "  ORDER BY vt_oid"
       ") "
       "UPDATE nvts"
       " SET epss_cve = epss_candidates.cve,"
       "     epss_score = epss_candidates.epss,"
       "     epss_percentile = epss_candidates.percentile,"
       "     epss_severity = epss_candidates.severity"
       " FROM epss_candidates"
       " WHERE epss_candidates.vt_oid = nvts.oid"
       "   AND epss_candidates.rank = 1;");

  sql ("WITH epss_candidates AS ("
       " SELECT vt_oid, cve, severity, epss, percentile,"
       "         rank() OVER (PARTITION BY vt_oid"
       "                      ORDER BY epss DESC,"
       "                      severity DESC,"
       "                      scap.cves.modification_time DESC) AS rank"
       "   FROM (SELECT * FROM vt_refs WHERE type='cve') AS vt_cves"
       "   JOIN scap.epss_scores ON ref_id = cve"
       "   LEFT JOIN scap.cves ON scap.cves.name = cve"
       "  ORDER BY vt_oid"
       ") "
       "UPDATE nvts"
       " SET max_epss_cve = epss_candidates.cve,"
       "     max_epss_score = epss_candidates.epss,"
       "     max_epss_percentile = epss_candidates.percentile,"
       "     max_epss_severity = epss_candidates.severity"
       " FROM epss_candidates"
       " WHERE epss_candidates.vt_oid = nvts.oid"
       "   AND epss_candidates.rank = 1;");

  create_view_result_vt_epss ();
}

/**
 * @brief Update CERT data that depends on SCAP.
 */
static void
update_cert_data ()
{
  int cert_db_version;

  cert_db_version = manage_cert_db_version();

  if (cert_db_version == -1)
    g_info ("CERT database does not exist (yet),"
            " skipping CERT severity score update");
  else if (cert_db_version < GVMD_CERT_DATABASE_VERSION)
    g_info ("CERT database has to be migrated,"
            " skipping CERT severity score update");
  else if (cert_db_version > GVMD_CERT_DATABASE_VERSION)
    g_warning ("CERT database is newer than supported version,"
               " skipping CERT severity score update");
  else
    {
      int last_cert_update, last_scap_update;

      last_cert_update = sql_int ("SELECT"
                                  " coalesce ((SELECT value FROM cert.meta"
                                  "            WHERE name = 'last_update'),"
                                  "           '0');");

      last_scap_update = sql_int ("SELECT"
                                  " coalesce ((SELECT value FROM scap.meta"
                                  "            WHERE name = 'last_update'),"
                                  "           '0');");

      g_debug ("%s: last_scap_update: %i", __func__, last_scap_update);
      g_debug ("%s: last_cert_update: %i", __func__, last_cert_update);

      update_cvss_dfn_cert (1, last_cert_update, last_scap_update);
      update_cvss_cert_bund (1, last_cert_update, last_scap_update);
    }
}

/**
 * @brief Finish scap update.
 */
static void
update_scap_end ()
{
  g_debug ("%s: update timestamp", __func__);

  update_scap_timestamp ();

  /* Replace the real scap schema with the new one. */

  if (sql_int ("SELECT EXISTS (SELECT schema_name FROM"
               "               information_schema.schemata"
               "               WHERE schema_name = 'scap');"))
    {
      sql ("ALTER SCHEMA scap RENAME TO scap3;");
      sql ("ALTER SCHEMA scap2 RENAME TO scap;");
      sql ("DROP SCHEMA scap3 CASCADE;");
      /* View 'vulns' contains references into the SCAP schema, so it is
       * removed by the CASCADE. */
      create_view_vulns ();
      create_view_result_vt_epss ();
    }
  else
    sql ("ALTER SCHEMA scap2 RENAME TO scap;");

  /* Update CERT data that depends on SCAP. */

  update_cert_data ();

  /* Analyze. */

  sql ("ANALYZE scap.cves;");
  sql ("ANALYZE scap.cpes;");
  sql ("ANALYZE scap.affected_products;");

  g_info ("%s: Updating SCAP info succeeded", __func__);
  setproctitle ("Syncing SCAP: done");
}

/**
 * @brief Abort scap update.
 */
static void
abort_scap_update ()
{
  g_debug ("%s: update timestamp", __func__);

  if (sql_int ("SELECT EXISTS (SELECT schema_name FROM"
               "               information_schema.schemata"
               "               WHERE schema_name = 'scap');"))
    {
      update_scap_timestamp ();
      sql ("UPDATE scap.meta SET value = "
           "    (SELECT value from scap2.meta WHERE name = 'last_update')"
           "  WHERE name = 'last_update';");
      sql ("DROP SCHEMA scap2 CASCADE;");
      /* View 'vulns' contains references into the SCAP schema, so it is
       * removed by the CASCADE. */
      create_view_vulns ();
      create_view_result_vt_epss ();
      /* Update CERT data that depends on SCAP. */
      update_cert_data ();
    }
  else
    {
      /* reset scap2 schema */
      if (manage_db_init ("scap"))
        {
          g_warning ("%s: could not reset scap2 schema, db init failed", __func__);
        }
      else if (manage_db_init_indexes ("scap"))
        {
          g_warning ("%s: could not reset scap2 schema, init indexes failed", __func__);
        }
      else if (manage_db_add_constraints ("scap"))
        {
          g_warning ("%s: could not reset scap2 schema, add constrains failed", __func__);
        }

      if (sql_int ("SELECT EXISTS (SELECT schema_name FROM"
                   "               information_schema.schemata"
                   "               WHERE schema_name = 'scap2');"))
        {
          update_scap_timestamp ();
          sql ("ALTER SCHEMA scap2 RENAME TO scap;");
          /* Update CERT data that depends on SCAP. */
          update_cert_data ();
        }
    }

  g_info ("%s: Updating SCAP data aborted", __func__);
  setproctitle ("Syncing SCAP: aborted");
}

/**
 * @brief Try load the feed from feed CSV files.
 *
 * @return 0 success, -1 error, 1 no CSV.
 */
static int
try_load_csv ()
{
  gchar *file_cves, *file_cpes, *file_affected_products;

  file_cves = g_build_filename (GVM_SCAP_DATA_CSV_DIR, "table-cves.csv", NULL);
  file_cpes = g_build_filename (GVM_SCAP_DATA_CSV_DIR, "table-cpes.csv", NULL);
  file_affected_products = g_build_filename (GVM_SCAP_DATA_CSV_DIR,
                                             "table-affected-products.csv",
                                             NULL);

  if (gvm_file_is_readable (file_cves)
      && gvm_file_is_readable (file_cpes)
      && gvm_file_is_readable (file_affected_products))
    {
      /* Create a new schema, "scap2". */

      if (manage_db_init ("scap"))
        {
          g_warning ("%s: could not initialize SCAP database 2", __func__);
          return -1;
        }

      sql ("COPY scap2.cves FROM '%s' WITH (FORMAT csv);", file_cves);
      g_free (file_cves);

      sql ("COPY scap2.cpes FROM '%s' WITH (FORMAT csv);", file_cpes);
      g_free (file_cpes);

      sql ("COPY scap2.affected_products FROM '%s' WITH (FORMAT csv);",
           file_affected_products);
      g_free (file_affected_products);


      /* Add the indexes and constraints, now that the data is ready. */

      g_debug ("%s: add indexes", __func__);
      setproctitle ("Syncing SCAP: Adding indexes");

      if (manage_db_init_indexes ("scap"))
        {
          g_warning ("%s: could not initialize SCAP indexes", __func__);
          return -1;
        }

      g_debug ("%s: add constraints", __func__);
      setproctitle ("Syncing SCAP: Adding constraints");

      if (manage_db_add_constraints ("scap"))
        {
          g_warning ("%s: could not add SCAP constraints", __func__);
          return -1;
        }

      update_scap_end ();
      return 0;
    }
  return 1;
}

/**
 * @brief Update all data in the SCAP DB.
 *
 * @param[in]  reset_scap_db  Whether to rebuild regardless of last_scap_update.
 *
 * @return 0 success, -1 error.
 */
static int
update_scap (gboolean reset_scap_db)
{
  if (reset_scap_db)
    g_warning ("%s: Full rebuild requested, resetting SCAP db",
               __func__);
  else if (manage_scap_loaded () == 0)
    g_warning ("%s: No SCAP db present, rebuilding SCAP db from scratch",
               __func__);
  else
    {
      int last_scap_update;

      last_scap_update = sql_int ("SELECT coalesce ((SELECT value FROM scap.meta"
                                  "                  WHERE name = 'last_update'),"
                                  "                 '-3');");
      if (last_scap_update == -3)
        g_warning ("%s: SCAP db missing last_update record, resetting SCAP db",
                   __func__);
      else if (last_scap_update < 0)
        g_warning ("%s: Inconsistent data, resetting SCAP db",
                   __func__);
      else
        {
          int last_feed_update;

          last_feed_update = manage_feed_timestamp ("scap");

          if (last_feed_update == -1)
            return -1;

          if (last_scap_update == last_feed_update)
            {
              setproctitle ("Syncing SCAP: done");
              return 0;
            }

          if (last_scap_update > last_feed_update)
            {
              g_warning ("%s: last scap update later than last feed update",
                         __func__);
              return -1;
            }
        }
    }

  /* If there's CSV in the feed, just load it. */

  if (try_load_csv () == 0)
    return 0;

  /* Create a new schema, "scap2". */

  if (manage_db_init ("scap"))
    {
      g_warning ("%s: could not initialize SCAP database 2", __func__);
      return -1;
    }

  /* Add the indexes and constraints. */

  g_debug ("%s: add indexes", __func__);
  setproctitle ("Syncing SCAP: Adding indexes");

  if (manage_db_init_indexes ("scap"))
    {
      g_warning ("%s: could not initialize SCAP indexes", __func__);
      return -1;
    }

  if (manage_db_add_constraints ("scap"))
    {
      g_warning ("%s: could not add SCAP constraints", __func__);
      return -1;
    }

  /* Update into the new schema. */

  g_debug ("%s: sync", __func__);

  g_info ("%s: Updating data from feed", __func__);

  g_debug ("%s: secinfo_fast_init = %d", __func__, secinfo_fast_init);

  g_debug ("%s: update cpes", __func__);
  setproctitle ("Syncing SCAP: Updating CPEs");

  if (update_scap_cpes () == -1)
    {
      abort_scap_update ();
      return -1;
    }

  g_debug ("%s: update cpe match strings", __func__);
  setproctitle ("Syncing SCAP: Updating CPE Match Strings");

  if (update_scap_cpe_match_strings () == -1)
    {
      abort_scap_update ();
      return -1;
    }

  g_debug ("%s: update cves", __func__);
  setproctitle ("Syncing SCAP: Updating CVEs");

  if (update_scap_cves () == -1)
    {
      abort_scap_update ();
      return -1;
    }

  if (secinfo_fast_init == 0)
    {
      g_debug ("%s: update affected_products", __func__);
      setproctitle ("Syncing SCAP: Updating affected products");

      update_scap_affected_products ();
    }

  g_debug ("%s: updating user defined data", __func__);

  g_debug ("%s: update epss", __func__);
  setproctitle ("Syncing SCAP: Updating EPSS scores");

  if (update_scap_epss () == -1)
    {
      abort_scap_update ();
      return -1;
    }

  /* Do calculations that need all data. */

  g_debug ("%s: update max cvss", __func__);
  setproctitle ("Syncing SCAP: Updating max CVSS");

  update_scap_cvss ();

  g_debug ("%s: update placeholders", __func__);
  setproctitle ("Syncing SCAP: Updating placeholders");

  update_scap_placeholders ();

  update_scap_end ();
  return 0;
}

/**
 * @brief Update extra data in the SCAP DB that depends on other feeds.
 */
void
update_scap_extra ()
{
  if (manage_scap_loaded () == 0)
    {
      g_info ("%s: SCAP database missing, skipping extra data update",
              __func__);
      return;
    }

  g_debug ("%s: update SCAP extra data of VTs", __func__);
  setproctitle ("Syncing SCAP: Updating VT extra data");

  update_vt_scap_extra_data ();
}

/**
 * @brief Sync the SCAP DB.
 *
 * @return 0 success, -1 error.
 */
static int
sync_scap ()
{
  return update_scap (FALSE);
}

/**
 * @brief Sync the SCAP DB.
 *
 * @param[in]  sigmask_current  Sigmask to restore in child.
 *
 * @return PID of the forked process handling the SCAP sync, -1 on error.
 */
pid_t
manage_sync_scap (sigset_t *sigmask_current)
{
  return sync_secinfo (sigmask_current,
                       sync_scap,
                       "Syncing SCAP");
}

/**
 * @brief Rebuild the entire SCAP DB.
 *
 * @return 0 success, 2 sync running, -1 error
 */
static int
rebuild_scap ()
{
  int ret = -1;
  lockfile_t lockfile;

  ret = feed_lockfile_lock_timeout (&lockfile);
  if (ret == 1)
    return 2;
  else if (ret)
    return -1;

  ret = update_scap (TRUE);

  if (ret == 0)
    update_scap_extra ();

  if (feed_lockfile_unlock (&lockfile))
    {
      g_warning (
        "%s: failed to close lock file: %s", __func__, strerror (errno));
      return -1;
    }

  return ret;
}

/**
 * @brief Rebuild part of the SCAP DB.
 *
 * @param[in]  log_config  Log configuration.
 * @param[in]  database    Location of manage database.
 *
 * @return 0 success, -1 error.
 */
int
manage_rebuild_scap (GSList *log_config, const db_conn_info_t *database)
{
  int ret;

  g_info ("   Rebuilding SCAP data");

  ret = manage_option_setup (log_config, database,
                             0 /* avoid_db_check_inserts */);
  if (ret)
    return -1;

  ret = rebuild_scap ();
  if (ret == 2)
    {
      printf ("SCAP sync is currently running.\n");
      goto fail;
    }
  else if (ret)
    goto fail;

  manage_option_cleanup ();
  return 0;

fail:
  manage_option_cleanup ();
  return -1;
}

/**
 * @brief Set the affected products query size.
 *
 * @param new_size The new affected products query size.
 */
void
set_affected_products_query_size (int new_size)
{
  if (new_size <= 0)
    affected_products_query_size = AFFECTED_PRODUCTS_QUERY_SIZE_DEFAULT;
  else
    affected_products_query_size = new_size;
}

/**
 * @brief Set the SecInfo update commit size.
 *
 * @param new_commit_size The new SecInfo update commit size.
 */
void
set_secinfo_commit_size (int new_commit_size)
{
  if (new_commit_size < 0)
    secinfo_commit_size = 0;
  else
    secinfo_commit_size = new_commit_size;
}

/**
 * @brief Set the SecInfo fast initialization option.
 *
 * @param new_fast_init The new SecInfo fast initialization option.
 */
void
set_secinfo_fast_init (int new_fast_init)
{
  if (new_fast_init < 0)
    secinfo_fast_init = SECINFO_FAST_INIT_DEFAULT;
  else
    secinfo_fast_init = new_fast_init;
}
