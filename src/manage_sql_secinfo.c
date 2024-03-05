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
 * @file manage_sql_secinfo.c
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

#include <gvm/base/gvm_sentry.h>
#include <bsd/unistd.h>
#include <gvm/util/fileutils.h>
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
 * @brief Commit size for updates.
 */
static int secinfo_commit_size = SECINFO_COMMIT_SIZE_DEFAULT;


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
 * @param[in]  name            Name of the info
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
 * @brief Get the status from a CPE iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The Status of the CPE, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (cpe_info_iterator_status, GET_ITERATOR_COLUMN_COUNT + 1);

/**
 * @brief Get the highest severity Score of all CVE's referencing this cpe.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The highest severity score of the CPE,
 *         or NULL if iteration is complete. Freed by cleanup_iterator.
 */
DEF_ACCESS (cpe_info_iterator_severity, GET_ITERATOR_COLUMN_COUNT + 3);

/**
 * @brief Get the Number of CVE's referencing this cpe from a CPE iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The Number of references to the CPE, or NULL if iteration is
 *         complete. Freed by cleanup_iterator.
 */
DEF_ACCESS (cpe_info_iterator_cve_refs, GET_ITERATOR_COLUMN_COUNT + 4);

/**
 * @brief Get the NVD ID for this CPE.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The NVD ID of this CPE, or NULL if iteration is
 *         complete. Freed by cleanup_iterator.
 */
DEF_ACCESS (cpe_info_iterator_nvd_id, GET_ITERATOR_COLUMN_COUNT + 5);

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
  return count ("cve", get, columns, NULL, filter_columns, 0, 0, 0, FALSE);
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
                           NULL,
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
 * @param[in]  name            Name of the info
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
 * @brief Insert a SCAP CPE.
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
  gchar *name, *status, *deprecated, *nvd_id;
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

  deprecated = element_attribute (item_metadata,
                                 "deprecated-by-nvd-id");
  if (deprecated
      && (g_regex_match_simple ("^[0-9]+$", (gchar *) deprecated, 0, 0)
          == 0))
    {
      g_warning ("%s: invalid deprecated-by-nvd-id: %s",
                 __func__,
                 deprecated);
      g_free (name);
      g_free (status);
      return -1;
    }

  nvd_id = element_attribute (item_metadata, "nvd-id");
  if (nvd_id == NULL)
    {
      g_warning ("%s: nvd_id missing", __func__);
      g_free (name);
      g_free (status);
      g_free (deprecated);
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
                          "%s ('%s', '%s', '%s', %i, %i, '%s', %s, '%s')",
                          first ? "" : ",",
                          quoted_name,
                          quoted_name,
                          quoted_title,
                          modification_time,
                          modification_time,
                          quoted_status,
                          deprecated ? deprecated : "NULL",
                          quoted_nvd_id);

  inserts->current_chunk_size++;

  g_free (quoted_title);
  g_free (quoted_name);
  g_free (quoted_status);
  g_free (quoted_nvd_id);
  g_free (deprecated);

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
 * @brief Update SCAP CPEs from a file.
 *
 * @param[in]  path             Path to file.
 *
 * @return 0 success, -1 error.
 */
static int
update_scap_cpes_from_file (const gchar *path)
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
                "  modification_time, status, deprecated_by_id,"
                "  nvd_id)"
                " VALUES",
                " ON CONFLICT (uuid) DO UPDATE"
                " SET name = EXCLUDED.name,"
                "     title = EXCLUDED.title,"
                "     creation_time = EXCLUDED.creation_time,"
                "     modification_time = EXCLUDED.modification_time,"
                "     status = EXCLUDED.status,"
                "     deprecated_by_id = EXCLUDED.deprecated_by_id,"
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

  g_info ("Updating CPEs");

  ret = update_scap_cpes_from_file (full_path);
  if (ret)
    return -1;

  return 0;
}


/* SCAP update: CVEs. */

/**
 * @brief Check if this is the last appearance of a product in its siblings.
 *
 * @param[in]  product  Product.
 *
 * @return 1 if last appearance of product, else 0.
 */
static int
last_appearance (element_t product)
{
  element_t product2;

  product2 = element_next (product);
  while (product2)
    {
      gchar *product_text, *product2_text;
      int cmp;

      product_text = element_text (product);
      product2_text = element_text (product2);

      cmp = strcmp (product_text, product2_text);
      g_free (product_text);
      g_free (product2_text);
      if (cmp == 0)
        break;
      product2 = element_next (product2);
    }
  return product2 == NULL;
}

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
  element_t product;
  int first_product, first_affected;
  GString *sql_cpes, *sql_affected;

  if (list == NULL)
    return;

  product = element_first_child (list);

  if (product == NULL)
    return;

  sql_cpes = g_string_new ("INSERT INTO scap2.cpes"
                           " (uuid, name, creation_time,"
                           "  modification_time)"
                           " VALUES");
  sql_affected = g_string_new ("INSERT INTO scap2.affected_products"
                               " (cve, cpe)"
                               " VALUES");

  /* Buffer the SQL. */

  first_product = first_affected = 1;

  while (product)
    {
      gchar *product_text;

      if (strcmp (element_name (product), "product"))
        {
          product = element_next (product);
          continue;
        }

      product_text = element_text (product);
      if (strlen (product_text))
        {
          gchar *quoted_product, *product_decoded;
          gchar *product_tilde;

          product_decoded = g_uri_unescape_string
                             (element_text (product), NULL);
          product_tilde = string_replace (product_decoded,
                                          "~", "%7E", "%7e",
                                          NULL);
          g_free (product_decoded);
          quoted_product = sql_quote (product_tilde);

          if (g_hash_table_contains (hashed_cpes, product_tilde) == 0)
            {
              /* The product was not in the db.
               *
               * Only insert the product if this is its last appearance
               * in the current CVE's XML, to avoid errors from Postgres
               * ON CONFLICT DO UPDATE. */

              if (last_appearance (product))
                {
                  /* The CPE does not appear later in this CVE's XML. */

                  g_string_append_printf
                   (sql_cpes,
                    "%s ('%s', '%s', %i, %i)",
                    first_product ? "" : ",", quoted_product, quoted_product,
                    time_published, time_modified);

                  first_product = 0;

                  /* We could add product_tilde to the hashtable but then we
                   * would have to worry about memory management in the
                   * hashtable. */
                }

              /* We don't know the db id of the CPE right now. */

              g_string_append_printf
               (sql_affected,
                "%s (%llu,"
                "    (SELECT id FROM scap2.cpes"
                "     WHERE name='%s'))",
                first_affected ? "" : ",", cve, quoted_product);
            }
          else
            {
              int cpe;

              /* The product is in the db.
               *
               * So we don't need to insert it. */

              cpe = hashed_cpes_cpe_id (hashed_cpes, product_tilde);

              g_string_append_printf
               (sql_affected,
                "%s (%llu, %i)",
                first_affected ? "" : ",", cve,
                cpe);
            }

          first_affected = 0;
          g_free (product_tilde);
          g_free (quoted_product);
        }

      g_free (product_text);

      product = element_next (product);
    }

  /* Run the SQL. */

  if (first_product == 0)
     {
       sql ("%s"
            " ON CONFLICT (uuid)"
            " DO UPDATE SET name = EXCLUDED.name;",
            sql_cpes->str);

       increment_transaction_size (transaction_size);
     }

   if (first_affected == 0)
     {
       sql ("%s"
            " ON CONFLICT DO NOTHING;",
            sql_affected->str);

       increment_transaction_size (transaction_size);
     }

   g_string_free (sql_cpes, TRUE);
   g_string_free (sql_affected, TRUE);
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
  gboolean cvss_is_v3;
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
      g_warning ("%s: vuln:published-datetime missing",
                 __func__);
      g_free (id);
      return -1;
    }

  cvss = element_child (entry, "vuln:cvss3");
  if (cvss == NULL)
    {
      cvss = element_child (entry, "vuln:cvss");
      cvss_is_v3 = FALSE;
    }
  else
     cvss_is_v3 = TRUE;

  if (cvss == NULL)
    base_metrics = NULL;
  else
    base_metrics = element_child (cvss,
                                  cvss_is_v3 ? "cvss3:base_metrics"
                                             : "cvss:base_metrics");

  if (base_metrics == NULL)
    {
      score = NULL;
      cvss_vector = NULL;
    }
  else
    {
      score = element_child (base_metrics,
                             cvss_is_v3 ? "cvss3:base-score" : "cvss:score");
      if (score == NULL)
        {
          g_warning ("%s: cvss:score missing", __func__);
          g_free (id);
          return -1;
        }

      cvss_vector = element_child (base_metrics,
                                   cvss_is_v3 ? "cvss3:vector-string"
                                              : "cvss:vector-string");
      if (cvss_vector == NULL)
        {
          g_warning ("%s: cvss:access-vector missing", __func__);
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
      g_warning ("%s: vuln:summary missing", __func__);
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
  GError *error;
  element_t element, entry;
  gchar *xml, *full_path;
  gsize xml_len;
  GStatBuf state;
  int transaction_size = 0;

  full_path = g_build_filename (GVM_SCAP_DATA_DIR, xml_path, NULL);

  if (g_stat (full_path, &state))
    {
      g_warning ("%s: Failed to stat SCAP file: %s",
                 __func__,
                 strerror (errno));
      return -1;
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
  entry = element_first_child (element);
  while (entry)
    {
      if (strcmp (element_name (entry), "entry") == 0)
        {
          element_t last_modified;

          last_modified = element_child (entry, "vuln:last-modified-datetime");
          if (last_modified == NULL)
            {
              g_warning ("%s: vuln:last-modified-datetime missing",
                         __func__);
              goto fail;
            }

          if (insert_cve_from_entry (entry, last_modified, hashed_cpes,
                                     &transaction_size))
            goto fail;
        }
      entry = element_next (entry);
    }

  element_free (element);
  g_free (full_path);
  sql_commit ();
  return 0;

 fail:
  element_free (element);
  g_warning ("Update of CVEs failed at file '%s'",
             full_path);
  g_free (full_path);
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
  const gchar *xml_path;
  GHashTable *hashed_cpes;
  iterator_t cpes;

  error = NULL;
  dir = g_dir_open (GVM_SCAP_DATA_DIR, 0, &error);
  if (dir == NULL)
    {
      g_warning ("%s: Failed to open directory '%s': %s",
                 __func__, GVM_SCAP_DATA_DIR, error->message);
      g_error_free (error);
      return -1;
    }

  hashed_cpes = g_hash_table_new (g_str_hash, g_str_equal);
  init_iterator (&cpes, "SELECT uuid, id FROM scap2.cpes;");
  while (next (&cpes))
    g_hash_table_insert (hashed_cpes,
                         (gpointer*) iterator_string (&cpes, 0),
                         GINT_TO_POINTER (iterator_int (&cpes, 1)));

  count = 0;
  while ((xml_path = g_dir_read_name (dir)))
    if (fnmatch ("nvdcve-2.0-*.xml", xml_path, 0) == 0)
      {
        if (update_cve_xml (xml_path, hashed_cpes))
          {
            g_dir_close (dir);
            g_hash_table_destroy (hashed_cpes);
            cleanup_iterator (&cpes);
            return -1;
          }
        count++;
      }

  if (count == 0)
    g_warning ("No CVEs found in %s", GVM_SCAP_DATA_DIR);

  g_dir_close (dir);
  g_hash_table_destroy (hashed_cpes);
  cleanup_iterator (&cpes);
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
 */
static void
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
        return;

      default:
        /* Parent.  Continue to next task. */
        return;

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
 *
 * @return 0 success, -1 error.
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
 */
void
manage_sync_cert (sigset_t *sigmask_current)
{
  sync_secinfo (sigmask_current,
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
 *
 * @return 0 success, -1 error.
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
 * @brief Finish scap update.
 *
 * @return 0 success, -1 error.
 */
static int
update_scap_end ()
{
  int cert_db_version;

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
    }
  else
    sql ("ALTER SCHEMA scap2 RENAME TO scap;");

  /* Update CERT data that depends on SCAP. */
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

  /* Analyze. */

  sql ("ANALYZE scap.cves;");
  sql ("ANALYZE scap.cpes;");
  sql ("ANALYZE scap.affected_products;");

  g_info ("%s: Updating SCAP info succeeded", __func__);
  setproctitle ("Syncing SCAP: done");

  return 0;
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

      return update_scap_end ();
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

  g_debug ("%s: update cpes", __func__);
  setproctitle ("Syncing SCAP: Updating CPEs");

  if (update_scap_cpes () == -1)
    {
      update_scap_timestamp ();
      return -1;
    }

  g_debug ("%s: update cves", __func__);
  setproctitle ("Syncing SCAP: Updating CVEs");

  if (update_scap_cves () == -1)
    {
      update_scap_timestamp ();
      return -1;
    }

  g_debug ("%s: updating user defined data", __func__);


  /* Do calculations that need all data. */

  g_debug ("%s: update max cvss", __func__);
  setproctitle ("Syncing SCAP: Updating max CVSS");

  update_scap_cvss ();

  g_debug ("%s: update placeholders", __func__);
  setproctitle ("Syncing SCAP: Updating placeholders");

  update_scap_placeholders ();

  return update_scap_end ();
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
 */
void
manage_sync_scap (sigset_t *sigmask_current)
{
  sync_secinfo (sigmask_current,
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
  if (ret == 1)
    ret = 2;

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

  ret = manage_option_setup (log_config, database);
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
