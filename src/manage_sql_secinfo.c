/* Copyright (C) 2009-2019 Greenbone Networks GmbH
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

#include <gvm/base/proctitle.h>
#include <gvm/util/fileutils.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"


/* Static variables. */

/**
 * @brief Maximum number of rows in an INSERT.
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

/**
 * @brief Split a file.
 *
 * @param[in]  path  Path to file.
 * @param[in]  size  Approx size of split files.  In same format that
 *                   xml_split accepts, eg "200Kb".
 * @param[in]  tail  Text to replace last line of split files.
 *
 * @return Temp dir holding split files.
 */
static const gchar *
split_xml_file (gchar *path, const gchar *size, const gchar *tail)
{
  int ret;
  static gchar dir[] = "/tmp/gvmd-split-xml-file-XXXXXX";
  gchar *previous_dir, *command;

  if (mkdtemp (dir) == NULL)
    {
      g_warning ("%s: Failed to make temp dir: %s",
                 __func__,
                 strerror (errno));
      return NULL;
    }

  previous_dir = getcwd (NULL, 0);
  if (previous_dir == NULL)
    {
      g_warning ("%s: Failed to getcwd: %s",
                 __func__,
                 strerror (errno));
      return NULL;
    }

  if (chdir (dir))
    {
      g_warning ("%s: Failed to chdir: %s",
                 __func__,
                 strerror (errno));
      g_free (previous_dir);
      return NULL;
    }

  if (gvm_file_copy (path, "split.xml") == FALSE)
    {
      g_free (previous_dir);
      return NULL;
    }

  /* xml_split will chop split.xml into files that are roughly 'size' big.
   *
   * The generated files are always put in the directory that holds
   * split.xml, as follows:
   *
   * split.xml      Source XML.
   * split-00.xml   Master generated XML.  No content, just includes other
   *                files.  The include statements are wrapped in the
   *                root element from split.xml.
   * split-01.xml   Generated XML content.  Wrapped in an <xml_split:root>
   *                element.
   * split-02.xml   Second generated content file.
   * ...
   * split-112.xml  Last content, for example.
   *
   * Parsing the generated files independently will only work if the files
   * contain the original root element (for example, because the parser
   * requires the namespace definitions to be present).
   *
   * So the command below needs to mess around a little bit to replace the
   * wrapper XML element in split-01.xml, split-02.xml, etc with the root
   * element from split-00.xml.
   *
   * Using tail and head is not super robust, but it's simple and it will
   * work as long as xml_split keeps the opening of the wrapper element
   * in split-00.xml on a dedicated line.  (It doesn't do this for the
   * closing element, so we use the tail argument instead.)
   */

  command = g_strdup_printf
             ("xml_split -s%s split.xml"
              " && head -n 2 split-00.xml > head.xml"
              " && echo '%s' > tail.xml"
              " && for F in split-*.xml; do"
              /*   Remove the first two lines and last line. */
              "    awk 'NR>3 {print last} {last=$0}' $F > body.xml"
              /*   Combine with new start and end. */
              "    && cat head.xml body.xml tail.xml > $F;"
              "    done",
              size,
              tail);

  g_debug ("%s: command: %s", __func__, command);
  ret = system (command);
  if ((ret == -1) || WIFEXITED(ret) == 0 || WEXITSTATUS (ret))
    {
      g_warning ("%s: system failed with ret %i, %i (%i), %s",
                 __func__,
                 ret,
                 WIFEXITED (ret),
                 WIFEXITED (ret) ? WEXITSTATUS (ret) : 0,
                 command);
      g_free (command);
      g_free (previous_dir);

      if (chdir (previous_dir))
        g_warning ("%s: and failed to chdir back", __func__);

      return NULL;
    }

  g_free (command);

  if (chdir (previous_dir))
    g_warning ("%s: Failed to chdir back (will continue anyway)",
               __func__);

  g_free (previous_dir);

  return dir;
}


/* Helper: buffer structure for INSERTs. */

/**
 * @brief Buffer for INSERT statements.
 */
typedef struct
{
  array_t *statements;     ///< Buffered statements.
  GString *statement;      ///< Current statement.
  int current_chunk_size;  ///< Number of rows in current statement.
  int max_chunk_size;      ///< Max number of rows per INSERT.
  gchar *open_sql;         ///< SQL to open each statement.
  gchar *close_sql;        ///< SQL to close each statement.
} inserts_t;

/**
 * @brief Check size of current statement.
 *
 * @param[in]  inserts         Insert buffer.
 * @param[in]  max_chunk_size  Max chunk size.
 * @param[in]  open_sql        SQL to to start each statement.
 * @param[in]  close_sql       SQL to append to the end of each statement.
 *
 * @return Whether this is the first value in the statement.
 */
static void
inserts_init (inserts_t *inserts, int max_chunk_size, const gchar *open_sql,
              const gchar *close_sql)
{
  inserts->statements = make_array ();
  inserts->statement = NULL;
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
      inserts->statement = NULL;
      inserts->current_chunk_size = 0;
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
 * @brief Free everything.
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
 */
static void
inserts_run (inserts_t *inserts)
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

  inserts_free (inserts);
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
 * @return The highest severity score (10 * CVSS score) of the CPE,
 *         or -1 if iteration is complete. Freed by cleanup_iterator.
 */
int
cpe_info_iterator_score (iterator_t *iterator)
{
  if (iterator->done) return -1;
  return iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 3);
}

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
                 "SELECT id, name, score FROM cves WHERE id IN"
                 " (SELECT cve FROM affected_products"
                 "  WHERE cpe ="
                 "  (SELECT id FROM cpes WHERE name = '%s'))"
                 " ORDER BY %s %s;",
                 quoted_cpe,
                 sort_field ? sort_field : "score DESC, name",
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
 * @return The severity score (10 * CVSS score) of the CVE,
 *         or -1 if iteration is complete.  Freed by cleanup_iterator.
 */
int
cve_iterator_score (iterator_t* iterator)
{
  if (iterator->done) return -1;
  return iterator_int (iterator, 2);
}

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
  ret = sql_string ("SELECT score / 10.0 FROM cves WHERE name = '%s'",
                    quoted_cve);
  g_free (quoted_cve);
  return ret;
}

/**
 * @brief Get the severity score from a CVE.
 *
 * @param[in]  cve  CVE-ID of the CVE to get the score of.
 *
 * @return Severity score (10 * CVSS score) of CVE.
 */
int
cve_score (const gchar *cve)
{
  gchar *quoted_cve;
  int ret;

  quoted_cve = sql_quote (cve);
  ret = sql_int ("SELECT score FROM cves WHERE name = '%s'",
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
 * @return The severity score  (10 * CVSS score) of this CVE,
 *         or -1 if iteration is complete. Freed by cleanup_iterator.
 */
int
cve_info_iterator_score (iterator_t* iterator)
{
  if (iterator->done) return -1;
  return iterator_int (iterator,  GET_ITERATOR_COLUMN_COUNT + 2);
}

/**
 * @brief Get the Summary for this CVE.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The Summary of this CVE, or NULL if iteration is
 *         complete. Freed by cleanup_iterator.
 */
DEF_ACCESS (cve_info_iterator_description, GET_ITERATOR_COLUMN_COUNT + 3);


/* OVAL data. */

/**
 * @brief Gets the SELECT columns for OVAL definition iterators and counts.
 *
 * @return The SELECT columns.
 */
static const column_t*
ovaldef_info_select_columns ()
{
  static column_t columns[] = OVALDEF_INFO_ITERATOR_COLUMNS;
  return columns;
}

/**
 * @brief Gets the filter columns for OVAL definition iterators and counts.
 *
 * @return The filter columns.
 */
static const char **
ovaldef_info_filter_columns ()
{
  static const char *filter_columns[] = OVALDEF_INFO_ITERATOR_FILTER_COLUMNS;
  return filter_columns;
}

/**
 * @brief Initialise an OVAL definition (ovaldef) info iterator.
 *
 * @param[in]  iterator        Iterator.
 * @param[in]  get             GET data.
 * @param[in]  name            Name of the info
 *
 * @return 0 success, 1 failed to find target, 2 failed to find filter,
 *         -1 error.
 */
int
init_ovaldef_info_iterator (iterator_t* iterator, get_data_t *get,
                            const char *name)
{
  static const char *filter_columns[] = OVALDEF_INFO_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = OVALDEF_INFO_ITERATOR_COLUMNS;
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
                           "ovaldef",
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
 * @brief Count number of ovaldef.
 *
 * @param[in]  get  GET params.
 *
 * @return Total number of OVAL definitions in filtered set.
 */
int
ovaldef_info_count (const get_data_t *get)
{
  static const char *filter_columns[] = OVALDEF_INFO_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = OVALDEF_INFO_ITERATOR_COLUMNS;
  return count ("ovaldef", get, columns, NULL, filter_columns, 0, 0, 0, FALSE);
}

/**
 * @brief Get the version number from an OVALDEF iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The version number of the OVAL definition,
 *         or NULL if iteration is complete.
 *         Freed by cleanup_iterator.
 */
DEF_ACCESS (ovaldef_info_iterator_version, GET_ITERATOR_COLUMN_COUNT);

/**
 * @brief Get the deprecation status from an OVALDEF iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return True if the OVAL definition is deprecated, false if not,
 *         or NULL if iteration is complete.
 *         Freed by cleanup_iterator.
 */
DEF_ACCESS (ovaldef_info_iterator_deprecated, GET_ITERATOR_COLUMN_COUNT + 1);

/**
 * @brief Get the definition class from an OVALDEF iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The definition class (e.g. 'patch' or 'vulnerability') of the OVAL
 *         definition, or NULL if iteration is complete.
 *         Freed by cleanup_iterator.
 */
DEF_ACCESS (ovaldef_info_iterator_class, GET_ITERATOR_COLUMN_COUNT + 2);

/**
 * @brief Get the title from an OVALDEF iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The title / short description of the OVAL definition,
 *         or NULL if iteration is complete.
 *         Freed by cleanup_iterator.
 */
DEF_ACCESS (ovaldef_info_iterator_title, GET_ITERATOR_COLUMN_COUNT + 3);

/**
 * @brief Get the description from an OVALDEF iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The long description of the OVAL definition,
 *         or NULL if iteration is complete.
 *         Freed by cleanup_iterator.
 */
DEF_ACCESS (ovaldef_info_iterator_description, GET_ITERATOR_COLUMN_COUNT + 4);

/**
 * @brief Get the source xml file from an OVALDEF iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The short xml source file name of the OVAL definition,
 *         or NULL if iteration is complete.
 *         Freed by cleanup_iterator.
 */
DEF_ACCESS (ovaldef_info_iterator_file, GET_ITERATOR_COLUMN_COUNT + 5);

/**
 * @brief Get the repository entry status from an OVALDEF iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The repository entry status of the OVAL definition,
 *         or NULL if iteration is complete.
 *         Freed by cleanup_iterator.
 */
DEF_ACCESS (ovaldef_info_iterator_status, GET_ITERATOR_COLUMN_COUNT + 6);

/**
 * @brief Get maximum severity score from an OVALDEF iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The maximum severity score  (10 * CVSS score) of the OVAL
 *         definition, or -1 if iteration is complete.
 *         Freed by cleanup_iterator.
 */
int
ovaldef_info_iterator_score (iterator_t* iterator)
{
  if (iterator->done) return -1;
  return iterator_int (iterator,  GET_ITERATOR_COLUMN_COUNT + 7);
}

/**
 * @brief Get number of referenced CVEs from an OVALDEF iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The maximum CVSS score of the OVAL definition,
 *         or NULL if iteration is complete.
 *         Freed by cleanup_iterator.
 */
DEF_ACCESS (ovaldef_info_iterator_cve_refs, GET_ITERATOR_COLUMN_COUNT + 8);


/**
 * @brief Get the short file name for an OVALDEF.
 *
 * @param[in]  item_id  Full OVAL identifier with file suffix.
 *
 * @return The file name of the OVAL definition relative to the SCAP directory,
 *         Freed by g_free.
 */
gchar*
get_ovaldef_short_filename (char* item_id)
{
  return sql_string ("SELECT xml_file FROM ovaldefs WHERE uuid = '%s';",
                     item_id);
}

/**
 * @brief Get the uuid for an OVALDEF from a name and file name.
 *
 * @param[in]  name     Oval definition name.
 * @param[in]  fname    Oval definition file name.
 *
 * @return The OVAL definition uuid from the SCAP directory. Freed by g_free.
 */
char*
ovaldef_uuid (const char *name, const char *fname)
{
  char *quoted_name, *quoted_fname, *ret;

  assert (name);
  assert (fname);
  quoted_name = sql_quote (name);
  quoted_fname = sql_quote (fname);
  ret = sql_string ("SELECT uuid FROM ovaldefs WHERE name = '%s'"
                    " AND xml_file = '%s';", name, fname);
  g_free (quoted_name);
  g_free (quoted_fname);
  return ret;
}

/**
 * @brief Get the severity of an OVALDEF using an ID.
 *
 * @param[in]  id  Oval definition ID.
 *
 * @return The severity of the OVAL definition from the SCAP directory.
 *         Freed by g_free.
 */
char *
ovaldef_severity (const char *id)
{
  char *quoted_id, *ret;

  assert (id);
  quoted_id = sql_quote (id);
  ret = sql_string ("SELECT score / 10.0 FROM ovaldefs WHERE uuid = '%s';",
                    quoted_id);
  g_free (quoted_id);
  return ret;
}

/**
 * @brief Get the version of an OVALDEF using an ID.
 *
 * @param[in]  id  Oval definition ID.
 *
 * @return The version of the OVAL definition from the SCAP directory.
 *         Freed by g_free.
 */
char *
ovaldef_version (const char *id)
{
  char *quoted_id, *ret;

  assert (id);
  quoted_id = sql_quote (id);
  ret = sql_string ("SELECT version FROM ovaldefs WHERE uuid = '%s';",
                    quoted_id);
  g_free (quoted_id);
  return ret;
}

/**
 * @brief Get the CVE names of an OVALDEF as ", " separated str.
 *
 * @param[in]  id  Oval definition ID.
 *
 * @return String of CVEs affecting of the OVAL definition, NULL otherwise.
 *         Freed by g_free.
 */
char *
ovaldef_cves (const char *id)
{
  char *quoted_id, *ret = NULL;
  iterator_t iterator;

  assert (id);
  quoted_id = sql_quote (id);
  init_iterator (&iterator,
                 "SELECT DISTINCT cves.name FROM cves, ovaldefs,"
                 " affected_ovaldefs WHERE ovaldefs.uuid = '%s'"
                 " AND cves.id = affected_ovaldefs.cve"
                 " AND ovaldefs.id = affected_ovaldefs.ovaldef;", quoted_id);
  g_free (quoted_id);
  while (next (&iterator))
    {
      char *tmp = ret;
      ret = g_strdup_printf ("%s%s%s", ret ?: "", ret ? ", " : "",
                             iterator_string (&iterator, 0));
      g_free (tmp);
    }
  cleanup_iterator (&iterator);
  return ret;
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
 * @return The maximum severity score (10 * CVSS score) of the CVEs referenced
 *         in the CERT-Bund advisory, or -1 if iteration is complete.
 *         Freed by cleanup_iterator.
 */
int
cert_bund_adv_info_iterator_score (iterator_t* iterator)
{
  if (iterator->done) return -1;
  return iterator_int (iterator,  GET_ITERATOR_COLUMN_COUNT + 3);
}

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
 * @return The maximum score (10 * CVSS score) of the CVEs referenced
 *         in the DFN-CERT advisory, or -1 if iteration is complete.
 *         Freed by cleanup_iterator.
 */
int
dfn_cert_adv_info_iterator_score (iterator_t* iterator)
{
  if (iterator->done) return -1;
  return iterator_int (iterator,  GET_ITERATOR_COLUMN_COUNT + 3);
}

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
  else if (strcmp (type, "ovaldef") == 0)
    {
      columns = ovaldef_info_select_columns ();
      filter_columns = ovaldef_info_filter_columns ();
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

/**
 * @brief Initialise an ovaldi file iterator.
 *
 * @param[in]  iterator        Iterator.
 */
void
init_ovaldi_file_iterator (iterator_t* iterator)
{
  init_iterator (iterator, "SELECT DISTINCT xml_file FROM ovaldefs;");
}

/**
 * @brief Get the name from an ovaldi file iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The name of the file, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (ovaldi_file_iterator_name, 0);


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
  gchar *name_decoded, *name_tilde;
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

  name_decoded = g_uri_unescape_string (name, NULL);
  g_free (name);
  name_tilde = string_replace (name_decoded,
                               "~", "%7E", "%7e", NULL);
  g_free (name_decoded);
  quoted_name = sql_quote (name_tilde);
  g_free (name_tilde);
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
 * @brief Update SCAP CPEs from a file.
 *
 * @param[in]  path             Path to file.
 *
 * @return 0 success, -1 error.
 */
static int
update_scap_cpes_from_file (const gchar *path)
{
  GError *error;
  element_t element, cpe_list, cpe_item;
  gchar *xml;
  gsize xml_len;
  inserts_t inserts;

  g_debug ("%s: parsing %s", __func__, path);

  error = NULL;
  g_file_get_contents (path, &xml, &xml_len, &error);
  if (error)
    {
      g_warning ("%s: Failed to get contents: %s",
                 __func__,
                 error->message);
      g_error_free (error);
      return -1;
    }

  if (parse_element (xml, &element))
    {
      g_free (xml);
      g_warning ("%s: Failed to parse element", __func__);
      return -1;
    }
  g_free (xml);

  cpe_list = element;
  if (strcmp (element_name (cpe_list), "cpe-list"))
    {
      element_free (element);
      g_warning ("%s: CPE dictionary missing CPE-LIST", __func__);
      return -1;
    }

  sql_begin_immediate ();

  inserts_init (&inserts,
                CPE_MAX_CHUNK_SIZE,
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
  cpe_item = element_first_child (cpe_list);
  while (cpe_item)
    {
      gchar *modification_date;
      int modification_time;
      element_t item_metadata;

      if (strcmp (element_name (cpe_item), "cpe-item"))
        {
          cpe_item = element_next (cpe_item);
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
      cpe_item = element_next (cpe_item);
    }

  element_free (element);

  inserts_run (&inserts);

  sql_commit ();
  return 0;

 fail:
  inserts_free (&inserts);
  element_free (element);
  g_warning ("Update of CPEs failed");
  sql_commit ();
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
  const gchar *split_dir;
  GStatBuf state;
  int index;

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

  split_dir = split_xml_file (full_path, "40Mb", "</cpe-list>");
  if (split_dir == NULL)
    {
      int ret;

      g_warning ("%s: Failed to split CPEs, attempting with full file",
                 __func__);
      ret = update_scap_cpes_from_file (full_path);
      g_free (full_path);
      return ret;
    }
  g_free (full_path);

  for (index = 1; 1; index++)
    {
      int ret;
      gchar *path, *name;

      name = g_strdup_printf ("split-%02i.xml", index);
      path = g_build_filename (split_dir, name, NULL);
      g_free (name);

      if (g_stat (path, &state))
        {
          g_free (path);
          break;
        }

      ret = update_scap_cpes_from_file (path);
      g_free (path);
      if (ret < 0)
        {
          gvm_file_remove_recurse (split_dir);
          return -1;
        }
    }

  gvm_file_remove_recurse (split_dir);

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
  int score_int;
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
    score_int = 0;
  else
    score_int = round (atof (element_text (score)) * 10);

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
          "  score, description, cvss_vector, products)"
          " VALUES"
          " ('%s', '%s', %i, %i,"
          "  %i, '%s', '%s', '%s')"
          " ON CONFLICT (uuid) DO UPDATE"
          " SET name = EXCLUDED.name,"
          "     creation_time = EXCLUDED.creation_time,"
          "     modification_time = EXCLUDED.modification_time,"
          "     score = EXCLUDED.score,"
          "     description = EXCLUDED.description,"
          "     cvss_vector = EXCLUDED.cvss_vector,"
          "     products = EXCLUDED.products"
          " RETURNING scap2.cves.id;",
          quoted_id,
          quoted_id,
          time_published,
          time_modified,
          score_int,
          quoted_summary,
          quoted_cvss_vector,
          quoted_software);
  increment_transaction_size (transaction_size);
  g_free (quoted_summary);
  g_free (quoted_cvss_vector);

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


/* SCAP update: OVAL. */

/**
 * @brief Get last date from definition element.
 *
 * @param[in]  definition              Definition.
 * @param[out] definition_date_newest  Newest date.
 * @param[out] definition_date_oldest  Oldest date.
 */
static void
oval_definition_dates (element_t definition, int *definition_date_newest,
                       int *definition_date_oldest)
{
  element_t metadata, oval_repository, date, dates;
  int first;
  gchar *oldest, *newest;

  assert (definition_date_newest);
  assert (definition_date_oldest);

  *definition_date_newest = 0;
  *definition_date_oldest = 0;

  metadata = element_child (definition, "metadata");
  if (metadata == NULL)
    {
      g_warning ("%s: metadata missing",
                 __func__);
      return;
    }

  oval_repository = element_child (metadata, "oval_repository");
  if (oval_repository == NULL)
    {
      g_warning ("%s: oval_repository missing",
                 __func__);
      return;
    }

  dates = element_child (oval_repository, "dates");
  if (dates == NULL)
    {
      g_warning ("%s: dates missing",
                 __func__);
      return;
    }

  newest = NULL;
  oldest = NULL;
  first = 1;
  date = element_first_child (dates);
  while (date)
    {
      if ((strcmp (element_name (date), "submitted") == 0)
          || (strcmp (element_name (date), "status_change") == 0)
          || (strcmp (element_name (date), "modified") == 0))
        {
          if (first)
            {
              g_free (newest);
              newest = element_attribute (date, "date");
              first = 0;
            }
          g_free (oldest);
          oldest = element_attribute (date, "date");
        }
      date = element_next (date);
    }

  if (newest)
    {
      *definition_date_newest = parse_iso_time (newest);
      g_free (newest);
    }
  if (oldest)
    {
      *definition_date_oldest = parse_iso_time (oldest);
      g_free (oldest);
    }
}

/**
 * @brief Get generator/timestamp from main oval_definitions element.
 *
 * @param[in]  element         Element.
 * @param[out] file_timestamp  Timestamp.
 */
static void
oval_oval_definitions_date (element_t element, int *file_timestamp)
{
  element_t generator, timestamp;

  assert (file_timestamp);

  *file_timestamp = 0;

  generator = element_child (element, "generator");
  if (generator == NULL)
    {
      g_warning ("%s: generator missing",
                 __func__);
      return;
    }

  timestamp = element_child (generator, "oval:timestamp");
  if (timestamp == NULL)
    {
      g_warning ("%s: oval:timestamp missing",
                 __func__);
      return;
    }

  *file_timestamp = parse_iso_time_element_text (timestamp);
}

/**
 * @brief Verify a OVAL definitions file.
 *
 * @param[in]  full_path  Full path to the OVAL definitions file to verify.
 *
 * @return 0 if valid, else -1.
 */
static int
verify_oval_file (const gchar *full_path)
{
  GError *error;
  gchar *xml;
  gsize xml_len;
  element_t element;

  error = NULL;
  g_file_get_contents (full_path, &xml, &xml_len, &error);
  if (error)
    {
      g_warning ("%s: Failed to get contents: %s",
                 __func__,
                 error->message);
      g_error_free (error);
      return -1;
    }

  if (parse_element (xml, &element))
    {
      g_free (xml);
      g_warning ("%s: Failed to parse element", __func__);
      return -1;
    }
  g_free (xml);

  if (strcmp (element_name (element), "oval_definitions") == 0)
    {
      int definition_count;
      element_t definitions;

      definition_count = 0;
      definitions = element_first_child (element);
      while (definitions)
        {
          if (strcmp (element_name (definitions), "definitions")
              == 0)
            {
              element_t definition;

              definition = element_first_child (definitions);
              while (definition)
                {
                  if (strcmp (element_name (definition), "definition")
                      == 0)
                    definition_count++;
                  definition = element_next (definition);
                }
            }
          definitions = element_next (definitions);
        }

      element_free (element);
      if (definition_count == 0)
        {
          g_warning ("%s: No OVAL definitions found", __func__);
          return -1;
        }
      else
        return 0;
    }

  if (strcmp (element_name (element), "oval_variables") == 0)
    {
      int variable_count;
      element_t variables;

      variable_count = 0;
      variables = element_first_child (element);
      while (variables)
        {
          if (strcmp (element_name (variables), "variables")
              == 0)
            {
              element_t variable;

              variable = element_first_child (variables);
              while (variable)
                {
                  if (strcmp (element_name (variable), "variable")
                      == 0)
                    variable_count++;
                  variable = element_next (variable);
                }
            }
          variables = element_next (variables);
        }

      element_free (element);
      if (variable_count == 0)
        {
          g_warning ("%s: No OVAL variables found", __func__);
          return -1;
        }
      else
        return 0;
    }

  if (strcmp (element_name (element), "oval_system_characteristics") == 0)
    {
      g_warning ("%s: File is an OVAL System Characteristics file",
                 __func__);
      return -1;
    }

  if (strcmp (element_name (element), "oval_results") == 0)
    {
      g_warning ("%s: File is an OVAL Results one",
                 __func__);
      return -1;
    }

  g_warning ("%s: Root tag neither oval_definitions nor oval_variables",
             __func__);
  element_free (element);
  return -1;
}

/**
 * @brief Update OVALDEF info from a single XML feed file.
 *
 * @param[in]  file_and_date     Array containing XML path and timestamp.
 * @param[in]  private           Whether this is from the user's private dir.
 *
 * @return 0 success, -1 error.
 */
static int
update_ovaldef_xml (gchar **file_and_date, int private)
{
  GError *error;
  element_t element, child;
  const gchar *xml_path;
  gchar *xml_basename, *xml, *quoted_xml_basename;
  gsize xml_len;
  int file_timestamp;
  int transaction_size = 0;

  /* Setup variables. */

  xml_path = file_and_date[0];
  assert (xml_path);

  g_debug ("%s: xml_path: %s", __func__, xml_path);

  xml_basename = strstr (xml_path, GVM_SCAP_DATA_DIR);
  if (xml_basename == NULL)
    {
      g_warning ("%s: xml_path missing GVM_SCAP_DATA_DIR: %s",
                 __func__,
                 xml_path);
      return -1;
    }
  xml_basename += strlen (GVM_SCAP_DATA_DIR);

  quoted_xml_basename = sql_quote (xml_basename);

  if (private)
    {
      /* Validate OVAL file. */

      if (verify_oval_file (xml_path))
        {
          g_info ("Validation failed for file '%s'",
                  xml_path);
          g_free (quoted_xml_basename);
          return 0;
        }
    }

  /* Parse XML from the file. */

  g_info ("Updating %s", xml_path);

  error = NULL;
  g_file_get_contents (xml_path, &xml, &xml_len, &error);
  if (error)
    {
      g_warning ("%s: Failed to get contents: %s",
                 __func__,
                 error->message);
      g_error_free (error);
      g_free (quoted_xml_basename);
      return -1;
    }

  if (parse_element (xml, &element))
    {
      g_free (xml);
      g_warning ("%s: Failed to parse element", __func__);
      g_free (quoted_xml_basename);
      return -1;
    }
  g_free (xml);

  /* Fill the db according to the XML. */

  sql_begin_immediate ();

  sql ("INSERT INTO ovalfiles (xml_file)"
       " SELECT '%s' WHERE NOT EXISTS (SELECT * FROM ovalfiles"
       "                               WHERE xml_file = '%s');",
       quoted_xml_basename,
       quoted_xml_basename);

  sql_commit();
  sql_begin_immediate();

  oval_oval_definitions_date (element, &file_timestamp);

  child = element_first_child (element);
  while (child)
    {
      element_t definition;

      if (strcmp (element_name (child), "definitions"))
        {
          child = element_next (child);
          continue;
        }

      definition = element_first_child (child);
      while (definition)
        {
          if (strcmp (element_name (definition), "definition") == 0)
            {
              int definition_date_newest, definition_date_oldest;
              gchar *quoted_id, *quoted_oval_id;
              element_t metadata, title, description, repository, reference;
              element_t status;
              gchar *deprecated, *version, *id, *id_value, *class;
              gchar *quoted_title, *quoted_class, *quoted_description;
              gchar *quoted_status, *status_text;
              int cve_count;

              /* The newest and oldest of this definition's dates (created,
               * modified, etc), from the OVAL XML. */
              oval_definition_dates (definition,
                                     &definition_date_newest,
                                     &definition_date_oldest);

              id_value = element_attribute (definition, "id");
              if (id_value == NULL)
                {
                  g_warning ("%s: oval_definition missing id",
                             __func__);
                  element_free (element);
                  goto fail;
                }

              metadata = element_child (definition, "metadata");
              if (metadata == NULL)
                {
                  g_warning ("%s: metadata missing",
                             __func__);
                  element_free (element);
                  g_free (id_value);
                  goto fail;
                }

              title = element_child (metadata, "title");
              if (title == NULL)
                {
                  g_warning ("%s: title missing",
                             __func__);
                  element_free (element);
                  g_free (id_value);
                  goto fail;
                }

              description = element_child (metadata, "description");
              if (description == NULL)
                {
                  g_warning ("%s: description missing",
                             __func__);
                  element_free (element);
                  g_free (id_value);
                  goto fail;
                }

              repository = element_child (metadata, "oval_repository");
              if (repository == NULL)
                {
                  g_warning ("%s: oval_repository missing",
                             __func__);
                  element_free (element);
                  g_free (id_value);
                  goto fail;
                }

              cve_count = 0;
              reference = element_first_child (metadata);
              while (reference)
                {
                  if (strcmp (element_name (reference), "reference") == 0)
                    {
                      gchar *source;

                      source = element_attribute (reference, "source");
                      if (source && strcasecmp (source, "cve") == 0)
                        cve_count++;
                      g_free (source);
                    }
                  reference = element_next (reference);
                }

              id = g_strdup_printf ("%s_%s", id_value, xml_basename);
              quoted_id = sql_quote (id);
              g_free (id);
              quoted_oval_id = sql_quote (id_value);
              g_free (id_value);

              version = element_attribute (definition, "version");
              if (g_regex_match_simple ("^[0-9]+$", (gchar *) version, 0, 0) == 0)
                {
                  g_warning ("%s: invalid version: %s",
                             __func__,
                             version);
                  element_free (element);
                  g_free (version);
                  goto fail;
                }

              class = element_attribute (definition, "class");
              quoted_class = sql_quote (class);
              g_free (class);
              quoted_title = sql_quote_element_text (title);
              quoted_description = sql_quote_element_text (description);
              status = element_child (repository, "status");
              deprecated = element_attribute (definition, "deprecated");
              status_text = NULL;
              if (status)
                status_text = element_text (status);
              if (status_text && strlen (status_text))
                quoted_status = sql_quote (status_text);
              else if (deprecated && strcasecmp (deprecated, "TRUE"))
                quoted_status = sql_quote ("DEPRECATED");
              else
                quoted_status = sql_quote ("");
              g_free (status_text);

              sql ("INSERT INTO scap2.ovaldefs"
                   " (uuid, name, comment, creation_time,"
                   "  modification_time, version, deprecated, def_class,"
                   "  title, description, xml_file, status,"
                   "  score, cve_refs)"
                   " VALUES ('%s', '%s', '', %i, %i, %s, %i, '%s', '%s',"
                   "         '%s', '%s', '%s', 0, %i)"
                   " ON CONFLICT (uuid) DO UPDATE"
                   " SET name = EXCLUDED.name,"
                   "     comment = EXCLUDED.comment,"
                   "     creation_time = EXCLUDED.creation_time,"
                   "     modification_time = EXCLUDED.modification_time,"
                   "     version = EXCLUDED.version,"
                   "     deprecated = EXCLUDED.deprecated,"
                   "     def_class = EXCLUDED.def_class,"
                   "     title = EXCLUDED.title,"
                   "     description = EXCLUDED.description,"
                   "     xml_file = EXCLUDED.xml_file,"
                   "     status = EXCLUDED.status,"
                   "     score = 0,"
                   "     cve_refs = EXCLUDED.cve_refs;",
                   quoted_id,
                   quoted_oval_id,
                   definition_date_oldest == 0
                    ? file_timestamp
                    : definition_date_newest,
                   definition_date_oldest == 0
                    ? file_timestamp
                    : definition_date_oldest,
                   version,
                   (deprecated && strcasecmp (deprecated, "TRUE")) ? 1 : 0,
                   quoted_class,
                   quoted_title,
                   quoted_description,
                   quoted_xml_basename,
                   quoted_status,
                   cve_count);
              increment_transaction_size (&transaction_size);
              g_free (quoted_id);
              g_free (quoted_class);
              g_free (quoted_title);
              g_free (quoted_description);
              g_free (quoted_status);
              g_free (deprecated);
              g_free (version);

              reference = element_first_child (metadata);
              while (reference)
                {
                  if (strcmp (element_name (reference), "reference") == 0)
                    {
                      gchar *source;

                      source = element_attribute (reference, "source");
                      if (source && strcasecmp (source, "cve") == 0)
                        {
                          gchar *ref_id, *quoted_ref_id;

                          ref_id = element_attribute (reference, "ref_id");
                          quoted_ref_id = sql_quote (ref_id);
                          g_free (ref_id);

                          sql ("INSERT INTO scap2.affected_ovaldefs (cve, ovaldef)"
                               " SELECT cves.id, ovaldefs.id"
                               " FROM scap2.cves, scap2.ovaldefs"
                               " WHERE cves.name='%s'"
                               " AND ovaldefs.name = '%s'"
                               " AND NOT EXISTS (SELECT * FROM scap2.affected_ovaldefs"
                               "                 WHERE cve = cves.id"
                               "                 AND ovaldef = ovaldefs.id);",
                               quoted_ref_id,
                               quoted_oval_id);

                          g_free (quoted_ref_id);
                          increment_transaction_size (&transaction_size);
                        }
                      g_free (source);
                    }
                  reference = element_next (reference);
                }

              g_free (quoted_oval_id);
            }
          definition = element_next (definition);
        }
      child = element_next (child);
    }

  /* Cleanup. */

  g_free (quoted_xml_basename);
  element_free (element);
  sql_commit ();
  return 0;

 fail:
  g_free (quoted_xml_basename);
  g_warning ("Update of OVAL definitions failed at file '%s'",
             xml_path);
  sql_commit ();
  return -1;
}

/**
 * @brief Extract generator timestamp from OVAL element.
 *
 * @param[in]  element   OVAL element.
 *
 * @return Freshly allocated timestamp if found, else NULL.
 */
static gchar *
oval_generator_timestamp (element_t element)
{
  gchar *generator_name;
  element_t generator;

  generator_name = g_strdup ("generator");
  generator = element_child (element, generator_name);
  g_free (generator_name);
  if (generator)
    {
      element_t timestamp;
      timestamp = element_child (generator, "oval:timestamp");
      if (timestamp)
        return element_text (timestamp);
    }

  return NULL;
}

/**
 * @brief Extract timestamp from OVAL XML.
 *
 * @param[in]  xml  OVAL XML.
 *
 * @return Freshly allocated timestamp, else NULL.
 */
static gchar *
oval_timestamp (const gchar *xml)
{
  element_t element;

  if (parse_element (xml, &element))
    {
      g_warning ("%s: Failed to parse element: %s", __func__, xml);
      return NULL;
    }

  if (strcmp (element_name (element), "oval_definitions") == 0)
    {
      gchar *timestamp;

      timestamp = oval_generator_timestamp (element);
      if (timestamp)
        {
          element_free (element);
          return timestamp;
        }
    }

  if (strcmp (element_name (element), "oval_variables") == 0)
    {
      gchar *timestamp;

      timestamp = oval_generator_timestamp (element);
      if (timestamp)
        {
          element_free (element);
          return timestamp;
        }
    }

  if (strcmp (element_name (element), "oval_system_characteristics")
      == 0)
    {
      gchar *timestamp;

      timestamp = oval_generator_timestamp (element);
      if (timestamp)
        {
          element_free (element);
          return timestamp;
        }
    }

  g_warning ("%s: No timestamp: %s", __func__, xml);
  return NULL;
}

/**
 * @brief Files for update_scap_ovaldefs.
 */
static array_t *oval_files = NULL;

/**
 * @brief Add an OVAL file to oval_files.
 *
 * @param[in]  path       Path of file.
 * @param[in]  stat       Status of file.
 * @param[in]  flag       Dummy arg for nftw.
 * @param[in]  traversal  Dummy arg for nftw.
 *
 * @return 0 success, -1 error.
 */
static int
oval_files_add (const char *path, const struct stat *stat, int flag,
                struct FTW *traversal)
{
  GError *error;
  gchar **pair, *oval_xml, *timestamp;
  gsize len;
  const char *dot;

  if (gvm_file_check_is_dir (path))
    return 0;

  dot = rindex (path, '.');
  if ((dot == NULL) || strcasecmp (dot, ".xml"))
    return 0;

  g_debug ("%s: path: %s", __func__, path);

  error = NULL;
  g_file_get_contents (path, &oval_xml, &len, &error);
  if (error)
    {
      g_warning ("%s: Failed get contents of %s: %s",
                 __func__,
                 path,
                 error->message);
      g_error_free (error);
      return -1;
    }

  /* Parse timestamp. */

  timestamp = oval_timestamp (oval_xml);
  g_free (oval_xml);

  /* Add file-timestamp pair to OVAL files. */

  pair = g_malloc (sizeof (gchar*) * 2);
  pair[0] = g_strdup (path);
  pair[1] = timestamp;

  array_add (oval_files, pair);

  return 0;
}

/**
 * @brief Compare OVAL files.
 *
 * @param[in]  one  First file.
 * @param[in]  two  Second file.
 *
 * @return 0 same, 1 one is greater than two, -1 two is greater than one.
 */
static gint
oval_files_compare (gconstpointer one, gconstpointer two)
{
  gchar **file_info_one, **file_info_two;

  file_info_one = *((gchar***) one);
  file_info_two = *((gchar***) two);

  if (file_info_one[1] == NULL)
    {
      if (file_info_two[1] == NULL)
        return 0;
      return -1;
    }

  if (file_info_two[1] == NULL)
    return 1;

  return strcmp (file_info_one[1], file_info_two[1]);
}


/**
 * @brief Free oval_files.
 */
static void
oval_files_free ()
{
  int index;

  index = 0;
  while (index < oval_files->len)
    {
      gchar **pair;

      pair = g_ptr_array_index (oval_files, index);
      g_free (pair[0]);
      g_free (pair[1]);
      index++;
    }
  array_free (oval_files);
  oval_files = NULL;
}

/**
 * @brief Update SCAP OVALDEFs.
 *
 * Assume that the databases are attached.
 *
 * @param[in]  private           Whether to update private SCAP data, instead
 *                               of the feed data.
 *
 * @return 0 success, -1 error.
 */
static int
update_scap_ovaldefs (int private)
{
  int count;
  gchar *oval_dir;
  guint index;
  struct stat state;

  assert (oval_files == NULL);

  if (private)
    g_info ("Updating user OVAL definitions.");
  else
    g_info ("Updating OVAL data");

  /* Get a list of the OVAL files. */

  if (private)
    {
      const char *subdir;

      subdir = getenv ("PRIVATE_SUBDIR");
      if ((subdir == NULL) || (strlen (subdir) == 0))
        subdir = "private";

      oval_dir = g_build_filename (GVM_SCAP_DATA_DIR, subdir, "oval",
                                   NULL);
    }
  else
    oval_dir = g_build_filename (GVM_SCAP_DATA_DIR, "oval", NULL);

  g_debug ("%s: private: %i", __func__, private);
  g_debug ("%s: oval_dir: %s", __func__, oval_dir);

  /* Pairs of pointers, pair[0]: absolute pathname, pair[1]: oval timestamp. */
  oval_files = make_array ();

  if (g_lstat (oval_dir, &state))
    {
      if (errno == ENOENT)
        {
          if (private)
            g_debug ("%s: no private OVAL dir (%s)",
                     __func__,
                     oval_dir);
          else
            g_warning ("%s: no OVAL dir (%s)",
                       __func__,
                       oval_dir);
          g_free (oval_dir);
          oval_files_free ();
          return 0;
        }
      g_warning ("%s: failed to lstat '%s': %s",
                  __func__,
                 oval_dir,
                 strerror (errno));
      g_free (oval_dir);
      oval_files_free ();
      return -1;
    }

  if (nftw (oval_dir, oval_files_add, 20, 0) == -1)
    {
      oval_files_free ();
      if (errno == ENOENT)
        {
          if (private)
            g_debug ("%s: nftw of private '%s': %s",
                     __func__,
                     oval_dir,
                     strerror (errno));
          else
            g_warning ("%s: nftw of '%s': %s",
                      __func__,
                      oval_dir,
                      strerror (errno));
          g_free (oval_dir);
          oval_files_free ();
          return 0;
        }
      g_warning ("%s: failed to traverse '%s': %s",
                  __func__,
                 oval_dir,
                 strerror (errno));
      g_free (oval_dir);
      oval_files_free ();
      return -1;
    }

  /* Sort the list by the OVAL timestamp. */

  g_ptr_array_sort (oval_files, oval_files_compare);

  if (private)
    {
      GError *error;
      GDir *directory;
      const gchar *entry;

      /* Check for files that aren't .xml or .asc. */

      error = NULL;
      directory = g_dir_open (oval_dir, 0, &error);

      if (directory == NULL)
        {
          assert (error);

          if (g_error_matches (error, G_FILE_ERROR, G_FILE_ERROR_NOENT))
            {
              g_warning ("No user data directory '%s' found.", oval_dir);
              g_free (oval_dir);
              g_error_free (error);
            }
          else
            {
              g_warning ("g_dir_open (%s) failed - %s", oval_dir,
                         error->message);
              g_free (oval_dir);
              g_error_free (error);
              oval_files_free ();
              return -1;
            }
        }

      entry = NULL;
      while ((entry = g_dir_read_name (directory)) != NULL)
        {
          if (g_str_has_suffix (entry, ".xml") < 0)
            continue;
          if (g_str_has_suffix (entry, ".asc") < 0)
            continue;
          g_warning ("Found non-XML and non-signature file '%s'.", entry);
        }
      g_dir_close (directory);
    }

  /* Process each file in the list, in the sorted order. */

  count = 0;
  for (index = 0; index < oval_files->len; index++)
    {
      gchar **pair;

      pair = g_ptr_array_index (oval_files, index);
      if (update_ovaldef_xml (pair, private))
        {
          oval_files_free ();
          g_free (oval_dir);
          return -1;
        }
      count++;
    }

  if (count == 0)
    g_warning ("%s: No XML files found in %s", __func__, oval_dir);

  if (private)
    {
      GString *oval_files_clause;
      int first;
      iterator_t files;

      /* Clean up user data. */

      g_info ("Cleaning up user OVAL data");

      g_debug ("%s: GVM_SCAP_DATA_DIR: %s", __func__, GVM_SCAP_DATA_DIR);

      oval_files_clause = g_string_new (" AND (xml_file NOT IN (");
      first = 1;
      for (index = 0; index < oval_files->len; index++)
        {
          gchar **pair;
          char *suffix;

          pair = g_ptr_array_index (oval_files, index);
          g_debug ("%s: pair[0]: %s", __func__, pair[0]);
          suffix = strstr (pair[0], GVM_SCAP_DATA_DIR);
          if (suffix == NULL)
            {
              g_warning ("%s: pair[0] missing GVM_SCAP_DATA_DIR: %s",
                         __func__,
                         pair[0]);
              g_free (oval_dir);
              oval_files_free ();
              return -1;
            }
          suffix += strlen (GVM_SCAP_DATA_DIR);
          g_string_append_printf (oval_files_clause,
                                  "%s'%s'",
                                  first ? "" : ", ",
                                  suffix);
          first = 0;
        }
      g_string_append (oval_files_clause, "))");

      init_iterator (&files,
                     "SELECT DISTINCT xml_file FROM scap2.ovaldefs"
                     " WHERE (xml_file NOT LIKE 'oval/%%')"
                     "%s",
                     oval_files_clause->str);
      first = 1;
      while (next (&files))
        {
          if (first)
            g_info ("Removing definitions formerly inserted from:");
          g_info ("%s", iterator_string (&files, 0));
          first = 0;
        }
      cleanup_iterator (&files);

      sql ("DELETE FROM scap2.ovaldefs"
           " WHERE (xml_file NOT LIKE 'oval/%%')"
           "%s;",
           oval_files_clause->str);

      g_string_free (oval_files_clause, TRUE);
    }

  /* Cleanup. */

  g_free (oval_dir);
  oval_files_free ();
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

  proctitle_set (process_title);

  if (update () == 0)
    {
      check_alerts ();
    }

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
static int
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
          return -1;
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
          return -1;
        }

      timestamp[8] = '\0';
      g_debug ("%s: parsing: %s", __func__, timestamp);
      stamp = parse_feed_timestamp (timestamp);
      g_free (timestamp);
      if (stamp == 0)
        return -1;
    }

  g_debug ("%s: setting last_update: %lld", __func__, (long long) stamp);
  sql ("UPDATE cert.meta SET value = '%lld' WHERE name = 'last_update';",
       (long long) stamp);

  return 0;
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
           " SET score = (SELECT max (score)"
           "                  FROM scap.cves"
           "                  WHERE name"
           "                  IN (SELECT cve_name"
           "                      FROM cert.dfn_cert_cves"
           "                      WHERE adv_id = dfn_cert_advs.id)"
           "                  AND score != 0);");

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
           " SET score = (SELECT max (score)"
           "               FROM scap.cves"
           "               WHERE name"
           "                     IN (SELECT cve_name"
           "                         FROM cert.cert_bund_cves"
           "                         WHERE adv_id = cert_bund_advs.id)"
           "               AND score != 0);");

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

  if (update_cert_timestamp ())
    goto fail;

  g_info ("%s: Updating CERT info succeeded.", __func__);

  return 0;

 fail:
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
                "gvmd: Syncing CERT");
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
static int
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
          return -1;
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
          return -1;
        }

      timestamp[8] = '\0';
      g_debug ("%s: parsing: %s", __func__, timestamp);
      stamp = parse_feed_timestamp (timestamp);
      g_free (timestamp);
      if (stamp == 0)
        return -1;
    }

  g_debug ("%s: setting last_update: %lld", __func__, (long long) stamp);
  sql ("UPDATE scap2.meta SET value = '%lld' WHERE name = 'last_update';",
       (long long) stamp);

  return 0;
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
       " SET (score, cve_refs)"
       "     = (WITH affected_cves"
       "        AS (SELECT cve FROM scap2.affected_products"
       "            WHERE cpe=cpes.id)"
       "        SELECT (SELECT max (score) FROM scap2.cves"
       "                WHERE id IN (SELECT cve FROM affected_cves)),"
       "               (SELECT count (*) FROM affected_cves));");

  g_info ("Updating CVSS scores for OVAL definitions");
  sql ("UPDATE scap2.ovaldefs"
       " SET score = (SELECT max (score)"
       "               FROM scap2.cves"
       "               WHERE id IN (SELECT cve"
       "                            FROM scap2.affected_ovaldefs"
       "                            WHERE ovaldef=ovaldefs.id)"
       "               AND score != 0);");
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

  if (update_scap_timestamp ())
    return -1;

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
  sql ("ANALYZE scap.ovaldefs;");
  sql ("ANALYZE scap.ovalfiles;");
  sql ("ANALYZE scap.affected_ovaldefs;");

  g_info ("%s: Updating SCAP info succeeded", __func__);
  proctitle_set ("gvmd: Syncing SCAP: done");

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
  gchar *file_ovaldefs, *file_ovalfiles, *file_affected_ovaldefs;

  file_cves = g_build_filename (GVM_SCAP_DATA_CSV_DIR, "table-cves.csv", NULL);
  file_cpes = g_build_filename (GVM_SCAP_DATA_CSV_DIR, "table-cpes.csv", NULL);
  file_affected_products = g_build_filename (GVM_SCAP_DATA_CSV_DIR,
                                             "table-affected-products.csv",
                                             NULL);
  file_ovaldefs = g_build_filename (GVM_SCAP_DATA_CSV_DIR,
                                    "table-ovaldefs.csv",
                                    NULL);
  file_ovalfiles = g_build_filename (GVM_SCAP_DATA_CSV_DIR,
                                     "table-ovalfiles.csv",
                                     NULL);
  file_affected_ovaldefs = g_build_filename (GVM_SCAP_DATA_CSV_DIR,
                                             "table-affected-ovaldefs.csv",
                                             NULL);

  if (g_file_test (file_cves, G_FILE_TEST_EXISTS)
      && g_file_test (file_cpes, G_FILE_TEST_EXISTS)
      && g_file_test (file_affected_products, G_FILE_TEST_EXISTS)
      && g_file_test (file_ovaldefs, G_FILE_TEST_EXISTS)
      && g_file_test (file_ovalfiles, G_FILE_TEST_EXISTS)
      && g_file_test (file_affected_ovaldefs, G_FILE_TEST_EXISTS))
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

      sql ("COPY scap2.ovaldefs FROM '%s' WITH (FORMAT csv);", file_ovaldefs);
      g_free (file_ovaldefs);

      sql ("COPY scap2.ovalfiles FROM '%s' WITH (FORMAT csv);", file_ovalfiles);
      g_free (file_ovalfiles);

      sql ("COPY scap2.affected_ovaldefs FROM '%s' WITH (FORMAT csv);",
           file_affected_ovaldefs);
      g_free (file_affected_ovaldefs);

      /* Add the indexes and constraints, now that the data is ready. */

      g_debug ("%s: add indexes", __func__);
      proctitle_set ("gvmd: Syncing SCAP: Adding indexes");

      if (manage_db_init_indexes ("scap"))
        {
          g_warning ("%s: could not initialize SCAP indexes", __func__);
          return -1;
        }

      g_debug ("%s: add constraints", __func__);
      proctitle_set ("gvmd: Syncing SCAP: Adding constraints");

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
              proctitle_set ("gvmd: Syncing SCAP: done");
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
  proctitle_set ("gvmd: Syncing SCAP: Adding indexes");

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
  proctitle_set ("gvmd: Syncing SCAP: Updating CPEs");

  if (update_scap_cpes () == -1)
    return -1;

  g_debug ("%s: update cves", __func__);
  proctitle_set ("gvmd: Syncing SCAP: Updating CVEs");

  if (update_scap_cves () == -1)
    return -1;

  g_debug ("%s: update ovaldefs", __func__);
  proctitle_set ("gvmd: Syncing SCAP: Updating OVALdefs");

  if (update_scap_ovaldefs (0 /* Feed data. */) == -1)
    return -1;

  g_debug ("%s: updating user defined data", __func__);

  if (update_scap_ovaldefs (1 /* Private data. */) == -1)
    return -1;

  /* Do calculations that need all data. */

  g_debug ("%s: update max cvss", __func__);
  proctitle_set ("gvmd: Syncing SCAP: Updating max CVSS");

  update_scap_cvss ();

  g_debug ("%s: update placeholders", __func__);
  proctitle_set ("gvmd: Syncing SCAP: Updating placeholders");

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
                "gvmd: Syncing SCAP");
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

  ret = feed_lockfile_lock (&lockfile);
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
