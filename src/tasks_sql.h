/* OpenVAS Manager
 * $Id$
 * Description: Manager Manage library: SQL based tasks.
 *
 * Authors:
 * Matthew Mundell <matt@mundell.ukfsn.org>
 *
 * Copyright:
 * Copyright (C) 2009 Greenbone Networks GmbH
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * or, at your option, any later version as published by the Free
 * Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <ctype.h>
#include <sqlite3.h>

#include <openvas/openvas_logging.h>
#include "lsc_user.h"

/**
 * @brief Version of the database schema.
 */
#define DATABASE_VERSION 4

/**
 * @brief NVT selector type for "all" rule.
 */
#define NVT_SELECTOR_TYPE_ALL 0

/**
 * @brief NVT selector type for "family" rule.
 */
#define NVT_SELECTOR_TYPE_FAMILY 1

/**
 * @brief NVT selector type for "NVT" rule.
 */
#define NVT_SELECTOR_TYPE_NVT 2


/* Types. */

typedef long long int config_t;


/* Static headers. */

static void
init_preference_iterator (iterator_t*, const char*, const char*);

static const char*
preference_iterator_name (iterator_t*);

static const char*
preference_iterator_value (iterator_t*);

static void
init_nvt_selector_iterator (iterator_t*, const char*, int);

static const char*
nvt_selector_iterator_nvt (iterator_t*);

static const char*
nvt_selector_iterator_name (iterator_t*);

static int
nvt_selector_iterator_include (iterator_t*);

gboolean
find_config (const char*, task_t*);

static int
insert_rc_into_config (config_t, const char*, char*);

static void
set_target_hosts (const char *, const char *);


/* Variables. */

sqlite3* task_db = NULL;

nvtis_t* nvti_cache = NULL;


/* SQL helpers. */

static gchar*
sql_nquote (const char* string, size_t length)
{
  gchar *new, *new_start;
  const gchar *start, *end;
  int count = 0;

  /* Count number of apostrophes. */

  start = string;
  while ((start = strchr (start, '\''))) start++, count++;

  /* Allocate new string. */

  new = new_start = g_malloc0 (length + count + 1);

  /* Copy string, replacing apostrophes with double apostrophes. */

  start = string;
  end = string + length;
  for (; start < end; start++, new++)
    {
      char ch = *start;
      if (ch == '\'')
        {
          *new = '\'';
          new++;
          *new = '\'';
        }
      else
        *new = ch;
    }

  return new_start;
}

static gchar*
sql_quote (const char* string)
{
  return sql_nquote (string, strlen (string));
}

void
sql (char* sql, ...)
{
  const char* tail;
  int ret;
  sqlite3_stmt* stmt;
  va_list args;
  gchar* formatted;

  va_start (args, sql);
  formatted = g_strdup_vprintf (sql, args);
  va_end (args);

  tracef ("   sql: %s\n", formatted);

  /* Prepare statement. */

  while (1)
    {
      ret = sqlite3_prepare (task_db, (char*) formatted, -1, &stmt, &tail);
      if (ret == SQLITE_BUSY) continue;
      g_free (formatted);
      if (ret == SQLITE_OK)
        {
          if (stmt == NULL)
            {
              g_warning ("%s: sqlite3_prepare failed with NULL stmt: %s\n",
                         __FUNCTION__,
                         sqlite3_errmsg (task_db));
              abort ();
            }
          break;
        }
      g_warning ("%s: sqlite3_prepare failed: %s\n",
                 __FUNCTION__,
                 sqlite3_errmsg (task_db));
      abort ();
    }

  /* Run statement. */

  while (1)
    {
      ret = sqlite3_step (stmt);
      if (ret == SQLITE_BUSY) continue;
      if (ret == SQLITE_DONE) break;
      if (ret == SQLITE_ERROR || ret == SQLITE_MISUSE)
        {
          if (ret == SQLITE_ERROR) ret = sqlite3_reset (stmt);
          g_warning ("%s: sqlite3_step failed: %s\n",
                     __FUNCTION__,
                     sqlite3_errmsg (task_db));
          abort ();
        }
    }

  sqlite3_finalize (stmt);
}

/**
 * @brief Get a particular cell from a SQL query.
 *
 * @param[in]   col          Column.
 * @param[in]   row          Row.
 * @param[in]   sql          Format string for SQL query.
 * @param[in]   args         Arguments for format string.
 * @param[out]  stmt_return  Return from statement.
 *
 * @return 0 success, 1 too few rows, -1 error.
 */
int
sql_x (unsigned int col, unsigned int row, char* sql, va_list args,
       sqlite3_stmt** stmt_return)
{
  const char* tail;
  int ret;
  sqlite3_stmt* stmt;
  gchar* formatted;

  //va_start (args, sql);
  formatted = g_strdup_vprintf (sql, args);
  //va_end (args);

  tracef ("   sql_x: %s\n", formatted);

  /* Prepare statement. */

  while (1)
    {
      ret = sqlite3_prepare (task_db, (char*) formatted, -1, &stmt, &tail);
      if (ret == SQLITE_BUSY) continue;
      g_free (formatted);
      *stmt_return = stmt;
      if (ret == SQLITE_OK)
        {
          if (stmt == NULL)
            {
              g_warning ("%s: sqlite3_prepare failed with NULL stmt: %s\n",
                         __FUNCTION__,
                         sqlite3_errmsg (task_db));
              return -1;
            }
          break;
        }
      g_warning ("%s: sqlite3_prepare failed: %s\n",
                 __FUNCTION__,
                 sqlite3_errmsg (task_db));
      return -1;
    }

  /* Run statement. */

  while (1)
    {
      ret = sqlite3_step (stmt);
      if (ret == SQLITE_BUSY) continue;
      if (ret == SQLITE_DONE)
        {
          g_warning ("%s: sqlite3_step finished too soon\n",
                     __FUNCTION__);
          return 1;
        }
      if (ret == SQLITE_ERROR || ret == SQLITE_MISUSE)
        {
          if (ret == SQLITE_ERROR) ret = sqlite3_reset (stmt);
          g_warning ("%s: sqlite3_step failed: %s\n",
                     __FUNCTION__,
                     sqlite3_errmsg (task_db));
          return -1;
        }
      if (row == 0) break;
      row--;
      tracef ("   sql_x row %i\n", row);
    }

  tracef ("   sql_x end\n");
  return 0;
}

int
sql_int (unsigned int col, unsigned int row, char* sql, ...)
{
  sqlite3_stmt* stmt;
  va_list args;
  va_start (args, sql);
  int sql_x_ret = sql_x (col, row, sql, args, &stmt);
  va_end (args);
  if (sql_x_ret)
    {
      sqlite3_finalize (stmt);
      abort ();
    }
  int ret = sqlite3_column_int (stmt, col);
  sqlite3_finalize (stmt);
  return ret;
}

char*
sql_string (unsigned int col, unsigned int row, char* sql, ...)
{
  sqlite3_stmt* stmt;
  const unsigned char* ret2;
  char* ret;
  va_list args;
  va_start (args, sql);
  int sql_x_ret = sql_x (col, row, sql, args, &stmt);
  va_end (args);
  if (sql_x_ret)
    {
      sqlite3_finalize (stmt);
      return NULL;
    }
  ret2 = sqlite3_column_text (stmt, col);
  /* TODO: For efficiency, save this duplication by adjusting the task
           interface. */
  ret = g_strdup ((char*) ret2);
  sqlite3_finalize (stmt);
  return ret;
}

/**
 * @brief Get a particular cell from a SQL query, as an int64.
 *
 * @param[in]  ret    Return value.
 * @param[in]  col    Column.
 * @param[in]  row    Row.
 * @param[in]  sql    Format string for SQL query.
 * @param[in]  ...    Arguments for format string.
 *
 * @return 0 success, 1 too few rows, -1 error.
 */
int
sql_int64 (long long int* ret, unsigned int col, unsigned int row, char* sql, ...)
{
  sqlite3_stmt* stmt;
  va_list args;
  va_start (args, sql);
  int sql_x_ret = sql_x (col, row, sql, args, &stmt);
  va_end (args);
  switch (sql_x_ret)
    {
      case  0:
        break;
      case  1:
        sqlite3_finalize (stmt);
        return 1;
        break;
      default:
        assert (0);
        /* Fall through. */
      case -1:
        sqlite3_finalize (stmt);
        return -1;
        break;
    }
  *ret = sqlite3_column_int64 (stmt, col);
  sqlite3_finalize (stmt);
  return 0;
}


/* Migration. */

/**
 * @brief Backup the database to a file.
 *
 * @return Name of backup file.
 */
gchar *
backup_db ()
{
  // FIX ensure lock on db and db synced first
  return NULL;
}

/**
 * @brief Restore the database from a file.
 *
 * @return 0 success, -1 fail.
 */
int
restore_db ()
{
  // FIX ensure lock on db and db synced first
  return -1;
}

/**
 * @brief Return the database version supported by this manager.
 *
 * @return Database version supported by this manager.
 */
int
manage_db_supported_version ()
{
  return DATABASE_VERSION;
}

/**
 * @brief Return the database version of the actual database.
 *
 * @return Database version read from database if possible, else -1.
 */
int
manage_db_version ()
{
  int number;
  char *version = sql_string (0, 0,
                              "SELECT value FROM meta"
                              " WHERE name = 'database_version' LIMIT 1;");
  if (number)
    {
      number = atoi (version);
      free (version);
      return number;
    }
  return -1;
}

/**
 * @brief Set the database version of the actual database.
 *
 * @param  version  New version number.
 */
static void
set_db_version (int version)
{
  assert (version >= DATABASE_VERSION);
  sql ("INSERT OR REPLACE INTO meta (name, value)"
       " VALUES ('database_version', '%i');",
       version);
}

/**
 * @brief A migrator.
 */
typedef struct
{
  int version;         ///< Version that the migrator produces.
  int (*function) ();  ///< Function that does the migration.  NULL if too hard.
} migrator_t;

/**
 * @brief Migrate the database from version 0 to version 1.
 *
 * @return 0 success, -1 error.
 */
int
migrate_0_to_1 ()
{
  /* Ensure that the database is currently version 0. */

  if (manage_db_version () != 0) return -1;

  /* Update the database. */

  /* In SVN the database version flag changed from 0 to 1 on 2009-09-30,
   * while the database changed to the version 1 schema on 2009-08-29.  This
   * means the database could be flagged as version 0 while it has a version
   * 1 schema.  In this case the ADD COLUMN below would fail.  A work around
   * would be simply to update the version number to 1 in the database by
   * hand. */

  sql ("ALTER TABLE reports ADD COLUMN scan_run_status INTEGER;");

  /* SQLite 3.1.3 and earlier require a VACUUM before they can read
   * from the new column.  However, vacuuming might change the ROWIDs,
   * which would screw up the data.  Debian 5.0 (Lenny) is 3.5.9-6
   * already. */

  sql ("UPDATE reports SET scan_run_status = '%u';",
       TASK_STATUS_INTERNAL_ERROR);

  sql ("UPDATE reports SET scan_run_status = '%u'"
       " WHERE start_time IS NULL OR end_time IS NULL;",
       TASK_STATUS_STOPPED);

  sql ("UPDATE reports SET scan_run_status = '%u'"
       " WHERE end_time IS NOT NULL;",
       TASK_STATUS_DONE);

  /* Set the database version to 1. */

  set_db_version (1);

  return 0;
}

/**
 * @brief Migrate the database from version 1 to version 2.
 *
 * @return 0 success, -1 error.
 */
int
migrate_1_to_2 ()
{
  iterator_t nvts;

  /* Ensure that the database is currently version 1. */

  if (manage_db_version () != 1) return -1;

  /* Update the database. */

  /* The category column in nvts changed type from string to int.  This
   * may be a redundant conversion, as SQLite may have converted these
   * values automatically in each query anyway. */

  init_nvt_iterator (&nvts, (nvt_t) 0);
  while (next (&nvts))
    {
      int category;
      const char *category_string;

      /* The category must be accessed with sqlite3_column_text because
       * nvt_iterator_category returns an int now. */

      if (nvts.done)
        {
          cleanup_iterator (&nvts);
          return -1;
        }
      category_string = (const char*) sqlite3_column_text (nvts.stmt, 11);

      category = atoi (category_string);
      sql ("UPDATE nvts SET category = %i WHERE category = '%s';",
           category,
           category_string);
    }
  cleanup_iterator (&nvts);

  /* Set the database version to 2. */

  set_db_version (2);

  return 0;
}

/**
 * @brief Migrate the database from version 2 to version 3.
 *
 * @return 0 success, -1 error.
 */
int
migrate_2_to_3 ()
{
  /* Ensure that the database is currently version 2. */

  if (manage_db_version () != 2) return -1;

  /* Update the database. */

  /* The lsc_credentials table changed: package columns changed type from
   * BLOB to string, a password column appeared and the dog column changed
   * name to exe.
   *
   * Just remove all the LSC credentials, as credential generation only
   * started working after version 3. */

  sql ("DELETE from lsc_credentials;");
  sql ("ALTER TABLE lsc_credentials ADD COLUMN password;");
  sql ("ALTER TABLE lsc_credentials ADD COLUMN exe;");

  /* Set the database version to 3. */

  set_db_version (3);

  return 0;
}

/**
 * @brief Migrate the database from version 3 to version 4.
 *
 * @return 0 success, -1 error.
 */
int
migrate_3_to_4 ()
{
  iterator_t nvts;

  /* Ensure that the database is currently version 3. */

  if (manage_db_version () != 3) return -1;

  /* Update the database. */

  /* The nvt_selectors table got a family column. */

  sql ("ALTER TABLE nvt_selectors ADD COLUMN family;");

  init_nvt_selector_iterator (&nvts, NULL, 2);
  while (next (&nvts))
    {
      gchar *quoted_name = sql_quote (nvt_selector_iterator_name (&nvts));
      gchar *quoted_nvt = sql_quote (nvt_selector_iterator_nvt (&nvts));
      sql ("UPDATE nvt_selectors SET family ="
           " (SELECT family FROM nvts where oid = '%s')"
           " WHERE name = '%s';",
           quoted_nvt, quoted_name);
      g_free (quoted_name);
      g_free (quoted_nvt);
    }
  cleanup_iterator (&nvts);

  /* Set the database version to 4. */

  set_db_version (4);

  return 0;
}

/**
 * @brief Array of database version migrators.
 */
static migrator_t database_migrators[]
 = {{0, NULL},
    {1, migrate_0_to_1},
    {2, migrate_1_to_2},
    {3, migrate_2_to_3},
    {4, migrate_3_to_4},
#if 0
    {5, migrate_4_to_5},
#endif
    /* End marker. */
    {-1, NULL}};

/**
 * @brief Check whether a migration is available.
 *
 * @return 1 yes, 0 no, -1 error.
 */
static int
migrate_is_available (int old_version, int new_version)
{
  migrator_t *migrators;

  migrators = database_migrators + old_version + 1;

  while ((migrators->version >= 0) && (migrators->version <= new_version))
    {
      if (migrators->function == NULL) return 0;
      if (migrators->version == new_version) return 1;
      migrators++;
    }

  return -1;
}

/**
 * @brief Migrate database to version supported by this manager.
 *
 * @param[in]  log_config  Log configuration.
 * @param[in]  database    Location of manage database.
 *
 * @return 0 success, 1 already on supported version, 2 too hard, -1 error.
 */
int
manage_migrate (GSList *log_config, const gchar *database)
{
  gchar *backup_file;
  migrator_t *migrators;
  /* The version on the disk. */
  int old_version;
  /* The version that this program requires. */
  int new_version;

  g_log_set_handler (G_LOG_DOMAIN,
                     ALL_LOG_LEVELS,
                     (GLogFunc) openvas_log_func,
                     log_config);

  init_manage_process (0, database);

  old_version = manage_db_version ();
  new_version = manage_db_supported_version ();

  if (old_version == -1)
    {
      cleanup_manage_process ();
      return -1;
    }

  if (old_version == new_version)
    {
      cleanup_manage_process ();
      return 1;
    }

  switch (migrate_is_available (old_version, new_version))
    {
      case -1:
        cleanup_manage_process ();
        return -1;
      case  0:
        cleanup_manage_process ();
        return  2;
    }

  backup_file = backup_db ();
  // FIX check return

  /* Call the migrators to take the DB from the old version to the new. */

  migrators = database_migrators + old_version + 1;

  while ((migrators->version >= 0) && (migrators->version <= new_version))
    {
      if (migrators->function == NULL)
        {
          restore_db (backup_file);
          g_free (backup_file);
          cleanup_manage_process ();
          return -1;
        }

      if (migrators->function ())
        {
          restore_db (backup_file);
          g_free (backup_file);
          cleanup_manage_process ();
          return -1;
        }
      migrators++;
    }

  // FIX remove backup_file
  g_free (backup_file);
  cleanup_manage_process ();
  return 0;
}


/* Collation. */

/**
 * @brief Collate two message type strings.
 *
 * Callback for SQLite "collate_message_type" collation.
 *
 * @param[in]  data     Dummy for callback.
 * @param[in]  one_len  Length of first string.
 * @param[in]  arg_one  First string.
 * @param[in]  two_len  Length of second string.
 * @param[in]  arg_two  Second string.
 *
 * @return -1, 0 or 1 if first is less than, equal to or greater than second.
 */
int
collate_message_type (void* data,
                      int one_len, const void* arg_one,
                      int two_len, const void* arg_two)
{
  const char* one = (const char*) arg_one;
  const char* two = (const char*) arg_two;

  if (strcmp (one, "Security Hole") == 0)
    {
      if (strcmp (two, "Security Hole") == 0)
        return 0;
      return -1;
    }
  if (strcmp (two, "Security Hole") == 0) return 1;

  if (strcmp (one, "Security Warning") == 0)
    {
      if (strcmp (two, "Security Warning") == 0)
        return 0;
      return -1;
    }
  if (strcmp (two, "Security Warning") == 0) return 1;

  if (strcmp (one, "Security Note") == 0)
    {
      if (strcmp (two, "Security Note") == 0)
        return 0;
      return -1;
    }
  if (strcmp (two, "Security Note") == 0) return 1;

  if (strcmp (one, "Log Message") == 0)
    {
      if (strcmp (two, "Log Message") == 0)
        return 0;
      return -1;
    }
  if (strcmp (two, "Log Message") == 0) return 1;

  if (strcmp (one, "Debug Message") == 0)
    {
      if (strcmp (two, "Debug Message") == 0)
        return 0;
      return -1;
    }
  if (strcmp (two, "Debug Message") == 0) return 1;

  return strcmp (one, two);
}


/* Task functions. */

void
inc_task_int (task_t task, const char* field)
{
  int current = sql_int (0, 0,
                         "SELECT %s FROM tasks WHERE ROWID = %llu;",
                         field,
                         task);
  sql ("UPDATE tasks SET %s = %i WHERE ROWID = %llu;",
       field,
       current + 1,
       task);
}

void
dec_task_int (task_t task, const char* field)
{
  int current = sql_int (0, 0,
                         "SELECT %s FROM tasks WHERE ROWID = %llu;",
                         field,
                         task);
  sql ("UPDATE tasks SET %s = %i WHERE ROWID = %llu;",
       field,
       current - 1,
       task);
}

void
append_to_task_string (task_t task, const char* field, const char* value)
{
  char* current;
  current = sql_string (0, 0,
                        "SELECT %s FROM tasks WHERE ROWID = %llu;",
                        field,
                        task);
  gchar* quote;
  if (current)
    {
      gchar* new = g_strconcat ((const gchar*) current, value, NULL);
      free (current);
      quote = sql_nquote (new, strlen (new));
      g_free (new);
    }
  else
    quote = sql_nquote (value, strlen (value));
  sql ("UPDATE tasks SET %s = '%s' WHERE ROWID = %llu;",
       field,
       quote,
       task);
  g_free (quote);
}

/**
 * @brief Initialise a task iterator.
 *
 * @param[in]  iterator  Task iterator.
 */
void
init_task_iterator (task_iterator_t* iterator)
{
  int ret;
  const char* tail;
  gchar* formatted;
  sqlite3_stmt* stmt;

  iterator->done = FALSE;
  if (current_credentials.username)
    formatted = g_strdup_printf ("SELECT ROWID FROM tasks WHERE owner ="
                                 " (SELECT ROWID FROM users WHERE name = '%s');",
                                  current_credentials.username);
  else
    formatted = g_strdup_printf ("SELECT ROWID FROM tasks;");
  tracef ("   sql (iterator): %s\n", formatted);
  while (1)
    {
      ret = sqlite3_prepare (task_db, (char*) formatted, -1, &stmt, &tail);
      if (ret == SQLITE_BUSY) continue;
      g_free (formatted);
      iterator->stmt = stmt;
      if (ret == SQLITE_OK)
        {
          if (stmt == NULL)
            {
              g_warning ("%s: sqlite3_prepare failed with NULL stmt: %s\n",
                         __FUNCTION__,
                         sqlite3_errmsg (task_db));
              abort ();
            }
          break;
        }
      g_warning ("%s: sqlite3_prepare failed: %s\n",
                 __FUNCTION__,
                 sqlite3_errmsg (task_db));
      abort ();
    }
}

/**
 * @brief Cleanup a task iterator.
 *
 * @param[in]  iterator  Task iterator.
 */
void
cleanup_task_iterator (task_iterator_t* iterator)
{
  sqlite3_finalize (iterator->stmt);
}

/**
 * @brief Read the next task from an iterator.
 *
 * @param[in]   iterator  Task iterator.
 * @param[out]  task      Task.
 *
 * @return TRUE if there was a next task, else FALSE.
 */
gboolean
next_task (task_iterator_t* iterator, task_t* task)
{
  int ret;

  if (iterator->done) return FALSE;

  while ((ret = sqlite3_step (iterator->stmt)) == SQLITE_BUSY);
  if (ret == SQLITE_DONE)
    {
      iterator->done = TRUE;
      return FALSE;
    }
  if (ret == SQLITE_ERROR || ret == SQLITE_MISUSE)
    {
      if (ret == SQLITE_ERROR) ret = sqlite3_reset (iterator->stmt);
      g_warning ("%s: sqlite3_step failed: %s\n",
                 __FUNCTION__,
                 sqlite3_errmsg (task_db));
      abort ();
    }
  *task = sqlite3_column_int64 (iterator->stmt, 0);
  return TRUE;
}

/**
 * @brief Initialize the manage library for a process.
 *
 * Open the SQL database.
 *
 * @param[in]  update_nvt_cache  If true, clear the NVT cache.
 * @param[in]  database          Location of manage database.
 */
void
init_manage_process (int update_nvt_cache, const gchar *database)
{
  gchar *mgr_dir;
  int ret;

  if (task_db)
    {
      if (update_nvt_cache)
        {
          sql ("BEGIN EXCLUSIVE;");
          sql ("DELETE FROM nvts;");
          sql ("DELETE FROM nvt_preferences;");
          sql ("DELETE FROM meta WHERE name = 'nvts_checksum';");
          sql ("COMMIT;");
        }
      return;
    }

  /* Ensure the mgr directory exists. */
  mgr_dir = g_build_filename (OPENVAS_STATE_DIR "/mgr/", NULL);
  ret = g_mkdir_with_parents (mgr_dir, 0755 /* "rwxr-xr-x" */);
  g_free (mgr_dir);
  if (ret == -1)
    {
      g_warning ("%s: failed to create mgr directory: %s\n",
                 __FUNCTION__,
                 strerror (errno));
      abort (); // FIX
    }

  /* Open the database. */
  if (sqlite3_open (database ? database
                             : OPENVAS_STATE_DIR "/mgr/tasks.db",
                    &task_db))
    {
      g_warning ("%s: sqlite3_open failed: %s\n",
                 __FUNCTION__,
                 sqlite3_errmsg (task_db));
      abort (); // FIX
    }

  if (update_nvt_cache)
    {
      sql ("BEGIN EXCLUSIVE;");
      sql ("DELETE FROM nvts;");
      sql ("DELETE FROM nvt_preferences;");
      sql ("DELETE FROM meta WHERE name = 'nvts_checksum';");
      sql ("COMMIT;");
    }
  else
    {
      /* Create the collate functions. */

      if (sqlite3_create_collation (task_db,
                                    "collate_message_type",
                                    SQLITE_UTF8,
                                    NULL,
                                    collate_message_type)
          != SQLITE_OK)
        {
          g_message ("%s: failed to create collate_message_type", __FUNCTION__);
          abort ();
        }
    }
}

/**
 * @brief Setup config preferences for a config.
 *
 * @param[in]  config         The config.
 * @param[in]  safe_checks    safe_checks option: 1 for "yes", 0 for "no".
 * @param[in]  optimize_test  optimize_test option: 1 for "yes", 0 for "no".
 * @param[in]  port_range     port_range option: 1 for "yes", 0 for "no".
 */
static void
setup_full_config_prefs (config_t config, int safe_checks,
                         int optimize_test, int port_range)
{
  sql ("INSERT into config_preferences (config, type, name, value)"
       " VALUES (%i, 'SERVER_PREFS', 'max_hosts', '20');",
       config);
  sql ("INSERT into config_preferences (config, type, name, value)"
       " VALUES (%i, 'SERVER_PREFS', 'max_checks', '4');",
       config);
  sql ("INSERT into config_preferences (config, type, name, value)"
       " VALUES (%i, 'SERVER_PREFS', 'cgi_path', '/cgi-bin:/scripts');",
       config);
  if (port_range)
    sql ("INSERT into config_preferences (config, type, name, value)"
         " VALUES (%i, 'SERVER_PREFS', 'port_range', '1-65535');",
         config);
  else
    sql ("INSERT into config_preferences (config, type, name, value)"
         " VALUES (%i, 'SERVER_PREFS', 'port_range', 'default');",
         config);
  sql ("INSERT into config_preferences (config, type, name, value)"
       " VALUES (%i, 'SERVER_PREFS', 'auto_enable_dependencies', 'yes');",
       config);
  sql ("INSERT into config_preferences (config, type, name, value)"
       " VALUES (%i, 'SERVER_PREFS', 'silent_dependencies', 'yes');",
       config);
  sql ("INSERT into config_preferences (config, type, name, value)"
       " VALUES (%i, 'SERVER_PREFS', 'host_expansion', 'ip');",
       config);
  sql ("INSERT into config_preferences (config, type, name, value)"
       " VALUES (%i, 'SERVER_PREFS', 'ping_hosts', 'no');",
       config);
  sql ("INSERT into config_preferences (config, type, name, value)"
       " VALUES (%i, 'SERVER_PREFS', 'reverse_lookup', 'no');",
       config);
  if (optimize_test)
    sql ("INSERT into config_preferences (config, type, name, value)"
         " VALUES (%i, 'SERVER_PREFS', 'optimize_test', 'yes');",
         config);
  else
    sql ("INSERT into config_preferences (config, type, name, value)"
         " VALUES (%i, 'SERVER_PREFS', 'optimize_test', 'no');",
         config);
  if (safe_checks)
    sql ("INSERT into config_preferences (config, type, name, value)"
         " VALUES (%i, 'SERVER_PREFS', 'safe_checks', 'yes');",
         config);
  else
    sql ("INSERT into config_preferences (config, type, name, value)"
         " VALUES (%i, 'SERVER_PREFS', 'safe_checks', 'no');",
         config);
  sql ("INSERT into config_preferences (config, type, name, value)"
       " VALUES (%i, 'SERVER_PREFS', 'use_mac_addr', 'no');",
       config);
  sql ("INSERT into config_preferences (config, type, name, value)"
       " VALUES (%i, 'SERVER_PREFS', 'unscanned_closed', 'no');",
       config);
  sql ("INSERT into config_preferences (config, type, name, value)"
       " VALUES (%i, 'SERVER_PREFS', 'save_knowledge_base', 'yes');",
       config);
  sql ("INSERT into config_preferences (config, type, name, value)"
       " VALUES (%i, 'SERVER_PREFS', 'only_test_hosts_whose_kb_we_dont_have', 'no');",
       config);
  sql ("INSERT into config_preferences (config, type, name, value)"
       " VALUES (%i, 'SERVER_PREFS', 'only_test_hosts_whose_kb_we_have', 'no');",
       config);
  sql ("INSERT into config_preferences (config, type, name, value)"
       " VALUES (%i, 'SERVER_PREFS', 'kb_restore', 'no');",
       config);
  sql ("INSERT into config_preferences (config, type, name, value)"
       " VALUES (%i, 'SERVER_PREFS', 'kb_dont_replay_scanners', 'no');",
       config);
  sql ("INSERT into config_preferences (config, type, name, value)"
       " VALUES (%i, 'SERVER_PREFS', 'kb_dont_replay_info_gathering', 'no');",
       config);
  sql ("INSERT into config_preferences (config, type, name, value)"
       " VALUES (%i, 'SERVER_PREFS', 'kb_dont_replay_attacks', 'no');",
       config);
  sql ("INSERT into config_preferences (config, type, name, value)"
       " VALUES (%i, 'SERVER_PREFS', 'kb_dont_replay_denials', 'no');",
       config);
  sql ("INSERT into config_preferences (config, type, name, value)"
       " VALUES (%i, 'SERVER_PREFS', 'kb_max_age', '864000');",
       config);
  sql ("INSERT into config_preferences (config, type, name, value)"
       " VALUES (%i, 'SERVER_PREFS', 'log_whole_attack', 'no');",
       config);
  sql ("INSERT into config_preferences (config, type, name, value)"
       " VALUES (%i, 'SERVER_PREFS', 'language', 'english');",
       config);
  sql ("INSERT into config_preferences (config, type, name, value)"
       " VALUES (%i, 'SERVER_PREFS', 'checks_read_timeout', '5');",
       config);
  sql ("INSERT into config_preferences (config, type, name, value)"
       " VALUES (%i, 'SERVER_PREFS', 'non_simult_ports', '139, 445');",
       config);
  sql ("INSERT into config_preferences (config, type, name, value)"
       " VALUES (%i, 'SERVER_PREFS', 'plugins_timeout', '320');",
       config);
  sql ("INSERT into config_preferences (config, type, name, value)"
       " VALUES (%i, 'SERVER_PREFS', 'slice_network_addresses', 'no');",
       config);
  sql ("INSERT into config_preferences (config, type, name, value)"
       " VALUES (%i, 'SERVER_PREFS', 'nasl_no_signature_check', 'yes');",
       config);
  sql ("INSERT into config_preferences (config, type, name, value)"
       " VALUES (%i, 'SERVER_PREFS', 'ping_hosts', 'no');",
       config);
  sql ("INSERT into config_preferences (config, type, name, value)"
       " VALUES (%i, 'SERVER_PREFS', 'reverse_lookup', 'no');",
       config);
  sql ("INSERT into config_preferences (config, type, name, value)"
       " VALUES (%i, 'SERVER_PREFS', 'use_mac_addr', 'no');",
       config);
  sql ("INSERT into config_preferences (config, type, name, value)"
       " VALUES (%i, 'SERVER_PREFS', 'unscanned_closed', 'no');",
       config);
}

/**
 * @brief Initialize the manage library.
 *
 * Ensure all tasks are in a clean initial state.
 *
 * Beware that calling this function while tasks are running may lead to
 * problems.
 *
 * @param[in]  log_config      Log configuration.
 * @param[in]  nvt_cache_mode  True when running in NVT caching mode.
 * @param[in]  database        Location of database.
 *
 * @return 0 success, -1 error, -2 database is wrong version, -3 database needs
 *         to be initialised from server.
 */
int
init_manage (GSList *log_config, int nvt_cache_mode, const gchar *database)
{
  const char *database_version;
  task_t index;
  task_iterator_t iterator;

  g_log_set_handler (G_LOG_DOMAIN,
                     ALL_LOG_LEVELS,
                     (GLogFunc) openvas_log_func,
                     log_config);

  current_credentials.username = NULL;
  current_credentials.password = NULL;

  init_manage_process (0, database);

  /* Check that the version of the database is correct. */

  database_version = sql_string (0, 0,
                                 "SELECT value FROM meta"
                                 " WHERE name = 'database_version';");
  /** @todo Free database_version. */
  if (nvt_cache_mode)
    {
      if (database_version
          && strcmp (database_version, G_STRINGIFY (DATABASE_VERSION)))
        {
          g_message ("%s: database version of database: %s\n",
                     __FUNCTION__,
                     database_version);
          g_message ("%s: database version supported by manager: %s\n",
                     __FUNCTION__,
                     G_STRINGIFY (DATABASE_VERSION));
          return -2;
        }

      /* If database_version was NULL then meta was missing, so assume
       * that the database is missing, which is OK. */
    }
  else
    {
      if (database_version)
        {
          if (strcmp (database_version, G_STRINGIFY (DATABASE_VERSION)))
            {
              g_message ("%s: database version of database: %s\n",
                         __FUNCTION__,
                         database_version);
              g_message ("%s: database version supported by manager: %s\n",
                         __FUNCTION__,
                         G_STRINGIFY (DATABASE_VERSION));
              return -2;
            }
        }
      else
        /* Assume database is missing. */
        return -3;

      /* Check that the database was initialised from the scanner.
       *
       * This can also fail after a migration, for example if the database
       * was created before NVT preferences were cached in the database.
       */

      long long int count;
      if (sql_int64 (&count, 0, 0,
                     "SELECT count(*) FROM meta"
                     " WHERE name = 'nvts_md5sum'"
                     " OR name = 'nvt_preferences_enabled';")
          || count < 2)
        return -3;
    }

  /* Ensure the tables exist. */

  sql ("CREATE TABLE IF NOT EXISTS meta    (name UNIQUE, value);");
  sql ("CREATE TABLE IF NOT EXISTS users   (name UNIQUE, password);");
  /* nvt_selectors types: 0 all, 1 family, 2 NVT (NVT_SELECTOR_TYPE_* above). */
  sql ("CREATE TABLE IF NOT EXISTS nvt_selectors (name, exclude INTEGER, type INTEGER, family_or_nvt, family);");
  sql ("CREATE TABLE IF NOT EXISTS targets (name, hosts, comment);");
  sql ("CREATE TABLE IF NOT EXISTS configs (name UNIQUE, nvt_selector, comment, family_count INTEGER, nvt_count INTEGER, families_growing INTEGER, nvts_growing INTEGER);");
  sql ("CREATE TABLE IF NOT EXISTS task_files (task INTEGER, name, content);");
  sql ("CREATE TABLE IF NOT EXISTS config_preferences (config INTEGER, type, name, value);");
  sql ("CREATE TABLE IF NOT EXISTS tasks   (uuid, name, hidden INTEGER, time, comment, description, owner, run_status INTEGER, start_time, end_time, config, target);");
  sql ("CREATE TABLE IF NOT EXISTS results (task INTEGER, subnet, host, port, nvt, type, description)");
  sql ("CREATE TABLE IF NOT EXISTS reports (uuid, hidden INTEGER, task INTEGER, date INTEGER, start_time, end_time, nbefile, comment, scan_run_status INTEGER);");
  sql ("CREATE TABLE IF NOT EXISTS report_hosts (report INTEGER, host, start_time, end_time, attack_state, current_port, max_port);");
  sql ("CREATE TABLE IF NOT EXISTS report_results (report INTEGER, result INTEGER);");
  sql ("CREATE TABLE IF NOT EXISTS nvts (oid, version, name, summary, description, copyright, cve, bid, xref, tag, sign_key_ids, category INTEGER, family);");
  sql ("CREATE TABLE IF NOT EXISTS nvt_preferences (name, value);");
  sql ("CREATE TABLE IF NOT EXISTS lsc_credentials (name, password, comment, public_key TEXT, private_key TEXT, rpm TEXT, deb TEXT, exe TEXT);");

  /* Ensure the version is set. */

  set_db_version (DATABASE_VERSION);

  /* Ensure the special "om" user exists. */

  if (sql_int (0, 0, "SELECT count(*) FROM users WHERE name = 'om';") == 0)
    sql ("INSERT into users (name, password) VALUES ('om', '');");

  /* Ensure the predefined selectors and configs exist. */

  if (sql_int (0, 0, "SELECT count(*) FROM nvt_selectors WHERE name = 'All';")
      == 0)
    sql ("INSERT into nvt_selectors (name, exclude, type, family_or_nvt)"
         " VALUES ('All', 0, " G_STRINGIFY (NVT_SELECTOR_TYPE_ALL) ", NULL);");

  if (sql_int (0, 0,
               "SELECT count(*) FROM configs"
               " WHERE name = 'Full and fast';")
      == 0)
    {
      config_t config;

      sql ("INSERT into configs (name, nvt_selector, comment, nvts_growing,"
           " families_growing)"
           " VALUES ('Full and fast', 'All',"
           " 'All NVT''s; optimized by using previously collected information.',"
           " 1, 1);");

      /* Setup preferences for the config. */
      config = sqlite3_last_insert_rowid (task_db);
      setup_full_config_prefs (config, 1, 1, 0);
    }

  if (sql_int (0, 0,
               "SELECT count(*) FROM configs"
               " WHERE name = 'Full and fast ultimate';")
      == 0)
    {
      config_t config;

      sql ("INSERT into configs (name, nvt_selector, comment, nvts_growing,"
           " families_growing)"
           " VALUES ('Full and fast ultimate', 'All',"
           " 'All NVT''s including those that can stop services/hosts;"
           " optimized by using previously collected information.',"
           " 1, 1);");

      /* Setup preferences for the config. */
      config = sqlite3_last_insert_rowid (task_db);
      setup_full_config_prefs (config, 0, 1, 0);
    }

  if (sql_int (0, 0,
               "SELECT count(*) FROM configs"
               " WHERE name = 'Full and very deep';")
      == 0)
    {
      config_t config;

      sql ("INSERT into configs (name, nvt_selector, comment, nvts_growing,"
           " families_growing)"
           " VALUES ('Full and very deep', 'All',"
           " 'All NVT''s; don''t trust previously collected information; slow.',"
           " 1, 1);");

      /* Setup preferences for the config. */
      config = sqlite3_last_insert_rowid (task_db);
      setup_full_config_prefs (config, 1, 0, 1);
    }

  if (sql_int (0, 0,
               "SELECT count(*) FROM configs"
               " WHERE name = 'Full and very deep ultimate';")
      == 0)
    {
      config_t config;

      sql ("INSERT into configs (name, nvt_selector, comment, nvts_growing,"
           " families_growing)"
           " VALUES ('Full and very deep ultimate', 'All',"
           " 'All NVT''s including those that can stop services/hosts;"
           " don''t trust previously collected information; slow.',"
           " 1, 1);");

      /* Setup preferences for the config. */
      config = sqlite3_last_insert_rowid (task_db);
      setup_full_config_prefs (config, 0, 0, 1);
    }

  /* Ensure the predefined target exists. */

  if (sql_int (0, 0, "SELECT count(*) FROM targets WHERE name = 'Localhost';")
      == 0)
    sql ("INSERT into targets (name, hosts) VALUES ('Localhost', 'localhost');");

  /* Ensure the predefined example task and report exists. */

  if (sql_int (0, 0, "SELECT count(*) FROM tasks WHERE hidden = 1;") == 0)
    {
      sql ("INSERT into tasks (uuid, name, hidden, comment, owner,"
           " run_status, start_time, end_time, config, target)"
           " VALUES ('343435d6-91b0-11de-9478-ffd71f4c6f29', 'Example task',"
           " 1, 'This is an example task for the help pages.', NULL, %i,"
           " 'Tue Aug 25 21:48:25 2009', 'Tue Aug 25 21:52:16 2009',"
           " 'Full', 'Localhost');",
           TASK_STATUS_DONE);
    }

  if (sql_int (0, 0,
               "SELECT count(*) FROM reports"
               " WHERE uuid = '343435d6-91b0-11de-9478-ffd71f4c6f30';")
      == 0)
    {
      task_t task;
      result_t result;
      report_t report;

      if (find_task ("343435d6-91b0-11de-9478-ffd71f4c6f29", &task))
        g_warning ("%s: failed to find the example task", __FUNCTION__);
      else
        {
          sql ("INSERT into reports (uuid, hidden, task, comment,"
               " start_time, end_time)"
               " VALUES ('343435d6-91b0-11de-9478-ffd71f4c6f30', 1, %llu,"
               " 'This is an example report for the help pages.',"
               " 'Tue Aug 25 21:48:25 2009', 'Tue Aug 25 21:52:16 2009');",
               task);
          report = sqlite3_last_insert_rowid (task_db);
          sql ("INSERT into results (task, subnet, host, port, nvt, type,"
               " description)"
               " VALUES (%llu, '', 'localhost', 'telnet (23/tcp)',"
               " '1.3.6.1.4.1.25623.1.0.10330', 'Security Note',"
               " 'A telnet server seems to be running on this port');",
               task);
          result = sqlite3_last_insert_rowid (task_db);
          sql ("INSERT into report_results (report, result) VALUES (%llu, %llu)",
               report, result);
          sql ("INSERT into report_hosts (report, host, start_time, end_time)"
               " VALUES (%llu, 'localhost', 'Tue Aug 25 21:48:26 2009',"
               " 'Tue Aug 25 21:52:15 2009')",
               report);
        }
    }

  /* Set requested and running tasks to stopped. */

  assert (current_credentials.username == NULL);
  init_task_iterator (&iterator);
  while (next_task (&iterator, &index))
    {
      switch (task_run_status (index))
        {
          case TASK_STATUS_DELETE_REQUESTED:
          case TASK_STATUS_REQUESTED:
          case TASK_STATUS_RUNNING:
          case TASK_STATUS_STOP_REQUESTED:
            set_task_run_status (index, TASK_STATUS_STOPPED);
            break;
          default:
            break;
        }
    }
  cleanup_task_iterator (&iterator);

  /* Load the NVT cache into memory. */

  if (nvti_cache == NULL)
    {
      iterator_t nvts;

      nvti_cache = nvtis_new ();

      init_nvt_iterator (&nvts, (nvt_t) 0);
      while (next (&nvts))
        {
          nvti_t *nvti = nvti_new ();
          nvti_set_oid (nvti, nvt_iterator_oid (&nvts));
          nvti_set_family (nvti, nvt_iterator_family (&nvts));
          nvtis_add (nvti_cache, nvti);
        }
      cleanup_iterator (&nvts);
    }

  sqlite3_close (task_db);
  task_db = NULL;
  return 0;
}

/**
 * @brief Cleanup the manage library.
 */
void
cleanup_manage_process ()
{
  if (task_db)
    {
      if (current_scanner_task)
        {
          if (task_run_status (current_scanner_task) == TASK_STATUS_REQUESTED)
            set_task_run_status (current_scanner_task, TASK_STATUS_STOPPED);
        }
      sqlite3_close (task_db);
      task_db = NULL;
    }
}

/**
 * @brief Authenticate credentials.
 *
 * @param[in]  credentials  Credentials.
 *
 * @return 0 authentication success, 1 authentication failure, -1 error.
 */
int
authenticate (credentials_t* credentials)
{
  if (credentials->username && credentials->password)
    {
      int fail;

      if (strcmp (credentials->username, "om") == 0) return 1;

      fail = openvas_authenticate (credentials->username,
                                   credentials->password);
      if (fail == 0)
        {
          gchar* name;

          /* Ensure the user exists in the database.  SELECT then INSERT
           * instead of using "INSERT OR REPLACE", so that the ROWID stays
           * the same. */

          name = sql_nquote (credentials->username,
                            strlen (credentials->username));
          if (sql_int (0, 0,
                       "SELECT count(*) FROM users WHERE name = '%s';",
                       name))
            {
              g_free (name);
              return 0;
            }
          sql ("INSERT INTO users (name) VALUES ('%s');", name);
          g_free (name);
          return 0;
        }
      return fail;
    }
  return 1;
}

/**
 * @brief Return the number of tasks associated with the current user.
 *
 * @return The number of tasks associated with the current user.
 */
unsigned int
task_count ()
{
  return (unsigned int) sql_int (0, 0,
                                 "SELECT count(*) FROM tasks WHERE owner ="
                                 " (SELECT ROWID FROM users WHERE name = '%s');",
                                 current_credentials.username);
}

/**
 * @brief Return the identifier of a task.
 *
 * @param[in]  task  Task.
 *
 * @return ID of task.
 */
unsigned int
task_id (task_t task)
{
  // FIX cast hack for tasks_fs compat, task is long long int
  return (unsigned int) task;
}

/**
 * @brief Return the UUID of a task.
 *
 * @param[in]   task  Task.
 * @param[out]  id    Pointer to a newly allocated string.
 *
 * @return 0.
 */
int
task_uuid (task_t task, char ** id)
{
  *id = sql_string (0, 0,
                    "SELECT uuid FROM tasks WHERE ROWID = %llu;",
                    task);
  return 0;
}

/**
 * @brief Return the name of a task.
 *
 * @param[in]  task  Task.
 *
 * @return Task name.
 */
char*
task_name (task_t task)
{
  return sql_string (0, 0,
                     "SELECT name FROM tasks WHERE ROWID = %llu;",
                     task);
}

/**
 * @brief Return the comment of a task.
 *
 * @param[in]  task  Task.
 *
 * @return Comment of task.
 */
char*
task_comment (task_t task)
{
  return sql_string (0, 0,
                     "SELECT comment FROM tasks WHERE ROWID = %llu;",
                     task);
}

/**
 * @brief Return the config of a task.
 *
 * @param[in]  task  Task.
 *
 * @return Config of task.
 */
char*
task_config (task_t task)
{
  return sql_string (0, 0,
                     "SELECT config FROM tasks WHERE ROWID = %llu;",
                     task);
}

/**
 * @brief Set the config of a task.
 *
 * @param[in]  task    Task.
 * @param[in]  config  Config.
 */
void
set_task_config (task_t task, const char* config)
{
  gchar* quote = sql_nquote (config, strlen (config));
  sql ("UPDATE tasks SET config = '%s' WHERE ROWID = %llu;",
       quote,
       task);
  g_free (quote);
}

/**
 * @brief Return the target of a task.
 *
 * @param[in]  task  Task.
 *
 * @return Target of task.
 */
char*
task_target (task_t task)
{
  return sql_string (0, 0,
                     "SELECT target FROM tasks WHERE ROWID = %llu;",
                     task);
}

/**
 * @brief Set the target of a task.
 *
 * @param[in]  task    Task.
 * @param[in]  target  Target.
 */
void
set_task_target (task_t task, const char* target)
{
  gchar* quote = sql_nquote (target, strlen (target));
  sql ("UPDATE tasks SET target = '%s' WHERE ROWID = %llu;",
       quote,
       task);
  g_free (quote);
}

/**
 * @brief Return the description of a task.
 *
 * @param[in]  task  Task.
 *
 * @return Description of task.
 */
char*
task_description (task_t task)
{
  return sql_string (0, 0,
                     "SELECT description FROM tasks WHERE ROWID = %llu;",
                     task);
}

/**
 * @brief Set the description of a task.
 *
 * @param[in]  task         Task.
 * @param[in]  description  Description.  Used directly, freed by free_task.
 * @param[in]  length       Length of description.
 */
void
set_task_description (task_t task, char* description, gsize length)
{
  gchar* quote = sql_nquote (description, strlen (description));
  sql ("UPDATE tasks SET description = '%s' WHERE ROWID = %llu;",
       quote,
       task);
  g_free (quote);
}

/**
 * @brief Return the run state of a task.
 *
 * @param[in]  task  Task.
 *
 * @return Task run status.
 */
task_status_t
task_run_status (task_t task)
{
  return (unsigned int) sql_int (0, 0,
                                 "SELECT run_status FROM tasks WHERE ROWID = %llu;",
                                 task);
}

/**
 * @brief Set the run state of a task.
 *
 * @param[in]  task    Task.
 * @param[in]  status  New run status.
 *
 */
void
set_task_run_status (task_t task, task_status_t status)
{
  if ((task == current_scanner_task) && current_report)
    sql ("UPDATE reports SET scan_run_status = %u WHERE ROWID = %llu;",
         status,
         current_report);
  sql ("UPDATE tasks SET run_status = %u WHERE ROWID = %llu;",
       status,
       task);
}

/**
 * @brief Return the report currently being produced.
 *
 * @param[in]  task  Task.
 *
 * @return Current report of task if task is active, else (report_t) 0.
 */
report_t
task_running_report (task_t task)
{
  task_status_t run_status = task_run_status (task);
  if (run_status == TASK_STATUS_REQUESTED
      || run_status == TASK_STATUS_RUNNING)
    {
      return (unsigned int) sql_int (0, 0,
                                     "SELECT ROWID FROM reports"
                                     " WHERE task = %llu AND end_time IS NULL;",
                                     task);
    }
  return (report_t) 0;
}

/**
 * @brief Return the most recent start time of a task.
 *
 * @param[in]  task  Task.
 *
 * @return Task start time.
 */
char*
task_start_time (task_t task)
{
  return sql_string (0, 0,
                     "SELECT start_time FROM tasks WHERE ROWID = %llu;",
                     task);
}

/**
 * @brief Set the start time of a task.
 *
 * @param[in]  task  Task.
 * @param[in]  time  New time.  Freed before return.
 */
void
set_task_start_time (task_t task, char* time)
{
  sql ("UPDATE tasks SET start_time = '%.*s' WHERE ROWID = %llu;",
       strlen (time),
       time,
       task);
  free (time);
}

/**
 * @brief Return the most recent end time of a task.
 *
 * @param[in]  task  Task.
 *
 * @return Task end time.
 */
char*
task_end_time (task_t task)
{
  return sql_string (0, 0,
                     "SELECT end_time FROM tasks WHERE ROWID = %llu;",
                     task);
}

/**
 * @brief Get the report ID from the very first completed invocation of task.
 *
 * @param[in]  task  The task.
 *
 * @return The UUID of the task as a newly allocated string.
 */
gchar*
task_first_report_id (task_t task)
{
  return sql_string (0, 0,
                     "SELECT uuid FROM reports WHERE task = %llu"
                     " AND scan_run_status = %u"
                     " ORDER BY date ASC LIMIT 1;",
                     task,
                     TASK_STATUS_DONE);
}

/**
 * @brief Get the report ID from the most recently completed invocation of task.
 *
 * @param[in]  task  The task.
 *
 * @return The UUID of the task as a newly allocated string.
 */
gchar*
task_last_report_id (task_t task)
{
  return sql_string (0, 0,
                     "SELECT uuid FROM reports WHERE task = %llu"
                     " AND scan_run_status = %u"
                     " ORDER BY date DESC LIMIT 1;",
                     task,
                     TASK_STATUS_DONE);
}

/**
 * @brief Get report ID from second most recently completed invocation of task.
 *
 * @param[in]  task  The task.
 *
 * @return The UUID of the task as a newly allocated string.
 */
gchar*
task_second_last_report_id (task_t task)
{
  return sql_string (0, 1,
                     "SELECT uuid FROM reports WHERE task = %llu"
                     " AND scan_run_status = %u"
                     " ORDER BY date DESC LIMIT 2;",
                     task,
                     TASK_STATUS_DONE);
}

/**
 * @brief Generate rcfile in task from config and target.
 *
 * @param[in]  task  The task.
 *
 * @return 0 success, -1 error.
 */
int
make_task_rcfile (task_t task)
{
  char *config, *target, *selector, *name, *hosts, *rc;
  iterator_t prefs;
  GString *buffer;

  config = task_config (task);
  if (config == NULL) return -1;

  target = task_target (task);
  if (target == NULL)
    {
      free (config);
      return -1;
    }

  selector = config_nvt_selector (config);
  if (selector == NULL)
    {
      free (config);
      free (target);
      return -1;
    }

  name = task_name (task);
  if (name == NULL)
    {
      free (config);
      free (target);
      free (selector);
      return -1;
    }

  /* Header. */

  buffer = g_string_new ("# This file was automatically created"
                         " by openvasmd, the OpenVAS Manager daemon.\n");

  /* General preferences. */

  init_preference_iterator (&prefs, config, NULL);
  while (next (&prefs))
    g_string_append_printf (buffer,
                            "%s = %s\n",
                            preference_iterator_name (&prefs),
                            preference_iterator_value (&prefs));
  cleanup_iterator (&prefs);

  /* Targets for general preferences. */

  hosts = target_hosts (target);
  free (target);
  if (hosts)
    g_string_append_printf (buffer, "targets = %s\n\n", hosts);
  else
    {
      free (hosts);
      free (config);
      free (selector);
      g_string_free (buffer, TRUE);
      return -1;
    }
  free (hosts);

  /* Scanner set. */

  g_string_append (buffer, "begin(SCANNER_SET)\n");
  // FIX how know if scanner?
  g_string_append (buffer, "end(SCANNER_SET)\n\n");

  /* Scanner preferences. */

  g_string_append (buffer, "begin(SERVER_PREFS)\n");
  init_preference_iterator (&prefs, config, "SERVER_PREFS");
  while (next (&prefs))
    g_string_append_printf (buffer,
                            " %s = %s\n",
                            preference_iterator_name (&prefs),
                            preference_iterator_value (&prefs));
  cleanup_iterator (&prefs);
  g_string_append (buffer, "end(SERVER_PREFS)\n\n");

  /* Client side user rules. */

  g_string_append (buffer, "begin(CLIENTSIDE_USERRULES)\n");
  g_string_append (buffer, "end(CLIENTSIDE_USERRULES)\n\n");

  /* Plugin preferences. */

  g_string_append (buffer, "begin(PLUGINS_PREFS)\n");
  init_preference_iterator (&prefs, config, "PLUGINS_PREFS");
  while (next (&prefs))
    g_string_append_printf (buffer,
                            " %s = %s\n",
                            preference_iterator_name (&prefs),
                            preference_iterator_value (&prefs));
  cleanup_iterator (&prefs);
  g_string_append (buffer, "end(PLUGINS_PREFS)\n\n");

  /* Plugin set. */

  g_string_append (buffer, "begin(PLUGIN_SET)\n");
  {
    /* This block is a modified copy of nvt_selector_plugins (from
     * manage.c). */
    if (nvt_selector_nvts_growing (selector))
      {
        if ((sql_int (0, 0,
                      "SELECT COUNT(*) FROM nvt_selectors WHERE name = '%s';",
                      selector)
             == 1)
            && (sql_int (0, 0,
                         "SELECT COUNT(*) FROM nvt_selectors"
                         " WHERE name = '%s'"
                         " AND type = " G_STRINGIFY (NVT_SELECTOR_TYPE_ALL)
                         ";",
                         selector)
                == 1))
          {
            iterator_t nvts;

            init_nvt_iterator (&nvts, (nvt_t) 0);
            while (next (&nvts))
              g_string_append_printf (buffer,
                                      " %s = yes\n",
                                      nvt_iterator_oid (&nvts));
            cleanup_iterator (&nvts);
          }
        // FIX finalise selector implementation
      }
    else
      {
        iterator_t nvts;

        init_nvt_selector_iterator (&nvts, selector, 2);
        while (next (&nvts))
          g_string_append_printf (buffer,
                                  " %s = %s\n",
                                  nvt_selector_iterator_nvt (&nvts),
                                  nvt_selector_iterator_include (&nvts)
                                  ? "yes" : "no");
        cleanup_iterator (&nvts);
      }
  }
  g_string_append (buffer, "end(PLUGIN_SET)\n\n");

  /* Scanner info. */

  g_string_append (buffer, "begin(SERVER_INFO)\n");
  g_string_append (buffer, "end(SERVER_INFO)\n");

  free (config);
  free (selector);

  rc = g_string_free (buffer, FALSE);

  set_task_description (task, rc, strlen (rc));
  free (rc);

  return 0;
}


/* Iterators. */

/**
 * @brief Cleanup an iterator.
 *
 * @param[in]  iterator  Iterator.
 */
void
cleanup_iterator (iterator_t* iterator)
{
  sqlite3_finalize (iterator->stmt);
}

/**
 * @brief Increment an iterator.
 *
 * @param[in]   iterator  Task iterator.
 *
 * @return TRUE if there was a next item, else FALSE.
 */
gboolean
next (iterator_t* iterator)
{
  int ret;

  if (iterator->done) return FALSE;

  while ((ret = sqlite3_step (iterator->stmt)) == SQLITE_BUSY);
  if (ret == SQLITE_DONE)
    {
      iterator->done = TRUE;
      return FALSE;
    }
  if (ret == SQLITE_ERROR || ret == SQLITE_MISUSE)
    {
      if (ret == SQLITE_ERROR) ret = sqlite3_reset (iterator->stmt);
      g_warning ("%s: sqlite3_step failed: %s\n",
                 __FUNCTION__,
                 sqlite3_errmsg (task_db));
      abort ();
    }
  return TRUE;
}


/* Results. */

/**
 * @brief Make a result.
 *
 * @param[in]  task         The task associated with the result.
 * @param[in]  subnet       Subnet.
 * @param[in]  host         Host.
 * @param[in]  port         The port the result refers to.
 * @param[in]  nvt          The OID of the NVT that produced the result.
 * @param[in]  type         Type of result.  "Security Hole", etc.
 * @param[in]  description  Description of the result.
 *
 * @return A result descriptor for the new result.
 */
result_t
make_result (task_t task, const char* subnet, const char* host,
             const char* port, const char* nvt, const char* type,
             const char* description)
{
  result_t result;
  gchar *quoted_descr = sql_quote (description);
  sql ("INSERT into results (task, subnet, host, port, nvt, type, description)"
       " VALUES (%llu, '%s', '%s', '%s', '%s', '%s', '%s');",
       task, subnet, host, port, nvt, type, quoted_descr);
  g_free (quoted_descr);
  result = sqlite3_last_insert_rowid (task_db);
  return result;
}


/* Reports. */

/**
 * @brief Make a report.
 *
 * @param[in]  task  The task associated with the report.
 * @param[in]  uuid  The UUID of the report.
 *
 * @return A report descriptor for the new report.
 */
report_t
make_report (task_t task, const char* uuid)
{
  report_t report;
  sql ("INSERT into reports (uuid, hidden, task, date, nbefile, comment)"
       " VALUES ('%s', 0, %llu, %i, '', '');",
       uuid, task, time (NULL));
  report = sqlite3_last_insert_rowid (task_db);
  return report;
}

/**
 * @brief Create the current report for a task.
 *
 * @param[in]   task       The task.
 * @param[out]  report_id  Report ID.
 *
 * @return 0 success, -1 current_report is already set, -2 failed to generate ID.
 */
static int
create_report (task_t task, char **report_id)
{
  assert (current_report == (report_t) 0);
  if (current_report) return -1;

  if (report_id == NULL) return -1;

  /* Generate report UUID. */

  *report_id = make_report_uuid ();
  if (*report_id == NULL) return -2;

  /* Create the report. */

  current_report = make_report (task, *report_id);

  return 0;
}

/**
 * @brief Return the UUID of a report.
 *
 * @param[in]  report  Report.
 *
 * @return Report UUID.
 */
char*
report_uuid (report_t report)
{
  return sql_string (0, 0,
                     "SELECT uuid FROM reports WHERE ROWID = %llu;",
                     report);
}

/**
 * @brief Return the task of a report.
 *
 * @param[in]   report  A report.
 * @param[out]  task    Task return, 0 if succesfully failed to find task.
 *
 * @return FALSE on success (including if failed to find report), TRUE on error.
 */
gboolean
report_task (report_t report, task_t *task)
{
  switch (sql_int64 (task, 0, 0,
                     "SELECT task FROM reports WHERE ROWID = %llu;",
                     report))
    {
      case 0:
        break;
      case 1:        /* Too few rows in result of query. */
        *task = 0;
        break;
      default:       /* Programming error. */
        assert (0);
      case -1:
        return TRUE;
        break;
    }
  return FALSE;
}

/**
 * @brief Get the number of holes in a report.
 *
 * @param[in]   report  Report.
 * @param[in]   host    The host whose holes to count.  NULL for all hosts.
 * @param[out]  holes   On success, number of holes.
 *
 * @return 0.
 */
int
report_holes (report_t report, const char* host, int* holes)
{
  if (host)
    *holes = sql_int (0, 0,
                      "SELECT count(*) FROM results, report_results"
                      " WHERE results.type = 'Security Hole'"
                      " AND results.ROWID = report_results.result"
                      " AND report_results.report = %llu"
                      " AND results.host = '%s';",
                      report,
                      host);
  else
    *holes = sql_int (0, 0,
                      "SELECT count(*) FROM results, report_results"
                      " WHERE results.type = 'Security Hole'"
                      " AND results.ROWID = report_results.result"
                      " AND report_results.report = %llu;",
                      report);
  return 0;
}

/**
 * @brief Get the number of notes in a report.
 *
 * @param[in]   report  Report.
 * @param[in]   host    The host whose notes to count.  NULL for all hosts.
 * @param[out]  notes   On success, number of notes.
 *
 * @return 0.
 */
int
report_notes (report_t report, const char* host, int* notes)
{
  if (host)
    *notes = sql_int (0, 0,
                      "SELECT count(*) FROM results, report_results"
                      " WHERE results.type = 'Security Note'"
                      " AND results.ROWID = report_results.result"
                      " AND report_results.report = %llu"
                      " AND results.host = '%s';",
                      report,
                      host);
  else
    *notes = sql_int (0, 0,
                      "SELECT count(*) FROM results, report_results"
                      " WHERE results.type = 'Security Note'"
                      " AND results.ROWID = report_results.result"
                      " AND report_results.report = %llu;",
                      report);
  return 0;
}

/**
 * @brief Get the number of warnings in a report.
 *
 * @param[in]   report    Report.
 * @param[in]   host      The host whose warnings to count.  NULL for all hosts.
 * @param[out]  warnings  On success, number of warnings.
 *
 * @return 0.
 */
int
report_warnings (report_t report, const char* host, int* warnings)
{
  if (host)
    *warnings = sql_int (0, 0,
                         "SELECT count(*) FROM results, report_results"
                         " WHERE results.type = 'Security Warning'"
                         " AND results.ROWID = report_results.result"
                         " AND report_results.report = %llu"
                         " AND results.host = '%s';",
                         report,
                         host);
  else
    *warnings = sql_int (0, 0,
                         "SELECT count(*) FROM results, report_results"
                         " WHERE results.type = 'Security Warning'"
                         " AND results.ROWID = report_results.result"
                         " AND report_results.report = %llu;",
                         report);
  return 0;
}

/**
 * @brief Add a result to a report.
 *
 * @param[in]  report  The report.
 * @param[in]  result  The result.
 */
void
report_add_result (report_t report, result_t result)
{
  sql ("INSERT into report_results (report, result)"
       " VALUES (%llu, %llu);",
       report, result);
}

/**
 * @brief Initialise a report iterator.
 *
 * @param[in]  iterator  Iterator.
 * @param[in]  task      Task whose reports the iterator loops over.
 *                       All tasks if NULL.
 */
void
init_report_iterator (iterator_t* iterator, task_t task)
{
  int ret;
  const char* tail;
  gchar* sql;
  sqlite3_stmt* stmt;

  iterator->done = FALSE;
  if (task)
    sql = g_strdup_printf ("SELECT ROWID FROM reports WHERE task = %llu;",
                           task);
  else
    sql = g_strdup_printf ("SELECT ROWID FROM reports;");
  tracef ("   sql (report iterator): %s\n", sql);
  while (1)
    {
      ret = sqlite3_prepare (task_db, (char*) sql, -1, &stmt, &tail);
      if (ret == SQLITE_BUSY) continue;
      g_free (sql);
      iterator->stmt = stmt;
      if (ret == SQLITE_OK)
        {
          if (stmt == NULL)
            {
              g_warning ("%s: sqlite3_prepare failed with NULL stmt: %s\n",
                         __FUNCTION__,
                         sqlite3_errmsg (task_db));
              abort ();
            }
          break;
        }
      g_warning ("%s: sqlite3_prepare failed: %s\n",
                 __FUNCTION__,
                 sqlite3_errmsg (task_db));
      abort ();
    }
}

/**
 * @brief Read the next report from an iterator.
 *
 * @param[in]   iterator  Task iterator.
 * @param[out]  report    Report.
 *
 * @return TRUE if there was a next task, else FALSE.
 */
gboolean
next_report (iterator_t* iterator, report_t* report)
{
  int ret;

  if (iterator->done) return FALSE;

  while ((ret = sqlite3_step (iterator->stmt)) == SQLITE_BUSY);
  if (ret == SQLITE_DONE)
    {
      iterator->done = TRUE;
      return FALSE;
    }
  if (ret == SQLITE_ERROR || ret == SQLITE_MISUSE)
    {
      if (ret == SQLITE_ERROR) ret = sqlite3_reset (iterator->stmt);
      g_warning ("%s: sqlite3_step failed: %s\n",
                 __FUNCTION__,
                 sqlite3_errmsg (task_db));
      abort ();
    }
  *report = sqlite3_column_int64 (iterator->stmt, 0);
  return TRUE;
}

/**
 * @brief Initialise a result iterator.
 *
 * The results are ordered by host, then port, then type (severity).
 *
 * @param[in]  iterator      Iterator.
 * @param[in]  report        Report whose results the iterator loops over.
 *                           All results if NULL.
 * @param[in]  host          Host whose results the iterator loops over.  All
 *                           results if NULL.  Only considered if report given.
 * @param[in]  first_result  The result to start from.  The results are 0
 *                           indexed.
 * @param[in]  max_results   The maximum number of results returned.
 */
void
init_result_iterator (iterator_t* iterator, report_t report, const char* host,
                      int first_result, int max_results)
{
  int ret;
  const char* tail;
  gchar* sql;
  sqlite3_stmt* stmt;

  iterator->done = FALSE;
  if (report)
    {
      if (host)
        sql = g_strdup_printf ("SELECT subnet, host, port, nvt, type, description"
                               " FROM results, report_results"
                               " WHERE report_results.report = %llu"
                               " AND report_results.result = results.ROWID"
                               " AND results.host = '%s'"
                               " ORDER BY port,"
                               " type COLLATE collate_message_type DESC"
                               " LIMIT %i OFFSET %i;",
                               report, host, max_results, first_result);
      else
        sql = g_strdup_printf ("SELECT subnet, host, port, nvt, type, description"
                               " FROM results, report_results"
                               " WHERE report_results.report = %llu"
                               " AND report_results.result = results.ROWID"
                               " ORDER BY host, port,"
                               " type COLLATE collate_message_type DESC"
                               " LIMIT %i OFFSET %i;",
                               report, max_results, first_result);
    }
  else
    sql = g_strdup_printf ("SELECT * FROM results LIMIT %i OFFSET %i;",
                           max_results, first_result);
  tracef ("   sql (result iterator): %s\n", sql);
  while (1)
    {
      ret = sqlite3_prepare (task_db, (char*) sql, -1, &stmt, &tail);
      if (ret == SQLITE_BUSY) continue;
      g_free (sql);
      iterator->stmt = stmt;
      if (ret == SQLITE_OK)
        {
          if (stmt == NULL)
            {
              g_warning ("%s: sqlite3_prepare failed with NULL stmt: %s\n",
                         __FUNCTION__,
                         sqlite3_errmsg (task_db));
              abort ();
            }
          break;
        }
      g_warning ("%s: sqlite3_prepare failed: %s\n",
                 __FUNCTION__,
                 sqlite3_errmsg (task_db));
      abort ();
    }
}

#if 0
/**
 * @brief Get the subnet from a result iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The subnet of the result as a newly allocated string, or NULL on
 *         error.
 */
char*
result_iterator_subnet (iterator_t* iterator)
{
  const char *ret;
  if (iterator->done) return NULL;
  ret = (const char*) sqlite3_column_text (iterator->stmt, 1);
  return ret ? g_strdup (ret) : NULL;
}
#endif

#if 0
/**
 * @brief Get the NAME from a result iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The NAME of the result.  Caller must use only before calling
 *         cleanup_iterator.
 */
#endif

#define DEF_ACCESS(name, col) \
const char* \
result_iterator_ ## name (iterator_t* iterator) \
{ \
  const char *ret; \
  if (iterator->done) return NULL; \
  ret = (const char*) sqlite3_column_text (iterator->stmt, col); \
  return ret; \
}

DEF_ACCESS (subnet, 0);
DEF_ACCESS (host, 1);
DEF_ACCESS (port, 2);
DEF_ACCESS (nvt, 3);
DEF_ACCESS (type, 4);
DEF_ACCESS (descr, 5);

#undef DEF_ACCESS

/**
 * @brief Initialise a host iterator.
 *
 * @param[in]  iterator  Iterator.
 * @param[in]  report    Report whose hosts the iterator loops over.
 *                       All hosts if NULL.
 */
void
init_host_iterator (iterator_t* iterator, report_t report)
{
  int ret;
  const char* tail;
  gchar* sql;
  sqlite3_stmt* stmt;

  iterator->done = FALSE;
  if (report)
    sql = g_strdup_printf ("SELECT * FROM report_hosts WHERE report = %llu;",
                           report);
  else
    sql = g_strdup_printf ("SELECT * FROM report_hosts;");
  tracef ("   sql (host iterator): %s\n", sql);
  while (1)
    {
      ret = sqlite3_prepare (task_db, (char*) sql, -1, &stmt, &tail);
      if (ret == SQLITE_BUSY) continue;
      g_free (sql);
      iterator->stmt = stmt;
      if (ret == SQLITE_OK)
        {
          if (stmt == NULL)
            {
              g_warning ("%s: sqlite3_prepare failed with NULL stmt: %s\n",
                         __FUNCTION__,
                         sqlite3_errmsg (task_db));
              abort ();
            }
          break;
        }
      g_warning ("%s: sqlite3_prepare failed: %s\n",
                 __FUNCTION__,
                 sqlite3_errmsg (task_db));
      abort ();
    }
}

#if 0
/**
 * @brief Get the NAME from a host iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The NAME of the host.  Caller must use only before calling
 *         cleanup_iterator.
 */
#endif

#define DEF_ACCESS(name, col) \
const char* \
name (iterator_t* iterator) \
{ \
  const char *ret; \
  if (iterator->done) return NULL; \
  ret = (const char*) sqlite3_column_text (iterator->stmt, col); \
  return ret; \
}

DEF_ACCESS (host_iterator_host, 1);
DEF_ACCESS (host_iterator_start_time, 2);
DEF_ACCESS (host_iterator_end_time, 3);
DEF_ACCESS (host_iterator_attack_state, 4);

int
host_iterator_current_port (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = (int) sqlite3_column_int (iterator->stmt, 5);
  return ret;
}

int
host_iterator_max_port (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = (int) sqlite3_column_int (iterator->stmt, 6);
  return ret;
}

/**
 * @brief Set the end time of a task.
 *
 * @param[in]  task  Task.
 * @param[in]  time  New time.  Freed before return.
 */
void
set_task_end_time (task_t task, char* time)
{
  sql ("UPDATE tasks SET end_time = '%.*s' WHERE ROWID = %llu;",
       strlen (time),
       time,
       task);
  free (time);
}

/**
 * @brief Get the start time of a scan.
 *
 * @param[in]  report  The report associated with the scan.
 *
 * @return Start time of scan, in a newly allocated string.
 */
char*
scan_start_time (report_t report)
{
  char *time = sql_string (0, 0,
                           "SELECT start_time FROM reports WHERE ROWID = %llu;",
                           report);
  return time ? time : g_strdup ("");
}

/**
 * @brief Set the start time of a scan.
 *
 * @param[in]  report     The report associated with the scan.
 * @param[in]  timestamp  Start time.
 */
void
set_scan_start_time (report_t report, const char* timestamp)
{
  sql ("UPDATE reports SET start_time = '%s' WHERE ROWID = %llu;",
       timestamp, report);
}

/**
 * @brief Get the end time of a scan.
 *
 * @param[in]  report  The report associated with the scan.
 *
 * @return End time of scan, in a newly allocated string.
 */
char*
scan_end_time (report_t report)
{
  char *time = sql_string (0, 0,
                           "SELECT end_time FROM reports WHERE ROWID = %llu;",
                           report);
  return time ? time : g_strdup ("");
}

/**
 * @brief Set the end time of a scan.
 *
 * @param[in]  report     The report associated with the scan.
 * @param[in]  timestamp  End time.
 */
void
set_scan_end_time (report_t report, const char* timestamp)
{
  sql ("UPDATE reports SET end_time = '%s' WHERE ROWID = %llu;",
       timestamp, report);
}

/**
 * @brief Set the end time of a scanned host.
 *
 * @param[in]  report     Report associated with the scan.
 * @param[in]  host       Host.
 * @param[in]  timestamp  End time.
 */
void
set_scan_host_end_time (report_t report, const char* host,
                        const char* timestamp)
{
  if (sql_int (0, 0,
               "SELECT COUNT(*) FROM report_hosts"
               " WHERE report = %llu AND host = '%s';",
               report, host))
    sql ("UPDATE report_hosts SET end_time = '%s'"
         " WHERE report = %llu AND host = '%s';",
         timestamp, report, host);
  else
    sql ("INSERT into report_hosts (report, host, end_time)"
         " VALUES (%llu, '%s', '%s');",
         report, host, timestamp);
}

/**
 * @brief Set the start time of a scanned host.
 *
 * @param[in]  report     Report associated with the scan.
 * @param[in]  host       Host.
 * @param[in]  timestamp  Start time.
 */
void
set_scan_host_start_time (report_t report, const char* host,
                          const char* timestamp)
{
  if (sql_int (0, 0,
               "SELECT COUNT(*) FROM report_hosts"
               " WHERE report = %llu AND host = '%s';",
               report, host))
    sql ("UPDATE report_hosts SET start_time = '%s'"
         " WHERE report = %llu AND host = '%s';",
         timestamp, report, host);
  else
    sql ("INSERT into report_hosts (report, host, start_time)"
         " VALUES (%llu, '%s', '%s');",
         report, host, timestamp);
}

/**
 * @brief Get the timestamp of a report.
 *
 * @param[in]   report_id    UUID of report.
 * @param[out]  timestamp    Timestamp on success.  Caller must free.
 *
 * @return 0 on success, -1 on error.
 */
int
report_timestamp (const char* report_id, gchar** timestamp)
{
  const char* stamp;
  time_t time = sql_int (0, 0,
                         "SELECT date FROM reports where uuid = '%s';",
                         report_id);
  stamp = ctime (&time);
  if (stamp == NULL) return -1;
  /* Allocate a copy, clearing the newline from the end of the timestamp. */
  *timestamp = g_strndup (stamp, strlen (stamp) - 1);
  return 0;
}

/**
 * @brief Return the run status of the scan associated with a report.
 *
 * @param[in]   report  Report.
 * @param[out]  status  Scan run status.
 *
 * @return 0 on success, -1 on error.
 */
int
report_scan_run_status (report_t report, int* status)
{
  *status = sql_int (0, 0,
                     "SELECT scan_run_status FROM reports"
                     " WHERE reports.ROWID = %llu;",
                     report);
  return 0;
}

/**
 * @brief Get the number of results in the scan associated with a report.
 *
 * @param[in]   report  Report.
 * @param[out]  count   Total number of results in the scan.
 *
 * @return 0 on success, -1 on error.
 */
int
report_scan_result_count (report_t report, int* count)
{
  *count = sql_int (0, 0,
                    "SELECT count(*) FROM results, report_results"
                    " WHERE results.ROWID = report_results.result"
                    " AND report_results.report = %llu;",
                    report);
  return 0;
}

#define REPORT_COUNT(var, name) \
  *var = sql_int (0, 0, \
                  "SELECT count(*) FROM results, report_results" \
                  " WHERE results.type = '" name "'" \
                  " AND results.ROWID = report_results.result" \
                  " AND report_results.report" \
                  " = (SELECT ROWID FROM reports WHERE uuid = '%s');", \
                  report_id)

/**
 * @brief Get the message counts for a report.
 *
 * @param[in]   report_id    ID of report.
 * @param[out]  debugs       Number of debug messages.
 * @param[out]  holes        Number of hole messages.
 * @param[out]  infos        Number of info messages.
 * @param[out]  logs         Number of log messages.
 * @param[out]  warnings     Number of warning messages.
 *
 * @return 0 on success, -1 on error.
 */
int
report_counts (const char* report_id, int* debugs, int* holes, int* infos,
               int* logs, int* warnings)
{
  REPORT_COUNT (debugs,   "Debug Message");
  REPORT_COUNT (holes,    "Security Hole");
  REPORT_COUNT (infos,    "Security Note");
  REPORT_COUNT (logs,     "Log Message");
  REPORT_COUNT (warnings, "Security Warning");
  return 0;
}

#undef REPORT_COUNT

/**
 * @brief Delete a report.
 *
 * @param[in]  report  Report.
 *
 * @return 0 success, 1 report is hidden.
 */
int
delete_report (report_t report)
{
  if (sql_int (0, 0, "SELECT hidden from reports WHERE ROWID = %llu;", report))
    return 1;

  sql ("DELETE FROM report_hosts WHERE report = %llu;", report);
  sql ("DELETE FROM report_results WHERE report = %llu;", report);
  sql ("DELETE FROM reports WHERE ROWID = %llu;", report);
  return 0;
}

/**
 * @brief Set a report parameter.
 *
 * @param[in]  report     The report.
 * @param[in]  parameter  The name of the parameter (in any case): COMMENT.
 * @param[in]  value      The value of the parameter.
 *
 * @return 0 success, -2 parameter name error,
 *         -3 failed to write parameter to disk,
 *         -4 username missing from current_credentials.
 */
int
set_report_parameter (report_t report, const char* parameter, char* value)
{
  tracef ("   set_report_parameter %llu %s\n", report, parameter);
  if (strcasecmp ("COMMENT", parameter) == 0)
    {
      gchar* quote = sql_nquote (value, strlen (value));
      sql ("UPDATE reports SET comment = '%s' WHERE ROWID = %llu;",
           value,
           report);
      g_free (quote);
    }
  else
    return -2;
  return 0;
}


/* FIX More task stuff. */

/**
 * @brief Return the number of reports associated with a task.
 *
 * @param[in]  task  Task.
 *
 * @return Number of reports.
 */
unsigned int
task_report_count (task_t task)
{
  return (unsigned int) sql_int (0, 0,
                                 "SELECT count(*) FROM reports WHERE task = %llu;",
                                 task);
}

/**
 * @brief Return the number of finished reports associated with a task.
 *
 * @param[in]  task  Task.
 *
 * @return Number of reports.
 */
unsigned int
task_finished_report_count (task_t task)
{
  return (unsigned int) sql_int (0, 0,
                                 "SELECT count(*) FROM reports"
                                 " WHERE task = %llu"
                                 " AND scan_run_status = %u;",
                                 task,
                                 TASK_STATUS_DONE);
}

/**
 * @brief Set the attack state of a scan (given by a report).
 *
 * @param[in]  report  Report.
 * @param[in]  host    Host to which the state refers.
 * @param[in]  state   New state.
 */
void
set_scan_attack_state (report_t report, const char* host, const char* state)
{
  sql ("UPDATE report_hosts SET attack_state = '%s'"
       " WHERE host = '%s' AND report = %llu;",
       state,
       host,
       report);
}

/**
 * @brief Return the number of debug messages in the current report of a task.
 *
 * @param[in]  task  Task.
 *
 * @return Number of debug messages.
 */
int
task_debugs_size (task_t task)
{
  return sql_int (0, 0,
                  "SELECT count(*) FROM results"
                  " WHERE task = %llu AND results.type = 'Debug Message';",
                  task);
}

/**
 * @brief Return the number of hole messages in the current report of a task.
 *
 * @param[in]  task  Task.
 *
 * @return Number of hole messages.
 */
int
task_holes_size (task_t task)
{
  return sql_int (0, 0,
                  "SELECT count(*) FROM results"
                  " WHERE task = %llu AND results.type = 'Security Hole';",
                  task);
}

/**
 * @brief Return the number of info messages in the current report of a task.
 *
 * @param[in]  task  Task.
 *
 * @return Number of info messages.
 */
int
task_infos_size (task_t task)
{
  return sql_int (0, 0,
                  "SELECT count(*) FROM results"
                  " WHERE task = %llu AND results.type = 'Security Notes';",
                  task);
}

/**
 * @brief Return the number of log messages in the current report of a task.
 *
 * @param[in]  task  Task.
 *
 * @return Number of log messages.
 */
int
task_logs_size (task_t task)
{
  return sql_int (0, 0,
                  "SELECT count(*) FROM results"
                  " WHERE task = %llu AND results.type = 'Log Message';",
                  task);
}

/**
 * @brief Return the number of note messages in the current report of a task.
 *
 * @param[in]  task  Task.
 *
 * @return Number of note messages.
 */
int
task_warnings_size (task_t task)
{
  return sql_int (0, 0,
                  "SELECT count(*) FROM results"
                  " WHERE task = %llu AND results.type = 'Security Warning';",
                  task);
}

/**
 * @brief Dummy function.
 */
void
free_tasks ()
{
  /* Empty. */
}

/**
 * @brief Make a task.
 *
 * The char* parameters name and comment are used directly and freed
 * when the task is freed.
 *
 * @param[in]  name     The name of the task.
 * @param[in]  time     The period of the task, in seconds.
 * @param[in]  comment  A comment associated the task.
 *
 * @return A pointer to the new task or the 0 task on error (in which
 *         case the caller must free name and comment).
 */
task_t
make_task (char* name, unsigned int time, char* comment)
{
  task_t task;
  char* uuid = make_task_uuid ();
  if (uuid == NULL) return (task_t) 0;
  // TODO: Escape name and comment.
  sql ("INSERT into tasks (owner, uuid, name, hidden, time, comment)"
       " VALUES ((SELECT ROWID FROM users WHERE name = '%s'),"
       "         '%s', %s, 0, %u, %s);",
       current_credentials.username, uuid, name, time, comment);
  task = sqlite3_last_insert_rowid (task_db);
  set_task_run_status (task, TASK_STATUS_NEW);
  free (uuid);
  free (name);
  free (comment);
  return task;
}

typedef /*@only@*/ struct dirent * only_dirent_pointer;

/**
 * @brief Dummy function.
 *
 * @return 0.
 */
int
load_tasks ()
{
  return 0;
}

/**
 * @brief Dummy function.
 *
 * @return 0.
 */
int
save_tasks ()
{
  return 0;
}

/**
 * @brief Set a task parameter.
 *
 * The "value" parameter is used directly and freed either immediately or
 * when the task is freed.
 *
 * @param[in]  task       A pointer to a task.
 * @param[in]  parameter  The name of the parameter (in any case): RCFILE,
 *                        NAME or COMMENT.
 * @param[in]  value      The value of the parameter, in base64 if parameter
 *                        is "RCFILE".
 *
 * @return 0 on success, -2 if parameter name error, -3 value error (NULL).
 */
int
set_task_parameter (task_t task, const char* parameter, /*@only@*/ char* value)
{
  /** @todo Free value consistently. */

  tracef ("   set_task_parameter %u %s\n",
          task_id (task),
          parameter ? parameter : "(null)");
  if (value == NULL) return -3;
  if (parameter == NULL)
    {
      free (value);
      return -2;
    }
  if (strcasecmp ("RCFILE", parameter) == 0)
    {
      gsize rc_len;
      guchar *rc;
      gchar *quoted_rc;

      rc = g_base64_decode (value, &rc_len);

      sql ("BEGIN IMMEDIATE;");

      /* Remove all files from the task. */

      sql ("DELETE FROM task_files WHERE task = %llu;", task);

      /* Update task description (rcfile). */

      quoted_rc = sql_quote ((gchar*) rc);
      sql ("UPDATE tasks SET description = '%s' WHERE ROWID = %llu;",
           quoted_rc,
           task);
      g_free (quoted_rc);

      /* Update task config. */

      {
        config_t config;
        char *config_name, *target, *selector;
        char *quoted_config_name, *quoted_selector;

        config_name = task_config (task);
        if (config_name == NULL)
          {
            g_free (rc);
            sql ("END");
            return -1;
          }

        target = task_target (task);
        if (target == NULL)
          {
            free (config_name);
            g_free (rc);
            sql ("END");
            return -1;
          }

        selector = config_nvt_selector (config_name);
        if (selector == NULL)
          {
            free (config_name);
            free (target);
            g_free (rc);
            sql ("END");
            return -1;
          }
        quoted_selector = sql_quote (selector);
        free (selector);

        if (find_config (config_name, &config))
          {
            free (quoted_selector);
            free (config_name);
            free (target);
            g_free (rc);
            sql ("END");
            return -1;
          }
        else if (config == 0)
          {
            free (quoted_selector);
            free (config_name);
            free (target);
            g_free (rc);
            sql ("END");
            return -1;
          }
        else
          {
            char *hosts;

            /* Flush config preferences. */

            sql ("DELETE FROM config_preferences WHERE config = %llu;",
                 config);

            /* Flush selector NVTs. */

            sql ("DELETE FROM nvt_selectors WHERE name = '%s';",
                 quoted_selector);
            free (quoted_selector);

            /* Replace targets. */

            hosts = rc_preference ((gchar*) rc, "targets");
            if (hosts == NULL)
              {
                free (config_name);
                g_free (rc);
                sql ("END");
                return -1;
              }
            set_target_hosts (target, hosts);
            free (hosts);

            /* Fill config from RC. */

            quoted_config_name = sql_quote (config_name);
            free (config_name);
            /* This modifies rc. */
            if (insert_rc_into_config (config, quoted_config_name, (gchar*) rc))
              {
                g_free (rc);
                sql ("END");
                return -1;
              }
            g_free (rc);
          }

        sql ("COMMIT");
      }
    }
  else if (strcasecmp ("NAME", parameter) == 0)
    {
      gchar* quote = sql_nquote (value, strlen (value));
      sql ("UPDATE tasks SET name = '%s' WHERE ROWID = %llu;",
           value,
           task);
      g_free (quote);
    }
  else if (strcasecmp ("COMMENT", parameter) == 0)
    {
      gchar* quote = sql_nquote (value, strlen (value));
      sql ("UPDATE tasks SET comment = '%s' WHERE ROWID = %llu;",
           value,
           task);
      g_free (quote);
    }
  else
    {
      free (value);
      return -2;
    }
  return 0;
}

/**
 * @brief Request deletion of a task.
 *
 * Stop the task beforehand with \ref stop_task, if it is running.
 *
 * @param[in]  task_pointer  A pointer to the task.
 *
 * @return 0 if deleted, 1 if delete requested, 2 if task is hidden,
 *         -1 if error.
 */
int
request_delete_task (task_t* task_pointer)
{
  task_t task = *task_pointer;

  tracef ("   request delete task %u\n", task_id (task));

  if (sql_int (0, 0,
               "SELECT hidden from tasks WHERE ROWID = %llu;",
               *task_pointer))
    return 2;

  if (current_credentials.username == NULL) return -1;

  switch (stop_task (task))
    {
      case 0:    /* Stopped. */
        // FIX check error?
        delete_task (task);
        return 0;
      case 1:    /* Stop requested. */
        set_task_run_status (task, TASK_STATUS_DELETE_REQUESTED);
        return 1;
      default:   /* Programming error. */
        assert (0);
      case -1:   /* Error. */
        return -1;
        break;
    }

  return 0;
}

/**
 * @brief Complete deletion of a task.
 *
 * @param[in]  task  A pointer to the task.
 *
 * @return 0 on success, 1 if task is hidden, -1 on error.
 */
int
delete_task (task_t task)
{
  char* tsk_uuid;

  tracef ("   delete task %u\n", task_id (task));

  if (sql_int (0, 0, "SELECT hidden from tasks WHERE ROWID = %llu;", task))
    return -1;

  if (current_credentials.username == NULL) return -1;

  if (task_uuid (task, &tsk_uuid)) return -1;

  // FIX may be atomic problems here

  if (delete_reports (task)) return -1;

  sql ("DELETE FROM results WHERE task = %llu;", task);
  sql ("DELETE FROM tasks WHERE ROWID = %llu;", task);
  sql ("DELETE FROM task_files WHERE task = %llu;", task);

  return 0;
}

/**
 * @brief Append text to the comment associated with a task.
 *
 * @param[in]  task    A pointer to the task.
 * @param[in]  text    The text to append.
 * @param[in]  length  Length of the text.
 *
 * @return 0 on success, -1 if out of memory.
 */
int
append_to_task_comment (task_t task, const char* text, /*@unused@*/ int length)
{
  append_to_task_string (task, "comment", text);
  return 0;
}

/**
 * @brief Append text to the config associated with a task.
 *
 * @param[in]  task    A pointer to the task.
 * @param[in]  text    The text to append.
 * @param[in]  length  Length of the text.
 *
 * @return 0 on success, -1 if out of memory.
 */
int
append_to_task_config (task_t task, const char* text, /*@unused@*/ int length)
{
  append_to_task_string (task, "config", text);
  return 0;
}

/**
 * @brief Append text to the name associated with a task.
 *
 * @param[in]  task    A pointer to the task.
 * @param[in]  text    The text to append.
 * @param[in]  length  Length of the text.
 *
 * @return 0 on success, -1 if out of memory.
 */
int
append_to_task_name (task_t task, const char* text,
                           /*@unused@*/ int length)
{
  append_to_task_string (task, "name", text);
  return 0;
}

/**
 * @brief Append text to the target associated with a task.
 *
 * @param[in]  task    A pointer to the task.
 * @param[in]  text    The text to append.
 * @param[in]  length  Length of the text.
 *
 * @return 0 on success, -1 if out of memory.
 */
int
append_to_task_target (task_t task, const char* text, /*@unused@*/ int length)
{
  append_to_task_string (task, "target", text);
  return 0;
}

/**
 * @brief Add a line to a task description.
 *
 * @param[in]  task         A pointer to the task.
 * @param[in]  line         The line.
 * @param[in]  line_length  The length of the line.
 */
int
add_task_description_line (task_t task, const char* line,
                           /*@unused@*/ size_t line_length)
{
  append_to_task_string (task, "description", line);
  return 0;
}

/**
 * @brief Set the ports for a particular host in a scan.
 *
 * @param[in]  report   Report associated with scan.
 * @param[in]  host     Host.
 * @param[in]  current  New value for port currently being scanned.
 * @param[in]  max      New value for last port to be scanned.
 */
void
set_scan_ports (report_t report, const char* host, unsigned int current,
                unsigned int max)
{
  sql ("UPDATE report_hosts SET current_port = %i, max_port = %i"
       " WHERE host = '%s' AND report = %llu;",
       current, max, host, report);
}

/**
 * @brief Add an open port to a task.
 *
 * @param[in]  task       The task.
 * @param[in]  number     The port number.
 * @param[in]  protocol   The port protocol.
 */
void
append_task_open_port (task_t task, unsigned int number, char* protocol)
{
  // FIX
}

/**
 * @brief Find a task given an identifier.
 *
 * @param[in]   uuid  A task identifier.
 * @param[out]  task  Task return, 0 if succesfully failed to find task.
 *
 * @return FALSE on success (including if failed to find task), TRUE on error.
 */
gboolean
find_task (const char* uuid, task_t* task)
{
  switch (sql_int64 (task, 0, 0,
                     "SELECT ROWID FROM tasks WHERE uuid = '%s';",
                     uuid))
    {
      case 0:
        break;
      case 1:        /* Too few rows in result of query. */
        *task = 0;
        break;
      default:       /* Programming error. */
        assert (0);
      case -1:
        return TRUE;
        break;
    }

  return FALSE;
}

/**
 * @brief Find a report given an identifier.
 *
 * @param[in]   uuid    A report identifier.
 * @param[out]  report  Report return, 0 if succesfully failed to find task.
 *
 * @return FALSE on success (including if failed to find report), TRUE on error.
 */
gboolean
find_report (const char* uuid, report_t* report)
{
  switch (sql_int64 (report, 0, 0,
                     "SELECT ROWID FROM reports WHERE uuid = '%s';",
                     uuid))
    {
      case 0:
        break;
      case 1:        /* Too few rows in result of query. */
        *report = 0;
        break;
      default:       /* Programming error. */
        assert (0);
      case -1:
        return TRUE;
        break;
    }

  return FALSE;
}

/**
 * @brief Reset all running information for a task.
 *
 * @param[in]  task  Task.
 */
void
reset_task (task_t task)
{
  sql ("UPDATE tasks SET"
       " start_time = '',"
       " end_time = ''"
       " WHERE ROWID = %llu;",
       task);
}

/**
 * @brief Add a file to a task, or update the file on the task.
 *
 * @param[in]  task     Task.
 * @param[in]  name     Name of file.
 * @param[in]  content  Content for file in base64 encoding.
 * @param[in]  content  Length of content.
 */
void
manage_task_update_file (task_t task, const char *name,
                         const void *content)
{
  gchar* quoted_name = sql_quote (name);
  gchar* quoted_content = sql_quote (content);

  /** @todo Probably better to save ASCII instead of base64. */

  if (sql_int (0, 0,
               "SELECT count(*) FROM task_files"
               " WHERE task = %llu AND name = '%s';",
               task,
               quoted_name))
    {
      /* Update the existing file. */

      sql ("UPDATE task_files SET content = '%s'"
           " WHERE task = %llu AND name = '%s';",
           quoted_content,
           task,
           quoted_name);
    }
  else
    {
      /* Insert the file. */

      sql ("INSERT INTO task_files (task, name, content)"
           " VALUES (%llu, '%s', '%s');",
           task,
           quoted_name,
           quoted_content);
    }

  g_free (quoted_name);
  g_free (quoted_content);
}

/**
 * @brief Remove a file on a task.
 *
 * @param[in]  task     Task.
 * @param[in]  name     Name of file.
 *
 * @return 0 success, -1 error.
 */
int
manage_task_remove_file (task_t task, const char *name)
{
  if (sql_int (0, 0,
               "SELECT count(*) FROM task_files"
               " WHERE task = %llu AND name = '%s';",
               task))
    {
      gchar* quoted_name = sql_quote (name);
      sql ("DELETE FROM task_files WHERE task = %llu AND name = '%s';",
           task,
           quoted_name);
      g_free (quoted_name);
      return 0;
    }
  return -1;
}


/**
 * @brief Initialise a task file iterator.
 *
 * @param[in]  iterator  Iterator.
 * @param[in]  task      Task.
 * @param[in]  file      File name, NULL for all files.
 */
void
init_task_file_iterator (iterator_t* iterator, task_t task, const char* file)
{
  int ret;
  const char* tail;
  gchar* formatted;
  sqlite3_stmt* stmt;

  iterator->done = FALSE;
  if (file)
    {
      gchar *quoted_file = sql_nquote (file, strlen (file));
      formatted = g_strdup_printf ("SELECT *, length(content) FROM task_files"
                                   " WHERE task = %llu"
                                   " AND name = '%s';",
                                   task, quoted_file);
      g_free (quoted_file);
    }
  else
    formatted = g_strdup_printf ("SELECT *, length(content) FROM task_files"
                                 " WHERE task = %llu;",
                                 task);

  while (1)
    {
      ret = sqlite3_prepare (task_db, (char*) formatted, -1, &stmt, &tail);
      if (ret == SQLITE_BUSY) continue;
      g_free (formatted);
      iterator->stmt = stmt;
      if (ret == SQLITE_OK)
        {
          if (stmt == NULL)
            {
              g_warning ("%s: sqlite3_prepare failed with NULL stmt: %s\n",
                         __FUNCTION__,
                         sqlite3_errmsg (task_db));
              abort ();
            }
          break;
        }
      g_warning ("%s: sqlite3_prepare failed: %s\n",
                 __FUNCTION__,
                 sqlite3_errmsg (task_db));
      abort ();
    }
}

/**
 * @brief Get the name of a file from an task_file_iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Name of the file or NULL if iteration is complete.
 */
static DEF_ACCESS (task_file_iterator_name, 1);

DEF_ACCESS (task_file_iterator_content, 2);

int
task_file_iterator_length (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = (int) sqlite3_column_int (iterator->stmt, 3);
  return ret;
}


/* Targets. */

/**
 * @brief Create a target.
 *
 * @param[in]  name     Name of target.
 * @param[in]  hosts    Host list of target.
 * @param[in]  comment  Comment on target.
 *
 * @return 0 success, 1 target exists already.
 */
int
create_target (const char* name, const char* hosts, const char* comment)
{
  gchar *quoted_name = sql_nquote (name, strlen (name));
  gchar *quoted_hosts, *quoted_comment;

  sql ("BEGIN IMMEDIATE;");

  if (sql_int (0, 0, "SELECT COUNT(*) FROM targets WHERE name = '%s';",
               quoted_name))
    {
      g_free (quoted_name);
      sql ("END;");
      return 1;
    }

  quoted_hosts = sql_nquote (hosts, strlen (hosts));

  if (comment)
    {
      quoted_comment = sql_nquote (comment, strlen (comment));
      sql ("INSERT INTO targets (name, hosts, comment)"
           " VALUES ('%s', '%s', '%s');",
           quoted_name, quoted_hosts, quoted_comment);
      g_free (quoted_comment);
    }
  else
    sql ("INSERT INTO targets (name, hosts, comment)"
         " VALUES ('%s', '%s', '');",
         quoted_name, quoted_hosts);

  g_free (quoted_name);
  g_free (quoted_hosts);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Delete a target.
 *
 * @param[in]  name   Name of target.
 *
 * @return 0 success, 1 fail because a task refers to the target, -1 error.
 */
int
delete_target (const char* name)
{
  gchar* quoted_name = sql_quote (name);
  sql ("BEGIN IMMEDIATE;");
  if (sql_int (0, 0,
               "SELECT count(*) FROM tasks WHERE target = '%s'",
               quoted_name))
    {
      g_free (quoted_name);
      sql ("END;");
      return 1;
    }
  sql ("DELETE FROM targets WHERE name = '%s';", quoted_name);
  sql ("COMMIT;");
  g_free (quoted_name);
  return 0;
}

/**
 * @brief Initialise a table iterator.
 *
 * @param[in]  iterator  Iterator.
 */
static void
init_table_iterator (iterator_t* iterator, const char* table)
{
  int ret;
  const char* tail;
  gchar* formatted;
  sqlite3_stmt* stmt;

  iterator->done = FALSE;
  formatted = g_strdup_printf ("SELECT * FROM %s;", table);
  while (1)
    {
      ret = sqlite3_prepare (task_db, (char*) formatted, -1, &stmt, &tail);
      if (ret == SQLITE_BUSY) continue;
      g_free (formatted);
      iterator->stmt = stmt;
      if (ret == SQLITE_OK)
        {
          if (stmt == NULL)
            {
              g_warning ("%s: sqlite3_prepare failed with NULL stmt: %s\n",
                         __FUNCTION__,
                         sqlite3_errmsg (task_db));
              abort ();
            }
          break;
        }
      g_warning ("%s: sqlite3_prepare failed: %s\n",
                 __FUNCTION__,
                 sqlite3_errmsg (task_db));
      abort ();
    }
}

/**
 * @brief Initialise a target iterator.
 *
 * @param[in]  iterator  Iterator.
 */
void
init_target_iterator (iterator_t* iterator)
{
  init_table_iterator (iterator, "targets");
}

DEF_ACCESS (target_iterator_name, 0);
DEF_ACCESS (target_iterator_hosts, 1);

const char*
target_iterator_comment (iterator_t* iterator)
{
  const char *ret;
  if (iterator->done) return "";
  ret = (const char*) sqlite3_column_text (iterator->stmt, 2);
  return ret ? ret : "";
}

/**
 * @brief Return the hosts associated with a target.
 *
 * @param[in]  name  Target name.
 *
 * @return Comma separated list of hosts if available, else NULL.
 */
char*
target_hosts (const char *name)
{
  gchar* quoted_name = sql_nquote (name, strlen (name));
  char* hosts = sql_string (0, 0,
                            "SELECT hosts FROM targets WHERE name = '%s';",
                            quoted_name);
  g_free (quoted_name);
  return hosts;
}

/**
 * @brief Set the hosts associated with a target.
 *
 * @param[in]  name  Target name.
 * @param[in]  name  New value for hosts.
 */
static void
set_target_hosts (const char *name, const char *hosts)
{
  gchar* quoted_name = sql_quote (name);
  gchar* quoted_hosts = sql_quote (hosts);
  sql ("UPDATE targets SET hosts = '%s' WHERE name = '%s';",
       quoted_hosts, quoted_name);
  g_free (quoted_hosts);
  g_free (quoted_name);
}

/**
 * @brief Return whether a target is referenced by a task
 *
 * @param[in]  name   Name of target.
 *
 * @return 1 if in use, else 0.
 */
int
target_in_use (const char* name)
{
  gchar* quoted_name = sql_quote (name);
  int ret = sql_int (0, 0,
                     "SELECT count(*) FROM tasks WHERE target = '%s'",
                     quoted_name);
  g_free (quoted_name);
  return ret;
}


/* Configs. */

/**
 * @brief Get the value of a config preference.
 *
 * @param[in]  config   Config.
 * @param[in]  type     Preference category, NULL for general preferences.
 * @param[in]  name     Name of the preference.
 *
 * @return If there is such a preference, the value of the preference as a
 *         newly allocated string, else NULL.
 */
static char *
config_preference (config_t config, const char *type, const char *preference)
{
  if (type)
    return sql_string (0, 0,
                       "SELECT value FROM config_preferences"
                       " WHERE type = '%s' AND name = '%s';",
                       type, preference);
  else
    return sql_string (0, 0,
                       "SELECT value FROM config_preferences"
                       " WHERE type = NULL AND name = '%s';",
                       preference);
}

/**
 * @brief Exclude or include an array of NVTs in a config.
 *
 * @param[in]  config_name  Config name.
 * @param[in]  array        Array of NVTs.
 * @param[in]  array_size   Size of no.
 * @param[in]  exclude      If true exclude, else include.
 */
static void
clude (const char *config_name, GArray *array, int array_size, int exclude,
       GHashTable *families)
{
  gint index;
  const char* tail;
  int ret;
  sqlite3_stmt* stmt;
  gchar* formatted;

  if (families)
    formatted = g_strdup_printf ("INSERT INTO nvt_selectors"
                                 " (name, exclude, type, family_or_nvt, family)"
                                 " VALUES ('%s', %i, 2, $value, $family);",
                                 config_name,
                                 exclude);
  else
    formatted = g_strdup_printf ("INSERT INTO nvt_selectors"
                                 " (name, exclude, type, family_or_nvt, family)"
                                 " VALUES ('%s', %i, 2, $value, NULL);",
                                 config_name,
                                 exclude);

  tracef ("   sql: %s\n", formatted);

  /* Prepare statement. */

  while (1)
    {
      ret = sqlite3_prepare (task_db, (char*) formatted, -1, &stmt, &tail);
      if (ret == SQLITE_BUSY) continue;
      if (ret == SQLITE_OK)
        {
          if (stmt == NULL)
            {
              g_warning ("%s: sqlite3_prepare failed with NULL stmt: %s\n",
                         __FUNCTION__,
                         sqlite3_errmsg (task_db));
              abort ();
            }
          break;
        }
      g_warning ("%s: sqlite3_prepare failed: %s\n",
                 __FUNCTION__,
                 sqlite3_errmsg (task_db));
      /** @todo END if in transaction. */
      abort ();
    }

  for (index = 0; index < array_size; index++)
    {
      const char *id;
      id = g_array_index (array, char*, index);

      /* Bind the ID to the "$value" in the SQL statement. */

      while (1)
        {
          ret = sqlite3_bind_text (stmt, 1, id, -1, SQLITE_TRANSIENT);
          if (ret == SQLITE_BUSY) continue;
          if (ret == SQLITE_OK) break;
          g_warning ("%s: sqlite3_prepare failed: %s\n",
                     __FUNCTION__,
                     sqlite3_errmsg (task_db));
          abort ();
        }

      /* Bind the family name to the "$family" in the SQL statement. */

      if (families)
        {
          char *family = NULL;
          nvti_t *nvti = nvtis_lookup (nvti_cache, id);

          if (nvti)
            {
              family = nvti_family (nvti);

              if (family)
                g_hash_table_insert (families, family, (gpointer) 1);
            }

          while (1)
            {
              if (family)
                ret = sqlite3_bind_text (stmt, 2, family, -1,
                                         SQLITE_TRANSIENT);
              else
                ret = sqlite3_bind_null (stmt, 2);
              if (ret == SQLITE_BUSY) continue;
              if (ret == SQLITE_OK) break;
              g_warning ("%s: sqlite3_prepare failed: %s\n",
                         __FUNCTION__,
                         sqlite3_errmsg (task_db));
              abort ();
            }
        }

      /* Run the statement. */

      while (1)
        {
          ret = sqlite3_step (stmt);
          if (ret == SQLITE_BUSY) continue;
          if (ret == SQLITE_DONE) break;
          if (ret == SQLITE_ERROR || ret == SQLITE_MISUSE)
            {
              if (ret == SQLITE_ERROR) ret = sqlite3_reset (stmt);
              g_warning ("%s: sqlite3_step failed: %s\n",
                         __FUNCTION__,
                         sqlite3_errmsg (task_db));
              abort ();
            }
        }

      /* Reset the statement. */

      while (1)
        {
          ret = sqlite3_reset (stmt);
          if (ret == SQLITE_BUSY) continue;
          if (ret == SQLITE_DONE || ret == SQLITE_OK) break;
          if (ret == SQLITE_ERROR || ret == SQLITE_MISUSE)
            {
              g_warning ("%s: sqlite3_reset failed: %s\n",
                         __FUNCTION__,
                         sqlite3_errmsg (task_db));
              abort ();
            }
        }
    }

  sqlite3_finalize (stmt);
  g_free (formatted);
}

/**
 * @brief Copy the preferences and nvt selector from an RC file to a config.
 *
 * @param[in]  config   Config.
 * @param[in]  rc       Text of RC file.
 *
 * @return 0 success, -1 error.
 */
static int
insert_rc_into_config (config_t config, const char *config_name, char *rc)
{
  GArray *yes = g_array_sized_new (FALSE, FALSE, sizeof (rc), 20000);
  GArray *no = g_array_sized_new (FALSE, FALSE, sizeof (rc), 20000);
  int yes_size = 0, no_size = 0;
  char* seek;
  GHashTable *families;

  if (rc == NULL)
    {
      tracef ("   rc NULL\n");
      return -1;
    }

  if (config_name == NULL)
    {
      tracef ("   config_name NULL\n");
      return -1;
    }

  families = g_hash_table_new_full (g_str_hash,
                                    g_str_equal,
                                    NULL,
                                    NULL);

  while (1)
    {
      char* eq;
      seek = strchr (rc, '\n');
      eq = seek
           ? memchr (rc, '=', seek - rc)
           : strchr (rc, '=');
      if (eq)
        {
          char* rc_end = eq;
          rc_end--;
          while (*rc_end == ' ') rc_end--;
          rc_end++;
          while (*rc == ' ') rc++;
          if (rc < rc_end)
            {
              gchar *name, *value;
              name = sql_nquote (rc, rc_end - rc);
              value = sql_nquote (eq + 2, /* Daring. */
                                  (seek ? seek - (eq + 2) : strlen (eq + 2)));
              sql ("INSERT OR REPLACE INTO config_preferences"
                   " (config, type, name, value)"
                   " VALUES (%llu, NULL, '%s', '%s');",
                   config, name, value);
              g_free (name);
              g_free (value);
            }
        }
      else if (((seek ? seek - rc >= 7 + strlen ("PLUGIN_SET") : 0)
                && (strncmp (rc, "begin(", 6) == 0)
                && (strncmp (rc + 6, "PLUGIN_SET", strlen ("PLUGIN_SET")) == 0)
                && (rc[6 + strlen ("PLUGIN_SET")] == ')'))
               || ((seek ? seek - rc >= 7 + strlen ("SCANNER_SET") : 0)
                   && (strncmp (rc, "begin(", 6) == 0)
                   && (strncmp (rc + 6, "SCANNER_SET", strlen ("SCANNER_SET"))
                       == 0)
                   && (rc[6 + strlen ("SCANNER_SET")] == ')')))
        {
          /* Create an NVT selector from the plugin list. */

          rc = seek + 1;
          while ((seek = strchr (rc, '\n')))
            {
              char* eq2;

              if ((seek ? seek - rc > 5 : 1)
                  && strncmp (rc, "end(", 4) == 0)
                {
                  break;
                }

              eq2 = memchr (rc, '=', seek - rc);
              if (eq2)
                {
                  char* rc_end = eq2;
                  rc_end--;
                  while (*rc_end == ' ') rc_end--;
                  rc_end++;
                  while (*rc == ' ') rc++;
                  if (rc < rc_end)
                    {
                      int value_len = (seek ? seek - (eq2 + 2)
                                            : strlen (eq2 + 2));
                      *rc_end = '\0';

                      if ((value_len == 3)
                          && strncasecmp (eq2 + 2, "yes", 3) == 0)
                        {
                          yes_size++;
                          g_array_append_val (yes, rc);
                        }
                      else
                        {
                          no_size++;
                          g_array_append_val (no, rc);
                        }
                    }
                }

              rc = seek + 1;
            }
        }
      else if ((seek ? seek - rc > 7 : 0)
               && (strncmp (rc, "begin(", 6) == 0))
        {
          gchar *section_name;

          section_name = sql_nquote (rc + 6, seek - (rc + 6) - 1);

          /* Insert the section. */

          rc = seek + 1;
          while ((seek = strchr (rc, '\n')))
            {
              char* eq2;

              if ((seek ? seek - rc > 5 : 1)
                  && strncmp (rc, "end(", 4) == 0)
                {
                  break;
                }

              eq2 = memchr (rc, '=', seek - rc);
              if (eq2)
                {
                  char* rc_end = eq2;
                  rc_end--;
                  while (*rc_end == ' ') rc_end--;
                  rc_end++;
                  while (*rc == ' ') rc++;
                  if (rc < rc_end)
                    {
                      gchar *name, *value;
                      name = sql_nquote (rc, rc_end - rc);
                      value = sql_nquote (eq2 + 2, /* Daring. */
                                          seek - (eq2 + 2));
                      sql ("INSERT OR REPLACE INTO config_preferences"
                           " (config, type, name, value)"
                           " VALUES (%llu, '%s', '%s', '%s');",
                           config, section_name, name, value);
                      g_free (name);
                      g_free (value);
                    }
                }

              rc = seek + 1;
            }

          g_free (section_name);
        }
      if (seek == NULL) break;
      rc = seek + 1;
    }

  {
    char *auto_enable;
    auto_enable = config_preference (config, NULL, "auto_enable_new_plugins");
    if (auto_enable
        && strcmp (auto_enable, "no")
        && strcmp (auto_enable, "0"))
      {
        free (auto_enable);

        /* Include the all selector. */

        sql ("INSERT INTO nvt_selectors"
             " (name, exclude, type, family_or_nvt)"
             " VALUES ('%s', 0, 0, 0);",
             config_name);

        /* Explicitly exclude any nos. */

        clude (config_name, no, no_size, 1, NULL);

        /* Cache the growth types. */

        sql ("UPDATE configs"
             " SET families_growing = 1, nvts_growing = 1"
             " WHERE name = '%s';",
             config_name);
      }
    else
      {
        /* Explictly include the yeses and exclude the nos.  Keep the nos
         * because the config may change to auto enable new plugins. */

        clude (config_name, yes, yes_size, 0, families);
        clude (config_name, no, no_size, 1, NULL);

        /* Cache the family and NVT count and selector types. */

        sql ("UPDATE configs SET"
             " family_count = %i,"
             " nvt_count = %i, families_growing = 0, nvts_growing = 0"
             " WHERE name = '%s';",
             g_hash_table_size (families),
             yes_size,
             config_name);
        g_hash_table_destroy (families);
      }
  }

  return 0;
}

/**
 * @brief Create a config from an RC file.
 *
 * @param[in]  name     Name of config and NVT selector.
 * @param[in]  comment  Comment on config.
 * @param[in]  rc       RC file text.
 *
 * @return 0 success, 1 config exists already, -1 error.
 */
int
create_config (const char* name, const char* comment, char* rc)
{
  gchar* quoted_name = sql_nquote (name, strlen (name));
  gchar* quoted_comment;
  config_t config;

  sql ("BEGIN IMMEDIATE;");

  if (sql_int (0, 0, "SELECT COUNT(*) FROM configs WHERE name = '%s';",
               quoted_name))
    {
      tracef ("   config \"%s\" already exists\n", name);
      sql ("END;");
      g_free (quoted_name);
      return 1;
    }

  if (sql_int (0, 0, "SELECT COUNT(*) FROM nvt_selectors WHERE name = '%s' LIMIT 1;",
               quoted_name))
    {
      tracef ("   NVT selector \"%s\" already exists\n", name);
      sql ("END;");
      g_free (quoted_name);
      return -1;
    }

  if (comment)
    {
      quoted_comment = sql_nquote (comment, strlen (comment));
      sql ("INSERT INTO configs (name, nvt_selector, comment)"
           " VALUES ('%s', '%s', '%s');",
           quoted_name, quoted_name, quoted_comment);
      g_free (quoted_comment);
    }
  else
    sql ("INSERT INTO configs (name, nvt_selector, comment)"
         " VALUES ('%s', '%s', '');",
         quoted_name, quoted_name);

  /* Insert the RC into the config_preferences table. */

  config = sqlite3_last_insert_rowid (task_db);
  if (insert_rc_into_config (config, quoted_name, rc))
    {
      sql ("END;");
      g_free (quoted_name);
      return -1;
    }

  sql ("COMMIT;");
  g_free (quoted_name);
  return 0;
}

/**
 * @brief Delete a config.
 *
 * @param[in]  name   Name of config.
 *
 * @return 0 success, 1 fail because a task refers to the config, -1 error.
 */
int
delete_config (const char* name)
{
  gchar* quoted_name;

  if (strcmp (name, "Full and fast") == 0
      || strcmp (name, "Full and fast ultimate") == 0
      || strcmp (name, "Full and very deep") == 0
      || strcmp (name, "Full and very deep ultimate") == 0)
    return 1;

  quoted_name = sql_nquote (name, strlen (name));
  sql ("BEGIN IMMEDIATE;");
  if (sql_int (0, 0,
               "SELECT count(*) FROM tasks WHERE config = '%s'",
               quoted_name))
    {
      g_free (quoted_name);
      sql ("END;");
      return 1;
    }
  sql ("DELETE FROM nvt_selectors WHERE name = '%s';",
       quoted_name);
  sql ("DELETE FROM config_preferences"
       " WHERE config = (SELECT ROWID from configs WHERE name = '%s');",
       quoted_name);
  sql ("DELETE FROM configs WHERE name = '%s';", quoted_name);
  sql ("COMMIT;");
  g_free (quoted_name);
  return 0;
}

/**
 * @brief Initialise a config iterator.
 *
 * @param[in]  iterator  Iterator.
 * @param[in]  name      Name of config.  NULL for all.
 */
void
init_config_iterator (iterator_t* iterator, const char *name)
{
  int ret;
  const char* tail;
  gchar* formatted;
  sqlite3_stmt* stmt;

  iterator->done = FALSE;
  if (name)
    {
      gchar *quoted_name = sql_quote (name);
      formatted = g_strdup_printf ("SELECT * FROM configs WHERE name = '%s';",
                                   quoted_name);
      g_free (quoted_name);
    }
  else
    formatted = g_strdup ("SELECT * FROM configs;");
  while (1)
    {
      ret = sqlite3_prepare (task_db, (char*) formatted, -1, &stmt, &tail);
      if (ret == SQLITE_BUSY) continue;
      g_free (formatted);
      iterator->stmt = stmt;
      if (ret == SQLITE_OK)
        {
          if (stmt == NULL)
            {
              g_warning ("%s: sqlite3_prepare failed with NULL stmt: %s\n",
                         __FUNCTION__,
                         sqlite3_errmsg (task_db));
              abort ();
            }
          break;
        }
      g_warning ("%s: sqlite3_prepare failed: %s\n",
                 __FUNCTION__,
                 sqlite3_errmsg (task_db));
      abort ();
    }
}

DEF_ACCESS (config_iterator_name, 0);
DEF_ACCESS (config_iterator_nvt_selector, 1);

const char*
config_iterator_comment (iterator_t* iterator)
{
  const char *ret;
  if (iterator->done) return "";
  ret = (const char*) sqlite3_column_text (iterator->stmt, 2);
  return ret ? ret : "";
}

int
config_iterator_families_growing (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = (int) sqlite3_column_int (iterator->stmt, 5);
  return ret;
}

int
config_iterator_nvts_growing (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = (int) sqlite3_column_int (iterator->stmt, 6);
  return ret;
}

/**
 * @brief Return whether a config is referenced by a task
 *
 * The predefined configs are always in use.
 *
 * @param[in]  name   Name of config.
 *
 * @return 1 if in use, else 0.
 */
int
config_in_use (const char* name)
{
  gchar* quoted_name;

  if (strcmp (name, "Full and fast") == 0
      || strcmp (name, "Full and fast ultimate") == 0
      || strcmp (name, "Full and very deep") == 0
      || strcmp (name, "Full and very deep ultimate") == 0)
    return 1;

  quoted_name = sql_quote (name);
  int ret = sql_int (0, 0,
                     "SELECT count(*) FROM tasks WHERE config = '%s'",
                     quoted_name);
  g_free (quoted_name);
  return ret;
}

/**
 * @brief Initialise a preference iterator.
 *
 * @param[in]  iterator  Iterator.
 * @param[in]  section   Preference section, NULL for general preferences.
 */
static void
init_preference_iterator (iterator_t* iterator, const char* config, const char* section)
{
  int ret;
  const char* tail;
  gchar* formatted;
  sqlite3_stmt* stmt;
  gchar *quoted_config = sql_nquote (config, strlen (config));

  iterator->done = FALSE;
  if (section)
    {
      gchar *quoted_section = sql_nquote (section, strlen (section));
      formatted = g_strdup_printf ("SELECT * FROM config_preferences"
                                   " WHERE config = (SELECT ROWID FROM configs WHERE name = '%s')"
                                   " AND type = '%s';",
                                   quoted_config, quoted_section);
      g_free (quoted_section);
    }
  else
    formatted = g_strdup_printf ("SELECT * FROM config_preferences"
                                 " WHERE config = (SELECT ROWID FROM configs WHERE name = '%s')"
                                 " AND type = NULL;",
                                 quoted_config);
  g_free (quoted_config);

  while (1)
    {
      ret = sqlite3_prepare (task_db, (char*) formatted, -1, &stmt, &tail);
      if (ret == SQLITE_BUSY) continue;
      g_free (formatted);
      iterator->stmt = stmt;
      if (ret == SQLITE_OK)
        {
          if (stmt == NULL)
            {
              g_warning ("%s: sqlite3_prepare failed with NULL stmt: %s\n",
                         __FUNCTION__,
                         sqlite3_errmsg (task_db));
              abort ();
            }
          break;
        }
      g_warning ("%s: sqlite3_prepare failed: %s\n",
                 __FUNCTION__,
                 sqlite3_errmsg (task_db));
      abort ();
    }
}

static DEF_ACCESS (preference_iterator_name, 2);
static DEF_ACCESS (preference_iterator_value, 3);

/**
 * @brief Return the NVT selector associated with a config.
 *
 * @param[in]  name  Config name.
 *
 * @return Name of NVT selector if config exists and NVT selector is set, else
 *         NULL.
 */
char*
config_nvt_selector (const char *name)
{
  gchar* quoted_name = sql_nquote (name, strlen (name));
  char* selector = sql_string (0, 0,
                               "SELECT nvt_selector FROM configs WHERE name = '%s';",
                               quoted_name);
  g_free (quoted_name);
  return selector;
}

/**
 * @brief Find a config given a name.
 *
 * @param[in]   name  Config name.
 * @param[out]  task  Task return, 0 if succesfully failed to find task.
 *
 * @return FALSE on success (including if failed to find task), TRUE on error.
 */
gboolean
find_config (const char* name, task_t* task)
{
  switch (sql_int64 (task, 0, 0,
                     "SELECT ROWID FROM configs WHERE name = '%s';",
                     name))
    {
      case 0:
        break;
      case 1:        /* Too few rows in result of query. */
        *task = 0;
        break;
      default:       /* Programming error. */
        assert (0);
      case -1:
        return TRUE;
        break;
    }

  return FALSE;
}


/* NVT's. */

/**
 * @brief Return whether the NVT cache is present.
 *
 * @return 1 if a cache of NVTs is present, else 0.
 */
static int
nvt_cache_present ()
{
  return sql_int (0, 0,
                  "SELECT count(value) FROM meta"
                  " WHERE name = 'nvts_md5sum' LIMIT 1;");
}

/**
 * @brief Return number of plugins in the plugin cache.
 *
 * @return Number of plugins.
 */
int
nvts_size ()
{
  return sql_int (0, 0, "SELECT count(*) FROM nvts;");
}

/**
 * @brief Return md5sum of the plugins in the plugin cache.
 *
 * @return Number of plugins if the plugins are cached, else NULL.
 */
char*
nvts_md5sum ()
{
  return sql_string (0, 0,
                     "SELECT value FROM meta WHERE name = 'nvts_md5sum';");
}

/**
 * @brief Set the md5sum of the plugins in the plugin cache.
 */
void
set_nvts_md5sum (const char *md5sum)
{
  gchar* quoted = sql_quote (md5sum);
  sql ("INSERT OR REPLACE INTO meta (name, value)"
       " VALUES ('nvts_md5sum', '%s');",
       quoted);
  g_free (quoted);
}

/**
 * @brief Find an NVT given an identifier.
 *
 * @param[in]   oid  An NVT identifier.
 * @param[out]  nvt  NVT return, 0 if succesfully failed to find task.
 *
 * @return FALSE on success (including if failed to find NVT), TRUE on error.
 */
gboolean
find_nvt (const char* oid, nvt_t* nvt)
{
  switch (sql_int64 (nvt, 0, 0,
                     "SELECT ROWID FROM nvts WHERE oid = '%s';",
                     oid))
    {
      case 0:
        break;
      case 1:        /* Too few rows in result of query. */
        *nvt = 0;
        break;
      default:       /* Programming error. */
        assert (0);
      case -1:
        return TRUE;
        break;
    }

  return FALSE;
}

/**
 * @brief Get the family of an NVT.
 *
 * @param[in]  nvt  NVT.
 *
 * @return Family name if set, else NULL.
 */
char *
nvt_family (nvt_t nvt)
{
  return sql_string (0, 0,
                     "SELECT family FROM nvts WHERE ROWID = %llu LIMIT 1;",
                     nvt);
}

/**
 * @brief Make an nvt from an nvti.
 *
 * @param[in]  nvti  NVTI.
 *
 * @return An NVT.
 */
nvt_t
make_nvt_from_nvti (const nvti_t *nvti)
{
  gchar *quoted_version, *quoted_name, *quoted_summary, *quoted_description;
  gchar *quoted_copyright, *quoted_cve, *quoted_bid, *quoted_xref, *quoted_tag;
  gchar *quoted_sign_key_ids, *quoted_family;

  quoted_version = sql_quote (nvti_version (nvti));
  quoted_name = sql_quote (nvti_name (nvti) ? nvti_name (nvti) : "");
  quoted_summary = sql_quote (nvti_summary (nvti) ? nvti_summary (nvti) : "");
  quoted_description = sql_quote (nvti_description (nvti)
                                  ? nvti_description (nvti)
                                  : "");
  quoted_copyright = sql_quote (nvti_copyright (nvti)
                                ? nvti_copyright (nvti)
                                : "");
  quoted_cve = sql_quote (nvti_cve (nvti) ? nvti_cve (nvti) : "");
  quoted_bid = sql_quote (nvti_bid (nvti) ? nvti_bid (nvti) : "");
  quoted_xref = sql_quote (nvti_xref (nvti) ? nvti_xref (nvti) : "");
  quoted_tag = sql_quote (nvti_tag (nvti) ? nvti_tag (nvti) : "");
  quoted_sign_key_ids = sql_quote (nvti_sign_key_ids (nvti)
                                   ? nvti_sign_key_ids (nvti)
                                   : "");
  quoted_family = sql_quote (nvti_family (nvti) ? nvti_family (nvti) : "");

  sql ("INSERT into nvts (oid, version, name, summary, description, copyright,"
       " cve, bid, xref, tag, sign_key_ids, category, family)"
       " VALUES ('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s',"
       " '%s', %i, '%s');",
       nvti_oid (nvti),
       quoted_version,
       quoted_name,
       quoted_summary,
       quoted_description,
       quoted_copyright,
       quoted_cve,
       quoted_bid,
       quoted_xref,
       quoted_tag,
       quoted_sign_key_ids,
       nvti_category (nvti),
       quoted_family);

  g_free (quoted_version);
  g_free (quoted_name);
  g_free (quoted_summary);
  g_free (quoted_description);
  g_free (quoted_copyright);
  g_free (quoted_cve);
  g_free (quoted_bid);
  g_free (quoted_xref);
  g_free (quoted_tag);
  g_free (quoted_sign_key_ids);
  g_free (quoted_family);

  return sqlite3_last_insert_rowid (task_db);
}

/**
 * @brief Initialise an NVT iterator.
 *
 * @param[in]  iterator  Iterator.
 * @param[in]  nvt       NVT to iterate over, all if 0.
 */
void
init_nvt_iterator (iterator_t* iterator, nvt_t nvt)
{
  int ret;
  const char* tail;
  gchar* formatted;
  sqlite3_stmt* stmt;

  iterator->done = FALSE;
  if (nvt)
    formatted = g_strdup_printf ("SELECT * FROM nvts WHERE ROWID = %llu;",
                                 nvt);
  else
    formatted = g_strdup_printf ("SELECT * FROM nvts;");
  while (1)
    {
      ret = sqlite3_prepare (task_db, (char*) formatted, -1, &stmt, &tail);
      if (ret == SQLITE_BUSY) continue;
      g_free (formatted);
      iterator->stmt = stmt;
      if (ret == SQLITE_OK)
        {
          if (stmt == NULL)
            {
              g_warning ("%s: sqlite3_prepare failed with NULL stmt: %s\n",
                         __FUNCTION__,
                         sqlite3_errmsg (task_db));
              abort ();
            }
          break;
        }
      g_warning ("%s: sqlite3_prepare failed: %s\n",
                 __FUNCTION__,
                 sqlite3_errmsg (task_db));
      abort ();
    }
}

DEF_ACCESS (nvt_iterator_oid, 0);
DEF_ACCESS (nvt_iterator_version, 1);
DEF_ACCESS (nvt_iterator_name, 2);
DEF_ACCESS (nvt_iterator_summary, 3);
DEF_ACCESS (nvt_iterator_description, 4);
DEF_ACCESS (nvt_iterator_copyright, 5);
DEF_ACCESS (nvt_iterator_cve, 6);
DEF_ACCESS (nvt_iterator_bid, 7);
DEF_ACCESS (nvt_iterator_xref, 8);
DEF_ACCESS (nvt_iterator_tag, 9);
DEF_ACCESS (nvt_iterator_sign_key_ids, 10);
DEF_ACCESS (nvt_iterator_family, 12);

int
nvt_iterator_category (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = (int) sqlite3_column_int (iterator->stmt, 11);
  return ret;
}

/**
 * @brief Get the number of NVTs in a family.
 *
 * @param[in]  family  Family name.
 *
 * @return Number of NVTs in family.
 */
int
family_nvt_count (const char *family)
{
  gchar *quoted_family = sql_quote (family);
  int ret = sql_int (0, 0,
                     "SELECT COUNT(*) FROM nvts WHERE family = '%s';",
                     quoted_family);
  g_free (quoted_family);
  return ret;
}


/* NVT selectors. */

/* TODO: These need to handle strange cases, like when a family is
 * included then excluded, or all is included then later excluded. */

/**
 * @brief Get the family growth status of an NVT selector.
 *
 * @param[in]  selector  NVT selector.
 *
 * @return 1 growing, 0 static.
 */
int
nvt_selector_families_growing (const char* selector)
{
  /* The number of families can only grow if there is selector that includes
   * all. */
#if 0
  return sql_int (0, 0,
                  "SELECT COUNT(*) FROM nvt_selectors"
                  " WHERE name = '%s'"
                  " AND type = " G_STRINGIFY (NVT_SELECTOR_TYPE_ALL)
                  " AND exclude = 0"
                  " LIMIT 1;",
                  selector);
#else
  char *string;
  string = sql_string (0, 0,
                       "SELECT name FROM nvt_selectors"
                       " WHERE name = '%s'"
                       " AND type = " G_STRINGIFY (NVT_SELECTOR_TYPE_ALL)
                       " AND exclude = 0"
                       " LIMIT 1;",
                       selector);
  if (string == NULL) return 0;
  free (string);
  return 1;
#endif
}

/**
 * @brief Get the NVT growth status of an NVT selector.
 *
 * @param[in]  selector  NVT selector.
 *
 * @return 1 growing, 0 static.
 */
int
nvt_selector_nvts_growing (const char* selector)
{
  /* The number of NVTs can grow if there is a selector that includes all,
   * or if there is a selector that includes a family. */
#if 0
  return sql_int (0, 0,
                  "SELECT COUNT(*) FROM nvt_selectors"
                  " WHERE name = '%s'"
                  " AND exclude = 0"
                  " AND (type = " G_STRINGIFY (NVT_SELECTOR_TYPE_ALL)
                  " OR type = " G_STRINGIFY (NVT_SELECTOR_TYPE_FAMILY) ")"
                  " LIMIT 1;",
                  selector);
#else
  char *string;
  string = sql_string (0, 0,
                       "SELECT name FROM nvt_selectors"
                       " WHERE name = '%s'"
                       " AND exclude = 0"
                       " AND (type = " G_STRINGIFY (NVT_SELECTOR_TYPE_ALL)
                         " OR type = " G_STRINGIFY (NVT_SELECTOR_TYPE_FAMILY) ")"
                       " LIMIT 1;",
                       selector);
  if (string == NULL) return 0;
  free (string);
  return 1;
#endif
}

/**
 * @brief Get the NVT growth status of a config.
 *
 * @param[in]  config  Config.
 *
 * @return 1 growing, 0 static.
 */
int
config_nvts_growing (const char* config)
{
  return sql_int (0, 0,
                  "SELECT nvts_growing FROM configs"
                  " WHERE name = '%s' LIMIT 1;",
                  config);
}

/**
 * @brief Get the family growth status of a config.
 *
 * @param[in]  config  Config.
 *
 * @return 1 growing, 0 static.
 */
int
config_families_growing (const char* config)
{
  return sql_int (0, 0,
                  "SELECT families_growing FROM configs"
                  " WHERE name = '%s' LIMIT 1;",
                  config);
}

/**
 * @brief Initialise an NVT selector iterator.
 *
 * @param[in]  iterator  Iterator.
 */
static void
init_nvt_selector_iterator (iterator_t* iterator, const char* selector, int type)
{
  int ret;
  const char* tail;
  gchar* formatted;
  sqlite3_stmt* stmt;

  assert (type >= 0 && type <= 2);

  iterator->done = FALSE;
  if (selector)
    /** todo Quote selector. */
    formatted = g_strdup_printf ("SELECT * FROM nvt_selectors"
                                 " WHERE name = '%s' AND type = %i;",
                                 selector, type);
  else
    formatted = g_strdup_printf ("SELECT * FROM nvt_selectors"
                                 " WHERE type = %i;",
                                 type);
  while (1)
    {
      ret = sqlite3_prepare (task_db, (char*) formatted, -1, &stmt, &tail);
      if (ret == SQLITE_BUSY) continue;
      g_free (formatted);
      iterator->stmt = stmt;
      if (ret == SQLITE_OK)
        {
          if (stmt == NULL)
            {
              g_warning ("%s: sqlite3_prepare failed with NULL stmt: %s\n",
                         __FUNCTION__,
                         sqlite3_errmsg (task_db));
              abort ();
            }
          break;
        }
      g_warning ("%s: sqlite3_prepare failed: %s\n",
                 __FUNCTION__,
                 sqlite3_errmsg (task_db));
      abort ();
    }
}

/**
 * @brief Get whether the selector rule is an include rule.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return -1 if iteration is complete, 1 if include, else 0.
 */
static int
nvt_selector_iterator_include (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = (int) sqlite3_column_int (iterator->stmt, 1);
  return ret == 0;
}

/**
 * @brief Get the NVT or family from an NVT selector iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return NVT selector, or NULL if iteration is complete.
 */
static DEF_ACCESS (nvt_selector_iterator_nvt, 3);

/**
 * @brief Get the name from an NVT selector iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return NVT selector, or NULL if iteration is complete.
 */
static DEF_ACCESS (nvt_selector_iterator_name, 0);

/**
 * @brief Get the number of families covered by a selector.
 *
 * @param[in]  selector  NVT selector.
 * @param[in]  config    Config selector is part of.
 *
 * @return Family count if known, else -1.
 */
int
nvt_selector_family_count (const char* selector, const char* config)
{
  if (nvt_cache_present ())
    {
      if (config_families_growing (config))
        {
          if ((sql_int (0, 0,
                        "SELECT COUNT(*) FROM nvt_selectors WHERE name = '%s';",
                        selector)
               == 1)
              && (sql_int (0, 0,
                           "SELECT COUNT(*) FROM nvt_selectors"
                           " WHERE name = '%s'"
                           " AND type = " G_STRINGIFY (NVT_SELECTOR_TYPE_ALL)
                           ";",
                           selector)
                  == 1))
            return sql_int (0, 0, "SELECT COUNT(DISTINCT family) FROM nvts;");
          return -1;
        }
      else
        return sql_int (0, 0,
                        "SELECT family_count FROM configs"
                        " WHERE name = '%s'"
                        " LIMIT 1;",
                        config);
    }
  return -1;
}

/**
 * @brief Get the number of NVTs covered by a selector.
 *
 * @param[in]  selector  NVT selector.
 * @param[in]  config    Config selector is part of.
 *
 * @return NVT count if known, else -1.
 */
int
nvt_selector_nvt_count (const char* selector, const char* config)
{
  if (config_nvts_growing (config))
    {
      if (nvt_cache_present ())
        {
          if ((sql_int (0, 0,
                        "SELECT COUNT(*) FROM nvt_selectors WHERE name = '%s';",
                        selector)
               == 1)
              && (sql_int (0, 0,
                           "SELECT COUNT(*) FROM nvt_selectors"
                           " WHERE name = '%s'"
                           " AND type = " G_STRINGIFY (NVT_SELECTOR_TYPE_ALL)
                           ";",
                           selector)
                  == 1))
            return sql_int (0, 0, "SELECT COUNT(*) FROM nvts;");
        }
      return -1;
    }
  else
    return sql_int (0, 0,
                    "SELECT nvt_count FROM configs"
                    " WHERE name = '%s'"
                    " LIMIT 1;",
                    config);
}

/**
 * @brief Initialise an NVT selector family iterator.
 *
 * @param[in]  iterator  Iterator.
 * @param[in]  all       True for an "all" selector, else 0.
 * @param[in]  selector  Name of NVT selector.
 */
void
init_family_iterator (iterator_t* iterator, int all, const char* selector)
{
  int ret;
  const char* tail;
  gchar* formatted;
  sqlite3_stmt* stmt;

  iterator->done = FALSE;
  if (all)
    formatted = g_strdup_printf ("SELECT distinct family FROM nvts;");
  else
    {
      gchar *quoted_selector = sql_quote (selector);
      formatted = g_strdup_printf ("SELECT distinct family FROM nvt_selectors"
                                   " WHERE (type = 1 OR type = 2) AND name = '%s';",
                                   quoted_selector);
      g_free (quoted_selector);
    }

  while (1)
    {
      ret = sqlite3_prepare (task_db, (char*) formatted, -1, &stmt, &tail);
      if (ret == SQLITE_BUSY) continue;
      g_free (formatted);
      iterator->stmt = stmt;
      if (ret == SQLITE_OK)
        {
          if (stmt == NULL)
            {
              g_warning ("%s: sqlite3_prepare failed with NULL stmt: %s\n",
                         __FUNCTION__,
                         sqlite3_errmsg (task_db));
              abort ();
            }
          break;
        }
      g_warning ("%s: sqlite3_prepare failed: %s\n",
                 __FUNCTION__,
                 sqlite3_errmsg (task_db));
      abort ();
    }
}

DEF_ACCESS (family_iterator_name, 0);

/**
 * @brief Get whether an NVT selector family is growing.
 *
 * @param[in]  selector  NVT selector.
 * @param[in]  family    Family name.
 * @param[in]  all       True if selector is an "all" selector, else 0.
 *
 * @return 1 growing, 0 static.
 */
int
nvt_selector_family_growing (const char *selector,
                             const char *family,
                             int all)
{
  int ret;

  if (all) return 1;

  gchar *quoted_selector = sql_quote (selector);
  gchar *quoted_family = sql_quote (family);

  ret = sql_int (0, 0,
                 "SELECT COUNT(*) FROM nvt_selectors"
                 " WHERE name = '%s' AND type = 1 AND family_or_nvt = '%s'"
                 " LIMIT 1;",
                 quoted_selector, quoted_family);

  g_free (quoted_selector);
  g_free (quoted_family);

  return ret == 0 ? 0 : 1;
}

/**
 * @brief Get the number of NVTs selected in an NVT selector family.
 *
 * @param[in]  selector  NVT selector.
 * @param[in]  family    Family name.
 * @param[in]  growing   True if the family is growing, else 0.
 *
 * @return Number of NVTs selected in family.
 */
int
nvt_selector_family_selected_count (const char *selector,
                                    const char *family,
                                    int growing)
{
  int ret;

  gchar *quoted_family = sql_quote (family);

  if (growing)
    ret = sql_int (0, 0,
                   "SELECT COUNT(*) FROM nvts WHERE family = '%s';",
                   quoted_family);
  else
    {
      gchar *quoted_selector = sql_quote (selector);
      ret = sql_int (0, 0,
                     "SELECT COUNT(*) FROM nvt_selectors"
                     " WHERE name = '%s' AND type = 2 AND family = '%s';",
                     quoted_selector,
                     quoted_family);
      g_free (quoted_selector);
    }

  g_free (quoted_family);

  return ret;
}


/* NVT preferences. */

/**
 * @brief Add an NVT preference.
 *
 * @param[in]  name   The name of the preference.
 * @param[in]  value  The value of the preference.
 */
void
manage_nvt_preference_add (const char* name, const char* value)
{
  gchar* quoted_name = sql_quote (name);
  gchar* quoted_value = sql_quote (value);
  sql ("INSERT into nvt_preferences (name, value)"
       " VALUES ('%s', '%s');",
       quoted_name, quoted_value);
  g_free (quoted_name);
  g_free (quoted_value);
}

/**
 * @brief Enable the NVT preferences.
 */
void
manage_nvt_preferences_enable ()
{
  sql ("INSERT OR REPLACE INTO meta (name, value)"
       " VALUES ('nvt_preferences_enabled', 1);");
}

/**
 * @brief Initialise an NVT preference iterator.
 *
 * @param[in]  iterator  Iterator.
 */
void
init_nvt_preference_iterator (iterator_t* iterator)
{
  init_table_iterator (iterator, "nvt_preferences");
}

DEF_ACCESS (nvt_preference_iterator_name, 0);
DEF_ACCESS (nvt_preference_iterator_value, 1);


/* LSC Credentials. */

/**
 * @brief Create an LSC credential.
 *
 * @param[in]  name     Name of LSC credential.  Must be at least one character.
 * @param[in]  comment  Comment on LSC credential.
 *
 * @return 0 success, 1 LSC credential exists already, 2 name contains space,
 *         -1 error.
 */
int
create_lsc_credential (const char* name, const char* comment)
{
  gchar *quoted_name = sql_nquote (name, strlen (name));
  gchar *quoted_comment, *public_key, *private_key, *base64;
  void *rpm, *deb, *exe;
  gsize rpm_size, deb_size, exe_size;
  int i;
  GRand *rand;
#define PASSWORD_LENGTH 10
  gchar password[PASSWORD_LENGTH];
  const char *s = name;

  assert (strlen (name) > 0);

  while (*s) if (!isalnum (*s++)) return 2;

  sql ("BEGIN IMMEDIATE;");

  if (sql_int (0, 0, "SELECT COUNT(*) FROM lsc_credentials WHERE name = '%s';",
               quoted_name))
    {
      g_free (quoted_name);
      sql ("END;");
      return 1;
    }

  /* Create the keys and packages. */

  rand = g_rand_new ();
  for (i = 0; i < PASSWORD_LENGTH - 1; i++)
    password[i] = (gchar) g_rand_int_range (rand, '0', 'z');
  password[PASSWORD_LENGTH - 1] = '\0';

  if (lsc_user_all_create (name,
                           password,
                           &public_key,
                           &private_key,
                           &rpm, &rpm_size,
                           &deb, &deb_size,
                           &exe, &exe_size))
    {
      g_free (quoted_name);
      sql ("END;");
      return -1;
    }

  /* Insert the packages. */

  {
    const char* tail;
    int ret;
    sqlite3_stmt* stmt;
    gchar* formatted, *quoted_password;

    quoted_password = sql_nquote (password, strlen (password));
    if (comment)
      {
        quoted_comment = sql_nquote (comment, strlen (comment));
        formatted = g_strdup_printf ("INSERT INTO lsc_credentials"
                                     " (name, password, comment,"
                                     "  public_key, private_key, rpm, deb, exe)"
                                     " VALUES"
                                     " ('%s', '%s', '%s',"
                                     "  $public_key, $private_key,"
                                     "  $rpm, $deb, $exe);",
                                     quoted_name,
                                     quoted_password,
                                     quoted_comment);
        g_free (quoted_comment);
      }
    else
      {
        formatted = g_strdup_printf ("INSERT INTO lsc_credentials"
                                     " (name, password, comment,"
                                     "  public_key, private_key, rpm, deb, exe)"
                                     " VALUES"
                                     " ('%s', '%s', '',"
                                     "  $public_key, $private_key,"
                                     "  $rpm, $deb, $exe);",
                                     quoted_name,
                                     quoted_password);
      }

    g_free (quoted_name);
    g_free (quoted_password);

    tracef ("   sql: %s\n", formatted);

    /* Prepare statement. */

    while (1)
      {
        ret = sqlite3_prepare (task_db, (char*) formatted, -1, &stmt, &tail);
        if (ret == SQLITE_BUSY) continue;
        if (ret == SQLITE_OK)
          {
            if (stmt == NULL)
              {
                g_warning ("%s: sqlite3_prepare failed with NULL stmt: %s\n",
                           __FUNCTION__,
                           sqlite3_errmsg (task_db));
                sql ("END;");
                g_free (public_key);
                g_free (private_key);
                g_free (rpm);
                g_free (deb);
                g_free (exe);
                return -1;
              }
            break;
          }
        g_warning ("%s: sqlite3_prepare failed: %s\n",
                   __FUNCTION__,
                   sqlite3_errmsg (task_db));
        sql ("END;");
        g_free (public_key);
        g_free (private_key);
        g_free (rpm);
        g_free (deb);
        g_free (exe);
        return -1;
      }

    /* Bind the keys to the "$values" in the SQL statement. */

    while (1)
      {
        ret = sqlite3_bind_text (stmt,
                                 1,
                                 public_key,
                                 strlen (public_key),
                                 SQLITE_TRANSIENT);
        if (ret == SQLITE_BUSY) continue;
        if (ret == SQLITE_OK) break;
        g_warning ("%s: sqlite3_prepare failed: %s\n",
                   __FUNCTION__,
                   sqlite3_errmsg (task_db));
        sql ("END;");
        g_free (public_key);
        g_free (private_key);
        g_free (rpm);
        g_free (deb);
        g_free (exe);
        return -1;
      }
    g_free (public_key);

    while (1)
      {
        ret = sqlite3_bind_text (stmt,
                                 2,
                                 private_key,
                                 strlen (private_key),
                                 SQLITE_TRANSIENT);
        if (ret == SQLITE_BUSY) continue;
        if (ret == SQLITE_OK) break;
        g_warning ("%s: sqlite3_prepare failed: %s\n",
                   __FUNCTION__,
                   sqlite3_errmsg (task_db));
        sql ("END;");
        g_free (private_key);
        g_free (rpm);
        g_free (deb);
        g_free (exe);
        return -1;
      }
    g_free (private_key);

    /* Bind the packages to the "$values" in the SQL statement. */

    base64 = (rpm && strlen (rpm))
             ? g_base64_encode (rpm, rpm_size)
             : g_strdup ("");
    g_free (rpm);
    while (1)
      {
        ret = sqlite3_bind_text (stmt,
                                 3,
                                 base64,
                                 strlen (base64),
                                 SQLITE_TRANSIENT);
        if (ret == SQLITE_BUSY) continue;
        if (ret == SQLITE_OK) break;
        g_warning ("%s: sqlite3_prepare failed: %s\n",
                   __FUNCTION__,
                   sqlite3_errmsg (task_db));
        sql ("END;");
        g_free (base64);
        g_free (deb);
        g_free (exe);
        return -1;
      }
    g_free (base64);

    base64 = (deb && strlen (deb))
             ? g_base64_encode (deb, deb_size)
             : g_strdup ("");
    g_free (deb);
    while (1)
      {
        ret = sqlite3_bind_text (stmt,
                                 4,
                                 base64,
                                 strlen (base64),
                                 SQLITE_TRANSIENT);
        if (ret == SQLITE_BUSY) continue;
        if (ret == SQLITE_OK) break;
        g_warning ("%s: sqlite3_prepare failed: %s\n",
                   __FUNCTION__,
                   sqlite3_errmsg (task_db));
        sql ("END;");
        g_free (base64);
        g_free (exe);
        return -1;
      }
    g_free (base64);

    base64 = (exe && strlen (exe))
             ? g_base64_encode (exe, exe_size)
             : g_strdup ("");
    g_free (exe);
    while (1)
      {
        ret = sqlite3_bind_blob (stmt,
                                 5,
                                 base64,
                                 strlen (base64),
                                 SQLITE_TRANSIENT);
        if (ret == SQLITE_BUSY) continue;
        if (ret == SQLITE_OK) break;
        g_warning ("%s: sqlite3_prepare failed: %s\n",
                   __FUNCTION__,
                   sqlite3_errmsg (task_db));
        sql ("END;");
        g_free (base64);
        return -1;
      }
    g_free (base64);

    /* Run the statement. */

    while (1)
      {
        ret = sqlite3_step (stmt);
        if (ret == SQLITE_BUSY) continue;
        if (ret == SQLITE_DONE) break;
        if (ret == SQLITE_ERROR || ret == SQLITE_MISUSE)
          {
            if (ret == SQLITE_ERROR) ret = sqlite3_reset (stmt);
            g_warning ("%s: sqlite3_step failed: %s\n",
                       __FUNCTION__,
                       sqlite3_errmsg (task_db));
            sql ("END;");
            return -1;
          }
      }

    sqlite3_finalize (stmt);
  }

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Delete an LSC credential.
 *
 * @param[in]  name   Name of LSC credential.
 *
 * @return 0 success, 1 fail because a task refers to the LSC credential, -1 error.
 */
int
delete_lsc_credential (const char* name)
{
  gchar* quoted_name = sql_quote (name);
  sql ("BEGIN IMMEDIATE;");
#if 0
  if (sql_int (0, 0,
               "SELECT count(*) FROM tasks WHERE lsc_credential = '%s'",
               quoted_name))
    {
      g_free (quoted_name);
      sql ("END;");
      return 1;
    }
#endif
  sql ("DELETE FROM lsc_credentials WHERE name = '%s';", quoted_name);
  sql ("COMMIT;");
  g_free (quoted_name);
  return 0;
}

/**
 * @brief Initialise an LSC Credential iterator.
 *
 * @param[in]  iterator  Iterator.
 */
void
init_lsc_credential_iterator (iterator_t* iterator, const char *name)
{
  int ret;
  const char* tail;
  gchar* formatted;
  sqlite3_stmt* stmt;

  iterator->done = FALSE;
  if (name && strlen (name))
    {
      gchar* quoted_name = sql_quote (name);
      formatted = g_strdup_printf ("SELECT * FROM lsc_credentials"
                                   " WHERE name = '%s';",
                                   quoted_name);
      g_free (quoted_name);
    }
  else
    formatted = g_strdup_printf ("SELECT * FROM lsc_credentials;");
  while (1)
    {
      ret = sqlite3_prepare (task_db, (char*) formatted, -1, &stmt, &tail);
      if (ret == SQLITE_BUSY) continue;
      g_free (formatted);
      iterator->stmt = stmt;
      if (ret == SQLITE_OK)
        {
          if (stmt == NULL)
            {
              g_warning ("%s: sqlite3_prepare failed with NULL stmt: %s\n",
                         __FUNCTION__,
                         sqlite3_errmsg (task_db));
              abort ();
            }
          break;
        }
      g_warning ("%s: sqlite3_prepare failed: %s\n",
                 __FUNCTION__,
                 sqlite3_errmsg (task_db));
      abort ();
    }
}

DEF_ACCESS (lsc_credential_iterator_name, 0);
DEF_ACCESS (lsc_credential_iterator_password, 1);
DEF_ACCESS (lsc_credential_iterator_public_key, 3);
DEF_ACCESS (lsc_credential_iterator_private_key, 4);
DEF_ACCESS (lsc_credential_iterator_rpm, 5);
DEF_ACCESS (lsc_credential_iterator_deb, 6);
DEF_ACCESS (lsc_credential_iterator_exe, 7);

const char*
lsc_credential_iterator_comment (iterator_t* iterator)
{
  const char *ret;
  if (iterator->done) return "";
  ret = (const char*) sqlite3_column_text (iterator->stmt, 2);
  return ret ? ret : "";
}

#undef DEF_ACCESS
