/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file manage_sql_copy.c
 * @brief GVM management layer: SQL COPY.
 *
 * Helper functions for using SQL COPY statements.
 */

#include "manage_sql_copy.h"
#include "sql.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Initialize a database COPY statement buffer.
 *
 * The SQL "COPY" statement must use "FROM STDIN".
 *
 * @param[in]  copy_buffer    The buffer data structure to initialize
 * @param[in]  max_data_size  Data size above which buffer is auto-committed
 * @param[in]  copy_sql       SQL COPY statement run on buffer commit
 */
void
db_copy_buffer_init (db_copy_buffer_t *copy_buffer,
                     int max_data_size,
                     const gchar *copy_sql)
{
  copy_buffer->data = g_string_new ("");
  copy_buffer->max_data_size = max_data_size;
  copy_buffer->copy_sql = g_strdup (copy_sql);
}

/**
 * @brief Frees all allocated fields in a COPY statement buffer
 *
 * @param[in]  copy_buffer  The COPY buffer to clean up.
 */
void
db_copy_buffer_cleanup (db_copy_buffer_t *copy_buffer)
{
  if (copy_buffer->data)
    g_string_free (copy_buffer->data, TRUE);
  copy_buffer->data = NULL;

  g_free (copy_buffer->copy_sql);
  copy_buffer->copy_sql = NULL;
}

/**
 * @brief Sends the data from a COPY buffer to the DB and clears the buffer.
 *
 * @param[in]  copy_buffer  The COPY buffer to commit the data from
 * @param[in]  finalize     Whether to free all allocated fields of the buffer
 *
 * @return 0 success, -1 error.
 */
int
db_copy_buffer_commit (db_copy_buffer_t *copy_buffer, gboolean finalize)
{
  if (copy_buffer->data->len)
    {
      sql ("%s", copy_buffer->copy_sql);

      if (sql_copy_write_str (copy_buffer->data->str,
                              copy_buffer->data->len))
        {
          g_warning ("%s: failed to write to database copy buffer",
                     __func__);
          if (sql_copy_end ())
            {
              g_warning ("%s: failed to close to database copy buffer",
                         __func__);
            }
          return -1;
        }

      if (sql_copy_end ())
        {
          g_warning ("%s: failed to commit database copy buffer", __func__);
          return -1;
        }
    }

  if (finalize)
    db_copy_buffer_cleanup (copy_buffer);
  else
    g_string_truncate (copy_buffer->data, 0);

  return 0;
}

/**
 * @brief Adds data to a COPY buffer with a printf-like format string.
 *
 * @param[in]  copy_buffer  The COPY buffer to commit the data from
 * @param[in]  format       The format string for the data to add
 * @param[in]  ...          Extra arguments to insert into the format string
 *
 * @return 0 success, -1 error.
 */
int
db_copy_buffer_append_printf (db_copy_buffer_t *copy_buffer,
                              const char *format,
                              ...)
{
  va_list args;
  va_start (args, format);
  g_string_append_vprintf (copy_buffer->data, format, args);
  va_end (args);

  if (copy_buffer->data->len >= copy_buffer->max_data_size)
    return db_copy_buffer_commit (copy_buffer, FALSE);

  return 0;
}
