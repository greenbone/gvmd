/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: SQL COPY headers.
 *
 * SQL COPY headers for the GVM management layer.
 */

#ifndef _GVMD_MANAGE_SQL_COPY_H
#define _GVMD_MANAGE_SQL_COPY_H

#include <glib.h>

/**
 * @brief Buffer for COPY statements.
 */
typedef struct
{
  GString *data;      ///< The table contents to send to the database
  gchar *copy_sql;    ///< SQL COPY statement run on buffer commit
  int max_data_size;  ///< Data size above which buffer is auto-committed
} db_copy_buffer_t;

void
db_copy_buffer_init (db_copy_buffer_t *, int, const gchar *);

void
db_copy_buffer_cleanup (db_copy_buffer_t *);

int
db_copy_buffer_commit (db_copy_buffer_t *, gboolean);

int
db_copy_buffer_append_printf (db_copy_buffer_t *, const char *, ...);

#endif /* not _GVMD_MANAGE_SQL_COPY_H */
