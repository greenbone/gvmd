/* Copyright (C) 2016-2022 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Headers for Iterators.
 *
 * The interface here is for "external" use.  The SQL parts of the interface
 * are in sql.h.  Both are defined in sql.c.
 */

#ifndef _GVMD_ITERATOR_H
#define _GVMD_ITERATOR_H

#include "lsc_crypt.h"

#include <glib.h>

/* Types. */

/**
 * @brief A resource, like a task or target.
 */
typedef long long int resource_t;

/**
 * @brief A prepared SQL statement.
 */
typedef struct sql_stmt sql_stmt_t;

/**
 * @brief A generic SQL iterator structure.
 */
struct iterator
{
  sql_stmt_t *stmt;          ///< SQL statement.
  gboolean done;             ///< End flag.
  lsc_crypt_ctx_t crypt_ctx; ///< Encryption context.
};

/**
 * @brief A generic SQL iterator type.
 */
typedef struct iterator iterator_t;

/* Functions. */

void
cleanup_iterator (iterator_t *);

gboolean
next (iterator_t *);

#endif /* not _GVMD_ITERATOR_H */
