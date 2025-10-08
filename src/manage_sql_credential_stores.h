/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file manage_credential_stores.h
 * @brief SQL functions and iterator definitions for credential stores.
 *
 * This header provides iterator macros and function declarations used
 * for managing agent groups in the SQL layer of GVMD, including support
 * for trashcan handling and restoration.
 */

#ifndef _GVMD_MANAGE_SQL_CREDENTIAL_STORES_H
#define _GVMD_MANAGE_SQL_CREDENTIAL_STORES_H

#include "manage_credential_stores.h"
#include "manage_sql.h"

/**
 * @brief Filter columns for credential stores
 */
#define CREDENTIAL_STORE_ITERATOR_FILTER_COLUMNS \
{                                           \
  GET_ITERATOR_FILTER_COLUMNS,              \
  "active",                                 \
  "host",                                   \
  "version",                                \
  NULL                                      \
}

/**
 * @brief Iterator columns for credential stores
 */
#define CREDENTIAL_STORE_ITERATOR_COLUMNS                     \
{                                                             \
  GET_ITERATOR_COLUMNS (credential_stores),                   \
  { "version", NULL, KEYWORD_TYPE_STRING },                   \
  { "active", NULL, KEYWORD_TYPE_INTEGER },                   \
  { "host", NULL, KEYWORD_TYPE_STRING },                      \
  { NULL, NULL, KEYWORD_TYPE_UNKNOWN }                        \
}

#endif /* _GVMD_MANAGE_SQL_CREDENTIAL_STORES_H */
