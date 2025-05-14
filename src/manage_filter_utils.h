/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file manage_filter_utils.h
 * @brief GVM management layer: Filter utilities headers.
 *
 * Filter parser and handling utilities headers for the GVM management layer.
 */

#ifndef GVMD_MANAGE_FILTER_UTILS_H
#define GVMD_MANAGE_FILTER_UTILS_H

#include "manage_resources.h"
#include <gvm/base/array.h>

/**
 * @brief Function type for getting a filter term by filter UUID.
 */
typedef char* (*filter_term_func)(const char*);

/**
 * @brief Keyword type.
 */
typedef enum
{
  KEYWORD_TYPE_UNKNOWN,
  KEYWORD_TYPE_INTEGER,
  KEYWORD_TYPE_DOUBLE,
  KEYWORD_TYPE_STRING
} keyword_type_t;

/**
 * @brief Comparison returns.
 */
typedef enum
{
  KEYWORD_RELATION_APPROX,
  KEYWORD_RELATION_COLUMN_ABOVE,
  KEYWORD_RELATION_COLUMN_APPROX,
  KEYWORD_RELATION_COLUMN_EQUAL,
  KEYWORD_RELATION_COLUMN_BELOW,
  KEYWORD_RELATION_COLUMN_REGEXP
} keyword_relation_t;

/**
 * @brief Keyword.
 */
struct keyword
{
  gchar *column;                 ///< The column prefix, or NULL.
  int approx;                    ///< Whether the keyword is like "~example".
  int equal;                     ///< Whether the keyword is like "=example".
  int integer_value;             ///< Integer value of the keyword.
  double double_value;           ///< Floating point value of the keyword.
  int quoted;                    ///< Whether the keyword was quoted.
  gchar *string;                 ///< The keyword string, outer quotes removed.
  keyword_type_t type;           ///< Type of keyword.
  keyword_relation_t relation;   ///< The relation.
};

/**
 * @brief Keyword type.
 */
typedef struct keyword keyword_t;


extern int table_order_if_sort_not_specified;


/**
 * @brief Default apply_overrides setting for filters.
 */
#define APPLY_OVERRIDES_DEFAULT 0

/**
 * @brief Default min quality of detection percentage for filters.
 */
#define MIN_QOD_DEFAULT 70


int
keyword_special (keyword_t *);

const char *
keyword_relation_symbol (keyword_relation_t);

void
filter_free (array_t*);

array_t *
split_filter (const gchar*);

gchar*
filter_term (const char *);

gchar*
filter_term_value (const char *, const char *);

int
filter_term_apply_overrides (const char *term);

int
filter_term_min_qod (const char *term);

void
init_manage_filter_utils_funcs (filter_term_func filter_term_f);


#endif /* GVMD_MANAGE_FILTER_UTILS_H */