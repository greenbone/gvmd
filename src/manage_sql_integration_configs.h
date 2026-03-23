/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GVMD_MANAGE_SQL_INTEGRATION_CONFIGS_H
#define _GVMD_MANAGE_SQL_INTEGRATION_CONFIGS_H

#include "manage_integration_configs.h"
#include "manage_sql.h"

/**
 * @brief Integration configs iterator columns.
 */
#define INTEGRATION_CONFIG_ITERATOR_COLUMNS                                 \
  {                                                                         \
    GET_ITERATOR_COLUMNS (integration_configs),                             \
      {"service_url", NULL, KEYWORD_TYPE_STRING},                           \
      {"service_cacert", NULL, KEYWORD_TYPE_STRING},                        \
      {"oidc_url", NULL, KEYWORD_TYPE_STRING},                              \
      {"oidc_client_id", NULL, KEYWORD_TYPE_STRING},                        \
      {"oidc_client_secret", NULL, KEYWORD_TYPE_STRING},                    \
    {                                                                       \
      NULL, NULL, KEYWORD_TYPE_UNKNOWN                                      \
    }                                                                       \
  }

/**
 * @brief Filter columns for integration config iterator.
 */
#define INTEGRATION_CONFIG_ITERATOR_FILTER_COLUMNS                             \
  {                                                                            \
      "id","uuid", "name", "comment", "service_url",                           \
      "service_cacert", "oidc_url", "oidc_client_id", "oidc_client_secret",    \
      "creation_time", "modification_time", "owner",                           \
      NULL                                                                     \
  }

#endif //_GVMD_MANAGE_SQL_INTEGRATION_CONFIGS_H
