
/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM GMP layer: Active Directory headers.
 *
 * Header for GMP Active Directory handlers
 */
#if ENABLE_AD_INTEGRATION

#ifndef _GVMD_MANAGE_ACTIVE_DIRECTORY_H
#define _GVMD_MANAGE_ACTIVE_DIRECTORY_H

#include "gmp_base.h"
#include "glib.h"

#include <gvm/ad_connector/ad_connector.h>

typedef struct
{
  char *host;
  char *port;
  char *bind_dn;
  char *bind_password;
  char *tls_mode;
  char *base_dn;
  char *ca_certificate;
} ad_credential_data_t;

typedef enum
{
  VERIFY_AD_CREDENTIAL_OK,
  VERIFY_AD_CREDENTIAL_INVALID_INPUT,
  VERIFY_AD_CREDENTIAL_PERMISSION_DENIED,
  VERIFY_AD_CREDENTIAL_NOT_FOUND,
  VERIFY_AD_CREDENTIAL_INVALID_TYPE,
  VERIFY_AD_CREDENTIAL_INVALID_STORED_CONFIGURATION,
  VERIFY_AD_CREDENTIAL_HOST_REQUIRED,
  VERIFY_AD_CREDENTIAL_BIND_DN_REQUIRED,
  VERIFY_AD_CREDENTIAL_BIND_PASSWORD_REQUIRED,
  VERIFY_AD_CREDENTIAL_BASE_DN_REQUIRED,
  VERIFY_AD_CREDENTIAL_TLS_MODE_REQUIRED,
  VERIFY_AD_CREDENTIAL_INVALID_TLS_MODE,
  VERIFY_AD_CREDENTIAL_INVALID_PORT,
  VERIFY_AD_CREDENTIAL_INVALID_CA_CERTIFICATE,
  VERIFY_AD_CREDENTIAL_CONNECTION_FAILED,
  VERIFY_AD_CREDENTIAL_BIND_FAILED,
  VERIFY_AD_CREDENTIAL_FEATURE_DISABLED,
  VERIFY_AD_CREDENTIAL_INTERNAL_ERROR
} verify_ad_return_t;

typedef enum
{
  GET_AD_OBJECTS_OK,
  GET_AD_OBJECTS_INVALID_INPUT,
  GET_AD_OBJECTS_PERMISSION_DENIED,
  GET_AD_OBJECTS_NOT_FOUND,
  GET_AD_OBJECTS_INVALID_TYPE,
  GET_AD_OBJECTS_INVALID_STORED_CONFIGURATION,
  GET_AD_OBJECTS_CONNECTION_FAILED,
  GET_AD_OBJECTS_BIND_FAILED,
  GET_AD_OBJECTS_SEARCH_FAILED,
  GET_AD_OBJECTS_RESULT_FAILED,
  GET_AD_OBJECTS_FEATURE_DISABLED,
  GET_AD_OBJECTS_INTERNAL_ERROR
} get_ad_objects_return_t;

gboolean
valid_ad_ca_certificate (const char *);

gboolean
valid_ad_port (const char *);

verify_ad_return_t
verify_active_directory_credential (const gchar *,
                                    const ad_credential_data_t *);

void
ad_credential_data_reset (ad_credential_data_t *);

/**
 * @brief Parameters for a synchronous Active Directory object search.
 */
typedef struct
{
  const gchar *credential_id;
  const gchar *base_dn;
  const gchar *group_dn;
  ad_connector_search_scope_t scope;
  ad_object_type_t object_types;
  guint max_results;
  gboolean include_disabled_computers;
  gboolean targets;
  gboolean tasks;
  gboolean details;
} get_ad_objects_params_t;

#define GET_AD_OBJECTS_MAX_RESULTS 1000

typedef struct
{
  gchar *uuid;
  gchar *name;
} ad_resource_ref_t;

typedef struct
{
  ad_resource_ref_t resource;
  ad_resource_ref_t *config;
} ad_task_match_t;

typedef struct
{
  ad_resource_ref_t resource;
  GPtrArray *tasks;
} ad_target_match_t;

/**
 * @brief Owned directory object.
 */
typedef struct
{
  ad_object_type_t type;
  gchar *name;
  gchar *distinguished_name;
  gchar *parent_dn;
  GHashTable *attributes;
  GPtrArray *target_matches; /**< NULL when matching was not requested;
                                 empty when no readable targets matched. */
} ad_directory_object_t;

typedef struct
{
  guint ou;
  guint group;
  guint computer_total;
  guint computer_disabled; /**< Disabled computers among the collected objects. */
} ad_object_counts_t;

/**
 * @brief Owned directory search results after LDAP filtering.
 *        Free with get_ad_objects_result_reset(), including on failure.
 */
typedef struct
{
  GPtrArray *objects;
  gboolean truncated;
  ad_object_counts_t counts;
} get_ad_objects_result_t;

const GPtrArray *
ad_object_attribute_values (const ad_directory_object_t *object,
                            const gchar *name);

const gchar *
ad_object_attribute_value (const ad_directory_object_t *object,
                           const gchar *name);

void
ad_directory_object_free (ad_directory_object_t *object);

void
get_ad_objects_result_reset (get_ad_objects_result_t *result);

get_ad_objects_return_t
get_active_directory_objects (const get_ad_objects_params_t *params,
                              get_ad_objects_result_t *result);


#endif /* _GVMD_MANAGE_ACTIVE_DIRECTORY_H */

#endif /* ENABLE_AD_INTEGRATION */
