/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Integration Configuration Management Interface in GVMD.
 *
 * This header defines the interface functions used by GVMD to handling
 * with the integration configurations
 */


#ifndef _GVM_MANAGE_INTEGRATION_CONFIGS_H
#define _GVM_MANAGE_INTEGRATION_CONFIGS_H

#include "manage_get.h"
#include "manage_resources_types.h"

#define INTEGRATION_CONFIG_SECURITY_INTELLIGENCE_UUID "1e1ee952-84b6-42cf-8431-2db3c5b5ca73"



/**
* @brief Integration Configuration Datastructures
*/
struct integration_config_data
{
    integration_config_t row_id;
    gchar* uuid;
    user_t owner;
    gchar* name;
    gchar* comment;
    gchar* service_url;
    gchar* service_cacert;
    gchar* oidc_url;
    gchar* oidc_client_id;
    gchar* oidc_client_secret;
    time_t creation_time;
    time_t modification_time;
};

typedef struct integration_config_data* integration_config_data_t;

/**
* @brief Integration configuration response types
*/
typedef enum
{
    INTEGRATION_CONFIG_SUCCESS = 0, ///< Success
    INTEGRATION_CONFIG_MISSING_SERVICE_URL = 1, ///< Failed with missing service url
    INTEGRATION_CONFIG_MISSING_OIDC_URL = 2, ///< Failed with missing oidc provider token url
    INTEGRATION_CONFIG_MISSING_OIDC_CLIENT_ID = 3, ///< Failed with missing oidc client id
    INTEGRATION_CONFIG_MISSING_OIDC_CLIENT_SECRET = 4, ///< Failed with missing oidc client secret
    INTEGRATION_CONFIG_INVALID_OWNER = 5, ///< Failed with invalid owner id
    INTEGRATION_CONFIG_INTERNAL_ERROR = 6, ///< Failed with internal error
    INTEGRATION_CONFIG_INVALID_DATA = 7, ///< Failed with the data pointer is null
    INTEGRATION_CONFIG_NOT_FOUND = 8, ///< Failed with if the config is not found
} integration_config_response_t;

integration_config_data_t
integration_config_data_new ();

void
integration_config_data_free (integration_config_data_t);

integration_config_response_t
modify_integration_config (integration_config_data_t);

int
integration_config_count (const get_data_t *);

int
integration_config_writable (integration_config_t);

int
integration_config_in_use (integration_config_t);

void
check_db_integration_configs ();

int
init_integration_config_iterator (iterator_t*, get_data_t*);

int
init_integration_config_iterator_one (iterator_t*, const gchar *);

const gchar *
integration_config_iterator_service_url (iterator_t *);

const gchar *
integration_config_iterator_service_cacert (iterator_t *);

const gchar *
integration_config_iterator_oidc_url (iterator_t *);

const gchar *
integration_config_iterator_oidc_client_id (iterator_t *);

const gchar *
integration_config_iterator_oidc_client_secret (iterator_t *);

const gchar *
integration_config_iterator_encrypted_oidc_client_secret (iterator_t *);

#endif //_GVM_MANAGE_INTEGRATION_CONFIGS_H
