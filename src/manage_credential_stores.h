/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file manage_credential_stores.h
 * @brief GVM manage layer headers: Credential stores.
 *
 * General management headers of credential stores.
 */

#ifndef _GVMD_MANAGE_CREDENTIAL_STORES_H
#define _GVMD_MANAGE_CREDENTIAL_STORES_H

#include "manage_get.h"
#include "manage_resources.h"

#define CREDENTIAL_STORE_UUID_CYBERARK "94e74cbe-0504-4ab1-b96f-0739f786f57c"

/**
 * @brief Enumeration of credential store preference data types.
 */
typedef enum {
  CREDENTIAL_STORE_PREFERENCE_TYPE_UNKNOWN = 0,
  CREDENTIAL_STORE_PREFERENCE_TYPE_STRING,
  CREDENTIAL_STORE_PREFERENCE_TYPE_INTEGER,
  CREDENTIAL_STORE_PREFERENCE_TYPE_FLOAT,
  CREDENTIAL_STORE_PREFERENCE_TYPE_BASE64,
  CREDENTIAL_STORE_PREFERENCE_TYPE_X509_CERTS,
  CREDENTIAL_STORE_PREFERENCE_TYPE_X509_PRIVKEY,
  CREDENTIAL_STORE_PREFERENCE_TYPE_PKCS12_FILE,
} credential_store_preference_type_t;

const char *
credential_store_preference_type_name (credential_store_preference_type_t type);

/**
 * @brief Structure for credential store preferences.
 */
typedef struct {
  /** Name of the preference */
  gchar *name;
  /** Whether the preference is an encrypted secret */
  gboolean secret;
  /** Data type of the preference */
  credential_store_preference_type_t type;
  /** Optional pattern for text preference values */
  gchar *pattern;
  /** Value of the preference */
  gchar *value;
  /** Default value of the preference */
  gchar *default_value;
  /** Optional name of passphrase prefence for encrypted keys */
  gchar *passphrase_name;
} credential_store_preference_data_t;

credential_store_preference_data_t *
credential_store_preference_new (const char *name,
                                 gboolean secret,
                                 credential_store_preference_type_t type,
                                 const char *pattern,
                                 const char *value,
                                 const char *default_value,
                                 const char *passphrase_name);

void
credential_store_preference_free (credential_store_preference_data_t *preference);


/**
 * @brief Structure for credential store selectors.
 */
typedef struct {
  /** Name of the selectors */
  gchar *name;
  /** Optional pattern for selector values */
  gchar *pattern;
  /** Default value of the preference */
  gchar *default_value;
  /** List of credential types supporting the selector */
  GList *credential_types;
  /** Internal rowid of the selector */
  resource_t rowid;
} credential_store_selector_data_t;

credential_store_selector_data_t *
credential_store_selector_new (const char *name,
                               const char *pattern,
                               const char *default_value,
                               resource_t rowid);

void
credential_store_selector_add_credential_type (credential_store_selector_data_t
                                                 *selector,
                                               const char *new_credential_type);

void
credential_store_selector_free (credential_store_selector_data_t *selector);


int
credential_store_count (const get_data_t *get);

int
init_credential_store_iterator (iterator_t *iterator, get_data_t *get);

const char*
credential_store_iterator_version (iterator_t *iterator);

int
credential_store_iterator_active (iterator_t *iterator);

const char*
credential_store_iterator_host (iterator_t *iterator);

const char*
credential_store_iterator_path (iterator_t *iterator);

void
init_credential_store_preference_iterator (
    iterator_t *iterator, credential_store_t credential_store);

credential_store_preference_data_t *
credential_store_preference_from_iterator (iterator_t *iterator);

const char *
credential_store_preference_iterator_name (iterator_t *iterator);

gboolean
credential_store_preference_iterator_secret (iterator_t *iterator);

credential_store_preference_type_t
credential_store_preference_iterator_type (iterator_t *iterator);

const char *
credential_store_preference_iterator_type_name (iterator_t *iterator);

const char *
credential_store_preference_iterator_pattern (iterator_t *iterator);

const char *
credential_store_preference_iterator_value (iterator_t *iterator);

const char *
credential_store_preference_iterator_decrypted_value (iterator_t *iterator);

const char *
credential_store_preference_iterator_default_value (iterator_t *iterator);

const char *
credential_store_preference_iterator_passphrase_name (iterator_t *iterator);


void
init_credential_store_selector_iterator (iterator_t *iterator,
                                         credential_store_t credential_store);

void
init_credential_store_selector_iterator_for_type (iterator_t *iterator,
                                                  credential_store_t
                                                    credential_store,
                                                  const char *credential_type);

credential_store_selector_data_t *
credential_store_selector_from_iterator (iterator_t *iterator,
                                         gboolean include_credential_types);

resource_t
credential_store_selector_iterator_resource_id (iterator_t *iterator);

const char *
credential_store_selector_iterator_name (iterator_t *iterator);

const char *
credential_store_selector_iterator_pattern (iterator_t *iterator);

const char *
credential_store_selector_iterator_default_value (iterator_t *iterator);


void
init_credential_store_selector_type_iterator (iterator_t *iterator,
                                              resource_t selector);

const char *
credential_store_selector_type_iterator_type (iterator_t *iterator);


char *
credential_store_uuid (credential_store_t group_id);

credential_store_t
credential_store_id_by_uuid (const gchar *credential_store_uuid);

int
credential_store_in_use (credential_store_t);

int
trash_credential_store_in_use (credential_store_t);

int
credential_store_writable (credential_store_t);

/**
 * @brief Enumeration of modify_credential_store return codes.
 */
typedef enum {
  MODIFY_CREDENTIAL_STORE_OK = 0,
  MODIFY_CREDENTIAL_STORE_MISSING_ID,
  MODIFY_CREDENTIAL_STORE_NOT_FOUND,
  MODIFY_CREDENTIAL_STORE_INVALID_HOST,
  MODIFY_CREDENTIAL_STORE_INVALID_PATH,
  MODIFY_CREDENTIAL_STORE_INVALID_PREFERENCE,
  MODIFY_CREDENTIAL_STORE_PERMISSION_DENIED = 99,
  MODIFY_CREDENTIAL_STORE_INTERNAL_ERROR = -1
} modify_credential_store_return_t;

modify_credential_store_return_t
modify_credential_store (const char *credential_store_id,
                         const char *active,
                         const char *host,
                         const char *path,
                         GHashTable *preference_values,
                         gchar **message);

int
create_or_update_credential_store (const char *credential_store_id,
                                   const char *name,
                                   const char *host,
                                   const char *path,
                                   const char *version,
                                   GList *preferences,
                                   GList *selectors,
                                   user_t owner);

#endif /* _GVMD_MANAGE_CREDENTIAL_STORES_H */
