/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM manage layer headers: Web Application Targets.
 *
 * General management headers of Web Application Targets.
 */

#if ENABLE_WEB_APPLICATION_SCANNING

#ifndef _GVMD_MANAGE_WEB_APPLICATION_TARGETS_H
#define _GVMD_MANAGE_WEB_APPLICATION_TARGETS_H

#include "iterator.h"
#include "manage_get.h"

/**
 * @brief Web application target creating responses
 */
typedef enum {
  CREATE_WEB_APPLICATION_TARGET_OK = 0,
  CREATE_WEB_APPLICATION_TARGET_EXISTS_ALREADY = 1,
  CREATE_WEB_APPLICATION_TARGET_INVALID_URLS = 2,
  CREATE_WEB_APPLICATION_TARGET_INVALID_CREDENTIAL = 3,
  CREATE_WEB_APPLICATION_TARGET_CREDENTIAL_NOT_FOUND = 4,
  CREATE_WEB_APPLICATION_TARGET_INVALID_CREDENTIAL_TYPE = 5,
  CREATE_WEB_APPLICATION_TARGET_INVALID_EXCLUDE_URLS = 6,
  CREATE_WEB_APPLICATION_TARGET_PERMISSION_DENIED = 99,
  CREATE_WEB_APPLICATION_TARGET_INTERNAL_ERROR = -1
} create_web_application_target_resp_t;

/**
 * @brief Web application target modifying responses
 */
typedef enum {
  MODIFY_WEB_APPLICATION_TARGET_OK = 0,
  MODIFY_WEB_APPLICATION_TARGET_NOT_FOUND = 1,
  MODIFY_WEB_APPLICATION_TARGET_INVALID_NAME = 2,
  MODIFY_WEB_APPLICATION_TARGET_EXISTS_ALREADY = 3,
  MODIFY_WEB_APPLICATION_TARGET_IN_USE = 4,
  MODIFY_WEB_APPLICATION_TARGET_CREDENTIAL_NOT_FOUND = 5,
  MODIFY_WEB_APPLICATION_TARGET_INVALID_CREDENTIAL_TYPE = 6,
  MODIFY_WEB_APPLICATION_TARGET_INVALID_URLS = 7,
  MODIFY_WEB_APPLICATION_TARGET_INVALID_EXCLUDE_URLS = 8,
  MODIFY_WEB_APPLICATION_TARGET_PERMISSION_DENIED = 99,
  MODIFY_WEB_APPLICATION_TARGET_INTERNAL_ERROR = -1
} modify_web_application_target_resp_t;

/**
 * @brief Represents a web application target and its metadata.
 */
struct web_application_target_data
{
  web_application_target_t row_id; ///> Internal database ID.
  gchar *uuid; ///> UUID of the web application target.
  gchar *name; ///> Name of the web application target.
  gchar *comment; ///> Comment on the web application target.
  gchar *urls; ///> URLs of the web application target, separated by commas.
  gchar *exclude_urls; ///> Exclude URLs of the web application target,
                       ///> separated by commas.
  credential_t credential; ///> Credential associated with the web application target,
                           ///> or 0 if none.
  gchar *credential_uuid; ///> UUID of the credential associated with the web application target,
                          ///> or NULL if none.
  user_t owner; ///> Owner of the web application target.
  time_t creation_time; ///> Creation time of the web application target.
  time_t modification_time; ///> Last modification time of the web application target.
};

typedef struct web_application_target_data *web_application_target_data_t;

web_application_target_data_t
web_application_target_data_new ();

void
web_application_target_data_free (web_application_target_data_t);

gboolean
find_web_application_target_with_permission (const char*,
                                             web_application_target_t*,
                                             const char *);

int
web_application_target_writable (web_application_target_t);

int
trash_web_application_target_writable (web_application_target_t);

int
validate_web_application_urls (const char *, gchar **);

int
valid_web_application_url (const gchar *);

create_web_application_target_resp_t
create_web_application_target (web_application_target_data_t,
                               web_application_target_t*, gchar**);

int
copy_web_application_target (const char*, const char*,
                             const char*, web_application_target_t*);

modify_web_application_target_resp_t
modify_web_application_target (web_application_target_data_t,
                               gchar**);

int
delete_web_application_target (const char*, int);

int
restore_web_application_target (const char *);

int
web_application_target_count (const get_data_t *);

int
init_web_application_target_iterator (iterator_t*, get_data_t *);

const char*
web_application_target_task_iterator_uuid (iterator_t*);

const char*
web_application_target_task_iterator_name (iterator_t*);

const char*
web_application_target_iterator_urls (iterator_t*);

const char*
web_application_target_iterator_exclude_urls (iterator_t*);

const char*
web_application_target_iterator_credential_name (iterator_t*);

credential_t
web_application_target_iterator_credential (iterator_t*);

int
web_application_target_iterator_credential_trash (iterator_t *);

char*
web_application_target_uuid (web_application_target_t);

char*
trash_web_application_target_uuid (web_application_target_t);

char*
web_application_target_name (web_application_target_t);

char*
trash_web_application_target_name (web_application_target_t);

char*
web_application_target_comment (web_application_target_t);

char*
trash_web_application_target_comment (web_application_target_t);

int
trash_web_application_target_readable (web_application_target_t);

int
web_application_target_in_use (web_application_target_t);

int
trash_web_application_target_in_use (web_application_target_t);

void
init_web_application_target_task_iterator (iterator_t*,
                                           web_application_target_t);

int
web_application_target_task_iterator_readable (iterator_t*);

gchar*
clean_urls (const char *);

#endif /* _GVMD_MANAGE_WEB_APPLICATION_TARGETS_H */

#endif /* ENABLE_WEB_APPLICATION_SCANNING */
