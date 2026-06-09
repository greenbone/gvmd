/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM GMP layer: Web Application Targets.
 *
 * GMP handlers for web application targets.
 */

#if ENABLE_WEB_APPLICATION_SCANNING

#include "gmp_web_application_targets.h"
#include "manage_web_application_targets.h"
#include "gmp_base.h"
#include "gmp_get.h"
#include "manage.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md    gmp"

/* CREATE_WEB_APPLICATION_TARGET. */

/**
 * @brief The create_web_application_target command.
 */
typedef struct
{
  context_data_t *context;     ///< XML parser context.
} create_web_application_target_t;

/**
 * @brief Parser callback data.
 *
 * This is initially 0 because it's a global variable.
 */
static create_web_application_target_t create_web_application_target_data;

/**
 * @brief Reset command data.
 */
static void
create_web_application_target_reset ()
{
  if (create_web_application_target_data.context->first)
    {
      free_entity (create_web_application_target_data.context->first->data);
      g_slist_free_1 (create_web_application_target_data.context->first);
    }

  g_free (create_web_application_target_data.context);

  memset (&create_web_application_target_data,
          0,
          sizeof (create_web_application_target_t));
}

/**
 * @brief Start a command.
 *
 * @param[in]  gmp_parser        GMP parser.
 * @param[in]  attribute_names   All attribute names.
 * @param[in]  attribute_values  All attribute values.
 */
void
create_web_application_target_start (gmp_parser_t *gmp_parser,
                                     const gchar **attribute_names,
                                     const gchar **attribute_values)
{
  memset (&create_web_application_target_data,
          0,
          sizeof (create_web_application_target_t));

  create_web_application_target_data.context =
    g_malloc0 (sizeof (context_data_t));

  create_web_application_target_element_start
    (gmp_parser,
     "create_web_application_target",
     attribute_names,
     attribute_values);
}

/**
 * @brief Start element.
 *
 * @param[in]  gmp_parser        GMP parser.
 * @param[in]  name              Element name.
 * @param[in]  attribute_names   All attribute names.
 * @param[in]  attribute_values  All attribute values.
 */
void
create_web_application_target_element_start (gmp_parser_t *gmp_parser,
                                             const gchar *name,
                                             const gchar **attribute_names,
                                             const gchar **attribute_values)
{
  (void) gmp_parser;

  xml_handle_start_element (create_web_application_target_data.context,
                            name,
                            attribute_names,
                            attribute_values);
}

/**
 * @brief Execute command.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 */
void
create_web_application_target_run (gmp_parser_t *gmp_parser, GError **error)
{
  web_application_target_t new_web_application_target;
  web_application_target_data_t target_data;
  entity_t entity, name, copy, comment, urls, exclude_urls, credential;
  create_web_application_target_resp_t ret;
  gchar *error_message = NULL;

  entity = (entity_t) create_web_application_target_data.context->first->data;

  copy = entity_child (entity, "copy");
  if (copy)
    {
      name = entity_child (entity, "name");
      comment = entity_child (entity, "comment");

      switch (copy_web_application_target
                (name ? entity_text (name) : NULL,
                 comment ? entity_text (comment) : NULL,
                 entity_text (copy),
                 &new_web_application_target))
        {
          case 0:
            {
              char *uuid;

              uuid = web_application_target_uuid (new_web_application_target);

              SENDF_TO_CLIENT_OR_FAIL
                (XML_OK_CREATED_ID ("create_web_application_target"), uuid);

              log_event ("web_application_target",
                         "Web Application Target",
                         uuid,
                         "created");

              free (uuid);
              break;
            }

          case 1:
            SEND_TO_CLIENT_OR_FAIL
              (XML_ERROR_SYNTAX ("create_web_application_target",
                                 "Web Application Target exists already"));

            log_event_fail ("web_application_target",
                            "Web Application Target",
                            NULL,
                            "created");
            break;

          case 2:
            if (send_find_error_to_client ("create_web_application_target",
                                           "Web Application Target",
                                           entity_text (copy),
                                           gmp_parser))
              {
                error_send_to_client (error);
                return;
              }

            log_event_fail ("web_application_target",
                            "Web Application Target",
                            NULL,
                            "created");
            break;

          case 99:
            SEND_TO_CLIENT_OR_FAIL
              (XML_ERROR_SYNTAX ("create_web_application_target",
                                 "Permission denied"));

            log_event_fail ("web_application_target",
                            "Web Application Target",
                            NULL,
                            "created");
            break;

          case -1:
          default:
            SEND_TO_CLIENT_OR_FAIL
              (XML_INTERNAL_ERROR ("create_web_application_target"));

            log_event_fail ("web_application_target",
                            "Web Application Target",
                            NULL,
                            "created");
            break;
        }

      create_web_application_target_reset ();
      return;
    }

  name = entity_child (entity, "name");
  comment = entity_child (entity, "comment");
  urls = entity_child (entity, "urls");
  exclude_urls = entity_child (entity, "exclude_urls");
  credential = entity_child (entity, "credential");

  if (name == NULL)
    {
      SEND_TO_CLIENT_OR_FAIL
        (XML_ERROR_SYNTAX ("create_web_application_target",
                           "A NAME element is required"));

      create_web_application_target_reset ();
      return;
    }
  else if (strlen (name->text) == 0)
    {
      SEND_TO_CLIENT_OR_FAIL
        (XML_ERROR_SYNTAX ("create_web_application_target",
                           "The NAME element must not be empty"));

      create_web_application_target_reset ();
      return;
    }
  else if (urls == NULL || strlen (urls->text) == 0)
    {
      SEND_TO_CLIENT_OR_FAIL
        (XML_ERROR_SYNTAX ("create_web_application_target",
                           "A URLS element is required"));

      create_web_application_target_reset ();
      return;
    }

  target_data = web_application_target_data_new ();

  target_data->name = g_strdup (name->text);
  target_data->comment = comment ? g_strdup (comment->text) : NULL;
  target_data->urls = g_strdup (urls->text);
  target_data->exclude_urls =
    exclude_urls ? g_strdup (exclude_urls->text) : NULL;

  if (credential)
    target_data->credential_uuid =
      g_strdup (entity_attribute (credential, "id"));

  ret = create_web_application_target (target_data,
                                       &new_web_application_target,
                                       &error_message);

  switch (ret)
    {
      case CREATE_WEB_APPLICATION_TARGET_OK:
        {
          char *uuid;

          uuid = web_application_target_uuid (new_web_application_target);

          SENDF_TO_CLIENT_OR_FAIL
            (XML_OK_CREATED_ID ("create_web_application_target"), uuid);

          log_event ("web_application_target",
                     "Web Application Target",
                     uuid,
                     "created");

          free (uuid);
          break;
        }

      case CREATE_WEB_APPLICATION_TARGET_EXISTS_ALREADY:
        SEND_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("create_web_application_target",
                             "Web Application Target with given name exists already"));

        log_event_fail ("web_application_target",
                        "Web Application Target",
                        NULL,
                        "created");
        break;

      case CREATE_WEB_APPLICATION_TARGET_INVALID_URLS:
        SENDF_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("create_web_application_target",
                             "Error in URLs specification: %s"),
           error_message ?: "");

        log_event_fail ("web_application_target",
                        "Web Application Target",
                        NULL,
                        "created");
        break;

      case CREATE_WEB_APPLICATION_TARGET_INVALID_CREDENTIAL:
        SEND_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("create_web_application_target",
                             "Invalid credential"));

        log_event_fail ("web_application_target",
                        "Web Application Target",
                        NULL,
                        "created");
        break;

      case CREATE_WEB_APPLICATION_TARGET_CREDENTIAL_NOT_FOUND:
        SENDF_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("create_web_application_target",
                             "Could not find credential: %s"),
           target_data->credential_uuid ?: "");

        log_event_fail ("web_application_target",
                        "Web Application Target",
                        NULL,
                        "created");
        break;

      case CREATE_WEB_APPLICATION_TARGET_INVALID_CREDENTIAL_TYPE:
        SEND_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("create_web_application_target",
                             "Invalid credential type"));

        log_event_fail ("web_application_target",
                        "Web Application Target",
                        NULL,
                        "created");
        break;

      case CREATE_WEB_APPLICATION_TARGET_INVALID_EXCLUDE_URLS:
        SENDF_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("create_web_application_target",
                             "Invalid exclude URLs: %s"),
           error_message ?: "");

        log_event_fail ("web_application_target",
                        "Web Application Target",
                        NULL,
                        "created");
        break;

      case CREATE_WEB_APPLICATION_TARGET_PERMISSION_DENIED:
        SEND_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("create_web_application_target",
                             "Permission denied"));

        log_event_fail ("web_application_target",
                        "Web Application Target",
                        NULL,
                        "created");
        break;

      case CREATE_WEB_APPLICATION_TARGET_INTERNAL_ERROR:
      default:
        SEND_TO_CLIENT_OR_FAIL
          (XML_INTERNAL_ERROR ("create_web_application_target"));

        log_event_fail ("web_application_target",
                        "Web Application Target",
                        NULL,
                        "created");
        break;
    }

  web_application_target_data_free (target_data);
  g_free (error_message);

  create_web_application_target_reset ();
}

/**
 * @brief End element.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 * @param[in]  name         Element name.
 *
 * @return 0 success, 1 command finished.
 */
int
create_web_application_target_element_end (gmp_parser_t *gmp_parser,
                                           GError **error,
                                           const gchar *name)
{
  xml_handle_end_element (create_web_application_target_data.context, name);

  if (create_web_application_target_data.context->done)
    {
      create_web_application_target_run (gmp_parser, error);
      return 1;
    }

  return 0;
}

/**
 * @brief Add text to element.
 *
 * @param[in]  text      Text.
 * @param[in]  text_len  Text length.
 */
void
create_web_application_target_element_text (const gchar *text, gsize text_len)
{
  xml_handle_text (create_web_application_target_data.context, text, text_len);
}

/* MODIFY_WEB_APPLICATION_TARGET. */

/**
 * @brief Command data for the modify_web_application_target command.
 */
typedef struct
{
  context_data_t *context;     ///< XML parser context.
} modify_web_application_target_t;

/**
 * @brief Parser callback data.
 *
 * This is initially 0 because it's a global variable.
 */
static modify_web_application_target_t modify_web_application_target_data;

/**
 * @brief Reset command data.
 */
static void
modify_web_application_target_reset ()
{
  if (modify_web_application_target_data.context->first)
    {
      free_entity (modify_web_application_target_data.context->first->data);
      g_slist_free_1 (modify_web_application_target_data.context->first);
    }

  g_free (modify_web_application_target_data.context);

  memset (&modify_web_application_target_data,
          0,
          sizeof (modify_web_application_target_t));
}

/**
 * @brief Start a command.
 *
 * @param[in]  gmp_parser        GMP parser.
 * @param[in]  attribute_names   All attribute names.
 * @param[in]  attribute_values  All attribute values.
 */
void
modify_web_application_target_start (gmp_parser_t *gmp_parser,
                                     const gchar **attribute_names,
                                     const gchar **attribute_values)
{
  memset (&modify_web_application_target_data,
          0,
          sizeof (modify_web_application_target_t));

  modify_web_application_target_data.context =
    g_malloc0 (sizeof (context_data_t));

  modify_web_application_target_element_start
    (gmp_parser,
     "modify_web_application_target",
     attribute_names,
     attribute_values);
}

/**
 * @brief Start element.
 *
 * @param[in]  gmp_parser        GMP parser.
 * @param[in]  name              Element name.
 * @param[in]  attribute_names   All attribute names.
 * @param[in]  attribute_values  All attribute values.
 */
void
modify_web_application_target_element_start (gmp_parser_t *gmp_parser,
                                             const gchar *name,
                                             const gchar **attribute_names,
                                             const gchar **attribute_values)
{
  (void) gmp_parser;

  xml_handle_start_element (modify_web_application_target_data.context,
                            name,
                            attribute_names,
                            attribute_values);
}

/**
 * @brief Execute command.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 */
void
modify_web_application_target_run (gmp_parser_t *gmp_parser, GError **error)
{
  entity_t entity, name, comment, credential, urls, exclude_urls;
  const char *web_application_target_id;
  web_application_target_data_t target_data;
  modify_web_application_target_resp_t ret;
  gchar *error_message = NULL;

  entity = (entity_t) modify_web_application_target_data.context->first->data;

  web_application_target_id =
    entity_attribute (entity, "web_application_target_id");

  name = entity_child (entity, "name");
  comment = entity_child (entity, "comment");
  credential = entity_child (entity, "credential");
  urls = entity_child (entity, "urls");
  exclude_urls = entity_child (entity, "exclude_urls");

  if (web_application_target_id == NULL)
    {
      SEND_TO_CLIENT_OR_FAIL
        (XML_ERROR_SYNTAX ("modify_web_application_target",
                           "A web_application_target_id attribute is required"));

      modify_web_application_target_reset ();
      return;
    }

  target_data = web_application_target_data_new ();

  target_data->uuid = g_strdup (web_application_target_id);
  target_data->name = name ? g_strdup (name->text) : NULL;
  target_data->comment = comment ? g_strdup (comment->text) : NULL;
  target_data->urls = urls ? g_strdup (urls->text) : NULL;
  target_data->exclude_urls =
    exclude_urls ? g_strdup (exclude_urls->text) : NULL;

  if (credential)
    target_data->credential_uuid =
      g_strdup (entity_attribute (credential, "id"));

  ret = modify_web_application_target (target_data, &error_message);

  switch (ret)
    {
      case MODIFY_WEB_APPLICATION_TARGET_OK:
        SENDF_TO_CLIENT_OR_FAIL
          (XML_OK ("modify_web_application_target"));

        log_event ("web_application_target",
                   "Web Application Target",
                   web_application_target_id,
                   "modified");
        break;

      case MODIFY_WEB_APPLICATION_TARGET_NOT_FOUND:
        if (send_find_error_to_client ("modify_web_application_target",
                                       "Web Application Target",
                                       web_application_target_id,
                                       gmp_parser))
          {
            error_send_to_client (error);
            return;
          }

        log_event_fail ("web_application_target",
                        "Web Application Target",
                        web_application_target_id,
                        "modified");
        break;

      case MODIFY_WEB_APPLICATION_TARGET_INVALID_NAME:
        SENDF_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("modify_web_application_target",
                             "Web Application Target should have a non-empty name"));

        log_event_fail ("web_application_target",
                        "Web Application Target",
                        web_application_target_id,
                        "modified");
        break;

      case MODIFY_WEB_APPLICATION_TARGET_EXISTS_ALREADY:
        SENDF_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("modify_web_application_target",
                             "Web Application Target exists already"));

        log_event_fail ("web_application_target",
                        "Web Application Target",
                        web_application_target_id,
                        "modified");
        break;

      case MODIFY_WEB_APPLICATION_TARGET_IN_USE:
        SENDF_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("modify_web_application_target",
                             "Target is in use"));

        log_event_fail ("web_application_target",
                        "Web Application Target",
                        web_application_target_id,
                        "modified");
        break;

      case MODIFY_WEB_APPLICATION_TARGET_CREDENTIAL_NOT_FOUND:
        SENDF_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("modify_web_application_target",
                             "Failed to find credential"));

        log_event_fail ("web_application_target",
                        "Web Application Target",
                        web_application_target_id,
                        "modified");
        break;

      case MODIFY_WEB_APPLICATION_TARGET_INVALID_CREDENTIAL_TYPE:
        SENDF_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("modify_web_application_target",
                             "Invalid credential type"));

        log_event_fail ("web_application_target",
                        "Web Application Target",
                        web_application_target_id,
                        "modified");
        break;

      case MODIFY_WEB_APPLICATION_TARGET_INVALID_URLS:
        SENDF_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("modify_web_application_target",
                             "Error in URLs specification: %s"),
           error_message ?: "");

        log_event_fail ("web_application_target",
                        "Web Application Target",
                        web_application_target_id,
                        "modified");
        break;

      case MODIFY_WEB_APPLICATION_TARGET_INVALID_EXCLUDE_URLS:
        SENDF_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("modify_web_application_target",
                             "Invalid exclude URLs: %s"),
           error_message ?: "");

        log_event_fail ("web_application_target",
                        "Web Application Target",
                        web_application_target_id,
                        "modified");
        break;

      case MODIFY_WEB_APPLICATION_TARGET_PERMISSION_DENIED:
        SEND_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("modify_web_application_target",
                             "Permission denied"));

        log_event_fail ("web_application_target",
                        "Web Application Target",
                        web_application_target_id,
                        "modified");
        break;

      case MODIFY_WEB_APPLICATION_TARGET_INTERNAL_ERROR:
      default:
        SEND_TO_CLIENT_OR_FAIL
          (XML_INTERNAL_ERROR ("modify_web_application_target"));

        log_event_fail ("web_application_target",
                        "Web Application Target",
                        web_application_target_id,
                        "modified");
        break;
    }

  web_application_target_data_free (target_data);
  g_free (error_message);

  modify_web_application_target_reset ();
}

/**
 * @brief End element.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 * @param[in]  name         Element name.
 *
 * @return 0 success, 1 command finished.
 */
int
modify_web_application_target_element_end (gmp_parser_t *gmp_parser,
                                           GError **error,
                                           const gchar *name)
{
  xml_handle_end_element (modify_web_application_target_data.context, name);

  if (modify_web_application_target_data.context->done)
    {
      modify_web_application_target_run (gmp_parser, error);
      return 1;
    }

  return 0;
}

/**
 * @brief Add text to element.
 *
 * @param[in]  text      Text.
 * @param[in]  text_len  Text length.
 */
void
modify_web_application_target_element_text (const gchar *text, gsize text_len)
{
  xml_handle_text (modify_web_application_target_data.context, text, text_len);
}

/* GET_WEB_APPLICATION_TARGETS. */

/**
 * @brief Command data for the get_web_application_targets command.
 */
typedef struct
{
  get_data_t get;    ///< Get args.
  int tasks;         ///< Boolean. Whether to include tasks that use target.
} get_web_application_targets_t;

/**
 * @brief Parser callback data.
 *
 * This is initially 0 because it's a global variable.
 */
static get_web_application_targets_t get_web_application_targets_data;

/**
 * @brief Reset command data.
 */
static void
get_web_application_targets_reset ()
{
  get_data_reset (&get_web_application_targets_data.get);

  memset (&get_web_application_targets_data,
          0,
          sizeof (get_web_application_targets_t));
}

/**
 * @brief Handle command start element.
 *
 * @param[in]  attribute_names   All attribute names.
 * @param[in]  attribute_values  All attribute values.
 */
void
get_web_application_targets_start (const gchar **attribute_names,
                                   const gchar **attribute_values)
{
  const gchar *attribute;

  get_data_parse_attributes (&get_web_application_targets_data.get,
                             "web_application_target",
                             attribute_names,
                             attribute_values);

  if (find_attribute (attribute_names,
                      attribute_values,
                      "tasks",
                      &attribute))
    get_web_application_targets_data.tasks = strcmp (attribute, "0");
  else
    get_web_application_targets_data.tasks = 0;
}

/**
 * @brief Execute command.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 */
void
get_web_application_targets_run (gmp_parser_t *gmp_parser, GError **error)
{
  iterator_t web_application_targets;
  int count = 0, filtered, ret, first;

  ret = init_get ("get_web_application_targets",
                  &get_web_application_targets_data.get,
                  "Web Application Targets",
                  &first);

  if (ret)
    {
      switch (ret)
        {
          case 99:
            SEND_TO_CLIENT_OR_FAIL
              (XML_ERROR_SYNTAX ("get_web_application_targets",
                                 "Permission denied"));
            break;

          default:
            internal_error_send_to_client (error);
            get_web_application_targets_reset ();
            return;
        }

      get_web_application_targets_reset ();
      return;
    }

  ret = init_web_application_target_iterator
          (&web_application_targets,
           &get_web_application_targets_data.get);

  if (ret)
    {
      switch (ret)
        {
          case 1:
            if (send_find_error_to_client
                  ("get_web_application_targets",
                   "web_application_target",
                   get_web_application_targets_data.get.id,
                   gmp_parser))
              {
                error_send_to_client (error);
                return;
              }
            break;

          case 2:
            if (send_find_error_to_client
                  ("get_web_application_targets",
                   "filter",
                   get_web_application_targets_data.get.filt_id,
                   gmp_parser))
              {
                error_send_to_client (error);
                return;
              }
            break;

          case -1:
          default:
            SEND_TO_CLIENT_OR_FAIL
              (XML_INTERNAL_ERROR ("get_web_application_targets"));
            break;
        }

      get_web_application_targets_reset ();
      return;
    }

  SEND_GET_START ("web_application_target");

  while (1)
    {
      char *cred_name, *cred_uuid;
      credential_t credential;
      const char *urls, *exclude_urls;
      int credential_available, credential_in_trash = 0;

      ret = get_next (&web_application_targets,
                      &get_web_application_targets_data.get,
                      &first,
                      &count,
                      init_web_application_target_iterator);

      if (ret == 1)
        break;

      if (ret == -1)
        {
          internal_error_send_to_client (error);
          get_web_application_targets_reset ();
          return;
        }

      credential =
        web_application_target_iterator_credential (&web_application_targets);

      credential_available = 1;

      if (credential)
        {
          if (get_web_application_targets_data.get.trash
              && web_application_target_iterator_credential_trash
                   (&web_application_targets))
            {
              cred_name = trash_credential_name (credential);
              cred_uuid = trash_credential_uuid (credential);
              credential_in_trash = 1;
              credential_available = trash_credential_readable (credential);
            }
          else
            {
              credential_t found;

              cred_name = credential_name (credential);
              cred_uuid = credential_uuid (credential);

              if (find_credential_with_permission (cred_uuid,
                                                   &found,
                                                   "get_credentials"))
                {
                  g_warning ("%s: Failed to find credential", __func__);
                  abort ();
                }

              credential_available = found > 0;
            }
        }
      else
        {
          cred_name = NULL;
          cred_uuid = NULL;
        }

      SEND_GET_COMMON (web_application_target,
                       &get_web_application_targets_data.get,
                       &web_application_targets);

      urls =
        web_application_target_iterator_urls (&web_application_targets);

      exclude_urls =
        web_application_target_iterator_exclude_urls
          (&web_application_targets);

      SENDF_TO_CLIENT_OR_FAIL ("<urls>%s</urls>"
                               "<exclude_urls>%s</exclude_urls>"
                               "<credential id=\"%s\">"
                               "<name>%s</name>"
                               "<trash>%i</trash>",
                               urls ?: "",
                               exclude_urls ?: "",
                               cred_uuid ?: "",
                               cred_name ?: "",
                               credential_in_trash);

      if (credential_available == 0)
        SEND_TO_CLIENT_OR_FAIL ("<permissions/>");

      SEND_TO_CLIENT_OR_FAIL ("</credential>");

      if (get_web_application_targets_data.tasks)
        {
          iterator_t tasks;
          web_application_target_t target;

          SEND_TO_CLIENT_OR_FAIL ("<tasks>");

          target = get_iterator_resource (&web_application_targets);

          init_web_application_target_task_iterator (&tasks, target);

          while (next (&tasks))
            {
              const char *task_name;
              const char *task_uuid;

              if (web_application_target_task_iterator_readable (&tasks) == 0)
                continue;

              task_name =
                web_application_target_task_iterator_name (&tasks);

              task_uuid =
                web_application_target_task_iterator_uuid (&tasks);

              SENDF_TO_CLIENT_OR_FAIL ("<task id=\"%s\">"
                                       "<name>%s</name>",
                                       task_uuid ?: "",
                                       task_name ?: "");

              if (web_application_target_task_iterator_readable (&tasks) == 0)
                SEND_TO_CLIENT_OR_FAIL ("<permissions/>");

              SEND_TO_CLIENT_OR_FAIL ("</task>");
            }

          cleanup_iterator (&tasks);

          SEND_TO_CLIENT_OR_FAIL ("</tasks>");
        }

      SEND_TO_CLIENT_OR_FAIL ("</web_application_target>");

      count++;

      free (cred_name);
      free (cred_uuid);
    }

  cleanup_iterator (&web_application_targets);

  filtered = get_web_application_targets_data.get.id
               ? 1
               : web_application_target_count
                   (&get_web_application_targets_data.get);

  SEND_GET_END ("web_application_target",
                &get_web_application_targets_data.get,
                count,
                filtered);

  get_web_application_targets_reset ();
}

#endif /* ENABLE_WEB_APPLICATION_SCANNING */
