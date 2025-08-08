/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM GMP layer: OCI Image Targets
 *
 * GMP handlers for OCI Image Targets
 */

#include "gmp_oci_image_targets.h"
#include "manage_oci_image_targets.h"
#include "gmp_base.h"
#include "gmp_get.h"
#include "manage.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md gmp"

/* CREATE_OCI_IMAGE_TARGET. */

/**
 * @brief The create_oci_image_target command.
 */
typedef struct
{
  context_data_t *context;     ///< XML parser context.
} create_oci_image_target_t;

/**
 * @brief Parser callback data.
 *
 * This is initially 0 because it's a global variable.
 */
static create_oci_image_target_t create_oci_image_target_data;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
create_oci_image_target_reset ()
{
  if (create_oci_image_target_data.context->first)
    {
      free_entity (create_oci_image_target_data.context->first->data);
      g_slist_free_1 (create_oci_image_target_data.context->first);
    }
  g_free (create_oci_image_target_data.context);
  memset (&create_oci_image_target_data, 0, sizeof (create_oci_image_target_t));
}

/**
 * @brief Start a command.
 *
 * @param[in]  gmp_parser        GMP parser.
 * @param[in]  attribute_names   All attribute names.
 * @param[in]  attribute_values  All attribute values.
 */
void
create_oci_image_target_start (gmp_parser_t *gmp_parser,
                               const gchar **attribute_names,
                               const gchar **attribute_values)
{
  memset (&create_oci_image_target_data, 0, sizeof (create_oci_image_target_t));
  create_oci_image_target_data.context = g_malloc0 (sizeof (context_data_t));
  create_oci_image_target_element_start (gmp_parser,
                                         "create_oci_image_target",
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
create_oci_image_target_element_start (gmp_parser_t *gmp_parser,
                                       const gchar *name,
                                       const gchar **attribute_names,
                                       const gchar **attribute_values)
{
  xml_handle_start_element (create_oci_image_target_data.context,
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
create_oci_image_target_run (gmp_parser_t *gmp_parser, GError **error)
{
  oci_image_target_t new_oci_image_target;
  entity_t entity, name, copy, comment, image_references, credential;
  const char *credential_id;
  int ret;
  gchar *error_message = NULL;

  entity = (entity_t) create_oci_image_target_data.context->first->data;

  copy = entity_child (entity, "copy");
  if (copy)
    {
      /* Copy from an existing image target. */

      name = entity_child (entity, "name");
      comment = entity_child (entity, "comment");

      switch (copy_oci_image_target (name ? entity_text (name) : NULL,
                                     comment ? entity_text (comment) : NULL,
                                     entity_text (copy),
                                     &new_oci_image_target))
        {
          case 0:
            {
              char * uuid = oci_image_target_uuid (new_oci_image_target);
              SENDF_TO_CLIENT_OR_FAIL (XML_OK_CREATED_ID
                                       ("create_oci_image_target"),
                                       uuid);
              log_event ("oci_image_target", "OCI Image Target",
                         uuid, "created");
              free (uuid);
              break;
            }
          case 1:
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_oci_image_target",
                                "OCI Image Target exists already"));
            log_event_fail ("oci_image_target", "OCI Image Target",
                            NULL, "created");
            break;
          case 2:
            if (send_find_error_to_client ("create_oci_image_target",
                                           "OCI Image Target",
                                           entity_text (copy),
                                           gmp_parser))
              {
                error_send_to_client (error);
                return;
              }
            log_event_fail ("oci_image_target", "OCI Image Target",
                            NULL, "created");
            break;
          case 99:
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_oci_image_target",
                                "Permission denied"));
            log_event_fail ("oci_image_target", "OCI Image Target",
                            NULL, "created");
            break;
          case -1:
          default:
            SEND_TO_CLIENT_OR_FAIL
             (XML_INTERNAL_ERROR ("create_oci_image_target"));
            log_event_fail ("image_target", "OCI Image Target",
                            NULL, "created");
            break;
        }

      create_oci_image_target_reset ();
      return;
    }

  /* Create new oci image target */

  name = entity_child (entity, "name");
  comment = entity_child (entity, "comment");
  image_references = entity_child (entity, "image_references");
  credential = entity_child (entity, "credential");

  credential_id = NULL;
  if (credential)
    credential_id = entity_attribute (credential, "id");

  if (name == NULL)
    {
      SEND_TO_CLIENT_OR_FAIL
        (XML_ERROR_SYNTAX ("create_oci_image_target",
                           "A NAME element is required"));
      create_oci_image_target_reset ();
      return;
    }
  else if (strlen (name->text) == 0)
    {
      SEND_TO_CLIENT_OR_FAIL
        (XML_ERROR_SYNTAX ("create_oci_image_target",
                           "The NAME element must not be empty"));
      create_oci_image_target_reset ();
      return;
    }
  else if (image_references == NULL)
    {
      SEND_TO_CLIENT_OR_FAIL
        (XML_ERROR_SYNTAX ("create_oci_image_target",
                           "An image_references element is required"));
      create_oci_image_target_reset ();
      return;
    }

  ret = create_oci_image_target (name->text,
                                 comment ? comment->text : NULL,
                                 image_references->text,
                                 credential_id,
                                 &new_oci_image_target,
                                 &error_message);

  switch (ret)
    {
      case 0:
        {
          char *uuid = oci_image_target_uuid (new_oci_image_target);
          SENDF_TO_CLIENT_OR_FAIL
            (XML_OK_CREATED_ID ("create_oci_image_target"), uuid);
          log_event ("oci_image_target", "OCI Image Target", uuid, "created");
          free (uuid);
          break;
        }
      case 1:
        SEND_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("create_oci_image_target",
                             "OCI image target with given name exists already"));
        log_event_fail ("oci_image_target", "OCI Image Target",
                        NULL, "created");
        break;
      case 2:
        SENDF_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("create_oci_image_target",
                             "Error in image references specification: %s"),
                              error_message);
        log_event_fail ("oci_image_target", "OCI Image Target",
                        NULL, "created");
        break;
      case 3:
        SEND_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("create_oci_image_target",
                             "Invalid credential"));
        log_event_fail ("oci_image_target", "OCI Image Target",
                        NULL, "created");
        break;
      case 4:
        SENDF_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("create_oci_image_target",
                             "Could not find credential: %s"),
                             credential_id);
        log_event_fail ("oci_image_target", "OCI Image Target",
                        NULL, "created");
        break;
      case 5:
        SEND_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("create_oci_image_target",
                             "Invalid credential type"));
        log_event_fail ("oci_image_target", "OCI Image Target",
                        NULL, "created");
        break;
      case 99:
        SEND_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("create_oci_image_target",
                              "Permission config"));
        log_event_fail ("oci_image_target", "OCI Image Target",
                        NULL, "created");
        break;
      default:
        SEND_TO_CLIENT_OR_FAIL
          (XML_INTERNAL_ERROR ("create_oci_image_target"));
        log_event_fail ("oci_image_target", "OCI Image Target",
                        NULL, "created");
        break;
    }

  g_free (error_message);
  create_oci_image_target_reset ();
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
create_oci_image_target_element_end (gmp_parser_t *gmp_parser, GError **error,
                                     const gchar *name)
{
  xml_handle_end_element (create_oci_image_target_data.context, name);
  if (create_oci_image_target_data.context->done)
    {
      create_oci_image_target_run (gmp_parser, error);
      return 1;
    }
  return 0;
}

/**
 * @brief Add text to element.
 *
 * @param[in]  text         Text.
 * @param[in]  text_len     Text length.
 */
void
create_oci_image_target_element_text (const gchar *text, gsize text_len)
{
  xml_handle_text (create_oci_image_target_data.context, text, text_len);
}

/* MODIFY_OCI_IMAGE_TARGET. */

/**
 * @brief Command data for the modify_container_image_target command.
 */
typedef struct
{
  context_data_t *context;     ///< XML parser context.
} modify_oci_image_target_t;

/**
 * @brief Parser callback data.
 *
 * This is initially 0 because it's a global variable.
 */
static modify_oci_image_target_t modify_oci_image_target_data;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
modify_oci_image_target_reset ()
{
  if (modify_oci_image_target_data.context->first)
    {
      free_entity (modify_oci_image_target_data.context->first->data);
      g_slist_free_1 (modify_oci_image_target_data.context->first);
    }
  g_free (modify_oci_image_target_data.context);
  memset (&modify_oci_image_target_data, 0, sizeof (modify_oci_image_target_t));
}

/**
 * @brief Start a command.
 *
 * @param[in]  gmp_parser        GMP parser.
 * @param[in]  attribute_names   All attribute names.
 * @param[in]  attribute_values  All attribute values.
 */
void
modify_oci_image_target_start (gmp_parser_t *gmp_parser,
                               const gchar **attribute_names,
                               const gchar **attribute_values)
{
  memset (&modify_oci_image_target_data, 0, sizeof (modify_oci_image_target_t));
  modify_oci_image_target_data.context = g_malloc0 (sizeof (context_data_t));
  modify_oci_image_target_element_start (gmp_parser, "modify_oci_image_target",
                                         attribute_names, attribute_values);
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
modify_oci_image_target_element_start (gmp_parser_t *gmp_parser,
                                       const gchar *name,
                                       const gchar **attribute_names,
                                       const gchar **attribute_values)
{
  xml_handle_start_element (modify_oci_image_target_data.context, name,
                            attribute_names, attribute_values);
}

/**
 * @brief Execute command.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 */
void
modify_oci_image_target_run (gmp_parser_t *gmp_parser, GError **error)
{
  entity_t entity, name, comment, credential, image_references;
  const char *oci_image_target_id, *credential_id;
  int ret;
  gchar *error_message = NULL;

  entity = (entity_t) modify_oci_image_target_data.context->first->data;

  oci_image_target_id = entity_attribute(entity, "oci_image_target_id");
  name = entity_child (entity, "name");
  comment = entity_child (entity, "comment");
  credential = entity_child (entity, "credential");
  image_references = entity_child (entity, "image_references");

  if (oci_image_target_id == NULL)
    {
      SEND_TO_CLIENT_OR_FAIL
        (XML_ERROR_SYNTAX ("modify_oci_image_target",
                           "An oci_image_target_id attribute is required"));
      modify_oci_image_target_reset ();
      return;
    }

  credential_id = NULL;
  if (credential)
    credential_id = entity_attribute (credential, "id");

  ret = modify_oci_image_target (oci_image_target_id,
                                 name ? name->text : NULL,
                                 comment ? comment->text : NULL,
                                 credential_id ?: NULL,
                                 image_references
                                 ? image_references->text 
                                 : NULL,
                                 &error_message);

  switch (ret)
    {
      case 0:
        SENDF_TO_CLIENT_OR_FAIL
          (XML_OK ("modify_oci_image_target"));
        log_event ("oci_image_target", "OCI Image Target",
                    oci_image_target_id, "modified");
        break;
      case 1:
        if (send_find_error_to_client ("modify_oci_image_target",
                                       "OCI Image Target",
                                       oci_image_target_id,
                                       gmp_parser))
          {
            error_send_to_client (error);
            return;
          }
        log_event_fail ("oci_image_target", "OCI Image Target",
                        oci_image_target_id, "modified");
        break;
      case 2:
        SENDF_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("modify_oci_image_target",
                             "OCI Image Target should have a non-empty name"));
        log_event_fail ("oci_image_target", "OCI Image Target",
                        NULL, "modified");
        break;
      case 3:
        SENDF_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("modify_oci_image_target",
                             "OCI Image Target exists already"));
        log_event_fail ("oci_image_target", "OCI Image Target",
                        NULL, "modified");
        break;
      case 4:
        SENDF_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("modify_oci_image_target",
                             "Target is in use"));
        log_event_fail ("oci_image_target", "OCI Image Target",
                        NULL, "modified");
        break;
      case 5:
        SENDF_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("modify_oci_image_target",
                             "Failed to find credential"));
        log_event_fail ("oci_image_target", "OCI Image Target",
                        NULL, "modified");
        break;
      case 6:
        SENDF_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("modify_oci_image_target",
                             "Invalid credential type"));
        log_event_fail ("oci_image_target", "OCI Image Target",
                        NULL, "modified");
        break;
      case 7:
        SENDF_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("modify_oci_image_target",
                             "Error in image references specification: %s"),
                             error_message);
        log_event_fail ("oci_image_target", "OCI Image Target",
                        NULL, "modified");
        break;
      case 99:
        SEND_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("modify_oci_image_target",
                             "Permission denied"));
        log_event_fail ("oci_image_target", "OCI Image Target",
                        oci_image_target_id, "modified");
        break;
      default:
        SEND_TO_CLIENT_OR_FAIL
          (XML_INTERNAL_ERROR ("modify_oci_image_target"));
        log_event_fail ("oci_image_target", "OCI Image Target",
                        oci_image_target_id, "modified");
        break;
    }

  modify_oci_image_target_reset ();
  g_free (error_message);
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
modify_oci_image_target_element_end (gmp_parser_t *gmp_parser, GError **error,
                                     const gchar *name)
{
  xml_handle_end_element (modify_oci_image_target_data.context, name);
  if (modify_oci_image_target_data.context->done)
    {
      modify_oci_image_target_run (gmp_parser, error);
      return 1;
    }
  return 0;
}

/**
 * @brief Add text to element.
 *
 * @param[in]  text         Text.
 * @param[in]  text_len     Text length.
 */
void
modify_oci_image_target_element_text (const gchar *text, gsize text_len)
{
  xml_handle_text (modify_oci_image_target_data.context, text, text_len);
}

/* GET_OCI_IMAGE_TARGETS */

/**
 * @brief Command data for the get_container_image_target command.
 */
typedef struct
{
  get_data_t get;    ///< Get args.
  int tasks;         ///< Boolean.  Whether to include tasks that use target.
} get_oci_image_targets_t;

/**
 * @brief Parser callback data.
 *
 * This is initially 0 because it's a global variable.
 */
static get_oci_image_targets_t get_oci_image_targets_data;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
get_oci_image_targets_reset ()
{
  get_data_reset (&get_oci_image_targets_data.get);
  memset (&get_oci_image_targets_data, 0, sizeof (get_oci_image_targets_t));
}

/**
 * @brief Handle command start element.
 *
 * @param[in]  attribute_names   All attribute names.
 * @param[in]  attribute_values  All attribute values.
 */
void
get_oci_image_targets_start (const gchar **attribute_names,
                             const gchar **attribute_values)
{
  const gchar *attribute;
  get_data_parse_attributes (&get_oci_image_targets_data.get,
                             "oci_image_target",
                             attribute_names,
                             attribute_values);
  if (find_attribute (attribute_names, attribute_values,
                      "tasks", &attribute))
    get_oci_image_targets_data.tasks = strcmp (attribute, "0");
  else
    get_oci_image_targets_data.tasks = 0;
}

/**
 * @brief Execute command.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 */
void
get_oci_image_targets_run (gmp_parser_t *gmp_parser, GError **error)
{
  iterator_t oci_image_targets;
  int count = 0, filtered, ret, first;

  ret = init_get ("get_oci_image_targets",
                  &get_oci_image_targets_data.get,
                  "OCI Image Targets",
                  &first);
  if (ret)
    {
      switch (ret)
        {
          case 99:
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("get_oci_image_targets",
                                "Permission denied"));
            break;
          default:
            internal_error_send_to_client (error);
            get_oci_image_targets_reset ();
            return;
        }
      get_oci_image_targets_reset ();
      return;
    }

  ret = init_oci_image_target_iterator (&oci_image_targets,
                                        &get_oci_image_targets_data.get);

  if (ret)
    {
      switch (ret)
        {
          case 1:
            if (send_find_error_to_client ("get_oci_image_targets",
                                            "oci_image_target",
                                            get_oci_image_targets_data.get.id,
                                            gmp_parser))
              {
                error_send_to_client (error);
                return;
              }
            break;
          case 2:
            if (send_find_error_to_client
                  ("get_oci_image_targets", "filter",
                    get_oci_image_targets_data.get.filt_id, gmp_parser))
              {
                error_send_to_client (error);
                return;
              }
            break;
          case -1:
            SEND_TO_CLIENT_OR_FAIL
              (XML_INTERNAL_ERROR ("get_oci_image_targets"));
            break;
        }
      get_oci_image_targets_reset ();
      return;
    }

  SEND_GET_START ("oci_image_target");

  while (1)
    {
      char *cred_name, *cred_uuid;
      credential_t credential;
      const char *image_references;
      int credential_available, credential_in_trash = 0;

      ret = get_next (&oci_image_targets, &get_oci_image_targets_data.get,
                      &first, &count, init_oci_image_target_iterator);
      if (ret == 1)
        break;
      if (ret == -1)
        {
          internal_error_send_to_client (error);
          get_oci_image_targets_reset ();
          return;
        }

      credential = oci_image_target_iterator_credential (&oci_image_targets);

      credential_available = 1;
      if (credential)
        {
          if (get_oci_image_targets_data.get.trash
              && oci_image_target_iterator_credential_trash (&oci_image_targets))
            {
              cred_name = trash_credential_name (credential);
              cred_uuid = trash_credential_uuid (credential);
              credential_in_trash = 1;
              credential_available
                = trash_credential_readable (credential);
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
              credential_available = (found > 0);
            }
        }
      else
        {
          cred_name = NULL;
          cred_uuid = NULL;
        }

      SEND_GET_COMMON (oci_image_target,
                       &get_oci_image_targets_data.get,
                       &oci_image_targets);

      image_references
        = oci_image_target_iterator_image_refs (&oci_image_targets);

      SENDF_TO_CLIENT_OR_FAIL ("<image_references>%s</image_references>"
                               "<credential id=\"%s\">"
                               "<name>%s</name>"
                               "<trash>%i</trash>",
                               image_references ?: "",
                               cred_uuid ?: "",
                               cred_name ?: "",
                               credential_in_trash);
      
      if (credential_available == 0)
        SEND_TO_CLIENT_OR_FAIL ("<permissions/>");

      SENDF_TO_CLIENT_OR_FAIL ("</credential>");


      if (get_oci_image_targets_data.tasks)
        {
          iterator_t tasks;
          oci_image_target_t target;
          
          SEND_TO_CLIENT_OR_FAIL ("<tasks>");
          
          target = get_iterator_resource (&oci_image_targets);
          init_oci_image_target_task_iterator (&tasks, target);

          while (next (&tasks))
            {
              if (oci_image_target_task_iterator_readable (&tasks) == 0)
                /* Only show tasks the user may see. */
                continue;

              const char *task_name
                = oci_image_target_task_iterator_name (&tasks);
              const char *task_uuid
                = oci_image_target_task_iterator_uuid (&tasks);

              SENDF_TO_CLIENT_OR_FAIL ("<task id=\"%s\">"
                                        "<name>%s</name>",
                                        task_uuid ?: "",
                                        task_name ?: "");

              if (oci_image_target_task_iterator_readable (&tasks) == 0)
                SEND_TO_CLIENT_OR_FAIL ("<permissions/>");

              SEND_TO_CLIENT_OR_FAIL ("</task>");
            }
            cleanup_iterator (&tasks);
            SEND_TO_CLIENT_OR_FAIL ("</tasks>");
        }

      SEND_TO_CLIENT_OR_FAIL ("</oci_image_target>");
      count++;
      free (cred_name);
      free (cred_uuid);
    }

  cleanup_iterator (&oci_image_targets);

  filtered = get_oci_image_targets_data.get.id 
              ? 1
              : oci_image_target_count (&get_oci_image_targets_data.get);
  SEND_GET_END ("oci_image_target", &get_oci_image_targets_data.get, 
                count, filtered);

  get_oci_image_targets_reset ();
}
