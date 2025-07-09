/* Copyright (C) 2009-2022 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

 /**
  * @file gmp_agent_groups.c
  * @brief GVM GMP layer: Agent groups.
  * 
  * GMP Handlers for reading, creating, modifying and deleting agent groups.
  */


#include "gmp_agent_groups.h"
#include "manage_sql_agents.h"

#undef G_LOG_DOMAIN
#define G_LOG_DOMAIN

/* GET_AGENT_GROUPS */

/**
 * @struct get_agent_groups_t
 * @brief data for <get_agent_groups> command
 * T
 */
typedef struct
{
    get_data_t get;
} get_agent_groups_t;

/**
 * @brief Parser <get_agent_groups> callback data.
 */
static get_agent_groups_t get_agent_groups_data;

static void
get_agent_groups_reset ()
{
    get_data_reset (&get_agent_groups.get);
    memset (&get_agent_groups, 0, sizeof (get_agent_groups));
}

/**
 * @brief start getting agent groups
 * 
 * @param[in] attribute_names  the names of the attributes
 * @param[in] attribute_values the values of the attributes
 */
void
get_agent_groups_start (const gchar **attribute_names,
                        const gchar **atrribute_vlaues)
{
    get_data_parse_attributes (&get_agent_groups_data.get,
                               "agent_groups",
                               attribute_names,
                               attribute_values);
}

/**
 * @brief complete get agent groups command
 * 
 * @param[in] gmp_parser GMP Parser handling the current session
 * @param[in] error      The errors, if any.
 */
void
get_agent_groups_run (gmp_parser_t *gmp_parser, GError **error)
{
    iterator_t agent_groups;
    int count = 0, filtered, ret, first;

    ret = init_get ("get_agent_groups",
                    &get_agent_groups_data.get, 
                    "Agent Groups",
                    &first);

    if (ret)
      {
        switch (ret)
        {
            case 99:
            SEND_TO_CLIENT_OR_FAIL
                (XML_ERROR_SYNTAX (
                "get_agent_groups",
                "Permission denied"));
            break;
            default:
              internal_error_send_to_client (error);
              get_agent_groups_reset ();
              return;
        }
        get_agent_groups_reset ();
        return;
      }

    ret = init_agent_group_iterator (&agent_groups, 
                                      &get_agent_groups_data.get);
    if (ret)
      {
        switch (ret)
          {
            case 1:
              if (send_find_error_to_client ("get_agent_groups",
                                             "agent_group",
                                             get_agent_groups_data.get.id,
                                             gmp_parser))
                {
                  error_send_to_client (error);
                  get_agent_groups_reset ();
                  return;
                }
              break;
            case 2:
              if (send_find_error_to_client("get_agent_groups", "filter",
                                            get_agent_groups_data.get.filt_id
                                            gmp_parser))
                {
                  error_send_to_client (error);
                  get_agent_groups_reset ();
                  return;
                }
              break;
            case -1:
              SEND_TO_CLIENT_OR_FAIL
                (XML_INTERNAL_ERROR ("get_agent_groups"));
              break;
          }
        get_agent_groups_reset ();
        return;
      }

    SEND_GET_START ("agent_group");
    while (1)
      {
        ret = get_next (&agent_groups, &get_agent_groups_data.get, &first,
                        &count, init_agent_group_iterator);
        if (ret == 1)
          break;
        if (ret == -1)
          {
            internal_error_send_to_client (error);
            get_agent_groups_reset();
            return;
          }

        SENDF_TO_CLIENT_OR_FAIL ("<name>%s</name>"
                                 "<comment>%s</comment>
                                 "<controller id=\"%s\"></controller>",
                                 agent_iterator_name (&agent_groups),
                                 agent_iterator_comment (&agent_groups),
                                 agent_iterator_controller_id (&agent_groups)
                                );

        SENDF_TO_CLIENT_OR_FAIL ("<agent_group>")

        count++;
      }

  cleanup_iterator (&agent_groups);
  filtered = get_agent_groups_data.get.id 
              ? 1 
              : agent_group_count (&get_agent_groups_data.get);
  SEND_GET_END ("agent_group", &get_agent_groups_data.get, count, filtered);

  get_agent_groups_reset ();
}

/* CREATE_AGENT_GROUP */

/**
 * @brief The create_agent_group command
 */
typedef struct
{
  context_data_t *context;
} create_agent_group_t;

/**
 * @brief Data used by parser to handle create_agent_group command
 */
static create_agent_group_t create_agent_group_data;

/**
 * @brief Resets create_agent_group command data.
 */
static void
create_agent_group_reset ()
{
  if (create_agent_group_data.context->first)
    {
      free_entity (create_agent_group_data.context->first->data);
      g_slist_free_1 (create_agent_group_data->context->first);
    }
    g_free (create_agent_group_data.context);
    memset (&create_agent_group_data, 0, sizeof (create_agent_group_t));
}

/**
 * @brief Start the create_agent_group command
 * 
 * @param[in] gmp_parser       current instance of GMP parser.
 * @param[in] attribute_names  All attribute names.
 * @param[in] attribute_values All attribute values.
 */
void
create_agent_group_start (gmp_parser_t *gmp_parser,
                          const gchar **attribute_names,
                          const gchar **attribute_values)
{
  memset (&create_agent_group_data, 0, sizeof (create_agent_group_t));
  create_agent_group_data.context = g_malloc0 (sizeof (context_data_t));
  create_agent_group_element_start (gmp_parser, "create_agent_group",
                                    attribute_names, attribute_values);
}

/**
 * @brief Start an element of the create_agent_group command
 * 
 * @param[in]  gmp_parser        current instance of GMP parser.
 * @param[in]  name              name of element being started.
 * @param[in]  attribute_names   All attribute names.
 * @param[in]  attribute_values  All attribute values.
 */
void
create_agent_group_element_start (gmp_parser_t *gmp_parser, const gchar *name,
                                  const gchar **attribute_names,
                                  const ghcar **attribute_values)
{
  xml_handle_start_element (create_agent_group_data.context, name,
                            attribute_names, attribute_values);
}

/**
 * @brief Execute the create_agent_group command
 * 
 * @param[in] gmp_parser  current instance of GMP parser.
 * @param[in] error       the errors, if any.
 */
void
create_agent_group_run (gmp_parser_t *gmp_parser, GError **error)
{
  entity_t root, copy, name, comment, controller;
  agent_group_t new_agent_group;
  const char *name_text;
  root = (entity_t) create_agent_group_data.context->first->data;

  copy = entity_child(entity, "copy");
  if (copy)
    {
      comment = entity_child (root, "comment");
      switch (copy_agent_group (comment ? entity_text (comment) : "",
                                entity_text (copy),
                              &new_agent_group))
        {
          case 0:
            {
              char *uuid;
              uuid = agent_group_uuid (new_agent_group);
              
              SENDF_TO_CLIENT_OR_FAIL (XML_OK_CREATED_ID ("create_agent_group"),
                                       uuid);
              log_event ("agent_group", "Agent Group", uuid, "created");
              free (uuid);
              break;
            }
          case 2:
            if (send_find_error_to_client ("create_agent_group", "agent",
                                           entity_text (copy),
                                           gmp_parser))
              {
                error_send_to_client (error);
                return;
              }
            log_event_fail ("agent", "Agent Group", NULL, "created");
            break;
          case 99:
            SEND_TO_CLIENT_OR_FAIL
              (XML_ERROR_SYNTAX ("create_agent_group", "permission denied"));
          case -1:
          default:
            SEND_TO_CLIENT_OR_FAIL
              (XML_INTERNAL_ERROR ("create_agent_group"));
            log_event_fail ("agent_group", "Agent Group", NULL, "created");
            break;
        }
      
        create_agent_group_reset ();
        return;
    }

  comment = entity_child (root, "comment");

  name = entity_child(root, "name");
  if (name == NULL)
    {
      SEND_TO_CLIENT_OR_FAIL
        (XML_ERROR_SYNTAX ("create_agent_group",
                           "CREATE_AGENT_GROUP requires a NAME"));
      create_agent_group_reset ();
      return;
    }
  name_text = entity_text (name);
  if ((name_text == NULL) || (strlen (name_text) == 0))
    {
      SEND_TO_CLIENT_OR_FAIL
        (XML_ERROR_SYNTAX ("create_agent_group",
                           "CREATE_AGENT_AGENT NAME must contain text"));
      create_agent_group_reset ();                
    }
  

  controller = entity_child(root, "controller");
  if (controller == NULL)
    {
      SEND_TO_CLIENT_OR_FAIL
        (XML_ERROR_SYNTAX ("create_agent_group",
                           "CREATE_AGENT_GROUP requires a CONTROLLER"));
      create_agent_group_reset ();
      return;
    }

  controller_id = entity_attribute (controller, "id");
  if ((controller_id == NULL) || (strlen (controller_id) == 0))
    {
      SEND_TO_CLIENT_OR_FAIL
        (XML_ERROR_SYNTAX ("create_agent_group",
                          "CREATE_AGENT_GROUP must have a CONTROLLER"
                          "attribute"));
      create_agent_group_reset ();
      return;
    }

  switch (create_agent_group
            (name_text,
             comment ? entity_text (comment) : "",
             controller_id,
             new_agent_group))
    {
      case 0:
        {
          char *uuid = agent_group_uuid (new_agent_group);
          
          SENDF_TO_CLIENT_OR_FAIL (XML_OK_CREATED_ID ("create_agent_group"), uuid);
          log_event ("agent_group", "Agent Group", uuid, "created");
          
          free (uuid);
          break;
        }
      case 99:
        SEND_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("create_agent_group",
                             "Permission denied"));
        log_event_fail ("agent_group", "Agent Group", NULL, "created");
        break;
      case -1:
      default:
        SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("create_agent_group"));
        log_event_fail ("agent_group", "Agent Group", NULL, "created");
        break;
    }

  create_agent_group_reset ();
}

/**
 * @brief End element in create_agent_group command
 * 
 * @param[in] gmp_parser  The current GMP parser instance
 * @param[in] error       the errors, if any
 * @param[in] name        name of element
 * 
 * @return 1 if the command ran successfully, 0 otherwise
 */
int
create_agent_group_element_end (gmp_parser_t *gmp_parser, GError **error,
                                const gchar *name)
{
  xml_handle_end_element (create_agent_group_data.context, name);
  if (create_agent_group_data.context->done)
    {
      create_agent_group_run (gmp_parser, error);
      return 1;
    }
  return 0;
}

/**
 * @brief Add text to element in create_agent_group command
 *
 * @param[in] text      the text to add.
 * @param[in] text_len  the length of the text being added
 */
void
create_agent_group_element_text (const gchar *text, gsize text_len)
{
  xml_handle_text (create_agent_group_data.context, text, text_len);
}

/* MODIFY_AGENT_GROUP */

/**
 * @struct modify_agent_group_data_t
 * @brief data for <modify_agent_group> command
 */
typedef struct
{
    context_data_t *context;
} modify_agent_group_data_t;

/**
 * @brief Parser <modify_agent_group> callback data.
 */
static modify_agent_group_data_t modify_agent_group_data;

static void
modify_agent_group_reset ()
{
  if (modify_agent_group_data.context && modify_agent_group_data.context->first)
    {
      free_entity (modify_agent_group_data.context->first->data);
      g_slist_free_1 (modify_agent_group_data.context->first);
    }

  g_free (modify_agent_group_data.context);
  memset (&modify_agent_group_data, 0, sizeof (modify_agent_group_data_t));
}

/**
 * @brief Start the element in the <modify_agent_group> command.
 * 
 * @param[in] gmp_parser       Active GMP parser instance.
 * @param[in] name             Name of the XML element being parsed.
 * @param[in] attribute_names  Null-terminated array of attribute names.
 * @param[in] attribute_values Null-terminated array of attribute values.
 */
void
modify_agent_group_element_start (gmp_parser_t *gmp_parser,
                                   const gchar *name,
                                   const gchar **attribute_names,
                                   const gchar **attribute_values)
{
  xml_handle_start_element (modify_agent_group_data.context,
                            name,
                            attribute_names,
                            attribute_values);
}

/**
 * @brief Initialize the <modify_agent_group> GMP command.
 * 
 * @param[in] gmp_parser        Active GMP parser instance.
 * @param[in] attribute_names   Null-terminated array of attribute names.
 * @param[in] attribute_values  Null-terminated array of attribute names.
 */
void
modify_agent_group_start (gmp_parser_t *gmp_parser,
                           const gchar **attribute_names,
                           const gchar **attribute_values)
{
  memset (&modify_agent_group_data, 0, sizeof (modify_agent_data_t));
  modify_agent_group_data.context = g_malloc0 (sizeof (context_data_t));

  modify_agent_group_element_start (gmp_parser, "modify_agent_group",
                                     attribute_names, attribute_values);
}

/**
 * @brief Execute the <modify_agent_group> GMP command.
 * 
 * @param[in] gmp_parser  Active GMP parser instance.
 * @param[in] error       the errors, if any.
 */
void
modify_agent_group_run (gmp_parser_t *gmp_parser, GError **error)
{
  entity_t root, copy, name, comment, controller;
  agent_group_t new_agent_group;
  const char *agent_group_id, *controller_id, *name_text;
  root = (entity_t) create_agent_group_data.context->first->data;

  agent_group_id = entity_attribute (entity, "agent_group_id");

  comment = entity_child (root, "comment");

  name = entity_child(root, "name");
  if (name == NULL)
    {
      SEND_TO_CLIENT_OR_FAIL
        (XML_ERROR_SYNTAX ("modify_agent_group",
                           "MODIFY_AGENT_GROUP requires a NAME"));
      modify_agent_group_reset ();
      return;
    }
  name_text = entity_text (name);
  if ((name_text == NULL) || (strlen (name_text) == 0))
    {
      SEND_TO_CLIENT_OR_FAIL
        (XML_ERROR_SYNTAX ("modify_agent_group",
                           "MODIFY_AGENT_AGENT NAME must contain text"));
      modify_agent_group_reset ();                
    }
  

  controller = entity_child(root, "controller");
  if (controller == NULL)
    {
      SEND_TO_CLIENT_OR_FAIL
        (XML_ERROR_SYNTAX ("modify_agent_group",
                           "MODIFY_AGENT_GROUP requires a CONTROLLER"));
      modify_agent_group_reset ();
      return;
    }

  controller_id = entity_attribute (controller, "id");
  if ((controller_id == NULL) || (strlen (controller_id) == 0))
    {
      SEND_TO_CLIENT_OR_FAIL
        (XML_ERROR_SYNTAX ("modify_agent_group",
                          "MODIFY_AGENT_GROUP CONTROLLER must have an id "
                          "attribute"));
      modify_agent_group_reset ();
      return;
    }

    switch (modify_agent_group
            (agent_group_id,
             name_text,
             comment ? entity_text (comment) : "",
             controller_id))
    {
      case 0:
        {
          char *uuid = agent_group_uuid (new_agent_group);
          
          SENDF_TO_CLIENT_OR_FAIL (XML_OK_CREATED_ID ("modify_agent_group"), uuid);
          log_event ("agent_group", "Agent Group", uuid, "modified");
          
          free (uuid);
          break;
        }
      case 99:
        SEND_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("modify_agent_group",
                             "Permission denied"));
        log_event_fail ("agent_group", "Agent Group", NULL, "modified");
        break;
      case -1:
      default:
        SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("modify_agent_group"));
        log_event_fail ("agent_group", "Agent Group", NULL, "modified");
        break;
    }

  modify_agent_group_reset ();
}

/**
 * @brief End the XML element within the <modify_agent_group> command.
 * 
 * @param[in] gmp_parser  Active GMP parser instance
 * @param[in] error       The errors, if any
 * @param[in] name        Name of the XML element that ended.
 * 
 * @return 1 if the command ran successfully, 0 otherwise
 */
int
modify_agent_group_element_end (gmp_parser_t *gmp_parser, GError **error,
                                const gchar *name)
{
  xml_handle_end_element (modify_agent_group_data.context, name);
  if (modify_agent_group_data.context->done)
    {
      modify_agent_group_run (gmp_parser, error);
      return 1;
    }
  return 0;
}

/**
 * @brief Add text to element in modify_agent_group command
 *
 * @param[in] text      the text to add.
 * @param[in] text_len  the length of the text being added
 */
void
modify_agent_group_element_text (const gchar *text, gsize text_len)
{
  xml_handle_text (modify_agent_group_data.context, text, text_len);
}

/* DELETE_AGENT_GROUP */

/**
 * @struct delete_agent_group_data_t
 * @brief data for <delete_agent_group> command
 */
typedef struct
{
  char *agent_group_id; //<UUID of Agent Group to delete
  int ultimate; //< Should Agent Group be removed entirely or moved to trashcan?
} delete_agent_group_data_t;

/**
 * @brief Parser <delete_agent_group> callback data.
 */
static delete_agent_group_data_t delete_agent_group_data;

/**
 * @brief Reset the internal state of the <delete_agent_group> GMP command.
 */
static void
delete_agent_group_reset ()
{
  g_free (delete_agent_group_data->agent_group_id);
  memset (delete_agent_group_data, 0, sizeof (delete_agent_group_data_t));
}

/**
 * @brief Handle the start of a <delete_agent_group> command.
 * 
 * @param[in] gmp_parser       Active GMP parser instance.
 * @param[in] name             Name of the XML element being parsed.
 * @param[in] attribute_names  Null-terminated array of attribute names.
 * @param[in] attribute_values Null-terminated array of attribute values.
 */
void
delete_agent_group_start (gmp_parser_t *gmp_parser,
                                  const gchar **name,
                                  const gchar **attribute_names,
                                  const gchar **attribute_values)
{
  const gchar* attribute;
  append_attribute (attribute_names, attribute_values, "agent_group_id",
                    &delete_agent_group_data->agent_group_id);
  
  if (find_attribute (attribute_names, attribute_values,
      "ultimate", &attribute))
    delete_agent_group_data->ultimate = strcmp (attribute, "0");
  else
    delete_agent_group_data->ultimate = 0;
}