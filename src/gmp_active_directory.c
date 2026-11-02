/* Copyright (C) 2009-2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM GMP layer: Active Directory.
 *
 * GMP Handlers for Active Directory.
 */

#include "gmp_active_directory.h"
#include "gmp_base.h"
#include "manage_active_directory.h"
#include "manage.h"

#include <string.h>

#include <gvm/util/xmlutils.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md    gmp"

/* GET_ACTIVE_DIRECTORY_OBJECTS */

#define AD_OBJECTS_DEFAULT_MAX_RESULTS 200

/* VERIFY_ACTIVE_DIRECTORY_CREDENTIAL */

typedef struct
{
  context_data_t *context;
} verify_active_directory_credential_data_t;

typedef struct
{
  context_data_t *context;
} get_active_directory_objects_data_t;


static verify_active_directory_credential_data_t
  verify_active_directory_credential_data;

static get_active_directory_objects_data_t
  get_active_directory_objects_data;

/**
 * @brief Reset the verify_active_directory_credential data.
 */
static void
verify_active_directory_credential_reset (void)
{
  context_data_t *context = verify_active_directory_credential_data.context;

  if (context && context->first)
    {
      free_entity (context->first->data);
      g_slist_free_1 (context->first);
    }

  g_free (context);
  memset (&verify_active_directory_credential_data, 0,
          sizeof (verify_active_directory_credential_data));
}

/**
 * @brief Handle the start of the VERIFY_ACTIVE_DIRECTORY_CREDENTIAL element.
 *
 * @param[in]  gmp_parser        current instance of GMP parser.
 * @param[in]  attribute_names   All attribute names.
 * @param[in]  attribute_values  All attribute values.
 */
void
verify_active_directory_credential_start (gmp_parser_t *gmp_parser,
                                          const gchar **attribute_names,
                                          const gchar **attribute_values)
{
  memset (&verify_active_directory_credential_data, 0,
          sizeof (verify_active_directory_credential_data));

  verify_active_directory_credential_data.context
    = g_malloc0 (sizeof (context_data_t));

  verify_active_directory_credential_element_start (
    gmp_parser,
    "verify_active_directory_credential",
    attribute_names,
    attribute_values
  );
}

/**
 * @brief Start an element of verify_active_directory_credential command.
 *
 * @param[in]  gmp_parser        current instance of GMP parser.
 * @param[in]  name              the name of the element.
 * @param[in]  attribute_names   All attribute names.
 * @param[in]  attribute_values  All attribute values.
 */
void
verify_active_directory_credential_element_start (gmp_parser_t *gmp_parser,
                                                  const gchar *name,
                                                  const gchar **attribute_names,
                                                  const gchar **attribute_values)
{
  xml_handle_start_element (verify_active_directory_credential_data.context,
                            name,
                            attribute_names,
                            attribute_values);
}

/**
 * @brief Add text to element in verify_active_directory_credential command.
 *
 * @param[in]  text      the text content of the element.
 * @param[in]  text_len  the length of the text content.
 */
void
verify_active_directory_credential_element_text (const gchar *text,
                                                 gsize text_len)
{
  xml_handle_text (verify_active_directory_credential_data.context,
                   text, text_len);
}

/**
 * @brief End element in verify_active_directory_credential command
 *
 * @param[in] gmp_parser  current instance of GMP parser.
 * @param[in] error       the errors, if any.
 * @param[in] name        the name of the element.
 *
 * @return 1 if the element is fully processed, 0 otherwise.
 */
int
verify_active_directory_credential_element_end (gmp_parser_t *gmp_parser,
                                                GError **error,
                                                const gchar *name)
{
  context_data_t *context = verify_active_directory_credential_data.context;

  xml_handle_end_element (context, name);
  if (!context->done)
    return 0;

  verify_active_directory_credential_run (gmp_parser, error);
  return 1;
}

/**
 * @brief Get the text content of a child element.
 *
 * @param root  The parent entity.
 * @param name  The name of the child element.
 *
 * @return A newly allocated string containing the text content
 *         or NULL otherwise.
 */
static gchar *
ad_child_text (entity_t root, const gchar *name)
{
  entity_t child = entity_child (root, name);
  const gchar *text;

  if (child == NULL)
    return NULL;

  text = entity_text (child);
  return g_strdup (text ? text : "");
}

/**
 * @brief Run the verify_active_directory_credential command.
 *
 * @param[in] gmp_parser  Active GMP parser instance.
 * @param[in] error       the errors, if any.
 */
void
verify_active_directory_credential_run (gmp_parser_t *gmp_parser,
                                        GError **error)
{
  credential_data_t data = { 0 };
  ad_credential_data_t *ad = &data.ad_credential_data;
  context_data_t *context = verify_active_directory_credential_data.context;
  entity_t root = context && context->first
                    ? context->first->data : NULL;
  const gchar *credential_id;
  const gchar *response = XML_INTERNAL_ERROR ("verify_active_directory_credential");
  verify_ad_return_t result;

  if (root == NULL)
    goto cleanup;

  credential_id = entity_attribute (root, "credential_id");

  ad->host = ad_child_text (root, "host");
  ad->port = ad_child_text (root, "port");
  ad->bind_dn = ad_child_text (root, "bind_dn");
  ad->bind_password = ad_child_text (root, "bind_password");
  ad->base_dn = ad_child_text (root, "base_dn");
  ad->tls_mode = ad_child_text (root, "tls_mode");
  ad->ca_certificate = ad_child_text (root, "ca_certificate");

  result = verify_active_directory_credential (credential_id, ad);

  switch (result)
    {
    case VERIFY_AD_CREDENTIAL_OK:
      response = XML_OK ("verify_active_directory_credential");
      break;
    case VERIFY_AD_CREDENTIAL_INVALID_INPUT:
      response = XML_ERROR_SYNTAX (
        "verify_active_directory_credential",
        "Invalid AD credential settings");
      break;
    case VERIFY_AD_CREDENTIAL_NOT_FOUND:
      response = XML_ERROR_MISSING (
        "verify_active_directory_credential");
      break;
    case VERIFY_AD_CREDENTIAL_PERMISSION_DENIED:
      response = XML_ERROR_ACCESS (
        "verify_active_directory_credential");
      break;
    case VERIFY_AD_CREDENTIAL_INVALID_TYPE:
      response = XML_ERROR_SYNTAX (
        "verify_active_directory_credential",
        "Credential is not an Active Directory credential");
      break;
    case VERIFY_AD_CREDENTIAL_INVALID_STORED_CONFIGURATION:
      response = XML_ERROR_SYNTAX (
        "verify_active_directory_credential",
        "Stored Active Directory credential configuration is invalid");
      break;
    case VERIFY_AD_CREDENTIAL_HOST_REQUIRED:
      response = XML_ERROR_SYNTAX (
        "verify_active_directory_credential",
        "AD host is required");
      break;
    case VERIFY_AD_CREDENTIAL_BIND_DN_REQUIRED:
      response = XML_ERROR_SYNTAX (
        "verify_active_directory_credential",
        "AD bind DN is required");
      break;
    case VERIFY_AD_CREDENTIAL_BIND_PASSWORD_REQUIRED:
      response = XML_ERROR_SYNTAX (
        "verify_active_directory_credential",
        "AD bind password is required");
      break;
    case VERIFY_AD_CREDENTIAL_BASE_DN_REQUIRED:
      response = XML_ERROR_SYNTAX (
        "verify_active_directory_credential",
        "AD base DN is required");
      break;
    case VERIFY_AD_CREDENTIAL_TLS_MODE_REQUIRED:
      response = XML_ERROR_SYNTAX (
        "verify_active_directory_credential",
        "AD TLS mode is required");
      break;
    case VERIFY_AD_CREDENTIAL_INVALID_TLS_MODE:
      response = XML_ERROR_SYNTAX (
        "verify_active_directory_credential",
        "Invalid AD TLS mode");
      break;
    case VERIFY_AD_CREDENTIAL_INVALID_PORT:
      response = XML_ERROR_SYNTAX (
        "verify_active_directory_credential",
        "Invalid AD port");
      break;
    case VERIFY_AD_CREDENTIAL_INVALID_CA_CERTIFICATE:
      response = XML_ERROR_SYNTAX (
        "verify_active_directory_credential",
        "Invalid AD CA certificate");
      break;
    case VERIFY_AD_CREDENTIAL_CONNECTION_FAILED:
      response = XML_ERROR_UNAVAILABLE (
        "verify_active_directory_credential",
        "Could not connect to Active Directory");
      break;
    case VERIFY_AD_CREDENTIAL_BIND_FAILED:
      response = XML_ERROR_UNAVAILABLE (
        "verify_active_directory_credential",
        "Active Directory bind failed");
      break;
    case VERIFY_AD_CREDENTIAL_FEATURE_DISABLED:
      response = XML_ERROR_SYNTAX (
        "verify_active_directory_credential",
        "Active Directory integration is disabled");
      break;
    case VERIFY_AD_CREDENTIAL_INTERNAL_ERROR:
    default:
      break;
    }

cleanup:
  if (send_to_client (response, gmp_parser->client_writer,
                      gmp_parser->client_writer_data))
    error_send_to_client (error);

  credential_data_reset (&data);
  verify_active_directory_credential_reset ();
}

/**
 * @brief Reset the get_active_directory_objects context.
 */
static void
get_active_directory_objects_reset (void)
{
  context_data_t *context = get_active_directory_objects_data.context;

  if (context && context->first)
    {
      free_entity (context->first->data);
      g_slist_free_1 (context->first);
    }

  g_free (context);
  memset (&get_active_directory_objects_data, 0,
          sizeof (get_active_directory_objects_data));
}

/**
 * @brief Start processing the get_active_directory_objects element.
 *
 * @param[in]  gmp_parser       current instance of GMP parser.
 * @param[in]  attribute_names  array of attribute names.
 * @param[in]  attribute_values array of attribute values.
 */
void
get_active_directory_objects_start (gmp_parser_t *gmp_parser,
                                    const gchar **attribute_names,
                                    const gchar **attribute_values)
{
  memset (&get_active_directory_objects_data, 0,
          sizeof (get_active_directory_objects_data));

  get_active_directory_objects_data.context
    = g_malloc0 (sizeof (context_data_t));

  get_active_directory_objects_element_start (
    gmp_parser,
    "get_active_directory_objects",
    attribute_names,
    attribute_values
  );
}

/**
 * @brief Start an element of get_active_directory_objects command.
 *
 * @param[in]  gmp_parser       current instance of GMP parser.
 * @param[in]  name             name of the element.
 * @param[in]  attribute_names  array of attribute names.
 * @param[in]  attribute_values array of attribute values.
 */
void
get_active_directory_objects_element_start (gmp_parser_t *gmp_parser,
                                            const gchar *name,
                                            const gchar **attribute_names,
                                            const gchar **attribute_values)
{
  (void) gmp_parser;

  xml_handle_start_element (get_active_directory_objects_data.context,
                            name,
                            attribute_names,
                            attribute_values);
}

/**
 * @brief Handle the text within the get_active_directory_objects context.
 *
 * @param[in]  text      text content.
 * @param[in]  text_len  length of the text content.
 */
void
get_active_directory_objects_element_text (const gchar *text, gsize text_len)
{
  xml_handle_text (get_active_directory_objects_data.context,
                   text,
                   text_len);
}

/**
 * @brief Append a computer's target, task and scan config matches as XML.
 *
 * @param[in]  targets  array of target matches.
 * @param[in]  xml      XML string to append to.
 *
 * @return TRUE on success, FALSE on failure.
 */
static gboolean
append_ad_computer_targets_xml (const GPtrArray *targets, GString *xml)
{
  if (!targets)
    return TRUE;

  if (!targets->len)
    {
      g_string_append (xml, "<targets/>");
      return TRUE;
    }

  g_string_append (xml, "<targets>");
  for (guint index = 0; index < targets->len; index++)
    {
      const ad_target_match_t *target = g_ptr_array_index (targets, index);

      if (!target || !target->resource.uuid || !*target->resource.uuid
          || !target->resource.name)
        return FALSE;

      buffer_xml_append_printf (xml, "<target id=\"%s\"><name>%s</name>",
                                target->resource.uuid,
                                target->resource.name);
      if (target->tasks)
        {
          g_string_append (xml, "<tasks>");
          for (guint task_index = 0;
               task_index < target->tasks->len;
               task_index++)
            {
              const ad_task_match_t *task
                = g_ptr_array_index (target->tasks, task_index);

              if (!task || !task->resource.uuid || !*task->resource.uuid
                  || !task->resource.name)
                return FALSE;

              buffer_xml_append_printf (xml,
                                        "<task id=\"%s\">"
                                        "<name>%s</name>",
                                        task->resource.uuid,
                                        task->resource.name);

              if (task->config)
                {
                  if (!task->config->uuid || !*task->config->uuid
                      || !task->config->name)
                    return FALSE;

                  buffer_xml_append_printf (xml,
                                            "<config id=\"%s\">"
                                            "<name>%s</name>"
                                            "</config>",
                                            task->config->uuid,
                                            task->config->name);
                }

              g_string_append (xml, "</task>");
            }

          g_string_append (xml, "</tasks>");

        }
      g_string_append (xml, "</target>");
    }

  g_string_append (xml, "</targets>");

  return TRUE;
}

/**
 * @brief Append computer-specific attributes and resource matches as XML.
 *
 * @param[in]     object  Computer object to serialize.
 * @param[in,out] xml     Buffer to append XML to.
 * @param[in]     details Whether detailed computer fields were requested.
 *
 * @return TRUE on success, FALSE for invalid data.
 */
static gboolean
append_ad_computer_xml (const ad_directory_object_t *object, GString *xml,
                        gboolean details)
{
  const gchar *value;

  value = ad_object_attribute_value (object, "dNSHostName");
  if (value)
    buffer_xml_append_printf (xml,
                              "<dns_hostname>%s</dns_hostname>",
                              value);

  value = ad_object_attribute_value (object, "operatingSystem");
  if (value)
    buffer_xml_append_printf (xml,
                              "<operating_system>%s</operating_system>",
                              value);

  if (details)
    {
      const GPtrArray *principal_names;

      value = ad_object_attribute_value (object, "operatingSystemVersion");
      if (value)
        buffer_xml_append_printf (
          xml,
          "<operating_system_version>%s</operating_system_version>",
          value
        );

      principal_names = ad_object_attribute_values (object,
                                                    "serviceprincipalname");
      g_string_append (xml, "<service_principal_names>");
      for (guint index = 0;
           principal_names && index < principal_names->len;
           index++)
        {
          const gchar *principal = g_ptr_array_index (principal_names, index);

          if (!principal)
            return FALSE;

          buffer_xml_append_printf (
            xml,
            "<service_principal_name>%s</service_principal_name>",
            principal
          );
        }
      g_string_append (xml, "</service_principal_names>");
    }

  value = ad_object_attribute_value (object, "userAccountControl");
  if (value && g_ascii_isdigit ((guchar) *value))
    {
      gchar *end;
      guint64 account_control = g_ascii_strtoull (value, &end, 10);

      if (*end == '\0' && account_control <= G_MAXUINT32)
        g_string_append_printf (xml,
                                "<disabled>%d</disabled>",
                                (account_control & 0x0002) != 0);
    }

  return append_ad_computer_targets_xml (object->target_matches, xml);
}

/**
 * @brief Append an AD object as XML to the given buffer.
 *
 * @param[in]     object  Owned directory object to serialize.
 * @param[in,out] xml     Buffer to append XML to.
 * @param[in]     details Whether detailed computer fields were requested.
 *
 * @return TRUE on success, FALSE for invalid data.
 */
static gboolean
append_ad_object_xml (const ad_directory_object_t *object, GString *xml,
                      gboolean details)
{
  const gchar *type;

  if (!object || !object->name || !object->distinguished_name)
    return FALSE;

  switch (object->type)
    {
    case AD_OBJECT_TYPE_OU:
      type = "ou";
      break;
    case AD_OBJECT_TYPE_COMPUTER:
      type = "computer";
      break;
    case AD_OBJECT_TYPE_GROUP:
      type = "group";
      break;
    default:
      return FALSE;
    }

  buffer_xml_append_printf (xml,
                            "<object type=\"%s\"><name>%s</name>"
                            "<distinguished_name>%s</distinguished_name>"
                            "<parent_dn>%s</parent_dn>",
                            type,
                            object->name,
                            object->distinguished_name,
                            object->parent_dn ? object->parent_dn : "");

  if (object->type == AD_OBJECT_TYPE_COMPUTER)
    {
      if (!append_ad_computer_xml (object, xml, details))
        return FALSE;
    }

  g_string_append (xml, "</object>");
  return TRUE;
}

/**
 * @brief Parse the maximum results value from text.
 *
 * @param[in]  text         text containing the maximum results.
 * @param[out] max_results  parsed maximum results.
 *
 * @return TRUE on success, FALSE on invalid input.
 */
static gboolean
ad_object_parse_max_results (const gchar *text, guint *max_results)
{
  const gchar *p;
  guint64 value;

  if (!text || !*text)
    return FALSE;

  for (p = text; *p; p++)
    if (!g_ascii_isdigit (*p))
      return FALSE;

  value = g_ascii_strtoull (text, NULL, 10);

  if (value < 1 || value > GET_AD_OBJECTS_MAX_RESULTS)
    return FALSE;

  *max_results = (guint) value;
  return TRUE;
}

/**
 * @brief Parse the object types from the given entity.
 *
 * @param[in]  types_entity  entity containing the object types.
 * @param[out] types         parsed object types.
 *
 * @return TRUE on success, FALSE on invalid input.
 */
static gboolean
ad_object_parse_types (entity_t types_entity, ad_object_type_t *types)
{
  entities_t children;
  guint mask = 0;

  if (!types_entity || !types_entity->entities)
    return FALSE;

  for (children = types_entity->entities; children;
       children = next_entities (children))
    {
      entity_t child = first_entity (children);
      const gchar *text;
      guint bit;

      if (strcmp (entity_name (child), "object_type"))
        continue;

      if (child->entities)
        return FALSE;

      text = entity_text (child);
      if (g_strcmp0 (text, "ou") == 0)
        bit = AD_OBJECT_TYPE_OU;
      else if (g_strcmp0 (text, "computer") == 0)
        bit = AD_OBJECT_TYPE_COMPUTER;
      else if (g_strcmp0 (text, "group") == 0)
        bit = AD_OBJECT_TYPE_GROUP;
      else
        return FALSE;

      mask |= bit;
    }

  if (!mask)
    return FALSE;

  *types = (ad_object_type_t) mask;
  return TRUE;
}

/**
 * @brief Parse and validate the command XML.
 *
 * @param[in]  root        Command entity.
 * @param[in,out] request  Initialized request.
 * @param[out] error_text  Static error message on failure, NULL on success.
 *
 * @return TRUE on success, FALSE on invalid input.
 */
static gboolean
parse_get_active_directory_objects (entity_t root,
                                    get_ad_objects_params_t *request,
                                    const gchar **error_text)
{
  const gchar *scope_text, *limit_text, *disabled_text, *targets_text;
  const gchar *details_text, *tasks_text;
  entity_t base_dn, group_dn, object_types;

  *error_text = NULL;

  if (!root)
    {
      *error_text = "Invalid Active Directory search request";
      return FALSE;
    }
  request->credential_id = entity_attribute (root, "credential_id");
  if (!request->credential_id || !*request->credential_id)
    {
      *error_text = "Missing or empty credential_id attribute";
      return FALSE;
    }

  scope_text = entity_attribute (root, "scope");
  if (scope_text)
    {
      if (strcmp (scope_text, "base") == 0)
        request->scope = AD_CONNECTOR_SEARCH_SCOPE_BASE;
      else if (strcmp (scope_text, "onelevel") == 0)
        request->scope = AD_CONNECTOR_SEARCH_SCOPE_ONELEVEL;
      else if (strcmp (scope_text, "subtree") == 0)
        request->scope = AD_CONNECTOR_SEARCH_SCOPE_SUBTREE;
      else
        {
          *error_text = "Invalid scope";
          return FALSE;
        }
    }

  limit_text = entity_attribute (root, "max_results");
  if (limit_text
      && !ad_object_parse_max_results (limit_text, &request->max_results))
    {
      *error_text = "Invalid max_results";
      return FALSE;
    }

  disabled_text = entity_attribute (root, "include_disabled_computers");
  if (disabled_text)
    {
      if (strcmp (disabled_text, "0") == 0)
        request->include_disabled_computers = FALSE;
      else if (strcmp (disabled_text, "1") == 0)
        request->include_disabled_computers = TRUE;
      else
        {
          *error_text = "Invalid include_disabled_computers";
          return FALSE;
        }
    }

  targets_text = entity_attribute (root, "targets");
  if (targets_text)
    {
      if (strcmp (targets_text, "0") == 0)
        request->targets = FALSE;
      else if (strcmp (targets_text, "1") == 0)
        request->targets = TRUE;
      else
        {
          *error_text = "Invalid targets";
          return FALSE;
        }
    }

  tasks_text = entity_attribute (root, "tasks");
  if (tasks_text)
    {
      if (strcmp (tasks_text, "0") == 0)
        request->tasks = FALSE;
      else if (strcmp (tasks_text, "1") == 0)
        request->tasks = TRUE;
      else
        {
          *error_text = "Invalid tasks";
          return FALSE;
        }
    }
  if (request->tasks && !request->targets)
    {
      *error_text = "tasks requires targets=1";
      return FALSE;
    }

  details_text = entity_attribute (root, "details");
  if (details_text)
    {
      if (strcmp (details_text, "0") == 0)
        request->details = FALSE;
      else if (strcmp (details_text, "1") == 0)
        request->details = TRUE;
      else
        {
          *error_text = "Invalid details";
          return FALSE;
        }
    }

  base_dn = entity_child (root, "base_dn");
  if (base_dn)
    {
      if (base_dn->entities)
        {
          *error_text = "Invalid base_dn element";
          return FALSE;
        }
      request->base_dn = entity_text (base_dn);
      if (!request->base_dn || !*request->base_dn)
        {
          *error_text = "Empty base_dn element";
          return FALSE;
        }
    }

  group_dn = entity_child (root, "group_dn");
  if (group_dn)
    {
      if (group_dn->entities)
        {
          *error_text = "Invalid group_dn element";
          return FALSE;
        }
      request->group_dn = entity_text (group_dn);
      if (!request->group_dn || !*request->group_dn)
        {
          *error_text = "Empty group_dn element";
          return FALSE;
        }
    }

  object_types = entity_child (root, "object_types");
  if (object_types
      && !ad_object_parse_types (object_types, &request->object_types))
    {
      *error_text = "Invalid object_types element";
      return FALSE;
    }

  return TRUE;
}

/**
 * @brief Serialize search results after all management processing has finished.
 *
 * @param[in] result Owned objects and search truncation status.
 * @param[in] details Whether detailed computer fields were requested.
 * @param[in] include_disabled_computers Whether to include the disabled count.
 *
 * @return Newly allocated response, or NULL for invalid data.
 */
static GString *
buffer_active_directory_objects_xml (const get_ad_objects_result_t *result,
                                     gboolean details,
                                     gboolean include_disabled_computers)
{
  GString *response = g_string_new (NULL);
  guint count = result->objects ? result->objects->len : 0;
  guint index;

  g_string_append_printf (
    response,
    "<get_active_directory_objects_response status=\"" STATUS_OK
    "\" status_text=\"" STATUS_OK_TEXT "\">"
    "<objects truncated=\"%d\">"
    "<count>"
    "<ou>%u</ou>"
    "<group>%u</group>"
    "<computer>"
    "<total>%u</total>",
    result->truncated ? 1 : 0,
    result->counts.ou,
    result->counts.group,
    result->counts.computer_total
  );

  if (include_disabled_computers)
    g_string_append_printf (response, "<disabled>%u</disabled>",
                            result->counts.computer_disabled);
  g_string_append (response, "</computer></count>");

  for (index = 0; index < count; index++)
    {
      const ad_directory_object_t *object
        = g_ptr_array_index (result->objects, index);

      if (!append_ad_object_xml (object, response, details))
        {
          g_string_free (response, TRUE);
          return NULL;
        }
    }
  g_string_append (response,
                   "</objects></get_active_directory_objects_response>");
  return response;
}

/**
 * @brief Execute the get_active_directory_objects command.
 * @param[in]  gmp_parser  current instance of GMP parser.
 * @param[in]  error       error information.
 *
 */
static void
get_active_directory_objects_run (gmp_parser_t *gmp_parser, GError **error)
{
  context_data_t *context = get_active_directory_objects_data.context;
  entity_t root = context && context->first
                    ? context->first->data : NULL;
  get_ad_objects_result_t result = {0};
  get_ad_objects_return_t ret;
  GString *response = NULL;
  const gchar *parse_error;
  const gchar *error_response
    = XML_INTERNAL_ERROR ("get_active_directory_objects");

  get_ad_objects_params_t request = {
    .scope = AD_CONNECTOR_SEARCH_SCOPE_ONELEVEL,
    .object_types = AD_OBJECT_TYPE_ALL,
    .max_results = AD_OBJECTS_DEFAULT_MAX_RESULTS,
    .include_disabled_computers = TRUE,
    .targets = FALSE,
    .tasks = FALSE,
    .details = FALSE,
  };

  if (!parse_get_active_directory_objects (root, &request, &parse_error))
    {
      response = g_string_new (NULL);
      buffer_xml_append_printf (
        response,
        "<get_active_directory_objects_response status=\"" STATUS_ERROR_SYNTAX
        "\" status_text=\"%s\"/>", parse_error);
      goto send;
    }

  ret = get_active_directory_objects (&request, &result);
  if (ret == GET_AD_OBJECTS_OK)
    {
      response = buffer_active_directory_objects_xml (&result,
                                                      request.details,
                                                      request.include_disabled_computers);
      goto send;
    }

  switch (ret)
    {
    case GET_AD_OBJECTS_INVALID_INPUT:
      error_response = XML_ERROR_SYNTAX (
        "get_active_directory_objects",
        "Invalid Active Directory search request");
      break;
    case GET_AD_OBJECTS_INVALID_TYPE:
      error_response = XML_ERROR_SYNTAX (
        "get_active_directory_objects",
        "Credential is not an Active Directory credential");
      break;
    case GET_AD_OBJECTS_INVALID_STORED_CONFIGURATION:
      error_response = XML_ERROR_SYNTAX (
        "get_active_directory_objects",
        "Stored Active Directory credential configuration is invalid");
      break;
    case GET_AD_OBJECTS_PERMISSION_DENIED:
      error_response = XML_ERROR_ACCESS ("get_active_directory_objects");
      break;
    case GET_AD_OBJECTS_NOT_FOUND:
      error_response = XML_ERROR_MISSING ("get_active_directory_objects");
      break;
    case GET_AD_OBJECTS_CONNECTION_FAILED:
      error_response = XML_ERROR_UNAVAILABLE (
        "get_active_directory_objects",
        "Could not connect to Active Directory");
      break;
    case GET_AD_OBJECTS_BIND_FAILED:
      error_response = XML_ERROR_UNAVAILABLE (
        "get_active_directory_objects",
        "Active Directory bind failed");
      break;
    case GET_AD_OBJECTS_SEARCH_FAILED:
      error_response = XML_ERROR_UNAVAILABLE (
        "get_active_directory_objects",
        "Active Directory search failed");
      break;
    case GET_AD_OBJECTS_FEATURE_DISABLED:
      error_response = XML_ERROR_SYNTAX (
        "get_active_directory_objects",
        "Active Directory integration is disabled");
      break;
    case GET_AD_OBJECTS_RESULT_FAILED:
    case GET_AD_OBJECTS_INTERNAL_ERROR:
    default:
      error_response = XML_INTERNAL_ERROR ("get_active_directory_objects");
      break;
    }

send:
  if (send_to_client (response ? response->str : error_response,
                      gmp_parser->client_writer,
                      gmp_parser->client_writer_data))
    error_send_to_client (error);

  if (response)
    g_string_free (response, TRUE);

  get_ad_objects_result_reset (&result);
  get_active_directory_objects_reset ();
}

/**
 * @brief Handle the end of the GET_ACTIVE_DIRECTORY_OBJECTS element.
 *
 * @param[in]  gmp_parser  current instance of GMP parser.
 * @param[in]  error       error information.
 * @param[in]  name        the name of the element.
 *
 * @return 1 if the element is fully processed, 0 otherwise.
 */
int
get_active_directory_objects_element_end (gmp_parser_t *gmp_parser,
                                          GError **error,
                                          const gchar *name)
{
  context_data_t *context = get_active_directory_objects_data.context;

  xml_handle_end_element (context, name);
  if (!context->done)
    return 0;

  get_active_directory_objects_run (gmp_parser, error);
  return 1;
}

