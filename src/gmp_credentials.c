/* Copyright (C) 2009-2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM GMP layer: Credentials.
 *
 * GMP Handlers for reading, creating, modifying and deleting credentials.
 */

#include "gmp_credentials.h"
#include "gmp_base.h"
#include "manage_credentials.h"
#include "manage.h"

#include <string.h>

#include <gvm/util/xmlutils.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md    gmp"

/* CREATE_CREDENTIAL */

/**
 * @brief The create_credential command
 */
typedef struct
{
  context_data_t *context;     ///< XML parser context.
} create_credential_t;

/**
 * @brief Data used by parser to handle create_credential command
 */
static create_credential_t create_credential_data;

/**
 * @brief Resets create_credential command data.
 */
static void
create_credential_reset ()
{
  if (create_credential_data.context
      && create_credential_data.context->first)
    {
      free_entity (create_credential_data.context->first->data);
      g_slist_free_1 (create_credential_data.context->first);
    }

  g_free (create_credential_data.context);
  memset (&create_credential_data, 0, sizeof (create_credential_t));
}

/**
 * @brief Start the create_credential command
 *
 * @param[in] gmp_parser       current instance of GMP parser.
 * @param[in] attribute_names  All attribute names.
 * @param[in] attribute_values All attribute values.
 */
void
create_credential_start (gmp_parser_t *gmp_parser,
                         const gchar **attribute_names,
                         const gchar **attribute_values)
{
  memset (&create_credential_data, 0, sizeof (create_credential_t));
  create_credential_data.context = g_malloc0 (sizeof (context_data_t));
  create_credential_element_start (gmp_parser, "create_credential",
                                    attribute_names, attribute_values);
}

/**
 * @brief Start an element of the create_credential command
 *
 * @param[in]  gmp_parser        current instance of GMP parser.
 * @param[in]  name              name of element being started.
 * @param[in]  attribute_names   All attribute names.
 * @param[in]  attribute_values  All attribute values.
 */
void
create_credential_element_start (gmp_parser_t *gmp_parser,
                                 const gchar *name,
                                 const gchar **attribute_names,
                                 const gchar **attribute_values)
{
  xml_handle_start_element (create_credential_data.context, name,
                            attribute_names, attribute_values);
}

/**
 * @brief Get the text content of a child element.
 *
 * @param[in]  parent  The parent entity.
 * @param[in]  name    The name of the child element.
 *
 * @return A newly allocated string containing the text content,
 *         or NULL if the child does not exist.
 */
static char *
credential_child_text (entity_t parent, const gchar *name)
{
  entity_t child = parent ? entity_child (parent, name) : NULL;
  const char *value;

  if (child == NULL)
    return NULL;

  value = entity_text (child);
  return g_strdup (value ? value : "");
}

/**
 * @brief Parse a credential entry from the given entity.
 *
 * @param[in]  entity           Root credential entity.
 * @param[out] data             The structure to populate.
 */
static void
parse_credential_entity (entity_t root, credential_data_t *data)
{
  entity_t key, privacy, kdcs;

  memset (data, 0, sizeof (*data));

  data->name = credential_child_text (root, "name");
  data->comment = credential_child_text (root, "comment");
  data->login = credential_child_text (root, "login");
  data->password = credential_child_text (root, "password");
  data->certificate = credential_child_text (root, "certificate");
  data->community = credential_child_text (root, "community");
  data->auth_algorithm = credential_child_text (root, "auth_algorithm");
  data->kdc = credential_child_text (root, "kdc");
  data->realm = credential_child_text (root, "realm");
  data->type = credential_child_text (root, "type");
  data->allow_insecure = credential_child_text (root, "allow_insecure");

  key = entity_child (root, "key");
  data->key_present = key != NULL;
  data->key_private = credential_child_text (key, "private");
  data->key_public = credential_child_text (key, "public");
  data->key_phrase = credential_child_text (key, "phrase");

  privacy = entity_child (root, "privacy");
  data->privacy_password = credential_child_text (privacy, "password");
  data->privacy_algorithm = credential_child_text (privacy, "algorithm");

  kdcs = entity_child (root, "kdcs");
  if (kdcs)
    {
      GSList *entry;
      data->kdcs = make_array ();

      for (entry = kdcs->entities; entry; entry = g_slist_next (entry))
        {
          entity_t kdc_entry = entry->data;
          if (strcmp (entity_name (kdc_entry), "kdc") == 0)
            {
              const char *value = entity_text (kdc_entry);
              array_add (data->kdcs, g_strdup (value ? value : ""));
            }
        }
    }

#if ENABLE_CREDENTIAL_STORES
  data->credential_store_id
    = credential_child_text (root, "credential_store_id");
  data->vault_id
    = credential_child_text (root, "vault_id");
  data->host_identifier
    = credential_child_text (root, "host_identifier");
  data->privacy_host_identifier
    = credential_child_text (root, "privacy_host_identifier");
#endif
}

/**
 * @brief Returns a human-readable error message for a given
 *        credential response code.
 *
 * @param response The credential response code.
 *
 * @return A human-readable error message corresponding to the
 *         response code or NULL otherwise.
 */
static const gchar *
credential_error_status_text (credential_return_t response)
{
  switch (response)
    {
      case CREDENTIAL_INTERNAL_ERROR:
        return "Internal error";

      case CREDENTIAL_PERMISSION_DENIED:
        return "Permission denied";

      case CREDENTIAL_NOT_FOUND:
        return "Credential not found";

      case CREDENTIAL_NAME_REQUIRED:
        return "Name must be at least one character long";

      case CREDENTIAL_NAME_ALREADY_EXISTS:
        return "Credential name exists already";

      case CREDENTIAL_CREDENTIAL_ID_REQUIRED:
        return "A credential_id is required";

      case CREDENTIAL_INVALID_LOGIN:
        return "Login may only contain alphanumeric characters"
               " or the following - _ \\ . @";

      case CREDENTIAL_UNSUPPORTED_TYPE:
        return "Erroneous credential type";

      case CREDENTIAL_TYPE_UNDETERMINED:
        return "Type undetermined";

      case CREDENTIAL_AUTOGENERATION_NOT_SUPPORTED:
        return "Selected type cannot be generated automatically";

      case CREDENTIAL_LOGIN_REQUIRED:
        return "Selected type requires a login username";

      case CREDENTIAL_PASSWORD_REQUIRED:
        return "Selected type requires a password";

      case CREDENTIAL_PRIVATE_KEY_REQUIRED:
        return "Selected type requires a private key";

      case CREDENTIAL_PUBLIC_KEY_REQUIRED:
        return "Selected type requires a public key";

      case CREDENTIAL_CERTIFICATE_REQUIRED:
        return "Selected type requires a certificate";

      case CREDENTIAL_INVALID_PRIVATE_KEY_OR_PASSPHRASE:
        return "Erroneous private key or associated passphrase";

      case CREDENTIAL_INVALID_PUBLIC_KEY:
        return "Erroneous Public Key";

      case CREDENTIAL_INVALID_CERTIFICATE:
        return "Erroneous Certificate.";

      case CREDENTIAL_SNMP_AUTHENTICATION_REQUIRED:
        return "Selected type requires a community and/or username + password";

      case CREDENTIAL_SNMP_AUTH_ALGORITHM_REQUIRED:
        return "Selected type requires an auth_algorithm";

      case CREDENTIAL_SNMP_PRIVACY_ALGORITHM_REQUIRED:
        return "Selected type requires an"
               " algorithm in the privacy element"
               " if a password is given";

      case CREDENTIAL_INVALID_SNMP_AUTH_ALGORITHM:
        return "Auth algorithm must be 'md5' or 'sha1'";

      case CREDENTIAL_INVALID_SNMP_PRIVACY_ALGORITHM:
        return "Privacy algorithm must be 'aes', 'des' or empty";

      case CREDENTIAL_KDC_REQUIRED:
        return "Selected type requires a kdc";

      case CREDENTIAL_INVALID_KDC:
        return "Invalid KDC value(s)";

      case CREDENTIAL_REALM_REQUIRED:
        return "Selected type requires a realm";

      case CREDENTIAL_INVALID_REALM:
        return "Invalid kerberos realm value";

      case CREDENTIAL_CREDENTIAL_STORE_ID_REQUIRED:
        return "Credential store ID missing and no default store available";

      case CREDENTIAL_CREDENTIAL_STORE_NOT_FOUND:
        return "Credential store cannot be found";

      case CREDENTIAL_CREDENTIAL_STORE_UNAVAILABLE:
        return "Credential store unavailable";

      case CREDENTIAL_VAULT_ID_REQUIRED:
        return "Vault ID missing";

      case CREDENTIAL_HOST_IDENTIFIER_REQUIRED:
        return "Host identifier missing";

      case CREDENTIAL_MIXED_CREDENTIAL_SOURCES:
        return "Value cannot be modified for credential store type";

      default:
        return NULL;
    }
}

/**
* @brief Creates an XML error response for a given credential error code.
*
* @param command      The command name to include in the XML response.
* @param return_code  The credential return code.
*
* @return A newly allocated string containing the XML error response.
*         Should be freed by the caller using g_free().
*/
static gchar *
credential_error_response (const gchar *command,
                           credential_return_t return_code)
{
  const gchar *text;

  if (return_code == CREDENTIAL_INTERNAL_ERROR)
   {
     return g_markup_printf_escaped (
       "<%s_response status=\"%s\" status_text=\"%s\"/>",
       command,
       STATUS_INTERNAL_ERROR,
       STATUS_INTERNAL_ERROR_TEXT);
   }

  text = credential_error_status_text (return_code);
  if (text == NULL)
    {
     return g_markup_printf_escaped (
       "<%s_response status=\"%s\" status_text=\"%s\"/>",
       command,
       STATUS_INTERNAL_ERROR,
       STATUS_INTERNAL_ERROR_TEXT);
    }

  return g_markup_printf_escaped (
    "<%s_response status=\"%s\" status_text=\"%s\"/>",
    command,
    STATUS_ERROR_SYNTAX,
    text);
}

/**
 * @brief Execute the create_credential command
 *
 * @param[in] gmp_parser  current instance of GMP parser.
 * @param[in] error       the errors, if any.
 */
static void
create_credential_run (gmp_parser_t *gmp_parser, GError **error)
{
  credential_data_t data = { 0 };
  entity_t root, copy;
  credential_t new_credential = 0;
  gchar *response = NULL;
  gchar *uuid = NULL;
  credential_return_t ret;
  gboolean created = FALSE;

  root = (entity_t) create_credential_data.context->first->data;
  copy = entity_child (root, "copy");

  if (copy)
  {
    const gchar *copy_id;
    entity_t name;
    entity_t comment;

    copy_id = entity_text (copy);
    name = entity_child (root, "name");
    comment = entity_child (root, "comment");

    ret = copy_credential (name ? entity_text (name) : NULL,
                           comment ? entity_text (comment) : NULL,
                           copy_id,
                           &new_credential);

    created = ret == CREDENTIAL_OK;

    if (created)
      {
        uuid = credential_uuid (new_credential);
        response = g_markup_printf_escaped (
          XML_OK_CREATED_ID ("create_credential"), uuid);
      }
    else if (ret == CREDENTIAL_NOT_FOUND)
      {
        response = g_markup_printf_escaped (
          "<create_credential_response"
          " status=\"" STATUS_ERROR_MISSING "\""
          " status_text=\"Failed to find credential '%s'\"/>",
          copy_id ? copy_id : "");
      }
    else
      {
        response = credential_error_response ("create_credential", ret);
      }

    goto cleanup;
  }

  parse_credential_entity (root, &data);

  if (data.name == NULL || data.name[0] == '\0')
    {
      response = g_strdup (
        XML_ERROR_SYNTAX ("create_credential",
                          "Name must be at least one character long"));
      goto cleanup;
    }
  if (data.key_present
      && data.key_private == NULL
      && data.key_public == NULL)
    {
      response = g_strdup (
        XML_ERROR_SYNTAX ("create_credential",
                          "KEY requires a PRIVATE or PUBLIC key"));
      goto cleanup;
    }

  ret = create_credential (&data, &new_credential);
  created = (ret == CREDENTIAL_OK);

  if (created)
    {
      uuid = credential_uuid (new_credential);
      response = g_markup_printf_escaped (
        XML_OK_CREATED_ID ("create_credential"), uuid);
    }
  else
    response = credential_error_response ("create_credential", ret);

cleanup:
  credential_data_reset (&data);
  create_credential_reset ();

  if (response
      && send_to_client (response,
                         gmp_parser->client_writer,
                         gmp_parser->client_writer_data))
    error_send_to_client (error);

  if (created)
    log_event ("credential", "Credential", uuid, "created");
  else
    log_event_fail ("credential", "Credential", uuid, "created");

  g_free (response);
  g_free (uuid);
}

/**
 * @brief End element in create_credential command
 *
 * @param[in] gmp_parser  The current GMP parser instance
 * @param[in] error       the errors, if any
 * @param[in] name        name of element
 *
 * @return 1 if the command ran successfully, 0 otherwise
 */
int
create_credential_element_end (gmp_parser_t *gmp_parser, GError **error,
                                const gchar *name)
{
  xml_handle_end_element (create_credential_data.context, name);
  if (create_credential_data.context->done)
  {
    create_credential_run (gmp_parser, error);
    return 1;
  }
  return 0;
}

/**
 * @brief Add text to element in create_credential command
 *
 * @param[in] text      the text to add.
 * @param[in] text_len  the length of the text being added
 */
void
create_credential_element_text (const gchar *text, gsize text_len)
{
  xml_handle_text (create_credential_data.context, text, text_len);
}

/* MODIFY_CREDENTIAL */

/**
 * @brief data for `<modify_credential>` command
 */
typedef struct
{
  context_data_t *context;     ///< XML parser context.
} modify_credential_data_t;

/**
 * @brief Parser `<modify_credential>` callback data.
 */
static modify_credential_data_t modify_credential_data;

/**
 * @brief Reset command data.
 */
static void
modify_credential_reset ()
{
  if (modify_credential_data.context
      && modify_credential_data.context->first)
    {
      free_entity (modify_credential_data.context->first->data);
      g_slist_free_1 (modify_credential_data.context->first);
    }

  g_free (modify_credential_data.context);
  memset (&modify_credential_data, 0, sizeof (modify_credential_data_t));
}

/**
 * @brief Start the element in the `<modify_credential>` command.
 *
 * @param[in] gmp_parser       Active GMP parser instance.
 * @param[in] name             Name of the XML element being parsed.
 * @param[in] attribute_names  Null-terminated array of attribute names.
 * @param[in] attribute_values Null-terminated array of attribute values.
 */
void
modify_credential_element_start (gmp_parser_t *gmp_parser,
                                  const gchar *name,
                                  const gchar **attribute_names,
                                  const gchar **attribute_values)
{
  xml_handle_start_element (modify_credential_data.context,
                            name,
                            attribute_names,
                            attribute_values);
}

/**
 * @brief Initialize the ``<modify_credential>`` GMP command.
 *
 * @param[in] gmp_parser        Active GMP parser instance.
 * @param[in] attribute_names   Null-terminated array of attribute names.
 * @param[in] attribute_values  Null-terminated array of attribute names.
 */
void
modify_credential_start (gmp_parser_t *gmp_parser,
                          const gchar **attribute_names,
                          const gchar **attribute_values)
{
  memset (&modify_credential_data, 0, sizeof (modify_credential_data_t));
  modify_credential_data.context = g_malloc0 (sizeof (context_data_t));

  modify_credential_element_start (gmp_parser, "modify_credential",
                                    attribute_names, attribute_values);
}

/**
 * @brief Add text to element for modify_credential.
 *
 * @param[in]  text         Text.
 * @param[in]  text_len     Text length.
 */
void
modify_credential_element_text (const gchar *text, gsize text_len)
{
  xml_handle_text (modify_credential_data.context, text, text_len);
}

/**
 * @brief Execute the `<modify_credential>` GMP command.
 *
 * @param[in] gmp_parser  Active GMP parser instance.
 * @param[in] error       the errors, if any.
 */
static void
modify_credential_run (gmp_parser_t *gmp_parser, GError **error)
{
  credential_data_t data = { 0 };
  entity_t root;
  gchar *response = NULL;
  credential_return_t ret;

  root = (entity_t) modify_credential_data.context->first->data;

  parse_credential_entity (root, &data);

  /* Preserve legacy code behavior for <privacy/> */
  if (entity_child (root, "privacy") != NULL
      && data.privacy_algorithm == NULL)
    data.privacy_algorithm = g_strdup ("");

  data.credential_id = g_strdup(entity_attribute (root, "credential_id"));

  ret = modify_credential (&data);

  if (ret == CREDENTIAL_OK)
    response = g_strdup (XML_OK ("modify_credential"));
  else if (ret == CREDENTIAL_NOT_FOUND)
   {
      if (send_find_error_to_client ("modify_credential", "credential",
                                     data.credential_id, gmp_parser))
        error_send_to_client (error);
      else
        log_event_fail ("credential", "Credential", data.credential_id,
                        "modified");

      goto cleanup;
   }
  else
   response = credential_error_response ("modify_credential", ret);

  if (response
      && send_to_client (response,
                         gmp_parser->client_writer,
                         gmp_parser->client_writer_data))
    error_send_to_client (error);

  if (ret == CREDENTIAL_OK)
    log_event ("credential", "Credential", data.credential_id, "modified");
  else
    log_event_fail ("credential", "Credential", data.credential_id, "modified");

cleanup:
  credential_data_reset (&data);
  g_free (response);
  modify_credential_reset ();
}

/**
 * @brief End the XML element within the `<modify_credential>` command.
 *
 * @param[in] gmp_parser  Active GMP parser instance
 * @param[in] error       The errors, if any
 * @param[in] name        Name of the XML element that ended.
 *
 * @return 1 if the command ran successfully, 0 otherwise
 */
int
modify_credential_element_end (gmp_parser_t *gmp_parser, GError **error,
                                const gchar *name)
{
  xml_handle_end_element (modify_credential_data.context, name);
  if (modify_credential_data.context->done)
  {
    modify_credential_run (gmp_parser, error);
    return 1;
  }
  return 0;
}
