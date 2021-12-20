/* Copyright (C) 2009-2022 Greenbone Networks GmbH
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @file  gmp.c
 * @brief The Greenbone Vulnerability Manager GMP library.
 *
 * This file defines a Greenbone Management Protocol (GMP) library, for
 * implementing managers such as the Greenbone Vulnerability Manager
 * daemon.
 *
 * The library provides \ref process_gmp_client_input.
 * This function parses a given string of GMP XML and tracks and manipulates
 * tasks in reaction to the GMP commands in the string.
 */

/**
 * @internal
 * The GMP-"Processor" is always in a state (\ref client_state_t
 * \ref client_state ) and currently looking at the opening of a GMP element
 * (\ref gmp_xml_handle_start_element ), at the text of a GMP element
 * (\ref gmp_xml_handle_text ) or at the closing of a GMP element
 * (\ref gmp_xml_handle_end_element ).
 *
 * The state usually represents the current location of the parser within the
 * XML (GMP) tree.  There has to be one state for every GMP element.
 *
 * State transitions occur in the start and end element handler callbacks.
 *
 * Generally, the strategy is to wait until the closing of an element before
 * doing any action or sending a response.  Also, error cases are to be detected
 * in the end element handler.
 *
 * If data has to be stored, it goes to \ref command_data (_t) , which is a
 * union.
 * More specific incarnations of this union are e.g. \ref create_user_data (_t)
 * , where the data to create a new user is stored (until the end element of
 * that command is reached).
 *
 * For implementing new commands that have to store data (e.g. not
 * "\<help_extended/\>"), \ref command_data has to be freed and NULL'ed in case
 * of errors and the \ref current_state has to be reset.
 * It can then be assumed that it is NULL'ed at the start of every new
 * command element.  To implement a new start element handler, be sure to just
 * copy an existing case and keep its structure.
 *
 * Attributes are easier to implement than elements.
 * E.g.
 * @code
 * <key_value_pair key="k" value="v"/>
 * @endcode
 * is obviously easier to handle than
 * @code
 * <key><attribute name="k"/><value>v</value></key>
 * @endcode
 * .
 * For this reason the GET commands like GET_TASKS all use attributes only.
 *
 * However, for the other commands it is preferred to avoid attributes and use
 * the text of elements
 * instead, like in
 * @code
 * <key_value_pair><key>k</key><value>v</value></key_value_pair>
 * @endcode
 * .
 *
 * If new elements are built of multiple words, separate the words with an
 * underscore.
 */

#include "gmp.h"
#include "gmp_base.h"
#include "gmp_delete.h"
#include "gmp_get.h"
#include "gmp_configs.h"
#include "gmp_license.h"
#include "gmp_port_lists.h"
#include "gmp_report_formats.h"
#include "gmp_tickets.h"
#include "gmp_tls_certificates.h"
#include "manage.h"
#include "manage_acl.h"
#include "manage_port_lists.h"
#include "manage_report_formats.h"
#include "utils.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <glib/gstdio.h>
#include <math.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <gnutls/x509.h>

#include <gvm/base/strings.h>
#include <gvm/base/logging.h>
#include <gvm/base/pwpolicy.h>
#include <gvm/util/gpgmeutils.h>
#include <gvm/util/fileutils.h>
#include <gvm/util/sshutils.h>
#include <gvm/util/authutils.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md    gmp"


/* Static headers. */

/** @todo Exported for manage_sql.c. */
void
buffer_results_xml (GString *, iterator_t *, task_t, int, int, int, int, int,
                    int, int, const char *, iterator_t *, int, int, int);


/* Helper functions. */

/**
 * @brief A simple key/value-pair.
 */
typedef struct
{
  gchar *key;                   ///< The key.
  gchar *value;                 ///< The value.
} auth_conf_setting_t;

/**
 * @brief Check that a string represents a valid x509 Certificate.
 *
 * @param[in]  cert_str     Certificate string.
 *
 * @return 0 if valid, 1 otherwise.
 */
static int
check_certificate_x509 (const char *cert_str)
{
  gnutls_x509_crt_t crt;
  gnutls_datum_t data;
  int ret = 0;

  assert (cert_str);
  if (gnutls_x509_crt_init (&crt))
    return 1;
  data.size = strlen (cert_str);
  data.data = (void *) g_strdup (cert_str);
  if (gnutls_x509_crt_import (crt, &data, GNUTLS_X509_FMT_PEM))
    {
      gnutls_x509_crt_deinit (crt);
      g_free (data.data);
      return 1;
    }

  if (time (NULL) > gnutls_x509_crt_get_expiration_time (crt))
    {
      g_warning ("Certificate expiration time passed");
      ret = 1;
    }
  if (time (NULL) < gnutls_x509_crt_get_activation_time (crt))
    {
      g_warning ("Certificate activation time in the future");
      ret = 1;
    }
  g_free (data.data);
  gnutls_x509_crt_deinit (crt);
  return ret;
}

/**
 * @brief Check that a string represents a valid public key or certificate.
 *
 * @param[in]  key_str     Key string.
 * @param[in]  key_types   GArray of the data types to check for.
 * @param[in]  protocol    The GPG protocol to check.
 *
 * @return 0 if valid, 1 otherwise.
 */
static int
try_gpgme_import (const char *key_str, GArray *key_types,
                  gpgme_protocol_t protocol)
{
  int ret = 0;
  gpgme_ctx_t ctx;
  char gpg_temp_dir[] = "/tmp/gvmd-gpg-XXXXXX";

  if (mkdtemp (gpg_temp_dir) == NULL)
    {
      g_warning ("%s: mkdtemp failed", __func__);
      return -1;
    }

  gpgme_new (&ctx);
  gpgme_ctx_set_engine_info (ctx, protocol, NULL, gpg_temp_dir);
  gpgme_set_protocol (ctx, protocol);

  ret = gvm_gpg_import_many_types_from_string (ctx, key_str, -1, key_types);

  gpgme_release (ctx);
  gvm_file_remove_recurse (gpg_temp_dir);

  return ret != 0;
}

/**
 * @brief Check that a string represents a valid S/MIME Certificate.
 *
 * @param[in]  cert_str     Certificate string.
 *
 * @return 0 if valid, 1 otherwise.
 */
static int
check_certificate_smime (const char *cert_str)
{
  int ret;
  const gpgme_data_type_t types_ptr[2] = {GPGME_DATA_TYPE_X509_CERT,
                                          GPGME_DATA_TYPE_CMS_OTHER};
  GArray *key_types = g_array_new (FALSE, FALSE, sizeof (gpgme_data_type_t));

  g_array_append_vals (key_types, types_ptr, 2);
  ret = try_gpgme_import (cert_str, key_types, GPGME_PROTOCOL_CMS);
  g_array_free (key_types, TRUE);

  return ret;
}

/**
 * @brief Check that a string represents a valid certificate.
 *
 * The type of certificate accepted depends on the credential_type.
 *
 * @param[in]  cert_str         Certificate string.
 * @param[in]  credential_type  The credential type to assume.
 *
 * @return 0 if valid, 1 otherwise.
 */
static int
check_certificate (const char *cert_str, const char *credential_type)
{
  if (credential_type && strcmp (credential_type, "smime") == 0)
    return check_certificate_smime (cert_str);
  else
    return check_certificate_x509 (cert_str);
}

/**
 * @brief Check that a string represents a valid Public Key.
 *
 * @param[in]  key_str  Public Key string.
 *
 * @return 0 if valid, 1 otherwise.
 */
static int
check_public_key (const char *key_str)
{
  int ret;
  const gpgme_data_type_t types_ptr[1] = {GPGME_DATA_TYPE_PGP_KEY};
  GArray *key_types = g_array_new (FALSE, FALSE, sizeof (gpgme_data_type_t));

  g_array_append_vals (key_types, types_ptr, 1);
  ret = try_gpgme_import (key_str, key_types, GPGME_PROTOCOL_OPENPGP);
  g_array_free (key_types, TRUE);

  return ret;
}


/* GMP parser. */

static int
process_gmp (gmp_parser_t *, const gchar *, gchar **);

/**
 * @brief Create a GMP parser.
 *
 * @param[in]  write_to_client       Function to write to client.
 * @param[in]  write_to_client_data  Argument to \p write_to_client.
 * @param[in]  disable               Commands to disable.  Copied, and freed by
 *                                   gmp_parser_free.
 *
 * @return A GMP parser.
 */
static gmp_parser_t *
gmp_parser_new (int (*write_to_client) (const char*, void*), void* write_to_client_data,
                gchar **disable)
{
  gmp_parser_t *gmp_parser = (gmp_parser_t*) g_malloc0 (sizeof (gmp_parser_t));
  gmp_parser->client_writer = write_to_client;
  gmp_parser->client_writer_data = write_to_client_data;
  gmp_parser->read_over = 0;
  gmp_parser->disabled_commands = g_strdupv (disable);
  return gmp_parser;
}

/**
 * @brief Free a GMP parser.
 *
 * @param[in]  gmp_parser  GMP parser.
 */
static void
gmp_parser_free (gmp_parser_t *gmp_parser)
{
  g_strfreev (gmp_parser->disabled_commands);
  g_free (gmp_parser);
}

/**
 * @brief Check if command has been disabled.
 *
 * @param[in]  gmp_parser  Parser.
 * @param[in]  name        Command name.
 *
 * @return 1 disabled, 0 enabled.
 */
static int
command_disabled (gmp_parser_t *gmp_parser, const gchar *name)
{
  gchar **disabled;
  disabled = gmp_parser->disabled_commands;
  if (disabled)
    while (*disabled)
      {
        if (strcasecmp (*disabled, name) == 0)
          return 1;
        disabled++;
      }
  return 0;
}


/* Command data passed between parser callbacks. */

/**
 * @brief Command data for the create_asset command.
 */
typedef struct
{
  char *name;                  ///< Name of asset.
  char *comment;               ///< Comment on asset.
  char *filter_term;           ///< Filter term, for report.
  char *report_id;             ///< Report UUID.
  char *type;                  ///< Type of asset.
} create_asset_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
create_asset_data_reset (create_asset_data_t *data)
{
  free (data->comment);
  free (data->filter_term);
  free (data->report_id);
  free (data->type);
  free (data->name);

  memset (data, 0, sizeof (create_asset_data_t));
}

/**
 * @brief Command data for the create_alert command.
 *
 * The pointers in the *_data arrays point to memory that contains two
 * strings concatenated, with a single \\0 between them.  The first string
 * is the name of the extra data (for example "To Address"), the second is
 * the value the the data (for example "alice@example.org").
 */
typedef struct
{
  char *active;              ///< Whether the alert is active.
  char *comment;             ///< Comment.
  char *copy;                ///< UUID of alert to copy.
  char *condition;           ///< Condition for alert, e.g. "Always".
  array_t *condition_data;   ///< Array of pointers.  Extra data for condition.
  char *event;               ///< Event that will cause alert.
  array_t *event_data;       ///< Array of pointers.  Extra data for event.
  char *filter_id;           ///< UUID of filter.
  char *method;              ///< Method of alert, e.g. "Email".
  array_t *method_data;      ///< Array of pointer.  Extra data for method.
  char *name;                ///< Name of alert.
  char *part_data;           ///< Second part of data during *_data: value.
  char *part_name;           ///< First part of data during *_data: name.
} create_alert_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
create_alert_data_reset (create_alert_data_t *data)
{
  free (data->active);
  free (data->comment);
  free (data->copy);
  free (data->condition);
  array_free (data->condition_data);
  free (data->event);
  array_free (data->event_data);
  free (data->filter_id);
  free (data->method);
  array_free (data->method_data);
  free (data->name);
  free (data->part_data);
  free (data->part_name);

  memset (data, 0, sizeof (create_alert_data_t));
}

/**
 * @brief Command data for the create_credential command.
 */
typedef struct
{
  char *allow_insecure;    ///< Whether to allow insecure use.
  char *certificate;       ///< Certificate for client certificate auth.
  char *comment;           ///< Comment.
  char *copy;              ///< UUID of resource to copy.
  int key;                 ///< Whether the command included a key element.
  char *key_phrase;        ///< Passphrase for key.
  char *key_private;       ///< Private key from key.
  char *key_public;        ///< Public key from key.
  char *login;             ///< Login name.
  char *name;              ///< Credential name.
  char *password;          ///< Password associated with login name.
  char *community;         ///< SNMP Community string.
  char *auth_algorithm;    ///< SNMP Authentication algorithm.
  char *privacy_password;  ///< SNMP Privacy password.
  char *privacy_algorithm; ///< SNMP Privacy algorithm.
  char *type;              ///< Type of credential.
} create_credential_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
create_credential_data_reset (create_credential_data_t *data)
{
  free (data->allow_insecure);
  free (data->certificate);
  free (data->comment);
  free (data->copy);
  free (data->key_phrase);
  free (data->key_private);
  free (data->key_public);
  free (data->login);
  free (data->name);
  free (data->password);
  free (data->community);
  free (data->auth_algorithm);
  free (data->privacy_password);
  free (data->privacy_algorithm);
  free (data->type);

  memset (data, 0, sizeof (create_credential_data_t));
}

/**
 * @brief Command data for the create_filter command.
 */
typedef struct
{
  char *comment;                 ///< Comment.
  char *copy;                    ///< UUID of resource to copy.
  char *name;                    ///< Name of new filter.
  char *term;                    ///< Filter term.
  char *type;                    ///< Type of new filter.
} create_filter_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
create_filter_data_reset (create_filter_data_t *data)
{
  free (data->comment);
  free (data->copy);
  free (data->name);
  free (data->term);
  free (data->type);

  memset (data, 0, sizeof (create_filter_data_t));
}

/**
 * @brief Command data for the create_group command.
 */
typedef struct
{
  char *comment;                 ///< Comment.
  char *copy;                    ///< UUID of resource to copy.
  char *name;                    ///< Name of new group.
  char *users;                   ///< Users belonging to new group.
  int special_full;              ///< Boolean.  Give group Super on itself.
} create_group_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
create_group_data_reset (create_group_data_t *data)
{
  free (data->comment);
  free (data->copy);
  free (data->name);
  free (data->users);

  memset (data, 0, sizeof (create_group_data_t));
}

/**
 * @brief Command data for the create_note command.
 */
typedef struct
{
  char *active;       ///< Whether the note is active.
  char *copy;         ///< UUID of resource to copy.
  char *hosts;        ///< Hosts to which to limit override.
  char *nvt_oid;      ///< NVT to which to limit override.
  char *port;         ///< Port to which to limit override.
  char *result_id;    ///< ID of result to which to limit override.
  char *severity;     ///< Severity score to which to limit note.
  char *task_id;      ///< ID of task to which to limit override.
  char *text;         ///< Text of override.
  char *threat;       ///< Threat to which to limit override.
} create_note_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
create_note_data_reset (create_note_data_t *data)
{
  free (data->active);
  free (data->copy);
  free (data->hosts);
  free (data->nvt_oid);
  free (data->port);
  free (data->result_id);
  free (data->severity);
  free (data->task_id);
  free (data->text);
  free (data->threat);

  memset (data, 0, sizeof (create_note_data_t));
}

/**
 * @brief Command data for the create_override command.
 */
typedef struct
{
  char *active;       ///< Whether the override is active.
  char *copy;         ///< UUID of resource to copy.
  char *hosts;        ///< Hosts to which to limit override.
  char *new_threat;   ///< New threat value of overridden results.
  char *new_severity; ///< New severity score of overridden results.
  char *nvt_oid;      ///< NVT to which to limit override.
  char *port;         ///< Port to which to limit override.
  char *result_id;    ///< ID of result to which to limit override.
  char *severity;     ///< Severity score of results to override.
  char *task_id;      ///< ID of task to which to limit override.
  char *text;         ///< Text of override.
  char *threat;       ///< Threat to which to limit override.
} create_override_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
create_override_data_reset (create_override_data_t *data)
{
  free (data->active);
  free (data->copy);
  free (data->hosts);
  free (data->new_threat);
  free (data->new_severity);
  free (data->nvt_oid);
  free (data->port);
  free (data->result_id);
  free (data->task_id);
  free (data->text);
  free (data->threat);
  free (data->severity);

  memset (data, 0, sizeof (create_override_data_t));
}

/**
 * @brief Command data for the create_permission command.
 */
typedef struct
{
  char *comment;         ///< Comment.
  char *copy;            ///< UUID of resource to copy.
  char *name;            ///< Permission name.
  char *resource_type;   ///< Resource type, for special permissions.
  char *resource_id;     ///< Resource permission applies to.
  char *subject_type;    ///< Subject type permission applies to.
  char *subject_id;      ///< Subject permission applies to.
} create_permission_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
create_permission_data_reset (create_permission_data_t *data)
{
  free (data->comment);
  free (data->copy);
  free (data->name);
  free (data->resource_type);
  free (data->resource_id);
  free (data->subject_type);
  free (data->subject_id);

  memset (data, 0, sizeof (create_permission_data_t));
}

/**
 * @brief Command data for the create_port_range command.
 */
typedef struct
{
  char *comment;                 ///< Comment.
  char *end;                     ///< Last port.
  char *port_list_id;            ///< Port list for new port range.
  char *start;                   ///< First port.
  char *type;                    ///< Type of new port range.
} create_port_range_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
create_port_range_data_reset (create_port_range_data_t *data)
{
  free (data->comment);
  free (data->end);
  free (data->port_list_id);
  free (data->start);
  free (data->type);

  memset (data, 0, sizeof (create_port_range_data_t));
}

/**
 * @brief Command data for the create_report command.
 */
typedef struct
{
  char *detail_name;              ///< Name of current host detail.
  char *detail_value;             ///< Value of current host detail.
  char *detail_source_name;       ///< Name of source of current host detail.
  char *detail_source_type;       ///< Type of source of current host detail.
  char *detail_source_desc;       ///< Description of source of current detail.
  array_t *details;               ///< Host details.
  char *host_end;                 ///< End time for a host.
  char *host_end_host;            ///< Host name for end time.
  array_t *host_ends;             ///< All host ends.
  char *host_start;               ///< Start time for a host.
  char *host_start_host;          ///< Host name for start time.
  array_t *host_starts;           ///< All host starts.
  char *in_assets;                ///< Whether to create assets from report.
  char *ip;                       ///< Current host for host details.
  char *result_description;       ///< Description of NVT for current result.
  char *result_host;              ///< Host for current result.
  char *result_hostname;          ///< Hostname for current result.
  char *result_nvt_oid;           ///< OID of NVT for current result.
  char *result_port;              ///< Port for current result.
  char *result_qod;               ///< QoD value of current result.
  char *result_qod_type;          ///< QoD type of current result.
  char *result_scan_nvt_version;  ///< Version of NVT used in scan.
  char *result_severity;          ///< Severity score for current result.
  char *result_threat;            ///< Message type for current result.
  char *result_detection_name;    ///< Name of detection in result.
  char *result_detection_product; ///< product of detection in result.
  char *result_detection_source_name; ///< source_name of detection in result.
  char *result_detection_source_oid; ///< source_oid of detection in result.
  char *result_detection_location; ///< location of detection in result.
  array_t *result_detection;      ///< Detections for current result
  array_t *results;               ///< All results.
  char *scan_end;                 ///< End time for a scan.
  char *scan_start;               ///< Start time for a scan.
  char *task_id;                  ///< ID of container task.
  char *type;                     ///< Type of report.
  int wrapper;                    ///< Whether there was a wrapper REPORT.
} create_report_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
create_report_data_reset (create_report_data_t *data)
{
  if (data->details)
    {
      guint index = data->details->len;
      while (index--)
        {
          host_detail_t *detail;
          detail = (host_detail_t*) g_ptr_array_index (data->details, index);
          if (detail)
            host_detail_free (detail);
        }
      array_free (data->details);
    }
  free (data->host_end);
  if (data->host_ends)
    {
      guint index = data->host_ends->len;
      while (index--)
        {
          create_report_result_t *result;
          result = (create_report_result_t*) g_ptr_array_index
                                              (data->host_ends,
                                               index);
          if (result)
            {
              free (result->description);
              free (result->host);
            }
        }
      array_free (data->host_ends);
    }
  free (data->host_start);
  if (data->host_starts)
    {
      guint index = data->host_starts->len;
      while (index--)
        {
          create_report_result_t *result;
          result = (create_report_result_t*) g_ptr_array_index
                                              (data->host_starts,
                                               index);
          if (result)
            {
              free (result->description);
              free (result->host);
            }
        }
      array_free (data->host_starts);
    }
  free (data->in_assets);
  free (data->ip);
  free (data->result_description);
  free (data->result_host);
  free (data->result_hostname);
  free (data->result_nvt_oid);
  free (data->result_port);
  free (data->result_threat);
  if (data->results)
    {
      guint index = data->results->len;
      while (index--)
        {
          create_report_result_t *result;
          result = (create_report_result_t*) g_ptr_array_index (data->results,
                                                                index);
          if (result)
            {
              free (result->host);
              free (result->hostname);
              free (result->description);
              free (result->nvt_oid);
              free (result->port);
              free (result->qod);
              free (result->qod_type);
              free (result->scan_nvt_version);
              free (result->severity);
            }
        }
      array_free (data->results);
    }
  free (data->scan_end);
  free (data->scan_start);
  free (data->task_id);
  free (data->type);

  memset (data, 0, sizeof (create_report_data_t));
}

/**
 * @brief Command data for the create_role command.
 */
typedef struct
{
  char *comment;                 ///< Comment.
  char *copy;                    ///< UUID of resource to copy.
  char *name;                    ///< Name of new role.
  char *users;                   ///< Users belonging to new role.
} create_role_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
create_role_data_reset (create_role_data_t *data)
{
  free (data->comment);
  free (data->copy);
  free (data->name);
  free (data->users);

  memset (data, 0, sizeof (create_role_data_t));
}

/**
 * @brief Command data for the create_scanner command.
 */
typedef struct
{
  char *name;               ///< Name for new scanner.
  char *copy;               ///< UUID of scanner to copy.
  char *comment;            ///< Comment.
  char *host;               ///< Host of new scanner.
  char *port;               ///< Port of new scanner.
  char *type;               ///< Type of new scanner.
  char *ca_pub;             ///< CA Certificate of new scanner.
  char *credential_id;      ///< UUID of credential for new scanner.
} create_scanner_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
create_scanner_data_reset (create_scanner_data_t *data)
{
  free (data->name);
  free (data->copy);
  free (data->comment);
  free (data->host);
  free (data->port);
  free (data->type);
  free (data->ca_pub);
  free (data->credential_id);

  memset (data, 0, sizeof (create_scanner_data_t));
}

/**
 * @brief Command data for the create_schedule command.
 */
typedef struct
{
  char *name;                    ///< Name for new schedule.
  char *comment;                 ///< Comment.
  char *copy;                    ///< UUID of resource to copy.
  char *timezone;                ///< Time zone of the schedule
  char *icalendar;               ///< iCalendar string
} create_schedule_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
create_schedule_data_reset (create_schedule_data_t *data)
{
  free (data->name);
  free (data->copy);
  free (data->comment);
  free (data->timezone);
  free (data->icalendar);

  memset (data, 0, sizeof (create_schedule_data_t));
}

/**
 * @brief Command data for the create_target command.
 */
typedef struct
{
  char *alive_tests;                ///< Alive tests.
  char *allow_simultaneous_ips;     ///< Boolean. Whether to scan multiple IPs of a host simultaneously.
  char *asset_hosts_filter;         ///< Asset hosts.
  char *comment;                    ///< Comment.
  char *exclude_hosts;              ///< Hosts to exclude from set.
  char *reverse_lookup_only;        ///< Boolean. Whether to consider only hosts that reverse lookup.
  char *reverse_lookup_unify;       ///< Boolean. Whether to unify based on reverse lookup.
  char *copy;                       ///< UUID of resource to copy.
  char *hosts;                      ///< Hosts for new target.
  char *port_list_id;               ///< Port list for new target.
  char *port_range;                 ///< Port range for new target.
  char *ssh_credential_id;          ///< SSH credential for new target.
  char *ssh_lsc_credential_id;      ///< SSH credential (deprecated).
  char *ssh_elevate_credential_id;  ///< SSH elevation credential.
  char *ssh_port;                   ///< Port for SSH.
  char *ssh_lsc_port;               ///< Port for SSH (deprecated).
  char *smb_credential_id;          ///< SMB credential for new target.
  char *smb_lsc_credential_id;      ///< SMB credential (deprecated).
  char *esxi_credential_id;         ///< ESXi credential for new target.
  char *esxi_lsc_credential_id;     ///< ESXi credential (deprecated).
  char *snmp_credential_id;         ///< SNMP credential for new target.
  char *name;                       ///< Name of new target.
} create_target_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
create_target_data_reset (create_target_data_t *data)
{
  free (data->alive_tests);
  free (data->allow_simultaneous_ips);
  free (data->asset_hosts_filter);
  free (data->comment);
  free (data->exclude_hosts);
  free (data->reverse_lookup_only);
  free (data->reverse_lookup_unify);
  free (data->copy);
  free (data->hosts);
  free (data->port_list_id);
  free (data->port_range);
  free (data->ssh_credential_id);
  free (data->ssh_lsc_credential_id);
  free (data->ssh_elevate_credential_id);
  free (data->ssh_port);
  free (data->ssh_lsc_port);
  free (data->smb_credential_id);
  free (data->smb_lsc_credential_id);
  free (data->esxi_credential_id);
  free (data->esxi_lsc_credential_id);
  free (data->snmp_credential_id);
  free (data->name);

  memset (data, 0, sizeof (create_target_data_t));
}

/**
 * @brief Command data for the create_tag command.
 */
typedef struct
{
  char *active;           ///< Whether the tag is active.
  array_t *resource_ids;  ///< IDs of the resource to which to attach the tag.
  char *resource_type;    ///< Type of the resource to which to attach the tag.
  char *resources_filter; ///< Filter used to select resources.
  char *comment;          ///< Comment to add to the tag.
  char *name;             ///< Name of the tag.
  char *value;            ///< Value of the tag.
  char *copy;             ///< UUID of resource to copy.
} create_tag_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
create_tag_data_reset (create_tag_data_t *data)
{
  free (data->active);
  array_free (data->resource_ids);
  free (data->resource_type);
  free (data->resources_filter);
  free (data->comment);
  free (data->name);
  free (data->value);
  free (data->copy);
  memset (data, 0, sizeof (create_tag_data_t));
}

/**
 * @brief Command data for the create_task command.
 */
typedef struct
{
  char *alterable;      ///< Boolean.  Whether task is alterable.
  char *config_id;      ///< ID of task config.
  char *hosts_ordering; ///< Order for scanning target hosts.
  char *scanner_id;     ///< ID of task scanner.
  array_t *alerts;      ///< IDs of alerts.
  char *copy;           ///< UUID of resource to copy.
  array_t *groups;      ///< IDs of groups.
  char *name;           ///< Name of task.
  char *observers;      ///< Space separated names of observer users.
  name_value_t *preference;  ///< Current preference.
  array_t *preferences; ///< Preferences.
  char *schedule_id;    ///< ID of task schedule.
  char *schedule_periods; ///< Number of periods the schedule must run for.
  char *target_id;      ///< ID of task target.
  task_t task;          ///< ID of new task.
  char *usage_type;     ///< Usage type ("scan" or "audit")
} create_task_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
create_task_data_reset (create_task_data_t *data)
{
  free (data->alterable);
  free (data->config_id);
  free (data->hosts_ordering);
  free (data->scanner_id);
  free (data->copy);
  array_free (data->alerts);
  array_free (data->groups);
  free (data->name);
  free (data->observers);
  if (data->preferences)
    {
      guint index = data->preferences->len;
      while (index--)
        {
          name_value_t *pair;
          pair = (name_value_t*) g_ptr_array_index (data->preferences, index);
          if (pair)
            {
              g_free (pair->name);
              g_free (pair->value);
            }
        }
    }
  array_free (data->preferences);
  free (data->schedule_id);
  free (data->schedule_periods);
  free (data->target_id);
  free (data->usage_type);

  memset (data, 0, sizeof (create_task_data_t));
}

/* Command data passed between parser callbacks. */

/**
 * @brief Command data for the create_user command.
 */
typedef struct
{
  char *copy;             ///< UUID of resource to copy.
  array_t *groups;        ///< IDs of groups.
  char *hosts;            ///< Hosts.
  int hosts_allow;        ///< Whether hosts are allowed.
  char *name;             ///< User name.
  char *password;         ///< Password.
  char *comment;          ///< Comment.
  array_t *roles;         ///< User's roles.
  gchar *current_source;  ///< Current source, for collecting sources.
  array_t *sources;       ///< Sources.
} create_user_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
create_user_data_reset (create_user_data_t * data)
{
  g_free (data->copy);
  array_free (data->groups);
  g_free (data->name);
  g_free (data->password);
  g_free (data->comment);
  g_free (data->hosts);
  array_free (data->roles);
  if (data->sources)
    {
      array_free (data->sources);
    }
  g_free (data->current_source);
  memset (data, 0, sizeof (create_user_data_t));
}

/**
 * @brief Command data for the delete_asset command.
 */
typedef struct
{
  char *asset_id;   ///< ID of asset to delete.
  char *report_id;  ///< ID of report from which to delete assets.
  int ultimate;     ///< Dummy field for generic macros.
} delete_asset_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
delete_asset_data_reset (delete_asset_data_t *data)
{
  free (data->asset_id);
  free (data->report_id);

  memset (data, 0, sizeof (delete_asset_data_t));
}

/**
 * @brief Command data for the delete_config command.
 */
typedef struct
{
  char *config_id;   ///< ID of config to delete.
  int ultimate;      ///< Boolean.  Whether to remove entirely or to trashcan.
} delete_config_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
delete_config_data_reset (delete_config_data_t *data)
{
  free (data->config_id);

  memset (data, 0, sizeof (delete_config_data_t));
}

/**
 * @brief Command data for the delete_alert command.
 */
typedef struct
{
  char *alert_id;   ///< ID of alert to delete.
  int ultimate;     ///< Boolean.  Whether to remove entirely or to trashcan.
} delete_alert_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
delete_alert_data_reset (delete_alert_data_t *data)
{
  free (data->alert_id);

  memset (data, 0, sizeof (delete_alert_data_t));
}

/**
 * @brief Command data for the delete_credential command.
 */
typedef struct
{
  char *credential_id;   ///< ID of Credential to delete.
  int ultimate;      ///< Boolean.  Whether to remove entirely or to trashcan.
} delete_credential_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
delete_credential_data_reset (delete_credential_data_t *data)
{
  free (data->credential_id);

  memset (data, 0, sizeof (delete_credential_data_t));
}

/**
 * @brief Command data for the delete_filter command.
 */
typedef struct
{
  char *filter_id;   ///< ID of filter to delete.
  int ultimate;      ///< Boolean.  Whether to remove entirely or to trashcan.
} delete_filter_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
delete_filter_data_reset (delete_filter_data_t *data)
{
  free (data->filter_id);

  memset (data, 0, sizeof (delete_filter_data_t));
}

/**
 * @brief Command data for the delete_group command.
 */
typedef struct
{
  char *group_id;   ///< ID of group to delete.
  int ultimate;      ///< Boolean.  Whether to remove entirely or to trashcan.
} delete_group_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
delete_group_data_reset (delete_group_data_t *data)
{
  free (data->group_id);

  memset (data, 0, sizeof (delete_group_data_t));
}

/**
 * @brief Command data for the delete_note command.
 */
typedef struct
{
  char *note_id;   ///< ID of note to delete.
  int ultimate;    ///< Boolean.  Whether to remove entirely or to trashcan.
} delete_note_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
delete_note_data_reset (delete_note_data_t *data)
{
  free (data->note_id);

  memset (data, 0, sizeof (delete_note_data_t));
}

/**
 * @brief Command data for the delete_override command.
 */
typedef struct
{
  char *override_id;   ///< ID of override to delete.
  int ultimate;        ///< Boolean.  Whether to remove entirely or to trashcan.
} delete_override_data_t;

/**
 * @brief Command data for the delete_permission command.
 */
typedef struct
{
  char *permission_id; ///< ID of permission to delete.
  int ultimate;        ///< Boolean.  Whether to remove entirely or to trashcan.
} delete_permission_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
delete_permission_data_reset (delete_permission_data_t *data)
{
  free (data->permission_id);

  memset (data, 0, sizeof (delete_permission_data_t));
}

/**
 * @brief Command data for the delete_port_list command.
 */
typedef struct
{
  char *port_list_id;  ///< ID of port list to delete.
  int ultimate;        ///< Boolean.  Whether to remove entirely or to trashcan.
} delete_port_list_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
delete_port_list_data_reset (delete_port_list_data_t *data)
{
  free (data->port_list_id);

  memset (data, 0, sizeof (delete_port_list_data_t));
}

/**
 * @brief Command data for the delete_port_range command.
 */
typedef struct
{
  char *port_range_id;  ///< ID of port range to delete.
  int ultimate;         ///< Dummy field for generic macros.
} delete_port_range_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
delete_port_range_data_reset (delete_port_range_data_t *data)
{
  free (data->port_range_id);

  memset (data, 0, sizeof (delete_port_range_data_t));
}

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
delete_override_data_reset (delete_override_data_t *data)
{
  free (data->override_id);

  memset (data, 0, sizeof (delete_override_data_t));
}

/**
 * @brief Command data for the delete_report command.
 */
typedef struct
{
  char *report_id;   ///< ID of report to delete.
  int ultimate;      ///< Dummy field for generic macros.
} delete_report_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
delete_report_data_reset (delete_report_data_t *data)
{
  free (data->report_id);

  memset (data, 0, sizeof (delete_report_data_t));
}

/**
 * @brief Command data for the delete_report_format command.
 */
typedef struct
{
  char *report_format_id;   ///< ID of report format to delete.
  int ultimate;     ///< Boolean.  Whether to remove entirely or to trashcan.
} delete_report_format_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
delete_report_format_data_reset (delete_report_format_data_t *data)
{
  free (data->report_format_id);

  memset (data, 0, sizeof (delete_report_format_data_t));
}

/**
 * @brief Command data for the delete_role command.
 */
typedef struct
{
  char *role_id;     ///< ID of role to delete.
  int ultimate;      ///< Dummy field for generic macros.
} delete_role_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
delete_role_data_reset (delete_role_data_t *data)
{
  free (data->role_id);

  memset (data, 0, sizeof (delete_role_data_t));
}

/**
 * @brief Command data for the delete_schedule command.
 */
typedef struct
{
  char *schedule_id;   ///< ID of schedule to delete.
  int ultimate;        ///< Boolean.  Whether to remove entirely or to trashcan.
} delete_schedule_data_t;

/**
 * @brief Command data for the delete_scanner command.
 */
typedef struct
{
  char *scanner_id; ///< ID of scanner to delete.
  int ultimate;     ///< Boolean.  Whether to remove entirely or to trashcan.
} delete_scanner_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
delete_scanner_data_reset (delete_scanner_data_t *data)
{
  g_free (data->scanner_id);

  memset (data, 0, sizeof (delete_scanner_data_t));
}

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
delete_schedule_data_reset (delete_schedule_data_t *data)
{
  free (data->schedule_id);

  memset (data, 0, sizeof (delete_schedule_data_t));
}

/**
 * @brief Command data for the delete_tag command.
 */
typedef struct
{
  char *tag_id;      ///< ID of tag to delete.
  int ultimate;      ///< Boolean.  Whether to remove entirely or to trashcan.
} delete_tag_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
delete_tag_data_reset (delete_tag_data_t *data)
{
  free (data->tag_id);

  memset (data, 0, sizeof (delete_tag_data_t));
}

/**
 * @brief Command data for the delete_target command.
 */
typedef struct
{
  char *target_id;   ///< ID of target to delete.
  int ultimate;      ///< Boolean.  Whether to remove entirely or to trashcan.
} delete_target_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
delete_target_data_reset (delete_target_data_t *data)
{
  free (data->target_id);

  memset (data, 0, sizeof (delete_target_data_t));
}

/**
 * @brief Command data for the delete_task command.
 */
typedef struct
{
  char *task_id;   ///< ID of task to delete.
  int ultimate;    ///< Boolean.  Whether to remove entirely or to trashcan.
} delete_task_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
delete_task_data_reset (delete_task_data_t *data)
{
  free (data->task_id);

  memset (data, 0, sizeof (delete_task_data_t));
}

/**
 * @brief Command data for the delete_user command.
 */
typedef struct
{
  char *name;         ///< Name of user to delete.
  char *user_id;      ///< ID of user to delete.
  int ultimate;       ///< Boolean.  Whether to remove entirely or to trashcan.
  char *inheritor_id;   ///< ID of user that will inherit owned objects.
  char *inheritor_name; ///< Name of user that will inherit owned objects.
} delete_user_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
delete_user_data_reset (delete_user_data_t *data)
{
  free (data->name);
  free (data->user_id);
  free (data->inheritor_id);
  free (data->inheritor_name);

  memset (data, 0, sizeof (delete_user_data_t));
}

/**
 * @brief Command data for the get_feeds command.
 */
typedef struct
{
  char *type;         ///< Type of feed.
} get_feeds_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
get_feeds_data_reset (get_feeds_data_t *data)
{
  free (data->type);

  memset (data, 0, sizeof (get_feeds_data_t));
}

/**
 * @brief Command data for the get_aggregates command.
 */
typedef struct
{
  get_data_t get;        ///< Get args.
  char *type;            ///< Resource type.
  char *subtype;         ///< Resource subtype.
  GList *data_columns;   ///< Columns to calculate aggregate for.
  GList *text_columns;   ///< Columns to get simple text from.
  char *group_column;    ///< Column to group data by.
  char *subgroup_column; ///< Column to further group data by.
  GList *sort_data;      ///< List of Sort data.
  int first_group;       ///< Skip over groups before this group number.
  int max_groups;        ///< Maximum number of aggregate groups to return.
  char *mode;            ///< Special aggregate mode.
} get_aggregates_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
get_aggregates_data_reset (get_aggregates_data_t *data)
{
  get_data_reset (&data->get);
  free (data->type);
  g_list_free_full (data->data_columns, g_free);
  data->data_columns = NULL;
  g_list_free_full (data->text_columns, g_free);
  data->text_columns = NULL;
  free (data->group_column);
  free (data->subgroup_column);
  g_list_free_full (data->sort_data, (GDestroyNotify)sort_data_free);
  data->sort_data = NULL;
  free (data->mode);

  memset (data, 0, sizeof (get_aggregates_data_t));
}

/**
 * @brief Command data for the get_assets command.
 */
typedef struct
{
  char *type;         ///< Requested asset type.
  get_data_t get;     ///< Get Args.
  int details;        ///< Boolean.  Whether to include full details.
} get_assets_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
get_assets_data_reset (get_assets_data_t *data)
{
  free (data->type);
  get_data_reset (&data->get);

  memset (data, 0, sizeof (get_assets_data_t));
}

/**
 * @brief Command data for the get_configs command.
 */
typedef struct
{
  int families;          ///< Boolean.  Whether to include config families.
  int preferences;       ///< Boolean.  Whether to include config preferences.
  get_data_t get;        ///< Get args.
  int tasks;             ///< Boolean.  Whether to include tasks that use scan config.
} get_configs_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
get_configs_data_reset (get_configs_data_t *data)
{
  get_data_reset (&data->get);
  memset (data, 0, sizeof (get_configs_data_t));
}

/**
 * @brief Command data for the get_alerts command.
 */
typedef struct
{
  get_data_t get;   ///< Get args.
  int tasks;        ///< Boolean.  Whether to include tasks that use alert.
} get_alerts_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
get_alerts_data_reset (get_alerts_data_t *data)
{
  get_data_reset (&data->get);
  memset (data, 0, sizeof (get_alerts_data_t));
}

/**
 * @brief Command data for the get_credentials command.
 */
typedef struct
{
  char *format;      ///< Format requested: "key", "deb", ....
  get_data_t get;    ///< Get Args.
  int scanners;      ///< Boolean.  Whether to return scanners using credential.
  int targets;       ///< Boolean.  Whether to return targets using credential.
} get_credentials_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
get_credentials_data_reset (get_credentials_data_t *data)
{
  get_data_reset (&data->get);
  memset (data, 0, sizeof (get_credentials_data_t));
}

/**
 * @brief Command data for the get_filters command.
 */
typedef struct
{
  get_data_t get;    ///< Get args.
  int alerts;        ///< Boolean.  Whether to include alerts that use filter.
} get_filters_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
get_filters_data_reset (get_filters_data_t *data)
{
  get_data_reset (&data->get);
  memset (data, 0, sizeof (get_filters_data_t));
}

/**
 * @brief Command data for the get_groups command.
 */
typedef struct
{
  get_data_t get;    ///< Get args.
} get_groups_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
get_groups_data_reset (get_groups_data_t *data)
{
  get_data_reset (&data->get);
  memset (data, 0, sizeof (get_groups_data_t));
}

/**
 * @brief Command data for the get_info command.
 */
typedef struct
{
  char *type;         ///< Requested information type.
  char *name;         ///< Name of the info
  get_data_t get;     ///< Get Args.
  int details;        ///< Boolean. Weather to include full details.
} get_info_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
get_info_data_reset (get_info_data_t *data)
{
  free (data->type);
  free (data->name);
  get_data_reset (&data->get);

  memset (data, 0, sizeof (get_info_data_t));
}

/**
 * @brief Command data for the get_notes command.
 */
typedef struct
{
  get_data_t get;        ///< Get args.
  char *note_id;         ///< ID of single note to get.
  char *nvt_oid;         ///< OID of NVT to which to limit listing.
  char *task_id;         ///< ID of task to which to limit listing.
  int result;            ///< Boolean.  Whether to include associated results.
} get_notes_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
get_notes_data_reset (get_notes_data_t *data)
{
  free (data->note_id);
  free (data->nvt_oid);
  free (data->task_id);

  memset (data, 0, sizeof (get_notes_data_t));
}

/**
 * @brief Command data for the get_nvts command.
 */
typedef struct
{
  char *config_id;       ///< ID of config to which to limit NVT selection.
  char *preferences_config_id;  ///< ID of config to get preference values from.
  int details;           ///< Boolean.  Whether to include full NVT details.
  char *family;          ///< Name of family to which to limit NVT selection.
  char *nvt_oid;         ///< Name of single NVT to get.
  int preference_count;  ///< Boolean.  Whether to include NVT preference count.
  int preferences;       ///< Boolean.  Whether to include NVT preferences.
  char *sort_field;      ///< Field to sort results on.
  int sort_order;        ///< Result sort order: 0 descending, else ascending.
  int timeout;           ///< Boolean.  Whether to include timeout preference.
} get_nvts_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
get_nvts_data_reset (get_nvts_data_t *data)
{
  free (data->config_id);
  free (data->preferences_config_id);
  free (data->family);
  free (data->nvt_oid);
  free (data->sort_field);

  memset (data, 0, sizeof (get_nvts_data_t));
}

/**
 * @brief Command data for the get_nvt_families command.
 */
typedef struct
{
  int sort_order;        ///< Result sort order: 0 descending, else ascending.
} get_nvt_families_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
get_nvt_families_data_reset (get_nvt_families_data_t *data)
{
  memset (data, 0, sizeof (get_nvt_families_data_t));
}

/**
 * @brief Command data for the get_overrides command.
 */
typedef struct
{
  get_data_t get;      ///< Get args.
  char *override_id;   ///< ID of override to get.
  char *nvt_oid;       ///< OID of NVT to which to limit listing.
  char *task_id;       ///< ID of task to which to limit listing.
  int result;          ///< Boolean.  Whether to include associated results.
} get_overrides_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
get_overrides_data_reset (get_overrides_data_t *data)
{
  free (data->override_id);
  free (data->nvt_oid);
  free (data->task_id);

  memset (data, 0, sizeof (get_overrides_data_t));
}

/**
 * @brief Command data for the get_permissions command.
 */
typedef struct
{
  get_data_t get;     ///< Get args.
  char *resource_id;  ///< Resource whose permissions to get.
} get_permissions_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
get_permissions_data_reset (get_permissions_data_t *data)
{
  free (data->resource_id);

  get_data_reset (&data->get);
  memset (data, 0, sizeof (get_permissions_data_t));
}

/**
 * @brief Command data for the get_port_lists command.
 */
typedef struct
{
  int targets;         ///< Boolean. Include targets that use Port List or not.
  get_data_t get;      ///< Get args.
} get_port_lists_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
get_port_lists_data_reset (get_port_lists_data_t *data)
{
  get_data_reset (&data->get);
  memset (data, 0, sizeof (get_port_lists_data_t));
}

/**
 * @brief Command data for the get_preferences command.
 */
typedef struct
{
  char *config_id;  ///< Config whose preference values to get.
  char *nvt_oid;    ///< Single NVT whose preferences to get.
  char *preference; ///< Single preference to get.
} get_preferences_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
get_preferences_data_reset (get_preferences_data_t *data)
{
  free (data->config_id);
  free (data->nvt_oid);
  free (data->preference);

  memset (data, 0, sizeof (get_preferences_data_t));
}

/**
 * @brief Command data for the get_reports command.
 */
typedef struct
{
  get_data_t get;        ///< Get args with result filtering.
  get_data_t report_get; ///< Get args with report filtering.
  char *delta_report_id; ///< ID of report to compare single report to.
  char *format_id;       ///< ID of report format.
  char *alert_id;        ///< ID of alert.
  char *report_id;       ///< ID of single report to get.
  int lean;              ///< Boolean.  Whether to return lean report.
  int notes_details;     ///< Boolean.  Whether to include details of above.
  int overrides_details; ///< Boolean.  Whether to include details of above.
  int result_tags;       ///< Boolean.  Whether to include result tags.
  int ignore_pagination; ///< Boolean.  Whether to ignore pagination filters.
} get_reports_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
get_reports_data_reset (get_reports_data_t *data)
{
  get_data_reset (&data->get);
  get_data_reset (&data->report_get);
  free (data->delta_report_id);
  free (data->format_id);
  free (data->alert_id);
  free (data->report_id);

  memset (data, 0, sizeof (get_reports_data_t));
}

/**
 * @brief Command data for the get_report_formats command.
 */
typedef struct
{
  get_data_t get;        ///< Get args.
  int alerts;   ///< Boolean.  Whether to include alerts that use Report Format
  int params;            ///< Boolean.  Whether to include params.
} get_report_formats_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
get_report_formats_data_reset (get_report_formats_data_t *data)
{
  get_data_reset (&data->get);
  memset (data, 0, sizeof (get_report_formats_data_t));
}

/**
 * @brief Command data for the get_results command.
 */
typedef struct
{
  get_data_t get;        ///< Get args.
  char *task_id;         ///< Task associated with results.
  int notes_details;     ///< Boolean.  Whether to include details of above.
  int overrides_details; ///< Boolean.  Whether to include details of above.
  int get_counts;        ///< Boolean.  Whether to include result counts.
} get_results_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
get_results_data_reset (get_results_data_t *data)
{
  get_data_reset (&data->get);
  free (data->task_id);

  memset (data, 0, sizeof (get_results_data_t));
}

/**
 * @brief Command data for the get_roles command.
 */
typedef struct
{
  get_data_t get;    ///< Get args.
} get_roles_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
get_roles_data_reset (get_roles_data_t *data)
{
  get_data_reset (&data->get);
  memset (data, 0, sizeof (get_roles_data_t));
}

/**
 * @brief Command data for the get_schedules command.
 */
typedef struct
{
  get_data_t get;      ///< Get args.
  int tasks;           ///< Boolean.  Whether to include tasks that use this schedule.
} get_schedules_data_t;

/**
 * @brief Command data for the get_scanners command.
 */
typedef struct
{
  get_data_t get;        ///< Get args.
} get_scanners_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
get_scanners_data_reset (get_scanners_data_t *data)
{
  get_data_reset (&data->get);

  memset (data, 0, sizeof (get_scanners_data_t));
}

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
get_schedules_data_reset (get_schedules_data_t *data)
{
  get_data_reset (&data->get);
  memset (data, 0, sizeof (get_schedules_data_t));
}

/**
 * @brief Command data.
 */
typedef struct
{
  char *filter;        ///< Filter term.
  int first;           ///< Skip over rows before this number.
  int max;             ///< Maximum number of rows returned.
  char *sort_field;    ///< Field to sort results on.
  int sort_order;      ///< Result sort order: 0 descending, else ascending.
  char *setting_id;    ///< UUID of single setting to get.
} get_settings_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
get_settings_data_reset (get_settings_data_t *data)
{
  free (data->filter);
  free (data->setting_id);
  free (data->sort_field);

  memset (data, 0, sizeof (get_settings_data_t));
}

/**
 * @brief Command data for the get_system_reports command.
 */
typedef struct
{
  int brief;        ///< Boolean.  Whether respond in brief.
  char *name;       ///< Name of single report to get.
  char *duration;   ///< Duration into the past to report on.
  char *end_time; ///< Time of the last data point to report on.
  char *slave_id;   ///< Slave that reports apply to, 0 for local Manager.
  char *start_time; ///< Time of the first data point to report on.
} get_system_reports_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
get_system_reports_data_reset (get_system_reports_data_t *data)
{
  free (data->name);
  free (data->duration);
  free (data->end_time);
  free (data->slave_id);
  free (data->start_time);

  memset (data, 0, sizeof (get_system_reports_data_t));
}

/**
 * @brief Command data for the get_tags command.
 */
typedef struct
{
  get_data_t get;    ///< Get args.
  int names_only;    ///< Boolean. Whether to get only distinct names.
} get_tags_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
get_tags_data_reset (get_tags_data_t *data)
{
  get_data_reset (&data->get);
  memset (data, 0, sizeof (get_tags_data_t));
}

/**
 * @brief Command data for the get_targets command.
 */
typedef struct
{
  get_data_t get;    ///< Get args.
  int tasks;         ///< Boolean.  Whether to include tasks that use target.
} get_targets_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
get_targets_data_reset (get_targets_data_t *data)
{
  get_data_reset (&data->get);
  memset (data, 0, sizeof (get_targets_data_t));
}

/**
 * @brief Command data for the get_users command.
 */
typedef struct
{
  get_data_t get;    ///< Get args.
} get_users_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
get_users_data_reset (get_users_data_t * data)
{
  get_data_reset (&data->get);
  memset (data, 0, sizeof (get_users_data_t));
}

/**
 * @brief Command data for the get_vulns command.
 */
typedef struct
{
  get_data_t get;    ///< Get args.
} get_vulns_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
get_vulns_data_reset (get_vulns_data_t * data)
{
  get_data_reset (&data->get);
  memset (data, 0, sizeof (get_vulns_data_t));
}

/**
 * @brief Command data for the modify_config command.
 */
typedef struct
{
  char *comment;                       ///< New comment for config.
  char *config_id;                     ///< ID of config to modify.
  array_t *families_growing_empty; ///< New family selection: growing, empty.
  array_t *families_growing_all;   ///< New family selection: growing, all NVTs.
  array_t *families_static_all;    ///< New family selection: static, all NVTs.
  int family_selection_family_all;     ///< All flag in FAMILY_SELECTION/FAMILY.
  char *family_selection_family_all_text; ///< Text version of above.
  int family_selection_family_growing; ///< FAMILY_SELECTION/FAMILY growing flag.
  char *family_selection_family_growing_text; ///< Text version of above.
  char *family_selection_family_name;  ///< FAMILY_SELECTION/FAMILY family name.
  int family_selection_growing;        ///< Whether families in selection grow.
  char *family_selection_growing_text; ///< Text version of above.
  char *name;                          ///< New name for config.
  array_t *nvt_selection;              ///< OID array. New NVT set for config.
  char *nvt_selection_family;          ///< Family of NVT selection.
  char *nvt_selection_nvt_oid;         ///< OID during NVT_selection/NVT.
  char *preference_id;                 ///< Config preference to modify.
  char *preference_name;               ///< Config preference to modify.
  char *preference_nvt_oid;            ///< OID of NVT of preference.
  char *preference_value;              ///< New value for preference.
} modify_config_data_t;

/**
 * @brief Command data for the get_tasks command.
 */
typedef struct
{
  get_data_t get;        ///< Get args.
  int schedules_only;    ///< Whether to to get only schedules and basic info.
} get_tasks_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
get_tasks_data_reset (get_tasks_data_t *data)
{
  get_data_reset (&data->get);

  memset (data, 0, sizeof (get_tasks_data_t));
}

/**
 * @brief Command data for the help command.
 */
typedef struct
{
  char *format;       ///< Format.
  char *type;         ///< Type of help.
} help_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
help_data_reset (help_data_t *data)
{
  free (data->format);
  free (data->type);

  memset (data, 0, sizeof (help_data_t));
}

/**
 * @brief Command data for the modify_alert command.
 */
typedef struct
{
  char *alert_id;                ///< alert UUID.
  char *name;                    ///< Name of alert.
  char *comment;                 ///< Comment.
  char *event;                   ///< Event that will cause alert.
  array_t *event_data;           ///< Array of pointers. Extra data for event.
  char *filter_id;               ///< UUID of filter.
  char *active;                  ///< Boolean.  Whether alert is active.
  char *condition;               ///< Condition for alert, e.g. "Always".
  array_t *condition_data;       ///< Array of pointers.  Extra data for condition.
  char *method;                  ///< Method of alert, e.g. "Email".
  array_t *method_data;          ///< Array of pointer.  Extra data for method.
  char *part_data;               ///< Second part of data during *_data: value.
  char *part_name;               ///< First part of data during *_data: name.
} modify_alert_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
modify_alert_data_reset (modify_alert_data_t *data)
{
  free (data->alert_id);
  free (data->name);
  free (data->comment);
  free (data->filter_id);
  free (data->active);
  free (data->event);
  array_free (data->event_data);
  free (data->condition);
  array_free (data->condition_data);
  free (data->method);
  array_free (data->method_data);

  memset (data, 0, sizeof (modify_alert_data_t));
}

/**
 * @brief Command data for the modify_asset command.
 */
typedef struct
{
  char *comment;                 ///< Comment.
  char *asset_id;                ///< asset UUID.
} modify_asset_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
modify_asset_data_reset (modify_asset_data_t *data)
{
  free (data->comment);
  free (data->asset_id);

  memset (data, 0, sizeof (modify_asset_data_t));
}

/**
 * @brief Authentication method settings.
 */
typedef struct
{
  gchar *group_name;            ///< Name of the current group
  GSList *settings;             ///< List of auth_conf_setting_t.
} auth_group_t;

/**
 * @brief Command data for the modify_auth command.
 */
typedef struct
{
  gchar *key;                   ///< Key for current auth_conf_setting.
  gchar *value;                 ///< Value for current auth_conf_setting.
  GSList *groups;               ///< List of auth_group_t
  GSList *curr_group_settings;  ///< Settings of currently parsed group.
} modify_auth_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
modify_auth_data_reset (modify_auth_data_t * data)
{
  GSList *item, *subitem;

  g_free (data->key);
  g_free (data->value);

  item = data->groups;
  subitem = NULL;
  while (item)
    {
      auth_group_t *group = (auth_group_t *) item->data;
      g_free (group->group_name);
      /* Free settings. */
      subitem = group->settings;
      while (subitem)
        {
          auth_conf_setting_t *kvp = (auth_conf_setting_t *) subitem->data;
          g_free (kvp->key);
          g_free (kvp->value);
          g_free (kvp);
          subitem = g_slist_next (subitem);
        }
      item = g_slist_next (item);
    }
  g_slist_free (data->groups);

  if (data->curr_group_settings)
    {
      item = data->curr_group_settings;
      while (item)
        {
          /* Free settings. */
          auth_conf_setting_t *kvp = (auth_conf_setting_t *) item->data;
          g_free (kvp->key);
          g_free (kvp->value);
          g_free (kvp);
          item = g_slist_next (item);
        }
      g_slist_free (data->curr_group_settings);
    }
  memset (data, 0, sizeof (modify_auth_data_t));
}

/**
 * @brief Command data for the modify_credential command.
 */
typedef struct
{
  char *allow_insecure;       ///< Whether to allow insecure use.
  char *auth_algorithm;       ///< SNMP Authentication algorithm.
  char *certificate;          ///< Certificate.
  char *comment;              ///< Comment.
  char *community;            ///< SNMP Community string.
  char *credential_id;        ///< ID of credential to modify.
  int key;                    ///< Whether the command included a key element.
  char *key_phrase;           ///< Passphrase for key.
  char *key_private;          ///< Private key from key.
  char *key_public;           ///< Public key from key.
  char *login;                ///< Login name.
  char *name;                 ///< Name.
  char *password;             ///< Password associated with login name.
  char *privacy_algorithm;    ///< SNMP Privacy algorithm.
  char *privacy_password;     ///< SNMP Privacy password.
} modify_credential_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
modify_credential_data_reset (modify_credential_data_t *data)
{
  free (data->allow_insecure);
  free (data->auth_algorithm);
  free (data->certificate);
  free (data->comment);
  free (data->community);
  free (data->credential_id);
  free (data->key_phrase);
  free (data->key_private);
  free (data->key_public);
  free (data->login);
  free (data->name);
  free (data->password);
  free (data->privacy_algorithm);
  free (data->privacy_password);

  memset (data, 0, sizeof (modify_credential_data_t));
}

/**
 * @brief Command data for the modify_filter command.
 */
typedef struct
{
  char *comment;                 ///< Comment.
  char *name;                    ///< Name of filter.
  char *filter_id;               ///< Filter UUID.
  char *term;                    ///< Term for filter.
  char *type;                    ///< Type of filter.
} modify_filter_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
modify_filter_data_reset (modify_filter_data_t *data)
{
  free (data->comment);
  free (data->name);
  free (data->filter_id);
  free (data->term);
  free (data->type);

  memset (data, 0, sizeof (modify_filter_data_t));
}

/**
 * @brief Command data for the modify_group command.
 */
typedef struct
{
  char *comment;                 ///< Comment.
  char *name;                    ///< Name of group.
  char *group_id;                ///< Group UUID.
  char *users;                   ///< Users for group.
} modify_group_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
modify_group_data_reset (modify_group_data_t *data)
{
  free (data->comment);
  free (data->name);
  free (data->group_id);
  free (data->users);

  memset (data, 0, sizeof (modify_group_data_t));
}

/**
 * @brief Command data for the modify_permission command.
 */
typedef struct
{
  char *comment;                 ///< Comment.
  char *name;                    ///< Name of permission.
  char *permission_id;           ///< Permission UUID.
  char *resource_id;             ///< Resource.
  char *resource_type;           ///< Resource type, for Super permissions.
  char *subject_type;            ///< Subject type.
  char *subject_id;              ///< Subject UUID.
} modify_permission_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
modify_permission_data_reset (modify_permission_data_t *data)
{
  free (data->comment);
  free (data->name);
  free (data->resource_id);
  free (data->resource_type);
  free (data->permission_id);
  free (data->subject_type);
  free (data->subject_id);

  memset (data, 0, sizeof (modify_permission_data_t));
}

/**
 * @brief Command data for the modify_port_list command.
 */
typedef struct
{
  char *comment;                 ///< Comment.
  char *name;                    ///< Name of Port List.
  char *port_list_id;            ///< UUID of Port List.
} modify_port_list_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
modify_port_list_data_reset (modify_port_list_data_t *data)
{
  free (data->comment);
  free (data->name);
  free (data->port_list_id);

  memset (data, 0, sizeof (modify_port_list_data_t));
}

/**
 * @brief Command data for the modify_report_format command.
 */
typedef struct
{
  char *active;               ///< Boolean.  Whether report format is active.
  char *name;                 ///< Name.
  char *param_name;           ///< Param name.
  char *param_value;          ///< Param value.
  char *report_format_id;     ///< ID of report format to modify.
  char *summary;              ///< Summary.
} modify_report_format_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
modify_report_format_data_reset (modify_report_format_data_t *data)
{
  free (data->active);
  free (data->name);
  free (data->param_name);
  free (data->param_value);
  free (data->report_format_id);
  free (data->summary);

  memset (data, 0, sizeof (modify_report_format_data_t));
}

/**
 * @brief Command data for the modify_role command.
 */
typedef struct
{
  char *comment;                 ///< Comment.
  char *name;                    ///< Name of role.
  char *role_id;                 ///< Role UUID.
  char *users;                   ///< Users for role.
} modify_role_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
modify_role_data_reset (modify_role_data_t *data)
{
  free (data->comment);
  free (data->name);
  free (data->role_id);
  free (data->users);

  memset (data, 0, sizeof (modify_role_data_t));
}

/**
 * @brief Command data for the modify_scanner command.
 */
typedef struct
{
  char *comment;            ///< Comment.
  char *name;               ///< Name of scanner.
  char *host;               ///< Host of scanner.
  char *port;               ///< Port of scanner.
  char *type;               ///< Type of scanner.
  char *scanner_id;         ///< scanner UUID.
  char *ca_pub;             ///< CA Certificate of scanner.
  char *credential_id;      ///< UUID of credential of scanner.
} modify_scanner_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
modify_scanner_data_reset (modify_scanner_data_t *data)
{
  g_free (data->comment);
  g_free (data->name);
  g_free (data->host);
  g_free (data->port);
  g_free (data->type);
  g_free (data->scanner_id);
  free (data->ca_pub);
  free (data->credential_id);

  memset (data, 0, sizeof (modify_scanner_data_t));
}

/**
 * @brief Command data for the modify_schedule command.
 */
typedef struct
{
  char *comment;                 ///< Comment.
  char *name;                    ///< Name of schedule.
  char *schedule_id;             ///< Schedule UUID.
  char *timezone;                ///< Timezone.
  char *icalendar;               ///< iCalendar string.
} modify_schedule_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
modify_schedule_data_reset (modify_schedule_data_t *data)
{
  free (data->comment);
  free (data->name);
  free (data->schedule_id);
  free (data->timezone);
  free (data->icalendar);

  memset (data, 0, sizeof (modify_schedule_data_t));
}

/**
 * @brief Command data for the modify_tag command.
 */
typedef struct
{
  char *tag_id;           ///< UUID of the tag.
  char *active;           ///< Whether the tag is active.
  array_t *resource_ids;  ///< IDs of the resource to which to attach the tag.
  char *resource_type;    ///< Type of the resource to which to attach the tag.
  char *resources_action; ///< Resources edit action, e.g. "remove" or "add".
  char *resources_filter; ///< Filter used to select resources.
  char *comment;          ///< Comment to add to the tag.
  char *name;             ///< Name of the tag.
  char *value;            ///< Value of the tag.
  int  resource_count;    ///< Number of attach tags.
} modify_tag_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
modify_tag_data_reset (modify_tag_data_t *data)
{
  free (data->tag_id);
  free (data->active);
  array_free (data->resource_ids);
  free (data->resource_type);
  free (data->resources_action);
  free (data->resources_filter);
  free (data->comment);
  free (data->name);
  free (data->value);

  memset (data, 0, sizeof (modify_tag_data_t));
}

/**
 * @brief Command data for the modify_setting command.
 */
typedef struct
{
  char *name;           ///< Name.
  char *setting_id;     ///< Setting.
  char *value;          ///< Value.
} modify_setting_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
modify_setting_data_reset (modify_setting_data_t *data)
{
  free (data->name);
  free (data->setting_id);
  free (data->value);

  memset (data, 0, sizeof (modify_setting_data_t));
}

/**
 * @brief Command data for the modify_target command.
 */
typedef struct
{
  char *alive_tests;                 ///< Alive tests.
  char *allow_simultaneous_ips;      ///< Boolean. Whether to scan multiple IPs of a host simultaneously.
  char *comment;                     ///< Comment.
  char *exclude_hosts;               ///< Hosts to exclude from set.
  char *reverse_lookup_only;         ///< Boolean. Whether to consider only hosts that reverse lookup.
  char *reverse_lookup_unify;        ///< Boolean. Whether to unify based on reverse lookup.
  char *hosts;                       ///< Hosts for target.
  char *name;                        ///< Name of target.
  char *port_list_id;                ///< Port list for target.
  char *ssh_credential_id;           ///< SSH credential for target.
  char *ssh_lsc_credential_id;       ///< SSH credential for target (deprecated).
  char *ssh_elevate_credential_id;   ///< SSH credential for target (deprecated).
  char *ssh_port;                    ///< Port for SSH.
  char *ssh_lsc_port;                ///< Port for SSH (deprecated).
  char *smb_credential_id;           ///< SMB credential for target.
  char *smb_lsc_credential_id;       ///< SMB credential for target (deprecated).
  char *esxi_credential_id;          ///< ESXi credential for target.
  char *esxi_lsc_credential_id;      ///< ESXi credential for target (deprecated).
  char *snmp_credential_id;          ///< SNMP credential for target.
  char *target_id;                   ///< Target UUID.
} modify_target_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
modify_target_data_reset (modify_target_data_t *data)
{
  free (data->alive_tests);
  free (data->allow_simultaneous_ips);
  free (data->exclude_hosts);
  free (data->reverse_lookup_only);
  free (data->reverse_lookup_unify);
  free (data->comment);
  free (data->hosts);
  free (data->name);
  free (data->port_list_id);
  free (data->ssh_credential_id);
  free (data->ssh_lsc_credential_id);
  free (data->ssh_elevate_credential_id);
  free (data->ssh_port);
  free (data->ssh_lsc_port);
  free (data->smb_credential_id);
  free (data->smb_lsc_credential_id);
  free (data->esxi_credential_id);
  free (data->esxi_lsc_credential_id);
  free (data->snmp_credential_id);
  free (data->target_id);

  memset (data, 0, sizeof (modify_target_data_t));
}

/**
 * @brief Command data for the modify_task command.
 */
typedef struct
{
  char *action;        ///< What to do to file: "update" or "remove".
  char *alterable;     ///< Boolean. Whether the task is alterable.
  char *comment;       ///< Comment.
  char *hosts_ordering; ///< Order for scanning of target hosts.
  char *scanner_id;    ///< ID of new scanner for task.
  char *config_id;     ///< ID of new config for task.
  array_t *alerts;     ///< IDs of new alerts for task.
  char *file;          ///< File to attach to task.
  char *file_name;     ///< Name of file to attach to task.
  array_t *groups;     ///< IDs of new groups for task.
  char *name;          ///< New name for task.
  char *observers;     ///< Space separated list of observer user names.
  name_value_t *preference;  ///< Current preference.
  array_t *preferences;   ///< Preferences.
  char *schedule_id;   ///< ID of new schedule for task.
  char *schedule_periods; ///< Number of periods the schedule must run for.
  char *target_id;     ///< ID of new target for task.
  char *task_id;       ///< ID of task to modify.
} modify_task_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
modify_task_data_reset (modify_task_data_t *data)
{
  free (data->action);
  free (data->alterable);
  array_free (data->alerts);
  array_free (data->groups);
  free (data->comment);
  free (data->hosts_ordering);
  free (data->scanner_id);
  free (data->config_id);
  free (data->file);
  free (data->file_name);
  free (data->name);
  free (data->observers);
  if (data->preferences)
    {
      guint index = data->preferences->len;
      while (index--)
        {
          name_value_t *pair;
          pair = (name_value_t*) g_ptr_array_index (data->preferences, index);
          if (pair)
            {
              g_free (pair->name);
              g_free (pair->value);
            }
        }
    }
  array_free (data->preferences);
  free (data->schedule_id);
  free (data->schedule_periods);
  free (data->target_id);
  free (data->task_id);

  memset (data, 0, sizeof (modify_task_data_t));
}

/**
 * @brief Command data for the modify_note command.
 */
typedef struct
{
  char *active;       ///< Whether the note is active.
  char *hosts;        ///< Hosts to which to limit override.
  char *note_id;      ///< ID of note to modify.
  char *nvt_oid;      ///< NVT to which to limit override.
  char *port;         ///< Port to which to limit override.
  char *result_id;    ///< ID of result to which to limit override.
  char *severity;     ///< Severity score to which to limit note.
  char *task_id;      ///< ID of task to which to limit override.
  char *text;         ///< Text of override.
  char *threat;       ///< Threat to which to limit override.
} modify_note_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
modify_note_data_reset (modify_note_data_t *data)
{
  free (data->active);
  free (data->hosts);
  free (data->note_id);
  free (data->nvt_oid);
  free (data->port);
  free (data->result_id);
  free (data->severity);
  free (data->task_id);
  free (data->text);
  free (data->threat);

  memset (data, 0, sizeof (modify_note_data_t));
}

/**
 * @brief Command data for the modify_override command.
 */
typedef struct
{
  char *active;       ///< Whether the override is active.
  char *hosts;        ///< Hosts to which to limit override.
  char *new_severity; ///< New severity score of overridden results.
  char *new_threat;   ///< New threat value of overridden results.
  char *nvt_oid;      ///< NVT to which to limit override.
  char *override_id;  ///< ID of override to modify.
  char *port;         ///< Port to which to limit override.
  char *result_id;    ///< ID of result to which to limit override.
  char *severity;     ///< Severity score of results to override.
  char *task_id;      ///< ID of task to which to limit override.
  char *text;         ///< Text of override.
  char *threat;       ///< Threat to which to limit override.
} modify_override_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
modify_override_data_reset (modify_override_data_t *data)
{
  free (data->active);
  free (data->hosts);
  free (data->new_severity);
  free (data->new_threat);
  free (data->nvt_oid);
  free (data->override_id);
  free (data->port);
  free (data->result_id);
  free (data->severity);
  free (data->task_id);
  free (data->text);
  free (data->threat);

  memset (data, 0, sizeof (modify_override_data_t));
}

/**
 * @brief Command data for the modify_user command.
 */
typedef struct
{
  array_t *groups;           ///< IDs of groups.
  gchar *hosts;              ///< Hosts.
  int hosts_allow;           ///< Whether hosts are allowed.
  gboolean modify_password;  ///< Whether to modify password.
  gchar *name;               ///< User name.
  gchar *new_name;           ///< New user name.
  gchar *password;           ///< Password.
  gchar *comment;            ///< Comment.
  array_t *roles;            ///< IDs of roles.
  array_t *sources;          ///< Sources.
  gchar *current_source;     ///< Current source, for collecting sources.
  gchar *user_id;            ///< ID of user.
} modify_user_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
modify_user_data_reset (modify_user_data_t * data)
{
  array_free (data->groups);
  g_free (data->name);
  g_free (data->new_name);
  g_free (data->user_id);
  g_free (data->password);
  g_free (data->comment);
  g_free (data->hosts);
  array_free (data->roles);
  if (data->sources)
    {
      array_free (data->sources);
    }
  g_free (data->current_source);
  memset (data, 0, sizeof (modify_user_data_t));
}

/**
 * @brief Command data for the move_task command.
 */
typedef struct
{
  gchar *task_id;   ///< ID of the task to move.
  gchar *slave_id;  ///< ID of the slave to move to.
} move_task_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
move_task_data_reset (move_task_data_t *data)
{
  g_free (data->task_id);
  g_free (data->slave_id);

  memset (data, 0, sizeof (move_task_data_t));
}

/**
 * @brief Command data for the restore command.
 */
typedef struct
{
  char *id;   ///< ID of resource to restore.
} restore_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
restore_data_reset (restore_data_t *data)
{
  free (data->id);

  memset (data, 0, sizeof (restore_data_t));
}

/**
 * @brief Command data for the resume_task command.
 */
typedef struct
{
  char *task_id;   ///< ID of task to resume.
} resume_task_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
resume_task_data_reset (resume_task_data_t *data)
{
  free (data->task_id);

  memset (data, 0, sizeof (resume_task_data_t));
}

/**
 * @brief Command data for the start_task command.
 */
typedef struct
{
  char *task_id;   ///< ID of task to start.
} start_task_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
start_task_data_reset (start_task_data_t *data)
{
  free (data->task_id);

  memset (data, 0, sizeof (start_task_data_t));
}

/**
 * @brief Command data for the stop_task command.
 */
typedef struct
{
  char *task_id;   ///< ID of task to stop.
} stop_task_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
stop_task_data_reset (stop_task_data_t *data)
{
  free (data->task_id);

  memset (data, 0, sizeof (stop_task_data_t));
}

/**
 * @brief Command data for the test_alert command.
 */
typedef struct
{
  char *alert_id;   ///< ID of alert to test.
} test_alert_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
test_alert_data_reset (test_alert_data_t *data)
{
  free (data->alert_id);

  memset (data, 0, sizeof (test_alert_data_t));
}

/**
 * @brief Command data for the verify_report_format command.
 */
typedef struct
{
  char *report_format_id;   ///< ID of report format to verify.
} verify_report_format_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
verify_report_format_data_reset (verify_report_format_data_t *data)
{
  free (data->report_format_id);

  memset (data, 0, sizeof (verify_report_format_data_t));
}

/**
 * @brief Command data for the verify_scanner command.
 */
typedef struct
{
  char *scanner_id;   ///< ID of scanner to verify.
} verify_scanner_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
verify_scanner_data_reset (verify_scanner_data_t *data)
{
  g_free (data->scanner_id);

  memset (data, 0, sizeof (verify_scanner_data_t));
}

/**
 * @brief Command data for the wizard command.
 */
typedef struct
{
  char *mode;          ///< Mode to run the wizard in.
  char *name;          ///< Name of the wizard.
  name_value_t *param; ///< Current param.
  array_t *params;     ///< Parameters.
  char *read_only;     ///< Read only flag.
} run_wizard_data_t;

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
static void
run_wizard_data_reset (run_wizard_data_t *data)
{
  free (data->mode);
  free (data->name);
  free (data->read_only);
  if (data->params)
    {
      guint index = data->params->len;
      while (index--)
        {
          name_value_t *pair;
          pair = (name_value_t*) g_ptr_array_index (data->params, index);
          if (pair)
            {
              g_free (pair->name);
              g_free (pair->value);
            }
        }
    }
  array_free (data->params);

  memset (data, 0, sizeof (run_wizard_data_t));
}

/**
 * @brief Command data, as passed between GMP parser callbacks.
 */
typedef union
{
  create_asset_data_t create_asset;                   ///< create_asset
  create_alert_data_t create_alert;                   ///< create_alert
  create_credential_data_t create_credential;         ///< create_credential
  create_filter_data_t create_filter;                 ///< create_filter
  create_group_data_t create_group;                   ///< create_group
  create_note_data_t create_note;                     ///< create_note
  create_override_data_t create_override;             ///< create_override
  create_permission_data_t create_permission;         ///< create_permission
  create_port_range_data_t create_port_range;         ///< create_port_range
  create_report_data_t create_report;                 ///< create_report
  create_role_data_t create_role;                     ///< create_role
  create_scanner_data_t create_scanner;               ///< create_scanner
  create_schedule_data_t create_schedule;             ///< create_schedule
  create_tag_data_t create_tag;                       ///< create_tag
  create_target_data_t create_target;                 ///< create_target
  create_task_data_t create_task;                     ///< create_task
  create_user_data_t create_user;                     ///< create_user
  delete_asset_data_t delete_asset;                   ///< delete_asset
  delete_credential_data_t delete_credential;         ///< delete_credential
  delete_config_data_t delete_config;                 ///< delete_config
  delete_alert_data_t delete_alert;                   ///< delete_alert
  delete_filter_data_t delete_filter;                 ///< delete_filter
  delete_group_data_t delete_group;                   ///< delete_group
  delete_note_data_t delete_note;                     ///< delete_note
  delete_override_data_t delete_override;             ///< delete_override
  delete_permission_data_t delete_permission;         ///< delete_permission
  delete_port_list_data_t delete_port_list;           ///< delete_port_list
  delete_port_range_data_t delete_port_range;         ///< delete_port_range
  delete_report_data_t delete_report;                 ///< delete_report
  delete_report_format_data_t delete_report_format;   ///< delete_report_format
  delete_role_data_t delete_role;                     ///< delete_role
  delete_scanner_data_t delete_scanner;               ///< delete_scanner
  delete_schedule_data_t delete_schedule;             ///< delete_schedule
  delete_tag_data_t delete_tag;                       ///< delete_tag
  delete_target_data_t delete_target;                 ///< delete_target
  delete_task_data_t delete_task;                     ///< delete_task
  delete_user_data_t delete_user;                     ///< delete_user
  get_aggregates_data_t get_aggregates;               ///< get_aggregates
  get_configs_data_t get_configs;                     ///< get_configs
  get_alerts_data_t get_alerts;                       ///< get_alerts
  get_assets_data_t get_assets;                       ///< get_assets
  get_credentials_data_t get_credentials;             ///< get_credentials
  get_feeds_data_t get_feeds;                         ///< get_feeds
  get_filters_data_t get_filters;                     ///< get_filters
  get_groups_data_t get_groups;                       ///< get_groups
  get_info_data_t get_info;                           ///< get_info
  get_notes_data_t get_notes;                         ///< get_notes
  get_nvts_data_t get_nvts;                           ///< get_nvts
  get_nvt_families_data_t get_nvt_families;           ///< get_nvt_families
  get_overrides_data_t get_overrides;                 ///< get_overrides
  get_permissions_data_t get_permissions;             ///< get_permissions
  get_port_lists_data_t get_port_lists;               ///< get_port_lists
  get_preferences_data_t get_preferences;             ///< get_preferences
  get_reports_data_t get_reports;                     ///< get_reports
  get_report_formats_data_t get_report_formats;       ///< get_report_formats
  get_results_data_t get_results;                     ///< get_results
  get_roles_data_t get_roles;                         ///< get_roles
  get_schedules_data_t get_schedules;                 ///< get_schedules
  get_scanners_data_t get_scanners;                   ///< get_scanners
  get_settings_data_t get_settings;                   ///< get_settings
  get_system_reports_data_t get_system_reports;       ///< get_system_reports
  get_tags_data_t get_tags;                           ///< get_tags
  get_targets_data_t get_targets;                     ///< get_targets
  get_tasks_data_t get_tasks;                         ///< get_tasks
  get_users_data_t get_users;                         ///< get_users
  get_vulns_data_t get_vulns;                         ///< get_vulns
  help_data_t help;                                   ///< help
  modify_alert_data_t modify_alert;                   ///< modify_alert
  modify_asset_data_t modify_asset;                   ///< modify_asset
  modify_auth_data_t modify_auth;                     ///< modify_auth
  modify_config_data_t modify_config;                 ///< modify_config
  modify_credential_data_t modify_credential;         ///< modify_credential
  modify_filter_data_t modify_filter;                 ///< modify_filter
  modify_group_data_t modify_group;                   ///< modify_group
  modify_permission_data_t modify_permission;         ///< modify_permission
  modify_port_list_data_t modify_port_list;           ///< modify_port_list
  modify_report_format_data_t modify_report_format;   ///< modify_report_format
  modify_role_data_t modify_role;                     ///< modify_role
  modify_scanner_data_t modify_scanner;               ///< modify_scanner
  modify_schedule_data_t modify_schedule;             ///< modify_schedule
  modify_setting_data_t modify_setting;               ///< modify_setting
  modify_tag_data_t modify_tag;                       ///< modify_tag
  modify_target_data_t modify_target;                 ///< modify_target
  modify_task_data_t modify_task;                     ///< modify_task
  modify_user_data_t modify_user;                     ///< modify_user
  move_task_data_t move_task;                         ///< move_task
  restore_data_t restore;                             ///< restore
  resume_task_data_t resume_task;                     ///< resume_task
  start_task_data_t start_task;                       ///< start_task
  stop_task_data_t stop_task;                         ///< stop_task
  test_alert_data_t test_alert;                       ///< test_alert
  verify_report_format_data_t verify_report_format;   ///< verify_report_format
  verify_scanner_data_t verify_scanner;               ///< verify_scanner
  run_wizard_data_t wizard;                           ///< run_wizard
} command_data_t;

/**
 * @brief Initialise command data.
 *
 * @param[in]  data  Command data.
 */
static void
command_data_init (command_data_t *data)
{
  memset (data, 0, sizeof (command_data_t));
}


/* Global variables. */

/**
 * @brief Parser callback data.
 */
static command_data_t command_data;

/**
 * @brief Parser callback data for CREATE_ASSET.
 */
static create_asset_data_t *create_asset_data
 = (create_asset_data_t*) &(command_data.create_asset);

/**
 * @brief Parser callback data for CREATE_ALERT.
 */
static create_alert_data_t *create_alert_data
 = (create_alert_data_t*) &(command_data.create_alert);

/**
 * @brief Parser callback data for CREATE_CREDENTIAL.
 */
static create_credential_data_t *create_credential_data
 = (create_credential_data_t*) &(command_data.create_credential);

/**
 * @brief Parser callback data for CREATE_FILTER.
 */
static create_filter_data_t *create_filter_data
 = (create_filter_data_t*) &(command_data.create_filter);

/**
 * @brief Parser callback data for CREATE_GROUP.
 */
static create_group_data_t *create_group_data
 = (create_group_data_t*) &(command_data.create_group);

/**
 * @brief Parser callback data for CREATE_NOTE.
 */
static create_note_data_t *create_note_data
 = (create_note_data_t*) &(command_data.create_note);

/**
 * @brief Parser callback data for CREATE_OVERRIDE.
 */
static create_override_data_t *create_override_data
 = (create_override_data_t*) &(command_data.create_override);

/**
 * @brief Parser callback data for CREATE_PERMISSION.
 */
static create_permission_data_t *create_permission_data
 = (create_permission_data_t*) &(command_data.create_permission);

/**
 * @brief Parser callback data for CREATE_PORT_RANGE.
 */
static create_port_range_data_t *create_port_range_data
 = (create_port_range_data_t*) &(command_data.create_port_range);

/**
 * @brief Parser callback data for CREATE_ROLE.
 */
static create_role_data_t *create_role_data
 = (create_role_data_t*) &(command_data.create_role);

/**
 * @brief Parser callback data for CREATE_REPORT.
 */
static create_report_data_t *create_report_data
 = (create_report_data_t*) &(command_data.create_report);

/**
 * @brief Parser callback data for CREATE_SCANNER.
 */
static create_scanner_data_t *create_scanner_data
 = (create_scanner_data_t*) &(command_data.create_scanner);

/**
 * @brief Parser callback data for CREATE_SCHEDULE.
 */
static create_schedule_data_t *create_schedule_data
 = (create_schedule_data_t*) &(command_data.create_schedule);

/**
 * @brief Parser callback data for CREATE_TAG.
 */
static create_tag_data_t *create_tag_data
 = (create_tag_data_t*) &(command_data.create_tag);

/**
 * @brief Parser callback data for CREATE_TARGET.
 */
static create_target_data_t *create_target_data
 = (create_target_data_t*) &(command_data.create_target);

/**
 * @brief Parser callback data for CREATE_TASK.
 */
static create_task_data_t *create_task_data
 = (create_task_data_t*) &(command_data.create_task);

/**
 * @brief Parser callback data for CREATE_USER.
 */
static create_user_data_t *create_user_data
 = &(command_data.create_user);

/**
 * @brief Parser callback data for DELETE_ASSET.
 */
static delete_asset_data_t *delete_asset_data
 = (delete_asset_data_t*) &(command_data.delete_asset);

/**
 * @brief Parser callback data for DELETE_CONFIG.
 */
static delete_config_data_t *delete_config_data
 = (delete_config_data_t*) &(command_data.delete_config);

/**
 * @brief Parser callback data for DELETE_ALERT.
 */
static delete_alert_data_t *delete_alert_data
 = (delete_alert_data_t*) &(command_data.delete_alert);

/**
 * @brief Parser callback data for DELETE_CREDENTIAL.
 */
static delete_credential_data_t *delete_credential_data
 = (delete_credential_data_t*) &(command_data.delete_credential);

/**
 * @brief Parser callback data for DELETE_FILTER.
 */
static delete_filter_data_t *delete_filter_data
 = (delete_filter_data_t*) &(command_data.delete_filter);

/**
 * @brief Parser callback data for DELETE_GROUP.
 */
static delete_group_data_t *delete_group_data
 = (delete_group_data_t*) &(command_data.delete_group);

/**
 * @brief Parser callback data for DELETE_NOTE.
 */
static delete_note_data_t *delete_note_data
 = (delete_note_data_t*) &(command_data.delete_note);

/**
 * @brief Parser callback data for DELETE_OVERRIDE.
 */
static delete_override_data_t *delete_override_data
 = (delete_override_data_t*) &(command_data.delete_override);

/**
 * @brief Parser callback data for DELETE_PERMISSION.
 */
static delete_permission_data_t *delete_permission_data
 = (delete_permission_data_t*) &(command_data.delete_permission);

/**
 * @brief Parser callback data for DELETE_PORT_LIST.
 */
static delete_port_list_data_t *delete_port_list_data
 = (delete_port_list_data_t*) &(command_data.delete_port_list);

/**
 * @brief Parser callback data for DELETE_PORT_RANGE.
 */
static delete_port_range_data_t *delete_port_range_data
 = (delete_port_range_data_t*) &(command_data.delete_port_range);

/**
 * @brief Parser callback data for DELETE_REPORT.
 */
static delete_report_data_t *delete_report_data
 = (delete_report_data_t*) &(command_data.delete_report);

/**
 * @brief Parser callback data for DELETE_REPORT_FORMAT.
 */
static delete_report_format_data_t *delete_report_format_data
 = (delete_report_format_data_t*) &(command_data.delete_report_format);

/**
 * @brief Parser callback data for DELETE_ROLE.
 */
static delete_role_data_t *delete_role_data
 = (delete_role_data_t*) &(command_data.delete_role);

/**
 * @brief Parser callback data for DELETE_SCANNER.
 */
static delete_scanner_data_t *delete_scanner_data
 = (delete_scanner_data_t*) &(command_data.delete_scanner);

/**
 * @brief Parser callback data for DELETE_SCHEDULE.
 */
static delete_schedule_data_t *delete_schedule_data
 = (delete_schedule_data_t*) &(command_data.delete_schedule);

/**
 * @brief Parser callback data for DELETE_TAG.
 */
static delete_tag_data_t *delete_tag_data
 = (delete_tag_data_t*) &(command_data.delete_tag);

/**
 * @brief Parser callback data for DELETE_TARGET.
 */
static delete_target_data_t *delete_target_data
 = (delete_target_data_t*) &(command_data.delete_target);

/**
 * @brief Parser callback data for DELETE_TASK.
 */
static delete_task_data_t *delete_task_data
 = (delete_task_data_t*) &(command_data.delete_task);

/**
 * @brief Parser callback data for DELETE_USER.
 */
static delete_user_data_t *delete_user_data
 = (delete_user_data_t*) &(command_data.delete_user);

/**
 * @brief Parser callback data for GET_AGGREGATES.
 */
static get_aggregates_data_t *get_aggregates_data
 = &(command_data.get_aggregates);

/**
 * @brief Parser callback data for GET_CONFIGS.
 */
static get_configs_data_t *get_configs_data
 = &(command_data.get_configs);

/**
 * @brief Parser callback data for GET_ALERTS.
 */
static get_alerts_data_t *get_alerts_data
 = &(command_data.get_alerts);

/**
 * @brief Parser callback data for GET_ASSETS.
 */
static get_assets_data_t *get_assets_data
 = &(command_data.get_assets);

/**
 * @brief Parser callback data for GET_CREDENTIALS.
 */
static get_credentials_data_t *get_credentials_data
 = &(command_data.get_credentials);

/**
 * @brief Parser callback data for GET_FEEDS.
 */
static get_feeds_data_t *get_feeds_data
 = &(command_data.get_feeds);

/**
 * @brief Parser callback data for GET_FILTERS.
 */
static get_filters_data_t *get_filters_data
 = &(command_data.get_filters);

/**
 * @brief Parser callback data for GET_GROUPS.
 */
static get_groups_data_t *get_groups_data
 = &(command_data.get_groups);

/**
 * @brief Parser callback data for GET_INFO.
 */
static get_info_data_t *get_info_data
 = &(command_data.get_info);

/**
 * @brief Parser callback data for GET_NOTES.
 */
static get_notes_data_t *get_notes_data
 = &(command_data.get_notes);

/**
 * @brief Parser callback data for GET_NVTS.
 */
static get_nvts_data_t *get_nvts_data
 = &(command_data.get_nvts);

/**
 * @brief Parser callback data for GET_NVT_FAMILIES.
 */
static get_nvt_families_data_t *get_nvt_families_data
 = &(command_data.get_nvt_families);

/**
 * @brief Parser callback data for GET_OVERRIDES.
 */
static get_overrides_data_t *get_overrides_data
 = &(command_data.get_overrides);

/**
 * @brief Parser callback data for GET_PERMISSIONS.
 */
static get_permissions_data_t *get_permissions_data
 = &(command_data.get_permissions);

/**
 * @brief Parser callback data for GET_PORT_LISTS.
 */
static get_port_lists_data_t *get_port_lists_data
 = &(command_data.get_port_lists);

/**
 * @brief Parser callback data for GET_PREFERENCES.
 */
static get_preferences_data_t *get_preferences_data
 = &(command_data.get_preferences);

/**
 * @brief Parser callback data for GET_REPORTS.
 */
static get_reports_data_t *get_reports_data
 = &(command_data.get_reports);

/**
 * @brief Parser callback data for GET_REPORT_FORMATS.
 */
static get_report_formats_data_t *get_report_formats_data
 = &(command_data.get_report_formats);

/**
 * @brief Parser callback data for GET_RESULTS.
 */
static get_results_data_t *get_results_data
 = &(command_data.get_results);

/**
 * @brief Parser callback data for GET_ROLES.
 */
static get_roles_data_t *get_roles_data
 = &(command_data.get_roles);

/**
 * @brief Parser callback data for GET_scannerS.
 */
static get_scanners_data_t *get_scanners_data
 = &(command_data.get_scanners);

/**
 * @brief Parser callback data for GET_SCHEDULES.
 */
static get_schedules_data_t *get_schedules_data
 = &(command_data.get_schedules);

/**
 * @brief Parser callback data for GET_SETTINGS.
 */
static get_settings_data_t *get_settings_data
 = &(command_data.get_settings);

/**
 * @brief Parser callback data for GET_SYSTEM_REPORTS.
 */
static get_system_reports_data_t *get_system_reports_data
 = &(command_data.get_system_reports);

/**
 * @brief Parser callback data for GET_TAGS.
 */
static get_tags_data_t *get_tags_data
 = &(command_data.get_tags);

/**
 * @brief Parser callback data for GET_TARGETS.
 */
static get_targets_data_t *get_targets_data
 = &(command_data.get_targets);

/**
 * @brief Parser callback data for GET_TASKS.
 */
static get_tasks_data_t *get_tasks_data
 = &(command_data.get_tasks);

/**
 * @brief Parser callback data for GET_USERS.
 */
static get_users_data_t *get_users_data
 = &(command_data.get_users);

/**
 * @brief Parser callback data for GET_VULNS.
 */
static get_vulns_data_t *get_vulns_data
 = &(command_data.get_vulns);

/**
 * @brief Parser callback data for HELP.
 */
static help_data_t *help_data
 = &(command_data.help);

/**
 * @brief Parser callback data for MODIFY_ALERT.
 */
static modify_alert_data_t *modify_alert_data
 = &(command_data.modify_alert);

/**
 * @brief Parser callback data for MODIFY_ASSET.
 */
static modify_asset_data_t *modify_asset_data
 = &(command_data.modify_asset);

/**
 * @brief Parser callback data for MODIFY_AUTH.
 */
static modify_auth_data_t *modify_auth_data
 = &(command_data.modify_auth);

/**
 * @brief Parser callback data for MODIFY_CREDENTIAL.
 */
static modify_credential_data_t *modify_credential_data
 = &(command_data.modify_credential);

/**
 * @brief Parser callback data for MODIFY_FILTER.
 */
static modify_filter_data_t *modify_filter_data
 = &(command_data.modify_filter);

/**
 * @brief Parser callback data for MODIFY_GROUP.
 */
static modify_group_data_t *modify_group_data
 = &(command_data.modify_group);

/**
 * @brief Parser callback data for MODIFY_NOTE.
 */
static modify_note_data_t *modify_note_data
 = (modify_note_data_t*) &(command_data.create_note);

/**
 * @brief Parser callback data for MODIFY_OVERRIDE.
 */
static modify_override_data_t *modify_override_data
 = (modify_override_data_t*) &(command_data.create_override);

/**
 * @brief Parser callback data for MODIFY_PERMISSION.
 */
static modify_permission_data_t *modify_permission_data
 = &(command_data.modify_permission);

/**
 * @brief Parser callback data for MODIFY_PORT_LIST.
 */
static modify_port_list_data_t *modify_port_list_data
 = &(command_data.modify_port_list);

/**
 * @brief Parser callback data for MODIFY_REPORT_FORMAT.
 */
static modify_report_format_data_t *modify_report_format_data
 = &(command_data.modify_report_format);

/**
 * @brief Parser callback data for MODIFY_ROLE.
 */
static modify_role_data_t *modify_role_data
 = &(command_data.modify_role);

/**
 * @brief Parser callback data for MODIFY_SCANNER.
 */
static modify_scanner_data_t *modify_scanner_data
 = &(command_data.modify_scanner);

/**
 * @brief Parser callback data for MODIFY_SCHEDULE.
 */
static modify_schedule_data_t *modify_schedule_data
 = &(command_data.modify_schedule);

/**
 * @brief Parser callback data for MODIFY_SETTING.
 */
static modify_setting_data_t *modify_setting_data
 = &(command_data.modify_setting);

/**
 * @brief Parser callback data for MODIFY_TAG.
 */
static modify_tag_data_t *modify_tag_data
 = (modify_tag_data_t*) &(command_data.modify_tag);

/**
 * @brief Parser callback data for MODIFY_TARGET.
 */
static modify_target_data_t *modify_target_data
 = &(command_data.modify_target);

/**
 * @brief Parser callback data for MODIFY_TASK.
 */
static modify_task_data_t *modify_task_data
 = &(command_data.modify_task);

/**
 * @brief Parser callback data for MODIFY_USER.
 */
static modify_user_data_t *modify_user_data = &(command_data.modify_user);

/**
 * @brief Parser callback data for MOVE_TASK.
 */
static move_task_data_t *move_task_data = &(command_data.move_task);

/**
 * @brief Parser callback data for RESTORE.
 */
static restore_data_t *restore_data
 = (restore_data_t*) &(command_data.restore);

/**
 * @brief Parser callback data for RESUME_TASK.
 */
static resume_task_data_t *resume_task_data
 = (resume_task_data_t*) &(command_data.resume_task);

/**
 * @brief Parser callback data for START_TASK.
 */
static start_task_data_t *start_task_data
 = (start_task_data_t*) &(command_data.start_task);

/**
 * @brief Parser callback data for STOP_TASK.
 */
static stop_task_data_t *stop_task_data
 = (stop_task_data_t*) &(command_data.stop_task);

/**
 * @brief Parser callback data for TEST_ALERT.
 */
static test_alert_data_t *test_alert_data
 = (test_alert_data_t*) &(command_data.test_alert);

/**
 * @brief Parser callback data for VERIFY_REPORT_FORMAT.
 */
static verify_report_format_data_t *verify_report_format_data
 = (verify_report_format_data_t*) &(command_data.verify_report_format);

/**
 * @brief Parser callback data for VERIFY_SCANNER.
 */
static verify_scanner_data_t *verify_scanner_data
 = (verify_scanner_data_t*) &(command_data.verify_scanner);

/**
 * @brief Parser callback data for WIZARD.
 */
static run_wizard_data_t *run_wizard_data
 = (run_wizard_data_t*) &(command_data.wizard);

/**
 * @brief Buffer of output to the client.
 */
char to_client[TO_CLIENT_BUFFER_SIZE];

/**
 * @brief The start of the data in the \ref to_client buffer.
 */
buffer_size_t to_client_start = 0;
/**
 * @brief The end of the data in the \ref to_client buffer.
 */
buffer_size_t to_client_end = 0;

/**
 * @brief Client input parsing context.
 */
static GMarkupParseContext*
xml_context = NULL;

/**
 * @brief Client input parser.
 */
static GMarkupParser xml_parser;


/* Client state. */

/**
 * @brief Possible states of the client.
 */
typedef enum
{
  CLIENT_TOP,
  CLIENT_AUTHENTIC,

  CLIENT_AUTHENTICATE,
  CLIENT_AUTHENTICATE_CREDENTIALS,
  CLIENT_AUTHENTICATE_CREDENTIALS_PASSWORD,
  CLIENT_AUTHENTICATE_CREDENTIALS_USERNAME,
  CLIENT_CREATE_ALERT,
  CLIENT_CREATE_ALERT_ACTIVE,
  CLIENT_CREATE_ALERT_COMMENT,
  CLIENT_CREATE_ALERT_CONDITION,
  CLIENT_CREATE_ALERT_CONDITION_DATA,
  CLIENT_CREATE_ALERT_CONDITION_DATA_NAME,
  CLIENT_CREATE_ALERT_COPY,
  CLIENT_CREATE_ALERT_EVENT,
  CLIENT_CREATE_ALERT_EVENT_DATA,
  CLIENT_CREATE_ALERT_EVENT_DATA_NAME,
  CLIENT_CREATE_ALERT_FILTER,
  CLIENT_CREATE_ALERT_METHOD,
  CLIENT_CREATE_ALERT_METHOD_DATA,
  CLIENT_CREATE_ALERT_METHOD_DATA_NAME,
  CLIENT_CREATE_ALERT_NAME,
  CLIENT_CREATE_ASSET,
  CLIENT_CREATE_ASSET_REPORT,
  CLIENT_CREATE_ASSET_REPORT_FILTER,
  CLIENT_CREATE_ASSET_REPORT_FILTER_TERM,
  CLIENT_CREATE_ASSET_ASSET,
  CLIENT_CREATE_ASSET_ASSET_COMMENT,
  CLIENT_CREATE_ASSET_ASSET_NAME,
  CLIENT_CREATE_ASSET_ASSET_TYPE,
  CLIENT_CREATE_CONFIG,
  CLIENT_CREATE_CREDENTIAL,
  CLIENT_CREATE_CREDENTIAL_ALLOW_INSECURE,
  CLIENT_CREATE_CREDENTIAL_AUTH_ALGORITHM,
  CLIENT_CREATE_CREDENTIAL_CERTIFICATE,
  CLIENT_CREATE_CREDENTIAL_COMMENT,
  CLIENT_CREATE_CREDENTIAL_COMMUNITY,
  CLIENT_CREATE_CREDENTIAL_COPY,
  CLIENT_CREATE_CREDENTIAL_KEY,
  CLIENT_CREATE_CREDENTIAL_KEY_PHRASE,
  CLIENT_CREATE_CREDENTIAL_KEY_PRIVATE,
  CLIENT_CREATE_CREDENTIAL_KEY_PUBLIC,
  CLIENT_CREATE_CREDENTIAL_LOGIN,
  CLIENT_CREATE_CREDENTIAL_NAME,
  CLIENT_CREATE_CREDENTIAL_PASSWORD,
  CLIENT_CREATE_CREDENTIAL_PRIVACY,
  CLIENT_CREATE_CREDENTIAL_PRIVACY_ALGORITHM,
  CLIENT_CREATE_CREDENTIAL_PRIVACY_PASSWORD,
  CLIENT_CREATE_CREDENTIAL_TYPE,
  CLIENT_CREATE_FILTER,
  CLIENT_CREATE_FILTER_COMMENT,
  CLIENT_CREATE_FILTER_COPY,
  CLIENT_CREATE_FILTER_NAME,
  CLIENT_CREATE_FILTER_TERM,
  CLIENT_CREATE_FILTER_TYPE,
  CLIENT_CREATE_GROUP,
  CLIENT_CREATE_GROUP_COMMENT,
  CLIENT_CREATE_GROUP_COPY,
  CLIENT_CREATE_GROUP_NAME,
  CLIENT_CREATE_GROUP_USERS,
  CLIENT_CREATE_GROUP_SPECIALS,
  CLIENT_CREATE_GROUP_SPECIALS_FULL,
  CLIENT_CREATE_NOTE,
  CLIENT_CREATE_NOTE_ACTIVE,
  CLIENT_CREATE_NOTE_COPY,
  CLIENT_CREATE_NOTE_HOSTS,
  CLIENT_CREATE_NOTE_NVT,
  CLIENT_CREATE_NOTE_PORT,
  CLIENT_CREATE_NOTE_RESULT,
  CLIENT_CREATE_NOTE_SEVERITY,
  CLIENT_CREATE_NOTE_TASK,
  CLIENT_CREATE_NOTE_TEXT,
  CLIENT_CREATE_NOTE_THREAT,
  CLIENT_CREATE_OVERRIDE,
  CLIENT_CREATE_OVERRIDE_ACTIVE,
  CLIENT_CREATE_OVERRIDE_COPY,
  CLIENT_CREATE_OVERRIDE_HOSTS,
  CLIENT_CREATE_OVERRIDE_NEW_SEVERITY,
  CLIENT_CREATE_OVERRIDE_NEW_THREAT,
  CLIENT_CREATE_OVERRIDE_NVT,
  CLIENT_CREATE_OVERRIDE_PORT,
  CLIENT_CREATE_OVERRIDE_RESULT,
  CLIENT_CREATE_OVERRIDE_SEVERITY,
  CLIENT_CREATE_OVERRIDE_TASK,
  CLIENT_CREATE_OVERRIDE_TEXT,
  CLIENT_CREATE_OVERRIDE_THREAT,
  CLIENT_CREATE_PERMISSION,
  CLIENT_CREATE_PERMISSION_COMMENT,
  CLIENT_CREATE_PERMISSION_COPY,
  CLIENT_CREATE_PERMISSION_NAME,
  CLIENT_CREATE_PERMISSION_RESOURCE,
  CLIENT_CREATE_PERMISSION_RESOURCE_TYPE,
  CLIENT_CREATE_PERMISSION_SUBJECT,
  CLIENT_CREATE_PERMISSION_SUBJECT_TYPE,
  CLIENT_CREATE_PORT_LIST,
  CLIENT_CREATE_PORT_RANGE,
  CLIENT_CREATE_PORT_RANGE_COMMENT,
  CLIENT_CREATE_PORT_RANGE_END,
  CLIENT_CREATE_PORT_RANGE_PORT_LIST,
  CLIENT_CREATE_PORT_RANGE_START,
  CLIENT_CREATE_PORT_RANGE_TYPE,
  CLIENT_CREATE_REPORT_FORMAT,
  /* CREATE_REPORT. */
  CLIENT_CREATE_REPORT,
  CLIENT_CREATE_REPORT_IN_ASSETS,
  CLIENT_CREATE_REPORT_REPORT,
  CLIENT_CREATE_REPORT_RR,
  CLIENT_CREATE_REPORT_RR_FILTERS,
  CLIENT_CREATE_REPORT_RR_ERRORS,
  CLIENT_CREATE_REPORT_RR_ERRORS_COUNT,
  CLIENT_CREATE_REPORT_RR_ERRORS_ERROR,
  CLIENT_CREATE_REPORT_RR_ERRORS_ERROR_DESCRIPTION,
  CLIENT_CREATE_REPORT_RR_ERRORS_ERROR_HOST,
  CLIENT_CREATE_REPORT_RR_ERRORS_ERROR_HOST_ASSET,
  CLIENT_CREATE_REPORT_RR_ERRORS_ERROR_HOST_HOSTNAME,
  CLIENT_CREATE_REPORT_RR_ERRORS_ERROR_NVT,
  CLIENT_CREATE_REPORT_RR_ERRORS_ERROR_NVT_CVSS_BASE,
  CLIENT_CREATE_REPORT_RR_ERRORS_ERROR_NVT_NAME,
  CLIENT_CREATE_REPORT_RR_ERRORS_ERROR_PORT,
  CLIENT_CREATE_REPORT_RR_ERRORS_ERROR_SCAN_NVT_VERSION,
  CLIENT_CREATE_REPORT_RR_ERRORS_ERROR_SEVERITY,
  /* RR_H is for RR_HOST because it clashes with entities like HOST_START. */
  CLIENT_CREATE_REPORT_RR_H,
  CLIENT_CREATE_REPORT_RR_HOSTS,
  CLIENT_CREATE_REPORT_RR_HOST_COUNT,
  CLIENT_CREATE_REPORT_RR_HOST_END,
  CLIENT_CREATE_REPORT_RR_HOST_END_HOST,
  CLIENT_CREATE_REPORT_RR_HOST_START,
  CLIENT_CREATE_REPORT_RR_HOST_START_HOST,
  CLIENT_CREATE_REPORT_RR_H_DETAIL,
  CLIENT_CREATE_REPORT_RR_H_DETAIL_NAME,
  CLIENT_CREATE_REPORT_RR_H_DETAIL_SOURCE,
  CLIENT_CREATE_REPORT_RR_H_DETAIL_SOURCE_DESC,
  CLIENT_CREATE_REPORT_RR_H_DETAIL_SOURCE_NAME,
  CLIENT_CREATE_REPORT_RR_H_DETAIL_SOURCE_TYPE,
  CLIENT_CREATE_REPORT_RR_H_DETAIL_VALUE,
  CLIENT_CREATE_REPORT_RR_H_END,
  CLIENT_CREATE_REPORT_RR_H_IP,
  CLIENT_CREATE_REPORT_RR_H_START,
  CLIENT_CREATE_REPORT_RR_PORTS,
  CLIENT_CREATE_REPORT_RR_REPORT_FORMAT,
  CLIENT_CREATE_REPORT_RR_RESULTS,
  CLIENT_CREATE_REPORT_RR_RESULTS_RESULT,
  CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_COMMENT,
  CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_CREATION_TIME,
  CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_DESCRIPTION,
  
  CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_DETECTION,
  CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_DETECTION_RESULT,
  CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_DETECTION_RESULT_DETAILS,
  CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_DETECTION_RESULT_DETAILS_DETAIL,
  CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_DETECTION_RESULT_DETAILS_DETAIL_NAME,
  CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_DETECTION_RESULT_DETAILS_DETAIL_VALUE,


  CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_HOST,
  CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_HOST_ASSET,
  CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_HOST_HOSTNAME,
  CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_MODIFICATION_TIME,
  CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_NAME,
  CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_NOTES,
  CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_NVT,
  CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_NVT_BID,
  CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_NVT_CERT,
  CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_NVT_CERT_CERT_REF,
  CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_NVT_CVE,
  CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_NVT_CVSS_BASE,
  CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_NVT_FAMILY,
  CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_NVT_NAME,
  CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_NVT_XREF,
  CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_OWNER,
  CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_ORIGINAL_SEVERITY,
  CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_ORIGINAL_THREAT,
  CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_OVERRIDES,
  CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_PORT,
  CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_QOD,
  CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_QOD_TYPE,
  CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_QOD_VALUE,
  CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_SCAN_NVT_VERSION,
  CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_SEVERITY,
  CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_THREAT,
  CLIENT_CREATE_REPORT_RR_RESULT_COUNT,
  CLIENT_CREATE_REPORT_RR_SCAN_END,
  CLIENT_CREATE_REPORT_RR_SCAN_RUN_STATUS,
  CLIENT_CREATE_REPORT_RR_SCAN_START,
  CLIENT_CREATE_REPORT_RR_SORT,
  CLIENT_CREATE_REPORT_RR_TASK,
  CLIENT_CREATE_REPORT_TASK,
  CLIENT_CREATE_REPORT_TASK_COMMENT,
  CLIENT_CREATE_REPORT_TASK_NAME,
  CLIENT_CREATE_ROLE,
  CLIENT_CREATE_ROLE_COMMENT,
  CLIENT_CREATE_ROLE_COPY,
  CLIENT_CREATE_ROLE_NAME,
  CLIENT_CREATE_ROLE_USERS,
  CLIENT_CREATE_SCANNER,
  CLIENT_CREATE_SCANNER_COMMENT,
  CLIENT_CREATE_SCANNER_COPY,
  CLIENT_CREATE_SCANNER_NAME,
  CLIENT_CREATE_SCANNER_HOST,
  CLIENT_CREATE_SCANNER_PORT,
  CLIENT_CREATE_SCANNER_TYPE,
  CLIENT_CREATE_SCANNER_CA_PUB,
  CLIENT_CREATE_SCANNER_CREDENTIAL,
  CLIENT_CREATE_SCHEDULE,
  CLIENT_CREATE_SCHEDULE_COMMENT,
  CLIENT_CREATE_SCHEDULE_COPY,
  CLIENT_CREATE_SCHEDULE_ICALENDAR,
  CLIENT_CREATE_SCHEDULE_NAME,
  CLIENT_CREATE_SCHEDULE_TIMEZONE,
  CLIENT_CREATE_TAG,
  CLIENT_CREATE_TAG_ACTIVE,
  CLIENT_CREATE_TAG_COMMENT,
  CLIENT_CREATE_TAG_COPY,
  CLIENT_CREATE_TAG_NAME,
  CLIENT_CREATE_TAG_RESOURCES,
  CLIENT_CREATE_TAG_RESOURCES_RESOURCE,
  CLIENT_CREATE_TAG_RESOURCES_TYPE,
  CLIENT_CREATE_TAG_VALUE,
  CLIENT_CREATE_TARGET,
  CLIENT_CREATE_TARGET_ALIVE_TESTS,
  CLIENT_CREATE_TARGET_ALLOW_SIMULTANEOUS_IPS,
  CLIENT_CREATE_TARGET_ASSET_HOSTS,
  CLIENT_CREATE_TARGET_EXCLUDE_HOSTS,
  CLIENT_CREATE_TARGET_REVERSE_LOOKUP_ONLY,
  CLIENT_CREATE_TARGET_REVERSE_LOOKUP_UNIFY,
  CLIENT_CREATE_TARGET_COMMENT,
  CLIENT_CREATE_TARGET_COPY,
  CLIENT_CREATE_TARGET_ESXI_CREDENTIAL,
  CLIENT_CREATE_TARGET_ESXI_LSC_CREDENTIAL,
  CLIENT_CREATE_TARGET_HOSTS,
  CLIENT_CREATE_TARGET_NAME,
  CLIENT_CREATE_TARGET_PORT_LIST,
  CLIENT_CREATE_TARGET_PORT_RANGE,
  CLIENT_CREATE_TARGET_SMB_CREDENTIAL,
  CLIENT_CREATE_TARGET_SNMP_CREDENTIAL,
  CLIENT_CREATE_TARGET_SSH_CREDENTIAL,
  CLIENT_CREATE_TARGET_SSH_CREDENTIAL_PORT,
  CLIENT_CREATE_TARGET_SMB_LSC_CREDENTIAL,
  CLIENT_CREATE_TARGET_SSH_LSC_CREDENTIAL,
  CLIENT_CREATE_TARGET_SSH_LSC_CREDENTIAL_PORT,
  CLIENT_CREATE_TARGET_SSH_ELEVATE_CREDENTIAL,
  CLIENT_CREATE_TASK,
  CLIENT_CREATE_TASK_ALERT,
  CLIENT_CREATE_TASK_ALTERABLE,
  CLIENT_CREATE_TASK_COMMENT,
  CLIENT_CREATE_TASK_CONFIG,
  CLIENT_CREATE_TASK_COPY,
  CLIENT_CREATE_TASK_HOSTS_ORDERING,
  CLIENT_CREATE_TASK_NAME,
  CLIENT_CREATE_TASK_OBSERVERS,
  CLIENT_CREATE_TASK_OBSERVERS_GROUP,
  CLIENT_CREATE_TASK_PREFERENCES,
  CLIENT_CREATE_TASK_PREFERENCES_PREFERENCE,
  CLIENT_CREATE_TASK_PREFERENCES_PREFERENCE_NAME,
  CLIENT_CREATE_TASK_PREFERENCES_PREFERENCE_VALUE,
  CLIENT_CREATE_TASK_SCANNER,
  CLIENT_CREATE_TASK_SCHEDULE,
  CLIENT_CREATE_TASK_SCHEDULE_PERIODS,
  CLIENT_CREATE_TASK_TARGET,
  CLIENT_CREATE_TASK_USAGE_TYPE,
  CLIENT_CREATE_TICKET,
  CLIENT_CREATE_TLS_CERTIFICATE,
  CLIENT_CREATE_USER,
  CLIENT_CREATE_USER_COMMENT,
  CLIENT_CREATE_USER_COPY,
  CLIENT_CREATE_USER_GROUPS,
  CLIENT_CREATE_USER_GROUPS_GROUP,
  CLIENT_CREATE_USER_HOSTS,
  CLIENT_CREATE_USER_NAME,
  CLIENT_CREATE_USER_PASSWORD,
  CLIENT_CREATE_USER_ROLE,
  CLIENT_CREATE_USER_SOURCES,
  CLIENT_CREATE_USER_SOURCES_SOURCE,
  CLIENT_DELETE_ALERT,
  CLIENT_DELETE_ASSET,
  CLIENT_DELETE_CONFIG,
  CLIENT_DELETE_CREDENTIAL,
  CLIENT_DELETE_FILTER,
  CLIENT_DELETE_GROUP,
  CLIENT_DELETE_NOTE,
  CLIENT_DELETE_OVERRIDE,
  CLIENT_DELETE_PERMISSION,
  CLIENT_DELETE_PORT_LIST,
  CLIENT_DELETE_PORT_RANGE,
  CLIENT_DELETE_REPORT,
  CLIENT_DELETE_REPORT_FORMAT,
  CLIENT_DELETE_ROLE,
  CLIENT_DELETE_SCANNER,
  CLIENT_DELETE_SCHEDULE,
  CLIENT_DELETE_TAG,
  CLIENT_DELETE_TARGET,
  CLIENT_DELETE_TASK,
  CLIENT_DELETE_TICKET,
  CLIENT_DELETE_TLS_CERTIFICATE,
  CLIENT_DELETE_USER,
  CLIENT_DESCRIBE_AUTH,
  CLIENT_EMPTY_TRASHCAN,
  CLIENT_GET_AGGREGATES,
  CLIENT_GET_AGGREGATES_DATA_COLUMN,
  CLIENT_GET_AGGREGATES_SORT,
  CLIENT_GET_AGGREGATES_TEXT_COLUMN,
  CLIENT_GET_ALERTS,
  CLIENT_GET_ASSETS,
  CLIENT_GET_CONFIGS,
  CLIENT_GET_CREDENTIALS,
  CLIENT_GET_FEEDS,
  CLIENT_GET_FILTERS,
  CLIENT_GET_GROUPS,
  CLIENT_GET_INFO,
  CLIENT_GET_LICENSE,
  CLIENT_GET_NOTES,
  CLIENT_GET_NVTS,
  CLIENT_GET_NVT_FAMILIES,
  CLIENT_GET_OVERRIDES,
  CLIENT_GET_PERMISSIONS,
  CLIENT_GET_PORT_LISTS,
  CLIENT_GET_PREFERENCES,
  CLIENT_GET_REPORTS,
  CLIENT_GET_REPORT_FORMATS,
  CLIENT_GET_RESULTS,
  CLIENT_GET_ROLES,
  CLIENT_GET_SCANNERS,
  CLIENT_GET_SCHEDULES,
  CLIENT_GET_SETTINGS,
  CLIENT_GET_SYSTEM_REPORTS,
  CLIENT_GET_TAGS,
  CLIENT_GET_TARGETS,
  CLIENT_GET_TASKS,
  CLIENT_GET_TICKETS,
  CLIENT_GET_TLS_CERTIFICATES,
  CLIENT_GET_USERS,
  CLIENT_GET_VERSION,
  CLIENT_GET_VERSION_AUTHENTIC,
  CLIENT_GET_VULNS,
  CLIENT_HELP,
  CLIENT_MODIFY_ALERT,
  CLIENT_MODIFY_ALERT_ACTIVE,
  CLIENT_MODIFY_ALERT_COMMENT,
  CLIENT_MODIFY_ALERT_CONDITION,
  CLIENT_MODIFY_ALERT_CONDITION_DATA,
  CLIENT_MODIFY_ALERT_CONDITION_DATA_NAME,
  CLIENT_MODIFY_ALERT_EVENT,
  CLIENT_MODIFY_ALERT_EVENT_DATA,
  CLIENT_MODIFY_ALERT_EVENT_DATA_NAME,
  CLIENT_MODIFY_ALERT_FILTER,
  CLIENT_MODIFY_ALERT_METHOD,
  CLIENT_MODIFY_ALERT_METHOD_DATA,
  CLIENT_MODIFY_ALERT_METHOD_DATA_NAME,
  CLIENT_MODIFY_ALERT_NAME,
  CLIENT_MODIFY_ASSET,
  CLIENT_MODIFY_ASSET_COMMENT,
  CLIENT_MODIFY_AUTH,
  CLIENT_MODIFY_AUTH_GROUP,
  CLIENT_MODIFY_AUTH_GROUP_AUTH_CONF_SETTING,
  CLIENT_MODIFY_AUTH_GROUP_AUTH_CONF_SETTING_KEY,
  CLIENT_MODIFY_AUTH_GROUP_AUTH_CONF_SETTING_VALUE,
  CLIENT_MODIFY_CONFIG,
  CLIENT_MODIFY_CREDENTIAL,
  CLIENT_MODIFY_CREDENTIAL_ALLOW_INSECURE,
  CLIENT_MODIFY_CREDENTIAL_AUTH_ALGORITHM,
  CLIENT_MODIFY_CREDENTIAL_CERTIFICATE,
  CLIENT_MODIFY_CREDENTIAL_COMMENT,
  CLIENT_MODIFY_CREDENTIAL_COMMUNITY,
  CLIENT_MODIFY_CREDENTIAL_KEY,
  CLIENT_MODIFY_CREDENTIAL_KEY_PHRASE,
  CLIENT_MODIFY_CREDENTIAL_KEY_PRIVATE,
  CLIENT_MODIFY_CREDENTIAL_KEY_PUBLIC,
  CLIENT_MODIFY_CREDENTIAL_LOGIN,
  CLIENT_MODIFY_CREDENTIAL_NAME,
  CLIENT_MODIFY_CREDENTIAL_PASSWORD,
  CLIENT_MODIFY_CREDENTIAL_PRIVACY,
  CLIENT_MODIFY_CREDENTIAL_PRIVACY_ALGORITHM,
  CLIENT_MODIFY_CREDENTIAL_PRIVACY_PASSWORD,
  CLIENT_MODIFY_FILTER,
  CLIENT_MODIFY_FILTER_COMMENT,
  CLIENT_MODIFY_FILTER_NAME,
  CLIENT_MODIFY_FILTER_TERM,
  CLIENT_MODIFY_FILTER_TYPE,
  CLIENT_MODIFY_GROUP,
  CLIENT_MODIFY_GROUP_COMMENT,
  CLIENT_MODIFY_GROUP_NAME,
  CLIENT_MODIFY_GROUP_USERS,
  CLIENT_MODIFY_LICENSE,
  CLIENT_MODIFY_NOTE,
  CLIENT_MODIFY_NOTE_ACTIVE,
  CLIENT_MODIFY_NOTE_HOSTS,
  CLIENT_MODIFY_NOTE_PORT,
  CLIENT_MODIFY_NOTE_RESULT,
  CLIENT_MODIFY_NOTE_SEVERITY,
  CLIENT_MODIFY_NOTE_TASK,
  CLIENT_MODIFY_NOTE_TEXT,
  CLIENT_MODIFY_NOTE_THREAT,
  CLIENT_MODIFY_NOTE_NVT,
  CLIENT_MODIFY_OVERRIDE,
  CLIENT_MODIFY_OVERRIDE_ACTIVE,
  CLIENT_MODIFY_OVERRIDE_HOSTS,
  CLIENT_MODIFY_OVERRIDE_NEW_SEVERITY,
  CLIENT_MODIFY_OVERRIDE_NEW_THREAT,
  CLIENT_MODIFY_OVERRIDE_PORT,
  CLIENT_MODIFY_OVERRIDE_RESULT,
  CLIENT_MODIFY_OVERRIDE_SEVERITY,
  CLIENT_MODIFY_OVERRIDE_TASK,
  CLIENT_MODIFY_OVERRIDE_TEXT,
  CLIENT_MODIFY_OVERRIDE_THREAT,
  CLIENT_MODIFY_OVERRIDE_NVT,
  CLIENT_MODIFY_PERMISSION,
  CLIENT_MODIFY_PERMISSION_COMMENT,
  CLIENT_MODIFY_PERMISSION_NAME,
  CLIENT_MODIFY_PERMISSION_RESOURCE,
  CLIENT_MODIFY_PERMISSION_RESOURCE_TYPE,
  CLIENT_MODIFY_PERMISSION_SUBJECT,
  CLIENT_MODIFY_PERMISSION_SUBJECT_TYPE,
  CLIENT_MODIFY_PORT_LIST,
  CLIENT_MODIFY_PORT_LIST_COMMENT,
  CLIENT_MODIFY_PORT_LIST_NAME,
  CLIENT_MODIFY_REPORT_FORMAT,
  CLIENT_MODIFY_REPORT_FORMAT_ACTIVE,
  CLIENT_MODIFY_REPORT_FORMAT_NAME,
  CLIENT_MODIFY_REPORT_FORMAT_PARAM,
  CLIENT_MODIFY_REPORT_FORMAT_PARAM_NAME,
  CLIENT_MODIFY_REPORT_FORMAT_PARAM_VALUE,
  CLIENT_MODIFY_REPORT_FORMAT_SUMMARY,
  CLIENT_MODIFY_ROLE,
  CLIENT_MODIFY_ROLE_COMMENT,
  CLIENT_MODIFY_ROLE_NAME,
  CLIENT_MODIFY_ROLE_USERS,
  CLIENT_MODIFY_SCANNER,
  CLIENT_MODIFY_SCANNER_COMMENT,
  CLIENT_MODIFY_SCANNER_NAME,
  CLIENT_MODIFY_SCANNER_HOST,
  CLIENT_MODIFY_SCANNER_PORT,
  CLIENT_MODIFY_SCANNER_TYPE,
  CLIENT_MODIFY_SCANNER_CA_PUB,
  CLIENT_MODIFY_SCANNER_CREDENTIAL,
  CLIENT_MODIFY_SCHEDULE,
  CLIENT_MODIFY_SCHEDULE_COMMENT,
  CLIENT_MODIFY_SCHEDULE_ICALENDAR,
  CLIENT_MODIFY_SCHEDULE_NAME,
  CLIENT_MODIFY_SCHEDULE_TIMEZONE,
  CLIENT_MODIFY_SETTING,
  CLIENT_MODIFY_SETTING_NAME,
  CLIENT_MODIFY_SETTING_VALUE,
  CLIENT_MODIFY_TAG,
  CLIENT_MODIFY_TAG_ACTIVE,
  CLIENT_MODIFY_TAG_COMMENT,
  CLIENT_MODIFY_TAG_NAME,
  CLIENT_MODIFY_TAG_RESOURCES,
  CLIENT_MODIFY_TAG_RESOURCES_RESOURCE,
  CLIENT_MODIFY_TAG_RESOURCES_TYPE,
  CLIENT_MODIFY_TAG_VALUE,
  CLIENT_MODIFY_TARGET,
  CLIENT_MODIFY_TARGET_ALIVE_TESTS,
  CLIENT_MODIFY_TARGET_ALLOW_SIMULTANEOUS_IPS,
  CLIENT_MODIFY_TARGET_COMMENT,
  CLIENT_MODIFY_TARGET_ESXI_CREDENTIAL,
  CLIENT_MODIFY_TARGET_ESXI_LSC_CREDENTIAL,
  CLIENT_MODIFY_TARGET_HOSTS,
  CLIENT_MODIFY_TARGET_EXCLUDE_HOSTS,
  CLIENT_MODIFY_TARGET_REVERSE_LOOKUP_ONLY,
  CLIENT_MODIFY_TARGET_REVERSE_LOOKUP_UNIFY,
  CLIENT_MODIFY_TARGET_NAME,
  CLIENT_MODIFY_TARGET_PORT_LIST,
  CLIENT_MODIFY_TARGET_SMB_CREDENTIAL,
  CLIENT_MODIFY_TARGET_SNMP_CREDENTIAL,
  CLIENT_MODIFY_TARGET_SSH_CREDENTIAL,
  CLIENT_MODIFY_TARGET_SSH_ELEVATE_CREDENTIAL,
  CLIENT_MODIFY_TARGET_SSH_CREDENTIAL_PORT,
  CLIENT_MODIFY_TARGET_SMB_LSC_CREDENTIAL,
  CLIENT_MODIFY_TARGET_SSH_LSC_CREDENTIAL,
  CLIENT_MODIFY_TARGET_SSH_LSC_CREDENTIAL_PORT,
  CLIENT_MODIFY_TASK,
  CLIENT_MODIFY_TASK_ALERT,
  CLIENT_MODIFY_TASK_ALTERABLE,
  CLIENT_MODIFY_TASK_COMMENT,
  CLIENT_MODIFY_TASK_CONFIG,
  CLIENT_MODIFY_TASK_FILE,
  CLIENT_MODIFY_TASK_NAME,
  CLIENT_MODIFY_TASK_OBSERVERS,
  CLIENT_MODIFY_TASK_OBSERVERS_GROUP,
  CLIENT_MODIFY_TASK_PREFERENCES,
  CLIENT_MODIFY_TASK_PREFERENCES_PREFERENCE,
  CLIENT_MODIFY_TASK_PREFERENCES_PREFERENCE_NAME,
  CLIENT_MODIFY_TASK_PREFERENCES_PREFERENCE_VALUE,
  CLIENT_MODIFY_TASK_SCHEDULE,
  CLIENT_MODIFY_TASK_SCHEDULE_PERIODS,
  CLIENT_MODIFY_TASK_TARGET,
  CLIENT_MODIFY_TASK_HOSTS_ORDERING,
  CLIENT_MODIFY_TASK_SCANNER,
  CLIENT_MODIFY_TICKET,
  CLIENT_MODIFY_TLS_CERTIFICATE,
  CLIENT_MODIFY_USER,
  CLIENT_MODIFY_USER_COMMENT,
  CLIENT_MODIFY_USER_GROUPS,
  CLIENT_MODIFY_USER_GROUPS_GROUP,
  CLIENT_MODIFY_USER_HOSTS,
  CLIENT_MODIFY_USER_NAME,
  CLIENT_MODIFY_USER_NEW_NAME,
  CLIENT_MODIFY_USER_PASSWORD,
  CLIENT_MODIFY_USER_ROLE,
  CLIENT_MODIFY_USER_SOURCES,
  CLIENT_MODIFY_USER_SOURCES_SOURCE,
  CLIENT_MOVE_TASK,
  CLIENT_RESTORE,
  CLIENT_RESUME_TASK,
  CLIENT_RUN_WIZARD,
  CLIENT_RUN_WIZARD_MODE,
  CLIENT_RUN_WIZARD_NAME,
  CLIENT_RUN_WIZARD_PARAMS,
  CLIENT_RUN_WIZARD_PARAMS_PARAM,
  CLIENT_RUN_WIZARD_PARAMS_PARAM_NAME,
  CLIENT_RUN_WIZARD_PARAMS_PARAM_VALUE,
  CLIENT_START_TASK,
  CLIENT_STOP_TASK,
  CLIENT_TEST_ALERT,
  CLIENT_VERIFY_REPORT_FORMAT,
  CLIENT_VERIFY_SCANNER,
} client_state_t;

/**
 * @brief The state of the client.
 */
static client_state_t client_state = CLIENT_TOP;

/**
 * @brief Set the client state.
 *
 * @param[in]  state  New state.
 */
static void
set_client_state (client_state_t state)
{
  client_state = state;
  g_debug ("   client state set: %i", client_state);
}


/* XML parser handlers. */

/**
 * @brief Expand to XML for a STATUS_ERROR_SYNTAX response.
 *
 * This is a variant of the XML_ERROR_SYNTAX macro to allow for a
 * runtime defined syntax_text attribute value.
 *
 * @param  tag   Name of the command generating the response.
 * @param text   Value for the status_text attribute of the response.
 *               The function takes care of proper quoting.
 *
 * @return A malloced XML string.  The caller must use g_free to
 *         release it.
 */
static char *
make_xml_error_syntax (const char *tag, const char *text)
{
  char *textbuf;
  char *ret;

  textbuf = g_markup_escape_text (text, -1);
  ret = g_strdup_printf ("<%s_response status=\"" STATUS_ERROR_SYNTAX "\""
                         " status_text=\"%s\"/>", tag, textbuf);
  g_free (textbuf);
  return ret;
}

/**
 * @brief Insert else clause for GET command in gmp_xml_handle_start_element.
 *
 * @param[in]  lower  What to get, in lowercase.
 * @param[in]  upper  What to get, in uppercase.
 */
#define ELSE_GET_START(lower, upper)                                    \
  else if (strcasecmp ("GET_" G_STRINGIFY (upper), element_name) == 0)  \
    {                                                                   \
      get_ ## lower ## _start (attribute_names, attribute_values);      \
      set_client_state (CLIENT_GET_ ## upper);                          \
    }

/**
 * @brief Set read_over flag on a parser.
 *
 * @param[in]  gmp_parser  Parser.
 */
static void
set_read_over (gmp_parser_t *gmp_parser)
{
  if (gmp_parser->read_over == 0)
    {
      gmp_parser->read_over = 1;
      gmp_parser->parent_state = client_state;
    }
}

/**
 * @brief Insert else clause for error in gmp_xml_handle_start_element.
 */
#define ELSE_READ_OVER                                          \
  else                                                          \
    {                                                           \
      set_read_over (gmp_parser);                               \
    }                                                           \
  break

/**
 * @brief Insert else clause for gmp_xml_handle_start_element in create_task.
 */
#define ELSE_READ_OVER_CREATE_TASK                              \
  else                                                          \
    {                                                           \
      request_delete_task (&create_task_data->task);            \
      set_read_over (gmp_parser);                               \
    }                                                           \
  break

/** @todo Free globals when tags open, in case of duplicate tags. */
/**
 * @brief Handle the start of a GMP XML element.
 *
 * React to the start of an XML element according to the current value
 * of \ref client_state, usually adjusting \ref client_state to indicate
 * the change (with \ref set_client_state).  Call \ref send_to_client to
 * queue any responses for the client.
 *
 * Set error parameter on encountering an error.
 *
 * @param[in]  context           Parser context.
 * @param[in]  element_name      XML element name.
 * @param[in]  attribute_names   XML attribute names.
 * @param[in]  attribute_values  XML attribute values.
 * @param[in]  user_data         GMP parser.
 * @param[in]  error             Error parameter.
 */
static void
gmp_xml_handle_start_element (/* unused */ GMarkupParseContext* context,
                              const gchar *element_name,
                              const gchar **attribute_names,
                              const gchar **attribute_values,
                              gpointer user_data,
                              GError **error)
{
  gmp_parser_t *gmp_parser = (gmp_parser_t*) user_data;
  int (*write_to_client) (const char *, void*)
    = (int (*) (const char *, void*)) gmp_parser->client_writer;
  void* write_to_client_data = (void*) gmp_parser->client_writer_data;

  g_debug ("   XML  start: %s (%i)", element_name, client_state);

  if (gmp_parser->read_over)
    gmp_parser->read_over++;
  else switch (client_state)
    {
      case CLIENT_TOP:
        if (strcasecmp ("GET_VERSION", element_name) == 0)
          set_client_state (CLIENT_GET_VERSION);
        else if (strcasecmp ("AUTHENTICATE", element_name) == 0)
          set_client_state (CLIENT_AUTHENTICATE);
        else
          {
            /** @todo If a real GMP command, return STATUS_ERROR_MUST_AUTH. */
            if (send_to_client
                 (XML_ERROR_SYNTAX ("gmp",
                                    "Only command GET_VERSION is"
                                    " allowed before AUTHENTICATE"),
                  write_to_client,
                  write_to_client_data))
              {
                error_send_to_client (error);
                return;
              }
            g_set_error (error, G_MARKUP_ERROR, G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Must authenticate first.");
          }
        break;

      case CLIENT_AUTHENTIC:
        if (command_disabled (gmp_parser, element_name))
          {
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_UNAVAILABLE ("gmp",
                                     "Service unavailable: Command disabled"));
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Command Unavailable");
          }
        else if (strcasecmp ("AUTHENTICATE", element_name) == 0)
          {
            free_credentials (&current_credentials);
            set_client_state (CLIENT_AUTHENTICATE);
          }
        else if (strcasecmp ("CREATE_ASSET", element_name) == 0)
          set_client_state (CLIENT_CREATE_ASSET);
        else if (strcasecmp ("CREATE_CONFIG", element_name) == 0)
          {
            create_config_start (gmp_parser, attribute_names,
                                 attribute_values);
            set_client_state (CLIENT_CREATE_CONFIG);
          }
        else if (strcasecmp ("CREATE_ALERT", element_name) == 0)
          {
            create_alert_data->condition_data = make_array ();
            create_alert_data->event_data = make_array ();
            create_alert_data->method_data = make_array ();

            gvm_append_string (&create_alert_data->part_data, "");
            gvm_append_string (&create_alert_data->part_name, "");
            gvm_append_string (&create_alert_data->comment, "");
            gvm_append_string (&create_alert_data->name, "");
            gvm_append_string (&create_alert_data->condition, "");
            gvm_append_string (&create_alert_data->method, "");
            gvm_append_string (&create_alert_data->event, "");

            set_client_state (CLIENT_CREATE_ALERT);
          }
        else if (strcasecmp ("CREATE_CREDENTIAL", element_name) == 0)
          {
            gvm_append_string (&create_credential_data->comment, "");
            gvm_append_string (&create_credential_data->name, "");
            set_client_state (CLIENT_CREATE_CREDENTIAL);
          }
        else if (strcasecmp ("CREATE_FILTER", element_name) == 0)
          {
            gvm_append_string (&create_filter_data->comment, "");
            gvm_append_string (&create_filter_data->term, "");
            set_client_state (CLIENT_CREATE_FILTER);
          }
        else if (strcasecmp ("CREATE_GROUP", element_name) == 0)
          {
            gvm_append_string (&create_group_data->users, "");
            set_client_state (CLIENT_CREATE_GROUP);
          }
        else if (strcasecmp ("CREATE_ROLE", element_name) == 0)
          {
            gvm_append_string (&create_role_data->users, "");
            set_client_state (CLIENT_CREATE_ROLE);
          }
        else if (strcasecmp ("CREATE_NOTE", element_name) == 0)
          set_client_state (CLIENT_CREATE_NOTE);
        else if (strcasecmp ("CREATE_OVERRIDE", element_name) == 0)
          set_client_state (CLIENT_CREATE_OVERRIDE);
        else if (strcasecmp ("CREATE_PORT_LIST", element_name) == 0)
          {
            create_port_list_start (gmp_parser, attribute_names,
                                    attribute_values);
            set_client_state (CLIENT_CREATE_PORT_LIST);
          }
        else if (strcasecmp ("CREATE_PORT_RANGE", element_name) == 0)
          set_client_state (CLIENT_CREATE_PORT_RANGE);
        else if (strcasecmp ("CREATE_PERMISSION", element_name) == 0)
          {
            gvm_append_string (&create_permission_data->comment, "");
            set_client_state (CLIENT_CREATE_PERMISSION);
          }
        else if (strcasecmp ("CREATE_REPORT", element_name) == 0)
          set_client_state (CLIENT_CREATE_REPORT);
        else if (strcasecmp ("CREATE_REPORT_FORMAT", element_name) == 0)
          {
            create_report_format_start (gmp_parser, attribute_names,
                                        attribute_values);
            set_client_state (CLIENT_CREATE_REPORT_FORMAT);
          }
        else if (strcasecmp ("CREATE_SCANNER", element_name) == 0)
          set_client_state (CLIENT_CREATE_SCANNER);
        else if (strcasecmp ("CREATE_SCHEDULE", element_name) == 0)
          set_client_state (CLIENT_CREATE_SCHEDULE);
        else if (strcasecmp ("CREATE_TAG", element_name) == 0)
          {
            create_tag_data->resource_ids = NULL;
            set_client_state (CLIENT_CREATE_TAG);
          }
        else if (strcasecmp ("CREATE_TARGET", element_name) == 0)
          {
            gvm_append_string (&create_target_data->comment, "");
            set_client_state (CLIENT_CREATE_TARGET);
          }
        else if (strcasecmp ("CREATE_TASK", element_name) == 0)
          {
            create_task_data->task = make_task (NULL, NULL, 1, 1);
            create_task_data->alerts = make_array ();
            create_task_data->groups = make_array ();
            set_client_state (CLIENT_CREATE_TASK);
          }
        else if (strcasecmp ("CREATE_TICKET", element_name) == 0)
          {
            create_ticket_start (gmp_parser, attribute_names,
                                 attribute_values);
            set_client_state (CLIENT_CREATE_TICKET);
          }
        else if (strcasecmp ("CREATE_TLS_CERTIFICATE", element_name) == 0)
          {
            create_tls_certificate_start (gmp_parser, attribute_names,
                                          attribute_values);
            set_client_state (CLIENT_CREATE_TLS_CERTIFICATE);
          }
        else if (strcasecmp ("CREATE_USER", element_name) == 0)
          {
            set_client_state (CLIENT_CREATE_USER);
            create_user_data->groups = make_array ();
            create_user_data->roles = make_array ();
            create_user_data->hosts_allow = 0;
          }
        else if (strcasecmp ("DELETE_ASSET", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "asset_id",
                              &delete_asset_data->asset_id);
            append_attribute (attribute_names, attribute_values, "report_id",
                              &delete_asset_data->report_id);
            set_client_state (CLIENT_DELETE_ASSET);
          }
        else if (strcasecmp ("DELETE_CONFIG", element_name) == 0)
          {
            const gchar* attribute;
            append_attribute (attribute_names, attribute_values,
                              "config_id", &delete_config_data->config_id);
            if (find_attribute (attribute_names, attribute_values,
                                "ultimate", &attribute))
              delete_config_data->ultimate = strcmp (attribute, "0");
            else
              delete_config_data->ultimate = 0;
            set_client_state (CLIENT_DELETE_CONFIG);
          }
        else if (strcasecmp ("DELETE_ALERT", element_name) == 0)
          {
            const gchar* attribute;
            append_attribute (attribute_names, attribute_values,
                              "alert_id",
                              &delete_alert_data->alert_id);
            if (find_attribute (attribute_names, attribute_values,
                                "ultimate", &attribute))
              delete_alert_data->ultimate = strcmp (attribute, "0");
            else
              delete_alert_data->ultimate = 0;
            set_client_state (CLIENT_DELETE_ALERT);
          }
        else if (strcasecmp ("DELETE_CREDENTIAL", element_name) == 0)
          {
            const gchar* attribute;
            append_attribute (attribute_names, attribute_values,
                              "credential_id",
                              &delete_credential_data->credential_id);
            if (find_attribute (attribute_names, attribute_values,
                                "ultimate", &attribute))
              delete_credential_data->ultimate
               = strcmp (attribute, "0");
            else
              delete_credential_data->ultimate = 0;
            set_client_state (CLIENT_DELETE_CREDENTIAL);
          }
        else if (strcasecmp ("DELETE_FILTER", element_name) == 0)
          {
            const gchar* attribute;
            append_attribute (attribute_names, attribute_values, "filter_id",
                              &delete_filter_data->filter_id);
            if (find_attribute (attribute_names, attribute_values,
                                "ultimate", &attribute))
              delete_filter_data->ultimate = strcmp (attribute, "0");
            else
              delete_filter_data->ultimate = 0;
            set_client_state (CLIENT_DELETE_FILTER);
          }
        else if (strcasecmp ("DELETE_GROUP", element_name) == 0)
          {
            const gchar* attribute;
            append_attribute (attribute_names, attribute_values, "group_id",
                              &delete_group_data->group_id);
            if (find_attribute (attribute_names, attribute_values,
                                "ultimate", &attribute))
              delete_group_data->ultimate = strcmp (attribute, "0");
            else
              delete_group_data->ultimate = 0;
            set_client_state (CLIENT_DELETE_GROUP);
          }
        else if (strcasecmp ("DELETE_NOTE", element_name) == 0)
          {
            const gchar* attribute;
            append_attribute (attribute_names, attribute_values, "note_id",
                              &delete_note_data->note_id);
            if (find_attribute (attribute_names, attribute_values,
                                "ultimate", &attribute))
              delete_note_data->ultimate = strcmp (attribute, "0");
            else
              delete_note_data->ultimate = 0;
            set_client_state (CLIENT_DELETE_NOTE);
          }
        else if (strcasecmp ("DELETE_OVERRIDE", element_name) == 0)
          {
            const gchar* attribute;
            append_attribute (attribute_names, attribute_values, "override_id",
                              &delete_override_data->override_id);
            if (find_attribute (attribute_names, attribute_values,
                                "ultimate", &attribute))
              delete_override_data->ultimate = strcmp (attribute, "0");
            else
              delete_override_data->ultimate = 0;
            set_client_state (CLIENT_DELETE_OVERRIDE);
          }
        else if (strcasecmp ("DELETE_PERMISSION", element_name) == 0)
          {
            const gchar* attribute;
            append_attribute (attribute_names, attribute_values,
                              "permission_id",
                              &delete_permission_data->permission_id);
            if (find_attribute (attribute_names, attribute_values,
                                "ultimate", &attribute))
              delete_permission_data->ultimate = strcmp (attribute, "0");
            else
              delete_permission_data->ultimate = 0;
            set_client_state (CLIENT_DELETE_PERMISSION);
          }
        else if (strcasecmp ("DELETE_PORT_LIST", element_name) == 0)
          {
            const gchar* attribute;
            append_attribute (attribute_names, attribute_values, "port_list_id",
                              &delete_port_list_data->port_list_id);
            if (find_attribute (attribute_names, attribute_values,
                                "ultimate", &attribute))
              delete_port_list_data->ultimate = strcmp (attribute, "0");
            else
              delete_port_list_data->ultimate = 0;
            set_client_state (CLIENT_DELETE_PORT_LIST);
          }
        else if (strcasecmp ("DELETE_PORT_RANGE", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "port_range_id",
                              &delete_port_range_data->port_range_id);
            set_client_state (CLIENT_DELETE_PORT_RANGE);
          }
        else if (strcasecmp ("DELETE_REPORT", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "report_id",
                              &delete_report_data->report_id);
            set_client_state (CLIENT_DELETE_REPORT);
          }
        else if (strcasecmp ("DELETE_REPORT_FORMAT", element_name) == 0)
          {
            const gchar* attribute;
            append_attribute (attribute_names, attribute_values, "report_format_id",
                              &delete_report_format_data->report_format_id);
            if (find_attribute (attribute_names, attribute_values,
                                "ultimate", &attribute))
              delete_report_format_data->ultimate = strcmp (attribute,
                                                            "0");
            else
              delete_report_format_data->ultimate = 0;
            set_client_state (CLIENT_DELETE_REPORT_FORMAT);
          }
        else if (strcasecmp ("DELETE_ROLE", element_name) == 0)
          {
            const gchar* attribute;
            append_attribute (attribute_names, attribute_values, "role_id",
                              &delete_role_data->role_id);
            if (find_attribute (attribute_names, attribute_values,
                                "ultimate", &attribute))
              delete_role_data->ultimate = strcmp (attribute, "0");
            else
              delete_role_data->ultimate = 0;
            set_client_state (CLIENT_DELETE_ROLE);
          }
        else if (strcasecmp ("DELETE_SCANNER", element_name) == 0)
          {
            const gchar* attribute;
            append_attribute (attribute_names, attribute_values,
                              "scanner_id", &delete_scanner_data->scanner_id);
            if (find_attribute (attribute_names, attribute_values, "ultimate",
                                &attribute))
              delete_scanner_data->ultimate = strcmp (attribute, "0");
            else
              delete_scanner_data->ultimate = 0;
            set_client_state (CLIENT_DELETE_SCANNER);
          }
        else if (strcasecmp ("DELETE_SCHEDULE", element_name) == 0)
          {
            const gchar* attribute;
            append_attribute (attribute_names, attribute_values, "schedule_id",
                              &delete_schedule_data->schedule_id);
            if (find_attribute (attribute_names, attribute_values,
                                "ultimate", &attribute))
              delete_schedule_data->ultimate = strcmp (attribute, "0");
            else
              delete_schedule_data->ultimate = 0;
            set_client_state (CLIENT_DELETE_SCHEDULE);
          }
        else if (strcasecmp ("DELETE_TAG", element_name) == 0)
          {
            const gchar* attribute;
            append_attribute (attribute_names, attribute_values, "tag_id",
                              &delete_tag_data->tag_id);
            if (find_attribute (attribute_names, attribute_values,
                                "ultimate", &attribute))
              delete_tag_data->ultimate = strcmp (attribute, "0");
            else
              delete_tag_data->ultimate = 0;
            set_client_state (CLIENT_DELETE_TAG);
          }
        else if (strcasecmp ("DELETE_TARGET", element_name) == 0)
          {
            const gchar* attribute;
            append_attribute (attribute_names, attribute_values, "target_id",
                              &delete_target_data->target_id);
            if (find_attribute (attribute_names, attribute_values,
                                "ultimate", &attribute))
              delete_target_data->ultimate = strcmp (attribute, "0");
            else
              delete_target_data->ultimate = 0;
            set_client_state (CLIENT_DELETE_TARGET);
          }
        else if (strcasecmp ("DELETE_TASK", element_name) == 0)
          {
            const gchar* attribute;
            append_attribute (attribute_names, attribute_values, "task_id",
                              &delete_task_data->task_id);
            if (find_attribute (attribute_names, attribute_values,
                                "ultimate", &attribute))
              delete_task_data->ultimate = strcmp (attribute, "0");
            else
              delete_task_data->ultimate = 0;
            set_client_state (CLIENT_DELETE_TASK);
          }
        else if (strcasecmp ("DELETE_TICKET", element_name) == 0)
          {
            delete_start ("ticket", "Ticket",
                          attribute_names, attribute_values);
            set_client_state (CLIENT_DELETE_TICKET);
          }
        else if (strcasecmp ("DELETE_TLS_CERTIFICATE", element_name) == 0)
          {
            delete_start ("tls_certificate", "TLS Certificate",
                          attribute_names, attribute_values);
            set_client_state (CLIENT_DELETE_TLS_CERTIFICATE);
          }
        else if (strcasecmp ("DELETE_USER", element_name) == 0)
          {
            const gchar* attribute;
            append_attribute (attribute_names, attribute_values, "name",
                              &delete_user_data->name);
            append_attribute (attribute_names, attribute_values, "user_id",
                              &delete_user_data->user_id);
            append_attribute (attribute_names, attribute_values,
                              "inheritor_id",
                              &delete_user_data->inheritor_id);
            append_attribute (attribute_names, attribute_values,
                              "inheritor_name",
                              &delete_user_data->inheritor_name);
            if (find_attribute (attribute_names, attribute_values,
                                "ultimate", &attribute))
              delete_user_data->ultimate = strcmp (attribute, "0");
            else
              delete_user_data->ultimate = 0;
            set_client_state (CLIENT_DELETE_USER);
          }
        else if (strcasecmp ("DESCRIBE_AUTH", element_name) == 0)
          set_client_state (CLIENT_DESCRIBE_AUTH);
        else if (strcasecmp ("EMPTY_TRASHCAN", element_name) == 0)
          set_client_state (CLIENT_EMPTY_TRASHCAN);
        else if (strcasecmp ("GET_AGGREGATES", element_name) == 0)
          {
            gchar *data_column = g_strdup ("");
            sort_data_t *sort_data;
            const gchar *attribute;
            int sort_order_given;

            sort_data = g_malloc0 (sizeof (sort_data_t));
            sort_data->field = g_strdup ("");
            sort_data->stat = g_strdup ("");

            append_attribute (attribute_names, attribute_values, "type",
                              &get_aggregates_data->type);

            if (get_aggregates_data->type
                && strcasecmp (get_aggregates_data->type, "info") == 0)
            {
              append_attribute (attribute_names, attribute_values, "info_type",
                                &get_aggregates_data->subtype);
            }

            append_attribute (attribute_names, attribute_values, "data_column",
                              &data_column);
            get_aggregates_data->data_columns
              = g_list_append (get_aggregates_data->data_columns,
                               data_column);

            append_attribute (attribute_names, attribute_values, "group_column",
                              &get_aggregates_data->group_column);

            append_attribute (attribute_names, attribute_values,
                              "subgroup_column",
                              &get_aggregates_data->subgroup_column);

            append_attribute (attribute_names, attribute_values, "sort_field",
                              &(sort_data->field));
            append_attribute (attribute_names, attribute_values, "sort_stat",
                              &(sort_data->stat));
            if (find_attribute (attribute_names, attribute_values,
                                "sort_order", &attribute))
              {
                sort_data->order = strcmp (attribute, "descending");
                sort_order_given = 1;
              }
            else
              {
                sort_data->order = 1;
                sort_order_given = 0;
              }

            if (strcmp (sort_data->field, "") || sort_order_given)
              {
                get_aggregates_data->sort_data
                  = g_list_append (get_aggregates_data->sort_data,
                                  sort_data);
              }

            append_attribute (attribute_names, attribute_values, "mode",
                              &get_aggregates_data->mode);

            if (find_attribute (attribute_names, attribute_values,
                                "first_group", &attribute))
              get_aggregates_data->first_group = atoi (attribute) - 1;
            else
              get_aggregates_data->first_group = 0;

            if (find_attribute (attribute_names, attribute_values,
                                "max_groups", &attribute))
              get_aggregates_data->max_groups = atoi (attribute);
            else
              get_aggregates_data->max_groups = -1;

            get_data_parse_attributes (&get_aggregates_data->get,
                                       get_aggregates_data->type
                                        ? get_aggregates_data->type
                                        : "",
                                       attribute_names,
                                       attribute_values);

            // get_aggregates ignores pagination by default
            if (find_attribute (attribute_names, attribute_values,
                                "ignore_pagination", &attribute) == 0)
              get_aggregates_data->get.ignore_pagination = 1;

            // Extra selection attribute for configs and tasks
            if (find_attribute (attribute_names, attribute_values,
                                "usage_type", &attribute))
              {
                get_data_set_extra (&get_aggregates_data->get,
                                    "usage_type",
                                    attribute);
              }

            set_client_state (CLIENT_GET_AGGREGATES);
          }
        else if (strcasecmp ("GET_CONFIGS", element_name) == 0)
          {
            const gchar* attribute;

            get_data_parse_attributes (&get_configs_data->get,
                                       "config",
                                       attribute_names,
                                       attribute_values);

            if (find_attribute (attribute_names, attribute_values,
                                "tasks", &attribute))
              get_configs_data->tasks = strcmp (attribute, "0");
            else
              get_configs_data->tasks = 0;

            if (find_attribute (attribute_names, attribute_values,
                                "families", &attribute))
              get_configs_data->families = strcmp (attribute, "0");
            else
              get_configs_data->families = 0;

            if (find_attribute (attribute_names, attribute_values,
                                "preferences", &attribute))
              get_configs_data->preferences = strcmp (attribute, "0");
            else
              get_configs_data->preferences = 0;

            if (find_attribute (attribute_names, attribute_values,
                                "usage_type", &attribute))
              {
                get_data_set_extra (&get_configs_data->get,
                                    "usage_type",
                                    attribute);
              }

            set_client_state (CLIENT_GET_CONFIGS);
          }
        else if (strcasecmp ("GET_ALERTS", element_name) == 0)
          {
            const gchar* attribute;

            get_data_parse_attributes (&get_alerts_data->get,
                                       "alert",
                                       attribute_names,
                                       attribute_values);
            if (find_attribute (attribute_names, attribute_values,
                                "tasks", &attribute))
              get_alerts_data->tasks = strcmp (attribute, "0");
            else
              get_alerts_data->tasks = 0;

            set_client_state (CLIENT_GET_ALERTS);
          }
        else if (strcasecmp ("GET_ASSETS", element_name) == 0)
          {
            const gchar* typebuf;
            get_data_parse_attributes (&get_assets_data->get, "asset",
                                       attribute_names,
                                       attribute_values);
            if (find_attribute (attribute_names, attribute_values,
                                "type", &typebuf))
              get_assets_data->type = g_ascii_strdown (typebuf, -1);
            set_client_state (CLIENT_GET_ASSETS);
          }
        else if (strcasecmp ("GET_CREDENTIALS", element_name) == 0)
          {
            const gchar* attribute;

            get_data_parse_attributes (&get_credentials_data->get,
                                       "credential",
                                       attribute_names,
                                       attribute_values);

            if (find_attribute (attribute_names, attribute_values,
                                "scanners", &attribute))
              get_credentials_data->scanners = strcmp (attribute, "0");
            else
              get_credentials_data->scanners = 0;

            if (find_attribute (attribute_names, attribute_values,
                                "targets", &attribute))
              get_credentials_data->targets = strcmp (attribute, "0");
            else
              get_credentials_data->targets = 0;

            append_attribute (attribute_names, attribute_values, "format",
                              &get_credentials_data->format);
            set_client_state (CLIENT_GET_CREDENTIALS);
          }
        else if (strcasecmp ("GET_FEEDS", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "type",
                              &get_feeds_data->type);
            set_client_state (CLIENT_GET_FEEDS);
          }
        else if (strcasecmp ("GET_FILTERS", element_name) == 0)
          {
            const gchar* attribute;
            get_data_parse_attributes (&get_filters_data->get, "filter",
                                       attribute_names,
                                       attribute_values);
            if (find_attribute (attribute_names, attribute_values,
                                "alerts", &attribute))
              get_filters_data->alerts = strcmp (attribute, "0");
            else
              get_filters_data->alerts = 0;
            set_client_state (CLIENT_GET_FILTERS);
          }
        else if (strcasecmp ("GET_GROUPS", element_name) == 0)
          {
            get_data_parse_attributes (&get_groups_data->get, "group",
                                       attribute_names,
                                       attribute_values);
            set_client_state (CLIENT_GET_GROUPS);
          }
        else if (strcasecmp ("GET_LICENSE", element_name) == 0)
          {
            get_license_start (gmp_parser,
                               attribute_names,
                               attribute_values);
            set_client_state (CLIENT_GET_LICENSE);
          }
        else if (strcasecmp ("GET_NOTES", element_name) == 0)
          {
            const gchar* attribute;

            get_data_parse_attributes (&get_notes_data->get, "note",
                                       attribute_names,
                                       attribute_values);

            append_attribute (attribute_names, attribute_values, "note_id",
                              &get_notes_data->note_id);

            append_attribute (attribute_names, attribute_values, "nvt_oid",
                              &get_notes_data->nvt_oid);

            append_attribute (attribute_names, attribute_values, "task_id",
                              &get_notes_data->task_id);

            if (find_attribute (attribute_names, attribute_values,
                                "result", &attribute))
              get_notes_data->result = strcmp (attribute, "0");
            else
              get_notes_data->result = 0;

            set_client_state (CLIENT_GET_NOTES);
          }
        else if (strcasecmp ("GET_NVTS", element_name) == 0)
          {
            const gchar* attribute;
            append_attribute (attribute_names, attribute_values, "nvt_oid",
                              &get_nvts_data->nvt_oid);
            append_attribute (attribute_names, attribute_values, "config_id",
                              &get_nvts_data->config_id);
            append_attribute (attribute_names, attribute_values,
                              "preferences_config_id",
                              &get_nvts_data->preferences_config_id);
            if (find_attribute (attribute_names, attribute_values,
                                "details", &attribute))
              get_nvts_data->details = strcmp (attribute, "0");
            else
              get_nvts_data->details = 0;
            append_attribute (attribute_names, attribute_values, "family",
                              &get_nvts_data->family);
            if (find_attribute (attribute_names, attribute_values,
                                "preferences", &attribute))
              get_nvts_data->preferences = strcmp (attribute, "0");
            else
              get_nvts_data->preferences = 0;
            if (find_attribute (attribute_names, attribute_values,
                                "preference_count", &attribute))
              get_nvts_data->preference_count = strcmp (attribute, "0");
            else
              get_nvts_data->preference_count = 0;
            if (find_attribute (attribute_names, attribute_values,
                                "timeout", &attribute))
              get_nvts_data->timeout = strcmp (attribute, "0");
            else
              get_nvts_data->timeout = 0;
            append_attribute (attribute_names, attribute_values, "sort_field",
                              &get_nvts_data->sort_field);
            if (find_attribute (attribute_names, attribute_values,
                                "sort_order", &attribute))
              get_nvts_data->sort_order = strcmp (attribute,
                                                         "descending");
            else
              get_nvts_data->sort_order = 1;
            set_client_state (CLIENT_GET_NVTS);
          }
        else if (strcasecmp ("GET_NVT_FAMILIES", element_name) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values,
                                "sort_order", &attribute))
              get_nvt_families_data->sort_order = strcmp (attribute,
                                                          "descending");
            else
              get_nvt_families_data->sort_order = 1;
            set_client_state (CLIENT_GET_NVT_FAMILIES);
          }
        else if (strcasecmp ("GET_OVERRIDES", element_name) == 0)
          {
            const gchar* attribute;

            get_data_parse_attributes (&get_overrides_data->get, "override",
                                       attribute_names,
                                       attribute_values);

            append_attribute (attribute_names, attribute_values, "override_id",
                              &get_overrides_data->override_id);

            append_attribute (attribute_names, attribute_values, "nvt_oid",
                              &get_overrides_data->nvt_oid);

            append_attribute (attribute_names, attribute_values, "task_id",
                              &get_overrides_data->task_id);

            if (find_attribute (attribute_names, attribute_values,
                                "result", &attribute))
              get_overrides_data->result = strcmp (attribute, "0");
            else
              get_overrides_data->result = 0;

            set_client_state (CLIENT_GET_OVERRIDES);
          }
        else if (strcasecmp ("GET_PORT_LISTS", element_name) == 0)
          {
            const gchar* attribute;

            get_data_parse_attributes (&get_port_lists_data->get,
                                       "port_list",
                                       attribute_names,
                                       attribute_values);
            if (find_attribute (attribute_names, attribute_values,
                                "targets", &attribute))
              get_port_lists_data->targets = strcmp (attribute, "0");
            else
              get_port_lists_data->targets = 0;
            set_client_state (CLIENT_GET_PORT_LISTS);
          }
        else if (strcasecmp ("GET_PERMISSIONS", element_name) == 0)
          {
            get_data_parse_attributes (&get_permissions_data->get, "permission",
                                       attribute_names,
                                       attribute_values);
            append_attribute (attribute_names, attribute_values, "resource_id",
                              &get_permissions_data->resource_id);
            set_client_state (CLIENT_GET_PERMISSIONS);
          }
        else if (strcasecmp ("GET_PREFERENCES", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "nvt_oid",
                              &get_preferences_data->nvt_oid);
            append_attribute (attribute_names, attribute_values, "config_id",
                              &get_preferences_data->config_id);
            append_attribute (attribute_names, attribute_values, "preference",
                              &get_preferences_data->preference);
            set_client_state (CLIENT_GET_PREFERENCES);
          }
        else if (strcasecmp ("GET_REPORTS", element_name) == 0)
          {
            const gchar* attribute;

            get_data_parse_attributes (&get_reports_data->get, "report",
                                       attribute_names,
                                       attribute_values);

            get_data_parse_attributes (&get_reports_data->report_get, "report",
                                       attribute_names,
                                       attribute_values);

            g_free (get_reports_data->report_get.filt_id);
            get_reports_data->report_get.filt_id = NULL;
            append_attribute (attribute_names, attribute_values,
                              "report_filt_id",
                              &get_reports_data->report_get.filt_id);

            g_free (get_reports_data->report_get.filter);
            get_reports_data->report_get.filter = NULL;
            append_attribute (attribute_names, attribute_values,
                              "report_filter",
                              &get_reports_data->report_get.filter);

            append_attribute (attribute_names, attribute_values, "report_id",
                              &get_reports_data->report_id);

            append_attribute (attribute_names, attribute_values,
                              "delta_report_id",
                              &get_reports_data->delta_report_id);

            append_attribute (attribute_names, attribute_values, "alert_id",
                              &get_reports_data->alert_id);

            append_attribute (attribute_names, attribute_values, "format_id",
                              &get_reports_data->format_id);

            if (find_attribute (attribute_names, attribute_values,
                                "lean", &attribute))
              get_reports_data->lean = atoi (attribute);
            else
              get_reports_data->lean = 0;

            if (find_attribute (attribute_names, attribute_values,
                                "notes_details", &attribute))
              get_reports_data->notes_details = strcmp (attribute, "0");
            else
              get_reports_data->notes_details = 0;

            if (find_attribute (attribute_names, attribute_values,
                                "overrides_details", &attribute))
              get_reports_data->overrides_details = strcmp (attribute, "0");
            else
              get_reports_data->overrides_details = 0;

            if (find_attribute (attribute_names, attribute_values,
                                "result_tags", &attribute))
              get_reports_data->result_tags = strcmp (attribute, "0");
            else
              get_reports_data->result_tags = 0;

            if (find_attribute (attribute_names, attribute_values,
                                "ignore_pagination", &attribute))
              get_reports_data->ignore_pagination = atoi (attribute);
            else
              get_reports_data->ignore_pagination = 0;

            set_client_state (CLIENT_GET_REPORTS);
          }
        else if (strcasecmp ("GET_REPORT_FORMATS", element_name) == 0)
          {
            const gchar* attribute;

            get_data_parse_attributes (&get_report_formats_data->get,
                                       "report_format",
                                       attribute_names,
                                       attribute_values);
            if (find_attribute (attribute_names, attribute_values,
                                "alerts", &attribute))
              get_report_formats_data->alerts = strcmp (attribute, "0");
            else
              get_report_formats_data->alerts = 0;

            if (find_attribute (attribute_names, attribute_values,
                                "params", &attribute))
              get_report_formats_data->params = strcmp (attribute, "0");
            else
              get_report_formats_data->params = 0;

            set_client_state (CLIENT_GET_REPORT_FORMATS);
          }
        else if (strcasecmp ("GET_RESULTS", element_name) == 0)
          {
            const gchar* attribute;
            get_data_parse_attributes (&get_results_data->get,
                                       "result",
                                       attribute_names,
                                       attribute_values);

            append_attribute (attribute_names, attribute_values, "task_id",
                              &get_results_data->task_id);

            if (find_attribute (attribute_names, attribute_values,
                                "notes_details", &attribute))
              get_results_data->notes_details = strcmp (attribute, "0");
            else
              get_results_data->notes_details = 0;

            if (find_attribute (attribute_names, attribute_values,
                                "overrides_details", &attribute))
              get_results_data->overrides_details = strcmp (attribute, "0");
            else
              get_results_data->overrides_details = 0;

            if (find_attribute (attribute_names, attribute_values,
                                "get_counts", &attribute))
              get_results_data->get_counts = strcmp (attribute, "0");
            else
              get_results_data->get_counts = 1;

            set_client_state (CLIENT_GET_RESULTS);
          }
        else if (strcasecmp ("GET_ROLES", element_name) == 0)
          {
            get_data_parse_attributes (&get_roles_data->get, "role",
                                       attribute_names,
                                       attribute_values);
            set_client_state (CLIENT_GET_ROLES);
          }
        else if (strcasecmp ("GET_SCANNERS", element_name) == 0)
          {
            get_data_parse_attributes (&get_scanners_data->get, "scanner",
                                       attribute_names, attribute_values);
            set_client_state (CLIENT_GET_SCANNERS);
          }
        else if (strcasecmp ("GET_SCHEDULES", element_name) == 0)
          {
            const gchar *attribute;
            get_data_parse_attributes (&get_schedules_data->get, "schedule",
                                       attribute_names,
                                       attribute_values);
            if (find_attribute (attribute_names, attribute_values,
                                "tasks", &attribute))
              get_schedules_data->tasks = strcmp (attribute, "0");
            else
              get_schedules_data->tasks = 0;
            set_client_state (CLIENT_GET_SCHEDULES);
          }
        else if (strcasecmp ("GET_SETTINGS", element_name) == 0)
          {
            const gchar* attribute;

            append_attribute (attribute_names, attribute_values, "setting_id",
                              &get_settings_data->setting_id);

            append_attribute (attribute_names, attribute_values, "filter",
                              &get_settings_data->filter);

            if (find_attribute (attribute_names, attribute_values,
                                "first", &attribute))
              /* Subtract 1 to switch from 1 to 0 indexing. */
              get_settings_data->first = atoi (attribute) - 1;
            else
              get_settings_data->first = 0;
            if (get_settings_data->first < 0)
              get_settings_data->first = 0;

            if (find_attribute (attribute_names, attribute_values,
                                "max", &attribute))
              get_settings_data->max = atoi (attribute);
            else
              get_settings_data->max = -1;
            if (get_settings_data->max < 1)
              get_settings_data->max = -1;

            append_attribute (attribute_names, attribute_values, "sort_field",
                              &get_settings_data->sort_field);

            if (find_attribute (attribute_names, attribute_values,
                                "sort_order", &attribute))
              get_settings_data->sort_order = strcmp (attribute, "descending");
            else
              get_settings_data->sort_order = 1;

            set_client_state (CLIENT_GET_SETTINGS);
          }
        else if (strcasecmp ("GET_TAGS", element_name) == 0)
          {
            const gchar* attribute;
            get_data_parse_attributes (&get_tags_data->get, "tag",
                                       attribute_names,
                                       attribute_values);

            if (find_attribute (attribute_names, attribute_values,
                                "names_only", &attribute))
              get_tags_data->names_only = strcmp (attribute, "0");
            else
              get_tags_data->names_only = 0;

            set_client_state (CLIENT_GET_TAGS);
          }
        else if (strcasecmp ("GET_SYSTEM_REPORTS", element_name) == 0)
          {
            const gchar* attribute;
            append_attribute (attribute_names, attribute_values, "name",
                              &get_system_reports_data->name);
            append_attribute (attribute_names, attribute_values, "duration",
                              &get_system_reports_data->duration);
            append_attribute (attribute_names, attribute_values, "end_time",
                              &get_system_reports_data->end_time);
            append_attribute (attribute_names, attribute_values, "slave_id",
                              &get_system_reports_data->slave_id);
            append_attribute (attribute_names, attribute_values, "start_time",
                              &get_system_reports_data->start_time);
            if (find_attribute (attribute_names, attribute_values,
                                "brief", &attribute))
              get_system_reports_data->brief = strcmp (attribute, "0");
            else
              get_system_reports_data->brief = 0;
            set_client_state (CLIENT_GET_SYSTEM_REPORTS);
          }
        else if (strcasecmp ("GET_TARGETS", element_name) == 0)
          {
            const gchar *attribute;
            get_data_parse_attributes (&get_targets_data->get, "target",
                                       attribute_names,
                                       attribute_values);
            if (find_attribute (attribute_names, attribute_values,
                                "tasks", &attribute))
              get_targets_data->tasks = strcmp (attribute, "0");
            else
              get_targets_data->tasks = 0;
            set_client_state (CLIENT_GET_TARGETS);
          }
        else if (strcasecmp ("GET_TASKS", element_name) == 0)
          {
            const gchar *attribute;
            get_data_parse_attributes (&get_tasks_data->get, "task",
                                       attribute_names,
                                       attribute_values);
            if (find_attribute (attribute_names, attribute_values,
                                "schedules_only", &attribute))
              get_tasks_data->schedules_only = strcmp (attribute, "0");
            else
              get_tasks_data->schedules_only = 0;

            if (find_attribute (attribute_names, attribute_values,
                                "usage_type", &attribute))
              {
                get_data_set_extra (&get_tasks_data->get,
                                    "usage_type",
                                    attribute);
              }

            set_client_state (CLIENT_GET_TASKS);
          }
        ELSE_GET_START (tickets, TICKETS)
        ELSE_GET_START (tls_certificates, TLS_CERTIFICATES)
        else if (strcasecmp ("GET_USERS", element_name) == 0)
          {
            get_data_parse_attributes (&get_users_data->get, "user",
                                       attribute_names,
                                       attribute_values);
            set_client_state (CLIENT_GET_USERS);
          }
        else if (strcasecmp ("GET_INFO", element_name) == 0)
          {
            const gchar* attribute;
            const gchar* typebuf;
            get_data_parse_attributes (&get_info_data->get, "info",
                                       attribute_names,
                                       attribute_values);
            append_attribute (attribute_names, attribute_values, "name",
                              &get_info_data->name);
            if (find_attribute (attribute_names, attribute_values,
                                "details", &attribute))
              get_info_data->details = strcmp (attribute, "0");
            else
              get_info_data->details = 0;

            if (find_attribute (attribute_names, attribute_values,
                                "type", &typebuf))
              get_info_data->type = g_ascii_strdown (typebuf, -1);
            set_client_state (CLIENT_GET_INFO);
          }
        else if (strcasecmp ("GET_VERSION", element_name) == 0)
          set_client_state (CLIENT_GET_VERSION_AUTHENTIC);
        else if (strcasecmp ("GET_VULNS", element_name) == 0)
          {
            get_data_parse_attributes (&get_vulns_data->get, "vuln",
                                       attribute_names,
                                       attribute_values);
            set_client_state (CLIENT_GET_VULNS);
          }
        else if (strcasecmp ("HELP", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "format",
                              &help_data->format);
            append_attribute (attribute_names, attribute_values, "type",
                              &help_data->type);
            set_client_state (CLIENT_HELP);
          }
        else if (strcasecmp ("MODIFY_ALERT", element_name) == 0)
          {
            modify_alert_data->event_data = make_array ();

            gvm_append_string (&modify_alert_data->part_data, "");
            gvm_append_string (&modify_alert_data->part_name, "");
            gvm_append_string (&modify_alert_data->event, "");
            modify_alert_data->condition_data = make_array ();
            gvm_append_string (&modify_alert_data->condition, "");
            modify_alert_data->method_data = make_array ();
            gvm_append_string (&modify_alert_data->method, "");

            append_attribute (attribute_names, attribute_values, "alert_id",
                              &modify_alert_data->alert_id);
            set_client_state (CLIENT_MODIFY_ALERT);
          }
        else if (strcasecmp ("MODIFY_ASSET", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "asset_id",
                              &modify_asset_data->asset_id);
            set_client_state (CLIENT_MODIFY_ASSET);
          }
        else if (strcasecmp ("MODIFY_AUTH", element_name) == 0)
          set_client_state (CLIENT_MODIFY_AUTH);
        else if (strcasecmp ("MODIFY_CONFIG", element_name) == 0)
          {
            modify_config_start (gmp_parser, attribute_names,
                                 attribute_values);
            set_client_state (CLIENT_MODIFY_CONFIG);
          }
        else if (strcasecmp ("MODIFY_CREDENTIAL", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values,
                              "credential_id",
                              &modify_credential_data->credential_id);
            set_client_state (CLIENT_MODIFY_CREDENTIAL);
          }
        else if (strcasecmp ("MODIFY_FILTER", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "filter_id",
                              &modify_filter_data->filter_id);
            set_client_state (CLIENT_MODIFY_FILTER);
          }
        else if (strcasecmp ("MODIFY_GROUP", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "group_id",
                              &modify_group_data->group_id);
            set_client_state (CLIENT_MODIFY_GROUP);
          }
        else if (strcasecmp ("MODIFY_PORT_LIST", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values,
                              "port_list_id",
                              &modify_port_list_data->port_list_id);
            set_client_state (CLIENT_MODIFY_PORT_LIST);
          }
        else if (strcasecmp ("MODIFY_LICENSE", element_name) == 0)
          {
            modify_license_start (gmp_parser,
                                  attribute_names,
                                  attribute_values);
            set_client_state (CLIENT_MODIFY_LICENSE);
          }
        else if (strcasecmp ("MODIFY_NOTE", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "note_id",
                              &modify_note_data->note_id);
            set_client_state (CLIENT_MODIFY_NOTE);
          }
        else if (strcasecmp ("MODIFY_OVERRIDE", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "override_id",
                              &modify_override_data->override_id);
            set_client_state (CLIENT_MODIFY_OVERRIDE);
          }
        else if (strcasecmp ("MODIFY_PERMISSION", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values,
                              "permission_id",
                              &modify_permission_data->permission_id);
            set_client_state (CLIENT_MODIFY_PERMISSION);
          }
        else if (strcasecmp ("MODIFY_REPORT_FORMAT", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values,
                              "report_format_id",
                              &modify_report_format_data->report_format_id);
            set_client_state (CLIENT_MODIFY_REPORT_FORMAT);
          }
        else if (strcasecmp ("MODIFY_ROLE", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "role_id",
                              &modify_role_data->role_id);
            set_client_state (CLIENT_MODIFY_ROLE);
          }
        else if (strcasecmp ("MODIFY_SCANNER", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "scanner_id",
                              &modify_scanner_data->scanner_id);
            set_client_state (CLIENT_MODIFY_SCANNER);
          }
        else if (strcasecmp ("MODIFY_SCHEDULE", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "schedule_id",
                              &modify_schedule_data->schedule_id);
            set_client_state (CLIENT_MODIFY_SCHEDULE);
          }
        else if (strcasecmp ("MODIFY_SETTING", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values,
                              "setting_id",
                              &modify_setting_data->setting_id);
            set_client_state (CLIENT_MODIFY_SETTING);
          }
        else if (strcasecmp ("MODIFY_TAG", element_name) == 0)
          {
            modify_tag_data->resource_ids = NULL;
            append_attribute (attribute_names, attribute_values, "tag_id",
                              &modify_tag_data->tag_id);
            set_client_state (CLIENT_MODIFY_TAG);
          }
        else if (strcasecmp ("MODIFY_TARGET", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "target_id",
                              &modify_target_data->target_id);
            set_client_state (CLIENT_MODIFY_TARGET);
          }
        else if (strcasecmp ("MODIFY_TASK", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "task_id",
                              &modify_task_data->task_id);
            modify_task_data->alerts = make_array ();
            modify_task_data->groups = make_array ();
            set_client_state (CLIENT_MODIFY_TASK);
          }
        else if (strcasecmp ("MODIFY_TICKET", element_name) == 0)
          {
            modify_ticket_start (gmp_parser, attribute_names,
                                 attribute_values);
            set_client_state (CLIENT_MODIFY_TICKET);
          }
        else if (strcasecmp ("MODIFY_TLS_CERTIFICATE", element_name) == 0)
          {
            modify_tls_certificate_start (gmp_parser, attribute_names,
                                          attribute_values);
            set_client_state (CLIENT_MODIFY_TLS_CERTIFICATE);
          }
        else if (strcasecmp ("MODIFY_USER", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "user_id",
                              &modify_user_data->user_id);
            set_client_state (CLIENT_MODIFY_USER);
          }
        else if (strcasecmp ("MOVE_TASK", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "task_id",
                              &move_task_data->task_id);
            append_attribute (attribute_names, attribute_values, "slave_id",
                              &move_task_data->slave_id);
            set_client_state (CLIENT_MOVE_TASK);
          }
        else if (strcasecmp ("RESTORE", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "id",
                              &restore_data->id);
            set_client_state (CLIENT_RESTORE);
          }
        else if (strcasecmp ("RESUME_TASK", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "task_id",
                              &resume_task_data->task_id);
            set_client_state (CLIENT_RESUME_TASK);
          }
        else if (strcasecmp ("RUN_WIZARD", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "name",
                              &run_wizard_data->name);
            append_attribute (attribute_names, attribute_values, "read_only",
                              &run_wizard_data->read_only);
            set_client_state (CLIENT_RUN_WIZARD);
          }
        else if (strcasecmp ("START_TASK", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "task_id",
                              &start_task_data->task_id);
            set_client_state (CLIENT_START_TASK);
          }
        else if (strcasecmp ("STOP_TASK", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "task_id",
                              &stop_task_data->task_id);
            set_client_state (CLIENT_STOP_TASK);
          }
        else if (strcasecmp ("TEST_ALERT", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values,
                              "alert_id",
                              &test_alert_data->alert_id);
            set_client_state (CLIENT_TEST_ALERT);
          }
        else if (strcasecmp ("VERIFY_REPORT_FORMAT", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "report_format_id",
                              &verify_report_format_data->report_format_id);
            set_client_state (CLIENT_VERIFY_REPORT_FORMAT);
          }
        else if (strcasecmp ("VERIFY_SCANNER", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "scanner_id",
                              &verify_scanner_data->scanner_id);
            set_client_state (CLIENT_VERIFY_SCANNER);
          }
        else
          {
            if (send_to_client (XML_ERROR_SYNTAX ("gmp", "Bogus command name"),
                                write_to_client,
                                write_to_client_data))
              {
                error_send_to_client (error);
                return;
              }
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
        break;

      case CLIENT_AUTHENTICATE:
        if (strcasecmp ("CREDENTIALS", element_name) == 0)
          {
            /* Init, so it's the empty string when the entity is empty. */
            append_to_credentials_password (&current_credentials, "", 0);
            set_client_state (CLIENT_AUTHENTICATE_CREDENTIALS);
          }
        ELSE_READ_OVER;

      case CLIENT_AUTHENTICATE_CREDENTIALS:
        if (strcasecmp ("USERNAME", element_name) == 0)
          set_client_state (CLIENT_AUTHENTICATE_CREDENTIALS_USERNAME);
        else if (strcasecmp ("PASSWORD", element_name) == 0)
          set_client_state (CLIENT_AUTHENTICATE_CREDENTIALS_PASSWORD);
        ELSE_READ_OVER;

      case CLIENT_CREATE_SCANNER:
        if (strcasecmp ("COMMENT", element_name) == 0)
          set_client_state (CLIENT_CREATE_SCANNER_COMMENT);
        else if (strcasecmp ("COPY", element_name) == 0)
          set_client_state (CLIENT_CREATE_SCANNER_COPY);
        else if (strcasecmp ("NAME", element_name) == 0)
          set_client_state (CLIENT_CREATE_SCANNER_NAME);
        else if (strcasecmp ("HOST", element_name) == 0)
          set_client_state (CLIENT_CREATE_SCANNER_HOST);
        else if (strcasecmp ("PORT", element_name) == 0)
          set_client_state (CLIENT_CREATE_SCANNER_PORT);
        else if (strcasecmp ("TYPE", element_name) == 0)
          set_client_state (CLIENT_CREATE_SCANNER_TYPE);
        else if (strcasecmp ("CA_PUB", element_name) == 0)
          set_client_state (CLIENT_CREATE_SCANNER_CA_PUB);
        else if (strcasecmp ("CREDENTIAL", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "id",
                              &create_scanner_data->credential_id);
            set_client_state (CLIENT_CREATE_SCANNER_CREDENTIAL);
          }
        ELSE_READ_OVER;

      case CLIENT_CREATE_SCHEDULE:
        if (strcasecmp ("COMMENT", element_name) == 0)
          set_client_state (CLIENT_CREATE_SCHEDULE_COMMENT);
        else if (strcasecmp ("COPY", element_name) == 0)
          set_client_state (CLIENT_CREATE_SCHEDULE_COPY);
        else if (strcasecmp ("ICALENDAR", element_name) == 0)
          set_client_state (CLIENT_CREATE_SCHEDULE_ICALENDAR);
        else if (strcasecmp ("NAME", element_name) == 0)
          set_client_state (CLIENT_CREATE_SCHEDULE_NAME);
        else if (strcasecmp ("TIMEZONE", element_name) == 0)
          set_client_state (CLIENT_CREATE_SCHEDULE_TIMEZONE);
        ELSE_READ_OVER;

      case CLIENT_GET_AGGREGATES:
        if (strcasecmp ("DATA_COLUMN", element_name) == 0)
          {
            get_aggregates_data->data_columns
              = g_list_append (get_aggregates_data->data_columns,
                               g_strdup (""));
            set_client_state (CLIENT_GET_AGGREGATES_DATA_COLUMN);
          }
        else if (strcasecmp ("SORT", element_name) == 0)
          {
            int sort_order_given;
            const gchar* attribute;
            sort_data_t *sort_data;
            sort_data = g_malloc0 (sizeof (sort_data_t));
            sort_data->field = g_strdup ("");
            sort_data->stat = g_strdup ("");

            append_attribute (attribute_names, attribute_values, "field",
                              &(sort_data->field));
            append_attribute (attribute_names, attribute_values, "stat",
                              &(sort_data->stat));
            if (find_attribute (attribute_names, attribute_values,
                                "order", &attribute))
              {
                sort_order_given = 1;
                sort_data->order = strcmp (attribute, "descending");
              }
            else
              {
                sort_order_given = 0;
                sort_data->order = 1;
              }

            if (strcmp (sort_data->field, "") || sort_order_given)
              {
                get_aggregates_data->sort_data
                  = g_list_append (get_aggregates_data->sort_data,
                                  sort_data);
              }

            set_client_state (CLIENT_GET_AGGREGATES_SORT);
          }
        else if (strcasecmp ("TEXT_COLUMN", element_name) == 0)
          {
            get_aggregates_data->text_columns
              = g_list_append (get_aggregates_data->text_columns,
                               g_strdup (""));
            set_client_state (CLIENT_GET_AGGREGATES_TEXT_COLUMN);
          }
        ELSE_READ_OVER;

      case CLIENT_MODIFY_ALERT:
        if (strcasecmp ("NAME", element_name) == 0)
          {
            gvm_append_string (&modify_alert_data->name, "");
            set_client_state (CLIENT_MODIFY_ALERT_NAME);
          }
        else if (strcasecmp ("COMMENT", element_name) == 0)
          {
            gvm_append_string (&modify_alert_data->comment, "");
            set_client_state (CLIENT_MODIFY_ALERT_COMMENT);
          }
        else if (strcasecmp ("EVENT", element_name) == 0)
          set_client_state (CLIENT_MODIFY_ALERT_EVENT);
        else if (strcasecmp ("FILTER", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "id",
                              &modify_alert_data->filter_id);
            set_client_state (CLIENT_MODIFY_ALERT_FILTER);
          }
        else if (strcasecmp ("ACTIVE", element_name) == 0)
          set_client_state (CLIENT_MODIFY_ALERT_ACTIVE);
        else if (strcasecmp ("CONDITION", element_name) == 0)
          set_client_state (CLIENT_MODIFY_ALERT_CONDITION);
        else if (strcasecmp ("METHOD", element_name) == 0)
          set_client_state (CLIENT_MODIFY_ALERT_METHOD);
        ELSE_READ_OVER;

      case CLIENT_MODIFY_ALERT_EVENT:
        if (strcasecmp ("DATA", element_name) == 0)
          set_client_state (CLIENT_MODIFY_ALERT_EVENT_DATA);
        ELSE_READ_OVER;

      case CLIENT_MODIFY_ALERT_EVENT_DATA:
        if (strcasecmp ("NAME", element_name) == 0)
          set_client_state (CLIENT_MODIFY_ALERT_EVENT_DATA_NAME);
        ELSE_READ_OVER;

      case CLIENT_MODIFY_ALERT_CONDITION:
        if (strcasecmp ("DATA", element_name) == 0)
          set_client_state (CLIENT_MODIFY_ALERT_CONDITION_DATA);
        ELSE_READ_OVER;

      case CLIENT_MODIFY_ALERT_CONDITION_DATA:
        if (strcasecmp ("NAME", element_name) == 0)
          set_client_state (CLIENT_MODIFY_ALERT_CONDITION_DATA_NAME);
        ELSE_READ_OVER;

      case CLIENT_MODIFY_ALERT_METHOD:
        if (strcasecmp ("DATA", element_name) == 0)
          set_client_state (CLIENT_MODIFY_ALERT_METHOD_DATA);
        ELSE_READ_OVER;

      case CLIENT_MODIFY_ALERT_METHOD_DATA:
        if (strcasecmp ("NAME", element_name) == 0)
          set_client_state (CLIENT_MODIFY_ALERT_METHOD_DATA_NAME);
        ELSE_READ_OVER;

      case CLIENT_MODIFY_ASSET:
        if (strcasecmp ("COMMENT", element_name) == 0)
          {
            gvm_append_string (&modify_asset_data->comment, "");
            set_client_state (CLIENT_MODIFY_ASSET_COMMENT);
          }
        ELSE_READ_OVER;

      case CLIENT_MODIFY_AUTH:
        if (strcasecmp ("GROUP", element_name) == 0)
          {
            const gchar* attribute;
            auth_group_t *new_group;

            new_group = g_malloc0 (sizeof (auth_group_t));
            if (find_attribute (attribute_names, attribute_values, "name",
                                &attribute))
              new_group->group_name = g_strdup (attribute);
            modify_auth_data->groups =
              g_slist_prepend (modify_auth_data->groups, new_group);
            set_client_state (CLIENT_MODIFY_AUTH_GROUP);
          }
        ELSE_READ_OVER;

      case CLIENT_MODIFY_AUTH_GROUP:
        if (strcasecmp ("AUTH_CONF_SETTING", element_name) == 0)
          set_client_state (CLIENT_MODIFY_AUTH_GROUP_AUTH_CONF_SETTING);
        ELSE_READ_OVER;

      case CLIENT_MODIFY_AUTH_GROUP_AUTH_CONF_SETTING:
        if (strcasecmp ("KEY", element_name) == 0)
          set_client_state (CLIENT_MODIFY_AUTH_GROUP_AUTH_CONF_SETTING_KEY);
        else if (strcasecmp ("VALUE", element_name) == 0)
          set_client_state (CLIENT_MODIFY_AUTH_GROUP_AUTH_CONF_SETTING_VALUE);
        ELSE_READ_OVER;

      case CLIENT_MODIFY_CONFIG:
        modify_config_element_start (gmp_parser, element_name,
                                     attribute_names,
                                     attribute_values);
        break;

      case CLIENT_MODIFY_CREDENTIAL:
        if (strcasecmp ("ALLOW_INSECURE", element_name) == 0)
          set_client_state (CLIENT_MODIFY_CREDENTIAL_ALLOW_INSECURE);
        else if (strcasecmp ("AUTH_ALGORITHM", element_name) == 0)
          {
            set_client_state (CLIENT_MODIFY_CREDENTIAL_AUTH_ALGORITHM);
          }
        else if (strcasecmp ("NAME", element_name) == 0)
          set_client_state (CLIENT_MODIFY_CREDENTIAL_NAME);
        else if (strcasecmp ("COMMENT", element_name) == 0)
          {
            gvm_free_string_var (&modify_credential_data->comment);
            gvm_append_string (&modify_credential_data->comment, "");
            set_client_state (CLIENT_MODIFY_CREDENTIAL_COMMENT);
          }
        else if (strcasecmp ("CERTIFICATE", element_name) == 0)
          {
            set_client_state (CLIENT_MODIFY_CREDENTIAL_CERTIFICATE);
          }
        else if (strcasecmp ("COMMUNITY", element_name) == 0)
          {
            gvm_append_string (&modify_credential_data->community, "");
            set_client_state (CLIENT_MODIFY_CREDENTIAL_COMMUNITY);
          }
        else if (strcasecmp ("KEY", element_name) == 0)
          {
            modify_credential_data->key = 1;
            set_client_state (CLIENT_MODIFY_CREDENTIAL_KEY);
          }
        else if (strcasecmp ("LOGIN", element_name) == 0)
          set_client_state (CLIENT_MODIFY_CREDENTIAL_LOGIN);
        else if (strcasecmp ("PASSWORD", element_name) == 0)
          {
            gvm_free_string_var (&modify_credential_data->password);
            gvm_append_string (&modify_credential_data->password, "");
            set_client_state (CLIENT_MODIFY_CREDENTIAL_PASSWORD);
          }
        else if (strcasecmp ("PRIVACY", element_name) == 0)
          {
            set_client_state (CLIENT_MODIFY_CREDENTIAL_PRIVACY);
            gvm_append_string (&modify_credential_data->privacy_algorithm,
                                   "");
          }
        ELSE_READ_OVER;

      case CLIENT_MODIFY_CREDENTIAL_KEY:
        if (strcasecmp ("PHRASE", element_name) == 0)
          {
            gvm_free_string_var (&modify_credential_data->key_phrase);
            gvm_append_string (&modify_credential_data->key_phrase, "");
            set_client_state (CLIENT_MODIFY_CREDENTIAL_KEY_PHRASE);
          }
        else if (strcasecmp ("PRIVATE", element_name) == 0)
          {
            set_client_state (CLIENT_MODIFY_CREDENTIAL_KEY_PRIVATE);
          }
        else if (strcasecmp ("PUBLIC", element_name) == 0)
          {
            set_client_state (CLIENT_MODIFY_CREDENTIAL_KEY_PUBLIC);
          }
        ELSE_READ_OVER;

      case CLIENT_MODIFY_CREDENTIAL_PRIVACY:
        if (strcasecmp ("ALGORITHM", element_name) == 0)
          {
            set_client_state (CLIENT_MODIFY_CREDENTIAL_PRIVACY_ALGORITHM);
          }
        else if (strcasecmp ("PASSWORD", element_name) == 0)
          {
            gvm_free_string_var (&modify_credential_data->privacy_password);
            gvm_append_string (&modify_credential_data->privacy_password, "");
            set_client_state (CLIENT_MODIFY_CREDENTIAL_PRIVACY_PASSWORD);
          }
        ELSE_READ_OVER;

      case CLIENT_MODIFY_FILTER:
        if (strcasecmp ("COMMENT", element_name) == 0)
          {
            gvm_append_string (&modify_filter_data->comment, "");
            set_client_state (CLIENT_MODIFY_FILTER_COMMENT);
          }
        else if (strcasecmp ("NAME", element_name) == 0)
          {
            gvm_append_string (&modify_filter_data->name, "");
            set_client_state (CLIENT_MODIFY_FILTER_NAME);
          }
        else if (strcasecmp ("TERM", element_name) == 0)
          {
            gvm_append_string (&modify_filter_data->term, "");
            set_client_state (CLIENT_MODIFY_FILTER_TERM);
          }
        else if (strcasecmp ("TYPE", element_name) == 0)
          {
            gvm_append_string (&modify_filter_data->type, "");
            set_client_state (CLIENT_MODIFY_FILTER_TYPE);
          }
        ELSE_READ_OVER;

      case CLIENT_MODIFY_GROUP:
        if (strcasecmp ("COMMENT", element_name) == 0)
          {
            gvm_append_string (&modify_group_data->comment, "");
            set_client_state (CLIENT_MODIFY_GROUP_COMMENT);
          }
        else if (strcasecmp ("NAME", element_name) == 0)
          {
            gvm_append_string (&modify_group_data->name, "");
            set_client_state (CLIENT_MODIFY_GROUP_NAME);
          }
        else if (strcasecmp ("USERS", element_name) == 0)
          {
            gvm_append_string (&modify_group_data->users, "");
            set_client_state (CLIENT_MODIFY_GROUP_USERS);
          }
        ELSE_READ_OVER;

      case CLIENT_MODIFY_PERMISSION:
        if (strcasecmp ("COMMENT", element_name) == 0)
          {
            gvm_append_string (&modify_permission_data->comment, "");
            set_client_state (CLIENT_MODIFY_PERMISSION_COMMENT);
          }
        else if (strcasecmp ("NAME", element_name) == 0)
          set_client_state (CLIENT_MODIFY_PERMISSION_NAME);
        else if (strcasecmp ("RESOURCE", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "id",
                              &modify_permission_data->resource_id);
            set_client_state (CLIENT_MODIFY_PERMISSION_RESOURCE);
          }
        else if (strcasecmp ("SUBJECT", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "id",
                              &modify_permission_data->subject_id);
            set_client_state (CLIENT_MODIFY_PERMISSION_SUBJECT);
          }
        ELSE_READ_OVER;

      case CLIENT_MODIFY_PERMISSION_RESOURCE:
        if (strcasecmp ("TYPE", element_name) == 0)
          set_client_state (CLIENT_MODIFY_PERMISSION_RESOURCE_TYPE);
        ELSE_READ_OVER;

      case CLIENT_MODIFY_PERMISSION_SUBJECT:
        if (strcasecmp ("TYPE", element_name) == 0)
          set_client_state (CLIENT_MODIFY_PERMISSION_SUBJECT_TYPE);
        ELSE_READ_OVER;

      case CLIENT_MODIFY_PORT_LIST:
        if (strcasecmp ("NAME", element_name) == 0)
          set_client_state (CLIENT_MODIFY_PORT_LIST_NAME);
        else if (strcasecmp ("COMMENT", element_name) == 0)
          {
            gvm_free_string_var (&modify_port_list_data->comment);
            gvm_append_string (&modify_port_list_data->comment, "");
            set_client_state (CLIENT_MODIFY_PORT_LIST_COMMENT);
          }
        ELSE_READ_OVER;

      case CLIENT_MODIFY_REPORT_FORMAT:
        if (strcasecmp ("ACTIVE", element_name) == 0)
          set_client_state (CLIENT_MODIFY_REPORT_FORMAT_ACTIVE);
        else if (strcasecmp ("NAME", element_name) == 0)
          set_client_state (CLIENT_MODIFY_REPORT_FORMAT_NAME);
        else if (strcasecmp ("SUMMARY", element_name) == 0)
          set_client_state (CLIENT_MODIFY_REPORT_FORMAT_SUMMARY);
        else if (strcasecmp ("PARAM", element_name) == 0)
          set_client_state (CLIENT_MODIFY_REPORT_FORMAT_PARAM);
        ELSE_READ_OVER;

      case CLIENT_MODIFY_REPORT_FORMAT_PARAM:
        if (strcasecmp ("NAME", element_name) == 0)
          set_client_state (CLIENT_MODIFY_REPORT_FORMAT_PARAM_NAME);
        else if (strcasecmp ("VALUE", element_name) == 0)
          set_client_state (CLIENT_MODIFY_REPORT_FORMAT_PARAM_VALUE);
        ELSE_READ_OVER;

      case CLIENT_MODIFY_ROLE:
        if (strcasecmp ("COMMENT", element_name) == 0)
          {
            gvm_append_string (&modify_role_data->comment, "");
            set_client_state (CLIENT_MODIFY_ROLE_COMMENT);
          }
        else if (strcasecmp ("NAME", element_name) == 0)
          {
            gvm_append_string (&modify_role_data->name, "");
            set_client_state (CLIENT_MODIFY_ROLE_NAME);
          }
        else if (strcasecmp ("USERS", element_name) == 0)
          {
            gvm_append_string (&modify_role_data->users, "");
            set_client_state (CLIENT_MODIFY_ROLE_USERS);
          }
        ELSE_READ_OVER;

      case CLIENT_MODIFY_SCANNER:
        if (strcasecmp ("COMMENT", element_name) == 0)
          {
            gvm_append_string (&modify_scanner_data->comment, "");
            set_client_state (CLIENT_MODIFY_SCANNER_COMMENT);
          }
        else if (strcasecmp ("NAME", element_name) == 0)
          {
            gvm_append_string (&modify_scanner_data->name, "");
            set_client_state (CLIENT_MODIFY_SCANNER_NAME);
          }
        else if (strcasecmp ("HOST", element_name) == 0)
          {
            gvm_append_string (&modify_scanner_data->host, "");
            set_client_state (CLIENT_MODIFY_SCANNER_HOST);
          }
        else if (strcasecmp ("PORT", element_name) == 0)
          {
            gvm_append_string (&modify_scanner_data->port, "");
            set_client_state (CLIENT_MODIFY_SCANNER_PORT);
          }
        else if (strcasecmp ("TYPE", element_name) == 0)
          {
            gvm_append_string (&modify_scanner_data->type, "");
            set_client_state (CLIENT_MODIFY_SCANNER_TYPE);
          }
        else if (strcasecmp ("CA_PUB", element_name) == 0)
          {
            gvm_append_string (&modify_scanner_data->ca_pub, "");
            set_client_state (CLIENT_MODIFY_SCANNER_CA_PUB);
          }
        else if (strcasecmp ("CREDENTIAL", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "id",
                              &modify_scanner_data->credential_id);
            set_client_state (CLIENT_MODIFY_SCANNER_CREDENTIAL);
          }
        ELSE_READ_OVER;

      case CLIENT_MODIFY_SCHEDULE:
        if (strcasecmp ("COMMENT", element_name) == 0)
          {
            gvm_append_string (&modify_schedule_data->comment, "");
            set_client_state (CLIENT_MODIFY_SCHEDULE_COMMENT);
          }
        else if (strcasecmp ("NAME", element_name) == 0)
          {
            gvm_append_string (&modify_schedule_data->name, "");
            set_client_state (CLIENT_MODIFY_SCHEDULE_NAME);
          }
        else if (strcasecmp ("ICALENDAR", element_name) == 0)
          set_client_state (CLIENT_MODIFY_SCHEDULE_ICALENDAR);
        else if (strcasecmp ("TIMEZONE", element_name) == 0)
          set_client_state (CLIENT_MODIFY_SCHEDULE_TIMEZONE);
        ELSE_READ_OVER;

      case CLIENT_MODIFY_SETTING:
        if (strcasecmp ("NAME", element_name) == 0)
          set_client_state (CLIENT_MODIFY_SETTING_NAME);
        else if (strcasecmp ("VALUE", element_name) == 0)
          {
            gvm_append_string (&modify_setting_data->value, "");
            set_client_state (CLIENT_MODIFY_SETTING_VALUE);
          }
        ELSE_READ_OVER;

      case CLIENT_MODIFY_TAG:
        if (strcasecmp ("ACTIVE", element_name) == 0)
          {
            gvm_append_string (&modify_tag_data->active, "");
            set_client_state (CLIENT_MODIFY_TAG_ACTIVE);
          }
        else if (strcasecmp ("RESOURCES", element_name) == 0)
          {
            modify_tag_data->resource_ids = make_array ();
            append_attribute (attribute_names, attribute_values, "filter",
                              &modify_tag_data->resources_filter);
            append_attribute (attribute_names, attribute_values, "action",
                              &modify_tag_data->resources_action);
            set_client_state (CLIENT_MODIFY_TAG_RESOURCES);
          }
        else if (strcasecmp ("COMMENT", element_name) == 0)
          {
            gvm_append_string (&modify_tag_data->comment, "");
            set_client_state (CLIENT_MODIFY_TAG_COMMENT);
          }
        else if (strcasecmp ("NAME", element_name) == 0)
          {
            gvm_append_string (&modify_tag_data->name, "");
            set_client_state (CLIENT_MODIFY_TAG_NAME);
          }
        else if (strcasecmp ("VALUE", element_name) == 0)
          {
            gvm_append_string (&modify_tag_data->value, "");
            set_client_state (CLIENT_MODIFY_TAG_VALUE);
          }
        ELSE_READ_OVER;

      case CLIENT_MODIFY_TAG_RESOURCES:
        if (strcasecmp ("RESOURCE", element_name) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values, "id",
                                &attribute))
              array_add (modify_tag_data->resource_ids, g_strdup (attribute));
            set_client_state (CLIENT_MODIFY_TAG_RESOURCES_RESOURCE);
          }
        else if (strcasecmp ("TYPE", element_name) == 0)
          {
            gvm_append_string (&modify_tag_data->resource_type, "");
            set_client_state (CLIENT_MODIFY_TAG_RESOURCES_TYPE);
          }
        ELSE_READ_OVER;

      case CLIENT_MODIFY_TARGET:
        if (strcasecmp ("EXCLUDE_HOSTS", element_name) == 0)
          {
            gvm_append_string (&modify_target_data->exclude_hosts, "");
            set_client_state (CLIENT_MODIFY_TARGET_EXCLUDE_HOSTS);
          }
        else if (strcasecmp ("REVERSE_LOOKUP_ONLY", element_name) == 0)
          set_client_state (CLIENT_MODIFY_TARGET_REVERSE_LOOKUP_ONLY);
        else if (strcasecmp ("REVERSE_LOOKUP_UNIFY", element_name) == 0)
          set_client_state (CLIENT_MODIFY_TARGET_REVERSE_LOOKUP_UNIFY);
        else if (strcasecmp ("ALIVE_TESTS", element_name) == 0)
          set_client_state (CLIENT_MODIFY_TARGET_ALIVE_TESTS);
        else if (strcasecmp ("ALLOW_SIMULTANEOUS_IPS", element_name) == 0)
          set_client_state (CLIENT_MODIFY_TARGET_ALLOW_SIMULTANEOUS_IPS);
        else if (strcasecmp ("COMMENT", element_name) == 0)
          {
            gvm_append_string (&modify_target_data->comment, "");
            set_client_state (CLIENT_MODIFY_TARGET_COMMENT);
          }
        else if (strcasecmp ("ESXI_CREDENTIAL", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "id",
                              &modify_target_data->esxi_credential_id);
            set_client_state (CLIENT_MODIFY_TARGET_ESXI_CREDENTIAL);
          }
        else if (strcasecmp ("ESXI_LSC_CREDENTIAL", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "id",
                              &modify_target_data->esxi_lsc_credential_id);
            set_client_state (CLIENT_MODIFY_TARGET_ESXI_LSC_CREDENTIAL);
          }
        else if (strcasecmp ("HOSTS", element_name) == 0)
          {
            gvm_append_string (&modify_target_data->hosts, "");
            set_client_state (CLIENT_MODIFY_TARGET_HOSTS);
          }
        else if (strcasecmp ("PORT_LIST", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "id",
                              &modify_target_data->port_list_id);
            set_client_state (CLIENT_MODIFY_TARGET_PORT_LIST);
          }
        else if (strcasecmp ("SSH_CREDENTIAL", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "id",
                              &modify_target_data->ssh_credential_id);
            set_client_state (CLIENT_MODIFY_TARGET_SSH_CREDENTIAL);
          }
        else if (strcasecmp ("SSH_LSC_CREDENTIAL", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "id",
                              &modify_target_data->ssh_lsc_credential_id);
            set_client_state (CLIENT_MODIFY_TARGET_SSH_LSC_CREDENTIAL);
          }
        else if (strcasecmp ("SSH_ELEVATE_CREDENTIAL", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "id",
                              &modify_target_data->ssh_elevate_credential_id);
            set_client_state (CLIENT_MODIFY_TARGET_SSH_ELEVATE_CREDENTIAL);
          }
        else if (strcasecmp ("SMB_CREDENTIAL", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "id",
                              &modify_target_data->smb_credential_id);
            set_client_state (CLIENT_MODIFY_TARGET_SMB_CREDENTIAL);
          }
        else if (strcasecmp ("SMB_LSC_CREDENTIAL", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "id",
                              &modify_target_data->smb_lsc_credential_id);
            set_client_state (CLIENT_MODIFY_TARGET_SMB_LSC_CREDENTIAL);
          }
        else if (strcasecmp ("SNMP_CREDENTIAL", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "id",
                              &modify_target_data->snmp_credential_id);
            set_client_state (CLIENT_MODIFY_TARGET_SNMP_CREDENTIAL);
          }
        else if (strcasecmp ("NAME", element_name) == 0)
          {
            gvm_append_string (&modify_target_data->name, "");
            set_client_state (CLIENT_MODIFY_TARGET_NAME);
          }
        ELSE_READ_OVER;

      case CLIENT_MODIFY_TARGET_SSH_CREDENTIAL:
        if (strcasecmp ("PORT", element_name) == 0)
          set_client_state (CLIENT_MODIFY_TARGET_SSH_CREDENTIAL_PORT);
        ELSE_READ_OVER;

      case CLIENT_MODIFY_TARGET_SSH_LSC_CREDENTIAL:
        if (strcasecmp ("PORT", element_name) == 0)
          set_client_state (CLIENT_MODIFY_TARGET_SSH_LSC_CREDENTIAL_PORT);
        ELSE_READ_OVER;

      case CLIENT_MODIFY_TASK:
        if (strcasecmp ("ALTERABLE", element_name) == 0)
          set_client_state (CLIENT_MODIFY_TASK_ALTERABLE);
        else if (strcasecmp ("COMMENT", element_name) == 0)
          {
            gvm_append_string (&modify_task_data->comment, "");
            set_client_state (CLIENT_MODIFY_TASK_COMMENT);
          }
        else if (strcasecmp ("HOSTS_ORDERING", element_name) == 0)
          set_client_state (CLIENT_MODIFY_TASK_HOSTS_ORDERING);
        else if (strcasecmp ("SCANNER", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "id",
                              &modify_task_data->scanner_id);
            set_client_state (CLIENT_MODIFY_TASK_SCANNER);
          }
        else if (strcasecmp ("ALERT", element_name) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values, "id",
                                &attribute))
              array_add (modify_task_data->alerts, g_strdup (attribute));
            set_client_state (CLIENT_MODIFY_TASK_ALERT);
          }
        else if (strcasecmp ("CONFIG", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "id",
                              &modify_task_data->config_id);
            set_client_state (CLIENT_MODIFY_TASK_CONFIG);
          }
        else if (strcasecmp ("NAME", element_name) == 0)
          set_client_state (CLIENT_MODIFY_TASK_NAME);
        else if (strcasecmp ("OBSERVERS", element_name) == 0)
          {
            gvm_append_string (&modify_task_data->observers, "");
            set_client_state (CLIENT_MODIFY_TASK_OBSERVERS);
          }
        else if (strcasecmp ("PREFERENCES", element_name) == 0)
          {
            modify_task_data->preferences = make_array ();
            set_client_state (CLIENT_MODIFY_TASK_PREFERENCES);
          }
        else if (strcasecmp ("SCHEDULE", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "id",
                              &modify_task_data->schedule_id);
            set_client_state (CLIENT_MODIFY_TASK_SCHEDULE);
          }
        else if (strcasecmp ("SCHEDULE_PERIODS", element_name) == 0)
          set_client_state (CLIENT_MODIFY_TASK_SCHEDULE_PERIODS);
        else if (strcasecmp ("TARGET", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "id",
                              &modify_task_data->target_id);
            set_client_state (CLIENT_MODIFY_TASK_TARGET);
          }
        else if (strcasecmp ("FILE", element_name) == 0)
          {
            const gchar* attribute;
            append_attribute (attribute_names, attribute_values, "name",
                              &modify_task_data->file_name);
            if (find_attribute (attribute_names, attribute_values,
                                "action", &attribute))
              gvm_append_string (&modify_task_data->action, attribute);
            else
              gvm_append_string (&modify_task_data->action, "update");
            set_client_state (CLIENT_MODIFY_TASK_FILE);
          }
        ELSE_READ_OVER;

      case CLIENT_MODIFY_TASK_OBSERVERS:
        if (strcasecmp ("GROUP", element_name) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values, "id",
                                &attribute))
              array_add (modify_task_data->groups, g_strdup (attribute));
            set_client_state (CLIENT_MODIFY_TASK_OBSERVERS_GROUP);
          }
        ELSE_READ_OVER;

      case CLIENT_MODIFY_TASK_PREFERENCES:
        if (strcasecmp ("PREFERENCE", element_name) == 0)
          {
            assert (modify_task_data->preference == NULL);
            modify_task_data->preference = g_malloc (sizeof (name_value_t));
            modify_task_data->preference->name = NULL;
            modify_task_data->preference->value = NULL;
            set_client_state (CLIENT_MODIFY_TASK_PREFERENCES_PREFERENCE);
          }
        ELSE_READ_OVER;

      case CLIENT_MODIFY_TASK_PREFERENCES_PREFERENCE:
        if (strcasecmp ("SCANNER_NAME", element_name) == 0)
          set_client_state (CLIENT_MODIFY_TASK_PREFERENCES_PREFERENCE_NAME);
        else if (strcasecmp ("VALUE", element_name) == 0)
          set_client_state (CLIENT_MODIFY_TASK_PREFERENCES_PREFERENCE_VALUE);
        ELSE_READ_OVER;

      case CLIENT_MODIFY_TICKET:
        modify_ticket_element_start (gmp_parser, element_name,
                                     attribute_names,
                                     attribute_values);
        break;

      case CLIENT_MODIFY_TLS_CERTIFICATE:
        modify_tls_certificate_element_start (gmp_parser, element_name,
                                              attribute_names,
                                              attribute_values);
        break;

      case CLIENT_MODIFY_USER:
        if (strcasecmp ("COMMENT", element_name) == 0)
          {
            gvm_append_string (&modify_user_data->comment, "");
            set_client_state (CLIENT_MODIFY_USER_COMMENT);
          }
        else if (strcasecmp ("GROUPS", element_name) == 0)
          {
            if (modify_user_data->groups)
              array_free (modify_user_data->groups);
            modify_user_data->groups = make_array ();
            set_client_state (CLIENT_MODIFY_USER_GROUPS);
          }
        else if (strcasecmp ("HOSTS", element_name) == 0)
          {
            const gchar *attribute;
            if (find_attribute
                (attribute_names, attribute_values, "allow", &attribute))
              modify_user_data->hosts_allow = strcmp (attribute, "0");
            else
              modify_user_data->hosts_allow = 1;
            /* Init, so that modify_user clears hosts if HOSTS is empty. */
            gvm_append_string (&modify_user_data->hosts, "");
            set_client_state (CLIENT_MODIFY_USER_HOSTS);
          }
        else if (strcasecmp ("NAME", element_name) == 0)
          set_client_state (CLIENT_MODIFY_USER_NAME);
        else if (strcasecmp ("NEW_NAME", element_name) == 0)
          set_client_state (CLIENT_MODIFY_USER_NEW_NAME);
        else if (strcasecmp ("PASSWORD", element_name) == 0)
          {
            const gchar *attribute;
            if (find_attribute
                (attribute_names, attribute_values, "modify", &attribute))
              modify_user_data->modify_password = strcmp (attribute, "0");
            else
              modify_user_data->modify_password = 1;
            set_client_state (CLIENT_MODIFY_USER_PASSWORD);
          }
        else if (strcasecmp ("ROLE", element_name) == 0)
          {
            const gchar* attribute;
            /* Init array here, so it's NULL if there are no ROLEs. */
            if (modify_user_data->roles == NULL)
              {
                array_free (modify_user_data->roles);
                modify_user_data->roles = make_array ();
              }
            if (find_attribute (attribute_names, attribute_values, "id",
                                &attribute))
              array_add (modify_user_data->roles, g_strdup (attribute));
            set_client_state (CLIENT_MODIFY_USER_ROLE);
          }
        else if (strcasecmp ("SOURCES", element_name) == 0)
          {
            modify_user_data->sources = make_array ();
            set_client_state (CLIENT_MODIFY_USER_SOURCES);
          }
        else
          set_read_over (gmp_parser);
        break;

      case CLIENT_MODIFY_USER_GROUPS:
        if (strcasecmp ("GROUP", element_name) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values, "id",
                                &attribute))
              array_add (modify_user_data->groups, g_strdup (attribute));
            set_client_state (CLIENT_MODIFY_USER_GROUPS_GROUP);
          }
        ELSE_READ_OVER;

      case CLIENT_MODIFY_USER_SOURCES:
        if (strcasecmp ("SOURCE", element_name) == 0)
         {
           set_client_state (CLIENT_MODIFY_USER_SOURCES_SOURCE);
         }
        else
          set_read_over (gmp_parser);
        break;

      case CLIENT_CREATE_ASSET:
        if (strcasecmp ("ASSET", element_name) == 0)
          set_client_state (CLIENT_CREATE_ASSET_ASSET);
        else if (strcasecmp ("REPORT", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "id",
                              &create_asset_data->report_id);
            set_client_state (CLIENT_CREATE_ASSET_REPORT);
          }
        ELSE_READ_OVER;

      case CLIENT_CREATE_ASSET_ASSET:
        if (strcasecmp ("COMMENT", element_name) == 0)
          set_client_state (CLIENT_CREATE_ASSET_ASSET_COMMENT);
        else if (strcasecmp ("NAME", element_name) == 0)
          set_client_state (CLIENT_CREATE_ASSET_ASSET_NAME);
        else if (strcasecmp ("TYPE", element_name) == 0)
          set_client_state (CLIENT_CREATE_ASSET_ASSET_TYPE);
        ELSE_READ_OVER;

      case CLIENT_CREATE_ASSET_REPORT:
        if (strcasecmp ("FILTER", element_name) == 0)
          set_client_state (CLIENT_CREATE_ASSET_REPORT_FILTER);
        ELSE_READ_OVER;

      case CLIENT_CREATE_ASSET_REPORT_FILTER:
        if (strcasecmp ("TERM", element_name) == 0)
          set_client_state (CLIENT_CREATE_ASSET_REPORT_FILTER_TERM);
        ELSE_READ_OVER;

      case CLIENT_CREATE_CONFIG:
        create_config_element_start (gmp_parser, element_name,
                                     attribute_names,
                                     attribute_values);
        break;

      case CLIENT_CREATE_ALERT:
        if (strcasecmp ("ACTIVE", element_name) == 0)
          set_client_state (CLIENT_CREATE_ALERT_ACTIVE);
        else if (strcasecmp ("COMMENT", element_name) == 0)
          set_client_state (CLIENT_CREATE_ALERT_COMMENT);
        else if (strcasecmp ("COPY", element_name) == 0)
          set_client_state (CLIENT_CREATE_ALERT_COPY);
        else if (strcasecmp ("CONDITION", element_name) == 0)
          set_client_state (CLIENT_CREATE_ALERT_CONDITION);
        else if (strcasecmp ("EVENT", element_name) == 0)
          set_client_state (CLIENT_CREATE_ALERT_EVENT);
        else if (strcasecmp ("FILTER", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "id",
                              &create_alert_data->filter_id);
            set_client_state (CLIENT_CREATE_ALERT_FILTER);
          }
        else if (strcasecmp ("METHOD", element_name) == 0)
          set_client_state (CLIENT_CREATE_ALERT_METHOD);
        else if (strcasecmp ("NAME", element_name) == 0)
          set_client_state (CLIENT_CREATE_ALERT_NAME);
        ELSE_READ_OVER;

      case CLIENT_CREATE_ALERT_CONDITION:
        if (strcasecmp ("DATA", element_name) == 0)
          set_client_state (CLIENT_CREATE_ALERT_CONDITION_DATA);
        ELSE_READ_OVER;

      case CLIENT_CREATE_ALERT_CONDITION_DATA:
        if (strcasecmp ("NAME", element_name) == 0)
          set_client_state (CLIENT_CREATE_ALERT_CONDITION_DATA_NAME);
        ELSE_READ_OVER;

      case CLIENT_CREATE_ALERT_EVENT:
        if (strcasecmp ("DATA", element_name) == 0)
          set_client_state (CLIENT_CREATE_ALERT_EVENT_DATA);
        ELSE_READ_OVER;

      case CLIENT_CREATE_ALERT_EVENT_DATA:
        if (strcasecmp ("NAME", element_name) == 0)
          set_client_state (CLIENT_CREATE_ALERT_EVENT_DATA_NAME);
        ELSE_READ_OVER;

      case CLIENT_CREATE_ALERT_METHOD:
        if (strcasecmp ("DATA", element_name) == 0)
          set_client_state (CLIENT_CREATE_ALERT_METHOD_DATA);
        ELSE_READ_OVER;

      case CLIENT_CREATE_ALERT_METHOD_DATA:
        if (strcasecmp ("NAME", element_name) == 0)
          set_client_state (CLIENT_CREATE_ALERT_METHOD_DATA_NAME);
        ELSE_READ_OVER;

      case CLIENT_CREATE_CREDENTIAL:
        if (strcasecmp ("ALLOW_INSECURE", element_name) == 0)
          set_client_state (CLIENT_CREATE_CREDENTIAL_ALLOW_INSECURE);
        else if (strcasecmp ("AUTH_ALGORITHM", element_name) == 0)
          set_client_state (CLIENT_CREATE_CREDENTIAL_AUTH_ALGORITHM);
        else if (strcasecmp ("CERTIFICATE", element_name) == 0)
          set_client_state (CLIENT_CREATE_CREDENTIAL_CERTIFICATE);
        else if (strcasecmp ("COMMENT", element_name) == 0)
          set_client_state (CLIENT_CREATE_CREDENTIAL_COMMENT);
        else if (strcasecmp ("COMMUNITY", element_name) == 0)
          set_client_state (CLIENT_CREATE_CREDENTIAL_COMMUNITY);
        else if (strcasecmp ("KEY", element_name) == 0)
          {
            create_credential_data->key = 1;
            set_client_state (CLIENT_CREATE_CREDENTIAL_KEY);
          }
        else if (strcasecmp ("LOGIN", element_name) == 0)
          set_client_state (CLIENT_CREATE_CREDENTIAL_LOGIN);
        else if (strcasecmp ("COPY", element_name) == 0)
          set_client_state (CLIENT_CREATE_CREDENTIAL_COPY);
        else if (strcasecmp ("NAME", element_name) == 0)
          set_client_state (CLIENT_CREATE_CREDENTIAL_NAME);
        else if (strcasecmp ("PASSWORD", element_name) == 0)
          {
            gvm_append_string (&create_credential_data->password, "");
            set_client_state (CLIENT_CREATE_CREDENTIAL_PASSWORD);
          }
        else if (strcasecmp ("PRIVACY", element_name) == 0)
          set_client_state (CLIENT_CREATE_CREDENTIAL_PRIVACY);
        else if (strcasecmp ("TYPE", element_name) == 0)
          set_client_state (CLIENT_CREATE_CREDENTIAL_TYPE);
        ELSE_READ_OVER;

      case CLIENT_CREATE_CREDENTIAL_KEY:
        if (strcasecmp ("PHRASE", element_name) == 0)
          {
            gvm_append_string (&create_credential_data->key_phrase, "");
            set_client_state (CLIENT_CREATE_CREDENTIAL_KEY_PHRASE);
          }
        else if (strcasecmp ("PRIVATE", element_name) == 0)
          set_client_state (CLIENT_CREATE_CREDENTIAL_KEY_PRIVATE);
        else if (strcasecmp ("PUBLIC", element_name) == 0)
          set_client_state (CLIENT_CREATE_CREDENTIAL_KEY_PUBLIC);
        ELSE_READ_OVER;

      case CLIENT_CREATE_CREDENTIAL_PRIVACY:
        if (strcasecmp ("ALGORITHM", element_name) == 0)
          set_client_state (CLIENT_CREATE_CREDENTIAL_PRIVACY_ALGORITHM);
        else if (strcasecmp ("PASSWORD", element_name) == 0)
          set_client_state (CLIENT_CREATE_CREDENTIAL_PRIVACY_PASSWORD);
        ELSE_READ_OVER;

      case CLIENT_CREATE_FILTER:
        if (strcasecmp ("COMMENT", element_name) == 0)
          set_client_state (CLIENT_CREATE_FILTER_COMMENT);
        else if (strcasecmp ("COPY", element_name) == 0)
          set_client_state (CLIENT_CREATE_FILTER_COPY);
        else if (strcasecmp ("NAME", element_name) == 0)
          {
            gvm_append_string (&create_filter_data->name, "");
            set_client_state (CLIENT_CREATE_FILTER_NAME);
          }
        else if (strcasecmp ("TERM", element_name) == 0)
          set_client_state (CLIENT_CREATE_FILTER_TERM);
        else if (strcasecmp ("TYPE", element_name) == 0)
          set_client_state (CLIENT_CREATE_FILTER_TYPE);
        ELSE_READ_OVER;

      case CLIENT_CREATE_GROUP:
        if (strcasecmp ("COMMENT", element_name) == 0)
          set_client_state (CLIENT_CREATE_GROUP_COMMENT);
        else if (strcasecmp ("COPY", element_name) == 0)
          set_client_state (CLIENT_CREATE_GROUP_COPY);
        else if (strcasecmp ("NAME", element_name) == 0)
          {
            gvm_append_string (&create_group_data->name, "");
            set_client_state (CLIENT_CREATE_GROUP_NAME);
          }
        else if (strcasecmp ("SPECIALS", element_name) == 0)
          set_client_state (CLIENT_CREATE_GROUP_SPECIALS);
        else if (strcasecmp ("USERS", element_name) == 0)
          set_client_state (CLIENT_CREATE_GROUP_USERS);
        ELSE_READ_OVER;

      case CLIENT_CREATE_GROUP_SPECIALS:
        if (strcasecmp ("FULL", element_name) == 0)
          {
            create_group_data->special_full = 1;
            set_client_state (CLIENT_CREATE_GROUP_SPECIALS_FULL);
          }
        ELSE_READ_OVER;

      case CLIENT_CREATE_NOTE:
        if (strcasecmp ("ACTIVE", element_name) == 0)
          set_client_state (CLIENT_CREATE_NOTE_ACTIVE);
        else if (strcasecmp ("COPY", element_name) == 0)
          set_client_state (CLIENT_CREATE_NOTE_COPY);
        else if (strcasecmp ("HOSTS", element_name) == 0)
          set_client_state (CLIENT_CREATE_NOTE_HOSTS);
        else if (strcasecmp ("NVT", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "oid",
                              &create_note_data->nvt_oid);
            set_client_state (CLIENT_CREATE_NOTE_NVT);
          }
        else if (strcasecmp ("PORT", element_name) == 0)
          set_client_state (CLIENT_CREATE_NOTE_PORT);
        else if (strcasecmp ("RESULT", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "id",
                              &create_note_data->result_id);
            if (create_note_data->result_id
                && create_note_data->result_id[0] == '\0')
              {
                g_free (create_note_data->result_id);
                create_note_data->result_id = NULL;
              }
            set_client_state (CLIENT_CREATE_NOTE_RESULT);
          }
        else if (strcasecmp ("SEVERITY", element_name) == 0)
          set_client_state (CLIENT_CREATE_NOTE_SEVERITY);
        else if (strcasecmp ("TASK", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "id",
                              &create_note_data->task_id);
            if (create_note_data->task_id
                && create_note_data->task_id[0] == '\0')
              {
                g_free (create_note_data->task_id);
                create_note_data->task_id = NULL;
              }
            set_client_state (CLIENT_CREATE_NOTE_TASK);
          }
        else if (strcasecmp ("TEXT", element_name) == 0)
          set_client_state (CLIENT_CREATE_NOTE_TEXT);
        else if (strcasecmp ("THREAT", element_name) == 0)
          set_client_state (CLIENT_CREATE_NOTE_THREAT);
        ELSE_READ_OVER;

      case CLIENT_CREATE_PERMISSION:
        if (strcasecmp ("COMMENT", element_name) == 0)
          set_client_state (CLIENT_CREATE_PERMISSION_COMMENT);
        else if (strcasecmp ("COPY", element_name) == 0)
          set_client_state (CLIENT_CREATE_PERMISSION_COPY);
        else if (strcasecmp ("NAME", element_name) == 0)
          {
            gvm_append_string (&create_permission_data->name, "");
            set_client_state (CLIENT_CREATE_PERMISSION_NAME);
          }
        else if (strcasecmp ("RESOURCE", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "id",
                              &create_permission_data->resource_id);
            set_client_state (CLIENT_CREATE_PERMISSION_RESOURCE);
          }
        else if (strcasecmp ("SUBJECT", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "id",
                              &create_permission_data->subject_id);
            set_client_state (CLIENT_CREATE_PERMISSION_SUBJECT);
          }
        ELSE_READ_OVER;

      case CLIENT_CREATE_PERMISSION_RESOURCE:
        if (strcasecmp ("TYPE", element_name) == 0)
          set_client_state (CLIENT_CREATE_PERMISSION_RESOURCE_TYPE);
        ELSE_READ_OVER;

      case CLIENT_CREATE_PERMISSION_SUBJECT:
        if (strcasecmp ("TYPE", element_name) == 0)
          set_client_state (CLIENT_CREATE_PERMISSION_SUBJECT_TYPE);
        ELSE_READ_OVER;

      case CLIENT_CREATE_PORT_LIST:
        create_port_list_element_start (gmp_parser, element_name,
                                        attribute_names,
                                        attribute_values);
        break;

      case CLIENT_CREATE_PORT_RANGE:
        if (strcasecmp ("COMMENT", element_name) == 0)
          set_client_state (CLIENT_CREATE_PORT_RANGE_COMMENT);
        else if (strcasecmp ("END", element_name) == 0)
          set_client_state (CLIENT_CREATE_PORT_RANGE_END);
        else if (strcasecmp ("PORT_LIST", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "id",
                              &create_port_range_data->port_list_id);
            set_client_state (CLIENT_CREATE_PORT_RANGE_PORT_LIST);
          }
        else if (strcasecmp ("START", element_name) == 0)
          set_client_state (CLIENT_CREATE_PORT_RANGE_START);
        else if (strcasecmp ("TYPE", element_name) == 0)
          set_client_state (CLIENT_CREATE_PORT_RANGE_TYPE);
        ELSE_READ_OVER;

      case CLIENT_CREATE_ROLE:
        if (strcasecmp ("COMMENT", element_name) == 0)
          set_client_state (CLIENT_CREATE_ROLE_COMMENT);
        else if (strcasecmp ("COPY", element_name) == 0)
          set_client_state (CLIENT_CREATE_ROLE_COPY);
        else if (strcasecmp ("NAME", element_name) == 0)
          {
            gvm_append_string (&create_role_data->name, "");
            set_client_state (CLIENT_CREATE_ROLE_NAME);
          }
        else if (strcasecmp ("USERS", element_name) == 0)
          set_client_state (CLIENT_CREATE_ROLE_USERS);
        ELSE_READ_OVER;

      case CLIENT_CREATE_REPORT:
        if (strcasecmp ("IN_ASSETS", element_name) == 0)
          {
            set_client_state (CLIENT_CREATE_REPORT_IN_ASSETS);
          }
        else if (strcasecmp ("REPORT", element_name) == 0)
          {
            const gchar* attribute;

            append_attribute (attribute_names, attribute_values,
                              "type", &create_report_data->type);

            if (find_attribute (attribute_names, attribute_values, "format_id",
                                &attribute))
              {
                /* Assume this is the wrapper REPORT. */
                create_report_data->wrapper = 1;
                set_client_state (CLIENT_CREATE_REPORT_REPORT);
              }
            else
              {
                /* Assume the report is immediately inside the CREATE_REPORT. */
                create_report_data->wrapper = 0;
                create_report_data->details = make_array ();
                create_report_data->host_ends = make_array ();
                create_report_data->host_starts = make_array ();
                create_report_data->results = make_array ();
                create_report_data->result_detection = make_array ();
                set_client_state (CLIENT_CREATE_REPORT_RR);
              }
          }
        else if (strcasecmp ("TASK", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "id",
                              &create_report_data->task_id);
            set_client_state (CLIENT_CREATE_REPORT_TASK);
          }
        ELSE_READ_OVER;

      case CLIENT_CREATE_REPORT_REPORT:
        if (strcasecmp ("REPORT", element_name) == 0)
          {
            create_report_data->details = make_array ();
            create_report_data->host_ends = make_array ();
            create_report_data->host_starts = make_array ();
            create_report_data->results = make_array ();
            create_report_data->result_detection = make_array ();
            set_client_state (CLIENT_CREATE_REPORT_RR);
          }
        ELSE_READ_OVER;

      case CLIENT_CREATE_REPORT_RR:
        if (strcasecmp ("ERRORS", element_name) == 0)
          {
            set_client_state (CLIENT_CREATE_REPORT_RR_ERRORS);
          }
        else if (strcasecmp ("HOST", element_name) == 0)
          {
            set_client_state (CLIENT_CREATE_REPORT_RR_H);
          }
        else if (strcasecmp ("HOST_END", element_name) == 0)
          set_client_state (CLIENT_CREATE_REPORT_RR_HOST_END);
        else if (strcasecmp ("HOST_START", element_name) == 0)
          set_client_state (CLIENT_CREATE_REPORT_RR_HOST_START);
        else if (strcasecmp ("RESULTS", element_name) == 0)
          set_client_state (CLIENT_CREATE_REPORT_RR_RESULTS);
        else if (strcasecmp ("SCAN_END", element_name) == 0)
          {
            set_client_state (CLIENT_CREATE_REPORT_RR_SCAN_END);
          }
        else if (strcasecmp ("SCAN_START", element_name) == 0)
          {
            set_client_state (CLIENT_CREATE_REPORT_RR_SCAN_START);
          }
        ELSE_READ_OVER;

      case CLIENT_CREATE_REPORT_RR_ERRORS:
        if (strcasecmp ("ERROR", element_name) == 0)
          {
            set_client_state (CLIENT_CREATE_REPORT_RR_ERRORS_ERROR);
          }
        ELSE_READ_OVER;

      case CLIENT_CREATE_REPORT_RR_ERRORS_ERROR:
        if (strcasecmp ("DESCRIPTION", element_name) == 0)
          set_client_state
           (CLIENT_CREATE_REPORT_RR_ERRORS_ERROR_DESCRIPTION);
        else if (strcasecmp ("HOST", element_name) == 0)
          {
            set_client_state (CLIENT_CREATE_REPORT_RR_ERRORS_ERROR_HOST);
          }
        else if (strcasecmp ("NVT", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "oid",
                              &create_report_data->result_nvt_oid);
            set_client_state (CLIENT_CREATE_REPORT_RR_ERRORS_ERROR_NVT);
          }
        else if (strcasecmp ("PORT", element_name) == 0)
          set_client_state (CLIENT_CREATE_REPORT_RR_ERRORS_ERROR_PORT);
        else if (strcasecmp ("SCAN_NVT_VERSION", element_name) == 0)
          set_client_state
           (CLIENT_CREATE_REPORT_RR_ERRORS_ERROR_SCAN_NVT_VERSION);
        else if (strcasecmp ("SEVERITY", element_name) == 0)
          set_client_state (CLIENT_CREATE_REPORT_RR_ERRORS_ERROR_SEVERITY);
        ELSE_READ_OVER;

      case CLIENT_CREATE_REPORT_RR_ERRORS_ERROR_HOST:
        if (strcasecmp ("ASSET", element_name) == 0)
          set_client_state
            (CLIENT_CREATE_REPORT_RR_ERRORS_ERROR_HOST_ASSET);
        else if (strcasecmp ("HOSTNAME", element_name) == 0)
          set_client_state
            (CLIENT_CREATE_REPORT_RR_ERRORS_ERROR_HOST_HOSTNAME);
        ELSE_READ_OVER;

      case CLIENT_CREATE_REPORT_RR_ERRORS_ERROR_NVT:
        if (strcasecmp ("CVSS_BASE", element_name) == 0)
          set_client_state
           (CLIENT_CREATE_REPORT_RR_ERRORS_ERROR_NVT_CVSS_BASE);
        else if (strcasecmp ("NAME", element_name) == 0)
          set_client_state (CLIENT_CREATE_REPORT_RR_ERRORS_ERROR_NVT_NAME);
        ELSE_READ_OVER;

      case CLIENT_CREATE_REPORT_RR_HOST_END:
        if (strcasecmp ("HOST", element_name) == 0)
          set_client_state (CLIENT_CREATE_REPORT_RR_HOST_END_HOST);
        ELSE_READ_OVER;

      case CLIENT_CREATE_REPORT_RR_HOST_START:
        if (strcasecmp ("HOST", element_name) == 0)
          set_client_state (CLIENT_CREATE_REPORT_RR_HOST_START_HOST);
        ELSE_READ_OVER;

      case CLIENT_CREATE_REPORT_RR_H:
        if (strcasecmp ("IP", element_name) == 0)
          {
            set_client_state (CLIENT_CREATE_REPORT_RR_H_IP);
          }
        else if (strcasecmp ("DETAIL", element_name) == 0)
          {
            set_client_state (CLIENT_CREATE_REPORT_RR_H_DETAIL);
          }
        else if (strcasecmp ("END", element_name) == 0)
          {
            set_client_state (CLIENT_CREATE_REPORT_RR_H_END);
          }
        else if (strcasecmp ("START", element_name) == 0)
          {
            set_client_state (CLIENT_CREATE_REPORT_RR_H_START);
          }
        ELSE_READ_OVER;

      case CLIENT_CREATE_REPORT_RR_H_DETAIL:
        if (strcasecmp ("NAME", element_name) == 0)
          {
            set_client_state (CLIENT_CREATE_REPORT_RR_H_DETAIL_NAME);
          }
        else if (strcasecmp ("VALUE", element_name) == 0)
          {
            set_client_state (CLIENT_CREATE_REPORT_RR_H_DETAIL_VALUE);
          }
        else if (strcasecmp ("SOURCE", element_name) == 0)
          {
            set_client_state (CLIENT_CREATE_REPORT_RR_H_DETAIL_SOURCE);
          }
        ELSE_READ_OVER;

      case CLIENT_CREATE_REPORT_RR_H_DETAIL_SOURCE:
        if (strcasecmp ("DESCRIPTION", element_name) == 0)
          {
            set_client_state (CLIENT_CREATE_REPORT_RR_H_DETAIL_SOURCE_DESC);
          }
        else if (strcasecmp ("NAME", element_name) == 0)
          {
            set_client_state (CLIENT_CREATE_REPORT_RR_H_DETAIL_SOURCE_NAME);
          }
        else if (strcasecmp ("TYPE", element_name) == 0)
          {
            set_client_state (CLIENT_CREATE_REPORT_RR_H_DETAIL_SOURCE_TYPE);
          }
        ELSE_READ_OVER;

      case CLIENT_CREATE_REPORT_RR_RESULTS:
        if (strcasecmp ("RESULT", element_name) == 0)
          set_client_state
           (CLIENT_CREATE_REPORT_RR_RESULTS_RESULT);
        ELSE_READ_OVER;

      case CLIENT_CREATE_REPORT_RR_RESULTS_RESULT:
        if (strcasecmp ("DESCRIPTION", element_name) == 0)
          set_client_state (CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_DESCRIPTION);
        else if (strcasecmp ("HOST", element_name) == 0)
          {
            set_client_state (CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_HOST);
          }
        else if (strcasecmp ("NVT", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "oid",
                              &create_report_data->result_nvt_oid);
            set_client_state (CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_NVT);
          }
        else if (strcasecmp ("ORIGINAL_SEVERITY", element_name) == 0)
          set_client_state (
            CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_ORIGINAL_SEVERITY);
        else if (strcasecmp ("ORIGINAL_THREAT", element_name) == 0)
          set_client_state (
            CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_ORIGINAL_THREAT);
        else if (strcasecmp ("PORT", element_name) == 0)
          set_client_state (CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_PORT);
        else if (strcasecmp ("QOD", element_name) == 0)
          set_client_state (CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_QOD);
        else if (strcasecmp ("SCAN_NVT_VERSION", element_name) == 0)
          set_client_state (
            CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_SCAN_NVT_VERSION);
        else if (strcasecmp ("SEVERITY", element_name) == 0)
          set_client_state (CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_SEVERITY);
        else if (strcasecmp ("THREAT", element_name) == 0)
          set_client_state (CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_THREAT);
        else if (strcasecmp ("DETECTION", element_name) == 0)
          set_client_state (CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_DETECTION);
        ELSE_READ_OVER;
      case CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_DETECTION:
        if (strcasecmp ("RESULT", element_name) == 0)
          {
            set_client_state (
              CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_DETECTION_RESULT);
          }
       ELSE_READ_OVER; 
     case CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_DETECTION_RESULT:
        if (strcasecmp ("DETAILS", element_name) == 0)
          {
            set_client_state (
              CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_DETECTION_RESULT_DETAILS);
          }
        ELSE_READ_OVER;
      case CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_DETECTION_RESULT_DETAILS:
        if (strcasecmp ("DETAIL", element_name) == 0)
          {
            set_client_state (
              CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_DETECTION_RESULT_DETAILS_DETAIL);
          }
        ELSE_READ_OVER;
      case CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_DETECTION_RESULT_DETAILS_DETAIL:
        if (strcasecmp ("NAME", element_name) == 0)
          {
            set_client_state (
              CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_DETECTION_RESULT_DETAILS_DETAIL_NAME);
          }
        else if (strcasecmp ("VALUE", element_name) == 0)
          {
            set_client_state (
              CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_DETECTION_RESULT_DETAILS_DETAIL_VALUE);
          }
        ELSE_READ_OVER;

      case CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_HOST:
        if (strcasecmp ("ASSET", element_name) == 0)
          set_client_state
            (CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_HOST_ASSET);
        else if (strcasecmp ("HOSTNAME", element_name) == 0)
          set_client_state
            (CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_HOST_HOSTNAME);
        ELSE_READ_OVER;

      case CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_NVT:
        if (strcasecmp ("BID", element_name) == 0)
          set_client_state (CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_NVT_BID);
        else if (strcasecmp ("CVE", element_name) == 0)
          set_client_state (CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_NVT_CVE);
        else if (strcasecmp ("CVSS_BASE", element_name) == 0)
          set_client_state
           (CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_NVT_CVSS_BASE);
        else if (strcasecmp ("FAMILY", element_name) == 0)
          set_client_state (CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_NVT_FAMILY);
        else if (strcasecmp ("NAME", element_name) == 0)
          set_client_state (CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_NVT_NAME);
        else if (strcasecmp ("XREF", element_name) == 0)
          set_client_state (CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_NVT_XREF);
        else if (strcasecmp ("CERT", element_name) == 0)
          set_client_state (CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_NVT_CERT);
        ELSE_READ_OVER;

      case (CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_NVT_CERT):
        if (strcasecmp ("CERT_REF", element_name) == 0)
          set_client_state
              (CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_NVT_CERT_CERT_REF);
        ELSE_READ_OVER;

      case CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_QOD:
        if (strcasecmp ("TYPE", element_name) == 0)
          set_client_state (CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_QOD_TYPE);
        else if (strcasecmp ("VALUE", element_name) == 0)
          set_client_state (CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_QOD_VALUE);
        ELSE_READ_OVER;

      case CLIENT_CREATE_REPORT_TASK:
        if (strcasecmp ("COMMENT", element_name) == 0)
          set_client_state (CLIENT_CREATE_REPORT_TASK_COMMENT);
        else if (strcasecmp ("NAME", element_name) == 0)
          set_client_state (CLIENT_CREATE_REPORT_TASK_NAME);
        ELSE_READ_OVER;

      case CLIENT_CREATE_REPORT_FORMAT:
        create_report_format_element_start (gmp_parser, element_name,
                                            attribute_names,
                                            attribute_values);
        break;

      case CLIENT_CREATE_OVERRIDE:
        if (strcasecmp ("ACTIVE", element_name) == 0)
          set_client_state (CLIENT_CREATE_OVERRIDE_ACTIVE);
        else if (strcasecmp ("COPY", element_name) == 0)
          set_client_state (CLIENT_CREATE_OVERRIDE_COPY);
        else if (strcasecmp ("HOSTS", element_name) == 0)
          set_client_state (CLIENT_CREATE_OVERRIDE_HOSTS);
        else if (strcasecmp ("NEW_SEVERITY", element_name) == 0)
          set_client_state (CLIENT_CREATE_OVERRIDE_NEW_SEVERITY);
        else if (strcasecmp ("NEW_THREAT", element_name) == 0)
          set_client_state (CLIENT_CREATE_OVERRIDE_NEW_THREAT);
        else if (strcasecmp ("NVT", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "oid",
                              &create_override_data->nvt_oid);
            set_client_state (CLIENT_CREATE_OVERRIDE_NVT);
          }
        else if (strcasecmp ("PORT", element_name) == 0)
          set_client_state (CLIENT_CREATE_OVERRIDE_PORT);
        else if (strcasecmp ("RESULT", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "id",
                              &create_override_data->result_id);
            if (create_override_data->result_id
                && create_override_data->result_id[0] == '\0')
              {
                g_free (create_override_data->result_id);
                create_override_data->result_id = NULL;
              }
            set_client_state (CLIENT_CREATE_OVERRIDE_RESULT);
          }
        else if (strcasecmp ("SEVERITY", element_name) == 0)
          set_client_state (CLIENT_CREATE_OVERRIDE_SEVERITY);
        else if (strcasecmp ("TASK", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "id",
                              &create_override_data->task_id);
            if (create_override_data->task_id
                && create_override_data->task_id[0] == '\0')
              {
                g_free (create_override_data->task_id);
                create_override_data->task_id = NULL;
              }
            set_client_state (CLIENT_CREATE_OVERRIDE_TASK);
          }
        else if (strcasecmp ("TEXT", element_name) == 0)
          set_client_state (CLIENT_CREATE_OVERRIDE_TEXT);
        else if (strcasecmp ("THREAT", element_name) == 0)
          set_client_state (CLIENT_CREATE_OVERRIDE_THREAT);
        ELSE_READ_OVER;

      case CLIENT_CREATE_TAG:
        if (strcasecmp ("ACTIVE", element_name) == 0)
          {
            gvm_append_string (&create_tag_data->active, "");
            set_client_state (CLIENT_CREATE_TAG_ACTIVE);
          }
        else if (strcasecmp ("RESOURCES", element_name) == 0)
          {
            create_tag_data->resource_ids = make_array ();
            append_attribute (attribute_names, attribute_values, "filter",
                              &create_tag_data->resources_filter);
            set_client_state (CLIENT_CREATE_TAG_RESOURCES);
          }
        else if (strcasecmp ("COMMENT", element_name) == 0)
          {
            gvm_append_string (&create_tag_data->comment, "");
            set_client_state (CLIENT_CREATE_TAG_COMMENT);
          }
        else if (strcasecmp ("COPY", element_name) == 0)
          {
            gvm_append_string (&create_tag_data->copy, "");
            set_client_state (CLIENT_CREATE_TAG_COPY);
          }
        else if (strcasecmp ("NAME", element_name) == 0)
          {
            gvm_append_string (&create_tag_data->name, "");
            set_client_state (CLIENT_CREATE_TAG_NAME);
          }
        else if (strcasecmp ("VALUE", element_name) == 0)
          {
            gvm_append_string (&create_tag_data->value, "");
            set_client_state (CLIENT_CREATE_TAG_VALUE);
          }
        ELSE_READ_OVER;

      case CLIENT_CREATE_TAG_RESOURCES:
        if (strcasecmp ("RESOURCE", element_name) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values, "id",
                                &attribute))
              array_add (create_tag_data->resource_ids, g_strdup (attribute));
            set_client_state (CLIENT_CREATE_TAG_RESOURCES_RESOURCE);
          }
        else if (strcasecmp ("TYPE", element_name) == 0)
          {
            gvm_append_string (&create_tag_data->resource_type, "");
            set_client_state (CLIENT_CREATE_TAG_RESOURCES_TYPE);
          }
        ELSE_READ_OVER;

      case CLIENT_CREATE_TARGET:
        if (strcasecmp ("ASSET_HOSTS", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "filter",
                              &create_target_data->asset_hosts_filter);
            set_client_state (CLIENT_CREATE_TARGET_ASSET_HOSTS);
          }
        else if (strcasecmp ("EXCLUDE_HOSTS", element_name) == 0)
          set_client_state (CLIENT_CREATE_TARGET_EXCLUDE_HOSTS);
        else if (strcasecmp ("REVERSE_LOOKUP_ONLY", element_name) == 0)
          set_client_state (CLIENT_CREATE_TARGET_REVERSE_LOOKUP_ONLY);
        else if (strcasecmp ("REVERSE_LOOKUP_UNIFY", element_name) == 0)
          set_client_state (CLIENT_CREATE_TARGET_REVERSE_LOOKUP_UNIFY);
        else if (strcasecmp ("ALIVE_TESTS", element_name) == 0)
          set_client_state (CLIENT_CREATE_TARGET_ALIVE_TESTS);
        else if (strcasecmp ("ALLOW_SIMULTANEOUS_IPS", element_name) == 0)
          set_client_state (CLIENT_CREATE_TARGET_ALLOW_SIMULTANEOUS_IPS);
        else if (strcasecmp ("COMMENT", element_name) == 0)
          set_client_state (CLIENT_CREATE_TARGET_COMMENT);
        else if (strcasecmp ("COPY", element_name) == 0)
          set_client_state (CLIENT_CREATE_TARGET_COPY);
        else if (strcasecmp ("ESXI_CREDENTIAL", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "id",
                              &create_target_data->esxi_credential_id);
            set_client_state (CLIENT_CREATE_TARGET_ESXI_CREDENTIAL);
          }
        else if (strcasecmp ("ESXI_LSC_CREDENTIAL", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "id",
                              &create_target_data->esxi_lsc_credential_id);
            set_client_state (CLIENT_CREATE_TARGET_ESXI_LSC_CREDENTIAL);
          }
        else if (strcasecmp ("HOSTS", element_name) == 0)
          set_client_state (CLIENT_CREATE_TARGET_HOSTS);
        else if (strcasecmp ("PORT_LIST", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "id",
                              &create_target_data->port_list_id);
            set_client_state (CLIENT_CREATE_TARGET_PORT_LIST);
          }
        else if (strcasecmp ("PORT_RANGE", element_name) == 0)
          {
            gvm_append_string (&create_target_data->port_range, "");
            set_client_state (CLIENT_CREATE_TARGET_PORT_RANGE);
          }
        else if (strcasecmp ("SSH_CREDENTIAL", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "id",
                              &create_target_data->ssh_credential_id);
            set_client_state (CLIENT_CREATE_TARGET_SSH_CREDENTIAL);
          }
        else if (strcasecmp ("SSH_LSC_CREDENTIAL", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "id",
                              &create_target_data->ssh_lsc_credential_id);
            set_client_state (CLIENT_CREATE_TARGET_SSH_LSC_CREDENTIAL);
          }
        else if (strcasecmp ("SSH_ELEVATE_CREDENTIAL", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "id",
                              &create_target_data->ssh_elevate_credential_id);
            set_client_state (CLIENT_CREATE_TARGET_SSH_ELEVATE_CREDENTIAL);
          }
        else if (strcasecmp ("SMB_CREDENTIAL", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "id",
                              &create_target_data->smb_credential_id);
            set_client_state (CLIENT_CREATE_TARGET_SMB_CREDENTIAL);
          }
        else if (strcasecmp ("SMB_LSC_CREDENTIAL", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "id",
                              &create_target_data->smb_lsc_credential_id);
            set_client_state (CLIENT_CREATE_TARGET_SMB_LSC_CREDENTIAL);
          }
        else if (strcasecmp ("SNMP_CREDENTIAL", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "id",
                              &create_target_data->snmp_credential_id);
            set_client_state (CLIENT_CREATE_TARGET_SNMP_CREDENTIAL);
          }
        else if (strcasecmp ("NAME", element_name) == 0)
          {
            gvm_append_string (&create_target_data->name, "");
            set_client_state (CLIENT_CREATE_TARGET_NAME);
          }
        ELSE_READ_OVER;

      case CLIENT_CREATE_TARGET_SSH_CREDENTIAL:
        if (strcasecmp ("PORT", element_name) == 0)
          set_client_state (CLIENT_CREATE_TARGET_SSH_CREDENTIAL_PORT);
        ELSE_READ_OVER;

      case CLIENT_CREATE_TARGET_SSH_LSC_CREDENTIAL:
        if (strcasecmp ("PORT", element_name) == 0)
          set_client_state (CLIENT_CREATE_TARGET_SSH_LSC_CREDENTIAL_PORT);
        ELSE_READ_OVER;

      case CLIENT_CREATE_TASK:
        if (strcasecmp ("ALTERABLE", element_name) == 0)
          set_client_state (CLIENT_CREATE_TASK_ALTERABLE);
        else if (strcasecmp ("COPY", element_name) == 0)
          set_client_state (CLIENT_CREATE_TASK_COPY);
        else if (strcasecmp ("PREFERENCES", element_name) == 0)
          {
            create_task_data->preferences = make_array ();
            set_client_state (CLIENT_CREATE_TASK_PREFERENCES);
          }
        else if (strcasecmp ("NAME", element_name) == 0)
          set_client_state (CLIENT_CREATE_TASK_NAME);
        else if (strcasecmp ("COMMENT", element_name) == 0)
          set_client_state (CLIENT_CREATE_TASK_COMMENT);
        else if (strcasecmp ("HOSTS_ORDERING", element_name) == 0)
          set_client_state (CLIENT_CREATE_TASK_HOSTS_ORDERING);
        else if (strcasecmp ("SCANNER", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "id",
                              &create_task_data->scanner_id);
            set_client_state (CLIENT_CREATE_TASK_SCANNER);
          }
        else if (strcasecmp ("CONFIG", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "id",
                              &create_task_data->config_id);
            set_client_state (CLIENT_CREATE_TASK_CONFIG);
          }
        else if (strcasecmp ("ALERT", element_name) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values, "id",
                                &attribute))
              array_add (create_task_data->alerts, g_strdup (attribute));
            set_client_state (CLIENT_CREATE_TASK_ALERT);
          }
        else if (strcasecmp ("OBSERVERS", element_name) == 0)
          set_client_state (CLIENT_CREATE_TASK_OBSERVERS);
        else if (strcasecmp ("SCHEDULE", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "id",
                              &create_task_data->schedule_id);
            set_client_state (CLIENT_CREATE_TASK_SCHEDULE);
          }
        else if (strcasecmp ("SCHEDULE_PERIODS", element_name) == 0)
          set_client_state (CLIENT_CREATE_TASK_SCHEDULE_PERIODS);
        else if (strcasecmp ("TARGET", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "id",
                              &create_task_data->target_id);
            set_client_state (CLIENT_CREATE_TASK_TARGET);
          }
        else if (strcasecmp ("USAGE_TYPE", element_name) == 0)
          set_client_state (CLIENT_CREATE_TASK_USAGE_TYPE);
        ELSE_READ_OVER_CREATE_TASK;

      case CLIENT_CREATE_TASK_OBSERVERS:
        if (strcasecmp ("GROUP", element_name) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values, "id",
                                &attribute))
              array_add (create_task_data->groups, g_strdup (attribute));
            set_client_state (CLIENT_CREATE_TASK_OBSERVERS_GROUP);
          }
        ELSE_READ_OVER_CREATE_TASK;

      case CLIENT_CREATE_TASK_PREFERENCES:
        if (strcasecmp ("PREFERENCE", element_name) == 0)
          {
            assert (create_task_data->preference == NULL);
            create_task_data->preference = g_malloc (sizeof (name_value_t));
            create_task_data->preference->name = NULL;
            create_task_data->preference->value = NULL;
            set_client_state (CLIENT_CREATE_TASK_PREFERENCES_PREFERENCE);
          }
        ELSE_READ_OVER_CREATE_TASK;

      case CLIENT_CREATE_TASK_PREFERENCES_PREFERENCE:
        if (strcasecmp ("SCANNER_NAME", element_name) == 0)
          set_client_state (CLIENT_CREATE_TASK_PREFERENCES_PREFERENCE_NAME);
        else if (strcasecmp ("VALUE", element_name) == 0)
          set_client_state (CLIENT_CREATE_TASK_PREFERENCES_PREFERENCE_VALUE);
        ELSE_READ_OVER_CREATE_TASK;

      case CLIENT_CREATE_TICKET:
        create_ticket_element_start (gmp_parser, element_name,
                                     attribute_names,
                                     attribute_values);
        break;

      case CLIENT_CREATE_TLS_CERTIFICATE:
        create_tls_certificate_element_start (gmp_parser, element_name,
                                              attribute_names,
                                              attribute_values);
        break;

      case CLIENT_CREATE_USER:
        if (strcasecmp ("COMMENT", element_name) == 0)
          set_client_state (CLIENT_CREATE_USER_COMMENT);
        else if (strcasecmp ("COPY", element_name) == 0)
          set_client_state (CLIENT_CREATE_USER_COPY);
        else if (strcasecmp ("GROUPS", element_name) == 0)
          set_client_state (CLIENT_CREATE_USER_GROUPS);
        else if (strcasecmp ("HOSTS", element_name) == 0)
          {
            const gchar *attribute;
            if (find_attribute
                (attribute_names, attribute_values, "allow", &attribute))
              create_user_data->hosts_allow = strcmp (attribute, "0");
            else
              create_user_data->hosts_allow = 1;
            set_client_state (CLIENT_CREATE_USER_HOSTS);
          }
        else if (strcasecmp ("NAME", element_name) == 0)
          set_client_state (CLIENT_CREATE_USER_NAME);
        else if (strcasecmp ("PASSWORD", element_name) == 0)
          set_client_state (CLIENT_CREATE_USER_PASSWORD);
        else if (strcasecmp ("ROLE", element_name) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values, "id",
                                &attribute))
              array_add (create_user_data->roles, g_strdup (attribute));
            set_client_state (CLIENT_CREATE_USER_ROLE);
          }
        else if (strcasecmp ("SOURCES", element_name) == 0)
          {
            create_user_data->sources = make_array ();
            set_client_state (CLIENT_CREATE_USER_SOURCES);
          }
        else
          set_read_over (gmp_parser);
        break;

      case CLIENT_CREATE_USER_GROUPS:
        if (strcasecmp ("GROUP", element_name) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values, "id",
                                &attribute))
              array_add (create_user_data->groups, g_strdup (attribute));
            set_client_state (CLIENT_CREATE_USER_GROUPS_GROUP);
          }
        ELSE_READ_OVER;

      case CLIENT_CREATE_USER_SOURCES:
        if (strcasecmp ("SOURCE", element_name) == 0)
          set_client_state (CLIENT_CREATE_USER_SOURCES_SOURCE);
        else
          set_read_over (gmp_parser);
        break;

      case CLIENT_MODIFY_LICENSE:
        modify_license_element_start (gmp_parser, element_name,
                                      attribute_names, attribute_values);
        break;

      case CLIENT_MODIFY_NOTE:
        if (strcasecmp ("ACTIVE", element_name) == 0)
          set_client_state (CLIENT_MODIFY_NOTE_ACTIVE);
        else if (strcasecmp ("HOSTS", element_name) == 0)
          set_client_state (CLIENT_MODIFY_NOTE_HOSTS);
        else if (strcasecmp ("PORT", element_name) == 0)
          set_client_state (CLIENT_MODIFY_NOTE_PORT);
        else if (strcasecmp ("RESULT", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "id",
                              &modify_note_data->result_id);
            if (modify_note_data->result_id
                && modify_note_data->result_id[0] == '\0')
              {
                g_free (modify_note_data->result_id);
                modify_note_data->result_id = NULL;
              }
            set_client_state (CLIENT_MODIFY_NOTE_RESULT);
          }
        else if (strcasecmp ("SEVERITY", element_name) == 0)
          set_client_state (CLIENT_MODIFY_NOTE_SEVERITY);
        else if (strcasecmp ("TASK", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "id",
                              &modify_note_data->task_id);
            if (modify_note_data->task_id
                && modify_note_data->task_id[0] == '\0')
              {
                g_free (modify_note_data->task_id);
                modify_note_data->task_id = NULL;
              }
            set_client_state (CLIENT_MODIFY_NOTE_TASK);
          }
        else if (strcasecmp ("TEXT", element_name) == 0)
          set_client_state (CLIENT_MODIFY_NOTE_TEXT);
        else if (strcasecmp ("THREAT", element_name) == 0)
          set_client_state (CLIENT_MODIFY_NOTE_THREAT);
        else if (strcasecmp ("NVT", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "oid",
                              &modify_note_data->nvt_oid);
            set_client_state (CLIENT_MODIFY_NOTE_NVT);
          }
        ELSE_READ_OVER;

      case CLIENT_MODIFY_OVERRIDE:
        if (strcasecmp ("ACTIVE", element_name) == 0)
          set_client_state (CLIENT_MODIFY_OVERRIDE_ACTIVE);
        else if (strcasecmp ("HOSTS", element_name) == 0)
          set_client_state (CLIENT_MODIFY_OVERRIDE_HOSTS);
        else if (strcasecmp ("NEW_SEVERITY", element_name) == 0)
          set_client_state (CLIENT_MODIFY_OVERRIDE_NEW_SEVERITY);
        else if (strcasecmp ("NEW_THREAT", element_name) == 0)
          set_client_state (CLIENT_MODIFY_OVERRIDE_NEW_THREAT);
        else if (strcasecmp ("PORT", element_name) == 0)
          set_client_state (CLIENT_MODIFY_OVERRIDE_PORT);
        else if (strcasecmp ("RESULT", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "id",
                              &modify_override_data->result_id);
            if (modify_override_data->result_id
                && modify_override_data->result_id[0] == '\0')
              {
                g_free (modify_override_data->result_id);
                modify_override_data->result_id = NULL;
              }
            set_client_state (CLIENT_MODIFY_OVERRIDE_RESULT);
          }
        else if (strcasecmp ("SEVERITY", element_name) == 0)
          set_client_state (CLIENT_MODIFY_OVERRIDE_SEVERITY);
        else if (strcasecmp ("TASK", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "id",
                              &modify_override_data->task_id);
            if (modify_override_data->task_id
                && modify_override_data->task_id[0] == '\0')
              {
                g_free (modify_override_data->task_id);
                modify_override_data->task_id = NULL;
              }
            set_client_state (CLIENT_MODIFY_OVERRIDE_TASK);
          }
        else if (strcasecmp ("TEXT", element_name) == 0)
          set_client_state (CLIENT_MODIFY_OVERRIDE_TEXT);
        else if (strcasecmp ("THREAT", element_name) == 0)
          set_client_state (CLIENT_MODIFY_OVERRIDE_THREAT);
        else if (strcasecmp ("NVT", element_name) == 0)
          {
            append_attribute (attribute_names, attribute_values, "oid",
                              &modify_override_data->nvt_oid);
            set_client_state (CLIENT_MODIFY_OVERRIDE_NVT);
          }
        ELSE_READ_OVER;

      case CLIENT_RUN_WIZARD:
        if (strcasecmp ("MODE", element_name) == 0)
          {
            set_client_state (CLIENT_RUN_WIZARD_MODE);
          }
        else if (strcasecmp ("NAME", element_name) == 0)
          {
            set_client_state (CLIENT_RUN_WIZARD_NAME);
          }
        else if (strcasecmp ("PARAMS", element_name) == 0)
          {
            run_wizard_data->params = make_array ();
            set_client_state (CLIENT_RUN_WIZARD_PARAMS);
          }
        ELSE_READ_OVER;

      case CLIENT_RUN_WIZARD_PARAMS:
        if (strcasecmp ("PARAM", element_name) == 0)
          {
            assert (run_wizard_data->param == NULL);
            run_wizard_data->param = g_malloc (sizeof (name_value_t));
            run_wizard_data->param->name = NULL;
            run_wizard_data->param->value = NULL;
            set_client_state (CLIENT_RUN_WIZARD_PARAMS_PARAM);
          }
        ELSE_READ_OVER;

      case CLIENT_RUN_WIZARD_PARAMS_PARAM:
        if (strcasecmp ("NAME", element_name) == 0)
          {
            set_client_state (CLIENT_RUN_WIZARD_PARAMS_PARAM_NAME);
          }
        else if (strcasecmp ("VALUE", element_name) == 0)
          {
            set_client_state (CLIENT_RUN_WIZARD_PARAMS_PARAM_VALUE);
          }
        ELSE_READ_OVER;

      default:
        /* Read over this element. */
        set_read_over (gmp_parser);
        break;
    }

  return;
}

/**
 * @brief Send XML for an NVT.
 *
 * The caller must send the closing NVT tag.
 *
 * @param[in]  nvts        The NVT.
 * @param[in]  details     If true, detailed XML, else simple XML.
 * @param[in]  preferences If true, included preferences.
 * @param[in]  pref_count  Preference count.  Used if details is true.
 * @param[in]  timeout     Timeout.  Used if details is true.
 * @param[in]  config      Config, used if preferences is true.
 * @param[in]  write_to_client       Function to write to client.
 * @param[in]  write_to_client_data  Argument to \p write_to_client.
 *
 * @return TRUE if out of space in to_client buffer, else FALSE.
 */
static gboolean
send_nvt (iterator_t *nvts, int details, int preferences, int pref_count,
          const char *timeout, config_t config,
          int (*write_to_client) (const char *, void*),
          void* write_to_client_data)
{
  gchar *msg;

  msg = get_nvt_xml (nvts, details, pref_count, preferences, timeout, config,
                     0);
  if (send_to_client (msg, write_to_client, write_to_client_data))
    {
      g_free (msg);
      return TRUE;
    }
  g_free (msg);
  return FALSE;
}

/**
 * @brief Convert \n's to real newline's.
 *
 * @param[in]  text  The text in which to insert newlines.
 *
 * @return A newly allocated version of text.
 */
static gchar*
convert_to_newlines (const char *text)
{
  char *nptr, *new;

  new = g_malloc (strlen (text) + 1);
  nptr = new;
  while (*text)
    if (*text == '\\')
      {
         /* Convert "\\n" to '\n' */
         if (*(text+1) == 'n')
           {
             text += 2;
             *nptr++ = '\n';
           }
         /* Skip "\\r" */
         else if (*(text+1) == 'r')
           text += 2;
         else
           *nptr++ = *text++;
      }
    else
      *nptr++ = *text++;
  *nptr = '\0';

  return new;
}

/**
 * @brief Get substring of UTF8 string.
 *
 * @param[in]  str        String
 * @param[in]  start_pos  Start.
 * @param[in]  end_pos    End.
 *
 * @return Substring.
 */
static gchar *
utf8_substring (const gchar *str, glong start_pos, glong end_pos)
{
  gchar *start, *end, *out;

  /* TODO This is a copy of g_utf8_substring from glib 2.38.2.  Once our glib
   * minimum goes past 2.30 we can just use g_utf8_substring. */

  start = g_utf8_offset_to_pointer (str, start_pos);
  end = g_utf8_offset_to_pointer (start, end_pos - start_pos);

  out = g_malloc (end - start + 1);
  memcpy (out, start, end - start);
  out[end - start] = 0;

  return out;
}

/**
 * @brief Buffer XML for some notes.
 *
 * @param[in]  buffer                 Buffer into which to buffer notes.
 * @param[in]  notes                  Notes iterator.
 * @param[in]  include_notes_details  Whether to include details of notes.
 * @param[in]  include_result         Whether to include associated result.
 * @param[out] count                  Number of notes.
 */
static void
buffer_notes_xml (GString *buffer, iterator_t *notes, int include_notes_details,
                  int include_result, int *count)
{
  while (next (notes))
    {
      int tag_count;
      char *uuid_task, *uuid_result;

      tag_count = resource_tag_count ("note",
                                      get_iterator_resource (notes),
                                      1);

      if (count)
        (*count)++;

      if (note_iterator_task (notes))
        task_uuid (note_iterator_task (notes),
                   &uuid_task);
      else
        uuid_task = NULL;

      if (note_iterator_result (notes))
        result_uuid (note_iterator_result (notes),
                     &uuid_result);
      else
        uuid_result = NULL;

      buffer_xml_append_printf (buffer,
                                "<note id=\"%s\">"
                                "<permissions>",
                                get_iterator_uuid (notes));

      if (/* The user is the owner. */
          (current_credentials.username
           && get_iterator_owner_name (notes)
           && (strcmp (get_iterator_owner_name (notes),
                       current_credentials.username)
              == 0))
          /* Or the user is effectively the owner. */
          || acl_user_has_super (current_credentials.uuid,
                                 get_iterator_owner (notes)))
        buffer_xml_append_printf (buffer,
                                  "<permission><name>Everything</name></permission>"
                                  "</permissions>");
      else
        {
          iterator_t perms;
          get_data_t perms_get;

          memset (&perms_get, '\0', sizeof (perms_get));
          perms_get.filter = g_strdup_printf ("resource_uuid=%s"
                                              " owner=any"
                                              " permission=any",
                                              get_iterator_uuid (notes));
          init_permission_iterator (&perms, &perms_get);
          g_free (perms_get.filter);
          while (next (&perms))
            buffer_xml_append_printf (buffer,
                                      "<permission><name>%s</name></permission>",
                                      get_iterator_name (&perms));
          cleanup_iterator (&perms);

          buffer_xml_append_printf (buffer, "</permissions>");
        }

      if (include_notes_details == 0)
        {
          const char *text = note_iterator_text (notes);
          gchar *excerpt = utf8_substring (text, 0, 60);
          /* This must match send_get_common. */
          buffer_xml_append_printf (buffer,
                                    "<owner><name>%s</name></owner>"
                                    "<nvt oid=\"%s\">"
                                    "<name>%s</name>"
                                    "<type>%s</type>"
                                    "</nvt>"
                                    "<creation_time>%s</creation_time>"
                                    "<modification_time>%s</modification_time>"
                                    "<writable>1</writable>"
                                    "<in_use>0</in_use>"
                                    "<active>%i</active>"
                                    "<text excerpt=\"%i\">%s</text>"
                                    "<orphan>%i</orphan>",
                                    get_iterator_owner_name (notes)
                                     ? get_iterator_owner_name (notes)
                                     : "",
                                    note_iterator_nvt_oid (notes),
                                    note_iterator_nvt_name (notes),
                                    note_iterator_nvt_type (notes),
                                    get_iterator_creation_time (notes),
                                    get_iterator_modification_time (notes),
                                    note_iterator_active (notes),
                                    strlen (excerpt) < strlen (text),
                                    excerpt,
                                    ((note_iterator_task (notes)
                                      && (uuid_task == NULL))
                                     || (note_iterator_result (notes)
                                         && (uuid_result == NULL))));

          if (tag_count)
            {
              buffer_xml_append_printf (buffer,
                                        "<user_tags>"
                                        "<count>%i</count>"
                                        "</user_tags>",
                                        tag_count);
            }

          g_string_append (buffer, "</note>");

          g_free (excerpt);
        }
      else
        {
          char *name_task;
          int trash_task;
          time_t end_time;
          iterator_t tags;

          if (uuid_task)
            {
              name_task = task_name (note_iterator_task (notes));
              trash_task = task_in_trash (note_iterator_task (notes));
            }
          else
            {
              name_task = NULL;
              trash_task = 0;
            }

          end_time = note_iterator_end_time (notes);

          /* This must match send_get_common. */
          buffer_xml_append_printf
           (buffer,
            "<owner><name>%s</name></owner>"
            "<nvt oid=\"%s\">"
            "<name>%s</name>"
            "<type>%s</type>"
            "</nvt>"
            "<creation_time>%s</creation_time>"
            "<modification_time>%s</modification_time>"
            "<writable>1</writable>"
            "<in_use>0</in_use>"
            "<active>%i</active>"
            "<end_time>%s</end_time>"
            "<text>%s</text>"
            "<hosts>%s</hosts>"
            "<port>%s</port>"
            "<severity>%s</severity>"
            "<task id=\"%s\"><name>%s</name><trash>%i</trash></task>"
            "<orphan>%i</orphan>",
            get_iterator_owner_name (notes)
             ? get_iterator_owner_name (notes)
             : "",
            note_iterator_nvt_oid (notes),
            note_iterator_nvt_name (notes),
            note_iterator_nvt_type (notes),
            get_iterator_creation_time (notes),
            get_iterator_modification_time (notes),
            note_iterator_active (notes),
            end_time > 1 ? iso_time (&end_time) : "",
            note_iterator_text (notes),
            note_iterator_hosts (notes)
             ? note_iterator_hosts (notes) : "",
            note_iterator_port (notes)
             ? note_iterator_port (notes) : "",
            note_iterator_severity (notes)
             ? note_iterator_severity (notes) : "",
            uuid_task ? uuid_task : "",
            name_task ? name_task : "",
            trash_task,
            ((note_iterator_task (notes) && (uuid_task == NULL))
             || (note_iterator_result (notes) && (uuid_result == NULL))));

          free (name_task);

          if (include_result && uuid_result && note_iterator_result (notes))
            {
              iterator_t results;
              get_data_t *result_get;
              result_get = report_results_get_data (1, 1,
                                                    1, /* apply_overrides */
                                                    0  /* min_qod */);
              result_get->id = g_strdup (uuid_result);
              init_result_get_iterator (&results, result_get,
                                        0,     /* No report restriction */
                                        NULL,  /* No host restriction */
                                        NULL); /* No extra order SQL. */
              get_data_reset (result_get);
              free (result_get);

              while (next (&results))
                buffer_results_xml (buffer,
                                    &results,
                                    0,
                                    0,  /* Notes. */
                                    0,  /* Note details. */
                                    0,  /* Overrides. */
                                    0,  /* Override details. */
                                    0,  /* Tags. */
                                    0,  /* Tag details. */
                                    0,  /* Result details. */
                                    NULL,
                                    NULL,
                                    0,
                                    -1,
                                    0); /* Lean. */
              cleanup_iterator (&results);
            }
          else
            buffer_xml_append_printf (buffer,
                                      "<result id=\"%s\"/>",
                                      uuid_result ? uuid_result : "");
          if (tag_count)
            {
              buffer_xml_append_printf (buffer,
                                        "<user_tags>"
                                        "<count>%i</count>",
                                        tag_count);

              init_resource_tag_iterator (&tags, "note",
                                          get_iterator_resource (notes),
                                          1, NULL, 1);

              while (next (&tags))
                {
                  buffer_xml_append_printf 
                     (buffer,
                      "<tag id=\"%s\">"
                      "<name>%s</name>"
                      "<value>%s</value>"
                      "<comment>%s</comment>"
                      "</tag>",
                      resource_tag_iterator_uuid (&tags),
                      resource_tag_iterator_name (&tags),
                      resource_tag_iterator_value (&tags),
                      resource_tag_iterator_comment (&tags));
                }

              cleanup_iterator (&tags);

              g_string_append (buffer, "</user_tags>");
            }

          g_string_append (buffer, "</note>");
        }
      free (uuid_task);
      free (uuid_result);
    }
}

/**
 * @brief Buffer XML for some overrides.
 *
 * @param[in]  buffer                     Buffer into which to buffer overrides.
 * @param[in]  overrides                  Overrides iterator.
 * @param[in]  include_overrides_details  Whether to include details of overrides.
 * @param[in]  include_result             Whether to include associated result.
 * @param[out] count                      Number of overrides.
 */
static void
buffer_overrides_xml (GString *buffer, iterator_t *overrides,
                      int include_overrides_details, int include_result,
                      int *count)
{
  while (next (overrides))
    {
      int tag_count;
      char *uuid_task, *uuid_result;
      tag_count = resource_tag_count ("override",
                                      get_iterator_resource (overrides),
                                      1);

      if (count)
        (*count)++;

      if (override_iterator_task (overrides))
        task_uuid (override_iterator_task (overrides),
                   &uuid_task);
      else
        uuid_task = NULL;

      if (override_iterator_result (overrides))
        result_uuid (override_iterator_result (overrides),
                     &uuid_result);
      else
        uuid_result = NULL;

      buffer_xml_append_printf (buffer,
                                "<override id=\"%s\">"
                                "<permissions>",
                                get_iterator_uuid (overrides));

      if (/* The user is the owner. */
          (current_credentials.username
           && get_iterator_owner_name (overrides)
           && (strcmp (get_iterator_owner_name (overrides),
                       current_credentials.username)
              == 0))
          /* Or the user is effectively the owner. */
          || acl_user_has_super (current_credentials.uuid,
                                 get_iterator_owner (overrides)))
        buffer_xml_append_printf (buffer,
                                  "<permission><name>Everything</name></permission>"
                                  "</permissions>");
      else
        {
          iterator_t perms;
          get_data_t perms_get;

          memset (&perms_get, '\0', sizeof (perms_get));
          perms_get.filter = g_strdup_printf ("resource_uuid=%s"
                                              " owner=any"
                                              " permission=any",
                                              get_iterator_uuid (overrides));
          init_permission_iterator (&perms, &perms_get);
          g_free (perms_get.filter);
          while (next (&perms))
            buffer_xml_append_printf (buffer,
                                      "<permission><name>%s</name></permission>",
                                      get_iterator_name (&perms));
          cleanup_iterator (&perms);

          buffer_xml_append_printf (buffer, "</permissions>");
        }

      if (include_overrides_details == 0)
        {
          const char *text = override_iterator_text (overrides);
          gchar *excerpt = utf8_substring (text, 0, 60);
          /* This must match send_get_common. */
          buffer_xml_append_printf (buffer,
                                    "<owner><name>%s</name></owner>"
                                    "<nvt oid=\"%s\">"
                                    "<name>%s</name>"
                                    "<type>%s</type>"
                                    "</nvt>"
                                    "<creation_time>%s</creation_time>"
                                    "<modification_time>%s</modification_time>"
                                    "<writable>1</writable>"
                                    "<in_use>0</in_use>"
                                    "<active>%i</active>"
                                    "<text excerpt=\"%i\">%s</text>"
                                    "<threat>%s</threat>"
                                    "<severity>%s</severity>"
                                    "<new_threat>%s</new_threat>"
                                    "<new_severity>%s</new_severity>"
                                    "<orphan>%i</orphan>",
                                    get_iterator_owner_name (overrides)
                                     ? get_iterator_owner_name (overrides)
                                     : "",
                                    override_iterator_nvt_oid (overrides),
                                    override_iterator_nvt_name (overrides),
                                    override_iterator_nvt_type (overrides),
                                    get_iterator_creation_time (overrides),
                                    get_iterator_modification_time (overrides),
                                    override_iterator_active (overrides),
                                    strlen (excerpt) < strlen (text),
                                    excerpt,
                                    override_iterator_threat (overrides)
                                     ? override_iterator_threat (overrides)
                                     : "",
                                    override_iterator_severity (overrides)
                                     ? override_iterator_severity (overrides)
                                     : "",
                                    override_iterator_new_threat (overrides),
                                    override_iterator_new_severity (overrides),
                                    ((override_iterator_task (overrides)
                                      && (uuid_task == NULL))
                                     || (override_iterator_result (overrides)
                                         && (uuid_result == NULL))));

          if (tag_count)
            {
              buffer_xml_append_printf (buffer,
                                        "<user_tags>"
                                        "<count>%i</count>"
                                        "</user_tags>",
                                        tag_count);
            }

          g_string_append (buffer, "</override>");

          g_free (excerpt);
        }
      else
        {
          char *name_task;
          int trash_task;
          time_t end_time;
          iterator_t tags;

          if (uuid_task)
            {
              name_task = task_name (override_iterator_task (overrides));
              trash_task = task_in_trash (override_iterator_task (overrides));
            }
          else
            {
              name_task = NULL;
              trash_task = 0;
            }

          end_time = override_iterator_end_time (overrides);

          /* This must match send_get_common. */
          buffer_xml_append_printf
           (buffer,
            "<owner><name>%s</name></owner>"
            "<nvt oid=\"%s\">"
            "<name>%s</name>"
            "<type>%s</type>"
            "</nvt>"
            "<creation_time>%s</creation_time>"
            "<modification_time>%s</modification_time>"
            "<writable>1</writable>"
            "<in_use>0</in_use>"
            "<active>%i</active>"
            "<end_time>%s</end_time>"
            "<text>%s</text>"
            "<hosts>%s</hosts>"
            "<port>%s</port>"
            "<threat>%s</threat>"
            "<severity>%s</severity>"
            "<new_threat>%s</new_threat>"
            "<new_severity>%s</new_severity>"
            "<task id=\"%s\"><name>%s</name><trash>%i</trash></task>"
            "<orphan>%i</orphan>",
            get_iterator_owner_name (overrides)
             ? get_iterator_owner_name (overrides)
             : "",
            override_iterator_nvt_oid (overrides),
            override_iterator_nvt_name (overrides),
            override_iterator_nvt_type (overrides),
            get_iterator_creation_time (overrides),
            get_iterator_modification_time (overrides),
            override_iterator_active (overrides),
            end_time > 1 ? iso_time (&end_time) : "",
            override_iterator_text (overrides),
            override_iterator_hosts (overrides)
             ? override_iterator_hosts (overrides) : "",
            override_iterator_port (overrides)
             ? override_iterator_port (overrides) : "",
            override_iterator_threat (overrides)
             ? override_iterator_threat (overrides) : "",
            override_iterator_severity (overrides)
             ? override_iterator_severity (overrides) : "",
            override_iterator_new_threat (overrides),
            override_iterator_new_severity (overrides),
            uuid_task ? uuid_task : "",
            name_task ? name_task : "",
            trash_task,
            ((override_iterator_task (overrides) && (uuid_task == NULL))
             || (override_iterator_result (overrides) && (uuid_result == NULL))));

          free (name_task);

          if (include_result && uuid_result
              && override_iterator_result (overrides))
            {
              iterator_t results;
              get_data_t *result_get;
              result_get = report_results_get_data (1, 1,
                                                    1, /* apply_overrides */
                                                    0  /* min_qod */);
              result_get->id = g_strdup (uuid_result);
              init_result_get_iterator (&results, result_get,
                                        0,  /* No report restriction */
                                        NULL, /* No host restriction */
                                        NULL);  /* No extra order SQL. */
              get_data_reset (result_get);
              free (result_get);

              while (next (&results))
                buffer_results_xml (buffer,
                                    &results,
                                    0,
                                    0,  /* Overrides. */
                                    0,  /* Override details. */
                                    0,  /* Overrides. */
                                    0,  /* Override details. */
                                    0,  /* Tags. */
                                    0,  /* Tag details. */
                                    0,  /* Result details. */
                                    NULL,
                                    NULL,
                                    0,
                                    -1,
                                    0); /* Lean. */
              cleanup_iterator (&results);
            }
          else
            buffer_xml_append_printf (buffer,
                                      "<result id=\"%s\"/>",
                                      uuid_result ? uuid_result : "");

          if (tag_count)
            {
              buffer_xml_append_printf (buffer,
                                        "<user_tags>"
                                        "<count>%i</count>",
                                        tag_count);

              init_resource_tag_iterator (&tags, "override",
                                          get_iterator_resource (overrides),
                                          1, NULL, 1);

              while (next (&tags))
                {
                  buffer_xml_append_printf 
                     (buffer,
                      "<tag id=\"%s\">"
                      "<name>%s</name>"
                      "<value>%s</value>"
                      "<comment>%s</comment>"
                      "</tag>",
                      resource_tag_iterator_uuid (&tags),
                      resource_tag_iterator_name (&tags),
                      resource_tag_iterator_value (&tags),
                      resource_tag_iterator_comment (&tags));
                }

              cleanup_iterator (&tags);

              g_string_append (buffer, "</user_tags>");
            }

          g_string_append (buffer, "</override>");
        }
      free (uuid_task);
      free (uuid_result);
    }
}

/* External for manage.c. */
/**
 * @brief Buffer XML for the NVT preference of a config.
 *
 * @param[in]  buffer  Buffer.
 * @param[in]  prefs   NVT preference iterator.
 * @param[in]  config  Config.
 * @param[in]  hide_passwords  Whether to hide passwords.
 */
void
buffer_config_preference_xml (GString *buffer, iterator_t *prefs,
                              config_t config, int hide_passwords)
{
  char *real_name, *type, *value, *oid, *id, *nvt = NULL;
  const char *default_value;

  oid = nvt_preference_iterator_oid (prefs);
  type = nvt_preference_iterator_type (prefs);
  real_name = nvt_preference_iterator_real_name (prefs);
  default_value = nvt_preference_iterator_value (prefs);
  value = nvt_preference_iterator_config_value (prefs, config);
  id = nvt_preference_iterator_id (prefs);

  if (oid)
    nvt = nvt_name (oid);
  buffer_xml_append_printf (buffer,
                            "<preference>"
                            "<nvt oid=\"%s\"><name>%s</name></nvt>"
                            "<id>%s</id>"
                            "<hr_name>%s</hr_name>"
                            "<name>%s</name>"
                            "<type>%s</type>",
                            oid ? oid : "",
                            nvt ? nvt : "",
                            id ? id : "",
                            real_name ? real_name : "",
                            real_name ? real_name : "",
                            type ? type : "");

  if (value
      && type
      && (strcmp (type, "radio") == 0))
    {
      /* Handle the other possible values. */
      char *pos = strchr (value, ';');
      if (pos) *pos = '\0';
      buffer_xml_append_printf (buffer, "<value>%s</value>", value);
    }
  else if (value
           && type
           && hide_passwords
           && (strcmp (type, "password") == 0))
    buffer_xml_append_printf (buffer, "<value></value>");
  else
    buffer_xml_append_printf (buffer, "<value>%s</value>", value ? value : "");

  if (default_value
      && type
      && (strcmp (type, "radio") == 0))
    {
      char *pos;
      gchar *alts;

      /* Handle the other possible values. */

      alts = g_strdup (default_value);

      pos = strchr (default_value, ';');
      if (pos) *pos = '\0';
      buffer_xml_append_printf (buffer, "<default>%s</default>", default_value);

      pos = alts;
      while (1)
        {
          char *pos2 = strchr (pos, ';');
          if (pos2) *pos2 = '\0';
          if (value == NULL || strcmp (pos, value))
            buffer_xml_append_printf (buffer, "<alt>%s</alt>", pos);
          if (pos2 == NULL)
            break;
          pos = pos2 + 1;
        }
      g_free (alts);
    }
  else if (default_value
           && type
           && (strcmp (type, "password") == 0))
    buffer_xml_append_printf (buffer, "<default></default>");
  else
    buffer_xml_append_printf (buffer, "<default>%s</default>", default_value
                                                               ? default_value
                                                               : "");

  buffer_xml_append_printf (buffer, "</preference>");

  g_free (real_name);
  g_free (type);
  g_free (value);
  g_free (nvt);
  g_free (oid);
}

/**
 * @brief Compare two string with the "diff" command.
 *
 * @param[in]  one     First string.
 * @param[in]  two     Second string.
 *
 * @return Output of "diff", or NULL on error.
 */
static gchar *
strdiff (const gchar *one, const gchar *two)
{
  gchar **cmd, *ret, *one_file, *two_file, *old_lc_all, *old_language;
  gint exit_status;
  gchar *standard_out = NULL;
  gchar *standard_err = NULL;
  char dir[] = "/tmp/gvmd-strdiff-XXXXXX";
  GError *error = NULL;
  gchar *c_one, *c_two;

  if (mkdtemp (dir) == NULL)
    return NULL;

  one_file = g_build_filename (dir, "Report 1", NULL);

  c_one = g_strdup_printf ("%s\n", one);

  g_file_set_contents (one_file, c_one, strlen (c_one), &error);

  g_free (c_one);

  if (error)
    {
      g_warning ("%s", error->message);
      g_error_free (error);
      gvm_file_remove_recurse (dir);
      g_free (one_file);
      return NULL;
    }

  two_file = g_build_filename (dir, "Report 2", NULL);

  c_two = g_strdup_printf ("%s\n", two);

  g_file_set_contents (two_file, c_two, strlen (c_two), &error);

  g_free (c_two);

  if (error)
    {
      g_warning ("%s", error->message);
      g_error_free (error);
      gvm_file_remove_recurse (dir);
      g_free (one_file);
      g_free (two_file);
      return NULL;
    }

  old_lc_all = getenv ("LC_ALL") ? g_strdup (getenv ("LC_ALL")) : NULL;
  if (setenv ("LC_ALL", "C", 1) == -1)
    {
      g_warning ("%s: failed to set LC_ALL", __func__);
      return NULL;
    }

  old_language = getenv ("LANGUAGE") ? g_strdup (getenv ("LANGUAGE")) : NULL;
  if (setenv ("LANGUAGE", "C", 1) == -1)
    {
      g_warning ("%s: failed to set LANGUAGE", __func__);
      return NULL;
    }

  cmd = (gchar **) g_malloc (7 * sizeof (gchar *));

  cmd[0] = g_strdup ("diff");
  cmd[1] = g_strdup ("--ignore-all-space");
  cmd[2] = g_strdup ("--ignore-blank-lines");
  cmd[3] = g_strdup ("-u");
  cmd[4] = g_strdup ("Report 1");
  cmd[5] = g_strdup ("Report 2");
  cmd[6] = NULL;
  g_debug ("%s: Spawning in %s: %s \"%s\" \"%s\"",
           __func__, dir,
           cmd[0], cmd[1], cmd[2]);
  if ((g_spawn_sync (dir,
                     cmd,
                     NULL,                 /* Environment. */
                     G_SPAWN_SEARCH_PATH,
                     NULL,                 /* Setup func. */
                     NULL,
                     &standard_out,
                     &standard_err,
                     &exit_status,
                     NULL) == FALSE)
      || (WIFEXITED (exit_status) == 0)
      || WEXITSTATUS (exit_status))
    {
      if (WEXITSTATUS (exit_status) == 1)
        ret = standard_out;
      else
        {
          g_debug ("%s: failed to run diff: %d (WIF %i, WEX %i)",
                   __func__,
                   exit_status,
                   WIFEXITED (exit_status),
                   WEXITSTATUS (exit_status));
          g_debug ("%s: stdout: %s", __func__, standard_out);
          g_debug ("%s: stderr: %s", __func__, standard_err);
          ret = NULL;
          g_free (standard_out);
        }
    }
  else
    ret = standard_out;

  if (old_lc_all && (setenv ("LC_ALL", old_lc_all, 1) == -1))
    {
      g_warning ("%s: failed to reset LC_ALL", __func__);
      ret = NULL;
    }
  else if (old_language && (setenv ("LANGUAGE", old_language, 1) == -1))
    {
      g_warning ("%s: failed to reset LANGUAGE", __func__);
      ret = NULL;
    }

  g_free (old_lc_all);
  g_free (old_language);
  g_free (cmd[0]);
  g_free (cmd[1]);
  g_free (cmd[2]);
  g_free (cmd[3]);
  g_free (cmd[4]);
  g_free (cmd[5]);
  g_free (cmd);
  g_free (standard_err);
  g_free (one_file);
  g_free (two_file);
  gvm_file_remove_recurse (dir);

  return ret;
}

/**
 * @brief Buffer XML for notes of a result.
 *
 * @param[in]  buffer                 Buffer into which to buffer results.
 * @param[in]  result                 Result.
 * @param[in]  task                   Task associated with result.
 * @param[in]  include_notes_details  Whether to include details of notes.
 * @param[in]  lean                   Whether to include less info.
 */
static void
buffer_result_notes_xml (GString *buffer, result_t result, task_t task,
                         int include_notes_details, int lean)
{
  if (task)
    {
      get_data_t get;
      iterator_t notes;
      GString *temp_buffer;

      memset (&get, '\0', sizeof (get));
      /* Most recent first. */
      get.filter = "sort-reverse=created owner=any permission=any";

      if (note_count (&get, 0, result, task) == 0)
        return;

      init_note_iterator (&notes,
                          &get,
                          0,
                          result,
                          task);

      temp_buffer = g_string_new ("");
      buffer_notes_xml (temp_buffer,
                        &notes,
                        include_notes_details,
                        0,
                        NULL);

      if (lean == 0 || strlen (temp_buffer->str))
        {
          g_string_append (buffer, "<notes>");
          g_string_append (buffer, temp_buffer->str);
          g_string_append (buffer, "</notes>");
        }
      g_string_free (temp_buffer, TRUE);

      cleanup_iterator (&notes);
    }
}

/**
 * @brief Buffer XML for overrides of a result.
 *
 * @param[in]  buffer                 Buffer into which to buffer results.
 * @param[in]  result                 Result.
 * @param[in]  task                   Task associated with result.
 * @param[in]  include_overrides_details  Whether to include details of overrides.
 * @param[in]  lean                       Whether to include less info.
 */
static void
buffer_result_overrides_xml (GString *buffer, result_t result, task_t task,
                             int include_overrides_details, int lean)
{
  if (task)
    {
      get_data_t get;
      iterator_t overrides;
      GString *temp_buffer;

      memset (&get, '\0', sizeof (get));
      /* Most recent first. */
      get.filter = "sort-reverse=created owner=any permission=any";

      if (override_count (&get, 0, result, task) == 0)
        return;

      init_override_iterator (&overrides,
                              &get,
                              0,
                              result,
                              task);

      temp_buffer = g_string_new ("");
      buffer_overrides_xml (temp_buffer,
                            &overrides,
                            include_overrides_details,
                            0,
                            NULL);
      if (lean == 0 || strlen (temp_buffer->str))
        {
          g_string_append (buffer, "<overrides>");
          g_string_append (buffer, temp_buffer->str);
          g_string_append (buffer, "</overrides>");
        }
      g_string_free (temp_buffer, TRUE);

      cleanup_iterator (&overrides);
    }
}

/**
 * @brief Add a detail block to a XML buffer.
 *
 * @param[in]  buffer  Buffer.
 * @param[in]  name    Name.
 * @param[in]  value   Value.
 */
static void
add_detail (GString *buffer, const gchar *name, const gchar *value)
{
  buffer_xml_append_printf (buffer,
                            "<detail>"
                            "<name>%s</name>"
                            "<value>%s</value>"
                            "</detail>",
                            name,
                            value);
}

/**
 * @brief Append a REFS element to an XML buffer.
 *
 * @param[in]  buffer       Buffer.
 * @param[in]  results      Result iterator.
 * @param[in]  oid          OID.
 * @param[in]  cert_loaded     Whether CERT db is loaded.
 * @param[in]  first           Marker for first element.
 */
static void
results_xml_append_cert (GString *buffer, iterator_t *results, const char *oid,
                         int cert_loaded, int *first)
{
  if (cert_loaded)
    {
      gchar **cert_bunds, **dfn_certs;

      cert_bunds = result_iterator_cert_bunds (results);
      if (cert_bunds)
        {
          gchar **point;

          point = cert_bunds;
          while (*point)
            {
              if (first && *first)
                {
                  buffer_xml_append_printf (buffer, "<refs>");
                  *first = 0;
                }
              g_string_append_printf
               (buffer, "<ref type=\"cert-bund\" id=\"%s\"/>", *point);

              point++;
            }
          g_strfreev (cert_bunds);
        }

      dfn_certs = result_iterator_dfn_certs (results);
      if (dfn_certs)
        {
          gchar **point;

          point = dfn_certs;
          while (*point)
            {
              if (first && *first)
                {
                  buffer_xml_append_printf (buffer, "<refs>");
                  *first = 0;
                }
              g_string_append_printf
               (buffer, "<ref type=\"dfn-cert\" id=\"%s\"/>", *point);

              point++;
            }
          g_strfreev (dfn_certs);
        }
    }
  else
    {
      if (*first)
        {
          buffer_xml_append_printf (buffer, "<refs>");
          *first = 0;
        }
      g_string_append_printf (buffer,
                              "<warning>database not available</warning>");
    }
}

/**
 * @brief Append an NVT element to an XML buffer.
 *
 * @param[in]  results  Results.
 * @param[in]  buffer   Buffer.
 * @param[in]  cert_loaded  Whether CERT db is loaded.
 */
static void
results_xml_append_nvt (iterator_t *results, GString *buffer, int cert_loaded)
{
  const char *oid = result_iterator_nvt_oid (results);

  assert (results);
  assert (buffer);

  if (oid)
    {
      if (g_str_has_prefix (oid, "CVE-"))
        {
          gchar *severity;

          severity = cve_cvss_base (oid);
          buffer_xml_append_printf (buffer,
                                    "<nvt oid=\"%s\">"
                                    "<type>cve</type>"
                                    "<name>%s</name>"
                                    "<cvss_base>%s</cvss_base>"
                                    "<severities score=\"%s\">"
                                    "</severities>"
                                    "<cpe id='%s'/>"
                                    "<cve>%s</cve>"
                                    "</nvt>",
                                    oid,
                                    oid,
                                    severity ? severity : "",
                                    severity ? severity : "",
                                    result_iterator_port (results),
                                    oid);
          g_free (severity);
          return;
        }

      {
        const char *cvss_base = result_iterator_nvt_cvss_base (results);
        GString *tags = g_string_new (result_iterator_nvt_tag (results));
        int first;
        iterator_t severities;

        if (!cvss_base && !strcmp (oid, "0"))
          cvss_base = "0.0";

        /* Add the elements that are expected as part of the pipe-separated
         * tag list via API although internally already explicitly stored.
         * Once the API is extended to have these elements explicitly, they
         * do not need to be added to this tag string anymore. */
        if (result_iterator_nvt_summary (results))
          {
            if (tags->str)
              g_string_append_printf (tags, "|summary=%s",
                                      result_iterator_nvt_summary (results));
            else
              g_string_append_printf (tags, "summary=%s",
                                      result_iterator_nvt_summary (results));
          }
        if (result_iterator_nvt_insight (results))
          {
            if (tags->str)
              g_string_append_printf (tags, "|insight=%s",
                                      result_iterator_nvt_insight (results));
            else
              g_string_append_printf (tags, "insight=%s",
                                        result_iterator_nvt_insight (results));
          }
        if (result_iterator_nvt_affected (results))
          {
            if (tags->str)
              g_string_append_printf (tags, "|affected=%s",
                                      result_iterator_nvt_affected (results));
            else
              g_string_append_printf (tags, "affected=%s",
                                      result_iterator_nvt_affected (results));
          }
        if (result_iterator_nvt_impact (results))
          {
            if (tags->str)
              g_string_append_printf (tags, "|impact=%s",
                                      result_iterator_nvt_impact (results));
            else
              g_string_append_printf (tags, "impact=%s",
                                      result_iterator_nvt_impact (results));
          }
        if (result_iterator_nvt_solution (results))
          {
            if (tags->str)
              g_string_append_printf (tags, "|solution=%s",
                                      result_iterator_nvt_solution (results));
            else
              g_string_append_printf (tags, "solution=%s",
                                      result_iterator_nvt_solution (results));
          }
        if (result_iterator_nvt_detection (results))
          {
            if (tags->str)
              g_string_append_printf (tags, "|vuldetect=%s",
                                      result_iterator_nvt_detection (results));
            else
              g_string_append_printf (tags, "vuldetect=%s",
                                      result_iterator_nvt_detection (results));
          }
        if (result_iterator_nvt_solution_type (results))
          {
            if (tags->str)
              g_string_append_printf (tags, "|solution_type=%s",
                                      result_iterator_nvt_solution_type (results));
            else
              g_string_append_printf (tags, "solution_type=%s",
                                      result_iterator_nvt_solution_type (results));
          }

        buffer_xml_append_printf (buffer,
                                  "<nvt oid=\"%s\">"
                                  "<type>nvt</type>"
                                  "<name>%s</name>"
                                  "<family>%s</family>"
                                  "<cvss_base>%s</cvss_base>"
                                  "<severities score=\"%s\">",
                                  oid,
                                  result_iterator_nvt_name (results) ?: oid,
                                  result_iterator_nvt_family (results) ?: "",
                                  cvss_base ?: "",
                                  cvss_base ?: "");

        init_nvt_severity_iterator (&severities, oid);
        while (next (&severities))
          {
            buffer_xml_append_printf
                (buffer,
                 "<severity type=\"%s\">"
                 "<origin>%s</origin>"
                 "<date>%s</date>"
                 "<score>%0.1f</score>"
                 "<value>%s</value>"
                 "</severity>",
                 nvt_severity_iterator_type (&severities),
                 nvt_severity_iterator_origin (&severities),
                 nvt_severity_iterator_date (&severities),
                 nvt_severity_iterator_score (&severities),
                 nvt_severity_iterator_value (&severities));
          }
        cleanup_iterator (&severities);

        buffer_xml_append_printf (buffer,
                                  "</severities>"
                                  "<tags>%s</tags>",
                                  tags->str ?: "");

        if (result_iterator_nvt_solution (results)
            || result_iterator_nvt_solution_type (results)
            || result_iterator_nvt_solution_method (results))
          {
            buffer_xml_append_printf (buffer, "<solution");

            if (result_iterator_nvt_solution_type (results))
              buffer_xml_append_printf (buffer, " type='%s'",
                result_iterator_nvt_solution_type (results));

            if (result_iterator_nvt_solution_method (results))
              buffer_xml_append_printf (buffer, " method='%s'",
                result_iterator_nvt_solution_method (results));

            if (result_iterator_nvt_solution (results))
              buffer_xml_append_printf (buffer, ">%s</solution>",
                                        result_iterator_nvt_solution (results));
            else
              buffer_xml_append_printf (buffer, "/>");
          }

        first = 1;
        xml_append_nvt_refs (buffer, result_iterator_nvt_oid (results),
                             &first);

        results_xml_append_cert (buffer, results, oid, cert_loaded, &first);
        if (first == 0)
          buffer_xml_append_printf (buffer, "</refs>");

        g_string_free (tags, TRUE);
      }
    }

  buffer_xml_append_printf (buffer, "</nvt>");
}

/** @todo Exported for manage_sql.c. */
/**
 * @brief Buffer XML for some results.
 *
 * Includes cert_loaded arg.
 *
 * @param[in]  buffer                 Buffer into which to buffer results.
 * @param[in]  results                Result iterator.
 * @param[in]  task                   Task associated with results.  Only
 *                                    needed with include_notes or
 *                                    include_overrides.
 * @param[in]  include_notes          Whether to include notes.
 * @param[in]  include_notes_details  Whether to include details of notes.
 * @param[in]  include_overrides          Whether to include overrides.
 * @param[in]  include_overrides_details  Whether to include details of overrides.
 * @param[in]  include_tags           Whether to include user tag count.
 * @param[in]  include_tags_details   Whether to include details of tags.
 * @param[in]  include_details        Whether to include details of the result.
 * @param[in]  delta_state            Delta state of result, or NULL.
 * @param[in]  delta_results          Iterator for delta result to include, or
 *                                    NULL.
 * @param[in]  changed                Whether the result is a "changed" delta.
 * @param[in]  cert_loaded            Whether the CERT db is loaded.  0 not loaded,
 *                                    -1 needs to be checked, else loaded.
 * @param[in]  lean                   Whether to include less info.
 */
void
buffer_results_xml (GString *buffer, iterator_t *results, task_t task,
                    int include_notes, int include_notes_details,
                    int include_overrides, int include_overrides_details,
                    int include_tags, int include_tags_details,
                    int include_details,
                    const char *delta_state, iterator_t *delta_results,
                    int changed, int cert_loaded, int lean)
{
  const char *descr = result_iterator_descr (results);
  const char *name, *comment, *creation_time;
  const char *port, *path;
  const char *asset_id;
  gchar *nl_descr, *nl_descr_escaped;
  const char *qod = result_iterator_qod (results);
  const char *qod_type = result_iterator_qod_type (results);
  result_t result = result_iterator_result (results);
  char *detect_oid, *detect_ref, *detect_cpe, *detect_loc, *detect_name;
  task_t selected_task;

  if (descr)
    {
      nl_descr = convert_to_newlines (descr);
      nl_descr_escaped = xml_escape_text_truncated (nl_descr,
                                                    TRUNCATE_TEXT_LENGTH,
                                                    TRUNCATE_TEXT_SUFFIX);
    }
  else
    {
      nl_descr = NULL;
      nl_descr_escaped = NULL;
    }

  buffer_xml_append_printf (buffer,
                            "<result id=\"%s\">",
                            get_iterator_uuid (results));

  selected_task = task;

  name = get_iterator_name (results);
  if (name)
    buffer_xml_append_printf (buffer,
                              "<name>%s</name>",
                              name);

  if (lean == 0)
    {
      const char *owner_name, *modification_time;

      owner_name = get_iterator_owner_name (results);
      if (owner_name)
        buffer_xml_append_printf (buffer,
                                  "<owner><name>%s</name></owner>",
                                  owner_name);

      modification_time = get_iterator_modification_time (results);
      if (modification_time)
        buffer_xml_append_printf (buffer,
                                  "<modification_time>%s</modification_time>",
                                  modification_time);
    }

  comment = get_iterator_comment (results);
  if (comment
      && (lean == 0 || strlen (comment)))
    buffer_xml_append_printf (buffer,
                              "<comment>%s</comment>",
                              comment);

  creation_time = get_iterator_creation_time (results);
  if (creation_time)
    buffer_xml_append_printf (buffer,
                              "<creation_time>%s</creation_time>",
                              creation_time);

  if (include_details)
    {
      char *result_report_id, *result_task_id, *result_task_name;

      if (task == 0)
        selected_task = result_iterator_task (results);

      task_uuid (selected_task, &result_task_id);
      result_task_name = task_name (result_iterator_task (results));
      result_report_id = report_uuid (result_iterator_report (results));

      buffer_xml_append_printf (buffer,
                                "<report id=\"%s\"/>"
                                "<task id=\"%s\"><name>%s</name></task>",
                                result_report_id,
                                result_task_id,
                                result_task_name);

      free (result_report_id);
      free (result_task_id);
      free (result_task_name);
    }

  if (include_tags)
    {
      if (resource_tag_exists ("result", result, 1))
        {
          buffer_xml_append_printf (buffer,
                                    "<user_tags>"
                                    "<count>%i</count>",
                                    resource_tag_count ("result", result, 1));

          if (include_tags_details)
            {
              iterator_t tags;

              init_resource_tag_iterator (&tags, "result", result, 1, NULL, 1);

              while (next (&tags))
                {
                  buffer_xml_append_printf 
                     (buffer,
                      "<tag id=\"%s\">"
                      "<name>%s</name>"
                      "<value>%s</value>"
                      "<comment>%s</comment>"
                      "</tag>",
                      resource_tag_iterator_uuid (&tags),
                      resource_tag_iterator_name (&tags),
                      resource_tag_iterator_value (&tags),
                      resource_tag_iterator_comment (&tags));
                }

              cleanup_iterator (&tags);
            }

          buffer_xml_append_printf (buffer, "</user_tags>");
        }
    }

  port = result_iterator_port (results);
  path = result_iterator_path (results);

  detect_oid = detect_ref = detect_cpe = detect_loc = detect_name = NULL;
  if (result_detection_reference (result, result_iterator_report (results),
                                  result_iterator_host (results), port, path,
                                  &detect_oid, &detect_ref, &detect_cpe,
                                  &detect_loc, &detect_name)
      == 0)
    {
      buffer_xml_append_printf (buffer,
                                "<detection>"
                                "<result id=\"%s\">"
                                "<details>",
                                detect_ref);

      add_detail (buffer, "product", detect_cpe);
      add_detail (buffer, "location", detect_loc);
      add_detail (buffer, "source_oid", detect_oid);
      add_detail (buffer, "source_name", detect_name);

      buffer_xml_append_printf (buffer,
                                "</details>"
                                "</result>"
                                "</detection>");
    }
  g_free (detect_ref);
  g_free (detect_cpe);
  g_free (detect_loc);
  g_free (detect_name);

  if (result_iterator_host (results))
    asset_id = result_iterator_asset_host_id (results);
  else
    asset_id = NULL;

  buffer_xml_append_printf (buffer,
                            "<host>"
                            "%s",
                            result_iterator_host (results) ?: "");

  if (asset_id && strlen (asset_id))
    buffer_xml_append_printf (buffer,
                              "<asset asset_id=\"%s\"/>",
                              asset_id);
  else if (lean == 0)
    buffer_xml_append_printf (buffer,
                              "<asset asset_id=\"\"/>");

  buffer_xml_append_printf (buffer,
                            "<hostname>%s</hostname>"
                            "</host>",
                            result_iterator_hostname (results) ?: "");

  buffer_xml_append_printf (buffer,
                            "<port>%s</port>",
                            port);

  if (path && strcmp (path, ""))
    buffer_xml_append_printf (buffer,
                              "<path>%s</path>",
                              path);

  if (cert_loaded == -1)
    cert_loaded = manage_cert_loaded ();
  results_xml_append_nvt (results, buffer, cert_loaded);

  if (lean == 0)
    buffer_xml_append_printf
     (buffer,
      "<scan_nvt_version>%s</scan_nvt_version>"
      "<threat>%s</threat>",
      result_iterator_scan_nvt_version (results),
      result_iterator_level (results));

  buffer_xml_append_printf
   (buffer,
    "<severity>%.1f</severity>"
    "<qod><value>%s</value>",
    result_iterator_severity_double (results),
    qod ? qod : "");

  if (qod_type && strlen (qod_type))
    buffer_xml_append_printf (buffer, "<type>%s</type>", qod_type);
  else if (lean == 0)
    buffer_xml_append_printf (buffer, "<type></type>");

  buffer_xml_append_printf (buffer, "</qod>");

  g_string_append_printf (buffer,
                          "<description>%s</description>",
                          descr ? nl_descr_escaped : "");

  if (include_overrides && lean)
    {
      /* Only send the original severity if it has changed. */
      if (strncmp (result_iterator_original_severity (results),
                   result_iterator_severity (results),
                   /* Avoid rounding differences. */
                   3))
        buffer_xml_append_printf (buffer,
                                  "<original_severity>%s</original_severity>",
                                  result_iterator_original_severity (results));
    }
  else if (include_overrides)
    buffer_xml_append_printf (buffer,
                              "<original_threat>%s</original_threat>"
                              "<original_severity>%s</original_severity>",
                              result_iterator_original_level (results),
                              result_iterator_original_severity (results));

  if (include_notes
      && result_iterator_may_have_notes (results))
    buffer_result_notes_xml (buffer, result,
                             selected_task, include_notes_details, lean);

  if (include_overrides
      && result_iterator_may_have_overrides (results))
    buffer_result_overrides_xml (buffer, result,
                                 selected_task, include_overrides_details,
                                 lean);

  if (delta_state || delta_results)
    {
      g_string_append (buffer, "<delta>");
      if (delta_state)
        g_string_append_printf (buffer, "%s", delta_state);
      if (changed && delta_results)
        {
          gchar *diff, *delta_nl_descr;
          const char *delta_descr;
          buffer_results_xml (buffer, delta_results, selected_task,
                              include_notes, include_notes_details,
                              include_overrides, include_overrides_details,
                              include_tags, include_tags_details,
                              include_details, delta_state, NULL, 0, -1, lean);
          delta_descr = result_iterator_descr (delta_results);
          delta_nl_descr = delta_descr ? convert_to_newlines (delta_descr)
                                       : NULL;
          diff = strdiff (descr ? nl_descr : "",
                          delta_descr ? delta_nl_descr : "");
          g_free (delta_nl_descr);
          if (diff)
            {
              gchar **split, *diff_xml;
              /* Remove the leading filename lines. */
              split = g_strsplit ((gchar*) diff, "\n", 3);
              if (split[0] && split[1] && split[2])
                diff_xml = xml_escape_text_truncated (split[2],
                                                      TRUNCATE_TEXT_LENGTH,
                                                      TRUNCATE_TEXT_SUFFIX);
              else
                diff_xml = xml_escape_text_truncated (diff,
                                                      TRUNCATE_TEXT_LENGTH,
                                                      TRUNCATE_TEXT_SUFFIX);
              g_strfreev (split);
              g_string_append_printf (buffer, "<diff>%s</diff>", diff_xml);
              g_free (diff_xml);
              g_free (diff);
            }
          else
            g_string_append (buffer, "<diff>Error creating diff.</diff>");
        }

      if (delta_results)
        {
          if (include_notes)
            buffer_result_notes_xml (buffer,
                                     result_iterator_result (delta_results),
                                     selected_task,
                                     include_notes_details,
                                     lean);

          if (include_overrides)
            buffer_result_overrides_xml (buffer,
                                         result_iterator_result (delta_results),
                                         selected_task,
                                         include_overrides_details,
                                         lean);
        }
      g_string_append (buffer, "</delta>");
    }

  if (descr)
    {
      g_free (nl_descr);
      g_free (nl_descr_escaped);
    }

  if (result_iterator_may_have_tickets (results))
    buffer_result_tickets_xml (buffer, result);

  g_string_append (buffer, "</result>");
}

#undef ADD_DETAIL

/**
 * @brief Initialize lists for aggregates.
 *
 * @param[in]  group_column      Column the data are grouped by.
 * @param[in]  subgroup_column   Second column the data grouped by.
 * @param[in]  data_column_list  GList of columns statistics are calculated for.
 * @param[in]  text_column_list  GList of columns used for labels.
 * @param[in]  sort_data_list    GList of sort data.
 * @param[out] group_column_type     Type of the group_column.
 * @param[out] subgroup_column_type  Type of the group_column.
 * @param[out] data_column_types     Types of the data_column.
 * @param[out] data_columns      data_column_list copied to a GArray.
 * @param[out] text_column_types Types of the text_columns.
 * @param[out] text_columns      text_column_list copied to a GArray.
 * @param[out] sort_data         sort_data_list copied to a GArray.
 * @param[out] c_sums            Array for calculating cumulative sums.
 */
static void
init_aggregate_lists (const gchar* group_column,
                      const gchar* subgroup_column,
                      GList *data_column_list,
                      GList *text_column_list,
                      GList *sort_data_list,
                      gchar **group_column_type,
                      gchar **subgroup_column_type,
                      GArray **data_column_types,
                      GArray **data_columns,
                      GArray **text_column_types,
                      GArray **text_columns,
                      GArray **sort_data,
                      GArray **c_sums)
{
  if (group_column == NULL)
    *group_column_type = "";
  else if (strcmp (group_column, "severity") == 0)
    *group_column_type = "cvss";
  else if (strcmp (group_column, "created") == 0
            || strcmp (group_column, "modified") == 0)
    *group_column_type = "unix_time";
  else
    *group_column_type = "text";

  if (subgroup_column == NULL)
    *subgroup_column_type = "";
  else if (strcmp (subgroup_column, "severity") == 0)
    *subgroup_column_type = "cvss";
  else if (strcmp (subgroup_column, "created") == 0
            || strcmp (subgroup_column, "modified") == 0)
    *subgroup_column_type = "unix_time";
  else
    *subgroup_column_type = "text";

  *data_columns = g_array_new (TRUE, TRUE, sizeof (gchar*));
  *data_column_types = g_array_new (TRUE, TRUE, sizeof (char*));
  *text_columns = g_array_new (TRUE, TRUE, sizeof (gchar*));
  *text_column_types = g_array_new (TRUE, TRUE, sizeof (char*));
  *c_sums = g_array_new (TRUE, TRUE, sizeof (double));
  *sort_data = g_array_new (TRUE, TRUE, sizeof (sort_data_t*));

  data_column_list = g_list_first (data_column_list);
  while (data_column_list)
    {
      gchar *data_column = data_column_list->data;
      if (strcmp (data_column, ""))
        {
          gchar *current_column = g_strdup (data_column);
          gchar *current_column_type;
          double c_sum = 0.0;
          g_array_append_val (*data_columns,
                              current_column);

          if (strcmp (data_column, "severity") == 0)
            current_column_type = g_strdup ("cvss");
          else if (strcmp (data_column, "created") == 0
                  || strcmp (data_column, "modified") == 0)
            current_column_type = g_strdup ("unix_time");
          else
            current_column_type = g_strdup ("decimal");

          g_array_append_val (*data_column_types, current_column_type);

          g_array_append_val (*c_sums, c_sum);
        }
      data_column_list = data_column_list->next;
    }

  text_column_list = g_list_first (text_column_list);
  while (text_column_list)
    {
      gchar *text_column = text_column_list->data;
      if (strcmp (text_column, ""))
        {
          gchar *current_column = g_strdup (text_column);
          gchar *current_column_type;

          current_column_type = g_strdup ("text");

          g_array_append_val (*text_columns, current_column);
          g_array_append_val (*text_column_types, current_column_type);
        }
      text_column_list = text_column_list->next;
    }

  sort_data_list = g_list_first (sort_data_list);
  while (sort_data_list)
    {
      sort_data_t *sort_data_item = sort_data_list->data;
      sort_data_t *sort_data_copy = g_malloc0 (sizeof (sort_data_t));

      sort_data_copy->field = g_strdup (sort_data_item->field);
      sort_data_copy->stat = g_strdup (sort_data_item->stat);
      sort_data_copy->order = sort_data_item->order;
      g_array_append_val (*sort_data, sort_data_copy);

      sort_data_list = sort_data_list->next;
    }
}

/**
 * @brief Helper data structure for word counts.
 */
typedef struct
{
  gchar *string;  ///< The string counted.
  int count;      ///< The number of occurrences.
} count_data_t;

/**
 * @brief Helper data structure for buffering word counts.
 */
typedef struct
{
  GString *buffer;  ///< The GString buffer to write to
  int skip;         ///< The amount of entries to skip at start.
  int limit;        ///< The maximum number of entries to output or -1 for all.
} buffer_counts_data_t;

/**
 * @brief Helper function for comparing strings in reverse order.
 *
 * @param[in]  s1   The first string to compare
 * @param[in]  s2   The second string to compare
 *
 * @return The result of g_ascii_strcasecmp with string order reversed.
 */
static int
strcasecmp_reverse (gchar *s1, gchar *s2)
{
  return g_ascii_strcasecmp (s2, s1);
}

/**
 * @brief Helper function for comparing word count structs by count.
 *
 * @param[in]  c1     The first count struct to compare
 * @param[in]  c2     The second count struct to compare
 * @param[in]  dummy  Dummy parameter required by glib.
 *
 * @return A value > 0 if c1 > c2, a value < 0 if c1 < c2, 0 if c1 = c2.
 */
static int
compare_count_data (gconstpointer c1, gconstpointer c2, gpointer dummy)
{
  return ((count_data_t*)c2)->count - ((count_data_t*)c1)->count;
}

/**
 * @brief Helper function for comparing word count structs by count in reverse.
 *
 * @param[in]  c1     The first count struct to compare
 * @param[in]  c2     The second count struct to compare
 * @param[in]  dummy  Dummy parameter required by glib.
 *
 * @return A value > 0 if c1 < c2, a value < 0 if c1 > c2, 0 if c1 = c2.
 */
static int
compare_count_data_reverse (gconstpointer c1, gconstpointer c2, gpointer dummy)
{
  return ((count_data_t*)c1)->count - ((count_data_t*)c2)->count;
}

/**
 * @brief Copy word counts to a GSequence of count_data_t structs (ascending).
 *
 * @param[in]  key    The key (word).
 * @param[in]  value  The value (count).
 * @param      data   The GSequence object to insert into.
 *
 * @return Always FALSE.
 */
static gboolean
copy_word_counts_asc (gpointer key, gpointer value, gpointer data)
{
  count_data_t* new_count = g_malloc (sizeof (count_data_t));

  new_count->string = (gchar*)key;
  new_count->count = GPOINTER_TO_INT (value);

  g_sequence_insert_sorted ((GSequence*) data,
                            new_count,
                            compare_count_data_reverse,
                            NULL);

  return FALSE;
}

/**
 * @brief Copy word counts to a GSequence of count_data_t structs (descending).
 *
 * @param[in]  key    The key (word).
 * @param[in]  value  The value (count).
 * @param      data   The GSequence object to insert into.
 *
 * @return Always FALSE.
 */
static gboolean
copy_word_counts_desc (gpointer key, gpointer value, gpointer data)
{
  count_data_t* new_count = g_malloc (sizeof (count_data_t));

  new_count->string = (gchar*)key;
  new_count->count = GPOINTER_TO_INT (value);

  g_sequence_insert_sorted ((GSequence*) data,
                            new_count,
                            compare_count_data,
                            NULL);

  return FALSE;
}

/**
 * @brief Buffer word count data
 *
 * @param[in]  key    The key (word).
 * @param[in]  value  The value (count).
 * @param      data   The buffer_counts_data_t struct containing info.
 *
 * @return TRUE if the limit has been reached, FALSE otherwise
 */
static gboolean
buffer_word_counts_tree (gpointer key, gpointer value, gpointer data)
{
  buffer_counts_data_t* count_data = (buffer_counts_data_t*) data;
  if (count_data->skip)
    {
      count_data->skip--;
      return FALSE;
    }
  xml_string_append (count_data->buffer,
                     "<group>"
                     "<value>%s</value>"
                     "<count>%d</count>"
                     "</group>",
                     (gchar*) key,
                     GPOINTER_TO_INT (value));
  if (count_data->limit > 0)
    count_data->limit--;

  return count_data->limit == 0;
}

/**
 * @brief Buffer word count data
 *
 * @param[in]  value  The value
 * @param      buffer The buffer object
 */
static void
buffer_word_counts_seq (gpointer value, gpointer buffer)
{
  xml_string_append ((GString*) buffer,
                     "<group>"
                     "<value>%s</value>"
                     "<count>%d</count>"
                     "</group>",
                     ((count_data_t*) value)->string,
                     ((count_data_t*) value)->count);
}

/**
 * @brief Count words of an aggregate and buffer as XML.
 *
 * @param[in]  xml           Buffer into which to buffer aggregate.
 * @param[in]  aggregate     The aggregate iterator.
 * @param[in]  type          The aggregated type.
 * @param[in]  group_column  Column the data are grouped by.
 * @param[in]  sort_data     Sort data.
 * @param[in]  first_group   Index of the first word to output, starting at 0.
 * @param[in]  max_groups    Maximum number of words to output or -1 for all.
 */
static void
buffer_aggregate_wc_xml (GString *xml, iterator_t* aggregate,
                         const gchar* type, const char* group_column,
                         GArray* sort_data,
                         int first_group, int max_groups)
{
  sort_data_t *first_sort_data;
  const char *sort_stat;
  int sort_order;

  if (sort_data && sort_data->len)
    {
      first_sort_data = g_array_index (sort_data, sort_data_t*, 0);
      sort_stat = first_sort_data->stat;
      sort_order = first_sort_data->order;
    }
  else
    {
      sort_stat = "value";
      sort_order = 0;
    }

  GTree *word_counts, *ignore_words;
  GRegex *word_regex;

  // Word regex: Words must contain at least 1 letter
  word_regex = g_regex_new ("[[:alpha:]]", 0, 0, NULL);

  ignore_words = g_tree_new_full ((GCompareDataFunc) g_ascii_strcasecmp, NULL,
                                  g_free, NULL);
  g_tree_insert (ignore_words, g_strdup ("an"), GINT_TO_POINTER (1));
  g_tree_insert (ignore_words, g_strdup ("the"), GINT_TO_POINTER (1));
  g_tree_insert (ignore_words, g_strdup ("and"), GINT_TO_POINTER (1));
  g_tree_insert (ignore_words, g_strdup ("or"), GINT_TO_POINTER (1));
  g_tree_insert (ignore_words, g_strdup ("not"), GINT_TO_POINTER (1));
  g_tree_insert (ignore_words, g_strdup ("is"), GINT_TO_POINTER (1));
  g_tree_insert (ignore_words, g_strdup ("are"), GINT_TO_POINTER (1));
  g_tree_insert (ignore_words, g_strdup ("was"), GINT_TO_POINTER (1));
  g_tree_insert (ignore_words, g_strdup ("were"), GINT_TO_POINTER (1));
  g_tree_insert (ignore_words, g_strdup ("you"), GINT_TO_POINTER (1));
  g_tree_insert (ignore_words, g_strdup ("your"), GINT_TO_POINTER (1));
  g_tree_insert (ignore_words, g_strdup ("it"), GINT_TO_POINTER (1));
  g_tree_insert (ignore_words, g_strdup ("its"), GINT_TO_POINTER (1));
  g_tree_insert (ignore_words, g_strdup ("they"), GINT_TO_POINTER (1));
  g_tree_insert (ignore_words, g_strdup ("this"), GINT_TO_POINTER (1));
  g_tree_insert (ignore_words, g_strdup ("that"), GINT_TO_POINTER (1));
  g_tree_insert (ignore_words, g_strdup ("which"), GINT_TO_POINTER (1));
  g_tree_insert (ignore_words, g_strdup ("when"), GINT_TO_POINTER (1));
  g_tree_insert (ignore_words, g_strdup ("if"), GINT_TO_POINTER (1));
  g_tree_insert (ignore_words, g_strdup ("do"), GINT_TO_POINTER (1));
  g_tree_insert (ignore_words, g_strdup ("does"), GINT_TO_POINTER (1));
  g_tree_insert (ignore_words, g_strdup ("did"), GINT_TO_POINTER (1));
  g_tree_insert (ignore_words, g_strdup ("at"), GINT_TO_POINTER (1));
  g_tree_insert (ignore_words, g_strdup ("where"), GINT_TO_POINTER (1));
  g_tree_insert (ignore_words, g_strdup ("in"), GINT_TO_POINTER (1));
  g_tree_insert (ignore_words, g_strdup ("will"), GINT_TO_POINTER (1));
  g_tree_insert (ignore_words, g_strdup ("as"), GINT_TO_POINTER (1));
  g_tree_insert (ignore_words, g_strdup ("has"), GINT_TO_POINTER (1));
  g_tree_insert (ignore_words, g_strdup ("have"), GINT_TO_POINTER (1));
  g_tree_insert (ignore_words, g_strdup ("can"), GINT_TO_POINTER (1));
  g_tree_insert (ignore_words, g_strdup ("cannot"), GINT_TO_POINTER (1));
  g_tree_insert (ignore_words, g_strdup ("been"), GINT_TO_POINTER (1));
  g_tree_insert (ignore_words, g_strdup ("with"), GINT_TO_POINTER (1));
  g_tree_insert (ignore_words, g_strdup ("under"), GINT_TO_POINTER (1));
  g_tree_insert (ignore_words, g_strdup ("for"), GINT_TO_POINTER (1));
  g_tree_insert (ignore_words, g_strdup ("than"), GINT_TO_POINTER (1));
  g_tree_insert (ignore_words, g_strdup ("seen"), GINT_TO_POINTER (1));
  g_tree_insert (ignore_words, g_strdup ("full"), GINT_TO_POINTER (1));
  g_tree_insert (ignore_words, g_strdup ("use"), GINT_TO_POINTER (1));
  g_tree_insert (ignore_words, g_strdup ("see"), GINT_TO_POINTER (1));
  g_tree_insert (ignore_words, g_strdup ("more"), GINT_TO_POINTER (1));

  if (sort_order)
    word_counts = g_tree_new_full ((GCompareDataFunc) g_ascii_strcasecmp, NULL,
                                   g_free, NULL);
  else
    word_counts = g_tree_new_full ((GCompareDataFunc) strcasecmp_reverse, NULL,
                                   g_free, NULL);

  g_string_append_printf (xml, "<aggregate>");

  g_string_append_printf (xml,
                          "<group_column>%s</group_column>",
                          group_column);

  while (next (aggregate))
    {
      const gchar *value = aggregate_iterator_value (aggregate);
      int count = aggregate_iterator_count (aggregate);

      int current_index = 0;
      gchar **split_string;

      if (!value)
        continue;

      split_string = g_strsplit_set (value, " \t\n.,:;\"'()[]{}<>&", -1);
      while (split_string [current_index])
        {
          gchar *word = split_string [current_index];
          if (strlen (word) >= 3
              && g_regex_match (word_regex, word, 0, NULL)
              && g_tree_lookup (ignore_words, word) == 0)
            {
              int word_count
                = GPOINTER_TO_INT (g_tree_lookup (word_counts, word));
              if (word_count)
                {
                  g_tree_insert (word_counts, word,
                                GINT_TO_POINTER (word_count + count));
                }
              else
                {
                  g_tree_insert (word_counts, g_strdup (word),
                                GINT_TO_POINTER (count));
                }
            }
          current_index++;
        }
    }

  if (sort_stat && strcasecmp (sort_stat, "count") == 0)
    {
      GSequence *word_counts_sorted;
      GSequenceIter *start, *end;
      word_counts_sorted = g_sequence_new (g_free);
      g_tree_foreach (word_counts,
                      sort_order
                        ? copy_word_counts_asc
                        : copy_word_counts_desc,
                      word_counts_sorted);

      start = g_sequence_get_iter_at_pos (word_counts_sorted, first_group);
      if (max_groups < 0)
        end = g_sequence_get_end_iter (word_counts_sorted);
      else
        end = g_sequence_get_iter_at_pos (word_counts_sorted,
                                          first_group + max_groups);

      g_sequence_foreach_range (start, end, buffer_word_counts_seq, xml);

      g_sequence_free (word_counts_sorted);
    }
  else
    {
      // value: use default alphabetical sorting
      buffer_counts_data_t counts_data;
      counts_data.buffer = xml;
      counts_data.skip = first_group;
      counts_data.limit = max_groups;
      g_tree_foreach (word_counts, buffer_word_counts_tree, &counts_data);
    }

  g_tree_destroy (word_counts);
  g_tree_destroy (ignore_words);

  g_string_append (xml, "<column_info>");

  g_string_append_printf (xml,
                          "<aggregate_column>"
                          "<name>value</name>"
                          "<stat>value</stat>"
                          "<type>%s</type>"
                          "<column>%s</column>"
                          "<data_type>text</data_type>"
                          "</aggregate_column>",
                          type,
                          group_column);

  g_string_append_printf (xml,
                          "<aggregate_column>"
                          "<name>count</name>"
                          "<stat>count</stat>"
                          "<type>%s</type>"
                          "<column></column>"
                          "<data_type>integer</data_type>"
                          "</aggregate_column>",
                          type);

  g_string_append (xml, "</column_info>");

  g_string_append_printf (xml, "</aggregate>");
}

/**
 * @brief Buffer a get_aggregates subgroup value from a cumulative count GTree.
 *
 * @param[in]     key     The subgroup value used as key in the GTree.
 * @param[in]     value   The cumulative count used as value in the GTree.
 * @param[in,out] buffer  A GString buffer to output the XML to.
 *
 * @return Always FALSE.
 */
static gboolean
buffer_aggregate_subgroup_value (gchar *key,
                                 long int *value,
                                 GString *buffer)
{
  xml_string_append (buffer, "<value>%s</value>", key ? key : "");
  return FALSE;
}

/**
 * @brief Buffer XML for an aggregate.
 *
 * @param[in]  xml                    Buffer into which to buffer aggregate.
 * @param[in]  aggregate              The aggregate iterator.
 * @param[in]  type                   The aggregated type.
 * @param[in]  group_column           Column the data are grouped by.
 * @param[in]  group_column_type      Type of the group_column.
 * @param[in]  subgroup_column        Column the data are further grouped by.
 * @param[in]  subgroup_column_type
 * @param[in]  data_columns           Columns statistics are calculated for.
 * @param[in]  data_column_types      Types of the data_columns.
 * @param[in]  text_columns           Columns used for labels.
 * @param[in]  text_column_types      Types of the text_columns.
 * @param[in]  c_sums                 Array for calculating cumulative sums.
 */
static void
buffer_aggregate_xml (GString *xml, iterator_t* aggregate, const gchar* type,
                      const char* group_column, const char* group_column_type,
                      const char* subgroup_column,
                      const char* subgroup_column_type,
                      GArray *data_columns, GArray *data_column_types,
                      GArray *text_columns, GArray *text_column_types,
                      GArray *c_sums)
{
  int index;
  long c_count, previous_c_count;
  gchar *previous_group_value;
  long int aggregate_group_count;
  GArray *group_mins, *group_maxs, *group_mean_sums, *group_sums, *group_c_sums;
  GTree *subgroup_c_counts;
  int has_groups = 0;

  g_string_append_printf (xml, "<aggregate>");

  for (index = 0; index < data_columns->len ;index ++)
    {
      gchar *column_name = g_array_index (data_columns, gchar*, index);
      if (column_name && strcmp (column_name, ""))
        {
          g_string_append_printf (xml,
                                  "<data_column>%s</data_column>",
                                  column_name);
        }
    }

  for (index = 0; index < text_columns->len ;index ++)
    {
      gchar *column_name = g_array_index (text_columns, gchar*, index);
      if (column_name && strcmp (column_name, ""))
        {
          g_string_append_printf (xml,
                                  "<text_column>%s</text_column>",
                                  column_name);
        }
    }

  if (group_column)
    g_string_append_printf (xml,
                            "<group_column>%s</group_column>",
                            group_column);

  if (subgroup_column)
    g_string_append_printf (xml,
                            "<subgroup_column>%s</subgroup_column>",
                            subgroup_column);

  previous_group_value = NULL;
  aggregate_group_count = 0L;
  c_count = 0L;
  previous_c_count = 0L;

  if (subgroup_column)
    {
      group_mins = g_array_new (TRUE, TRUE, sizeof (double));
      group_maxs = g_array_new (TRUE, TRUE, sizeof (double));
      group_mean_sums = g_array_new (TRUE, TRUE, sizeof (double));
      group_sums = g_array_new (TRUE, TRUE, sizeof (double));

      group_c_sums = g_array_new (TRUE, TRUE, sizeof (GTree*));
      for (index = 0; index < data_columns->len; index++)
        {
          g_array_index (group_c_sums, GTree*, index)
            = g_tree_new_full ((GCompareDataFunc) g_strcmp0, NULL,
                               g_free, g_free);
        }

      subgroup_c_counts = g_tree_new_full ((GCompareDataFunc) g_strcmp0, NULL,
                                           g_free, g_free);
    }
  else
    {
      group_mins = NULL;
      group_maxs = NULL;
      group_mean_sums = NULL;
      group_sums = NULL;
      group_c_sums = NULL;
      subgroup_c_counts = NULL;
    }

  while (next (aggregate))
    {
      const char *value = aggregate_iterator_value (aggregate);
      const char *subgroup_value
        = aggregate_iterator_subgroup_value (aggregate);
      gchar *value_escaped, *subgroup_value_escaped;

      has_groups = 1;

      c_count += aggregate_iterator_count (aggregate);

      if (value && column_is_timestamp (group_column))
        {
          time_t value_int;
          if (sscanf (value, "%ld", &value_int) == 1)
            value_escaped = g_strdup (iso_time (&value_int));
          else
            value_escaped = g_markup_escape_text (value, -1);
        }
      else if (value && group_column_type
               && strcmp (group_column_type, "cvss") == 0)
        {
          double dbl_value;
          sscanf (value, "%lf", &dbl_value);
          value_escaped = g_strdup_printf ("%0.1lf", dbl_value);
        }
      else if (group_column && value)
        value_escaped = g_markup_escape_text (value, -1);
      else
        value_escaped = NULL;

      if (subgroup_column && column_is_timestamp (subgroup_column))
        {
          time_t value_int;
          if (sscanf (subgroup_value, "%ld", &value_int) == 1)
            subgroup_value_escaped = g_strdup (iso_time (&value_int));
          else
            subgroup_value_escaped = g_markup_escape_text (subgroup_value, -1);
        }
      else if (subgroup_value && subgroup_column_type
               && strcmp (subgroup_column_type, "cvss") == 0)
        {
          double dbl_value;
          sscanf (subgroup_value, "%lf", &dbl_value);
          subgroup_value_escaped = g_strdup_printf ("%0.1lf", dbl_value);
        }
      else if (subgroup_column && subgroup_value)
        subgroup_value_escaped = g_markup_escape_text (subgroup_value, -1);
      else
        subgroup_value_escaped = NULL;

      if (group_column)
        {
          if (subgroup_column)
            {
              long int *subgroup_c_count;

              // Update cumulative count for subgroup value
              subgroup_c_count
                = g_tree_lookup (subgroup_c_counts, subgroup_value);
              if (subgroup_c_count == NULL)
                {
                  subgroup_c_count = g_malloc0 (sizeof (long int*));
                  g_tree_insert (subgroup_c_counts,
                                 g_strdup (subgroup_value),
                                 subgroup_c_count);
                }
              *subgroup_c_count += aggregate_iterator_count (aggregate);

              // Output of group elements
              if (previous_group_value == NULL)
                {
                  // Output start of first group
                  g_string_append_printf (xml,
                                          "<group>"
                                          "<value>%s</value>",
                                          value_escaped);
                }
              else if (strcmp (previous_group_value, value))
                {
                  // First subgroup of a new group:
                  //  output collected data of previous group and close it, ...
                  g_string_append_printf (xml,
                                          "<count>%ld</count>"
                                          "<c_count>%ld</c_count>",
                                          aggregate_group_count,
                                          previous_c_count);

                  for (index = 0; index < data_columns->len; index++)
                    {
                      gchar *data_column = g_array_index (data_columns,
                                                          gchar*, index);
                      double c_sum = g_array_index (c_sums, double, index);

                      if (column_is_timestamp (data_column))
                        {
                          time_t min, max, mean;
                          min = (time_t)(g_array_index (group_mins,
                                                        double, index));
                          max = (time_t)(g_array_index (group_maxs,
                                                        double, index));
                          mean = (time_t)(g_array_index (group_mean_sums,
                                                         double, index)
                                          / aggregate_group_count);

                          g_string_append_printf (xml,
                                                  "<stats column=\"%s\">"
                                                  "<min>%s</min>"
                                                  "<max>%s</max>"
                                                  "<mean>%s</mean>"
                                                  "<sum></sum>"
                                                  "<c_sum></c_sum>"
                                                  "</stats>",
                                                  data_column,
                                                  iso_time (&min),
                                                  iso_time (&max),
                                                  iso_time (&mean));
                        }
                      else
                        g_string_append_printf (xml,
                                                "<stats column=\"%s\">"
                                                "<min>%g</min>"
                                                "<max>%g</max>"
                                                "<mean>%g</mean>"
                                                "<sum>%g</sum>"
                                                "<c_sum>%g</c_sum>"
                                                "</stats>",
                                                data_column,
                                                g_array_index (group_mins,
                                                               double, index),
                                                g_array_index (group_maxs,
                                                               double, index),
                                                (g_array_index (group_mean_sums,
                                                               double, index)
                                                 / aggregate_group_count),
                                                g_array_index (group_sums,
                                                               double, index),
                                                c_sum);
                    }

                  g_string_append_printf (xml,
                                          "</group>");

                  // ... then start new group
                  g_string_append_printf (xml,
                                          "<group>"
                                          "<value>%s</value>",
                                          value_escaped);
                }

              // Update group statistics using current subgroup after output
              if (previous_group_value == NULL
                  || strcmp (previous_group_value, value))
                {
                  // First subgroup of any group:
                  //  Reset group statistics using current subgroup data
                  aggregate_group_count = aggregate_iterator_count (aggregate);

                  for (index = 0; index < data_columns->len; index++)
                    {
                      g_array_index (group_mins, double, index)
                        = aggregate_iterator_min (aggregate, index);
                      g_array_index (group_maxs, double, index)
                        = aggregate_iterator_max (aggregate, index);
                      g_array_index (group_mean_sums, double, index)
                        = (aggregate_iterator_mean (aggregate, index)
                           * aggregate_iterator_count (aggregate));
                      g_array_index (group_sums, double, index)
                        = aggregate_iterator_sum (aggregate, index);
                    }
                }
              else
                {
                  // Subgroup, but no new group: Update statistics
                  aggregate_group_count += aggregate_iterator_count (aggregate);

                  for (index = 0; index < data_columns->len; index++)
                    {
                      g_array_index (group_mins, double, index)
                        = fmin (aggregate_iterator_min (aggregate, index),
                                g_array_index (group_mins, double, index));
                      g_array_index (group_maxs, double, index)
                        = fmax (aggregate_iterator_max (aggregate, index),
                                g_array_index (group_maxs, double, index));
                      g_array_index (group_mean_sums, double, index)
                        += (aggregate_iterator_mean (aggregate, index)
                            * aggregate_iterator_count (aggregate));
                      g_array_index (group_sums, double, index)
                        += aggregate_iterator_sum (aggregate, index);
                    }
                }

              g_free (previous_group_value);
              previous_group_value = g_strdup (value);

              // Add subgroup values
              g_string_append_printf (xml,
                                      "<subgroup>"
                                      "<value>%s</value>"
                                      "<count>%d</count>"
                                      "<c_count>%ld</c_count>",
                                      subgroup_value_escaped
                                        ? subgroup_value_escaped : "",
                                      aggregate_iterator_count (aggregate),
                                      *subgroup_c_count);
            }
          else
            {
              // No subgrouping
              g_string_append_printf (xml,
                                      "<group>"
                                      "<value>%s</value>"
                                      "<count>%d</count>"
                                      "<c_count>%ld</c_count>",
                                      value_escaped ? value_escaped : "",
                                      aggregate_iterator_count (aggregate),
                                      c_count);
            }

          previous_c_count = c_count;
        }
      else
        {
          g_string_append_printf (xml,
                                  "<overall>"
                                  "<count>%d</count>"
                                  "<c_count>%ld</c_count>",
                                  aggregate_iterator_count (aggregate),
                                  c_count);
        }

      for (index = 0; index < data_columns->len; index++)
        {
          gchar *data_column = g_array_index (data_columns, gchar*, index);;
          double c_sum;
          double *subgroup_c_sum = NULL;

          if (subgroup_column && column_is_timestamp (data_column) == FALSE)
            {
              GTree *c_sum_tree;

              c_sum_tree = g_array_index (group_c_sums, GTree*, index);
              subgroup_c_sum = g_tree_lookup (c_sum_tree, subgroup_value);

              if (subgroup_c_sum == NULL)
                {
                  subgroup_c_sum = g_malloc (sizeof (double *));
                  *subgroup_c_sum = 0;

                  g_tree_insert (c_sum_tree,
                                 g_strdup (subgroup_value),
                                 subgroup_c_sum);
                }

              *subgroup_c_sum += aggregate_iterator_sum (aggregate, index);
            }

          c_sum = g_array_index (c_sums, double, index);
          c_sum += aggregate_iterator_sum (aggregate, index);
          g_array_index (c_sums, double, index) = c_sum;

          if (column_is_timestamp (data_column))
            {
              time_t min, max, mean;
              min = (time_t)(aggregate_iterator_min (aggregate, index));
              max = (time_t)(aggregate_iterator_max (aggregate, index));
              mean = (time_t)(aggregate_iterator_mean (aggregate, index));

              g_string_append_printf (xml,
                                      "<stats column=\"%s\">"
                                      "<min>%s</min>"
                                      "<max>%s</max>"
                                      "<mean>%s</mean>"
                                      "<sum></sum>"
                                      "<c_sum></c_sum>"
                                      "</stats>",
                                      data_column,
                                      iso_time (&min),
                                      iso_time (&max),
                                      iso_time (&mean));
            }
          else
            {
              g_string_append_printf (xml,
                                      "<stats column=\"%s\">"
                                      "<min>%g</min>"
                                      "<max>%g</max>"
                                      "<mean>%g</mean>"
                                      "<sum>%g</sum>"
                                      "<c_sum>%g</c_sum>"
                                      "</stats>",
                                      data_column,
                                      aggregate_iterator_min (aggregate, index),
                                      aggregate_iterator_max (aggregate, index),
                                      aggregate_iterator_mean (aggregate, index),
                                      aggregate_iterator_sum (aggregate, index),
                                      subgroup_column && subgroup_c_sum
                                        ? *subgroup_c_sum : c_sum);
          }
        }

      for (index = 0; index < text_columns->len; index++)
        {
          const char *text = aggregate_iterator_text (aggregate, index,
                                                      data_columns->len);
          gchar *text_escaped;
          gchar *text_column = g_array_index (text_columns, gchar*, index);

          if (text && column_is_timestamp (text_column))
            {
              time_t text_int;
              if (sscanf (text, "%ld", &text_int) == 1)
                text_escaped = g_strdup (iso_time (&text_int));
              else
                text_escaped = g_markup_escape_text (text, -1);
            }
          else if (text)
            text_escaped  = g_markup_escape_text (text, -1);
          else
            text_escaped = NULL;

          g_string_append_printf (xml,
                                  "<text column=\"%s\">%s</text>",
                                  text_column,
                                  text_escaped ? text_escaped : "");
          g_free (text_escaped);
        }

      if (subgroup_column)
        {
          g_string_append_printf (xml, "</subgroup>");
        }
      else if (group_column)
        {
          g_string_append_printf (xml, "</group>");
        }
      else
        {
          g_string_append_printf (xml, "</overall>");
        }
      g_free (value_escaped);
      g_free (subgroup_value_escaped);
    }

  if (subgroup_column)
    {
      // Add elements for last group in case subgroups are used
      if (has_groups)
        {
          g_string_append_printf (xml,
                                  "<count>%ld</count>"
                                  "<c_count>%ld</c_count>"
                                  "</group>",
                                  aggregate_group_count,
                                  previous_c_count);
        }

      // Also add overview of all subgroup values
      g_string_append_printf (xml,
                              "<subgroups>");

      g_tree_foreach (subgroup_c_counts,
                      (GTraverseFunc) buffer_aggregate_subgroup_value,
                      xml);

      g_string_append_printf (xml,
                              "</subgroups>");
    }

  g_string_append (xml, "<column_info>");

  if (group_column)
    {
      g_string_append_printf (xml,
                              "<aggregate_column>"
                              "<name>value</name>"
                              "<stat>value</stat>"
                              "<type>%s</type>"
                              "<column>%s</column>"
                              "<data_type>%s</data_type>"
                              "</aggregate_column>",
                              type,
                              group_column,
                              group_column_type);
    }

  if (subgroup_column)
    {
      g_string_append_printf (xml,
                              "<aggregate_column>"
                              "<name>subgroup_value</name>"
                              "<stat>value</stat>"
                              "<type>%s</type>"
                              "<column>%s</column>"
                              "<data_type>%s</data_type>"
                              "</aggregate_column>",
                              type,
                              subgroup_column,
                              subgroup_column_type);
    }

  g_string_append_printf (xml,
                          "<aggregate_column>"
                          "<name>count</name>"
                          "<stat>count</stat>"
                          "<type>%s</type>"
                          "<column></column>"
                          "<data_type>integer</data_type>"
                          "</aggregate_column>",
                          type);

  g_string_append_printf (xml,
                          "<aggregate_column>"
                          "<name>c_count</name>"
                          "<stat>c_count</stat>"
                          "<type>%s</type>"
                          "<column></column>"
                          "<data_type>integer</data_type>"
                          "</aggregate_column>",
                          type);

  for (index = 0; index < data_columns->len; index++)
    {
      gchar *column_name, *column_type;
      column_name = g_array_index (data_columns, gchar*, index);
      column_type = g_array_index (data_column_types, gchar*, index);
      g_string_append_printf (xml,
                              "<aggregate_column>"
                              "<name>%s_min</name>"
                              "<stat>min</stat>"
                              "<type>%s</type>"
                              "<column>%s</column>"
                              "<data_type>%s</data_type>"
                              "</aggregate_column>",
                              column_name,
                              type,
                              column_name,
                              column_type);
      g_string_append_printf (xml,
                              "<aggregate_column>"
                              "<name>%s_max</name>"
                              "<stat>max</stat>"
                              "<type>%s</type>"
                              "<column>%s</column>"
                              "<data_type>%s</data_type>"
                              "</aggregate_column>",
                              column_name,
                              type,
                              column_name,
                              column_type);
      g_string_append_printf (xml,
                              "<aggregate_column>"
                              "<name>%s_mean</name>"
                              "<stat>mean</stat>"
                              "<type>%s</type>"
                              "<column>%s</column>"
                              "<data_type>%s</data_type>"
                              "</aggregate_column>",
                              column_name,
                              type,
                              column_name,
                              column_type);
      g_string_append_printf (xml,
                              "<aggregate_column>"
                              "<name>%s_sum</name>"
                              "<stat>sum</stat>"
                              "<type>%s</type>"
                              "<column>%s</column>"
                              "<data_type>%s</data_type>"
                              "</aggregate_column>",
                              column_name,
                              type,
                              column_name,
                              column_type);
      g_string_append_printf (xml,
                              "<aggregate_column>"
                              "<name>%s_c_sum</name>"
                              "<stat>c_sum</stat>"
                              "<type>%s</type>"
                              "<column>%s</column>"
                              "<data_type>%s</data_type>"
                              "</aggregate_column>",
                              column_name,
                              type,
                              column_name,
                              column_type);
    }

  for (index = 0; index < text_columns->len; index++)
    {
      gchar *column_name, *column_type;
      column_name = g_array_index (text_columns, gchar*, index);
      column_type = g_array_index (text_column_types, gchar*, index);
      g_string_append_printf (xml,
                              "<aggregate_column>"
                              "<name>%s</name>"
                              "<stat>text</stat>"
                              "<type>%s</type>"
                              "<column>%s</column>"
                              "<data_type>%s</data_type>"
                              "</aggregate_column>",
                              column_name,
                              type,
                              column_name,
                              column_type);
    }

  g_string_append (xml, "</column_info>");

  g_string_append (xml, "</aggregate>");

  if (subgroup_column)
    {
      g_array_free (group_mins, TRUE);
      g_array_free (group_maxs, TRUE);
      g_array_free (group_mean_sums, TRUE);
      g_array_free (group_sums, TRUE);

      for (index = 0; index < data_columns->len; index++)
        {
          g_tree_destroy (g_array_index (group_c_sums, GTree*, index));
        }

      g_array_free (group_c_sums, TRUE);

      g_tree_destroy(subgroup_c_counts);
    };
}

/**
 * @brief Insert else clause for gmp_xml_handle_start_element.
 *
 * @param[in]  parent   Parent element.
 * @param[in]  element  Element.
 */
#define CLOSE(parent, element)                                           \
  case parent ## _ ## element:                                           \
    set_client_state (parent);                                           \
    break

/**
 * @brief Insert GET case for gmp_xml_handle_end_element.
 *
 * @param[in]  upper    What to GET, in uppercase.
 * @param[in]  lower    What to GET, in lowercase.
 */
#define CASE_GET_END(upper, lower)              \
  case CLIENT_GET_ ## upper:                    \
    get_ ## lower ## _run (gmp_parser, error);  \
    set_client_state (CLIENT_AUTHENTIC);        \
    break;

/**
 * @brief Insert DELETE case for gmp_xml_handle_end_element.
 *
 * @param[in]  upper    Resource type in uppercase.
 * @param[in]  type     Resource type.
 * @param[in]  capital  Resource type capitalised.
 */
#define CASE_DELETE(upper, type, capital)                                   \
  case CLIENT_DELETE_ ## upper :                                            \
    if (delete_ ## type ## _data-> type ## _id)                             \
      switch (delete_ ## type (delete_ ## type ## _data-> type ## _id,      \
                             delete_ ## type ## _data->ultimate))           \
        {                                                                   \
          case 0:                                                           \
            SEND_TO_CLIENT_OR_FAIL (XML_OK ("delete_" G_STRINGIFY (type))); \
            log_event (G_STRINGIFY(type), capital,                          \
                       delete_ ## type ## _data-> type ## _id, "deleted");  \
            break;                                                          \
          case 1:                                                           \
            SEND_TO_CLIENT_OR_FAIL                                          \
             (XML_ERROR_SYNTAX ("delete_" G_STRINGIFY (type),               \
                                capital " is in use"));                     \
            log_event_fail (G_STRINGIFY(type), capital,                     \
                            delete_ ## type ## _data-> type ## _id,         \
                            "deleted");                                     \
            break;                                                          \
          case 2:                                                           \
            if (send_find_error_to_client                                   \
                 ("delete_" G_STRINGIFY (type),                             \
                  G_STRINGIFY (type),                                       \
                  delete_ ## type ## _data-> type ## _id,                   \
                  gmp_parser))                                              \
              {                                                             \
                error_send_to_client (error);                               \
                return;                                                     \
              }                                                             \
            log_event_fail (G_STRINGIFY(type), capital,                     \
                            delete_ ## type ## _data-> type ## _id,         \
                            "deleted");                                     \
            break;                                                          \
          case 3:                                                           \
            SEND_TO_CLIENT_OR_FAIL                                          \
             (XML_ERROR_SYNTAX ("delete_" G_STRINGIFY (type),               \
                                "Attempt to delete a predefined"            \
                                " " G_STRINGIFY (type)));                   \
            break;                                                          \
          case 99:                                                          \
            SEND_TO_CLIENT_OR_FAIL                                          \
             (XML_ERROR_SYNTAX ("delete_" G_STRINGIFY (type),               \
                                "Permission denied"));                      \
            log_event_fail (G_STRINGIFY(type), capital,                     \
                            delete_ ## type ## _data-> type ## _id,         \
                            "deleted");                                     \
            break;                                                          \
          default:                                                          \
            SEND_TO_CLIENT_OR_FAIL                                          \
             (XML_INTERNAL_ERROR ("delete_" G_STRINGIFY (type)));           \
            log_event_fail (G_STRINGIFY(type), capital,                     \
                            delete_ ## type ## _data-> type ## _id,         \
                            "deleted");                                     \
        }                                                                   \
    else                                                                    \
      SEND_TO_CLIENT_OR_FAIL                                                \
       (XML_ERROR_SYNTAX ("delete_" G_STRINGIFY (type),                     \
                          "Attribute " G_STRINGIFY (type) "_id is"          \
                          " required"));                                    \
    delete_ ## type ## _data_reset (delete_ ## type ## _data);              \
    set_client_state (CLIENT_AUTHENTIC);                                    \
    break

/**
 * @brief Handle end of GET_AGGREGATES element.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 */
static void
handle_get_aggregates (gmp_parser_t *gmp_parser, GError **error)
{
  iterator_t aggregate;
  const char *type;
  get_data_t *get;
  GArray *data_columns, *data_column_types;
  GArray *text_columns, *text_column_types;
  GArray *sort_data;
  GArray *c_sums;
  const char *group_column, *subgroup_column;
  char *group_column_type, *subgroup_column_type;
  int ret, index;
  GString *xml;
  gchar *sort_field, *filter;
  int first, sort_order;
  GString *type_many;

  type = get_aggregates_data->type;
  if (type == NULL)
    {
      SEND_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("get_aggregates",
                             "A 'type' attribute is required"));
      return;
    }

  get = &get_aggregates_data->get;

  ret = init_get ("get_aggregates",
                  &get_aggregates_data->get,
                  "Aggregates",
                  &first);
  if (ret)
    {
      switch (ret)
        {
          case 99:
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("get_aggregates",
                                "Permission denied"));
            break;
          default:
            internal_error_send_to_client (error);
            return;
        }
      get_aggregates_data_reset (get_aggregates_data);
      set_client_state (CLIENT_AUTHENTIC);
      return;
    }

  group_column = get_aggregates_data->group_column;
  subgroup_column = get_aggregates_data->subgroup_column;

  init_aggregate_lists (group_column,
                        subgroup_column,
                        get_aggregates_data->data_columns,
                        get_aggregates_data->text_columns,
                        get_aggregates_data->sort_data,
                        &group_column_type, &subgroup_column_type,
                        &data_column_types, &data_columns,
                        &text_column_types, &text_columns,
                        &sort_data,
                        &c_sums);

  if (get_aggregates_data->mode
      && strcasecmp (get_aggregates_data->mode, "word_counts") == 0)
    {
      ret = init_aggregate_iterator (&aggregate, type, get,
                                    0 /* distinct */,
                                    data_columns,
                                    group_column, subgroup_column,
                                    text_columns,
                                    NULL, /* ignore sorting */
                                    0,    /* get all groups */
                                    -1,
                                    NULL /* extra_tables */,
                                    NULL /* extra_where */);
    }
  else
    {
      ret = init_aggregate_iterator (&aggregate, type, get,
                                    0 /* distinct */,
                                    data_columns,
                                    group_column, subgroup_column,
                                    text_columns,
                                    sort_data,
                                    get_aggregates_data->first_group,
                                    get_aggregates_data->max_groups,
                                    NULL /* extra_tables */,
                                    NULL /* extra_where */);
    }

  switch (ret)
    {
      case 0:
        break;
      case 1:
        SEND_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("get_aggregates",
                             "Failed to find resource"));
        break;
      case 2:
        SEND_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("get_aggregates",
                             "Failed to find filter"));
        break;
      case 3:
        SEND_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("get_aggregates",
                             "Invalid data_column"));
        break;
      case 4:
        SEND_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("get_aggregates",
                             "Invalid group_column"));
        break;
      case 5:
        SEND_TO_CLIENT_OR_FAIL
            (XML_ERROR_SYNTAX ("get_aggregates",
                               "Invalid resource type"));
        break;
      case 6:
        SEND_TO_CLIENT_OR_FAIL
            (XML_ERROR_SYNTAX ("get_aggregates",
                               "Trashcan not used by resource type"));
        break;
      case 7:
        SEND_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("get_aggregates",
                             "Invalid text_column"));
        break;
      case 8:
        SEND_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("get_aggregates",
                             "Invalid subgroup_column"));
        break;
      case 99:
        SEND_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("get_aggregates",
                             "Permission denied"));
        break;
      default:
        assert (0);
        /* fallthrough */
      case -1:
        SEND_TO_CLIENT_OR_FAIL
          (XML_INTERNAL_ERROR ("get_aggregates"));
        break;
    }

  if (ret)
    {
      g_array_free (data_columns, TRUE);
      g_array_free (data_column_types, TRUE);
      for (index = 0; index < sort_data->len; index++)
        sort_data_free (g_array_index (sort_data, sort_data_t*, index));
      g_array_free (sort_data, TRUE);
      g_array_free (c_sums, TRUE);
      return;
    }

  xml = g_string_new ("<get_aggregates_response"
                      "  status_text=\"" STATUS_OK_TEXT "\""
                      "  status=\"" STATUS_OK "\">");

  if (get_aggregates_data->mode
      && strcasecmp (get_aggregates_data->mode, "word_counts") == 0)
    {
      buffer_aggregate_wc_xml (xml, &aggregate, type, group_column,
                                sort_data,
                                get_aggregates_data->first_group,
                                get_aggregates_data->max_groups);
    }
  else
    {
      buffer_aggregate_xml (xml, &aggregate, type,
                            group_column, group_column_type,
                            subgroup_column, subgroup_column_type,
                            data_columns, data_column_types,
                            text_columns, text_column_types,
                            c_sums);
    }

  if (get->filt_id && strcmp (get->filt_id, FILT_ID_NONE))
    {
      if (get->filter_replacement)
        filter = g_strdup (get->filter_replacement);
      else
        filter = filter_term (get->filt_id);
      if (filter == NULL)
        SEND_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("get_aggregates",
                             "Failed to find filter"));
    }
  else
    filter = NULL;

  manage_filter_controls (filter ? filter : get->filter,
                          &first, NULL, &sort_field, &sort_order);

  if (filter || get->filter)
    {
      gchar *new_filter;
      new_filter = manage_clean_filter (filter ? filter : get->filter);
      g_free (filter);
      if ((strcmp (type, "task") == 0)
          && (filter_term_value (new_filter, "apply_overrides")
              == NULL))
        {
          filter = new_filter;
          new_filter = g_strdup_printf ("apply_overrides=%i %s",
                                        APPLY_OVERRIDES_DEFAULT,
                                        filter);
          g_free (filter);
        }
      filter = new_filter;
    }
  else
    filter = manage_clean_filter ("");

  type_many = g_string_new (type);

  if (strcmp (type, "info") != 0)
    g_string_append (type_many, "s");

  buffer_get_filter_xml (xml, type, get, filter, NULL);

  g_string_append (xml, "</get_aggregates_response>");

  for (index = 0; index < data_columns->len; index++)
    g_free (g_array_index (data_columns, gchar*, index));
  g_array_free (data_columns, TRUE);
  for (index = 0; index < data_column_types->len; index++)
    g_free (g_array_index (data_column_types, gchar*, index));
  g_array_free (data_column_types, TRUE);
  for (index = 0; index < sort_data->len; index++)
    sort_data_free (g_array_index (sort_data, sort_data_t*, index));
  g_array_free (sort_data, TRUE);
  g_array_free (c_sums, TRUE);

  SEND_TO_CLIENT_OR_FAIL (xml->str);

  cleanup_iterator (&aggregate);
  g_string_free (xml, TRUE);
  get_aggregates_data_reset (get_aggregates_data);
  set_client_state (CLIENT_AUTHENTIC);
}

/**
 * @brief Handle end of GET_ALERTS element.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 */
static void
handle_get_alerts (gmp_parser_t *gmp_parser, GError **error)
{
  iterator_t alerts;
  int count, filtered, ret, first;

  INIT_GET (alert, Alert);

  ret = init_alert_iterator (&alerts, &get_alerts_data->get);
  if (ret)
    {
      switch (ret)
        {
          case 1:
            if (send_find_error_to_client ("get_alerts", "alert",
                                           get_alerts_data->get.id,
                                           gmp_parser))
              {
                error_send_to_client (error);
                return;
              }
            break;
          case 2:
            if (send_find_error_to_client
                  ("get_alerts", "filter", get_alerts_data->get.filt_id,
                   gmp_parser))
              {
                error_send_to_client (error);
                return;
              }
            break;
          case -1:
            SEND_TO_CLIENT_OR_FAIL
              (XML_INTERNAL_ERROR ("get_alerts"));
            break;
        }
      get_alerts_data_reset (get_alerts_data);
      set_client_state (CLIENT_AUTHENTIC);
      return;
    }

  SEND_GET_START ("alert");
  while (1)
    {
      iterator_t data;
      char *filter_uuid;
      int notice, message, has_secinfo_type;
      const char *method;

      ret = get_next (&alerts, &get_alerts_data->get, &first,
                      &count, init_alert_iterator);
      if (ret == 1)
        break;
      if (ret == -1)
        {
          internal_error_send_to_client (error);
          return;
        }
      SEND_GET_COMMON (alert, &get_alerts_data->get,
                        &alerts);

      /* Filter. */

      filter_uuid = alert_iterator_filter_uuid (&alerts);
      if (filter_uuid)
        {
          SENDF_TO_CLIENT_OR_FAIL ("<filter id=\"%s\">"
                                   "<name>%s</name>"
                                   "<trash>%i</trash>",
                                   filter_uuid,
                                   alert_iterator_filter_name (&alerts),
                                   alert_iterator_filter_trash (&alerts));
          if (alert_iterator_filter_readable (&alerts))
            SEND_TO_CLIENT_OR_FAIL ("</filter>");
          else
            SEND_TO_CLIENT_OR_FAIL ("<permissions/>"
                                    "</filter>");
        }

      /* Condition. */

      SENDF_TO_CLIENT_OR_FAIL ("<condition>%s",
                               alert_condition_name
                               (alert_iterator_condition (&alerts)));
      init_alert_data_iterator (&data, get_iterator_resource (&alerts),
                                get_alerts_data->get.trash,
                                "condition");
      while (next (&data))
        SENDF_TO_CLIENT_OR_FAIL ("<data>"
                                 "<name>%s</name>"
                                 "%s"
                                 "</data>",
                                 alert_data_iterator_name (&data),
                                 alert_data_iterator_data (&data));
      cleanup_iterator (&data);

      SEND_TO_CLIENT_OR_FAIL ("</condition>");

      /* Event. */

      SENDF_TO_CLIENT_OR_FAIL ("<event>%s",
                                event_name (alert_iterator_event (&alerts)));
      init_alert_data_iterator (&data, get_iterator_resource (&alerts),
                                get_alerts_data->get.trash, "event");
      has_secinfo_type = 0;
      while (next (&data))
        {
          if (strcmp (alert_data_iterator_name (&data), "secinfo_type")
              == 0)
            has_secinfo_type = 1;
          SENDF_TO_CLIENT_OR_FAIL ("<data>"
                                   "<name>%s</name>"
                                   "%s"
                                   "</data>",
                                   alert_data_iterator_name (&data),
                                   alert_data_iterator_data (&data));
        }
      if ((alert_iterator_event (&alerts) == EVENT_NEW_SECINFO
            || alert_iterator_event (&alerts) == EVENT_UPDATED_SECINFO)
          && (has_secinfo_type == 0))
        SENDF_TO_CLIENT_OR_FAIL ("<data>"
                                 "<name>secinfo_type</name>"
                                 "NVT"
                                 "</data>");
      cleanup_iterator (&data);
      SEND_TO_CLIENT_OR_FAIL ("</event>");

      /* Method. */

      method = alert_method_name (alert_iterator_method (&alerts));
      SENDF_TO_CLIENT_OR_FAIL ("<method>%s", method);
      init_alert_data_iterator (&data, get_iterator_resource (&alerts),
                                get_alerts_data->get.trash, "method");
      notice = -1;
      message = 0;
      while (next (&data))
        {
          const char *name;
          name = alert_data_iterator_name (&data);
          if (strcmp (name, "notice") == 0)
            notice = atoi (alert_data_iterator_data (&data));
          else if (strcmp (method, "Email") == 0
                    && strcmp (name, "message") == 0)
            {
              if (strlen (alert_data_iterator_data (&data)) == 0)
                continue;
              message = 1;
            }

          if (strcmp (name, "scp_credential") == 0
              || strcmp (name, "verinice_server_credential") == 0)
            {
              // Username + Password credentials
              const char *credential_id;
              credential_t credential;
              credential_id = alert_data_iterator_data (&data);
              if (find_credential_with_permission (credential_id,
                                                   &credential,
                                                   "get_credentials"))
                {
                  abort ();
                }
              else if (credential == 0)
                {
                  SENDF_TO_CLIENT_OR_FAIL ("<data>"
                                           "<name>%s</name>"
                                           "%s"
                                           "</data>",
                                           name,
                                           credential_id);
                }
              else
                {
                  gchar *cred_name, *username;
                  cred_name = credential_name (credential);
                  username = credential_value (credential, "username");

                  SENDF_TO_CLIENT_OR_FAIL ("<data>"
                                           "<name>%s</name>"
                                           "<credential id=\"%s\">"
                                           "<name>%s</name>"
                                           "<login>%s</login>"
                                           "</credential>"
                                           "%s"
                                           "</data>",
                                           name,
                                           credential_id,
                                           cred_name,
                                           username,
                                           credential_id);

                  g_free (cred_name);
                  g_free (username);
                }
            }
          else
            {
              SENDF_TO_CLIENT_OR_FAIL ("<data>"
                                       "<name>%s</name>"
                                       "%s"
                                       "</data>",
                                       name,
                                       alert_data_iterator_data (&data));
            }
        }
      /* If there is no email message data, send the default. */
      if (strcmp (method, "Email") == 0
          && message == 0
          && (notice == 0 || notice == 2))
        SENDF_TO_CLIENT_OR_FAIL ("<data>"
                                 "<name>message</name>"
                                 "%s"
                                 "</data>",
                                 notice == 0
                                  ? ALERT_MESSAGE_INCLUDE
                                  : ALERT_MESSAGE_ATTACH);
      cleanup_iterator (&data);
      SEND_TO_CLIENT_OR_FAIL ("</method>");

      if (get_alerts_data->tasks)
        {
          iterator_t tasks;

          SEND_TO_CLIENT_OR_FAIL ("<tasks>");
          init_alert_task_iterator (&tasks,
                                    get_iterator_resource (&alerts), 0);
          while (next (&tasks))
            {
              SENDF_TO_CLIENT_OR_FAIL ("<task id=\"%s\">"
                                       "<name>%s</name>",
                                       alert_task_iterator_uuid (&tasks),
                                       alert_task_iterator_name (&tasks));

              if (alert_task_iterator_readable (&tasks))
                SEND_TO_CLIENT_OR_FAIL ("</task>");
              else
                SEND_TO_CLIENT_OR_FAIL ("<permissions/>"
                                        "</task>");
            }
          cleanup_iterator (&tasks);
          SEND_TO_CLIENT_OR_FAIL ("</tasks>");
        }

      SENDF_TO_CLIENT_OR_FAIL ("<active>%i</active>"
                               "</alert>",
                               alert_iterator_active (&alerts));
      count++;
    }
  cleanup_iterator (&alerts);
  filtered = get_alerts_data->get.id
              ? 1
              : alert_count (&get_alerts_data->get);
  SEND_GET_END ("alert", &get_alerts_data->get, count, filtered);

  get_alerts_data_reset (get_alerts_data);
  set_client_state (CLIENT_AUTHENTIC);
}

/**
 * @brief Handle end of GET_ASSETS element.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 */
static void
handle_get_assets (gmp_parser_t *gmp_parser, GError **error)
{
  iterator_t assets;
  int count, first, filtered, ret;
  int (*init_asset_iterator) (iterator_t *, const get_data_t *);
  int (*asset_count) (const get_data_t *get);

  if (acl_user_may ("get_assets") == 0)
    {
      SEND_TO_CLIENT_OR_FAIL
        (XML_ERROR_SYNTAX ("get_assets",
                           "Permission denied"));
      get_assets_data_reset (get_assets_data);
      set_client_state (CLIENT_AUTHENTIC);
      return;
    }

  if (get_assets_data->type == NULL)
    {
      SEND_TO_CLIENT_OR_FAIL
        (XML_ERROR_SYNTAX ("get_assets",
                           "No type specified."));
      get_assets_data_reset (get_assets_data);
      set_client_state (CLIENT_AUTHENTIC);
      return;
    }

  /* Set type specific functions. */
  if (g_strcmp0 ("host", get_assets_data->type) == 0)
    {
      INIT_GET (asset, Host);
      init_asset_iterator = init_asset_host_iterator;
      asset_count = asset_host_count;
      get_assets_data->get.subtype = g_strdup ("host");
    }
  else if (g_strcmp0 ("os", get_assets_data->type) == 0)
    {
      INIT_GET (asset, Operating System);
      init_asset_iterator = init_asset_os_iterator;
      asset_count = asset_os_count;
      get_assets_data->get.subtype = g_strdup ("os");
    }
  else
    {
      if (send_find_error_to_client ("get_assets", "type",
                                     get_assets_data->type, gmp_parser))
        {
          error_send_to_client (error);
        }
      get_assets_data_reset (get_assets_data);
      set_client_state (CLIENT_AUTHENTIC);
      return;
    }

  ret = init_asset_iterator (&assets, &get_assets_data->get);
  if (ret)
    {
      switch (ret)
        {
        case 1:
          if (send_find_error_to_client ("get_assets", "type",
                                         get_assets_data->type,
                                         gmp_parser))
            {
              error_send_to_client (error);
              return;
            }
          break;
        case 2:
          if (send_find_error_to_client
              ("get_assets", "filter", get_assets_data->get.filt_id,
               gmp_parser))
            {
              error_send_to_client (error);
              return;
            }
          break;
        case -1:
          SEND_TO_CLIENT_OR_FAIL
            (XML_INTERNAL_ERROR ("get_assets"));
          break;
        }
      get_assets_data_reset (get_assets_data);
      set_client_state (CLIENT_AUTHENTIC);
      return;
    }

  count = 0;
  manage_filter_controls (get_assets_data->get.filter, &first, NULL, NULL, NULL);
  SEND_GET_START ("asset");
  while (next (&assets))
    {
      GString *result;
      iterator_t identifiers;
      resource_t asset;
      gchar *routes_xml;

      asset = get_iterator_resource (&assets);
      /* Assets are currently always writable. */
      if (send_get_common ("asset", &get_assets_data->get, &assets,
                           gmp_parser->client_writer,
                           gmp_parser->client_writer_data,
                           asset_iterator_writable (&assets),
                           asset_iterator_in_use (&assets)))
        {
          error_send_to_client (error);
          return;
        }

      result = g_string_new ("");

      /* Information depending on type. */

      if (g_strcmp0 ("host", get_assets_data->type) == 0)
        {
          xml_string_append (result, "<identifiers>");
          init_host_identifier_iterator (&identifiers,
                                          get_iterator_resource (&assets),
                                          0, NULL);
          while (next (&identifiers))
            {
              const char *source_type;
              gchar *name;

              source_type = host_identifier_iterator_source_type
                              (&identifiers);
              if (strcmp (source_type, "User") == 0)
                name = user_name (host_identifier_iterator_source_id
                                    (&identifiers));
              else
                name = NULL;

              xml_string_append (result,
                                 "<identifier id=\"%s\">"
                                 "<name>%s</name>"
                                 "<value>%s</value>"
                                 "<creation_time>%s</creation_time>"
                                 "<modification_time>%s</modification_time>"
                                 "<source id=\"%s\">"
                                 "<type>%s</type>"
                                 "<data>%s</data>"
                                 "<deleted>%i</deleted>"
                                 "<name>%s</name>"
                                 "</source>",
                                 get_iterator_uuid (&identifiers),
                                 get_iterator_name (&identifiers),
                                 host_identifier_iterator_value (&identifiers),
                                 get_iterator_creation_time (&identifiers),
                                 get_iterator_modification_time (&identifiers),
                                 host_identifier_iterator_source_id
                                  (&identifiers),
                                 source_type,
                                 host_identifier_iterator_source_data
                                  (&identifiers),
                                 host_identifier_iterator_source_orphan
                                  (&identifiers),
                                 name ? name : "");

              g_free (name);

              if (strcmp (get_iterator_name (&identifiers), "OS") == 0)
                xml_string_append (result,
                                   "<os id=\"%s\">"
                                   "<title>%s</title>"
                                   "</os>",
                                   host_identifier_iterator_os_id
                                    (&identifiers),
                                   host_identifier_iterator_os_title
                                    (&identifiers));

              xml_string_append (result, "</identifier>");
            }
          cleanup_iterator (&identifiers);
          xml_string_append (result, "</identifiers>");
        }

      g_string_append_printf (result, "<type>%s</type>",
                              get_assets_data->type);
      g_string_append_printf (result, "<%s>", get_assets_data->type);

      if (g_strcmp0 ("os", get_assets_data->type) == 0)
        {
          iterator_t os_hosts;
          const char *latest, *highest, *average;

          latest = asset_os_iterator_latest_severity (&assets);
          highest = asset_os_iterator_highest_severity (&assets);
          average = asset_os_iterator_average_severity (&assets);
          g_string_append_printf (result,
                                  "<latest_severity>"
                                  "<value>%s</value>"
                                  "</latest_severity>"
                                  "<highest_severity>"
                                  "<value>%s</value>"
                                  "</highest_severity>"
                                  "<average_severity>"
                                  "<value>%s</value>"
                                  "</average_severity>",
                                  latest ? latest : "",
                                  highest ? highest : "",
                                  average ? average : "");

          g_string_append_printf (result,
                                  "<title>%s</title>"
                                  "<installs>%i</installs>"
                                  "<hosts>"
                                  "%i",
                                  asset_os_iterator_title (&assets),
                                  asset_os_iterator_installs (&assets),
                                  asset_os_iterator_installs (&assets));
          init_os_host_iterator (&os_hosts,
                                  get_iterator_resource (&assets));
          while (next (&os_hosts))
            {
              const char *severity;
              severity = os_host_iterator_severity (&os_hosts);
              g_string_append_printf (result,
                                      "<asset id=\"%s\">"
                                      "<name>%s</name>"
                                      "<severity>"
                                      "<value>%s</value>"
                                      "</severity>"
                                      "</asset>",
                                      get_iterator_uuid (&os_hosts),
                                      get_iterator_name (&os_hosts),
                                      severity ? severity : "");
            }
          cleanup_iterator (&os_hosts);
          g_string_append_printf (result, "</hosts>");
        }
      else if (g_strcmp0 ("host", get_assets_data->type) == 0)
        {
          const char *severity;
          iterator_t details;

          severity = asset_host_iterator_severity (&assets);
          g_string_append_printf (result,
                                  "<severity>"
                                  "<value>%s</value>"
                                  "</severity>",
                                  severity ? severity : "");

          init_host_detail_iterator (&details,
                                      get_iterator_resource (&assets));
          while (next (&details))
            g_string_append_printf (result,
                                    "<detail>"
                                    "<name>%s</name>"
                                    "<value>%s</value>"
                                    "<source id=\"%s\">"
                                    "<type>%s</type>"
                                    "</source>"
                                    "</detail>",
                                    host_detail_iterator_name
                                      (&details),
                                    host_detail_iterator_value
                                      (&details),
                                    host_detail_iterator_source_id
                                      (&details),
                                    host_detail_iterator_source_type
                                      (&details));
          cleanup_iterator (&details);

          if (get_assets_data->details || get_assets_data->get.id)
            {
              routes_xml = host_routes_xml (asset);
              g_string_append (result, routes_xml);
              g_free (routes_xml);
            }
        }

      g_string_append_printf (result,
                              "</%s>"
                              "</asset>",
                              get_assets_data->type);
      SEND_TO_CLIENT_OR_FAIL (result->str);
      count++;
      g_string_free (result, TRUE);
    }
  cleanup_iterator (&assets);

  if (get_assets_data->details == 1)
    SEND_TO_CLIENT_OR_FAIL ("<details>1</details>");

  filtered = get_assets_data->get.id
              ? 1
              : asset_count (&get_assets_data->get);

  SEND_GET_END ("asset", &get_assets_data->get, count, filtered);

  get_assets_data_reset (get_assets_data);
  set_client_state (CLIENT_AUTHENTIC);
}

/**
 * @brief Handle end of GET_CONFIGS element.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 */
static void
handle_get_configs (gmp_parser_t *gmp_parser, GError **error)
{
  iterator_t configs;
  int ret, filtered, first, count;

  INIT_GET (config, Config);
  ret = init_config_iterator (&configs, &get_configs_data->get);
  if (ret)
    {
      switch (ret)
        {
          case 1:
            if (send_find_error_to_client
                 ("get_configs", "config", get_configs_data->get.id,
                  gmp_parser))
              {
                error_send_to_client (error);
                return;
              }
            break;
          case 2:
            if (send_find_error_to_client
                 ("get_configs", "filter", get_configs_data->get.filt_id,
                  gmp_parser))
              {
                error_send_to_client (error);
                return;
              }
            break;
          case -1:
            SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_configs"));
            break;
        }
      get_configs_data_reset (get_configs_data);
      set_client_state (CLIENT_AUTHENTIC);
      return;
    }

  SEND_GET_START ("config");
  while (1)
    {
      int config_nvts_growing, config_families_growing;
      const char *selector, *usage_type;
      config_t config;

      ret = get_next (&configs, &get_configs_data->get, &first,
                      &count, init_config_iterator);
      if (ret == 1)
        break;
      if (ret == -1)
        {
          internal_error_send_to_client (error);
          return;
        }
      SEND_GET_COMMON (config, &get_configs_data->get, &configs);

      /** @todo This should really be an nvt_selector_t. */
      selector = config_iterator_nvt_selector (&configs);
      config = get_iterator_resource (&configs);
      config_nvts_growing = config_iterator_nvts_growing (&configs);
      usage_type = config_iterator_usage_type (&configs);
      config_families_growing = config_iterator_families_growing
                                 (&configs);

      SENDF_TO_CLIENT_OR_FAIL ("<family_count>"
                               "%i<growing>%i</growing>"
                               "</family_count>"
                               /* The number of NVT's selected
                                * by the selector. */
                               "<nvt_count>"
                               "%i<growing>%i</growing>"
                               "</nvt_count>"
                               "<type>0</type>"
                               "<usage_type>%s</usage_type>"
                               "<predefined>%i</predefined>",
                               config_iterator_family_count (&configs),
                               config_families_growing,
                               config_iterator_nvt_count (&configs),
                               config_nvts_growing,
                               usage_type,
                               config_iterator_predefined (&configs));

      if (get_configs_data->families || get_configs_data->get.details)
        {
          iterator_t families;
          int max_nvt_count = 0, known_nvt_count = 0;

          SENDF_TO_CLIENT_OR_FAIL ("<families>");
          init_family_iterator (&families, config_families_growing, selector,
                                1);
          while (next (&families))
            {
              int family_growing, family_max;
              int family_selected_count;
              const char *family;

              family = family_iterator_name (&families);
              if (family)
                {
                  family_growing = nvt_selector_family_growing
                                    (selector, family, config_families_growing);
                  family_max = family_nvt_count (family);
                  family_selected_count
                    = nvt_selector_nvt_count (selector, family, family_growing);
                  known_nvt_count += family_selected_count;
                }
              else
                {
                  /* The family can be NULL if an RC adds an
                   * NVT to a config and the NVT is missing
                   * from the NVT cache. */
                  family_growing = 0;
                  family_max = -1;
                  family_selected_count = nvt_selector_nvt_count
                                           (selector, NULL, 0);
                }

              SENDF_TO_CLIENT_OR_FAIL
               ("<family>"
                "<name>%s</name>"
                /* The number of selected NVT's. */
                "<nvt_count>%i</nvt_count>"
                /* The total number of NVT's in the family. */
                "<max_nvt_count>%i</max_nvt_count>"
                "<growing>%i</growing>"
                "</family>",
                family ? family : "",
                family_selected_count,
                family_max,
                family_growing);
              if (family_max > 0)
                max_nvt_count += family_max;
            }
          cleanup_iterator (&families);
          SENDF_TO_CLIENT_OR_FAIL
           ("</families>"
            /* The total number of NVT's in all the
             * families for selector selects at least one
             * NVT. */
            "<max_nvt_count>%i</max_nvt_count>"
            /* Total number of selected known NVT's. */
            "<known_nvt_count>"
            "%i"
            "</known_nvt_count>",
            max_nvt_count,
            known_nvt_count);
        }

      if (get_configs_data->preferences || get_configs_data->get.details)
        {
          iterator_t prefs;

          assert (config);

          SEND_TO_CLIENT_OR_FAIL ("<preferences>");

          /* Send NVT timeout preferences where a timeout has been
           * specified. */
          init_config_timeout_iterator (&prefs, config);
          while (next (&prefs))
            {
              const char *timeout;

              timeout = config_timeout_iterator_value (&prefs);

              if (timeout && strlen (timeout))
                SENDF_TO_CLIENT_OR_FAIL
                 ("<preference>"
                  "<nvt oid=\"%s\">"
                  "<name>%s</name>"
                  "</nvt>"
                  "<id>0</id>"
                  "<name>Timeout</name>"
                  "<type>entry</type>"
                  "<value>%s</value>"
                  "</preference>",
                  config_timeout_iterator_oid (&prefs),
                  config_timeout_iterator_nvt_name (&prefs),
                  timeout);
            }
          cleanup_iterator (&prefs);

          init_nvt_preference_iterator (&prefs, NULL);
          while (next (&prefs))
            {
              GString *buffer = g_string_new ("");
              buffer_config_preference_xml (buffer, &prefs, config, 1);
              SEND_TO_CLIENT_OR_FAIL (buffer->str);
              g_string_free (buffer, TRUE);
            }
          cleanup_iterator (&prefs);

          SEND_TO_CLIENT_OR_FAIL ("</preferences>");
        }

      if (get_configs_data->get.details)
        {
          iterator_t selectors;

          SEND_TO_CLIENT_OR_FAIL ("<nvt_selectors>");

          init_nvt_selector_iterator (&selectors, NULL, config,
                                      NVT_SELECTOR_TYPE_ANY);
          while (next (&selectors))
            {
              int type = nvt_selector_iterator_type (&selectors);
              SENDF_TO_CLIENT_OR_FAIL
               ("<nvt_selector>"
                "<name>%s</name>"
                "<include>%i</include>"
                "<type>%i</type>"
                "<family_or_nvt>%s</family_or_nvt>"
                "</nvt_selector>",
                nvt_selector_iterator_name (&selectors),
                nvt_selector_iterator_include (&selectors),
                type,
                (type == NVT_SELECTOR_TYPE_ALL
                  ? "" : nvt_selector_iterator_nvt (&selectors)));
            }
          cleanup_iterator (&selectors);

          SEND_TO_CLIENT_OR_FAIL ("</nvt_selectors>");
        }

      if (get_configs_data->tasks)
        {
          iterator_t tasks;

          SEND_TO_CLIENT_OR_FAIL ("<tasks>");
          init_config_task_iterator
           (&tasks, get_iterator_resource (&configs), 0);
          while (next (&tasks))
            {
              if (config_task_iterator_readable (&tasks) == 0)
                /* Only show tasks the user may see. */
                continue;

              SENDF_TO_CLIENT_OR_FAIL
               ("<task id=\"%s\">"
                "<name>%s</name>",
                config_task_iterator_uuid (&tasks),
                config_task_iterator_name (&tasks));
              if (config_task_iterator_readable (&tasks))
                SEND_TO_CLIENT_OR_FAIL ("</task>");
              else
                SEND_TO_CLIENT_OR_FAIL ("<permissions/>"
                                        "</task>");
            }
          cleanup_iterator (&tasks);
          SEND_TO_CLIENT_OR_FAIL ("</tasks>");
        }

      SEND_TO_CLIENT_OR_FAIL ("</config>");
      count++;
    }
  cleanup_iterator (&configs);
  filtered = get_configs_data->get.id
              ? 1 : config_count (&get_configs_data->get);
  SEND_GET_END ("config", &get_configs_data->get, count, filtered);

  get_configs_data_reset (get_configs_data);
  set_client_state (CLIENT_AUTHENTIC);
}

/**
 * @brief Handle end of GET_CREDENTIALS element.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 */
static void
handle_get_credentials (gmp_parser_t *gmp_parser, GError **error)
{
  iterator_t credentials;
  int count, filtered, ret, first;
  credential_format_t format;
  char *data_format;

  data_format = get_credentials_data->format;
  if (data_format)
    {
      if (strlen (data_format))
        {
          if (strcasecmp (data_format, "key") == 0)
            format = CREDENTIAL_FORMAT_KEY;
          else if (strcasecmp (data_format, "rpm") == 0)
            format = CREDENTIAL_FORMAT_RPM;
          else if (strcasecmp (data_format, "deb") == 0)
            format = CREDENTIAL_FORMAT_DEB;
          else if (strcasecmp (data_format, "exe") == 0)
            format = CREDENTIAL_FORMAT_EXE;
          else if (strcasecmp (data_format, "pem") == 0)
            format = CREDENTIAL_FORMAT_PEM;
          else
            format = CREDENTIAL_FORMAT_ERROR;
        }
      else
        format = CREDENTIAL_FORMAT_NONE;
    }
  else
    format = CREDENTIAL_FORMAT_NONE;

  if (format == CREDENTIAL_FORMAT_ERROR)
    SEND_TO_CLIENT_OR_FAIL
      (XML_ERROR_SYNTAX ("get_credentials",
                         "Format attribute should"
                         " be 'key', 'rpm', 'deb', 'exe' or 'pem'"));

  INIT_GET (credential, Credential);

  ret = init_credential_iterator (&credentials,
                                  &get_credentials_data->get);
  if (ret)
    {
      switch (ret)
        {
          case 1:
            if (send_find_error_to_client ("get_credentials",
                                           "credential",
                                           get_credentials_data->get.id,
                                           gmp_parser))
              {
                error_send_to_client (error);
                return;
              }
            break;
          case 2:
            if (send_find_error_to_client ("get_credentials",
                                           "filter",
                                           get_credentials_data->get.filt_id,
                                           gmp_parser))
              {
                error_send_to_client (error);
                return;
              }
            break;
          case -1:
            SEND_TO_CLIENT_OR_FAIL
              (XML_INTERNAL_ERROR ("get_credentials"));
            break;
        }
      get_credentials_data_reset (get_credentials_data);
      set_client_state (CLIENT_AUTHENTIC);
      return;
    }

  SEND_GET_START("credential");
  while (1)
    {
      const char *private_key, *public_key, *login, *type, *cert;
      gchar *formats_xml;

      ret = get_next (&credentials, &get_credentials_data->get,
                      &first, &count, init_credential_iterator);
      if (ret == 1)
        break;
      if (ret == -1)
        {
          internal_error_send_to_client (error);
          return;
        }

      SEND_GET_COMMON (credential, &get_credentials_data->get, &credentials);
      private_key = credential_iterator_private_key (&credentials);
      public_key = credential_iterator_public_key (&credentials);
      login = credential_iterator_login (&credentials);
      type = credential_iterator_type (&credentials);
      cert = credential_iterator_certificate (&credentials);

      SENDF_TO_CLIENT_OR_FAIL
       ("<allow_insecure>%d</allow_insecure>"
        "<login>%s</login>"
        "<type>%s</type>"
        "<full_type>%s</full_type>",
        credential_iterator_allow_insecure (&credentials),
        login ? login : "",
        type ? type : "",
        type ? credential_full_type (type) : "");

      formats_xml = credential_iterator_formats_xml (&credentials);
      SEND_TO_CLIENT_OR_FAIL (formats_xml);
      g_free (formats_xml);

      if (type && (strcmp (type, "snmp") == 0))
        {
          const char *auth_algorithm, *privacy_algorithm;
          auth_algorithm
            = credential_iterator_auth_algorithm (&credentials);
          privacy_algorithm
            = credential_iterator_privacy_algorithm (&credentials);

          SENDF_TO_CLIENT_OR_FAIL
           ("<auth_algorithm>%s</auth_algorithm>"
            "<privacy><algorithm>%s</algorithm></privacy>",
            auth_algorithm ? auth_algorithm : "",
            privacy_algorithm ? privacy_algorithm : "");
        }

      if (cert && get_credentials_data->get.details)
        {
          /* get certificate info */
          time_t activation_time, expiration_time;
          gchar *activation_time_str, *expiration_time_str;
          gchar *md5_fingerprint, *issuer;

          get_certificate_info (cert,
                                -1,
                                &activation_time,
                                &expiration_time,
                                &md5_fingerprint,
                                NULL,   /* sha256_fingerprint */
                                NULL,   /* subject */
                                &issuer,
                                NULL,   /* serial */
                                NULL);  /* certificate_format */

          activation_time_str = certificate_iso_time (activation_time);
          expiration_time_str = certificate_iso_time (expiration_time);
          SENDF_TO_CLIENT_OR_FAIL
           ("<certificate_info>"
            "<time_status>%s</time_status>"
            "<activation_time>%s</activation_time>"
            "<expiration_time>%s</expiration_time>"
            "<md5_fingerprint>%s</md5_fingerprint>"
            "<issuer>%s</issuer>"
            "</certificate_info>",
            certificate_time_status (activation_time, expiration_time),
            activation_time_str,
            expiration_time_str,
            md5_fingerprint ? md5_fingerprint : "",
            issuer ? issuer : "");
          g_free (activation_time_str);
          g_free (expiration_time_str);
          g_free (md5_fingerprint);
          g_free (issuer);
        }

      switch (format)
        {
          char *package;

          case CREDENTIAL_FORMAT_KEY:
            {
              if (public_key && strcmp (public_key, ""))
                {
                  SENDF_TO_CLIENT_OR_FAIL
                    ("<public_key>%s</public_key>", public_key);
                }
              else
                {
                  char *pub;
                  const char *pass;

                  pass = credential_iterator_password (&credentials);
                  pub = gvm_ssh_public_from_private (private_key, pass);
                  SENDF_TO_CLIENT_OR_FAIL
                    ("<public_key>%s</public_key>", pub ?: "");
                  g_free (pub);
                }
              break;
            }
          case CREDENTIAL_FORMAT_RPM:
            package = credential_iterator_rpm (&credentials);
            SENDF_TO_CLIENT_OR_FAIL
              ("<package format=\"rpm\">%s</package>", package ?: "");
            g_free (package);
            break;
          case CREDENTIAL_FORMAT_DEB:
            package = credential_iterator_deb (&credentials);
            SENDF_TO_CLIENT_OR_FAIL
              ("<package format=\"deb\">%s</package>", package ?: "");
            g_free (package);
            break;
          case CREDENTIAL_FORMAT_EXE:
            package = credential_iterator_exe (&credentials);
            SENDF_TO_CLIENT_OR_FAIL
              ("<package format=\"exe\">%s</package>", package ?: "");
            g_free (package);
            break;
          case CREDENTIAL_FORMAT_PEM:
            {
              SENDF_TO_CLIENT_OR_FAIL
                ("<certificate>%s</certificate>", cert ?: "");
              break;
            }
          case CREDENTIAL_FORMAT_NONE:
            break;
          default:
            g_warning ("%s: Unexpected credential format.", __func__);
        }

      if (get_credentials_data->scanners)
        {
          iterator_t scanners;

          SENDF_TO_CLIENT_OR_FAIL ("<scanners>");
          init_credential_scanner_iterator
            (&scanners, get_iterator_resource (&credentials), 0);
          while (next (&scanners))
            {
              SENDF_TO_CLIENT_OR_FAIL
               ("<scanner id=\"%s\">"
                "<name>%s</name>",
                credential_scanner_iterator_uuid (&scanners),
                credential_scanner_iterator_name (&scanners));
              if (credential_scanner_iterator_readable (&scanners))
                SEND_TO_CLIENT_OR_FAIL ("</scanner>");
              else
                SEND_TO_CLIENT_OR_FAIL ("<permissions/>"
                                        "</scanner>");
            }
          cleanup_iterator (&scanners);

          SEND_TO_CLIENT_OR_FAIL ("</scanners>");
        }

      if (get_credentials_data->targets)
        {
          iterator_t targets;

          SENDF_TO_CLIENT_OR_FAIL ("<targets>");
          init_credential_target_iterator
            (&targets, get_iterator_resource (&credentials), 0);
          while (next (&targets))
            {
              SENDF_TO_CLIENT_OR_FAIL
               ("<target id=\"%s\">"
                "<name>%s</name>",
                credential_target_iterator_uuid (&targets),
                credential_target_iterator_name (&targets));
              if (credential_target_iterator_readable (&targets))
                SEND_TO_CLIENT_OR_FAIL ("</target>");
              else
                SEND_TO_CLIENT_OR_FAIL ("<permissions/>"
                                        "</target>");
            }
          cleanup_iterator (&targets);

          SEND_TO_CLIENT_OR_FAIL ("</targets>");
        }

      SEND_TO_CLIENT_OR_FAIL ("</credential>");
      count++;
    }

  cleanup_iterator (&credentials);
  filtered = get_credentials_data->get.id
              ? 1
              : credential_count (&get_credentials_data->get);
  SEND_GET_END ("credential", &get_credentials_data->get,
                count, filtered);
  get_credentials_data_reset (get_credentials_data);
  set_client_state (CLIENT_AUTHENTIC);
}

/**
 * @brief Get a single feed.
 *
 * @param[in]  feed_type  Feed type.
 *
 * @return Name of feed type.
 */
static const char*
feed_type_name (int feed_type)
{
  switch (feed_type)
    {
      case NVT_FEED:
        return "NVT";
      case CERT_FEED:
        return "CERT";
      case SCAP_FEED:
        return "SCAP";
      case GVMD_DATA_FEED:
        return "GVMD_DATA";
      default:
        return "Error";
    }
}

/**
 * @brief Gets the status and timestamp of a feed lockfile.
 *
 * @param[in]  lockfile_name  Path to the lockfile.
 * @param[out] timestamp      Optional output o timestamp string.
 *
 * @return 0 lockfile was not locked, 1 lockfile was locked.
 */
static int
get_feed_lock_status (const char *lockfile_name, gchar **timestamp)
{
  mode_t old_umask;
  int lockfile;
  int ret;

  if (timestamp)
    *timestamp = NULL;
  ret = 0;

  old_umask = umask(0);
  lockfile = open (lockfile_name,
                   O_RDWR | O_CREAT,
                   /* "-rw-rw-r--" */
                   S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
  if (lockfile == -1)
    {
      g_warning ("%s: failed to open lock file '%s': %s", __func__,
                 lockfile_name, strerror (errno));
      umask (old_umask);
    }
  else
    {
      umask (old_umask);
      if (flock (lockfile, LOCK_EX | LOCK_NB))  /* Exclusive, Non blocking. */
        {
          if (errno == EWOULDBLOCK)
            {
              gchar *content;
              GError *file_error;

              /* File is locked, must be a sync in process. */

              ret = 1;

              if (!g_file_get_contents (lockfile_name, &content, NULL,
                                        &file_error))
                {
                  if (g_error_matches (file_error, G_FILE_ERROR,
                                       G_FILE_ERROR_NOENT)
                      || g_error_matches (file_error, G_FILE_ERROR,
                                          G_FILE_ERROR_ACCES))
                    {
                      g_error_free (file_error);
                    }
                  else
                    {
                      g_warning ("%s: %s", __func__, file_error->message);
                      g_error_free (file_error);
                    }
                }
              else
                {
                  gchar **lines;

                  lines = g_strsplit (content, "\n", 2);
                  g_free (content);
                  if (timestamp)
                    *timestamp = g_strdup(lines[0]);
                  g_strfreev (lines);
                }
            }
          else
            {
              g_warning ("%s: flock: %s", __func__, strerror (errno));
            }
        }
      else
        /* Got the lock, so no sync is in progress. */
        flock (lockfile, LOCK_UN);
    }

  if (close (lockfile))
    g_warning ("%s: failed to close lock file '%s': %s", __func__,
               lockfile_name, strerror (errno));

  return ret;
}

/**
 * @brief Template string for feed descriptions.
 *
 * The first and second placeholders are replaced with the name,
 * the third one with the vendor and the last one with the home URL.
 */
#define FEED_DESCRIPTION_TEMPLATE \
"This script synchronizes an NVT collection with the '%s'.\n" \
"The '%s' is provided by '%s'.\n"                             \
"Online information about this feed: '%s'.\n"

/**
 * @brief Template string for get_nvt_feed error messages.
 *
 * The placeholder is to be replaced by the actual message.
 */
#define GET_NVT_FEED_ERROR \
"<feed>"                      \
"<type>NVT</type>"            \
"<name></name>"               \
"<version></version>"         \
"<description></description>" \
"<sync_not_available>"        \
"<error>%s</error>"           \
"</sync_not_available>"       \
"</feed>"

/**
 * @brief Get NVT feed.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 */
static void
get_nvt_feed (gmp_parser_t *gmp_parser, GError **error)
{
  gchar *vts_version, *feed_name, *feed_vendor, *feed_home;

  vts_version = feed_name = feed_vendor = feed_home = NULL;

  switch (nvts_feed_info (&vts_version, &feed_name, &feed_vendor, &feed_home))
    {
      case 0:
        {
          gchar *feed_description;
          gchar *self_test_error_msg;
          int ret, lockfile_in_use, self_test_exit_error;

          feed_description = g_strdup_printf (FEED_DESCRIPTION_TEMPLATE,
                                              feed_name,
                                              feed_name,
                                              feed_vendor,
                                              feed_home);
          SENDF_TO_CLIENT_OR_FAIL
           ("<feed>"
            "<type>NVT</type>"
            "<name>%s</name>"
            "<version>%s</version>"
            "<description>%s</description>",
            feed_name,
            vts_version,
            feed_description);

          self_test_error_msg = NULL;
          lockfile_in_use = self_test_exit_error = 0;
          ret = nvts_check_feed (&lockfile_in_use,
                                 &self_test_exit_error, &self_test_error_msg);
          if (ret == 1)
            {
              SENDF_TO_CLIENT_OR_FAIL ("<sync_not_available>"
                                       "<error>"
                                       "Could not connect to scanner for"
                                       " sync lock status and self test."
                                       "</error>"
                                       "</sync_not_available>");
            }
          else if (ret)
            {
              SENDF_TO_CLIENT_OR_FAIL ("<sync_not_available>"
                                       "<error>"
                                       "Error getting sync lock status"
                                       " and self test."
                                       "</error>"
                                       "</sync_not_available>");
            }
          else
            {
              if (self_test_exit_error)
                SENDF_TO_CLIENT_OR_FAIL ("<sync_not_available>"
                                         "<error>%s</error>"
                                         "</sync_not_available>",
                                         self_test_error_msg
                                           ? self_test_error_msg : "");

              if (lockfile_in_use)
                SENDF_TO_CLIENT_OR_FAIL ("<currently_syncing>"
                                         "<timestamp></timestamp>"
                                         "</currently_syncing>");
            }
          g_free (self_test_error_msg);
          g_free (feed_description);

          SEND_TO_CLIENT_OR_FAIL ("</feed>");
        }
        break;
      case 1:
        SENDF_TO_CLIENT_OR_FAIL
           (GET_NVT_FEED_ERROR,
            "Could not connect to scanner to get feed info");
        break;
      case 2:
        SENDF_TO_CLIENT_OR_FAIL
           (GET_NVT_FEED_ERROR,
            "Scanner is still starting");
        break;
      default:
        SENDF_TO_CLIENT_OR_FAIL
           (GET_NVT_FEED_ERROR,
            "Error getting feed info from scanner");
    }

  g_free (vts_version);
  g_free (feed_name);
  g_free (feed_vendor);
  g_free (feed_home);
}

/**
 * @brief Parse feed info entity.
 *
 * @param[in]  entity       Config XML.
 * @param[in]  config_path  Path to config XML file.
 * @param[out] name         Name of feed.
 * @param[out] version      Version of feed.
 * @param[out] description  Description of feed.
 *
 * @return 0 success, -1 error.
 */
static int
get_feed_info_parse (entity_t entity, const gchar *config_path,
                     gchar **name, gchar **version, gchar **description)
{
  entity_t child;

  assert (name && version && description);

  child = entity_child (entity, "name");
  if (child == NULL)
    {
      g_warning ("%s: Missing name in '%s'", __func__, config_path);
      return -1;
    }
  *name = entity_text (child);

  child = entity_child (entity, "description");
  if (child == NULL)
    {
      g_warning ("%s: Missing description in '%s'",
                 __func__, config_path);
      return -1;
    }
  *description = entity_text (child);

  child = entity_child (entity, "version");
  if (child == NULL)
    {
      g_warning ("%s: Missing version in '%s'", __func__, config_path);
      return -1;
    }
  *version = entity_text (child);

  return 0;
}

/**
 * @brief Get feed info.
 *
 * @param[in]  feed_type         Type of feed.
 * @param[out] feed_name         Name of feed.
 * @param[out] feed_version      Version of feed.
 * @param[out] feed_description  Description of feed.
 *
 * @return 0 success, -1 error.
 */
static int
get_feed_info (int feed_type, gchar **feed_name, gchar **feed_version,
               gchar **feed_description)
{
  GError *error;
  const char *feed_data_dir;
  gchar *config_path, *xml, *name, *version, *description;
  gsize xml_len;
  entity_t entity;

  assert (feed_type == SCAP_FEED
          || feed_type == CERT_FEED
          || feed_type == GVMD_DATA_FEED);

  switch (feed_type)
    {
      case SCAP_FEED:
        feed_data_dir = GVM_SCAP_DATA_DIR;
        break;
      case CERT_FEED:
        feed_data_dir = GVM_CERT_DATA_DIR;
        break;
      case GVMD_DATA_FEED:
        feed_data_dir = GVMD_FEED_DIR;
        break;
      default :
        return -1;
    }

  config_path = g_build_filename (feed_data_dir,
                                  "feed.xml",
                                  NULL);
  g_debug ("%s: config_path: %s", __func__, config_path);

  /* Read the file in. */

  error = NULL;
  g_file_get_contents (config_path, &xml, &xml_len, &error);
  if (error)
    {
      g_warning ("%s: Failed to read '%s': %s",
                  __func__,
                 config_path,
                 error->message);
      g_error_free (error);
      g_free (config_path);
      return -1;
    }

  /* Parse it as XML. */

  if (parse_entity (xml, &entity))
    {
      g_warning ("%s: Failed to parse '%s'", __func__, config_path);
      g_free (config_path);
      return -1;
    }

  /* Get the report format properties from the XML. */

  if (get_feed_info_parse (entity, config_path, &name, &version, &description))
    {
      g_free (config_path);
      free_entity (entity);
      return -1;
    }
  g_free (config_path);

  if (feed_name)
    *feed_name = g_strdup (name);
  if (feed_description)
    *feed_description = g_strdup (description);
  if (feed_version)
    *feed_version = g_strdup (version);

  free_entity (entity);

  return 0;
}

/**
 * @brief Get a single feed.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 * @param[in]  feed_type    Type of feed.
 */
static void
get_feed (gmp_parser_t *gmp_parser, GError **error, int feed_type)
{
  gchar *feed_name, *feed_description, *feed_version;
  const char *lockfile_name;
  gchar *timestamp;

  if (feed_type == NVT_FEED)
    {
      get_nvt_feed (gmp_parser, error);
      return;
    }

  if (get_feed_info (feed_type, &feed_name, &feed_version, &feed_description))
    return;

  SENDF_TO_CLIENT_OR_FAIL
   ("<feed>"
    "<type>%s</type>"
    "<name>%s</name>"
    "<version>%s</version>"
    "<description>%s</description>",
    feed_type_name (feed_type),
    feed_name,
    feed_version,
    feed_description);

  lockfile_name = get_feed_lock_path ();

  if (get_feed_lock_status (lockfile_name, &timestamp))
    {
      SENDF_TO_CLIENT_OR_FAIL ("<currently_syncing>"
                               "<timestamp>%s</timestamp>"
                               "</currently_syncing>",
                               timestamp);
      g_free (timestamp);
    }

  g_free (feed_name);
  g_free (feed_version);
  g_free (feed_description);

  SEND_TO_CLIENT_OR_FAIL ("</feed>");
}

/**
 * @brief Handle end of GET_FEEDS element.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 */
static void
handle_get_feeds (gmp_parser_t *gmp_parser, GError **error)
{
  assert (current_credentials.username);

  if (acl_user_may ("get_feeds") == 0)
    {
      SEND_TO_CLIENT_OR_FAIL
       (XML_ERROR_SYNTAX ("get_feeds",
                          "Permission denied"));
      set_client_state (CLIENT_AUTHENTIC);
      return;
    }

  SEND_TO_CLIENT_OR_FAIL ("<get_feeds_response"
                          " status=\"" STATUS_OK "\""
                          " status_text=\"" STATUS_OK_TEXT "\">");

  if ((get_feeds_data->type == NULL)
      || (strcasecmp (get_feeds_data->type, "nvt") == 0))
    get_feed (gmp_parser, error, NVT_FEED);

  if ((get_feeds_data->type == NULL)
      || (strcasecmp (get_feeds_data->type, "scap") == 0))
    get_feed (gmp_parser, error, SCAP_FEED);

  if ((get_feeds_data->type == NULL)
      || (strcasecmp (get_feeds_data->type, "cert") == 0))
    get_feed (gmp_parser, error, CERT_FEED);

  if ((get_feeds_data->type == NULL)
      || (strcasecmp (get_feeds_data->type, "gvmd_data") == 0))
    get_feed (gmp_parser, error, GVMD_DATA_FEED);

  SEND_TO_CLIENT_OR_FAIL ("</get_feeds_response>");

  get_feeds_data_reset (get_feeds_data);
  set_client_state (CLIENT_AUTHENTIC);
}

/**
 * @brief Handle end of GET_FILTERS element.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 */
static void
handle_get_filters (gmp_parser_t *gmp_parser, GError **error)
{
  iterator_t filters;
  int count, filtered, ret, first;

  INIT_GET (filter, Filter);

  ret = init_filter_iterator (&filters, &get_filters_data->get);
  if (ret)
    {
      switch (ret)
        {
          case 1:
            if (send_find_error_to_client ("get_filters", "filter",
                                           get_filters_data->get.id,
                                           gmp_parser))
              {
                error_send_to_client (error);
                return;
              }
            break;
          case 2:
            if (send_find_error_to_client
                  ("get_filters", "filter",
                   get_filters_data->get.filt_id, gmp_parser))
              {
                error_send_to_client (error);
                return;
              }
            break;
          case -1:
            SEND_TO_CLIENT_OR_FAIL
              (XML_INTERNAL_ERROR ("get_filters"));
            break;
        }
      get_filters_data_reset (get_filters_data);
      set_client_state (CLIENT_AUTHENTIC);
      return;
    }

  SEND_GET_START ("filter");
  while (1)
    {
      ret = get_next (&filters, &get_filters_data->get, &first, &count,
                      init_filter_iterator);
      if (ret == 1)
        break;
      if (ret == -1)
        {
          internal_error_send_to_client (error);
          return;
        }

      SEND_GET_COMMON (filter, &get_filters_data->get, &filters);

      SENDF_TO_CLIENT_OR_FAIL ("<type>%s</type>"
                               "<term>%s</term>",
                               filter_iterator_type (&filters),
                               filter_iterator_term (&filters));

      if (get_filters_data->alerts)
        {
          iterator_t alerts;

          SEND_TO_CLIENT_OR_FAIL ("<alerts>");
          init_filter_alert_iterator (&alerts,
                                      get_iterator_resource
                                        (&filters));
          while (next (&alerts))
            {
              SENDF_TO_CLIENT_OR_FAIL
               ("<alert id=\"%s\">"
                "<name>%s</name>",
                filter_alert_iterator_uuid (&alerts),
                filter_alert_iterator_name (&alerts));
              if (filter_alert_iterator_readable (&alerts))
                SEND_TO_CLIENT_OR_FAIL ("</alert>");
              else
                SEND_TO_CLIENT_OR_FAIL ("<permissions/>"
                                        "</alert>");
            }
          cleanup_iterator (&alerts);
          SEND_TO_CLIENT_OR_FAIL ("</alerts>");
        }

      SEND_TO_CLIENT_OR_FAIL ("</filter>");

      count++;
    }
  cleanup_iterator (&filters);
  filtered = get_filters_data->get.id
              ? 1
              : filter_count (&get_filters_data->get);
  SEND_GET_END ("filter", &get_filters_data->get, count, filtered);

  get_filters_data_reset (get_filters_data);
  set_client_state (CLIENT_AUTHENTIC);
}

/**
 * @brief Handle end of GET_GROUPS element.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 */
static void
handle_get_groups (gmp_parser_t *gmp_parser, GError **error)
{
  iterator_t groups;
  int count, filtered, ret, first;

  INIT_GET (group, Group);

  ret = init_group_iterator (&groups, &get_groups_data->get);
  if (ret)
    {
      switch (ret)
        {
          case 1:
            if (send_find_error_to_client ("get_groups", "group",
                                           get_groups_data->get.id,
                                           gmp_parser))
              {
                error_send_to_client (error);
                return;
              }
            break;
          case 2:
            if (send_find_error_to_client
                  ("get_groups", "filter", get_groups_data->get.filt_id,
                   gmp_parser))
              {
                error_send_to_client (error);
                return;
              }
            break;
          case -1:
            SEND_TO_CLIENT_OR_FAIL
              (XML_INTERNAL_ERROR ("get_groups"));
            break;
        }
      get_groups_data_reset (get_groups_data);
      set_client_state (CLIENT_AUTHENTIC);
      return;
    }

  SEND_GET_START ("group");
  while (1)
    {
      gchar *users;

      ret = get_next (&groups, &get_groups_data->get, &first, &count,
                      init_group_iterator);
      if (ret == 1)
        break;
      if (ret == -1)
        {
          internal_error_send_to_client (error);
          return;
        }

      SEND_GET_COMMON (group, &get_groups_data->get, &groups);

      users = group_users (get_iterator_resource (&groups));
      SENDF_TO_CLIENT_OR_FAIL ("<users>%s</users>", users ? users : "");
      g_free (users);

      SEND_TO_CLIENT_OR_FAIL ("</group>");

      count++;
    }
  cleanup_iterator (&groups);
  filtered = get_groups_data->get.id
              ? 1
              : group_count (&get_groups_data->get);
  SEND_GET_END ("group", &get_groups_data->get, count, filtered);

  get_groups_data_reset (get_groups_data);
  set_client_state (CLIENT_AUTHENTIC);
}

/**
 * @brief Handle end of GET_INFO element.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 */
static void
handle_get_info (gmp_parser_t *gmp_parser, GError **error)
{
  iterator_t info;
  int count, first, filtered, ret;
  int (*init_info_iterator) (iterator_t*, get_data_t *, const char *);
  int (*info_count) (const get_data_t *get);
  const char *update_time;
  get_data_t *get;

  if (acl_user_may ("get_info") == 0)
    {
      SEND_TO_CLIENT_OR_FAIL
       (XML_ERROR_SYNTAX ("get_info",
                          "Permission denied"));
      get_info_data_reset (get_info_data);
      set_client_state (CLIENT_AUTHENTIC);
      return;
    }

  if (manage_scap_loaded () == 0)
    {
      SEND_TO_CLIENT_OR_FAIL
       (XML_ERROR_SYNTAX ("get_info",
                          "The SCAP database is required"));
      get_info_data_reset (get_info_data);
      set_client_state (CLIENT_AUTHENTIC);
      return;
    }
  if (manage_cert_loaded () == 0)
    {
      SEND_TO_CLIENT_OR_FAIL
       (XML_ERROR_SYNTAX ("get_info",
                          "The CERT database is required"));
      get_info_data_reset (get_info_data);
      set_client_state (CLIENT_AUTHENTIC);
      return;
    }

  if (get_info_data->name && get_info_data->get.id)
    {
      SEND_TO_CLIENT_OR_FAIL
       (XML_ERROR_SYNTAX ("get_info",
                          "Only one of name and the id attribute"
                          " may be given."));
      get_info_data_reset (get_info_data);
      set_client_state (CLIENT_AUTHENTIC);
      return;
    }
  if (get_info_data->type == NULL)
    {
      SEND_TO_CLIENT_OR_FAIL
       (XML_ERROR_SYNTAX ("get_info",
                          "No type specified."));
      get_info_data_reset (get_info_data);
      set_client_state (CLIENT_AUTHENTIC);
      return;
    }

  get = &get_info_data->get;
  if (get->filt_id && strcmp (get->filt_id, FILT_ID_USER_SETTING) == 0)
    {
      char *user_filter;
      gchar *name;

      if (strcmp (get_info_data->type, "cpe") == 0)
        name = g_strdup ("CPE");
      else if (strcmp (get_info_data->type, "cve") == 0)
        name = g_strdup ("CVE");
      else if (strcmp (get_info_data->type, "cert_bund_adv") == 0)
        name = g_strdup ("CERT-Bund");
      else if (strcmp (get_info_data->type, "dfn_cert_adv") == 0)
        name = g_strdup ("DFN-CERT");
      else if (strcmp (get_info_data->type, "nvt") == 0)
        name = g_strdup ("NVT");
      else
        {
          if (send_find_error_to_client ("get_info", "type",
                                          get_info_data->type,
                                          gmp_parser))
            {
              error_send_to_client (error);
              return;
            }
          get_info_data_reset (get_info_data);
          set_client_state (CLIENT_AUTHENTIC);
          return;
        }

      user_filter = setting_filter (name);
      g_free (name);

      if (user_filter && strlen (user_filter))
        {
          get->filt_id = user_filter;
          get->filter = filter_term (user_filter);
        }
      else
        get->filt_id = g_strdup("0");
    }

  /* Set type specific functions */
  if (g_strcmp0 ("cpe", get_info_data->type) == 0)
    {
      init_info_iterator = init_cpe_info_iterator;
      info_count = cpe_info_count;
      get_info_data->get.subtype = g_strdup ("cpe");
    }
  else if (g_strcmp0 ("cve", get_info_data->type) == 0)
    {
      init_info_iterator = init_cve_info_iterator;
      info_count = cve_info_count;
      get_info_data->get.subtype = g_strdup ("cve");
    }
  else if (g_strcmp0 ("nvt", get_info_data->type) == 0)
    {
      init_info_iterator = init_nvt_info_iterator;
      info_count = nvt_info_count;
      get_info_data->get.subtype = g_strdup ("nvt");
    }
  else if (g_strcmp0 ("cert_bund_adv", get_info_data->type) == 0)
    {
      init_info_iterator = init_cert_bund_adv_info_iterator;
      info_count = cert_bund_adv_info_count;
      get_info_data->get.subtype = g_strdup ("cert_bund_adv");
    }
  else if (g_strcmp0 ("dfn_cert_adv", get_info_data->type) == 0)
    {
      init_info_iterator = init_dfn_cert_adv_info_iterator;
      info_count = dfn_cert_adv_info_count;
      get_info_data->get.subtype = g_strdup ("dfn_cert_adv");
    }
  else
    {
      if (send_find_error_to_client ("get_info", "type",
                                     get_info_data->type, gmp_parser))
        {
          error_send_to_client (error);
        }
      return;
    }

  ret = init_info_iterator (&info, &get_info_data->get, get_info_data->name);
  if (ret)
    {
      switch (ret)
        {
        case 1:
          if (send_find_error_to_client ("get_info",
                                         get_info_data->name
                                          ? "name"
                                          : "ID",
                                         get_info_data->name
                                          ? get_info_data->name
                                          : get_info_data->get.id,
                                         gmp_parser))
            {
              error_send_to_client (error);
              return;
            }
          break;
        case 2:
          if (send_find_error_to_client
               ("get_info", "filter", get_info_data->get.filt_id,
                gmp_parser))
            {
              error_send_to_client (error);
              return;
            }
          break;
        case -1:
          SEND_TO_CLIENT_OR_FAIL
            (XML_INTERNAL_ERROR ("get_info"));
          break;
        }
      get_info_data_reset (get_info_data);
      set_client_state (CLIENT_AUTHENTIC);
      return;
    }

  count = 0;
  manage_filter_controls (get_info_data->get.filter, &first, NULL, NULL, NULL);
  SEND_GET_START ("info");
  update_time = manage_scap_update_time ();
  while (next (&info))
    {
      GString *result;

      /* Info's are currently always read only */
      if (send_get_common ("info", &get_info_data->get, &info,
                           gmp_parser->client_writer,
                           gmp_parser->client_writer_data, 0, 0))
        {
          error_send_to_client (error);
          return;
        }

      SENDF_TO_CLIENT_OR_FAIL ("<update_time>%s</update_time>",
                               update_time);

      result = g_string_new ("");

      /* Information depending on type */

      if (g_strcmp0 ("cpe", get_info_data->type) == 0)
        {
          const char *title;

          xml_string_append (result, "<cpe>");
          title = cpe_info_iterator_title (&info);
          if (title)
            xml_string_append (result,
                               "<title>%s</title>",
                               cpe_info_iterator_title (&info));
          xml_string_append (result,
                             "<nvd_id>%s</nvd_id>"
                             "<severity>%s</severity>"
                             "<cve_refs>%s</cve_refs>"
                             "<status>%s</status>",
                             cpe_info_iterator_nvd_id (&info)
                              ? cpe_info_iterator_nvd_id (&info)
                              : "",
                             cpe_info_iterator_severity (&info)
                              ? cpe_info_iterator_severity (&info)
                              : "",
                             cpe_info_iterator_cve_refs (&info),
                             cpe_info_iterator_status (&info)
                              ? cpe_info_iterator_status (&info)
                              : "");

          if (get_info_data->details == 1)
            {
              iterator_t cves;
              g_string_append (result, "<cves>");
              init_cpe_cve_iterator (&cves, get_iterator_name (&info), 0, NULL);
              while (next (&cves))
                xml_string_append (result,
                                   "<cve>"
                                   "<entry"
                                   " xmlns:cpe-lang=\"http://cpe.mitre.org/language/2.0\""
                                   " xmlns:vuln=\"http://scap.nist.gov/schema/vulnerability/0.4\""
                                   " xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
                                   " xmlns:patch=\"http://scap.nist.gov/schema/patch/0.1\""
                                   " xmlns:scap-core=\"http://scap.nist.gov/schema/scap-core/0.1\""
                                   " xmlns:cvss=\"http://scap.nist.gov/schema/cvss-v2/0.2\""
                                   " xmlns=\"http://scap.nist.gov/schema/feed/vulnerability/2.0\""
                                   " id=\"%s\">"
                                   "<vuln:cvss>"
                                   "<cvss:base_metrics>"
                                   "<cvss:score>%s</cvss:score>"
                                   "</cvss:base_metrics>"
                                   "</vuln:cvss>"
                                   "</entry>"
                                   "</cve>",
                                   cve_iterator_name (&cves),
                                   cve_iterator_cvss_score (&cves)
                                    ? cve_iterator_cvss_score (&cves)
                                    : "");
              cleanup_iterator (&cves);
              g_string_append (result, "</cves>");
            }
        }
      else if (g_strcmp0 ("cve", get_info_data->type) == 0)
        {
          xml_string_append (result,
                             "<cve>"
                             "<severity>%s</severity>"
                             "<cvss_vector>%s</cvss_vector>"
                             "<description>%s</description>"
                             "<products>%s</products>",
                             cve_info_iterator_severity (&info)
                              ? cve_info_iterator_severity (&info)
                              : "",
                             cve_info_iterator_vector (&info),
                             cve_info_iterator_description (&info),
                             cve_info_iterator_products (&info));
          if (get_info_data->details == 1)
            {
              iterator_t nvts;
              iterator_t cert_advs;
              init_cve_nvt_iterator (&nvts, get_iterator_name (&info), 1, NULL);
              g_string_append (result, "<nvts>");
              while (next (&nvts))
                xml_string_append (result,
                                   "<nvt oid=\"%s\">"
                                   "<name>%s</name>"
                                   "</nvt>",
                                   nvt_iterator_oid (&nvts),
                                   nvt_iterator_name (&nvts));
              g_string_append (result, "</nvts>");
              cleanup_iterator (&nvts);

              g_string_append (result, "<cert>");
              if (manage_cert_loaded())
                {
                  init_cve_cert_bund_adv_iterator (&cert_advs,
                                                  get_iterator_name (&info),
                                                  1, NULL);
                  while (next (&cert_advs))
                    {
                      xml_string_append
                        (result,
                         "<cert_ref type=\"CERT-Bund\">"
                         "<name>%s</name>"
                         "<title>%s</title>"
                         "</cert_ref>",
                         get_iterator_name (&cert_advs),
                         cert_bund_adv_info_iterator_title (&cert_advs));
                  };
                  cleanup_iterator (&cert_advs);

                  init_cve_dfn_cert_adv_iterator (&cert_advs,
                                                  get_iterator_name
                                                    (&info),
                                                  1, NULL);
                  while (next (&cert_advs))
                    {
                      xml_string_append (result,
                                         "<cert_ref type=\"DFN-CERT\">"
                                         "<name>%s</name>"
                                         "<title>%s</title>"
                                         "</cert_ref>",
                                         get_iterator_name (&cert_advs),
                                         dfn_cert_adv_info_iterator_title
                                          (&cert_advs));
                  };
                  cleanup_iterator (&cert_advs);
                }
              else
                {
                  g_string_append(result, "<warning>"
                                          "database not available"
                                          "</warning>");
                }
              g_string_append (result, "</cert>");
            }
        }
      else if (g_strcmp0 ("cert_bund_adv", get_info_data->type) == 0)
        xml_string_append (result,
                           "<cert_bund_adv>"
                           "<title>%s</title>"
                           "<summary>%s</summary>"
                           "<severity>%s</severity>"
                           "<cve_refs>%s</cve_refs>",
                           cert_bund_adv_info_iterator_title (&info),
                           cert_bund_adv_info_iterator_summary (&info),
                           cert_bund_adv_info_iterator_severity(&info)
                            ? cert_bund_adv_info_iterator_severity(&info)
                            : "",
                           cert_bund_adv_info_iterator_cve_refs (&info));
      else if (g_strcmp0 ("dfn_cert_adv", get_info_data->type) == 0)
        xml_string_append (result,
                           "<dfn_cert_adv>"
                           "<title>%s</title>"
                           "<summary>%s</summary>"
                           "<severity>%s</severity>"
                           "<cve_refs>%s</cve_refs>",
                           dfn_cert_adv_info_iterator_title (&info),
                           dfn_cert_adv_info_iterator_summary (&info),
                           dfn_cert_adv_info_iterator_severity(&info)
                            ? dfn_cert_adv_info_iterator_severity(&info)
                            : "",
                           dfn_cert_adv_info_iterator_cve_refs (&info));
      else if (g_strcmp0 ("nvt", get_info_data->type) == 0)
        {
          if (send_nvt (&info, 1, 1, -1, NULL, 0,
                        gmp_parser->client_writer,
                        gmp_parser->client_writer_data))
            {
              cleanup_iterator (&info);
              error_send_to_client (error);
              return;
            }
        }

      /* Append raw data if full details are requested */

      if (get_info_data->details == 1)
        {
          gchar *raw_data = NULL;
          gchar *nonconst_id = g_strdup(get_iterator_uuid (&info));
          gchar *nonconst_name = g_strdup(get_iterator_name (&info));
          manage_read_info (get_info_data->type, nonconst_id,
                            nonconst_name, &raw_data);
          g_string_append_printf (result, "<raw_data>%s</raw_data>",
                                  raw_data);
          g_free(nonconst_id);
          g_free(nonconst_name);
          g_free(raw_data);
        }

      g_string_append_printf (result, "</%s></info>", get_info_data->type);
      SEND_TO_CLIENT_OR_FAIL (result->str);
      count++;
      g_string_free (result, TRUE);
    }

  cleanup_iterator (&info);

  if (get_info_data->details == 1)
    SEND_TO_CLIENT_OR_FAIL ("<details>1</details>");

  filtered = get_info_data->get.id
              ? 1
              : (get_info_data->name
                  ? info_name_count (get_info_data->type, get_info_data->name)
                  : info_count (&get_info_data->get));

  SEND_GET_END ("info", &get_info_data->get, count, filtered);

  get_info_data_reset (get_info_data);
  set_client_state (CLIENT_AUTHENTIC);
}

/**
 * @brief Handle end of GET_NOTES element.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 */
static void
handle_get_notes (gmp_parser_t *gmp_parser, GError **error)
{
  nvt_t nvt = 0;
  task_t task = 0;

  if (get_notes_data->note_id && get_notes_data->nvt_oid)
    SEND_TO_CLIENT_OR_FAIL
     (XML_ERROR_SYNTAX ("get_notes",
                        "Only one of NVT and the note_id attribute"
                        " may be given"));
  else if (get_notes_data->note_id && get_notes_data->task_id)
    SEND_TO_CLIENT_OR_FAIL
     (XML_ERROR_SYNTAX ("get_notes",
                        "Only one of the note_id and task_id"
                        " attributes may be given"));
  else if (get_notes_data->task_id
           && find_task_with_permission (get_notes_data->task_id, &task,
                                         "get_tasks"))
    SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_notes"));
  else if (get_notes_data->task_id && task == 0)
    {
      if (send_find_error_to_client ("get_notes",
                                     "task", get_notes_data->task_id,
                                     gmp_parser))
        {
          error_send_to_client (error);
          return;
        }
    }
  else if (get_notes_data->nvt_oid
            && find_nvt (get_notes_data->nvt_oid, &nvt))
    SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_notes"));
  else if (get_notes_data->nvt_oid && nvt == 0)
    {
      if (send_find_error_to_client ("get_notes", "NVT",
                                     get_notes_data->nvt_oid,
                                     gmp_parser))
        {
          error_send_to_client (error);
          return;
        }
    }
  else
    {
      iterator_t notes;
      GString *buffer;
      int count, filtered, ret, first;

      INIT_GET (note, Note);

      ret = init_note_iterator (&notes, &get_notes_data->get, nvt, 0,
                                task);
      if (ret)
        {
          switch (ret)
            {
              case 1:
                if (send_find_error_to_client ("get_notes", "note",
                                               get_notes_data->get.id,
                                               gmp_parser))
                  {
                    error_send_to_client (error);
                    return;
                  }
                break;
              case 2:
                if (send_find_error_to_client
                      ("get_notes", "filter",
                       get_notes_data->get.filt_id, gmp_parser))
                  {
                    error_send_to_client (error);
                    return;
                  }
                break;
              case -1:
                SEND_TO_CLIENT_OR_FAIL
                  (XML_INTERNAL_ERROR ("get_notes"));
                break;
            }
          get_notes_data_reset (get_notes_data);
          set_client_state (CLIENT_AUTHENTIC);
          return;
        }

      SEND_GET_START ("note");

      buffer = g_string_new ("");

      // TODO: Do the iteration with get_next so it checks "first".
      buffer_notes_xml (buffer, &notes, get_notes_data->get.details,
                        get_notes_data->result, &count);

      SEND_TO_CLIENT_OR_FAIL (buffer->str);
      g_string_free (buffer, TRUE);

      cleanup_iterator (&notes);
      filtered = get_notes_data->get.id
                  ? 1
                  : note_count (&get_notes_data->get, nvt, 0, task);
      SEND_GET_END ("note", &get_notes_data->get, count, filtered);
    }
  get_notes_data_reset (get_notes_data);
  set_client_state (CLIENT_AUTHENTIC);

}

/**
 * @brief Handle end of GET_NVTS element.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 */
static void
handle_get_nvts (gmp_parser_t *gmp_parser, GError **error)
{
  char *feed_version;

  if (acl_user_may ("get_nvts") == 0)
    {
      SEND_TO_CLIENT_OR_FAIL
       (XML_ERROR_SYNTAX ("get_nvts",
                          "Permission denied"));
      get_nvts_data_reset (get_nvts_data);
      set_client_state (CLIENT_AUTHENTIC);
      return;
    }

  feed_version = nvts_feed_version ();
  if (feed_version)
    {
      config_t config, preferences_config;
      nvt_t nvt = 0;

      config = preferences_config = 0;

      free (feed_version);

      if (get_nvts_data->nvt_oid && get_nvts_data->family)
        SEND_TO_CLIENT_OR_FAIL
         (XML_ERROR_SYNTAX ("get_nvts",
                            "Too many parameters at once"));
      else if ((get_nvts_data->details == 0)
                && get_nvts_data->preference_count)
        SEND_TO_CLIENT_OR_FAIL
         (XML_ERROR_SYNTAX ("get_nvts",
                            "The preference_count attribute"
                            " requires the details attribute"));
      else if ((get_nvts_data->details == 0)
                && get_nvts_data->preferences)
        SEND_TO_CLIENT_OR_FAIL
         (XML_ERROR_SYNTAX ("get_nvts",
                            "The preferences attribute"
                            " requires the details attribute"));
      else if (((get_nvts_data->details == 0)
                || ((get_nvts_data->config_id == NULL)
                    && (get_nvts_data->preferences_config_id == NULL)))
                && get_nvts_data->timeout)
        SEND_TO_CLIENT_OR_FAIL
         (XML_ERROR_SYNTAX ("get_nvts",
                            "The timeout attribute"
                            " requires the details and config_id"
                            " attributes"));
      else if (get_nvts_data->nvt_oid
                && find_nvt (get_nvts_data->nvt_oid, &nvt))
        SEND_TO_CLIENT_OR_FAIL
          (XML_INTERNAL_ERROR ("get_nvts"));
      else if (get_nvts_data->nvt_oid && nvt == 0)
        {
          if (send_find_error_to_client ("get_nvts", "NVT",
                                          get_nvts_data->nvt_oid,
                                          gmp_parser))
            {
              error_send_to_client (error);
              return;
            }
        }
      else if (get_nvts_data->config_id
                && get_nvts_data->preferences_config_id)
        SEND_TO_CLIENT_OR_FAIL
         (XML_ERROR_SYNTAX ("get_nvts",
                            "config_id and"
                            " preferences_config_id both given"));
      else if (get_nvts_data->config_id
                && find_config_with_permission (get_nvts_data->config_id,
                                                &config,
                                                NULL))
        SEND_TO_CLIENT_OR_FAIL
          (XML_INTERNAL_ERROR ("get_nvts"));
      else if (get_nvts_data->config_id && (config == 0))
        {
          if (send_find_error_to_client
                ("get_nvts", "config", get_nvts_data->config_id,
                gmp_parser))
            {
              error_send_to_client (error);
              return;
            }
        }
      else if (get_nvts_data->preferences_config_id
                && find_config_with_permission
                    (get_nvts_data->preferences_config_id,
                    &preferences_config,
                    NULL))
        SEND_TO_CLIENT_OR_FAIL
          (XML_INTERNAL_ERROR ("get_nvts"));
      else if (get_nvts_data->preferences_config_id
                && (preferences_config == 0))
        {
          if (send_find_error_to_client
                ("get_nvts", "config",
                get_nvts_data->preferences_config_id,
                gmp_parser))
            {
              error_send_to_client (error);
              return;
            }
        }
      else
        {
          iterator_t nvts;

          SENDF_TO_CLIENT_OR_FAIL
           ("<get_nvts_response"
            " status=\"" STATUS_OK "\""
            " status_text=\"" STATUS_OK_TEXT "\">");

          init_nvt_iterator (&nvts,
                              nvt,
                              get_nvts_data->nvt_oid
                              /* Presume the NVT is in the config (if
                                * a config was given). */
                              ? 0
                              : config,
                              get_nvts_data->family,
                              NULL,
                              get_nvts_data->sort_order,
                              get_nvts_data->sort_field);
          if (preferences_config)
            config = preferences_config;
          if (get_nvts_data->details)
            while (next (&nvts))
              {
                int pref_count = -1;
                char *timeout = NULL;

                if (get_nvts_data->timeout)
                  timeout = config_nvt_timeout (config,
                                                nvt_iterator_oid (&nvts));

                if (get_nvts_data->preferences && (timeout == NULL))
                  timeout = config_nvt_timeout
                              (config,
                              nvt_iterator_oid (&nvts));

                if (get_nvts_data->preference_count)
                  {
                    const char *nvt_oid = nvt_iterator_oid (&nvts);
                    pref_count = nvt_preference_count (nvt_oid);
                  }
                if (send_nvt (&nvts, 1, get_nvts_data->preferences,
                              pref_count, timeout, config,
                              gmp_parser->client_writer,
                              gmp_parser->client_writer_data))
                  {
                    free (timeout);
                    cleanup_iterator (&nvts);
                    error_send_to_client (error);
                    return;
                  }
                free (timeout);

                SEND_TO_CLIENT_OR_FAIL ("</nvt>");
              }
          else
            while (next (&nvts))
              {
                if (send_nvt (&nvts, 0, 0, -1, NULL, 0,
                              gmp_parser->client_writer,
                              gmp_parser->client_writer_data))
                  {
                    cleanup_iterator (&nvts);
                    error_send_to_client (error);
                    return;
                  }
                SEND_TO_CLIENT_OR_FAIL ("</nvt>");
              }
          cleanup_iterator (&nvts);

          SEND_TO_CLIENT_OR_FAIL ("</get_nvts_response>");
        }
    }
  else
    SEND_XML_SERVICE_DOWN ("get_nvts");

  get_nvts_data_reset (get_nvts_data);
  set_client_state (CLIENT_AUTHENTIC);
}

/**
 * @brief Handle end of GET_NVT_FAMILIES element.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 */
static void
handle_get_nvt_families (gmp_parser_t *gmp_parser, GError **error)
{
  iterator_t families;

  if (acl_user_may ("get_nvt_families") == 0)
    {
      SEND_TO_CLIENT_OR_FAIL
       (XML_ERROR_SYNTAX ("get_nvt_families",
                          "Permission denied"));
      get_nvt_families_data_reset (get_nvt_families_data);
      set_client_state (CLIENT_AUTHENTIC);
      return;
    }

  SEND_TO_CLIENT_OR_FAIL ("<get_nvt_families_response"
                          " status=\"" STATUS_OK "\""
                          " status_text=\"" STATUS_OK_TEXT "\">"
                          "<families>");

  init_family_iterator (&families,
                        1,
                        NULL,
                        get_nvt_families_data->sort_order);
  while (next (&families))
    {
      int family_max;
      const char *family;

      family = family_iterator_name (&families);
      if (family)
        family_max = family_nvt_count (family);
      else
        family_max = -1;

      SENDF_TO_CLIENT_OR_FAIL
       ("<family>"
        "<name>%s</name>"
        /* The total number of NVT's in the family. */
        "<max_nvt_count>%i</max_nvt_count>"
        "</family>",
        family ? family : "",
        family_max);
    }
  cleanup_iterator (&families);

  SEND_TO_CLIENT_OR_FAIL ("</families>"
                          "</get_nvt_families_response>");

  get_nvt_families_data_reset (get_nvt_families_data);
  set_client_state (CLIENT_AUTHENTIC);
}

/**
 * @brief Handle end of GET_OVERRIDES element.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 */
static void
handle_get_overrides (gmp_parser_t *gmp_parser, GError **error)
{
  nvt_t nvt = 0;
  task_t task = 0;

  if (get_overrides_data->override_id && get_overrides_data->nvt_oid)
    SEND_TO_CLIENT_OR_FAIL
     (XML_ERROR_SYNTAX ("get_overrides",
                        "Only one of NVT and the override_id attribute"
                        " may be given"));
  else if (get_overrides_data->override_id
            && get_overrides_data->task_id)
    SEND_TO_CLIENT_OR_FAIL
     (XML_ERROR_SYNTAX ("get_overrides",
                        "Only one of the override_id and task_id"
                        " attributes may be given"));
  else if (get_overrides_data->task_id
           && find_task_with_permission (get_overrides_data->task_id, &task,
                                         "get_tasks"))
    SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_overrides"));
  else if (get_overrides_data->task_id && task == 0)
    {
      if (send_find_error_to_client ("get_overrides", "task",
                                     get_overrides_data->task_id,
                                     gmp_parser))
        {
          error_send_to_client (error);
          return;
        }
    }
  else if (get_overrides_data->nvt_oid
            && find_nvt (get_overrides_data->nvt_oid, &nvt))
    SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_overrides"));
  else if (get_overrides_data->nvt_oid && nvt == 0)
    {
      if (send_find_error_to_client ("get_overrides",
                                     "NVT", get_overrides_data->nvt_oid,
                                     gmp_parser))
        {
          error_send_to_client (error);
          return;
        }
    }
  else
    {
      iterator_t overrides;
      GString *buffer;
      int count, filtered, ret, first;

      INIT_GET (override, Override);

      ret = init_override_iterator (&overrides,
                                    &get_overrides_data->get, nvt, 0,
                                    task);
      if (ret)
        {
          switch (ret)
            {
              case 1:
                if (send_find_error_to_client
                      ("get_overrides", "override",
                       get_overrides_data->get.id, gmp_parser))
                  {
                    error_send_to_client (error);
                    return;
                  }
                break;
              case 2:
                if (send_find_error_to_client
                      ("get_overrides", "filter",
                       get_overrides_data->get.filt_id, gmp_parser))
                  {
                    error_send_to_client (error);
                    return;
                  }
                break;
              case -1:
                SEND_TO_CLIENT_OR_FAIL
                  (XML_INTERNAL_ERROR ("get_overrides"));
                break;
            }
          get_overrides_data_reset (get_overrides_data);
          set_client_state (CLIENT_AUTHENTIC);
          return;
        }

      SEND_GET_START ("override");

      buffer = g_string_new ("");

      // TODO: Do the iteration with get_next so it checks "first".
      buffer_overrides_xml (buffer, &overrides,
                            get_overrides_data->get.details,
                            get_overrides_data->result, &count);

      SEND_TO_CLIENT_OR_FAIL (buffer->str);
      g_string_free (buffer, TRUE);

      cleanup_iterator (&overrides);
      filtered = get_overrides_data->get.id
                  ? 1
                  : override_count (&get_overrides_data->get, nvt, 0,
                                    task);
      SEND_GET_END ("override", &get_overrides_data->get, count,
                    filtered);
    }
  get_overrides_data_reset (get_overrides_data);
  set_client_state (CLIENT_AUTHENTIC);
}

/**
 * @brief Handle end of GET_PERMISSIONS element.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 */
static void
handle_get_permissions (gmp_parser_t *gmp_parser, GError **error)
{
  iterator_t permissions;
  int count, filtered, ret, first;

  INIT_GET (permission, Permission);

  ret = init_permission_iterator (&permissions,
                                  &get_permissions_data->get);
  if (ret)
    {
      switch (ret)
        {
          case 1:
            if (send_find_error_to_client ("get_permissions",
                                           "permission",
                                           get_permissions_data->get.id,
                                           gmp_parser))
              {
                error_send_to_client (error);
                return;
              }
            break;
          case 2:
            if (send_find_error_to_client
                  ("get_permissions", "filter",
                   get_permissions_data->get.filt_id, gmp_parser))
              {
                error_send_to_client (error);
                return;
              }
            break;
          case -1:
            SEND_TO_CLIENT_OR_FAIL
              (XML_INTERNAL_ERROR ("get_permissions"));
            break;
        }
      get_permissions_data_reset (get_permissions_data);
      set_client_state (CLIENT_AUTHENTIC);
      return;
    }

  SEND_GET_START ("permission");
  while (1)
    {
      const char *resource_type;

      ret = get_next (&permissions, &get_permissions_data->get, &first,
                      &count, init_permission_iterator);
      if (ret == 1)
        break;
      if (ret == -1)
        {
          internal_error_send_to_client (error);
          return;
        }

      SEND_GET_COMMON (permission, &get_permissions_data->get, &permissions);

      resource_type = permission_iterator_resource_type (&permissions);
      SENDF_TO_CLIENT_OR_FAIL
       ("<resource id=\"%s\">"
        "<name>%s</name>"
        "<type>%s</type>"
        "<trash>%i</trash>"
        "<deleted>%i</deleted>",
        permission_iterator_resource_uuid (&permissions),
        resource_type && strcmp (resource_type, "")
          ? permission_iterator_resource_name (&permissions)
          : "",
        permission_iterator_resource_type (&permissions),
        permission_iterator_resource_in_trash (&permissions),
        permission_iterator_resource_orphan (&permissions));

      if (permission_iterator_resource_readable (&permissions))
        SEND_TO_CLIENT_OR_FAIL ("</resource>");
      else
        SEND_TO_CLIENT_OR_FAIL ("<permissions/>"
                                "</resource>");

      SENDF_TO_CLIENT_OR_FAIL
       ("<subject id=\"%s\">"
        "<name>%s</name>"
        "<type>%s</type>"
        "<trash>%i</trash>",
        permission_iterator_subject_uuid (&permissions),
        permission_iterator_subject_name (&permissions),
        permission_iterator_subject_type (&permissions),
        permission_iterator_subject_in_trash (&permissions));

      if (permission_iterator_subject_readable (&permissions))
        SEND_TO_CLIENT_OR_FAIL ("</subject>");
      else
        SEND_TO_CLIENT_OR_FAIL ("<permissions/>"
                                "</subject>");

      SEND_TO_CLIENT_OR_FAIL ("</permission>");
      count++;
    }
  cleanup_iterator (&permissions);
  filtered = get_permissions_data->get.id
              ? 1
              : permission_count (&get_permissions_data->get);
  SEND_GET_END ("permission", &get_permissions_data->get, count, filtered);

  get_permissions_data_reset (get_permissions_data);
  set_client_state (CLIENT_AUTHENTIC);
}

/**
 * @brief Handle end of GET_PORT_LISTS element.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 */
static void
handle_get_port_lists (gmp_parser_t *gmp_parser, GError **error)
{
  iterator_t port_lists;
  int count, filtered, ret, first;

  INIT_GET (port_list, Port List);

  ret = init_port_list_iterator (&port_lists,
                                  &get_port_lists_data->get);
  if (ret)
    {
      switch (ret)
        {
          case 1:
            if (send_find_error_to_client ("get_port_lists",
                                           "port_list",
                                           get_port_lists_data->get.id,
                                           gmp_parser))
              {
                error_send_to_client (error);
                return;
              }
            break;
          case 2:
            if (send_find_error_to_client
                  ("get_port_lists", "filter",
                   get_port_lists_data->get.filt_id, gmp_parser))
              {
                error_send_to_client (error);
                return;
              }
            break;
          case -1:
            SEND_TO_CLIENT_OR_FAIL
              (XML_INTERNAL_ERROR ("get_port_lists"));
            break;
        }
      get_port_lists_data_reset (get_port_lists_data);
      set_client_state (CLIENT_AUTHENTIC);
      return;
    }

  SEND_GET_START ("port_list");
  while (1)
    {
      ret = get_next (&port_lists, &get_port_lists_data->get, &first,
                      &count, init_port_list_iterator);
      if (ret == 1)
        break;
      if (ret == -1)
        {
          internal_error_send_to_client (error);
          return;
        }

      SEND_GET_COMMON (port_list, &get_port_lists_data->get,
                        &port_lists);

      SENDF_TO_CLIENT_OR_FAIL ("<port_count>"
                               "<all>%i</all>"
                               "<tcp>%i</tcp>"
                               "<udp>%i</udp>"
                               "</port_count>"
                               "<predefined>%i</predefined>",
                               port_list_iterator_count_all (&port_lists),
                               port_list_iterator_count_tcp (&port_lists),
                               port_list_iterator_count_udp (&port_lists),
                               port_list_iterator_predefined (&port_lists));

      if (get_port_lists_data->get.details)
        {
          iterator_t ranges;

          SEND_TO_CLIENT_OR_FAIL ("<port_ranges>");

          init_port_range_iterator (&ranges,
                                    get_iterator_resource (&port_lists),
                                    0, 1, NULL);
          while (next (&ranges))
            SENDF_TO_CLIENT_OR_FAIL
             ("<port_range id=\"%s\">"
              "<start>%s</start>"
              "<end>%s</end>"
              "<type>%s</type>"
              "<comment>%s</comment>"
              "</port_range>",
              port_range_iterator_uuid (&ranges),
              port_range_iterator_start (&ranges),
              port_range_iterator_end (&ranges)
                ? port_range_iterator_end (&ranges)
                : port_range_iterator_start (&ranges),
              port_range_iterator_type (&ranges),
              port_range_iterator_comment (&ranges));
          cleanup_iterator (&ranges);

          SENDF_TO_CLIENT_OR_FAIL ("</port_ranges>");
        }

      if (get_port_lists_data->targets)
        {
          iterator_t targets;

          SEND_TO_CLIENT_OR_FAIL ("<targets>");

          init_port_list_target_iterator (&targets,
                                          get_iterator_resource
                                            (&port_lists), 0);
          while (next (&targets))
            {
              if (port_list_target_iterator_readable (&targets) == 0)
                /* Only show targets the user may see. */
                continue;

              SENDF_TO_CLIENT_OR_FAIL
               ("<target id=\"%s\">"
                "<name>%s</name>",
                port_list_target_iterator_uuid (&targets),
                port_list_target_iterator_name (&targets));
              if (port_list_target_iterator_readable (&targets))
                SEND_TO_CLIENT_OR_FAIL ("</target>");
              else
                SEND_TO_CLIENT_OR_FAIL ("<permissions/>"
                                        "</target>");
            }

          cleanup_iterator (&targets);

          SEND_TO_CLIENT_OR_FAIL ("</targets>");
        }

      SEND_TO_CLIENT_OR_FAIL ("</port_list>");

      count++;
    }

  cleanup_iterator (&port_lists);
  filtered = get_port_lists_data->get.id
              ? 1
              : port_list_count (&get_port_lists_data->get);
  SEND_GET_END ("port_list", &get_port_lists_data->get, count, filtered);

  get_port_lists_data_reset (get_port_lists_data);
  set_client_state (CLIENT_AUTHENTIC);
}

/**
 * @brief Handle end of GET_PREFERENCES element.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 */
static void
handle_get_preferences (gmp_parser_t *gmp_parser, GError **error)
{
  iterator_t prefs;
  nvt_t nvt = 0;
  config_t config = 0;

  if (acl_user_may ("get_preferences") == 0)
    {
      SEND_TO_CLIENT_OR_FAIL
       (XML_ERROR_SYNTAX ("get_preferences",
                          "Permission denied"));
      get_preferences_data_reset (get_preferences_data);
      set_client_state (CLIENT_AUTHENTIC);
      return;
    }

  if (get_preferences_data->nvt_oid
      && find_nvt (get_preferences_data->nvt_oid, &nvt))
    SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_preferences"));
  else if (get_preferences_data->nvt_oid && nvt == 0)
    {
      if (send_find_error_to_client ("get_preferences", "NVT",
                                     get_preferences_data->nvt_oid,
                                     gmp_parser))
        {
          error_send_to_client (error);
          return;
        }
    }
  else if (get_preferences_data->config_id
           && find_config_with_permission (get_preferences_data->config_id,
                                           &config,
                                           "get_configs"))
    SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_preferences"));
  else if (get_preferences_data->config_id && config == 0)
    {
      if (send_find_error_to_client ("get_preferences", "config",
                                     get_preferences_data->config_id,
                                     gmp_parser))
        {
          error_send_to_client (error);
          return;
        }
    }
  else
    {
      char *nvt_oid = get_preferences_data->nvt_oid;
      SEND_TO_CLIENT_OR_FAIL ("<get_preferences_response"
                              " status=\"" STATUS_OK "\""
                              " status_text=\"" STATUS_OK_TEXT "\">");
      init_nvt_preference_iterator (&prefs, nvt_oid);
      if (get_preferences_data->preference)
        while (next (&prefs))
          {
            char *name = strstr (nvt_preference_iterator_name (&prefs), ":");
            if (name)
              name = strstr (name + 1, ":");
            if (name && (strcmp (name + 1, get_preferences_data->preference)
                         == 0))
              {
                GString *buffer = g_string_new ("");
                buffer_config_preference_xml (buffer, &prefs, config, 1);
                SEND_TO_CLIENT_OR_FAIL (buffer->str);
                g_string_free (buffer, TRUE);
                break;
              }
          }
      else
        while (next (&prefs))
          {
            GString *buffer = g_string_new ("");
            buffer_config_preference_xml (buffer, &prefs, config, 1);
            SEND_TO_CLIENT_OR_FAIL (buffer->str);
            g_string_free (buffer, TRUE);
          }

      cleanup_iterator (&prefs);
      SEND_TO_CLIENT_OR_FAIL ("</get_preferences_response>");
    }
  get_preferences_data_reset (get_preferences_data);
  set_client_state (CLIENT_AUTHENTIC);
}

/**
 * @brief Handle end of GET_REPORTS element.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 */
static void
handle_get_reports (gmp_parser_t *gmp_parser, GError **error)
{
  report_t request_report = 0, delta_report = 0, report;
  char no_report_format;
  report_format_t report_format;
  iterator_t reports;
  int count, filtered, ret, first;

  if (current_credentials.username == NULL)
    {
      get_reports_data_reset (get_reports_data);
      SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_reports"));
      set_client_state (CLIENT_AUTHENTIC);
      return;
    }

  if (acl_user_may ("get_reports") == 0)
    {
      SEND_TO_CLIENT_OR_FAIL
       (XML_ERROR_SYNTAX ("get_reports",
                          "Permission denied"));
      get_reports_data_reset (get_reports_data);
      set_client_state (CLIENT_AUTHENTIC);
      return;
    }

  if (get_reports_data->get.trash)
    {
      SEND_TO_CLIENT_OR_FAIL
       (XML_ERROR_SYNTAX ("get_reports",
                          "Getting reports from the trashcan"
                          " is not supported"));
      get_reports_data_reset (get_reports_data);
      set_client_state (CLIENT_AUTHENTIC);
      return;
    }

  /** @todo Respond in all error cases.
    *
    * When something fails mid-way through the report, we can only close
    * the connection.  It would be nice to instead prepare everything
    * before trying to send it, so that we could send an error response
    * when there is a problem.  Buffering the entire report before sending
    * it would probably take too long and/or use to much memory. */

  if (get_reports_data->report_id
      && find_report_with_permission (get_reports_data->report_id,
                                      &request_report,
                                      NULL))
    {
      get_reports_data_reset (get_reports_data);
      SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_reports"));
      set_client_state (CLIENT_AUTHENTIC);
      return;
    }

  if (get_reports_data->delta_report_id
      && strcmp (get_reports_data->delta_report_id, "0")
      && find_report_with_permission (get_reports_data->delta_report_id,
                                      &delta_report,
                                      NULL))
    {
      get_reports_data_reset (get_reports_data);
      SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_reports"));
      set_client_state (CLIENT_AUTHENTIC);
      return;
    }

  no_report_format = (get_reports_data->format_id == NULL)
                      || (strcmp(get_reports_data->format_id, "") == 0);

  if ((!no_report_format)
      && find_report_format_with_permission (get_reports_data->format_id,
                                             &report_format,
                                             "get_report_formats"))
    {
      get_reports_data_reset (get_reports_data);
      SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_reports"));
      set_client_state (CLIENT_AUTHENTIC);
      return;
    }

  if ((!no_report_format) && (report_format == 0))
    {
      if (send_find_error_to_client ("get_reports", "report format",
                                     get_reports_data->format_id,
                                     gmp_parser))
        {
          error_send_to_client (error);
          return;
        }
      get_reports_data_reset (get_reports_data);
      set_client_state (CLIENT_AUTHENTIC);
      return;
    }

  if (get_reports_data->get.filt_id
      && strcmp (get_reports_data->get.filt_id, FILT_ID_NONE)
      && strcmp (get_reports_data->get.filt_id, FILT_ID_USER_SETTING))
    {
      filter_t filter;
      if (find_filter_with_permission (get_reports_data->get.filt_id,
                                       &filter,
                                       "get_filters"))
        {
          get_reports_data_reset (get_reports_data);
          SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_reports"));
          set_client_state (CLIENT_AUTHENTIC);
          return;
        }

      if (filter == 0)
        {
          if (send_find_error_to_client ("get_reports", "filter",
                                         get_reports_data->get.filt_id,
                                         gmp_parser))
            {
              error_send_to_client (error);
              return;
            }
          get_reports_data_reset (get_reports_data);
          set_client_state (CLIENT_AUTHENTIC);
          return;
        }
    }

  if (get_reports_data->report_id
      && request_report == 0)
    {
      if (send_find_error_to_client ("get_reports", "report",
                                     get_reports_data->report_id,
                                     gmp_parser))
        {
          error_send_to_client (error);
          return;
        }
      get_reports_data_reset (get_reports_data);
      set_client_state (CLIENT_AUTHENTIC);
      return;
    }

  if (get_reports_data->delta_report_id
      && strcmp (get_reports_data->delta_report_id, "0")
      && delta_report == 0)
    {
      if (send_find_error_to_client ("get_reports", "report",
                                     get_reports_data->delta_report_id,
                                     gmp_parser))
        {
          error_send_to_client (error);
          return;
        }
      get_reports_data_reset (get_reports_data);
      set_client_state (CLIENT_AUTHENTIC);
      return;
    }

  if ((!no_report_format) && (report_format_active (report_format) == 0))
    {
      get_reports_data_reset (get_reports_data);
      SEND_TO_CLIENT_OR_FAIL
       (XML_ERROR_SYNTAX ("get_reports",
                          "Report format must be active"));
      set_client_state (CLIENT_AUTHENTIC);
      return;
    }

  if ((!no_report_format) &&
      ((report_format_predefined (report_format) == 0)
      && (report_format_trust (report_format) > 1)))
    {
      get_reports_data_reset (get_reports_data);
      SEND_TO_CLIENT_OR_FAIL
       (XML_ERROR_SYNTAX ("get_reports",
                          "Report format must be trusted"));
      set_client_state (CLIENT_AUTHENTIC);
      return;
    }

  if (get_reports_data->get.id)
    {
      /* Showing requested report, use Results Filter setting. */
      INIT_GET (report, Result);
    }
  else
    {
      /* Showing multiple reports.  Use Report Filter setting.  Expand
        * INIT_GET here to pass the get_reports_data->report_get to
        * init_get. */
      ret = init_get ("get_reports",
                      &get_reports_data->report_get,
                      "Reports",
                      &first);
      if (ret)
        {
          switch (ret)
            {
              case 99:
                SEND_TO_CLIENT_OR_FAIL
                  (XML_ERROR_SYNTAX ("get_reports",
                                     "Permission denied"));
                break;
              default:
                internal_error_send_to_client (error);
                return;
            }
          get_reports_data_reset (get_reports_data);
          set_client_state (CLIENT_AUTHENTIC);
          return;
        }
    }

  if ((get_reports_data->report_get.id == NULL)
      || (strlen (get_reports_data->report_get.id) == 0))
    {
      int overrides, min_qod;
      gchar *filter;
      get_data_t * get;

      /* For simplicity, use a fixed result filter when filtering
        * reports.  A given result filter is only applied when getting
        * a single specified report. */

      get = &get_reports_data->report_get;

      /* Get overrides value from report filter. */
      if (get->filt_id && strcmp (get->filt_id, FILT_ID_NONE))
        {
          filter = filter_term (get->filt_id);
          if (filter == NULL)
            assert (0);
        }
      else
        filter = NULL;
      g_free (get_reports_data->get.filter);
      overrides = filter_term_apply_overrides (filter ? filter : get->filter);
      min_qod = filter_term_min_qod (filter ? filter : get->filter);
      g_free (filter);

      /* Setup result filter from overrides. */
      get_reports_data->get.filter
        = g_strdup_printf ("apply_overrides=%i min_qod=%i",
                           overrides, min_qod);
    }

  ret = init_report_iterator (&reports, &get_reports_data->report_get);
  if (ret)
    {
      switch (ret)
        {
          case 1:
            if (send_find_error_to_client ("get_reports", "report",
                                           get_reports_data->get.id,
                                           gmp_parser))
              {
                error_send_to_client (error);
                return;
              }
            break;
          case 2:
            if (send_find_error_to_client
                  ("get_reports", "filter",
                   get_reports_data->get.filt_id, gmp_parser))
              {
                error_send_to_client (error);
                return;
              }
            break;
          case -1:
            SEND_TO_CLIENT_OR_FAIL
              (XML_INTERNAL_ERROR ("get_reports"));
            break;
        }
      get_reports_data_reset (get_reports_data);
      set_client_state (CLIENT_AUTHENTIC);
      return;
    }

  count = 0;
  if (get_reports_data->alert_id == NULL)
    SEND_GET_START ("report");
  while (next_report (&reports, &report))
    {
      gchar *extension, *content_type;
      GString *prefix;

      prefix = g_string_new ("");
      content_type = no_report_format
                        ? g_strdup("application/xml")
                        : report_format_content_type (report_format);
      extension = no_report_format
                    ? g_strdup("")
                    : report_format_extension (report_format);

      if (get_reports_data->alert_id == NULL)
        g_string_append_printf (prefix,
                                "<report"
                                " id=\"%s\""
                                " format_id=\"%s\""
                                " extension=\"%s\""
                                " content_type=\"%s\">",
                                report_iterator_uuid (&reports),
                                no_report_format
                                  ? ""
                                  : get_reports_data->format_id,
                                extension,
                                content_type);

      g_free (extension);
      g_free (content_type);

      if (get_reports_data->alert_id == NULL)
        {
          task_t task;

          /* Send the standard elements.  Should match send_get_common. */
          buffer_xml_append_printf
            (prefix,
             "<owner><name>%s</name></owner>"
             "<name>%s</name>"
             "<comment>%s</comment>"
             "<creation_time>%s</creation_time>"
             "<modification_time>"
             "%s"
             "</modification_time>"
             "<writable>0</writable>"
             "<in_use>0</in_use>",
             get_iterator_owner_name (&reports)
              ? get_iterator_owner_name (&reports)
              : "",
             get_iterator_name (&reports)
              ? get_iterator_name (&reports)
              : "",
             get_iterator_comment (&reports)
              ? get_iterator_comment (&reports)
              : "",
             get_iterator_creation_time (&reports)
              ? get_iterator_creation_time (&reports)
              : "",
             get_iterator_modification_time (&reports)
              ? get_iterator_modification_time (&reports)
              : "");
          /* Send short task and report format info */
          report_task (report, &task);
          if (task)
            {
              gchar *report_task_uuid;
              task_uuid (task, &report_task_uuid);

              buffer_xml_append_printf (prefix,
                                        "<task id=\"%s\">",
                                        report_task_uuid);

              /* Skip task name for Anonymous XML report format. */
              if (get_reports_data->format_id == NULL
                  || strcmp (get_reports_data->format_id,
                             "5057e5cc-b825-11e4-9d0e-28d24461215b"))
                {
                  gchar *report_task_name;
                  report_task_name = task_name (task);
                  buffer_xml_append_printf (prefix,
                                            "<name>%s</name>",
                                            report_task_name);
                  g_free (report_task_name);
                }

              buffer_xml_append_printf (prefix, "</task>");

              g_free (report_task_uuid);
            }

            if (get_reports_data->format_id)
              {
                gchar *format_name = NULL;
                format_name = report_format_name (report_format);

                buffer_xml_append_printf
                  (prefix,
                   "<report_format id=\"%s\">"
                   "<name>%s</name>"
                   "</report_format>",
                   get_reports_data->format_id,
                   format_name ? format_name : "");
                // g_free (report_format_name);
              }

        }
      /* If there's just one report then cleanup the iterator early.  This
        * closes the iterator transaction, allowing manage_schedule to lock
        * the db during generation of large reports. */
      if (request_report)
        cleanup_iterator (&reports);

      /* Always enable details when using a report to test an alert. */
      if (get_reports_data->alert_id)
        get_reports_data->get.details = 1;

      ret = manage_send_report (report,
                                delta_report,
                                no_report_format ? -1 : report_format,
                                &get_reports_data->get,
                                get_reports_data->notes_details,
                                get_reports_data->overrides_details,
                                get_reports_data->result_tags,
                                get_reports_data->ignore_pagination,
                                get_reports_data->lean,
                                /* Special case the XML report, bah. */
                                (!no_report_format)
                                && get_reports_data->format_id
                                && strcmp
                                    (get_reports_data->format_id,
                                     "a994b278-1f62-11e1-96ac-406186ea4fc5")
                                && strcmp
                                    (get_reports_data->format_id,
                                      "5057e5cc-b825-11e4-9d0e-28d24461215b"),
                                send_to_client,
                                gmp_parser->client_writer,
                                gmp_parser->client_writer_data,
                                get_reports_data->alert_id,
                                prefix->str);
      g_string_free (prefix, TRUE);
      if (ret)
        {
          if (get_reports_data->alert_id)
            switch (ret)
              {
                case 0:
                  break;
                case 1:
                  if (send_find_error_to_client
                        ("get_reports", "alert",
                        get_reports_data->alert_id, gmp_parser))
                    {
                      error_send_to_client (error);
                      return;
                    }
                  /* Close the connection with the client, as part of the
                    * response may have been sent before the error
                    * occurred. */
                  internal_error_send_to_client (error);
                  if (request_report == 0)
                    cleanup_iterator (&reports);
                  get_reports_data_reset (get_reports_data);
                  set_client_state (CLIENT_AUTHENTIC);
                  return;
                  break;
                case 2:
                  if (send_find_error_to_client
                        ("get_reports", "filter",
                        get_reports_data->get.filt_id, gmp_parser))
                    {
                      error_send_to_client (error);
                      return;
                    }
                  /* This error always occurs before anything is sent
                    * to the client, so the connection can stay up. */
                  if (request_report == 0)
                    cleanup_iterator (&reports);
                  get_reports_data_reset (get_reports_data);
                  set_client_state (CLIENT_AUTHENTIC);
                  return;
                  break;
                case -2:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("get_reports",
                                      "Failed to find report format for"
                                      " alert"));
                  if (request_report == 0)
                    cleanup_iterator (&reports);
                  get_reports_data_reset (get_reports_data);
                  set_client_state (CLIENT_AUTHENTIC);
                  return;
                  break;
                case -3:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_INTERNAL_ERROR ("get_reports"));
                  if (request_report == 0)
                    cleanup_iterator (&reports);
                  get_reports_data_reset (get_reports_data);
                  set_client_state (CLIENT_AUTHENTIC);
                  return;
                  break;
                case -4:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("get_reports",
                                      "Failed to find filter for"
                                      " alert"));
                  if (request_report == 0)
                    cleanup_iterator (&reports);
                  get_reports_data_reset (get_reports_data);
                  set_client_state (CLIENT_AUTHENTIC);
                  return;
                  break;
                default:
                case -1:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_INTERNAL_ERROR ("get_reports"));
                  /* Close the connection with the client, as part of the
                    * response may have been sent before the error
                    * occurred. */
                  internal_error_send_to_client (error);
                  if (request_report == 0)
                    cleanup_iterator (&reports);
                  get_reports_data_reset (get_reports_data);
                  set_client_state (CLIENT_AUTHENTIC);
                  return;
                  break;
              }
          else if (ret == 2)
            {
              if (send_find_error_to_client
                    ("get_reports", "filter",
                     get_reports_data->get.filt_id, gmp_parser))
                {
                  error_send_to_client (error);
                  return;
                }
              /* This error always occurs before anything is sent
                * to the client, so the connection can stay up. */
              if (request_report == 0)
                cleanup_iterator (&reports);
              get_reports_data_reset (get_reports_data);
              set_client_state (CLIENT_AUTHENTIC);
              return;
            }
          else
            {
              /* Close the connection with the client, as part of the
                * response may have been sent before the error
                * occurred. */
              internal_error_send_to_client (error);
              if (request_report == 0)
                cleanup_iterator (&reports);
              get_reports_data_reset (get_reports_data);
              set_client_state (CLIENT_AUTHENTIC);
              return;
            }
        }
      if (get_reports_data->alert_id == NULL)
        SEND_TO_CLIENT_OR_FAIL ("</report>");

      count++;

      if (request_report)
        /* Just to be safe, because iterator has been freed. */
        break;
    }
  if (request_report == 0)
    cleanup_iterator (&reports);

  if (get_reports_data->alert_id)
    SEND_TO_CLIENT_OR_FAIL (XML_OK ("get_reports"));
  else
    {
      filtered = get_reports_data->get.id
                  ? 1
                  : report_count (&get_reports_data->report_get);
      SEND_GET_END ("report", &get_reports_data->report_get, count,
                    filtered);
    }

  get_reports_data_reset (get_reports_data);
  set_client_state (CLIENT_AUTHENTIC);
}

/**
 * @brief Handle end of GET_REPORT_FORMATS element.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 */
static void
handle_get_report_formats (gmp_parser_t *gmp_parser, GError **error)
{
  if (get_report_formats_data->params &&
      get_report_formats_data->get.trash)
    SEND_TO_CLIENT_OR_FAIL
     (XML_ERROR_SYNTAX ("get_report_formats",
                        "Params given with trash"));
  else
    {
      iterator_t report_formats;
      int count, filtered, ret, first;

      INIT_GET (report_format, Report Format);

      ret = init_report_format_iterator (&report_formats,
                                          &get_report_formats_data->get);
      if (ret)
        {
          switch (ret)
            {
              case 1:
                if (send_find_error_to_client ("get_report_formats",
                                               "report_format",
                                               get_report_formats_data->get.id,
                                               gmp_parser))
                  {
                    error_send_to_client (error);
                    return;
                  }
                break;
              case 2:
                if (send_find_error_to_client
                      ("get_report_formats", "filter",
                       get_report_formats_data->get.filt_id, gmp_parser))
                  {
                    error_send_to_client (error);
                    return;
                  }
                break;
              case -1:
                SEND_TO_CLIENT_OR_FAIL
                  (XML_INTERNAL_ERROR ("get_report_formats"));
                break;
            }
          get_report_formats_data_reset (get_report_formats_data);
          set_client_state (CLIENT_AUTHENTIC);
          return;
        }

      SEND_GET_START ("report_format");
      while (1)
        {
          time_t trust_time;

          ret = get_next (&report_formats,
                          &get_report_formats_data->get, &first, &count,
                          init_report_format_iterator);
          if (ret == 1)
            break;
          if (ret == -1)
            {
              internal_error_send_to_client (error);
              return;
            }

          SEND_GET_COMMON (report_format,
                            &get_report_formats_data->get,
                            &report_formats);

          trust_time = report_format_iterator_trust_time
                        (&report_formats);

          SENDF_TO_CLIENT_OR_FAIL
           ("<extension>%s</extension>"
            "<content_type>%s</content_type>"
            "<summary>%s</summary>"
            "<description>%s</description>"
            "<predefined>%i</predefined>",
            report_format_iterator_extension (&report_formats),
            report_format_iterator_content_type (&report_formats),
            report_format_iterator_summary (&report_formats),
            report_format_iterator_description (&report_formats),
            get_report_formats_data->get.trash
              ? trash_report_format_predefined
                 (get_iterator_resource (&report_formats))
              : report_format_predefined
                 (get_iterator_resource (&report_formats)));

          if (get_report_formats_data->alerts)
            {
              iterator_t alerts;

              SEND_TO_CLIENT_OR_FAIL ("<alerts>");
              init_report_format_alert_iterator (&alerts,
                                          get_iterator_resource
                                            (&report_formats));
              while (next (&alerts))
                {
                  if (report_format_alert_iterator_readable (&alerts) == 0)
                    /* Only show alerts the user may see. */
                    continue;

                  SENDF_TO_CLIENT_OR_FAIL
                   ("<alert id=\"%s\">"
                    "<name>%s</name>",
                    report_format_alert_iterator_uuid (&alerts),
                    report_format_alert_iterator_name (&alerts));
                  if (report_format_alert_iterator_readable (&alerts))
                    SEND_TO_CLIENT_OR_FAIL ("</alert>");
                  else
                    SEND_TO_CLIENT_OR_FAIL ("<permissions/>"
                                            "</alert>");
                }
              cleanup_iterator (&alerts);
              SEND_TO_CLIENT_OR_FAIL ("</alerts>");
            }

          if (get_report_formats_data->params
              || get_report_formats_data->get.details)
            {
              iterator_t params;
              init_report_format_param_iterator
                (&params, get_iterator_resource (&report_formats),
                get_report_formats_data->get.trash, 1, NULL);
              while (next (&params))
                {
                  long long int min, max;
                  iterator_t options;

                  SENDF_TO_CLIENT_OR_FAIL
                   ("<param>"
                    "<name>%s</name>"
                    "<type>%s",
                    report_format_param_iterator_name (&params),
                    report_format_param_iterator_type_name (&params));

                  min = report_format_param_iterator_type_min (&params);
                  if (min > LLONG_MIN)
                    SENDF_TO_CLIENT_OR_FAIL ("<min>%lli</min>", min);

                  max = report_format_param_iterator_type_max (&params);
                  if (max < LLONG_MAX)
                    SENDF_TO_CLIENT_OR_FAIL ("<max>%lli</max>", max);

                  if (report_format_param_iterator_type (&params)
                      == REPORT_FORMAT_PARAM_TYPE_REPORT_FORMAT_LIST)
                    {
                      const char *value;
                      const char *fallback;
                      value = report_format_param_iterator_value (&params);
                      fallback = report_format_param_iterator_fallback
                                    (&params);

                      SENDF_TO_CLIENT_OR_FAIL
                        ("</type><value>%s",
                         value ? value : "");
                      if (value)
                        {
                          gchar **ids, **current_id;
                          ids = g_strsplit (value, ",", -1);
                          current_id = ids;
                          while (*current_id)
                            {
                              report_format_t value_rf;
                              gchar *name;
                              find_report_format_with_permission
                                    (*current_id, &value_rf,
                                     "get_report_formats");
                              name = value_rf ? report_format_name (value_rf)
                                              : NULL;

                              SENDF_TO_CLIENT_OR_FAIL
                                ("<report_format id=\"%s\">"
                                 "<name>%s</name>"
                                 "</report_format>",
                                 *current_id,
                                 name ? name : "");

                              g_free (name);
                              current_id ++;
                            }
                          g_strfreev (ids);
                        }

                      SENDF_TO_CLIENT_OR_FAIL
                        ("</value><default>%s",
                         fallback ? fallback : "");
                      if (fallback)
                        {
                          gchar **ids, **current_id;
                          ids = g_strsplit (fallback, ",", -1);
                          current_id = ids;
                          while (*current_id)
                            {
                              report_format_t value_rf;
                              gchar *name;
                              find_report_format_with_permission
                                    (*current_id, &value_rf,
                                     "get_report_formats");
                              name = value_rf ? report_format_name (value_rf)
                                              : NULL;

                              SENDF_TO_CLIENT_OR_FAIL
                                ("<report_format id=\"%s\">"
                                 "<name>%s</name>"
                                 "</report_format>",
                                 *current_id,
                                 name ? name : "");

                              g_free (name);
                              current_id ++;
                            }
                          g_strfreev (ids);
                        }

                      SENDF_TO_CLIENT_OR_FAIL
                        ("</default>");
                    }
                  else
                    {
                      SENDF_TO_CLIENT_OR_FAIL
                        ("</type>"
                         "<value>%s</value>"
                         "<default>%s</default>",
                         report_format_param_iterator_value (&params),
                         report_format_param_iterator_fallback (&params));
                    }

                  if (report_format_param_iterator_type (&params)
                      == REPORT_FORMAT_PARAM_TYPE_SELECTION)
                    {
                      SEND_TO_CLIENT_OR_FAIL ("<options>");
                      init_param_option_iterator
                        (&options,
                        report_format_param_iterator_param
                          (&params),
                        1,
                        NULL);
                      while (next (&options))
                        SENDF_TO_CLIENT_OR_FAIL
                         ("<option>%s</option>",
                          param_option_iterator_value (&options));
                      cleanup_iterator (&options);
                      SEND_TO_CLIENT_OR_FAIL ("</options>");
                    }

                  SEND_TO_CLIENT_OR_FAIL ("</param>");
                }
              cleanup_iterator (&params);
            }

          if (get_report_formats_data->get.details)
            {
              file_iterator_t files;
              if (init_report_format_file_iterator
                    (&files, get_iterator_resource (&report_formats)))
                {
                  cleanup_iterator (&report_formats);
                  error_send_to_client (error);
                  return;
                }
              while (next_file (&files))
                {
                  gchar *content = file_iterator_content_64 (&files);
                  SENDF_TO_CLIENT_OR_FAIL
                   ("<file name=\"%s\">%s</file>",
                    file_iterator_name (&files),
                    content);
                  g_free (content);
                }
              cleanup_file_iterator (&files);

              SENDF_TO_CLIENT_OR_FAIL
               ("<signature>%s</signature>",
                report_format_iterator_signature (&report_formats));
            }

          SENDF_TO_CLIENT_OR_FAIL
           ("<trust>%s<time>%s</time></trust>"
            "<active>%i</active>",
            get_report_formats_data->get.trash
              ? report_format_iterator_trust (&report_formats)
              : (report_format_predefined (get_iterator_resource
                                            (&report_formats))
                  ? "yes"
                  : report_format_iterator_trust (&report_formats)),
            iso_time (&trust_time),
            report_format_iterator_active (&report_formats));

          SEND_TO_CLIENT_OR_FAIL ("</report_format>");
          count++;
        }
      cleanup_iterator (&report_formats);
      filtered = get_report_formats_data->get.id
                  ? 1
                  : report_format_count (&get_report_formats_data->get);
      SEND_GET_END ("report_format", &get_report_formats_data->get,
                    count, filtered);
    }
  get_report_formats_data_reset (get_report_formats_data);
  set_client_state (CLIENT_AUTHENTIC);
}

/**
 * @brief Handle end of GET_RESULTS element.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 */
static void
handle_get_results (gmp_parser_t *gmp_parser, GError **error)
{
  result_t result = 0;
  task_t task = 0;

  if (acl_user_may ("get_results") == 0)
    {
      SEND_TO_CLIENT_OR_FAIL
       (XML_ERROR_SYNTAX ("get_results",
                          "Permission denied"));
      get_results_data_reset (get_results_data);
      set_client_state (CLIENT_AUTHENTIC);
      return;
    }

  if (current_credentials.username == NULL)
    {
      get_results_data_reset (get_results_data);
      SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_results"));
      set_client_state (CLIENT_AUTHENTIC);
      return;
    }

  if (get_results_data->get.trash)
    {
      SEND_TO_CLIENT_OR_FAIL
       (XML_ERROR_SYNTAX ("get_results",
                          "Getting results from the trashcan is not"
                          " supported"));
      get_results_data_reset (get_results_data);
      set_client_state (CLIENT_AUTHENTIC);
      return;
    }

  if (get_results_data->get.id
      && find_result_with_permission (get_results_data->get.id,
                                      &result,
                                      NULL))
    SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_results"));
  else if (get_results_data->get.id && result == 0)
    {
      if (send_find_error_to_client ("get_results", "result",
                                      get_results_data->get.id,
                                      gmp_parser))
        {
          error_send_to_client (error);
          return;
        }
    }
  else if (get_results_data->task_id
            && find_task_with_permission (get_results_data->task_id,
                                          &task,
                                          NULL))
    SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_results"));
  else if (get_results_data->task_id && task == 0)
    {
      if (send_find_error_to_client ("get_results", "task",
                                      get_results_data->task_id,
                                      gmp_parser))
        {
          error_send_to_client (error);
          return;
        }
    }
  else
    {
      const char* filter;
      iterator_t results;
      int notes, overrides;
      int count, ret, first;
      gchar *report_id;
      report_t report;

      if (get_results_data->get.filt_id
          && strcmp (get_results_data->get.filt_id, FILT_ID_NONE))
        {
          filter = filter_term (get_results_data->get.filt_id);
        }
      else
        filter = get_results_data->get.filter;

      SEND_TO_CLIENT_OR_FAIL ("<get_results_response"
                              " status=\"" STATUS_OK "\""
                              " status_text=\"" STATUS_OK_TEXT "\">");
      INIT_GET (result, Result);

      // Do not allow ignore_pagination here
      get_results_data->get.ignore_pagination = 0;

      /* Note: This keyword may be removed or renamed at any time once there
       * is a better solution like an operator for conditions that must always
       * apply or support for parentheses in filters. */
      report_id = filter_term_value (filter,
                                     "_and_report_id");
      report = 0;

      if (report_id)
        {
          if (find_report_with_permission (report_id,
                                           &report,
                                           NULL))
            {
              g_free (report_id);
              g_warning ("Failed to get report");
              SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_results"));
              return;
            }

          if (report == 0)
            report = -1;
        }
      g_free (report_id);

      init_result_get_iterator (&results, &get_results_data->get,
                                report,  /* report restriction */
                                NULL, /* No host restriction */
                                NULL);  /* No extra order SQL. */

      manage_report_filter_controls (filter,
                                      NULL, /* first */
                                      NULL, /* max */
                                      NULL, /* sort_field */
                                      NULL, /* sort_order */
                                      NULL, /* result_hosts_only */
                                      NULL, /* min_qod */
                                      NULL, /* levels */
                                      NULL, /* delta_states */
                                      NULL, /* search_phrase */
                                      NULL, /* search_phrase_exact */
                                      &notes,
                                      &overrides,
                                      NULL, /* apply_overrides */
                                      NULL);/* zone */

      if (next (&results))
        {
          if (get_results_data->get.id && (task == 0))
            {
              char *task_id;
              task_uuid (result_iterator_task (&results), &task_id);
              if (find_task_with_permission (task_id, &task, NULL))
                {
                  free (task_id);
                  internal_error_send_to_client (error);
                  cleanup_iterator (&results);
                  return;
                }
              free (task_id);
            }

          count = 0;
          do
            {
              GString *buffer = g_string_new ("");
              buffer_results_xml (buffer,
                                  &results,
                                  task,
                                  notes,
                                  get_results_data->notes_details,
                                  overrides,
                                  get_results_data->overrides_details,
                                  1,
                                  /* show tag details if selected by ID */
                                  get_results_data->get.id != NULL,
                                  get_results_data->get.details,
                                  NULL,
                                  NULL,
                                  0,
                                  -1,
                                  0);   /* Lean. */
              SEND_TO_CLIENT_OR_FAIL (buffer->str);
              g_string_free (buffer, TRUE);
              count ++;
            }
          while (next (&results));
        }
      cleanup_iterator (&results);

      manage_filter_controls (get_results_data->get.filter,
                              &first, NULL, NULL, NULL);

      if (get_results_data->get_counts)
        {
          int filtered;

          filtered = get_results_data->get.id
                      ? 1 : result_count (&get_results_data->get,
                                          report /* No report */,
                                          NULL /* No host */);

          if (send_get_end ("result", &get_results_data->get, count, filtered,
                            resource_count ("result", &get_results_data->get),
                            gmp_parser->client_writer,
                            gmp_parser->client_writer_data))
            {
              error_send_to_client (error);
              return;
            }
        }
      else if (send_get_end_no_counts ("result",
                                       &get_results_data->get,
                                       gmp_parser->client_writer,
                                       gmp_parser->client_writer_data))
        {
          error_send_to_client (error);
          return;
        }
    }

  get_results_data_reset (get_results_data);
  set_client_state (CLIENT_AUTHENTIC);
}

/**
 * @brief Handle end of GET_ROLES element.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 */
static void
handle_get_roles (gmp_parser_t *gmp_parser, GError **error)
{
  iterator_t roles;
  int count, filtered, ret, first;

  INIT_GET (role, Role);

  ret = init_role_iterator (&roles, &get_roles_data->get);
  if (ret)
    {
      switch (ret)
        {
          case 1:
            if (send_find_error_to_client ("get_roles", "role",
                                            get_roles_data->get.id,
                                            gmp_parser))
              {
                error_send_to_client (error);
                return;
              }
            break;
          case 2:
            if (send_find_error_to_client
                  ("get_roles", "filter", get_roles_data->get.filt_id,
                  gmp_parser))
              {
                error_send_to_client (error);
                return;
              }
            break;
          case -1:
            SEND_TO_CLIENT_OR_FAIL
              (XML_INTERNAL_ERROR ("get_roles"));
            break;
        }
      get_roles_data_reset (get_roles_data);
      set_client_state (CLIENT_AUTHENTIC);
      return;
    }

  SEND_GET_START ("role");
  while (1)
    {
      gchar *users;

      ret = get_next (&roles, &get_roles_data->get, &first, &count,
                      init_role_iterator);
      if (ret == 1)
        break;
      if (ret == -1)
        {
          internal_error_send_to_client (error);
          return;
        }

      SEND_GET_COMMON (role, &get_roles_data->get, &roles);

      users = role_users (get_iterator_resource (&roles));
      SENDF_TO_CLIENT_OR_FAIL ("<users>%s</users>", users ? users : "");
      g_free (users);

      SEND_TO_CLIENT_OR_FAIL ("</role>");

      count++;
    }
  cleanup_iterator (&roles);
  filtered = get_roles_data->get.id
              ? 1
              : role_count (&get_roles_data->get);
  SEND_GET_END ("role", &get_roles_data->get, count, filtered);

  get_roles_data_reset (get_roles_data);
  set_client_state (CLIENT_AUTHENTIC);
}

/**
 * @brief Handle end of GET_SCANNERS element.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 */
static void
handle_get_scanners (gmp_parser_t *gmp_parser, GError **error)
{
  iterator_t scanners;
  int ret, count, filtered, first;

  INIT_GET (scanner, Scanner);
  ret = init_scanner_iterator (&scanners, &get_scanners_data->get);
  switch (ret)
    {
      case 0:
        break;
      case 1:
        if (send_find_error_to_client
             ("get_scanners", "scanners", get_scanners_data->get.id,
              gmp_parser))
          {
            error_send_to_client (error);
            break;
          }
        break;
      case 2:
        if (send_find_error_to_client
             ("get_scanners", "filter", get_scanners_data->get.filt_id,
              gmp_parser))
          {
            error_send_to_client (error);
            break;
          }
        break;
      case -1:
        SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_scanners"));
        break;
    }
  if (ret)
    {
      get_scanners_data_reset (get_scanners_data);
      set_client_state (CLIENT_AUTHENTIC);
      return;
    }

  SEND_GET_START ("scanner");
  while (1)
    {
      gchar *credential_id;
      ret = get_next (&scanners, &get_scanners_data->get, &first, &count,
                      init_scanner_iterator);
      if (ret == 1)
        break;
      if (ret == -1)
        {
          internal_error_send_to_client (error);
          break;
        }

      SEND_GET_COMMON (scanner, &get_scanners_data->get, &scanners);

      SENDF_TO_CLIENT_OR_FAIL
       ("<host>%s</host>"
        "<port>%d</port>"
        "<type>%d</type>"
        "<ca_pub>%s</ca_pub>",
        scanner_iterator_host (&scanners) ?: "",
        scanner_iterator_port (&scanners) ?: 0,
        scanner_iterator_type (&scanners),
        scanner_iterator_ca_pub (&scanners) ?: "");

      if (get_scanners_data->get.details)
        {
          time_t activation_time, expiration_time;
          gchar *activation_time_str, *expiration_time_str;

          if (scanner_iterator_ca_pub (&scanners))
            {
              /* CA Certificate */
              gchar *md5_fingerprint, *issuer;

              get_certificate_info (scanner_iterator_ca_pub (&scanners),
                                    -1,
                                    &activation_time,
                                    &expiration_time,
                                    &md5_fingerprint,
                                    NULL,   /* sha256_fingerprint */
                                    NULL,   /* subject */
                                    &issuer,
                                    NULL,   /* serial */
                                    NULL);  /* certificate_format */

              activation_time_str = certificate_iso_time (activation_time);
              expiration_time_str = certificate_iso_time (expiration_time);
              SENDF_TO_CLIENT_OR_FAIL
               ("<ca_pub_info>"
                "<time_status>%s</time_status>"
                "<activation_time>%s</activation_time>"
                "<expiration_time>%s</expiration_time>"
                "<md5_fingerprint>%s</md5_fingerprint>"
                "<issuer>%s</issuer>"
                "</ca_pub_info>",
                certificate_time_status (activation_time, expiration_time),
                activation_time_str,
                expiration_time_str,
                md5_fingerprint,
                issuer);
              g_free (activation_time_str);
              g_free (expiration_time_str);
              g_free (md5_fingerprint);
              g_free (issuer);
            }
        }

      credential_id = credential_uuid (scanner_iterator_credential (&scanners));
      SENDF_TO_CLIENT_OR_FAIL
       ("<credential id=\"%s\">"
        "<name>%s</name>"
        "<type>%s</type>"
        "<trash>%d</trash>",
        credential_id ? credential_id : "",
        scanner_iterator_credential_name (&scanners) ?: "",
        scanner_iterator_credential_type (&scanners) ?: "",
        scanner_iterator_credential_trash (&scanners));

      if (get_scanners_data->get.details)
        {
          time_t activation_time, expiration_time;
          gchar *activation_time_str, *expiration_time_str;

          if (scanner_iterator_key_pub (&scanners))
            {
              /* Certificate */
              gchar *md5_fingerprint, *issuer;

              get_certificate_info (scanner_iterator_key_pub (&scanners),
                                    -1,
                                    &activation_time,
                                    &expiration_time,
                                    &md5_fingerprint,
                                    NULL,   /* sha256_fingerprint */
                                    NULL,   /* subject */
                                    &issuer,
                                    NULL,   /* serial */
                                    NULL);  /* certificate_format */

              activation_time_str = certificate_iso_time (activation_time);
              expiration_time_str = certificate_iso_time (expiration_time);
              SENDF_TO_CLIENT_OR_FAIL
               ("<certificate_info>"
                "<time_status>%s</time_status>"
                "<activation_time>%s</activation_time>"
                "<expiration_time>%s</expiration_time>"
                "<md5_fingerprint>%s</md5_fingerprint>"
                "<issuer>%s</issuer>"
                "</certificate_info>",
                certificate_time_status (activation_time, expiration_time),
                activation_time_str,
                expiration_time_str,
                md5_fingerprint,
                issuer);
              g_free (activation_time_str);
              g_free (expiration_time_str);
              g_free (md5_fingerprint);
              g_free (issuer);
            }
        }

      SENDF_TO_CLIENT_OR_FAIL
        ("</credential>");
      g_free (credential_id);
      count++;
      if (get_scanners_data->get.details)
        {
          iterator_t tasks;

          SEND_TO_CLIENT_OR_FAIL ("<tasks>");
          init_scanner_task_iterator (&tasks,
                                      get_iterator_resource (&scanners));
          while (next (&tasks))
            {
              if (scanner_task_iterator_readable (&tasks) == 0)
                /* Only show tasks the user may see. */
                continue;

              SENDF_TO_CLIENT_OR_FAIL
               ("<task id=\"%s\">"
                "<name>%s</name>",
                scanner_task_iterator_uuid (&tasks),
                scanner_task_iterator_name (&tasks));

              if (scanner_task_iterator_readable (&tasks))
                SEND_TO_CLIENT_OR_FAIL ("</task>");
              else
                SEND_TO_CLIENT_OR_FAIL ("<permissions/>"
                                        "</task>");
            }
          cleanup_iterator (&tasks);
          SEND_TO_CLIENT_OR_FAIL ("</tasks>");
        }
      if ((scanner_iterator_type (&scanners) == SCANNER_TYPE_OPENVAS)
          && get_scanners_data->get.details)
        {
          char *s_name = NULL, *s_ver = NULL;
          char *d_name = NULL, *d_ver = NULL;
          char *p_name = NULL, *p_ver = NULL, *desc = NULL;
          GSList *params = NULL, *nodes;

          if (!osp_get_version_from_iterator
                (&scanners, &s_name, &s_ver, &d_name, &d_ver, &p_name, &p_ver)
              && !osp_get_details_from_iterator (&scanners, &desc, &params))
            {
              SENDF_TO_CLIENT_OR_FAIL
               ("<info><scanner><name>%s</name><version>%s</version>"
                "</scanner><daemon><name>%s</name><version>%s</version>"
                "</daemon><protocol><name>%s</name><version>%s"
                "</version></protocol><description>%s</description>",
                s_name, s_ver, d_name, d_ver, p_name, p_ver, desc);

              SENDF_TO_CLIENT_OR_FAIL ("<params>");
              nodes = params;
              while (nodes)
                {
                  osp_param_t *param = nodes->data;

                  SENDF_TO_CLIENT_OR_FAIL
                   ("<param><id>%s</id><name>%s</name>"
                    "<default>%s</default><description>%s</description>"
                    "<type>osp_%s</type><mandatory>%d</mandatory></param>",
                    osp_param_id (param), osp_param_name (param),
                    osp_param_default (param), osp_param_desc (param),
                    osp_param_type_str (param), osp_param_mandatory (param));

                  osp_param_free (nodes->data);
                  nodes = nodes->next;
                }
              SENDF_TO_CLIENT_OR_FAIL ("</params></info>");
            }
          else
            SENDF_TO_CLIENT_OR_FAIL
             ("<info><scanner><name/><version/></scanner>"
              "<daemon><name/><version/></daemon>"
              "<protocol><name/><version/></protocol><description/><params/>"
              "</info>");
          g_free (s_name);
          g_free (s_ver);
          g_free (d_name);
          g_free (d_ver);
          g_free (p_name);
          g_free (p_ver);
          g_free (desc);
          g_slist_free (params);
        }
      else if (get_scanners_data->get.details)
        {
          SENDF_TO_CLIENT_OR_FAIL
           ("<info><scanner><name>OpenVAS</name><version/></scanner>"
            "<daemon><name/><version/></daemon>"
            "<protocol><name/><version/></protocol><description/><params/>"
            "</info>");
        }
      SEND_TO_CLIENT_OR_FAIL ("</scanner>");
    }
  cleanup_iterator (&scanners);
  filtered = get_scanners_data->get.id
              ? 1 : scanner_count (&get_scanners_data->get);
  SEND_GET_END ("scanner", &get_scanners_data->get, count, filtered);
  get_scanners_data_reset (get_scanners_data);
  set_client_state (CLIENT_AUTHENTIC);
}

/**
 * @brief Handle end of GET_SCHEDULES element.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 */
static void
handle_get_schedules (gmp_parser_t *gmp_parser, GError **error)
{
  if (get_schedules_data->tasks && get_schedules_data->get.trash)
    SEND_TO_CLIENT_OR_FAIL
     (XML_ERROR_SYNTAX ("get_schedules",
                        "Attributes tasks and trash both given"));
  else
    {
      iterator_t schedules;
      int count, filtered, ret, first;

      INIT_GET (schedule, Schedule);

      ret = init_schedule_iterator (&schedules, &get_schedules_data->get);
      if (ret)
        {
          switch (ret)
            {
              case 1:
                if (send_find_error_to_client ("get_schedules",
                                               "schedule",
                                               get_schedules_data->get.id,
                                               gmp_parser))
                  {
                    error_send_to_client (error);
                    return;
                  }
                break;
              case 2:
                if (send_find_error_to_client
                      ("get_schedules", "filter",
                       get_schedules_data->get.filt_id, gmp_parser))
                  {
                    error_send_to_client (error);
                    return;
                  }
                break;
              case -1:
                SEND_TO_CLIENT_OR_FAIL
                  (XML_INTERNAL_ERROR ("get_schedules"));
                break;
            }
          get_schedules_data_reset (get_schedules_data);
          set_client_state (CLIENT_AUTHENTIC);
          return;
        }

      SEND_GET_START ("schedule");
      while (1)
        {
          const char *icalendar;

          ret = get_next (&schedules, &get_schedules_data->get, &first,
                          &count, init_schedule_iterator);
          if (ret == 1)
            break;
          if (ret == -1)
            {
              internal_error_send_to_client (error);
              return;
            }

          SEND_GET_COMMON (schedule, &get_schedules_data->get, &schedules);

          icalendar = schedule_iterator_icalendar (&schedules);

          SENDF_TO_CLIENT_OR_FAIL
           ("<icalendar>%s</icalendar>"
            "<timezone>%s</timezone>",
            icalendar ? icalendar : "",
            schedule_iterator_timezone (&schedules)
              ? schedule_iterator_timezone (&schedules)
              : "UTC");

          if (get_schedules_data->tasks)
            {
              iterator_t tasks;

              SEND_TO_CLIENT_OR_FAIL ("<tasks>");
              init_schedule_task_iterator (&tasks,
                                            get_iterator_resource
                                            (&schedules));
              while (next (&tasks))
                {
                  SENDF_TO_CLIENT_OR_FAIL ("<task id=\"%s\">"
                                           "<name>%s</name>",
                                           schedule_task_iterator_uuid (&tasks),
                                           schedule_task_iterator_name
                                            (&tasks));
                  if (schedule_task_iterator_readable (&tasks))
                    SEND_TO_CLIENT_OR_FAIL ("</task>");
                  else
                    SEND_TO_CLIENT_OR_FAIL ("<permissions/>"
                                            "</task>");
                }
              cleanup_iterator (&tasks);
              SEND_TO_CLIENT_OR_FAIL ("</tasks>");
            }
          SEND_TO_CLIENT_OR_FAIL ("</schedule>");
          count++;
        }
      cleanup_iterator (&schedules);
      filtered = get_schedules_data->get.id
                  ? 1
                  : schedule_count (&get_schedules_data->get);
      SEND_GET_END ("schedule", &get_schedules_data->get, count, filtered);
    }
  get_schedules_data_reset (get_schedules_data);
  set_client_state (CLIENT_AUTHENTIC);
}

/**
 * @brief Handle end of CREATE_SCHEDULE element.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 */
static void
handle_create_schedule (gmp_parser_t *gmp_parser, GError **error)
{
  schedule_t new_schedule;
  gchar *ical_error = NULL;

  // Copy the schedule
  if (create_schedule_data->copy)
    {
      switch (copy_schedule (create_schedule_data->name,
                             create_schedule_data->comment,
                             create_schedule_data->copy,
                             &new_schedule))
        {
          case 0:
            {
              char *uuid;
              uuid = schedule_uuid (new_schedule);
              SENDF_TO_CLIENT_OR_FAIL (XML_OK_CREATED_ID ("create_schedule"),
                                       uuid);
              log_event ("schedule", "Schedule", uuid, "created");
              free (uuid);
              break;
            }
          case 1:
            SEND_TO_CLIENT_OR_FAIL
              (XML_ERROR_SYNTAX ("create_schedule",
                                 "Schedule exists already"));
            log_event_fail ("schedule", "Schedule", NULL, "created");
            break;
          case 2:
            if (send_find_error_to_client ("create_schedule", "schedule",
                                           create_schedule_data->copy,
                                           gmp_parser))
              {
                error_send_to_client (error);
                return;
              }
            log_event_fail ("schedule", "Schedule", NULL, "created");
            break;
          case 99:
            SEND_TO_CLIENT_OR_FAIL
              (XML_ERROR_SYNTAX ("create_schedule",
                                 "Permission denied"));
            log_event_fail ("schedule", "Schedule", NULL, "created");
            break;
          case -1:
          default:
            SEND_TO_CLIENT_OR_FAIL
              (XML_INTERNAL_ERROR ("create_schedule"));
            log_event_fail ("schedule", "Schedule", NULL, "created");
            break;
        }
      goto create_schedule_leave;
    }
  else if (create_schedule_data->name == NULL)
    {
      SEND_TO_CLIENT_OR_FAIL
        (XML_ERROR_SYNTAX ("create_schedule",
                           "A NAME entity is required"));
      goto create_schedule_leave;
    }
  else if (create_schedule_data->icalendar == NULL
           || strcmp (create_schedule_data->icalendar, "") == 0)
    {
      SEND_TO_CLIENT_OR_FAIL
        (XML_ERROR_SYNTAX ("create_schedule",
                           "An ICALENDAR entity is required"));
      goto create_schedule_leave;
    }

  switch (create_schedule (create_schedule_data->name,
                           create_schedule_data->comment,
                           create_schedule_data->icalendar,
                           create_schedule_data->timezone,
                           &new_schedule,
                           &ical_error))
    {
      case 0:
        {
          char *uuid = schedule_uuid (new_schedule);
          SENDF_TO_CLIENT_OR_FAIL
            ("<create_schedule_response status=\"201\""
             " status_text=\"OK, resource created\""
             " id=\"%s\">",
             uuid);
          if (ical_error)
            {
              SEND_TO_CLIENT_OR_FAIL
                ("<status_details>");
              SEND_TO_CLIENT_OR_FAIL
                (ical_error ? ical_error : "");
              SEND_TO_CLIENT_OR_FAIL
                ("</status_details>");
            }
          SEND_TO_CLIENT_OR_FAIL 
            ("</create_schedule_response>");
          log_event ("schedule", "Schedule", uuid, "created");
          free (uuid);
          break;
        }
      case 1:
        SEND_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("create_schedule",
                             "Schedule exists already"));
        log_event_fail ("schedule", "Schedule", NULL, "created");
        break;
      case 3:
        {
          SENDF_TO_CLIENT_OR_FAIL
            ("<create_schedule_response status=\"400\""
             " status_text=\"Invalid ICALENDAR: %s\">"
             "</create_schedule_response>", ical_error);
          log_event_fail ("schedule", "Schedule", NULL, "created");
        }
        break;
      case 4:
        SEND_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("create_schedule",
                             "Error in TIMEZONE"));
        log_event_fail ("schedule", "Schedule", NULL, "created");
        break;
      case 99:
        SEND_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("create_schedule",
                             "Permission denied"));
        log_event_fail ("schedule", "Schedule", NULL, "created");
        break;
      case -1:
        SEND_TO_CLIENT_OR_FAIL
          (XML_INTERNAL_ERROR ("create_schedule"));
        log_event_fail ("schedule", "Schedule", NULL, "created");
        break;
      default:
        assert (0);
        SEND_TO_CLIENT_OR_FAIL
          (XML_INTERNAL_ERROR ("create_schedule"));
        log_event_fail ("schedule", "Schedule", NULL, "created");
        break;
    }

create_schedule_leave:
  create_schedule_data_reset (create_schedule_data);
  set_client_state (CLIENT_AUTHENTIC);
}

/**
 * @brief Handle end of MODIFY_SCHEDULE element.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 */
static void
handle_modify_schedule (gmp_parser_t *gmp_parser, GError **error)
{
  gchar *ical_error = NULL;

  if (modify_schedule_data->icalendar == NULL
      || strcmp (modify_schedule_data->icalendar, "") == 0)
    {
      SEND_TO_CLIENT_OR_FAIL
        (XML_ERROR_SYNTAX ("modify_schedule",
                           "ICALENDAR element is required"));
      modify_schedule_data_reset (modify_schedule_data);
      set_client_state (CLIENT_AUTHENTIC);
      return;
    }

  switch (modify_schedule
                (modify_schedule_data->schedule_id,
                 modify_schedule_data->name,
                 modify_schedule_data->comment,
                 modify_schedule_data->icalendar,
                 modify_schedule_data->timezone,
                 &ical_error))
    {
      case 0:
        SENDF_TO_CLIENT_OR_FAIL
          ("<modify_schedule_response status=\"200\""
           " status_text=\"OK\">"
           "<status_details>%s</status_details>"
           "</modify_schedule_response>",
           ical_error ? ical_error : "");
        log_event ("schedule", "Schedule",
                   modify_schedule_data->schedule_id, "modified");
        break;
      case 1:
        if (send_find_error_to_client ("modify_schedule", "schedule",
                                        modify_schedule_data->schedule_id,
                                        gmp_parser))
          {
            error_send_to_client (error);
            return;
          }
        log_event_fail ("schedule", "Schedule",
                        modify_schedule_data->schedule_id,
                        "modified");
        break;
      case 2:
        SEND_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("modify_schedule",
                            "Schedule with new name exists already"));
        log_event_fail ("schedule", "Schedule",
                        modify_schedule_data->schedule_id,
                        "modified");
        break;
      case 3:
        SEND_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("modify_schedule",
                             "Error in type name"));
        log_event_fail ("schedule", "Schedule",
                        modify_schedule_data->schedule_id,
                        "modified");
        break;
      case 4:
        SEND_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("modify_schedule",
                             "MODIFY_SCHEDULE requires a schedule_id"));
        log_event_fail ("schedule", "Schedule",
                        modify_schedule_data->schedule_id,
                        "modified");
        break;
      case 6:
        {
          SENDF_TO_CLIENT_OR_FAIL
            ("<modify_schedule_response status=\"400\""
             " status_text=\"Invalid ICALENDAR: %s\">"
             "</modify_schedule_response>", ical_error);
          log_event_fail ("schedule", "Schedule",
                          modify_schedule_data->schedule_id, "modified");
        }
        break;
      case 7:
        SEND_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("modify_schedule",
                             "Error in TIMEZONE"));
        log_event_fail ("schedule", "Schedule",
                        modify_schedule_data->schedule_id, "modified");
        break;
      case 99:
        SEND_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("modify_schedule",
                             "Permission denied"));
        log_event_fail ("schedule", "Schedule",
                        modify_schedule_data->schedule_id,
                        "modified");
        break;
      default:
      case -1:
        SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("modify_schedule"));
        log_event_fail ("schedule", "Schedule",
                        modify_schedule_data->schedule_id,
                        "modified");
        break;
    }

  modify_schedule_data_reset (modify_schedule_data);
  set_client_state (CLIENT_AUTHENTIC);
}

/**
 * @brief Handle end of GET_SCHEDULES element.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 */
static void
handle_get_settings (gmp_parser_t *gmp_parser, GError **error)
{
  setting_t setting = 0;
  iterator_t settings;
  int count, filtered;

  if (acl_user_may ("get_settings") == 0)
    {
      SEND_TO_CLIENT_OR_FAIL
        (XML_ERROR_SYNTAX ("get_settings",
                           "Permission denied"));
      get_settings_data_reset (get_settings_data);
      set_client_state (CLIENT_AUTHENTIC);
      return;
    }

  init_setting_iterator (&settings,
                         get_settings_data->setting_id,
                         get_settings_data->filter,
                         get_settings_data->first,
                         get_settings_data->max,
                         get_settings_data->sort_order,
                         get_settings_data->sort_field);

  SEND_TO_CLIENT_OR_FAIL ("<get_settings_response"
                          " status=\"" STATUS_OK "\""
                          " status_text=\"" STATUS_OK_TEXT "\">");
  SENDF_TO_CLIENT_OR_FAIL ("<filters>"
                           "<term>%s</term>"
                           "</filters>"
                           "<settings start=\"%i\" max=\"%i\"/>",
                           get_settings_data->filter
                            ? get_settings_data->filter
                            : "",
                           /* Add 1 for 1 indexing. */
                           get_settings_data->first + 1,
                           get_settings_data->max);
  count = 0;
  while (next (&settings))
    {
      SENDF_TO_CLIENT_OR_FAIL ("<setting id=\"%s\">"
                               "<name>%s</name>"
                               "<comment>%s</comment>"
                               "<value>%s</value>",
                               setting_iterator_uuid (&settings),
                               setting_iterator_name (&settings),
                               setting_iterator_comment (&settings),
                               setting_iterator_value (&settings));

      if (setting_is_default_ca_cert (setting_iterator_uuid (&settings))
          && setting_iterator_value (&settings)
          && strlen (setting_iterator_value (&settings)))
        {
          time_t activation_time, expiration_time;
          gchar *activation_time_str, *expiration_time_str, *md5_fingerprint;
          gchar *issuer;

          get_certificate_info (setting_iterator_value (&settings),
                                -1,
                                &activation_time,
                                &expiration_time,
                                &md5_fingerprint,
                                NULL,   /* sha256_fingerprint */
                                NULL,   /* subject */
                                &issuer,
                                NULL,   /* serial */
                                NULL);  /* certificate_format */

          activation_time_str = certificate_iso_time (activation_time);
          expiration_time_str = certificate_iso_time (expiration_time);
          SENDF_TO_CLIENT_OR_FAIL
           ("<certificate_info>"
            "<time_status>%s</time_status>"
            "<activation_time>%s</activation_time>"
            "<expiration_time>%s</expiration_time>"
            "<md5_fingerprint>%s</md5_fingerprint>"
            "<issuer>%s</issuer>"
            "</certificate_info>",
            certificate_time_status (activation_time, expiration_time),
            activation_time_str,
            expiration_time_str,
            md5_fingerprint,
            issuer);
          g_free (activation_time_str);
          g_free (expiration_time_str);
          g_free (md5_fingerprint);
          g_free (issuer);
        }

      SEND_TO_CLIENT_OR_FAIL ("</setting>");

      count++;
    }
  filtered = setting
              ? 1
              : setting_count (get_settings_data->filter);
  SENDF_TO_CLIENT_OR_FAIL ("<setting_count>"
                           "<filtered>%i</filtered>"
                           "<page>%i</page>"
                           "</setting_count>",
                           filtered,
                           count);
  cleanup_iterator (&settings);
  SEND_TO_CLIENT_OR_FAIL ("</get_settings_response>");

  get_settings_data_reset (get_settings_data);
  set_client_state (CLIENT_AUTHENTIC);
}

/**
 * @brief Handle end of GET_SYSTEM_REPORTS element.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 */
static void
handle_get_system_reports (gmp_parser_t *gmp_parser, GError **error)
{
  int ret;
  report_type_iterator_t types;

  ret = init_system_report_type_iterator
         (&types,
          get_system_reports_data->name,
          get_system_reports_data->slave_id);
  switch (ret)
    {
      case 1:
        if (send_find_error_to_client ("get_system_reports",
                                       "system report",
                                       get_system_reports_data->name,
                                       gmp_parser))
          {
            error_send_to_client (error);
            return;
          }
        break;
      case 2:
        if (send_find_error_to_client
              ("get_system_reports", "slave",
               get_system_reports_data->slave_id, gmp_parser))
          {
            error_send_to_client (error);
            return;
          }
        break;
      case 4:
        SEND_TO_CLIENT_OR_FAIL
          (XML_ERROR_UNAVAILABLE ("get_system_reports",
                                  "Could not connect to slave"));
        break;
      case 5:
        SEND_TO_CLIENT_OR_FAIL
          (XML_ERROR_UNAVAILABLE ("get_system_reports",
                                  "Authentication to slave failed"));
        break;
      case 6:
        SEND_TO_CLIENT_OR_FAIL
          (XML_ERROR_UNAVAILABLE ("get_system_reports",
                                  "Failed to get system report from slave"));
        break;
      case 99:
        SEND_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("get_system_reports",
                             "Permission denied"));
        break;
      default:
        assert (0);
        /* fallthrough */
      case -1:
        SEND_TO_CLIENT_OR_FAIL
          (XML_INTERNAL_ERROR ("get_system_reports"));
        break;
      case 0:
      case 3:
        {
          int report_ret;
          char *report;
          SEND_TO_CLIENT_OR_FAIL ("<get_system_reports_response"
                                  " status=\"" STATUS_OK "\""
                                  " status_text=\"" STATUS_OK_TEXT "\">");
          while (next_report_type (&types))
            if (get_system_reports_data->brief
                && (ret != 3))
              SENDF_TO_CLIENT_OR_FAIL
               ("<system_report>"
                "<name>%s</name>"
                "<title>%s</title>"
                "</system_report>",
                report_type_iterator_name (&types),
                report_type_iterator_title (&types));
            else if ((report_ret = manage_system_report
                                     (report_type_iterator_name (&types),
                                      get_system_reports_data->duration,
                                      get_system_reports_data->start_time,
                                      get_system_reports_data->end_time,
                                      get_system_reports_data->slave_id,
                                      &report))
                      && (report_ret != 3))
              {
                cleanup_report_type_iterator (&types);
                internal_error_send_to_client (error);
                return;
              }
            else if (report)
              {
                SENDF_TO_CLIENT_OR_FAIL
                 ("<system_report>"
                  "<name>%s</name>"
                  "<title>%s</title>"
                  "<report format=\"%s\""
                  " start_time=\"%s\" end_time=\"%s\""
                  " duration=\"%s\">"
                  "%s"
                  "</report>"
                  "</system_report>",
                  report_type_iterator_name (&types),
                  report_type_iterator_title (&types),
                  (report_ret == 3 ? "txt" : "png"),
                  get_system_reports_data->start_time
                    ? get_system_reports_data->start_time : "",
                  get_system_reports_data->end_time
                    ? get_system_reports_data->end_time : "",
                  get_system_reports_data->duration
                    ? get_system_reports_data->duration
                    : (get_system_reports_data->start_time
                       && get_system_reports_data->end_time)
                      ? ""
                      : "86400",
                  report);
                free (report);
              }
          cleanup_report_type_iterator (&types);
          SEND_TO_CLIENT_OR_FAIL ("</get_system_reports_response>");
        }
    }

  get_system_reports_data_reset (get_system_reports_data);
  set_client_state (CLIENT_AUTHENTIC);
}

/**
 * @brief Handle end of GET_TAGS element.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 */
static void
handle_get_tags (gmp_parser_t *gmp_parser, GError **error)
{
  iterator_t tags;
  int ret, count, first, filtered;

  INIT_GET (tag, Tag);

  if (get_tags_data->names_only)
    ret = init_tag_name_iterator (&tags, &get_tags_data->get);
  else
    ret = init_tag_iterator (&tags, &get_tags_data->get);

  if (ret)
    {
      switch (ret)
        {
          case 1:
            if (send_find_error_to_client ("get_tags",
                                           "tag", get_tags_data->get.id,
                                           gmp_parser))
              {
                error_send_to_client (error);
                return;
              }
            break;
          case 2:
            if (send_find_error_to_client
                  ("get_tags", "filter", get_tags_data->get.filt_id,
                   gmp_parser))
              {
                error_send_to_client (error);
                return;
              }
            break;
          default:
            SEND_TO_CLIENT_OR_FAIL
              (XML_INTERNAL_ERROR ("get_tags"));
        }
      get_tags_data_reset (get_tags_data);
      set_client_state (CLIENT_AUTHENTIC);
      return;
    }

  SEND_GET_START ("tag");
  while (1)
    {
      ret = get_next (&tags, &get_tags_data->get, &first, &count,
                      get_tags_data->names_only
                        ? init_tag_name_iterator
                        : init_tag_iterator);
      if (ret == 1)
        break;
      if (ret == -1)
        {
          internal_error_send_to_client (error);
          return;
        }

      if (get_tags_data->names_only)
        SENDF_TO_CLIENT_OR_FAIL ("<tag>"
                                 "<name>%s</name>"
                                 "</tag>",
                                 tag_name_iterator_name (&tags));
      else
        {
          gchar* value;

          value = g_markup_escape_text (tag_iterator_value (&tags), -1);

          SEND_GET_COMMON (tag, &get_tags_data->get, &tags);

          SENDF_TO_CLIENT_OR_FAIL ("<resources>"
                                   "<type>%s</type>"
                                   "<count><total>%d</total></count>"
                                   "</resources>"
                                   "<value>%s</value>"
                                   "<active>%d</active>"
                                   "</tag>",
                                   tag_iterator_resource_type (&tags),
                                   tag_iterator_resources (&tags),
                                   value,
                                   tag_iterator_active (&tags));

          g_free (value);
        }
      count++;
    }
  cleanup_iterator (&tags);
  filtered = get_tags_data->get.id
              ? 1
              : tag_count (&get_tags_data->get);
  SEND_GET_END ("tag", &get_tags_data->get, count, filtered);

  get_tags_data_reset (get_tags_data);
  set_client_state (CLIENT_AUTHENTIC);
}

/**
 * @brief Handle end of GET_TARGETS element.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 */
static void
handle_get_targets (gmp_parser_t *gmp_parser, GError **error)
{
  if (get_targets_data->tasks && get_targets_data->get.trash)
    SEND_TO_CLIENT_OR_FAIL
     (XML_ERROR_SYNTAX ("get_target",
                        "GET_TARGETS tasks given with trash"));
  else
    {
      iterator_t targets;
      int count, filtered, ret, first;

      INIT_GET (target, Target);

      ret = init_target_iterator (&targets, &get_targets_data->get);
      if (ret)
        {
          switch (ret)
            {
              case 1:
                if (send_find_error_to_client ("get_targets",
                                               "target",
                                               get_targets_data->get.id,
                                               gmp_parser))
                  {
                    error_send_to_client (error);
                    return;
                  }
                break;
              case 2:
                if (send_find_error_to_client
                      ("get_targets", "filter",
                       get_targets_data->get.filt_id, gmp_parser))
                  {
                    error_send_to_client (error);
                    return;
                  }
                break;
              case -1:
                SEND_TO_CLIENT_OR_FAIL
                  (XML_INTERNAL_ERROR ("get_targets"));
                break;
            }
          get_targets_data_reset (get_targets_data);
          set_client_state (CLIENT_AUTHENTIC);
          return;
        }

      SEND_GET_START ("target");
      while (1)
        {
          char *ssh_name, *ssh_uuid, *smb_name, *smb_uuid;
          char *esxi_name, *esxi_uuid, *snmp_name, *snmp_uuid;
          char *ssh_elevate_name, *ssh_elevate_uuid;
          const char *port_list_uuid, *port_list_name, *ssh_port;
          const char *hosts, *exclude_hosts, *reverse_lookup_only;
          const char *reverse_lookup_unify, *allow_simultaneous_ips;
          credential_t ssh_credential, smb_credential;
          credential_t esxi_credential, snmp_credential;
          credential_t ssh_elevate_credential;
          int port_list_trash, max_hosts, port_list_available;
          int ssh_credential_available;
          int smb_credential_available;
          int esxi_credential_available;
          int snmp_credential_available;
          int ssh_elevate_credential_available;

          ret = get_next (&targets, &get_targets_data->get, &first,
                          &count, init_target_iterator);
          if (ret == 1)
            break;
          if (ret == -1)
            {
              internal_error_send_to_client (error);
              return;
            }

          ssh_credential = target_iterator_ssh_credential (&targets);
          smb_credential = target_iterator_smb_credential (&targets);
          esxi_credential = target_iterator_esxi_credential (&targets);
          snmp_credential = target_iterator_snmp_credential (&targets);
          ssh_elevate_credential
            = target_iterator_ssh_elevate_credential (&targets);
          ssh_credential_available = 1;
          if (get_targets_data->get.trash
              && target_iterator_ssh_trash (&targets))
            {
              ssh_name = trash_credential_name (ssh_credential);
              ssh_uuid = trash_credential_uuid (ssh_credential);
              ssh_credential_available
                = trash_credential_readable (ssh_credential);
            }
          else if (ssh_credential)
            {
              credential_t found;

              ssh_name = credential_name (ssh_credential);
              ssh_uuid = credential_uuid (ssh_credential);
              if (find_credential_with_permission
                    (ssh_uuid,
                     &found,
                     "get_credentials"))
                abort ();
              ssh_credential_available = (found > 0);
            }
          else
            {
              ssh_name = NULL;
              ssh_uuid = NULL;
            }
          smb_credential_available = 1;
          if (get_targets_data->get.trash
              && target_iterator_smb_trash (&targets))
            {
              smb_name = trash_credential_name (smb_credential);
              smb_uuid = trash_credential_uuid (smb_credential);
              smb_credential_available
                = trash_credential_readable (smb_credential);
            }
          else if (smb_credential)
            {
              credential_t found;

              smb_name = credential_name (smb_credential);
              smb_uuid = credential_uuid (smb_credential);
              if (find_credential_with_permission
                    (smb_uuid,
                     &found,
                     "get_credentials"))
                abort ();
              smb_credential_available = (found > 0);
            }
          else
            {
              smb_name = NULL;
              smb_uuid = NULL;
            }
          esxi_credential_available = 1;
          if (get_targets_data->get.trash
              && target_iterator_esxi_trash (&targets))
            {
              esxi_name
                = trash_credential_name (esxi_credential);
              esxi_uuid
                = trash_credential_uuid (esxi_credential);
              esxi_credential_available
                = trash_credential_readable (esxi_credential);
            }
          else if (esxi_credential)
            {
              credential_t found;

              esxi_name = credential_name (esxi_credential);
              esxi_uuid = credential_uuid (esxi_credential);
              if (find_credential_with_permission
                    (esxi_uuid,
                     &found,
                     "get_credentials"))
                abort ();
              esxi_credential_available = (found > 0);
            }
          else
            {
              esxi_name = NULL;
              esxi_uuid = NULL;
            }
          snmp_credential_available = 1;
          if (get_targets_data->get.trash
              && target_iterator_snmp_trash (&targets))
            {
              snmp_name
                = trash_credential_name (snmp_credential);
              snmp_uuid
                = trash_credential_uuid (snmp_credential);
              snmp_credential_available
                = trash_credential_readable (snmp_credential);
            }
          else if (snmp_credential)
            {
              credential_t found;

              snmp_name = credential_name (snmp_credential);
              snmp_uuid = credential_uuid (snmp_credential);
              if (find_credential_with_permission
                    (snmp_uuid,
                     &found,
                     "get_credentials"))
                abort ();
              snmp_credential_available = (found > 0);
            }
          else
            {
              snmp_name = NULL;
              snmp_uuid = NULL;
            }
          ssh_elevate_credential_available = 1;
          if (get_targets_data->get.trash
              && target_iterator_ssh_elevate_trash (&targets))
            {
              ssh_elevate_name
                = trash_credential_name (ssh_elevate_credential);
              ssh_elevate_uuid
                = trash_credential_uuid (ssh_elevate_credential);
              ssh_elevate_credential_available
                = trash_credential_readable (ssh_elevate_credential);
            }
          else if (ssh_elevate_credential)
            {
              credential_t found;

              ssh_elevate_name = credential_name (ssh_elevate_credential);
              ssh_elevate_uuid = credential_uuid (ssh_elevate_credential);
              if (find_credential_with_permission
                    (ssh_elevate_uuid,
                     &found,
                     "get_credentials"))
                abort ();
              ssh_elevate_credential_available = (found > 0);
            }
          else
            {
              ssh_elevate_name = NULL;
              ssh_elevate_uuid = NULL;
            }
          port_list_uuid = target_iterator_port_list_uuid (&targets);
          port_list_name = target_iterator_port_list_name (&targets);
          port_list_trash = target_iterator_port_list_trash (&targets);
          ssh_port = target_iterator_ssh_port (&targets);

          port_list_available = 1;
          if (port_list_trash)
            port_list_available = trash_port_list_readable_uuid
                                    (port_list_uuid);
          else if (port_list_uuid)
            {
              port_list_t found;
              if (find_port_list_with_permission (port_list_uuid,
                                                  &found,
                                                  "get_port_lists"))
                abort ();
              port_list_available = (found > 0);
            }

          SEND_GET_COMMON (target, &get_targets_data->get, &targets);

          hosts = target_iterator_hosts (&targets);
          exclude_hosts = target_iterator_exclude_hosts (&targets);
          max_hosts = manage_count_hosts_max (hosts, exclude_hosts, 0);
          reverse_lookup_only = target_iterator_reverse_lookup_only
                                  (&targets);
          reverse_lookup_unify = target_iterator_reverse_lookup_unify
                                  (&targets);
          allow_simultaneous_ips
            = target_iterator_allow_simultaneous_ips (&targets);

          SENDF_TO_CLIENT_OR_FAIL ("<hosts>%s</hosts>"
                                   "<exclude_hosts>%s</exclude_hosts>"
                                   "<max_hosts>%i</max_hosts>"
                                   "<port_list id=\"%s\">"
                                   "<name>%s</name>"
                                   "<trash>%i</trash>",
                                   hosts,
                                   exclude_hosts ? exclude_hosts : "",
                                   max_hosts,
                                   port_list_uuid ? port_list_uuid : "",
                                   port_list_name ? port_list_name : "",
                                   port_list_trash);

          if (port_list_available == 0)
            SEND_TO_CLIENT_OR_FAIL ("<permissions/>");

          SENDF_TO_CLIENT_OR_FAIL ("</port_list>"
                                   "<ssh_credential id=\"%s\">"
                                   "<name>%s</name>"
                                   "<port>%s</port>"
                                   "<trash>%i</trash>",
                                   ssh_uuid ? ssh_uuid : "",
                                   ssh_name ? ssh_name : "",
                                   ssh_port ? ssh_port : "",
                                   (get_targets_data->get.trash
                                    && target_iterator_ssh_trash (&targets)));

          if (ssh_credential_available == 0)
            SEND_TO_CLIENT_OR_FAIL ("<permissions/>");

          SENDF_TO_CLIENT_OR_FAIL ("</ssh_credential>"
                                   "<smb_credential id=\"%s\">"
                                   "<name>%s</name>"
                                   "<trash>%i</trash>",
                                   smb_uuid ? smb_uuid : "",
                                   smb_name ? smb_name : "",
                                   (get_targets_data->get.trash
                                    && target_iterator_smb_trash (&targets)));

          if (smb_credential_available == 0)
            SEND_TO_CLIENT_OR_FAIL ("<permissions/>");

          SENDF_TO_CLIENT_OR_FAIL ("</smb_credential>"
                                   "<esxi_credential id=\"%s\">"
                                   "<name>%s</name>"
                                   "<trash>%i</trash>",
                                   esxi_uuid ? esxi_uuid : "",
                                   esxi_name ? esxi_name : "",
                                   (get_targets_data->get.trash
                                    && target_iterator_esxi_trash (&targets)));

          if (esxi_credential_available == 0)
            SEND_TO_CLIENT_OR_FAIL ("<permissions/>");

          SENDF_TO_CLIENT_OR_FAIL ("</esxi_credential>"
                                   "<snmp_credential id=\"%s\">"
                                   "<name>%s</name>"
                                   "<trash>%i</trash>",
                                   snmp_uuid ? snmp_uuid : "",
                                   snmp_name ? snmp_name : "",
                                   (get_targets_data->get.trash
                                    && target_iterator_snmp_trash (&targets)));

          if (snmp_credential_available == 0)
            SEND_TO_CLIENT_OR_FAIL ("<permissions/>");

          SENDF_TO_CLIENT_OR_FAIL ("</snmp_credential>"
                                   "<ssh_elevate_credential id=\"%s\">"
                                   "<name>%s</name>"
                                   "<trash>%i</trash>",
                                   ssh_elevate_uuid ? ssh_elevate_uuid : "",
                                   ssh_elevate_name ? ssh_elevate_name : "",
                                   (get_targets_data->get.trash
                                    && target_iterator_ssh_elevate_trash (&targets)));

          if (ssh_elevate_credential_available == 0)
            SEND_TO_CLIENT_OR_FAIL ("<permissions/>");

          SENDF_TO_CLIENT_OR_FAIL ("</ssh_elevate_credential>"
                                   "<reverse_lookup_only>"
                                   "%s"
                                   "</reverse_lookup_only>"
                                   "<reverse_lookup_unify>"
                                   "%s"
                                   "</reverse_lookup_unify>"
                                   "<alive_tests>%s</alive_tests>"
                                   "<allow_simultaneous_ips>"
                                   "%s"
                                   "</allow_simultaneous_ips>",
                                   reverse_lookup_only,
                                   reverse_lookup_unify,
                                   target_iterator_alive_tests (&targets),
                                   allow_simultaneous_ips);

          if (get_targets_data->get.details)
            SENDF_TO_CLIENT_OR_FAIL ("<port_range>%s</port_range>",
                                     target_port_range
                                      (get_iterator_resource (&targets)));

          if (get_targets_data->tasks)
            {
              iterator_t tasks;

              SEND_TO_CLIENT_OR_FAIL ("<tasks>");
              init_target_task_iterator (&tasks,
                                         get_iterator_resource (&targets));
              while (next (&tasks))
                {
                  if (target_task_iterator_readable (&tasks) == 0)
                    /* Only show tasks the user may see. */
                    continue;

                  SENDF_TO_CLIENT_OR_FAIL ("<task id=\"%s\">"
                                           "<name>%s</name>",
                                           target_task_iterator_uuid (&tasks),
                                           target_task_iterator_name (&tasks));
                  if (target_task_iterator_readable (&tasks))
                    SEND_TO_CLIENT_OR_FAIL ("</task>");
                  else
                    SEND_TO_CLIENT_OR_FAIL ("<permissions/>"
                                            "</task>");
                }
              cleanup_iterator (&tasks);
              SEND_TO_CLIENT_OR_FAIL ("</tasks>");
            }

          SEND_TO_CLIENT_OR_FAIL ("</target>");
          count++;
          free (ssh_name);
          free (ssh_uuid);
          free (smb_name);
          free (smb_uuid);
          free (esxi_name);
          free (esxi_uuid);
          free (ssh_elevate_name);
          free (ssh_elevate_uuid);
        }
      cleanup_iterator (&targets);
      filtered = get_targets_data->get.id
                  ? 1
                  : target_count (&get_targets_data->get);
      SEND_GET_END ("target", &get_targets_data->get, count, filtered);
    }
  get_targets_data_reset (get_targets_data);
  set_client_state (CLIENT_AUTHENTIC);
}

/**
 * @brief Gets task schedule data of a task as XML.
 *
 * @param[in]  task  The task to get schedule data for.
 *
 * @return Newly allocated XML string.
 */
static gchar*
get_task_schedule_xml (task_t task)
{
  schedule_t schedule;
  int schedule_in_trash, schedule_available;
  char *task_schedule_uuid, *task_schedule_name;
  GString *xml;

  xml = g_string_new ("");

  schedule_available = 1;
  schedule = task_schedule (task);
  if (schedule)
    {
      schedule_in_trash = task_schedule_in_trash (task);
      if (schedule_in_trash)
        {
          task_schedule_uuid = trash_schedule_uuid (schedule);
          task_schedule_name = trash_schedule_name (schedule);
          schedule_available = trash_schedule_readable (schedule);
        }
      else
        {
          schedule_t found;
          task_schedule_uuid = schedule_uuid (schedule);
          task_schedule_name = schedule_name (schedule);
          if (find_schedule_with_permission (task_schedule_uuid,
                                            &found,
                                            "get_schedules"))
            g_error ("%s: GET_TASKS: error finding"
                      " task schedule, aborting",
                      __func__);
          schedule_available = (found > 0);
        }
    }
  else
    {
      task_schedule_uuid = (char*) g_strdup ("");
      task_schedule_name = (char*) g_strdup ("");
      schedule_in_trash = 0;
    }

  if (schedule_available && schedule)
    {
      gchar *icalendar, *zone;

      icalendar = zone = NULL;

      if (schedule_info (schedule, schedule_in_trash, &icalendar, &zone) == 0)
        xml_string_append (xml,
                           "<schedule id=\"%s\">"
                           "<name>%s</name>"
                           "<trash>%d</trash>"
                           "<icalendar>%s</icalendar>"
                           "<timezone>%s</timezone>"
                           "</schedule>",
                           task_schedule_uuid,
                           task_schedule_name,
                           schedule_in_trash,
                           icalendar ? icalendar : "",
                           zone ? zone : "");

      g_free (icalendar);
      g_free (zone);
    }
  else
    {
      xml_string_append (xml,
                         "<schedule id=\"%s\">"
                         "<name>%s</name>"
                         "<trash>%d</trash>"
                         "</schedule>",
                         task_schedule_uuid,
                         task_schedule_name,
                         schedule_in_trash);
    }

  xml_string_append (xml,
                     "<schedule_periods>"
                     "%d"
                     "</schedule_periods>",
                     task_schedule_periods (task));

  return g_string_free (xml, FALSE);
}


/**
 * @brief Handle end of GET_TASKS element.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 */
static void
handle_get_tasks (gmp_parser_t *gmp_parser, GError **error)
{
  iterator_t tasks;
  int count, filtered, ret, first;
  get_data_t *get;
  const char *filter;
  gchar *clean_filter;
  int apply_overrides, min_qod;

  if (get_tasks_data->get.details && get_tasks_data->get.trash)
    {
      SEND_TO_CLIENT_OR_FAIL
       (XML_ERROR_SYNTAX ("get_task",
                          "GET_TASKS details given with trash"));
      get_tasks_data_reset (get_tasks_data);
      set_client_state (CLIENT_AUTHENTIC);
      return;
    }

  INIT_GET (task, Task);

  get_tasks_data->get.minimal = get_tasks_data->schedules_only;
  ret = init_task_iterator (&tasks, &get_tasks_data->get);
  if (ret)
    {
      switch (ret)
        {
          case 1:
            if (send_find_error_to_client ("get_tasks",
                                           "task",
                                           get_tasks_data->get.id,
                                           gmp_parser))
              {
                error_send_to_client (error);
                return;
              }
            break;
          case 2:
            if (send_find_error_to_client
                  ("get_tasks", "filter", get_tasks_data->get.filt_id,
                  gmp_parser))
              {
                error_send_to_client (error);
                return;
              }
            break;
          case -1:
            SEND_TO_CLIENT_OR_FAIL
              (XML_INTERNAL_ERROR ("get_tasks"));
            break;
        }
      get_tasks_data_reset (get_tasks_data);
      set_client_state (CLIENT_AUTHENTIC);
      return;
    }

  SEND_GET_START ("task");

  get = &get_tasks_data->get;
  if (get->filt_id && strcmp (get->filt_id, FILT_ID_NONE))
    {
      filter = filter_term (get->filt_id);
      if (filter == NULL)
        {
          error_send_to_client (error);
          return;
        }
    }
  else
    filter = NULL;

  clean_filter = manage_clean_filter (filter ? filter : get->filter);
  apply_overrides = filter_term_apply_overrides (clean_filter);
  min_qod = filter_term_min_qod (clean_filter);
  g_free (clean_filter);

  SENDF_TO_CLIENT_OR_FAIL ("<apply_overrides>%i</apply_overrides>",
                           apply_overrides);

  while (1)
    {
      task_t index;
      gchar *progress_xml;
      target_t target;
      scanner_t scanner;
      const char *first_report_id, *last_report_id;
      char *config_name, *config_uuid;
      gchar *config_name_escaped;
      char *task_target_uuid, *task_target_name;
      gchar *task_target_name_escaped;
      gchar *task_schedule_xml;
      char *task_scanner_uuid, *task_scanner_name;
      gchar *task_scanner_name_escaped;
      gchar *last_report;
      gchar *second_last_report_id;
      gchar *current_report;
      report_t running_report;
      char *owner, *observers;
      int target_in_trash, scanner_in_trash;
      int holes = 0, infos = 0, logs = 0, warnings = 0;
      int holes_2 = 0, infos_2 = 0, warnings_2 = 0;
      int false_positives = 0, task_scanner_type;
      int target_available, config_available;
      int scanner_available;
      double severity = 0, severity_2 = 0;
      gchar *response;
      iterator_t alerts, groups, roles;
      gchar *in_assets, *max_checks, *max_hosts;
      gchar *auto_delete, *auto_delete_data, *assets_apply_overrides;
      gchar *assets_min_qod;

      ret = get_next (&tasks, &get_tasks_data->get, &first, &count,
                      init_task_iterator);
      if (ret == 1)
        break;
      if (ret == -1)
        {
          internal_error_send_to_client (error);
          return;
        }

      index = get_iterator_resource (&tasks);
      target = task_target (index);

      task_schedule_xml = get_task_schedule_xml (index);

      if (get_tasks_data->schedules_only)
        {
          SENDF_TO_CLIENT_OR_FAIL ("<task id=\"%s\">"
                                   "<name>%s</name>",
                                   get_iterator_uuid (&tasks),
                                   get_iterator_name (&tasks));

          SEND_TO_CLIENT_OR_FAIL (task_schedule_xml);
          g_free (task_schedule_xml);

          SENDF_TO_CLIENT_OR_FAIL ("</task>");

        }
      else
        {
          SEND_GET_COMMON (task, &get_tasks_data->get, &tasks);
          target_in_trash = task_target_in_trash (index);
          if ((target == 0)
              && (task_iterator_run_status (&tasks)
                  == TASK_STATUS_RUNNING))
            {
              progress_xml = g_strdup_printf
                              ("%i",
                              task_upload_progress (index));
              running_report = 0;
            }
          else
            {
              int progress;

              running_report = task_iterator_current_report (&tasks);
              progress
                = report_progress (running_report);
              progress_xml
                = g_strdup_printf ("%i", progress);
            }

          if (running_report)
            {
              gchar *timestamp;
              char *scan_start, *scan_end, *current_report_id;

              current_report_id = report_uuid (running_report);

              if (report_timestamp (current_report_id, &timestamp))
                g_error ("%s: GET_TASKS: error getting timestamp"
                         " of report, aborting",
                         __func__);

              scan_start = scan_start_time_uuid (current_report_id),
              scan_end = scan_end_time_uuid (current_report_id),

              current_report = g_strdup_printf ("<current_report>"
                                                "<report id=\"%s\">"
                                                "<timestamp>"
                                                "%s"
                                                "</timestamp>"
                                                "<scan_start>"
                                                "%s"
                                                "</scan_start>"
                                                "<scan_end>"
                                                "%s"
                                                "</scan_end>"
                                                "</report>"
                                                "</current_report>",
                                                current_report_id,
                                                timestamp,
                                                scan_start,
                                                scan_end);
              free (current_report_id);
              free (scan_start);
              free (scan_end);
              g_free (timestamp);
            }
          else
            current_report = g_strdup ("");

          first_report_id = task_iterator_first_report (&tasks);
          if (first_report_id && (get_tasks_data->get.trash == 0))
            {
              // TODO Could skip this count for tasks page.
              if (report_counts (first_report_id,
                                 &holes_2, &infos_2, &logs,
                                 &warnings_2, &false_positives,
                                 &severity_2, apply_overrides, min_qod))
                g_error ("%s: GET_TASKS: error getting counts for"
                         " first report, aborting",
                         __func__);
            }

          second_last_report_id = task_second_last_report_id (index);
          if (second_last_report_id && (get_tasks_data->get.trash == 0))
            {
              /* If the first report is the second last report then skip
                * doing the count again. */
              if (((first_report_id == NULL)
                  || (strcmp (second_last_report_id, first_report_id)))
                  && report_counts (second_last_report_id,
                                    &holes_2, &infos_2,
                                    &logs, &warnings_2,
                                    &false_positives, &severity_2,
                                    apply_overrides, min_qod))
                g_error ("%s: GET_TASKS: error getting counts for"
                         " second report, aborting",
                         __func__);
            }

          last_report_id = task_iterator_last_report (&tasks);
          if (get_tasks_data->get.trash && last_report_id)
            {
              gchar *timestamp;
              char *scan_start, *scan_end;

              if (report_timestamp (last_report_id, &timestamp))
                g_error ("%s: GET_TASKS: error getting timestamp for"
                         " last report, aborting",
                         __func__);

              scan_start = scan_start_time_uuid (last_report_id);
              scan_end = scan_end_time_uuid (last_report_id);

              last_report = g_strdup_printf ("<last_report>"
                                             "<report id=\"%s\">"
                                             "<timestamp>%s</timestamp>"
                                             "<scan_start>%s</scan_start>"
                                             "<scan_end>%s</scan_end>"
                                             "</report>"
                                             "</last_report>",
                                             last_report_id,
                                             timestamp,
                                             scan_start,
                                             scan_end);

              free (scan_start);
              free (scan_end);
              g_free (timestamp);
            }
          else if (last_report_id)
            {
              gchar *timestamp;
              char *scan_start, *scan_end;

              /* If the last report is the first report or the second
                * last report, then reuse the counts from before. */
              if ((first_report_id == NULL)
                  || (second_last_report_id == NULL)
                  || (strcmp (last_report_id, first_report_id)
                      && strcmp (last_report_id,
                                second_last_report_id)))
                {
                  if (report_counts
                      (last_report_id,
                        &holes, &infos, &logs,
                        &warnings, &false_positives, &severity,
                        apply_overrides, min_qod))
                    g_error ("%s: GET_TASKS: error getting counts for"
                             " last report, aborting",
                             __func__);
                }
              else
                {
                  holes = holes_2;
                  infos = infos_2;
                  warnings = warnings_2;
                  severity = severity_2;
                }

              if (report_timestamp (last_report_id, &timestamp))
                g_error ("%s: GET_TASKS: error getting timestamp for"
                         " last report, aborting",
                         __func__);

              scan_start = scan_start_time_uuid (last_report_id);
              scan_end = scan_end_time_uuid (last_report_id);

              if (strcmp (task_iterator_usage_type (&tasks), "audit") == 0)
                {
                  int compliance_yes, compliance_no, compliance_incomplete;

                  report_compliance_by_uuid (last_report_id,
                                             &compliance_yes,
                                             &compliance_no,
                                             &compliance_incomplete);

                  last_report
                    = g_strdup_printf ("<last_report>"
                                       "<report id=\"%s\">"
                                       "<timestamp>%s</timestamp>"
                                       "<scan_start>%s</scan_start>"
                                       "<scan_end>%s</scan_end>"
                                       "<compliance_count>"
                                       "<yes>%d</yes>"
                                       "<no>%d</no>"
                                       "<incomplete>%d</incomplete>"
                                       "</compliance_count>"
                                       "</report>"
                                       "</last_report>",
                                       last_report_id,
                                       timestamp,
                                       scan_start,
                                       scan_end,
                                       compliance_yes,
                                       compliance_no,
                                       compliance_incomplete);
                }
              else
                last_report
                    = g_strdup_printf ("<last_report>"
                                       "<report id=\"%s\">"
                                       "<timestamp>%s</timestamp>"
                                       "<scan_start>%s</scan_start>"
                                       "<scan_end>%s</scan_end>"
                                       "<result_count>"
                                       "<hole>%i</hole>"
                                       "<info>%i</info>"
                                       "<log>%i</log>"
                                       "<warning>%i</warning>"
                                       "<false_positive>"
                                       "%i"
                                       "</false_positive>"
                                       "</result_count>"
                                       "<severity>"
                                       "%1.1f"
                                       "</severity>"
                                       "</report>"
                                       "</last_report>",
                                       last_report_id,
                                       timestamp,
                                       scan_start,
                                       scan_end,
                                       holes,
                                       infos,
                                       logs,
                                       warnings,
                                       false_positives,
                                       severity);
              free (scan_start);
              free (scan_end);
              g_free (timestamp);
            }
          else
            last_report = g_strdup ("");

          g_free (second_last_report_id);

          owner = task_owner_name (index);
          observers = task_observers (index);
          config_name = task_config_name (index);
          config_uuid = task_config_uuid (index);
          target_available = 1;
          if (target_in_trash)
            {
              task_target_uuid = trash_target_uuid (target);
              task_target_name = trash_target_name (target);
              target_available = trash_target_readable (target);
            }
          else if (target)
            {
              target_t found;
              task_target_uuid = target_uuid (target);
              task_target_name = target_name (target);
              if (find_target_with_permission (task_target_uuid,
                                                &found,
                                                "get_targets"))
                g_error ("%s: GET_TASKS: error finding task target,"
                         " aborting",
                         __func__);
              target_available = (found > 0);
            }
          else
            {
              task_target_uuid = NULL;
              task_target_name = NULL;
            }
          config_available = 1;
          if (task_config_in_trash (index))
            config_available = trash_config_readable_uuid (config_uuid);
          else if (config_uuid)
            {
              config_t found;
              if (find_config_with_permission (config_uuid,
                                              &found,
                                              "get_configs"))
                g_error ("%s: GET_TASKS: error finding task config,"
                         " aborting",
                         __func__);
              config_available = (found > 0);
            }
          scanner_available = 1;
          scanner = task_iterator_scanner (&tasks);
          if (scanner)
            {
              scanner_in_trash = task_scanner_in_trash (index);

              task_scanner_uuid = scanner_uuid (scanner);
              task_scanner_name = scanner_name (scanner);
              task_scanner_type = scanner_type (scanner);
              if (scanner_in_trash)
                scanner_available = trash_scanner_readable (scanner);
              else
                {
                  scanner_t found;

                  if (find_scanner_with_permission
                      (task_scanner_uuid, &found, "get_scanners"))
                    g_error ("%s: GET_TASKS: error finding"
                             " task scanner, aborting",
                             __func__);
                  scanner_available = (found > 0);
                }
            }
          else
            {
              /* Container tasks have no associated scanner. */
              task_scanner_uuid = g_strdup ("");
              task_scanner_name = g_strdup ("");
              task_scanner_type = 0;
              scanner_in_trash = 0;
            }

          config_name_escaped
            = config_name
                ? g_markup_escape_text (config_name, -1)
                : NULL;
          task_target_name_escaped
            = task_target_name
                ? g_markup_escape_text (task_target_name, -1)
                : NULL;
          task_scanner_name_escaped
            = task_scanner_name
                ? g_markup_escape_text (task_scanner_name, -1)
                : NULL;

          response = g_strdup_printf
                      ("<alterable>%i</alterable>"
                       "<usage_type>%s</usage_type>"
                       "<config id=\"%s\">"
                       "<name>%s</name>"
                       "<trash>%i</trash>"
                       "%s"
                       "</config>"
                       "<target id=\"%s\">"
                       "<name>%s</name>"
                       "<trash>%i</trash>"
                       "%s"
                       "</target>"
                       "<hosts_ordering>%s</hosts_ordering>"
                       "<scanner id='%s'>"
                       "<name>%s</name>"
                       "<type>%d</type>"
                       "<trash>%i</trash>"
                       "%s"
                       "</scanner>"
                       "<status>%s</status>"
                       "<progress>%s</progress>"
                       "<report_count>"
                       "%u<finished>%u</finished>"
                       "</report_count>"
                       "<trend>%s</trend>"
                       "%s" // Schedule XML
                       "%s%s",
                       get_tasks_data->get.trash
                        ? 0
                        : task_alterable (index),
                       task_iterator_usage_type (&tasks),
                       config_uuid ?: "",
                       config_name_escaped ?: "",
                       task_config_in_trash (index),
                       config_available ? "" : "<permissions/>",
                       task_target_uuid ?: "",
                       task_target_name_escaped ?: "",
                       target_in_trash,
                       target_available ? "" : "<permissions/>",
                       task_iterator_hosts_ordering (&tasks)
                        ? task_iterator_hosts_ordering (&tasks)
                        : "",
                       task_scanner_uuid,
                       task_scanner_name_escaped,
                       task_scanner_type,
                       scanner_in_trash,
                       scanner_available ? "" : "<permissions/>",
                       task_iterator_run_status_name (&tasks),
                       progress_xml,
                       task_iterator_total_reports (&tasks),
                       task_iterator_finished_reports (&tasks),
                       get_tasks_data->get.trash
                        ? ""
                        : task_iterator_trend_counts
                           (&tasks, holes, warnings, infos, severity,
                            holes_2, warnings_2, infos_2, severity_2),
                       task_schedule_xml,
                       current_report,
                       last_report);
          g_free (config_name);
          g_free (config_uuid);
          g_free (config_name_escaped);
          free (task_target_name);
          free (task_target_uuid);
          g_free (task_target_name_escaped);
          g_free (progress_xml);
          g_free (current_report);
          g_free (last_report);
          g_free (task_schedule_xml);
          g_free (task_scanner_uuid);
          g_free (task_scanner_name);
          g_free (task_scanner_name_escaped);
          if (send_to_client (response,
                              gmp_parser->client_writer,
                              gmp_parser->client_writer_data))
            {
              g_free (response);
              cleanup_iterator (&tasks);
              error_send_to_client (error);
              cleanup_iterator (&tasks);
              return;
            }
          g_free (response);

          SENDF_TO_CLIENT_OR_FAIL
           ("<observers>%s",
            ((owner == NULL)
            || (strcmp (owner,
                        current_credentials.username)))
              ? ""
              : observers);
          free (owner);
          free (observers);

          init_task_group_iterator (&groups, index);
          while (next (&groups))
            SENDF_TO_CLIENT_OR_FAIL
             ("<group id=\"%s\">"
              "<name>%s</name>"
              "</group>",
              task_group_iterator_uuid (&groups),
              task_group_iterator_name (&groups));
          cleanup_iterator (&groups);

          init_task_role_iterator (&roles, index);
          while (next (&roles))
            SENDF_TO_CLIENT_OR_FAIL
             ("<role id=\"%s\">"
              "<name>%s</name>"
              "</role>",
              task_role_iterator_uuid (&roles),
              task_role_iterator_name (&roles));
          cleanup_iterator (&roles);

          SENDF_TO_CLIENT_OR_FAIL ("</observers>");

          init_task_alert_iterator (&alerts, index);
          while (next (&alerts))
            {
              alert_t found;

              if (find_alert_with_permission (task_alert_iterator_uuid
                                              (&alerts),
                                              &found,
                                              "get_alerts"))
                abort ();

              SENDF_TO_CLIENT_OR_FAIL
               ("<alert id=\"%s\">"
                "<name>%s</name>",
                task_alert_iterator_uuid (&alerts),
                task_alert_iterator_name (&alerts));

              if (found)
                SENDF_TO_CLIENT_OR_FAIL
                ("</alert>");
              else
                SENDF_TO_CLIENT_OR_FAIL
                 ("<permissions/>"
                  "</alert>");
            }
          cleanup_iterator (&alerts);

          if (get_tasks_data->get.details
              || get_tasks_data->get.id)
            {
              SENDF_TO_CLIENT_OR_FAIL ("<average_duration>"
                                       "%d"
                                       "</average_duration>",
                                       task_average_scan_duration (index));
            }

          if (get_tasks_data->get.details)
            {
              /* The detailed version. */

              SENDF_TO_CLIENT_OR_FAIL ("<result_count>%i</result_count>",
                                        task_result_count (index, min_qod));
            }

          in_assets = task_preference_value (index, "in_assets");
          assets_apply_overrides = task_preference_value
                                    (index, "assets_apply_overrides");
          assets_min_qod = task_preference_value (index, "assets_min_qod");
          max_checks = task_preference_value (index, "max_checks");
          max_hosts = task_preference_value (index, "max_hosts");
          auto_delete = task_preference_value (index, "auto_delete");
          auto_delete_data = task_preference_value (index, "auto_delete_data");

          SENDF_TO_CLIENT_OR_FAIL
           ("<preferences>"
            "<preference>"
            "<name>"
            "Maximum concurrently executed NVTs per host"
            "</name>"
            "<scanner_name>max_checks</scanner_name>"
            "<value>%s</value>"
            "</preference>"
            "<preference>"
            "<name>"
            "Maximum concurrently scanned hosts"
            "</name>"
            "<scanner_name>max_hosts</scanner_name>"
            "<value>%s</value>"
            "</preference>"
            "<preference>"
            "<name>"
            "Add results to Asset Management"
            "</name>"
            "<scanner_name>in_assets</scanner_name>"
            "<value>%s</value>"
            "</preference>"
            "<preference>"
            "<name>"
            "Apply Overrides when adding Assets"
            "</name>"
            "<scanner_name>assets_apply_overrides</scanner_name>"
            "<value>%s</value>"
            "</preference>"
            "<preference>"
            "<name>"
            "Min QOD when adding Assets"
            "</name>"
            "<scanner_name>assets_min_qod</scanner_name>"
            "<value>%s</value>"
            "</preference>"
            "<preference>"
            "<name>"
            "Auto Delete Reports"
            "</name>"
            "<scanner_name>auto_delete</scanner_name>"
            "<value>%s</value>"
            "</preference>"
            "<preference>"
            "<name>"
            "Auto Delete Reports Data"
            "</name>"
            "<scanner_name>auto_delete_data</scanner_name>"
            "<value>%s</value>"
            "</preference>"
            "</preferences>"
            "</task>",
            max_checks ? max_checks : "4",
            max_hosts ? max_hosts : "20",
            in_assets ? in_assets : "yes",
            assets_apply_overrides ? assets_apply_overrides : "yes",
            assets_min_qod
              ? assets_min_qod
              : G_STRINGIFY (MIN_QOD_DEFAULT),
            auto_delete ? auto_delete : "0",
            auto_delete_data ? auto_delete_data : "0");

          g_free (in_assets);
          g_free (max_checks);
          g_free (max_hosts);
        }

      count++;
    }
  cleanup_iterator (&tasks);
  filtered = get_tasks_data->get.id
              ? 1
              : task_count (&get_tasks_data->get);
  SEND_GET_END ("task", &get_tasks_data->get, count, filtered);

  get_tasks_data_reset (get_tasks_data);
  set_client_state (CLIENT_AUTHENTIC);
}

/**
 * @brief Handle end of GET_USER element.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 */
static void
handle_get_users (gmp_parser_t *gmp_parser, GError **error)
{
  iterator_t users;
  int count, filtered, ret, first;

  INIT_GET (user, User);

  ret = init_user_iterator (&users, &get_users_data->get);
  if (ret)
    {
      switch (ret)
        {
          case 1:
            if (send_find_error_to_client ("get_users",
                                           "user",
                                           get_users_data->get.id,
                                           gmp_parser))
              {
                error_send_to_client (error);
                return;
              }
            break;
          case 2:
            if (send_find_error_to_client
                  ("get_users", "filter", get_users_data->get.filt_id,
                   gmp_parser))
              {
                error_send_to_client (error);
                return;
              }
            break;
          case -1:
            SEND_TO_CLIENT_OR_FAIL
              (XML_INTERNAL_ERROR ("get_users"));
            break;
        }
      get_users_data_reset (get_users_data);
      set_client_state (CLIENT_AUTHENTIC);
      return;
    }

  SEND_GET_START ("user");
  while (1)
    {
      iterator_t groups, roles;
      const char *hosts;
      int hosts_allow;

      ret = get_next (&users, &get_users_data->get, &first, &count,
                      init_user_iterator);
      if (ret == 1)
        break;
      if (ret == -1)
        {
          internal_error_send_to_client (error);
          return;
        }

      SEND_GET_COMMON (user, &get_users_data->get, &users);

      hosts = user_iterator_hosts (&users);
      hosts_allow = user_iterator_hosts_allow (&users);

      SENDF_TO_CLIENT_OR_FAIL ("<hosts allow=\"%i\">%s</hosts>"
                               "<sources><source>%s</source></sources>",
                               hosts_allow,
                               hosts ? hosts : "",
                               user_iterator_method (&users)
                                ? user_iterator_method (&users)
                                : "file");

      /* User Roles */
      init_user_role_iterator (&roles,
                                get_iterator_resource (&users));
      while (next (&roles))
        {
          SENDF_TO_CLIENT_OR_FAIL ("<role id=\"%s\">"
                                   "<name>%s</name>",
                                   user_role_iterator_uuid (&roles),
                                   user_role_iterator_name (&roles));
          if (user_role_iterator_readable (&roles))
            SEND_TO_CLIENT_OR_FAIL ("</role>");
          else
            SEND_TO_CLIENT_OR_FAIL ("<permissions/>"
                                    "</role>");
        }
      cleanup_iterator (&roles);

      SEND_TO_CLIENT_OR_FAIL ("<groups>");
      init_user_group_iterator (&groups,
                                get_iterator_resource (&users));
      while (next (&groups))
        {
          SENDF_TO_CLIENT_OR_FAIL ("<group id=\"%s\">"
                                   "<name>%s</name>",
                                   user_group_iterator_uuid (&groups),
                                   user_group_iterator_name (&groups));
          if (user_group_iterator_readable (&groups))
            SEND_TO_CLIENT_OR_FAIL ("</group>");
          else
            SEND_TO_CLIENT_OR_FAIL ("<permissions/>"
                                    "</group>");
        }
      cleanup_iterator (&groups);
      SEND_TO_CLIENT_OR_FAIL ("</groups>"
                              "</user>");
      count++;
    }
  cleanup_iterator (&users);
  filtered = get_users_data->get.id
              ? 1
              : user_count (&get_users_data->get);
  SEND_GET_END ("user", &get_users_data->get, count, filtered);

  get_users_data_reset (get_users_data);
  set_client_state (CLIENT_AUTHENTIC);
}

/**
 * @brief Handle end of GET_VERSION element.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 */
static void
handle_get_version (gmp_parser_t *gmp_parser, GError **error)
{
  SEND_TO_CLIENT_OR_FAIL ("<get_version_response"
                          " status=\"" STATUS_OK "\""
                          " status_text=\"" STATUS_OK_TEXT "\">"
                          "<version>" GMP_VERSION "</version>"
                          "</get_version_response>");
  if (client_state == CLIENT_GET_VERSION_AUTHENTIC)
    set_client_state (CLIENT_AUTHENTIC);
  else
    set_client_state (CLIENT_TOP);
}

/**
 * @brief Handle end of GET_VULNS element.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 */
static void
handle_get_vulns (gmp_parser_t *gmp_parser, GError **error)
{
  get_data_t *get;
  int count, filtered, first;
  int ret;
  iterator_t vulns;

  get = &get_vulns_data->get;

  // Assumes that second param is only used for plural
  INIT_GET (vuln, Vulnerabilitie);

  ret = init_vuln_iterator (&vulns, get);
  if (ret)
    {
      switch (ret)
        {
          case 1:
            if (send_find_error_to_client ("get_vulns",
                                           "vuln",
                                           get_vulns_data->get.id,
                                           gmp_parser))
              {
                error_send_to_client (error);
                return;
              }
            break;
          case 2:
            if (send_find_error_to_client
                  ("get_vulns", "filter",
                   get_vulns_data->get.filt_id, gmp_parser))
              {
                error_send_to_client (error);
                return;
              }
            break;
          case -1:
            SEND_TO_CLIENT_OR_FAIL
              (XML_INTERNAL_ERROR ("get_vulns"));
            break;
        }
      get_vulns_data_reset (get_vulns_data);
      set_client_state (CLIENT_AUTHENTIC);
      return;
    }

  SEND_GET_START ("vuln");

  while (next (&vulns))
    {
      time_t oldest, newest;

      count ++;
      SENDF_TO_CLIENT_OR_FAIL ("<vuln id=\"%s\">"
                               "<name>%s</name>"
                               "<type>%s</type>"
                               "<creation_time>%s</creation_time>"
                               "<modification_time>%s</modification_time>"
                               "<severity>%1.1f</severity>"
                               "<qod>%d</qod>",
                               get_iterator_uuid (&vulns),
                               get_iterator_name (&vulns),
                               vuln_iterator_type (&vulns),
                               get_iterator_creation_time (&vulns),
                               get_iterator_modification_time (&vulns),
                               vuln_iterator_severity (&vulns),
                               vuln_iterator_qod (&vulns));

      // results for the vulnerability
      oldest = vuln_iterator_oldest (&vulns);
      SENDF_TO_CLIENT_OR_FAIL ("<results>"
                               "<count>%d</count>"
                               "<oldest>%s</oldest>",
                               vuln_iterator_results (&vulns),
                               iso_time (&oldest));

      newest = vuln_iterator_newest (&vulns);
      SENDF_TO_CLIENT_OR_FAIL ("<newest>%s</newest>",
                               iso_time (&newest));

      SEND_TO_CLIENT_OR_FAIL ("</results>");

      // hosts with the vulnerability
      SENDF_TO_CLIENT_OR_FAIL ("<hosts>"
                               "<count>%d</count>",
                               vuln_iterator_hosts (&vulns));

      SEND_TO_CLIENT_OR_FAIL ("</hosts>");

      // closing tag
      SEND_TO_CLIENT_OR_FAIL ("</vuln>");
    }

  cleanup_iterator (&vulns);

  filtered = vuln_count (get);

  SEND_GET_END ("vuln", &get_vulns_data->get, count, filtered);

  get_vulns_data_reset (get_vulns_data);
  set_client_state (CLIENT_AUTHENTIC);
}

/**
 * @brief Handle end of CREATE_SCANNER element.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 */
static void
handle_create_scanner (gmp_parser_t *gmp_parser, GError **error)
{
  scanner_t new_scanner;

  if (create_scanner_data->copy)
    switch (copy_scanner (create_scanner_data->name,
                          create_scanner_data->comment,
                          create_scanner_data->copy, &new_scanner))
      {
        case 0:
          {
            char *uuid;
            uuid = scanner_uuid (new_scanner);
            SENDF_TO_CLIENT_OR_FAIL (XML_OK_CREATED_ID ("create_scanner"),
                                     uuid);
            log_event ("scanner", "scanner", uuid, "created");
            g_free (uuid);
            goto create_scanner_leave;
          }
        case 1:
          SEND_TO_CLIENT_OR_FAIL
           (XML_ERROR_SYNTAX ("create_scanner", "Scanner name exists already"));
          log_event_fail ("scanner", "Scanner", NULL, "created");
          goto create_scanner_leave;
        case 2:
          if (send_find_error_to_client ("create_scanner", "scanner",
                                         create_scanner_data->copy, gmp_parser))
            {
              error_send_to_client (error);
              goto create_scanner_leave;
            }
          log_event_fail ("scanner", "Scanner", NULL, "created");
          goto create_scanner_leave;
        case 98:
          SEND_TO_CLIENT_OR_FAIL
           (XML_ERROR_SYNTAX ("create_scanner", "It is not possible to clone a "
                              "CVE scanner "));
          log_event_fail ("scanner", "Scanner", NULL, "created");
          goto create_scanner_leave;
        case 99:
          SEND_TO_CLIENT_OR_FAIL
           (XML_ERROR_SYNTAX ("create_scanner", "Permission denied"));
          log_event_fail ("scanner", "Scanner", NULL, "created");
          goto create_scanner_leave;
        case -1:
        default:
          SEND_TO_CLIENT_OR_FAIL
           (XML_INTERNAL_ERROR ("create_scanner"));
          log_event_fail ("scanner", "Scanner", NULL, "created");
          goto create_scanner_leave;
      }

  if (!create_scanner_data->name)
    {
      SEND_TO_CLIENT_OR_FAIL
       (XML_ERROR_SYNTAX ("create_scanner", "Missing NAME"));
      goto create_scanner_leave;
    }

  if (!create_scanner_data->host)
    {
      SEND_TO_CLIENT_OR_FAIL
       (XML_ERROR_SYNTAX ("create_scanner", "Missing HOST"));
      goto create_scanner_leave;
    }

  if (!create_scanner_data->port)
    {
      SEND_TO_CLIENT_OR_FAIL
       (XML_ERROR_SYNTAX ("create_scanner", "Missing PORT"));
      goto create_scanner_leave;
    }

  if (!create_scanner_data->type)
    {
      SEND_TO_CLIENT_OR_FAIL
       (XML_ERROR_SYNTAX ("create_scanner", "Missing TYPE"));
      goto create_scanner_leave;
    }

  /* Specifying unix file socket over GMP is not allowed. */
  if (*create_scanner_data->host == '/')
    {
      SEND_TO_CLIENT_OR_FAIL
       (XML_ERROR_SYNTAX ("create_scanner", "Erroneous host value."));
      goto create_scanner_leave;
    }
  if (create_scanner_data->ca_pub
      && check_certificate_x509 (create_scanner_data->ca_pub))
    {
      SEND_TO_CLIENT_OR_FAIL
       (XML_ERROR_SYNTAX ("create_scanner", "Erroneous CA Certificate."));
      goto create_scanner_leave;
    }
  switch (create_scanner
           (create_scanner_data->name, create_scanner_data->comment,
            create_scanner_data->host, create_scanner_data->port,
            create_scanner_data->type, &new_scanner,
            create_scanner_data->ca_pub, create_scanner_data->credential_id))
    {
      case 0:
        {
          char *uuid = scanner_uuid (new_scanner);
          SENDF_TO_CLIENT_OR_FAIL
           (XML_OK_CREATED_ID ("create_scanner"), uuid);
          log_event ("scanner", "Scanner", uuid, "created");
          g_free (uuid);
          break;
        }
      case 1:
        SEND_TO_CLIENT_OR_FAIL
         (XML_ERROR_SYNTAX ("create_scanner", "Scanner exists already"));
        log_event_fail ("scanner", "Scanner", NULL, "created");
        break;
      case 2:
        SEND_TO_CLIENT_OR_FAIL
         (XML_ERROR_SYNTAX ("create_scanner", "Invalid entity value"));
        log_event_fail ("scanner", "Scanner", NULL, "created");
        break;
      case 3:
        if (send_find_error_to_client ("create_scanner", "credential",
                                       create_scanner_data->credential_id,
                                       gmp_parser))
          {
            error_send_to_client (error);
            return;
          }
        log_event_fail ("scanner", "Scanner", NULL, "created");
        break;
      case 4:
        SEND_TO_CLIENT_OR_FAIL
         (XML_ERROR_SYNTAX ("create_scanner",
                            "Credential must be of type 'up'"
                            " (username + password)"));
        log_event_fail ("scanner", "Scanner", NULL, "created");
        break;
      case 5:
        SEND_TO_CLIENT_OR_FAIL
         (XML_ERROR_SYNTAX ("create_scanner",
                            "Credential must be of type 'cc'"
                            " (client certificate)"));
        log_event_fail ("scanner", "Scanner", NULL, "created");
        break;
      case 6:
        SEND_TO_CLIENT_OR_FAIL
         (XML_ERROR_SYNTAX ("create_scanner",
                            "Scanner type requires a credential"));
        log_event_fail ("scanner", "Scanner", NULL, "created");
        break;
      case 99:
        SEND_TO_CLIENT_OR_FAIL
         (XML_ERROR_SYNTAX ("create_scanner", "Permission denied"));
        log_event_fail ("scanner", "Scanner", NULL, "created");
        break;
      case -1:
        SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("create_scanner"));
        log_event_fail ("scanner", "Scanner", NULL, "created");
        break;
      default:
        assert (0);
        SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("create_scanner"));
        log_event_fail ("scanner", "Scanner", NULL, "created");
        break;
    }

create_scanner_leave:
  create_scanner_data_reset (create_scanner_data);
  set_client_state (CLIENT_AUTHENTIC);
}

/**
 * @brief Handle end of MODIFY_SCANNER element.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 */
static void
handle_modify_scanner (gmp_parser_t *gmp_parser, GError **error)
{
  if (modify_scanner_data->ca_pub && *modify_scanner_data->ca_pub
      && check_certificate_x509 (modify_scanner_data->ca_pub))
    {
      SEND_TO_CLIENT_OR_FAIL
       (XML_ERROR_SYNTAX ("modify_scanner", "Erroneous CA Certificate."));
      goto modify_scanner_leave;
    }

  /* Specifying unix file socket over GMP is not allowed. */
  if (modify_scanner_data->host
      && *modify_scanner_data->host == '/')
    {
      SEND_TO_CLIENT_OR_FAIL
       (XML_ERROR_SYNTAX ("create_scanner", "Erroneous host value."));
      goto modify_scanner_leave;
    }
  switch (modify_scanner
           (modify_scanner_data->scanner_id, modify_scanner_data->name,
            modify_scanner_data->comment, modify_scanner_data->host,
            modify_scanner_data->port, modify_scanner_data->type,
            modify_scanner_data->ca_pub, modify_scanner_data->credential_id))
    {
      case 0:
        SENDF_TO_CLIENT_OR_FAIL (XML_OK ("modify_scanner"));
        log_event ("scanner", "Scanner", modify_scanner_data->scanner_id,
                   "modified");
        break;
      case 1:
        if (send_find_error_to_client ("modify_scanner", "scanner",
                                       modify_scanner_data->scanner_id,
                                       gmp_parser))
          {
            error_send_to_client (error);
            return;
          }
        log_event_fail ("scanner", "Scanner", modify_scanner_data->scanner_id,
                        "modified");
        break;
      case 2:
        SEND_TO_CLIENT_OR_FAIL
         (XML_ERROR_SYNTAX ("modify_scanner",
                            "Scanner with new name exists already"));
        log_event_fail ("scanner", "Scanner", modify_scanner_data->scanner_id,
                        "modified");
        break;
      case 3:
        SEND_TO_CLIENT_OR_FAIL
         (XML_ERROR_SYNTAX ("modify_scanner", "Missing scanner_id"));
        log_event_fail ("scanner", "Scanner", modify_scanner_data->scanner_id,
                        "modified");
        break;
      case 4:
        SEND_TO_CLIENT_OR_FAIL
         (XML_ERROR_SYNTAX ("modify_scanner", "Invalid value"));
        log_event_fail ("scanner", "Scanner", modify_scanner_data->scanner_id,
                        "modified");
        break;
      case 5:
        if (send_find_error_to_client ("create_scanner", "credential",
                                       modify_scanner_data->credential_id,
                                       gmp_parser))
          {
            error_send_to_client (error);
            return;
          }
        log_event_fail ("scanner", "Scanner", modify_scanner_data->scanner_id,
                        "modified");
        break;
      case 6:
        SEND_TO_CLIENT_OR_FAIL
         (XML_ERROR_SYNTAX ("modify_scanner",
                            "Credential must be of type 'cc'"
                            " (client certificate)"));
        log_event_fail ("scanner", "Scanner", modify_scanner_data->scanner_id,
                        "modified");
        break;
      case 7:
        SEND_TO_CLIENT_OR_FAIL
         (XML_ERROR_SYNTAX ("modify_scanner",
                            "Credential must be of type 'up'"
                            " (username + password)"));
        log_event_fail ("scanner", "Scanner", modify_scanner_data->scanner_id,
                        "modified");
        break;
      case 8:
        SEND_TO_CLIENT_OR_FAIL
         (XML_ERROR_SYNTAX ("modify_scanner",
                            "Scanner type requires a credential"));
        log_event_fail ("scanner", "Scanner", modify_scanner_data->scanner_id,
                        "modified");
        break;
      case 99:
        SEND_TO_CLIENT_OR_FAIL
         (XML_ERROR_SYNTAX ("modify_scanner", "Permission denied"));
        log_event_fail ("scanner", "Scanner", modify_scanner_data->scanner_id,
                        "modified");
        break;
      default:
      case -1:
        SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("modify_scanner"));
        log_event_fail ("scanner", "Scanner", modify_scanner_data->scanner_id,
                        "modified");
        break;
    }
modify_scanner_leave:
  modify_scanner_data_reset (modify_scanner_data);
  set_client_state (CLIENT_AUTHENTIC);
}

extern char client_address[];

/**
 * @brief Handle create_report_data->results_* for gmp_xml_handle_end_element
 *
 * Uses data:
 * create_report_data->result_description
 * create_report_data->result_host
 * create_report_data->result_hostname
 * create_report_data->result_nvt_oid
 * create_report_data->result_port
 * create_report_data->result_qod
 * create_report_data->result_qod_type
 * create_report_data->result_scan_nvt_version
 * create_report_data->result_severity
 * create_report_data->result_threat
 * create_report_data->result_detection_name
 * create_report_data->result_detection_product
 * create_report_data->result_detection_source_name
 * create_report_data->result_detection_source_oid
 * create_report_data->result_detection_location
 * create_report_data->result_detection
 *
 * to create a create_report_data->result and add it into
 * create_report_data->results
 *
 */
static void
gmp_xml_handle_result ()
{
  create_report_result_t *result;

  assert (create_report_data->results);

  if (create_report_data->result_scan_nvt_version == NULL)
    create_report_data->result_scan_nvt_version = strdup ("");

  if (create_report_data->result_severity == NULL)
    {
      if (create_report_data->result_threat == NULL)
        {
          create_report_data->result_severity = strdup ("");
        }
      else if (strcasecmp (create_report_data->result_threat, "High") == 0)
        {
          create_report_data->result_severity = strdup ("10.0");
        }
      else if (strcasecmp (create_report_data->result_threat, "Medium") == 0)
        {
          create_report_data->result_severity = strdup ("5.0");
        }
      else if (strcasecmp (create_report_data->result_threat, "Low") == 0)
        {
          create_report_data->result_severity = strdup ("2.0");
        }
      else if (strcasecmp (create_report_data->result_threat, "Log") == 0)
        {
          create_report_data->result_severity = strdup ("0.0");
        }
      else if (strcasecmp (create_report_data->result_threat, "False Positive")
               == 0)
        {
          create_report_data->result_severity = strdup ("-1.0");
        }
      else
        {
          create_report_data->result_severity = strdup ("");
        }
    }

  result = g_malloc (sizeof (create_report_result_t));
  result->description = create_report_data->result_description;
  // sometimes host has newlines in it, so we 0 terminate first newline
  // According to
  // https://www.freebsd.org/cgi/man.cgi?query=strcspn&sektion=3
  // strcspn returns the number of chars spanned so it should be safe
  // without double checking.
  if (create_report_data->result_host)
    create_report_data
      ->result_host[strcspn (create_report_data->result_host, "\n")] = 0;
  result->host = create_report_data->result_host;
  result->hostname = create_report_data->result_hostname;
  result->nvt_oid = create_report_data->result_nvt_oid;
  result->scan_nvt_version = create_report_data->result_scan_nvt_version;
  result->port = create_report_data->result_port;
  result->qod = create_report_data->result_qod;
  result->qod_type = create_report_data->result_qod_type;
  result->severity = create_report_data->result_severity;
  result->threat = create_report_data->result_threat;
  if (result->host)
    {
      for (unsigned int i = 0; i < create_report_data->result_detection->len;
           i++)
        {
          host_detail_t *detail;
          // prepare detection to be found within
          // result_detection_reference
          detection_detail_t *detection =
            (detection_detail_t *) g_ptr_array_index (
              create_report_data->result_detection, i);

          // used to find location within report_host_details via
          // - oid as source_name
          // - detected_at as name
          detail = g_malloc (sizeof (host_detail_t));
          detail->ip = g_strdup (result->host);
          detail->name = g_strdup ("detected_at");
          detail->source_desc = g_strdup ("create_report_import");
          detail->source_name = g_strdup (
            detection->source_oid); // verify when detected_at || detected_by
          detail->source_type = g_strdup ("create_report_import");
          detail->value = g_strdup (detection->location);
          array_add (create_report_data->details, detail);
          // used to find oid within report_host_details via
          // - oid as source_name
          // - detected_by as name
          detail = g_malloc (sizeof (host_detail_t));
          detail->ip = g_strdup (result->host);
          detail->name = g_strconcat ("detected_by@", detection->location, NULL);
          detail->source_desc = g_strdup ("create_report_import");
          detail->source_name = g_strdup (result->nvt_oid);
          detail->source_type = g_strdup ("create_report_import");
          detail->value = g_strdup (detection->source_oid);
          array_add (create_report_data->details, detail);
          g_free (detection->location);
          g_free (detection->product);
          g_free (detection->source_name);
          g_free (detection->source_oid);
          g_free (detection);
        }
    }
  array_add (create_report_data->results, result);

  create_report_data->result_description = NULL;
  create_report_data->result_host = NULL;
  create_report_data->result_hostname = NULL;
  create_report_data->result_nvt_oid = NULL;
  create_report_data->result_port = NULL;
  create_report_data->result_qod = NULL;
  create_report_data->result_qod_type = NULL;
  create_report_data->result_scan_nvt_version = NULL;
  create_report_data->result_severity = NULL;
  create_report_data->result_threat = NULL;
  create_report_data->result_detection = NULL;
  create_report_data->result_detection = make_array ();
}

/**
 * @brief Handle the end of a GMP XML element.
 *
 * React to the end of an XML element according to the current value
 * of \ref client_state, usually adjusting \ref client_state to indicate
 * the change (with \ref set_client_state).  Call \ref send_to_client to queue
 * any responses for the client.  Call the task utilities to adjust the
 * tasks (for example \ref start_task, \ref stop_task, \ref modify_task,
 * \ref delete_task and \ref find_task_with_permission ).
 *
 * Set error parameter on encountering an error.
 *
 * @param[in]  context           Parser context.
 * @param[in]  element_name      XML element name.
 * @param[in]  user_data         GMP parser.
 * @param[in]  error             Error parameter.
 */
static void
gmp_xml_handle_end_element (/* unused */ GMarkupParseContext* context,
                            const gchar *element_name,
                            gpointer user_data,
                            GError **error)
{
  gmp_parser_t *gmp_parser = (gmp_parser_t*) user_data;
  int (*write_to_client) (const char *, void*)
    = (int (*) (const char *, void*)) gmp_parser->client_writer;
  void* write_to_client_data = (void*) gmp_parser->client_writer_data;

  g_debug ("   XML    end: %s", element_name);

  if (gmp_parser->read_over > 1)
    {
      gmp_parser->read_over--;
    }
  else if (gmp_parser->read_over == 1)
    {
      assert (gmp_parser->parent_state);
      client_state = gmp_parser->parent_state;
      gmp_parser->parent_state = 0;
      gmp_parser->read_over = 0;
    }
  else switch (client_state)
    {
      case CLIENT_TOP:
        assert (0);
        break;

      case CLIENT_AUTHENTICATE:
        switch (authenticate (&current_credentials))
          {
            case 0:   /* Authentication succeeded. */
              {
                const char *zone;
                char *pw_warning;

                zone = (current_credentials.timezone
                        && strlen (current_credentials.timezone))
                         ? current_credentials.timezone
                         : "UTC";

                if (setenv ("TZ", zone, 1) == -1)
                  {
                    free_credentials (&current_credentials);
                    g_warning ("Timezone setting failure for %s",
                               current_credentials.username);
                    SEND_TO_CLIENT_OR_FAIL
                     (XML_INTERNAL_ERROR ("authenticate"));
                    set_client_state (CLIENT_TOP);
                    break;
                  }
                tzset ();

                manage_session_set_timezone (zone);

                pw_warning = gvm_validate_password
                              (current_credentials.password,
                               current_credentials.username);

                if (pw_warning)
                  SENDF_TO_CLIENT_OR_FAIL
                  ("<authenticate_response"
                    " status=\"" STATUS_OK "\""
                    " status_text=\"" STATUS_OK_TEXT "\">"
                    "<role>%s</role>"
                    "<timezone>%s</timezone>"
                    "<password_warning>%s</password_warning>"
                    "</authenticate_response>",
                    current_credentials.role
                      ? current_credentials.role
                      : "",
                    zone,
                    pw_warning ? pw_warning : "");
                else
                  SENDF_TO_CLIENT_OR_FAIL
                  ("<authenticate_response"
                    " status=\"" STATUS_OK "\""
                    " status_text=\"" STATUS_OK_TEXT "\">"
                    "<role>%s</role>"
                    "<timezone>%s</timezone>"
                    "</authenticate_response>",
                    current_credentials.role
                      ? current_credentials.role
                      : "",
                    zone);

                free (pw_warning);
                set_client_state (CLIENT_AUTHENTIC);

                break;
              }
            case 1:   /* Authentication failed. */
              g_warning ("Authentication failure for '%s' from %s",
                         current_credentials.username ?: "", client_address);
              free_credentials (&current_credentials);
              SEND_TO_CLIENT_OR_FAIL (XML_ERROR_AUTH_FAILED ("authenticate"));
              set_client_state (CLIENT_TOP);
              break;
            case 99:   /* Authentication failed. */
              g_warning ("Authentication failure for '%s' from %s",
                         current_credentials.username ?: "", client_address);
              free_credentials (&current_credentials);
              SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX ("authenticate",
                                                        "Permission denied"));
              set_client_state (CLIENT_TOP);
              break;
            case -1:  /* Error while authenticating. */
            default:
              g_warning ("Authentication failure for '%s' from %s",
                         current_credentials.username ?: "", client_address);
              free_credentials (&current_credentials);
              SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("authenticate"));
              set_client_state (CLIENT_TOP);
              break;
          }
        break;

      case CLIENT_AUTHENTICATE_CREDENTIALS:
        set_client_state (CLIENT_AUTHENTICATE);
        break;

      case CLIENT_AUTHENTICATE_CREDENTIALS_USERNAME:
        set_client_state (CLIENT_AUTHENTICATE_CREDENTIALS);
        break;

      case CLIENT_AUTHENTICATE_CREDENTIALS_PASSWORD:
        set_client_state (CLIENT_AUTHENTICATE_CREDENTIALS);
        break;

      CASE_DELETE (ALERT, alert, "Alert");

      case CLIENT_DELETE_ASSET:
        if (delete_asset_data->asset_id
            || delete_asset_data->report_id)
          switch (delete_asset (delete_asset_data->asset_id,
                                delete_asset_data->report_id,
                                delete_asset_data->ultimate))
            {
              case 0:
                SEND_TO_CLIENT_OR_FAIL (XML_OK ("delete_asset"));
                log_event ("asset", "Asset",
                           delete_asset_data->asset_id, "deleted");
                break;
              case 1:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("delete_asset",
                                    "Asset is in use"));
                log_event_fail ("asset", "Asset",
                                delete_asset_data->asset_id,
                                "deleted");
                break;
              case 2:
                if (send_find_error_to_client
                     ("delete_asset",
                      "asset",
                      delete_asset_data->asset_id,
                      gmp_parser))
                  {
                    error_send_to_client (error);
                    return;
                  }
                log_event_fail ("asset", "Asset",
                                delete_asset_data->asset_id,
                                "deleted");
                break;
              case 3:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("delete_asset",
                                    "Attempt to delete a predefined asset"));
                log_event_fail ("asset", "Asset",
                                delete_asset_data->asset_id,
                                "deleted");
                break;
              case 4:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("delete_asset",
                                    "An asset_id or a"
                                    "report_id is required"));
                log_event_fail ("asset", "Asset",
                                delete_asset_data->asset_id,
                                "deleted");
                break;
              case 99:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("delete_asset",
                                    "Permission denied"));
                log_event_fail ("asset", "Asset",
                                delete_asset_data->asset_id,
                                "deleted");
                break;
              default:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_INTERNAL_ERROR ("delete_asset"));
                log_event_fail ("asset", "Asset",
                                delete_asset_data->asset_id,
                                "deleted");
            }
        else
          SEND_TO_CLIENT_OR_FAIL
           (XML_ERROR_SYNTAX ("delete_asset",
                              "An asset_id attribute is required"));
        delete_asset_data_reset (delete_asset_data);
        set_client_state (CLIENT_AUTHENTIC);
        break;

      CASE_DELETE (CONFIG, config, "Config");
      CASE_DELETE (CREDENTIAL, credential, "Credential");
      CASE_DELETE (FILTER, filter, "Filter");
      CASE_DELETE (GROUP, group, "Group");
      CASE_DELETE (NOTE, note, "Note");
      CASE_DELETE (OVERRIDE, override, "Override");
      CASE_DELETE (PERMISSION, permission, "Permission");
      CASE_DELETE (PORT_LIST, port_list, "Port list");
      CASE_DELETE (PORT_RANGE, port_range, "Port range");
      CASE_DELETE (REPORT, report, "Report");
      CASE_DELETE (REPORT_FORMAT, report_format, "Report format");
      CASE_DELETE (ROLE, role, "Role");
      CASE_DELETE (SCANNER, scanner, "Scanner");
      CASE_DELETE (SCHEDULE, schedule, "Schedule");
      CASE_DELETE (TAG, tag, "Tag");
      CASE_DELETE (TARGET, target, "Target");

      case CLIENT_DELETE_TASK:
        if (delete_task_data->task_id)
          {
            switch (request_delete_task_uuid (delete_task_data->task_id,
                                              delete_task_data->ultimate))
              {
                case 0:    /* Deleted. */
                  SEND_TO_CLIENT_OR_FAIL (XML_OK ("delete_task"));
                  log_event ("task", "Task", delete_task_data->task_id,
                             "deleted");
                  break;
                case 1:    /* Delete requested. */
                  SEND_TO_CLIENT_OR_FAIL (XML_OK_REQUESTED ("delete_task"));
                  log_event ("task", "Task", delete_task_data->task_id,
                             "requested for delete");
                  break;
                case 2:    /* Hidden task. */
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("delete_task",
                                      "Attempt to delete a hidden task"));
                  log_event_fail ("task", "Task", delete_task_data->task_id,
                                  "deleted");
                  break;
                case 3:  /* Failed to find task. */
                  if (send_find_error_to_client
                       ("delete_task", "task", delete_task_data->task_id,
                        gmp_parser))
                    {
                      error_send_to_client (error);
                      return;
                    }
                  break;
                case 99:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("delete_task",
                                      "Permission denied"));
                  log_event_fail ("task", "Task", delete_task_data->task_id,
                                  "deleted");
                  break;
                default:   /* Programming error. */
                  assert (0);
                case -1:
                  /* Some other error occurred. */
                  /** @todo Should respond with internal error. */
                  g_debug ("delete_task failed");
                  abort ();
                  break;
                case -5:
                  SEND_XML_SERVICE_DOWN ("delete_task");
                  log_event_fail ("task", "Task",
                                  delete_task_data->task_id,
                                  "deleted");
                  break;
                case -7:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("delete_task", "No CA certificate"));
                  log_event_fail ("task", "Task",
                                  delete_task_data->task_id,
                                  "deleted");
                  break;
              }
          }
        else
          SEND_TO_CLIENT_OR_FAIL
           (XML_ERROR_SYNTAX ("delete_task",
                              "A task_id attribute is required"));
        delete_task_data_reset (delete_task_data);
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_DELETE_TICKET:
      case CLIENT_DELETE_TLS_CERTIFICATE:
        delete_run (gmp_parser, error);
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_DELETE_USER:
        if (delete_user_data->user_id || delete_user_data->name)
          switch (delete_user (delete_user_data->user_id,
                               delete_user_data->name,
                               delete_user_data->ultimate,
                               1,
                               delete_user_data->inheritor_id,
                               delete_user_data->inheritor_name))
            {
              case 0:
                SEND_TO_CLIENT_OR_FAIL (XML_OK ("delete_user"));
                log_event ("user", "User", delete_user_data->user_id,
                           "deleted");
                break;
              case 2:
                if (send_find_error_to_client ("delete_user",
                                               "user",
                                               delete_user_data->user_id
                                                ? delete_user_data->user_id
                                                : delete_user_data->name,
                                               gmp_parser))
                  {
                    error_send_to_client (error);
                    return;
                  }
                log_event_fail ("user", "User", delete_user_data->user_id,
                                "deleted");
                break;
              case 3:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("delete_user",
                                    "Attempt to delete a predefined"
                                    " user"));
                break;
              case 4:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("delete_user",
                                    "User has an active task"));
                break;
              case 5:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("delete_user",
                                    "Attempt to delete current user"));
                break;
              case 6:
                if (send_find_error_to_client ("delete_user", "inheriting user",
                                               delete_user_data->inheritor_id,
                                               gmp_parser))
                  {
                    error_send_to_client (error);
                    return;
                  }
                break;
              case 7:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("delete_user",
                                    "Inheritor is the same as the deleted"
                                    " user."));
                break;
              case 8:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("delete_user",
                                    "Invalid inheritor."));
                break;
              case 9:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("delete_user",
                                    "Resources owned by the user are still"
                                    " in use by others."));
                break;
              case 10:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("delete_user",
                                    "User is Feed Import Owner"));
                break;
              case 99:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("delete_user",
                                    "Permission denied"));
                log_event_fail ("user", "User", delete_user_data->user_id,
                                "deleted");
                break;
              default:
                SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("delete_user"));
                log_event_fail ("user", "User", delete_user_data->user_id,
                                "deleted");
            }
        else
          SEND_TO_CLIENT_OR_FAIL
           (XML_ERROR_SYNTAX ("delete_user",
                              "A user_id attribute is required"));
        delete_user_data_reset (delete_user_data);
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_DESCRIBE_AUTH:
        {
          if (acl_user_may ("describe_auth") == 0)
            {
              SEND_TO_CLIENT_OR_FAIL
               (XML_ERROR_SYNTAX ("describe_auth",
                                  "Permission denied"));
              set_client_state (CLIENT_AUTHENTIC);
              break;
            }

          SEND_TO_CLIENT_OR_FAIL ("<describe_auth_response"
                                  " status=\"" STATUS_OK "\""
                                  " status_text=\"" STATUS_OK_TEXT "\">"
                                  "<group name=\"method:file\">"
                                  "<auth_conf_setting>"
                                  "<key>enable</key>"
                                  "<value>true</value>"
                                  "</auth_conf_setting>"
                                  "<auth_conf_setting>"
                                  "<key>order</key>"
                                  "<value>1</value>"
                                  "</auth_conf_setting>"
                                  "</group>");

          if (gvm_auth_ldap_enabled ())
            {
              gchar *ldap_host, *ldap_authdn, *ldap_cacert;
              int ldap_enabled, ldap_allow_plaintext;
              manage_get_ldap_info (&ldap_enabled, &ldap_host, &ldap_authdn,
                                    &ldap_allow_plaintext, &ldap_cacert);
              SENDF_TO_CLIENT_OR_FAIL
               ("<group name=\"method:ldap_connect\">"
                "<auth_conf_setting>"
                "<key>enable</key>"
                "<value>%s</value>"
                "</auth_conf_setting>"
                "<auth_conf_setting>"
                "<key>order</key>"
                "<value>0</value>"
                "</auth_conf_setting>"
                "<auth_conf_setting>"
                "<key>ldaphost</key>"
                "<value>%s</value>"
                "</auth_conf_setting>"
                "<auth_conf_setting>"
                "<key>authdn</key>"
                "<value>%s</value>"
                "</auth_conf_setting>"
                "<auth_conf_setting>"
                "<key>allow-plaintext</key>"
                "<value>%i</value>"
                "</auth_conf_setting>",
                ldap_enabled ? "true" : "false",
                ldap_host,
                ldap_authdn,
                ldap_allow_plaintext);

              g_free (ldap_host);
              g_free (ldap_authdn);

              if (ldap_cacert)
                {
                  time_t activation_time, expiration_time;
                  gchar *activation_time_str, *expiration_time_str;
                  gchar *md5_fingerprint, *issuer;

                  SENDF_TO_CLIENT_OR_FAIL
                   ("<auth_conf_setting>"
                    "<key>cacert</key>"
                    "<value>%s</value>",
                    ldap_cacert);

                  get_certificate_info (ldap_cacert,
                                        -1,
                                        &activation_time,
                                        &expiration_time,
                                        &md5_fingerprint,
                                        NULL,   /* sha256_fingerprint */
                                        NULL,   /* subject */
                                        &issuer,
                                        NULL,   /* serial */
                                        NULL);  /* certificate_format */

                  activation_time_str = certificate_iso_time (activation_time);
                  expiration_time_str = certificate_iso_time (expiration_time);
                  SENDF_TO_CLIENT_OR_FAIL
                   ("<certificate_info>"
                    "<time_status>%s</time_status>"
                    "<activation_time>%s</activation_time>"
                    "<expiration_time>%s</expiration_time>"
                    "<md5_fingerprint>%s</md5_fingerprint>"
                    "<issuer>%s</issuer>"
                    "</certificate_info>",
                    certificate_time_status (activation_time, expiration_time),
                    activation_time_str,
                    expiration_time_str,
                    md5_fingerprint,
                    issuer);
                  g_free (activation_time_str);
                  g_free (expiration_time_str);
                  g_free (md5_fingerprint);
                  g_free (issuer);

                  SEND_TO_CLIENT_OR_FAIL ("</auth_conf_setting>");

                  g_free (ldap_cacert);
                }

              SEND_TO_CLIENT_OR_FAIL ("</group>");
            }

          if (gvm_auth_radius_enabled ())
            {
              char *radius_host, *radius_key;
              int radius_enabled;
              manage_get_radius_info (&radius_enabled, &radius_host,
                                      &radius_key);
              SENDF_TO_CLIENT_OR_FAIL
               ("<group name=\"method:radius_connect\">"
                "<auth_conf_setting>"
                "<key>enable</key>"
                "<value>%s</value>"
                "</auth_conf_setting>"
                "<auth_conf_setting>"
                "<key>radiushost</key>"
                "<value>%s</value>"
                "</auth_conf_setting>"
                "<auth_conf_setting>"
                "<key>radiuskey</key>"
                "<value>%s</value>"
                "</auth_conf_setting>"
                "</group>",
                radius_enabled ? "true" : "false", radius_host, radius_key);
              g_free (radius_host);
              g_free (radius_key);
            }

          SEND_TO_CLIENT_OR_FAIL ("</describe_auth_response>");

          set_client_state (CLIENT_AUTHENTIC);
          break;
        }

      case CLIENT_GET_AGGREGATES:
        handle_get_aggregates (gmp_parser, error);
        break;

      CLOSE (CLIENT_GET_AGGREGATES, DATA_COLUMN);
      CLOSE (CLIENT_GET_AGGREGATES, SORT);
      CLOSE (CLIENT_GET_AGGREGATES, TEXT_COLUMN);

      case CLIENT_GET_ALERTS:
        handle_get_alerts (gmp_parser, error);
        break;

      case CLIENT_GET_ASSETS:
        handle_get_assets (gmp_parser, error);
        break;

      case CLIENT_GET_CONFIGS:
        handle_get_configs (gmp_parser, error);
        break;

      case CLIENT_GET_CREDENTIALS:
        handle_get_credentials (gmp_parser, error);
        break;

      case CLIENT_GET_FEEDS:
        handle_get_feeds (gmp_parser, error);
        break;

      case CLIENT_GET_FILTERS:
        handle_get_filters (gmp_parser, error);
        break;

      case CLIENT_GET_GROUPS:
        handle_get_groups (gmp_parser, error);
        break;

      case CLIENT_GET_INFO:
        handle_get_info (gmp_parser, error);
        break;

      case CLIENT_GET_LICENSE:
        {
          if (get_license_element_end (gmp_parser,
                                       error,
                                       element_name))
            set_client_state (CLIENT_AUTHENTIC);
          break;
        }

      case CLIENT_GET_NOTES:
        handle_get_notes (gmp_parser, error);
        break;

      case CLIENT_GET_NVTS:
        handle_get_nvts (gmp_parser, error);
        break;

      case CLIENT_GET_NVT_FAMILIES:
        handle_get_nvt_families (gmp_parser, error);
        break;

      case CLIENT_GET_OVERRIDES:
        handle_get_overrides (gmp_parser, error);
        break;

      case CLIENT_GET_PERMISSIONS:
        handle_get_permissions (gmp_parser, error);
        break;

      case CLIENT_GET_PORT_LISTS:
        handle_get_port_lists (gmp_parser, error);
        break;

      case CLIENT_GET_PREFERENCES:
        handle_get_preferences (gmp_parser, error);
        break;

      case CLIENT_GET_REPORTS:
        handle_get_reports (gmp_parser, error);
        break;

      case CLIENT_GET_REPORT_FORMATS:
        handle_get_report_formats (gmp_parser, error);
        break;

      case CLIENT_GET_RESULTS:
        handle_get_results (gmp_parser, error);
        break;

      case CLIENT_GET_ROLES:
        handle_get_roles (gmp_parser, error);
        break;

      case CLIENT_GET_SCANNERS:
        handle_get_scanners (gmp_parser, error);
        break;

      case CLIENT_GET_SCHEDULES:
        handle_get_schedules (gmp_parser, error);
        break;

      case CLIENT_GET_SETTINGS:
        handle_get_settings (gmp_parser, error);
        break;

      case CLIENT_GET_SYSTEM_REPORTS:
        handle_get_system_reports (gmp_parser, error);
        break;

      case CLIENT_GET_TAGS:
        handle_get_tags (gmp_parser, error);
        break;

      case CLIENT_GET_TARGETS:
        handle_get_targets (gmp_parser, error);
        break;

      case CLIENT_GET_TASKS:
        handle_get_tasks (gmp_parser, error);
        break;

      CASE_GET_END (TICKETS, tickets);

      CASE_GET_END (TLS_CERTIFICATES, tls_certificates);

      case CLIENT_GET_USERS:
        handle_get_users (gmp_parser, error);
        break;

      case CLIENT_GET_VERSION:
      case CLIENT_GET_VERSION_AUTHENTIC:
        handle_get_version (gmp_parser, error);
        break;

      case CLIENT_GET_VULNS:
        handle_get_vulns (gmp_parser, error);
        break;

      case CLIENT_HELP:
        if (acl_user_may ("help") == 0)
          {
            SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX ("help",
                                                      "Permission denied"));
            help_data_reset (help_data);
            set_client_state (CLIENT_AUTHENTIC);
            break;
          }

        if (help_data->format == NULL
            || (strcmp (help_data->format, "text") == 0))
          {
            command_t *commands;
            SEND_TO_CLIENT_OR_FAIL ("<help_response"
                                    " status=\"" STATUS_OK "\""
                                    " status_text=\"" STATUS_OK_TEXT "\">\n");
            commands = gmp_commands;
            while ((*commands).name)
              {
                if (command_disabled (gmp_parser, (*commands).name) == 0)
                  {
                    int count;
                    SENDF_TO_CLIENT_OR_FAIL ("    %s",
                                             (*commands).name);
                    for (count = 23 - strlen ((*commands).name);
                         count > 0;
                         count--)
                      SEND_TO_CLIENT_OR_FAIL (" ");
                    SENDF_TO_CLIENT_OR_FAIL ("%s\n",
                                             (*commands).summary);
                  }
                commands++;
              }
            SEND_TO_CLIENT_OR_FAIL ("</help_response>");
          }
        else if (help_data->type && (strcmp (help_data->type, "brief") == 0))
          {
            command_t *commands;
            int index;

            SEND_TO_CLIENT_OR_FAIL ("<help_response"
                                    " status=\"" STATUS_OK "\""
                                    " status_text=\"" STATUS_OK_TEXT "\">\n"
                                    "<schema"
                                    " format=\"XML\""
                                    " extension=\"xml\""
                                    " content_type=\"text/xml\">");
            commands = acl_commands (gmp_parser->disabled_commands);
            for (index = 0; commands[index].name; index++)
              SENDF_TO_CLIENT_OR_FAIL ("<command>"
                                       "<name>%s</name>"
                                       "<summary>%s</summary>"
                                       "</command>",
                                       commands[index].name,
                                       commands[index].summary);
            g_free (commands);
            SEND_TO_CLIENT_OR_FAIL ("</schema>"
                                    "</help_response>");
          }
        else
          {
            gchar *extension, *content_type, *output;
            gsize output_len;

            switch (manage_schema (help_data->format,
                                   &output,
                                   &output_len,
                                   &extension,
                                   &content_type))
              {
                case 0:
                  {

                    SENDF_TO_CLIENT_OR_FAIL ("<help_response"
                                             " status=\"" STATUS_OK "\""
                                             " status_text=\"" STATUS_OK_TEXT "\">"
                                             "<schema"
                                             " format=\"%s\""
                                             " extension=\"%s\""
                                             " content_type=\"%s\">",
                                             help_data->format
                                              ? help_data->format
                                              : "XML",
                                             extension,
                                             content_type);
                    g_free (extension);
                    g_free (content_type);

                    if (output && strlen (output))
                      {
                        /* Encode and send the output. */

                        if (help_data->format
                            && strcasecmp (help_data->format, "XML"))
                          {
                            gchar *base64;

                            base64 = g_base64_encode ((guchar*) output, output_len);
                            if (send_to_client (base64,
                                                write_to_client,
                                                write_to_client_data))
                              {
                                g_free (output);
                                g_free (base64);
                                error_send_to_client (error);
                                return;
                              }
                            g_free (base64);
                          }
                        else
                          {
                            /* Special case the XML schema, bah. */
                            if (send_to_client (output,
                                                write_to_client,
                                                write_to_client_data))
                              {
                                g_free (output);
                                error_send_to_client (error);
                                return;
                              }
                          }
                      }
                    g_free (output);
                    SEND_TO_CLIENT_OR_FAIL ("</schema>"
                                            "</help_response>");
                  }
                  break;
                case 1:
                  assert (help_data->format);
                  if (send_find_error_to_client ("help", "schema_format",
                                                 help_data->format, gmp_parser))
                    {
                      error_send_to_client (error);
                      return;
                    }
                  break;
                default:
                  SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("help"));
                  break;
              }
          }
        help_data_reset (help_data);
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_CREATE_ASSET:
        {
          resource_t asset;

          if (create_asset_data->report_id == NULL
              && (create_asset_data->name == NULL
                  || create_asset_data->type == NULL))
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_asset",
                                "A report ID or an"
                                " ASSET with TYPE and NAME is required"));
          else if (create_asset_data->report_id)
            switch (create_asset_report (create_asset_data->report_id,
                                         create_asset_data->filter_term))
              {
                case 0:
                  SENDF_TO_CLIENT_OR_FAIL (XML_OK_CREATED ("create_asset"));
                  log_event ("asset", "Asset", NULL, "created");
                  break;
                case 1:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("create_asset",
                                      "Asset exists already"));
                  log_event_fail ("asset", "Asset", NULL, "created");
                  break;
                case 2:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("create_asset",
                                      "Name may only contain alphanumeric"
                                      " characters"));
                  log_event_fail ("asset", "Asset", NULL, "created");
                  break;
                case 99:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("create_asset",
                                      "Permission denied"));
                  log_event_fail ("asset", "Asset", NULL, "created");
                  break;
                default:
                  assert (0);
                case -1:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_INTERNAL_ERROR ("create_asset"));
                  log_event_fail ("asset", "Asset", NULL, "created");
                  break;
              }
          else if (strcasecmp (create_asset_data->type, "host") == 0)
            {
              switch (create_asset_host (create_asset_data->name,
                                         create_asset_data->comment,
                                         &asset))
                {
                  case 0:
                    {
                      char *uuid;
                      uuid = host_uuid (asset);
                      SENDF_TO_CLIENT_OR_FAIL
                        (XML_OK_CREATED_ID ("create_asset"), uuid);
                      log_event ("asset", "Asset", uuid, "created");
                      g_free (uuid);
                      break;
                    }
                  case 1:
                    SEND_TO_CLIENT_OR_FAIL
                       (XML_ERROR_SYNTAX ("create_asset",
                                          "Asset exists already"));
                    log_event_fail ("asset", "Asset", NULL, "created");
                    break;
                  case 2:
                    SEND_TO_CLIENT_OR_FAIL
                       (XML_ERROR_SYNTAX ("create_asset",
                                          "Name must be an IP address"));
                    log_event_fail ("asset", "Asset", NULL, "created");
                    break;
                  case 99:
                    SEND_TO_CLIENT_OR_FAIL
                       (XML_ERROR_SYNTAX ("create_asset",
                                          "Permission denied"));
                    log_event_fail ("asset", "Asset", NULL, "created");
                    break;
                  default:
                    assert (0);
                  case -1:
                    SEND_TO_CLIENT_OR_FAIL
                       (XML_INTERNAL_ERROR ("create_asset"));
                    log_event_fail ("asset", "Asset", NULL, "created");
                    break;
                }
            }
          else
            {
              SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_asset",
                                    "ASSET TYPE must be 'host'"));
              log_event_fail ("asset", "Asset", NULL, "created");
              break;
            }
          create_asset_data_reset (create_asset_data);
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }
      CLOSE (CLIENT_CREATE_ASSET, REPORT);
      CLOSE (CLIENT_CREATE_ASSET, ASSET);
      CLOSE (CLIENT_CREATE_ASSET_ASSET, COMMENT);
      CLOSE (CLIENT_CREATE_ASSET_ASSET, NAME);
      CLOSE (CLIENT_CREATE_ASSET_ASSET, TYPE);
      CLOSE (CLIENT_CREATE_ASSET_REPORT, FILTER);
      CLOSE (CLIENT_CREATE_ASSET_REPORT_FILTER, TERM);

      case CLIENT_CREATE_CONFIG:
        if (create_config_element_end (gmp_parser, error, element_name))
          set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_CREATE_ALERT:
        {
          event_t event;
          alert_condition_t condition;
          alert_method_t method;
          alert_t new_alert;

          assert (create_alert_data->name != NULL);
          assert (create_alert_data->condition != NULL);
          assert (create_alert_data->method != NULL);
          assert (create_alert_data->event != NULL);

          array_terminate (create_alert_data->condition_data);
          array_terminate (create_alert_data->event_data);
          array_terminate (create_alert_data->method_data);

          if (create_alert_data->copy)
            switch (copy_alert (create_alert_data->name,
                                create_alert_data->comment,
                                create_alert_data->copy,
                                &new_alert))
              {
                case 0:
                  {
                    char *uuid;
                    uuid = alert_uuid (new_alert);
                    SENDF_TO_CLIENT_OR_FAIL (XML_OK_CREATED_ID ("create_alert"),
                                             uuid);
                    log_event ("alert", "Alert", uuid, "created");
                    free (uuid);
                    break;
                  }
                case 1:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("create_alert",
                                      "Alert exists already"));
                  log_event_fail ("alert", "Alert", NULL, "created");
                  break;
                case 2:
                  if (send_find_error_to_client ("create_alert", "alert",
                                                 create_alert_data->copy,
                                                 gmp_parser))
                    {
                      error_send_to_client (error);
                      return;
                    }
                  log_event_fail ("alert", "Alert", NULL, "created");
                  break;
                case 99:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("create_alert",
                                      "Permission denied"));
                  log_event_fail ("alert", "Alert", NULL, "created");
                  break;
                case -1:
                default:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_INTERNAL_ERROR ("create_alert"));
                  log_event_fail ("alert", "Alert", NULL, "created");
                  break;
              }
          else if (strlen (create_alert_data->name) == 0)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_alert",
                                "A NAME element which"
                                " is at least one character long is required"));
          else if (strlen (create_alert_data->condition) == 0)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_alert",
                                "A value in a"
                                " CONDITION element is required"));
          else if (strlen (create_alert_data->event) == 0)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_alert",
                                "A value in an"
                                " EVENT element is required"));
          else if (strlen (create_alert_data->method) == 0)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_alert",
                                "A value in a"
                                " METHOD element is required"));
          else if ((condition = alert_condition_from_name
                                 (create_alert_data->condition))
                   == 0)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_alert",
                                "Failed to recognise condition name"));
          else if ((event = event_from_name (create_alert_data->event))
                   == 0)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_alert",
                                "Failed to recognise event name"));
          else if ((method = alert_method_from_name
                              (create_alert_data->method))
                   == 0)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_alert",
                                "Failed to recognise method name"));
          else
            {
              switch (create_alert (create_alert_data->name,
                                    create_alert_data->comment,
                                    create_alert_data->filter_id,
                                    create_alert_data->active,
                                    event,
                                    create_alert_data->event_data,
                                    condition,
                                    create_alert_data->condition_data,
                                    method,
                                    create_alert_data->method_data,
                                    &new_alert))
                {
                  case 0:
                    {
                      char *uuid;
                      uuid = alert_uuid (new_alert);
                      SENDF_TO_CLIENT_OR_FAIL
                       (XML_OK_CREATED_ID ("create_alert"), uuid);
                      log_event ("alert", "Alert", uuid, "created");
                      free (uuid);
                      break;
                    }
                  case 1:
                    SEND_TO_CLIENT_OR_FAIL
                     (XML_ERROR_SYNTAX ("create_alert",
                                        "Alert exists already"));
                    log_event_fail ("alert", "Alert", NULL, "created");
                    break;
                  case 2:
                    SEND_TO_CLIENT_OR_FAIL
                     (XML_ERROR_SYNTAX ("create_alert",
                                        "Validation of email address failed"));
                    log_event_fail ("alert", "Alert", NULL, "created");
                    break;
                  case 3:
                    if (send_find_error_to_client ("create_alert", "filter",
                                                   create_alert_data->filter_id,
                                                   gmp_parser))
                      {
                        error_send_to_client (error);
                        return;
                      }
                    log_event_fail ("alert", "Alert", NULL, "created");
                    break;
                  case 4:
                    SEND_TO_CLIENT_OR_FAIL
                     (XML_ERROR_SYNTAX ("create_alert",
                                        "Filter type must be result if"
                                        " specified"));
                    log_event_fail ("alert", "Alert", NULL, "created");
                    break;
                  case 5:
                    SEND_TO_CLIENT_OR_FAIL
                     (XML_ERROR_SYNTAX ("create_alert",
                                        "Invalid or unexpected condition data"
                                        " name"));
                    log_event_fail ("alert", "Alert", NULL, "created");
                    break;
                  case 6:
                    SEND_TO_CLIENT_OR_FAIL
                     (XML_ERROR_SYNTAX ("create_alert",
                                        "Syntax error in condition data"));
                    log_event_fail ("alert", "Alert", NULL, "created");
                    break;
                  case 7:
                    SEND_TO_CLIENT_OR_FAIL
                     (XML_ERROR_SYNTAX ("create_alert",
                                        "Email subject too long"));
                    log_event_fail ("alert", "Alert", NULL, "created");
                    break;
                  case 8:
                    SEND_TO_CLIENT_OR_FAIL
                     (XML_ERROR_SYNTAX ("create_alert",
                                        "Email message too long"));
                    log_event_fail ("alert", "Alert", NULL, "created");
                    break;
                  case 9:
                    SEND_TO_CLIENT_OR_FAIL
                     (XML_ERROR_SYNTAX ("create_alert",
                                        "Failed to find filter for condition"));
                    log_event_fail ("alert", "Alert", NULL, "created");
                    break;
                  case 12:
                    SEND_TO_CLIENT_OR_FAIL
                     (XML_ERROR_SYNTAX ("create_alert",
                                        "Error in Send host"));
                    log_event_fail ("alert", "Alert", NULL, "created");
                    break;
                  case 13:
                    SEND_TO_CLIENT_OR_FAIL
                     (XML_ERROR_SYNTAX ("create_alert",
                                        "Error in Send port"));
                    log_event_fail ("alert", "Alert", NULL, "created");
                    break;
                  case 14:
                    SEND_TO_CLIENT_OR_FAIL
                     (XML_ERROR_SYNTAX ("create_alert",
                                        "Failed to find report format for Send"
                                        " method"));
                    log_event_fail ("alert", "Alert", NULL, "created");
                    break;
                  case 15:
                    SEND_TO_CLIENT_OR_FAIL
                     (XML_ERROR_SYNTAX ("create_alert",
                                        "Error in SCP host"));
                    log_event_fail ("alert", "Alert", NULL, "created");
                    break;
                  case 17:
                    SEND_TO_CLIENT_OR_FAIL
                     (XML_ERROR_SYNTAX ("create_alert",
                                        "Failed to find report format for SCP"
                                        " method"));
                    log_event_fail ("alert", "Alert", NULL, "created");
                    break;
                  case 18:
                    SEND_TO_CLIENT_OR_FAIL
                     (XML_ERROR_SYNTAX ("create_alert",
                                        "Error in SCP credential"));
                    log_event_fail ("alert", "Alert", NULL, "created");
                    break;
                  case 19:
                    SEND_TO_CLIENT_OR_FAIL
                     (XML_ERROR_SYNTAX ("create_alert",
                                        "Error in SCP path"));
                    log_event_fail ("alert", "Alert", NULL, "created");
                    break;
                  case 20:
                    SEND_TO_CLIENT_OR_FAIL
                     (XML_ERROR_SYNTAX ("create_alert",
                                        "Method does not match event type"));
                    log_event_fail ("alert", "Alert", NULL, "created");
                    break;
                  case 21:
                    SEND_TO_CLIENT_OR_FAIL
                     (XML_ERROR_SYNTAX ("create_alert",
                                        "Condition does not match event type"));
                    log_event_fail ("alert", "Alert", NULL, "created");
                    break;
                  case 31:
                    SEND_TO_CLIENT_OR_FAIL
                     (XML_ERROR_SYNTAX ("create_alert",
                                        "Unexpected event data name"));
                    log_event_fail ("alert", "Alert", NULL, "created");
                    break;
                  case 32:
                    SEND_TO_CLIENT_OR_FAIL
                     (XML_ERROR_SYNTAX ("create_alert",
                                        "Syntax error in event data"));
                    log_event_fail ("alert", "Alert", NULL, "created");
                    break;
                  case 40:
                    SEND_TO_CLIENT_OR_FAIL
                     (XML_ERROR_SYNTAX ("create_alert",
                                        "Error in SMB credential"));
                    log_event_fail ("alert", "Alert", NULL, "created");
                    break;
                  case 41:
                    SEND_TO_CLIENT_OR_FAIL
                     (XML_ERROR_SYNTAX ("create_alert",
                                        "Error in SMB share path"));
                    log_event_fail ("alert", "Alert", NULL, "created");
                    break;
                  case 42:
                    SEND_TO_CLIENT_OR_FAIL
                     (XML_ERROR_SYNTAX ("create_alert",
                                        "Error in SMB file path"));
                    log_event_fail ("alert", "Alert", NULL, "created");
                    break;
                  case 43:
                    SEND_TO_CLIENT_OR_FAIL
                     (XML_ERROR_SYNTAX ("create_alert",
                                        "SMB file path must not contain"
                                        " any file or subdirectory ending in"
                                        " a dot (.)."));
                    log_event_fail ("alert", "Alert", NULL, "created");
                    break;
                  case 50:
                    SEND_TO_CLIENT_OR_FAIL
                     (XML_ERROR_SYNTAX ("create_alert",
                                        "Error in TippingPoint credential"));
                    log_event_fail ("alert", "Alert", NULL, "created");
                    break;
                  case 51:
                    SEND_TO_CLIENT_OR_FAIL
                     (XML_ERROR_SYNTAX ("create_alert",
                                        "Error in TippingPoint hostname"));
                    log_event_fail ("alert", "Alert", NULL, "created");
                    break;
                  case 52:
                    SEND_TO_CLIENT_OR_FAIL
                     (XML_ERROR_SYNTAX ("create_alert",
                                        "Error in TippingPoint TLS"
                                        " certificate"));
                    log_event_fail ("alert", "Alert", NULL, "created");
                    break;
                  case 53:
                    SEND_TO_CLIENT_OR_FAIL
                     (XML_ERROR_SYNTAX ("create_alert",
                                        "TippingPoint TLS workaround must be"
                                        " set to 0 or 1"));
                    log_event_fail ("alert", "Alert", NULL, "created");
                    break;
                  case 60:
                    {
                      SEND_TO_CLIENT_OR_FAIL
                        ("<create_alert_response"
                         " status=\"" STATUS_ERROR_MISSING "\""
                         " status_text=\"Recipient credential not found\"/>");
                      log_event_fail ("alert", "Alert", NULL, "created");
                    }
                    break;
                  case 61:
                    SEND_TO_CLIENT_OR_FAIL
                     (XML_ERROR_SYNTAX ("create_alert",
                                        "Email recipient credential must have"
                                        " type 'pgp' or 'smime'"));
                    log_event_fail ("alert", "Alert", NULL, "created");
                    break;
                  case 70:
                    {
                      SEND_TO_CLIENT_OR_FAIL
                        ("<create_alert_response"
                         " status=\"" STATUS_ERROR_MISSING "\""
                         " status_text=\"Credential for vFire not found\"/>");
                      log_event_fail ("alert", "Alert", NULL, "created");
                    }
                    break;
                  case 71:
                    SEND_TO_CLIENT_OR_FAIL
                     (XML_ERROR_SYNTAX ("create_alert",
                                        "vFire credential must have"
                                        " type 'up'"));
                    log_event_fail ("alert", "Alert", NULL, "created");
                    break;
                  case 80:
                    {
                      SEND_TO_CLIENT_OR_FAIL
                        ("<create_alert_response"
                         " status=\"" STATUS_ERROR_MISSING "\""
                         " status_text=\"Credential for Sourcefire"
                         " PKCS12 password not found\"/>");
                      log_event_fail ("alert", "Alert", NULL, "created");
                    }
                    break;
                  case 81:
                    SEND_TO_CLIENT_OR_FAIL
                     (XML_ERROR_SYNTAX ("create_alert",
                                        "Sourcefire credential must have"
                                        " type 'pw' or 'up'"));
                    log_event_fail ("alert", "Alert", NULL, "created");
                    break;
                  case 99:
                    SEND_TO_CLIENT_OR_FAIL
                     (XML_ERROR_SYNTAX ("create_alert",
                                        "Permission denied"));
                    log_event_fail ("alert", "Alert", NULL, "created");
                    break;
                  default:
                    assert (0);
                  case -1:
                    SEND_TO_CLIENT_OR_FAIL
                     (XML_INTERNAL_ERROR ("create_alert"));
                    log_event_fail ("alert", "Alert", NULL, "created");
                    break;
                }
            }
          create_alert_data_reset (create_alert_data);
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }
      CLOSE (CLIENT_CREATE_ALERT, ACTIVE);
      CLOSE (CLIENT_CREATE_ALERT, COMMENT);
      CLOSE (CLIENT_CREATE_ALERT, COPY);
      CLOSE (CLIENT_CREATE_ALERT, CONDITION);
      CLOSE (CLIENT_CREATE_ALERT, EVENT);
      CLOSE (CLIENT_CREATE_ALERT, FILTER);
      CLOSE (CLIENT_CREATE_ALERT, METHOD);
      CLOSE (CLIENT_CREATE_ALERT, NAME);

      case CLIENT_CREATE_ALERT_CONDITION_DATA:
        {
          gchar *string;

          assert (create_alert_data->condition_data);
          assert (create_alert_data->part_data);
          assert (create_alert_data->part_name);

          string = g_strconcat (create_alert_data->part_name,
                                "0",
                                create_alert_data->part_data,
                                NULL);
          string[strlen (create_alert_data->part_name)] = '\0';
          array_add (create_alert_data->condition_data, string);

          gvm_free_string_var (&create_alert_data->part_data);
          gvm_free_string_var (&create_alert_data->part_name);
          gvm_append_string (&create_alert_data->part_data, "");
          gvm_append_string (&create_alert_data->part_name, "");
          set_client_state (CLIENT_CREATE_ALERT_CONDITION);
          break;
        }
      case CLIENT_CREATE_ALERT_CONDITION_DATA_NAME:
        set_client_state (CLIENT_CREATE_ALERT_CONDITION_DATA);
        break;

      case CLIENT_CREATE_ALERT_EVENT_DATA:
        {
          gchar *string;

          assert (create_alert_data->event_data);
          assert (create_alert_data->part_data);
          assert (create_alert_data->part_name);

          string = g_strconcat (create_alert_data->part_name,
                                "0",
                                create_alert_data->part_data,
                                NULL);
          string[strlen (create_alert_data->part_name)] = '\0';
          array_add (create_alert_data->event_data, string);

          gvm_free_string_var (&create_alert_data->part_data);
          gvm_free_string_var (&create_alert_data->part_name);
          gvm_append_string (&create_alert_data->part_data, "");
          gvm_append_string (&create_alert_data->part_name, "");
          set_client_state (CLIENT_CREATE_ALERT_EVENT);
          break;
        }
      CLOSE (CLIENT_CREATE_ALERT_EVENT_DATA, NAME);

      case CLIENT_CREATE_ALERT_METHOD_DATA:
        {
          gchar *string;

          assert (create_alert_data->method_data);
          assert (create_alert_data->part_data);
          assert (create_alert_data->part_name);

          string = g_strconcat (create_alert_data->part_name,
                                "0",
                                create_alert_data->part_data,
                                NULL);
          string[strlen (create_alert_data->part_name)] = '\0';
          array_add (create_alert_data->method_data, string);

          gvm_free_string_var (&create_alert_data->part_data);
          gvm_free_string_var (&create_alert_data->part_name);
          gvm_append_string (&create_alert_data->part_data, "");
          gvm_append_string (&create_alert_data->part_name, "");
          set_client_state (CLIENT_CREATE_ALERT_METHOD);
          break;
        }
      CLOSE (CLIENT_CREATE_ALERT_METHOD_DATA, NAME);

      case CLIENT_CREATE_CREDENTIAL:
        {
          credential_t new_credential;

          assert (create_credential_data->name != NULL);

          if (create_credential_data->copy)
            switch (copy_credential (create_credential_data->name,
                                     create_credential_data->comment,
                                     create_credential_data->copy,
                                     &new_credential))
              {
                case 0:
                  {
                    char *uuid;
                    uuid = credential_uuid (new_credential);
                    SENDF_TO_CLIENT_OR_FAIL (XML_OK_CREATED_ID ("create_credential"),
                                             uuid);
                    log_event ("credential", "Credential", uuid, "created");
                    free (uuid);
                    break;
                  }
                case 1:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("create_credential",
                                      "Credential exists already"));
                  log_event_fail ("credential", "Credential", NULL, "created");
                  break;
                case 2:
                  if (send_find_error_to_client ("create_credential",
                                                 "credential",
                                                 create_credential_data->copy,
                                                 gmp_parser))
                    {
                      error_send_to_client (error);
                      return;
                    }
                  log_event_fail ("credential", "Credential", NULL, "created");
                  break;
                case 99:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("create_credential",
                                      "Permission denied"));
                  log_event_fail ("credential", "Credential", NULL, "created");
                  break;
                case -1:
                default:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_INTERNAL_ERROR ("create_credential"));
                  log_event_fail ("credential", "Credential", NULL, "created");
                  break;
              }
          else if (strlen (create_credential_data->name) == 0)
            {
              SEND_TO_CLIENT_OR_FAIL
               (XML_ERROR_SYNTAX ("create_credential",
                                  "Name must be at"
                                  " least one character long"));
            }
          else if (create_credential_data->login
                   && strlen (create_credential_data->login) == 0)
            {
              SEND_TO_CLIENT_OR_FAIL
               (XML_ERROR_SYNTAX ("create_credential",
                                  "Login must be at"
                                  " least one character long"));
            }
          else if (create_credential_data->key
                   && create_credential_data->key_private == NULL
                   && create_credential_data->key_public == NULL)
            {
              SEND_TO_CLIENT_OR_FAIL
               (XML_ERROR_SYNTAX ("create_credential",
                                  "KEY requires a PRIVATE"
                                  " or PUBLIC key"));
            }
          else if (create_credential_data->key
                   && create_credential_data->key_private
                   && check_private_key (create_credential_data->key_private,
                                         create_credential_data->key_phrase))
            {
              SEND_TO_CLIENT_OR_FAIL
              (XML_ERROR_SYNTAX ("create_credential",
                                 "Erroneous Private Key."));
            }
          else if (create_credential_data->key
                   && create_credential_data->key_public
                   && check_public_key (create_credential_data->key_public))
            {
              SEND_TO_CLIENT_OR_FAIL
              (XML_ERROR_SYNTAX ("create_credential",
                                 "Erroneous Public Key."));
            }
          else if (create_credential_data->certificate
                   && check_certificate
                          (create_credential_data->certificate,
                           create_credential_data->type))
            {
              SEND_TO_CLIENT_OR_FAIL
              (XML_ERROR_SYNTAX ("create_credential",
                                 "Erroneous Certificate."));
            }
          else switch (create_credential
                        (create_credential_data->name,
                         create_credential_data->comment,
                         create_credential_data->login,
                         create_credential_data->key_private
                          ? create_credential_data->key_phrase
                          : create_credential_data->password,
                         create_credential_data->key_private,
                         create_credential_data->key_public,
                         create_credential_data->certificate,
                         create_credential_data->community,
                         create_credential_data->auth_algorithm,
                         create_credential_data->privacy_password,
                         create_credential_data->privacy_algorithm,
                         create_credential_data->type,
                         create_credential_data->allow_insecure,
                         &new_credential))
            {
              case 0:
                {
                  char *uuid = credential_uuid (new_credential);
                  SENDF_TO_CLIENT_OR_FAIL
                   (XML_OK_CREATED_ID ("create_credential"), uuid);
                  log_event ("credential", "Credential", uuid, "created");
                  free (uuid);
                  break;
                }
              case 1:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_credential",
                                    "Credential exists already"));
                break;
              case 2:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_credential",
                                    "Login may only contain alphanumeric"
                                    " characters or the following:"
                                    " - _ \\ . @"));
                break;
              case 3:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_credential",
                                    "Erroneous private key or associated"
                                    " passphrase"));
                break;
              case 4:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_credential",
                                    "Erroneous credential type"));
                break;
              case 5:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_credential",
                                    "Selected type requires a login username"));
                break;
              case 6:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_credential",
                                    "Selected type requires a password"));
                break;
              case 7:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_credential",
                                    "Selected type requires a private key"));
                break;
              case 8:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_credential",
                                    "Selected type requires a certificate"));
                break;
              case 9:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_credential",
                                    "Selected type requires a public key"));
                break;
              case 10:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_credential",
                                    "Selected type cannot be generated"
                                    " automatically"));
                break;
              case 11:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_credential",
                                    "Selected type requires a community and/or"
                                    " username + password"));
                break;
              case 12:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_credential",
                                    "Selected type requires an"
                                    " auth_algorithm"));
                break;
              case 14:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_credential",
                                    "Selected type requires an"
                                    " algorithm in the privacy element"
                                    " if a password is given"));
                break;
              case 15:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_credential",
                                    "auth algorithm must be 'md5' or 'sha1'"));
                break;
              case 16:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_credential",
                                    "privacy algorithm must be 'aes', 'des'"
                                    " or empty"));
                break;
              case 17:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_credential",
                                    "Erroneous certificate"));
                break;
              case 99:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_credential",
                                    "Permission denied"));
                break;
              default:
                assert (0);
              case -1:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_INTERNAL_ERROR ("create_credential"));
                break;
            }
          create_credential_data_reset (create_credential_data);
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }
      CLOSE (CLIENT_CREATE_CREDENTIAL, ALLOW_INSECURE);
      CLOSE (CLIENT_CREATE_CREDENTIAL, AUTH_ALGORITHM);
      CLOSE (CLIENT_CREATE_CREDENTIAL, CERTIFICATE);
      CLOSE (CLIENT_CREATE_CREDENTIAL, COMMENT);
      CLOSE (CLIENT_CREATE_CREDENTIAL, COMMUNITY);
      CLOSE (CLIENT_CREATE_CREDENTIAL, COPY);
      CLOSE (CLIENT_CREATE_CREDENTIAL, KEY);
      CLOSE (CLIENT_CREATE_CREDENTIAL_KEY, PHRASE);
      CLOSE (CLIENT_CREATE_CREDENTIAL_KEY, PRIVATE);
      CLOSE (CLIENT_CREATE_CREDENTIAL_KEY, PUBLIC);
      CLOSE (CLIENT_CREATE_CREDENTIAL, LOGIN);
      CLOSE (CLIENT_CREATE_CREDENTIAL, NAME);
      CLOSE (CLIENT_CREATE_CREDENTIAL, PASSWORD);
      CLOSE (CLIENT_CREATE_CREDENTIAL, PRIVACY);
      CLOSE (CLIENT_CREATE_CREDENTIAL_PRIVACY, ALGORITHM);
      CLOSE (CLIENT_CREATE_CREDENTIAL_PRIVACY, PASSWORD);
      CLOSE (CLIENT_CREATE_CREDENTIAL, TYPE);

      case CLIENT_CREATE_FILTER:
        {
          filter_t new_filter;

          assert (create_filter_data->term != NULL);

          if (create_filter_data->copy)
            switch (copy_filter (create_filter_data->name,
                                 create_filter_data->comment,
                                 create_filter_data->copy,
                                 &new_filter))
              {
                case 0:
                  {
                    char *uuid;
                    uuid = filter_uuid (new_filter);
                    SENDF_TO_CLIENT_OR_FAIL (XML_OK_CREATED_ID ("create_filter"),
                                             uuid);
                    log_event ("filter", "Filter", uuid, "created");
                    free (uuid);
                    break;
                  }
                case 1:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("create_filter",
                                      "Filter exists already"));
                  log_event_fail ("filter", "Filter", NULL, "created");
                  break;
                case 2:
                  if (send_find_error_to_client ("create_filter", "filter",
                                                 create_filter_data->copy,
                                                 gmp_parser))
                    {
                      error_send_to_client (error);
                      return;
                    }
                  log_event_fail ("filter", "Filter", NULL, "created");
                  break;
                case 99:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("create_filter",
                                      "Permission denied"));
                  log_event_fail ("filter", "Filter", NULL, "created");
                  break;
                case -1:
                default:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_INTERNAL_ERROR ("create_filter"));
                  log_event_fail ("filter", "Filter", NULL, "created");
                  break;
              }
          else if (create_filter_data->name == NULL)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_filter",
                                "A NAME is required"));
          else if (strlen (create_filter_data->name) == 0)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_filter",
                                "Name must be at"
                                " least one character long"));
          else switch (create_filter
                        (create_filter_data->name,
                         create_filter_data->comment,
                         create_filter_data->type,
                         create_filter_data->term,
                         &new_filter))
            {
              case 0:
                {
                  char *uuid = filter_uuid (new_filter);
                  SENDF_TO_CLIENT_OR_FAIL (XML_OK_CREATED_ID ("create_filter"),
                                           uuid);
                  log_event ("filter", "Filter", uuid, "created");
                  free (uuid);
                  break;
                }
              case 1:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_filter",
                                    "Filter exists already"));
                log_event_fail ("filter", "Filter", NULL, "created");
                break;
              case 2:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_filter",
                                    "Type must be a valid GMP type"));
                log_event_fail ("filter", "Filter", NULL, "created");
                break;
              case 99:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_filter",
                                    "Permission denied"));
                log_event_fail ("filter", "Filter", NULL, "created");
                break;
              default:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_INTERNAL_ERROR ("create_filter"));
                log_event_fail ("filter", "Filter", NULL, "created");
                break;
            }

          create_filter_data_reset (create_filter_data);
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }
      CLOSE (CLIENT_CREATE_FILTER, COMMENT);
      CLOSE (CLIENT_CREATE_FILTER, COPY);
      CLOSE (CLIENT_CREATE_FILTER, NAME);
      CLOSE (CLIENT_CREATE_FILTER, TERM);
      CLOSE (CLIENT_CREATE_FILTER, TYPE);

      case CLIENT_CREATE_GROUP:
        {
          group_t new_group;

          assert (create_group_data->users != NULL);

          if (create_group_data->copy)
            switch (copy_group (create_group_data->name,
                                create_group_data->comment,
                                create_group_data->copy,
                                &new_group))
              {
                case 0:
                  {
                    char *uuid;
                    uuid = group_uuid (new_group);
                    SENDF_TO_CLIENT_OR_FAIL (XML_OK_CREATED_ID ("create_group"),
                                             uuid);
                    log_event ("group", "Group", uuid, "created");
                    free (uuid);
                    break;
                  }
                case 1:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("create_group",
                                      "Group exists already"));
                  log_event_fail ("group", "Group", NULL, "created");
                  break;
                case 2:
                  if (send_find_error_to_client ("create_group", "group",
                                                 create_group_data->copy,
                                                 gmp_parser))
                    {
                      error_send_to_client (error);
                      return;
                    }
                  log_event_fail ("group", "Group", NULL, "created");
                  break;
                case 4:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("create_group",
                                      "Syntax error in group name"));
                  log_event_fail ("group", "Group", NULL, "created");
                  break;
                case 99:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("create_group",
                                      "Permission denied"));
                  log_event_fail ("group", "Group", NULL, "created");
                  break;
                case -1:
                default:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_INTERNAL_ERROR ("create_group"));
                  log_event_fail ("group", "Group", NULL, "created");
                  break;
              }
          else if (create_group_data->name == NULL)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_group",
                                "A NAME is required"));
          else if (strlen (create_group_data->name) == 0)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_group",
                                "Name must be at"
                                " least one character long"));
          else switch (create_group
                        (create_group_data->name,
                         create_group_data->comment,
                         create_group_data->users,
                         create_group_data->special_full,
                         &new_group))
            {
              case 0:
                {
                  char *uuid = group_uuid (new_group);
                  SENDF_TO_CLIENT_OR_FAIL (XML_OK_CREATED_ID ("create_group"),
                                           uuid);
                  log_event ("group", "Group", uuid, "created");
                  free (uuid);
                  break;
                }
              case 1:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_group",
                                    "Group exists already"));
                log_event_fail ("group", "Group", NULL, "created");
                break;
              case 2:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_group",
                                    "Failed to find user"));
                log_event_fail ("group", "Group", NULL, "created");
                break;
              case 4:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_group",
                                    "Error in user name"));
                log_event_fail ("group", "Group", NULL, "created");
                break;
              case 99:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_group",
                                    "Permission denied"));
                log_event_fail ("group", "Group", NULL, "created");
                break;
              default:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_INTERNAL_ERROR ("create_group"));
                log_event_fail ("group", "Group", NULL, "created");
                break;
            }

          create_group_data_reset (create_group_data);
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }
      CLOSE (CLIENT_CREATE_GROUP, COMMENT);
      CLOSE (CLIENT_CREATE_GROUP, COPY);
      CLOSE (CLIENT_CREATE_GROUP, NAME);
      CLOSE (CLIENT_CREATE_GROUP, SPECIALS);
      CLOSE (CLIENT_CREATE_GROUP_SPECIALS, FULL);
      CLOSE (CLIENT_CREATE_GROUP, USERS);

      case CLIENT_CREATE_NOTE:
        {
          task_t task = 0;
          result_t result = 0;
          note_t new_note;
          int max;

          if (create_note_data->copy)
            switch (copy_note (create_note_data->copy, &new_note))
              {
                case 0:
                  {
                    char *uuid;
                    note_uuid (new_note, &uuid);
                    SENDF_TO_CLIENT_OR_FAIL (XML_OK_CREATED_ID ("create_note"),
                                             uuid);
                    log_event ("note", "Note", uuid, "created");
                    free (uuid);
                    break;
                  }
                case 1:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("create_note",
                                      "Note exists already"));
                  log_event_fail ("note", "Note", NULL, "created");
                  break;
                case 2:
                  if (send_find_error_to_client ("create_note", "note",
                                                 create_note_data->copy,
                                                 gmp_parser))
                    {
                      error_send_to_client (error);
                      return;
                    }
                  log_event_fail ("note", "Note", NULL, "created");
                  break;
                case 99:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("create_note",
                                      "Permission denied"));
                  log_event_fail ("note", "Note", NULL, "created");
                  break;
                case -1:
                default:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_INTERNAL_ERROR ("create_note"));
                  log_event_fail ("note", "Note", NULL, "created");
                  break;
              }
          else if (create_note_data->nvt_oid == NULL)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_note",
                                "An NVT entity is required"));
          else if (create_note_data->text == NULL)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_note",
                                "A TEXT entity is required"));
          else if (create_note_data->hosts
                   && ((max = manage_count_hosts (create_note_data->hosts, NULL))
                       == -1))
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_note",
                                "Error in host specification"));
          else if (create_note_data->hosts && (max > manage_max_hosts ()))
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_note",
                                "Host specification exceeds maximum number of"
                                " hosts"));
          else if (create_note_data->task_id
                   && find_task_with_permission (create_note_data->task_id,
                                                 &task,
                                                 NULL))
            SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("create_note"));
          else if (create_note_data->task_id && task == 0)
            {
              if (send_find_error_to_client ("create_note", "task",
                                             create_note_data->task_id,
                                             gmp_parser))
                {
                  error_send_to_client (error);
                  return;
                }
            }
          else if (create_note_data->result_id
                   && find_result_with_permission (create_note_data->result_id,
                                                   &result,
                                                   NULL))
            SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("create_note"));
          else if (create_note_data->result_id && result == 0)
            {
              if (send_find_error_to_client ("create_note", "result",
                                             create_note_data->result_id,
                                             gmp_parser))
                {
                  error_send_to_client (error);
                  return;
                }
            }
          else switch (create_note (create_note_data->active,
                                    create_note_data->nvt_oid,
                                    create_note_data->text,
                                    create_note_data->hosts,
                                    create_note_data->port,
                                    create_note_data->severity,
                                    create_note_data->threat,
                                    task,
                                    result,
                                    &new_note))
            {
              case 0:
                {
                  char *uuid;
                  note_uuid (new_note, &uuid);
                  SENDF_TO_CLIENT_OR_FAIL (XML_OK_CREATED_ID ("create_note"),
                                           uuid);
                  log_event ("note", "Note", uuid, "created");
                  free (uuid);
                  break;
                }
              case 1:
                if (send_find_error_to_client ("create_note", "nvt",
                                               create_note_data->nvt_oid,
                                               gmp_parser))
                  {
                    error_send_to_client (error);
                    return;
                  }
                break;
              case 2:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_note",
                                    "Error in port specification"));
                log_event_fail ("note", "Note", NULL, "created");
                break;
              case 99:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_note",
                                    "Permission denied"));
                break;
              case -1:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_INTERNAL_ERROR ("create_note"));
                break;
              default:
                assert (0);
                SEND_TO_CLIENT_OR_FAIL
                 (XML_INTERNAL_ERROR ("create_note"));
                break;
            }
          create_note_data_reset (create_note_data);
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }
      CLOSE (CLIENT_CREATE_NOTE, ACTIVE);
      CLOSE (CLIENT_CREATE_NOTE, COPY);
      CLOSE (CLIENT_CREATE_NOTE, HOSTS);
      CLOSE (CLIENT_CREATE_NOTE, NVT);
      CLOSE (CLIENT_CREATE_NOTE, PORT);
      CLOSE (CLIENT_CREATE_NOTE, SEVERITY);
      CLOSE (CLIENT_CREATE_NOTE, RESULT);
      CLOSE (CLIENT_CREATE_NOTE, TASK);
      CLOSE (CLIENT_CREATE_NOTE, TEXT);
      CLOSE (CLIENT_CREATE_NOTE, THREAT);

      case CLIENT_CREATE_OVERRIDE:
        {
          task_t task = 0;
          result_t result = 0;
          override_t new_override;
          int max;

          if (create_override_data->copy)
            switch (copy_override (create_override_data->copy, &new_override))
              {
                case 0:
                  {
                    char *uuid;
                    override_uuid (new_override, &uuid);
                    SENDF_TO_CLIENT_OR_FAIL (XML_OK_CREATED_ID ("create_override"),
                                             uuid);
                    log_event ("override", "Override", uuid, "created");
                    free (uuid);
                    break;
                  }
                case 1:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("create_override",
                                      "Override exists already"));
                  log_event_fail ("override", "Override", NULL, "created");
                  break;
                case 2:
                  if (send_find_error_to_client ("create_override", "override",
                                                 create_override_data->copy,
                                                 gmp_parser))
                    {
                      error_send_to_client (error);
                      return;
                    }
                  log_event_fail ("override", "Override", NULL, "created");
                  break;
                case 99:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("create_override",
                                      "Permission denied"));
                  log_event_fail ("override", "Override", NULL, "created");
                  break;
                case -1:
                default:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_INTERNAL_ERROR ("create_override"));
                  log_event_fail ("override", "Override", NULL, "created");
                  break;
              }
          else if (create_override_data->nvt_oid == NULL)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_override",
                                "An NVT entity is required"));
          else if (create_override_data->text == NULL)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_override",
                                "A TEXT entity is required"));
          else if (create_override_data->hosts
                   && ((max = manage_count_hosts (create_override_data->hosts,
                                                  NULL))
                       == -1))
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_override",
                                "Error in host specification"));
          else if (create_override_data->hosts && (max > manage_max_hosts ()))
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_override",
                                "Host specification exceeds maximum number"
                                " of hosts"));
          else if (create_override_data->new_threat == NULL
                   && create_override_data->new_severity == NULL)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_override",
                                "A NEW_THREAT"
                                " or NEW_SEVERITY entity is required"));
          else if (create_override_data->task_id
              && find_task_with_permission (create_override_data->task_id,
                                            &task,
                                            NULL))
            SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("create_override"));
          else if (create_override_data->task_id && task == 0)
            {
              if (send_find_error_to_client ("create_override", "task",
                                             create_override_data->task_id,
                                             gmp_parser))
                {
                  error_send_to_client (error);
                  return;
                }
            }
          else if (create_override_data->result_id
                   && find_result_with_permission (create_override_data->result_id,
                                                   &result,
                                                   NULL))
            SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("create_override"));
          else if (create_override_data->result_id && result == 0)
            {
              if (send_find_error_to_client ("create_override", "result",
                                             create_override_data->result_id,
                                             gmp_parser))
                {
                  error_send_to_client (error);
                  return;
                }
            }
          else switch (create_override (create_override_data->active,
                                        create_override_data->nvt_oid,
                                        create_override_data->text,
                                        create_override_data->hosts,
                                        create_override_data->port,
                                        create_override_data->threat,
                                        create_override_data->new_threat,
                                        create_override_data->severity,
                                        create_override_data->new_severity,
                                        task,
                                        result,
                                        &new_override))
            {
              case 0:
                {
                  char *uuid;
                  override_uuid (new_override, &uuid);
                  SENDF_TO_CLIENT_OR_FAIL
                   (XML_OK_CREATED_ID ("create_override"), uuid);
                  log_event ("override", "Override", uuid, "created");
                  free (uuid);
                  break;
                }
              case 1:
                if (send_find_error_to_client ("create_override", "nvt",
                                               create_override_data->nvt_oid,
                                               gmp_parser))
                  {
                    error_send_to_client (error);
                    return;
                  }
                break;
              case 2:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_override",
                                    "Error in port specification"));
                log_event_fail ("override", "Override", NULL, "created");
                break;
              case 3:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_override",
                                    "Error in new_severity specification"));
                log_event_fail ("override", "Override", NULL, "created");
                break;
              case 99:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_override",
                                    "Permission denied"));
                break;
              case -1:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_INTERNAL_ERROR ("create_override"));
                break;
              default:
                assert (0);
                SEND_TO_CLIENT_OR_FAIL
                 (XML_INTERNAL_ERROR ("create_override"));
                break;
            }
          create_override_data_reset (create_override_data);
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }
      CLOSE (CLIENT_CREATE_OVERRIDE, ACTIVE);
      CLOSE (CLIENT_CREATE_OVERRIDE, COPY);
      CLOSE (CLIENT_CREATE_OVERRIDE, HOSTS);
      CLOSE (CLIENT_CREATE_OVERRIDE, NEW_SEVERITY);
      CLOSE (CLIENT_CREATE_OVERRIDE, NEW_THREAT);
      CLOSE (CLIENT_CREATE_OVERRIDE, NVT);
      CLOSE (CLIENT_CREATE_OVERRIDE, PORT);
      CLOSE (CLIENT_CREATE_OVERRIDE, SEVERITY);
      CLOSE (CLIENT_CREATE_OVERRIDE, RESULT);
      CLOSE (CLIENT_CREATE_OVERRIDE, TASK);
      CLOSE (CLIENT_CREATE_OVERRIDE, TEXT);
      CLOSE (CLIENT_CREATE_OVERRIDE, THREAT);

      case CLIENT_CREATE_PERMISSION:
        {
          permission_t new_permission;

          if (create_permission_data->copy)
            switch (copy_permission (create_permission_data->comment,
                                     create_permission_data->copy,
                                     &new_permission))
              {
                case 0:
                  {
                    char *uuid;
                    uuid = permission_uuid (new_permission);
                    SENDF_TO_CLIENT_OR_FAIL (XML_OK_CREATED_ID ("create_permission"),
                                             uuid);
                    log_event ("permission", "Permission", uuid, "created");
                    free (uuid);
                    break;
                  }
                case 1:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("create_permission",
                                      "Permission exists already"));
                  log_event_fail ("permission", "Permission", NULL, "created");
                  break;
                case 2:
                  if (send_find_error_to_client ("create_permission",
                                                 "permission",
                                                 create_permission_data->copy,
                                                 gmp_parser))
                    {
                      error_send_to_client (error);
                      return;
                    }
                  log_event_fail ("permission", "Permission", NULL, "created");
                  break;
                case 99:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("create_permission",
                                      "Permission denied"));
                  log_event_fail ("permission", "Permission", NULL, "created");
                  break;
                case -1:
                default:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_INTERNAL_ERROR ("create_permission"));
                  log_event_fail ("permission", "Permission", NULL, "created");
                  break;
              }
          else if (create_permission_data->name == NULL)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_permission",
                                "A NAME is required"));
          else if (strlen (create_permission_data->name) == 0)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_permission",
                                "Name must be at"
                                " least one character long"));
          else switch (create_permission
                        (create_permission_data->name,
                         create_permission_data->comment,
                         create_permission_data->resource_type,
                         create_permission_data->resource_id,
                         create_permission_data->subject_type,
                         create_permission_data->subject_id,
                         &new_permission))
            {
              case 0:
                {
                  char *uuid = permission_uuid (new_permission);
                  SENDF_TO_CLIENT_OR_FAIL (XML_OK_CREATED_ID
                                            ("create_permission"),
                                           uuid);
                  log_event ("permission", "Permission", uuid, "created");
                  free (uuid);
                  break;
                }
              case 2:
                if (send_find_error_to_client
                     ("create_permission", "subject",
                      create_permission_data->subject_id, gmp_parser))
                  {
                    error_send_to_client (error);
                    return;
                  }
                log_event_fail ("permission", "Permission", NULL, "created");
                break;
              case 3:
                if (send_find_error_to_client
                     ("create_permission", "resource",
                      create_permission_data->resource_id, gmp_parser))
                  {
                    error_send_to_client (error);
                    return;
                  }
                log_event_fail ("permission", "Permission", NULL, "created");
                break;
              case 5:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_permission",
                                    "Error in RESOURCE"));
                log_event_fail ("permission", "Permission", NULL, "created");
                break;
              case 6:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_permission",
                                    "Error in SUBJECT"));
                log_event_fail ("permission", "Permission", NULL, "created");
                break;
              case 7:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_permission",
                                    "Error in NAME"));
                log_event_fail ("permission", "Permission", NULL, "created");
                break;
              case 8:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_permission",
                                    "Attempt to create permission on"
                                    " permission"));
                log_event_fail ("permission", "Permission", NULL, "created");
                break;
              case 9:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_permission",
                                    "Permission does not accept a resource"));
                log_event_fail ("permission", "Permission", NULL, "created");
                break;
              case 99:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_permission",
                                    "Permission denied"));
                log_event_fail ("permission", "Permission", NULL, "created");
                break;
              case -1:
              default:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_INTERNAL_ERROR ("create_permission"));
                log_event_fail ("permission", "Permission", NULL, "created");
                break;
            }

          create_permission_data_reset (create_permission_data);
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }
      CLOSE (CLIENT_CREATE_PERMISSION, COMMENT);
      CLOSE (CLIENT_CREATE_PERMISSION, COPY);
      CLOSE (CLIENT_CREATE_PERMISSION, NAME);
      CLOSE (CLIENT_CREATE_PERMISSION, RESOURCE);
      CLOSE (CLIENT_CREATE_PERMISSION_RESOURCE, TYPE);
      CLOSE (CLIENT_CREATE_PERMISSION, SUBJECT);
      CLOSE (CLIENT_CREATE_PERMISSION_SUBJECT, TYPE);

      case CLIENT_CREATE_PORT_LIST:
        if (create_port_list_element_end (gmp_parser, error, element_name))
          set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_CREATE_PORT_RANGE:
        {
          port_range_t new_port_range;

          if (create_port_range_data->start == NULL
              || create_port_range_data->end == NULL
              || create_port_range_data->port_list_id == NULL)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_port_range",
                                "A START, END and"
                                " PORT_LIST ID are required"));
          else switch (create_port_range
                        (create_port_range_data->port_list_id,
                         create_port_range_data->type,
                         create_port_range_data->start,
                         create_port_range_data->end,
                         create_port_range_data->comment,
                         &new_port_range))
            {
              case 1:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_port_range",
                                    "Port range START must be a number"
                                    " 1-65535"));
                log_event_fail ("port_range", "Port Range", NULL, "created");
                break;
              case 2:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_port_range",
                                    "Port range END must be a number"
                                    " 1-65535"));
                log_event_fail ("port_range", "Port Range", NULL, "created");
                break;
              case 3:
                if (send_find_error_to_client
                     ("create_port_range", "port_range",
                      create_port_range_data->port_list_id, gmp_parser))
                  {
                    error_send_to_client (error);
                    return;
                  }
                log_event_fail ("port_range", "Port Range", NULL, "created");
                break;
              case 4:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_port_range",
                                    "Port range TYPE must be TCP or UDP"));
                log_event_fail ("port_range", "Port Range", NULL, "created");
                break;
              case 5:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_port_range",
                                    "Port list is in use"));
                break;
              case 6:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_port_range",
                                    "New range overlaps an existing"
                                    " range"));
                break;
              case 99:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_port_range",
                                    "Permission denied"));
                break;
              case -1:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_INTERNAL_ERROR ("create_port_range"));
                log_event_fail ("port_range", "Port Range", NULL, "created");
                break;
              default:
                {
                  char *uuid;
                  uuid = port_range_uuid (new_port_range);
                  SENDF_TO_CLIENT_OR_FAIL
                   (XML_OK_CREATED_ID ("create_port_range"), uuid);
                  log_event ("port_range", "Port range", uuid, "created");
                  free (uuid);
                  break;
                }
            }

          create_port_range_data_reset (create_port_range_data);
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }
      CLOSE (CLIENT_CREATE_PORT_RANGE, COMMENT);
      CLOSE (CLIENT_CREATE_PORT_RANGE, END);
      CLOSE (CLIENT_CREATE_PORT_RANGE, START);
      CLOSE (CLIENT_CREATE_PORT_RANGE, TYPE);
      CLOSE (CLIENT_CREATE_PORT_RANGE, PORT_LIST);

      case CLIENT_CREATE_REPORT:
        {
          char *uuid;

          array_terminate (create_report_data->results);
          array_terminate (create_report_data->host_ends);
          array_terminate (create_report_data->host_starts);
          array_terminate (create_report_data->details);

          if (create_report_data->results == NULL)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_report",
                                "A REPORT element is required"));
          else if (create_report_data->type
                   && strcmp (create_report_data->type, "scan"))
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_report",
                                "Type must be 'scan'"));
          else switch (create_report
                        (create_report_data->results,
                         create_report_data->task_id,
                         create_report_data->in_assets,
                         create_report_data->scan_start,
                         create_report_data->scan_end,
                         create_report_data->host_starts,
                         create_report_data->host_ends,
                         create_report_data->details,
                         &uuid))
            {
              case 99:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_report",
                                    "Permission denied"));
                log_event_fail ("report", "Report", NULL, "created");
                break;
              case -1:
              case -2:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_INTERNAL_ERROR ("create_report"));
                log_event_fail ("report", "Report", NULL, "created");
                break;
              case -3:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_report",
                                    "A TASK id attribute is required"));
                log_event_fail ("report", "Report", NULL, "created");
                break;
              case -4:
                log_event_fail ("report", "Report", NULL, "created");
                if (send_find_error_to_client
                     ("create_report", "task",
                      create_report_data->task_id, gmp_parser))
                  {
                    error_send_to_client (error);
                    return;
                  }
                break;
              case -5:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_report",
                                    "TASK must be a container"));
                log_event_fail ("report", "Report", NULL, "created");
                break;
              case -6:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_report",
                                    "Permission to add to Assets denied"));
                log_event_fail ("report", "Report", NULL, "created");
                break;
              default:
                {
                  SENDF_TO_CLIENT_OR_FAIL
                   (XML_OK_CREATED_ID ("create_report"),
                    uuid);
                  log_event ("report", "Report", uuid, "created");
                  free (uuid);
                  break;
                }
            }

          create_report_data_reset (create_report_data);
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }
      CLOSE (CLIENT_CREATE_REPORT, IN_ASSETS);
      CLOSE (CLIENT_CREATE_REPORT, REPORT);
      case CLIENT_CREATE_REPORT_RR:
        if (create_report_data->wrapper)
          set_client_state (CLIENT_CREATE_REPORT_REPORT);
        else
          set_client_state (CLIENT_CREATE_REPORT);
        break;

      CLOSE (CLIENT_CREATE_REPORT_RR, ERRORS);
      case CLIENT_CREATE_REPORT_RR_ERRORS_ERROR:
        {
          if (create_report_data->result_severity == NULL)
            {
              create_report_data->result_severity = strdup ("-3.0");
            }
          if (create_report_data->result_threat == NULL)
            {
              create_report_data->result_threat = strdup ("Error");
            }
          gmp_xml_handle_result();
          set_client_state (CLIENT_CREATE_REPORT_RR_ERRORS);
          break;
        }
      CLOSE (CLIENT_CREATE_REPORT_RR_ERRORS_ERROR, DESCRIPTION);
      CLOSE (CLIENT_CREATE_REPORT_RR_ERRORS_ERROR, HOST);
      CLOSE (CLIENT_CREATE_REPORT_RR_ERRORS_ERROR_HOST, ASSET);
      CLOSE (CLIENT_CREATE_REPORT_RR_ERRORS_ERROR_HOST, HOSTNAME);
      CLOSE (CLIENT_CREATE_REPORT_RR_ERRORS_ERROR, NVT);
      CLOSE (CLIENT_CREATE_REPORT_RR_ERRORS_ERROR, PORT);
      CLOSE (CLIENT_CREATE_REPORT_RR_ERRORS_ERROR, SCAN_NVT_VERSION);
      CLOSE (CLIENT_CREATE_REPORT_RR_ERRORS_ERROR, SEVERITY);

      CLOSE (CLIENT_CREATE_REPORT_RR_ERRORS_ERROR_NVT, CVSS_BASE);
      CLOSE (CLIENT_CREATE_REPORT_RR_ERRORS_ERROR_NVT, NAME);

      case CLIENT_CREATE_REPORT_RR_HOST_END:
        if (create_report_data->host_end_host)
          {
            create_report_result_t *result;

            assert (create_report_data->host_ends);
            assert (create_report_data->host_end_host);

            result = g_malloc (sizeof (create_report_result_t));
            result->description = create_report_data->host_end;
            result->host = create_report_data->host_end_host;

            array_add (create_report_data->host_ends, result);

            create_report_data->host_end = NULL;
            create_report_data->host_end_host = NULL;
          }
        else
          gvm_free_string_var (&create_report_data->host_end);

        set_client_state (CLIENT_CREATE_REPORT_RR);
        break;
      case CLIENT_CREATE_REPORT_RR_HOST_START:
        if (create_report_data->host_start_host)
          {
            create_report_result_t *result;

            assert (create_report_data->host_starts);
            assert (create_report_data->host_start);
            assert (create_report_data->host_start_host);

            result = g_malloc (sizeof (create_report_result_t));
            result->description = create_report_data->host_start;
            result->host = create_report_data->host_start_host;

            array_add (create_report_data->host_starts, result);

            create_report_data->host_start = NULL;
            create_report_data->host_start_host = NULL;
          }
        else
          gvm_free_string_var (&create_report_data->host_start);

        set_client_state (CLIENT_CREATE_REPORT_RR);
        break;
      CLOSE (CLIENT_CREATE_REPORT_RR, RESULTS);
      CLOSE (CLIENT_CREATE_REPORT_RR, SCAN_END);
      CLOSE (CLIENT_CREATE_REPORT_RR, SCAN_START);

      CLOSE (CLIENT_CREATE_REPORT_RR_HOST_END, HOST);
      CLOSE (CLIENT_CREATE_REPORT_RR_HOST_START, HOST);

      case CLIENT_CREATE_REPORT_RR_H:
        {
          if (create_report_data->host_start)
            {
              create_report_result_t *result;

              result = g_malloc (sizeof (create_report_result_t));
              result->description = create_report_data->host_start;
              result->host = strdup (create_report_data->ip);

              array_add (create_report_data->host_starts, result);

              create_report_data->host_start = NULL;
            }

          if (create_report_data->host_end)
            {
              create_report_result_t *result;

              result = g_malloc (sizeof (create_report_result_t));
              result->description = create_report_data->host_end;
              result->host = strdup (create_report_data->ip);

              array_add (create_report_data->host_ends, result);

              create_report_data->host_end = NULL;
            }

          gvm_free_string_var (&create_report_data->ip);
          set_client_state (CLIENT_CREATE_REPORT_RR);
          break;
        }

      CLOSE (CLIENT_CREATE_REPORT_RR_H, IP);
      CLOSE (CLIENT_CREATE_REPORT_RR_H, START);
      CLOSE (CLIENT_CREATE_REPORT_RR_H, END);

      case CLIENT_CREATE_REPORT_RR_H_DETAIL:
        {
          assert (create_report_data->details);

          if (create_report_data->ip)
            {
              host_detail_t *detail;

              detail = g_malloc (sizeof (host_detail_t));
              detail->ip = g_strdup (create_report_data->ip);
              detail->name = create_report_data->detail_name;
              detail->source_desc = create_report_data->detail_source_desc;
              detail->source_name = create_report_data->detail_source_name;
              detail->source_type = create_report_data->detail_source_type;
              detail->value = create_report_data->detail_value;

              array_add (create_report_data->details, detail);

              create_report_data->detail_name = NULL;
              create_report_data->detail_source_desc = NULL;
              create_report_data->detail_source_name = NULL;
              create_report_data->detail_source_type = NULL;
              create_report_data->detail_value = NULL;
            }

          set_client_state (CLIENT_CREATE_REPORT_RR_H);
          break;
        }

      CLOSE (CLIENT_CREATE_REPORT_RR_H_DETAIL, NAME);
      CLOSE (CLIENT_CREATE_REPORT_RR_H_DETAIL, VALUE);
      CLOSE (CLIENT_CREATE_REPORT_RR_H_DETAIL, SOURCE);

      CLOSE (CLIENT_CREATE_REPORT_RR_H_DETAIL_SOURCE, TYPE);
      CLOSE (CLIENT_CREATE_REPORT_RR_H_DETAIL_SOURCE, NAME);
      case CLIENT_CREATE_REPORT_RR_H_DETAIL_SOURCE_DESC:
        set_client_state (CLIENT_CREATE_REPORT_RR_H_DETAIL_SOURCE);
        break;

      case CLIENT_CREATE_REPORT_RR_RESULTS_RESULT:
        {
          gmp_xml_handle_result();
          set_client_state (CLIENT_CREATE_REPORT_RR_RESULTS);
          break;
        }
      CLOSE (CLIENT_CREATE_REPORT_RR_RESULTS_RESULT, DESCRIPTION);
      CLOSE (CLIENT_CREATE_REPORT_RR_RESULTS_RESULT, DETECTION);
      CLOSE (CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_DETECTION, RESULT);
      CLOSE (CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_DETECTION_RESULT, DETAILS);
      CLOSE (CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_DETECTION_RESULT_DETAILS, DETAIL);
      CLOSE (CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_DETECTION_RESULT_DETAILS_DETAIL, NAME);
      CLOSE (CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_DETECTION_RESULT_DETAILS_DETAIL, VALUE);

      CLOSE (CLIENT_CREATE_REPORT_RR_RESULTS_RESULT, HOST);
      CLOSE (CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_HOST, ASSET);
      CLOSE (CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_HOST, HOSTNAME);
      CLOSE (CLIENT_CREATE_REPORT_RR_RESULTS_RESULT, NVT);
      CLOSE (CLIENT_CREATE_REPORT_RR_RESULTS_RESULT, ORIGINAL_SEVERITY);
      CLOSE (CLIENT_CREATE_REPORT_RR_RESULTS_RESULT, ORIGINAL_THREAT);
      CLOSE (CLIENT_CREATE_REPORT_RR_RESULTS_RESULT, PORT);
      CLOSE (CLIENT_CREATE_REPORT_RR_RESULTS_RESULT, QOD);
      CLOSE (CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_QOD, TYPE);
      CLOSE (CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_QOD, VALUE);
      CLOSE (CLIENT_CREATE_REPORT_RR_RESULTS_RESULT, SCAN_NVT_VERSION);
      CLOSE (CLIENT_CREATE_REPORT_RR_RESULTS_RESULT, SEVERITY);
      CLOSE (CLIENT_CREATE_REPORT_RR_RESULTS_RESULT, THREAT);

      CLOSE (CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_NVT, BID);
      CLOSE (CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_NVT, CVE);
      CLOSE (CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_NVT, CVSS_BASE);
      CLOSE (CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_NVT, FAMILY);
      CLOSE (CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_NVT, NAME);
      CLOSE (CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_NVT, XREF);
      CLOSE (CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_NVT, CERT);

      CLOSE (CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_NVT_CERT, CERT_REF);

      CLOSE (CLIENT_CREATE_REPORT, TASK);
      CLOSE (CLIENT_CREATE_REPORT_TASK, COMMENT);
      CLOSE (CLIENT_CREATE_REPORT_TASK, NAME);

      case CLIENT_CREATE_REPORT_FORMAT:
        if (create_report_format_element_end (gmp_parser, error, element_name))
          set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_CREATE_ROLE:
        {
          role_t new_role;

          assert (create_role_data->users != NULL);

          if (create_role_data->copy)
            switch (copy_role (create_role_data->name,
                                create_role_data->comment,
                                create_role_data->copy,
                                &new_role))
              {
                case 0:
                  {
                    char *uuid;
                    uuid = role_uuid (new_role);
                    SENDF_TO_CLIENT_OR_FAIL (XML_OK_CREATED_ID ("create_role"),
                                             uuid);
                    log_event ("role", "Role", uuid, "created");
                    free (uuid);
                    break;
                  }
                case 1:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("create_role",
                                      "Role exists already"));
                  log_event_fail ("role", "Role", NULL, "created");
                  break;
                case 2:
                  if (send_find_error_to_client ("create_role", "role",
                                                 create_role_data->copy,
                                                 gmp_parser))
                    {
                      error_send_to_client (error);
                      return;
                    }
                  log_event_fail ("role", "Role", NULL, "created");
                  break;
                case 4:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("create_role",
                                      "Syntax error in role name"));
                  log_event_fail ("role", "Role", NULL, "created");
                  break;
                case 99:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("create_role",
                                      "Permission denied"));
                  log_event_fail ("role", "Role", NULL, "created");
                  break;
                case -1:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_INTERNAL_ERROR ("create_role"));
                  log_event_fail ("role", "Role", NULL, "created");
                  break;
              }
          else if (create_role_data->name == NULL)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_role",
                                "A NAME is required"));
          else if (strlen (create_role_data->name) == 0)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_role",
                                "Name must be at"
                                " least one character long"));
          else switch (create_role
                        (create_role_data->name,
                         create_role_data->comment,
                         create_role_data->users,
                         &new_role))
            {
              case 0:
                {
                  char *uuid = role_uuid (new_role);
                  SENDF_TO_CLIENT_OR_FAIL (XML_OK_CREATED_ID ("create_role"),
                                           uuid);
                  log_event ("role", "Role", NULL, "created");
                  free (uuid);
                  break;
                }
              case 1:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_role",
                                    "Role exists already"));
                log_event_fail ("role", "Role", NULL, "created");
                break;
              case 2:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_role",
                                    "Failed to find user"));
                log_event_fail ("role", "Role", NULL, "created");
                break;
              case 4:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_role",
                                    "Error in user name"));
                log_event_fail ("group", "Group", NULL, "created");
                break;
              case 99:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_role",
                                    "Permission denied"));
                log_event_fail ("role", "Role", NULL, "created");
                break;
              default:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_INTERNAL_ERROR ("create_role"));
                log_event_fail ("role", "Role", NULL, "created");
                break;
            }

          create_role_data_reset (create_role_data);
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }
      CLOSE (CLIENT_CREATE_ROLE, COMMENT);
      CLOSE (CLIENT_CREATE_ROLE, COPY);
      CLOSE (CLIENT_CREATE_ROLE, NAME);
      CLOSE (CLIENT_CREATE_ROLE, USERS);

      case CLIENT_CREATE_SCANNER:
        handle_create_scanner (gmp_parser, error);
        break;
      CLOSE (CLIENT_CREATE_SCANNER, COMMENT);
      CLOSE (CLIENT_CREATE_SCANNER, COPY);
      CLOSE (CLIENT_CREATE_SCANNER, NAME);
      CLOSE (CLIENT_CREATE_SCANNER, HOST);
      CLOSE (CLIENT_CREATE_SCANNER, PORT);
      CLOSE (CLIENT_CREATE_SCANNER, TYPE);
      CLOSE (CLIENT_CREATE_SCANNER, CA_PUB);
      CLOSE (CLIENT_CREATE_SCANNER, CREDENTIAL);

      case CLIENT_CREATE_SCHEDULE:
        {
          handle_create_schedule (gmp_parser, error);
          break;
        }
      CLOSE (CLIENT_CREATE_SCHEDULE, COMMENT);
      CLOSE (CLIENT_CREATE_SCHEDULE, COPY);
      CLOSE (CLIENT_CREATE_SCHEDULE, ICALENDAR);
      CLOSE (CLIENT_CREATE_SCHEDULE, NAME);
      CLOSE (CLIENT_CREATE_SCHEDULE, TIMEZONE);

      case CLIENT_CREATE_TAG:
        {
          tag_t new_tag;

          if (create_tag_data->resource_ids)
            array_terminate (create_tag_data->resource_ids);

          if (create_tag_data->copy)
            switch (copy_tag (create_tag_data->name,
                              create_tag_data->comment,
                              create_tag_data->copy,
                              &new_tag))
              {
                case 0:
                  {
                    char *uuid;
                    uuid = tag_uuid (new_tag);
                    SENDF_TO_CLIENT_OR_FAIL (XML_OK_CREATED_ID ("create_tag"),
                                             uuid);
                    log_event ("tag", "Tag", uuid, "created");
                    free (uuid);
                    break;
                  }
                case 1:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("create_tag",
                                      "Tag exists already"));
                  log_event_fail ("tag", "Tag", NULL, "created");
                  break;
                case 2:
                  if (send_find_error_to_client ("create_tag", "tag",
                                                 create_tag_data->copy,
                                                 gmp_parser))
                    {
                      error_send_to_client (error);
                      return;
                    }
                  log_event_fail ("tag", "Tag", NULL, "created");
                  break;
                case 99:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("create_tag",
                                      "Permission denied"));
                  log_event_fail ("tag", "Tag", NULL, "created");
                  break;
                case -1:
                default:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_INTERNAL_ERROR ("create_tag"));
                  log_event_fail ("tag", "Tag", NULL, "created");
                  break;
              }
          else if (create_tag_data->name == NULL)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_tag",
                                "A NAME element is required"));
          else if (strlen (create_tag_data->name) == 0)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_tag",
                                "Name must be"
                                " at least one character long"));
          else if (create_tag_data->resource_ids == NULL)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_tag",
                                "A RESOURCES element with TYPE element"
                                " is required"));
          else if (create_tag_data->resource_type == NULL)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_tag",
                                "RESOURCES requires"
                                " a TYPE element"));
          else if (valid_db_resource_type (create_tag_data->resource_type)
                     == 0)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_tag",
                                "TYPE in RESOURCES must be"
                                " a valid resource type."));
          else if (strcasecmp (create_tag_data->resource_type, "tag") == 0)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_tag",
                                "TYPE in RESOURCES must not"
                                " be 'tag'."));
          else
            {
              gchar *error_extra = NULL;
              switch (create_tag (create_tag_data->name,
                                  create_tag_data->comment,
                                  create_tag_data->value,
                                  create_tag_data->resource_type,
                                  create_tag_data->resource_ids,
                                  create_tag_data->resources_filter,
                                  create_tag_data->active,
                                  &new_tag, &error_extra))
                {
                  case 0:
                    {
                      char *uuid;
                      uuid = tag_uuid (new_tag);
                      SENDF_TO_CLIENT_OR_FAIL (XML_OK_CREATED_ID ("create_tag"),
                                               uuid);
                      log_event ("tag", "Tag", uuid, "created");
                      free (uuid);
                      break;
                    }
                  case 1:
                    if (send_find_error_to_client ("create_tag", "resource",
                                                   error_extra,
                                                   gmp_parser))
                      {
                        error_send_to_client (error);
                        g_free (error_extra);
                        return;
                      }
                    g_free (error_extra);
                    log_event_fail ("tag", "Tag", NULL, "created");
                    break;
                  case 2:
                    SEND_TO_CLIENT_OR_FAIL 
                      ("<create_tag_response"
                       " status=\"" STATUS_ERROR_MISSING "\""
                       " status_text=\"No resources found for filter\"/>");
                    log_event_fail ("tag", "Tag", NULL, "created");
                    break;
                  case 3:
                    SEND_TO_CLIENT_OR_FAIL
                     (XML_ERROR_SYNTAX ("create_tag",
                                        "Too many resources selected"));
                    log_event_fail ("tag", "Tag", NULL, "created");
                    break;
                  case 99:
                    SEND_TO_CLIENT_OR_FAIL
                     (XML_ERROR_SYNTAX ("create_tag",
                                        "Permission denied"));
                    log_event_fail ("tag", "Tag", NULL, "created");
                    break;
                  case -1:
                    SEND_TO_CLIENT_OR_FAIL
                     (XML_INTERNAL_ERROR ("create_tag"));
                    log_event_fail ("tag", "Tag", NULL, "created");
                    break;
                }
            }
          g_debug ("trying reset");
          create_tag_data_reset (create_tag_data);
          g_debug ("trying set client state");
          set_client_state (CLIENT_AUTHENTIC);

          break;
        }

      CLOSE (CLIENT_CREATE_TAG, ACTIVE);
      CLOSE (CLIENT_CREATE_TAG, RESOURCES);
      CLOSE (CLIENT_CREATE_TAG, COPY);
      CLOSE (CLIENT_CREATE_TAG, COMMENT);
      CLOSE (CLIENT_CREATE_TAG, NAME);
      CLOSE (CLIENT_CREATE_TAG, VALUE);

      CLOSE (CLIENT_CREATE_TAG_RESOURCES, TYPE);
      CLOSE (CLIENT_CREATE_TAG_RESOURCES, RESOURCE);

      case CLIENT_CREATE_TARGET:
        {
          credential_t ssh_credential = 0, ssh_elevate_credential = 0;
          credential_t smb_credential = 0;
          credential_t esxi_credential = 0, snmp_credential = 0;
          target_t new_target;

          if (create_target_data->copy)
            switch (copy_target (create_target_data->name,
                                 create_target_data->comment,
                                 create_target_data->copy,
                                 &new_target))
              {
                case 0:
                  {
                    char *uuid;
                    uuid = target_uuid (new_target);
                    SENDF_TO_CLIENT_OR_FAIL (XML_OK_CREATED_ID ("create_target"),
                                             uuid);
                    log_event ("target", "Target", uuid, "created");
                    free (uuid);
                    break;
                  }
                case 1:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("create_target",
                                      "Target exists already"));
                  log_event_fail ("target", "Target", NULL, "created");
                  break;
                case 2:
                  if (send_find_error_to_client ("create_target", "target",
                                                 create_target_data->copy,
                                                 gmp_parser))
                    {
                      error_send_to_client (error);
                      return;
                    }
                  log_event_fail ("target", "Target", NULL, "created");
                  break;
                case 99:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("create_target",
                                      "Permission denied"));
                  log_event_fail ("target", "Target", NULL, "created");
                  break;
                case -1:
                default:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_INTERNAL_ERROR ("create_target"));
                  log_event_fail ("target", "Target", NULL, "created");
                  break;
              }
          else if (create_target_data->name == NULL)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_target",
                                "A NAME is required"));
          else if (strlen (create_target_data->name) == 0)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_target",
                                "Name must be at"
                                " least one character long"));
          else if (create_target_data->asset_hosts_filter == NULL
                   && create_target_data->hosts == NULL)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_target",
                                "A host is required"));
          else if (create_target_data->asset_hosts_filter == NULL
                   && strlen (create_target_data->hosts) == 0)
            /** @todo Legitimate to pass an empty hosts element? */
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_target",
                                "Hosts must be at least one"
                                " character long"));
          else if (create_target_data->ssh_credential_id
                   && find_credential_with_permission
                       (create_target_data->ssh_credential_id,
                        &ssh_credential,
                        "get_credentials"))
            SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("create_target"));
          else if (create_target_data->ssh_credential_id == NULL
                   && create_target_data->ssh_lsc_credential_id
                   && find_credential_with_permission
                       (create_target_data->ssh_lsc_credential_id,
                        &ssh_credential,
                        "get_credentials"))
            SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("create_target"));
          else if ((create_target_data->ssh_credential_id
                    || create_target_data->ssh_lsc_credential_id)
                   && ssh_credential == 0)
            {
              if (send_find_error_to_client
                   ("create_target", "Credential",
                    create_target_data->ssh_credential_id
                      ? create_target_data->ssh_credential_id
                      : create_target_data->ssh_lsc_credential_id,
                    gmp_parser))
                {
                  error_send_to_client (error);
                  return;
                }
            }
          else if (create_target_data->ssh_elevate_credential_id
                   && find_credential_with_permission
                       (create_target_data->ssh_elevate_credential_id,
                        &ssh_elevate_credential,
                        "get_credentials"))
            SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("create_target"));
          else if (create_target_data->smb_credential_id
                   && find_credential_with_permission
                       (create_target_data->smb_credential_id,
                        &smb_credential,
                        "get_credentials"))
            SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("create_target"));
          else if (create_target_data->smb_credential_id == NULL
                   && create_target_data->smb_lsc_credential_id
                   && find_credential_with_permission
                       (create_target_data->smb_lsc_credential_id,
                        &smb_credential,
                        "get_credentials"))
            SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("create_target"));
          else if ((create_target_data->smb_credential_id
                    || create_target_data->smb_lsc_credential_id)
                   && smb_credential == 0)
            {
              if (send_find_error_to_client
                   ("create_target", "Credential",
                    create_target_data->smb_credential_id
                      ? create_target_data->smb_credential_id
                      : create_target_data->smb_lsc_credential_id,
                    gmp_parser))
                {
                  error_send_to_client (error);
                  return;
                }
            }
          else if (create_target_data->esxi_credential_id
                   && find_credential_with_permission
                       (create_target_data->esxi_credential_id,
                        &esxi_credential,
                        "get_credentials"))
            SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("create_target"));
          else if (create_target_data->esxi_credential_id == NULL
                   && create_target_data->esxi_lsc_credential_id
                   && find_credential_with_permission
                       (create_target_data->esxi_lsc_credential_id,
                        &esxi_credential,
                        "get_credentials"))
            SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("create_target"));
          else if ((create_target_data->esxi_credential_id
                    || create_target_data->esxi_lsc_credential_id)
                   && esxi_credential == 0)
            {
              if (send_find_error_to_client
                   ("create_target", "Credential",
                    create_target_data->esxi_credential_id
                      ? create_target_data->esxi_credential_id
                      : create_target_data->esxi_lsc_credential_id,
                    gmp_parser))
                {
                  error_send_to_client (error);
                  return;
                }
            }
          else if (create_target_data->snmp_credential_id
                   && find_credential_with_permission
                       (create_target_data->snmp_credential_id,
                        &snmp_credential,
                        "get_credentials"))
            SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("create_target"));
          else if (create_target_data->snmp_credential_id
                   && snmp_credential == 0)
            {
              if (send_find_error_to_client
                   ("create_target", "Credential",
                    create_target_data->snmp_credential_id,
                    gmp_parser))
                {
                  error_send_to_client (error);
                  return;
                }
            }
          /* Create target from host string. */
          else switch (create_target
                        (create_target_data->name,
                         create_target_data->asset_hosts_filter,
                         create_target_data->hosts,
                         create_target_data->exclude_hosts,
                         create_target_data->comment,
                         create_target_data->port_list_id,
                         create_target_data->port_range,
                         ssh_credential,
			 ssh_elevate_credential,
                         create_target_data->ssh_credential_id
                          ? create_target_data->ssh_port
                          : create_target_data->ssh_lsc_port,
                         smb_credential,
                         esxi_credential,
                         snmp_credential,
                         create_target_data->reverse_lookup_only,
                         create_target_data->reverse_lookup_unify,
                         create_target_data->alive_tests,
                         create_target_data->allow_simultaneous_ips,
                         &new_target))
            {
              case 1:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_target",
                                    "Target exists already"));
                log_event_fail ("target", "Target", NULL, "created");
                break;
              case 2:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_target",
                                    "Error in host specification"));
                log_event_fail ("target", "Target", NULL, "created");
                break;
              case 3:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_target",
                                    "Host specification exceeds maximum number"
                                    " of hosts"));
                log_event_fail ("target", "Target", NULL, "created");
                break;
              case 4:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_target",
                                    "Error in port range"));
                log_event_fail ("target", "Target", NULL, "created");
                break;
              case 5:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_target",
                                    "Error in SSH port"));
                log_event_fail ("target", "Target", NULL, "created");
                break;
              case 6:
                log_event_fail ("target", "Target", NULL, "created");
                if (send_find_error_to_client
                     ("create_target", "port_list",
                      create_target_data->port_list_id, gmp_parser))
                  {
                    error_send_to_client (error);
                    return;
                  }
                break;
              case 7:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_target",
                                    "Error in alive test"));
                log_event_fail ("target", "Target", NULL, "created");
                break;
              case 8:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_target",
                                    "SSH credential must be of type"
                                    " 'up' or 'usk'"));
                log_event_fail ("target", "Target", NULL, "created");
                break;
              case 9:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_target",
                                    "ELEVATE credential must be of type"
                                    " 'up'"));
                log_event_fail ("target", "Target", NULL, "created");
                break;
              case 10:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_target",
                                    "SMB credential must be of type"
                                    " 'up'"));
                log_event_fail ("target", "Target", NULL, "created");
                break;
              case 11:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_target",
                                    "ESXi credential must be of type"
                                    " 'up'"));
                log_event_fail ("target", "Target", NULL, "created");
                break;
              case 12:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_target",
                                    "SNMP credential must be of type"
                                    " 'snmp'"));
                log_event_fail ("target", "Target", NULL, "created");
                break;
              case 13:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_target",
                                    "One of PORT_LIST and PORT_RANGE are"
                                    " required"));
                log_event_fail ("target", "Target", NULL, "created");
                break;
              case 14:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_target",
                                    "The elevate credential requires"
                                    " an SSH credential"));
                log_event_fail ("target", "Target", NULL, "created");
                break;
              case 15:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_target",
                                    "The elevate credential must be"
                                    " different from the SSH credential"));
                log_event_fail ("target", "Target", NULL, "created");
                break;
              case 99:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_target",
                                    "Permission denied"));
                log_event_fail ("target", "Target", NULL, "created");
                break;
              case -1:
                SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("create_target"));
                log_event_fail ("target", "Target", NULL, "created");
                break;
              default:
                {
                  char *uuid = target_uuid (new_target);
                  SENDF_TO_CLIENT_OR_FAIL (XML_OK_CREATED_ID ("create_target"),
                                           uuid);
                  log_event ("target", "Target", uuid, "created");
                  free (uuid);
                  break;
                }
            }

          create_target_data_reset (create_target_data);
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }
      CLOSE (CLIENT_CREATE_TARGET, ASSET_HOSTS);
      CLOSE (CLIENT_CREATE_TARGET, COMMENT);
      CLOSE (CLIENT_CREATE_TARGET, ESXI_CREDENTIAL);
      CLOSE (CLIENT_CREATE_TARGET, ESXI_LSC_CREDENTIAL);
      CLOSE (CLIENT_CREATE_TARGET, EXCLUDE_HOSTS);
      CLOSE (CLIENT_CREATE_TARGET, REVERSE_LOOKUP_ONLY);
      CLOSE (CLIENT_CREATE_TARGET, REVERSE_LOOKUP_UNIFY);
      CLOSE (CLIENT_CREATE_TARGET, ALIVE_TESTS);
      CLOSE (CLIENT_CREATE_TARGET, ALLOW_SIMULTANEOUS_IPS);
      CLOSE (CLIENT_CREATE_TARGET, COPY);
      CLOSE (CLIENT_CREATE_TARGET, HOSTS);
      CLOSE (CLIENT_CREATE_TARGET, NAME);
      CLOSE (CLIENT_CREATE_TARGET, PORT_LIST);
      CLOSE (CLIENT_CREATE_TARGET, PORT_RANGE);
      CLOSE (CLIENT_CREATE_TARGET, SSH_CREDENTIAL);
      CLOSE (CLIENT_CREATE_TARGET, SSH_LSC_CREDENTIAL);
      CLOSE (CLIENT_CREATE_TARGET, SSH_ELEVATE_CREDENTIAL);
      CLOSE (CLIENT_CREATE_TARGET, SMB_CREDENTIAL);
      CLOSE (CLIENT_CREATE_TARGET, SMB_LSC_CREDENTIAL);
      CLOSE (CLIENT_CREATE_TARGET, SNMP_CREDENTIAL);

      CLOSE (CLIENT_CREATE_TARGET_SSH_CREDENTIAL, PORT);

      CLOSE (CLIENT_CREATE_TARGET_SSH_LSC_CREDENTIAL, PORT);

      case CLIENT_CREATE_TASK:
        {
          config_t config = 0;
          target_t target = 0;
          scanner_t scanner = 0;
          char *tsk_uuid = NULL;
          guint index;

          /* @todo Buffer the entire task creation and pass everything to a
           *       libmanage function, so that libmanage can do the locking
           *       properly instead of exposing the task_t.  Probably easier
           *       after removing the option to create a task from an RC
           *       file. */

          assert (create_task_data->task != (task_t) 0);

          /* The task already exists in the database at this point, so on
           * failure be sure to call request_delete_task to remove the
           * task. */
          /** @todo Any fail cases of the CLIENT_CREATE_TASK_* states must do
           *        so too. */

          if (create_task_data->copy)
            {
              int ret;
              gchar *name, *comment;
              task_t new_task;
              int alterable;

              name = task_name (create_task_data->task);
              comment = task_comment (create_task_data->task);

              if(create_task_data->alterable)
                alterable = strcmp (create_task_data->alterable, "0") ? 1 : 0;
              else
                alterable = -1;

              ret = copy_task (name,
                               comment,
                               create_task_data->copy,
                               alterable,
                               &new_task);

              g_free (name);
              g_free (comment);
              /* Remove the task that was created while parsing elements. */
              request_delete_task (&create_task_data->task);
              switch (ret)
                {
                  case 0:
                    {
                      char *uuid;
                      task_uuid (new_task, &uuid);
                      SENDF_TO_CLIENT_OR_FAIL (XML_OK_CREATED_ID ("create_task"),
                                               uuid);
                      log_event ("task", "Task", uuid, "created");
                      free (uuid);
                      break;
                    }
                  case 1:
                    SEND_TO_CLIENT_OR_FAIL
                     (XML_ERROR_SYNTAX ("create_task",
                                        "Task exists already"));
                    log_event_fail ("task", "Task", NULL, "created");
                    break;
                  case 2:
                    if (send_find_error_to_client ("create_task", "task",
                                                   create_task_data->copy,
                                                   gmp_parser))
                      {
                        error_send_to_client (error);
                        return;
                      }
                    log_event_fail ("task", "Task", NULL, "created");
                    break;
                  case 99:
                    SEND_TO_CLIENT_OR_FAIL
                     (XML_ERROR_SYNTAX ("create_task",
                                        "Permission denied"));
                    log_event_fail ("task", "Task", NULL, "created");
                    break;
                  case -1:
                    SEND_TO_CLIENT_OR_FAIL
                     (XML_INTERNAL_ERROR ("create_task"));
                    log_event_fail ("task", "Task", NULL, "created");
                    break;
                }
              create_task_data_reset (create_task_data);
              set_client_state (CLIENT_AUTHENTIC);
              break;
            }

          if (create_task_data->scanner_id == NULL)
            create_task_data->scanner_id = g_strdup (scanner_uuid_default ());

          /* Check permissions. */

          if (acl_user_may ("create_task") == 0)
            {
              SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX ("create_task",
                                                        "Permission denied"));
              goto create_task_fail;
            }

          /* Check and set name. */

          if (create_task_data->name == NULL)
            {
              SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX ("create_task",
                                                        "A NAME is required"));
              goto create_task_fail;
            }
          else
            set_task_name (create_task_data->task, create_task_data->name);

          /* Get the task ID. */

          if (task_uuid (create_task_data->task, &tsk_uuid))
            {
              SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("create_task"));
              goto create_task_fail;
            }

          /* Check for the right combination of target and config. */

          if (create_task_data->target_id == NULL)
            {
              SEND_TO_CLIENT_OR_FAIL
               (XML_ERROR_SYNTAX ("create_task",
                                  "A target is required"));
              goto create_task_fail;
            }

          if (strcmp (create_task_data->target_id, "0") == 0)
            {
              /* Container task. */

              set_task_target (create_task_data->task, 0);
              set_task_usage_type (create_task_data->task,
                                   create_task_data->usage_type);
              SENDF_TO_CLIENT_OR_FAIL (XML_OK_CREATED_ID ("create_task"),
                                       tsk_uuid);
              make_task_complete (create_task_data->task);
              log_event ("task", "Task", tsk_uuid, "created");
              g_free (tsk_uuid);
              create_task_data_reset (create_task_data);
              set_client_state (CLIENT_AUTHENTIC);
              break;
            }

          if (create_task_data->config_id == NULL)
            {
              SEND_TO_CLIENT_OR_FAIL
               (XML_ERROR_SYNTAX ("create_task",
                                  "A config is required"));
              goto create_task_fail;
            }

          /* Set any alert. */

          assert (create_task_data->alerts);
          index = create_task_data->alerts->len;
          while (index--)
            {
              alert_t alert;
              gchar *alert_id;

              alert_id = (gchar*) g_ptr_array_index (create_task_data->alerts,
                                                     index);
              if (strcmp (alert_id, "0") == 0)
                continue;
              if (find_alert_with_permission (alert_id, &alert, "get_alerts"))
                {
                  SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("create_task"));
                  goto create_task_fail;
                }
              if (alert == 0)
                {
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("create_task",
                                      "Alert must exist"));
                  goto create_task_fail;
                }
              add_task_alert (create_task_data->task, alert);
            }

          /* Set alterable state. */

          if (create_task_data->alterable
              && strcmp (create_task_data->alterable, "0"))
            set_task_alterable (create_task_data->task, 1);

          /* Set any schedule. */

          if (create_task_data->schedule_id)
            {
              schedule_t schedule;
              int periods;

              periods = create_task_data->schedule_periods
                         ? atoi (create_task_data->schedule_periods)
                         : 0;
              if (find_schedule_with_permission (create_task_data->schedule_id,
                                                 &schedule,
                                                 "get_schedules"))
                {
                  SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("create_task"));
                  goto create_task_fail;
                }
              if (schedule == 0)
                {
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("create_task",
                                      "Schedule must exist"));
                  goto create_task_fail;
                }
              /** @todo
               *
               * This is a contention hole.  Some other process could remove
               * the schedule at this point.  The variable "schedule" would
               * still refer to the removed schedule.
               *
               * This happens all over the place.  Anywhere that a libmanage
               * client gets a reference to a resource, in fact.
               *
               * Possibly libmanage should lock the db whenever it hands out a
               * reference, and the client should call something to release
               * the lock when it's done.
               *
               * In many cases, like this one, the client could pass the UUID
               * directly to libmanage, instead of getting the reference.  In
               * this case the client would then need something like
               * set_task_schedule_uuid.
               */
              set_task_schedule (create_task_data->task, schedule, periods);
            }
          else if (create_task_data->schedule_periods
                   && strlen (create_task_data->schedule_periods))
            set_task_schedule_periods_id
             (create_task_data->task,
              atoi (create_task_data->schedule_periods));

          /* Set any observers. */

          if (create_task_data->observers)
            {
              int fail;
              fail = set_task_observers (create_task_data->task,
                                         create_task_data->observers);
              switch (fail)
                {
                  case 0:
                    break;
                  case 1:
                  case 2:
                    SEND_TO_CLIENT_OR_FAIL
                      (XML_ERROR_SYNTAX ("create_task",
                                         "User name error in observers"));
                    goto create_task_fail;
                  case -1:
                  default:
                    SEND_TO_CLIENT_OR_FAIL
                      (XML_INTERNAL_ERROR ("create_task"));
                    goto create_task_fail;
                }
            }

          /* Set any observer groups. */

          if (create_task_data->groups->len)
            {
              gchar *fail_group_id;

              switch (set_task_groups (create_task_data->task,
                                               create_task_data->groups,
                                               &fail_group_id))
                {
                  case 0:
                    break;
                  case 1:
                    if (send_find_error_to_client
                         ("create_task", "group", fail_group_id, gmp_parser))
                      {
                        error_send_to_client (error);
                        return;
                      }
                    log_event_fail ("task", "Task", NULL, "created");
                    goto create_task_fail;
                  case -1:
                  default:
                    SEND_TO_CLIENT_OR_FAIL
                      (XML_INTERNAL_ERROR ("create_task"));
                    log_event_fail ("task", "Task", NULL, "created");
                    goto create_task_fail;
                }
            }

          if (find_scanner_with_permission (create_task_data->scanner_id,
                                            &scanner,
                                            "get_scanners"))
            {
              SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("create_task"));
              goto create_task_fail;
            }
          if (create_task_data->scanner_id && scanner == 0)
            {
              if (send_find_error_to_client ("create_task", "scanner",
                                             create_task_data->scanner_id,
                                             gmp_parser))
                error_send_to_client (error);
              goto create_task_fail;
            }
          if ((scanner == 0) || (scanner_type (scanner) != SCANNER_TYPE_CVE))
            {
              if (find_config_with_permission (create_task_data->config_id,
                                               &config,
                                               "get_configs"))
                {
                  SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("create_task"));
                  goto create_task_fail;
                }
              if (config == 0)
                {
                  if (send_find_error_to_client ("create_task", "config",
                                                 create_task_data->config_id,
                                                 gmp_parser))
                    error_send_to_client (error);
                  goto create_task_fail;
                }

              if (!create_task_check_scanner_type (scanner))
                {
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("create_task",
                                      "Scanner and config mismatched types."));
                  goto create_task_fail;
                }
            }
          if (find_target_with_permission (create_task_data->target_id,
                                           &target,
                                           "get_targets"))
            {
              SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("create_task"));
              goto create_task_fail;
            }
          if (target == 0)
            {
              if (send_find_error_to_client ("create_task", "target",
                                             create_task_data->target_id,
                                             gmp_parser))
                error_send_to_client (error);
              goto create_task_fail;
            }

          set_task_config (create_task_data->task, config);
          set_task_target (create_task_data->task, target);
          set_task_scanner (create_task_data->task, scanner);
          set_task_hosts_ordering (create_task_data->task,
                                   create_task_data->hosts_ordering);
          set_task_usage_type (create_task_data->task,
                               create_task_data->usage_type);
          if (create_task_data->preferences)
            switch (set_task_preferences (create_task_data->task,
                                          create_task_data->preferences))
              {
                case 0:
                  break;
                case 1:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("create_task",
                                      "Invalid auto_delete value"));
                  goto create_task_fail;
                case 2:
                  SENDF_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("create_task",
                                      "Auto Delete count out of range"
                                      " (must be from %d to %d)"),
                    AUTO_DELETE_KEEP_MIN, AUTO_DELETE_KEEP_MAX);
                  goto create_task_fail;
                default:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_INTERNAL_ERROR ("create_task"));
                  goto create_task_fail;
              }

          /* Send success response. */

          SENDF_TO_CLIENT_OR_FAIL (XML_OK_CREATED_ID ("create_task"),
                                   tsk_uuid);
          make_task_complete (create_task_data->task);
          log_event ("task", "Task", tsk_uuid, "created");
          g_free (tsk_uuid);
          create_task_data_reset (create_task_data);
          set_client_state (CLIENT_AUTHENTIC);
          break;

 create_task_fail:
          request_delete_task (&create_task_data->task);
          g_free (tsk_uuid);
          create_task_data_reset (create_task_data);
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }
      CLOSE (CLIENT_CREATE_TASK, ALTERABLE);
      CLOSE (CLIENT_CREATE_TASK, COMMENT);
      CLOSE (CLIENT_CREATE_TASK, HOSTS_ORDERING);
      CLOSE (CLIENT_CREATE_TASK, SCANNER);
      CLOSE (CLIENT_CREATE_TASK, CONFIG);
      CLOSE (CLIENT_CREATE_TASK, COPY);
      CLOSE (CLIENT_CREATE_TASK, ALERT);
      CLOSE (CLIENT_CREATE_TASK, NAME);
      CLOSE (CLIENT_CREATE_TASK, OBSERVERS);
      CLOSE (CLIENT_CREATE_TASK, PREFERENCES);
      CLOSE (CLIENT_CREATE_TASK, TARGET);
      CLOSE (CLIENT_CREATE_TASK, USAGE_TYPE);
      CLOSE (CLIENT_CREATE_TASK, SCHEDULE);
      CLOSE (CLIENT_CREATE_TASK, SCHEDULE_PERIODS);

      CLOSE (CLIENT_CREATE_TASK_OBSERVERS, GROUP);

      case CLIENT_CREATE_TASK_PREFERENCES_PREFERENCE:
        array_add (create_task_data->preferences,
                   create_task_data->preference);
        create_task_data->preference = NULL;
        set_client_state (CLIENT_CREATE_TASK_PREFERENCES);
        break;
      case CLIENT_CREATE_TASK_PREFERENCES_PREFERENCE_NAME:
        set_client_state (CLIENT_CREATE_TASK_PREFERENCES_PREFERENCE);
        break;
      CLOSE (CLIENT_CREATE_TASK_PREFERENCES_PREFERENCE, VALUE);

      case CLIENT_CREATE_TICKET:
        if (create_ticket_element_end (gmp_parser, error, element_name))
          set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_CREATE_TLS_CERTIFICATE:
        if (create_tls_certificate_element_end (gmp_parser, error,
                                                element_name))
          set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_CREATE_USER:
        {
          gchar *errdesc;
          gchar *fail_group_id, *fail_role_id;
          user_t new_user;

          errdesc = NULL;
          if (create_user_data->copy)
            switch (copy_user (create_user_data->name,
                               NULL,
                               create_user_data->copy,
                               &new_user))
              {
                case 0:
                  {
                    char *uuid;
                    uuid = user_uuid (new_user);
                    SENDF_TO_CLIENT_OR_FAIL (XML_OK_CREATED_ID ("create_user"),
                                             uuid);
                    log_event ("user", "User", uuid, "created");
                    free (uuid);
                    break;
                  }
                case 1:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("create_user",
                                      "User exists already"));
                    log_event_fail ("user", "User", NULL, "created");
                  break;
                case 2:
                  if (send_find_error_to_client ("create_user", "user",
                                                 create_user_data->copy,
                                                 gmp_parser))
                    {
                      error_send_to_client (error);
                      return;
                    }
                    log_event_fail ("user", "User", NULL, "created");
                  break;
                case 99:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("create_user",
                                      "Permission denied"));
                  log_event_fail ("user", "User", NULL, "created");
                  break;
                case -1:
                default:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_INTERNAL_ERROR ("create_user"));
                  log_event_fail ("user", "User", NULL, "created");
                  break;
              }
          else if (create_user_data->name == NULL
              || strlen (create_user_data->name) == 0)
            SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX
                                    ("create_user",
                                     "A name is required"));
          else
            switch (create_user
                     (create_user_data->name,
                      create_user_data->password
                        ? create_user_data->password : "",
                      create_user_data->comment
                        ? create_user_data->comment : "",
                      create_user_data->hosts,
                      create_user_data->hosts_allow,
                      create_user_data->sources,
                      create_user_data->groups,
                      &fail_group_id,
                      create_user_data->roles,
                      &fail_role_id,
                      &errdesc,
                      &new_user,
                      1))
              {
                case 0:
                  {
                    char *uuid;
                    uuid = user_uuid (new_user);
                    SENDF_TO_CLIENT_OR_FAIL (XML_OK_CREATED_ID ("create_user"),
                                             uuid);
                    log_event ("user", "User", create_user_data->name, "created");
                    free (uuid);
                    break;
                  }
                case 1:
                  if (send_find_error_to_client
                       ("create_user", "group", fail_group_id, gmp_parser))
                    {
                      error_send_to_client (error);
                      return;
                    }
                  log_event_fail ("user", "User", NULL, "created");
                  break;
                case 2:
                  if (send_find_error_to_client
                       ("create_user", "role", fail_role_id, gmp_parser))
                    {
                      error_send_to_client (error);
                      return;
                    }
                  log_event_fail ("user", "User", NULL, "created");
                  break;
                case 3:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("create_user",
                                      "Error in host specification"));
                  log_event_fail ("user", "User", NULL, "created");
                  break;
                case 99:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("create_user",
                                      "Permission denied"));
                  log_event_fail ("user", "User", NULL, "created");
                  break;
                case -2:
                  SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX
                                          ("create_user", "User already exists"));
                  log_event_fail ("user", "User", NULL, "created");
                  break;
                case -3:
                  SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX
                                          ("create_user", "Error in SOURCE"));
                  log_event_fail ("user", "User", NULL, "created");
                  break;
                case -1:
                  if (errdesc)
                    {
                      char *buf = make_xml_error_syntax ("create_user", errdesc);
                      SEND_TO_CLIENT_OR_FAIL (buf);
                      g_free (buf);
                      break;
                    }
                  /* Fall through.  */
                default:
                  SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("create_user"));
                  log_event_fail ("user", "User", NULL, "created");
                  break;
              }
          create_user_data_reset (create_user_data);
          set_client_state (CLIENT_AUTHENTIC);
          g_free (errdesc);
          break;
        }
      CLOSE (CLIENT_CREATE_USER, COMMENT);
      CLOSE (CLIENT_CREATE_USER, COPY);
      CLOSE (CLIENT_CREATE_USER, GROUPS);
      CLOSE (CLIENT_CREATE_USER_GROUPS, GROUP);
      CLOSE (CLIENT_CREATE_USER, HOSTS);
      CLOSE (CLIENT_CREATE_USER, NAME);
      CLOSE (CLIENT_CREATE_USER, PASSWORD);
      CLOSE (CLIENT_CREATE_USER, ROLE);
      case CLIENT_CREATE_USER_SOURCES:
        array_terminate (create_user_data->sources);
        set_client_state (CLIENT_CREATE_USER);
        break;
      case CLIENT_CREATE_USER_SOURCES_SOURCE:
        if (create_user_data->current_source)
          array_add (create_user_data->sources,
                     g_strdup (create_user_data->current_source));
        g_free (create_user_data->current_source);
        create_user_data->current_source = NULL;
        set_client_state (CLIENT_CREATE_USER_SOURCES);
        break;

      case CLIENT_EMPTY_TRASHCAN:
        switch (manage_empty_trashcan ())
          {
            case 0:
              SEND_TO_CLIENT_OR_FAIL (XML_OK ("empty_trashcan"));
              log_event ("trashcan", "Trashcan", NULL, "emptied");
              break;
            case 99:
              SEND_TO_CLIENT_OR_FAIL
               (XML_ERROR_SYNTAX ("empty_trashcan",
                                  "Permission denied"));
              break;
            default:  /* Programming error. */
              assert (0);
            case -1:
              SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("empty_trashcan"));
              break;
          }
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_MODIFY_ALERT:
        {
          event_t event;
          alert_condition_t condition;
          alert_method_t method;

          event = EVENT_ERROR;
          condition = ALERT_CONDITION_ERROR;
          method  = ALERT_METHOD_ERROR;

          array_terminate (modify_alert_data->event_data);
          array_terminate (modify_alert_data->condition_data);
          array_terminate (modify_alert_data->method_data);

          if (strlen (modify_alert_data->event)
              && (event = event_from_name (modify_alert_data->event)) == 0)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("modify_alert",
                                "Failed to recognise event name"));
          else if (strlen (modify_alert_data->condition) &&
                   (condition = alert_condition_from_name
                                 (modify_alert_data->condition))
                   == 0)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("modify_alert",
                                "Failed to recognise condition name"));
          else if (strlen (modify_alert_data->method) &&
                   (method = alert_method_from_name
                                 (modify_alert_data->method))
                   == 0)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("modify_alert",
                                "Failed to recognise method name"));
          else switch (modify_alert
                        (modify_alert_data->alert_id,
                         modify_alert_data->name,
                         modify_alert_data->comment,
                         modify_alert_data->filter_id,
                         modify_alert_data->active,
                         event,
                         modify_alert_data->event_data,
                         condition,
                         modify_alert_data->condition_data,
                         method,
                         modify_alert_data->method_data))
            {
              case 0:
                SENDF_TO_CLIENT_OR_FAIL (XML_OK ("modify_alert"));
                log_event ("alert", "Alert", modify_alert_data->alert_id,
                           "modified");
                break;
              case 1:
                if (send_find_error_to_client ("modify_alert", "alert",
                                               modify_alert_data->alert_id,
                                               gmp_parser))
                  {
                    error_send_to_client (error);
                    return;
                  }
                log_event_fail ("alert", "Alert", modify_alert_data->alert_id,
                                "modified");
                break;
              case 2:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_alert",
                                    "alert with new name exists already"));
                log_event_fail ("alert", "Alert", modify_alert_data->alert_id,
                                "modified");
                break;
              case 3:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_alert",
                                    "An alert_id is required"));
                log_event_fail ("alert", "Alert", modify_alert_data->alert_id,
                                "modified");
                break;
              case 4:
                if (send_find_error_to_client ("modify_alert", "filter",
                                               modify_alert_data->filter_id,
                                               gmp_parser))
                  {
                    error_send_to_client (error);
                    return;
                  }
                log_event_fail ("alert", "Alert", modify_alert_data->alert_id,
                                "modified");
                break;
              case 5:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_alert",
                                    "Filter type must be result if"
                                    " specified"));
                log_event_fail ("alert", "Alert", modify_alert_data->alert_id,
                                "modified");
                break;
              case 6:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_alert",
                                    "Validation of email address failed"));
                log_event_fail ("alert", "Alert", modify_alert_data->alert_id,
                                "modified");
                break;
              case 7:
                SEND_TO_CLIENT_OR_FAIL
                  (XML_ERROR_SYNTAX ("modify_alert",
                                     "Invalid or unexpected condition data"
                                     " name"));
                log_event_fail ("alert", "Alert", NULL, "modified");
                break;
              case 8:
                SEND_TO_CLIENT_OR_FAIL
                  (XML_ERROR_SYNTAX ("modify_alert",
                                     "Syntax error in condition data"));
                log_event_fail ("alert", "Alert", NULL, "modified");
                break;
              case 9:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_alert",
                                    "Email subject too long"));
                log_event_fail ("alert", "Alert", NULL, "modified");
                break;
              case 10:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_alert",
                                    "Email message too long"));
                log_event_fail ("alert", "Alert", NULL, "modified");
                break;
              case 11:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_alert",
                                    "Failed to find filter for condition"));
                log_event_fail ("alert", "Alert", NULL, "modified");
                break;
              case 12:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_alert",
                                    "Error in Send host"));
                log_event_fail ("alert", "Alert", NULL, "modify");
                break;
              case 13:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_alert",
                                    "Error in Send port"));
                log_event_fail ("alert", "Alert", NULL, "modify");
                break;
              case 14:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_alert",
                                    "Failed to find report format for Send"
                                    " method"));
                log_event_fail ("alert", "Alert", NULL, "modify");
                break;
              case 15:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_alert",
                                    "Error in SCP host"));
                log_event_fail ("alert", "Alert", NULL, "modify");
                break;
              case 17:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_alert",
                                    "Failed to find report format for SCP"
                                    " method"));
                log_event_fail ("alert", "Alert", NULL, "modify");
                break;
              case 18:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_alert",
                                    "Error in SCP credential"));
                log_event_fail ("alert", "Alert", NULL, "modify");
                break;
              case 19:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_alert",
                                    "Error in SCP path"));
                log_event_fail ("alert", "Alert", NULL, "modify");
                break;
              case 20:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_alert",
                                    "Method does not match event type"));
                log_event_fail ("alert", "Alert", NULL, "modify");
                break;
              case 21:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_alert",
                                    "Condition does not match event type"));
                log_event_fail ("alert", "Alert", NULL, "modify");
                break;
              case 31:
                SEND_TO_CLIENT_OR_FAIL
                  (XML_ERROR_SYNTAX ("modify_alert",
                                    "Unexpected event data name"));
                log_event_fail ("alert", "Alert", NULL, "modified");
                break;
              case 32:
                SEND_TO_CLIENT_OR_FAIL
                  (XML_ERROR_SYNTAX ("modify_alert",
                                     "Syntax error in event data"));
                log_event_fail ("alert", "Alert", NULL, "modified");
                break;
              case 40:
                SEND_TO_CLIENT_OR_FAIL
                  (XML_ERROR_SYNTAX ("modify_alert",
                                     "Error in SMB credential"));
                log_event_fail ("alert", "Alert", NULL, "modified");
                break;
              case 41:
                SEND_TO_CLIENT_OR_FAIL
                  (XML_ERROR_SYNTAX ("modify_alert",
                                     "Error in SMB share path"));
                log_event_fail ("alert", "Alert", NULL, "modified");
                break;
              case 42:
                SEND_TO_CLIENT_OR_FAIL
                  (XML_ERROR_SYNTAX ("modify_alert",
                                     "Error in SMB file path"));
                log_event_fail ("alert", "Alert", NULL, "modified");
                break;
              case 43:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_alert",
                                    "SMB file path must not contain"
                                    " any file or subdirectory ending in"
                                    " a dot (.)."));
                log_event_fail ("alert", "Alert", NULL, "modified");
                break;
              case 50:
                SEND_TO_CLIENT_OR_FAIL
                  (XML_ERROR_SYNTAX ("create_alert",
                                     "Error in TippingPoint credential"));
                log_event_fail ("alert", "Alert", NULL, "created");
                break;
              case 51:
                SEND_TO_CLIENT_OR_FAIL
                  (XML_ERROR_SYNTAX ("create_alert",
                                     "Error in TippingPoint hostname"));
                log_event_fail ("alert", "Alert", NULL, "created");
                break;
              case 52:
                SEND_TO_CLIENT_OR_FAIL
                  (XML_ERROR_SYNTAX ("create_alert",
                                     "Error in TippingPoint TLS"
                                     " certificate"));
                log_event_fail ("alert", "Alert", NULL, "created");
                break;
              case 53:
                SEND_TO_CLIENT_OR_FAIL
                  (XML_ERROR_SYNTAX ("create_alert",
                                     "TippingPoint TLS workaround must be"
                                     " set to 0 or 1"));
                log_event_fail ("alert", "Alert", NULL, "created");
                break;
              case 60:
                SEND_TO_CLIENT_OR_FAIL
                   ("<create_alert_response"
                    " status=\"" STATUS_ERROR_MISSING "\""
                    " status_text=\"Recipient credential not found\"/>");
                  log_event_fail ("alert", "Alert", NULL, "created");
                break;
              case 61:
                SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("create_alert",
                                      "Email recipient credential must have"
                                      " type 'pgp' or 'smime'"));
                log_event_fail ("alert", "Alert", NULL, "created");
                break;
              case 70:
                {
                  SEND_TO_CLIENT_OR_FAIL
                    ("<create_alert_response"
                      " status=\"" STATUS_ERROR_MISSING "\""
                      " status_text=\"Credential for vFire not found\"/>");
                  log_event_fail ("alert", "Alert", NULL, "created");
                }
                break;
              case 71:
                SEND_TO_CLIENT_OR_FAIL
                  (XML_ERROR_SYNTAX ("create_alert",
                                     "vFire credential must have"
                                     " type 'up'"));
                log_event_fail ("alert", "Alert", NULL, "created");
                break;
              case 80:
                {
                  SEND_TO_CLIENT_OR_FAIL
                     ("<create_alert_response"
                      " status=\"" STATUS_ERROR_MISSING "\""
                      " status_text=\"Credential for Sourcefire"
                      " PKCS12 password not found\"/>");
                  log_event_fail ("alert", "Alert", NULL, "modified");
                }
                break;
              case 81:
                SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("create_alert",
                                      "Sourcefire credential must have"
                                      " type 'up'"));
                log_event_fail ("alert", "Alert", NULL, "modified");
                break;
              case 99:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_alert",
                                    "Permission denied"));
                log_event_fail ("alert", "Alert", modify_alert_data->alert_id,
                                "modified");
                break;
              default:
              case -1:
                SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("modify_alert"));
                log_event_fail ("alert", "Alert", modify_alert_data->alert_id,
                                "modified");
                break;
            }

          modify_alert_data_reset (modify_alert_data);
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }
      CLOSE (CLIENT_MODIFY_ALERT, COMMENT);
      CLOSE (CLIENT_MODIFY_ALERT, NAME);
      CLOSE (CLIENT_MODIFY_ALERT, FILTER);
      CLOSE (CLIENT_MODIFY_ALERT, ACTIVE);
      CLOSE (CLIENT_MODIFY_ALERT, EVENT);
      CLOSE (CLIENT_MODIFY_ALERT, CONDITION);
      CLOSE (CLIENT_MODIFY_ALERT, METHOD);

      case CLIENT_MODIFY_ALERT_EVENT_DATA:
        {
          gchar *string;

          assert (modify_alert_data->event_data);
          assert (modify_alert_data->part_data);
          assert (modify_alert_data->part_name);

          string = g_strconcat (modify_alert_data->part_name,
                                "0",
                                modify_alert_data->part_data,
                                NULL);
          string[strlen (modify_alert_data->part_name)] = '\0';
          array_add (modify_alert_data->event_data, string);

          gvm_free_string_var (&modify_alert_data->part_data);
          gvm_free_string_var (&modify_alert_data->part_name);
          gvm_append_string (&modify_alert_data->part_data, "");
          gvm_append_string (&modify_alert_data->part_name, "");
          set_client_state (CLIENT_MODIFY_ALERT_EVENT);
          break;
        }
      CLOSE (CLIENT_MODIFY_ALERT_EVENT_DATA, NAME);

      case CLIENT_MODIFY_ALERT_CONDITION_DATA:
        {
          gchar *string;

          assert (modify_alert_data->condition_data);
          assert (modify_alert_data->part_data);
          assert (modify_alert_data->part_name);

          string = g_strconcat (modify_alert_data->part_name,
                                "0",
                                modify_alert_data->part_data,
                                NULL);
          string[strlen (modify_alert_data->part_name)] = '\0';
          array_add (modify_alert_data->condition_data, string);

          gvm_free_string_var (&modify_alert_data->part_data);
          gvm_free_string_var (&modify_alert_data->part_name);
          gvm_append_string (&modify_alert_data->part_data, "");
          gvm_append_string (&modify_alert_data->part_name, "");
          set_client_state (CLIENT_MODIFY_ALERT_CONDITION);
          break;
        }
      CLOSE (CLIENT_MODIFY_ALERT_CONDITION_DATA, NAME);

      case CLIENT_MODIFY_ALERT_METHOD_DATA:
        {
          gchar *string;

          assert (modify_alert_data->method_data);
          assert (modify_alert_data->part_data);
          assert (modify_alert_data->part_name);

          string = g_strconcat (modify_alert_data->part_name,
                                "0",
                                modify_alert_data->part_data,
                                NULL);
          string[strlen (modify_alert_data->part_name)] = '\0';
          array_add (modify_alert_data->method_data, string);

          gvm_free_string_var (&modify_alert_data->part_data);
          gvm_free_string_var (&modify_alert_data->part_name);
          gvm_append_string (&modify_alert_data->part_data, "");
          gvm_append_string (&modify_alert_data->part_name, "");
          set_client_state (CLIENT_MODIFY_ALERT_METHOD);
          break;
        }
      CLOSE (CLIENT_MODIFY_ALERT_METHOD_DATA, NAME);

      case CLIENT_MODIFY_ASSET:
        {
          switch (modify_asset
                   (modify_asset_data->asset_id,
                    modify_asset_data->comment))
            {
              case 0:
                SENDF_TO_CLIENT_OR_FAIL (XML_OK ("modify_asset"));
                log_event ("asset", "Asset", modify_asset_data->asset_id,
                           "modified");
                break;
              case 1:
                if (send_find_error_to_client ("modify_asset", "asset",
                                               modify_asset_data->asset_id,
                                               gmp_parser))
                  {
                    error_send_to_client (error);
                    return;
                  }
                log_event_fail ("asset", "Asset", modify_asset_data->asset_id,
                                "modified");
                break;
              case 2:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_asset",
                                    "asset with new name exists already"));
                log_event_fail ("asset", "Asset", modify_asset_data->asset_id,
                                "modified");
                break;
              case 3:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_asset",
                                    "MODIFY_asset requires a asset_id"));
                log_event_fail ("asset", "Asset", modify_asset_data->asset_id,
                                "modified");
                break;
              case 99:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_asset",
                                    "Permission denied"));
                log_event_fail ("asset", "Asset", modify_asset_data->asset_id,
                                "modified");
                break;
              default:
              case -1:
                SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("modify_asset"));
                log_event_fail ("asset", "Asset", modify_asset_data->asset_id,
                                "modified");
                break;
            }

          modify_asset_data_reset (modify_asset_data);
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }
      CLOSE (CLIENT_MODIFY_ASSET, COMMENT);

      case CLIENT_MODIFY_AUTH:
        {
          GSList *item;

          if (acl_user_may ("modify_auth") == 0)
            {
              SEND_TO_CLIENT_OR_FAIL
               (XML_ERROR_SYNTAX ("modify_auth",
                                  "Permission denied"));
              modify_auth_data_reset (modify_auth_data);
              set_client_state (CLIENT_AUTHENTIC);
              break;
            }

          item = modify_auth_data->groups;
          while (item)
            {
              auth_group_t *auth_group;
              gchar *group;

              auth_group = (auth_group_t *) item->data;
              group = auth_group->group_name;
              if (group == NULL)
                {
                  SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX
                                           ("modify_auth",
                                            "GROUP requires a name attribute"));
                  set_client_state (CLIENT_AUTHENTIC);
                  modify_auth_data_reset (modify_auth_data);
                  break;
                }
              if (strcmp (group, "method:ldap_connect") == 0)
                {
                  GSList *setting;
                  gchar *ldap_host, *ldap_authdn, *ldap_cacert;
                  int ldap_enabled, ldap_plaintext;

                  ldap_enabled = ldap_plaintext = -1;
                  ldap_host = ldap_authdn = ldap_cacert = NULL;
                  setting = auth_group->settings;
                  while (setting)
                    {
                      auth_conf_setting_t *kvp =
                        (auth_conf_setting_t *) setting->data;

                      if (kvp->key == NULL || kvp->value == NULL)
                        /* Skip this one. */;
                      else if (strcmp (kvp->key, "enable") == 0)
                        ldap_enabled = (strcmp (kvp->value, "true") == 0);
                      else if (strcmp (kvp->key, "ldaphost") == 0)
                        ldap_host = g_strdup (kvp->value);
                      else if (strcmp (kvp->key, "authdn") == 0)
                        ldap_authdn = g_strdup (kvp->value);
                      else if (strcmp (kvp->key, "allow-plaintext") == 0)
                        ldap_plaintext = (strcmp (kvp->value, "true") == 0);
                      else if (strcmp (kvp->key, "cacert") == 0)
                        ldap_cacert = g_strdup (kvp->value);

                      setting = g_slist_next (setting);
                    }

                  manage_set_ldap_info (ldap_enabled, ldap_host, ldap_authdn,
                                        ldap_plaintext, ldap_cacert);
                }
              if (strcmp (group, "method:radius_connect") == 0)
                {
                  GSList *setting;
                  char *radius_host, *radius_key;
                  int radius_enabled;

                  radius_enabled = -1;
                  radius_host = radius_key = NULL;
                  setting = auth_group->settings;
                  while (setting)
                    {
                      auth_conf_setting_t *kvp =
                        (auth_conf_setting_t *) setting->data;

                      if (kvp->key == NULL || kvp->value == NULL)
                        /* Skip this one. */;
                      else if (strcmp (kvp->key, "enable") == 0)
                        radius_enabled = (strcmp (kvp->value, "true") == 0);
                      else if (strcmp (kvp->key, "radiushost") == 0)
                        radius_host = g_strdup (kvp->value);
                      else if (strcmp (kvp->key, "radiuskey") == 0)
                        radius_key = g_strdup (kvp->value);

                      setting = g_slist_next (setting);
                    }

                  manage_set_radius_info (radius_enabled, radius_host,
                                          radius_key);
                }
              item = g_slist_next (item);
            }

          SEND_TO_CLIENT_OR_FAIL (XML_OK ("modify_auth"));
          modify_auth_data_reset (modify_auth_data);
          set_client_state (CLIENT_AUTHENTIC);

          break;
        }

      case CLIENT_MODIFY_AUTH_GROUP:
        {
          /* Add settings to group. */
          if (modify_auth_data->curr_group_settings)
            {
              auth_group_t *new_group;
              assert (modify_auth_data->groups);
              new_group = modify_auth_data->groups->data;
              assert (new_group);
              new_group->settings = modify_auth_data->curr_group_settings;
            }

          modify_auth_data->curr_group_settings = NULL;
          set_client_state (CLIENT_MODIFY_AUTH);
          break;
        }
      case CLIENT_MODIFY_AUTH_GROUP_AUTH_CONF_SETTING:
        {
          auth_conf_setting_t *setting;

          setting = g_malloc0 (sizeof (auth_conf_setting_t));
          setting->key = modify_auth_data->key;
          modify_auth_data->key = NULL;
          setting->value = modify_auth_data->value;
          modify_auth_data->value = NULL;

          /* Add setting to settings. */
          modify_auth_data->curr_group_settings
           = g_slist_prepend (modify_auth_data->curr_group_settings, setting);

          set_client_state (CLIENT_MODIFY_AUTH_GROUP);
          break;
        }
      CLOSE (CLIENT_MODIFY_AUTH_GROUP_AUTH_CONF_SETTING, KEY);
      CLOSE (CLIENT_MODIFY_AUTH_GROUP_AUTH_CONF_SETTING, VALUE);

      case CLIENT_MODIFY_CONFIG:
        if (modify_config_element_end (gmp_parser, error, element_name))
          set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_MODIFY_CREDENTIAL:
        {
          switch (modify_credential
                   (modify_credential_data->credential_id,
                    modify_credential_data->name,
                    modify_credential_data->comment,
                    modify_credential_data->login,
                    (modify_credential_data->key_phrase
                     || modify_credential_data->key_private)
                      ? modify_credential_data->key_phrase
                      : modify_credential_data->password,
                    modify_credential_data->key_private,
                    modify_credential_data->key_public,
                    modify_credential_data->certificate,
                    modify_credential_data->community,
                    modify_credential_data->auth_algorithm,
                    modify_credential_data->privacy_password,
                    modify_credential_data->privacy_algorithm,
                    modify_credential_data->allow_insecure))
            {
              case 0:
                SENDF_TO_CLIENT_OR_FAIL (XML_OK ("modify_credential"));
                log_event ("credential", "Credential",
                           modify_credential_data->credential_id,
                           "modified");
                break;
              case 1:
                if (send_find_error_to_client
                     ("modify_credential", "credential",
                      modify_credential_data->credential_id,
                      gmp_parser))
                  {
                    error_send_to_client (error);
                    return;
                  }
                log_event_fail ("credential", "Credential",
                                modify_credential_data->credential_id,
                                "modified");
                break;
              case 2:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_credential",
                                    "credential with new name"
                                    " exists already"));
                log_event_fail ("credential", "Credential",
                                modify_credential_data->credential_id,
                                "modified");
                break;
              case 3:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_credential",
                                    "A credential_id is required"));
                log_event_fail ("credential", "Credential",
                                modify_credential_data->credential_id,
                                "modified");
                break;
              case 4:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_credential",
                                    "Login name must not be empty and may"
                                    " contain only alphanumeric characters"
                                    " or the following: - _ \\ . @"));
                log_event_fail ("credential", "Credential",
                                modify_credential_data->credential_id,
                                "modified");
                break;
              case 5:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_credential",
                                    "Invalid or empty certificate"));
                log_event_fail ("credential", "Credential",
                                modify_credential_data->credential_id,
                                "modified");
                break;
              case 6:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_credential",
                                    "Invalid or empty auth_algorithm"));
                log_event_fail ("credential", "Credential",
                                modify_credential_data->credential_id,
                                "modified");
                break;
              case 7:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_credential",
                                    "Invalid or empty privacy_algorithm"));
                log_event_fail ("credential", "Credential",
                                modify_credential_data->credential_id,
                                "modified");
                break;
              case 8:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_credential",
                                    "Invalid or empty private key"));
                log_event_fail ("credential", "Credential",
                                modify_credential_data->credential_id,
                                "modified");
                break;
              case 9:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_credential",
                                    "Invalid or empty public key"));
                log_event_fail ("credential", "Credential",
                                modify_credential_data->credential_id,
                                "modified");
                break;
              case 10:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_credential",
                                    "Privacy password must also be empty"
                                    " if privacy algorithm is empty"));
                log_event_fail ("credential", "Credential",
                                modify_credential_data->credential_id,
                                "modified");
                break;
              case 99:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_credential",
                                    "Permission denied"));
                log_event_fail ("credential", "Credential",
                                modify_credential_data->credential_id,
                                "modified");
                break;
              default:
              case -1:
                SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("modify_credential"));
                log_event_fail ("credential", "Credential",
                                modify_credential_data->credential_id,
                                "modified");
                break;
            }

          modify_credential_data_reset (modify_credential_data);
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }
        modify_credential_data_reset (modify_credential_data);
        set_client_state (CLIENT_AUTHENTIC);
        break;
      CLOSE (CLIENT_MODIFY_CREDENTIAL, ALLOW_INSECURE);
      CLOSE (CLIENT_MODIFY_CREDENTIAL, AUTH_ALGORITHM);
      CLOSE (CLIENT_MODIFY_CREDENTIAL, CERTIFICATE);
      CLOSE (CLIENT_MODIFY_CREDENTIAL, COMMENT);
      CLOSE (CLIENT_MODIFY_CREDENTIAL, COMMUNITY);
      CLOSE (CLIENT_MODIFY_CREDENTIAL, KEY);
      CLOSE (CLIENT_MODIFY_CREDENTIAL_KEY, PHRASE);
      CLOSE (CLIENT_MODIFY_CREDENTIAL_KEY, PRIVATE);
      CLOSE (CLIENT_MODIFY_CREDENTIAL_KEY, PUBLIC);
      CLOSE (CLIENT_MODIFY_CREDENTIAL, LOGIN);
      CLOSE (CLIENT_MODIFY_CREDENTIAL, NAME);
      CLOSE (CLIENT_MODIFY_CREDENTIAL, PASSWORD);
      CLOSE (CLIENT_MODIFY_CREDENTIAL, PRIVACY);
      CLOSE (CLIENT_MODIFY_CREDENTIAL_PRIVACY, ALGORITHM);
      CLOSE (CLIENT_MODIFY_CREDENTIAL_PRIVACY, PASSWORD);

      case CLIENT_MODIFY_FILTER:
        {
          switch (modify_filter
                   (modify_filter_data->filter_id,
                    modify_filter_data->name,
                    modify_filter_data->comment,
                    modify_filter_data->term,
                    modify_filter_data->type))
            {
              case 0:
                SENDF_TO_CLIENT_OR_FAIL (XML_OK ("modify_filter"));
                log_event ("filter", "Filter", modify_filter_data->filter_id,
                           "modified");
                break;
              case 1:
                if (send_find_error_to_client ("modify_filter", "filter",
                                               modify_filter_data->filter_id,
                                               gmp_parser))
                  {
                    error_send_to_client (error);
                    return;
                  }
                log_event_fail ("filter", "Filter",
                                modify_filter_data->filter_id, "modified");
                break;
              case 2:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_filter",
                                    "Filter with new name exists already"));
                log_event_fail ("filter", "Filter",
                                modify_filter_data->filter_id, "modified");
                break;
              case 3:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_filter",
                                    "Error in type name"));
                log_event_fail ("filter", "Filter",
                                modify_filter_data->filter_id, "modified");
                break;
              case 4:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_filter",
                                    "A filter_id is required"));
                log_event_fail ("filter", "Filter",
                                modify_filter_data->filter_id, "modified");
                break;
              case 5:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_filter",
                                    "Filter is used by an alert so type must be"
                                    " 'result' if specified"));
                log_event_fail ("filter", "Filter",
                                modify_filter_data->filter_id, "modified");
                break;
              case 6:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_filter",
                                    "Filter is used by an alert so type must be"
                                    " 'info' if specified"));
                log_event_fail ("filter", "Filter",
                                modify_filter_data->filter_id, "modified");
                break;
              case 99:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_filter",
                                    "Permission denied"));
                log_event_fail ("filter", "Filter",
                                modify_filter_data->filter_id, "modified");
                break;
              default:
              case -1:
                SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("modify_filter"));
                log_event_fail ("filter", "Filter",
                                modify_filter_data->filter_id, "modified");
                break;
            }

          modify_filter_data_reset (modify_filter_data);
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }
      CLOSE (CLIENT_MODIFY_FILTER, COMMENT);
      CLOSE (CLIENT_MODIFY_FILTER, NAME);
      CLOSE (CLIENT_MODIFY_FILTER, TYPE);
      CLOSE (CLIENT_MODIFY_FILTER, TERM);

      case CLIENT_MODIFY_GROUP:
        {
          switch (modify_group
                   (modify_group_data->group_id,
                    modify_group_data->name,
                    modify_group_data->comment,
                    modify_group_data->users))
            {
              case 0:
                SENDF_TO_CLIENT_OR_FAIL (XML_OK ("modify_group"));
                log_event ("group", "Group", modify_group_data->group_id,
                           "modified");
                break;
              case 1:
                if (send_find_error_to_client ("modify_group", "group",
                                               modify_group_data->group_id,
                                               gmp_parser))
                  {
                    error_send_to_client (error);
                    return;
                  }
                log_event_fail ("group", "Group",
                                modify_group_data->group_id, "modified");
                break;
              case 2:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_group",
                                    "Failed to find user"));
                log_event_fail ("group", "Group",
                                modify_group_data->group_id, "modified");
                break;
              case 3:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_group",
                                    "A group_id attribute is required"));
                log_event_fail ("group", "Group",
                                modify_group_data->group_id, "modified");
                break;
              case 4:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_group",
                                    "Error in user name"));
                log_event_fail ("group", "Group",
                                modify_group_data->group_id, "modified");
                break;
              case 5:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_group",
                                    "Group with new name exists already"));
                log_event_fail ("group", "Group",
                                modify_group_data->group_id, "modified");
                break;
              case 99:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_group",
                                    "Permission denied"));
                log_event_fail ("group", "Group",
                                modify_group_data->group_id, "modified");
                break;
              default:
              case -1:
                SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("modify_group"));
                log_event_fail ("group", "Group",
                                modify_group_data->group_id, "modified");
                break;
            }

          modify_group_data_reset (modify_group_data);
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }
      CLOSE (CLIENT_MODIFY_GROUP, COMMENT);
      CLOSE (CLIENT_MODIFY_GROUP, NAME);
      CLOSE (CLIENT_MODIFY_GROUP, USERS);

      case CLIENT_MODIFY_LICENSE:
        {
          if (modify_license_element_end (gmp_parser,
                                          error,
                                          element_name))
            set_client_state (CLIENT_AUTHENTIC);
          break;
        }

      case CLIENT_MODIFY_NOTE:
        {
          if (acl_user_may ("modify_note") == 0)
            {
              SEND_TO_CLIENT_OR_FAIL
               (XML_ERROR_SYNTAX ("modify_note",
                                  "Permission denied"));
              modify_note_data_reset (modify_note_data);
              set_client_state (CLIENT_AUTHENTIC);
              break;
            }

          if (modify_note_data->note_id == NULL)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("modify_note",
                                "A note_id attribute is required"));
          else if (modify_note_data->text == NULL)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("modify_note",
                                "A TEXT entity is required"));
          else switch (modify_note (modify_note_data->note_id,
                                    modify_note_data->active,
                                    modify_note_data->nvt_oid,
                                    modify_note_data->text,
                                    modify_note_data->hosts,
                                    modify_note_data->port,
                                    modify_note_data->severity,
                                    modify_note_data->threat,
                                    modify_note_data->task_id,
                                    modify_note_data->result_id))
            {
              case 0:
                SENDF_TO_CLIENT_OR_FAIL (XML_OK ("modify_note"));
                break;
              case -1:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_INTERNAL_ERROR ("modify_note"));
                break;
              case 2:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_note",
                                    "Error in port specification"));
                log_event_fail ("note", "Note", modify_note_data->note_id,
                                "modified");
                break;
              case 3:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_note",
                                    "Error in severity specification"));
                log_event_fail ("note", "Note", modify_note_data->note_id,
                                "modified");
                break;
              case 4:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_note",
                                    "Invalid nvt oid"));
                log_event_fail ("note", "Note", modify_note_data->note_id,
                                "modified");
                break;
              case 5:
                if (send_find_error_to_client ("modify_note", "note",
                                               modify_note_data->note_id,
                                               gmp_parser))
                  {
                    error_send_to_client (error);
                    return;
                  }
                log_event_fail ("note", "Note", modify_note_data->note_id,
                                "modified");
                break;
              case 6:
                if (send_find_error_to_client ("modify_note", "task",
                                               modify_note_data->task_id,
                                               gmp_parser))
                  {
                    error_send_to_client (error);
                    return;
                  }
                log_event_fail ("note", "Note", modify_note_data->note_id,
                                "modified");
                break;
              case 7:
                if (send_find_error_to_client ("modify_note", "result",
                                               modify_note_data->result_id,
                                               gmp_parser))
                  {
                    error_send_to_client (error);
                    return;
                  }
                log_event_fail ("note", "Note", modify_note_data->note_id,
                                "modified");
                break;
              default:
                assert (0);
                SEND_TO_CLIENT_OR_FAIL
                 (XML_INTERNAL_ERROR ("modify_note"));
                break;
            }
          modify_note_data_reset (modify_note_data);
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }
      CLOSE (CLIENT_MODIFY_NOTE, ACTIVE);
      CLOSE (CLIENT_MODIFY_NOTE, HOSTS);
      CLOSE (CLIENT_MODIFY_NOTE, PORT);
      CLOSE (CLIENT_MODIFY_NOTE, RESULT);
      CLOSE (CLIENT_MODIFY_NOTE, SEVERITY);
      CLOSE (CLIENT_MODIFY_NOTE, TASK);
      CLOSE (CLIENT_MODIFY_NOTE, TEXT);
      CLOSE (CLIENT_MODIFY_NOTE, THREAT);
      CLOSE (CLIENT_MODIFY_NOTE, NVT);

      case CLIENT_MODIFY_OVERRIDE:
        {
          int max;

          if (acl_user_may ("modify_override") == 0)
            {
              SEND_TO_CLIENT_OR_FAIL
               (XML_ERROR_SYNTAX ("modify_override",
                                  "Permission denied"));
              modify_override_data_reset (modify_override_data);
              set_client_state (CLIENT_AUTHENTIC);
              break;
            }

          if (modify_override_data->override_id == NULL)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("modify_override",
                                "An override_id attribute is required"));
          else if (modify_override_data->text == NULL)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("modify_override",
                                "A TEXT entity is required"));
          else if (modify_override_data->hosts
                   && ((max = manage_count_hosts (modify_override_data->hosts,
                                                  NULL))
                       == -1))
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("modify_override",
                                "Error in host specification"));
          else if (modify_override_data->hosts && (max > manage_max_hosts ()))
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("modify_override",
                                "Host specification exceeds maximum number"
                                " of hosts"));
          else switch (modify_override (modify_override_data->override_id,
                                        modify_override_data->active,
                                        modify_override_data->nvt_oid,
                                        modify_override_data->text,
                                        modify_override_data->hosts,
                                        modify_override_data->port,
                                        modify_override_data->threat,
                                        modify_override_data->new_threat,
                                        modify_override_data->severity,
                                        modify_override_data->new_severity,
                                        modify_override_data->task_id,
                                        modify_override_data->result_id))
            {
              case 0:
                SENDF_TO_CLIENT_OR_FAIL (XML_OK ("modify_override"));
                break;
              case 1:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_override",
                                    "ACTIVE must be an integer >= -2"));
                break;
              case 2:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_override",
                                    "Error in port specification"));
                log_event_fail ("override", "Override",
                                modify_override_data->override_id,
                                "modified");
                break;
              case 3:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_override",
                                    "Error in severity specification"));
                log_event_fail ("override", "Override",
                                modify_override_data->override_id,
                                "modified");
                break;
              case 4:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_override",
                                    "Invalid nvt oid"));
                log_event_fail ("override", "Override",
                                modify_override_data->override_id,
                                "modified");
                break;
              case 5:
                if (send_find_error_to_client ("modify_override", "override",
                                               modify_override_data->override_id,
                                               gmp_parser))
                  {
                    error_send_to_client (error);
                    return;
                  }
                log_event_fail ("override", "Override",
                                modify_override_data->override_id,
                                "modified");
                break;
              case 6:
                if (send_find_error_to_client ("modify_override", "task",
                                               modify_override_data->task_id,
                                               gmp_parser))
                  {
                    error_send_to_client (error);
                    return;
                  }
                log_event_fail ("override", "Override",
                                modify_override_data->override_id,
                                "modified");
                break;
              case 7:
                if (send_find_error_to_client ("modify_override", "result",
                                               modify_override_data->result_id,
                                               gmp_parser))
                  {
                    error_send_to_client (error);
                    return;
                  }
                log_event_fail ("override", "Override",
                                modify_override_data->override_id,
                                "modified");
                break;
              case 8:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_override",
                                    "Error in threat specification"));
                log_event_fail ("override", "Override",
                                modify_override_data->override_id,
                                "modified");
                break;
              case 9:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_override",
                                    "Error in new_threat specification"));
                log_event_fail ("override", "Override",
                                modify_override_data->override_id,
                                "modified");
                break;
              case 10:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_override",
                                    "Error in new_severity specification"));
                log_event_fail ("override", "Override",
                                modify_override_data->override_id,
                                "modified");
                break;
              case 11:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_override",
                                    "new_severity is required"));
                log_event_fail ("override", "Override",
                                modify_override_data->override_id,
                                "modified");
                break;
              case -1:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_INTERNAL_ERROR ("modify_override"));
                break;
              default:
                assert (0);
                SEND_TO_CLIENT_OR_FAIL
                 (XML_INTERNAL_ERROR ("modify_override"));
                break;
            }
          modify_override_data_reset (modify_override_data);
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }
      CLOSE (CLIENT_MODIFY_OVERRIDE, ACTIVE);
      CLOSE (CLIENT_MODIFY_OVERRIDE, HOSTS);
      CLOSE (CLIENT_MODIFY_OVERRIDE, NEW_SEVERITY);
      CLOSE (CLIENT_MODIFY_OVERRIDE, NEW_THREAT);
      CLOSE (CLIENT_MODIFY_OVERRIDE, PORT);
      CLOSE (CLIENT_MODIFY_OVERRIDE, RESULT);
      CLOSE (CLIENT_MODIFY_OVERRIDE, SEVERITY);
      CLOSE (CLIENT_MODIFY_OVERRIDE, TASK);
      CLOSE (CLIENT_MODIFY_OVERRIDE, TEXT);
      CLOSE (CLIENT_MODIFY_OVERRIDE, THREAT);
      CLOSE (CLIENT_MODIFY_OVERRIDE, NVT);

      case CLIENT_MODIFY_PERMISSION:
        {
          if (modify_permission_data->permission_id == NULL)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("modify_permission",
                                "A permission_id attribute is required"));
          else switch (modify_permission
                        (modify_permission_data->permission_id,
                         modify_permission_data->name,
                         modify_permission_data->comment,
                         modify_permission_data->resource_id,
                         modify_permission_data->resource_type,
                         modify_permission_data->subject_type,
                         modify_permission_data->subject_id))
            {
              case 1:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_permission",
                                    "Permission exists already"));
                log_event_fail ("permission", "Permission",
                                modify_permission_data->permission_id,
                                "modified");
                break;
              case 2:
                if (send_find_error_to_client
                     ("modify_permission", "subject",
                      modify_permission_data->subject_id, gmp_parser))
                  {
                    error_send_to_client (error);
                    return;
                  }
                log_event_fail ("permission", "Permission",
                                modify_permission_data->permission_id,
                                "modified");
                break;
              case 3:
                if (send_find_error_to_client
                     ("modify_permission", "resource",
                      modify_permission_data->resource_id, gmp_parser))
                  {
                    error_send_to_client (error);
                    return;
                  }
                log_event_fail ("permission", "Permission",
                                modify_permission_data->permission_id,
                                "modified");
                break;
              case 4:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_permission",
                                    "A PERMISSION"
                                    " ID is required"));
                log_event_fail ("permission", "Permission",
                                modify_permission_data->permission_id,
                                "modified");
                break;
              case 5:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_permission",
                                    "Error in RESOURCE"));
                log_event_fail ("permission", "Permission",
                                modify_permission_data->permission_id,
                                "modified");
                break;
              case 6:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_permission",
                                    "Error in SUBJECT"));
                log_event_fail ("permission", "Permission",
                                modify_permission_data->permission_id,
                                "modified");
                break;
              case 7:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_permission",
                                    "Error in NAME"));
                log_event_fail ("permission", "Permission",
                                modify_permission_data->permission_id,
                                "modified");
                break;
              case 8:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_permission",
                                    "NAME required to find resource"));
                log_event_fail ("permission", "Permission",
                                modify_permission_data->permission_id,
                                "modified");
                break;
              case 9:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_permission",
                                    "Permission does not accept a resource"));
                log_event_fail ("permission", "Permission", NULL, "modified");
                break;
              case 99:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_permission",
                                    "Permission denied"));
                log_event_fail ("permission", "Permission",
                                modify_permission_data->permission_id,
                                "modified");
                break;
              case -1:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_INTERNAL_ERROR ("modify_permission"));
                log_event_fail ("permission", "Permission",
                                modify_permission_data->permission_id,
                                "modified");
                break;
              default:
                {
                  SENDF_TO_CLIENT_OR_FAIL (XML_OK ("modify_permission"));
                  log_event ("permission", "Permission",
                             modify_permission_data->permission_id, "modified");
                  break;
                }
            }

          modify_permission_data_reset (modify_permission_data);
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }
      CLOSE (CLIENT_MODIFY_PERMISSION, COMMENT);
      CLOSE (CLIENT_MODIFY_PERMISSION, SUBJECT);
      CLOSE (CLIENT_MODIFY_PERMISSION_SUBJECT, TYPE);
      CLOSE (CLIENT_MODIFY_PERMISSION, NAME);
      CLOSE (CLIENT_MODIFY_PERMISSION, RESOURCE);
      CLOSE (CLIENT_MODIFY_PERMISSION_RESOURCE, TYPE);

      case CLIENT_MODIFY_PORT_LIST:
        {
          switch (modify_port_list
                   (modify_port_list_data->port_list_id,
                    modify_port_list_data->name,
                    modify_port_list_data->comment))
            {
              case 0:
                SENDF_TO_CLIENT_OR_FAIL (XML_OK ("modify_port_list"));
                log_event ("port_list", "Port List",
                           modify_port_list_data->port_list_id, "modified");
                break;
              case 1:
                if (send_find_error_to_client ("modify_port_list", "port_list",
                                               modify_port_list_data->port_list_id,
                                               gmp_parser))
                  {
                    error_send_to_client (error);
                    return;
                  }
                log_event_fail ("port_list", "Port List",
                                modify_port_list_data->port_list_id,
                                "modified");
                break;
              case 2:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_port_list",
                                    "Port List with new name exists already"));
                log_event_fail ("port_list", "Port List",
                                modify_port_list_data->port_list_id,
                                "modified");
                break;
              case 3:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_port_list",
                                    "A port_list_id is required"));
                log_event_fail ("port_list", "Port List",
                                modify_port_list_data->port_list_id,
                                "modified");
                break;
              case 99:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_port_list",
                                    "Permission denied"));
                log_event_fail ("port_list", "Port List",
                                modify_port_list_data->port_list_id,
                                "modified");
                break;
              default:
              case -1:
                SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("modify_port_list"));
                log_event_fail ("port_list", "Port List",
                                modify_port_list_data->port_list_id,
                                "modified");
                break;
            }

          modify_port_list_data_reset (modify_port_list_data);
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }
      CLOSE (CLIENT_MODIFY_PORT_LIST, COMMENT);
      CLOSE (CLIENT_MODIFY_PORT_LIST, NAME);

      case CLIENT_MODIFY_REPORT_FORMAT:
        {
          switch (modify_report_format
                   (modify_report_format_data->report_format_id,
                    modify_report_format_data->name,
                    modify_report_format_data->summary,
                    modify_report_format_data->active,
                    modify_report_format_data->param_name,
                    modify_report_format_data->param_value))
            {
              case 0:
                SENDF_TO_CLIENT_OR_FAIL (XML_OK ("modify_report_format"));
                log_event ("report_format", "Report Format",
                           modify_report_format_data->report_format_id,
                           "modified");
                break;
              case 1:
                if (send_find_error_to_client
                     ("modify_report_format", "report_format",
                      modify_report_format_data->report_format_id,
                      gmp_parser))
                  {
                    error_send_to_client (error);
                    return;
                  }
                log_event_fail ("report_format", "Report Format",
                                modify_report_format_data->report_format_id,
                                "modified");
                break;
              case 2:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX
                   ("modify_report_format",
                    "A report_format_id is required"));
                log_event_fail ("report_format", "Report Format",
                                modify_report_format_data->report_format_id,
                                "modified");
                break;
              case 3:
                if (send_find_error_to_client
                     ("modify_report_format", "report format param",
                      modify_report_format_data->param_name, gmp_parser))
                  {
                    error_send_to_client (error);
                    return;
                  }
                log_event_fail ("report_format", "Report Format",
                                modify_report_format_data->report_format_id,
                                "modified");
                break;
              case 4:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_report_format",
                                    "Parameter validation failed"));
                log_event_fail ("report_format", "Report Format",
                                modify_report_format_data->report_format_id,
                                "modified");
                break;
              case 99:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_report_format",
                                    "Permission denied"));
                log_event_fail ("report_format", "Report Format",
                                modify_report_format_data->report_format_id,
                                "modified");
                break;
              default:
              case -1:
                SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR
                                         ("modify_report_format"));
                log_event_fail ("report_format", "Report Format",
                                modify_report_format_data->report_format_id,
                                "modified");
                break;
            }

          modify_report_format_data_reset (modify_report_format_data);
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }
      CLOSE (CLIENT_MODIFY_REPORT_FORMAT, ACTIVE);
      CLOSE (CLIENT_MODIFY_REPORT_FORMAT, NAME);
      CLOSE (CLIENT_MODIFY_REPORT_FORMAT, SUMMARY);
      CLOSE (CLIENT_MODIFY_REPORT_FORMAT, PARAM);
      CLOSE (CLIENT_MODIFY_REPORT_FORMAT_PARAM, NAME);
      CLOSE (CLIENT_MODIFY_REPORT_FORMAT_PARAM, VALUE);

      case CLIENT_MODIFY_ROLE:
        {
          switch (modify_role
                   (modify_role_data->role_id,
                    modify_role_data->name,
                    modify_role_data->comment,
                    modify_role_data->users))
            {
              case 0:
                SENDF_TO_CLIENT_OR_FAIL (XML_OK ("modify_role"));
                log_event ("role", "Role", modify_role_data->role_id,
                           "modified");
                break;
              case 1:
                if (send_find_error_to_client ("modify_role", "role",
                                               modify_role_data->role_id,
                                               gmp_parser))
                  {
                    error_send_to_client (error);
                    return;
                  }
                log_event_fail ("role", "Role",
                                modify_role_data->role_id, "modified");
                break;
              case 2:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_role",
                                    "Failed to find user"));
                log_event_fail ("role", "Role",
                                modify_role_data->role_id, "modified");
                break;
              case 3:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_role",
                                    "A role_id"
                                    " attribute is required"));
                log_event_fail ("role", "Role",
                                modify_role_data->role_id, "modified");
                break;
              case 4:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_role",
                                    "Error in user name"));
                log_event_fail ("role", "Role",
                                modify_role_data->role_id, "modified");
                break;
              case 5:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_role",
                                    "Role with new name exists already"));
                log_event_fail ("role", "Role",
                                modify_role_data->role_id, "modified");
                break;
              case 99:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_role",
                                    "Permission denied"));
                log_event_fail ("role", "Role",
                                modify_role_data->role_id, "modified");
                break;
              default:
              case -1:
                SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("modify_role"));
                log_event_fail ("role", "Role",
                                modify_role_data->role_id, "modified");
                break;
            }

          modify_role_data_reset (modify_role_data);
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }
      CLOSE (CLIENT_MODIFY_ROLE, COMMENT);
      CLOSE (CLIENT_MODIFY_ROLE, NAME);
      CLOSE (CLIENT_MODIFY_ROLE, USERS);

      case CLIENT_MODIFY_SCANNER:
        handle_modify_scanner (gmp_parser, error);
        break;
      CLOSE (CLIENT_MODIFY_SCANNER, TYPE);
      CLOSE (CLIENT_MODIFY_SCANNER, PORT);
      CLOSE (CLIENT_MODIFY_SCANNER, HOST);
      CLOSE (CLIENT_MODIFY_SCANNER, COMMENT);
      CLOSE (CLIENT_MODIFY_SCANNER, NAME);
      CLOSE (CLIENT_MODIFY_SCANNER, CA_PUB);
      CLOSE (CLIENT_MODIFY_SCANNER, CREDENTIAL);

      case CLIENT_MODIFY_SCHEDULE:
        {
          handle_modify_schedule (gmp_parser, error);
          break;
        }
      CLOSE (CLIENT_MODIFY_SCHEDULE, COMMENT);
      CLOSE (CLIENT_MODIFY_SCHEDULE, ICALENDAR);
      CLOSE (CLIENT_MODIFY_SCHEDULE, NAME);
      CLOSE (CLIENT_MODIFY_SCHEDULE, TIMEZONE);

      case CLIENT_MODIFY_SETTING:
        {
          gchar *errdesc = NULL;

          if (((modify_setting_data->name == NULL)
               && (modify_setting_data->setting_id == NULL))
              || (modify_setting_data->value == NULL))
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("modify_setting",
                                "A NAME or setting_id"
                                " and a VALUE is required"));
          else switch (modify_setting (modify_setting_data->setting_id,
                                       modify_setting_data->name,
                                       modify_setting_data->value,
                                       &errdesc))
            {
              case 0:
                SEND_TO_CLIENT_OR_FAIL (XML_OK ("modify_setting"));
                break;
              case 1:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_setting",
                                    "Failed to find setting"));
                break;
              case 2:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_setting",
                                    "Value validation failed"));
                break;
              case 99:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_setting",
                                    "Permission denied"));
                break;
              case -1:
                if (errdesc)
                  {
                    char *buf = make_xml_error_syntax ("modify_setting",
                                                       errdesc);
                    SEND_TO_CLIENT_OR_FAIL (buf);
                    g_free (buf);
                    break;
                  }
                /* Fall through.  */
              default:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_INTERNAL_ERROR ("modify_setting"));
                break;
            }
          g_free (errdesc);
        }
        modify_setting_data_reset (modify_setting_data);
        set_client_state (CLIENT_AUTHENTIC);
        break;
      CLOSE (CLIENT_MODIFY_SETTING, NAME);
      CLOSE (CLIENT_MODIFY_SETTING, VALUE);

      case CLIENT_MODIFY_TAG:
        {
          gchar *error_extra = NULL;

          if (modify_tag_data->resource_ids)
            array_terminate (modify_tag_data->resource_ids);

          if (modify_tag_data->tag_id == NULL)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("modify_tag",
                                "A tag_id attribute is required"));
          else if (modify_tag_data->name
                   && strcmp(modify_tag_data->name, "") == 0)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("modify_tag",
                                "name must be at least one"
                                " character long or omitted completely"));
          else if (modify_tag_data->resource_type &&
                   valid_db_resource_type (modify_tag_data->resource_type) == 0)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("modify_tag",
                                "TYPE in RESOURCES must be"
                                " a valid resource type."));
          else if (modify_tag_data->resource_type
                   && strcasecmp (modify_tag_data->resource_type, "tag") == 0)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("modify_tag",
                                "TYPE in RESOURCES must not"
                                " be 'tag'."));
          else switch (modify_tag (modify_tag_data->tag_id,
                                   modify_tag_data->name,
                                   modify_tag_data->comment,
                                   modify_tag_data->value,
                                   modify_tag_data->resource_type,
                                   modify_tag_data->resource_ids,
                                   modify_tag_data->resources_filter,
                                   modify_tag_data->resources_action,
                                   modify_tag_data->active,
                                   &error_extra))
            {
              case 0:
                SENDF_TO_CLIENT_OR_FAIL (XML_OK ("modify_tag"));
                log_event ("tag", "Tag", modify_tag_data->tag_id,
                           "modified");
                break;
              case 1:
                if (send_find_error_to_client ("modify_tag", "tag",
                                               modify_tag_data->tag_id,
                                               gmp_parser))
                  {
                    error_send_to_client (error);
                    return;
                  }
                log_event_fail ("tag", "Tag", modify_tag_data->tag_id,
                                "modified");
                break;
              case 2:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_tag",
                                    "A tag_id is required"));
                log_event_fail ("tag", "Tag", modify_tag_data->tag_id,
                                "modified");
                break;
              case 3:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_tag",
                                    "RESOURCES action must be"
                                    " 'add', 'set', 'remove'"
                                    " or empty."));
                log_event_fail ("tag", "Tag", modify_tag_data->tag_id,
                                "modified");
                break;
              case 4:
                if (send_find_error_to_client ("modify_tag", "resource",
                                                error_extra,
                                                gmp_parser))
                  {
                    error_send_to_client (error);
                    g_free (error_extra);
                    return;
                  }
                g_free (error_extra);
                log_event_fail ("tag", "Tag", NULL, "modified");
                break;
              case 5:
                SEND_TO_CLIENT_OR_FAIL 
                  ("<modify_tag_response"
                    " status=\"" STATUS_ERROR_MISSING "\""
                    " status_text=\"No resources found for filter\"/>");
                log_event_fail ("tag", "Tag", NULL, "modified");
                break;
              case 6:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_tag",
                                    "Too many resources selected"));
                log_event_fail ("tag", "Tag", NULL, "modified");
                break;
              case 99:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_tag",
                                    "Permission denied"));
                log_event_fail ("tag", "Tag", modify_tag_data->tag_id,
                                "modified");
                break;
              default:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_INTERNAL_ERROR ("modify_tag"));
                log_event_fail ("tag", "Tag", modify_tag_data->tag_id,
                                "modified");
                break;
            }

          modify_tag_data_reset (modify_tag_data);
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }

      CLOSE (CLIENT_MODIFY_TAG, ACTIVE);
      CLOSE (CLIENT_MODIFY_TAG, RESOURCES);
      CLOSE (CLIENT_MODIFY_TAG, COMMENT);
      CLOSE (CLIENT_MODIFY_TAG, NAME);
      CLOSE (CLIENT_MODIFY_TAG, VALUE);

      CLOSE (CLIENT_MODIFY_TAG_RESOURCES, RESOURCE);
      CLOSE (CLIENT_MODIFY_TAG_RESOURCES, TYPE);

      case CLIENT_MODIFY_TARGET:
        {
          if (modify_target_data->target_id == NULL)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("modify_target",
                                "A target_id"
                                " attribute is required"));
          else switch (modify_target
                        (modify_target_data->target_id,
                         modify_target_data->name,
                         modify_target_data->hosts,
                         modify_target_data->exclude_hosts,
                         modify_target_data->comment,
                         modify_target_data->port_list_id,
                         modify_target_data->ssh_credential_id
                          ? modify_target_data->ssh_credential_id
                          : modify_target_data->ssh_lsc_credential_id,
                         modify_target_data->ssh_elevate_credential_id,
                         modify_target_data->ssh_credential_id
                          ? modify_target_data->ssh_port
                          : modify_target_data->ssh_lsc_port,
                         modify_target_data->smb_credential_id
                          ? modify_target_data->smb_credential_id
                          : modify_target_data->smb_lsc_credential_id,
                         modify_target_data->esxi_credential_id
                          ? modify_target_data->esxi_credential_id
                          : modify_target_data->esxi_lsc_credential_id,
                         modify_target_data->snmp_credential_id,
                         modify_target_data->reverse_lookup_only,
                         modify_target_data->reverse_lookup_unify,
                         modify_target_data->alive_tests,
                         modify_target_data->allow_simultaneous_ips))
            {
              case 1:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_target",
                                    "Target exists already"));
                log_event_fail ("target", "Target",
                                modify_target_data->target_id,
                                "modified");
                break;
              case 2:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_target",
                                    "Error in host specification"));
                log_event_fail ("target", "Target",
                                modify_target_data->target_id,
                                "modified");
                break;
              case 3:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_target",
                                    "Host specification exceeds maximum number"
                                    " of hosts"));
                log_event_fail ("target", "Target",
                                modify_target_data->target_id,
                                "modified");
                break;
              case 4:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_target",
                                    "Error in port range"));
                log_event_fail ("target", "Target",
                                modify_target_data->target_id,
                                "modified");
                break;
              case 5:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_target",
                                    "Error in SSH port"));
                log_event_fail ("target", "Target",
                                modify_target_data->target_id,
                                "modified");
                break;
              case 6:
                log_event_fail ("target", "Target",
                                modify_target_data->target_id,
                                "modified");
                if (send_find_error_to_client
                     ("modify_target", "port_list",
                      modify_target_data->port_list_id, gmp_parser))
                  {
                    error_send_to_client (error);
                    return;
                  }
                break;
              case 7:
                log_event_fail ("target", "Target",
                                modify_target_data->target_id,
                                "modified");
                if (send_find_error_to_client
                     ("modify_target", "Credential",
                      modify_target_data->ssh_credential_id
                        ? modify_target_data->ssh_credential_id
                        : modify_target_data->ssh_lsc_credential_id,
                      gmp_parser))
                  {
                    error_send_to_client (error);
                    return;
                  }
                break;
              case 8:
                log_event_fail ("target", "Target",
                                modify_target_data->target_id,
                                "modified");
                if (send_find_error_to_client
                     ("modify_target", "Credential",
                      modify_target_data->smb_credential_id
                        ? modify_target_data->smb_credential_id
                        : modify_target_data->smb_lsc_credential_id,
                      gmp_parser))
                  {
                    error_send_to_client (error);
                    return;
                  }
                break;
              case 9:
                log_event_fail ("target", "Target",
                                modify_target_data->target_id,
                                "modified");
                if (send_find_error_to_client
                     ("modify_target", "target", modify_target_data->target_id,
                      gmp_parser))
                  {
                    error_send_to_client (error);
                    return;
                  }
                break;
              case 10:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_target",
                                    "Error in alive test"));
                log_event_fail ("target", "Target",
                                modify_target_data->target_id,
                                "modified");
                break;
              case 11:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_target",
                                    "Name must be at"
                                    " least one character long"));
                log_event_fail ("target", "Target",
                                modify_target_data->target_id,
                                "modified");
                break;
              case 12:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_target",
                                    "EXCLUDE_HOSTS requires"
                                    " a HOSTS"));
                log_event_fail ("target", "Target",
                                modify_target_data->target_id,
                                "modified");
                break;
              case 13:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_target",
                                    "HOSTS requires an"
                                    " EXCLUDE_HOSTS"));
                log_event_fail ("target", "Target",
                                modify_target_data->target_id,
                                "modified");
                break;
              case 14:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_target",
                                    "HOSTS must be at least one"
                                    "character long"));
                log_event_fail ("target", "Target",
                                modify_target_data->target_id,
                                "modified");
                break;
              case 15:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_target",
                                    "Target is in use"));
                log_event_fail ("target", "Target",
                                modify_target_data->target_id,
                                "modified");
                break;
              case 16:
                log_event_fail ("target", "Target",
                                modify_target_data->target_id,
                                "modified");
                if (send_find_error_to_client
                     ("modify_target", "Credential",
                      modify_target_data->esxi_credential_id
                        ? modify_target_data->esxi_credential_id
                        : modify_target_data->esxi_lsc_credential_id,
                      gmp_parser))
                  {
                    error_send_to_client (error);
                    return;
                  }
                break;
              case 17:
                log_event_fail ("target", "Target",
                                modify_target_data->target_id,
                                "modified");
                if (send_find_error_to_client
                     ("modify_target", "Credential",
                      modify_target_data->snmp_credential_id,
                      gmp_parser))
                  {
                    error_send_to_client (error);
                    return;
                  }
                break;
              case 18:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_target",
                                    "SSH credential must be of type"
                                    " 'up' or 'usk'"));
                log_event_fail ("target", "Target",
                                modify_target_data->target_id, "modified");
                break;
              case 19:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_target",
                                    "SMB credential must be of type"
                                    " 'up'"));
                log_event_fail ("target", "Target",
                                modify_target_data->target_id, "modified");
                break;
              case 20:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_target",
                                    "ESXi credential must be of type"
                                    " 'up'"));
                log_event_fail ("target", "Target",
                                modify_target_data->target_id, "modified");
                break;
              case 21:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_target",
                                    "SNMP credential must be of type"
                                    " 'snmp'"));
                log_event_fail ("target", "Target",
                                modify_target_data->target_id, "modified");
                break;
              case 22:
                log_event_fail ("target", "Target",
                                modify_target_data->target_id,
                                "modified");
                if (send_find_error_to_client
                     ("modify_target", "Credential",
                      modify_target_data->ssh_elevate_credential_id,
                      gmp_parser))
                  {
                    error_send_to_client (error);
                    return;
                  }
                break;
              case 23:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_target",
                                    "ELEVATE credential must be of type"
                                    " 'up'"));
                log_event_fail ("target", "Target",
                                modify_target_data->target_id, "modified");
                break;
              case 24:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_target",
                                    "The elevate credential requires"
                                    " an SSH credential"));
                log_event_fail ("target", "Target",
                                modify_target_data->target_id, "modified");
                break;
              case 25:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_target",
                                    "The elevate credential must be different"
                                    " from the SSH credential"));
                log_event_fail ("target", "Target",
                                modify_target_data->target_id, "modified");
                break;
              case 99:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("modify_target",
                                    "Permission denied"));
                log_event_fail ("target", "Target",
                                modify_target_data->target_id,
                                "modified");
                break;
              case -1:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_INTERNAL_ERROR ("modify_target"));
                log_event_fail ("target", "Target",
                                modify_target_data->target_id,
                                "modified");
                break;
              default:
                {
                  SENDF_TO_CLIENT_OR_FAIL (XML_OK ("modify_target"));
                  log_event ("target", "Target", modify_target_data->target_id,
                             "modified");
                  break;
                }
            }

          modify_target_data_reset (modify_target_data);
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }
      CLOSE (CLIENT_MODIFY_TARGET, ESXI_CREDENTIAL);
      CLOSE (CLIENT_MODIFY_TARGET, ESXI_LSC_CREDENTIAL);
      CLOSE (CLIENT_MODIFY_TARGET, EXCLUDE_HOSTS);
      CLOSE (CLIENT_MODIFY_TARGET, REVERSE_LOOKUP_ONLY);
      CLOSE (CLIENT_MODIFY_TARGET, REVERSE_LOOKUP_UNIFY);
      CLOSE (CLIENT_MODIFY_TARGET, ALIVE_TESTS);
      CLOSE (CLIENT_MODIFY_TARGET, ALLOW_SIMULTANEOUS_IPS);
      CLOSE (CLIENT_MODIFY_TARGET, COMMENT);
      CLOSE (CLIENT_MODIFY_TARGET, HOSTS);
      CLOSE (CLIENT_MODIFY_TARGET, NAME);
      CLOSE (CLIENT_MODIFY_TARGET, PORT_LIST);
      CLOSE (CLIENT_MODIFY_TARGET, SSH_CREDENTIAL);
      CLOSE (CLIENT_MODIFY_TARGET, SSH_LSC_CREDENTIAL);
      CLOSE (CLIENT_MODIFY_TARGET, SSH_ELEVATE_CREDENTIAL);
      CLOSE (CLIENT_MODIFY_TARGET, SMB_CREDENTIAL);
      CLOSE (CLIENT_MODIFY_TARGET, SMB_LSC_CREDENTIAL);
      CLOSE (CLIENT_MODIFY_TARGET, SNMP_CREDENTIAL);

      CLOSE (CLIENT_MODIFY_TARGET_SSH_CREDENTIAL, PORT);

      CLOSE (CLIENT_MODIFY_TARGET_SSH_LSC_CREDENTIAL, PORT);

      case CLIENT_MODIFY_TASK:
        if (acl_user_may ("modify_task") == 0)
          {
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("modify_task",
                                "Permission denied"));
            modify_task_data_reset (modify_task_data);
            set_client_state (CLIENT_AUTHENTIC);
            break;
          }

        if (modify_task_data->task_id)
          {
            gchar *fail_alert_id, *fail_group_id;

            if (modify_task_data->action && (modify_task_data->comment
                                             || modify_task_data->alerts->len
                                             || modify_task_data->groups->len
                                             || modify_task_data->name))
              SEND_TO_CLIENT_OR_FAIL
               (XML_ERROR_SYNTAX ("modify_task",
                                  "Too many parameters at once"));
            else if (modify_task_data->action)
              {
                if (modify_task_data->file_name == NULL)
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("modify_task",
                                      "FILE requires a name"
                                      " attribute"));
                else if (strcmp (modify_task_data->action, "update") == 0)
                  {
                    switch (manage_task_update_file (modify_task_data->task_id,
                                                     modify_task_data->file_name,
                                                     modify_task_data->file
                                                      ? modify_task_data->file
                                                      : ""))
                      {
                        case 0:
                          log_event ("task", "Task", modify_task_data->task_id,
                                     "modified");
                          SEND_TO_CLIENT_OR_FAIL (XML_OK ("modify_task"));
                          break;
                        case 1:
                          if (send_find_error_to_client ("modify_task", "Task",
                                                         modify_task_data->task_id,
                                                         gmp_parser))
                            {
                              error_send_to_client (error);
                              return;
                            }
                          break;
                        default:
                        case -1:
                          SEND_TO_CLIENT_OR_FAIL
                            (XML_INTERNAL_ERROR ("modify_task"));
                          log_event_fail ("task", "Task",
                                          modify_task_data->task_id,
                                          "modified");
                      }
                  }
                else if (strcmp (modify_task_data->action, "remove") == 0)
                  {
                    switch (manage_task_remove_file (modify_task_data->task_id,
                                                     modify_task_data->file_name))
                      {
                        case 0:
                          log_event ("task", "Task", modify_task_data->task_id,
                                     "modified");
                          SEND_TO_CLIENT_OR_FAIL (XML_OK ("modify_task"));
                          break;
                        case 1:
                          if (send_find_error_to_client ("modify_task", "Task",
                                                         modify_task_data->task_id,
                                                         gmp_parser))
                            {
                              error_send_to_client (error);
                              return;
                            }
                          break;
                        default:
                        case -1:
                          SEND_TO_CLIENT_OR_FAIL
                            (XML_INTERNAL_ERROR ("modify_task"));
                          log_event_fail ("task", "Task",
                                          modify_task_data->task_id,
                                          "modified");
                      }
                  }
                else
                  {
                    SEND_TO_CLIENT_OR_FAIL
                      (XML_ERROR_SYNTAX ("modify_task",
                                         "Action must be"
                                         " \"update\" or \"remove\""));
                    log_event_fail ("task", "Task",
                                    modify_task_data->task_id,
                                    "modified");
                  }
              }
            else switch (modify_task (modify_task_data->task_id,
                                      modify_task_data->name,
                                      modify_task_data->comment,
                                      modify_task_data->scanner_id,
                                      modify_task_data->target_id,
                                      modify_task_data->config_id,
                                      modify_task_data->observers,
                                      modify_task_data->alerts,
                                      modify_task_data->alterable,
                                      modify_task_data->groups,
                                      modify_task_data->schedule_id,
                                      modify_task_data->schedule_periods,
                                      modify_task_data->preferences,
                                      modify_task_data->hosts_ordering,
                                      &fail_alert_id,
                                      &fail_group_id))
              {
                case 0:
                  log_event ("task", "Task", modify_task_data->task_id,
                             "modified");
                  SEND_TO_CLIENT_OR_FAIL (XML_OK ("modify_task"));
                  break;
                case 1:
                  if (send_find_error_to_client ("modify_task", "Task",
                                                 modify_task_data->task_id,
                                                 gmp_parser))
                    {
                      error_send_to_client (error);
                      return;
                    }
                  break;
                case 2:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX
                     ("modify_task",
                      "Status must be New to edit scanner"));
                  break;
                case 3:
                  if (send_find_error_to_client
                       ("modify_task", "scanner",
                        modify_task_data->scanner_id, gmp_parser))
                    {
                      error_send_to_client (error);
                      return;
                    }
                  break;
                case 4:
                  if (send_find_error_to_client
                       ("modify_task", "config",
                        modify_task_data->config_id, gmp_parser))
                    {
                      error_send_to_client (error);
                      return;
                    }
                  break;
                case 5:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX
                     ("modify_task",
                      "Status must be New to edit config"));
                  break;
                case 6:
                case 7:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("modify_task",
                                      "User name error"));
                  log_event_fail ("task", "Task",
                                  modify_task_data->task_id,
                                  "modified");
                  break;
                case 8:
                  if (send_find_error_to_client ("modify_task", "alert",
                                                 fail_alert_id, gmp_parser))
                    {
                      error_send_to_client (error);
                      return;
                    }
                  log_event_fail ("task", "Task",
                                  modify_task_data->task_id,
                                  "modified");
                  break;
                case 9:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("modify_task",
                                      "Task must be New to modify"
                                      " Alterable state"));
                  log_event_fail ("task", "Task",
                                  modify_task_data->task_id,
                                  "modified");
                  break;
                case 10:
                  if (send_find_error_to_client ("modify_task", "group",
                                                 fail_group_id, gmp_parser))
                    {
                      error_send_to_client (error);
                      return;
                    }
                  log_event_fail ("task", "Task",
                                  modify_task_data->task_id,
                                  "modified");
                  break;
                case 11:
                  if (send_find_error_to_client
                       ("modify_task", "schedule",
                        modify_task_data->schedule_id, gmp_parser))
                    {
                      error_send_to_client (error);
                      return;
                    }
                  log_event_fail ("task", "Task",
                                  modify_task_data->task_id,
                                  "modified");
                  break;
                case 12:
                  if (send_find_error_to_client
                       ("modify_task", "target",
                        modify_task_data->target_id, gmp_parser))
                    {
                      error_send_to_client (error);
                      return;
                    }
                  log_event_fail ("task", "Task",
                                  modify_task_data->task_id,
                                  "modified");
                  break;
                case 13:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("modify_task",
                                      "Invalid auto_delete value"));
                  log_event_fail ("task", "Task",
                                  modify_task_data->task_id,
                                  "modified");
                  break;
                case 14:
                  SENDF_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("modify_task",
                                      "Auto Delete count out of range"
                                      " (must be from %d to %d)"),
                    AUTO_DELETE_KEEP_MIN, AUTO_DELETE_KEEP_MAX);
                  log_event_fail ("task", "Task",
                                  modify_task_data->task_id,
                                  "modified");
                  break;
                case 15:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("modify_task",
                                      "Config and Scanner types mismatch"));
                  log_event_fail ("task", "Task",
                                  modify_task_data->task_id,
                                  "modified");
                  break;
                case 16:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("modify_task",
                                      "Status must be New to edit Target"));
                  log_event_fail ("task", "Task",
                                  modify_task_data->task_id,
                                  "modified");
                  break;
                case 17:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("modify_task",
                                      "For container tasks only name, comment"
                                      " and observers can be modified"));
                  log_event_fail ("task", "Task",
                                  modify_task_data->task_id,
                                  "modified");
                  break;
                default:
                case -1:
                  SEND_TO_CLIENT_OR_FAIL
                    (XML_INTERNAL_ERROR ("modify_task"));
                  log_event_fail ("task", "Task",
                                  modify_task_data->task_id,
                                  "modified");
                  break;
              }
          }
        else
          SEND_TO_CLIENT_OR_FAIL
           (XML_ERROR_SYNTAX ("modify_task",
                              "A task_id attribute is required"));
        modify_task_data_reset (modify_task_data);
        set_client_state (CLIENT_AUTHENTIC);
        break;
      CLOSE (CLIENT_MODIFY_TASK, ALTERABLE);
      CLOSE (CLIENT_MODIFY_TASK, COMMENT);
      CLOSE (CLIENT_MODIFY_TASK, HOSTS_ORDERING);
      CLOSE (CLIENT_MODIFY_TASK, SCANNER);
      CLOSE (CLIENT_MODIFY_TASK, CONFIG);
      CLOSE (CLIENT_MODIFY_TASK, ALERT);
      CLOSE (CLIENT_MODIFY_TASK, NAME);
      CLOSE (CLIENT_MODIFY_TASK, OBSERVERS);
      CLOSE (CLIENT_MODIFY_TASK, PREFERENCES);
      CLOSE (CLIENT_MODIFY_TASK, SCHEDULE);
      CLOSE (CLIENT_MODIFY_TASK, SCHEDULE_PERIODS);
      CLOSE (CLIENT_MODIFY_TASK, TARGET);
      CLOSE (CLIENT_MODIFY_TASK, FILE);

      CLOSE (CLIENT_MODIFY_TASK_OBSERVERS, GROUP);

      case CLIENT_MODIFY_TASK_PREFERENCES_PREFERENCE:
        array_add (modify_task_data->preferences,
                   modify_task_data->preference);
        modify_task_data->preference = NULL;
        set_client_state (CLIENT_MODIFY_TASK_PREFERENCES);
        break;
      case CLIENT_MODIFY_TASK_PREFERENCES_PREFERENCE_NAME:
        set_client_state (CLIENT_MODIFY_TASK_PREFERENCES_PREFERENCE);
        break;
      CLOSE (CLIENT_MODIFY_TASK_PREFERENCES_PREFERENCE, VALUE);

      case CLIENT_MODIFY_TICKET:
        if (modify_ticket_element_end (gmp_parser, error, element_name))
          set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_MODIFY_TLS_CERTIFICATE:
        if (modify_tls_certificate_element_end (gmp_parser,
                                                error,
                                                element_name))
          set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_MODIFY_USER:
        {
          if ((modify_user_data->name == NULL
               && modify_user_data->user_id == NULL)
              || (modify_user_data->name
                  && (strlen (modify_user_data->name) == 0))
              || (modify_user_data->user_id
                  && (strlen (modify_user_data->user_id) == 0)))
            SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX
                                    ("modify_user",
                                     "A NAME or user_id is required"));
          else
            {
              gchar *fail_group_id, *fail_role_id, *errdesc;

              errdesc = NULL;

              switch (modify_user
                      (modify_user_data->user_id,
                       &modify_user_data->name,
                       modify_user_data->new_name,
                       ((modify_user_data->modify_password
                         && modify_user_data->password)
                         ? modify_user_data->password
                         /* Leave the password as it is. */
                         : NULL),
                       modify_user_data->comment,
                       modify_user_data->hosts,
                       modify_user_data->hosts_allow,
                       modify_user_data->sources,
                       modify_user_data->groups, &fail_group_id,
                       modify_user_data->roles, &fail_role_id,
                       &errdesc))
                {
                  case 0:
                    SEND_TO_CLIENT_OR_FAIL (XML_OK ("modify_user"));
                    break;
                  case 1:
                    if (send_find_error_to_client
                         ("modify_user", "group", fail_group_id, gmp_parser))
                      {
                        error_send_to_client (error);
                        return;
                      }
                    break;
                  case 2:
                    if (send_find_error_to_client
                         ("modify_user", "user",
                          modify_user_data->user_id ?: modify_user_data->name,
                          gmp_parser))
                      {
                        error_send_to_client (error);
                        return;
                      }
                    break;
                  case 3:
                    SEND_TO_CLIENT_OR_FAIL (XML_OK ("modify_user"));
                    log_event ("user", "User", modify_user_data->name,
                               "raised to Admin role");
                    break;
                  case 4:
                    SEND_TO_CLIENT_OR_FAIL (XML_OK ("modify_user"));
                    log_event ("user", "User", modify_user_data->name,
                               "downgraded from Admin role");
                    break;
                  case 5:
                    if (send_find_error_to_client
                         ("modify_user", "role", fail_role_id, gmp_parser))
                      {
                        error_send_to_client (error);
                        return;
                      }
                    break;
                  case 6:
                    SEND_TO_CLIENT_OR_FAIL
                     (XML_ERROR_SYNTAX ("modify_user",
                                        "Error in host specification"));
                    log_event_fail ("user", "User", NULL, "modified");
                    break;
                  case 7:
                    SEND_TO_CLIENT_OR_FAIL
                     (XML_ERROR_SYNTAX ("modify_user",
                                        "Error in user name"));
                    log_event_fail ("user", "User", NULL, "modified");
                    break;
                  case 8:
                    SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX
                                            ("modify_user",
                                             "User with name exists already"));
                    log_event_fail ("user", "User", NULL, "modified");
                    break;
                  case 99:
                    SEND_TO_CLIENT_OR_FAIL
                     (XML_ERROR_SYNTAX ("modify_user",
                                        "Permission denied"));
                    break;
                  case -2:
                    SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX
                                            ("modify_user", "Unknown role"));
                    break;
                  case -3:
                    SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX
                                            ("modify_user", "Error in SOURCES"));
                    break;
                  case -1:
                    if (errdesc)
                      {
                        char *buf = make_xml_error_syntax ("modify_user", errdesc);
                        SEND_TO_CLIENT_OR_FAIL (buf);
                        g_free (buf);
                        break;
                      }
                  /* Fall through.  */
                  default:
                    SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("modify_user"));
                    break;
                }
              g_free (errdesc);
            }
          modify_user_data_reset (modify_user_data);
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }
      CLOSE (CLIENT_MODIFY_USER, COMMENT);
      CLOSE (CLIENT_MODIFY_USER, GROUPS);
      CLOSE (CLIENT_MODIFY_USER_GROUPS, GROUP);
      CLOSE (CLIENT_MODIFY_USER, HOSTS);
      CLOSE (CLIENT_MODIFY_USER, NAME);
      CLOSE (CLIENT_MODIFY_USER, NEW_NAME);
      CLOSE (CLIENT_MODIFY_USER, PASSWORD);
      CLOSE (CLIENT_MODIFY_USER, ROLE);
      case CLIENT_MODIFY_USER_SOURCES:
        array_terminate (modify_user_data->sources);
        set_client_state (CLIENT_MODIFY_USER);
        break;
      case CLIENT_MODIFY_USER_SOURCES_SOURCE:
        array_add (modify_user_data->sources,
                   g_strdup (modify_user_data->current_source));
        g_free (modify_user_data->current_source);
        modify_user_data->current_source = NULL;
        set_client_state (CLIENT_MODIFY_USER_SOURCES);
        break;

      case CLIENT_MOVE_TASK:
        if (move_task_data->task_id == NULL
            || strcmp (move_task_data->task_id, "") == 0)
          {
            SEND_TO_CLIENT_OR_FAIL
              (XML_ERROR_SYNTAX ("move_task",
                                 "A non-empty task_id"
                                 " attribute is required"));
            break;
          }

        if (move_task_data->slave_id == NULL)
          {
            SEND_TO_CLIENT_OR_FAIL
              (XML_ERROR_SYNTAX ("move_task",
                                 "A slave_id attribute is required"));
            break;
          }

        switch (move_task (move_task_data->task_id,
                           move_task_data->slave_id))
          {
            case 0:
              SEND_TO_CLIENT_OR_FAIL (XML_OK ("move_task"));
              break;
            case 2:
              if (send_find_error_to_client ("move_task",
                                              "Task",
                                              move_task_data->task_id,
                                              gmp_parser))
                {
                  error_send_to_client (error);
                  return;
                }
              break;
            case 3:
              if (send_find_error_to_client ("move_task",
                                              "Slave",
                                              move_task_data->slave_id,
                                              gmp_parser))
                {
                  error_send_to_client (error);
                  return;
                }
              break;
            case 4:
              SEND_TO_CLIENT_OR_FAIL
                (XML_ERROR_SYNTAX ("move_task",
                                   "Task must use an OpenVAS scanner to assign"
                                   " a slave."));
              break;
            case 5:
              SEND_TO_CLIENT_OR_FAIL
                (XML_ERROR_SYNTAX ("move_task",
                                   "Task cannot be stopped at the moment."));
              break;
            case 6:
              SEND_TO_CLIENT_OR_FAIL
                (XML_ERROR_SYNTAX ("move_task",
                                   "Scanner does not allow stopping"
                                   " the Task."));
              break;
            case 7:
              SEND_TO_CLIENT_OR_FAIL
                (XML_ERROR_SYNTAX ("move_task",
                                   "Destination scanner does not support"
                                   " slaves."));
              break;
            case 98:
              SEND_TO_CLIENT_OR_FAIL
                (XML_ERROR_SYNTAX ("move_task",
                                   "Permission to stop and resume denied"));
              break;
            case 99:
              SEND_TO_CLIENT_OR_FAIL
                (XML_ERROR_SYNTAX ("move_task",
                                   "Permission denied"));
              break;
            default: /* Programming error. */
              SEND_TO_CLIENT_OR_FAIL
                (XML_INTERNAL_ERROR ("move_task"));
              assert (0);
              break;
          }
          move_task_data_reset (move_task_data);
          set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_TEST_ALERT:
        if (test_alert_data->alert_id)
          {
            gchar *script_message = NULL;
            switch (manage_test_alert (test_alert_data->alert_id,
                                       &script_message))
              {
                case 0:
                  SEND_TO_CLIENT_OR_FAIL (XML_OK ("test_alert"));
                  break;
                case 1:
                  if (send_find_error_to_client
                       ("test_alert", "alert", test_alert_data->alert_id,
                        gmp_parser))
                    {
                      error_send_to_client (error);
                      return;
                    }
                  break;
                case 99:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("test_alert",
                                      "Permission denied"));
                  break;
                case 2:
                case -1:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_INTERNAL_ERROR ("test_alert"));
                  break;
                case -2:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("test_alert",
                                      "Failed to find report format for"
                                      " alert"));
                  break;
                case -3:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("test_alert",
                                      "Failed to find filter for alert"));
                  break;
                case -4:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("test_alert",
                                      "Failed to find credential for alert"));
                  break;
                case -5:
                  if (script_message)
                    {
                      gchar *msg;
                      msg = g_markup_printf_escaped
                              ("<test_alert_response status=\"400\""
                               " status_text=\"Alert script failed\">"
                               "<status_details>%s</status_details>"
                               "</test_alert_response>",
                               script_message);

                      if (send_to_client (msg, gmp_parser->client_writer,
                                          gmp_parser->client_writer_data))
                        {
                          error_send_to_client (error);
                          g_free (msg);
                          return;
                        }
                      g_free (msg);
                    }
                  else
                    {
                      SEND_TO_CLIENT_OR_FAIL
                      (XML_ERROR_SYNTAX ("test_alert",
                                         "Alert script failed"));
                    }
                  break;
                default: /* Programming error. */
                  assert (0);
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_INTERNAL_ERROR ("test_alert"));
                  break;
              }
          }
        else
          SEND_TO_CLIENT_OR_FAIL
           (XML_ERROR_SYNTAX ("test_alert",
                              "An alert_id"
                              " attribute is required"));
        test_alert_data_reset (test_alert_data);
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_RESTORE:
        if (restore_data->id)
          {
            switch (manage_restore (restore_data->id))
              {
                case 0:
                  SEND_TO_CLIENT_OR_FAIL (XML_OK ("restore"));
                  log_event ("resource", "Resource", restore_data->id,
                             "restored");
                  break;
                case 1:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("restore",
                                      "Resource refers into trashcan"));
                  break;
                case 2:
                  if (send_find_error_to_client ("restore", "resource",
                                                 restore_data->id, gmp_parser))
                    {
                      error_send_to_client (error);
                      return;
                    }
                  break;
                case 3:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("restore",
                                      "A resource with this name exists"
                                      " already"));
                  break;
                case 4:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("restore",
                                      "A resource with this UUID exists"
                                      " already"));
                  break;
                case 99:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("restore",
                                      "Permission denied"));
                  break;
                default:  /* Programming error. */
                  assert (0);
                case -1:
                  SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("restore"));
                  break;
              }
          }
        else
          SEND_TO_CLIENT_OR_FAIL
           (XML_ERROR_SYNTAX ("restore",
                              "An id attribute is required"));
        restore_data_reset (restore_data);
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_RESUME_TASK:
        if (resume_task_data->task_id)
          {
            char *report_id;
            switch (resume_task (resume_task_data->task_id, &report_id))
              {
                case 0:
                  {
                    gchar *msg;
                    msg = g_strdup_printf
                           ("<resume_task_response"
                            " status=\"" STATUS_OK_REQUESTED "\""
                            " status_text=\""
                            STATUS_OK_REQUESTED_TEXT
                            "\">"
                            "<report_id>%s</report_id>"
                            "</resume_task_response>",
                            report_id);
                    free (report_id);
                    if (send_to_client (msg,
                                        write_to_client,
                                        write_to_client_data))
                      {
                        g_free (msg);
                        error_send_to_client (error);
                        return;
                      }
                    g_free (msg);
                  }
                  log_event ("task", "Task",
                             resume_task_data->task_id,
                             "resumed");
                  break;
                case 1:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("resume_task",
                                      "Task is active already"));
                  log_event_fail ("task", "Task",
                                  resume_task_data->task_id,
                                  "resumed");
                  break;
                case 22:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("resume_task",
                                      "Task must be in Stopped or Interrupted state"));
                  log_event_fail ("task", "Task",
                                  resume_task_data->task_id,
                                  "resumed");
                  break;
                case 4:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("resume_task",
                                      "Resuming not supported"));
                  log_event_fail ("task", "Task",
                                  resume_task_data->task_id,
                                  "resumed");
                  break;
                case 3:   /* Find failed. */
                  if (send_find_error_to_client
                       ("resume_task", "task", resume_task_data->task_id,
                        gmp_parser))
                    {
                      error_send_to_client (error);
                      return;
                    }
                  break;
                case 99:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("resume_task",
                                      "Permission denied"));
                  log_event_fail ("task", "Task",
                                  resume_task_data->task_id,
                                  "resumed");
                  break;
                case -6:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("resume_task",
                                      "There is already a task running in"
                                      " this process"));
                  log_event_fail ("task", "Task",
                                  resume_task_data->task_id,
                                  "resumed");
                  break;
                case -2:
                  /* Task target lacks hosts.  This is checked when the
                   * target is created. */
                  assert (0);
                  /* fallthrough */
                case -4:
                  /* Task lacks target.  This is checked when the task is
                   * created anyway. */
                  assert (0);
                  /* fallthrough */
                case -1:
                case -3: /* Failed to create report. */
                  SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("resume_task"));
                  log_event_fail ("task", "Task",
                                  resume_task_data->task_id,
                                  "resumed");
                  break;
                case -5:
                  SEND_XML_SERVICE_DOWN ("resume_task");
                  log_event_fail ("task", "Task",
                                  resume_task_data->task_id,
                                  "resumed");
                  break;
                case -7:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("resume_task", "No CA certificate"));
                  log_event_fail ("task", "Task",
                                  resume_task_data->task_id,
                                  "resumed");
                  break;
                default: /* Programming error. */
                  assert (0);
                  SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("resume_task"));
                  log_event_fail ("task", "Task",
                                  resume_task_data->task_id,
                                  "resumed");
                  break;
              }
          }
        else
          SEND_TO_CLIENT_OR_FAIL
           (XML_ERROR_SYNTAX ("resume_task",
                              "A task_id"
                              " attribute is required"));
        resume_task_data_reset (resume_task_data);
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_RUN_WIZARD:
        if (run_wizard_data->name)
          {
            gchar *command_error, *command_error_code;
            gchar *response = NULL;
            int read_only;

            read_only = (run_wizard_data->read_only
                         && strcmp (run_wizard_data->read_only, "")
                         && strcmp (run_wizard_data->read_only, "0"));

            switch (manage_run_wizard (run_wizard_data->name,
                                       (int (*) (void *, gchar *, gchar **))
                                         process_gmp,
                                       gmp_parser,
                                       run_wizard_data->params,
                                       read_only,
                                       run_wizard_data->mode,
                                       &command_error,
                                       &command_error_code,
                                       &response))
              {
                case 0:
                  {
                    gchar *msg;
                    msg = g_strdup_printf
                           ("<run_wizard_response"
                            " status=\"%s\""
                            " status_text=\"%s\">"
                            "%s%s%s"
                            "</run_wizard_response>",
                            command_error_code ? command_error_code
                                               : STATUS_OK_REQUESTED,
                            command_error ? command_error
                                          : STATUS_OK_REQUESTED_TEXT,
                            response ? "<response>" : "",
                            response ? response : "",
                            response ? "</response>" : "");
                    if (send_to_client (msg,
                                        write_to_client,
                                        write_to_client_data))
                      {
                        g_free (msg);
                        g_free (response);
                        error_send_to_client (error);
                        return;
                      }
                    g_free (msg);
                    g_free (response);
                    if (run_wizard_data->read_only == 0)
                      log_event ("wizard", "Wizard", run_wizard_data->name,
                                "run");
                    break;
                  }

                case 1:
                  {
                    SEND_TO_CLIENT_OR_FAIL
                     (XML_ERROR_SYNTAX ("run_wizard",
                                        "NAME characters must be alphanumeric"
                                        " or underscore"));
                    run_wizard_data_reset (run_wizard_data);
                    set_client_state (CLIENT_AUTHENTIC);
                    break;
                  }

                case 4:
                case 6:
                  {
                    gchar *msg;
                    msg = g_strdup_printf
                           ("<run_wizard_response"
                            " status=\"%s\""
                            " status_text=\"%s\"/>",
                            command_error_code ? command_error_code
                                               : STATUS_ERROR_SYNTAX,
                            command_error ? command_error : "Internal Error");
                    if (command_error)
                      g_free (command_error);
                    if (send_to_client (msg,
                                        write_to_client,
                                        write_to_client_data))
                      {
                        g_free (msg);
                        error_send_to_client (error);
                        return;
                      }
                    g_free (msg);
                    log_event_fail ("wizard", "Wizard", run_wizard_data->name,
                                    "run");
                    break;
                  }

                case 5:
                  {
                    SEND_TO_CLIENT_OR_FAIL
                     (XML_ERROR_SYNTAX ("run_wizard",
                                        "Wizard is not marked as read only"));
                    break;
                  }

                case 99:
                  {
                    SEND_TO_CLIENT_OR_FAIL
                     (XML_ERROR_SYNTAX ("run_wizard",
                                        "Permission denied"));
                    break;
                  }

                case -1:
                  {
                    /* Internal error. */
                    SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("run_wizard"));
                    log_event_fail ("wizard", "Wizard", run_wizard_data->name,
                                    "run");
                    break;
                  }
              }
          }
        else
          SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX ("run_wizard",
                                                    "A NAME"
                                                    " element is required"));
        run_wizard_data_reset (run_wizard_data);
        set_client_state (CLIENT_AUTHENTIC);
        break;

      CLOSE (CLIENT_RUN_WIZARD, MODE);
      CLOSE (CLIENT_RUN_WIZARD, NAME);
      CLOSE (CLIENT_RUN_WIZARD, PARAMS);
      CLOSE (CLIENT_RUN_WIZARD_PARAMS_PARAM, NAME);
      CLOSE (CLIENT_RUN_WIZARD_PARAMS_PARAM, VALUE);

      case CLIENT_RUN_WIZARD_PARAMS_PARAM:
        array_add (run_wizard_data->params, run_wizard_data->param);
        run_wizard_data->param = NULL;
        set_client_state (CLIENT_RUN_WIZARD_PARAMS);
        break;

      case CLIENT_START_TASK:
        if (start_task_data->task_id)
          {
            char *report_id = NULL;

            switch (start_task (start_task_data->task_id, &report_id))
              {
                case 0:
                  {
                    gchar *msg;
                    msg = g_strdup_printf
                           ("<start_task_response"
                            " status=\"" STATUS_OK_REQUESTED "\""
                            " status_text=\""
                            STATUS_OK_REQUESTED_TEXT
                            "\">"
                            "<report_id>%s</report_id>"
                            "</start_task_response>",
                            report_id ?: "0");
                    g_free (report_id);
                    if (send_to_client (msg,
                                        write_to_client,
                                        write_to_client_data))
                      {
                        g_free (msg);
                        error_send_to_client (error);
                        return;
                      }
                    g_free (msg);
                    log_event ("task", "Task", start_task_data->task_id,
                               "requested to start");
                  }
                  break;
                case 1:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("start_task",
                                      "Task is active already"));
                  log_event_fail ("task", "Task",
                                  start_task_data->task_id,
                                  "started");
                  break;
                case 3:   /* Find failed. */
                  if (send_find_error_to_client ("start_task", "task",
                                                 start_task_data->task_id,
                                                 gmp_parser))
                    {
                      error_send_to_client (error);
                      return;
                    }
                  break;
                case 99:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("start_task",
                                      "Permission denied"));
                  log_event_fail ("task", "Task",
                                  start_task_data->task_id,
                                  "started");
                  break;
                case -2:
                  /* Task lacks target.  This is true for container
                   * tasks. */
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("start_task",
                                      "Task must have a target"));
                  log_event_fail ("task", "Task",
                                  start_task_data->task_id,
                                  "started");
                  break;
                case -4:
                  /* Task target lacks hosts.  This is checked when the
                   * target is created. */
                  assert (0);
                  /* fallthrough */
                case -9:
                  /* Fork failed. */
                  /* fallthrough */
                case -3: /* Failed to create report. */
                case -1:
                  SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("start_task"));
                  log_event_fail ("task", "Task",
                                  start_task_data->task_id,
                                  "started");
                  break;
                case -5:
                  SEND_XML_SERVICE_DOWN ("start_task");
                  log_event_fail ("task", "Task",
                                  start_task_data->task_id,
                                  "started");
                  break;
                case -6:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("start_task",
                                      "There is already a task running in"
                                      " this process"));
                  log_event_fail ("task", "Task",
                                  start_task_data->task_id,
                                  "started");
                  break;
                case -7:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("start_task", "No CA certificate"));
                  log_event_fail ("task", "Task",
                                  start_task_data->task_id,
                                  "started");
                  break;
                default: /* Programming error. */
                  assert (0);
                  SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("start_task"));
                  log_event_fail ("task", "Task",
                                  start_task_data->task_id,
                                  "started");
                  break;
              }
          }
        else
          SEND_TO_CLIENT_OR_FAIL
           (XML_ERROR_SYNTAX ("start_task",
                              "A task_id attribute is required"));
        start_task_data_reset (start_task_data);
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_STOP_TASK:
        if (stop_task_data->task_id)
          {
            switch (stop_task (stop_task_data->task_id))
              {
                case 0:   /* Stopped. */
                  SEND_TO_CLIENT_OR_FAIL (XML_OK ("stop_task"));
                  log_event ("task", "Task", stop_task_data->task_id,
                             "stopped");
                  break;
                case 1:   /* Stop requested. */
                  SEND_TO_CLIENT_OR_FAIL (XML_OK_REQUESTED ("stop_task"));
                  log_event ("task", "Task", stop_task_data->task_id,
                             "requested to stop");
                  break;
                case 3:   /* Find failed. */
                  if (send_find_error_to_client ("stop_task", "task",
                                                 stop_task_data->task_id,
                                                 gmp_parser))
                    {
                      error_send_to_client (error);
                      return;
                    }
                  break;
                case 99:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("stop_task",
                                      "Permission denied"));
                  log_event_fail ("task", "Task",
                                  stop_task_data->task_id,
                                  "stopped");
                  break;
                default:  /* Programming error. */
                  assert (0);
                case -1:
                  /* Some other error occurred. */
                  /** @todo Should respond with internal error. */
                  abort ();
              }
          }
        else
          SEND_TO_CLIENT_OR_FAIL
           (XML_ERROR_SYNTAX ("stop_task",
                              "A task_id attribute is required"));
        stop_task_data_reset (stop_task_data);
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_VERIFY_REPORT_FORMAT:
        if (verify_report_format_data->report_format_id)
          {
            switch (verify_report_format
                     (verify_report_format_data->report_format_id))
              {
                case 0:
                  SEND_TO_CLIENT_OR_FAIL (XML_OK ("verify_report_format"));
                  break;
                case 1:
                  if (send_find_error_to_client
                       ("verify_report_format", "report format",
                        verify_report_format_data->report_format_id,
                        gmp_parser))
                    {
                      error_send_to_client (error);
                      return;
                    }
                  break;
                case 99:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("verify_report_format",
                                      "Permission denied"));
                  break;
                default:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_INTERNAL_ERROR ("verify_report_format"));
                  break;
              }
          }
        else
          SEND_TO_CLIENT_OR_FAIL
           (XML_ERROR_SYNTAX ("verify_report_format",
                              "A report_format_id"
                              " attribute is required"));
        verify_report_format_data_reset (verify_report_format_data);
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_VERIFY_SCANNER:
        if (verify_scanner_data->scanner_id)
          {
            char *version = NULL;
            switch (verify_scanner (verify_scanner_data->scanner_id, &version))
              {
                case 0:
                  SENDF_TO_CLIENT_OR_FAIL
                   ("<verify_scanner_response status=\"" STATUS_OK "\""
                    " status_text=\"" STATUS_OK_TEXT "\">"
                    "<version>%s</version>"
                    "</verify_scanner_response>", version);
                  break;
                case 1:
                  if (send_find_error_to_client
                       ("verify_scanner", "scanner",
                        verify_scanner_data->scanner_id, gmp_parser))
                    {
                      error_send_to_client (error);
                      return;
                    }
                  break;
                case 2:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_UNAVAILABLE ("verify_scanner",
                                           "Service unavailable"));
                  break;
                case 3:
                  SENDF_TO_CLIENT_OR_FAIL
                   ("<verify_scanner_response status=\"%s\""
                    " status_text=\"Failed to authenticate\">"
                    "<version>%s</version>"
                    "</verify_scanner_response>",
                    STATUS_SERVICE_UNAVAILABLE,
                    version);
                  break;
                case 99:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("verify_scanner", "Permission denied"));
                  break;
                default:
                  SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR
                                           ("verify_scanner"));
                  break;
              }
          }
        else
          SEND_TO_CLIENT_OR_FAIL
           (XML_ERROR_SYNTAX ("verify_scanner",
                              "A scanner_id attribute is required"));
        verify_scanner_data_reset (verify_scanner_data);
        set_client_state (CLIENT_AUTHENTIC);
        break;

      default:
        assert (0);
        break;
    }
}

/**
 * @brief Append text to a var for a case in gmp_xml_hand_text.
 *
 * @param[in]  state  Parser state.
 * @param[in]  dest   Append destination.
 */
#define APPEND(state, dest)                      \
  case state:                                    \
    gvm_append_text (dest, text, text_len);  \
    break;

/**
 * @brief Handle the addition of text to a GMP XML element.
 *
 * React to the addition of text to the value of an XML element.
 * React according to the current value of \ref client_state,
 * usually appending the text to some part of the current task
 * with functions like gvm_append_text and \ref append_to_task_comment.
 *
 * @param[in]  context           Parser context.
 * @param[in]  text              The text.
 * @param[in]  text_len          Length of the text.
 * @param[in]  user_data         Dummy parameter.
 * @param[in]  error             Error parameter.
 */
static void
gmp_xml_handle_text (/* unused */ GMarkupParseContext* context,
                     const gchar *text,
                     gsize text_len,
                     /* unused */ gpointer user_data,
                     /* unused */ GError **error)
{
  if (text_len == 0) return;
  g_debug ("   XML   text: %s", text);
  switch (client_state)
    {
      case CLIENT_AUTHENTICATE_CREDENTIALS_USERNAME:
        append_to_credentials_username (&current_credentials, text, text_len);
        break;

      case CLIENT_AUTHENTICATE_CREDENTIALS_PASSWORD:
        append_to_credentials_password (&current_credentials, text, text_len);
        break;


      case CLIENT_MODIFY_CONFIG:
        modify_config_element_text (text, text_len);
        break;


      APPEND (CLIENT_MODIFY_CREDENTIAL_ALLOW_INSECURE,
              &modify_credential_data->allow_insecure);

      APPEND (CLIENT_MODIFY_CREDENTIAL_AUTH_ALGORITHM,
              &modify_credential_data->auth_algorithm);

      APPEND (CLIENT_MODIFY_CREDENTIAL_CERTIFICATE,
              &modify_credential_data->certificate);

      APPEND (CLIENT_MODIFY_CREDENTIAL_COMMENT,
              &modify_credential_data->comment);

      APPEND (CLIENT_MODIFY_CREDENTIAL_COMMUNITY,
              &modify_credential_data->community);

      APPEND (CLIENT_MODIFY_CREDENTIAL_KEY_PHRASE,
              &modify_credential_data->key_phrase);

      APPEND (CLIENT_MODIFY_CREDENTIAL_KEY_PRIVATE,
              &modify_credential_data->key_private);

      APPEND (CLIENT_MODIFY_CREDENTIAL_KEY_PUBLIC,
              &modify_credential_data->key_public);

      APPEND (CLIENT_MODIFY_CREDENTIAL_LOGIN,
              &modify_credential_data->login);

      APPEND (CLIENT_MODIFY_CREDENTIAL_NAME,
              &modify_credential_data->name);

      APPEND (CLIENT_MODIFY_CREDENTIAL_PASSWORD,
              &modify_credential_data->password);

      APPEND (CLIENT_MODIFY_CREDENTIAL_PRIVACY_ALGORITHM,
              &modify_credential_data->privacy_algorithm);

      APPEND (CLIENT_MODIFY_CREDENTIAL_PRIVACY_PASSWORD,
              &modify_credential_data->privacy_password);



      APPEND (CLIENT_MODIFY_REPORT_FORMAT_ACTIVE,
              &modify_report_format_data->active);

      APPEND (CLIENT_MODIFY_REPORT_FORMAT_NAME,
              &modify_report_format_data->name);

      APPEND (CLIENT_MODIFY_REPORT_FORMAT_SUMMARY,
              &modify_report_format_data->summary);

      APPEND (CLIENT_MODIFY_REPORT_FORMAT_PARAM_NAME,
              &modify_report_format_data->param_name);

      APPEND (CLIENT_MODIFY_REPORT_FORMAT_PARAM_VALUE,
              &modify_report_format_data->param_value);


      APPEND (CLIENT_MODIFY_SETTING_NAME,
              &modify_setting_data->name);

      APPEND (CLIENT_MODIFY_SETTING_VALUE,
              &modify_setting_data->value);


      APPEND (CLIENT_MODIFY_TASK_ALTERABLE,
              &modify_task_data->alterable);

      APPEND (CLIENT_MODIFY_TASK_COMMENT,
              &modify_task_data->comment);

      APPEND (CLIENT_MODIFY_TASK_HOSTS_ORDERING,
              &modify_task_data->hosts_ordering);

      APPEND (CLIENT_MODIFY_TASK_NAME,
              &modify_task_data->name);

      APPEND (CLIENT_MODIFY_TASK_OBSERVERS,
              &modify_task_data->observers);

      APPEND (CLIENT_MODIFY_TASK_FILE,
              &modify_task_data->file);

      APPEND (CLIENT_MODIFY_TASK_SCHEDULE_PERIODS,
              &modify_task_data->schedule_periods);


      APPEND (CLIENT_MODIFY_TASK_PREFERENCES_PREFERENCE_NAME,
              &modify_task_data->preference->name);

      APPEND (CLIENT_MODIFY_TASK_PREFERENCES_PREFERENCE_VALUE,
              &modify_task_data->preference->value);

      APPEND (CLIENT_MODIFY_USER_COMMENT,
              &modify_user_data->comment);

      APPEND (CLIENT_MODIFY_USER_HOSTS,
              &modify_user_data->hosts);

      APPEND (CLIENT_MODIFY_USER_NAME,
              &modify_user_data->name);

      APPEND (CLIENT_MODIFY_USER_NEW_NAME,
              &modify_user_data->new_name);

      APPEND (CLIENT_MODIFY_USER_PASSWORD,
              &modify_user_data->password);

      APPEND (CLIENT_MODIFY_USER_SOURCES_SOURCE,
              &modify_user_data->current_source);


      APPEND (CLIENT_CREATE_ASSET_ASSET_COMMENT,
              &create_asset_data->comment);

      APPEND (CLIENT_CREATE_ASSET_ASSET_NAME,
              &create_asset_data->name);

      APPEND (CLIENT_CREATE_ASSET_ASSET_TYPE,
              &create_asset_data->type);

      APPEND (CLIENT_CREATE_ASSET_REPORT_FILTER_TERM,
              &create_asset_data->filter_term);


      APPEND (CLIENT_CREATE_CREDENTIAL_ALLOW_INSECURE,
              &create_credential_data->allow_insecure);

      APPEND (CLIENT_CREATE_CREDENTIAL_AUTH_ALGORITHM,
              &create_credential_data->auth_algorithm);

      APPEND (CLIENT_CREATE_CREDENTIAL_CERTIFICATE,
              &create_credential_data->certificate);

      APPEND (CLIENT_CREATE_CREDENTIAL_COMMENT,
              &create_credential_data->comment);

      APPEND (CLIENT_CREATE_CREDENTIAL_COMMUNITY,
              &create_credential_data->community);

      APPEND (CLIENT_CREATE_CREDENTIAL_COPY,
              &create_credential_data->copy);

      APPEND (CLIENT_CREATE_CREDENTIAL_KEY_PHRASE,
              &create_credential_data->key_phrase);

      APPEND (CLIENT_CREATE_CREDENTIAL_KEY_PRIVATE,
              &create_credential_data->key_private);

      APPEND (CLIENT_CREATE_CREDENTIAL_KEY_PUBLIC,
              &create_credential_data->key_public);

      APPEND (CLIENT_CREATE_CREDENTIAL_LOGIN,
              &create_credential_data->login);

      APPEND (CLIENT_CREATE_CREDENTIAL_NAME,
              &create_credential_data->name);

      APPEND (CLIENT_CREATE_CREDENTIAL_PASSWORD,
              &create_credential_data->password);

      APPEND (CLIENT_CREATE_CREDENTIAL_PRIVACY_ALGORITHM,
              &create_credential_data->privacy_algorithm);

      APPEND (CLIENT_CREATE_CREDENTIAL_PRIVACY_PASSWORD,
              &create_credential_data->privacy_password);

      APPEND (CLIENT_CREATE_CREDENTIAL_TYPE,
              &create_credential_data->type);


      APPEND (CLIENT_CREATE_ALERT_ACTIVE,
              &create_alert_data->active);

      APPEND (CLIENT_CREATE_ALERT_COMMENT,
              &create_alert_data->comment);

      APPEND (CLIENT_CREATE_ALERT_COPY,
              &create_alert_data->copy);

      APPEND (CLIENT_CREATE_ALERT_CONDITION,
              &create_alert_data->condition);

      APPEND (CLIENT_CREATE_ALERT_EVENT,
              &create_alert_data->event);

      APPEND (CLIENT_CREATE_ALERT_METHOD,
              &create_alert_data->method);

      APPEND (CLIENT_CREATE_ALERT_NAME,
              &create_alert_data->name);


      APPEND (CLIENT_CREATE_ALERT_CONDITION_DATA,
              &create_alert_data->part_data);

      APPEND (CLIENT_CREATE_ALERT_EVENT_DATA,
              &create_alert_data->part_data);

      APPEND (CLIENT_CREATE_ALERT_METHOD_DATA,
              &create_alert_data->part_data);


      APPEND (CLIENT_CREATE_ALERT_CONDITION_DATA_NAME,
              &create_alert_data->part_name);

      APPEND (CLIENT_CREATE_ALERT_EVENT_DATA_NAME,
              &create_alert_data->part_name);

      APPEND (CLIENT_CREATE_ALERT_METHOD_DATA_NAME,
              &create_alert_data->part_name);


      case CLIENT_CREATE_CONFIG:
        create_config_element_text (text, text_len);
        break;


      APPEND (CLIENT_CREATE_FILTER_COMMENT,
              &create_filter_data->comment);

      APPEND (CLIENT_CREATE_FILTER_COPY,
              &create_filter_data->copy);

      APPEND (CLIENT_CREATE_FILTER_NAME,
              &create_filter_data->name);

      APPEND (CLIENT_CREATE_FILTER_TERM,
              &create_filter_data->term);

      APPEND (CLIENT_CREATE_FILTER_TYPE,
              &create_filter_data->type);


      APPEND (CLIENT_CREATE_GROUP_COMMENT,
              &create_group_data->comment);

      APPEND (CLIENT_CREATE_GROUP_COPY,
              &create_group_data->copy);

      APPEND (CLIENT_CREATE_GROUP_NAME,
              &create_group_data->name);

      APPEND (CLIENT_CREATE_GROUP_USERS,
              &create_group_data->users);


      APPEND (CLIENT_CREATE_NOTE_ACTIVE,
              &create_note_data->active);

      APPEND (CLIENT_CREATE_NOTE_COPY,
              &create_note_data->copy);

      APPEND (CLIENT_CREATE_NOTE_HOSTS,
              &create_note_data->hosts);

      APPEND (CLIENT_CREATE_NOTE_PORT,
              &create_note_data->port);

      APPEND (CLIENT_CREATE_NOTE_SEVERITY,
              &create_note_data->severity);

      APPEND (CLIENT_CREATE_NOTE_TEXT,
              &create_note_data->text);

      APPEND (CLIENT_CREATE_NOTE_THREAT,
              &create_note_data->threat);


      APPEND (CLIENT_CREATE_OVERRIDE_ACTIVE,
              &create_override_data->active);

      APPEND (CLIENT_CREATE_OVERRIDE_COPY,
              &create_override_data->copy);

      APPEND (CLIENT_CREATE_OVERRIDE_HOSTS,
              &create_override_data->hosts);

      APPEND (CLIENT_CREATE_OVERRIDE_NEW_SEVERITY,
              &create_override_data->new_severity);

      APPEND (CLIENT_CREATE_OVERRIDE_NEW_THREAT,
              &create_override_data->new_threat);

      APPEND (CLIENT_CREATE_OVERRIDE_PORT,
              &create_override_data->port);

      APPEND (CLIENT_CREATE_OVERRIDE_SEVERITY,
              &create_override_data->severity);

      APPEND (CLIENT_CREATE_OVERRIDE_TEXT,
              &create_override_data->text);

      APPEND (CLIENT_CREATE_OVERRIDE_THREAT,
              &create_override_data->threat);


      APPEND (CLIENT_CREATE_PERMISSION_COMMENT,
              &create_permission_data->comment);

      APPEND (CLIENT_CREATE_PERMISSION_COPY,
              &create_permission_data->copy);

      APPEND (CLIENT_CREATE_PERMISSION_NAME,
              &create_permission_data->name);

      APPEND (CLIENT_CREATE_PERMISSION_RESOURCE_TYPE,
              &create_permission_data->resource_type);

      APPEND (CLIENT_CREATE_PERMISSION_SUBJECT_TYPE,
              &create_permission_data->subject_type);


      case CLIENT_CREATE_PORT_LIST:
        create_port_list_element_text (text, text_len);
        break;


      APPEND (CLIENT_CREATE_PORT_RANGE_COMMENT,
              &create_port_range_data->comment);

      APPEND (CLIENT_CREATE_PORT_RANGE_END,
              &create_port_range_data->end);

      APPEND (CLIENT_CREATE_PORT_RANGE_START,
              &create_port_range_data->start);

      APPEND (CLIENT_CREATE_PORT_RANGE_TYPE,
              &create_port_range_data->type);


      APPEND (CLIENT_CREATE_REPORT_IN_ASSETS,
              &create_report_data->in_assets);

      APPEND (CLIENT_CREATE_REPORT_RR_ERRORS_ERROR_DESCRIPTION,
              &create_report_data->result_description);

      APPEND (CLIENT_CREATE_REPORT_RR_ERRORS_ERROR_HOST,
              &create_report_data->result_host);

      APPEND (CLIENT_CREATE_REPORT_RR_ERRORS_ERROR_HOST_HOSTNAME,
              &create_report_data->result_hostname);

      APPEND (CLIENT_CREATE_REPORT_RR_ERRORS_ERROR_SCAN_NVT_VERSION,
              &create_report_data->result_scan_nvt_version);

      APPEND (CLIENT_CREATE_REPORT_RR_ERRORS_ERROR_PORT,
              &create_report_data->result_port);

      APPEND (CLIENT_CREATE_REPORT_RR_HOST_END,
              &create_report_data->host_end);

      APPEND (CLIENT_CREATE_REPORT_RR_HOST_END_HOST,
              &create_report_data->host_end_host);

      APPEND (CLIENT_CREATE_REPORT_RR_HOST_START,
              &create_report_data->host_start);

      APPEND (CLIENT_CREATE_REPORT_RR_HOST_START_HOST,
              &create_report_data->host_start_host);


      APPEND (CLIENT_CREATE_REPORT_RR_SCAN_END,
              &create_report_data->scan_end);

      APPEND (CLIENT_CREATE_REPORT_RR_SCAN_START,
              &create_report_data->scan_start);


      APPEND (CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_DESCRIPTION,
              &create_report_data->result_description);

      APPEND (CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_HOST,
              &create_report_data->result_host);

      APPEND (CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_HOST_HOSTNAME,
              &create_report_data->result_hostname);

      APPEND (CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_SCAN_NVT_VERSION,
              &create_report_data->result_scan_nvt_version);

      APPEND (CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_PORT,
              &create_report_data->result_port);

      APPEND (CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_QOD_TYPE,
              &create_report_data->result_qod_type);

      APPEND (CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_QOD_VALUE,
              &create_report_data->result_qod);

      APPEND (CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_SEVERITY,
              &create_report_data->result_severity);

      APPEND (CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_THREAT,
              &create_report_data->result_threat);

      case CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_DETECTION_RESULT_DETAILS_DETAIL_NAME:
        gvm_append_text (&create_report_data->result_detection_name, text, text_len);
        break;
      case CLIENT_CREATE_REPORT_RR_RESULTS_RESULT_DETECTION_RESULT_DETAILS_DETAIL_VALUE:
        if (create_report_data->result_detection_name != NULL)
          {
            if (strcmp("product", create_report_data->result_detection_name) == 0)
              {
                gvm_append_text (&create_report_data->result_detection_product, text, text_len);
              }
            else if (strcmp("location", create_report_data->result_detection_name) == 0)
              {
                gvm_append_text (&create_report_data->result_detection_location, text, text_len);
              }
            else if (strcmp("source_oid", create_report_data->result_detection_name) == 0)
              {
                gvm_append_text (&create_report_data->result_detection_source_oid, text, text_len);
              }
            else if (strcmp("source_name", create_report_data->result_detection_name) == 0)
              {
                gvm_append_text (&create_report_data->result_detection_source_name, text, text_len);
              }
            free(create_report_data->result_detection_name);
            create_report_data->result_detection_name = NULL;

            if (create_report_data->result_detection_product &&
                    create_report_data->result_detection_location &&
                    create_report_data->result_detection_source_oid &&
                    create_report_data->result_detection_source_name)
              {

                detection_detail_t *detail = 
                    (detection_detail_t*) g_malloc (sizeof (detection_detail_t));
                if (detail)
                  {
                    detail->product = create_report_data->result_detection_product;
                    create_report_data->result_detection_product = NULL;
                    detail->location = create_report_data->result_detection_location;
                    create_report_data->result_detection_location = NULL;
                    detail->source_oid = create_report_data->result_detection_source_oid;
                    create_report_data->result_detection_source_oid = NULL;
                    detail->source_name = create_report_data->result_detection_source_name; 
                    create_report_data->result_detection_source_name = NULL;
                    array_add(create_report_data->result_detection, detail);
                  }
            }

 

        }
        break;
    
      APPEND (CLIENT_CREATE_REPORT_RR_H_DETAIL_NAME,
              &create_report_data->detail_name);

      APPEND (CLIENT_CREATE_REPORT_RR_H_DETAIL_VALUE,
              &create_report_data->detail_value);

      APPEND (CLIENT_CREATE_REPORT_RR_H_DETAIL_SOURCE_DESC,
              &create_report_data->detail_source_desc);

      APPEND (CLIENT_CREATE_REPORT_RR_H_DETAIL_SOURCE_NAME,
              &create_report_data->detail_source_name);

      APPEND (CLIENT_CREATE_REPORT_RR_H_DETAIL_SOURCE_TYPE,
              &create_report_data->detail_source_type);

      APPEND (CLIENT_CREATE_REPORT_RR_H_END,
              &create_report_data->host_end);

      APPEND (CLIENT_CREATE_REPORT_RR_H_IP,
              &create_report_data->ip);

      APPEND (CLIENT_CREATE_REPORT_RR_H_START,
              &create_report_data->host_start);


      case CLIENT_CREATE_REPORT_FORMAT:
        create_report_format_element_text (text, text_len);
        break;


      APPEND (CLIENT_CREATE_ROLE_COMMENT,
              &create_role_data->comment);

      APPEND (CLIENT_CREATE_ROLE_COPY,
              &create_role_data->copy);

      APPEND (CLIENT_CREATE_ROLE_NAME,
              &create_role_data->name);

      APPEND (CLIENT_CREATE_ROLE_USERS,
              &create_role_data->users);

      APPEND (CLIENT_CREATE_SCANNER_NAME,
              &create_scanner_data->name);

      APPEND (CLIENT_CREATE_SCANNER_COMMENT,
              &create_scanner_data->comment);

      APPEND (CLIENT_CREATE_SCANNER_COPY,
              &create_scanner_data->copy);

      APPEND (CLIENT_CREATE_SCANNER_HOST,
              &create_scanner_data->host);

      APPEND (CLIENT_CREATE_SCANNER_PORT,
              &create_scanner_data->port);

      APPEND (CLIENT_CREATE_SCANNER_TYPE,
              &create_scanner_data->type);

      APPEND (CLIENT_CREATE_SCANNER_CA_PUB,
              &create_scanner_data->ca_pub);


      APPEND (CLIENT_CREATE_SCHEDULE_COMMENT,
              &create_schedule_data->comment);

      APPEND (CLIENT_CREATE_SCHEDULE_COPY,
              &create_schedule_data->copy);

      APPEND (CLIENT_CREATE_SCHEDULE_ICALENDAR,
              &create_schedule_data->icalendar);

      APPEND (CLIENT_CREATE_SCHEDULE_NAME,
              &create_schedule_data->name);

      APPEND (CLIENT_CREATE_SCHEDULE_TIMEZONE,
              &create_schedule_data->timezone);


      APPEND (CLIENT_CREATE_TAG_ACTIVE,
              &create_tag_data->active);

      APPEND (CLIENT_CREATE_TAG_RESOURCES_TYPE,
              &create_tag_data->resource_type);

      APPEND (CLIENT_CREATE_TAG_COPY,
              &create_tag_data->copy);

      APPEND (CLIENT_CREATE_TAG_COMMENT,
              &create_tag_data->comment);

      APPEND (CLIENT_CREATE_TAG_NAME,
              &create_tag_data->name);

      APPEND (CLIENT_CREATE_TAG_VALUE,
              &create_tag_data->value);


      APPEND (CLIENT_CREATE_TARGET_EXCLUDE_HOSTS,
              &create_target_data->exclude_hosts);

      APPEND (CLIENT_CREATE_TARGET_REVERSE_LOOKUP_ONLY,
              &create_target_data->reverse_lookup_only);

      APPEND (CLIENT_CREATE_TARGET_REVERSE_LOOKUP_UNIFY,
              &create_target_data->reverse_lookup_unify);

      APPEND (CLIENT_CREATE_TARGET_ALIVE_TESTS,
              &create_target_data->alive_tests);

      APPEND (CLIENT_CREATE_TARGET_ALLOW_SIMULTANEOUS_IPS,
              &create_target_data->allow_simultaneous_ips);

      APPEND (CLIENT_CREATE_TARGET_COMMENT,
              &create_target_data->comment);

      APPEND (CLIENT_CREATE_TARGET_COPY,
              &create_target_data->copy);

      APPEND (CLIENT_CREATE_TARGET_HOSTS,
              &create_target_data->hosts);

      APPEND (CLIENT_CREATE_TARGET_NAME,
              &create_target_data->name);

      APPEND (CLIENT_CREATE_TARGET_PORT_RANGE,
              &create_target_data->port_range);

      APPEND (CLIENT_CREATE_TARGET_SSH_CREDENTIAL_PORT,
              &create_target_data->ssh_port);

      APPEND (CLIENT_CREATE_TARGET_SSH_LSC_CREDENTIAL_PORT,
              &create_target_data->ssh_lsc_port);


      APPEND (CLIENT_CREATE_TASK_ALTERABLE,
              &create_task_data->alterable);

      case CLIENT_CREATE_TASK_COMMENT:
        append_to_task_comment (create_task_data->task, text, text_len);
        break;

      APPEND (CLIENT_CREATE_TASK_HOSTS_ORDERING,
              &create_task_data->hosts_ordering);

      APPEND (CLIENT_CREATE_TASK_COPY,
              &create_task_data->copy);

      APPEND (CLIENT_CREATE_TASK_NAME,
              &create_task_data->name);

      APPEND (CLIENT_CREATE_TASK_OBSERVERS,
              &create_task_data->observers);

      APPEND (CLIENT_CREATE_TASK_PREFERENCES_PREFERENCE_NAME,
              &create_task_data->preference->name);

      APPEND (CLIENT_CREATE_TASK_PREFERENCES_PREFERENCE_VALUE,
              &create_task_data->preference->value);

      APPEND (CLIENT_CREATE_TASK_SCHEDULE_PERIODS,
              &create_task_data->schedule_periods);

      APPEND (CLIENT_CREATE_TASK_USAGE_TYPE,
              &create_task_data->usage_type);

      case CLIENT_CREATE_TICKET:
        create_ticket_element_text (text, text_len);
        break;

      case CLIENT_CREATE_TLS_CERTIFICATE:
        create_tls_certificate_element_text (text, text_len);
        break;


      APPEND (CLIENT_CREATE_USER_COMMENT,
              &create_user_data->comment);

      APPEND (CLIENT_CREATE_USER_COPY,
              &create_user_data->copy);

      APPEND (CLIENT_CREATE_USER_HOSTS,
              &create_user_data->hosts);

      APPEND (CLIENT_CREATE_USER_NAME,
              &create_user_data->name);

      APPEND (CLIENT_CREATE_USER_PASSWORD,
              &create_user_data->password);

      APPEND (CLIENT_CREATE_USER_SOURCES_SOURCE,
              &create_user_data->current_source);


      case CLIENT_GET_AGGREGATES_DATA_COLUMN:
        {
          GList *last = g_list_last (get_aggregates_data->data_columns);
          gchar *data_column = last->data;
          gvm_append_text (&data_column, text, text_len);
          last->data = data_column;
          break;
        }

      case CLIENT_GET_AGGREGATES_TEXT_COLUMN:
        {
          GList *last = g_list_last (get_aggregates_data->text_columns);
          gchar *text_column = last->data;
          gvm_append_text (&text_column, text, text_len);
          last->data = text_column;
          break;
        }


      case CLIENT_GET_LICENSE:
        get_license_element_text (text, text_len);
        break;


      APPEND (CLIENT_MODIFY_ALERT_NAME,
              &modify_alert_data->name);

      APPEND (CLIENT_MODIFY_ALERT_COMMENT,
              &modify_alert_data->comment);

      APPEND (CLIENT_MODIFY_ALERT_ACTIVE,
              &modify_alert_data->active);

      APPEND (CLIENT_MODIFY_ALERT_EVENT,
              &modify_alert_data->event);

      APPEND (CLIENT_MODIFY_ALERT_CONDITION,
              &modify_alert_data->condition);

      APPEND (CLIENT_MODIFY_ALERT_METHOD,
              &modify_alert_data->method);


      APPEND (CLIENT_MODIFY_ALERT_EVENT_DATA,
              &modify_alert_data->part_data);

      APPEND (CLIENT_MODIFY_ALERT_CONDITION_DATA,
              &modify_alert_data->part_data);

      APPEND (CLIENT_MODIFY_ALERT_METHOD_DATA,
              &modify_alert_data->part_data);


      APPEND (CLIENT_MODIFY_ALERT_EVENT_DATA_NAME,
              &modify_alert_data->part_name);

      APPEND (CLIENT_MODIFY_ALERT_CONDITION_DATA_NAME,
              &modify_alert_data->part_name);

      APPEND (CLIENT_MODIFY_ALERT_METHOD_DATA_NAME,
              &modify_alert_data->part_name);


      APPEND (CLIENT_MODIFY_ASSET_COMMENT,
              &modify_asset_data->comment);


      APPEND (CLIENT_MODIFY_AUTH_GROUP_AUTH_CONF_SETTING_KEY,
              &modify_auth_data->key);

      APPEND (CLIENT_MODIFY_AUTH_GROUP_AUTH_CONF_SETTING_VALUE,
              &modify_auth_data->value);


      APPEND (CLIENT_MODIFY_FILTER_COMMENT,
              &modify_filter_data->comment);

      APPEND (CLIENT_MODIFY_FILTER_NAME,
              &modify_filter_data->name);

      APPEND (CLIENT_MODIFY_FILTER_TERM,
              &modify_filter_data->term);

      APPEND (CLIENT_MODIFY_FILTER_TYPE,
              &modify_filter_data->type);


      APPEND (CLIENT_MODIFY_GROUP_COMMENT,
              &modify_group_data->comment);

      APPEND (CLIENT_MODIFY_GROUP_NAME,
              &modify_group_data->name);

      APPEND (CLIENT_MODIFY_GROUP_USERS,
              &modify_group_data->users);


      case CLIENT_MODIFY_LICENSE:
        modify_license_element_text (text, text_len);
        break;


      APPEND (CLIENT_MODIFY_NOTE_ACTIVE,
              &modify_note_data->active);

      APPEND (CLIENT_MODIFY_NOTE_HOSTS,
              &modify_note_data->hosts);

      APPEND (CLIENT_MODIFY_NOTE_PORT,
              &modify_note_data->port);

      APPEND (CLIENT_MODIFY_NOTE_SEVERITY,
              &modify_note_data->severity);

      APPEND (CLIENT_MODIFY_NOTE_TEXT,
              &modify_note_data->text);

      APPEND (CLIENT_MODIFY_NOTE_THREAT,
              &modify_note_data->threat);

      APPEND (CLIENT_MODIFY_NOTE_NVT,
              &modify_note_data->nvt_oid);


      APPEND (CLIENT_MODIFY_OVERRIDE_ACTIVE,
              &modify_override_data->active);

      APPEND (CLIENT_MODIFY_OVERRIDE_HOSTS,
              &modify_override_data->hosts);

      APPEND (CLIENT_MODIFY_OVERRIDE_NEW_SEVERITY,
              &modify_override_data->new_severity);

      APPEND (CLIENT_MODIFY_OVERRIDE_NEW_THREAT,
              &modify_override_data->new_threat);

      APPEND (CLIENT_MODIFY_OVERRIDE_PORT,
              &modify_override_data->port);

      APPEND (CLIENT_MODIFY_OVERRIDE_SEVERITY,
              &modify_override_data->severity);

      APPEND (CLIENT_MODIFY_OVERRIDE_TEXT,
              &modify_override_data->text);

      APPEND (CLIENT_MODIFY_OVERRIDE_THREAT,
              &modify_override_data->threat);


      APPEND (CLIENT_MODIFY_PERMISSION_COMMENT,
              &modify_permission_data->comment);

      APPEND (CLIENT_MODIFY_PERMISSION_NAME,
              &modify_permission_data->name);

      APPEND (CLIENT_MODIFY_PERMISSION_RESOURCE_TYPE,
              &modify_permission_data->resource_type);

      APPEND (CLIENT_MODIFY_PERMISSION_SUBJECT_TYPE,
              &modify_permission_data->subject_type);


      APPEND (CLIENT_MODIFY_PORT_LIST_COMMENT,
              &modify_port_list_data->comment);

      APPEND (CLIENT_MODIFY_PORT_LIST_NAME,
              &modify_port_list_data->name);


      APPEND (CLIENT_MODIFY_ROLE_COMMENT,
              &modify_role_data->comment);

      APPEND (CLIENT_MODIFY_ROLE_NAME,
              &modify_role_data->name);

      APPEND (CLIENT_MODIFY_ROLE_USERS,
              &modify_role_data->users);

      APPEND (CLIENT_MODIFY_SCANNER_COMMENT,
              &modify_scanner_data->comment);

      APPEND (CLIENT_MODIFY_SCANNER_NAME,
              &modify_scanner_data->name);

      APPEND (CLIENT_MODIFY_SCANNER_HOST,
              &modify_scanner_data->host);

      APPEND (CLIENT_MODIFY_SCANNER_PORT,
              &modify_scanner_data->port);

      APPEND (CLIENT_MODIFY_SCANNER_TYPE,
              &modify_scanner_data->type);

      APPEND (CLIENT_MODIFY_SCANNER_CA_PUB,
              &modify_scanner_data->ca_pub);


      APPEND (CLIENT_MODIFY_SCHEDULE_COMMENT,
              &modify_schedule_data->comment);

      APPEND (CLIENT_MODIFY_SCHEDULE_ICALENDAR,
              &modify_schedule_data->icalendar);

      APPEND (CLIENT_MODIFY_SCHEDULE_NAME,
              &modify_schedule_data->name);

      APPEND (CLIENT_MODIFY_SCHEDULE_TIMEZONE,
              &modify_schedule_data->timezone);


      APPEND (CLIENT_MODIFY_TAG_ACTIVE,
              &modify_tag_data->active);

      APPEND (CLIENT_MODIFY_TAG_RESOURCES_TYPE,
              &modify_tag_data->resource_type);

      APPEND (CLIENT_MODIFY_TAG_COMMENT,
              &modify_tag_data->comment);

      APPEND (CLIENT_MODIFY_TAG_NAME,
              &modify_tag_data->name);

      APPEND (CLIENT_MODIFY_TAG_VALUE,
              &modify_tag_data->value);


      APPEND (CLIENT_MODIFY_TARGET_EXCLUDE_HOSTS,
              &modify_target_data->exclude_hosts);

      APPEND (CLIENT_MODIFY_TARGET_REVERSE_LOOKUP_ONLY,
              &modify_target_data->reverse_lookup_only);

      APPEND (CLIENT_MODIFY_TARGET_REVERSE_LOOKUP_UNIFY,
              &modify_target_data->reverse_lookup_unify);

      APPEND (CLIENT_MODIFY_TARGET_ALIVE_TESTS,
              &modify_target_data->alive_tests);

      APPEND (CLIENT_MODIFY_TARGET_ALLOW_SIMULTANEOUS_IPS,
              &modify_target_data->allow_simultaneous_ips);

      APPEND (CLIENT_MODIFY_TARGET_COMMENT,
              &modify_target_data->comment);

      APPEND (CLIENT_MODIFY_TARGET_HOSTS,
              &modify_target_data->hosts);

      APPEND (CLIENT_MODIFY_TARGET_NAME,
              &modify_target_data->name);

      APPEND (CLIENT_MODIFY_TARGET_SSH_CREDENTIAL_PORT,
              &modify_target_data->ssh_port);

      APPEND (CLIENT_MODIFY_TARGET_SSH_LSC_CREDENTIAL_PORT,
              &modify_target_data->ssh_lsc_port);


      case CLIENT_MODIFY_TICKET:
        modify_ticket_element_text (text, text_len);
        break;

      case CLIENT_MODIFY_TLS_CERTIFICATE:
        modify_tls_certificate_element_text (text, text_len);
        break;

      APPEND (CLIENT_RUN_WIZARD_MODE,
              &run_wizard_data->mode);

      APPEND (CLIENT_RUN_WIZARD_NAME,
              &run_wizard_data->name);

      APPEND (CLIENT_RUN_WIZARD_PARAMS_PARAM_NAME,
              &run_wizard_data->param->name);

      APPEND (CLIENT_RUN_WIZARD_PARAMS_PARAM_VALUE,
              &run_wizard_data->param->value);


      default:
        /* Just pass over the text. */
        break;
    }
}

/**
 * @brief Handle a GMP XML parsing error.
 *
 * Simply leave the error for the caller of the parser to handle.
 *
 * @param[in]  context           Parser context.
 * @param[in]  error             The error.
 * @param[in]  user_data         Dummy parameter.
 */
static void
gmp_xml_handle_error (/* unused */ GMarkupParseContext* context,
                      GError *error,
                      /* unused */ gpointer user_data)
{
  g_debug ("   XML ERROR %s", error->message);
}


/* GMP input processor. */

/** @todo Most likely the client should get these from init_gmp_process
 *        inside an gmp_parser_t and should pass the gmp_parser_t to
 *        process_gmp_client_input.  process_gmp_client_input can pass then
 *        pass them on to the other Manager "libraries". */
extern char from_client[];
extern buffer_size_t from_client_start;
extern buffer_size_t from_client_end;

/**
 * @brief Initialise GMP library.
 *
 * @param[in]  log_config      Logging configuration list.
 * @param[in]  database        Location of manage database.
 * @param[in]  max_ips_per_target  Max number of IPs per target.
 * @param[in]  max_email_attachment_size  Max size of email attachments.
 * @param[in]  max_email_include_size     Max size of email inclusions.
 * @param[in]  max_email_message_size     Max size of email user message text.
 * @param[in]  fork_connection  Function to fork a connection to the GMP
 *                              daemon layer, or NULL.
 * @param[in]  skip_db_check    Skip DB check.
 *
 * @return 0 success, -1 error, -2 database is wrong version,
 *         -4 max_ips_per_target out of range.
 */
int
init_gmp (GSList *log_config, const db_conn_info_t *database,
          int max_ips_per_target, int max_email_attachment_size,
          int max_email_include_size, int max_email_message_size,
          manage_connection_forker_t fork_connection, int skip_db_check)
{
  g_log_set_handler (G_LOG_DOMAIN,
                     ALL_LOG_LEVELS,
                     (GLogFunc) gvm_log_func,
                     log_config);
  command_data_init (&command_data);
  return init_manage (log_config, database, max_ips_per_target,
                      max_email_attachment_size, max_email_include_size,
                      max_email_message_size,
                      fork_connection, skip_db_check);
}

/**
 * @brief Initialise GMP library data for a process.
 *
 * @param[in]  database          Location of manage database.
 * @param[in]  write_to_client       Function to write to client.
 * @param[in]  write_to_client_data  Argument to \p write_to_client.
 * @param[in]  disable               Commands to disable.
 *
 * This should run once per process, before the first call to \ref
 * process_gmp_client_input.
 */
void
init_gmp_process (const db_conn_info_t *database,
                  int (*write_to_client) (const char*, void*),
                  void* write_to_client_data, gchar **disable)
{
  client_state = CLIENT_TOP;
  command_data_init (&command_data);
  init_manage_process (database);
  manage_reset_currents ();
  /* Create the XML parser. */
  xml_parser.start_element = gmp_xml_handle_start_element;
  xml_parser.end_element = gmp_xml_handle_end_element;
  xml_parser.text = gmp_xml_handle_text;
  xml_parser.passthrough = NULL;
  xml_parser.error = gmp_xml_handle_error;
  /* Don't free xml_context because we likely are inside the parser that is
   * the context, which would cause Glib to freak out.  Just leak, the process
   * is going to exit after this anyway. */
  xml_context = g_markup_parse_context_new
                 (&xml_parser,
                  0,
                  gmp_parser_new (write_to_client, write_to_client_data,
                                  disable),
                  (GDestroyNotify) gmp_parser_free);
}

/**
 * @brief Process any XML available in \ref from_client.
 *
 * \if STATIC
 *
 * Call the XML parser and let the callback functions do the work
 * (\ref gmp_xml_handle_start_element, \ref gmp_xml_handle_end_element,
 * \ref gmp_xml_handle_text and \ref gmp_xml_handle_error).
 *
 * The callback functions will queue any replies for
 * the client in \ref to_client (using \ref send_to_client).
 *
 * \endif
 *
 * @return 0 success,
 *         -1 error,
 *         -4 XML syntax error.
 */
int
process_gmp_client_input ()
{
  gboolean success;
  GError* error = NULL;

  /* Terminate any pending transaction. (force close = TRUE). */
  manage_transaction_stop (TRUE);

  if (xml_context == NULL) return -1;

  success = g_markup_parse_context_parse (xml_context,
                                          from_client + from_client_start,
                                          from_client_end - from_client_start,
                                          &error);
  if (success == FALSE)
    {
      int err;
      if (error)
        {
          err = -4;
          if (g_error_matches (error,
                               G_MARKUP_ERROR,
                               G_MARKUP_ERROR_UNKNOWN_ELEMENT))
            g_debug ("   client error: G_MARKUP_ERROR_UNKNOWN_ELEMENT");
          else if (g_error_matches (error,
                                    G_MARKUP_ERROR,
                                    G_MARKUP_ERROR_INVALID_CONTENT))
            g_debug ("   client error: G_MARKUP_ERROR_INVALID_CONTENT");
          else if (g_error_matches (error,
                                    G_MARKUP_ERROR,
                                    G_MARKUP_ERROR_UNKNOWN_ATTRIBUTE))
            g_debug ("   client error: G_MARKUP_ERROR_UNKNOWN_ATTRIBUTE");
          else
            err = -1;
          g_info ("   Failed to parse client XML: %s", error->message);
          g_error_free (error);
        }
      else
        err = -1;
      /* In all error cases the caller must cease to call this function as it
       * would be too hard, if possible at all, to figure out the position of
       * start of the next command. */
      return err;
    }
  from_client_end = from_client_start = 0;
  return 0;
}

/**
 * @brief Buffer the response for process_gmp.
 *
 * @param[in]  msg     GMP response.
 * @param[in]  buffer  Buffer.
 *
 * @return TRUE if failed, else FALSE.
 */
static int
process_gmp_write (const char* msg, void* buffer)
{
  g_debug ("-> client internal: %s", msg);
  g_string_append ((GString*) buffer, msg);
  return FALSE;
}

/**
 * @brief Process an XML string.
 *
 * \if STATIC
 *
 * Call the XML parser and let the callback functions do the work
 * (\ref gmp_xml_handle_start_element, \ref gmp_xml_handle_end_element,
 * \ref gmp_xml_handle_text and \ref gmp_xml_handle_error).
 *
 * The callback functions will queue any replies for
 * the client in \ref to_client (using \ref send_to_client).
 *
 * \endif
 *
 * @param[in]  parser    Parser.
 * @param[in]  command   Command.
 * @param[in]  response  Response.
 *
 * @return 0 success,
 *         -4 XML syntax error.
 *         -1 error.
 */
static int
process_gmp (gmp_parser_t *parser, const gchar *command, gchar **response)
{
  gboolean success;
  GError* error = NULL;
  GString *buffer;
  int (*client_writer) (const char*, void*);
  void* client_writer_data;
  GMarkupParseContext *old_xml_context;
  client_state_t old_client_state;
  command_data_t old_command_data;

  /* Terminate any pending transaction. (force close = TRUE). */
  manage_transaction_stop (TRUE);

  if (response) *response = NULL;

  old_xml_context = xml_context;
  xml_context = g_markup_parse_context_new (&xml_parser, 0, parser, NULL);
  if (xml_context == NULL)
    {
      xml_context = old_xml_context;
      return -1;
    }

  old_command_data = command_data;
  command_data_init (&command_data);
  old_client_state = client_state;
  client_state = CLIENT_AUTHENTIC;
  buffer = g_string_new ("");
  client_writer = parser->client_writer;
  client_writer_data = parser->client_writer_data;
  parser->client_writer = process_gmp_write;
  parser->client_writer_data = buffer;
  success = g_markup_parse_context_parse (xml_context,
                                          command,
                                          strlen (command),
                                          &error);
  parser->client_writer = client_writer;
  parser->client_writer_data = client_writer_data;
  xml_context = old_xml_context;
  client_state = old_client_state;
  command_data = old_command_data;
  if (success == FALSE)
    {
      int err;
      if (error)
        {
          err = -4;
          if (g_error_matches (error,
                               G_MARKUP_ERROR,
                               G_MARKUP_ERROR_UNKNOWN_ELEMENT))
            g_debug ("   client error: G_MARKUP_ERROR_UNKNOWN_ELEMENT");
          else if (g_error_matches (error,
                                    G_MARKUP_ERROR,
                                    G_MARKUP_ERROR_INVALID_CONTENT))
            g_debug ("   client error: G_MARKUP_ERROR_INVALID_CONTENT");
          else if (g_error_matches (error,
                                    G_MARKUP_ERROR,
                                    G_MARKUP_ERROR_UNKNOWN_ATTRIBUTE))
            g_debug ("   client error: G_MARKUP_ERROR_UNKNOWN_ATTRIBUTE");
          else
            err = -1;
          g_info ("   Failed to parse client XML: %s", error->message);
          g_error_free (error);
        }
      else
        err = -1;
      return err;
    }

  if (response)
    *response = g_string_free (buffer, FALSE);
  else
    g_string_free (buffer, TRUE);

  return 0;
}
