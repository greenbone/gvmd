/* OpenVAS Manager
 * $Id$
 * Description: Module for OpenVAS Manager: the OMP library.
 *
 * Authors:
 * Matthew Mundell <matt@mundell.ukfsn.org>
 *
 * Copyright:
 * Copyright (C) 2009 Greenbone Networks GmbH
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * or, at your option, any later version as published by the Free
 * Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/**
 * @file  omp.c
 * @brief The OpenVAS Manager OMP library.
 *
 * This file defines an OpenVAS Management Protocol (OMP) library, for
 * implementing OpenVAS managers such as the OpenVAS Manager daemon.
 *
 * The library provides \ref process_omp_client_input.
 * This function parses a given string of OMP XML and tracks and manipulates
 * tasks in reaction to the OMP commands in the string.
 */

#include "omp.h"
#include "manage.h"
#include "otp.h"      // FIX for access to scanner_t scanner
#include "tracef.h"

#include <arpa/inet.h>
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <glib/gstdio.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <openvas/base/certificate.h>
#include <openvas/base/nvti.h>
#include <openvas/base/openvas_string.h>
#include <openvas/nvt_categories.h>
#include <openvas/openvas_logging.h>

#ifdef S_SPLINT_S
#include "splint.h"
#endif

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md    omp"


/* Helper functions. */

/** @brief Return the name of a category.
 *
 * @param  category  The number of the category.
 *
 * @return The name of the category.
 */
static const char*
category_name (int category)
{
  static const char *categories[] = { ACT_STRING_LIST_ALL };
  if (category >= ACT_FIRST && category <= ACT_END)
    {
      return categories[category];
    }
  return categories[ACT_UNKNOWN];
}

/** @brief Return the threat associated with a result type.
 *
 * @param  type  Result type.
 *
 * @return Threat name.
 */
static const char*
result_type_threat (const char* type)
{
  if (strcasecmp (type, "Security Hole") == 0)
    return "High";
  if (strcasecmp (type, "Security Warning") == 0)
    return "Medium";
  if (strcasecmp (type, "Security Note") == 0)
    return "Low";
  return "Log";
}

static gint
compare_ports_desc (gconstpointer arg_one, gconstpointer arg_two)
{
  gchar *one = *((gchar**) arg_one);
  gchar *two = *((gchar**) arg_two);
  return collate_message_type (NULL,
                               strlen (two), two,
                               strlen (one), one);
}

static gint
compare_ports_asc (gconstpointer arg_one, gconstpointer arg_two)
{
  gchar *one = *((gchar**) arg_one);
  gchar *two = *((gchar**) arg_two);
  return collate_message_type (NULL,
                               strlen (one), one,
                               strlen (two), two);
}

/**
 * @brief Make a global array.
 *
 * @return New array.
 */
static GPtrArray *
make_array ()
{
  return g_ptr_array_new ();
}

/**
 * @brief Push a string onto a global array.
 *
 * @param[in]  array   Array.
 * @param[in]  string  String.
 */
static void
array_add (GPtrArray *array, gchar* string)
{
  if (array) g_ptr_array_add (array, string);
}

/**
 * @brief Terminate a global array.
 */
static void
array_terminate (GPtrArray *array)
{
  if (array) g_ptr_array_add (array, NULL);
}

/**
 * @brief Free global array value.
 *
 * @param[in]  array  Pointer to array.
 */
static void
free_array (GPtrArray *array)
{
  int index = 0;
  gpointer item;
  while ((item = g_ptr_array_index (array, index++)))
    g_free (item);
  g_ptr_array_free (array, TRUE);
}

/** @todo Duplicated from lsc_user.c. */
/**
 * @brief Checks whether a file is a directory or not.
 *
 * This is a replacement for the g_file_test functionality which is reported
 * to be unreliable under certain circumstances, for example if this
 * application and glib are compiled with a different libc.
 *
 * @todo FIXME: handle symbolic links
 * @todo Move to libs?
 *
 * @param[in]  name  File name.
 *
 * @return 1 if parameter is directory, 0 if it is not, -1 if it does not
 *         exist or could not be accessed.
 */
static int
check_is_dir (const char *name)
{
  struct stat sb;

  if (stat (name, &sb))
    {
      return -1;
    }
  else
    {
      return (S_ISDIR (sb.st_mode));
    }
}

/** @todo Duplicated from lsc_user.c. */
/**
 * @brief Recursively removes files and directories.
 *
 * This function will recursively call itself to delete a path and any
 * contents of this path.
 *
 * @param[in]  pathname  Name of file to be deleted from filesystem.
 *
 * @return 0 if the name was successfully deleted, -1 if an error occurred.
 */
static int
file_utils_rmdir_rf (const gchar * pathname)
{
  if (check_is_dir (pathname) == 1)
    {
      GError *error = NULL;
      GDir *directory = g_dir_open (pathname, 0, &error);

      if (directory == NULL)
        {
          if (error)
            {
              g_warning ("g_dir_open(%s) failed - %s\n", pathname, error->message);
              g_error_free (error);
            }
          return -1;
        }
      else
        {
          int ret = 0;
          const gchar *entry = NULL;

          while ((entry = g_dir_read_name (directory)) != NULL && (ret == 0))
            {
              gchar *entry_path = g_build_filename (pathname, entry, NULL);
              ret = file_utils_rmdir_rf (entry_path);
              g_free (entry_path);
              if (ret != 0)
                {
                  g_warning ("Failed to remove %s from %s!", entry, pathname);
                  g_dir_close (directory);
                  return ret;
                }
            }
          g_dir_close (directory);
        }
    }

  return g_remove (pathname);
}


/* Help message. */

static char* help_text = "\n"
"    ABORT_TASK             Abort a running task.\n"
"    AUTHENTICATE           Authenticate with the manager.\n"
"    COMMANDS               Run a list of commands.\n"
"    CREATE_AGENT           Create an agent.\n"
"    CREATE_CONFIG          Create a config.\n"
"    CREATE_ESCALATOR       Create an escalator.\n"
"    CREATE_LSC_CREDENTIAL  Create a local security check credential.\n"
"    CREATE_TARGET          Create a target.\n"
"    CREATE_TASK            Create a task.\n"
"    DELETE_AGENT           Delete an agent.\n"
"    DELETE_CONFIG          Delete a config.\n"
"    DELETE_ESCALATOR       Delete an escalator.\n"
"    DELETE_LSC_CREDENTIAL  Delete a local security check credential.\n"
"    DELETE_REPORT          Delete a report.\n"
"    DELETE_TARGET          Delete a target.\n"
"    DELETE_TASK            Delete a task.\n"
"    GET_AGENTS             Get all agents.\n"
"    GET_CERTIFICATES       Get all available certificates.\n"
"    GET_CONFIGS            Get all configs.\n"
"    GET_DEPENDENCIES       Get dependencies for all available NVTs.\n"
"    GET_ESCALATORS         Get all escalators.\n"
"    GET_LSC_CREDENTIALS    Get all local security check credentials.\n"
"    GET_NVT_ALL            Get IDs and names of all available NVTs.\n"
"    GET_NVT_DETAILS        Get all details for all available NVTs.\n"
"    GET_NVT_FAMILIES       Get a list of all NVT families.\n"
"    GET_NVT_FEED_CHECKSUM  Get checksum for entire NVT collection.\n"
"    GET_PREFERENCES        Get preferences for all available NVTs.\n"
"    GET_REPORT             Get a report identified by its unique ID.\n"
"    GET_RULES              Get the rules for the authenticated user.\n"
"    GET_STATUS             Get task status information.\n"
"    GET_TARGETS            Get all targets.\n"
"    GET_VERSION            Get the OpenVAS Manager Protocol version.\n"
"    HELP                   Get this help text.\n"
"    MODIFY_CONFIG          Update an existing config.\n"
"    MODIFY_REPORT          Modify an existing report.\n"
"    MODIFY_TASK            Update an existing task.\n"
"    TEST_ESCALATOR         Run an escalator.\n"
"    START_TASK             Manually start an existing task.\n";


/* Status codes. */

/* HTTP status codes used:
 *
 *     200 OK
 *     201 Created
 *     202 Accepted
 *     400 Bad request
 *     401 Must auth
 *     404 Missing
 */

/**
 * @brief Response code for a syntax error.
 */
#define STATUS_ERROR_SYNTAX            "400"

/**
 * @brief Response code when authorisation is required.
 */
#define STATUS_ERROR_MUST_AUTH         "401"

/**
 * @brief Response code when authorisation is required.
 */
#define STATUS_ERROR_MUST_AUTH_TEXT    "Authenticate first"

/**
 * @brief Response code for a missing resource.
 */
#define STATUS_ERROR_MISSING           "404"

/**
 * @brief Response code text for a missing resource.
 */
#define STATUS_ERROR_MISSING_TEXT      "Resource missing"

/**
 * @brief Response code when authorisation failed.
 */
#define STATUS_ERROR_AUTH_FAILED       "400"

/**
 * @brief Response code text when authorisation failed.
 */
#define STATUS_ERROR_AUTH_FAILED_TEXT  "Authentication failed"

/**
 * @brief Response code on success.
 */
#define STATUS_OK                      "200"

/**
 * @brief Response code text on success.
 */
#define STATUS_OK_TEXT                 "OK"

/**
 * @brief Response code on success, when a resource is created.
 */
#define STATUS_OK_CREATED              "201"

/**
 * @brief Response code on success, when a resource is created.
 */
#define STATUS_OK_CREATED_TEXT         "OK, resource created"

/**
 * @brief Response code on success, when the operation will finish later.
 */
#define STATUS_OK_REQUESTED            "202"

/**
 * @brief Response code text on success, when the operation will finish later.
 */
#define STATUS_OK_REQUESTED_TEXT       "OK, request submitted"

/**
 * @brief Response code for an internal error.
 */
#define STATUS_INTERNAL_ERROR          "500"

/**
 * @brief Response code text for an internal error.
 */
#define STATUS_INTERNAL_ERROR_TEXT     "Internal error"

/**
 * @brief Response code when a service is down.
 */
#define STATUS_SERVICE_DOWN            "503"

/**
 * @brief Response code text when a service is down.
 */
#define STATUS_SERVICE_DOWN_TEXT       "Service temporarily down"


/* Global variables. */

/**
 * @brief Hack for returning forked process status from the callbacks.
 */
int current_error;

/**
 * @brief Hack for returning fork status to caller.
 */
int forked;

/**
 * @brief Generic array variable for communicating between the callbacks.
 */
GPtrArray *current_array_1;

/**
 * @brief Generic array variable for communicating between the callbacks.
 */
GPtrArray *current_array_2;

/**
 * @brief Generic array variable for communicating between the callbacks.
 */
GPtrArray *current_array_3;

/**
 * @brief Generic integer variable for communicating between the callbacks.
 */
int current_int_1;

/**
 * @brief Generic integer variable for communicating between the callbacks.
 */
int current_int_2;

/**
 * @brief Generic integer variable for communicating between the callbacks.
 */
int current_int_3;

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
 * @brief Current client task during commands like CREATE_TASK and MODIFY_TASK.
 */
/*@null@*/ /*@dependent@*/
static task_t current_client_task = (task_t) 0;

/**
 * @brief Current report or task UUID, during a few operations.
 */
static /*@null@*/ /*@only@*/ char*
current_uuid = NULL;

/**
 * @brief Current name of file, during MODIFY_TASK.
 */
static /*@null@*/ /*@only@*/ char*
current_name = NULL;

/**
 * @brief Current format of report, during GET_REPORT.
 */
static /*@null@*/ /*@only@*/ char*
current_format = NULL;

/**
 * @brief Parameter name during OMP MODIFY_TASK.
 */
static /*@null@*/ /*@only@*/ char*
modify_task_parameter = NULL;

/**
 * @brief Comment during OMP MODIFY_TASK.
 */
static /*@null@*/ /*@only@*/ char*
modify_task_comment = NULL;

/**
 * @brief File during OMP MODIFY_TASK.
 */
static /*@null@*/ /*@only@*/ char*
modify_task_file = NULL;

/**
 * @brief Name during OMP MODIFY_TASK.
 */
static /*@null@*/ /*@only@*/ char*
modify_task_name = NULL;

/**
 * @brief RC file during OMP MODIFY_TASK.
 */
static /*@null@*/ /*@only@*/ char*
modify_task_rcfile = NULL;

/**
 * @brief Parameter value during OMP MODIFY_TASK.
 */
static /*@null@*/ /*@only@*/ char*
modify_task_value = NULL;

/**
 * @brief Client input parsing context.
 */
static /*@null@*/ /*@only@*/ GMarkupParseContext*
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

  CLIENT_ABORT_TASK,
  // FIX
#if 0
  CLIENT_ABORT_TASK_CRITERION,
#endif
  CLIENT_AUTHENTICATE,
  CLIENT_AUTHENTIC_COMMANDS,
  CLIENT_COMMANDS,
  CLIENT_CREATE_AGENT,
  CLIENT_CREATE_AGENT_NAME,
  CLIENT_CREATE_AGENT_COMMENT,
  CLIENT_CREATE_AGENT_INSTALLER,
  CLIENT_CREATE_AGENT_HOWTO_INSTALL,
  CLIENT_CREATE_AGENT_HOWTO_USE,
  CLIENT_CREATE_CONFIG,
  CLIENT_CREATE_CONFIG_COMMENT,
  CLIENT_CREATE_CONFIG_COPY,
  CLIENT_CREATE_CONFIG_NAME,
  CLIENT_CREATE_CONFIG_RCFILE,
  CLIENT_CREATE_ESCALATOR,
  CLIENT_CREATE_ESCALATOR_COMMENT,
  CLIENT_CREATE_ESCALATOR_CONDITION,
  CLIENT_CREATE_ESCALATOR_CONDITION_DATA,
  CLIENT_CREATE_ESCALATOR_CONDITION_DATA_NAME,
  CLIENT_CREATE_ESCALATOR_EVENT,
  CLIENT_CREATE_ESCALATOR_EVENT_DATA,
  CLIENT_CREATE_ESCALATOR_EVENT_DATA_NAME,
  CLIENT_CREATE_ESCALATOR_METHOD,
  CLIENT_CREATE_ESCALATOR_METHOD_DATA,
  CLIENT_CREATE_ESCALATOR_METHOD_DATA_NAME,
  CLIENT_CREATE_ESCALATOR_NAME,
  CLIENT_CREATE_LSC_CREDENTIAL,
  CLIENT_CREATE_LSC_CREDENTIAL_COMMENT,
  CLIENT_CREATE_LSC_CREDENTIAL_NAME,
  CLIENT_CREATE_LSC_CREDENTIAL_PASSWORD,
  CLIENT_CREATE_LSC_CREDENTIAL_LOGIN,
  CLIENT_CREATE_TARGET,
  CLIENT_CREATE_TARGET_COMMENT,
  CLIENT_CREATE_TARGET_HOSTS,
  CLIENT_CREATE_TARGET_LSC_CREDENTIAL,
  CLIENT_CREATE_TARGET_NAME,
  CLIENT_CREATE_TASK,
  CLIENT_CREATE_TASK_COMMENT,
  CLIENT_CREATE_TASK_CONFIG,
  CLIENT_CREATE_TASK_ESCALATOR,
  CLIENT_CREATE_TASK_NAME,
  CLIENT_CREATE_TASK_RCFILE,
  CLIENT_CREATE_TASK_TARGET,
  CLIENT_CREDENTIALS,
  CLIENT_CREDENTIALS_PASSWORD,
  CLIENT_CREDENTIALS_USERNAME,
  CLIENT_DELETE_AGENT,
  CLIENT_DELETE_AGENT_NAME,
  CLIENT_DELETE_CONFIG,
  CLIENT_DELETE_CONFIG_NAME,
  CLIENT_DELETE_ESCALATOR,
  CLIENT_DELETE_ESCALATOR_NAME,
  CLIENT_DELETE_LSC_CREDENTIAL,
  CLIENT_DELETE_LSC_CREDENTIAL_NAME,
  CLIENT_DELETE_REPORT,
  CLIENT_DELETE_TASK,
  CLIENT_DELETE_TARGET,
  CLIENT_DELETE_TARGET_NAME,
  CLIENT_GET_AGENTS,
  CLIENT_GET_CERTIFICATES,
  CLIENT_GET_CONFIGS,
  CLIENT_GET_DEPENDENCIES,
  CLIENT_GET_ESCALATORS,
  CLIENT_GET_LSC_CREDENTIALS,
  CLIENT_GET_NVT_ALL,
  CLIENT_GET_NVT_DETAILS,
  CLIENT_GET_NVT_FAMILIES,
  CLIENT_GET_NVT_FEED_CHECKSUM,
  CLIENT_GET_PREFERENCES,
  CLIENT_GET_REPORT,
  CLIENT_GET_RULES,
  CLIENT_GET_STATUS,
  CLIENT_GET_TARGETS,
  CLIENT_HELP,
  CLIENT_MODIFY_REPORT,
  CLIENT_MODIFY_REPORT_PARAMETER,
  CLIENT_MODIFY_CONFIG,
  CLIENT_MODIFY_CONFIG_NAME,
  CLIENT_MODIFY_CONFIG_PREFERENCE,
  CLIENT_MODIFY_CONFIG_PREFERENCE_NAME,
  CLIENT_MODIFY_CONFIG_PREFERENCE_NVT,
  CLIENT_MODIFY_CONFIG_PREFERENCE_VALUE,
  CLIENT_MODIFY_CONFIG_FAMILY_SELECTION,
  CLIENT_MODIFY_CONFIG_FAMILY_SELECTION_FAMILY,
  CLIENT_MODIFY_CONFIG_FAMILY_SELECTION_FAMILY_ALL,
  CLIENT_MODIFY_CONFIG_FAMILY_SELECTION_FAMILY_GROWING,
  CLIENT_MODIFY_CONFIG_FAMILY_SELECTION_FAMILY_NAME,
  CLIENT_MODIFY_CONFIG_FAMILY_SELECTION_GROWING,
  CLIENT_MODIFY_CONFIG_NVT_SELECTION,
  CLIENT_MODIFY_CONFIG_NVT_SELECTION_FAMILY,
  CLIENT_MODIFY_CONFIG_NVT_SELECTION_NVT,
  CLIENT_MODIFY_TASK,
  CLIENT_MODIFY_TASK_COMMENT,
  CLIENT_MODIFY_TASK_FILE,
  CLIENT_MODIFY_TASK_NAME,
  CLIENT_MODIFY_TASK_PARAMETER,
  CLIENT_MODIFY_TASK_RCFILE,
  CLIENT_START_TASK,
  CLIENT_TEST_ESCALATOR,
  CLIENT_TEST_ESCALATOR_NAME,
  CLIENT_VERSION
} client_state_t;

/**
 * @brief The state of the client.
 */
static client_state_t client_state = CLIENT_TOP;

/**
 * @brief Set the client state.
 */
static void
set_client_state (client_state_t state)
{
  client_state = state;
  tracef ("   client state set: %i\n", client_state);
}


/* Communication. */

/**
 * @brief Send a response message to the client.
 *
 * Queue a message in \ref to_client.
 *
 * @param[in]  msg  The message, a string.
 *
 * @return TRUE if out of space in to_client, else FALSE.
 */
static gboolean
send_to_client (const char* msg)
{
  assert (to_client_end <= TO_CLIENT_BUFFER_SIZE);
  if (((buffer_size_t) TO_CLIENT_BUFFER_SIZE) - to_client_end
      < strlen (msg))
    {
      tracef ("   send_to_client out of space (%i < %i)\n",
              ((buffer_size_t) TO_CLIENT_BUFFER_SIZE) - to_client_end,
              strlen (msg));
      return TRUE;
    }

#if 1
  /** @todo FIX Temp hack to catch ISO chars sent by scanner. */
  {
    gsize size_dummy;
    gchar* msg_utf8 = msg ? g_convert (msg, strlen (msg),
                                       "UTF-8", "ISO_8859-1",
                                       NULL, &size_dummy, NULL)
                          : NULL;
    memmove (to_client + to_client_end, msg_utf8, strlen (msg_utf8));
    tracef ("-> client: %s\n", msg_utf8);
    to_client_end += strlen (msg_utf8);
    g_free (msg_utf8);
  }
#else /* 1 */
  memmove (to_client + to_client_end, msg, strlen (msg));
  tracef ("-> client: %s\n", msg);
  to_client_end += strlen (msg);
#endif /* not 1 */
  return FALSE;
}

/**
 * @brief Send an XML element error response message to the client.
 *
 * @param[in]  command  Command name.
 * @param[in]  element  Element name.
 *
 * @return TRUE if out of space in to_client, else FALSE.
 */
static gboolean
send_element_error_to_client (const char* command, const char* element)
{
  gchar *msg;
  gboolean ret;

  msg = g_strdup_printf ("<%s_response status=\""
                         STATUS_ERROR_SYNTAX
                         "\" status_text=\"Bogus element: %s\"/>",
                         command,
                         element);
  ret = send_to_client (msg);
  g_free (msg);
  return ret;
}

/**
 * @brief Send an XML find error response message to the client.
 *
 * @param[in]  command  Command name.
 * @param[in]  type     Resource type.
 * @param[in]  id       Resource ID.
 *
 * @return TRUE if out of space in to_client, else FALSE.
 */
static gboolean
send_find_error_to_client (const char* command, const char* type,
                           const char* id)
{
  gchar *msg;
  gboolean ret;

  msg = g_strdup_printf ("<%s_response status=\""
                         STATUS_ERROR_MISSING
                         "\" status_text=\"Failed to find %s '%s'\"/>",
                         command, type, id);
  ret = send_to_client (msg);
  g_free (msg);
  return ret;
}

/**
 * @brief Set an out of space parse error on a GError.
 *
 * @param [out]  error  The error.
 */
static void
error_send_to_client (GError** error)
{
  tracef ("   send_to_client out of space in to_client\n");
  g_set_error (error, G_MARKUP_ERROR, G_MARKUP_ERROR_PARSE,
               "Manager out of space for reply to client.");
}


/* XML parser handlers. */

/**
 * @brief Expand to XML for a STATUS_ERROR_SYNTAX response.
 *
 * @param  tag   Name of the command generating the response.
 * @param  text  Text for the status_text attribute of the response.
 */
#define XML_ERROR_SYNTAX(tag, text)                      \
 "<" tag "_response"                                     \
 " status=\"" STATUS_ERROR_SYNTAX "\""                   \
 " status_text=\"" text "\"/>"

/**
 * @brief Expand to XML for a STATUS_ERROR_MISSING response.
 *
 * @param  tag  Name of the command generating the response.
 */
#define XML_ERROR_MISSING(tag)                           \
 "<" tag "_response"                                     \
 " status=\"" STATUS_ERROR_MISSING "\""                  \
 " status_text=\"" STATUS_ERROR_MISSING_TEXT "\"/>"

/**
 * @brief Expand to XML for a STATUS_ERROR_AUTH_FAILED response.
 *
 * @param  tag  Name of the command generating the response.
 */
#define XML_ERROR_AUTH_FAILED(tag)                       \
 "<" tag "_response"                                     \
 " status=\"" STATUS_ERROR_AUTH_FAILED "\""              \
 " status_text=\"" STATUS_ERROR_AUTH_FAILED_TEXT "\"/>"

/**
 * @brief Expand to XML for a STATUS_OK response.
 *
 * @param  tag  Name of the command generating the response.
 */
#define XML_OK(tag)                                      \
 "<" tag "_response"                                     \
 " status=\"" STATUS_OK "\""                             \
 " status_text=\"" STATUS_OK_TEXT "\"/>"

/**
 * @brief Expand to XML for a STATUS_OK_CREATED response.
 *
 * @param  tag  Name of the command generating the response.
 */
#define XML_OK_CREATED(tag)                              \
 "<" tag "_response"                                     \
 " status=\"" STATUS_OK_CREATED "\""                     \
 " status_text=\"" STATUS_OK_CREATED_TEXT "\"/>"

/**
 * @brief Expand to XML for a STATUS_OK_REQUESTED response.
 *
 * @param  tag  Name of the command generating the response.
 */
#define XML_OK_REQUESTED(tag)                            \
 "<" tag "_response"                                     \
 " status=\"" STATUS_OK_REQUESTED "\""                   \
 " status_text=\"" STATUS_OK_REQUESTED_TEXT "\"/>"

/**
 * @brief Expand to XML for a STATUS_INTERNAL_ERROR response.
 *
 * @param  tag  Name of the command generating the response.
 */
#define XML_INTERNAL_ERROR(tag)                          \
 "<" tag "_response"                                     \
 " status=\"" STATUS_INTERNAL_ERROR "\""                 \
 " status_text=\"" STATUS_INTERNAL_ERROR_TEXT "\"/>"

/**
 * @brief Expand to XML for a STATUS_SERVICE_DOWN response.
 *
 * @param  tag  Name of the command generating the response.
 */
#define XML_SERVICE_DOWN(tag)                            \
 "<" tag "_response"                                     \
 " status=\"" STATUS_SERVICE_DOWN "\""                   \
 " status_text=\"" STATUS_SERVICE_DOWN_TEXT "\"/>"

/**
 * @brief Return number of hosts described by a hosts string.
 *
 * @param[in]  hosts  String describing hosts.
 *
 * @return Number of hosts, or -1 on error.
 */
int
max_hosts (const char *hosts)
{
  long count = 0;
  gchar** split = g_strsplit (hosts, ",", 0);
  gchar** point = split;

  // TODO: check for errors in "hosts"

  while (*point)
    {
      gchar* slash = strchr (*point, '/');
      if (slash)
        {
          slash++;
          if (*slash)
            {
              long int mask;
              struct in_addr addr;

              /* Convert text after slash to a bit netmask. */

              if (atoi (slash) > 32 && inet_aton (slash, &addr))
                {
                  in_addr_t haddr;

                  /* 192.168.200.0/255.255.255.252 */

                  haddr = ntohl (addr.s_addr);
                  mask = 32;
                  while ((haddr & 1) == 0)
                    {
                      mask--;
                      haddr = haddr >> 1;
                    }
                  if (mask < 8 || mask > 32) return -1;
                }
              else
                {
                  /* 192.168.200.0/30 */

                  errno = 0;
                  mask = strtol (slash, NULL, 10);
                  if (errno == ERANGE || mask < 8 || mask > 32) return -1;
                }

              /* Calculate number of hosts. */

              count += 1L << (32 - mask);
              /* Leave out the network and broadcast addresses. */
              if (mask < 31) count--;
            }
          else
            /* Just a trailing /. */
            count++;
        }
      else
        count++;
      point += 1;
    }
  return count;
}

/**
 * @brief Find an attribute in a parser callback list of attributes.
 *
 * @param[in]   attribute_names   List of names.
 * @param[in]   attribute_values  List of values.
 * @param[in]   attribute_name    Name of sought attribute.
 * @param[out]  attribute_value   Attribute value return.
 *
 * @return 1 if found, else 0.
 */
int
find_attribute (const gchar **attribute_names,
                const gchar **attribute_values,
                const char *attribute_name,
                const gchar **attribute_value)
{
  while (*attribute_names && *attribute_values)
    if (strcmp (*attribute_names, attribute_name))
      attribute_names++, attribute_values++;
    else
      {
        *attribute_value = *attribute_values;
        return 1;
      }
  return 0;
}

/** @cond STATIC */

/**
 * @brief Send response message to client, returning on fail.
 *
 * Queue a message in \ref to_client with \ref send_to_client.  On failure
 * call \ref error_send_to_client on a GError* called "error" and do a return.
 *
 * @param[in]   msg    The message, a string.
 */
#define SEND_TO_CLIENT_OR_FAIL(msg)                                          \
  do                                                                         \
    {                                                                        \
      if (send_to_client (msg))                                              \
        {                                                                    \
          error_send_to_client (error);                                      \
          return;                                                            \
        }                                                                    \
    }                                                                        \
  while (0)

/**
 * @brief Send response message to client, returning on fail.
 *
 * Queue a message in \ref to_client with \ref send_to_client.  On failure
 * call \ref error_send_to_client on a GError* called "error" and do a return.
 *
 * @param[in]   format    Format string for message.
 * @param[in]   args      Arguments for format string.
 */
#define SENDF_TO_CLIENT_OR_FAIL(format, args...)                             \
  do                                                                         \
    {                                                                        \
      gchar* msg = g_markup_printf_escaped (format , ## args);               \
      if (send_to_client (msg))                                              \
        {                                                                    \
          g_free (msg);                                                      \
          error_send_to_client (error);                                      \
          return;                                                            \
        }                                                                    \
      g_free (msg);                                                          \
    }                                                                        \
  while (0)

/** @endcond */

/** @todo Free globals when tags open, in case of duplicate tags. */
/**
 * @brief Handle the start of an OMP XML element.
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
 * @param[in]  attribute_names   XML attribute name.
 * @param[in]  attribute_values  XML attribute values.
 * @param[in]  user_data         Dummy parameter.
 * @param[in]  error             Error parameter.
 */
static void
omp_xml_handle_start_element (/*@unused@*/ GMarkupParseContext* context,
                              const gchar *element_name,
                              const gchar **attribute_names,
                              const gchar **attribute_values,
                              /*@unused@*/ gpointer user_data,
                              GError **error)
{
  tracef ("   XML  start: %s (%i)\n", element_name, client_state);

  switch (client_state)
    {
      case CLIENT_TOP:
      case CLIENT_COMMANDS:
        if (strcasecmp ("AUTHENTICATE", element_name) == 0)
          {
// FIX
#if 0
            assert (tasks == NULL);
            assert (current_credentials.username == NULL);
            assert (current_credentials.password == NULL);
#endif
            set_client_state (CLIENT_AUTHENTICATE);
          }
        else if (strcasecmp ("COMMANDS", element_name) == 0)
          {
            SENDF_TO_CLIENT_OR_FAIL
             ("<commands_response"
              " status=\"" STATUS_OK "\" status_text=\"" STATUS_OK_TEXT "\">");
            set_client_state (CLIENT_COMMANDS);
          }
        else
          {
            // TODO: If one of other commands, STATUS_ERROR_MUST_AUTH
            if (send_to_client
                 (XML_ERROR_SYNTAX ("omp",
                                    "First command must be AUTHENTICATE")))
              {
                error_send_to_client (error);
                return;
              }
            g_set_error (error, G_MARKUP_ERROR, G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Must authenticate first.");
          }
        break;

      case CLIENT_AUTHENTIC:
      case CLIENT_AUTHENTIC_COMMANDS:
        if (strcasecmp ("AUTHENTICATE", element_name) == 0)
          {
            // FIX Could check if reauthenticating current credentials, to
            // save the loading of the tasks.
            if (save_tasks ()) abort ();
            free_tasks ();
            free_credentials (&current_credentials);
            set_client_state (CLIENT_AUTHENTICATE);
          }
        else if (strcasecmp ("ABORT_TASK", element_name) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values,
                                "task_id", &attribute))
              openvas_append_string (&current_uuid, attribute);
            set_client_state (CLIENT_ABORT_TASK);
          }
        else if (strcasecmp ("COMMANDS", element_name) == 0)
          {
            SEND_TO_CLIENT_OR_FAIL
             ("<commands_response"
              " status=\"" STATUS_OK "\" status_text=\"" STATUS_OK_TEXT "\">");
            set_client_state (CLIENT_AUTHENTIC_COMMANDS);
          }
        else if (strcasecmp ("DELETE_AGENT", element_name) == 0)
          {
            assert (modify_task_name == NULL);
            openvas_append_string (&modify_task_name, "");
            set_client_state (CLIENT_DELETE_AGENT);
          }
        else if (strcasecmp ("DELETE_CONFIG", element_name) == 0)
          {
            assert (modify_task_name == NULL);
            openvas_append_string (&modify_task_name, "");
            set_client_state (CLIENT_DELETE_CONFIG);
          }
        else if (strcasecmp ("DELETE_ESCALATOR", element_name) == 0)
          {
            assert (modify_task_name == NULL);
            openvas_append_string (&modify_task_name, "");
            set_client_state (CLIENT_DELETE_ESCALATOR);
          }
        else if (strcasecmp ("DELETE_LSC_CREDENTIAL", element_name) == 0)
          {
            assert (modify_task_name == NULL);
            openvas_append_string (&modify_task_name, "");
            set_client_state (CLIENT_DELETE_LSC_CREDENTIAL);
          }
        else if (strcasecmp ("DELETE_REPORT", element_name) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values,
                                "report_id", &attribute))
              openvas_append_string (&current_uuid, attribute);
            set_client_state (CLIENT_DELETE_REPORT);
          }
        else if (strcasecmp ("DELETE_TARGET", element_name) == 0)
          {
            assert (modify_task_name == NULL);
            openvas_append_string (&modify_task_name, "");
            set_client_state (CLIENT_DELETE_TARGET);
          }
        else if (strcasecmp ("DELETE_TASK", element_name) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values,
                                "task_id", &attribute))
              openvas_append_string (&current_uuid, attribute);
            set_client_state (CLIENT_DELETE_TASK);
          }
        else if (strcasecmp ("GET_AGENTS", element_name) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values,
                                "name", &attribute))
              openvas_append_string (&current_uuid, attribute);
            if (find_attribute (attribute_names, attribute_values,
                                "format", &attribute))
              openvas_append_string (&current_format, attribute);
            if (find_attribute (attribute_names, attribute_values,
                                "sort_field", &attribute))
              openvas_append_string (&current_name, attribute);
            if (find_attribute (attribute_names, attribute_values,
                                "sort_order", &attribute))
              current_int_2 = strcmp (attribute, "descending");
            else
              current_int_2 = 1;
            set_client_state (CLIENT_GET_AGENTS);
          }
        else if (strcasecmp ("GET_CERTIFICATES", element_name) == 0)
          set_client_state (CLIENT_GET_CERTIFICATES);
        else if (strcasecmp ("GET_CONFIGS", element_name) == 0)
          {
            const gchar* attribute;
            assert (current_name == NULL);
            if (find_attribute (attribute_names, attribute_values,
                                "name", &attribute))
              openvas_append_string (&current_name, attribute);
            if (find_attribute (attribute_names, attribute_values,
                                "families", &attribute))
              current_int_1 = atoi (attribute);
            else
              current_int_1 = 0;
            if (find_attribute (attribute_names, attribute_values,
                                "sort_field", &attribute))
              openvas_append_string (&current_format, attribute);
            if (find_attribute (attribute_names, attribute_values,
                                "sort_order", &attribute))
              current_int_2 = strcmp (attribute, "descending");
            else
              current_int_2 = 1;
            if (find_attribute (attribute_names, attribute_values,
                                "preferences", &attribute))
              current_int_3 = atoi (attribute);
            else
              current_int_3 = 0;
            set_client_state (CLIENT_GET_CONFIGS);
          }
        else if (strcasecmp ("GET_DEPENDENCIES", element_name) == 0)
          set_client_state (CLIENT_GET_DEPENDENCIES);
        else if (strcasecmp ("GET_ESCALATORS", element_name) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values,
                                "name", &attribute))
              openvas_append_string (&current_name, attribute);
            if (find_attribute (attribute_names, attribute_values,
                                "sort_field", &attribute))
              openvas_append_string (&current_format, attribute);
            if (find_attribute (attribute_names, attribute_values,
                                "sort_order", &attribute))
              current_int_2 = strcmp (attribute, "descending");
            else
              current_int_2 = 1;
            set_client_state (CLIENT_GET_ESCALATORS);
          }
        else if (strcasecmp ("GET_LSC_CREDENTIALS", element_name) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values,
                                "name", &attribute))
              openvas_append_string (&current_uuid, attribute);
            if (find_attribute (attribute_names, attribute_values,
                                "format", &attribute))
              openvas_append_string (&current_format, attribute);
            if (find_attribute (attribute_names, attribute_values,
                                "sort_field", &attribute))
              openvas_append_string (&current_name, attribute);
            if (find_attribute (attribute_names, attribute_values,
                                "sort_order", &attribute))
              current_int_2 = strcmp (attribute, "descending");
            else
              current_int_2 = 1;
            set_client_state (CLIENT_GET_LSC_CREDENTIALS);
          }
        else if (strcasecmp ("GET_NVT_ALL", element_name) == 0)
          set_client_state (CLIENT_GET_NVT_ALL);
        else if (strcasecmp ("GET_NVT_FEED_CHECKSUM", element_name) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values,
                                "algorithm", &attribute))
              openvas_append_string (&current_uuid, attribute);
            set_client_state (CLIENT_GET_NVT_FEED_CHECKSUM);
          }
        else if (strcasecmp ("GET_NVT_DETAILS", element_name) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values,
                                "oid", &attribute))
              openvas_append_string (&current_uuid, attribute);
            if (find_attribute (attribute_names, attribute_values,
                                "config", &attribute))
              openvas_append_string (&current_name, attribute);
            if (find_attribute (attribute_names, attribute_values,
                                "family", &attribute))
              openvas_append_string (&current_format, attribute);
            if (find_attribute (attribute_names, attribute_values,
                                "sort_field", &attribute))
              openvas_append_string (&modify_task_value, attribute);
            if (find_attribute (attribute_names, attribute_values,
                                "sort_order", &attribute))
              current_int_2 = strcmp (attribute, "descending");
            else
              current_int_2 = 1;
            set_client_state (CLIENT_GET_NVT_DETAILS);
          }
        else if (strcasecmp ("GET_NVT_FAMILIES", element_name) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values,
                                "sort_order", &attribute))
              current_int_2 = strcmp (attribute, "descending");
            else
              current_int_2 = 1;
            set_client_state (CLIENT_GET_NVT_FAMILIES);
          }
        else if (strcasecmp ("GET_PREFERENCES", element_name) == 0)
          set_client_state (CLIENT_GET_PREFERENCES);
        else if (strcasecmp ("GET_REPORT", element_name) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values,
                                "report_id", &attribute))
              openvas_append_string (&current_uuid, attribute);

            if (find_attribute (attribute_names, attribute_values,
                                "format", &attribute))
              openvas_append_string (&current_format, attribute);

            if (find_attribute (attribute_names, attribute_values,
                                "first_result", &attribute))
              /* Subtract 1 to switch from 1 to 0 indexing. */
              current_int_1 = atoi (attribute) - 1;
            else
              current_int_1 = 0;

            if (find_attribute (attribute_names, attribute_values,
                                "max_results", &attribute))
              current_int_2 = atoi (attribute);
            else
              current_int_2 = -1;

            if (find_attribute (attribute_names, attribute_values,
                                "sort_field", &attribute))
              openvas_append_string (&current_name, attribute);

            if (find_attribute (attribute_names, attribute_values,
                                "sort_order", &attribute))
              current_int_3 = strcmp (attribute, "descending");
            else
              {
                if (current_name == NULL
                    || (strcmp (current_name, "type") == 0))
                  /* Normally it makes more sense to order type descending. */
                  current_int_3 = 0;
                else
                  current_int_3 = 1;
              }

            if (find_attribute (attribute_names, attribute_values,
                                "levels", &attribute))
              openvas_append_string (&modify_task_value, attribute);

            set_client_state (CLIENT_GET_REPORT);
          }
        else if (strcasecmp ("GET_RULES", element_name) == 0)
          set_client_state (CLIENT_GET_RULES);
        else if (strcasecmp ("GET_TARGETS", element_name) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values,
                                "name", &attribute))
              openvas_append_string (&current_name, attribute);
            if (find_attribute (attribute_names, attribute_values,
                                "sort_field", &attribute))
              openvas_append_string (&current_format, attribute);
            if (find_attribute (attribute_names, attribute_values,
                                "sort_order", &attribute))
              current_int_2 = strcmp (attribute, "descending");
            else
              current_int_2 = 1;
            set_client_state (CLIENT_GET_TARGETS);
          }
        else if (strcasecmp ("HELP", element_name) == 0)
          set_client_state (CLIENT_HELP);
        else if (strcasecmp ("MODIFY_CONFIG", element_name) == 0)
          set_client_state (CLIENT_MODIFY_CONFIG);
        else if (strcasecmp ("MODIFY_REPORT", element_name) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values,
                                "report_id", &attribute))
              openvas_append_string (&current_uuid, attribute);
            set_client_state (CLIENT_MODIFY_REPORT);
          }
        else if (strcasecmp ("MODIFY_TASK", element_name) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values,
                                "task_id", &attribute))
              openvas_append_string (&current_uuid, attribute);
            set_client_state (CLIENT_MODIFY_TASK);
          }
        else if (strcasecmp ("CREATE_AGENT", element_name) == 0)
          {
            assert (modify_task_comment == NULL);
            assert (modify_task_name == NULL);
            openvas_append_string (&modify_task_comment, "");
            openvas_append_string (&modify_task_name, "");
            openvas_append_string (&modify_task_file, "");
            openvas_append_string (&modify_task_parameter, "");
            openvas_append_string (&modify_task_value, "");
            set_client_state (CLIENT_CREATE_AGENT);
          }
        else if (strcasecmp ("CREATE_CONFIG", element_name) == 0)
          {
            assert (modify_task_comment == NULL);
            assert (modify_task_name == NULL);
            assert (modify_task_value == NULL);
            openvas_append_string (&modify_task_comment, "");
            openvas_append_string (&modify_task_name, "");
            set_client_state (CLIENT_CREATE_CONFIG);
          }
        else if (strcasecmp ("CREATE_ESCALATOR", element_name) == 0)
          {
            assert (current_array_1 == NULL);
            assert (current_array_2 == NULL);
            assert (current_array_3 == NULL);
            assert (current_format == NULL);
            assert (current_uuid == NULL);
            assert (modify_task_comment == NULL);
            assert (modify_task_name == NULL);
            assert (modify_task_parameter == NULL);
            assert (modify_task_rcfile == NULL);
            assert (modify_task_value == NULL);

            current_array_1 = make_array ();
            current_array_2 = make_array ();
            current_array_3 = make_array ();

            openvas_append_string (&current_format, "");
            openvas_append_string (&current_uuid, "");
            openvas_append_string (&modify_task_comment, "");
            openvas_append_string (&modify_task_name, "");
            openvas_append_string (&modify_task_parameter, "");
            openvas_append_string (&modify_task_rcfile, "");
            openvas_append_string (&modify_task_value, "");

            set_client_state (CLIENT_CREATE_ESCALATOR);
          }
        else if (strcasecmp ("CREATE_LSC_CREDENTIAL", element_name) == 0)
          {
            assert (modify_task_comment == NULL);
            assert (modify_task_name == NULL);
            openvas_append_string (&modify_task_comment, "");
            openvas_append_string (&modify_task_name, "");
            openvas_append_string (&current_name, "");
            set_client_state (CLIENT_CREATE_LSC_CREDENTIAL);
          }
        else if (strcasecmp ("CREATE_TASK", element_name) == 0)
          {
            assert (current_client_task == (task_t) 0);
            assert (modify_task_name == NULL);
            current_client_task = make_task (NULL, 0, NULL);
            if (current_client_task == (task_t) 0) abort (); // FIX
            openvas_append_string (&modify_task_name, "");
            set_client_state (CLIENT_CREATE_TASK);
          }
        else if (strcasecmp ("CREATE_TARGET", element_name) == 0)
          {
            assert (modify_task_comment == NULL);
            assert (modify_task_name == NULL);
            assert (modify_task_value == NULL);
            openvas_append_string (&modify_task_comment, "");
            openvas_append_string (&modify_task_name, "");
            openvas_append_string (&modify_task_value, "");
            set_client_state (CLIENT_CREATE_TARGET);
          }
        else if (strcasecmp ("GET_VERSION", element_name) == 0)
          set_client_state (CLIENT_VERSION);
        else if (strcasecmp ("TEST_ESCALATOR", element_name) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values,
                                "name", &attribute))
              openvas_append_string (&current_name, attribute);
            set_client_state (CLIENT_TEST_ESCALATOR);
          }
        else if (strcasecmp ("START_TASK", element_name) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values,
                                "task_id", &attribute))
              openvas_append_string (&current_uuid, attribute);
            set_client_state (CLIENT_START_TASK);
          }
        else if (strcasecmp ("GET_STATUS", element_name) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values,
                                "task_id", &attribute))
              openvas_append_string (&current_uuid, attribute);
            if (find_attribute (attribute_names, attribute_values,
                                "rcfile", &attribute))
              current_int_1 = atoi (attribute);
            else
              current_int_1 = 0;
            if (find_attribute (attribute_names, attribute_values,
                                "sort_field", &attribute))
              openvas_append_string (&current_format, attribute);
            if (find_attribute (attribute_names, attribute_values,
                                "sort_order", &attribute))
              current_int_2 = strcmp (attribute, "descending");
            else
              current_int_2 = 1;
            set_client_state (CLIENT_GET_STATUS);
          }
        else
          {
            if (send_to_client (XML_ERROR_SYNTAX ("omp", "Bogus command name")))
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
          set_client_state (CLIENT_CREDENTIALS);
        else
          {
            if (send_element_error_to_client ("authenticate", element_name))
              {
                error_send_to_client (error);
                return;
              }
            free_credentials (&current_credentials);
            set_client_state (CLIENT_TOP);
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
        break;

      case CLIENT_CREDENTIALS:
        if (strcasecmp ("USERNAME", element_name) == 0)
          set_client_state (CLIENT_CREDENTIALS_USERNAME);
        else if (strcasecmp ("PASSWORD", element_name) == 0)
          set_client_state (CLIENT_CREDENTIALS_PASSWORD);
        else
          {
            if (send_element_error_to_client ("authenticate", element_name))
              {
                error_send_to_client (error);
                return;
              }
            free_credentials (&current_credentials);
            set_client_state (CLIENT_TOP);
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
        break;

      case CLIENT_DELETE_AGENT:
        if (strcasecmp ("NAME", element_name) == 0)
          set_client_state (CLIENT_DELETE_AGENT_NAME);
        else
          {
            if (send_element_error_to_client ("delete_agent",
                                              element_name))
              {
                error_send_to_client (error);
                return;
              }
            set_client_state (CLIENT_AUTHENTIC);
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
        break;

      case CLIENT_DELETE_CONFIG:
        if (strcasecmp ("NAME", element_name) == 0)
          set_client_state (CLIENT_DELETE_CONFIG_NAME);
        else
          {
            if (send_element_error_to_client ("delete_config", element_name))
              {
                error_send_to_client (error);
                return;
              }
            set_client_state (CLIENT_AUTHENTIC);
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
        break;

      case CLIENT_DELETE_ESCALATOR:
        if (strcasecmp ("NAME", element_name) == 0)
          set_client_state (CLIENT_DELETE_ESCALATOR_NAME);
        else
          {
            if (send_element_error_to_client ("delete_escalator", element_name))
              {
                error_send_to_client (error);
                return;
              }
            set_client_state (CLIENT_AUTHENTIC);
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
        break;

      case CLIENT_DELETE_LSC_CREDENTIAL:
        if (strcasecmp ("NAME", element_name) == 0)
          set_client_state (CLIENT_DELETE_LSC_CREDENTIAL_NAME);
        else
          {
            if (send_element_error_to_client ("delete_lsc_credential",
                                              element_name))
              {
                error_send_to_client (error);
                return;
              }
            set_client_state (CLIENT_AUTHENTIC);
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
        break;

      case CLIENT_DELETE_REPORT:
        if (send_element_error_to_client ("delete_report", element_name))
          {
            error_send_to_client (error);
            return;
          }
        set_client_state (CLIENT_AUTHENTIC);
        g_set_error (error,
                     G_MARKUP_ERROR,
                     G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                     "Error");
        break;

      case CLIENT_DELETE_TARGET:
        if (strcasecmp ("NAME", element_name) == 0)
          set_client_state (CLIENT_DELETE_TARGET_NAME);
        else
          {
            if (send_element_error_to_client ("delete_target", element_name))
              {
                error_send_to_client (error);
                return;
              }
            set_client_state (CLIENT_AUTHENTIC);
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
        break;

      case CLIENT_DELETE_TASK:
        if (send_element_error_to_client ("delete_task", element_name))
          {
            error_send_to_client (error);
            return;
          }
        set_client_state (CLIENT_AUTHENTIC);
        g_set_error (error,
                     G_MARKUP_ERROR,
                     G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                     "Error");
        break;

      case CLIENT_GET_AGENTS:
          {
            if (send_element_error_to_client ("get_agents",
                                              element_name))
              {
                error_send_to_client (error);
                return;
              }
            set_client_state (CLIENT_AUTHENTIC);
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
        break;

      case CLIENT_GET_CERTIFICATES:
          {
            if (send_element_error_to_client ("get_certificates", element_name))
              {
                error_send_to_client (error);
                return;
              }
            set_client_state (CLIENT_AUTHENTIC);
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
        break;

      case CLIENT_GET_CONFIGS:
          {
            if (send_element_error_to_client ("get_configs", element_name))
              {
                error_send_to_client (error);
                return;
              }
            set_client_state (CLIENT_AUTHENTIC);
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
        break;

      case CLIENT_GET_DEPENDENCIES:
          {
            if (send_element_error_to_client ("get_dependencies", element_name))
              {
                error_send_to_client (error);
                return;
              }
            set_client_state (CLIENT_AUTHENTIC);
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
        break;

      case CLIENT_GET_ESCALATORS:
          {
            if (send_element_error_to_client ("get_escalators", element_name))
              {
                error_send_to_client (error);
                return;
              }
            set_client_state (CLIENT_AUTHENTIC);
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
        break;

      case CLIENT_GET_LSC_CREDENTIALS:
          {
            if (send_element_error_to_client ("get_lsc_credentials",
                                              element_name))
              {
                error_send_to_client (error);
                return;
              }
            set_client_state (CLIENT_AUTHENTIC);
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
        break;

      case CLIENT_GET_NVT_ALL:
          {
            if (send_element_error_to_client ("get_nvt_all", element_name))
              {
                error_send_to_client (error);
                return;
              }
            set_client_state (CLIENT_AUTHENTIC);
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
        break;

      case CLIENT_GET_NVT_FEED_CHECKSUM:
          {
            if (send_element_error_to_client ("get_nvt_feed_checksum",
                                              element_name))
              {
                error_send_to_client (error);
                return;
              }
            set_client_state (CLIENT_AUTHENTIC);
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
        break;

      case CLIENT_GET_NVT_DETAILS:
        if (send_element_error_to_client ("get_nvt_details", element_name))
          {
            error_send_to_client (error);
            return;
          }
        set_client_state (CLIENT_AUTHENTIC);
        g_set_error (error,
                     G_MARKUP_ERROR,
                     G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                     "Error");
        break;

      case CLIENT_GET_NVT_FAMILIES:
        if (send_element_error_to_client ("get_nvt_families", element_name))
          {
            error_send_to_client (error);
            return;
          }
        set_client_state (CLIENT_AUTHENTIC);
        g_set_error (error,
                     G_MARKUP_ERROR,
                     G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                     "Error");
        break;

      case CLIENT_GET_PREFERENCES:
          {
            if (send_element_error_to_client ("get_preferences", element_name))
              {
                error_send_to_client (error);
                return;
              }
            set_client_state (CLIENT_AUTHENTIC);
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
        break;

      case CLIENT_GET_REPORT:
        if (send_element_error_to_client ("get_report", element_name))
          {
            error_send_to_client (error);
            return;
          }
        set_client_state (CLIENT_AUTHENTIC);
        g_set_error (error,
                     G_MARKUP_ERROR,
                     G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                     "Error");
        break;

      case CLIENT_GET_RULES:
          {
            if (send_element_error_to_client ("get_rules", element_name))
              {
                error_send_to_client (error);
                return;
              }
            set_client_state (CLIENT_AUTHENTIC);
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
        break;

      case CLIENT_GET_TARGETS:
          {
            if (send_element_error_to_client ("get_targets", element_name))
              {
                error_send_to_client (error);
                return;
              }
            set_client_state (CLIENT_AUTHENTIC);
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
        break;

      case CLIENT_HELP:
        {
          if (send_element_error_to_client ("help", element_name))
            {
              error_send_to_client (error);
              return;
            }
          set_client_state (CLIENT_AUTHENTIC);
          g_set_error (error,
                       G_MARKUP_ERROR,
                       G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                       "Error");
        }
        break;

      case CLIENT_MODIFY_CONFIG:
        if (strcasecmp ("NAME", element_name) == 0)
          set_client_state (CLIENT_MODIFY_CONFIG_NAME);
        else if (strcasecmp ("FAMILY_SELECTION", element_name) == 0)
          {
            assert (current_array_1 == NULL);
            assert (current_array_2 == NULL);
            assert (current_array_3 == NULL);
            current_array_1 = make_array ();
            current_array_2 = make_array ();
            current_array_3 = make_array ();
            current_int_3 = 0; /* For GROWING entity, in case missing. */
            set_client_state (CLIENT_MODIFY_CONFIG_FAMILY_SELECTION);
          }
        else if (strcasecmp ("NVT_SELECTION", element_name) == 0)
          {
            assert (current_array_1 == NULL);
            current_array_1 = make_array ();
            set_client_state (CLIENT_MODIFY_CONFIG_NVT_SELECTION);
          }
        else if (strcasecmp ("PREFERENCE", element_name) == 0)
          set_client_state (CLIENT_MODIFY_CONFIG_PREFERENCE);
        else
          {
            if (send_element_error_to_client ("modify_config", element_name))
              {
                error_send_to_client (error);
                return;
              }
            set_client_state (CLIENT_AUTHENTIC);
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
        break;

      case CLIENT_MODIFY_CONFIG_NVT_SELECTION:
        if (strcasecmp ("FAMILY", element_name) == 0)
          {
            openvas_free_string_var (&modify_task_comment);
            set_client_state (CLIENT_MODIFY_CONFIG_NVT_SELECTION_FAMILY);
          }
        else if (strcasecmp ("NVT", element_name) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values,
                                "oid", &attribute))
              openvas_append_string (&current_uuid, attribute);
            set_client_state (CLIENT_MODIFY_CONFIG_NVT_SELECTION_NVT);
          }
        else
          {
            if (send_element_error_to_client ("modify_config", element_name))
              {
                error_send_to_client (error);
                return;
              }
            set_client_state (CLIENT_AUTHENTIC);
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
        break;

      case CLIENT_MODIFY_CONFIG_FAMILY_SELECTION:
        if (strcasecmp ("FAMILY", element_name) == 0)
          {
            openvas_free_string_var (&modify_task_comment);
            current_int_2 = 0; /* For ALL entity, in case missing. */
            current_int_1 = 0; /* For GROWING entity, in case missing. */
            set_client_state (CLIENT_MODIFY_CONFIG_FAMILY_SELECTION_FAMILY);
          }
        else if (strcasecmp ("GROWING", element_name) == 0)
          {
            openvas_free_string_var (&modify_task_comment);
            set_client_state (CLIENT_MODIFY_CONFIG_FAMILY_SELECTION_GROWING);
          }
        else
          {
            if (send_element_error_to_client ("modify_config", element_name))
              {
                error_send_to_client (error);
                return;
              }
            set_client_state (CLIENT_AUTHENTIC);
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
        break;

      case CLIENT_MODIFY_CONFIG_FAMILY_SELECTION_FAMILY:
        if (strcasecmp ("ALL", element_name) == 0)
          set_client_state
           (CLIENT_MODIFY_CONFIG_FAMILY_SELECTION_FAMILY_ALL);
        else if (strcasecmp ("GROWING", element_name) == 0)
          set_client_state
           (CLIENT_MODIFY_CONFIG_FAMILY_SELECTION_FAMILY_GROWING);
        else if (strcasecmp ("NAME", element_name) == 0)
          set_client_state (CLIENT_MODIFY_CONFIG_FAMILY_SELECTION_FAMILY_NAME);
        else
          {
            if (send_element_error_to_client ("modify_config", element_name))
              {
                error_send_to_client (error);
                return;
              }
            set_client_state (CLIENT_AUTHENTIC);
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
        break;

      case CLIENT_MODIFY_CONFIG_PREFERENCE:
        if (strcasecmp ("NAME", element_name) == 0)
          set_client_state (CLIENT_MODIFY_CONFIG_PREFERENCE_NAME);
        else if (strcasecmp ("NVT", element_name) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values,
                                "oid", &attribute))
              openvas_append_string (&current_uuid, attribute);
            set_client_state (CLIENT_MODIFY_CONFIG_PREFERENCE_NVT);
          }
        else if (strcasecmp ("VALUE", element_name) == 0)
          set_client_state (CLIENT_MODIFY_CONFIG_PREFERENCE_VALUE);
        else
          {
            if (send_element_error_to_client ("modify_config", element_name))
              {
                error_send_to_client (error);
                return;
              }
            set_client_state (CLIENT_AUTHENTIC);
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
        break;

      case CLIENT_MODIFY_REPORT:
        if (strcasecmp ("PARAMETER", element_name) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values,
                                "id", &attribute))
              openvas_append_string (&modify_task_parameter, attribute);
            set_client_state (CLIENT_MODIFY_REPORT_PARAMETER);
          }
        else
          {
            if (send_element_error_to_client ("modify_report", element_name))
              {
                error_send_to_client (error);
                return;
              }
            set_client_state (CLIENT_AUTHENTIC);
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
        break;

      case CLIENT_MODIFY_TASK:
        if (strcasecmp ("COMMENT", element_name) == 0)
          set_client_state (CLIENT_MODIFY_TASK_COMMENT);
        else if (strcasecmp ("NAME", element_name) == 0)
          set_client_state (CLIENT_MODIFY_TASK_NAME);
        else if (strcasecmp ("PARAMETER", element_name) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values,
                                "id", &attribute))
              openvas_append_string (&modify_task_parameter, attribute);
            set_client_state (CLIENT_MODIFY_TASK_PARAMETER);
          }
        else if (strcasecmp ("RCFILE", element_name) == 0)
          set_client_state (CLIENT_MODIFY_TASK_RCFILE);
        else if (strcasecmp ("FILE", element_name) == 0)
          {
            const gchar* attribute;
            assert (current_format == NULL);
            assert (current_name == NULL);
            if (find_attribute (attribute_names, attribute_values,
                                "name", &attribute))
              openvas_append_string (&current_name, attribute);
            if (find_attribute (attribute_names, attribute_values,
                                "action", &attribute))
              openvas_append_string (&current_format, attribute);
            else
              openvas_append_string (&current_format, "update");
            set_client_state (CLIENT_MODIFY_TASK_FILE);
          }
        else
          {
            if (send_element_error_to_client ("modify_task", element_name))
              {
                error_send_to_client (error);
                return;
              }
            set_client_state (CLIENT_AUTHENTIC);
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
        break;

      case CLIENT_ABORT_TASK:
#if 0
        if (strcasecmp ("CRITERION", element_name) == 0)
          set_client_state (CLIENT_ABORT_TASK_CRITERION);
#else
        if (0)
          ;
#endif
        else
          {
            if (send_element_error_to_client ("abort_task", element_name))
              {
                error_send_to_client (error);
                return;
              }
            set_client_state (CLIENT_AUTHENTIC);
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
        break;

      case CLIENT_CREATE_AGENT:
        if (strcasecmp ("COMMENT", element_name) == 0)
          set_client_state (CLIENT_CREATE_AGENT_COMMENT);
        else if (strcasecmp ("HOWTO_INSTALL", element_name) == 0)
          set_client_state (CLIENT_CREATE_AGENT_HOWTO_INSTALL);
        else if (strcasecmp ("HOWTO_USE", element_name) == 0)
          set_client_state (CLIENT_CREATE_AGENT_HOWTO_USE);
        else if (strcasecmp ("INSTALLER", element_name) == 0)
          set_client_state (CLIENT_CREATE_AGENT_INSTALLER);
        else if (strcasecmp ("NAME", element_name) == 0)
          set_client_state (CLIENT_CREATE_AGENT_NAME);
        else
          {
            if (send_element_error_to_client ("create_agent",
                                              element_name))
              {
                error_send_to_client (error);
                return;
              }
            set_client_state (CLIENT_AUTHENTIC);
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
        break;

      case CLIENT_CREATE_CONFIG:
        if (strcasecmp ("COMMENT", element_name) == 0)
          set_client_state (CLIENT_CREATE_CONFIG_COMMENT);
        else if (strcasecmp ("COPY", element_name) == 0)
          set_client_state (CLIENT_CREATE_CONFIG_COPY);
        else if (strcasecmp ("NAME", element_name) == 0)
          set_client_state (CLIENT_CREATE_CONFIG_NAME);
        else if (strcasecmp ("RCFILE", element_name) == 0)
          set_client_state (CLIENT_CREATE_CONFIG_RCFILE);
        else
          {
            if (send_element_error_to_client ("create_config", element_name))
              {
                error_send_to_client (error);
                return;
              }
            set_client_state (CLIENT_AUTHENTIC);
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
        break;

      case CLIENT_CREATE_ESCALATOR:
        if (strcasecmp ("COMMENT", element_name) == 0)
          set_client_state (CLIENT_CREATE_ESCALATOR_COMMENT);
        else if (strcasecmp ("CONDITION", element_name) == 0)
          set_client_state (CLIENT_CREATE_ESCALATOR_CONDITION);
        else if (strcasecmp ("EVENT", element_name) == 0)
          set_client_state (CLIENT_CREATE_ESCALATOR_EVENT);
        else if (strcasecmp ("METHOD", element_name) == 0)
          set_client_state (CLIENT_CREATE_ESCALATOR_METHOD);
        else if (strcasecmp ("NAME", element_name) == 0)
          set_client_state (CLIENT_CREATE_ESCALATOR_NAME);
        else
          {
            if (send_element_error_to_client ("create_escalator", element_name))
              {
                error_send_to_client (error);
                return;
              }
            set_client_state (CLIENT_AUTHENTIC);
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
        break;

      case CLIENT_CREATE_ESCALATOR_CONDITION:
        if (strcasecmp ("DATA", element_name) == 0)
          set_client_state (CLIENT_CREATE_ESCALATOR_CONDITION_DATA);
        else
          {
            if (send_element_error_to_client ("create_escalator", element_name))
              {
                error_send_to_client (error);
                return;
              }
            set_client_state (CLIENT_AUTHENTIC);
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
        break;

      case CLIENT_CREATE_ESCALATOR_CONDITION_DATA:
        if (strcasecmp ("NAME", element_name) == 0)
          set_client_state (CLIENT_CREATE_ESCALATOR_CONDITION_DATA_NAME);
        else
          {
            if (send_element_error_to_client ("create_escalator", element_name))
              {
                error_send_to_client (error);
                return;
              }
            set_client_state (CLIENT_AUTHENTIC);
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
        break;

      case CLIENT_CREATE_ESCALATOR_EVENT:
        if (strcasecmp ("DATA", element_name) == 0)
          set_client_state (CLIENT_CREATE_ESCALATOR_EVENT_DATA);
        else
          {
            if (send_element_error_to_client ("create_escalator", element_name))
              {
                error_send_to_client (error);
                return;
              }
            set_client_state (CLIENT_AUTHENTIC);
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
        break;

      case CLIENT_CREATE_ESCALATOR_EVENT_DATA:
        if (strcasecmp ("NAME", element_name) == 0)
          set_client_state (CLIENT_CREATE_ESCALATOR_EVENT_DATA_NAME);
        else
          {
            if (send_element_error_to_client ("create_escalator", element_name))
              {
                error_send_to_client (error);
                return;
              }
            set_client_state (CLIENT_AUTHENTIC);
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
        break;

      case CLIENT_CREATE_ESCALATOR_METHOD:
        if (strcasecmp ("DATA", element_name) == 0)
          set_client_state (CLIENT_CREATE_ESCALATOR_METHOD_DATA);
        else
          {
            if (send_element_error_to_client ("create_escalator", element_name))
              {
                error_send_to_client (error);
                return;
              }
            set_client_state (CLIENT_AUTHENTIC);
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
        break;

      case CLIENT_CREATE_ESCALATOR_METHOD_DATA:
        if (strcasecmp ("NAME", element_name) == 0)
          set_client_state (CLIENT_CREATE_ESCALATOR_METHOD_DATA_NAME);
        else
          {
            if (send_element_error_to_client ("create_escalator", element_name))
              {
                error_send_to_client (error);
                return;
              }
            set_client_state (CLIENT_AUTHENTIC);
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
        break;

      case CLIENT_CREATE_LSC_CREDENTIAL:
        if (strcasecmp ("COMMENT", element_name) == 0)
          set_client_state (CLIENT_CREATE_LSC_CREDENTIAL_COMMENT);
        else if (strcasecmp ("LOGIN", element_name) == 0)
          set_client_state (CLIENT_CREATE_LSC_CREDENTIAL_LOGIN);
        else if (strcasecmp ("NAME", element_name) == 0)
          set_client_state (CLIENT_CREATE_LSC_CREDENTIAL_NAME);
        else if (strcasecmp ("PASSWORD", element_name) == 0)
          set_client_state (CLIENT_CREATE_LSC_CREDENTIAL_PASSWORD);
        else
          {
            if (send_element_error_to_client ("create_lsc_credential",
                                              element_name))
              {
                error_send_to_client (error);
                return;
              }
            set_client_state (CLIENT_AUTHENTIC);
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
        break;

      case CLIENT_CREATE_TARGET:
        if (strcasecmp ("COMMENT", element_name) == 0)
          set_client_state (CLIENT_CREATE_TARGET_COMMENT);
        else if (strcasecmp ("HOSTS", element_name) == 0)
          set_client_state (CLIENT_CREATE_TARGET_HOSTS);
        else if (strcasecmp ("LSC_CREDENTIAL", element_name) == 0)
          set_client_state (CLIENT_CREATE_TARGET_LSC_CREDENTIAL);
        else if (strcasecmp ("NAME", element_name) == 0)
          set_client_state (CLIENT_CREATE_TARGET_NAME);
        else
          {
            if (send_element_error_to_client ("create_target", element_name))
              {
                error_send_to_client (error);
                return;
              }
            set_client_state (CLIENT_AUTHENTIC);
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
        break;

      case CLIENT_CREATE_TASK:
        if (strcasecmp ("RCFILE", element_name) == 0)
          {
            /* Initialise the task description. */
            if (current_client_task
                && add_task_description_line (current_client_task, "", 0))
              abort (); // FIX out of mem
            set_client_state (CLIENT_CREATE_TASK_RCFILE);
          }
        else if (strcasecmp ("NAME", element_name) == 0)
          set_client_state (CLIENT_CREATE_TASK_NAME);
        else if (strcasecmp ("COMMENT", element_name) == 0)
          set_client_state (CLIENT_CREATE_TASK_COMMENT);
        else if (strcasecmp ("CONFIG", element_name) == 0)
          set_client_state (CLIENT_CREATE_TASK_CONFIG);
        else if (strcasecmp ("ESCALATOR", element_name) == 0)
          set_client_state (CLIENT_CREATE_TASK_ESCALATOR);
        else if (strcasecmp ("TARGET", element_name) == 0)
          set_client_state (CLIENT_CREATE_TASK_TARGET);
        else
          {
            if (send_element_error_to_client ("create_task", element_name))
              {
                error_send_to_client (error);
                return;
              }
            set_client_state (CLIENT_AUTHENTIC);
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
        break;

      case CLIENT_TEST_ESCALATOR:
        if (strcasecmp ("NAME", element_name) == 0)
          set_client_state (CLIENT_TEST_ESCALATOR_NAME);
        else
          {
            if (send_element_error_to_client ("test_escalator",
                                              element_name))
              {
                error_send_to_client (error);
                return;
              }
            set_client_state (CLIENT_AUTHENTIC);
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
        break;

      case CLIENT_START_TASK:
        if (send_element_error_to_client ("start_task", element_name))
          {
            error_send_to_client (error);
            return;
          }
        set_client_state (CLIENT_AUTHENTIC);
        g_set_error (error,
                     G_MARKUP_ERROR,
                     G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                     "Error");
        break;

      case CLIENT_GET_STATUS:
        if (send_element_error_to_client ("get_status", element_name))
          {
            error_send_to_client (error);
            return;
          }
        set_client_state (CLIENT_AUTHENTIC);
        g_set_error (error,
                     G_MARKUP_ERROR,
                     G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                     "Error");
        break;

      default:
        assert (0);
        // FIX respond fail to client
        g_set_error (error,
                     G_MARKUP_ERROR,
                     G_MARKUP_ERROR_PARSE,
                     "Manager programming error.");
        break;
    }

  return;
}

/**
 * @brief Send XML for a certificate.
 *
 * @param[in]  cert_gp  The certificate.
 * @param[in]  dummy    Dummy variable, for certificate_find.
 *
 * @return 0 if out of space in to_client buffer, else 1.
 */
static gint
send_certificate (gpointer cert_gp, /*@unused@*/ gpointer dummy)
{
  certificate_t* cert = (certificate_t*) cert_gp;
  gchar* msg;
  gsize size_dummy;

  const char* public_key = certificate_public_key (cert);
  const char* owner = certificate_owner (cert);
  /* FIX The g_convert is a temp hack. */
  gchar* owner_utf8 = owner ? g_convert (owner, strlen (owner),
                                         "UTF-8", "ISO_8859-1",
                                         NULL, &size_dummy, NULL)
                            : NULL;
  gchar* owner_text = owner_utf8
                      ? g_markup_escape_text (owner_utf8, -1)
                      : g_strdup ("");
  g_free (owner_utf8);

  msg = g_strdup_printf ("<certificate>"
                         "<fingerprint>%s</fingerprint>"
                         "<owner>%s</owner>"
                         "<trust_level>%s</trust_level>"
                         "<length>%u</length>"
                         "<public_key>%s</public_key>"
                         "</certificate>",
                         certificate_fingerprint (cert),
                         owner_utf8,
                         certificate_trusted (cert) ? "trusted" : "notrust",
                         strlen (public_key),
                         public_key);
  g_free (owner_text);
  if (send_to_client (msg))
    {
      g_free (msg);
      return 0;
    }
  g_free (msg);
  return 1;
}

/**
 * @brief Send XML for a requirement of a plugin.
 *
 * @param[in]  element  The required plugin.
 * @param[in]  dummy    Dummy variable for g_hash_table_find.
 *
 * @return 0 if out of space in to_client buffer, else 1.
 */
static gint
send_requirement (gconstpointer element, /*@unused@*/ gconstpointer dummy)
{
  gboolean fail;
  gchar* text = g_markup_escape_text ((char*) element,
                                      strlen ((char*) element));
  gchar* msg = g_strdup_printf ("<need>%s</need>", text);
  g_free (text);

  fail = send_to_client (msg);
  g_free (msg);
  return fail ? 0 : 1;
}

/**
 * @brief Send XML for a plugin dependency.
 *
 * @param[in]  key    The dependency hashtable key.
 * @param[in]  value  The dependency hashtable value.
 * @param[in]  dummy  Dummy variable for g_hash_table_find.
 *
 * @return TRUE if out of space in to_client buffer, else FALSE.
 */
static gboolean
send_dependency (gpointer key, gpointer value, /*@unused@*/ gpointer dummy)
{
  /* \todo Do these reallocations affect performance? */
  gchar* key_text = g_markup_escape_text ((char*) key, strlen ((char*) key));
  gchar* msg = g_strdup_printf ("<dependency><needer>%s</needer>",
                                key_text);
  g_free (key_text);
  if (send_to_client (msg))
    {
      g_free (msg);
      return TRUE;
    }

  if (g_slist_find_custom ((GSList*) value, NULL, send_requirement))
    {
      g_free (msg);
      return TRUE;
    }

  if (send_to_client ("</dependency>"))
    {
      g_free (msg);
      return TRUE;
    }

  g_free (msg);
  return FALSE;
}

/**
 * @brief Define a code snippet for send_plugin.
 *
 * @param  x  Prefix for names in snippet.
 */
#define DEF(x)                                                    \
      const char* x = nvt_iterator_ ## x (nvts);                  \
      /* FIX The g_convert is a temp hack. */                     \
      gchar* x ## _utf8 = x ? g_convert (x, strlen (x),           \
                                         "UTF-8", "ISO_8859-1",   \
                                         NULL, &dummy, NULL)      \
                            : NULL;                               \
      gchar* x ## _text = x ## _utf8                              \
                          ? g_markup_escape_text (x ## _utf8, -1) \
                          : g_strdup ("");                        \
      g_free (x ## _utf8);

/**
 * @brief Send XML for an NVT.
 *
 * @param[in]  key         The plugin OID.
 * @param[in]  details     If true, detailed XML, else simple XML.
 * @param[in]  pref_count  Preference count.  Used if details is true.
 * @param[in]  timeout     Timeout.  Used if details is true.
 *
 * @return TRUE if out of space in to_client buffer, else FALSE.
 */
static gboolean
send_nvt (iterator_t *nvts, int details, int pref_count, const char *timeout)
{
  const char* oid = nvt_iterator_oid (nvts);
  const char* name = nvt_iterator_name (nvts);
  gchar* msg;

  gchar* name_text = g_markup_escape_text (name, strlen (name));
  if (details)
    {
      gsize dummy;

#ifndef S_SPLINT_S
      DEF (copyright);
      DEF (description);
      DEF (summary);
      DEF (family);
      DEF (version);
      DEF (tag);
#endif /* not S_SPLINT_S */

#undef DEF

      msg = g_strdup_printf ("<nvt"
                             " oid=\"%s\">"
                             "<name>%s</name>"
                             "<category>%s</category>"
                             "<copyright>%s</copyright>"
                             "<description>%s</description>"
                             "<summary>%s</summary>"
                             "<family>%s</family>"
                             "<version>%s</version>"
                             // FIX spec has multiple <cve_id>s
                             "<cve_id>%s</cve_id>"
                             "<bugtraq_id>%s</bugtraq_id>"
                             "<xrefs>%s</xrefs>"
                             "<fingerprints>%s</fingerprints>"
                             "<tags>%s</tags>"
                             "<preference_count>%i</preference_count>"
                             "<timeout>%s</timeout>"
                             "<checksum>"
                             "<algorithm>md5</algorithm>"
                             // FIX implement
                             "2397586ea5cd3a69f953836f7be9ef7b"
                             "</checksum>"
                             "</nvt>",
                             oid,
                             name_text,
                             category_name (nvt_iterator_category (nvts)),
                             copyright_text,
                             description_text,
                             summary_text,
                             family_text,
                             version_text,
                             nvt_iterator_cve (nvts),
                             nvt_iterator_bid (nvts),
                             nvt_iterator_xref (nvts),
                             nvt_iterator_sign_key_ids (nvts),
                             tag_text,
                             pref_count,
                             timeout ? timeout : "");
      g_free (copyright_text);
      g_free (description_text);
      g_free (summary_text);
      g_free (family_text);
      g_free (version_text);
      g_free (tag_text);
    }
  else
    msg = g_strdup_printf ("<nvt"
                           " oid=\"%s\">"
                           "<name>%s</name>"
                           "<checksum>"
                           "<algorithm>md5</algorithm>"
                           // FIX implement
                           "2397586ea5cd3a69f953836f7be9ef7b"
                           "</checksum>"
                           "</nvt>",
                           oid,
                           name_text);
  g_free (name_text);
  if (send_to_client (msg))
    {
      g_free (msg);
      return TRUE;
    }
  g_free (msg);
  return FALSE;
}

/**
 * @brief Send XML for a rule.
 *
 * @param[in]  rule  The rule.
 *
 * @return TRUE if out of space in to_client buffer, else FALSE.
 */
static gboolean
send_rule (gpointer rule)
{
  /* \todo Do these reallocations affect performance? */
  gchar* rule_text = g_markup_escape_text ((char*) rule,
                                           strlen ((char*) rule));
  gchar* msg = g_strdup_printf ("<rule>%s</rule>", rule_text);
  g_free (rule_text);
  if (send_to_client (msg))
    {
      g_free (msg);
      return TRUE;
    }
  g_free (msg);
  return FALSE;
}

/**
 * @brief Send XML for the reports of a task.
 *
 * @param[in]  task  The task.
 *
 * @return 0 success, -4 out of space in to_client,
 *         -5 failed to get report counts, -6 failed to get timestamp.
 */
static int
send_reports (task_t task)
{
  iterator_t iterator;
  report_t index;

  init_report_iterator (&iterator, task);
  while (next_report (&iterator, &index))
    {
      gchar *uuid, *timestamp, *msg;
      int debugs, holes, infos, logs, warnings, run_status;

      uuid = report_uuid (index);

      if (report_counts (uuid,
                         &debugs, &holes, &infos, &logs,
                         &warnings))
        {
          free (uuid);
          return -5;
        }

      if (report_timestamp (uuid, &timestamp))
        {
          free (uuid);
          return -6;
        }

      tracef ("     %s\n", uuid);

      report_scan_run_status (index, &run_status);
      msg = g_strdup_printf ("<report"
                             " id=\"%s\">"
                             // FIX s/b scan_start like get_report
                             "<timestamp>%s</timestamp>"
                             "<scan_run_status>%s</scan_run_status>"
                             "<messages>"
                             "<debug>%i</debug>"
                             "<hole>%i</hole>"
                             "<info>%i</info>"
                             "<log>%i</log>"
                             "<warning>%i</warning>"
                             "</messages>"
                             "</report>",
                             uuid,
                             timestamp,
                             run_status_name
                              (run_status ? run_status
                                          : TASK_STATUS_INTERNAL_ERROR),
                             debugs,
                             holes,
                             infos,
                             logs,
                             warnings);
      g_free (timestamp);
      if (send_to_client (msg))
        {
          g_free (msg);
          free (uuid);
          return -4;
        }
      g_free (msg);
      free (uuid);
    }
  cleanup_iterator (&iterator);

  return 0;
}

/**
 * @brief Print the XML for a report to a file.
 *
 * @param[in]  report      The report.
 * @param[in]  xml_file    File name.
 * @param[in]  ascending   Whether to sort ascending or descending.
 * @param[in]  sort_field  Field to sort on, or NULL for "type".
 *
 * @return 0 on success, else -1 with errno set.
 */
static int
print_report_xml (report_t report, gchar* xml_file, int ascending,
                  const char* sort_field)
{
  FILE *out;
  iterator_t results, hosts;
  char *end_time, *start_time;

  /* TODO: This is now out of sync with the XML report.  It is only used to
   *       generate the "html" report and the "html-pdf", which need extensive
   *       work anyway. */

  out = fopen (xml_file, "w");

  if (out == NULL)
    {
      g_warning ("%s: fopen failed: %s\n",
                 __FUNCTION__,
                 strerror (errno));
      return -1;
    }

  fputs ("<get_report_response"
         " status=\"" STATUS_OK "\" status_text=\"" STATUS_OK_TEXT "\">"
         "<report>",
         out);

  start_time = scan_start_time (report);
  fprintf (out,
           "<scan_start>%s</scan_start>",
           start_time);
  free (start_time);

  init_host_iterator (&hosts, report);
  while (next (&hosts))
    fprintf (out,
             "<host_start><host>%s</host>%s</host_start>",
             host_iterator_host (&hosts),
             host_iterator_start_time (&hosts));
  cleanup_iterator (&hosts);

  init_result_iterator (&results, report, NULL,
                        current_int_1,  /* First result. */
                        current_int_2,  /* Max results. */
                        ascending,
                        sort_field,
                        /* Attribute levels. */
                        modify_task_value);

  while (next (&results))
    {
      gchar *descr;

      descr = g_markup_escape_text (result_iterator_descr (&results), -1);
      // FIX as in other <result response below?
      //gchar *nl_descr = descr ? convert_to_newlines (descr) : NULL;
      fprintf (out,
               "<result>"
               "<subnet>%s</subnet>"
               "<host>%s</host>"
               "<port>%s</port>"
               "<nvt>%s</nvt>"
               "<type>%s</type>"
               "<description>%s</description>"
               "</result>",
               result_iterator_subnet (&results),
               result_iterator_host (&results),
               result_iterator_port (&results),
               result_iterator_nvt (&results),
               result_iterator_type (&results),
               descr);
      g_free (descr);
    }
  cleanup_iterator (&results);

  init_host_iterator (&hosts, report);
  while (next (&hosts))
    fprintf (out,
             "<host_end><host>%s</host>%s</host_end>",
             host_iterator_host (&hosts),
             host_iterator_end_time (&hosts));
  cleanup_iterator (&hosts);

  end_time = scan_end_time (report);
  fprintf (out, "<scan_end>%s</scan_end>", end_time);
  free (end_time);

  fprintf (out, "</report></get_report_response>");

  if (fclose (out))
    {
      g_warning ("%s: fclose failed: %s\n",
                 __FUNCTION__,
                 strerror (errno));
      return -1;
    }
  return 0;
}

/**
 * @brief Return the position at which to wrap text.
 *
 * Only space is considered a word boundary, for wrapping.
 *
 * Presume that the caller treats "\n" as a newline and skips over "\r".
 *
 * @param[in]  text        Text to inspect.
 * @param[in]  line_width  Line width before or at which to wrap.
 *
 * @return The maximum number of chars of \param text which the caller must
 *         write out in order to write out at most line_width characters of the
 *         next line in \param text.  As a special case if a newline occurs
 *         before line width then just return one more than number of chars
 *         needed to write up to the newline.
 */
static int
next_break (const char* text, int line_width)
{
  const char* pos = text;
  /* The number of characters the caller would have written out before
   * reaching the last space. */
  int last_space = -1;
  /* The number of characters the caller would have written out. */
  int nchars = 0;

  /**
   * @todo Test special cases.
   */

  /* Loop over the text one character at a time, recording how the caller
   * would write it out to a stream as LaTeX.  Account for caller treating
   * "\n" in the text like a newline, and skipping over "\r".  Keep track
   * of the position of the last space character.  On reaching a newline or
   * end of file return one more than the number of characters written, so
   * that the caller can find the newline or EOF too.  On reaching
   * line_width return the position of the last space if there was one,
   * otherwise just return the current position. */

  while (*pos)
    {
      switch (*pos)
        {
          case '\\':
            /* Reached a backslash, go on to the next character to look for
             * special sequences. */
            pos++;
            if (*pos && *pos == 'n')
              {
                /* Reached "\n". */
                return nchars + 2;
              }
            if (*pos && *pos == 'r')
              {
                /* Reached "\r", skip over it. */
                pos++;
              }
            else
              {
                /* The caller would write out the backslash. */
                nchars++;
              }
            break;
          case '\n':
            /* Reached a real newline. */
            return nchars + 1;
            break;
          case ' ':
            last_space = nchars + 1;
            /*@fallthrough@*/
          default:
            /* A normal character, that the caller would just write out. */
            pos++;
            nchars++;
            break;
        }

      if (nchars == line_width)
        {
          /* @todo It's weird to break at the first character (last_space ==
           *       0).  This function and the caller should drop any leading
           *       space when wrapping. */
          if (last_space >= 0)
            return last_space;
          return nchars;
        }
    }

  /* Reached the end of file before a newline or line_width. */
  return nchars;
}

/**
 * @brief Write verbatim LaTeX text to a stream, with wrapping.
 *
 * Write \ref text to \ref file, doing line wraps at 80 chars, adding a
 * symbol to indicate each line wrap, and putting each line in a separate
 * verbatim environment so that the text breaks across pages.
 *
 * Function used to print verbatim text to LaTeX documents within a longtable
 * environment.  It is up to the caller to ensure that file is positioned
 * within a tabular environment.
 *
 * @param[in]   file  Stream to write to.
 * @param[out]  text  Text to write to file.  Zero or more lines of newline
 *                    terminated text, where the final newline is optional.
 */
static void
latex_print_verbatim_text (FILE* file, const char* text)
{
  const char* pos = text;
  /* The number of chars processed of the current line of the text. */
  int nchars = 0;
  int line_width = 80;
  int break_pos;

  /** @todo Do this better.  Word wrapping has problems with first line. */

  /* Get the position at which to break the first line. */

  break_pos = next_break (pos, line_width);

  /* Loop over the text one character at a time, writing it out to the file
   * as LaTeX.  Put each line of the text in a verbatim environment.  On
   * reaching the break position write out LaTeX to wrap the line,
   * calculate the next break position, and continue.  While writing out
   * the text, treat "\n" in the text like a newline, and skip over "\r". */

  fputs ("\\verb=", file);
  while (*pos)
    {
      if (nchars == break_pos)
        {
          /* Reached the break position, start a new line in the LaTeX. */
          fputs ("=\\\\\n", file);
          fputs ("$\\hookrightarrow$\\verb=", file);
          nchars = 0;
          /* Subtract 2 because the hookrightarrow has taken up some space. */
          break_pos = next_break (pos, line_width - 2);
          continue;
        }
      switch (*pos)
        {
          case '\\':
            /* Reached a backslash, go on to the next character to look for
             * special sequences. */
            pos++;
            if (*pos && *pos == 'n')
              {
                /* Reached "\n", start a new line in the LaTeX. */
                fputs ("=\\\\\n\\verb=", file);
                nchars = 0;
                pos++;
                break_pos = next_break (pos, line_width);
              }
            else if (*pos && *pos == 'r')
              {
                /* Reached "\r", skip over it. */
                pos++;
              }
            else
              {
                /* Write out the backslash. */
                nchars++;
                fputc ('\\', file);
              }
            break;
          case '\n':
            /* Reached a real newline, start a new line in the LaTeX. */
            fputs ("=\\\\\n\\verb=", file);
            nchars = 0;
            pos++;
            break_pos = next_break (pos, line_width);
            break;
          case '=':
            /* Print equal in a whole new \verb environment that uses dash
             * instead of equal to begin and end the text. */
            fputs ("=\\verb-=-\\verb=", file);
            nchars++;
            pos++;
            break;
          default:
            /* A normal character, write it out. */
            fputc (*pos, file);
            nchars++;
            pos++;
            break;
        }
    }
  /**
   * @todo Handle special situations (empty string, newline at end etc)
   *       more clever, break at word boundaries.
   */
  fputs ("=\\\\\n", file);
}

/**
 * @brief Convert \n's to real newline's.
 *
 * @return A newly allocated version of text.
 */
static gchar*
convert_to_newlines (const char *text)
{
  // TODO: Do this better.

  gsize left = strlen (text);
  gchar *new, *ch;

  /* Allocate buffer of a safe length. */
  {
    new = g_strdup (text);
  }

  ch = new;
  while (*ch)
    {
      if (*ch == '\\')
        {
          ch++;
          switch (*ch)
            {
              case 'r':
                {
                  /* \r is flushed */
                  memmove (ch - 1, ch + 1, left);
                  left--;
                  ch -= 2;
                  break;
                }
              case 'n':
                {
                  /* \n becomes "\n" (one newline) */
                  memmove (ch, ch + 1, left);
                  left--;
                  *(ch - 1) = '\n';
                  ch--;
                  break;
                }
              default:
                {
                  ch--;
                  break;
                }
            }
        }
      ch++; left--;
    }
  return new;
}

/**
 * @brief Get the heading associated with a certain result severity.
 *
 * @param[in]  severity  The severity type.
 *
 * @return The heading associated with the given severity (for example,
 *         "Informational").
 */
const char*
latex_severity_heading (const char *severity)
{
  if (strcmp (severity, "Security Hole") == 0)
    return "Severity: High";
  if (strcmp (severity, "Security Note") == 0)
    return "Severity: Low";
  if (strcmp (severity, "Security Warning") == 0)
    return "Severity: Medium";
  return severity;
}

/**
 * @brief Get the colour associated with a certain result severity.
 *
 * @param[in]  severity  The severity type.
 *
 * @return The colour associated with the given severity (for example,
 *         "[rgb]{0.1,0.7,0}" or "{red}").
 */
const char*
latex_severity_colour (const char *severity)
{
  if (strcmp (severity, "Debug Message") == 0)
    return "{openvas_debug}";
  if (strcmp (severity, "Log Message") == 0)
    return "{openvas_log}";
  if (strcmp (severity, "Security Hole") == 0)
    return "{openvas_hole}";
  if (strcmp (severity, "Security Note") == 0)
    return "{openvas_note}";
  if (strcmp (severity, "Security Warning") == 0)
    return "{openvas_warning}";
  return "{openvas_report}";
}

/**
 * @brief Header for latex report.
 */
const char* latex_header
  = "\\documentclass{article}\n"
    "\\pagestyle{empty}\n"
    "\n"
    "%\\usepackage{color}\n"
    "\\usepackage{tabularx}\n"
    "\\usepackage{geometry}\n"
    "\\usepackage{comment}\n"
    "\\usepackage{longtable}\n"
    "\\usepackage{titlesec}\n"
    "\\usepackage{chngpage}\n"
    "\\usepackage{calc}\n"
    "\\usepackage{url}\n"
    // FIX encoding issue
    /** @todo Following line is a fix to include special characters, including
     *        umlauts, in the verbatim sections of the latex/pdf reports.
     *        Handling of the encoding should be done at a different point. */
    "\\usepackage[latin1]{inputenc}\n"
    "\n"
    "\\usepackage{colortbl}\n"
    "\n"
    "% must come last\n"
    "\\usepackage{hyperref}\n"
    "\\definecolor{linkblue}{rgb}{0.11,0.56,1}\n"
    "\\definecolor{openvas_debug}{rgb}{0.78,0.78,0.78}\n"
    /* Log */
    "\\definecolor{openvas_log}{rgb}{0.2275,0.2275,0.2275}\n"
    /* High: #CB1D17 */
    "\\definecolor{openvas_hole}{rgb}{0.7960,0.1137,0.0902}\n"
    /* Low: #539DCB */
    "\\definecolor{openvas_note}{rgb}{0.3255,0.6157,0.7961}\n"
    "\\definecolor{openvas_report}{rgb}{0.68,0.74,0.88}\n"
    /* Medium: #F99F31 */
    "\\definecolor{openvas_warning}{rgb}{0.9764,0.6235,0.1922}\n"
    "\\hypersetup{colorlinks=true,linkcolor=linkblue,urlcolor=blue,bookmarks=true,bookmarksopen=true}\n"
    "\\usepackage[all]{hypcap}\n"
    "\n"
    "%\\geometry{verbose,a4paper,tmargin=24mm,bottom=24mm}\n"
    "\\geometry{verbose,a4paper}\n"
    "\\setlength{\\parskip}{\\smallskipamount}\n"
    "\\setlength{\\parindent}{0pt}\n"
    "\n"
    "\\title{Scan Report}\n"
    "\\pagestyle{headings}\n"
    "\\pagenumbering{arabic}\n"
    "\n"
    "\\begin{document}\n"
    "\n"
    "\\maketitle\n"
    "\n"
    "\\renewcommand{\\abstractname}{Summary}\n";

/**
 * @brief Header for latex report.
 */
const char* latex_footer
  = "\n"
    "\\begin{center}\n"
    "\\medskip\n"
    "\\rule{\\textwidth}{0.1pt}\n"
    "\n"
    "This file was automatically generated.\n"
    "\\end{center}\n"
    "\n"
    "\\end{document}\n";

/**
 * @brief Print LaTeX for a report to a file.
 *
 * @param[in]  report      The report.
 * @param[in]  latex_file  File name.
 * @param[in]  ascending   Whether to sort ascending or descending.
 * @param[in]  sort_field  Field to sort on, or NULL for "type".
 *
 * @return 0 on success, else -1 with errno set.
 */
static int
print_report_latex (report_t report, gchar* latex_file, int ascending,
                    const char* sort_field)
{
  FILE *out;
  iterator_t results, hosts;
  int num_hosts = 0, total_holes = 0, total_notes = 0, total_warnings = 0;
  char *start_time, *end_time;

  /**
   * @todo Also, this code produces empty tables (probably because of the
   *       'if (last_port == )' code).
   * @todo Escape all text that should appear as text in latex.
   */

  out = fopen (latex_file, "w");

  if (out == NULL)
    {
      g_warning ("%s: fopen failed: %s\n",
                 __FUNCTION__,
                 strerror (errno));
      return -1;
    }

  fputs (latex_header, out);

  start_time = scan_start_time (report);
  end_time = scan_end_time (report);
  fprintf (out,
           "\\begin{abstract}\n"
           "This document reports on the results of an automatic security scan.\n"
           "The scan started at %s and ended at %s.  The\n"
           "report first summarises the results found.  Then, for each host,\n"
           "the report describes every issue found.  Please consider the\n"
           "advice given in each desciption, in order to rectify the issue.\n"
           "\\end{abstract}\n",
           start_time,
           end_time);
  free (start_time);
  free (end_time);

  fputs ("\\tableofcontents\n", out);
  fputs ("\\newpage\n", out);

  /* Print the list of hosts. */

  fprintf (out, "\\section{Result Overview}\n\n");
  fprintf (out, "\\begin{longtable}{|l|l|l|l|l|l|}\n");
  fprintf (out, "\\hline\n"
                "\\rowcolor{openvas_report}"
                "Host&Most Severe Result(s)&Holes&Warnings&Notes&False Positives\\\\\n"
                "\\hline\n"
                "\\endfirsthead\n"
                "\\multicolumn{6}{l}{\\hfill\\ldots continued from previous page \\ldots}\\\\\n"
                "\\hline\n"
                "\\rowcolor{openvas_report}"
                "Host&Most Severe Result(s)&Holes&Warnings&Notes&False Positives\\\\\n"
                "\\endhead\n"
                "\\hline\n"
                "\\multicolumn{6}{l}{\\ldots continues on next page \\ldots}\\\\\n"
                "\\endfoot\n"
                "\\hline\n"
                "\\endlastfoot\n");

  init_host_iterator (&hosts, report);
  while (next (&hosts))
    {
      int holes, warnings, notes;
      const char *host = host_iterator_host (&hosts);

      report_holes (report, host, &holes);
      report_warnings (report, host, &warnings);
      report_notes (report, host, &notes);

      total_holes += holes;
      total_warnings += warnings;
      total_notes += notes;

      num_hosts++;
      /* RATS: ignore, argument 2 is a constant string. */
      fprintf (out,
               "\\hline\n"
               // FIX 0 (false positives)
               "\\hyperref[host:%s]{%s}&%s&%i&%i&%i&0\\\\\n",
               host,
               host,
               ((holes > 1) ? "Severity: High"
                : ((holes == 1) ? "Severity: High"
                   : ((warnings > 1) ? "Severity: Medium"
                      : ((warnings == 1) ? "Severity: Medium"
                         : ((notes > 1) ? "Severity: Low"
                            : ((notes == 1) ? "Severity: Low"
                               : "")))))),
               holes,
               warnings,
               notes);
    }
  cleanup_iterator (&hosts);

  /* RATS: ignore, argument 2 is a constant string. */
  fprintf (out,
           "\\hline\n"
           // FIX 0 (false positives)
           "Total: %i&&%i&%i&%i&0\\\\\n"
           "\\hline\n"
           "\\end{longtable}\n"
           "\n"
           "\\section{Results per Host}\n"
           "\n",
           num_hosts,
           total_holes,
           total_warnings,
           total_notes);

  /* Print a section for each host. */

  init_host_iterator (&hosts, report);
  while (next (&hosts))
    {
      gchar *last_port;
      const char *host = host_iterator_host (&hosts);

      /* Print the times. */

      fprintf (out,
               "\\subsection{%s}\n"
               "\\label{host:%s}\n"
               "\n"
               "\\begin{tabular}{ll}\n"
               "Host scan start&%s\\\\\n"
               "Host scan end&%s\\\\\n"
               "\\end{tabular}\n\n",
               host,
               host,
               host_iterator_start_time (&hosts),
               host_iterator_end_time (&hosts));

      /* Print the result summary table. */

      fprintf (out,
               "\\begin{tabular}{|l|l|}\n"
               "\\hline\n"
               "\\rowcolor{openvas_report}Service (Port)&Threat Level\\\\\n"
               "\\hline\n");

      init_result_iterator (&results, report, host,
                            current_int_1,  /* First result. */
                            current_int_2,  /* Max results. */
                            ascending,
                            sort_field,
                            /* Attribute levels. */
                            modify_task_value);
      last_port = NULL;
      while (next (&results))
        {
          if (last_port
              && (strcmp (last_port, result_iterator_port (&results)) == 0))
            continue;
          if (last_port) g_free (last_port);
          last_port = g_strdup (result_iterator_port (&results));
          fprintf (out,
                   "\\hyperref[port:%s %s]{%s}&%s\\\\\n"
                   "\\hline\n",
                   host_iterator_host (&hosts),
                   last_port,
                   last_port,
                   result_type_threat (result_iterator_type (&results)));
        }
      cleanup_iterator (&results);
      if (last_port) g_free (last_port);

      fprintf (out,
               "\\end{tabular}\n"
               "\n"
               "%%\\subsection*{Security Issues and Fixes -- %s}\n\n",
               host_iterator_host (&hosts));

      /* Print the result details. */

      init_result_iterator (&results, report, host,
                            current_int_1,  /* First result. */
                            current_int_2,  /* Max results. */
                            ascending,
                            sort_field,
                            /* Attribute levels. */
                            modify_task_value);
      last_port = NULL;
      /* Results are ordered by port, and then by severity (more severity
       * before less severe). */
      // FIX severity ordering is alphabetical on severity name
      while (next (&results))
        {
          const char *severity;

          if (last_port == NULL
              || strcmp (last_port, result_iterator_port (&results)))
            {
              if (last_port)
                {
                  fprintf (out,
                           "\\end{longtable}\n"
                           "\\begin{footnotesize}"
                           "\\hyperref[host:%s]{[ return to %s ]}\n"
                           "\\end{footnotesize}\n",
                           host,
                           host);
                  g_free (last_port);
                  last_port = NULL;
                }
              fprintf (out,
                       "\\subsubsection{%s}\n"
                       "\\label{port:%s %s}\n\n"
                       "\\begin{longtable}{|p{\\textwidth * 1}|}\n",
                       result_iterator_port (&results),
                       host_iterator_host (&hosts),
                       result_iterator_port (&results));
            }
          if (last_port == NULL)
            last_port = g_strdup (result_iterator_port (&results));
          severity = result_iterator_type (&results);
          fprintf (out,
                   "\\hline\n"
                   "\\rowcolor%s{\\color{white}{%s}}\\\\\n"
                   "\\hline\n"
                   "\\endfirsthead\n"
                   "\\hfill\\ldots continued from previous page \\ldots \\\\\n"
                   "\\hline\n"
                   "\\endhead\n"
                   "\\hline\n"
                   "\\ldots continues on next page \\ldots \\\\\n"
                   "\\endfoot\n"
                   "\\hline\n"
                   "\\endlastfoot\n",
                   latex_severity_colour (severity),
                   latex_severity_heading (severity));
          latex_print_verbatim_text (out, result_iterator_descr (&results));
          fprintf (out,
                   "\\\\\n"
                   "OID of test routine: %s\\\\\n"
                   //"\\hline\n"
                   "\\end{longtable}\n"
                   "\n"
                   "\\begin{longtable}{|p{\\textwidth * 1}|}\n",
                   result_iterator_nvt (&results));

        }
      if (last_port)
        {
          g_free (last_port);

          fprintf (out,
                   "\\end{longtable}\n"
                   "\\begin{footnotesize}"
                   "\\hyperref[host:%s]{[ return to %s ]}"
                   "\\end{footnotesize}\n",
                   host,
                   host);
        }
      cleanup_iterator (&results);
    }
  cleanup_iterator (&hosts);

  /* Close off. */

  fputs (latex_footer, out);

  if (fclose (out))
    {
      g_warning ("%s: fclose failed: %s\n",
                 __FUNCTION__,
                 strerror (errno));
      return -1;
    }
  return 0;
}

/**
 * @brief Handle the end of an OMP XML element.
 *
 * React to the end of an XML element according to the current value
 * of \ref client_state, usually adjusting \ref client_state to indicate
 * the change (with \ref set_client_state).  Call \ref send_to_client to queue
 * any responses for the client.  Call the task utilities to adjust the
 * tasks (for example \ref start_task, \ref stop_task, \ref set_task_parameter,
 * \ref delete_task and \ref find_task).
 *
 * Set error parameter on encountering an error.
 *
 * @param[in]  context           Parser context.
 * @param[in]  element_name      XML element name.
 * @param[in]  user_data         Dummy parameter.
 * @param[in]  error             Error parameter.
 */
static void
omp_xml_handle_end_element (/*@unused@*/ GMarkupParseContext* context,
                            const gchar *element_name,
                            /*@unused@*/ gpointer user_data,
                            GError **error)
{
  tracef ("   XML    end: %s\n", element_name);
  switch (client_state)
    {
      case CLIENT_TOP:
        assert (0);
        break;

      case CLIENT_ABORT_TASK:
        if (current_uuid)
          {
            task_t task;

            assert (current_client_task == (task_t) 0);

            if (find_task (current_uuid, &task))
              SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("abort_task"));
            else if (task == 0)
              {
                if (send_find_error_to_client ("abort_task",
                                               "task",
                                               current_uuid))
                  {
                    error_send_to_client (error);
                    return;
                  }
              }
            else switch (stop_task (task))
              {
                case 0:   /* Stopped. */
                  SEND_TO_CLIENT_OR_FAIL (XML_OK ("abort_task"));
                  break;
                case 1:   /* Stop requested. */
                  SEND_TO_CLIENT_OR_FAIL (XML_OK_REQUESTED ("abort_task"));
                  break;
                default:  /* Programming error. */
                  assert (0);
                case -1:
                  /* to_scanner is full. */
                  // FIX revert parsing for retry
                  // process_omp_client_input must return -2
                  abort ();
              }
            openvas_free_string_var (&current_uuid);
          }
        else
          SEND_TO_CLIENT_OR_FAIL
           (XML_ERROR_SYNTAX ("abort_task",
                              "ABORT_TASK requires a task_id attribute"));
        set_client_state (CLIENT_AUTHENTIC);
        break;

#if 0
      case CLIENT_ABORT_TASK_CRITERION:
        assert (strcasecmp ("CRITERION", element_name) == 0);
        set_client_state (CLIENT_ABORT_TASK);
        break;
      case CLIENT_ABORT_TASK_CRITERION_VALUE:
        assert (strcasecmp ("TASK_ID", element_name) == 0);
        set_client_state (CLIENT_ABORT_TASK);
        break;
#endif

      case CLIENT_AUTHENTICATE:
        switch (authenticate (&current_credentials))
          {
            case 0:
              if (load_tasks ())
                {
                  g_warning ("%s: failed to load tasks\n", __FUNCTION__);
                  g_set_error (error, G_MARKUP_ERROR, G_MARKUP_ERROR_PARSE,
                               "Manager failed to load tasks.");
                  free_credentials (&current_credentials);
                  SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("authenticate"));
                  set_client_state (CLIENT_TOP);
                }
              else
                {
                  SEND_TO_CLIENT_OR_FAIL (XML_OK ("authenticate"));
                  set_client_state (CLIENT_AUTHENTIC);
                }
              break;
            case 1:
              free_credentials (&current_credentials);
              SEND_TO_CLIENT_OR_FAIL (XML_ERROR_AUTH_FAILED ("authenticate"));
              set_client_state (CLIENT_TOP);
              break;
            case -1:
            default:
              free_credentials (&current_credentials);
              SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("authenticate"));
              set_client_state (CLIENT_TOP);
              break;
          }
        break;

      case CLIENT_AUTHENTIC:
      case CLIENT_COMMANDS:
      case CLIENT_AUTHENTIC_COMMANDS:
        assert (strcasecmp ("COMMANDS", element_name) == 0);
        SENDF_TO_CLIENT_OR_FAIL ("</commands_response>");
        break;

      case CLIENT_CREDENTIALS:
        assert (strcasecmp ("CREDENTIALS", element_name) == 0);
        set_client_state (CLIENT_AUTHENTICATE);
        break;

      case CLIENT_CREDENTIALS_USERNAME:
        assert (strcasecmp ("USERNAME", element_name) == 0);
        set_client_state (CLIENT_CREDENTIALS);
        break;

      case CLIENT_CREDENTIALS_PASSWORD:
        assert (strcasecmp ("PASSWORD", element_name) == 0);
        set_client_state (CLIENT_CREDENTIALS);
        break;

      case CLIENT_GET_PREFERENCES:
        {
          iterator_t prefs;
          SEND_TO_CLIENT_OR_FAIL ("<get_preferences_response"
                                  " status=\"" STATUS_OK "\""
                                  " status_text=\"" STATUS_OK_TEXT "\">");
          init_nvt_preference_iterator (&prefs, NULL);
          while (next (&prefs))
            {
              SENDF_TO_CLIENT_OR_FAIL ("<preference>"
                                       "<name>%s</name>"
                                       "<value>%s</value>"
                                       "</preference>",
                                       nvt_preference_iterator_name (&prefs),
                                       nvt_preference_iterator_value (&prefs));
            }
          cleanup_iterator (&prefs);
          SEND_TO_CLIENT_OR_FAIL ("</get_preferences_response>");
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }

      case CLIENT_GET_CERTIFICATES:
        if (scanner.certificates)
          {
            SEND_TO_CLIENT_OR_FAIL ("<get_certificates_response"
                                    " status=\"" STATUS_OK "\""
                                    " status_text=\"" STATUS_OK_TEXT "\">");
            if (certificates_find (scanner.certificates,
                                   send_certificate,
                                   NULL))
              {
                error_send_to_client (error);
                return;
              }
            SEND_TO_CLIENT_OR_FAIL ("</get_certificates_response>");
          }
        else
          SEND_TO_CLIENT_OR_FAIL (XML_SERVICE_DOWN ("get_certificates"));
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_GET_DEPENDENCIES:
        if (scanner.plugins_dependencies)
          {
            SEND_TO_CLIENT_OR_FAIL ("<get_dependencies_response"
                                    " status=\"" STATUS_OK "\""
                                    " status_text=\"" STATUS_OK_TEXT "\">");
            if (g_hash_table_find (scanner.plugins_dependencies,
                                   send_dependency,
                                   NULL))
              {
                error_send_to_client (error);
                return;
              }
            SEND_TO_CLIENT_OR_FAIL ("</get_dependencies_response>");
          }
        else
          SEND_TO_CLIENT_OR_FAIL (XML_SERVICE_DOWN ("get_dependencies"));
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_GET_NVT_ALL:
        {
          char *md5sum = nvts_md5sum ();
          if (md5sum)
            {
              iterator_t nvts;

              SEND_TO_CLIENT_OR_FAIL ("<get_nvt_all_response"
                                      " status=\"" STATUS_OK "\""
                                      " status_text=\"" STATUS_OK_TEXT "\">");
              SENDF_TO_CLIENT_OR_FAIL ("<nvt_count>%u</nvt_count>",
                                       nvts_size ());
              SEND_TO_CLIENT_OR_FAIL ("<feed_checksum algorithm=\"md5\">");
              SEND_TO_CLIENT_OR_FAIL (md5sum);
              free (md5sum);
              SEND_TO_CLIENT_OR_FAIL ("</feed_checksum>");

              init_nvt_iterator (&nvts, (nvt_t) 0, NULL, NULL, 1, NULL);
              while (next (&nvts))
                if (send_nvt (&nvts, 0, -1, NULL))
                  {
                    error_send_to_client (error);
                    return;
                  }
              cleanup_iterator (&nvts);

              SEND_TO_CLIENT_OR_FAIL ("</get_nvt_all_response>");
            }
          else
            SEND_TO_CLIENT_OR_FAIL (XML_SERVICE_DOWN ("get_nvt_all"));
        }
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_GET_NVT_FEED_CHECKSUM:
        {
          char *md5sum;
          if (current_uuid && strcasecmp (current_uuid, "md5"))
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("get_nvt_feed_checksum",
                                "GET_NVT_FEED_CHECKSUM algorithm must be md5"));

          else if ((md5sum = nvts_md5sum ()))
            {
              SEND_TO_CLIENT_OR_FAIL ("<get_nvt_feed_checksum_response"
                                      " status=\"" STATUS_OK "\""
                                      " status_text=\"" STATUS_OK_TEXT "\">"
                                      "<checksum algorithm=\"md5\">");
              SEND_TO_CLIENT_OR_FAIL (md5sum);
              free (md5sum);
              SEND_TO_CLIENT_OR_FAIL ("</checksum>"
                                      "</get_nvt_feed_checksum_response>");
            }
          else
            SEND_TO_CLIENT_OR_FAIL (XML_SERVICE_DOWN ("get_nvt_feed_checksum"));
          openvas_free_string_var (&current_uuid);
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }

      case CLIENT_GET_NVT_DETAILS:
        {
          char *md5sum = nvts_md5sum ();
          if (md5sum)
            {
              if (current_uuid)
                {
                  nvt_t nvt;

                  free (md5sum);
                  if (find_nvt (current_uuid, &nvt))
                    SEND_TO_CLIENT_OR_FAIL
                     (XML_INTERNAL_ERROR ("get_nvt_details"));
                  else if (nvt == 0)
                    {
                      if (send_find_error_to_client ("get_nvt_details",
                                                     "NVT",
                                                     current_uuid))
                        {
                          error_send_to_client (error);
                          return;
                        }
                    }
                  else
                    {
                      iterator_t nvts;

                      SEND_TO_CLIENT_OR_FAIL
                       ("<get_nvt_details_response"
                        " status=\"" STATUS_OK "\""
                        " status_text=\"" STATUS_OK_TEXT "\">");

                      init_nvt_iterator (&nvts, nvt, NULL, NULL, 1, NULL);
                      while (next (&nvts))
                        {
                          char *timeout = NULL;

                          if (current_name) /* Attribute config. */
                            timeout = config_nvt_timeout (current_name,
                                                          nvt_iterator_oid
                                                           (&nvts));

                          if (send_nvt (&nvts, 1, -1, timeout))
                            {
                              error_send_to_client (error);
                              return;
                            }
                          if (current_name) /* Attribute config. */
                            {
                              iterator_t prefs;
                              const char *nvt_name = nvt_iterator_name (&nvts);

                              /* Send the preferences for the NVT. */

                              SENDF_TO_CLIENT_OR_FAIL ("<preferences>"
                                                       "<timeout>%s</timeout>",
                                                       timeout ? timeout : "");
                              free (timeout);

                              init_nvt_preference_iterator (&prefs, nvt_name);
                              while (next (&prefs))
                                {
                                  char *real_name, *type, *value, *nvt;
                                  char *oid = NULL;
                                  real_name
                                   = nvt_preference_iterator_real_name (&prefs);
                                  type = nvt_preference_iterator_type (&prefs);
                                  value = nvt_preference_iterator_config_value
                                           (&prefs, current_name);
                                  nvt = nvt_preference_iterator_nvt (&prefs);
                                  if (nvt) oid = nvt_oid (nvt);

                                  SENDF_TO_CLIENT_OR_FAIL
                                   ("<preference>"
                                    "<nvt oid=\"%s\"><name>%s</name></nvt>"
                                    "<name>%s</name>"
                                    "<type>%s</type>",
                                    oid ? oid : "",
                                    nvt ? nvt : "",
                                    real_name ? real_name : "",
                                    type ? type : "");

                                  if (value
                                      && type
                                      && (strcmp (type, "radio") == 0))
                                    {
                                      /* Handle the other possible values. */
                                      char *pos = strchr (value, ';');
                                      if (pos) *pos = '\0';
                                      SENDF_TO_CLIENT_OR_FAIL
                                       ("<value>%s</value>", value);
                                      while (pos)
                                        {
                                          char *pos2 = strchr (++pos, ';');
                                          if (pos2) *pos2 = '\0';
                                          SENDF_TO_CLIENT_OR_FAIL
                                           ("<alt>%s</alt>", pos);
                                          pos = pos2;
                                        }
                                    }
                                  else if (value
                                           && type
                                           && (strcmp (type, "password") == 0))
                                    SEND_TO_CLIENT_OR_FAIL ("<value></value>");
                                  else
                                    SENDF_TO_CLIENT_OR_FAIL
                                     ("<value>%s</value>", value ? value : "");

                                  SEND_TO_CLIENT_OR_FAIL ("</preference>");

                                }
                              cleanup_iterator (&prefs);

                              SEND_TO_CLIENT_OR_FAIL ("</preferences>");

                            }
                        }
                      cleanup_iterator (&nvts);

                      SEND_TO_CLIENT_OR_FAIL ("</get_nvt_details_response>");
                    }
                }
              else
                {
                  iterator_t nvts;

                  SENDF_TO_CLIENT_OR_FAIL
                   ("<get_nvt_details_response"
                    " status=\"" STATUS_OK "\""
                    " status_text=\"" STATUS_OK_TEXT "\">"
                    "<nvt_count>%u</nvt_count>",
                    nvts_size ());
                  SEND_TO_CLIENT_OR_FAIL ("<feed_checksum>"
                                          "<algorithm>md5</algorithm>");
                  SEND_TO_CLIENT_OR_FAIL (md5sum);
                  free (md5sum);
                  SEND_TO_CLIENT_OR_FAIL ("</feed_checksum>");

                  init_nvt_iterator (&nvts,
                                     (nvt_t) 0,
                                     current_name,    /* Attribute config. */
                                     current_format,  /* Attribute family. */
                                     /* Attribute sort_order. */
                                     current_int_2,
                                     /* Attribute sort_field. */
                                     modify_task_value);
                  while (next (&nvts))
                    {
                      int pref_count = -1;
                      char *timeout = NULL;

                      if (current_name) /* Attribute config. */
                        timeout = config_nvt_timeout (current_name,
                                                      nvt_iterator_oid
                                                       (&nvts));

                      if (current_name       /* Attribute config. */
                          || current_format) /* Attribute family. */
                        {
                          const char *nvt_name = nvt_iterator_name (&nvts);
                          pref_count = nvt_preference_count (nvt_name);
                        }
                      if (send_nvt (&nvts, 1, pref_count, timeout))
                        {
                          error_send_to_client (error);
                          return;
                        }
                    }
                  cleanup_iterator (&nvts);

                  SEND_TO_CLIENT_OR_FAIL ("</get_nvt_details_response>");
                }
            }
          else
            SEND_TO_CLIENT_OR_FAIL (XML_SERVICE_DOWN ("get_nvt_details"));
        }
        openvas_free_string_var (&current_uuid);
        openvas_free_string_var (&current_name);
        openvas_free_string_var (&current_format);
        openvas_free_string_var (&modify_task_value);
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_GET_NVT_FAMILIES:
        {
          iterator_t families;

          SEND_TO_CLIENT_OR_FAIL ("<get_nvt_families_response"
                                  " status=\"" STATUS_OK "\""
                                  " status_text=\"" STATUS_OK_TEXT "\">"
                                  "<families>");

          init_family_iterator (&families,
                                1,
                                NULL,
                                /* Attribute sort_order. */
                                current_int_2);
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
        }
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_DELETE_REPORT:
        assert (strcasecmp ("DELETE_REPORT", element_name) == 0);
        if (current_uuid)
          {
            report_t report;

            // FIX check syntax of current_uuid  STATUS_ERROR_SYNTAX
            if (find_report (current_uuid, &report))
              SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("delete_report"));
            else if (report == 0)
              {
                if (send_find_error_to_client ("delete_report",
                                               "report",
                                               current_uuid))
                  {
                    error_send_to_client (error);
                    return;
                  }
              }
            else
              {
                int ret = delete_report (report);
                switch (ret)
                  {
                    case 0:
                      SEND_TO_CLIENT_OR_FAIL (XML_OK ("delete_report"));
                      break;
                    case 1:
                      SEND_TO_CLIENT_OR_FAIL
                       (XML_ERROR_SYNTAX ("delete_report",
                                          "Attempt to delete a hidden report"));
                      break;
                    default:
                      SEND_TO_CLIENT_OR_FAIL
                       (XML_INTERNAL_ERROR ("delete_report"));
                      break;
                  }
              }
            openvas_free_string_var (&current_uuid);
          }
        else
          SEND_TO_CLIENT_OR_FAIL
           (XML_ERROR_SYNTAX ("delete_report",
                              "DELETE_REPORT requires a report_id attribute"));
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_GET_REPORT:
        assert (strcasecmp ("GET_REPORT", element_name) == 0);
        if (current_credentials.username == NULL)
          {
            openvas_free_string_var (&current_uuid);
            SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_report"));
            set_client_state (CLIENT_AUTHENTIC);
            break;
          }

        if (current_uuid == NULL) /* Attribute report_id. */
          SEND_TO_CLIENT_OR_FAIL
           (XML_ERROR_SYNTAX ("get_report",
                              "GET_REPORT must have a report_id attribute"));
        else
          {
            report_t report;
            iterator_t results, hosts;
            GString *nbe;
            gchar *content;

            if (find_report (current_uuid, &report))
              SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_report"));
            else if (report == 0)
              {
                if (send_find_error_to_client ("get_report",
                                               "report",
                                               current_uuid))
                  {
                    error_send_to_client (error);
                    return;
                  }
              }
            else if (current_format == NULL
                     || strcasecmp (current_format, "xml") == 0)
              {
                task_t task;
                char *tsk_uuid = NULL, *start_time, *end_time;
                int result_count, filtered_result_count, run_status;
                const char *levels;

                /* Attribute levels. */
                levels = modify_task_value ? modify_task_value : "hmlgd";

                if (report_task (report, &task))
                  {
                    SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_report"));
                    openvas_free_string_var (&current_uuid);
                    openvas_free_string_var (&current_format);
                    set_client_state (CLIENT_AUTHENTIC);
                    break;
                  }
                else if (task && task_uuid (task, &tsk_uuid))
                  {
                    SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_report"));
                    openvas_free_string_var (&current_uuid);
                    openvas_free_string_var (&current_format);
                    set_client_state (CLIENT_AUTHENTIC);
                    break;
                  }

                report_scan_result_count (report, NULL, &result_count);
                report_scan_result_count (report, levels,
                                          &filtered_result_count);
                report_scan_run_status (report, &run_status);
                SENDF_TO_CLIENT_OR_FAIL
                 ("<get_report_response"
                  " status=\"" STATUS_OK "\""
                  " status_text=\"" STATUS_OK_TEXT "\">"
                  "<report id=\"%s\">"
                  "<sort><field>%s<order>%s</order></field></sort>"
                  "<filters>%s",
                  current_uuid,
                  /* Attribute sort_field. */
                  current_name ? current_name : "type",
                  /* Attribute sort_order. */
                  current_int_3 ? "ascending" : "descending",
                  levels);

                if (strchr (levels, 'h'))
                  SEND_TO_CLIENT_OR_FAIL ("<filter>High</filter>");
                if (strchr (levels, 'm'))
                  SEND_TO_CLIENT_OR_FAIL ("<filter>Medium</filter>");
                if (strchr (levels, 'l'))
                  SEND_TO_CLIENT_OR_FAIL ("<filter>Low</filter>");
                if (strchr (levels, 'g'))
                  SEND_TO_CLIENT_OR_FAIL ("<filter>Log</filter>");
                if (strchr (levels, 'd'))
                  SEND_TO_CLIENT_OR_FAIL ("<filter>Debug</filter>");

                SENDF_TO_CLIENT_OR_FAIL
                 ("</filters>"
                  "<scan_run_status>%s</scan_run_status>"
                  "<scan_result_count>"
                  "%i"
                  "<filtered>%i</filtered>"
                  "</scan_result_count>",
                  run_status_name (run_status
                                   ? run_status
                                   : TASK_STATUS_INTERNAL_ERROR),
                  result_count,
                  filtered_result_count);

                if (task && tsk_uuid)
                  {
                    char* tsk_name = task_name (task);
                    SENDF_TO_CLIENT_OR_FAIL ("<task id=\"%s\">"
                                             "<name>%s</name>"
                                             "</task>",
                                             tsk_uuid,
                                             tsk_name ? tsk_name : "");
                    free (tsk_name);
                    free (tsk_uuid);
                  }

                start_time = scan_start_time (report);
                SENDF_TO_CLIENT_OR_FAIL ("<scan_start>%s</scan_start>",
                                         start_time);
                free (start_time);

                init_host_iterator (&hosts, report);
                while (next (&hosts))
                  SENDF_TO_CLIENT_OR_FAIL ("<host_start><host>%s</host>%s</host_start>",
                                           host_iterator_host (&hosts),
                                           host_iterator_start_time (&hosts));
                cleanup_iterator (&hosts);

                /* Port summary. */

                {
                  gchar *last_port;
                  GArray *ports = g_array_new (TRUE, FALSE, sizeof (gchar*));

                  init_result_iterator (&results, report, NULL,
                                        current_int_1,   /* First result. */
                                        current_int_2,   /* Max results. */
                                        /* Sort by port in order requested. */
                                        ((current_name   /* "sort_field". */
                                          && (strcmp (current_name, "port")
                                              == 0))
                                         ? current_int_3 /* "sort_order". */
                                         : 1),
                                        "port", /* Always desc. by threat. */
                                        levels);

                  /* Buffer the results. */

                  last_port = NULL;
                  while (next (&results))
                    {
                      const char *port = result_iterator_port (&results);

                      if (last_port == NULL || strcmp (port, last_port))
                        {
                          const char *host, *type;
                          gchar *item;
                          int type_len, host_len;

                          g_free (last_port);
                          last_port = g_strdup (port);

                          host = result_iterator_host (&results);
                          type = result_iterator_type (&results);
                          type_len = strlen (type);
                          host_len = strlen (host);
                          item = g_malloc (type_len
                                           + host_len
                                           + strlen (port)
                                           + 3);
                          g_array_append_val (ports, item);
                          strcpy (item, type);
                          strcpy (item + type_len + 1, host);
                          strcpy (item + type_len + host_len + 2, port);
                        }

                    }
                  g_free (last_port);

                  /* Ensure the buffered results are sorted. */

                  if (current_name
                      && strcmp (current_name, /* Attribute sort_field. */
                                 "port"))
                    {
                      /* Sort by threat. */
                      if (current_int_3) /* Attribute sort_order. */
                        g_array_sort (ports, compare_ports_asc);
                      else
                        g_array_sort (ports, compare_ports_desc);
                    }

                  /* Send from the buffer. */

                  SENDF_TO_CLIENT_OR_FAIL ("<ports"
                                           " start=\"%i\""
                                           " max=\"%i\">",
                                           /* Add 1 for 1 indexing. */
                                           current_int_1 + 1,
                                           current_int_2);
                  {
                    gchar *item;
                    int index = 0;

                    while ((item = g_array_index (ports, gchar*, index++)))
                      {
                        int type_len = strlen (item);
                        int host_len = strlen (item + type_len + 1);
                        SENDF_TO_CLIENT_OR_FAIL ("<port>"
                                                 "<host>%s</host>"
                                                 "%s"
                                                 "<threat>%s</threat>"
                                                 "</port>",
                                                 item + type_len + 1,
                                                 item + type_len
                                                      + host_len
                                                      + 2,
                                                 result_type_threat (item));
                        g_free (item);
                      }
                    g_array_free (ports, TRUE);
                  }
                  SENDF_TO_CLIENT_OR_FAIL ("</ports>");
                  cleanup_iterator (&results);
                }

                /* Threat counts. */

                {
                  int debugs, holes, infos, logs, warnings;

                  report_counts_id (report, &debugs, &holes, &infos, &logs,
                                    &warnings);

                  SENDF_TO_CLIENT_OR_FAIL ("<messages>"
                                           "<debug>%i</debug>"
                                           "<hole>%i</hole>"
                                           "<info>%i</info>"
                                           "<log>%i</log>"
                                           "<warning>%i</warning>"
                                           "</messages>",
                                           debugs,
                                           holes,
                                           infos,
                                           logs,
                                           warnings);
                }

                /* Results. */

                init_result_iterator (&results, report, NULL,
                                      current_int_1,  /* First result. */
                                      current_int_2,  /* Max results. */
                                      /* Attribute sort_order. */
                                      current_int_3,
                                      /* Attribute sort_field. */
                                      current_name,
                                      levels);

                SENDF_TO_CLIENT_OR_FAIL ("<results"
                                         " start=\"%i\""
                                         " max=\"%i\">",
                                         /* Add 1 for 1 indexing. */
                                         current_int_1 + 1,
                                         current_int_2);
                while (next (&results))
                  {
                    const char *descr = result_iterator_descr (&results);
                    gchar *nl_descr = descr ? convert_to_newlines (descr) : NULL;
                    SENDF_TO_CLIENT_OR_FAIL ("<result>"
                                             "<subnet>%s</subnet>"
                                             "<host>%s</host>"
                                             "<port>%s</port>"
                                             "<nvt>%s</nvt>"
                                             "<threat>%s</threat>"
                                             "<description>%s</description>"
                                             "</result>",
                                             result_iterator_subnet (&results),
                                             result_iterator_host (&results),
                                             result_iterator_port (&results),
                                             result_iterator_nvt (&results),
                                             result_type_threat
                                              (result_iterator_type (&results)),
                                             descr ? nl_descr : "");
                    if (descr) g_free (nl_descr);
                  }
                SENDF_TO_CLIENT_OR_FAIL ("</results>");
                cleanup_iterator (&results);

                init_host_iterator (&hosts, report);
                while (next (&hosts))
                  SENDF_TO_CLIENT_OR_FAIL ("<host_end><host>%s</host>%s</host_end>",
                                           host_iterator_host (&hosts),
                                           host_iterator_end_time (&hosts));
                cleanup_iterator (&hosts);

                end_time = scan_end_time (report);
                SENDF_TO_CLIENT_OR_FAIL ("<scan_end>%s</scan_end>",
                                         end_time);
                free (end_time);

                SEND_TO_CLIENT_OR_FAIL ("</report>"
                                        "</get_report_response>");
              }
            else if (strcasecmp (current_format, "nbe") == 0)
              {
                char *start_time, *end_time;

                /* TODO: Encode and send in chunks, after each printf. */

                /* Build the NBE in memory. */

                nbe = g_string_new ("");
                start_time = scan_start_time (report);
                g_string_append_printf (nbe,
                                        "timestamps|||scan_start|%s|\n",
                                        start_time);
                free (start_time);

                init_host_iterator (&hosts, report);
                while (next (&hosts))
                  g_string_append_printf (nbe,
                                          "timestamps||%s|host_start|%s|\n",
                                          host_iterator_host (&hosts),
                                          host_iterator_start_time (&hosts));
                cleanup_iterator (&hosts);

                init_result_iterator (&results, report, NULL,
                                      current_int_1,  /* First result. */
                                      current_int_2,  /* Max results. */
                                      /* Attribute sort_order. */
                                      current_int_3,
                                      /* Attribute sort_field. */
                                      current_name,
                                      /* Attribute levels. */
                                      modify_task_value);
                while (next (&results))
                  g_string_append_printf (nbe,
                                          "results|%s|%s|%s|%s|%s|%s\n",
                                          result_iterator_subnet (&results),
                                          result_iterator_host (&results),
                                          result_iterator_port (&results),
                                          result_iterator_nvt (&results),
                                          result_iterator_type (&results),
                                          result_iterator_descr (&results));
                cleanup_iterator (&results);

                init_host_iterator (&hosts, report);
                while (next (&hosts))
                  g_string_append_printf (nbe,
                                          "timestamps||%s|host_end|%s|\n",
                                          host_iterator_host (&hosts),
                                          host_iterator_end_time (&hosts));
                cleanup_iterator (&hosts);

                end_time = scan_end_time (report);
                g_string_append_printf (nbe,
                                        "timestamps|||scan_end|%s|\n",
                                        end_time);
                free (end_time);

                /* Encode and send the NBE. */

                SEND_TO_CLIENT_OR_FAIL ("<get_report_response"
                                        " status=\"" STATUS_OK "\""
                                        " status_text=\"" STATUS_OK_TEXT "\">"
                                        "<report format=\"nbe\">");
                content = g_string_free (nbe, FALSE);
                if (content && strlen (content))
                  {
                    gchar *base64_content;
                    base64_content = g_base64_encode ((guchar*) content,
                                                      strlen (content));
                    if (send_to_client (base64_content))
                      {
                        g_free (content);
                        g_free (base64_content);
                        error_send_to_client (error);
                        return;
                      }
                    g_free (base64_content);
                  }
                g_free (content);
                SEND_TO_CLIENT_OR_FAIL ("</report>"
                                        "</get_report_response>");
              }
            else if (strcasecmp (current_format, "html") == 0)
              {
                gchar *xml_file;
                char xml_dir[] = "/tmp/openvasmd_XXXXXX";

                if (mkdtemp (xml_dir) == NULL)
                  {
                    g_warning ("%s: g_mkdtemp failed\n", __FUNCTION__);
                    SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_report"));
                  }
                else if (xml_file = g_strdup_printf ("%s/report.xml", xml_dir),
                         print_report_xml (report,
                                           xml_file,
                                           /* Attribute sort_order. */
                                           current_int_3,
                                           /* Attribute sort_field. */
                                           current_name))
                  {
                    g_free (xml_file);
                    SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_report"));
                  }
                else
                  {
                    gchar *xsl_file;

                    xsl_file = g_build_filename (OPENVAS_DATA_DIR,
                                                 "openvasmd_report_html.xsl",
                                                 NULL);
                    if (!g_file_test (xsl_file, G_FILE_TEST_EXISTS))
                      {
                        g_warning ("%s: XSL missing: %s\n",
                                   __FUNCTION__,
                                   xsl_file);
                        g_free (xsl_file);
                        g_free (xml_file);
                        /* This is a missing resource, however the resource is
                         * the responsibility of the manager admin. */
                        SEND_TO_CLIENT_OR_FAIL
                         (XML_INTERNAL_ERROR ("get_report"));
                      }
                    else
                      {
                        gchar *html_file, *command;
                        int ret;

                        html_file = g_strdup_printf ("%s/report.html", xml_dir);

                        command = g_strdup_printf ("xsltproc -v %s %s -o %s 2> /dev/null",
                                                   xsl_file,
                                                   xml_file,
                                                   html_file);
                        g_free (xsl_file);
                        g_free (xml_file);

                        g_message ("   command: %s\n", command);

                        /* RATS: ignore, command is defined above. */
                        if (ret = system (command),
                            // FIX ret is always -1
                            0 && ((ret) == -1
                                  || WEXITSTATUS (ret)))
                          {
                            g_warning ("%s: system failed with ret %i, %i, %s\n",
                                       __FUNCTION__,
                                       ret,
                                       WEXITSTATUS (ret),
                                       command);
                            g_free (command);
                            g_free (html_file);
                            SEND_TO_CLIENT_OR_FAIL
                             (XML_INTERNAL_ERROR ("get_report"));
                          }
                        else
                          {
                            GError *get_error;
                            gchar *html;
                            gsize html_len;

                            g_free (command);

                            /* Send the HTML to the client. */

                            get_error = NULL;
                            g_file_get_contents (html_file,
                                                 &html,
                                                 &html_len,
                                                 &get_error);
                            g_free (html_file);
                            if (get_error)
                              {
                                g_warning ("%s: Failed to get HTML: %s\n",
                                           __FUNCTION__,
                                           get_error->message);
                                g_error_free (get_error);
                                SEND_TO_CLIENT_OR_FAIL
                                 (XML_INTERNAL_ERROR ("get_report"));
                              }
                            else
                              {
                                /* Remove the directory. */

                                file_utils_rmdir_rf (xml_dir);

                                /* Encode and send the HTML. */

                                SEND_TO_CLIENT_OR_FAIL
                                 ("<get_report_response"
                                  " status=\"" STATUS_OK "\""
                                  " status_text=\"" STATUS_OK_TEXT "\">"
                                  "<report format=\"html\">");
                                if (html && strlen (html))
                                  {
                                    gchar *base64;
                                    base64 = g_base64_encode ((guchar*) html,
                                                              html_len);
                                    if (send_to_client (base64))
                                      {
                                        g_free (html);
                                        g_free (base64);
                                        error_send_to_client (error);
                                        return;
                                      }
                                    g_free (base64);
                                  }
                                g_free (html);
                                SEND_TO_CLIENT_OR_FAIL
                                 ("</report>"
                                  "</get_report_response>");
                              }
                          }
                      }
                  }
              }
            else if (strcasecmp (current_format, "html-pdf") == 0)
              {
                gchar *xml_file;
                char xml_dir[] = "/tmp/openvasmd_XXXXXX";

                // TODO: This block is very similar to the HTML block above.

                if (mkdtemp (xml_dir) == NULL)
                  {
                    g_warning ("%s: g_mkdtemp failed\n", __FUNCTION__);
                    SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_report"));
                  }
                else if (xml_file = g_strdup_printf ("%s/report.xml", xml_dir),
                         print_report_xml (report,
                                           xml_file,
                                           /* Attribute sort_order. */
                                           current_int_3,
                                           /* Attribute sort_field. */
                                           current_name))
                  {
                    g_free (xml_file);
                    SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_report"));
                  }
                else
                  {
                    gchar *xsl_file;

                    xsl_file = g_build_filename (OPENVAS_DATA_DIR,
                                                 "openvasmd_report_html.xsl",
                                                 NULL);
                    if (!g_file_test (xsl_file, G_FILE_TEST_EXISTS))
                      {
                        g_warning ("%s: XSL missing: %s\n",
                                   __FUNCTION__,
                                   xsl_file);
                        g_free (xsl_file);
                        g_free (xml_file);
                        /* This is a missing resource, however the resource is
                         * the responsibility of the manager admin. */
                        SEND_TO_CLIENT_OR_FAIL
                         (XML_INTERNAL_ERROR ("get_report"));
                      }
                    else
                      {
                        gchar *pdf_file, *command;
                        int ret;

                        pdf_file = g_strdup_printf ("%s/report.pdf", xml_dir);

                        command = g_strdup_printf ("xsltproc -v %s %s"
                                                   " 2> /dev/null"
                                                   " | tee /tmp/openvasmd_html"
                                                   " | htmldoc -t pdf --webpage -f %s -"
                                                   " 2> /dev/null",
                                                   xsl_file,
                                                   xml_file,
                                                   pdf_file);
                        g_free (xsl_file);
                        g_free (xml_file);

                        g_message ("   command: %s\n", command);

                        /* RATS: ignore, command is defined above. */
                        if (ret = system (command),
                            // FIX ret is always -1
                            0 && ((ret) == -1
                                  || WEXITSTATUS (ret)))
                          {
                            g_warning ("%s: system failed with ret %i, %i, %s\n",
                                       __FUNCTION__,
                                       ret,
                                       WEXITSTATUS (ret),
                                       command);
                            g_free (command);
                            g_free (pdf_file);
                            SEND_TO_CLIENT_OR_FAIL
                             (XML_INTERNAL_ERROR ("get_report"));
                          }
                        else
                          {
                            GError *get_error;
                            gchar *pdf;
                            gsize pdf_len;

                            g_free (command);

                            /* Send the PDF to the client. */

                            get_error = NULL;
                            g_file_get_contents (pdf_file,
                                                 &pdf,
                                                 &pdf_len,
                                                 &get_error);
                            g_free (pdf_file);
                            if (get_error)
                              {
                                g_warning ("%s: Failed to get PDF: %s\n",
                                           __FUNCTION__,
                                           get_error->message);
                                g_error_free (get_error);
                                SEND_TO_CLIENT_OR_FAIL
                                 (XML_INTERNAL_ERROR ("get_report"));
                              }
                            else
                              {
                                /* Remove the directory. */

                                file_utils_rmdir_rf (xml_dir);

                                /* Encode and send the HTML. */

                                SEND_TO_CLIENT_OR_FAIL
                                 ("<get_report_response"
                                  " status=\"" STATUS_OK "\""
                                  " status_text=\"" STATUS_OK_TEXT "\">"
                                  "<report format=\"pdf\">");
                                if (pdf && strlen (pdf))
                                  {
                                    gchar *base64;
                                    base64 = g_base64_encode ((guchar*) pdf,
                                                              pdf_len);
                                    if (send_to_client (base64))
                                      {
                                        g_free (pdf);
                                        g_free (base64);
                                        error_send_to_client (error);
                                        return;
                                      }
                                    g_free (base64);
                                  }
                                g_free (pdf);
                                SEND_TO_CLIENT_OR_FAIL ("</report>"
                                                        "</get_report_response>");
                              }
                          }
                      }
                  }
              }
            else if (strcasecmp (current_format, "pdf") == 0)
              {
                gchar *latex_file;
                char latex_dir[] = "/tmp/openvasmd_XXXXXX";

                if (mkdtemp (latex_dir) == NULL)
                  {
                    g_warning ("%s: g_mkdtemp failed\n", __FUNCTION__);
                    SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_report"));
                  }
                else if (latex_file = g_strdup_printf ("%s/report.tex",
                                                       latex_dir),
                         print_report_latex (report,
                                             latex_file,
                                             /* Attribute sort_order. */
                                             current_int_3,
                                             /* Attribute sort_field. */
                                             current_name))
                  {
                    g_free (latex_file);
                    SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_report"));
                  }
                else
                  {
                    gchar *pdf_file, *command;
                    gint pdf_fd;
                    int ret;

                    pdf_file = g_strdup (latex_file);
                    pdf_file[strlen (pdf_file) - 1] = 'f';
                    pdf_file[strlen (pdf_file) - 2] = 'd';
                    pdf_file[strlen (pdf_file) - 3] = 'p';

                    pdf_fd = open (pdf_file,
                                   O_RDWR | O_CREAT,
                                   S_IRUSR | S_IWUSR);

                    command = g_strdup_printf
                               ("pdflatex -output-directory %s %s"
                                " > /tmp/openvasmd_pdflatex_out 2>&1"
                                " && pdflatex -output-directory %s %s"
                                " > /tmp/openvasmd_pdflatex_out 2>&1",
                                latex_dir,
                                latex_file,
                                latex_dir,
                                latex_file);

                    g_free (latex_file);

                    g_message ("   command: %s\n", command);

                    if (pdf_fd == -1)
                      {
                        g_warning ("%s: open of %s failed\n",
                                   __FUNCTION__,
                                   pdf_file);
                        g_free (pdf_file);
                        SEND_TO_CLIENT_OR_FAIL
                         (XML_INTERNAL_ERROR ("get_report"));
                      }
                    /* RATS: ignore, command is defined above. */
                    else if (ret = system (command),
                             // FIX ret is always -1
                             0 && ((ret) == -1
                                   || WEXITSTATUS (ret)))
                      {
                        g_warning ("%s: system failed with ret %i, %i, %s\n",
                                   __FUNCTION__,
                                   ret,
                                   WEXITSTATUS (ret),
                                   command);
                        close (pdf_fd);
                        g_free (pdf_file);
                        g_free (command);
                        SEND_TO_CLIENT_OR_FAIL
                         (XML_INTERNAL_ERROR ("get_report"));
                      }
                    else
                      {
                        GError *get_error;
                        gchar *pdf;
                        gsize pdf_len;

                        close (pdf_fd);
                        g_free (command);

                        /* Send the PDF to the client. */

                        get_error = NULL;
                        g_file_get_contents (pdf_file,
                                             &pdf,
                                             &pdf_len,
                                             &get_error);
                        g_free (pdf_file);
                        if (get_error)
                          {
                            g_warning ("%s: Failed to get PDF: %s\n",
                                       __FUNCTION__,
                                       get_error->message);
                            g_error_free (get_error);
                            SEND_TO_CLIENT_OR_FAIL
                             (XML_INTERNAL_ERROR ("get_report"));
                          }
                        else
                          {
                            /* Remove the directory. */

                            file_utils_rmdir_rf (latex_dir);

                            /* Encode and send the PDF data. */

                            SEND_TO_CLIENT_OR_FAIL
                             ("<get_report_response"
                              " status=\"" STATUS_OK "\""
                              " status_text=\"" STATUS_OK_TEXT "\">"
                              "<report format=\"pdf\">");
                            if (pdf && strlen (pdf))
                              {
                                gchar *base64;
                                base64 = g_base64_encode ((guchar*) pdf,
                                                          pdf_len);
                                if (send_to_client (base64))
                                  {
                                    g_free (pdf);
                                    g_free (base64);
                                    error_send_to_client (error);
                                    return;
                                  }
                                g_free (base64);
                              }
                            g_free (pdf);
                            SEND_TO_CLIENT_OR_FAIL ("</report>"
                                                    "</get_report_response>");
                          }
                      }
                  }
              }
            else
              SEND_TO_CLIENT_OR_FAIL
               (XML_ERROR_SYNTAX ("get_report",
                                  "Bogus report format in format attribute"));
          }
        openvas_free_string_var (&current_uuid);
        openvas_free_string_var (&current_format);
        openvas_free_string_var (&modify_task_value);
        openvas_free_string_var (&current_name);
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_GET_RULES:
        if (scanner.rules)
          {
            int index;
            SEND_TO_CLIENT_OR_FAIL ("<get_rules_response"
                                    " status=\"" STATUS_OK "\""
                                    " status_text=\"" STATUS_OK_TEXT "\">");
            for (index = 0; index < scanner.rules_size; index++)
              if (send_rule (g_ptr_array_index (scanner.rules, index)))
                {
                  error_send_to_client (error);
                  return;
                }
            SEND_TO_CLIENT_OR_FAIL ("</get_rules_response>");
          }
        else
          SEND_TO_CLIENT_OR_FAIL (XML_SERVICE_DOWN ("get_rules"));
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_VERSION:
        SEND_TO_CLIENT_OR_FAIL ("<get_version_response"
                                " status=\"" STATUS_OK "\""
                                " status_text=\"" STATUS_OK_TEXT "\">"
                                "<version preferred=\"yes\">1.0</version>"
                                "</get_version_response>");
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_DELETE_AGENT:
        {
          assert (strcasecmp ("DELETE_AGENT", element_name) == 0);
          assert (modify_task_name != NULL);

          if (strlen (modify_task_name) == 0)
            {
              openvas_free_string_var (&modify_task_name);
              SEND_TO_CLIENT_OR_FAIL
               (XML_ERROR_SYNTAX ("delete_agent",
                                  "DELETE_AGENT name must be at least"
                                  " one character long"));
            }
          else switch (delete_agent (modify_task_name))
            {
              case 0:
                openvas_free_string_var (&modify_task_name);
                SEND_TO_CLIENT_OR_FAIL (XML_OK ("delete_agent"));
                break;
              case 1:
                openvas_free_string_var (&modify_task_name);
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("delete_agent",
                                    "Agent is in use"));
                break;
              default:
                openvas_free_string_var (&modify_task_name);
                SEND_TO_CLIENT_OR_FAIL
                 (XML_INTERNAL_ERROR ("delete_agent"));
            }
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }
      case CLIENT_DELETE_AGENT_NAME:
        assert (strcasecmp ("NAME", element_name) == 0);
        set_client_state (CLIENT_DELETE_AGENT);
        break;

      case CLIENT_DELETE_CONFIG:
        {
          assert (strcasecmp ("DELETE_CONFIG", element_name) == 0);
          assert (modify_task_name != NULL);

          if (strlen (modify_task_name) == 0)
            {
              openvas_free_string_var (&modify_task_name);
              SEND_TO_CLIENT_OR_FAIL
               (XML_ERROR_SYNTAX ("delete_config",
                                  "DELETE_CONFIG name must be at least one"
                                  " character long"));
            }
          else switch (delete_config (modify_task_name))
            {
              case 0:
                openvas_free_string_var (&modify_task_name);
                SEND_TO_CLIENT_OR_FAIL (XML_OK ("delete_config"));
                break;
              case 1:
                openvas_free_string_var (&modify_task_name);
                SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX ("delete_config",
                                                          "Config is in use"));
                break;
              default:
                openvas_free_string_var (&modify_task_name);
                SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("delete_config"));
            }
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }
      case CLIENT_DELETE_CONFIG_NAME:
        assert (strcasecmp ("NAME", element_name) == 0);
        set_client_state (CLIENT_DELETE_CONFIG);
        break;

      case CLIENT_DELETE_ESCALATOR:
        {
          assert (strcasecmp ("DELETE_ESCALATOR", element_name) == 0);
          assert (modify_task_name != NULL);

          if (strlen (modify_task_name) == 0)
            {
              openvas_free_string_var (&modify_task_name);
              SEND_TO_CLIENT_OR_FAIL
               (XML_ERROR_SYNTAX ("delete_escalator",
                                  "DELETE_ESCALATOR name must be at least one"
                                  " character long"));
            }
          else switch (delete_escalator (modify_task_name))
            {
              case 0:
                openvas_free_string_var (&modify_task_name);
                SEND_TO_CLIENT_OR_FAIL (XML_OK ("delete_escalator"));
                break;
              case 1:
                openvas_free_string_var (&modify_task_name);
                SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX ("delete_escalator",
                                                          "Escalator is in use"));
                break;
              default:
                openvas_free_string_var (&modify_task_name);
                SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("delete_escalator"));
            }
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }
      case CLIENT_DELETE_ESCALATOR_NAME:
        assert (strcasecmp ("NAME", element_name) == 0);
        set_client_state (CLIENT_DELETE_ESCALATOR);
        break;

      case CLIENT_DELETE_LSC_CREDENTIAL:
        {
          assert (strcasecmp ("DELETE_LSC_CREDENTIAL", element_name) == 0);
          assert (modify_task_name != NULL);

          if (strlen (modify_task_name) == 0)
            {
              openvas_free_string_var (&modify_task_name);
              SEND_TO_CLIENT_OR_FAIL
               (XML_ERROR_SYNTAX ("delete_lsc_credential",
                                  "DELETE_LSC_CREDENTIAL name must be at least"
                                  " one character long"));
            }
          else switch (delete_lsc_credential (modify_task_name))
            {
              case 0:
                openvas_free_string_var (&modify_task_name);
                SEND_TO_CLIENT_OR_FAIL (XML_OK ("delete_lsc_credential"));
                break;
              case 1:
                openvas_free_string_var (&modify_task_name);
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("delete_lsc_credential",
                                    "LSC credential is in use"));
                break;
              default:
                openvas_free_string_var (&modify_task_name);
                SEND_TO_CLIENT_OR_FAIL
                 (XML_INTERNAL_ERROR ("delete_lsc_credential"));
            }
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }
      case CLIENT_DELETE_LSC_CREDENTIAL_NAME:
        assert (strcasecmp ("NAME", element_name) == 0);
        set_client_state (CLIENT_DELETE_LSC_CREDENTIAL);
        break;

      case CLIENT_DELETE_TARGET:
        {
          assert (strcasecmp ("DELETE_TARGET", element_name) == 0);
          assert (modify_task_name != NULL);

          if (strlen (modify_task_name) == 0)
            {
              openvas_free_string_var (&modify_task_name);
              SEND_TO_CLIENT_OR_FAIL
               (XML_ERROR_SYNTAX ("delete_target",
                                  "DELETE_TARGET name must be at least one"
                                  " character long"));
            }
          else switch (delete_target (modify_task_name))
            {
              case 0:
                openvas_free_string_var (&modify_task_name);
                SEND_TO_CLIENT_OR_FAIL (XML_OK ("delete_target"));
                break;
              case 1:
                openvas_free_string_var (&modify_task_name);
                SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX ("delete_target",
                                                          "Target is in use"));
                break;
              default:
                openvas_free_string_var (&modify_task_name);
                SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("delete_target"));
            }
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }
      case CLIENT_DELETE_TARGET_NAME:
        assert (strcasecmp ("NAME", element_name) == 0);
        set_client_state (CLIENT_DELETE_TARGET);
        break;

      case CLIENT_DELETE_TASK:
        if (current_uuid)
          {
            task_t task;
            assert (current_client_task == (task_t) 0);
            if (find_task (current_uuid, &task))
              SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("delete_task"));
            else if (task == 0)
              {
                if (send_find_error_to_client ("delete_task",
                                               "task",
                                               current_uuid))
                  {
                    error_send_to_client (error);
                    return;
                  }
              }
            else switch (request_delete_task (&task))
              {
                case 0:    /* Deleted. */
                  SEND_TO_CLIENT_OR_FAIL (XML_OK ("delete_task"));
                  break;
                case 1:    /* Delete requested. */
                  SEND_TO_CLIENT_OR_FAIL (XML_OK_REQUESTED ("delete_task"));
                  break;
                case 2:    /* Hidden task. */
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("delete_task",
                                      "Attempt to delete a hidden task"));
                  break;
                default:   /* Programming error. */
                  assert (0);
                case -1:
                  /* to_scanner is full. */
                  // FIX or some other error
                  // FIX revert parsing for retry
                  // process_omp_client_input must return -2
                  tracef ("delete_task failed\n");
                  abort ();
                  break;
              }
            openvas_free_string_var (&current_uuid);
          }
        else
          SEND_TO_CLIENT_OR_FAIL
           (XML_ERROR_SYNTAX ("delete_task",
                              "DELETE_TASK requires a task_id attribute"));
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_HELP:
        SEND_TO_CLIENT_OR_FAIL ("<help_response"
                                " status=\"" STATUS_OK "\""
                                " status_text=\"" STATUS_OK_TEXT "\">");
        SEND_TO_CLIENT_OR_FAIL (help_text);
        SEND_TO_CLIENT_OR_FAIL ("</help_response>");
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_MODIFY_CONFIG:
        /** @todo find_config */
        if (current_name == NULL || strlen (current_name) == 0)
          SEND_TO_CLIENT_OR_FAIL
           (XML_ERROR_SYNTAX ("modify_config",
                              "MODIFY_CONFIG requires a NAME element"));
        else if ((current_format         /* NVT_SELECTION family. */
                  && current_array_2)    /* Implies FAMILY_SELECTION. */
                 || ((current_format || current_array_2)
                     && (modify_task_name
                         || modify_task_value
                         || current_uuid)))
          SEND_TO_CLIENT_OR_FAIL
           (XML_ERROR_SYNTAX ("modify_config",
                              "MODIFY_CONFIG requires either a PREFERENCE or"
                              " an NVT_SELECTION or a FAMILY_SELECTION"));
        else if (current_format)
          {
            assert (current_array_1);

            array_terminate (current_array_1);
            switch (manage_set_config_nvts (current_name,
                                            current_format,
                                            current_array_1))
              {
                case 0:
                  SEND_TO_CLIENT_OR_FAIL (XML_OK ("modify_config"));
                  break;
                case 1:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("modify_config", "Config is in use"));
                  break;
#if 0
                case -1:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("modify_config",
                                      "MODIFY_CONFIG PREFERENCE requires at least"
                                      " one of the VALUE and NVT elements"));
                  break;
#endif
                default:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_INTERNAL_ERROR ("modify_config"));
                  break;
              }

            free_array (current_array_1);
            current_array_1 = NULL;
          }
        else if (current_array_2)    /* Implies FAMILY_SELECTION. */
          {
            assert (current_array_1);
            assert (current_array_3);

            array_terminate (current_array_1);
            array_terminate (current_array_2);
            array_terminate (current_array_3);
            switch (manage_set_config_families (current_name,
                                                current_array_1,
                                                current_array_2,
                                                current_array_3,
                                                current_int_3))
              {
                case 0:
                  SEND_TO_CLIENT_OR_FAIL (XML_OK ("modify_config"));
                  break;
                case 1:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("modify_config", "Config is in use"));
                  break;
#if 0
                case -1:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("modify_config",
                                      "MODIFY_CONFIG PREFERENCE requires at least"
                                      " one of the VALUE and NVT elements"));
                  break;
#endif
                default:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_INTERNAL_ERROR ("modify_report"));
                  break;
              }

            free_array (current_array_1);
            free_array (current_array_2);
            free_array (current_array_3);
            current_array_1 = NULL;
            current_array_2 = NULL;
            current_array_3 = NULL;
          }
        else if (modify_task_name == NULL || strlen (modify_task_name) == 0)
          SEND_TO_CLIENT_OR_FAIL
           (XML_ERROR_SYNTAX ("modify_config",
                              "MODIFY_CONFIG PREFERENCE requires a NAME"
                              " element"));
        else switch (manage_set_config_preference (current_name,
                                                   current_uuid,
                                                   modify_task_name,
                                                   modify_task_value))
          {
            case 0:
              SEND_TO_CLIENT_OR_FAIL (XML_OK ("modify_config"));
              break;
            case 1:
              SEND_TO_CLIENT_OR_FAIL
               (XML_ERROR_SYNTAX ("modify_config", "Config is in use"));
              break;
            case -1:
              SEND_TO_CLIENT_OR_FAIL
               (XML_ERROR_SYNTAX ("modify_config",
                                  "MODIFY_CONFIG PREFERENCE requires at least"
                                  " one of the VALUE and NVT elements"));
              break;
            default:
              SEND_TO_CLIENT_OR_FAIL
               (XML_INTERNAL_ERROR ("modify_report"));
              break;
          }
        openvas_free_string_var (&current_format);
        openvas_free_string_var (&current_name);
        openvas_free_string_var (&modify_task_name);
        openvas_free_string_var (&modify_task_value);
        openvas_free_string_var (&current_uuid);
        set_client_state (CLIENT_AUTHENTIC);
        break;
      case CLIENT_MODIFY_CONFIG_NAME:
        assert (strcasecmp ("NAME", element_name) == 0);
        set_client_state (CLIENT_MODIFY_CONFIG);
        break;
      case CLIENT_MODIFY_CONFIG_FAMILY_SELECTION:
        assert (strcasecmp ("FAMILY_SELECTION", element_name) == 0);
        set_client_state (CLIENT_MODIFY_CONFIG);
        break;
      case CLIENT_MODIFY_CONFIG_NVT_SELECTION:
        assert (strcasecmp ("NVT_SELECTION", element_name) == 0);
        set_client_state (CLIENT_MODIFY_CONFIG);
        break;
      case CLIENT_MODIFY_CONFIG_PREFERENCE:
        assert (strcasecmp ("PREFERENCE", element_name) == 0);
        set_client_state (CLIENT_MODIFY_CONFIG);
        break;

      case CLIENT_MODIFY_CONFIG_FAMILY_SELECTION_FAMILY:
        assert (strcasecmp ("FAMILY", element_name) == 0);
        if (current_uuid)
          {
            if (current_int_1)
              {
                if (current_int_2)
                  /* Growing 1 and select all 1. */
                  array_add (current_array_1, current_uuid);
                else
                  /* Growing 1 and select all 0. */
                  array_add (current_array_3, current_uuid);
              }
            else
              {
                if (current_int_2)
                  /* Growing 0 and select all 1. */
                  array_add (current_array_2, current_uuid);
                /* Else growing 0 and select all 0. */
              }
          }
        current_uuid = NULL;
        set_client_state (CLIENT_MODIFY_CONFIG_FAMILY_SELECTION);
        break;
      case CLIENT_MODIFY_CONFIG_FAMILY_SELECTION_GROWING:
        assert (strcasecmp ("GROWING", element_name) == 0);
        if (modify_task_rcfile)
          {
            current_int_3 = atoi (modify_task_rcfile);
            openvas_free_string_var (&modify_task_rcfile);
          }
        else
          current_int_3 = 0;
        set_client_state (CLIENT_MODIFY_CONFIG_FAMILY_SELECTION);
        break;

      case CLIENT_MODIFY_CONFIG_FAMILY_SELECTION_FAMILY_ALL:
        assert (strcasecmp ("ALL", element_name) == 0);
        if (modify_task_rcfile)
          {
            current_int_2 = atoi (modify_task_rcfile);
            openvas_free_string_var (&modify_task_rcfile);
          }
        else
          current_int_2 = 0;
        set_client_state (CLIENT_MODIFY_CONFIG_FAMILY_SELECTION_FAMILY);
        break;
      case CLIENT_MODIFY_CONFIG_FAMILY_SELECTION_FAMILY_NAME:
        assert (strcasecmp ("NAME", element_name) == 0);
        set_client_state (CLIENT_MODIFY_CONFIG_FAMILY_SELECTION_FAMILY);
        break;
      case CLIENT_MODIFY_CONFIG_FAMILY_SELECTION_FAMILY_GROWING:
        assert (strcasecmp ("GROWING", element_name) == 0);
        if (modify_task_rcfile)
          {
            current_int_1 = atoi (modify_task_rcfile);
            openvas_free_string_var (&modify_task_rcfile);
          }
        else
          current_int_1 = 0;
        set_client_state (CLIENT_MODIFY_CONFIG_FAMILY_SELECTION_FAMILY);
        break;

      case CLIENT_MODIFY_CONFIG_NVT_SELECTION_FAMILY:
        assert (strcasecmp ("FAMILY", element_name) == 0);
        set_client_state (CLIENT_MODIFY_CONFIG_NVT_SELECTION);
        break;
      case CLIENT_MODIFY_CONFIG_NVT_SELECTION_NVT:
        assert (strcasecmp ("NVT", element_name) == 0);
        if (current_uuid)
          array_add (current_array_1, current_uuid);
        current_uuid = NULL;
        set_client_state (CLIENT_MODIFY_CONFIG_NVT_SELECTION);
        break;

      case CLIENT_MODIFY_CONFIG_PREFERENCE_NAME:
        assert (strcasecmp ("NAME", element_name) == 0);
        set_client_state (CLIENT_MODIFY_CONFIG_PREFERENCE);
        break;
      case CLIENT_MODIFY_CONFIG_PREFERENCE_NVT:
        assert (strcasecmp ("NVT", element_name) == 0);
        set_client_state (CLIENT_MODIFY_CONFIG_PREFERENCE);
        break;
      case CLIENT_MODIFY_CONFIG_PREFERENCE_VALUE:
        assert (strcasecmp ("VALUE", element_name) == 0);
        /* Init, so it's the empty string when the value is empty. */
        openvas_append_string (&modify_task_value, "");
        set_client_state (CLIENT_MODIFY_CONFIG_PREFERENCE);
        break;

      case CLIENT_MODIFY_REPORT:
        if (modify_task_parameter != NULL
            && modify_task_value != NULL)
          {
            report_t report;

            if (current_uuid == NULL)
              SEND_TO_CLIENT_OR_FAIL
               (XML_ERROR_SYNTAX ("modify_report",
                                  "MODIFY_REPORT requires a report_id attribute"));
            else if (find_report (current_uuid, &report))
              {
                openvas_free_string_var (&current_uuid);
                openvas_free_string_var (&modify_task_parameter);
                openvas_free_string_var (&modify_task_value);
                SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("modify_report"));
              }
            else if (report == 0)
              {
                openvas_free_string_var (&current_uuid);
                openvas_free_string_var (&modify_task_parameter);
                openvas_free_string_var (&modify_task_value);
                if (send_find_error_to_client ("modify_report",
                                               "report",
                                               current_uuid))
                  {
                    error_send_to_client (error);
                    return;
                  }
              }
            else
              {
                int ret = set_report_parameter (report,
                                                modify_task_parameter,
                                                modify_task_value);
                openvas_free_string_var (&modify_task_parameter);
                openvas_free_string_var (&modify_task_value);
                switch (ret)
                  {
                    case 0:
                      SEND_TO_CLIENT_OR_FAIL (XML_OK ("modify_report"));
                      break;
                    case -2: /* Parameter name error. */
                      SEND_TO_CLIENT_OR_FAIL
                       (XML_ERROR_SYNTAX ("modify_report",
                                          "Bogus MODIFY_REPORT parameter"));
                      break;
                    case -3: /* Failed to write to disk. */
                    default:
                      SEND_TO_CLIENT_OR_FAIL
                       (XML_INTERNAL_ERROR ("modify_report"));
                      break;
                  }
              }
          }
        else
          {
            openvas_free_string_var (&modify_task_parameter);
            openvas_free_string_var (&modify_task_value);
            openvas_free_string_var (&current_uuid);
            SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("modify_report"));
          }
        set_client_state (CLIENT_AUTHENTIC);
        break;
      case CLIENT_MODIFY_REPORT_PARAMETER:
        assert (strcasecmp ("PARAMETER", element_name) == 0);
        set_client_state (CLIENT_MODIFY_REPORT);
        break;

      case CLIENT_MODIFY_TASK:
        // FIX update to match create_task (config, target)
        if (current_uuid)
          {
            task_t task;
            assert (current_client_task == (task_t) 0);
            if (find_task (current_uuid, &task))
              SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("modify_task"));
            else if (task == 0)
              {
                if (send_find_error_to_client ("modify_task",
                                               "task",
                                               current_uuid))
                  {
                    error_send_to_client (error);
                    return;
                  }
              }
            else if (current_format
                     && (modify_task_comment
                         || modify_task_name
                         || modify_task_parameter
                         || modify_task_rcfile))
              SEND_TO_CLIENT_OR_FAIL
               (XML_ERROR_SYNTAX ("modify_task",
                                  "Too many parameters at once"));
            else if (current_format)
              {
                if (current_name == NULL)
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("modify_task",
                                      "MODIFY_TASK requires a name attribute"));
                else if (strcmp (current_format, "update") == 0)
                  {
                    manage_task_update_file (task,
                                             current_name,
                                             modify_task_file
                                             ? modify_task_file : "");
                    SEND_TO_CLIENT_OR_FAIL (XML_OK ("modify_task"));
                  }
                else if (strcmp (current_format, "remove") == 0)
                  {
                    manage_task_remove_file (task, current_name);
                    SEND_TO_CLIENT_OR_FAIL (XML_OK ("modify_task"));
                  }
                else
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("modify_task",
                                      "MODIFY_TASK action must be"
                                      " \"update\" or \"remove\""));
              }
            else
              {
                int fail = 0, first = 1;

                /* \todo TODO: It'd probably be better to allow only one
                 * modification at a time, that is, one parameter or one of
                 * file, name and comment.  Otherwise a syntax error in a
                 * later part of the command would result in an error being
                 * returned while some part of the command actually
                 * succeeded. */

                if (modify_task_rcfile)
                  {
                    fail = set_task_parameter (task,
                                               "RCFILE",
                                               modify_task_rcfile);
                    modify_task_rcfile = NULL;
                    if (fail)
                      {
                        openvas_free_string_var (&modify_task_name);
                        openvas_free_string_var (&modify_task_comment);
                        openvas_free_string_var (&modify_task_parameter);
                        openvas_free_string_var (&modify_task_value);
                        SEND_TO_CLIENT_OR_FAIL
                         (XML_INTERNAL_ERROR ("modify_task"));
                      }
                    else
                      first = 0;
                  }

                if (fail == 0 && modify_task_name)
                  {
                    fail = set_task_parameter (task,
                                               "NAME",
                                               modify_task_name);
                    modify_task_name = NULL;
                    if (fail)
                      {
                        openvas_free_string_var (&modify_task_comment);
                        openvas_free_string_var (&modify_task_parameter);
                        openvas_free_string_var (&modify_task_value);
                        SEND_TO_CLIENT_OR_FAIL
                         (XML_INTERNAL_ERROR ("modify_task"));
                      }
                    else
                      first = 0;
                  }

                if (fail == 0 && modify_task_comment)
                  {
                    fail = set_task_parameter (task,
                                               "COMMENT",
                                               modify_task_comment);
                    modify_task_comment = NULL;
                    if (fail)
                      {
                        openvas_free_string_var (&modify_task_parameter);
                        openvas_free_string_var (&modify_task_value);
                        SEND_TO_CLIENT_OR_FAIL
                         (XML_INTERNAL_ERROR ("modify_task"));
                      }
                    else
                      first = 0;
                  }

                if (fail == 0)
                  {
                    if (modify_task_parameter && modify_task_value)
                      {
                        fail = set_task_parameter (task,
                                                   modify_task_parameter,
                                                   modify_task_value);
                        openvas_free_string_var (&modify_task_parameter);
                        modify_task_value = NULL;
                        if (fail)
                          {
                            if (fail == -3)
                              SEND_TO_CLIENT_OR_FAIL
                               (XML_INTERNAL_ERROR ("modify_task"));
                            else
                              SEND_TO_CLIENT_OR_FAIL
                               (XML_ERROR_SYNTAX ("modify_task",
                                                  "Bogus MODIFY_TASK parameter"));
                          }
                        else
                          SEND_TO_CLIENT_OR_FAIL
                           (XML_OK ("modify_task"));
                      }
                    else if (first)
                      {
                        if (modify_task_value)
                          {
                            openvas_free_string_var (&modify_task_value);
                            SEND_TO_CLIENT_OR_FAIL
                             (XML_ERROR_SYNTAX ("modify_task",
                                                "MODIFY_TASK parameter requires"
                                                " an id attribute"));
                          }
                        else if (modify_task_parameter)
                          {
                            openvas_free_string_var (&modify_task_parameter);
                            SEND_TO_CLIENT_OR_FAIL
                             (XML_INTERNAL_ERROR ("modify_task"));
                          }
                        else
                          SEND_TO_CLIENT_OR_FAIL (XML_OK ("modify_task"));
                      }
                    else
                      {
                        openvas_free_string_var (&modify_task_parameter);
                        openvas_free_string_var (&modify_task_value);
                        SEND_TO_CLIENT_OR_FAIL (XML_OK ("modify_task"));
                      }
                  }
              }
            openvas_free_string_var (&current_uuid);
            openvas_free_string_var (&current_format);
            openvas_free_string_var (&current_name);
            openvas_free_string_var (&modify_task_file);
          }
        else
          SEND_TO_CLIENT_OR_FAIL
           (XML_ERROR_SYNTAX ("modify_task",
                              "MODIFY_TASK requires a task_id attribute"));
        set_client_state (CLIENT_AUTHENTIC);
        break;
      case CLIENT_MODIFY_TASK_NAME:
        assert (strcasecmp ("NAME", element_name) == 0);
        set_client_state (CLIENT_MODIFY_TASK);
        break;
      case CLIENT_MODIFY_TASK_PARAMETER:
        assert (strcasecmp ("PARAMETER", element_name) == 0);
        set_client_state (CLIENT_MODIFY_TASK);
        break;
      case CLIENT_MODIFY_TASK_RCFILE:
        assert (strcasecmp ("RCFILE", element_name) == 0);
        set_client_state (CLIENT_MODIFY_TASK);
        break;
      case CLIENT_MODIFY_TASK_FILE:
        assert (strcasecmp ("FILE", element_name) == 0);
        set_client_state (CLIENT_MODIFY_TASK);
        break;

      case CLIENT_CREATE_AGENT:
        {
          assert (strcasecmp ("CREATE_AGENT", element_name) == 0);
          assert (modify_task_name != NULL);

          if (strlen (modify_task_name) == 0)
            {
              SEND_TO_CLIENT_OR_FAIL
               (XML_ERROR_SYNTAX ("create_agent",
                                  "CREATE_AGENT name must be at"
                                  " least one character long"));
            }
          else if (strlen (modify_task_file) == 0)
            {
              SEND_TO_CLIENT_OR_FAIL
               (XML_ERROR_SYNTAX ("create_agent",
                                  "CREATE_AGENT installer must be at"
                                  " least one byte long"));
            }
          else switch (create_agent (modify_task_name,
                                     modify_task_comment,
                                     modify_task_file,      /* Installer. */
                                     modify_task_parameter, /* HOWTO Install. */
                                     modify_task_value))    /* HOWTO Use. */
            {
              case 0:
                SEND_TO_CLIENT_OR_FAIL (XML_OK_CREATED ("create_agent"));
                break;
              case 1:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_agent",
                                    "Agent exists already"));
                break;
              case 2:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_agent",
                                    "Name may only contain alphanumeric"
                                    " characters"));
                break;
              default:
                assert (0);
              case -1:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_INTERNAL_ERROR ("create_agent"));
                break;
            }
          openvas_free_string_var (&modify_task_comment);
          openvas_free_string_var (&modify_task_name);
          openvas_free_string_var (&modify_task_file);
          openvas_free_string_var (&modify_task_parameter);
          openvas_free_string_var (&modify_task_value);
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }
      case CLIENT_CREATE_AGENT_COMMENT:
        assert (strcasecmp ("COMMENT", element_name) == 0);
        set_client_state (CLIENT_CREATE_AGENT);
        break;
      case CLIENT_CREATE_AGENT_HOWTO_INSTALL:
        assert (strcasecmp ("HOWTO_INSTALL", element_name) == 0);
        set_client_state (CLIENT_CREATE_AGENT);
        break;
      case CLIENT_CREATE_AGENT_HOWTO_USE:
        assert (strcasecmp ("HOWTO_USE", element_name) == 0);
        set_client_state (CLIENT_CREATE_AGENT);
        break;
      case CLIENT_CREATE_AGENT_INSTALLER:
        assert (strcasecmp ("INSTALLER", element_name) == 0);
        set_client_state (CLIENT_CREATE_AGENT);
        break;
      case CLIENT_CREATE_AGENT_NAME:
        assert (strcasecmp ("NAME", element_name) == 0);
        set_client_state (CLIENT_CREATE_AGENT);
        break;

      case CLIENT_CREATE_CONFIG:
        {
          assert (strcasecmp ("CREATE_CONFIG", element_name) == 0);
          assert (modify_task_name != NULL);

          if (strlen (modify_task_name) == 0)
            {
              openvas_free_string_var (&modify_task_comment);
              openvas_free_string_var (&modify_task_name);
              openvas_free_string_var (&modify_task_value);
              openvas_free_string_var (&current_name);
              SEND_TO_CLIENT_OR_FAIL
               (XML_ERROR_SYNTAX ("create_config",
                                  // FIX could pass an empty rcfile?
                                  "CREATE_CONFIG name and rcfile must be at"
                                  " least one character long"));
            }
          else if ((modify_task_value && current_name)
                   || (modify_task_value == NULL && current_name == NULL))
            {
              openvas_free_string_var (&modify_task_comment);
              openvas_free_string_var (&modify_task_name);
              openvas_free_string_var (&modify_task_value);
              openvas_free_string_var (&current_name);
              SEND_TO_CLIENT_OR_FAIL
               (XML_ERROR_SYNTAX ("create_config",
                                  "CREATE_CONFIG requires either a COPY or an"
                                  " RCFILE element"));
            }
          else if (modify_task_value)
            {
              int ret;
              gsize base64_len;
              guchar *base64;

              base64 = g_base64_decode (modify_task_value, &base64_len);
              openvas_free_string_var (&modify_task_value);
              /* g_base64_decode can return NULL (Glib 2.12.4-2), at least
               * when modify_task_value is zero length. */
              if (base64 == NULL)
                {
                  base64 = (guchar*) g_strdup ("");
                  base64_len = 0;
                }

              ret = create_config (modify_task_name,
                                   modify_task_comment,
                                   (char*) base64);
              openvas_free_string_var (&modify_task_comment);
              openvas_free_string_var (&modify_task_name);
              g_free (base64);
              switch (ret)
                {
                  case 0:
                    SEND_TO_CLIENT_OR_FAIL (XML_OK_CREATED ("create_config"));
                    break;
                  case 1:
                    SEND_TO_CLIENT_OR_FAIL
                     (XML_ERROR_SYNTAX ("create_config",
                                        "Config exists already"));
                    break;
                  case -1:
                    SEND_TO_CLIENT_OR_FAIL
                     (XML_INTERNAL_ERROR ("create_config"));
                    break;
                }
            }
          else
            {
              int ret;

              assert (current_name);

              ret = copy_config (modify_task_name,
                                 modify_task_comment,
                                 current_name);
              openvas_free_string_var (&modify_task_comment);
              openvas_free_string_var (&modify_task_name);
              openvas_free_string_var (&current_name);
              switch (ret)
                {
                  case 0:
                    SEND_TO_CLIENT_OR_FAIL (XML_OK_CREATED ("create_config"));
                    break;
                  case 1:
                    SEND_TO_CLIENT_OR_FAIL
                     (XML_ERROR_SYNTAX ("create_config",
                                        "Config exists already"));
                    break;
                  case 2:
                    SEND_TO_CLIENT_OR_FAIL
                     (XML_ERROR_SYNTAX ("create_config",
                                        "Copied config must exist"));
                    break;
                  case -1:
                    SEND_TO_CLIENT_OR_FAIL
                     (XML_INTERNAL_ERROR ("create_config"));
                    break;
                }
            }
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }
      case CLIENT_CREATE_CONFIG_COMMENT:
        assert (strcasecmp ("COMMENT", element_name) == 0);
        set_client_state (CLIENT_CREATE_CONFIG);
        break;
      case CLIENT_CREATE_CONFIG_COPY:
        assert (strcasecmp ("COPY", element_name) == 0);
        set_client_state (CLIENT_CREATE_CONFIG);
        break;
      case CLIENT_CREATE_CONFIG_NAME:
        assert (strcasecmp ("NAME", element_name) == 0);
        set_client_state (CLIENT_CREATE_CONFIG);
        break;
      case CLIENT_CREATE_CONFIG_RCFILE:
        assert (strcasecmp ("RCFILE", element_name) == 0);
        set_client_state (CLIENT_CREATE_CONFIG);
        break;

      case CLIENT_CREATE_ESCALATOR:
        {
          event_t event;
          escalator_condition_t condition;
          escalator_method_t method;

          assert (strcasecmp ("CREATE_ESCALATOR", element_name) == 0);
          assert (modify_task_name != NULL);
          assert (modify_task_parameter != NULL);
          assert (modify_task_rcfile != NULL);
          assert (modify_task_value != NULL);

          array_terminate (current_array_1);
          array_terminate (current_array_2);
          array_terminate (current_array_3);

          if (strlen (modify_task_name) == 0)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_escalator",
                                "CREATE_ESCALATOR requires NAME element which"
                                " is at least one character long"));
          else if (strlen (modify_task_parameter) == 0)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_escalator",
                                "CREATE_ESCALATOR requires a value in a"
                                " CONDITION element"));
          else if (strlen (modify_task_value) == 0)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_escalator",
                                "CREATE_ESCALATOR requires a value in an"
                                " EVENT element"));
          else if (strlen (modify_task_rcfile) == 0)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_escalator",
                                "CREATE_ESCALATOR requires a value in a"
                                " METHOD element"));
          else if ((condition = escalator_condition_from_name
                                 (modify_task_parameter))
                   == 0)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_escalator",
                                "Failed to recognise condition name"));
          else if ((event = event_from_name (modify_task_value)) == 0)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_escalator",
                                "Failed to recognise event name"));
          else if ((method = escalator_method_from_name (modify_task_rcfile))
                   == 0)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_escalator",
                                "Failed to recognise method name"));
          else
            {
              switch (create_escalator (modify_task_name,
                                        modify_task_comment,
                                        /* Event. */
                                        event,
                                        /* Event data. */
                                        current_array_2,
                                        /* Condition. */
                                        condition,
                                        /* Condition data. */
                                        current_array_1,
                                        /* Method. */
                                        method,
                                        /* Method data. */
                                        current_array_3))
                {
                  case 0:
                    SEND_TO_CLIENT_OR_FAIL
                     (XML_OK_CREATED ("create_escalator"));
                    break;
                  case 1:
                    SEND_TO_CLIENT_OR_FAIL
                     (XML_ERROR_SYNTAX ("create_escalator",
                                        "Escalator exists already"));
                    break;
                  default:
                    assert (0);
                  case -1:
                    SEND_TO_CLIENT_OR_FAIL
                     (XML_INTERNAL_ERROR ("create_escalator"));
                    break;
                }
            }
          openvas_free_string_var (&current_format);
          openvas_free_string_var (&current_uuid);
          openvas_free_string_var (&modify_task_comment);
          openvas_free_string_var (&modify_task_name);
          openvas_free_string_var (&modify_task_parameter);
          openvas_free_string_var (&modify_task_rcfile);
          openvas_free_string_var (&modify_task_value);
          free_array (current_array_1);
          free_array (current_array_2);
          free_array (current_array_3);
          current_array_1 = NULL;
          current_array_2 = NULL;
          current_array_3 = NULL;
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }
      case CLIENT_CREATE_ESCALATOR_COMMENT:
        assert (strcasecmp ("COMMENT", element_name) == 0);
        set_client_state (CLIENT_CREATE_ESCALATOR);
        break;
      case CLIENT_CREATE_ESCALATOR_CONDITION:
        assert (strcasecmp ("CONDITION", element_name) == 0);
        set_client_state (CLIENT_CREATE_ESCALATOR);
        break;
      case CLIENT_CREATE_ESCALATOR_EVENT:
        assert (strcasecmp ("EVENT", element_name) == 0);
        set_client_state (CLIENT_CREATE_ESCALATOR);
        break;
      case CLIENT_CREATE_ESCALATOR_METHOD:
        assert (strcasecmp ("METHOD", element_name) == 0);
        set_client_state (CLIENT_CREATE_ESCALATOR);
        break;
      case CLIENT_CREATE_ESCALATOR_NAME:
        assert (strcasecmp ("NAME", element_name) == 0);
        set_client_state (CLIENT_CREATE_ESCALATOR);
        break;

      case CLIENT_CREATE_ESCALATOR_CONDITION_DATA:
        {
          gchar *string;

          assert (strcasecmp ("DATA", element_name) == 0);
          assert (current_array_1);
          assert (current_format);
          assert (current_uuid);

          string = g_strconcat (current_uuid, "0", current_format, NULL);
          string[strlen (current_uuid)] = '\0';
          array_add (current_array_1, string);

          openvas_free_string_var (&current_format);
          openvas_free_string_var (&current_uuid);
          openvas_append_string (&current_format, "");
          openvas_append_string (&current_uuid, "");
          set_client_state (CLIENT_CREATE_ESCALATOR_CONDITION);
          break;
        }
      case CLIENT_CREATE_ESCALATOR_CONDITION_DATA_NAME:
        assert (strcasecmp ("NAME", element_name) == 0);
        set_client_state (CLIENT_CREATE_ESCALATOR_CONDITION_DATA);
        break;

      case CLIENT_CREATE_ESCALATOR_EVENT_DATA:
        {
          gchar *string;

          assert (strcasecmp ("DATA", element_name) == 0);
          assert (current_array_2);
          assert (current_format);
          assert (current_uuid);

          string = g_strconcat (current_uuid, "0", current_format, NULL);
          string[strlen (current_uuid)] = '\0';
          array_add (current_array_2, string);

          openvas_free_string_var (&current_format);
          openvas_free_string_var (&current_uuid);
          openvas_append_string (&current_format, "");
          openvas_append_string (&current_uuid, "");
          set_client_state (CLIENT_CREATE_ESCALATOR_EVENT);
          break;
        }
      case CLIENT_CREATE_ESCALATOR_EVENT_DATA_NAME:
        assert (strcasecmp ("NAME", element_name) == 0);
        set_client_state (CLIENT_CREATE_ESCALATOR_EVENT_DATA);
        break;

      case CLIENT_CREATE_ESCALATOR_METHOD_DATA:
        {
          gchar *string;

          assert (strcasecmp ("DATA", element_name) == 0);
          assert (current_array_3);
          assert (current_format);
          assert (current_uuid);

          string = g_strconcat (current_uuid, "0", current_format, NULL);
          string[strlen (current_uuid)] = '\0';
          array_add (current_array_3, string);

          openvas_free_string_var (&current_format);
          openvas_free_string_var (&current_uuid);
          openvas_append_string (&current_format, "");
          openvas_append_string (&current_uuid, "");
          set_client_state (CLIENT_CREATE_ESCALATOR_METHOD);
          break;
        }
      case CLIENT_CREATE_ESCALATOR_METHOD_DATA_NAME:
        assert (strcasecmp ("NAME", element_name) == 0);
        set_client_state (CLIENT_CREATE_ESCALATOR_METHOD_DATA);
        break;

      case CLIENT_CREATE_LSC_CREDENTIAL:
        {
          assert (strcasecmp ("CREATE_LSC_CREDENTIAL", element_name) == 0);
          assert (modify_task_name != NULL);
          assert (current_name != NULL);

          if (strlen (modify_task_name) == 0)
            {
              SEND_TO_CLIENT_OR_FAIL
               (XML_ERROR_SYNTAX ("create_lsc_credential",
                                  "CREATE_LSC_CREDENTIAL name must be at"
                                  " least one character long"));
            }
          else if (strlen (current_name) == 0)
            {
              SEND_TO_CLIENT_OR_FAIL
               (XML_ERROR_SYNTAX ("create_lsc_credential",
                                  "CREATE_LSC_CREDENTIAL login must be at"
                                  " least one character long"));
            }
          else switch (create_lsc_credential (modify_task_name,
                                              modify_task_comment,
                                              current_name,
                                              modify_task_parameter))
            {
              case 0:
                SEND_TO_CLIENT_OR_FAIL (XML_OK_CREATED ("create_lsc_credential"));
                break;
              case 1:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_lsc_credential",
                                    "LSC Credential exists already"));
                break;
              case 2:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_lsc_credential",
                                    "Name may only contain alphanumeric"
                                    " characters"));
                break;
              default:
                assert (0);
              case -1:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_INTERNAL_ERROR ("create_lsc_credential"));
                break;
            }
          openvas_free_string_var (&modify_task_comment);
          openvas_free_string_var (&current_name);
          openvas_free_string_var (&modify_task_name);
          openvas_free_string_var (&modify_task_parameter);
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }
      case CLIENT_CREATE_LSC_CREDENTIAL_COMMENT:
        assert (strcasecmp ("COMMENT", element_name) == 0);
        set_client_state (CLIENT_CREATE_LSC_CREDENTIAL);
        break;
      case CLIENT_CREATE_LSC_CREDENTIAL_LOGIN:
        assert (strcasecmp ("LOGIN", element_name) == 0);
        set_client_state (CLIENT_CREATE_LSC_CREDENTIAL);
        break;
      case CLIENT_CREATE_LSC_CREDENTIAL_NAME:
        assert (strcasecmp ("NAME", element_name) == 0);
        set_client_state (CLIENT_CREATE_LSC_CREDENTIAL);
        break;
      case CLIENT_CREATE_LSC_CREDENTIAL_PASSWORD:
        assert (strcasecmp ("PASSWORD", element_name) == 0);
        set_client_state (CLIENT_CREATE_LSC_CREDENTIAL);
        break;

      case CLIENT_CREATE_TARGET:
        {
          assert (strcasecmp ("CREATE_TARGET", element_name) == 0);
          assert (modify_task_name != NULL);
          assert (modify_task_value != NULL);

          if (strlen (modify_task_name) == 0
              || strlen (modify_task_value) == 0)
            {
              openvas_free_string_var (&modify_task_comment);
              openvas_free_string_var (&modify_task_name);
              openvas_free_string_var (&modify_task_value);
              openvas_free_string_var (&modify_task_parameter);
              SEND_TO_CLIENT_OR_FAIL
               (XML_ERROR_SYNTAX ("create_target",
                                  // FIX could pass an empty hosts element?
                                  "CREATE_TARGET name and hosts must both be at"
                                  " least one character long"));
            }
          else if (create_target (modify_task_name,
                                  modify_task_value,
                                  modify_task_comment,
                                  modify_task_parameter))
            {
              openvas_free_string_var (&modify_task_comment);
              openvas_free_string_var (&modify_task_name);
              openvas_free_string_var (&modify_task_value);
              openvas_free_string_var (&modify_task_parameter);
              SEND_TO_CLIENT_OR_FAIL
               (XML_ERROR_SYNTAX ("create_target",
                                  "Target exists already"));
            }
          else
            {
              openvas_free_string_var (&modify_task_comment);
              openvas_free_string_var (&modify_task_name);
              openvas_free_string_var (&modify_task_value);
              openvas_free_string_var (&modify_task_parameter);
              SEND_TO_CLIENT_OR_FAIL (XML_OK_CREATED ("create_target"));
            }
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }
      case CLIENT_CREATE_TARGET_COMMENT:
        assert (strcasecmp ("COMMENT", element_name) == 0);
        set_client_state (CLIENT_CREATE_TARGET);
        break;
      case CLIENT_CREATE_TARGET_HOSTS:
        assert (strcasecmp ("HOSTS", element_name) == 0);
        set_client_state (CLIENT_CREATE_TARGET);
        break;
      case CLIENT_CREATE_TARGET_NAME:
        assert (strcasecmp ("NAME", element_name) == 0);
        set_client_state (CLIENT_CREATE_TARGET);
        break;
      case CLIENT_CREATE_TARGET_LSC_CREDENTIAL:
        assert (strcasecmp ("LSC_CREDENTIAL", element_name) == 0);
        set_client_state (CLIENT_CREATE_TARGET);
        break;

      case CLIENT_CREATE_TASK:
        {
          gchar* msg;
          char *tsk_uuid, *name, *description, *config, *target;

          assert (strcasecmp ("CREATE_TASK", element_name) == 0);
          assert (current_client_task != (task_t) 0);

          /* The task already exists in the database at this point,
           * including the RC file (in the description column), so on
           * failure be sure to call request_delete_task to remove the
           * task. */
          // FIX fail cases of CLIENT_CREATE_TASK_* states must do so too

          /* Get the task ID. */

          if (task_uuid (current_client_task, &tsk_uuid))
            {
              request_delete_task (&current_client_task);
              if (send_find_error_to_client ("create_task",
                                             "task",
                                             current_uuid))
                {
                  error_send_to_client (error);
                  return;
                }
              current_client_task = (task_t) 0;
              openvas_free_string_var (&modify_task_name);
              set_client_state (CLIENT_AUTHENTIC);
              break;
            }

          /* Check for the right combination of rcfile, target and config. */

          description = task_description (current_client_task);
          config = task_config (current_client_task);
          target = task_target (current_client_task);
          if ((description && (config || target))
              || (description == NULL
                  && (config == NULL || target == NULL)))
            {
              request_delete_task (&current_client_task);
              free (tsk_uuid);
              free (config);
              free (target);
              SEND_TO_CLIENT_OR_FAIL
               (XML_ERROR_SYNTAX ("create_task",
                                  "CREATE_TASK requires either an rcfile"
                                  " or both a config and a target"));
              current_client_task = (task_t) 0;
              openvas_free_string_var (&modify_task_name);
              set_client_state (CLIENT_AUTHENTIC);
              break;
            }

          /* Set any escalator. */

          if (strlen (modify_task_name))
            {
              escalator_t escalator;
              if (find_escalator (modify_task_name, &escalator))
                {
                  SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("create_task"));
                  openvas_free_string_var (&modify_task_name);
                  break;
                }
              if (escalator == 0)
                {
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("create_task",
                                      "CREATE_TASK escalator must exist"));
                  openvas_free_string_var (&modify_task_name);
                  break;
                }
              add_task_escalator (current_client_task, modify_task_name);
            }
          openvas_free_string_var (&modify_task_name);

          /* Check for name. */

          name = task_name (current_client_task);
          if (name == NULL)
            {
              request_delete_task (&current_client_task);
              free (tsk_uuid);
              free (description);
              free (config);
              free (target);
              SEND_TO_CLIENT_OR_FAIL
               (XML_ERROR_SYNTAX ("create_task",
                                  "CREATE_TASK requires a name attribute"));
              current_client_task = (task_t) 0;
              set_client_state (CLIENT_AUTHENTIC);
              break;
            }

          /* If there's an rc file, setup the target and config, otherwise
           * check that the target and config exist. */

          if (description)
            {
              int ret;
              char *hosts;
              gchar *target_name, *config_name;

              /* Create the config. */

              config_name = g_strdup_printf ("Imported config for task %s",
                                             tsk_uuid);
              ret = create_config (config_name, NULL, (char*) description);
              set_task_config (current_client_task, config_name);
              g_free (config_name);
              if (ret)
                {
                  request_delete_task (&current_client_task);
                  free (description);
                  SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("create_task"));
                  current_client_task = (task_t) 0;
                  set_client_state (CLIENT_AUTHENTIC);
                  break;
                }

              /* Create the target. */

              hosts = rc_preference (description, "targets");
              if (hosts == NULL)
                {
                  request_delete_task (&current_client_task);
                  free (description);
                  free (tsk_uuid);
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX
                     ("create_task",
                      "CREATE_TASK rcfile must have targets"));
                  current_client_task = (task_t) 0;
                  set_client_state (CLIENT_AUTHENTIC);
                  break;
                }
              free (description);

              target_name = g_strdup_printf ("Imported target for task %s",
                                             tsk_uuid);
              set_task_target (current_client_task, target_name);
              if (create_target (target_name, hosts, NULL, NULL))
                {
                  request_delete_task (&current_client_task);
                  g_free (target_name);
                  free (tsk_uuid);
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_INTERNAL_ERROR ("create_task"));
                  current_client_task = (task_t) 0;
                  set_client_state (CLIENT_AUTHENTIC);
                  break;
                }
              g_free (target_name);
            }
          else
            {
              if (target_hosts (target) == NULL)
                {
                  request_delete_task (&current_client_task);
                  free (tsk_uuid);
                  free (config);
                  free (target);
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("create_task",
                                      "CREATE_TASK target must exist"));
                  current_client_task = (task_t) 0;
                  set_client_state (CLIENT_AUTHENTIC);
                  break;
                }
              if (config_nvt_selector (config) == NULL)
                {
                  request_delete_task (&current_client_task);
                  free (tsk_uuid);
                  free (config);
                  free (target);
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("create_task",
                                      "CREATE_TASK config must exist"));
                  current_client_task = (task_t) 0;
                  set_client_state (CLIENT_AUTHENTIC);
                  break;
                }

              /* Generate the rcfile in the task. */

              if (make_task_rcfile (current_client_task))
                {
                  request_delete_task (&current_client_task);
                  free (tsk_uuid);
                  free (config);
                  free (target);
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("create_task",
                                      "Failed to generate task rcfile"));
                  current_client_task = (task_t) 0;
                  set_client_state (CLIENT_AUTHENTIC);
                  break;
                }
            }

          /* Send success response. */

          msg = g_strdup_printf
                 ("<create_task_response"
                  " status=\"" STATUS_OK_CREATED "\""
                  " status_text=\"" STATUS_OK_CREATED_TEXT "\">"
                  "<task_id>%s</task_id>"
                  "</create_task_response>",
                  tsk_uuid);
          free (tsk_uuid);
          if (send_to_client (msg))
            {
              g_free (msg);
              error_send_to_client (error);
              return;
            }
          g_free (msg);
          current_client_task = (task_t) 0;
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }
      case CLIENT_CREATE_TASK_COMMENT:
        assert (strcasecmp ("COMMENT", element_name) == 0);
        set_client_state (CLIENT_CREATE_TASK);
        break;
      case CLIENT_CREATE_TASK_CONFIG:
        assert (strcasecmp ("CONFIG", element_name) == 0);
        set_client_state (CLIENT_CREATE_TASK);
        break;
      case CLIENT_CREATE_TASK_ESCALATOR:
        assert (strcasecmp ("ESCALATOR", element_name) == 0);
        set_client_state (CLIENT_CREATE_TASK);
        break;
      case CLIENT_CREATE_TASK_NAME:
        assert (strcasecmp ("NAME", element_name) == 0);
        set_client_state (CLIENT_CREATE_TASK);
        break;
      case CLIENT_CREATE_TASK_RCFILE:
        assert (strcasecmp ("RCFILE", element_name) == 0);
        if (current_client_task)
          {
            gsize out_len;
            guchar* out;
            char* description = task_description (current_client_task);
            if (description)
              {
                out = g_base64_decode (description, &out_len);
                /* g_base64_decode can return NULL (Glib 2.12.4-2), at least
                 * when description is zero length. */
                if (out == NULL)
                  {
                    out = (guchar*) g_strdup ("");
                    out_len = 0;
                  }
              }
            else
              {
                out = (guchar*) g_strdup ("");
                out_len = 0;
              }
            free (description);
            set_task_description (current_client_task, (char*) out, out_len);
            set_client_state (CLIENT_CREATE_TASK);
          }
        break;
      case CLIENT_CREATE_TASK_TARGET:
        assert (strcasecmp ("TARGET", element_name) == 0);
        set_client_state (CLIENT_CREATE_TASK);
        break;

      case CLIENT_TEST_ESCALATOR:
        if (current_name)
          {
            escalator_t escalator;
            task_t task;

            if (find_escalator (current_name, &escalator))
              SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("test_escalator"));
            else if (escalator == 0)
              {
                if (send_find_error_to_client ("test_escalator",
                                               "escalator",
                                               current_uuid))
                  {
                    error_send_to_client (error);
                    return;
                  }
              }
            else if (find_task (MANAGE_EXAMPLE_TASK_UUID, &task))
              SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("test_escalator"));
            else if (task == 0)
              SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("test_escalator"));
            else switch (escalate (escalator,
                                   task,
                                   EVENT_TASK_RUN_STATUS_CHANGED,
                                   (void*) TASK_STATUS_DONE))
              {
                case 0:
                  SEND_TO_CLIENT_OR_FAIL (XML_OK ("test_escalator"));
                  break;
                case -1:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_INTERNAL_ERROR ("test_escalator"));
                  break;
                default: /* Programming error. */
                  assert (0);
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_INTERNAL_ERROR ("test_escalator"));
                  break;
              }
            openvas_free_string_var (&current_name);
          }
        else
          SEND_TO_CLIENT_OR_FAIL
           (XML_ERROR_SYNTAX ("test_escalator",
                              "TEST_ESCALATOR requires a name element"));
        set_client_state (CLIENT_AUTHENTIC);
        break;
      case CLIENT_TEST_ESCALATOR_NAME:
        assert (strcasecmp ("NAME", element_name) == 0);
        set_client_state (CLIENT_TEST_ESCALATOR);
        break;

      case CLIENT_START_TASK:
        if (current_uuid)
          {
            task_t task;
            assert (current_client_task == (task_t) 0);
            if (find_task (current_uuid, &task))
              SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("start_task"));
            else if (task == 0)
              {
                if (send_find_error_to_client ("start_task",
                                               "task",
                                               current_uuid))
                  {
                    error_send_to_client (error);
                    return;
                  }
              }
            else if (forked == 2)
              /* Prevent the forked child from forking again, as then both
               * forked children would be using the same server session. */
              abort (); // FIX respond with error or something
            else
              {
                char *report_id;
                switch (start_task (task, &report_id))
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
                                report_id);
                        free (report_id);
                        if (send_to_client (msg))
                          {
                            g_free (msg);
                            error_send_to_client (error);
                            return;
                          }
                        g_free (msg);
                      }
                      forked = 1;
                      break;
                    case 1:
                      SEND_TO_CLIENT_OR_FAIL
                       (XML_ERROR_SYNTAX ("start_task",
                                          "Task is active already"));
                      break;
                    case 2:
                      /* Forked task process: success. */
                      current_error = 2;
                      g_set_error (error,
                                   G_MARKUP_ERROR,
                                   G_MARKUP_ERROR_INVALID_CONTENT,
                                   "Dummy error for current_error");
                      break;
                    case -10:
                      /* Forked task process: error. */
                      current_error = -10;
                      g_set_error (error,
                                   G_MARKUP_ERROR,
                                   G_MARKUP_ERROR_INVALID_CONTENT,
                                   "Dummy error for current_error");
                      break;
                    case -6:
                      SEND_TO_CLIENT_OR_FAIL
                       (XML_ERROR_SYNTAX ("start_task",
                                          "There is already a task running in"
                                          " this process"));
                      break;
                    case -2:
                      /* Task target lacks hosts.  This is checked when the
                       * target is created. */
                      assert (0);
                      /*@fallthrough@*/
                    case -4:
                      /* Task lacks target.  This is checked when the task is
                       * created anyway. */
                      assert (0);
                      /*@fallthrough@*/
                    case -3: /* Failed to create report. */
                      SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("start_task"));
                      break;
                    default: /* Programming error. */
                      assert (0);
                      SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("start_task"));
                      break;
                  }
              }
            openvas_free_string_var (&current_uuid);
          }
        else
          SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("start_task"));
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_GET_STATUS:
        assert (strcasecmp ("GET_STATUS", element_name) == 0);
        if (current_uuid && strlen (current_uuid))
          {
            task_t task;
            if (find_task (current_uuid, &task))
              SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_status"));
            else if (task == 0)
              {
                if (send_find_error_to_client ("get_status",
                                               "task",
                                               current_uuid))
                  {
                    error_send_to_client (error);
                    return;
                  }
              }
            else
              {
                char* tsk_uuid;

                if (task_uuid (task, &tsk_uuid))
                  SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_status"));
                else
                  {
                    int ret, maximum_hosts;
                    gchar *response, *progress_xml;
                    char *name, *config, *escalator, *target, *hosts;
                    gchar *first_report_id, *first_report;
                    char* description;
                    gchar *description64, *last_report_id, *last_report;
                    gchar *second_last_report_id, *second_last_report;
                    report_t running_report;

                    target = task_target (task);
                    hosts = target ? target_hosts (target) : NULL;
                    maximum_hosts = hosts ? max_hosts (hosts) : 0;

                    first_report_id = task_first_report_id (task);
                    if (first_report_id)
                      {
                        int debugs, holes, infos, logs, warnings;
                        gchar *timestamp;

                        if (report_counts (first_report_id,
                                           &debugs, &holes, &infos, &logs,
                                           &warnings))
                          abort (); // FIX fail better

                        if (report_timestamp (first_report_id, &timestamp))
                          abort (); // FIX fail better

                        first_report = g_strdup_printf ("<first_report>"
                                                        "<report id=\"%s\">"
                                                        "<timestamp>"
                                                        "%s"
                                                        "</timestamp>"
                                                        "<messages>"
                                                        "<debug>%i</debug>"
                                                        "<hole>%i</hole>"
                                                        "<info>%i</info>"
                                                        "<log>%i</log>"
                                                        "<warning>%i</warning>"
                                                        "</messages>"
                                                        "</report>"
                                                        "</first_report>",
                                                        first_report_id,
                                                        timestamp,
                                                        debugs,
                                                        holes,
                                                        infos,
                                                        logs,
                                                        warnings);
                        g_free (timestamp);
                        g_free (first_report_id);
                      }
                    else
                      first_report = g_strdup ("");

                    last_report_id = task_last_report_id (task);
                    if (last_report_id)
                      {
                        int debugs, holes, infos, logs, warnings;
                        gchar *timestamp;

                        if (report_counts (last_report_id,
                                           &debugs, &holes, &infos, &logs,
                                           &warnings))
                          abort (); // FIX fail better

                        if (report_timestamp (last_report_id, &timestamp))
                          abort (); // FIX fail better

                        last_report = g_strdup_printf ("<last_report>"
                                                       "<report id=\"%s\">"
                                                       "<timestamp>"
                                                       "%s"
                                                       "</timestamp>"
                                                       "<messages>"
                                                       "<debug>%i</debug>"
                                                       "<hole>%i</hole>"
                                                       "<info>%i</info>"
                                                       "<log>%i</log>"
                                                       "<warning>%i</warning>"
                                                       "</messages>"
                                                       "</report>"
                                                       "</last_report>",
                                                       last_report_id,
                                                       timestamp,
                                                       debugs,
                                                       holes,
                                                       infos,
                                                       logs,
                                                       warnings);
                        g_free (timestamp);
                        g_free (last_report_id);
                      }
                    else
                      last_report = g_strdup ("");

                    second_last_report_id = task_second_last_report_id (task);
                    if (second_last_report_id)
                      {
                        int debugs, holes, infos, logs, warnings;
                        gchar *timestamp;

                        if (report_counts (second_last_report_id,
                                           &debugs, &holes, &infos, &logs,
                                           &warnings))
                          abort (); // FIX fail better

                        if (report_timestamp (second_last_report_id,
                                              &timestamp))
                          abort (); // FIX fail better

                        second_last_report = g_strdup_printf
                                              ("<second_last_report>"
                                               "<report id=\"%s\">"
                                               "<timestamp>"
                                               "%s"
                                               "</timestamp>"
                                               "<messages>"
                                               "<debug>%i</debug>"
                                               "<hole>%i</hole>"
                                               "<info>%i</info>"
                                               "<log>%i</log>"
                                               "<warning>%i</warning>"
                                               "</messages>"
                                               "</report>"
                                               "</second_last_report>",
                                               second_last_report_id,
                                               timestamp,
                                               debugs,
                                               holes,
                                               infos,
                                               logs,
                                               warnings);
                        g_free (timestamp);
                        g_free (second_last_report_id);
                      }
                    else
                      second_last_report = g_strdup ("");

                    running_report = task_running_report (task);
                    if (running_report)
                      {
                        long total = 0;
                        int num_hosts = 0, total_progress;
                        iterator_t hosts;
                        GString *string = g_string_new ("");

                        init_host_iterator (&hosts, running_report);
                        while (next (&hosts))
                          {
                            unsigned int max_port, current_port;
                            long progress;

                            max_port = host_iterator_max_port (&hosts);
                            current_port = host_iterator_current_port (&hosts);
                            if (max_port)
                              {
                                progress = (current_port * 100) / max_port;
                                if (progress < 0) progress = 0;
                                else if (progress > 100) progress = 100;
                              }
                            else
                              progress = current_port ? 100 : 0;

#if 1
                            tracef ("   attack_state: %s\n", host_iterator_attack_state (&hosts));
                            tracef ("   current_port: %u\n", current_port);
                            tracef ("   max_port: %u\n", max_port);
                            tracef ("   progress for %s: %li\n", host_iterator_host (&hosts), progress);
                            tracef ("   total now: %li\n", total);
#endif
                            total += progress;
                            num_hosts++;

                            g_string_append_printf (string,
                                                    "<host_progress>"
                                                    "<host>%s</host>"
                                                    "%li"
                                                    "</host_progress>",
                                                    host_iterator_host (&hosts),
                                                    progress);
                          }
                        cleanup_iterator (&hosts);

                        total_progress = maximum_hosts
                                         ? (total / maximum_hosts) : 0;

#if 1
                        tracef ("   total: %li\n", total);
                        tracef ("   num_hosts: %i\n", num_hosts);
                        tracef ("   maximum_hosts: %i\n", maximum_hosts);
                        tracef ("   total_progress: %i\n", total_progress);
#endif

                        g_string_append_printf (string,
                                                "%i",
                                                total_progress);
                        progress_xml = g_string_free (string, FALSE);
                      }
                    else
                      progress_xml = g_strdup ("-1");

                    if (current_int_1)
                      {
                        description = task_description (task);
                        if (description && strlen (description))
                          {
                            gchar *d64;
                            d64 = g_base64_encode ((guchar*) description,
                                                   strlen (description));
                            description64 = g_strdup_printf ("<rcfile>"
                                                             "%s"
                                                             "</rcfile>",
                                                             d64);
                            g_free (d64);
                          }
                        else
                          description64 = g_strdup ("<rcfile></rcfile>");
                        free (description);
                      }
                    else
                      description64 = g_strdup ("");

                    name = task_name (task);
                    escalator = task_escalator (task);
                    config = task_config (task);
                    response = g_strdup_printf
                                ("<get_status_response"
                                 " status=\"" STATUS_OK "\""
                                 " status_text=\"" STATUS_OK_TEXT "\">"
                                 "<task id=\"%s\">"
                                 "<name>%s</name>"
                                 "<config><name>%s</name></config>"
                                 "<escalator><name>%s</name></escalator>"
                                 "<target><name>%s</name></target>"
                                 "<status>%s</status>"
                                 "<progress>%s</progress>"
                                 "%s"
                                 "<messages>"
                                 "<debug>%i</debug>"
                                 "<hole>%i</hole>"
                                 "<info>%i</info>"
                                 "<log>%i</log>"
                                 "<warning>%i</warning>"
                                 "</messages>"
                                 "<report_count>"
                                 "%u<finished>%u</finished>"
                                 "</report_count>"
                                 "%s%s%s",
                                 tsk_uuid,
                                 name,
                                 config ? config : "",
                                 escalator ? escalator : "",
                                 target ? target : "",
                                 task_run_status_name (task),
                                 progress_xml,
                                 description64,
                                 task_debugs_size (task),
                                 task_holes_size (task),
                                 task_infos_size (task),
                                 task_logs_size (task),
                                 task_warnings_size (task),
                                 task_report_count (task),
                                 task_finished_report_count (task),
                                 first_report,
                                 last_report,
                                 second_last_report);
                    free (config);
                    free (escalator);
                    free (target);
                    g_free (progress_xml);
                    g_free (last_report);
                    g_free (second_last_report);
                    ret = send_to_client (response);
                    g_free (response);
                    g_free (name);
                    g_free (description64);
                    free (tsk_uuid);
                    if (ret)
                      {
                        error_send_to_client (error);
                        return;
                      }
                    // FIX need to handle err cases before send status
                    (void) send_reports (task);
                    SEND_TO_CLIENT_OR_FAIL ("</task>"
                                            "</get_status_response>");
                  }
              }
            openvas_free_string_var (&current_uuid);
          }
        else if (current_uuid)
          SEND_TO_CLIENT_OR_FAIL
           (XML_ERROR_SYNTAX ("get_status",
                              "GET_STATUS task_id attribute must be at least"
                              " one character long"));
        else
          {
            gchar* response;
            task_iterator_t iterator;
            task_t index;

            // TODO: A lot of this block is the same as the one above.

            openvas_free_string_var (&current_uuid);

            SEND_TO_CLIENT_OR_FAIL ("<get_status_response"
                                    " status=\"" STATUS_OK "\""
                                    " status_text=\"" STATUS_OK_TEXT "\">");
            response = g_strdup_printf ("<task_count>%u</task_count>",
                                        task_count ());
            if (send_to_client (response))
              {
                g_free (response);
                error_send_to_client (error);
                return;
              }
            g_free (response);

            SENDF_TO_CLIENT_OR_FAIL
             ("<sort>"
              "<field>%s<order>%s</order></field>"
              "</sort>",
              current_format ? current_format : "ROWID",
              current_int_2 ? "ascending" : "descending");

            init_task_iterator (&iterator,
                                current_int_2,      /* Attribute sort_order. */
                                current_format);    /* Attribute sort_field. */
            while (next_task (&iterator, &index))
              {
                gchar *line, *progress_xml;
                char *name = task_name (index);
                char *tsk_uuid, *config, *escalator, *target, *hosts;
                gchar *first_report_id, *first_report;
                char *description;
                gchar *description64, *last_report_id, *last_report;
                gchar *second_last_report_id, *second_last_report;
                report_t running_report;
                int maximum_hosts;

                // FIX buffer entire response so this can respond on err
                if (task_uuid (index, &tsk_uuid)) abort ();

                target = task_target (index);
                hosts = target ? target_hosts (target) : NULL;
                maximum_hosts = hosts ? max_hosts (hosts) : 0;

                first_report_id = task_first_report_id (index);
                if (first_report_id)
                  {
                    int debugs, holes, infos, logs, warnings;
                    gchar *timestamp;

                    if (report_counts (first_report_id,
                                       &debugs, &holes, &infos, &logs,
                                       &warnings))
                      abort (); // FIX fail better

                    if (report_timestamp (first_report_id, &timestamp))
                      abort (); // FIX fail better

                    first_report = g_strdup_printf ("<first_report>"
                                                    "<report id=\"%s\">"
                                                    "<timestamp>"
                                                    "%s"
                                                    "</timestamp>"
                                                    "<messages>"
                                                    "<debug>%i</debug>"
                                                    "<hole>%i</hole>"
                                                    "<info>%i</info>"
                                                    "<log>%i</log>"
                                                    "<warning>%i</warning>"
                                                    "</messages>"
                                                    "</report>"
                                                    "</first_report>",
                                                    first_report_id,
                                                    timestamp,
                                                    debugs,
                                                    holes,
                                                    infos,
                                                    logs,
                                                    warnings);
                    g_free (timestamp);
                    g_free (first_report_id);
                  }
                else
                  first_report = g_strdup ("");

                last_report_id = task_last_report_id (index);
                if (last_report_id)
                  {
                    int debugs, holes, infos, logs, warnings;
                    gchar *timestamp;

                    if (report_counts (last_report_id,
                                       &debugs, &holes, &infos, &logs,
                                       &warnings))
                      abort (); // FIX fail better

                    if (report_timestamp (last_report_id, &timestamp))
                      abort ();

                    last_report = g_strdup_printf ("<last_report>"
                                                   "<report id=\"%s\">"
                                                   "<timestamp>%s</timestamp>"
                                                   "<messages>"
                                                   "<debug>%i</debug>"
                                                   "<hole>%i</hole>"
                                                   "<info>%i</info>"
                                                   "<log>%i</log>"
                                                   "<warning>%i</warning>"
                                                   "</messages>"
                                                   "</report>"
                                                   "</last_report>",
                                                   last_report_id,
                                                   timestamp,
                                                   debugs,
                                                   holes,
                                                   infos,
                                                   logs,
                                                   warnings);
                    g_free (timestamp);
                    g_free (last_report_id);
                  }
                else
                  last_report = g_strdup ("");

                if (current_int_1)
                  {
                    description = task_description (index);
                    if (description && strlen (description))
                      {
                        gchar *d64;
                        d64 = g_base64_encode ((guchar*) description,
                                               strlen (description));
                        description64 = g_strdup_printf ("<rcfile>"
                                                         "%s"
                                                         "</rcfile>",
                                                         d64);
                        g_free (d64);
                      }
                    else
                      description64 = g_strdup ("<rcfile></rcfile>");
                    free (description);
                  }
                else
                  description64 = g_strdup ("");

                second_last_report_id = task_second_last_report_id (index);
                if (second_last_report_id)
                  {
                    int debugs, holes, infos, logs, warnings;
                    gchar *timestamp;

                    if (report_counts (second_last_report_id,
                                       &debugs, &holes, &infos, &logs,
                                       &warnings))
                      abort (); // FIX fail better

                    if (report_timestamp (second_last_report_id, &timestamp))
                      abort ();

                    second_last_report = g_strdup_printf
                                          ("<second_last_report>"
                                           "<report id=\"%s\">"
                                           "<timestamp>%s</timestamp>"
                                           "<messages>"
                                           "<debug>%i</debug>"
                                           "<hole>%i</hole>"
                                           "<info>%i</info>"
                                           "<log>%i</log>"
                                           "<warning>%i</warning>"
                                           "</messages>"
                                           "</report>"
                                           "</second_last_report>",
                                           second_last_report_id,
                                           timestamp,
                                           debugs,
                                           holes,
                                           infos,
                                           logs,
                                           warnings);
                    g_free (timestamp);
                    g_free (second_last_report_id);
                  }
                else
                  second_last_report = g_strdup ("");

                running_report = task_running_report (index);
                if (running_report)
                  {
                    long total = 0;
                    int num_hosts = 0, total_progress;
                    iterator_t hosts;
                    GString *string = g_string_new ("");

                    init_host_iterator (&hosts, running_report);
                    while (next (&hosts))
                      {
                        unsigned int max_port, current_port;
                        long progress;

                        max_port = host_iterator_max_port (&hosts);
                        current_port = host_iterator_current_port (&hosts);
                        if (max_port)
                          {
                            progress = (current_port * 100) / max_port;
                            if (progress < 0) progress = 0;
                            else if (progress > 100) progress = 100;
                          }
                        else
                          progress = current_port ? 100 : 0;
                        total += progress;
                        num_hosts++;

#if 1
                        tracef ("   attack_state: %s\n", host_iterator_attack_state (&hosts));
                        tracef ("   current_port: %u\n", current_port);
                        tracef ("   max_port: %u\n", max_port);
                        tracef ("   progress for %s: %li\n", host_iterator_host (&hosts), progress);
                        tracef ("   total now: %li\n", total);
#endif

                        g_string_append_printf (string,
                                                "<host_progress>"
                                                "<host>%s</host>"
                                                "%li"
                                                "</host_progress>",
                                                host_iterator_host (&hosts),
                                                progress);
                      }
                    cleanup_iterator (&hosts);

                    total_progress = maximum_hosts ? (total / maximum_hosts) : 0;

#if 1
                    tracef ("   total: %li\n", total);
                    tracef ("   num_hosts: %i\n", num_hosts);
                    tracef ("   maximum_hosts: %i\n", maximum_hosts);
                    tracef ("   total_progress: %i\n", total_progress);
#endif

                    g_string_append_printf (string,
                                            "%i",
                                            total_progress);
                    progress_xml = g_string_free (string, FALSE);
                  }
                else
                  progress_xml = g_strdup ("-1");

                config = task_config (index);
                escalator = task_escalator (index);
                line = g_strdup_printf ("<task"
                                        " id=\"%s\">"
                                        "<name>%s</name>"
                                        "<config><name>%s</name></config>"
                                        "<escalator><name>%s</name></escalator>"
                                        "<target><name>%s</name></target>"
                                        "<status>%s</status>"
                                        "<progress>%s</progress>"
                                        "%s"
                                        "<messages>"
                                        "<debug>%i</debug>"
                                        "<hole>%i</hole>"
                                        "<info>%i</info>"
                                        "<log>%i</log>"
                                        "<warning>%i</warning>"
                                        "</messages>"
                                        "<report_count>"
                                        "%u<finished>%u</finished>"
                                        "</report_count>"
                                        "%s%s%s"
                                        "</task>",
                                        tsk_uuid,
                                        name,
                                        config ? config : "",
                                        escalator ? escalator : "",
                                        target ? target : "",
                                        task_run_status_name (index),
                                        progress_xml,
                                        description64,
                                        task_debugs_size (index),
                                        task_holes_size (index),
                                        task_infos_size (index),
                                        task_logs_size (index),
                                        task_warnings_size (index),
                                        task_report_count (index),
                                        task_finished_report_count (index),
                                        first_report,
                                        last_report,
                                        second_last_report);
                free (config);
                free (escalator);
                free (target);
                g_free (progress_xml);
                g_free (last_report);
                g_free (second_last_report);
                free (name);
                g_free (description64);
                free (tsk_uuid);
                if (send_to_client (line))
                  {
                    g_free (line);
                    error_send_to_client (error);
                    cleanup_task_iterator (&iterator);
                    return;
                  }
                g_free (line);
              }
            cleanup_task_iterator (&iterator);
            SEND_TO_CLIENT_OR_FAIL ("</get_status_response>");
          }
        openvas_free_string_var (&current_format);
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_GET_AGENTS:
        {
          iterator_t targets;
          int format;
          assert (strcasecmp ("GET_AGENTS", element_name) == 0);

          if (current_format)
            {
              if (strlen (current_format))
                {
                  if (strcasecmp (current_format, "installer") == 0)
                    format = 1;
                  else if (strcasecmp (current_format, "howto_install") == 0)
                    format = 2;
                  else if (strcasecmp (current_format, "howto_use") == 0)
                    format = 3;
                  else
                    format = -1;
                }
              else
                format = 0;
              openvas_free_string_var (&current_format);
            }
          else
            format = 0;
          if (format == -1)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("get_agents",
                                "GET_AGENTS format attribute should"
                                " be \"installer\", \"howto_install\" or \"howto_use\"."));
          else
            {
              SEND_TO_CLIENT_OR_FAIL ("<get_agents_response"
                                      " status=\"" STATUS_OK "\""
                                      " status_text=\"" STATUS_OK_TEXT "\">");
              init_agent_iterator (&targets,
                                   current_uuid,
                                   /* Attribute sort_order. */
                                   current_int_2,
                                   /* Attribute sort_field. */
                                   current_name);
              while (next (&targets))
                {
                  switch (format)
                    {
                      case 1: /* installer */
                        SENDF_TO_CLIENT_OR_FAIL
                         ("<agent>"
                          "<name>%s</name>"
                          "<comment>%s</comment>"
                          "<package format=\"installer\">%s</package>"
                          "<in_use>0</in_use>"
                          "</agent>",
                          agent_iterator_name (&targets),
                          agent_iterator_comment (&targets),
                          agent_iterator_installer (&targets));
                        break;
                      case 2: /* howto_install */
                        SENDF_TO_CLIENT_OR_FAIL
                         ("<agent>"
                          "<name>%s</name>"
                          "<comment>%s</comment>"
                          "<package format=\"howto_install\">%s</package>"
                          "<in_use>0</in_use>"
                          "</agent>",
                          agent_iterator_name (&targets),
                          agent_iterator_comment (&targets),
                          agent_iterator_howto_install (&targets));
                        break;
                      case 3: /* howto_use */
                        SENDF_TO_CLIENT_OR_FAIL
                         ("<agent>"
                          "<name>%s</name>"
                          "<comment>%s</comment>"
                          "<package format=\"howto_use\">%s</package>"
                          "<in_use>0</in_use>"
                          "</agent>",
                          agent_iterator_name (&targets),
                          agent_iterator_comment (&targets),
                          agent_iterator_howto_use (&targets));
                        break;
                      default:
                        SENDF_TO_CLIENT_OR_FAIL
                         ("<agent>"
                          "<name>%s</name>"
                          "<comment>%s</comment>"
                          "<in_use>0</in_use>"
                          "</agent>",
                          agent_iterator_name (&targets),
                          agent_iterator_comment (&targets));
                        break;
                    }
                }
              cleanup_iterator (&targets);
              SEND_TO_CLIENT_OR_FAIL ("</get_agents_response>");
            }
          openvas_free_string_var (&current_name);
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }

      case CLIENT_GET_CONFIGS:
        {
          iterator_t configs;
          assert (strcasecmp ("GET_CONFIGS", element_name) == 0);

          SEND_TO_CLIENT_OR_FAIL ("<get_configs_response"
                                  " status=\"" STATUS_OK "\""
                                  " status_text=\"" STATUS_OK_TEXT "\">");
          init_config_iterator (&configs,
                                current_name,
                                current_int_2,      /* Attribute sort_order. */
                                current_format);    /* Attribute sort_field. */
          while (next (&configs))
            {
              int config_nvts_growing, config_families_growing;
              const char *selector, *config_name;
              iterator_t tasks;

              selector = config_iterator_nvt_selector (&configs);
              config_name = config_iterator_name (&configs);
              config_nvts_growing = config_iterator_nvts_growing (&configs);
              config_families_growing
                = config_iterator_families_growing (&configs);

              SENDF_TO_CLIENT_OR_FAIL ("<config>"
                                       "<name>%s</name>"
                                       "<comment>%s</comment>"
                                       "<family_count>"
                                       "%i<growing>%i</growing>"
                                       "</family_count>"
                                       /* The number of NVT's selected by
                                        * the selector. */
                                       "<nvt_count>"
                                       "%i<growing>%i</growing>"
                                       "</nvt_count>"
                                       "<in_use>%i</in_use>"
                                       "<tasks>",
                                       config_name,
                                       config_iterator_comment (&configs),
                                       config_family_count (config_name),
                                       config_families_growing,
                                       config_nvt_count (config_name),
                                       config_nvts_growing,
                                       config_in_use (config_name));

              init_config_task_iterator (&tasks,
                                         config_name,
                                         /* Attribute sort_order. */
                                         current_int_2);
              while (next (&tasks))
                SENDF_TO_CLIENT_OR_FAIL ("<task id=\"%s\">"
                                         "<name>%s</name>"
                                         "</task>",
                                         config_task_iterator_uuid (&tasks),
                                         config_task_iterator_name (&tasks));
              cleanup_iterator (&tasks);
              SEND_TO_CLIENT_OR_FAIL ("</tasks>");

              if (current_int_1)
                {
                  iterator_t families;
                  int max_nvt_count = 0, known_nvt_count = 0;

                  /* The "families" attribute was true. */

                  SENDF_TO_CLIENT_OR_FAIL ("<families>");
                  init_family_iterator (&families,
                                        config_families_growing,
                                        selector,
                                        /* Attribute sort_order. */
                                        current_int_2);
                  while (next (&families))
                    {
                      int family_growing, family_max, family_selected_count;
                      const char *family;

                      family = family_iterator_name (&families);
                      if (family)
                        {
                          family_growing = nvt_selector_family_growing
                                            (selector,
                                             family,
                                             config_families_growing);
                          family_max = family_nvt_count (family);
                          family_selected_count = nvt_selector_nvt_count
                                                   (selector,
                                                    family,
                                                    family_growing);
                          known_nvt_count += family_selected_count;
                        }
                      else
                        {
                          /* The family can be NULL if an RC adds an NVT to a
                           * config and the NVT is missing from the NVT
                           * cache. */
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
                  SENDF_TO_CLIENT_OR_FAIL ("</families>"
                                           /* The total number of NVT's in all
                                            * the families for which the
                                            * selector selects at least one
                                            * NVT. */
                                           "<max_nvt_count>%i</max_nvt_count>"
                                           /* Total number of selected known
                                            * NVT's. */
                                           "<known_nvt_count>"
                                           "%i"
                                           "</known_nvt_count>",
                                           max_nvt_count,
                                           known_nvt_count);
                }

              if (current_int_3)
                {
                  iterator_t prefs;

                  /** @todo Similar to block in CLIENT_GET_NVT_DETAILS. */

                  /* The "preferences" attribute was true. */

                  SEND_TO_CLIENT_OR_FAIL ("<preferences>");

                  init_nvt_preference_iterator (&prefs, NULL);
                  while (next (&prefs))
                    {
                      char *real_name, *type, *value, *nvt, *oid = NULL;
                      real_name
                       = nvt_preference_iterator_real_name (&prefs);
                      type = nvt_preference_iterator_type (&prefs);
                      value = nvt_preference_iterator_config_value
                               (&prefs, config_name);
                      nvt = nvt_preference_iterator_nvt (&prefs);
                      if (nvt) oid = nvt_oid (nvt);

                      SENDF_TO_CLIENT_OR_FAIL
                       ("<preference>"
                        "<nvt oid=\"%s\"><name>%s</name></nvt>"
                        "<name>%s</name>"
                        "<type>%s</type>",
                        oid ? oid : "",
                        nvt ? nvt : "",
                        real_name ? real_name : "",
                        type ? type : "");

                      if (value && type && (strcmp (type, "radio") == 0))
                        {
                          /* Handle the other possible values. */
                          char *pos = strchr (value, ';');
                          if (pos) *pos = '\0';
                          SENDF_TO_CLIENT_OR_FAIL ("<value>%s</value>", value);
                          while (pos)
                            {
                              char *pos2 = strchr (++pos, ';');
                              if (pos2) *pos2 = '\0';
                              SENDF_TO_CLIENT_OR_FAIL ("<alt>%s</alt>", pos);
                              pos = pos2;
                            }
                        }
                      else if (type && (strcmp (type, "password") == 0))
                        SEND_TO_CLIENT_OR_FAIL ("<value></value>");
                      else
                        SENDF_TO_CLIENT_OR_FAIL ("<value>%s</value>",
                                                 value ? value : "");

                      SEND_TO_CLIENT_OR_FAIL ("</preference>");

                      free (real_name);
                      free (type);
                      free (value);
                      free (nvt);
                      free (oid);
                    }
                  cleanup_iterator (&prefs);

                  SEND_TO_CLIENT_OR_FAIL ("</preferences>");
                }

              SENDF_TO_CLIENT_OR_FAIL ("</config>");
            }
          openvas_free_string_var (&current_name);
          openvas_free_string_var (&current_format);
          cleanup_iterator (&configs);
          SEND_TO_CLIENT_OR_FAIL ("</get_configs_response>");
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }

      case CLIENT_GET_ESCALATORS:
        {
          iterator_t escalators;
          assert (strcasecmp ("GET_ESCALATORS", element_name) == 0);

          SEND_TO_CLIENT_OR_FAIL ("<get_escalators_response"
                                  " status=\"" STATUS_OK "\""
                                  " status_text=\"" STATUS_OK_TEXT "\">");
          init_escalator_iterator (&escalators,
                                   current_name,
                                   (task_t) 0,
                                   (event_t) 0,
                                   current_int_2,   /* Attribute sort_order. */
                                   current_format); /* Attribute sort_field. */
          while (next (&escalators))
            {
              iterator_t data;

              SENDF_TO_CLIENT_OR_FAIL ("<escalator>"
                                       "<name>%s</name>"
                                       "<comment>%s</comment>"
                                       "<in_use>%i</in_use>",
                                       escalator_iterator_name (&escalators),
                                       escalator_iterator_comment (&escalators),
                                       escalator_iterator_in_use (&escalators));

              /* Condition. */

              SENDF_TO_CLIENT_OR_FAIL ("<condition>%s",
                                       escalator_condition_name
                                        (escalator_iterator_condition
                                          (&escalators)));
              init_escalator_data_iterator (&data,
                                            escalator_iterator_escalator
                                             (&escalators),
                                            "condition");
              while (next (&data))
                SENDF_TO_CLIENT_OR_FAIL ("<data>"
                                         "<name>%s</name>"
                                         "%s"
                                         "</data>",
                                         escalator_data_iterator_name (&data),
                                         escalator_data_iterator_data (&data));
              cleanup_iterator (&data);
              SEND_TO_CLIENT_OR_FAIL ("</condition>");

              /* Event. */

              SENDF_TO_CLIENT_OR_FAIL ("<event>%s",
                                       event_name (escalator_iterator_event
                                        (&escalators)));
              init_escalator_data_iterator (&data,
                                            escalator_iterator_escalator
                                             (&escalators),
                                            "event");
              while (next (&data))
                SENDF_TO_CLIENT_OR_FAIL ("<data>"
                                         "<name>%s</name>"
                                         "%s"
                                         "</data>",
                                         escalator_data_iterator_name (&data),
                                         escalator_data_iterator_data (&data));
              cleanup_iterator (&data);
              SEND_TO_CLIENT_OR_FAIL ("</event>");

              /* Method. */

              SENDF_TO_CLIENT_OR_FAIL ("<method>%s",
                                       escalator_method_name
                                        (escalator_iterator_method
                                          (&escalators)));
              init_escalator_data_iterator (&data,
                                            escalator_iterator_escalator
                                             (&escalators),
                                            "method");
              while (next (&data))
                SENDF_TO_CLIENT_OR_FAIL ("<data>"
                                         "<name>%s</name>"
                                         "%s"
                                         "</data>",
                                         escalator_data_iterator_name (&data),
                                         escalator_data_iterator_data (&data));
              cleanup_iterator (&data);
              SEND_TO_CLIENT_OR_FAIL ("</method>");

              /**
               * @todo
               * (OMP) For consistency, the operations should respond the
               * same way if one, some or all elements are requested.  The
               * level of details in the response should instead be controlled
               * by some other mechanism, like a details flag.
               */

              if (current_name)
                {
                  iterator_t tasks;

                  SEND_TO_CLIENT_OR_FAIL ("<tasks>");
                  init_escalator_task_iterator (&tasks,
                                                current_name,
                                                /* Attribute sort_order. */
                                                current_int_2);
                  while (next (&tasks))
                    SENDF_TO_CLIENT_OR_FAIL
                     ("<task id=\"%s\">"
                      "<name>%s</name>"
                      "</task>",
                      escalator_task_iterator_uuid (&tasks),
                      escalator_task_iterator_name (&tasks));
                  cleanup_iterator (&tasks);
                  SEND_TO_CLIENT_OR_FAIL ("</tasks>");
                }

              SEND_TO_CLIENT_OR_FAIL ("</escalator>");
            }
          cleanup_iterator (&escalators);
          SEND_TO_CLIENT_OR_FAIL ("</get_escalators_response>");
          openvas_free_string_var (&current_format);
          openvas_free_string_var (&current_name);
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }

      case CLIENT_GET_LSC_CREDENTIALS:
        {
          iterator_t credentials;
          int format;
          assert (strcasecmp ("GET_LSC_CREDENTIALS", element_name) == 0);

          if (current_format)
            {
              if (strlen (current_format))
                {
                  if (strcasecmp (current_format, "key") == 0)
                    format = 1;
                  else if (strcasecmp (current_format, "rpm") == 0)
                    format = 2;
                  else if (strcasecmp (current_format, "deb") == 0)
                    format = 3;
                  else if (strcasecmp (current_format, "exe") == 0)
                    format = 4;
                  else
                    format = -1;
                }
              else
                format = 0;
              openvas_free_string_var (&current_format);
            }
          else
            format = 0;
          if (format == -1)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("get_lsc_credentials",
                                "GET_LSC_CREDENTIALS format attribute should"
                                " be \"key\", \"rpm\", \"deb\" or \"exe\"."));
          else
            {
              SEND_TO_CLIENT_OR_FAIL ("<get_lsc_credentials_response"
                                      " status=\"" STATUS_OK "\""
                                      " status_text=\"" STATUS_OK_TEXT "\">");
              init_lsc_credential_iterator (&credentials,
                                            current_uuid,
                                            /* Attribute sort_order. */
                                            current_int_2,
                                            /* Attribute sort_field. */
                                            current_name);
              while (next (&credentials))
                {
                  switch (format)
                    {
                      case 1: /* key */
                        SENDF_TO_CLIENT_OR_FAIL
                         ("<lsc_credential>"
                          "<name>%s</name>"
                          "<login>%s</login>"
                          "<comment>%s</comment>"
                          "<in_use>%i</in_use>"
                          "<type>%s</type>"
                          "<public_key>%s</public_key>"
                          "</lsc_credential>",
                          lsc_credential_iterator_name (&credentials),
                          lsc_credential_iterator_login (&credentials),
                          lsc_credential_iterator_comment (&credentials),
                          lsc_credential_iterator_in_use (&credentials),
                          lsc_credential_iterator_public_key (&credentials)
                            ? "gen" : "pass",
                          lsc_credential_iterator_public_key (&credentials));
                        break;
                      case 2: /* rpm */
                        SENDF_TO_CLIENT_OR_FAIL
                         ("<lsc_credential>"
                          "<name>%s</name>"
                          "<login>%s</login>"
                          "<comment>%s</comment>"
                          "<in_use>%i</in_use>"
                          "<type>%s</type>"
                          "<package format=\"rpm\">%s</package>"
                          "</lsc_credential>",
                          lsc_credential_iterator_name (&credentials),
                          lsc_credential_iterator_login (&credentials),
                          lsc_credential_iterator_comment (&credentials),
                          lsc_credential_iterator_in_use (&credentials),
                          lsc_credential_iterator_public_key (&credentials)
                            ? "gen" : "pass",
                          lsc_credential_iterator_rpm (&credentials));
                        break;
                      case 3: /* deb */
                        SENDF_TO_CLIENT_OR_FAIL
                         ("<lsc_credential>"
                          "<name>%s</name>"
                          "<login>%s</login>"
                          "<comment>%s</comment>"
                          "<in_use>%i</in_use>"
                          "<type>%s</type>"
                          "<package format=\"deb\">%s</package>"
                          "</lsc_credential>",
                          lsc_credential_iterator_name (&credentials),
                          lsc_credential_iterator_login (&credentials),
                          lsc_credential_iterator_comment (&credentials),
                          lsc_credential_iterator_in_use (&credentials),
                          lsc_credential_iterator_public_key (&credentials)
                            ? "gen" : "pass",
                          lsc_credential_iterator_deb (&credentials));
                        break;
                      case 4: /* exe */
                        SENDF_TO_CLIENT_OR_FAIL
                         ("<lsc_credential>"
                          "<name>%s</name>"
                          "<login>%s</login>"
                          "<comment>%s</comment>"
                          "<in_use>%i</in_use>"
                          "<type>%s</type>"
                          "<package format=\"exe\">%s</package>"
                          "</lsc_credential>",
                          lsc_credential_iterator_name (&credentials),
                          lsc_credential_iterator_login (&credentials),
                          lsc_credential_iterator_comment (&credentials),
                          lsc_credential_iterator_in_use (&credentials),
                          lsc_credential_iterator_public_key (&credentials)
                            ? "gen" : "pass",
                          lsc_credential_iterator_exe (&credentials));
                        break;
                      default:
                        {
                          const char *name;
                          iterator_t targets;

                          name = lsc_credential_iterator_name (&credentials);
                          SENDF_TO_CLIENT_OR_FAIL
                           ("<lsc_credential>"
                            "<name>%s</name>"
                            "<login>%s</login>"
                            "<comment>%s</comment>"
                            "<in_use>%i</in_use>"
                            "<type>%s</type>"
                            "<targets>",
                            name,
                            lsc_credential_iterator_login (&credentials),
                            lsc_credential_iterator_comment (&credentials),
                            lsc_credential_iterator_in_use (&credentials),
                            lsc_credential_iterator_public_key (&credentials)
                              ? "gen" : "pass");

                          init_lsc_credential_target_iterator (&targets,
                                                               name,
                                                               /* sort_order. */
                                                               current_int_2);
                          while (next (&targets))
                            SENDF_TO_CLIENT_OR_FAIL
                             ("<target>"
                              "<name>%s</name>"
                              "</target>",
                              lsc_credential_target_iterator_name (&targets));
                          cleanup_iterator (&targets);

                          SEND_TO_CLIENT_OR_FAIL ("</targets>"
                                                  "</lsc_credential>");
                          break;
                        }
                    }
                }
              cleanup_iterator (&credentials);
              SEND_TO_CLIENT_OR_FAIL ("</get_lsc_credentials_response>");
            }
          openvas_free_string_var (&current_name);
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }

      case CLIENT_GET_TARGETS:
        {
          iterator_t targets, tasks;
          assert (strcasecmp ("GET_TARGETS", element_name) == 0);

          SEND_TO_CLIENT_OR_FAIL ("<get_targets_response"
                                  " status=\"" STATUS_OK "\""
                                  " status_text=\"" STATUS_OK_TEXT "\">");
          init_target_iterator (&targets,
                                current_name,    /* Attribute name. */
                                current_int_2,   /* Attribute sort_order. */
                                current_format); /* Attribute sort_field. */
          while (next (&targets))
            {
              char *lsc_name;
              lsc_credential_t lsc_credential;

              lsc_credential = target_iterator_lsc_credential (&targets);
              lsc_name = lsc_credential_name (lsc_credential);
              SENDF_TO_CLIENT_OR_FAIL ("<target>"
                                       "<name>%s</name>"
                                       "<hosts>%s</hosts>"
                                       "<max_hosts>%i</max_hosts>"
                                       "<comment>%s</comment>"
                                       "<in_use>%i</in_use>"
                                       "<lsc_credential>"
                                       "<name>%s</name>"
                                       "</lsc_credential>"
                                       "<tasks>",
                                       target_iterator_name (&targets),
                                       target_iterator_hosts (&targets),
                                       max_hosts
                                        (target_iterator_hosts (&targets)),
                                       target_iterator_comment (&targets),
                                       target_in_use
                                        (target_iterator_name (&targets)),
                                       lsc_name ? lsc_name : "");

              if (current_name)
                {
                  init_target_task_iterator (&tasks,
                                             current_name,
                                             /* Attribute sort_order. */
                                             current_int_2);
                  while (next (&tasks))
                    SENDF_TO_CLIENT_OR_FAIL ("<task id=\"%s\">"
                                             "<name>%s</name>"
                                             "</task>",
                                             target_task_iterator_uuid (&tasks),
                                             target_task_iterator_name (&tasks));
                  cleanup_iterator (&tasks);
                }

              SEND_TO_CLIENT_OR_FAIL ("</tasks>"
                                      "</target>");
              free (lsc_name);
            }
          cleanup_iterator (&targets);
          SEND_TO_CLIENT_OR_FAIL ("</get_targets_response>");
          openvas_free_string_var (&current_format);
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }

      default:
        assert (0);
        break;
    }
}

/**
 * @brief Handle the addition of text to an OMP XML element.
 *
 * React to the addition of text to the value of an XML element.
 * React according to the current value of \ref client_state,
 * usually appending the text to some part of the current task
 * (\ref current_client_task) with functions like \ref openvas_append_text,
 * \ref add_task_description_line and \ref append_to_task_comment.
 *
 * @param[in]  context           Parser context.
 * @param[in]  text              The text.
 * @param[in]  text_len          Length of the text.
 * @param[in]  user_data         Dummy parameter.
 * @param[in]  error             Error parameter.
 */
static void
omp_xml_handle_text (/*@unused@*/ GMarkupParseContext* context,
                     const gchar *text,
                     gsize text_len,
                     /*@unused@*/ gpointer user_data,
                     /*@unused@*/ GError **error)
{
  if (text_len == 0) return;
  tracef ("   XML   text: %s\n", text);
  switch (client_state)
    {
      case CLIENT_MODIFY_CONFIG_NAME:
        openvas_append_text (&current_name, text, text_len);
        break;

      case CLIENT_MODIFY_CONFIG_NVT_SELECTION_FAMILY:
        openvas_append_text (&current_format, text, text_len);
        break;

      case CLIENT_MODIFY_CONFIG_FAMILY_SELECTION_FAMILY_ALL:
      case CLIENT_MODIFY_CONFIG_FAMILY_SELECTION_FAMILY_GROWING:
        openvas_append_text (&modify_task_rcfile, text, text_len);
        break;
      case CLIENT_MODIFY_CONFIG_FAMILY_SELECTION_FAMILY_NAME:
        openvas_append_text (&current_uuid, text, text_len);
        break;
      case CLIENT_MODIFY_CONFIG_FAMILY_SELECTION_GROWING:
        openvas_append_text (&modify_task_rcfile, text, text_len);
        break;

      case CLIENT_MODIFY_CONFIG_PREFERENCE_NAME:
        openvas_append_text (&modify_task_name, text, text_len);
        break;
      case CLIENT_MODIFY_CONFIG_PREFERENCE_VALUE:
        openvas_append_text (&modify_task_value, text, text_len);
        break;

      case CLIENT_MODIFY_REPORT_PARAMETER:
        openvas_append_text (&modify_task_value, text, text_len);
        break;

      case CLIENT_MODIFY_TASK_COMMENT:
        openvas_append_text (&modify_task_comment, text, text_len);
        break;
      case CLIENT_MODIFY_TASK_NAME:
        openvas_append_text (&modify_task_name, text, text_len);
        break;
      case CLIENT_MODIFY_TASK_PARAMETER:
        openvas_append_text (&modify_task_value, text, text_len);
        break;
      case CLIENT_MODIFY_TASK_RCFILE:
        openvas_append_text (&modify_task_rcfile, text, text_len);
        break;
      case CLIENT_MODIFY_TASK_FILE:
        openvas_append_text (&modify_task_file, text, text_len);
        break;

      case CLIENT_CREDENTIALS_USERNAME:
        append_to_credentials_username (&current_credentials, text, text_len);
        break;
      case CLIENT_CREDENTIALS_PASSWORD:
        append_to_credentials_password (&current_credentials, text, text_len);
        break;

      case CLIENT_CREATE_AGENT_COMMENT:
        openvas_append_text (&modify_task_comment, text, text_len);
        break;
      case CLIENT_CREATE_AGENT_HOWTO_INSTALL:
        openvas_append_text (&modify_task_parameter, text, text_len);
        break;
      case CLIENT_CREATE_AGENT_HOWTO_USE:
        openvas_append_text (&modify_task_value, text, text_len);
        break;
      case CLIENT_CREATE_AGENT_INSTALLER:
        openvas_append_text (&modify_task_file, text, text_len);
        break;
      case CLIENT_CREATE_AGENT_NAME:
        openvas_append_text (&modify_task_name, text, text_len);
        break;

      case CLIENT_CREATE_CONFIG_COMMENT:
        openvas_append_text (&modify_task_comment, text, text_len);
        break;
      case CLIENT_CREATE_CONFIG_COPY:
        openvas_append_text (&current_name, text, text_len);
        break;
      case CLIENT_CREATE_CONFIG_NAME:
        openvas_append_text (&modify_task_name, text, text_len);
        break;
      case CLIENT_CREATE_CONFIG_RCFILE:
        openvas_append_text (&modify_task_value, text, text_len);
        break;

      case CLIENT_CREATE_LSC_CREDENTIAL_COMMENT:
        openvas_append_text (&modify_task_comment, text, text_len);
        break;
      case CLIENT_CREATE_LSC_CREDENTIAL_LOGIN:
        openvas_append_text (&current_name, text, text_len);
        break;
      case CLIENT_CREATE_LSC_CREDENTIAL_NAME:
        openvas_append_text (&modify_task_name, text, text_len);
        break;
      case CLIENT_CREATE_LSC_CREDENTIAL_PASSWORD:
        openvas_append_text (&modify_task_parameter, text, text_len);
        break;

      case CLIENT_CREATE_ESCALATOR_COMMENT:
        openvas_append_text (&modify_task_comment, text, text_len);
        break;
      case CLIENT_CREATE_ESCALATOR_CONDITION:
        openvas_append_text (&modify_task_parameter, text, text_len);
        break;
      case CLIENT_CREATE_ESCALATOR_EVENT:
        openvas_append_text (&modify_task_value, text, text_len);
        break;
      case CLIENT_CREATE_ESCALATOR_METHOD:
        openvas_append_text (&modify_task_rcfile, text, text_len);
        break;
      case CLIENT_CREATE_ESCALATOR_NAME:
        openvas_append_text (&modify_task_name, text, text_len);
        break;

      case CLIENT_CREATE_ESCALATOR_CONDITION_DATA:
        openvas_append_text (&current_format, text, text_len);
        break;
      case CLIENT_CREATE_ESCALATOR_EVENT_DATA:
        openvas_append_text (&current_format, text, text_len);
        break;
      case CLIENT_CREATE_ESCALATOR_METHOD_DATA:
        openvas_append_text (&current_format, text, text_len);
        break;

      case CLIENT_CREATE_ESCALATOR_CONDITION_DATA_NAME:
        openvas_append_text (&current_uuid, text, text_len);
        break;
      case CLIENT_CREATE_ESCALATOR_EVENT_DATA_NAME:
        openvas_append_text (&current_uuid, text, text_len);
        break;
      case CLIENT_CREATE_ESCALATOR_METHOD_DATA_NAME:
        openvas_append_text (&current_uuid, text, text_len);
        break;

      case CLIENT_CREATE_TARGET_COMMENT:
        openvas_append_text (&modify_task_comment, text, text_len);
        break;
      case CLIENT_CREATE_TARGET_HOSTS:
        openvas_append_text (&modify_task_value, text, text_len);
        break;
      case CLIENT_CREATE_TARGET_LSC_CREDENTIAL:
        openvas_append_text (&modify_task_parameter, text, text_len);
        break;
      case CLIENT_CREATE_TARGET_NAME:
        openvas_append_text (&modify_task_name, text, text_len);
        break;

      case CLIENT_CREATE_TASK_COMMENT:
        append_to_task_comment (current_client_task, text, text_len);
        break;
      case CLIENT_CREATE_TASK_CONFIG:
        append_to_task_config (current_client_task, text, text_len);
        break;
      case CLIENT_CREATE_TASK_ESCALATOR:
        openvas_append_text (&modify_task_name, text, text_len);
        break;
      case CLIENT_CREATE_TASK_NAME:
        append_to_task_name (current_client_task, text, text_len);
        break;
      case CLIENT_CREATE_TASK_RCFILE:
        /* Append the text to the task description. */
        if (add_task_description_line (current_client_task,
                                       text,
                                       text_len))
          abort (); // FIX out of mem
        break;
      case CLIENT_CREATE_TASK_TARGET:
        append_to_task_target (current_client_task, text, text_len);
        break;

      case CLIENT_DELETE_AGENT_NAME:
      case CLIENT_DELETE_CONFIG_NAME:
      case CLIENT_DELETE_ESCALATOR_NAME:
      case CLIENT_DELETE_LSC_CREDENTIAL_NAME:
      case CLIENT_DELETE_TARGET_NAME:
      case CLIENT_TEST_ESCALATOR_NAME:
        openvas_append_text (&modify_task_name, text, text_len);
        break;

      default:
        /* Just pass over the text. */
        break;
    }
}

/**
 * @brief Handle an OMP XML parsing error.
 *
 * Simply leave the error for the caller of the parser to handle.
 *
 * @param[in]  context           Parser context.
 * @param[in]  error             The error.
 * @param[in]  user_data         Dummy parameter.
 */
static void
omp_xml_handle_error (/*@unused@*/ GMarkupParseContext* context,
                      GError *error,
                      /*@unused@*/ gpointer user_data)
{
  tracef ("   XML ERROR %s\n", error->message);
}


/* OMP input processor. */

// FIX probably should pass to process_omp_client_input
extern char from_client[];
extern buffer_size_t from_client_start;
extern buffer_size_t from_client_end;

/**
 * @brief Initialise OMP library.
 *
 * @param[in]  log_config      Logging configuration list.
 * @param[in]  nvt_cache_mode  True when running in NVT caching mode.
 * @param[in]  database        Location of manage database.
 *
 * @return 0 success, -1 error, -2 database is wrong version, -3 database
 *         needs to be initialized from server.
 */
int
init_omp (GSList *log_config, int nvt_cache_mode, const gchar *database)
{
  g_log_set_handler (G_LOG_DOMAIN,
                     ALL_LOG_LEVELS,
                     (GLogFunc) openvas_log_func,
                     log_config);
  return init_manage (log_config, nvt_cache_mode, database);
}

/**
 * @brief Initialise OMP library data for a process.
 *
 * @param[in]  update_nvt_cache  0 operate normally, -1 just update NVT cache,
 *                               -2 just rebuild NVT cache.
 * @param[in]  database          Location of manage database.
 *
 * This should run once per process, before the first call to \ref
 * process_omp_client_input.
 */
void
init_omp_process (int update_nvt_cache, const gchar *database)
{
  forked = 0;
  init_manage_process (update_nvt_cache, database);
  /* Create the XML parser. */
  xml_parser.start_element = omp_xml_handle_start_element;
  xml_parser.end_element = omp_xml_handle_end_element;
  xml_parser.text = omp_xml_handle_text;
  xml_parser.passthrough = NULL;
  xml_parser.error = omp_xml_handle_error;
  if (xml_context) g_free (xml_context);
  xml_context = g_markup_parse_context_new (&xml_parser,
                                            0,
                                            NULL,
                                            NULL);
}

/**
 * @brief Process any XML available in \ref from_client.
 *
 * \if STATIC
 *
 * Call the XML parser and let the callback functions do the work
 * (\ref omp_xml_handle_start_element, \ref omp_xml_handle_end_element,
 * \ref omp_xml_handle_text and \ref omp_xml_handle_error).
 *
 * The callback functions will queue any resulting scanner commands in
 * \ref to_scanner (using \ref send_to_server) and any replies for
 * the client in \ref to_client (using \ref send_to_client).
 *
 * \endif
 *
 * @return 0 success, -1 error, -2 or -3 too little space in \ref to_client
 *         or the scanner output buffer (respectively), -4 XML syntax error.
 */
int
process_omp_client_input ()
{
  gboolean success;
  GError* error = NULL;

  /* In the XML parser handlers all writes to the to_scanner buffer must be
   * complete OTP commands, because the caller may also write into to_scanner
   * between calls to this function (via manage_check_current_task). */

  if (xml_context == NULL) return -1;

  current_error = 0;
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
            tracef ("   client error: G_MARKUP_ERROR_UNKNOWN_ELEMENT\n");
          else if (g_error_matches (error,
                                    G_MARKUP_ERROR,
                                    G_MARKUP_ERROR_INVALID_CONTENT))
            {
              if (current_error)
                {
                  /* This is the return status for a forked child. */
                  forked = 2; /* Prevent further forking. */
                  g_error_free (error);
                  return current_error;
                }
              tracef ("   client error: G_MARKUP_ERROR_INVALID_CONTENT\n");
            }
          else if (g_error_matches (error,
                                    G_MARKUP_ERROR,
                                    G_MARKUP_ERROR_UNKNOWN_ATTRIBUTE))
            tracef ("   client error: G_MARKUP_ERROR_UNKNOWN_ATTRIBUTE\n");
          else
            err = -1;
          g_message ("   Failed to parse client XML: %s\n", error->message);
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
  if (forked)
    return 3;
  return 0;
}

/**
 * @brief Return whether the scanner is active.
 *
 * @return 1 if the scanner is doing something that the manager
 *         must wait for, else 0.
 */
short
scanner_is_active ()
{
  return scanner_active;
}
