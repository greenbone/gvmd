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


/* Static headers. */

static void
buffer_results_xml (GString *, iterator_t *, task_t, int, int);


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

/**
 * @brief Return string from ctime with newline replaces with terminator.
 *
 * @param[in]  time  Time.
 *
 * @return Return from ctime applied to time, with newline stripped off.
 */
static char*
ctime_strip_newline (time_t *time)
{
  char* ret = ctime (time);
  if (ret && strlen (ret) > 0)
    ret[strlen (ret) - 1] = '\0';
  return ret;
}

/**
 * @brief Return time defined by broken down time strings.
 *
 * If any argument is NULL, use the value from the current time.
 *
 * @param[in]   hour          Hour (0 to 23).
 * @param[in]   minute        Minute (0 to 59).
 * @param[in]   day_of_month  Day of month (1 to 31).
 * @param[in]   month         Month (1 to 12).
 * @param[in]   year          Year.
 *
 * @return Time described by arguments on success, else -1.
 */
static time_t
time_from_strings (const char *hour, const char *minute,
                   const char *day_of_month, const char *month,
                   const char *year)
{
  struct tm given_broken, *now_broken;
  time_t now;

  time (&now);
  now_broken = localtime (&now);

  given_broken.tm_sec = 0;
  given_broken.tm_min = (minute ? atoi (minute) : now_broken->tm_min);
  given_broken.tm_hour = (hour ? atoi (hour) : now_broken->tm_hour);
  given_broken.tm_mday = (day_of_month
                           ? atoi (day_of_month)
                           : now_broken->tm_mday);
  given_broken.tm_mon = (month ? (atoi (month) - 1) : now_broken->tm_mon);
  given_broken.tm_year = (year ? (atoi (year) - 1900) : now_broken->tm_year);
  given_broken.tm_isdst = now_broken->tm_isdst;

  return mktime (&given_broken);
}

/**
 * @brief Return interval defined by time and unit strings.
 *
 * @param[in]   value   Value.  0 if NULL.
 * @param[in]   unit    Calendar unit: second, minute, hour, day, week,
 *                      month, year or decade.  "second" if NULL.
 * @param[out]  months  Months return.
 *
 * @return Interval described by arguments on success, else -1.
 */
static time_t
interval_from_strings (const char *value, const char *unit, time_t *months)
{
  if (value == NULL)
    return 0;

  if ((unit == NULL) || (strcasecmp (unit, "second") == 0))
    return atoi (value);

  if (strcasecmp (unit, "minute") == 0)
    return atoi (value) * 60;

  if (strcasecmp (unit, "hour") == 0)
    return atoi (value) * 60 * 60;

  if (strcasecmp (unit, "day") == 0)
    return atoi (value) * 60 * 60 * 24;

  if (strcasecmp (unit, "week") == 0)
    return atoi (value) * 60 * 60 * 24 * 7;

  if (months)
    {
      if (strcasecmp (unit, "month") == 0)
        {
          *months = atoi (value);
          return 0;
        }

      if (strcasecmp (unit, "year") == 0)
        {
          *months = atoi (value) * 12;
          return 0;
        }

      if (strcasecmp (unit, "decade") == 0)
        {
          *months = atoi (value) * 12 * 10;
          return 0;
        }
    }

  return -1;
}

/**
 * @brief Ensure a string is in an array.
 *
 * @param[in]  array   Array.
 * @param[in]  string  String.  Copied into array.
 */
static void
array_add_new_string (array_t *array, const gchar *string)
{
  guint index;
  for (index = 0; index < array->len; index++)
    if (strcmp (g_ptr_array_index (array, index), string) == 0)
      return;
  array_add (array, g_strdup (string));
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
"    CREATE_NOTE            Create a note.\n"
"    CREATE_SCHEDULE        Create a schedule.\n"
"    CREATE_TARGET          Create a target.\n"
"    CREATE_TASK            Create a task.\n"
"    DELETE_AGENT           Delete an agent.\n"
"    DELETE_CONFIG          Delete a config.\n"
"    DELETE_ESCALATOR       Delete an escalator.\n"
"    DELETE_LSC_CREDENTIAL  Delete a local security check credential.\n"
"    DELETE_NOTE            Delete a note.\n"
"    DELETE_REPORT          Delete a report.\n"
"    DELETE_SCHEDULE        Delete a schedule.\n"
"    DELETE_TARGET          Delete a target.\n"
"    DELETE_TASK            Delete a task.\n"
"    GET_AGENTS             Get all agents.\n"
"    GET_CERTIFICATES       Get all available certificates.\n"
"    GET_CONFIGS            Get all configs.\n"
"    GET_DEPENDENCIES       Get dependencies for all available NVTs.\n"
"    GET_ESCALATORS         Get all escalators.\n"
"    GET_LSC_CREDENTIALS    Get all local security check credentials.\n"
"    GET_NOTES              Get all notes.\n"
"    GET_NVT_ALL            Get IDs and names of all available NVTs.\n"
"    GET_NVT_DETAILS        Get all details for all available NVTs.\n"
"    GET_NVT_FAMILIES       Get a list of all NVT families.\n"
"    GET_NVT_FEED_CHECKSUM  Get checksum for entire NVT collection.\n"
"    GET_PREFERENCES        Get preferences for all available NVTs.\n"
"    GET_REPORT             Get a report identified by its unique ID.\n"
"    GET_RESULTS            Get results.\n"
"    GET_RULES              Get the rules for the authenticated user.\n"
"    GET_SCHEDULES          Get all schedules.\n"
"    GET_STATUS             Get task status information.\n"
"    GET_SYSTEM_REPORTS     Get all system reports.\n"
"    GET_TARGETS            Get all targets.\n"
"    GET_VERSION            Get the OpenVAS Manager Protocol version.\n"
"    HELP                   Get this help text.\n"
"    MODIFY_CONFIG          Update an existing config.\n"
"    MODIFY_NOTE            Modify an existing note.\n"
"    MODIFY_REPORT          Modify an existing report.\n"
"    MODIFY_TASK            Update an existing task.\n"
"    PAUSE_TASK             Pause a running task.\n"
"    RESUME_OR_START_TASK   Resume task if stopped, else start task.\n"
"    RESUME_PAUSED_TASK     Resume a paused task.\n"
"    RESUME_STOPPED_TASK    Resume a stopped task.\n"
"    START_TASK             Manually start an existing task.\n"
"    TEST_ESCALATOR         Run an escalator.\n";


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
 * @brief Response code for forbidden access.
 */
#define STATUS_ERROR_ACCESS            "403"

/**
 * @brief Response code text for forbidden access.
 */
#define STATUS_ERROR_ACCESS_TEXT       "Access to resource forbidden"

/**
 * @brief Response code for a missing resource.
 */
#define STATUS_ERROR_MISSING           "404"

/**
 * @brief Response code text for a missing resource.
 */
#define STATUS_ERROR_MISSING_TEXT      "Resource missing"

/**
 * @brief Response code for a busy resource.
 */
#define STATUS_ERROR_BUSY              "409"

/**
 * @brief Response code text for a busy resource.
 */
#define STATUS_ERROR_BUSY_TEXT         "Resource busy"

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


/* Command data passed between parser callbacks. */

static gpointer
preference_new (char *name, char *type, char *value, char *nvt_name,
                char *nvt_oid, array_t *alts /* gchar. */)
{
  preference_t *preference;

  preference = (preference_t*) g_malloc0 (sizeof (preference_t));
  preference->name = name;
  preference->type = type;
  preference->value = value;
  preference->nvt_name = nvt_name;
  preference->nvt_oid = nvt_oid;
  preference->alts = alts;

  return preference;
}

static gpointer
nvt_selector_new (char *name, char *type, int include, char *family_or_nvt)
{
  nvt_selector_t *selector;

  selector = (nvt_selector_t*) g_malloc0 (sizeof (nvt_selector_t));
  selector->name = name;
  selector->type = type;
  selector->include = include;
  selector->family_or_nvt = family_or_nvt;

  return selector;
}

typedef struct
{
  char *task_id;
} abort_task_data_t;

static void
abort_task_data_reset (abort_task_data_t *data)
{
  free (data->task_id);

  memset (data, 0, sizeof (abort_task_data_t));
}

typedef struct
{
  char *comment;
  char *howto_install;
  char *howto_use;
  char *installer;
  char *name;
} create_agent_data_t;

static void
create_agent_data_reset (create_agent_data_t *data)
{
  free (data->comment);
  free (data->howto_install);
  free (data->howto_use);
  free (data->installer);
  free (data->name);

  memset (data, 0, sizeof (create_agent_data_t));
}

typedef struct
{
  int import;                        /* The import element was present. */
  char *comment;
  char *name;
  array_t *nvt_selectors;            /* nvt_selector_t. */
  char *nvt_selector_name;
  char *nvt_selector_type;
  char *nvt_selector_include;
  char *nvt_selector_family_or_nvt;
  array_t *preferences;              /* preference_t. */
  array_t *preference_alts;          /* gchar. */
  char *preference_alt;
  char *preference_name;
  char *preference_nvt_name;
  char *preference_nvt_oid;
  char *preference_type;
  char *preference_value;
} import_config_data_t;

typedef struct
{
  char *comment;
  char *copy;
  import_config_data_t import;
  char *name;
  char *rcfile;
} create_config_data_t;

// array members must be created separately
static void
create_config_data_reset (create_config_data_t *data)
{
  int index = 0;
  const preference_t *preference;
  import_config_data_t *import = (import_config_data_t*) &data->import;

  free (data->comment);
  free (data->copy);

  free (import->comment);
  free (import->name);
  array_free (import->nvt_selectors);
  free (import->nvt_selector_name);
  free (import->nvt_selector_type);
  free (import->nvt_selector_family_or_nvt);

  if (import->preferences)
    {
      while ((preference = (preference_t*) g_ptr_array_index (import->preferences,
                                                              index++)))
        array_free (preference->alts);
      array_free (import->preferences);
    }

  free (import->preference_alt);
  free (import->preference_name);
  free (import->preference_nvt_name);
  free (import->preference_nvt_oid);
  free (import->preference_type);
  free (import->preference_value);

  free (data->name);
  free (data->rcfile);

  memset (data, 0, sizeof (create_config_data_t));
}

typedef struct
{
  char *comment;
  char *condition;
  array_t *condition_data;
  char *event;
  array_t *event_data;
  char *method;
  array_t *method_data;
  char *name;
  char *part_data;
  char *part_name;
} create_escalator_data_t;

static void
create_escalator_data_reset (create_escalator_data_t *data)
{
  free (data->comment);
  free (data->condition);
  array_free (data->condition_data);
  free (data->event);
  array_free (data->event_data);
  free (data->method);
  array_free (data->method_data);
  free (data->name);
  free (data->part_data);
  free (data->part_name);

  memset (data, 0, sizeof (create_escalator_data_t));
}

typedef struct
{
  char *comment;
  char *login;
  char *name;
  char *password;
} create_lsc_credential_data_t;

static void
create_lsc_credential_data_reset (create_lsc_credential_data_t *data)
{
  free (data->comment);
  free (data->login);
  free (data->name);
  free (data->password);

  memset (data, 0, sizeof (create_lsc_credential_data_t));
}

typedef struct
{
  char *hosts;
  char *note_id;
  char *nvt;
  char *port;
  char *result;
  char *task;
  char *text;
  char *threat;
} create_note_data_t;

static void
create_note_data_reset (create_note_data_t *data)
{
  free (data->hosts);
  free (data->note_id);
  free (data->nvt);
  free (data->port);
  free (data->result);
  free (data->task);
  free (data->text);
  free (data->threat);

  memset (data, 0, sizeof (create_note_data_t));
}

typedef struct
{
  char *name;
  char *comment;
  char *first_time_day_of_month;
  char *first_time_hour;
  char *first_time_minute;
  char *first_time_month;
  char *first_time_year;
  char *period;
  char *period_unit;
  char *duration;
  char *duration_unit;
} create_schedule_data_t;

static void
create_schedule_data_reset (create_schedule_data_t *data)
{
  free (data->name);
  free (data->comment);
  free (data->first_time_day_of_month);
  free (data->first_time_hour);
  free (data->first_time_minute);
  free (data->first_time_month);
  free (data->first_time_year);
  free (data->period);
  free (data->period_unit);
  free (data->duration);
  free (data->duration_unit);

  memset (data, 0, sizeof (create_schedule_data_t));
}

typedef struct
{
  char *comment;
  char *hosts;
  char *lsc_credential;
  char *name;
} create_target_data_t;

static void
create_target_data_reset (create_target_data_t *data)
{
  free (data->comment);
  free (data->hosts);
  free (data->lsc_credential);
  free (data->name);

  memset (data, 0, sizeof (create_target_data_t));
}

typedef struct
{
  char *config;
  char *escalator;
  char *schedule;
  char *target;
  task_t task;
} create_task_data_t;

static void
create_task_data_reset (create_task_data_t *data)
{
  free (data->config);
  free (data->escalator);
  free (data->schedule);
  free (data->target);

  memset (data, 0, sizeof (create_task_data_t));
}

typedef struct
{
  char *name;
} delete_agent_data_t;

static void
delete_agent_data_reset (delete_agent_data_t *data)
{
  free (data->name);

  memset (data, 0, sizeof (delete_agent_data_t));
}

typedef struct
{
  char *name;
} delete_config_data_t;

static void
delete_config_data_reset (delete_config_data_t *data)
{
  free (data->name);

  memset (data, 0, sizeof (delete_config_data_t));
}

typedef struct
{
  char *name;
} delete_escalator_data_t;

static void
delete_escalator_data_reset (delete_escalator_data_t *data)
{
  free (data->name);

  memset (data, 0, sizeof (delete_escalator_data_t));
}

typedef struct
{
  char *name;
} delete_lsc_credential_data_t;

static void
delete_lsc_credential_data_reset (delete_lsc_credential_data_t *data)
{
  free (data->name);

  memset (data, 0, sizeof (delete_lsc_credential_data_t));
}

typedef struct
{
  char *note_id;
} delete_note_data_t;

static void
delete_note_data_reset (delete_note_data_t *data)
{
  free (data->note_id);

  memset (data, 0, sizeof (delete_note_data_t));
}

typedef struct
{
  char *report_id;
} delete_report_data_t;

static void
delete_report_data_reset (delete_report_data_t *data)
{
  free (data->report_id);

  memset (data, 0, sizeof (delete_report_data_t));
}

typedef struct
{
  char *schedule_id;
} delete_schedule_data_t;

static void
delete_schedule_data_reset (delete_schedule_data_t *data)
{
  free (data->schedule_id);

  memset (data, 0, sizeof (delete_schedule_data_t));
}

typedef struct
{
  char *name;
} delete_target_data_t;

static void
delete_target_data_reset (delete_target_data_t *data)
{
  free (data->name);

  memset (data, 0, sizeof (delete_target_data_t));
}

typedef struct
{
  char *task_id;
} delete_task_data_t;

static void
delete_task_data_reset (delete_task_data_t *data)
{
  free (data->task_id);

  memset (data, 0, sizeof (delete_task_data_t));
}

typedef struct
{
  char *note_id;
  char *nvt_oid;
  char *task_id;
  char *sort_field;
  int sort_order;
  int details;
  int result;
} get_notes_data_t;

static void
get_notes_data_reset (get_notes_data_t *data)
{
  free (data->note_id);
  free (data->nvt_oid);
  free (data->task_id);
  memset (data, 0, sizeof (get_notes_data_t));
}

typedef struct
{
  char *config;
  char *oid;
  char *preference;
} get_preferences_data_t;

static void
get_preferences_data_reset (get_preferences_data_t *data)
{
  free (data->config);
  free (data->oid);
  free (data->preference);
  memset (data, 0, sizeof (get_preferences_data_t));
}

typedef struct
{
  char *format;
  char *report_id;
  int first_result;
  int max_results;
  char *sort_field;
  int sort_order;
  char *levels;
  char *search_phrase;
  char *min_cvss_base;
  int notes;
  int notes_details;
  int result_hosts_only;
} get_report_data_t;

static void
get_report_data_reset (get_report_data_t *data)
{
  free (data->format);
  free (data->report_id);
  free (data->sort_field);
  free (data->levels);
  free (data->search_phrase);
  free (data->min_cvss_base);
  memset (data, 0, sizeof (get_report_data_t));
}

typedef struct
{
  char *result_id;
  char *task_id;
  int notes;
  int notes_details;
} get_results_data_t;

static void
get_results_data_reset (get_results_data_t *data)
{
  free (data->result_id);
  free (data->task_id);
  memset (data, 0, sizeof (get_results_data_t));
}

typedef struct
{
  char *schedule_id;
  char *sort_field;
  int sort_order;
  int details;
} get_schedules_data_t;

static void
get_schedules_data_reset (get_schedules_data_t *data)
{
  free (data->schedule_id);
  memset (data, 0, sizeof (get_schedules_data_t));
}

typedef struct
{
  char *name;
  char *duration;
} get_system_reports_data_t;

static void
get_system_reports_data_reset (get_system_reports_data_t *data)
{
  free (data->name);
  free (data->duration);
  memset (data, 0, sizeof (get_system_reports_data_t));
}

typedef struct
{
  array_t *families_growing_empty;
  array_t *families_growing_all;
  array_t *families_static_all;
  int family_selection_family_all;
  char *family_selection_family_all_text;
  int family_selection_family_growing;
  char *family_selection_family_growing_text;
  char *family_selection_family_name;
  int family_selection_growing;
  char *family_selection_growing_text;
  char *name;
  array_t *nvt_selection;
  char *nvt_selection_family;
  char *nvt_selection_nvt_oid;
  char *preference_name;
  char *preference_nvt_oid;
  char *preference_value;
} modify_config_data_t;

static void
modify_config_data_reset (modify_config_data_t *data)
{
  array_free (data->families_growing_empty);
  array_free (data->families_growing_all);
  array_free (data->families_static_all);
  free (data->family_selection_family_all_text);
  free (data->family_selection_family_growing_text);
  free (data->family_selection_family_name);
  free (data->family_selection_growing_text);
  free (data->name);
  array_free (data->nvt_selection);
  free (data->nvt_selection_family);
  free (data->nvt_selection_nvt_oid);
  free (data->preference_name);
  free (data->preference_nvt_oid);
  free (data->preference_value);
  memset (data, 0, sizeof (modify_config_data_t));
}

typedef struct
{
  char *report_id;
  char *parameter_id;
  char *parameter_value;
} modify_report_data_t;

static void
modify_report_data_reset (modify_report_data_t *data)
{
  free (data->report_id);
  free (data->parameter_id);
  free (data->parameter_value);
  memset (data, 0, sizeof (modify_report_data_t));
}

typedef struct
{
  char *action;
  char *comment;
  char *escalator_id;
  char *file;
  char *file_name;
  char *name;
  char *parameter;
  char *rcfile;
  char *schedule_id;
  char *task_id;
  char *value;
} modify_task_data_t;

static void
modify_task_data_reset (modify_task_data_t *data)
{
  free (data->action);
  free (data->comment);
  free (data->escalator_id);
  free (data->file);
  free (data->file_name);
  free (data->name);
  free (data->parameter);
  free (data->rcfile);
  free (data->schedule_id);
  free (data->task_id);
  free (data->value);
  memset (data, 0, sizeof (modify_task_data_t));
}

typedef create_note_data_t modify_note_data_t;

#define modify_note_data_reset create_note_data_reset

typedef struct
{
  char *task_id;
} pause_task_data_t;

static void
pause_task_data_reset (pause_task_data_t *data)
{
  free (data->task_id);

  memset (data, 0, sizeof (pause_task_data_t));
}

typedef struct
{
  char *task_id;
} resume_or_start_task_data_t;

static void
resume_or_start_task_data_reset (resume_or_start_task_data_t *data)
{
  free (data->task_id);

  memset (data, 0, sizeof (resume_or_start_task_data_t));
}

typedef struct
{
  char *task_id;
} resume_paused_task_data_t;

static void
resume_paused_task_data_reset (resume_paused_task_data_t *data)
{
  free (data->task_id);

  memset (data, 0, sizeof (resume_paused_task_data_t));
}

typedef struct
{
  char *task_id;
} resume_stopped_task_data_t;

static void
resume_stopped_task_data_reset (resume_stopped_task_data_t *data)
{
  free (data->task_id);

  memset (data, 0, sizeof (resume_stopped_task_data_t));
}

typedef struct
{
  char *task_id;
} start_task_data_t;

static void
start_task_data_reset (start_task_data_t *data)
{
  free (data->task_id);

  memset (data, 0, sizeof (start_task_data_t));
}

typedef struct
{
  char *name;
} test_escalator_data_t;

static void
test_escalator_data_reset (test_escalator_data_t *data)
{
  free (data->name);

  memset (data, 0, sizeof (test_escalator_data_t));
}

typedef union
{
  abort_task_data_t abort_task;
  create_agent_data_t create_agent;
  create_config_data_t create_config;
  create_escalator_data_t create_escalator;
  create_lsc_credential_data_t create_lsc_credential;
  create_note_data_t create_note;
  create_schedule_data_t create_schedule;
  create_target_data_t create_target;
  create_task_data_t create_task;
  delete_agent_data_t delete_agent;
  delete_config_data_t delete_config;
  delete_escalator_data_t delete_escalator;
  delete_lsc_credential_data_t delete_lsc_credential;
  delete_note_data_t delete_note;
  delete_report_data_t delete_report;
  delete_schedule_data_t delete_schedule;
  delete_target_data_t delete_target;
  delete_task_data_t delete_task;
  get_notes_data_t get_notes;
  get_preferences_data_t get_preferences;
  get_report_data_t get_report;
  get_results_data_t get_results;
  get_schedules_data_t get_schedules;
  get_system_reports_data_t get_system_reports;
  modify_config_data_t modify_config;
  modify_report_data_t modify_report;
  modify_task_data_t modify_task;
  pause_task_data_t pause_task;
  resume_or_start_task_data_t resume_or_start_task;
  resume_paused_task_data_t resume_paused_task;
  resume_stopped_task_data_t resume_stopped_task;
  start_task_data_t start_task;
  test_escalator_data_t test_escalator;
} command_data_t;

/**
 * @brief Initialise command data.
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
command_data_t command_data;

/**
 * @brief Parser callback data for ABORT_TASK.
 */
abort_task_data_t *abort_task_data
 = (abort_task_data_t*) &(command_data.abort_task);

/**
 * @brief Parser callback data for CREATE_AGENT.
 */
create_agent_data_t *create_agent_data
 = (create_agent_data_t*) &(command_data.create_agent);

/**
 * @brief Parser callback data for CREATE_CONFIG.
 */
create_config_data_t *create_config_data
 = (create_config_data_t*) &(command_data.create_config);

/**
 * @brief Parser callback data for CREATE_ESCALATOR.
 */
create_escalator_data_t *create_escalator_data
 = (create_escalator_data_t*) &(command_data.create_escalator);

/**
 * @brief Parser callback data for CREATE_LSC_CREDENTIAL.
 */
create_lsc_credential_data_t *create_lsc_credential_data
 = (create_lsc_credential_data_t*) &(command_data.create_lsc_credential);

/**
 * @brief Parser callback data for CREATE_NOTE.
 */
create_note_data_t *create_note_data
 = (create_note_data_t*) &(command_data.create_note);

/**
 * @brief Parser callback data for CREATE_SCHEDULE.
 */
create_schedule_data_t *create_schedule_data
 = (create_schedule_data_t*) &(command_data.create_schedule);

/**
 * @brief Parser callback data for CREATE_TARGET.
 */
create_target_data_t *create_target_data
 = (create_target_data_t*) &(command_data.create_target);

/**
 * @brief Parser callback data for CREATE_TASK.
 */
create_task_data_t *create_task_data
 = (create_task_data_t*) &(command_data.create_task);

/**
 * @brief Parser callback data for DELETE_AGENT.
 */
delete_agent_data_t *delete_agent_data
 = (delete_agent_data_t*) &(command_data.delete_agent);

/**
 * @brief Parser callback data for DELETE_CONFIG.
 */
delete_config_data_t *delete_config_data
 = (delete_config_data_t*) &(command_data.delete_config);

/**
 * @brief Parser callback data for DELETE_ESCALATOR.
 */
delete_escalator_data_t *delete_escalator_data
 = (delete_escalator_data_t*) &(command_data.delete_escalator);

/**
 * @brief Parser callback data for DELETE_LSC_CREDENTIAL.
 */
delete_lsc_credential_data_t *delete_lsc_credential_data
 = (delete_lsc_credential_data_t*) &(command_data.delete_lsc_credential);

/**
 * @brief Parser callback data for DELETE_NOTE.
 */
delete_note_data_t *delete_note_data
 = (delete_note_data_t*) &(command_data.delete_note);

/**
 * @brief Parser callback data for DELETE_REPORT.
 */
delete_report_data_t *delete_report_data
 = (delete_report_data_t*) &(command_data.delete_report);

/**
 * @brief Parser callback data for DELETE_SCHEDULE.
 */
delete_schedule_data_t *delete_schedule_data
 = (delete_schedule_data_t*) &(command_data.delete_schedule);

/**
 * @brief Parser callback data for DELETE_TARGET.
 */
delete_target_data_t *delete_target_data
 = (delete_target_data_t*) &(command_data.delete_target);

/**
 * @brief Parser callback data for DELETE_TASK.
 */
delete_task_data_t *delete_task_data
 = (delete_task_data_t*) &(command_data.delete_task);

/**
 * @brief Parser callback data for GET_NOTES.
 */
get_notes_data_t *get_notes_data
 = &(command_data.get_notes);

/**
 * @brief Parser callback data for GET_PREFERENCES.
 */
get_preferences_data_t *get_preferences_data
 = &(command_data.get_preferences);

/**
 * @brief Parser callback data for GET_REPORT.
 */
get_report_data_t *get_report_data
 = &(command_data.get_report);

/**
 * @brief Parser callback data for GET_RESULTS.
 */
get_results_data_t *get_results_data
 = &(command_data.get_results);

/**
 * @brief Parser callback data for GET_SCHEDULES.
 */
get_schedules_data_t *get_schedules_data
 = &(command_data.get_schedules);

/**
 * @brief Parser callback data for GET_SYSTEM_REPORTS.
 */
get_system_reports_data_t *get_system_reports_data
 = &(command_data.get_system_reports);

/**
 * @brief Parser callback data for CREATE_CONFIG (import).
 */
import_config_data_t *import_config_data
 = (import_config_data_t*) &(command_data.create_config.import);

/**
 * @brief Parser callback data for MODIFY_CONFIG.
 */
modify_config_data_t *modify_config_data
 = &(command_data.modify_config);

/**
 * @brief Parser callback data for MODIFY_NOTE.
 */
modify_note_data_t *modify_note_data
 = (modify_note_data_t*) &(command_data.create_note);

/**
 * @brief Parser callback data for MODIFY_REPORT.
 */
modify_report_data_t *modify_report_data
 = &(command_data.modify_report);

/**
 * @brief Parser callback data for MODIFY_TASK.
 */
modify_task_data_t *modify_task_data
 = &(command_data.modify_task);

/**
 * @brief Parser callback data for PAUSE_TASK.
 */
pause_task_data_t *pause_task_data
 = (pause_task_data_t*) &(command_data.pause_task);

/**
 * @brief Parser callback data for RESUME_OR_START_TASK.
 */
resume_or_start_task_data_t *resume_or_start_task_data
 = (resume_or_start_task_data_t*) &(command_data.resume_or_start_task);

/**
 * @brief Parser callback data for RESUME_PAUSED_TASK.
 */
resume_paused_task_data_t *resume_paused_task_data
 = (resume_paused_task_data_t*) &(command_data.resume_paused_task);

/**
 * @brief Parser callback data for RESUME_STOPPED_TASK.
 */
resume_stopped_task_data_t *resume_stopped_task_data
 = (resume_stopped_task_data_t*) &(command_data.resume_stopped_task);

/**
 * @brief Parser callback data for START_TASK.
 */
start_task_data_t *start_task_data
 = (start_task_data_t*) &(command_data.start_task);

/**
 * @brief Parser callback data for TEST_ESCALATOR.
 */
test_escalator_data_t *test_escalator_data
 = (test_escalator_data_t*) &(command_data.test_escalator);

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
 * @brief Generic integer variable for communicating between the callbacks.
 */
int current_int_4;

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
 * @brief Name during OMP MODIFY_TASK.
 */
static /*@null@*/ /*@only@*/ char*
modify_task_name = NULL;

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
  /* get_configs_response (GCR) is used for config export.  CLIENT_C_C is
   * for CLIENT_CREATE_CONFIG. */
  CLIENT_C_C_GCR,
  CLIENT_C_C_GCR_CONFIG,
  CLIENT_C_C_GCR_CONFIG_COMMENT,
  CLIENT_C_C_GCR_CONFIG_NAME,
  CLIENT_C_C_GCR_CONFIG_NVT_SELECTORS,
  CLIENT_C_C_GCR_CONFIG_NVT_SELECTORS_NVT_SELECTOR,
  CLIENT_C_C_GCR_CONFIG_NVT_SELECTORS_NVT_SELECTOR_NAME,
  CLIENT_C_C_GCR_CONFIG_NVT_SELECTORS_NVT_SELECTOR_INCLUDE,
  CLIENT_C_C_GCR_CONFIG_NVT_SELECTORS_NVT_SELECTOR_TYPE,
  CLIENT_C_C_GCR_CONFIG_NVT_SELECTORS_NVT_SELECTOR_FAMILY_OR_NVT,
  CLIENT_C_C_GCR_CONFIG_PREFERENCES,
  CLIENT_C_C_GCR_CONFIG_PREFERENCES_PREFERENCE,
  CLIENT_C_C_GCR_CONFIG_PREFERENCES_PREFERENCE_ALT,
  CLIENT_C_C_GCR_CONFIG_PREFERENCES_PREFERENCE_NAME,
  CLIENT_C_C_GCR_CONFIG_PREFERENCES_PREFERENCE_NVT,
  CLIENT_C_C_GCR_CONFIG_PREFERENCES_PREFERENCE_NVT_NAME,
  CLIENT_C_C_GCR_CONFIG_PREFERENCES_PREFERENCE_TYPE,
  CLIENT_C_C_GCR_CONFIG_PREFERENCES_PREFERENCE_VALUE,
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
  CLIENT_CREATE_NOTE,
  CLIENT_CREATE_NOTE_HOSTS,
  CLIENT_CREATE_NOTE_NVT,
  CLIENT_CREATE_NOTE_PORT,
  CLIENT_CREATE_NOTE_RESULT,
  CLIENT_CREATE_NOTE_TASK,
  CLIENT_CREATE_NOTE_TEXT,
  CLIENT_CREATE_NOTE_THREAT,
  CLIENT_CREATE_SCHEDULE,
  CLIENT_CREATE_SCHEDULE_NAME,
  CLIENT_CREATE_SCHEDULE_COMMENT,
  CLIENT_CREATE_SCHEDULE_FIRST_TIME,
  CLIENT_CREATE_SCHEDULE_FIRST_TIME_DAY_OF_MONTH,
  CLIENT_CREATE_SCHEDULE_FIRST_TIME_HOUR,
  CLIENT_CREATE_SCHEDULE_FIRST_TIME_MINUTE,
  CLIENT_CREATE_SCHEDULE_FIRST_TIME_MONTH,
  CLIENT_CREATE_SCHEDULE_FIRST_TIME_YEAR,
  CLIENT_CREATE_SCHEDULE_DURATION,
  CLIENT_CREATE_SCHEDULE_DURATION_UNIT,
  CLIENT_CREATE_SCHEDULE_PERIOD,
  CLIENT_CREATE_SCHEDULE_PERIOD_UNIT,
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
  CLIENT_CREATE_TASK_SCHEDULE,
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
  CLIENT_DELETE_NOTE,
  CLIENT_DELETE_REPORT,
  CLIENT_DELETE_SCHEDULE,
  CLIENT_DELETE_TASK,
  CLIENT_DELETE_TARGET,
  CLIENT_DELETE_TARGET_NAME,
  CLIENT_GET_AGENTS,
  CLIENT_GET_CERTIFICATES,
  CLIENT_GET_CONFIGS,
  CLIENT_GET_DEPENDENCIES,
  CLIENT_GET_ESCALATORS,
  CLIENT_GET_LSC_CREDENTIALS,
  CLIENT_GET_NOTES,
  CLIENT_GET_NOTES_NVT,
  CLIENT_GET_NOTES_TASK,
  CLIENT_GET_NVT_ALL,
  CLIENT_GET_NVT_DETAILS,
  CLIENT_GET_NVT_FAMILIES,
  CLIENT_GET_NVT_FEED_CHECKSUM,
  CLIENT_GET_PREFERENCES,
  CLIENT_GET_REPORT,
  CLIENT_GET_RESULTS,
  CLIENT_GET_RULES,
  CLIENT_GET_SCHEDULES,
  CLIENT_GET_STATUS,
  CLIENT_GET_SYSTEM_REPORTS,
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
  CLIENT_MODIFY_NOTE,
  CLIENT_MODIFY_NOTE_HOSTS,
  CLIENT_MODIFY_NOTE_PORT,
  CLIENT_MODIFY_NOTE_RESULT,
  CLIENT_MODIFY_NOTE_TASK,
  CLIENT_MODIFY_NOTE_TEXT,
  CLIENT_MODIFY_NOTE_THREAT,
  CLIENT_MODIFY_TASK,
  CLIENT_MODIFY_TASK_COMMENT,
  CLIENT_MODIFY_TASK_ESCALATOR,
  CLIENT_MODIFY_TASK_FILE,
  CLIENT_MODIFY_TASK_NAME,
  CLIENT_MODIFY_TASK_PARAMETER,
  CLIENT_MODIFY_TASK_RCFILE,
  CLIENT_MODIFY_TASK_SCHEDULE,
  CLIENT_PAUSE_TASK,
  CLIENT_RESUME_OR_START_TASK,
  CLIENT_RESUME_PAUSED_TASK,
  CLIENT_RESUME_STOPPED_TASK,
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
      tracef ("   send_to_client out of space (%i < %zu)\n",
              ((buffer_size_t) TO_CLIENT_BUFFER_SIZE) - to_client_end,
              strlen (msg));
      return TRUE;
    }

  memmove (to_client + to_client_end, msg, strlen (msg));
  tracef ("-> client: %s\n", msg);
  to_client_end += strlen (msg);
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

  /** @todo Set gerror so parsing terminates. */
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
 * @brief Expand to XML for a STATUS_ERROR_ACCESS response.
 *
 * @param  tag  Name of the command generating the response.
 */
#define XML_ERROR_ACCESS(tag)                            \
 "<" tag "_response"                                     \
 " status=\"" STATUS_ERROR_ACCESS "\""                   \
 " status_text=\"" STATUS_ERROR_ACCESS_TEXT "\"/>"

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
              openvas_append_string (&abort_task_data->task_id, attribute);
            set_client_state (CLIENT_ABORT_TASK);
          }
        else if (strcasecmp ("COMMANDS", element_name) == 0)
          {
            SEND_TO_CLIENT_OR_FAIL
             ("<commands_response"
              " status=\"" STATUS_OK "\" status_text=\"" STATUS_OK_TEXT "\">");
            set_client_state (CLIENT_AUTHENTIC_COMMANDS);
          }
        else if (strcasecmp ("CREATE_AGENT", element_name) == 0)
          {
            openvas_append_string (&create_agent_data->comment, "");
            openvas_append_string (&create_agent_data->name, "");
            openvas_append_string (&create_agent_data->installer, "");
            openvas_append_string (&create_agent_data->howto_install, "");
            openvas_append_string (&create_agent_data->howto_use, "");
            set_client_state (CLIENT_CREATE_AGENT);
          }
        else if (strcasecmp ("CREATE_CONFIG", element_name) == 0)
          {
            openvas_append_string (&create_config_data->comment, "");
            openvas_append_string (&create_config_data->name, "");
            set_client_state (CLIENT_CREATE_CONFIG);
          }
        else if (strcasecmp ("CREATE_ESCALATOR", element_name) == 0)
          {
            create_escalator_data->condition_data = make_array ();
            create_escalator_data->event_data = make_array ();
            create_escalator_data->method_data = make_array ();

            openvas_append_string (&create_escalator_data->part_data, "");
            openvas_append_string (&create_escalator_data->part_name, "");
            openvas_append_string (&create_escalator_data->comment, "");
            openvas_append_string (&create_escalator_data->name, "");
            openvas_append_string (&create_escalator_data->condition, "");
            openvas_append_string (&create_escalator_data->method, "");
            openvas_append_string (&create_escalator_data->event, "");

            set_client_state (CLIENT_CREATE_ESCALATOR);
          }
        else if (strcasecmp ("CREATE_LSC_CREDENTIAL", element_name) == 0)
          {
            openvas_append_string (&create_lsc_credential_data->comment, "");
            openvas_append_string (&create_lsc_credential_data->login, "");
            openvas_append_string (&create_lsc_credential_data->name, "");
            set_client_state (CLIENT_CREATE_LSC_CREDENTIAL);
          }
        else if (strcasecmp ("CREATE_NOTE", element_name) == 0)
          set_client_state (CLIENT_CREATE_NOTE);
        else if (strcasecmp ("CREATE_SCHEDULE", element_name) == 0)
          set_client_state (CLIENT_CREATE_SCHEDULE);
        else if (strcasecmp ("CREATE_TARGET", element_name) == 0)
          {
            openvas_append_string (&create_target_data->comment, "");
            openvas_append_string (&create_target_data->name, "");
            openvas_append_string (&create_target_data->hosts, "");
            set_client_state (CLIENT_CREATE_TARGET);
          }
        else if (strcasecmp ("CREATE_TASK", element_name) == 0)
          {
            create_task_data->task = make_task (NULL, 0, NULL);
            if (create_task_data->task == (task_t) 0) abort (); // FIX
            openvas_append_string (&create_task_data->escalator, "");
            openvas_append_string (&create_task_data->schedule, "");
            set_client_state (CLIENT_CREATE_TASK);
          }
        else if (strcasecmp ("DELETE_AGENT", element_name) == 0)
          {
            openvas_append_string (&delete_agent_data->name, "");
            set_client_state (CLIENT_DELETE_AGENT);
          }
        else if (strcasecmp ("DELETE_CONFIG", element_name) == 0)
          {
            openvas_append_string (&delete_config_data->name, "");
            set_client_state (CLIENT_DELETE_CONFIG);
          }
        else if (strcasecmp ("DELETE_ESCALATOR", element_name) == 0)
          {
            openvas_append_string (&delete_escalator_data->name, "");
            set_client_state (CLIENT_DELETE_ESCALATOR);
          }
        else if (strcasecmp ("DELETE_LSC_CREDENTIAL", element_name) == 0)
          {
            openvas_append_string (&delete_lsc_credential_data->name, "");
            set_client_state (CLIENT_DELETE_LSC_CREDENTIAL);
          }
        else if (strcasecmp ("DELETE_NOTE", element_name) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values,
                                "note_id", &attribute))
              openvas_append_string (&delete_note_data->note_id, attribute);
            set_client_state (CLIENT_DELETE_NOTE);
          }
        else if (strcasecmp ("DELETE_REPORT", element_name) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values,
                                "report_id", &attribute))
              openvas_append_string (&delete_report_data->report_id, attribute);
            set_client_state (CLIENT_DELETE_REPORT);
          }
        else if (strcasecmp ("DELETE_SCHEDULE", element_name) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values,
                                "schedule_id", &attribute))
              openvas_append_string (&delete_schedule_data->schedule_id,
                                     attribute);
            set_client_state (CLIENT_DELETE_SCHEDULE);
          }
        else if (strcasecmp ("DELETE_TARGET", element_name) == 0)
          {
            openvas_append_string (&delete_target_data->name, "");
            set_client_state (CLIENT_DELETE_TARGET);
          }
        else if (strcasecmp ("DELETE_TASK", element_name) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values,
                                "task_id", &attribute))
              openvas_append_string (&delete_task_data->task_id, attribute);
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
            if (find_attribute (attribute_names, attribute_values,
                                "export", &attribute))
              current_int_4 = atoi (attribute);
            else
              current_int_4 = 0;
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
        else if (strcasecmp ("GET_NOTES", element_name) == 0)
          {
            const gchar* attribute;

            if (find_attribute (attribute_names, attribute_values,
                                "note_id", &attribute))
              openvas_append_string (&get_notes_data->note_id, attribute);

            if (find_attribute (attribute_names, attribute_values,
                                "details", &attribute))
              get_notes_data->details = strcmp (attribute, "0");
            else
              get_notes_data->details = 0;

            if (find_attribute (attribute_names, attribute_values,
                                "result", &attribute))
              get_notes_data->result = strcmp (attribute, "0");
            else
              get_notes_data->result = 0;

            if (find_attribute (attribute_names, attribute_values,
                                "sort_field", &attribute))
              openvas_append_string (&get_notes_data->sort_field, attribute);

            if (find_attribute (attribute_names, attribute_values,
                                "sort_order", &attribute))
              get_notes_data->sort_order = strcmp (attribute, "descending");
            else
              get_notes_data->sort_order = 1;

            set_client_state (CLIENT_GET_NOTES);
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
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values,
                                "oid", &attribute))
              openvas_append_string (&get_preferences_data->oid,
                                     attribute);
            if (find_attribute (attribute_names, attribute_values,
                                "config", &attribute))
              openvas_append_string (&get_preferences_data->config,
                                     attribute);
            if (find_attribute (attribute_names, attribute_values,
                                "preference", &attribute))
              openvas_append_string (&get_preferences_data->preference,
                                     attribute);
            set_client_state (CLIENT_GET_PREFERENCES);
          }
        else if (strcasecmp ("GET_REPORT", element_name) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values,
                                "report_id", &attribute))
              openvas_append_string (&get_report_data->report_id, attribute);

            if (find_attribute (attribute_names, attribute_values,
                                "format", &attribute))
              openvas_append_string (&get_report_data->format, attribute);

            if (find_attribute (attribute_names, attribute_values,
                                "first_result", &attribute))
              /* Subtract 1 to switch from 1 to 0 indexing. */
              get_report_data->first_result = atoi (attribute) - 1;
            else
              get_report_data->first_result = 0;

            if (find_attribute (attribute_names, attribute_values,
                                "max_results", &attribute))
              get_report_data->max_results = atoi (attribute);
            else
              get_report_data->max_results = -1;

            if (find_attribute (attribute_names, attribute_values,
                                "sort_field", &attribute))
              openvas_append_string (&get_report_data->sort_field, attribute);

            if (find_attribute (attribute_names, attribute_values,
                                "sort_order", &attribute))
              get_report_data->sort_order = strcmp (attribute, "descending");
            else
              {
                if (current_name == NULL
                    || (strcmp (current_name, "type") == 0))
                  /* Normally it makes more sense to order type descending. */
                  get_report_data->sort_order = 0;
                else
                  get_report_data->sort_order = 1;
              }

            if (find_attribute (attribute_names, attribute_values,
                                "levels", &attribute))
              openvas_append_string (&get_report_data->levels, attribute);

            if (find_attribute (attribute_names, attribute_values,
                                "search_phrase", &attribute))
              openvas_append_string (&get_report_data->search_phrase, attribute);

            if (find_attribute (attribute_names, attribute_values,
                                "notes", &attribute))
              get_report_data->notes = strcmp (attribute, "0");
            else
              get_report_data->notes = 0;

            if (find_attribute (attribute_names, attribute_values,
                                "notes_details", &attribute))
              get_report_data->notes_details = strcmp (attribute, "0");
            else
              get_report_data->notes_details = 0;

            if (find_attribute (attribute_names, attribute_values,
                                "result_hosts_only", &attribute))
              get_report_data->result_hosts_only = strcmp (attribute, "0");
            else
              get_report_data->result_hosts_only = 1;

            if (find_attribute (attribute_names, attribute_values,
                                "min_cvss_base", &attribute))
              openvas_append_string (&get_report_data->min_cvss_base,
                                     attribute);

            set_client_state (CLIENT_GET_REPORT);
          }
        else if (strcasecmp ("GET_RESULTS", element_name) == 0)
          {
            const gchar* attribute;

            if (find_attribute (attribute_names, attribute_values,
                                "result_id", &attribute))
              openvas_append_string (&get_results_data->result_id, attribute);

            if (find_attribute (attribute_names, attribute_values,
                                "task_id", &attribute))
              openvas_append_string (&get_results_data->task_id, attribute);

            if (find_attribute (attribute_names, attribute_values,
                                "notes", &attribute))
              get_results_data->notes = strcmp (attribute, "0");
            else
              get_results_data->notes = 0;

            if (find_attribute (attribute_names, attribute_values,
                                "notes_details", &attribute))
              get_results_data->notes_details = strcmp (attribute, "0");
            else
              get_results_data->notes_details = 0;

            set_client_state (CLIENT_GET_RESULTS);
          }
        else if (strcasecmp ("GET_RULES", element_name) == 0)
          set_client_state (CLIENT_GET_RULES);
        else if (strcasecmp ("GET_SCHEDULES", element_name) == 0)
          {
            const gchar* attribute;

            if (find_attribute (attribute_names, attribute_values,
                                "schedule_id", &attribute))
              openvas_append_string (&get_schedules_data->schedule_id,
                                     attribute);

            if (find_attribute (attribute_names, attribute_values,
                                "details", &attribute))
              get_schedules_data->details = strcmp (attribute, "0");
            else
              get_schedules_data->details = 0;

            if (find_attribute (attribute_names, attribute_values,
                                "sort_field", &attribute))
              openvas_append_string (&get_schedules_data->sort_field, attribute);

            if (find_attribute (attribute_names, attribute_values,
                                "sort_order", &attribute))
              get_schedules_data->sort_order = strcmp (attribute, "descending");
            else
              get_schedules_data->sort_order = 1;

            set_client_state (CLIENT_GET_SCHEDULES);
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
        else if (strcasecmp ("GET_SYSTEM_REPORTS", element_name) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values,
                                "name", &attribute))
              openvas_append_string (&(get_system_reports_data->name),
                                     attribute);
            if (find_attribute (attribute_names, attribute_values,
                                "duration", &attribute))
              openvas_append_string (&(get_system_reports_data->duration),
                                     attribute);
            set_client_state (CLIENT_GET_SYSTEM_REPORTS);
          }
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
        else if (strcasecmp ("GET_VERSION", element_name) == 0)
          set_client_state (CLIENT_VERSION);
        else if (strcasecmp ("HELP", element_name) == 0)
          set_client_state (CLIENT_HELP);
        else if (strcasecmp ("MODIFY_CONFIG", element_name) == 0)
          set_client_state (CLIENT_MODIFY_CONFIG);
        else if (strcasecmp ("MODIFY_NOTE", element_name) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values,
                                "note_id", &attribute))
              openvas_append_string (&modify_note_data->note_id, attribute);
            set_client_state (CLIENT_MODIFY_NOTE);
          }
        else if (strcasecmp ("MODIFY_REPORT", element_name) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values,
                                "report_id", &attribute))
              openvas_append_string (&modify_report_data->report_id, attribute);
            set_client_state (CLIENT_MODIFY_REPORT);
          }
        else if (strcasecmp ("MODIFY_TASK", element_name) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values,
                                "task_id", &attribute))
              openvas_append_string (&modify_task_data->task_id, attribute);
            set_client_state (CLIENT_MODIFY_TASK);
          }
        else if (strcasecmp ("PAUSE_TASK", element_name) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values,
                                "task_id", &attribute))
              openvas_append_string (&pause_task_data->task_id, attribute);
            set_client_state (CLIENT_PAUSE_TASK);
          }
        else if (strcasecmp ("RESUME_OR_START_TASK", element_name) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values,
                                "task_id", &attribute))
              openvas_append_string (&resume_or_start_task_data->task_id,
                                     attribute);
            set_client_state (CLIENT_RESUME_OR_START_TASK);
          }
        else if (strcasecmp ("RESUME_PAUSED_TASK", element_name) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values,
                                "task_id", &attribute))
              openvas_append_string (&resume_paused_task_data->task_id,
                                     attribute);
            set_client_state (CLIENT_RESUME_PAUSED_TASK);
          }
        else if (strcasecmp ("RESUME_STOPPED_TASK", element_name) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values,
                                "task_id", &attribute))
              openvas_append_string (&resume_paused_task_data->task_id,
                                     attribute);
            set_client_state (CLIENT_RESUME_STOPPED_TASK);
          }
        else if (strcasecmp ("START_TASK", element_name) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values,
                                "task_id", &attribute))
              openvas_append_string (&start_task_data->task_id, attribute);
            set_client_state (CLIENT_START_TASK);
          }
        else if (strcasecmp ("TEST_ESCALATOR", element_name) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values,
                                "name", &attribute))
              openvas_append_string (&test_escalator_data->name, attribute);
            set_client_state (CLIENT_TEST_ESCALATOR);
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
          {
            /* Init, so it's the empty string when the entity is empty. */
            append_to_credentials_password (&current_credentials, "", 0);
            set_client_state (CLIENT_CREDENTIALS);
          }
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

      case CLIENT_CREATE_SCHEDULE:
        if (strcasecmp ("COMMENT", element_name) == 0)
          set_client_state (CLIENT_CREATE_SCHEDULE_COMMENT);
        else if (strcasecmp ("DURATION", element_name) == 0)
          set_client_state (CLIENT_CREATE_SCHEDULE_DURATION);
        else if (strcasecmp ("FIRST_TIME", element_name) == 0)
          set_client_state (CLIENT_CREATE_SCHEDULE_FIRST_TIME);
        else if (strcasecmp ("NAME", element_name) == 0)
          set_client_state (CLIENT_CREATE_SCHEDULE_NAME);
        else if (strcasecmp ("PERIOD", element_name) == 0)
          set_client_state (CLIENT_CREATE_SCHEDULE_PERIOD);
        else
          {
            if (send_element_error_to_client ("create_schedule", element_name))
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

      case CLIENT_CREATE_SCHEDULE_FIRST_TIME:
        if (strcasecmp ("DAY_OF_MONTH", element_name) == 0)
          set_client_state (CLIENT_CREATE_SCHEDULE_FIRST_TIME_DAY_OF_MONTH);
        else if (strcasecmp ("HOUR", element_name) == 0)
          set_client_state (CLIENT_CREATE_SCHEDULE_FIRST_TIME_HOUR);
        else if (strcasecmp ("MINUTE", element_name) == 0)
          set_client_state (CLIENT_CREATE_SCHEDULE_FIRST_TIME_MINUTE);
        else if (strcasecmp ("MONTH", element_name) == 0)
          set_client_state (CLIENT_CREATE_SCHEDULE_FIRST_TIME_MONTH);
        else if (strcasecmp ("YEAR", element_name) == 0)
          set_client_state (CLIENT_CREATE_SCHEDULE_FIRST_TIME_YEAR);
        else
          {
            if (send_element_error_to_client ("create_schedule", element_name))
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

      case CLIENT_CREATE_SCHEDULE_DURATION:
        if (strcasecmp ("UNIT", element_name) == 0)
          set_client_state (CLIENT_CREATE_SCHEDULE_DURATION_UNIT);
        else
          {
            if (send_element_error_to_client ("create_schedule", element_name))
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

      case CLIENT_CREATE_SCHEDULE_PERIOD:
        if (strcasecmp ("UNIT", element_name) == 0)
          set_client_state (CLIENT_CREATE_SCHEDULE_PERIOD_UNIT);
        else
          {
            if (send_element_error_to_client ("create_schedule", element_name))
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

      case CLIENT_CREATE_SCHEDULE_COMMENT:
      case CLIENT_CREATE_SCHEDULE_NAME:
      case CLIENT_CREATE_SCHEDULE_FIRST_TIME_DAY_OF_MONTH:
      case CLIENT_CREATE_SCHEDULE_FIRST_TIME_HOUR:
      case CLIENT_CREATE_SCHEDULE_FIRST_TIME_MINUTE:
      case CLIENT_CREATE_SCHEDULE_FIRST_TIME_MONTH:
      case CLIENT_CREATE_SCHEDULE_FIRST_TIME_YEAR:
      case CLIENT_CREATE_SCHEDULE_DURATION_UNIT:
      case CLIENT_CREATE_SCHEDULE_PERIOD_UNIT:
        if (send_element_error_to_client ("create_schedule", element_name))
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

      case CLIENT_DELETE_NOTE:
        if (send_element_error_to_client ("delete_note", element_name))
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

      case CLIENT_DELETE_SCHEDULE:
        if (send_element_error_to_client ("delete_schedule", element_name))
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

      case CLIENT_GET_NOTES:
        if (strcasecmp ("NVT", element_name) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values,
                                "id", &attribute))
              openvas_append_string (&get_notes_data->nvt_oid, attribute);
            set_client_state (CLIENT_GET_NOTES_NVT);
          }
        else if (strcasecmp ("TASK", element_name) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values,
                                "id", &attribute))
              openvas_append_string (&get_notes_data->task_id, attribute);
            set_client_state (CLIENT_GET_NOTES_TASK);
          }
        else
          {
            if (send_element_error_to_client ("get_notes", element_name))
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
      case CLIENT_GET_NOTES_NVT:
        if (send_element_error_to_client ("get_notes", element_name))
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
      case CLIENT_GET_NOTES_TASK:
        if (send_element_error_to_client ("get_notes", element_name))
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

      case CLIENT_GET_RESULTS:
        if (send_element_error_to_client ("get_results", element_name))
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

      case CLIENT_GET_SCHEDULES:
          {
            if (send_element_error_to_client ("get_schedules", element_name))
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

      case CLIENT_GET_SYSTEM_REPORTS:
          {
            if (send_element_error_to_client ("get_system_reports", element_name))
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
            modify_config_data->families_growing_all = make_array ();
            modify_config_data->families_static_all = make_array ();
            modify_config_data->families_growing_empty = make_array ();
            /* For GROWING entity, in case missing. */
            modify_config_data->family_selection_growing = 0;
            set_client_state (CLIENT_MODIFY_CONFIG_FAMILY_SELECTION);
          }
        else if (strcasecmp ("NVT_SELECTION", element_name) == 0)
          {
            modify_config_data->nvt_selection = make_array ();
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
          set_client_state (CLIENT_MODIFY_CONFIG_NVT_SELECTION_FAMILY);
        else if (strcasecmp ("NVT", element_name) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values,
                                "oid", &attribute))
              openvas_append_string (&modify_config_data->nvt_selection_nvt_oid,
                                     attribute);
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
            /* For ALL entity, in case missing. */
            modify_config_data->family_selection_family_all = 0;
            /* For GROWING entity, in case missing. */
            modify_config_data->family_selection_family_growing = 0;
            set_client_state (CLIENT_MODIFY_CONFIG_FAMILY_SELECTION_FAMILY);
          }
        else if (strcasecmp ("GROWING", element_name) == 0)
          set_client_state (CLIENT_MODIFY_CONFIG_FAMILY_SELECTION_GROWING);
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
              openvas_append_string (&modify_config_data->preference_nvt_oid,
                                     attribute);
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
              openvas_append_string (&modify_report_data->parameter_id,
                                     attribute);
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
          {
            openvas_append_string (&modify_task_data->comment, "");
            set_client_state (CLIENT_MODIFY_TASK_COMMENT);
          }
        else if (strcasecmp ("ESCALATOR", element_name) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values,
                                "id", &attribute))
              openvas_append_string (&modify_task_data->escalator_id,
                                     attribute);
            set_client_state (CLIENT_MODIFY_TASK_ESCALATOR);
          }
        else if (strcasecmp ("NAME", element_name) == 0)
          set_client_state (CLIENT_MODIFY_TASK_NAME);
        else if (strcasecmp ("PARAMETER", element_name) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values,
                                "id", &attribute))
              openvas_append_string (&modify_task_data->parameter, attribute);
            set_client_state (CLIENT_MODIFY_TASK_PARAMETER);
          }
        else if (strcasecmp ("RCFILE", element_name) == 0)
          set_client_state (CLIENT_MODIFY_TASK_RCFILE);
        else if (strcasecmp ("SCHEDULE", element_name) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values,
                                "id", &attribute))
              openvas_append_string (&modify_task_data->schedule_id,
                                     attribute);
            set_client_state (CLIENT_MODIFY_TASK_SCHEDULE);
          }
        else if (strcasecmp ("FILE", element_name) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values,
                                "name", &attribute))
              openvas_append_string (&modify_task_data->file_name, attribute);
            if (find_attribute (attribute_names, attribute_values,
                                "action", &attribute))
              openvas_append_string (&modify_task_data->action, attribute);
            else
              openvas_append_string (&modify_task_data->action, "update");
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
        else if (strcasecmp ("GET_CONFIGS_RESPONSE", element_name) == 0)
          set_client_state (CLIENT_C_C_GCR);
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

      case CLIENT_C_C_GCR:
        if (strcasecmp ("CONFIG", element_name) == 0)
          {
            /* Reset here in case there was a previous config element. */
            create_config_data_reset (create_config_data);
            set_client_state (CLIENT_C_C_GCR_CONFIG);
          }
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

      case CLIENT_C_C_GCR_CONFIG:
        if (strcasecmp ("COMMENT", element_name) == 0)
          set_client_state (CLIENT_C_C_GCR_CONFIG_COMMENT);
        else if (strcasecmp ("NAME", element_name) == 0)
          set_client_state (CLIENT_C_C_GCR_CONFIG_NAME);
        else if (strcasecmp ("NVT_SELECTORS", element_name) == 0)
          {
            /* Reset array, in case there was a previous nvt_selectors element. */
            array_reset (&import_config_data->nvt_selectors);
            set_client_state (CLIENT_C_C_GCR_CONFIG_NVT_SELECTORS);
          }
        else if (strcasecmp ("PREFERENCES", element_name) == 0)
          {
            /* Reset array, in case there was a previous preferences element. */
            array_reset (&import_config_data->preferences);
            set_client_state (CLIENT_C_C_GCR_CONFIG_PREFERENCES);
          }
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

      case CLIENT_C_C_GCR_CONFIG_NVT_SELECTORS:
        if (strcasecmp ("NVT_SELECTOR", element_name) == 0)
          set_client_state (CLIENT_C_C_GCR_CONFIG_NVT_SELECTORS_NVT_SELECTOR);
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

      case CLIENT_C_C_GCR_CONFIG_NVT_SELECTORS_NVT_SELECTOR:
        if (strcasecmp ("INCLUDE", element_name) == 0)
          set_client_state
           (CLIENT_C_C_GCR_CONFIG_NVT_SELECTORS_NVT_SELECTOR_INCLUDE);
        else if (strcasecmp ("NAME", element_name) == 0)
          set_client_state
           (CLIENT_C_C_GCR_CONFIG_NVT_SELECTORS_NVT_SELECTOR_NAME);
        else if (strcasecmp ("TYPE", element_name) == 0)
          set_client_state
           (CLIENT_C_C_GCR_CONFIG_NVT_SELECTORS_NVT_SELECTOR_TYPE);
        else if (strcasecmp ("FAMILY_OR_NVT", element_name) == 0)
          set_client_state
           (CLIENT_C_C_GCR_CONFIG_NVT_SELECTORS_NVT_SELECTOR_FAMILY_OR_NVT);
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

      case CLIENT_C_C_GCR_CONFIG_PREFERENCES:
        if (strcasecmp ("PREFERENCE", element_name) == 0)
          {
            array_reset (&import_config_data->preference_alts);
            set_client_state (CLIENT_C_C_GCR_CONFIG_PREFERENCES_PREFERENCE);
          }
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

      case CLIENT_C_C_GCR_CONFIG_PREFERENCES_PREFERENCE:
        if (strcasecmp ("ALT", element_name) == 0)
          set_client_state
           (CLIENT_C_C_GCR_CONFIG_PREFERENCES_PREFERENCE_ALT);
        else if (strcasecmp ("NAME", element_name) == 0)
          set_client_state
           (CLIENT_C_C_GCR_CONFIG_PREFERENCES_PREFERENCE_NAME);
        else if (strcasecmp ("NVT", element_name) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values,
                                "oid", &attribute))
              openvas_append_string (&(import_config_data->preference_nvt_oid),
                                     attribute);
            set_client_state
             (CLIENT_C_C_GCR_CONFIG_PREFERENCES_PREFERENCE_NVT);
          }
        else if (strcasecmp ("TYPE", element_name) == 0)
          set_client_state
           (CLIENT_C_C_GCR_CONFIG_PREFERENCES_PREFERENCE_TYPE);
        else if (strcasecmp ("VALUE", element_name) == 0)
          set_client_state
           (CLIENT_C_C_GCR_CONFIG_PREFERENCES_PREFERENCE_VALUE);
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

      case CLIENT_C_C_GCR_CONFIG_PREFERENCES_PREFERENCE_NVT:
        if (strcasecmp ("NAME", element_name) == 0)
          set_client_state
           (CLIENT_C_C_GCR_CONFIG_PREFERENCES_PREFERENCE_NVT_NAME);
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

      case CLIENT_C_C_GCR_CONFIG_COMMENT:
      case CLIENT_C_C_GCR_CONFIG_NAME:
      case CLIENT_C_C_GCR_CONFIG_NVT_SELECTORS_NVT_SELECTOR_INCLUDE:
      case CLIENT_C_C_GCR_CONFIG_NVT_SELECTORS_NVT_SELECTOR_NAME:
      case CLIENT_C_C_GCR_CONFIG_NVT_SELECTORS_NVT_SELECTOR_TYPE:
      case CLIENT_C_C_GCR_CONFIG_NVT_SELECTORS_NVT_SELECTOR_FAMILY_OR_NVT:
      case CLIENT_C_C_GCR_CONFIG_PREFERENCES_PREFERENCE_ALT:
      case CLIENT_C_C_GCR_CONFIG_PREFERENCES_PREFERENCE_NAME:
      case CLIENT_C_C_GCR_CONFIG_PREFERENCES_PREFERENCE_NVT_NAME:
      case CLIENT_C_C_GCR_CONFIG_PREFERENCES_PREFERENCE_TYPE:
      case CLIENT_C_C_GCR_CONFIG_PREFERENCES_PREFERENCE_VALUE:
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
          {
            openvas_append_string (&create_lsc_credential_data->password, "");
            set_client_state (CLIENT_CREATE_LSC_CREDENTIAL_PASSWORD);
          }
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

      case CLIENT_CREATE_NOTE:
        if (strcasecmp ("HOSTS", element_name) == 0)
          set_client_state (CLIENT_CREATE_NOTE_HOSTS);
        else if (strcasecmp ("NVT", element_name) == 0)
          set_client_state (CLIENT_CREATE_NOTE_NVT);
        else if (strcasecmp ("PORT", element_name) == 0)
          set_client_state (CLIENT_CREATE_NOTE_PORT);
        else if (strcasecmp ("RESULT", element_name) == 0)
          set_client_state (CLIENT_CREATE_NOTE_RESULT);
        else if (strcasecmp ("TASK", element_name) == 0)
          set_client_state (CLIENT_CREATE_NOTE_TASK);
        else if (strcasecmp ("TEXT", element_name) == 0)
          set_client_state (CLIENT_CREATE_NOTE_TEXT);
        else if (strcasecmp ("THREAT", element_name) == 0)
          set_client_state (CLIENT_CREATE_NOTE_THREAT);
        else
          {
            if (send_element_error_to_client ("create_note", element_name))
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
            if (create_task_data->task
                && add_task_description_line (create_task_data->task, "", 0))
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
        else if (strcasecmp ("SCHEDULE", element_name) == 0)
          set_client_state (CLIENT_CREATE_TASK_SCHEDULE);
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

      case CLIENT_MODIFY_NOTE:
        if (strcasecmp ("HOSTS", element_name) == 0)
          set_client_state (CLIENT_MODIFY_NOTE_HOSTS);
        else if (strcasecmp ("PORT", element_name) == 0)
          set_client_state (CLIENT_MODIFY_NOTE_PORT);
        else if (strcasecmp ("RESULT", element_name) == 0)
          set_client_state (CLIENT_MODIFY_NOTE_RESULT);
        else if (strcasecmp ("TASK", element_name) == 0)
          set_client_state (CLIENT_MODIFY_NOTE_TASK);
        else if (strcasecmp ("TEXT", element_name) == 0)
          set_client_state (CLIENT_MODIFY_NOTE_TEXT);
        else if (strcasecmp ("THREAT", element_name) == 0)
          set_client_state (CLIENT_MODIFY_NOTE_THREAT);
        else
          {
            if (send_element_error_to_client ("MODIFY_note", element_name))
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

      case CLIENT_PAUSE_TASK:
        if (send_element_error_to_client ("pause_task", element_name))
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

      case CLIENT_RESUME_OR_START_TASK:
        if (send_element_error_to_client ("resume_or_start_task", element_name))
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

      case CLIENT_RESUME_PAUSED_TASK:
        if (send_element_error_to_client ("resume_paused_task", element_name))
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

      case CLIENT_RESUME_STOPPED_TASK:
        if (send_element_error_to_client ("resume_stopped_task", element_name))
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

  const char* public_key = certificate_public_key (cert);
  const char* owner = certificate_owner (cert);
  gchar* owner_text = owner
                      ? g_markup_escape_text (owner, -1)
                      : g_strdup ("");

  msg = g_strdup_printf ("<certificate>"
                         "<fingerprint>%s</fingerprint>"
                         "<owner>%s</owner>"
                         "<trust_level>%s</trust_level>"
                         "<length>%zu</length>"
                         "<public_key>%s</public_key>"
                         "</certificate>",
                         certificate_fingerprint (cert),
                         owner_text,
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
 * @brief Define a code snippet for send_nvt.
 *
 * @param  x  Prefix for names in snippet.
 */
#define DEF(x)                                                    \
      const char* x = nvt_iterator_ ## x (nvts);                  \
      gchar* x ## _text = x                                       \
                          ? g_markup_escape_text (x, -1)          \
                          : g_strdup ("");

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
                             "<cvss_base>%s</cvss_base>"
                             "<risk_factor>%s</risk_factor>"
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
                             nvt_iterator_cvss_base (nvts)
                              ? nvt_iterator_cvss_base (nvts)
                              : "",
                             nvt_iterator_risk_factor (nvts)
                              ? nvt_iterator_risk_factor (nvts)
                              : "",
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

  if (send_to_client ("<reports>"))
    return -4;

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

  if (send_to_client ("</reports>"))
    return -4;

  return 0;
}

/**
 * @brief Print the XML for a report to a file.
 *
 * @param[in]  report      The report.
 * @param[in]  task        Task associated with report.
 * @param[in]  xml_file    File name.
 * @param[in]  ascending   Whether to sort ascending or descending.
 * @param[in]  sort_field  Field to sort on, or NULL for "type".
 * @param[in]  result_hosts_only  Whether to show only hosts with results.
 * @param[in]  min_cvss_base      Minimum CVSS base of included results.  All
 *                                results if NULL.
 *
 * @return 0 on success, else -1 with errno set.
 */
static int
print_report_xml (report_t report, task_t task, gchar* xml_file,
                  int ascending, const char* sort_field, int result_hosts_only,
                  const char *min_cvss_base)
{
  FILE *out;
  iterator_t results, hosts;
  char *end_time, *start_time;
  array_t *result_hosts;

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

  init_result_iterator (&results, report, 0, NULL,
                        get_report_data->first_result,
                        get_report_data->max_results,
                        ascending,
                        sort_field,
                        get_report_data->levels,
                        get_report_data->search_phrase,
                        min_cvss_base);

  if (result_hosts_only)
    result_hosts = make_array ();
  else
    /* Quiet erroneous compiler warning. */
    result_hosts = NULL;
  while (next (&results))
    {
      GString *buffer = g_string_new ("");
      buffer_results_xml (buffer,
                          &results,
                          task,
                          get_report_data->notes,
                          get_report_data->notes_details);
      fputs (buffer->str, out);
      g_string_free (buffer, TRUE);
      if (result_hosts_only)
        array_add_new_string (result_hosts,
                              result_iterator_host (&results));
    }
  cleanup_iterator (&results);

  if (result_hosts_only)
    {
      gchar *host;
      int index = 0;
      array_terminate (result_hosts);
      while ((host = g_ptr_array_index (result_hosts, index++)))
        {
          init_host_iterator (&hosts, report, host);
          if (next (&hosts))
            {
              fprintf (out,
                       "<host_start>"
                       "<host>%s</host>%s"
                       "</host_start>",
                       host,
                       host_iterator_start_time (&hosts));
              fprintf (out,
                       "<host_end>"
                       "<host>%s</host>%s"
                       "</host_end>",
                       host,
                       host_iterator_end_time (&hosts));
            }
          cleanup_iterator (&hosts);
        }
      array_free (result_hosts);
    }
  else
    {
      init_host_iterator (&hosts, report, NULL);
      while (next (&hosts))
        fprintf (out,
                 "<host_start><host>%s</host>%s</host_start>",
                 host_iterator_host (&hosts),
                 host_iterator_start_time (&hosts));
      cleanup_iterator (&hosts);

      init_host_iterator (&hosts, report, NULL);
      while (next (&hosts))
        fprintf (out,
                 "<host_end><host>%s</host>%s</host_end>",
                 host_iterator_host (&hosts),
                 host_iterator_end_time (&hosts));
      cleanup_iterator (&hosts);
    }

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
 * @param[in]   file        Stream to write to.
 * @param[out]  text        Text to write to file.  Zero or more lines of
 *                          newline terminated text, where the final newline
 *                          is optional.
 * @param[in]   row_colour  Row colour.
 */
static void
latex_print_verbatim_text (FILE* file, const char* text, const char *row_colour)
{
  const char* pos = text;
  /* The number of chars processed of the current line of the text. */
  int nchars = 0;
  int line_width = 80;
  int break_pos;

  if (row_colour == NULL) row_colour = "white";

  /** @todo Do this better.  Word wrapping has problems with first line. */

  /* Get the position at which to break the first line. */

  break_pos = next_break (pos, line_width);

  /* Loop over the text one character at a time, writing it out to the file
   * as LaTeX.  Put each line of the text in a verbatim environment.  On
   * reaching the break position write out LaTeX to wrap the line,
   * calculate the next break position, and continue.  While writing out
   * the text, treat "\n" in the text like a newline, and skip over "\r". */

  fprintf (file, "\\rowcolor{%s}{\\verb=", row_colour);
  while (*pos)
    {
      if (nchars == break_pos)
        {
          /* Reached the break position, start a new line in the LaTeX. */
          fputs ("=}\\\\\n", file);
          fprintf (file,
                   "\\rowcolor{%s}{$\\hookrightarrow$\\verb=",
                   row_colour);
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
                fprintf (file, "=}\\\\\n\\rowcolor{%s}{\\verb=", row_colour);
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
            fprintf (file, "=}\\\\\n\\rowcolor{%s}{\\verb=", row_colour);
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
  fputs ("=}\\\\\n", file);
}

/**
 * @brief Make text safe for LaTeX.
 *
 * Replace LaTeX special characters with LaTeX equivalents.
 *
 * @return A newly allocated version of text.
 */
static gchar*
latex_escape_text (const char *text)
{
  // TODO: Do this better.

  gsize left = strlen (text);
  gchar *new, *ch;

  /* Allocate buffer of a safe length. */
  {
    int bs = 0;
    const char *c = text;
    while (*c) { if (*c == '\\') bs++; c++; }
    new = g_strndup (text,
                     (left - bs) * 2 + bs * (strlen ("$\\backslash$") - 1) + 1);
  }

  ch = new;
  while (*ch)
    {
      /* FIX \~ becomes \verb{~} or \~{} */
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
                  /* \n becomes "\n\n" (two newlines) */
                  left--;
                  *(ch - 1) = '\n';
                  *ch = '\n';
                  break;
                }
              default:
                {
                  /* \ becomes $\backslash$ */
                  memmove (ch - 1 + strlen ("$\\backslash$"), ch, left);
                  strncpy (ch - 1, "$\\backslash$", strlen ("$\\backslash$"));
                  /* Get back to the position of the original backslash. */
                  ch--;
                  /* Move over the newly inserted characters. */
                  ch += (strlen ("$\\backslash$") - 1);
                  break;
                }
            }
        }
      else if (   *ch == '#' || *ch == '$' || *ch == '%'
               || *ch == '&' || *ch == '_' || *ch == '^'
               || *ch == '{' || *ch == '}')
        {
          ch++;
          switch (*ch)
            {
              case '\0':
                break;
              default:
                /* & becomes \& */
                memmove (ch, ch - 1, left);
                *(ch - 1) = '\\';
            }
        }
      ch++; left--;
    }
  return new;
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
    "\\usepackage[utf8x]{inputenc}\n"
    "\n"
    "\\usepackage{colortbl}\n"
    "\n"
    "% must come last\n"
    "\\usepackage{hyperref}\n"
    "\\definecolor{linkblue}{rgb}{0.11,0.56,1}\n"
    "\\definecolor{inactive}{rgb}{0.56,0.56,0.56}\n"
    "\\definecolor{openvas_debug}{rgb}{0.78,0.78,0.78}\n"
    /* Log */
    "\\definecolor{openvas_log}{rgb}{0.2275,0.2275,0.2275}\n"
    /* High: #CB1D17 */
    "\\definecolor{openvas_hole}{rgb}{0.7960,0.1137,0.0902}\n"
    /* Low: #539DCB */
    "\\definecolor{openvas_note}{rgb}{0.3255,0.6157,0.7961}\n"
    "\\definecolor{openvas_report}{rgb}{0.68,0.74,0.88}\n"
    /* Note: #FFFF90 */
    "\\definecolor{openvas_user_note}{rgb}{1.0,1.0,0.5625}\n"
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
 * @brief Print LaTeX for notes on a report to a file.
 *
 * @param[in]  out      Destination.
 * @param[in]  results  Result iterator.
 * @param[in]  task     Task associated with report containing results.
 */
static void
print_report_notes_latex (FILE *out, iterator_t *results, task_t task)
{
  iterator_t notes;

  init_note_iterator (&notes,
                      0,
                      0,
                      result_iterator_result (results),
                      task,
                      0, /* Most recent first. */
                      "creation_time");
  while (next (&notes))
    {
      time_t mod_time = note_iterator_modification_time (&notes);
      fprintf (out,
               "\\hline\n"
               "\\rowcolor{openvas_user_note}{\\textbf{Note}}\\\\\n");
      latex_print_verbatim_text (out, note_iterator_text (&notes),
                                 "openvas_user_note");
      fprintf (out,
               "\\rowcolor{openvas_user_note}{}\\\\\n"
               "\\rowcolor{openvas_user_note}{Last modified: %s}\\\\\n",
               ctime_strip_newline (&mod_time));
    }
  cleanup_iterator (&notes);
}

/**
 * @brief Print LaTeX for a report to a file.
 *
 * @param[in]  report      The report.
 * @param[in]  task        Task associated with report.
 * @param[in]  latex_file  File name.
 * @param[in]  ascending   Whether to sort ascending or descending.
 * @param[in]  sort_field  Field to sort on, or NULL for "type".
 * @param[in]  result_hosts_only  Whether to show only hosts with results.
 * @param[in]  min_cvss_base      Minimum CVSS base of included results.  All
 *                                results if NULL.
 *
 * @return 0 on success, else -1 with errno set.
 */
static int
print_report_latex (report_t report, task_t task, gchar* latex_file,
                    int ascending, const char* sort_field,
                    int result_hosts_only, const char* min_cvss_base)
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

  /* Print Header. */

  fputs (latex_header, out);

  /* Print Abstract. */

  start_time = scan_start_time (report);
  end_time = scan_end_time (report);
  fprintf (out,
           "\\begin{abstract}\n"
           "This document reports on the results of an automatic security scan.\n"
           "The scan started at %s and %s%s.  The\n"
           "report first summarises the results found.  Then, for each host,\n"
           "the report describes every issue found.  Please consider the\n"
           "advice given in each description, in order to rectify the issue.\n"
           "\\end{abstract}\n",
           start_time,
           (strlen (end_time) > 0
             ? "ended at "
             : "was still running when the report was created"),
           end_time);
  free (start_time);
  free (end_time);

  /* Print TOC. */

  fputs ("\\tableofcontents\n", out);
  fputs ("\\newpage\n", out);

  /* Print first section, Overview. */

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

  /* In Overview, print the list of hosts. */

  init_host_iterator (&hosts, report, NULL);
  /** @todo Either modify this table or show another table in which the
   *        filtered result count is shown. Also, one could alter columns
   *        in the table, e.g. with \\cellcolor{inactive}. */
  while (next (&hosts))
    {
      int holes, warnings, notes;
      const char *host = host_iterator_host (&hosts);

      if (result_hosts_only
          && manage_report_host_has_results (report, host) == 0)
        continue;

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
           "\n",
           num_hosts,
           total_holes,
           total_warnings,
           total_notes);

  const char *levels = get_report_data->levels ? get_report_data->levels
                                               : "hmlgd";
  if (get_report_data->search_phrase || strcmp (levels, "hmlgd"))
    {
      fputs ("This report might not show details of all issues that were"
             " found.\\\\\n",
             out);
      if (result_hosts_only)
        fputs ("It only lists hosts that produced issues.\\\\\n", out);
      if (get_report_data->search_phrase
          && strcmp (get_report_data->search_phrase, ""))
        fprintf (out,
                 "It shows issues that contain the search phrase \"%s\".\\\\\n",
                 get_report_data->search_phrase);
      if (!strchr (levels, 'h'))
        {
          fputs ("Issues with the threat level ", out);
          fputs ("\"High\"", out);
          fputs (" are not shown.\\\\\n", out);
        }
      if (!strchr (levels, 'm'))
        {
          fputs ("Issues with the threat level ", out);
          fputs ("\"Medium\"", out);
          fputs (" are not shown.\\\\\n", out);
        }
      if (!strchr (levels, 'l'))
        {
          fputs ("Issues with the threat level ", out);
          fputs ("\"Low\"", out);
          fputs (" are not shown.\\\\\n", out);
        }
      if (!strchr (levels, 'g'))
        {
          fputs ("Issues with the threat level ", out);
          fputs ("\"Log\"", out);
          fputs (" are not shown.\\\\\n", out);
        }
      if (!strchr (levels, 'd'))
        {
          fputs ("Issues with the threat level ", out);
          fputs ("\"Debug\"", out);
          fputs (" are not shown.\\\\\n", out);
        }
    }

  /* Print second section, "Results per Host". */

  fprintf (out, "%s\n\n", "\\section{Results per Host}");

  /* Print a subsection for each host. */

  init_host_iterator (&hosts, report, NULL);
  while (next (&hosts))
    {
      gchar *last_port;
      const char *host = host_iterator_host (&hosts);

      if (result_hosts_only
          && manage_report_host_has_results (report, host) == 0)
        continue;

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
               ((host_iterator_end_time (&hosts)
                 && strlen (host_iterator_end_time (&hosts)))
                 ? host_iterator_end_time (&hosts)
                 : ""));

      /* Print the result summary table. */

      fprintf (out,
               "\\begin{longtable}{|l|l|}\n"
               "\\hline\n"
               "\\rowcolor{openvas_report}Service (Port)&Threat Level\\\\\n"
               "\\hline\n"
               "\\endfirsthead\n"
               "\\multicolumn{2}{l}{\\hfill\\ldots (continued) \\ldots}\\\\\n"
               "\\hline\n"
               "\\rowcolor{openvas_report}Service (Port)&Threat Level\\\\\n"
               "\\hline\n"
               "\\endhead\n"
               "\\hline\n"
               "\\multicolumn{2}{l}{\\ldots (continues) \\ldots}\\\\\n"
               "\\endfoot\n"
               "\\hline\n"
               "\\endlastfoot\n");

      init_result_iterator (&results, report, 0, host,
                            get_report_data->first_result,
                            get_report_data->max_results,
                            ascending,
                            sort_field,
                            get_report_data->levels,
                            get_report_data->search_phrase,
                            min_cvss_base);
      last_port = NULL;
      while (next (&results))
        {
          if (last_port
              && (strcmp (last_port, result_iterator_port (&results)) == 0))
            continue;
          if (last_port) g_free (last_port);
          last_port = latex_escape_text (result_iterator_port (&results));
          fprintf (out,
                   "\\hyperref[port:%s %s]{%s}&%s\\\\\n"
                   "\\hline\n",
                   host_iterator_host (&hosts),
                   result_iterator_port (&results),
                   last_port,
                   result_type_threat (result_iterator_type (&results)));
        }
      cleanup_iterator (&results);
      if (last_port) g_free (last_port);

      fprintf (out,
               "\\end{longtable}\n"
               "\n"
               "%%\\subsection*{Security Issues and Fixes -- %s}\n\n",
               host_iterator_host (&hosts));

      /* Print the result details. */

      init_result_iterator (&results, report, 0, host,
                            get_report_data->first_result,
                            get_report_data->max_results,
                            ascending,
                            sort_field,
                            get_report_data->levels,
                            get_report_data->search_phrase,
                            min_cvss_base);
      last_port = NULL;
      /* Results are ordered by port, and then by severity (more severity
       * before less severe). */
      // FIX severity ordering is alphabetical on severity name
      while (next (&results))
        {
          const char *severity, *cvss_base;

          if (last_port == NULL
              || strcmp (last_port, result_iterator_port (&results)))
            {
              gchar *result_port;
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
              result_port = latex_escape_text (result_iterator_port (&results));
              fprintf (out,
                       "\\subsubsection{%s}\n"
                       "\\label{port:%s %s}\n\n"
                       "\\begin{longtable}{|p{\\textwidth * 1}|}\n",
                       result_port,
                       host_iterator_host (&hosts),
                       result_iterator_port (&results));
              g_free (result_port);
            }
          if (last_port == NULL)
            last_port = g_strdup (result_iterator_port (&results));
          severity = result_iterator_type (&results);
          cvss_base = result_iterator_nvt_cvss_base (&results);
          fprintf (out,
                   "\\hline\n"
                   "\\rowcolor%s{\\color{white}{%s%s%s%s}}\\\\\n"
                   "\\rowcolor%s{\\color{white}{NVT: %s}}\\\\\n"
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
                   latex_severity_heading (severity),
                   cvss_base ? " (CVSS: " : "",
                   cvss_base ? cvss_base : "",
                   cvss_base ? ") " : "",
                   latex_severity_colour (severity),
                   result_iterator_nvt_name (&results));
          latex_print_verbatim_text (out,
                                     result_iterator_descr (&results),
                                     NULL);
          fprintf (out,
                   "\\\\\n"
                   "OID of test routine: %s\\\\\n",
                   result_iterator_nvt_oid (&results));

          if (get_report_data->notes)
            print_report_notes_latex (out, &results, task);

          fprintf (out,
                   "\\end{longtable}\n"
                   "\n"
                   "\\begin{longtable}{|p{\\textwidth * 1}|}\n");
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
 * @brief Format XML into a buffer.
 *
 * @param[in]  buffer  Buffer.
 * @param[in]  format  Format string for XML.
 * @param[in]  args    Arguments for format string.
 */
static void
buffer_xml_append_printf (GString *buffer, const char *format, ...)
{
  va_list args;
  gchar *msg;
  va_start (args, format);
  msg = g_markup_vprintf_escaped (format, args);
  va_end (args);
  g_string_append (buffer, msg);
  g_free (msg);
}

/**
 * @brief Buffer XML for some notes.
 *
 * @param[in]  notes                  Notes iterator.
 * @param[in]  include_notes_details  Whether to include details of notes.
 * @param[in]  include_result         Whether to include associated result.
 */
static void
buffer_notes_xml (GString *buffer, iterator_t *notes, int include_notes_details,
                  int include_result)
{
  while (next (notes))
    {
      char *uuid_task, *uuid_result;

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

      if (include_notes_details == 0)
        {
          const char *text = note_iterator_text (notes);
          gchar *excerpt = g_strndup (text, 40);
          buffer_xml_append_printf (buffer,
                                    "<note id=\"%s\">"
                                    "<nvt oid=\"%s\">"
                                    "<name>%s</name>"
                                    "</nvt>"
                                    "<text excerpt=\"%i\">%s</text>"
                                    "<orphan>%i</orphan>"
                                    "</note>",
                                    note_iterator_uuid (notes),
                                    note_iterator_nvt_oid (notes),
                                    note_iterator_nvt_name (notes),
                                    strlen (excerpt) < strlen (text),
                                    excerpt,
                                    ((note_iterator_task (notes)
                                      && (uuid_task == NULL))
                                     || (note_iterator_result (notes)
                                         && (uuid_result == NULL))));
          g_free (excerpt);
        }
      else
        {
          char *name_task;
          time_t creation_time, mod_time;

          if (uuid_task)
            name_task = task_name (note_iterator_task (notes));
          else
            name_task = NULL;

          creation_time = note_iterator_creation_time (notes);
          mod_time = note_iterator_modification_time (notes);

          buffer_xml_append_printf
           (buffer,
            "<note id=\"%s\">"
            "<nvt oid=\"%s\"><name>%s</name></nvt>"
            "<creation_time>%s</creation_time>"
            "<modification_time>%s</modification_time>"
            "<text>%s</text>"
            "<hosts>%s</hosts>"
            "<port>%s</port>"
            "<threat>%s</threat>"
            "<task id=\"%s\"><name>%s</name></task>"
            "<orphan>%i</orphan>",
            note_iterator_uuid (notes),
            note_iterator_nvt_oid (notes),
            note_iterator_nvt_name (notes),
            ctime_strip_newline (&creation_time),
            ctime_strip_newline (&mod_time),
            note_iterator_text (notes),
            note_iterator_hosts (notes)
             ? note_iterator_hosts (notes) : "",
            note_iterator_port (notes)
             ? note_iterator_port (notes) : "",
            note_iterator_threat (notes)
             ? note_iterator_threat (notes) : "",
            uuid_task ? uuid_task : "",
            name_task ? name_task : "",
            ((note_iterator_task (notes) && (uuid_task == NULL))
             || (note_iterator_result (notes) && (uuid_result == NULL))));

          free (name_task);

          if (include_result && note_iterator_result (notes))
            {
              iterator_t results;

              init_result_iterator (&results, 0,
                                    note_iterator_result (notes),
                                    NULL, 0, 1, 1, NULL, NULL, NULL, NULL);
              while (next (&results))
                buffer_results_xml (buffer,
                                    &results,
                                    0,
                                    0,  /* Notes. */
                                    0); /* Note details. */
              cleanup_iterator (&results);

              buffer_xml_append_printf (buffer, "</note>");
            }
          else
            buffer_xml_append_printf (buffer,
                                      "<result id=\"%s\"/>"
                                      "</note>",
                                      uuid_result ? uuid_result : "");
        }
      free (uuid_task);
      free (uuid_result);
    }
}

/**
 * @brief Buffer XML for the NVT preference of a config.
 *
 * @param[in]  buffer  Buffer.
 * @param[in]  prefs   NVT preference iterator.
 * @param[in]  config  Config.
 */
static void
buffer_config_preference_xml (GString *buffer, iterator_t *prefs,
                              config_t config)
{
  char *real_name, *type, *value, *nvt;
  char *oid = NULL;

  real_name = nvt_preference_iterator_real_name (prefs);
  type = nvt_preference_iterator_type (prefs);
  value = nvt_preference_iterator_config_value (prefs, config);
  nvt = nvt_preference_iterator_nvt (prefs);

  if (nvt) oid = nvt_oid (nvt);

  buffer_xml_append_printf (buffer,
                            "<preference>"
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
      buffer_xml_append_printf (buffer, "<value>%s</value>", value);
      while (pos)
        {
          char *pos2 = strchr (++pos, ';');
          if (pos2) *pos2 = '\0';
          buffer_xml_append_printf (buffer, "<alt>%s</alt>", pos);
          pos = pos2;
        }
    }
  else if (value
           && type
           && (strcmp (type, "password") == 0))
    buffer_xml_append_printf (buffer, "<value></value>");
  else
    buffer_xml_append_printf (buffer, "<value>%s</value>", value ? value : "");

  buffer_xml_append_printf (buffer, "</preference>");

  free (real_name);
  free (type);
  free (value);
  free (nvt);
  free (oid);
}

/**
 * @brief Buffer XML for some results.
 *
 * @param[in]  results                Result iterator.
 * @param[in]  task                   Task associated with results.  Only needed
 *                                    with include_notes.
 * @param[in]  include_notes          Whether to include notes.
 * @param[in]  include_notes_details  Whether to include details of notes.
 */
static void
buffer_results_xml (GString *buffer, iterator_t *results, task_t task,
                    int include_notes, int include_notes_details)
{
  const char *descr = result_iterator_descr (results);
  gchar *nl_descr = descr ? convert_to_newlines (descr) : NULL;
  const char *name = result_iterator_nvt_name (results);
  const char *cvss_base = result_iterator_nvt_cvss_base (results);
  const char *risk_factor = result_iterator_nvt_risk_factor (results);
  char *uuid;

  result_uuid (result_iterator_result (results), &uuid);

  buffer_xml_append_printf
   (buffer,
    "<result id=\"%s\">"
    "<subnet>%s</subnet>"
    "<host>%s</host>"
    "<port>%s</port>"
    "<nvt oid=\"%s\">"
    "<name>%s</name>"
    "<cvss_base>%s</cvss_base>"
    "<risk_factor>%s</risk_factor>"
    "</nvt>"
    "<threat>%s</threat>"
    "<description>%s</description>",
    uuid,
    result_iterator_subnet (results),
    result_iterator_host (results),
    result_iterator_port (results),
    result_iterator_nvt_oid (results),
    name ? name : "",
    cvss_base ? cvss_base : "",
    risk_factor ? risk_factor : "",
    result_type_threat (result_iterator_type (results)),
    descr ? nl_descr : "");

  free (uuid);

  if (descr) g_free (nl_descr);

  if (include_notes)
    {
      iterator_t notes;

      assert (task);

      g_string_append (buffer, "<notes>");

      init_note_iterator (&notes,
                          0,
                          0,
                          result_iterator_result (results),
                          task,
                          0, /* Most recent first. */
                          "creation_time");
      buffer_notes_xml (buffer, &notes, include_notes_details, 0);
      cleanup_iterator (&notes);

      g_string_append (buffer, "</notes>");
    }

  g_string_append (buffer, "</result>");
}

/**
 * @brief Buffer XML for some schedules.
 *
 * @param[in]  buffer           Buffer.
 * @param[in]  schedules        Schedules iterator.
 * @param[in]  include_details  Whether to include details.
 */
static void
buffer_schedules_xml (GString *buffer, iterator_t *schedules,
                      int include_details)
{
  while (next (schedules))
    {
      if (include_details == 0)
        {
          buffer_xml_append_printf (buffer,
                                    "<schedule id=\"%s\">"
                                    "<name>%s</name>"
                                    "</schedule>",
                                    schedule_iterator_uuid (schedules),
                                    schedule_iterator_name (schedules));
        }
      else
        {
          iterator_t tasks;
          time_t first_time = schedule_iterator_first_time (schedules);
          time_t next_time = schedule_iterator_next_time (schedules);
          gchar *first_ctime = g_strdup (ctime_strip_newline (&first_time));

          buffer_xml_append_printf
           (buffer,
            "<schedule id=\"%s\">"
            "<name>%s</name>"
            "<comment>%s</comment>"
            "<first_time>%s</first_time>"
            "<next_time>%s</next_time>"
            "<period>%i</period>"
            "<period_months>%i</period_months>"
            "<duration>%i</duration>"
            "<in_use>%i</in_use>",
            schedule_iterator_uuid (schedules),
            schedule_iterator_name (schedules),
            schedule_iterator_comment (schedules),
            first_ctime,
            (next_time == 0 ? "over" : ctime_strip_newline (&next_time)),
            schedule_iterator_period (schedules),
            schedule_iterator_period_months (schedules),
            schedule_iterator_duration (schedules),
            schedule_iterator_in_use (schedules));

          g_free (first_ctime);

          buffer_xml_append_printf (buffer, "<tasks>");
          init_schedule_task_iterator (&tasks,
                                       schedule_iterator_schedule (schedules));
          while (next (&tasks))
            buffer_xml_append_printf (buffer,
                                      "<task id=\"%s\">"
                                      "<name>%s</name>"
                                      "</task>",
                                      schedule_task_iterator_uuid (&tasks),
                                      schedule_task_iterator_name (&tasks));
          cleanup_iterator (&tasks);
          buffer_xml_append_printf (buffer,
                                    "</tasks>"
                                    "</schedule>");
        }
    }
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
        if (abort_task_data->task_id)
          {
            task_t task;

            assert (current_client_task == (task_t) 0);

            if (find_task (abort_task_data->task_id, &task))
              SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("abort_task"));
            else if (task == 0)
              {
                if (send_find_error_to_client ("abort_task",
                                               "task",
                                               abort_task_data->task_id))
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
          }
        else
          SEND_TO_CLIENT_OR_FAIL
           (XML_ERROR_SYNTAX ("abort_task",
                              "ABORT_TASK requires a task_id attribute"));
        abort_task_data_reset (abort_task_data);
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_AUTHENTICATE:
        switch (authenticate (&current_credentials))
          {
            // Authentication succeeded.
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
            // Authentication failed.
            case 1:
              free_credentials (&current_credentials);
              SEND_TO_CLIENT_OR_FAIL (XML_ERROR_AUTH_FAILED ("authenticate"));
              set_client_state (CLIENT_TOP);
              break;
            // Error while authenticating.
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
          nvt_t nvt = 0;
          config_t config = 0;
          if (get_preferences_data->oid
              && find_nvt (get_preferences_data->oid, &nvt))
            SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_preferences"));
          else if (get_preferences_data->oid && nvt == 0)
            {
              if (send_find_error_to_client ("get_preferences",
                                             "NVT",
                                             get_preferences_data->oid))
                {
                  error_send_to_client (error);
                  return;
                }
            }
          else if (get_preferences_data->config
                   && find_config (get_preferences_data->config, &config))
            SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_preferences"));
          else if (get_preferences_data->config && config == 0)
            {
              if (send_find_error_to_client ("get_preferences",
                                             "config",
                                             get_preferences_data->config))
                {
                  error_send_to_client (error);
                  return;
                }
            }
          else
            {
              char *nvt_name = manage_nvt_name (nvt);
              SEND_TO_CLIENT_OR_FAIL ("<get_preferences_response"
                                      " status=\"" STATUS_OK "\""
                                      " status_text=\"" STATUS_OK_TEXT "\">");
              init_nvt_preference_iterator (&prefs, nvt_name);
              free (nvt_name);
              if (get_preferences_data->preference)
                while (next (&prefs))
                  {
                    char *name = strstr (nvt_preference_iterator_name (&prefs), "]:");
                    if (name
                        && (strcmp (name + 2,
                                    get_preferences_data->preference)
                            == 0))
                      {
                        if (config)
                          {
                            GString *buffer = g_string_new ("");
                            buffer_config_preference_xml (buffer, &prefs, config);
                            SEND_TO_CLIENT_OR_FAIL (buffer->str);
                            g_string_free (buffer, TRUE);
                          }
                        else
                          SENDF_TO_CLIENT_OR_FAIL ("<preference>"
                                                   "<name>%s</name>"
                                                   "<value>%s</value>"
                                                   "</preference>",
                                                   nvt_preference_iterator_name (&prefs),
                                                   nvt_preference_iterator_value (&prefs));
                        break;
                      }
                  }
              else
                while (next (&prefs))
                  if (config)
                    {
                      GString *buffer = g_string_new ("");
                      buffer_config_preference_xml (buffer, &prefs, config);
                      SEND_TO_CLIENT_OR_FAIL (buffer->str);
                      g_string_free (buffer, TRUE);
                    }
                  else
                    SENDF_TO_CLIENT_OR_FAIL ("<preference>"
                                             "<name>%s</name>"
                                             "<value>%s</value>"
                                             "</preference>",
                                             nvt_preference_iterator_name (&prefs),
                                             nvt_preference_iterator_value (&prefs));
              cleanup_iterator (&prefs);
              SEND_TO_CLIENT_OR_FAIL ("</get_preferences_response>");
            }
          get_preferences_data_reset (get_preferences_data);
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

              init_nvt_iterator (&nvts, (nvt_t) 0, (config_t) 0, NULL, 1, NULL);
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

      case CLIENT_GET_NOTES:
        {
          note_t note = 0;
          nvt_t nvt = 0;
          task_t task = 0;

          assert (strcasecmp ("GET_NOTES", element_name) == 0);

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
          else if (get_notes_data->note_id
              && find_note (get_notes_data->note_id, &note))
            SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_notes"));
          else if (get_notes_data->note_id && note == 0)
            {
              if (send_find_error_to_client ("get_notes",
                                             "note",
                                             get_notes_data->note_id))
                {
                  error_send_to_client (error);
                  return;
                }
            }
          else if (get_notes_data->task_id
                   && find_task (get_notes_data->task_id, &task))
            SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_notes"));
          else if (get_notes_data->task_id && task == 0)
            {
              if (send_find_error_to_client ("get_notes",
                                             "task",
                                             get_notes_data->task_id))
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
              if (send_find_error_to_client ("get_notes",
                                             "NVT",
                                             get_notes_data->nvt_oid))
                {
                  error_send_to_client (error);
                  return;
                }
            }
          else
            {
              iterator_t notes;
              GString *buffer;

              SENDF_TO_CLIENT_OR_FAIL ("<get_notes_response"
                                       " status=\"" STATUS_OK "\""
                                       " status_text=\"" STATUS_OK_TEXT "\">");

              buffer = g_string_new ("");

              init_note_iterator (&notes,
                                  note,
                                  nvt,
                                  0,
                                  task,
                                  get_notes_data->sort_order,
                                  get_notes_data->sort_field);
              buffer_notes_xml (buffer, &notes, get_notes_data->details,
                                get_notes_data->result);
              cleanup_iterator (&notes);

              SEND_TO_CLIENT_OR_FAIL (buffer->str);
              g_string_free (buffer, TRUE);

              SEND_TO_CLIENT_OR_FAIL ("</get_notes_response>");
            }

          get_notes_data_reset (get_notes_data);
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }
      case CLIENT_GET_NOTES_NVT:
        assert (strcasecmp ("NVT", element_name) == 0);
        set_client_state (CLIENT_GET_NOTES);
        break;
      case CLIENT_GET_NOTES_TASK:
        assert (strcasecmp ("TASK", element_name) == 0);
        set_client_state (CLIENT_GET_NOTES);
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
              config_t config = (config_t) 0;

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
                  else if (current_name /* Attribute config. */
                           && find_config (current_name, &config))
                    SEND_TO_CLIENT_OR_FAIL
                     (XML_INTERNAL_ERROR ("get_nvt_details"));
                  else if (current_name && (config == 0))
                    {
                      if (send_find_error_to_client ("get_nvt_details",
                                                     "config",
                                                     current_name))
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

                      init_nvt_iterator (&nvts, nvt, (config_t) 0, NULL, 1,
                                         NULL);
                      while (next (&nvts))
                        {
                          char *timeout = NULL;

                          if (config)
                            timeout = config_nvt_timeout (config,
                                                          nvt_iterator_oid
                                                           (&nvts));

                          if (send_nvt (&nvts, 1, -1, timeout))
                            {
                              error_send_to_client (error);
                              return;
                            }
                          if (config)
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
                                  GString *buffer = g_string_new ("");
                                  buffer_config_preference_xml (buffer, &prefs, config);
                                  SEND_TO_CLIENT_OR_FAIL (buffer->str);
                                  g_string_free (buffer, TRUE);
                                }
                              cleanup_iterator (&prefs);

                              SEND_TO_CLIENT_OR_FAIL ("</preferences>");

                            }
                        }
                      cleanup_iterator (&nvts);

                      SEND_TO_CLIENT_OR_FAIL ("</get_nvt_details_response>");
                    }
                }
              else if (current_name && find_config (current_name, &config))
                SEND_TO_CLIENT_OR_FAIL
                 (XML_INTERNAL_ERROR ("get_nvt_details"));
              else if (current_name && (config == 0))
                {
                  if (send_find_error_to_client ("get_nvt_details",
                                                 "config",
                                                 current_name))
                    {
                      error_send_to_client (error);
                      return;
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
                                     config,
                                     current_format,  /* Attribute family. */
                                     /* Attribute sort_order. */
                                     current_int_2,
                                     /* Attribute sort_field. */
                                     modify_task_value);
                  while (next (&nvts))
                    {
                      int pref_count = -1;
                      char *timeout = NULL;

                      if (config)
                        timeout = config_nvt_timeout (config,
                                                      nvt_iterator_oid (&nvts));

                      if (config || current_format) /* Attribute family. */
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

      case CLIENT_DELETE_NOTE:
        assert (strcasecmp ("DELETE_NOTE", element_name) == 0);
        if (delete_note_data->note_id)
          {
            note_t note;

            if (find_note (delete_note_data->note_id, &note))
              SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("delete_note"));
            else if (note == 0)
              {
                if (send_find_error_to_client ("delete_note",
                                               "note",
                                               delete_note_data->note_id))
                  {
                    error_send_to_client (error);
                    return;
                  }
              }
            else switch (delete_note (note))
              {
                case 0:
                  SEND_TO_CLIENT_OR_FAIL (XML_OK ("delete_note"));
                  break;
                default:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_INTERNAL_ERROR ("delete_note"));
                  break;
              }
          }
        else
          SEND_TO_CLIENT_OR_FAIL
           (XML_ERROR_SYNTAX ("delete_note",
                              "DELETE_NOTE requires a note_id attribute"));
        delete_note_data_reset (delete_note_data);
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_DELETE_REPORT:
        assert (strcasecmp ("DELETE_REPORT", element_name) == 0);
        if (delete_report_data->report_id)
          {
            report_t report;

            // FIX check syntax of delete_report_data->report_id  STATUS_ERROR_SYNTAX
            if (find_report (delete_report_data->report_id, &report))
              SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("delete_report"));
            else if (report == 0)
              {
                if (send_find_error_to_client ("delete_report",
                                               "report",
                                               delete_report_data->report_id))
                  {
                    error_send_to_client (error);
                    return;
                  }
              }
            else switch (delete_report (report))
              {
                case 0:
                  SEND_TO_CLIENT_OR_FAIL (XML_OK ("delete_report"));
                  break;
                case 1:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("delete_report",
                                      "Attempt to delete a hidden report"));
                  break;
                case 2:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("delete_report",
                                      "Report is in use"));
                  break;
                default:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_INTERNAL_ERROR ("delete_report"));
                  break;
              }
          }
        else
          SEND_TO_CLIENT_OR_FAIL
           (XML_ERROR_SYNTAX ("delete_report",
                              "DELETE_REPORT requires a report_id attribute"));
        delete_report_data_reset (delete_report_data);
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_DELETE_SCHEDULE:
        assert (strcasecmp ("DELETE_SCHEDULE", element_name) == 0);
        if (delete_schedule_data->schedule_id)
          {
            schedule_t schedule;

            if (find_schedule (delete_schedule_data->schedule_id, &schedule))
              SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("delete_schedule"));
            else if (schedule == 0)
              {
                if (send_find_error_to_client
                     ("delete_schedule",
                      "schedule",
                      delete_schedule_data->schedule_id))
                  {
                    error_send_to_client (error);
                    return;
                  }
              }
            else switch (delete_schedule (schedule))
              {
                case 0:
                  SEND_TO_CLIENT_OR_FAIL (XML_OK ("delete_schedule"));
                  break;
                case 1:
                  openvas_free_string_var (&modify_task_name);
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("delete_schedule",
                                      "Schedule is in use"));
                  break;
                default:
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_INTERNAL_ERROR ("delete_schedule"));
                  break;
              }
          }
        else
          SEND_TO_CLIENT_OR_FAIL
           (XML_ERROR_SYNTAX ("delete_schedule",
                              "DELETE_SCHEDULE requires a schedule_id"
                              " attribute"));
        delete_schedule_data_reset (delete_schedule_data);
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_GET_REPORT:
        assert (strcasecmp ("GET_REPORT", element_name) == 0);
        if (current_credentials.username == NULL)
          {
            get_report_data_reset (get_report_data);
            SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_report"));
            set_client_state (CLIENT_AUTHENTIC);
            break;
          }

        if (get_report_data->report_id == NULL)
          {
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("get_report",
                                "GET_REPORT must have a report_id attribute"));
            get_report_data_reset (get_report_data);
            set_client_state (CLIENT_AUTHENTIC);
            break;
          }

        report_t report;
        iterator_t results, hosts;
        GString *nbe;
        gchar *content;
        float min_cvss_base;

        if (find_report (get_report_data->report_id, &report))
          SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_report"));
        else if (report == 0)
          {
            if (send_find_error_to_client ("get_report",
                                           "report",
                                           get_report_data->report_id))
              {
                error_send_to_client (error);
                return;
              }
          }
        else if (get_report_data->min_cvss_base
                 && strlen (get_report_data->min_cvss_base)
                 && (sscanf (get_report_data->min_cvss_base,
                             "%f",
                             &min_cvss_base)
                     != 1))
          SEND_TO_CLIENT_OR_FAIL
           (XML_ERROR_SYNTAX ("get_report",
                              "GET_REPORT min_cvss_base must be a float"
                              " or the empty string"));
        else if (get_report_data->format == NULL
                  || strcasecmp (get_report_data->format, "xml") == 0)
          {
            task_t task;
            char *tsk_uuid = NULL, *start_time, *end_time;
            int result_count, filtered_result_count, run_status;
            const char *levels;
            array_t *result_hosts;

            levels = get_report_data->levels
                      ? get_report_data->levels : "hmlgd";

            if (report_task (report, &task))
              {
                SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_report"));
                get_report_data_reset (get_report_data);
                set_client_state (CLIENT_AUTHENTIC);
                break;
              }
            else if (task && task_uuid (task, &tsk_uuid))
              {
                SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_report"));
                get_report_data_reset (get_report_data);
                set_client_state (CLIENT_AUTHENTIC);
                break;
              }

            report_scan_result_count (report, NULL, NULL, NULL, &result_count);
            report_scan_result_count (report,
                                      levels,
                                      get_report_data->search_phrase,
                                      get_report_data->min_cvss_base,
                                      &filtered_result_count);
            report_scan_run_status (report, &run_status);
            SENDF_TO_CLIENT_OR_FAIL
             ("<get_report_response"
              " status=\"" STATUS_OK "\""
              " status_text=\"" STATUS_OK_TEXT "\">"
              "<report id=\"%s\">"
              "<sort><field>%s<order>%s</order></field></sort>"
              "<filters>"
              "%s"
              "<phrase>%s</phrase>"
              "<notes>%i</notes>"
              "<result_hosts_only>%i</result_hosts_only>"
              "<min_cvss_base>%s</min_cvss_base>",
              get_report_data->report_id,
              get_report_data->sort_field ? get_report_data->sort_field
                                          : "type",
              get_report_data->sort_order ? "ascending" : "descending",
              levels,
              get_report_data->search_phrase
                ? get_report_data->search_phrase
                : "",
              get_report_data->notes ? 1 : 0,
              get_report_data->result_hosts_only ? 1 : 0,
              get_report_data->min_cvss_base
                ? get_report_data->min_cvss_base
                : "");

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

            /* Port summary. */

            {
              gchar *last_port;
              GArray *ports = g_array_new (TRUE, FALSE, sizeof (gchar*));

              init_result_iterator
               (&results, report, 0, NULL,
                get_report_data->first_result,
                get_report_data->max_results,
                /* Sort by port in order requested. */
                ((get_report_data->sort_field
                  && (strcmp (get_report_data->sort_field, "port")
                              == 0))
                  ? get_report_data->sort_order
                  : 1),
                "port",
                levels,
                get_report_data->search_phrase,
                get_report_data->min_cvss_base);

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

              if (get_report_data->sort_field
                  && strcmp (get_report_data->sort_field, "port"))
                {
                  /* Sort by threat. */
                  if (get_report_data->sort_order)
                    g_array_sort (ports, compare_ports_asc);
                  else
                    g_array_sort (ports, compare_ports_desc);
                }

              /* Send from the buffer. */

              SENDF_TO_CLIENT_OR_FAIL ("<ports"
                                       " start=\"%i\""
                                       " max=\"%i\">",
                                       /* Add 1 for 1 indexing. */
                                       get_report_data->first_result + 1,
                                       get_report_data->max_results);
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

            init_result_iterator (&results, report, 0, NULL,
                                  get_report_data->first_result,
                                  get_report_data->max_results,
                                  get_report_data->sort_order,
                                  get_report_data->sort_field,
                                  levels,
                                  get_report_data->search_phrase,
                                  get_report_data->min_cvss_base);

            SENDF_TO_CLIENT_OR_FAIL ("<results"
                                     " start=\"%i\""
                                     " max=\"%i\">",
                                     /* Add 1 for 1 indexing. */
                                     get_report_data->first_result + 1,
                                     get_report_data->max_results);
            if (get_report_data->result_hosts_only)
              result_hosts = make_array ();
            else
              /* Quiet erroneous compiler warning. */
              result_hosts = NULL;
            while (next (&results))
              {
                GString *buffer = g_string_new ("");
                buffer_results_xml (buffer,
                                    &results,
                                    task,
                                    get_report_data->notes,
                                    get_report_data->notes_details);
                SEND_TO_CLIENT_OR_FAIL (buffer->str);
                g_string_free (buffer, TRUE);
                if (get_report_data->result_hosts_only)
                  array_add_new_string (result_hosts,
                                        result_iterator_host (&results));
              }
            SEND_TO_CLIENT_OR_FAIL ("</results>");
            cleanup_iterator (&results);

            if (get_report_data->result_hosts_only)
              {
                gchar *host;
                int index = 0;
                array_terminate (result_hosts);
                while ((host = g_ptr_array_index (result_hosts, index++)))
                  {
                    init_host_iterator (&hosts, report, host);
                    if (next (&hosts))
                      {
                        SENDF_TO_CLIENT_OR_FAIL ("<host_start>"
                                                 "<host>%s</host>%s"
                                                 "</host_start>",
                                                 host,
                                                 host_iterator_start_time (&hosts));
                        SENDF_TO_CLIENT_OR_FAIL ("<host_end>"
                                                 "<host>%s</host>%s"
                                                 "</host_end>",
                                                 host,
                                                 host_iterator_end_time (&hosts));
                      }
                    cleanup_iterator (&hosts);
                  }
                array_free (result_hosts);
              }
            else
              {
                init_host_iterator (&hosts, report, NULL);
                while (next (&hosts))
                  SENDF_TO_CLIENT_OR_FAIL ("<host_start><host>%s</host>%s</host_start>",
                                           host_iterator_host (&hosts),
                                           host_iterator_start_time (&hosts));
                cleanup_iterator (&hosts);

                init_host_iterator (&hosts, report, NULL);
                while (next (&hosts))
                  SENDF_TO_CLIENT_OR_FAIL ("<host_end><host>%s</host>%s</host_end>",
                                           host_iterator_host (&hosts),
                                           host_iterator_end_time (&hosts));
                cleanup_iterator (&hosts);
              }
            end_time = scan_end_time (report);
            SENDF_TO_CLIENT_OR_FAIL ("<scan_end>%s</scan_end>",
                                     end_time);
            free (end_time);

            SEND_TO_CLIENT_OR_FAIL ("</report>"
                                    "</get_report_response>");
          }
        else if (strcasecmp (get_report_data->format, "nbe") == 0)
          {
            char *start_time, *end_time;
            array_t *result_hosts;

            /* TODO: Encode and send in chunks, after each printf. */

            /* Build the NBE in memory. */

            nbe = g_string_new ("");
            start_time = scan_start_time (report);
            g_string_append_printf (nbe,
                                    "timestamps|||scan_start|%s|\n",
                                    start_time);
            free (start_time);

            init_result_iterator (&results, report, 0, NULL,
                                  get_report_data->first_result,
                                  get_report_data->max_results,
                                  get_report_data->sort_order,
                                  get_report_data->sort_field,
                                  get_report_data->levels,
                                  get_report_data->search_phrase,
                                  get_report_data->min_cvss_base);
            if (get_report_data->result_hosts_only)
              result_hosts = make_array ();
            else
              /* Quiet erroneous compiler warning. */
              result_hosts = NULL;
            while (next (&results))
              {
                g_string_append_printf (nbe,
                                        "results|%s|%s|%s|%s|%s|%s\n",
                                        result_iterator_subnet (&results),
                                        result_iterator_host (&results),
                                        result_iterator_port (&results),
                                        result_iterator_nvt_oid (&results),
                                        result_iterator_type (&results),
                                        result_iterator_descr (&results));
                if (get_report_data->result_hosts_only)
                  array_add_new_string (result_hosts,
                                        result_iterator_host (&results));
              }
            cleanup_iterator (&results);

            if (get_report_data->result_hosts_only)
              {
                gchar *host;
                int index = 0;
                array_terminate (result_hosts);
                while ((host = g_ptr_array_index (result_hosts, index++)))
                  {
                    init_host_iterator (&hosts, report, host);
                    if (next (&hosts))
                      {
                        g_string_append_printf (nbe,
                                                "timestamps||%s|host_start|%s|\n",
                                                host,
                                                host_iterator_start_time (&hosts));
                        g_string_append_printf (nbe,
                                                "timestamps||%s|host_end|%s|\n",
                                                host,
                                                host_iterator_end_time (&hosts));
                      }
                    cleanup_iterator (&hosts);
                  }
                array_free (result_hosts);
              }
            else
              {
                init_host_iterator (&hosts, report, NULL);
                while (next (&hosts))
                  g_string_append_printf (nbe,
                                          "timestamps||%s|host_start|%s|\n",
                                          host_iterator_host (&hosts),
                                          host_iterator_start_time (&hosts));
                cleanup_iterator (&hosts);

                init_host_iterator (&hosts, report, NULL);
                while (next (&hosts))
                  g_string_append_printf (nbe,
                                          "timestamps||%s|host_end|%s|\n",
                                          host_iterator_host (&hosts),
                                          host_iterator_end_time (&hosts));
                cleanup_iterator (&hosts);
              }

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
        else if (strcasecmp (get_report_data->format, "html") == 0)
          {
            task_t task;
            gchar *xml_file;
            char xml_dir[] = "/tmp/openvasmd_XXXXXX";

            if (report_task (report, &task))
              {
                SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_report"));
                get_report_data_reset (get_report_data);
                set_client_state (CLIENT_AUTHENTIC);
                break;
              }

            if (mkdtemp (xml_dir) == NULL)
              {
                g_warning ("%s: g_mkdtemp failed\n", __FUNCTION__);
                SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_report"));
              }
            else if (xml_file = g_strdup_printf ("%s/report.xml", xml_dir),
                     print_report_xml (report,
                                       task,
                                       xml_file,
                                       get_report_data->sort_order,
                                       get_report_data->sort_field,
                                       get_report_data->result_hosts_only,
                                       get_report_data->min_cvss_base))
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

                    command = g_strdup_printf ("xsltproc -v %s %s > %s"
                                               " 2> /tmp/openvasmd_html",
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
        else if (strcasecmp (get_report_data->format, "html-pdf") == 0)
          {
            task_t task;
            gchar *xml_file;
            char xml_dir[] = "/tmp/openvasmd_XXXXXX";

            if (report_task (report, &task))
              {
                SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_report"));
                get_report_data_reset (get_report_data);
                set_client_state (CLIENT_AUTHENTIC);
                break;
              }

            // TODO: This block is very similar to the HTML block above.

            if (mkdtemp (xml_dir) == NULL)
              {
                g_warning ("%s: g_mkdtemp failed\n", __FUNCTION__);
                SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_report"));
              }
            else if (xml_file = g_strdup_printf ("%s/report.xml", xml_dir),
                     print_report_xml (report,
                                       task,
                                       xml_file,
                                       get_report_data->sort_order,
                                       get_report_data->sort_field,
                                       get_report_data->result_hosts_only,
                                       get_report_data->min_cvss_base))
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
                                               " | tee /tmp/openvasmd_html-pdf"
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
        else if ((strcasecmp (get_report_data->format, "pdf") == 0)
                 || (strcasecmp (get_report_data->format, "dvi") == 0))
          {
            task_t task;
            gchar *latex_file;
            char latex_dir[] = "/tmp/openvasmd_XXXXXX";
            int dvi;

            dvi = (strcasecmp (get_report_data->format, "dvi") == 0);

            if (report_task (report, &task))
              {
                SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_report"));
                get_report_data_reset (get_report_data);
                set_client_state (CLIENT_AUTHENTIC);
                break;
              }

            if (mkdtemp (latex_dir) == NULL)
              {
                g_warning ("%s: g_mkdtemp failed\n", __FUNCTION__);
                SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_report"));
              }
            else if (latex_file = g_strdup_printf ("%s/report.tex",
                                                   latex_dir),
                     print_report_latex (report,
                                         task,
                                         latex_file,
                                         get_report_data->sort_order,
                                         get_report_data->sort_field,
                                         get_report_data->result_hosts_only,
                                         get_report_data->min_cvss_base))
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
                pdf_file[strlen (pdf_file) - 1] = dvi ? 'i' : 'f';
                pdf_file[strlen (pdf_file) - 2] = dvi ? 'v' : 'd';
                pdf_file[strlen (pdf_file) - 3] = dvi ? 'd' : 'p';

                pdf_fd = open (pdf_file,
                               O_RDWR | O_CREAT,
                               S_IRUSR | S_IWUSR);

                if (dvi)
                  command = g_strdup_printf
                             ("latex -output-directory %s %s"
                              " > /tmp/openvasmd_latex_out 2>&1"
                              " && latex -output-directory %s %s"
                              " > /tmp/openvasmd_latex_out 2>&1",
                              latex_dir,
                              latex_file,
                              latex_dir,
                              latex_file);
                else
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
          {
            task_t task;
            gchar *xml_file;
            char xml_dir[] = "/tmp/openvasmd_XXXXXX";

            /* Try apply a stylesheet from the SYSCONF/manager/ dir. */

            if (report_task (report, &task))
              {
                SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_report"));
                get_report_data_reset (get_report_data);
                set_client_state (CLIENT_AUTHENTIC);
                break;
              }

            if (mkdtemp (xml_dir) == NULL)
              {
                g_warning ("%s: g_mkdtemp failed\n", __FUNCTION__);
                SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_report"));
              }
            else if (xml_file = g_strdup_printf ("%s/report.xml", xml_dir),
                     print_report_xml (report,
                                       task,
                                       xml_file,
                                       get_report_data->sort_order,
                                       get_report_data->sort_field,
                                       get_report_data->result_hosts_only,
                                       get_report_data->min_cvss_base))
              {
                g_free (xml_file);
                SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_report"));
              }
            else
              {
                gchar *xsl_name, *xsl_file;

                xsl_name = g_strdup_printf ("%s.xsl", get_report_data->format);

                xsl_file = g_build_filename (OPENVAS_SYSCONF_DIR,
                                             "openvasmd",
                                             "xsl",
                                             xsl_name,
                                             NULL);

                g_free (xsl_name);

                if (!g_file_test (xsl_file, G_FILE_TEST_EXISTS))
                  {
                    g_free (xsl_file);
                    g_free (xml_file);
                    SEND_TO_CLIENT_OR_FAIL
                     (XML_ERROR_SYNTAX ("get_report",
                                        "Bogus report format in format"
                                        " attribute"));
                  }
                else
                  {
                    gchar *output_file, *command;
                    int ret;

                    output_file = g_strdup_printf ("%s/report.out", xml_dir);

                    command = g_strdup_printf ("xsltproc -v %s %s > %s"
                                               " 2> /tmp/openvasmd_generic",
                                               xsl_file,
                                               xml_file,
                                               output_file);
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
                        g_free (output_file);
                        SEND_TO_CLIENT_OR_FAIL
                         (XML_INTERNAL_ERROR ("get_report"));
                      }
                    else
                      {
                        GError *get_error;
                        gchar *output;
                        gsize output_len;

                        g_free (command);

                        /* Send the output to the client. */

                        get_error = NULL;
                        g_file_get_contents (output_file,
                                             &output,
                                             &output_len,
                                             &get_error);
                        g_free (output_file);
                        if (get_error)
                          {
                            g_warning ("%s: Failed to get output: %s\n",
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

                            /* Encode and send the output. */

                            SENDF_TO_CLIENT_OR_FAIL
                             ("<get_report_response"
                              " status=\"" STATUS_OK "\""
                              " status_text=\"" STATUS_OK_TEXT "\">"
                              "<report format=\"%s\">",
                              get_report_data->format);
                            if (output && strlen (output))
                              {
                                gchar *base64;
                                base64 = g_base64_encode ((guchar*) output,
                                                          output_len);
                                if (send_to_client (base64))
                                  {
                                    g_free (output);
                                    g_free (base64);
                                    error_send_to_client (error);
                                    return;
                                  }
                                g_free (base64);
                              }
                            g_free (output);
                            SEND_TO_CLIENT_OR_FAIL
                             ("</report>"
                              "</get_report_response>");
                          }
                      }
                  }
              }
          }

        get_report_data_reset (get_report_data);
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_GET_RESULTS:
        {
          result_t result;
          task_t task = 0;

          assert (strcasecmp ("GET_RESULTS", element_name) == 0);

          if (current_credentials.username == NULL)
            {
              get_results_data_reset (get_results_data);
              SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_results"));
              set_client_state (CLIENT_AUTHENTIC);
              break;
            }

          if (get_results_data->result_id == NULL)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("get_results",
                                "GET_RESULTS must have a result_id attribute"));
          else if (get_results_data->notes
                   && (get_results_data->task_id == NULL))
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("get_results",
                                "GET_RESULTS must have a task_id attribute"
                                " if the notes attribute is true"));
          else if (find_result (get_results_data->result_id, &result))
            SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_results"));
          else if (result == 0)
            {
              if (send_find_error_to_client ("get_results",
                                             "result",
                                             get_results_data->result_id))
                {
                  error_send_to_client (error);
                  return;
                }
            }
          else if (get_results_data->task_id
                   && find_task (get_results_data->task_id, &task))
            SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_results"));
          else if (get_results_data->task_id && task == 0)
            {
              if (send_find_error_to_client ("get_results",
                                             "task",
                                             get_results_data->task_id))
                {
                  error_send_to_client (error);
                  return;
                }
            }
          else
            {
              SEND_TO_CLIENT_OR_FAIL ("<get_results_response"
                                      " status=\"" STATUS_OK "\""
                                      " status_text=\"" STATUS_OK_TEXT "\">"
                                      "<results>");
              init_result_iterator (&results, 0, result, NULL, 0, 1, 1, NULL,
                                    NULL, NULL, NULL);
              while (next (&results))
                {
                  GString *buffer = g_string_new ("");
                  buffer_results_xml (buffer,
                                      &results,
                                      task,
                                      get_results_data->notes,
                                      get_results_data->notes_details);
                  SEND_TO_CLIENT_OR_FAIL (buffer->str);
                  g_string_free (buffer, TRUE);
                }
              cleanup_iterator (&results);
              SEND_TO_CLIENT_OR_FAIL ("</results>"
                                      "</get_results_response>");
            }

          get_results_data_reset (get_results_data);
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }

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

      case CLIENT_GET_SCHEDULES:
        {
          schedule_t schedule = 0;

          assert (strcasecmp ("GET_SCHEDULES", element_name) == 0);

          if (get_schedules_data->schedule_id
              && find_schedule (get_schedules_data->schedule_id, &schedule))
            SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_schedules"));
          else if (get_schedules_data->schedule_id && schedule == 0)
            {
              if (send_find_error_to_client ("get_schedules",
                                             "schedule",
                                             get_schedules_data->schedule_id))
                {
                  error_send_to_client (error);
                  return;
                }
            }
          else
            {
              iterator_t schedules;
              GString *buffer;

              SENDF_TO_CLIENT_OR_FAIL ("<get_schedules_response"
                                       " status=\"" STATUS_OK "\""
                                       " status_text=\"" STATUS_OK_TEXT "\">");

              buffer = g_string_new ("");

              init_schedule_iterator (&schedules,
                                      schedule,
                                      get_schedules_data->sort_order,
                                      get_schedules_data->sort_field);
              buffer_schedules_xml (buffer, &schedules, get_schedules_data->details
                                    /* get_schedules_data->tasks */);
              cleanup_iterator (&schedules);

              SEND_TO_CLIENT_OR_FAIL (buffer->str);
              g_string_free (buffer, TRUE);

              SEND_TO_CLIENT_OR_FAIL ("</get_schedules_response>");
            }

          get_schedules_data_reset (get_schedules_data);
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }

      case CLIENT_DELETE_AGENT:
        {
          agent_t agent;

          assert (strcasecmp ("DELETE_AGENT", element_name) == 0);
          assert (delete_agent_data->name != NULL);

          if (strlen (delete_agent_data->name) == 0)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("delete_agent",
                                "DELETE_AGENT name must be at least"
                                " one character long"));
          else if (find_agent (delete_agent_data->name, &agent))
            SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("delete_agent"));
          else if (agent == 0)
            {
              if (send_find_error_to_client ("delete_agent",
                                             "agent",
                                             delete_agent_data->name))
                {
                  error_send_to_client (error);
                  return;
                }
            }
          else switch (delete_agent (agent))
            {
              case 0:
                SEND_TO_CLIENT_OR_FAIL (XML_OK ("delete_agent"));
                break;
              case 1:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("delete_agent",
                                    "Agent is in use"));
                break;
              default:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_INTERNAL_ERROR ("delete_agent"));
            }
          delete_agent_data_reset (delete_agent_data);
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }
      case CLIENT_DELETE_AGENT_NAME:
        assert (strcasecmp ("NAME", element_name) == 0);
        set_client_state (CLIENT_DELETE_AGENT);
        break;

      case CLIENT_DELETE_CONFIG:
        {
          config_t config = 0;

          assert (strcasecmp ("DELETE_CONFIG", element_name) == 0);
          assert (delete_config_data->name != NULL);

          if (strlen (delete_config_data->name) == 0)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("delete_config",
                                "DELETE_CONFIG name must be at least one"
                                " character long"));
          else if (find_config (delete_config_data->name, &config))
            SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("delete_config"));
          else if (config == 0)
            {
              if (send_find_error_to_client ("delete_config",
                                             "config",
                                             delete_config_data->name))
                {
                  error_send_to_client (error);
                  return;
                }
            }
          else switch (delete_config (config))
            {
              case 0:
                SEND_TO_CLIENT_OR_FAIL (XML_OK ("delete_config"));
                break;
              case 1:
                SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX ("delete_config",
                                                          "Config is in use"));
                break;
              default:
                SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("delete_config"));
            }
          delete_config_data_reset (delete_config_data);
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }
      case CLIENT_DELETE_CONFIG_NAME:
        assert (strcasecmp ("NAME", element_name) == 0);
        set_client_state (CLIENT_DELETE_CONFIG);
        break;

      case CLIENT_DELETE_ESCALATOR:
        {
          escalator_t escalator;

          assert (strcasecmp ("DELETE_ESCALATOR", element_name) == 0);
          assert (delete_escalator_data->name != NULL);

          if (strlen (delete_escalator_data->name) == 0)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("delete_escalator",
                                "DELETE_ESCALATOR name must be at least one"
                                " character long"));
          else if (find_escalator (delete_escalator_data->name, &escalator))
            SEND_TO_CLIENT_OR_FAIL
             (XML_INTERNAL_ERROR ("delete_escalator"));
          else if (escalator == 0)
            {
              if (send_find_error_to_client ("delete_escalator",
                                             "escalator",
                                             delete_escalator_data->name))
                {
                  error_send_to_client (error);
                  return;
                }
            }
          else switch (delete_escalator (escalator))
            {
              case 0:
                SEND_TO_CLIENT_OR_FAIL (XML_OK ("delete_escalator"));
                break;
              case 1:
                SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX ("delete_escalator",
                                                          "Escalator is in use"));
                break;
              default:
                SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("delete_escalator"));
            }
          delete_escalator_data_reset (delete_escalator_data);
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }
      case CLIENT_DELETE_ESCALATOR_NAME:
        assert (strcasecmp ("NAME", element_name) == 0);
        set_client_state (CLIENT_DELETE_ESCALATOR);
        break;

      case CLIENT_DELETE_LSC_CREDENTIAL:
        {
          lsc_credential_t lsc_credential = 0;

          assert (strcasecmp ("DELETE_LSC_CREDENTIAL", element_name) == 0);
          assert (delete_lsc_credential_data->name != NULL);

          if (strlen (delete_lsc_credential_data->name) == 0)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("delete_lsc_credential",
                                "DELETE_LSC_CREDENTIAL name must be at least"
                                " one character long"));
          else if (find_lsc_credential (delete_lsc_credential_data->name,
                                        &lsc_credential))
            SEND_TO_CLIENT_OR_FAIL
             (XML_INTERNAL_ERROR ("delete_lsc_credential"));
          else if (lsc_credential == 0)
            {
              if (send_find_error_to_client ("delete_lsc_credential",
                                             "lsc_credential",
                                             delete_lsc_credential_data->name))
                {
                  error_send_to_client (error);
                  return;
                }
            }
          else switch (delete_lsc_credential (lsc_credential))
            {
              case 0:
                SEND_TO_CLIENT_OR_FAIL (XML_OK ("delete_lsc_credential"));
                break;
              case 1:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("delete_lsc_credential",
                                    "LSC credential is in use"));
                break;
              default:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_INTERNAL_ERROR ("delete_lsc_credential"));
            }
          delete_lsc_credential_data_reset (delete_lsc_credential_data);
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }
      case CLIENT_DELETE_LSC_CREDENTIAL_NAME:
        assert (strcasecmp ("NAME", element_name) == 0);
        set_client_state (CLIENT_DELETE_LSC_CREDENTIAL);
        break;

      case CLIENT_DELETE_TARGET:
        {
          target_t target = 0;

          assert (strcasecmp ("DELETE_TARGET", element_name) == 0);
          assert (delete_target_data->name != NULL);

          if (strlen (delete_target_data->name) == 0)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("delete_target",
                                "DELETE_TARGET name must be at least one"
                                " character long"));
          else if (find_target (delete_target_data->name, &target))
            SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("delete_target"));
          else if (target == 0)
            {
              if (send_find_error_to_client ("delete_target",
                                             "target",
                                             delete_target_data->name))
                {
                  error_send_to_client (error);
                  return;
                }
            }
          else switch (delete_target (target))
            {
              case 0:
                SEND_TO_CLIENT_OR_FAIL (XML_OK ("delete_target"));
                break;
              case 1:
                SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX ("delete_target",
                                                          "Target is in use"));
                break;
              default:
                SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("delete_target"));
            }
          delete_target_data_reset (delete_target_data);
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }
      case CLIENT_DELETE_TARGET_NAME:
        assert (strcasecmp ("NAME", element_name) == 0);
        set_client_state (CLIENT_DELETE_TARGET);
        break;

      case CLIENT_DELETE_TASK:
        if (delete_task_data->task_id)
          {
            task_t task;
            assert (current_client_task == (task_t) 0);
            if (find_task (delete_task_data->task_id, &task))
              SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("delete_task"));
            else if (task == 0)
              {
                if (send_find_error_to_client ("delete_task",
                                               "task",
                                               delete_task_data->task_id))
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
          }
        else
          SEND_TO_CLIENT_OR_FAIL
           (XML_ERROR_SYNTAX ("delete_task",
                              "DELETE_TASK requires a task_id attribute"));
        delete_task_data_reset (delete_task_data);
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
        {
          config_t config;
          if (modify_config_data->name == NULL
              || strlen (modify_config_data->name) == 0)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("modify_config",
                                "MODIFY_CONFIG requires a NAME element"));
          else if ((modify_config_data->nvt_selection_family
                    /* This array implies FAMILY_SELECTION. */
                    && modify_config_data->families_static_all)
                   || ((modify_config_data->nvt_selection_family
                        || modify_config_data->families_static_all)
                       && (modify_config_data->preference_name
                           || modify_config_data->preference_value
                           || modify_config_data->preference_nvt_oid)))
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("modify_config",
                                "MODIFY_CONFIG requires either a PREFERENCE or"
                                " an NVT_SELECTION or a FAMILY_SELECTION"));
          else if (find_config (modify_config_data->name, &config))
            SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("modify_config"));
          else if (config == 0)
            {
              if (send_find_error_to_client ("modify_config",
                                             "config",
                                             modify_config_data->name))
                {
                  error_send_to_client (error);
                  return;
                }
            }
          else if (modify_config_data->nvt_selection_family)
            {
              assert (modify_config_data->nvt_selection);

              array_terminate (modify_config_data->nvt_selection);
              switch (manage_set_config_nvts
                       (config,
                        modify_config_data->nvt_selection_family,
                        modify_config_data->nvt_selection))
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
                                        "MODIFY_CONFIG PREFERENCE requires at"
                                        " least one of the VALUE and NVT"
                                        " elements"));
                    break;
#endif
                  default:
                    SEND_TO_CLIENT_OR_FAIL
                     (XML_INTERNAL_ERROR ("modify_config"));
                    break;
                }
            }
          else if (modify_config_data->families_static_all)
            {
              /* There was a FAMILY_SELECTION. */

              assert (modify_config_data->families_growing_all);
              assert (modify_config_data->families_static_all);

              array_terminate (modify_config_data->families_growing_all);
              array_terminate (modify_config_data->families_static_all);
              array_terminate (modify_config_data->families_growing_empty);
              switch (manage_set_config_families
                       (config,
                        modify_config_data->families_growing_all,
                        modify_config_data->families_static_all,
                        modify_config_data->families_growing_empty,
                        modify_config_data->family_selection_growing))
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
                                        "MODIFY_CONFIG PREFERENCE requires at"
                                        " least one of the VALUE and NVT"
                                        " elements"));
                    break;
#endif
                  default:
                    SEND_TO_CLIENT_OR_FAIL
                     (XML_INTERNAL_ERROR ("modify_report"));
                    break;
                }
            }
          else if (modify_config_data->preference_name == NULL
                   || strlen (modify_config_data->preference_name) == 0)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("modify_config",
                                "MODIFY_CONFIG PREFERENCE requires a NAME"
                                " element"));
          else switch (manage_set_config_preference
                        (config,
                         modify_config_data->preference_nvt_oid,
                         modify_config_data->preference_name,
                         modify_config_data->preference_value))
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
        }
        modify_config_data_reset (modify_config_data);
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
        if (modify_config_data->family_selection_family_name)
          {
            if (modify_config_data->family_selection_family_growing)
              {
                if (modify_config_data->family_selection_family_all)
                  /* Growing 1 and select all 1. */
                  array_add (modify_config_data->families_growing_all,
                             modify_config_data->family_selection_family_name);
                else
                  /* Growing 1 and select all 0. */
                  array_add (modify_config_data->families_growing_empty,
                             modify_config_data->family_selection_family_name);
              }
            else
              {
                if (modify_config_data->family_selection_family_all)
                  /* Growing 0 and select all 1. */
                  array_add (modify_config_data->families_static_all,
                             modify_config_data->family_selection_family_name);
                /* Else growing 0 and select all 0. */
              }
          }
        modify_config_data->family_selection_family_name = NULL;
        set_client_state (CLIENT_MODIFY_CONFIG_FAMILY_SELECTION);
        break;
      case CLIENT_MODIFY_CONFIG_FAMILY_SELECTION_GROWING:
        assert (strcasecmp ("GROWING", element_name) == 0);
        if (modify_config_data->family_selection_growing_text)
          {
            modify_config_data->family_selection_growing
             = atoi (modify_config_data->family_selection_growing_text);
            openvas_free_string_var
             (&modify_config_data->family_selection_growing_text);
          }
        else
          modify_config_data->family_selection_growing = 0;
        set_client_state (CLIENT_MODIFY_CONFIG_FAMILY_SELECTION);
        break;

      case CLIENT_MODIFY_CONFIG_FAMILY_SELECTION_FAMILY_ALL:
        assert (strcasecmp ("ALL", element_name) == 0);
        if (modify_config_data->family_selection_family_all_text)
          {
            modify_config_data->family_selection_family_all
             = atoi (modify_config_data->family_selection_family_all_text);
            openvas_free_string_var
             (&modify_config_data->family_selection_family_all_text);
          }
        else
          modify_config_data->family_selection_family_all = 0;
        set_client_state (CLIENT_MODIFY_CONFIG_FAMILY_SELECTION_FAMILY);
        break;
      case CLIENT_MODIFY_CONFIG_FAMILY_SELECTION_FAMILY_NAME:
        assert (strcasecmp ("NAME", element_name) == 0);
        set_client_state (CLIENT_MODIFY_CONFIG_FAMILY_SELECTION_FAMILY);
        break;
      case CLIENT_MODIFY_CONFIG_FAMILY_SELECTION_FAMILY_GROWING:
        assert (strcasecmp ("GROWING", element_name) == 0);
        if (modify_config_data->family_selection_family_growing_text)
          {
            modify_config_data->family_selection_family_growing
             = atoi (modify_config_data->family_selection_family_growing_text);
            openvas_free_string_var
             (&modify_config_data->family_selection_family_growing_text);
          }
        else
          modify_config_data->family_selection_family_growing = 0;
        set_client_state (CLIENT_MODIFY_CONFIG_FAMILY_SELECTION_FAMILY);
        break;

      case CLIENT_MODIFY_CONFIG_NVT_SELECTION_FAMILY:
        assert (strcasecmp ("FAMILY", element_name) == 0);
        set_client_state (CLIENT_MODIFY_CONFIG_NVT_SELECTION);
        break;
      case CLIENT_MODIFY_CONFIG_NVT_SELECTION_NVT:
        assert (strcasecmp ("NVT", element_name) == 0);
        if (modify_config_data->nvt_selection_nvt_oid)
          array_add (modify_config_data->nvt_selection,
                     modify_config_data->nvt_selection_nvt_oid);
        modify_config_data->nvt_selection_nvt_oid = NULL;
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
        openvas_append_string (&modify_config_data->preference_value, "");
        set_client_state (CLIENT_MODIFY_CONFIG_PREFERENCE);
        break;

      case CLIENT_MODIFY_REPORT:
        if (modify_report_data->parameter_id != NULL
            && modify_report_data->parameter_value != NULL)
          {
            report_t report;

            if (modify_report_data->report_id == NULL)
              SEND_TO_CLIENT_OR_FAIL
               (XML_ERROR_SYNTAX ("modify_report",
                                  "MODIFY_REPORT requires a report_id attribute"));
            else if (find_report (modify_report_data->report_id, &report))
              SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("modify_report"));
            else if (report == 0)
              {
                if (send_find_error_to_client ("modify_report",
                                               "report",
                                               modify_report_data->report_id))
                  {
                    error_send_to_client (error);
                    return;
                  }
              }
            else
              {
                int ret = set_report_parameter
                           (report,
                            modify_report_data->parameter_id,
                            modify_report_data->parameter_value);
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
          SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("modify_report"));
        modify_report_data_reset (modify_report_data);
        set_client_state (CLIENT_AUTHENTIC);
        break;
      case CLIENT_MODIFY_REPORT_PARAMETER:
        assert (strcasecmp ("PARAMETER", element_name) == 0);
        set_client_state (CLIENT_MODIFY_REPORT);
        break;

      case CLIENT_MODIFY_TASK:
        // FIX update to match create_task (config, target)
        if (modify_task_data->task_id)
          {
            task_t task;
            assert (current_client_task == (task_t) 0);
            if (find_task (modify_task_data->task_id, &task))
              SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("modify_task"));
            else if (task == 0)
              {
                if (send_find_error_to_client ("modify_task",
                                               "task",
                                               modify_task_data->task_id))
                  {
                    error_send_to_client (error);
                    return;
                  }
              }
            else if (modify_task_data->action
                     && (modify_task_data->comment
                         || modify_task_data->name
                         || modify_task_data->parameter
                         || modify_task_data->rcfile))
              SEND_TO_CLIENT_OR_FAIL
               (XML_ERROR_SYNTAX ("modify_task",
                                  "Too many parameters at once"));
            else if (modify_task_data->action)
              {
                if (modify_task_data->file_name == NULL)
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("modify_task",
                                      "MODIFY_TASK requires a name attribute"));
                else if (strcmp (modify_task_data->action, "update") == 0)
                  {
                    manage_task_update_file (task,
                                             modify_task_data->file_name,
                                             modify_task_data->file
                                              ? modify_task_data->file
                                              : "");
                    SEND_TO_CLIENT_OR_FAIL (XML_OK ("modify_task"));
                  }
                else if (strcmp (modify_task_data->action, "remove") == 0)
                  {
                    manage_task_remove_file (task, modify_task_data->file_name);
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

                if (modify_task_data->rcfile)
                  {
                    fail = set_task_parameter (task,
                                               "RCFILE",
                                               modify_task_data->rcfile);
                    modify_task_data->rcfile = NULL;
                    if (fail)
                      SEND_TO_CLIENT_OR_FAIL
                       (XML_INTERNAL_ERROR ("modify_task"));
                    else
                      first = 0;
                  }

                if (fail == 0 && modify_task_data->name)
                  {
                    fail = set_task_parameter (task,
                                               "NAME",
                                               modify_task_data->name);
                    modify_task_data->name = NULL;
                    if (fail)
                      SEND_TO_CLIENT_OR_FAIL
                       (XML_INTERNAL_ERROR ("modify_task"));
                    else
                      first = 0;
                  }

                if (fail == 0 && modify_task_data->comment)
                  {
                    fail = set_task_parameter (task,
                                               "COMMENT",
                                               modify_task_data->comment);
                    modify_task_data->comment = NULL;
                    if (fail)
                      SEND_TO_CLIENT_OR_FAIL
                       (XML_INTERNAL_ERROR ("modify_task"));
                    else
                      first = 0;
                  }

                if (fail == 0 && modify_task_data->escalator_id)
                  {
                    int fail;
                    escalator_t escalator = 0;

                    if (strcmp (modify_task_data->escalator_id, "") == 0)
                      {
                        set_task_escalator (task, 0);
                        first = 0;
                      }
                    else if ((fail = find_escalator
                                      (modify_task_data->escalator_id,
                                       &escalator)))
                      SEND_TO_CLIENT_OR_FAIL
                       (XML_INTERNAL_ERROR ("modify_task"));
                    else if (escalator == 0)
                      {
                        if (send_find_error_to_client
                             ("modify_task",
                              "escalator",
                              modify_task_data->escalator_id))
                          {
                            error_send_to_client (error);
                            return;
                          }
                        fail = 1;
                      }
                    else
                      {
                        set_task_escalator (task, escalator);
                        first = 0;
                      }
                  }

                if (fail == 0 && modify_task_data->schedule_id)
                  {
                    int fail;
                    schedule_t schedule = 0;

                    if (strcmp (modify_task_data->schedule_id, "0") == 0)
                      {
                        set_task_schedule (task, 0);
                        first = 0;
                      }
                    else if ((fail = find_schedule
                                      (modify_task_data->schedule_id,
                                       &schedule)))
                      SEND_TO_CLIENT_OR_FAIL
                       (XML_INTERNAL_ERROR ("modify_task"));
                    else if (schedule == 0)
                      {
                        if (send_find_error_to_client
                             ("modify_task",
                              "schedule",
                              modify_task_data->schedule_id))
                          {
                            error_send_to_client (error);
                            return;
                          }
                        fail = 1;
                      }
                    else
                      {
                        set_task_schedule (task, schedule);
                        first = 0;
                      }
                  }

                if (fail == 0)
                  {
                    if (modify_task_data->parameter && modify_task_data->value)
                      {
                        fail = set_task_parameter (task,
                                                   modify_task_data->parameter,
                                                   modify_task_data->value);
                        modify_task_data->value = NULL;
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
                        if (modify_task_data->value)
                          SEND_TO_CLIENT_OR_FAIL
                           (XML_ERROR_SYNTAX ("modify_task",
                                              "MODIFY_TASK parameter requires"
                                              " an id attribute"));
                        else if (modify_task_data->parameter)
                          SEND_TO_CLIENT_OR_FAIL
                           (XML_INTERNAL_ERROR ("modify_task"));
                        else
                          SEND_TO_CLIENT_OR_FAIL (XML_OK ("modify_task"));
                      }
                    else
                      SEND_TO_CLIENT_OR_FAIL (XML_OK ("modify_task"));
                  }
              }
          }
        else
          SEND_TO_CLIENT_OR_FAIL
           (XML_ERROR_SYNTAX ("modify_task",
                              "MODIFY_TASK requires a task_id attribute"));
        modify_task_data_reset (modify_task_data);
        set_client_state (CLIENT_AUTHENTIC);
        break;
      case CLIENT_MODIFY_TASK_COMMENT:
        assert (strcasecmp ("COMMENT", element_name) == 0);
        set_client_state (CLIENT_MODIFY_TASK);
        break;
      case CLIENT_MODIFY_TASK_ESCALATOR:
        assert (strcasecmp ("ESCALATOR", element_name) == 0);
        set_client_state (CLIENT_MODIFY_TASK);
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
      case CLIENT_MODIFY_TASK_SCHEDULE:
        assert (strcasecmp ("SCHEDULE", element_name) == 0);
        set_client_state (CLIENT_MODIFY_TASK);
        break;
      case CLIENT_MODIFY_TASK_FILE:
        assert (strcasecmp ("FILE", element_name) == 0);
        set_client_state (CLIENT_MODIFY_TASK);
        break;

      case CLIENT_CREATE_AGENT:
        {
          assert (strcasecmp ("CREATE_AGENT", element_name) == 0);
          assert (create_agent_data->name != NULL);

          if (strlen (create_agent_data->name) == 0)
            {
              SEND_TO_CLIENT_OR_FAIL
               (XML_ERROR_SYNTAX ("create_agent",
                                  "CREATE_AGENT name must be at"
                                  " least one character long"));
            }
          else if (strlen (create_agent_data->installer) == 0)
            {
              SEND_TO_CLIENT_OR_FAIL
               (XML_ERROR_SYNTAX ("create_agent",
                                  "CREATE_AGENT installer must be at"
                                  " least one byte long"));
            }
          else switch (create_agent (create_agent_data->name,
                                     create_agent_data->comment,
                                     create_agent_data->installer,
                                     create_agent_data->howto_install,
                                     create_agent_data->howto_use))
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
          create_agent_data_reset (create_agent_data);
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
          config_t config = 0;

          assert (strcasecmp ("CREATE_CONFIG", element_name) == 0);
          assert (import_config_data->import
                  || (create_config_data->name != NULL));

          /* For now the import element, GET_CONFIGS_RESPONSE, overrides
           * any other elements. */
          if (import_config_data->import)
            {
              char *name;
              array_terminate (import_config_data->nvt_selectors);
              array_terminate (import_config_data->preferences);
              switch (create_config (import_config_data->name,
                                     import_config_data->comment,
                                     import_config_data->nvt_selectors,
                                     import_config_data->preferences,
                                     &name))
                {
                  case 0:
                    SENDF_TO_CLIENT_OR_FAIL
                     ("<create_config_response"
                      " status=\"" STATUS_OK_CREATED "\""
                      " status_text=\"" STATUS_OK_CREATED_TEXT "\">"
                      "<config><name>%s</name></config>"
                      "</create_config_response>",
                      name);
                    free (name);
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
                  case -2:
                    SEND_TO_CLIENT_OR_FAIL
                     (XML_ERROR_SYNTAX ("create_config",
                                        "CREATE_CONFIG import name must be at"
                                        " least one character long"));
                    break;
                  case -3:
                    SEND_TO_CLIENT_OR_FAIL
                     (XML_ERROR_SYNTAX ("create_config",
                                        "Error in NVT_SELECTORS element."));
                    break;
                  case -4:
                    SEND_TO_CLIENT_OR_FAIL
                     (XML_ERROR_SYNTAX ("create_config",
                                        "Error in PREFERENCES element."));
                    break;
                }
            }
          else if (strlen (create_config_data->name) == 0)
            {
              SEND_TO_CLIENT_OR_FAIL
               (XML_ERROR_SYNTAX ("create_config",
                                  // FIX could pass an empty rcfile?
                                  "CREATE_CONFIG name and rcfile must be at"
                                  " least one character long"));
            }
          else if ((create_config_data->rcfile
                    && create_config_data->copy)
                   || (create_config_data->rcfile == NULL
                       && create_config_data->copy == NULL))
            {
              SEND_TO_CLIENT_OR_FAIL
               (XML_ERROR_SYNTAX ("create_config",
                                  "CREATE_CONFIG requires either a COPY or an"
                                  " RCFILE element"));
            }
          else if (create_config_data->rcfile)
            {
              int ret;
              gsize base64_len;
              guchar *base64;

              base64 = g_base64_decode (create_config_data->rcfile,
                                        &base64_len);
              /* g_base64_decode can return NULL (Glib 2.12.4-2), at least
               * when create_config_data->rcfile is zero length. */
              if (base64 == NULL)
                {
                  base64 = (guchar*) g_strdup ("");
                  base64_len = 0;
                }

              ret = create_config_rc (create_config_data->name,
                                      create_config_data->comment,
                                      (char*) base64,
                                      NULL);
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
          else if (find_config (create_config_data->copy, &config))
            SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("create_config"));
          else if (config == 0)
            {
              if (send_find_error_to_client ("create_config",
                                             "config",
                                             create_config_data->copy))
                {
                  error_send_to_client (error);
                  return;
                }
            }
          else switch (copy_config (create_config_data->name,
                                    create_config_data->comment,
                                    config))
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
          create_config_data_reset (create_config_data);
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

      case CLIENT_C_C_GCR:
        assert (strcasecmp ("GET_CONFIGS_RESPONSE", element_name) == 0);
        import_config_data->import = 1;
        set_client_state (CLIENT_CREATE_CONFIG);
        break;
      case CLIENT_C_C_GCR_CONFIG:
        assert (strcasecmp ("CONFIG", element_name) == 0);
        set_client_state (CLIENT_C_C_GCR);
        break;
      case CLIENT_C_C_GCR_CONFIG_COMMENT:
        assert (strcasecmp ("COMMENT", element_name) == 0);
        set_client_state (CLIENT_C_C_GCR_CONFIG);
        break;
      case CLIENT_C_C_GCR_CONFIG_NAME:
        assert (strcasecmp ("NAME", element_name) == 0);
        set_client_state (CLIENT_C_C_GCR_CONFIG);
        break;
      case CLIENT_C_C_GCR_CONFIG_NVT_SELECTORS:
        assert (strcasecmp ("NVT_SELECTORS", element_name) == 0);
        set_client_state (CLIENT_C_C_GCR_CONFIG);
        break;
      case CLIENT_C_C_GCR_CONFIG_NVT_SELECTORS_NVT_SELECTOR:
        {
          int include;

          assert (strcasecmp ("NVT_SELECTOR", element_name) == 0);

          if (import_config_data->nvt_selector_include
              && strcmp (import_config_data->nvt_selector_include, "0") == 0)
            include = 0;
          else
            include = 1;

          array_add (import_config_data->nvt_selectors,
                     nvt_selector_new
                      (import_config_data->nvt_selector_name,
                       import_config_data->nvt_selector_type,
                       include,
                       import_config_data->nvt_selector_family_or_nvt));

          import_config_data->nvt_selector_name = NULL;
          import_config_data->nvt_selector_type = NULL;
          free (import_config_data->nvt_selector_include);
          import_config_data->nvt_selector_include = NULL;
          import_config_data->nvt_selector_family_or_nvt = NULL;

          set_client_state (CLIENT_C_C_GCR_CONFIG_NVT_SELECTORS);
          break;
        }
      case CLIENT_C_C_GCR_CONFIG_NVT_SELECTORS_NVT_SELECTOR_INCLUDE:
        assert (strcasecmp ("INCLUDE", element_name) == 0);
        set_client_state (CLIENT_C_C_GCR_CONFIG_NVT_SELECTORS_NVT_SELECTOR);
        break;
      case CLIENT_C_C_GCR_CONFIG_NVT_SELECTORS_NVT_SELECTOR_NAME:
        assert (strcasecmp ("NAME", element_name) == 0);
        set_client_state (CLIENT_C_C_GCR_CONFIG_NVT_SELECTORS_NVT_SELECTOR);
        break;
      case CLIENT_C_C_GCR_CONFIG_NVT_SELECTORS_NVT_SELECTOR_TYPE:
        assert (strcasecmp ("TYPE", element_name) == 0);
        set_client_state (CLIENT_C_C_GCR_CONFIG_NVT_SELECTORS_NVT_SELECTOR);
        break;
      case CLIENT_C_C_GCR_CONFIG_NVT_SELECTORS_NVT_SELECTOR_FAMILY_OR_NVT:
        assert (strcasecmp ("FAMILY_OR_NVT", element_name) == 0);
        set_client_state (CLIENT_C_C_GCR_CONFIG_NVT_SELECTORS_NVT_SELECTOR);
        break;
      case CLIENT_C_C_GCR_CONFIG_PREFERENCES:
        assert (strcasecmp ("PREFERENCES", element_name) == 0);
        set_client_state (CLIENT_C_C_GCR_CONFIG);
        break;
      case CLIENT_C_C_GCR_CONFIG_PREFERENCES_PREFERENCE:
        assert (strcasecmp ("PREFERENCE", element_name) == 0);
        array_terminate (import_config_data->preference_alts);
        array_add (import_config_data->preferences,
                   preference_new (import_config_data->preference_name,
                                   import_config_data->preference_type,
                                   import_config_data->preference_value,
                                   import_config_data->preference_nvt_name,
                                   import_config_data->preference_nvt_oid,
                                   import_config_data->preference_alts));
        import_config_data->preference_name = NULL;
        import_config_data->preference_type = NULL;
        import_config_data->preference_value = NULL;
        import_config_data->preference_nvt_name = NULL;
        import_config_data->preference_nvt_oid = NULL;
        import_config_data->preference_alts = NULL;
        set_client_state (CLIENT_C_C_GCR_CONFIG_PREFERENCES);
        break;
      case CLIENT_C_C_GCR_CONFIG_PREFERENCES_PREFERENCE_ALT:
        assert (strcasecmp ("ALT", element_name) == 0);
        array_add (import_config_data->preference_alts,
                   import_config_data->preference_alt);
        import_config_data->preference_alt = NULL;
        set_client_state (CLIENT_C_C_GCR_CONFIG_PREFERENCES_PREFERENCE);
        break;
      case CLIENT_C_C_GCR_CONFIG_PREFERENCES_PREFERENCE_NAME:
        assert (strcasecmp ("NAME", element_name) == 0);
        set_client_state (CLIENT_C_C_GCR_CONFIG_PREFERENCES_PREFERENCE);
        break;
      case CLIENT_C_C_GCR_CONFIG_PREFERENCES_PREFERENCE_NVT:
        assert (strcasecmp ("NVT", element_name) == 0);
        set_client_state (CLIENT_C_C_GCR_CONFIG_PREFERENCES_PREFERENCE);
        break;
      case CLIENT_C_C_GCR_CONFIG_PREFERENCES_PREFERENCE_NVT_NAME:
        assert (strcasecmp ("NAME", element_name) == 0);
        set_client_state (CLIENT_C_C_GCR_CONFIG_PREFERENCES_PREFERENCE_NVT);
        break;
      case CLIENT_C_C_GCR_CONFIG_PREFERENCES_PREFERENCE_TYPE:
        assert (strcasecmp ("TYPE", element_name) == 0);
        set_client_state (CLIENT_C_C_GCR_CONFIG_PREFERENCES_PREFERENCE);
        break;
      case CLIENT_C_C_GCR_CONFIG_PREFERENCES_PREFERENCE_VALUE:
        assert (strcasecmp ("VALUE", element_name) == 0);
        set_client_state (CLIENT_C_C_GCR_CONFIG_PREFERENCES_PREFERENCE);
        break;

      case CLIENT_CREATE_ESCALATOR:
        {
          event_t event;
          escalator_condition_t condition;
          escalator_method_t method;

          assert (strcasecmp ("CREATE_ESCALATOR", element_name) == 0);
          assert (create_escalator_data->name != NULL);
          assert (create_escalator_data->condition != NULL);
          assert (create_escalator_data->method != NULL);
          assert (create_escalator_data->event != NULL);

          array_terminate (create_escalator_data->condition_data);
          array_terminate (create_escalator_data->event_data);
          array_terminate (create_escalator_data->method_data);

          if (strlen (create_escalator_data->name) == 0)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_escalator",
                                "CREATE_ESCALATOR requires NAME element which"
                                " is at least one character long"));
          else if (strlen (create_escalator_data->condition) == 0)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_escalator",
                                "CREATE_ESCALATOR requires a value in a"
                                " CONDITION element"));
          else if (strlen (create_escalator_data->event) == 0)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_escalator",
                                "CREATE_ESCALATOR requires a value in an"
                                " EVENT element"));
          else if (strlen (create_escalator_data->method) == 0)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_escalator",
                                "CREATE_ESCALATOR requires a value in a"
                                " METHOD element"));
          else if ((condition = escalator_condition_from_name
                                 (create_escalator_data->condition))
                   == 0)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_escalator",
                                "Failed to recognise condition name"));
          else if ((event = event_from_name (create_escalator_data->event))
                   == 0)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_escalator",
                                "Failed to recognise event name"));
          else if ((method = escalator_method_from_name
                              (create_escalator_data->method))
                   == 0)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_escalator",
                                "Failed to recognise method name"));
          else
            {
              switch (create_escalator (create_escalator_data->name,
                                        create_escalator_data->comment,
                                        event,
                                        create_escalator_data->event_data,
                                        condition,
                                        create_escalator_data->condition_data,
                                        method,
                                        create_escalator_data->method_data))
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
          create_escalator_data_reset (create_escalator_data);
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
          assert (create_escalator_data->condition_data);
          assert (create_escalator_data->part_data);
          assert (create_escalator_data->part_name);

          string = g_strconcat (create_escalator_data->part_name,
                                "0",
                                create_escalator_data->part_data,
                                NULL);
          string[strlen (create_escalator_data->part_name)] = '\0';
          array_add (create_escalator_data->condition_data, string);

          openvas_free_string_var (&create_escalator_data->part_data);
          openvas_free_string_var (&create_escalator_data->part_name);
          openvas_append_string (&create_escalator_data->part_data, "");
          openvas_append_string (&create_escalator_data->part_name, "");
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
          assert (create_escalator_data->event_data);
          assert (create_escalator_data->part_data);
          assert (create_escalator_data->part_name);

          string = g_strconcat (create_escalator_data->part_name,
                                "0",
                                create_escalator_data->part_data,
                                NULL);
          string[strlen (create_escalator_data->part_name)] = '\0';
          array_add (create_escalator_data->event_data, string);

          openvas_free_string_var (&create_escalator_data->part_data);
          openvas_free_string_var (&create_escalator_data->part_name);
          openvas_append_string (&create_escalator_data->part_data, "");
          openvas_append_string (&create_escalator_data->part_name, "");
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
          assert (create_escalator_data->method_data);
          assert (create_escalator_data->part_data);
          assert (create_escalator_data->part_name);

          string = g_strconcat (create_escalator_data->part_name,
                                "0",
                                create_escalator_data->part_data,
                                NULL);
          string[strlen (create_escalator_data->part_name)] = '\0';
          array_add (create_escalator_data->method_data, string);

          openvas_free_string_var (&create_escalator_data->part_data);
          openvas_free_string_var (&create_escalator_data->part_name);
          openvas_append_string (&create_escalator_data->part_data, "");
          openvas_append_string (&create_escalator_data->part_name, "");
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
          assert (create_lsc_credential_data->name != NULL);
          assert (create_lsc_credential_data->login != NULL);

          if (strlen (create_lsc_credential_data->name) == 0)
            {
              SEND_TO_CLIENT_OR_FAIL
               (XML_ERROR_SYNTAX ("create_lsc_credential",
                                  "CREATE_LSC_CREDENTIAL name must be at"
                                  " least one character long"));
            }
          else if (strlen (create_lsc_credential_data->login) == 0)
            {
              SEND_TO_CLIENT_OR_FAIL
               (XML_ERROR_SYNTAX ("create_lsc_credential",
                                  "CREATE_LSC_CREDENTIAL login must be at"
                                  " least one character long"));
            }
          else switch (create_lsc_credential
                        (create_lsc_credential_data->name,
                         create_lsc_credential_data->comment,
                         create_lsc_credential_data->login,
                         create_lsc_credential_data->password))
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
          create_lsc_credential_data_reset (create_lsc_credential_data);
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

      case CLIENT_CREATE_NOTE:
        {
          task_t task = 0;
          result_t result = 0;

          assert (strcasecmp ("CREATE_NOTE", element_name) == 0);

          if (create_note_data->nvt == NULL)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_note",
                                "CREATE_NOTE requires an NVT entity"));
          else if (create_note_data->text == NULL)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_note",
                                "CREATE_NOTE requires a TEXT entity"));
          else if (create_note_data->task
              && find_task (create_note_data->task, &task))
            SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("create_note"));
          else if (create_note_data->task && task == 0)
            {
              if (send_find_error_to_client ("create_note",
                                             "task",
                                             create_note_data->task))
                {
                  error_send_to_client (error);
                  return;
                }
            }
          else if (create_note_data->result
                   && find_result (create_note_data->result, &result))
            SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("create_note"));
          else if (create_note_data->result && result == 0)
            {
              if (send_find_error_to_client ("create_note",
                                             "result",
                                             create_note_data->result))
                {
                  error_send_to_client (error);
                  return;
                }
            }
          else switch (create_note (create_note_data->nvt,
                                    create_note_data->text,
                                    create_note_data->hosts,
                                    create_note_data->port,
                                    create_note_data->threat,
                                    task,
                                    result))
            {
              case 0:
                SENDF_TO_CLIENT_OR_FAIL (XML_OK_CREATED ("create_note"));
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
      case CLIENT_CREATE_NOTE_HOSTS:
        assert (strcasecmp ("HOSTS", element_name) == 0);
        set_client_state (CLIENT_CREATE_NOTE);
        break;
      case CLIENT_CREATE_NOTE_NVT:
        assert (strcasecmp ("NVT", element_name) == 0);
        set_client_state (CLIENT_CREATE_NOTE);
        break;
      case CLIENT_CREATE_NOTE_PORT:
        assert (strcasecmp ("PORT", element_name) == 0);
        set_client_state (CLIENT_CREATE_NOTE);
        break;
      case CLIENT_CREATE_NOTE_RESULT:
        assert (strcasecmp ("RESULT", element_name) == 0);
        set_client_state (CLIENT_CREATE_NOTE);
        break;
      case CLIENT_CREATE_NOTE_TASK:
        assert (strcasecmp ("TASK", element_name) == 0);
        set_client_state (CLIENT_CREATE_NOTE);
        break;
      case CLIENT_CREATE_NOTE_TEXT:
        assert (strcasecmp ("TEXT", element_name) == 0);
        set_client_state (CLIENT_CREATE_NOTE);
        break;
      case CLIENT_CREATE_NOTE_THREAT:
        assert (strcasecmp ("THREAT", element_name) == 0);
        set_client_state (CLIENT_CREATE_NOTE);
        break;

      case CLIENT_CREATE_SCHEDULE:
        {
          time_t first_time, period, period_months, duration;

          period_months = 0;

          assert (strcasecmp ("CREATE_SCHEDULE", element_name) == 0);

          if (create_schedule_data->name == NULL)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_schedule",
                                "CREATE_SCHEDULE requires a NAME entity"));
          else if ((first_time = time_from_strings
                                  (create_schedule_data->first_time_hour,
                                   create_schedule_data->first_time_minute,
                                   create_schedule_data->first_time_day_of_month,
                                   create_schedule_data->first_time_month,
                                   create_schedule_data->first_time_year))
                   == -1)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_schedule",
                                "Failed to create time from FIRST_TIME"
                                " elements"));
          else if ((period = interval_from_strings
                              (create_schedule_data->period,
                               create_schedule_data->period_unit,
                               &period_months))
                   == -1)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_schedule",
                                "Failed to create interval from PERIOD"));
          else if ((duration = interval_from_strings
                                (create_schedule_data->duration,
                                 create_schedule_data->duration_unit,
                                 NULL))
                   == -1)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_schedule",
                                "Failed to create interval from DURATION"));
          else if (period_months
                   && (duration > (period_months * 60 * 60 * 24 * 28)))
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_schedule",
                                "Duration too long for number of months"));
          else if (period && (duration > period))
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_schedule",
                                "Duration is longer than period"));
          else switch (create_schedule (create_schedule_data->name,
                                        create_schedule_data->comment,
                                        first_time,
                                        period,
                                        period_months,
                                        duration,
                                        NULL))
            {
              case 0:
                SENDF_TO_CLIENT_OR_FAIL (XML_OK_CREATED ("create_schedule"));
                break;
              case 1:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("create_schedule",
                                    "Schedule exists already"));
                break;
              case -1:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_INTERNAL_ERROR ("create_schedule"));
                break;
              default:
                assert (0);
                SEND_TO_CLIENT_OR_FAIL
                 (XML_INTERNAL_ERROR ("create_schedule"));
                break;
            }
          create_schedule_data_reset (create_schedule_data);
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }
      case CLIENT_CREATE_SCHEDULE_COMMENT:
        assert (strcasecmp ("COMMENT", element_name) == 0);
        set_client_state (CLIENT_CREATE_SCHEDULE);
        break;
      case CLIENT_CREATE_SCHEDULE_DURATION:
        assert (strcasecmp ("DURATION", element_name) == 0);
        set_client_state (CLIENT_CREATE_SCHEDULE);
        break;
      case CLIENT_CREATE_SCHEDULE_FIRST_TIME:
        assert (strcasecmp ("FIRST_TIME", element_name) == 0);
        set_client_state (CLIENT_CREATE_SCHEDULE);
        break;
      case CLIENT_CREATE_SCHEDULE_NAME:
        assert (strcasecmp ("NAME", element_name) == 0);
        set_client_state (CLIENT_CREATE_SCHEDULE);
        break;
      case CLIENT_CREATE_SCHEDULE_PERIOD:
        assert (strcasecmp ("PERIOD", element_name) == 0);
        set_client_state (CLIENT_CREATE_SCHEDULE);
        break;

      case CLIENT_CREATE_SCHEDULE_FIRST_TIME_DAY_OF_MONTH:
        assert (strcasecmp ("DAY_OF_MONTH", element_name) == 0);
        set_client_state (CLIENT_CREATE_SCHEDULE_FIRST_TIME);
        break;
      case CLIENT_CREATE_SCHEDULE_FIRST_TIME_HOUR:
        assert (strcasecmp ("HOUR", element_name) == 0);
        set_client_state (CLIENT_CREATE_SCHEDULE_FIRST_TIME);
        break;
      case CLIENT_CREATE_SCHEDULE_FIRST_TIME_MINUTE:
        assert (strcasecmp ("MINUTE", element_name) == 0);
        set_client_state (CLIENT_CREATE_SCHEDULE_FIRST_TIME);
        break;
      case CLIENT_CREATE_SCHEDULE_FIRST_TIME_MONTH:
        assert (strcasecmp ("MONTH", element_name) == 0);
        set_client_state (CLIENT_CREATE_SCHEDULE_FIRST_TIME);
        break;
      case CLIENT_CREATE_SCHEDULE_FIRST_TIME_YEAR:
        assert (strcasecmp ("YEAR", element_name) == 0);
        set_client_state (CLIENT_CREATE_SCHEDULE_FIRST_TIME);
        break;

      case CLIENT_CREATE_SCHEDULE_DURATION_UNIT:
        assert (strcasecmp ("UNIT", element_name) == 0);
        set_client_state (CLIENT_CREATE_SCHEDULE_DURATION);
        break;

      case CLIENT_CREATE_SCHEDULE_PERIOD_UNIT:
        assert (strcasecmp ("UNIT", element_name) == 0);
        set_client_state (CLIENT_CREATE_SCHEDULE_PERIOD);
        break;

      case CLIENT_CREATE_TARGET:
        {
          lsc_credential_t lsc_credential = 0;

          assert (strcasecmp ("CREATE_TARGET", element_name) == 0);
          assert (&create_target_data->name != NULL);
          assert (&create_target_data->hosts != NULL);

          if (strlen (create_target_data->name) == 0
              || strlen (create_target_data->hosts) == 0)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_target",
                                // FIX could pass an empty hosts element?
                                "CREATE_TARGET name and hosts must both be at"
                                " least one character long"));
          else if (create_target_data->lsc_credential
                   && find_lsc_credential (create_target_data->lsc_credential,
                                           &lsc_credential))
            SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("create_target"));
          else if (create_target_data->lsc_credential && lsc_credential == 0)
            {
              if (send_find_error_to_client
                   ("create_target",
                    "lsc_credential",
                    create_target_data->lsc_credential))
                {
                  error_send_to_client (error);
                  return;
                }
            }
          else if (create_target (create_target_data->name,
                                  create_target_data->hosts,
                                  create_target_data->comment,
                                  lsc_credential,
                                  NULL))
            SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX ("create_target",
                                                      "Target exists already"));
          else
            SEND_TO_CLIENT_OR_FAIL (XML_OK_CREATED ("create_target"));
          create_target_data_reset (create_target_data);
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
          config_t config = 0;
          target_t target = 0;
          char *tsk_uuid, *name, *description;

          assert (strcasecmp ("CREATE_TASK", element_name) == 0);
          assert (create_task_data->task != (task_t) 0);

          /* The task already exists in the database at this point,
           * including the RC file (in the description column), so on
           * failure be sure to call request_delete_task to remove the
           * task. */
          // FIX fail cases of CLIENT_CREATE_TASK_* states must do so too

          /* Get the task ID. */

          if (task_uuid (create_task_data->task, &tsk_uuid))
            {
              request_delete_task (&create_task_data->task);
              if (send_find_error_to_client ("create_task",
                                             "task",
                                             create_task_data->config))
                {
                  error_send_to_client (error);
                  return;
                }
              create_task_data_reset (create_task_data);
              set_client_state (CLIENT_AUTHENTIC);
              break;
            }

          /* Check for the right combination of rcfile, target and config. */

          description = task_description (create_task_data->task);
          if ((description
               && (create_task_data->config || create_task_data->target))
              || (description == NULL
                  && (create_task_data->config == NULL
                      || create_task_data->target == NULL)))
            {
              request_delete_task (&create_task_data->task);
              free (tsk_uuid);
              SEND_TO_CLIENT_OR_FAIL
               (XML_ERROR_SYNTAX ("create_task",
                                  "CREATE_TASK requires either an rcfile"
                                  " or both a config and a target"));
              create_task_data_reset (create_task_data);
              set_client_state (CLIENT_AUTHENTIC);
              break;
            }

          assert (description
                  || (create_task_data->config && create_task_data->target));

          /* Set any escalator. */

          if (strlen (create_task_data->escalator))
            {
              escalator_t escalator;
              if (find_escalator (create_task_data->escalator, &escalator))
                {
                  SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("create_task"));
                  create_task_data_reset (create_task_data);
                  set_client_state (CLIENT_AUTHENTIC);
                  break;
                }
              if (escalator == 0)
                {
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("create_task",
                                      "CREATE_TASK escalator must exist"));
                  create_task_data_reset (create_task_data);
                  set_client_state (CLIENT_AUTHENTIC);
                  break;
                }
              add_task_escalator (create_task_data->task, escalator);
            }

          /* Set any schedule. */

          if (strlen (create_task_data->schedule))
            {
              schedule_t schedule;
              if (find_schedule (create_task_data->schedule, &schedule))
                {
                  SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("create_task"));
                  create_task_data_reset (create_task_data);
                  set_client_state (CLIENT_AUTHENTIC);
                  break;
                }
              if (schedule == 0)
                {
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("create_task",
                                      "CREATE_TASK schedule must exist"));
                  create_task_data_reset (create_task_data);
                  set_client_state (CLIENT_AUTHENTIC);
                  break;
                }
              set_task_schedule (create_task_data->task, schedule);
            }

          /* Check for name. */

          name = task_name (create_task_data->task);
          if (name == NULL)
            {
              request_delete_task (&create_task_data->task);
              free (tsk_uuid);
              free (description);
              SEND_TO_CLIENT_OR_FAIL
               (XML_ERROR_SYNTAX ("create_task",
                                  "CREATE_TASK requires a name attribute"));
              create_task_data_reset (create_task_data);
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
              ret = create_config_rc (config_name, NULL, (char*) description,
                                      &config);
              set_task_config (create_task_data->task, config);
              g_free (config_name);
              if (ret)
                {
                  request_delete_task (&create_task_data->task);
                  free (description);
                  SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("create_task"));
                  create_task_data_reset (create_task_data);
                  set_client_state (CLIENT_AUTHENTIC);
                  break;
                }

              /* Create the target. */

              hosts = rc_preference (description, "targets");
              if (hosts == NULL)
                {
                  request_delete_task (&create_task_data->task);
                  free (description);
                  free (tsk_uuid);
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX
                     ("create_task",
                      "CREATE_TASK rcfile must have targets"));
                  create_task_data_reset (create_task_data);
                  set_client_state (CLIENT_AUTHENTIC);
                  break;
                }
              free (description);

              target_name = g_strdup_printf ("Imported target for task %s",
                                             tsk_uuid);
              if (create_target (target_name, hosts, NULL, 0, &target))
                {
                  request_delete_task (&create_task_data->task);
                  g_free (target_name);
                  free (tsk_uuid);
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_INTERNAL_ERROR ("create_task"));
                  create_task_data_reset (create_task_data);
                  set_client_state (CLIENT_AUTHENTIC);
                  break;
                }
              set_task_target (create_task_data->task, target);
              g_free (target_name);
            }
          else if (find_config (create_task_data->config, &config))
            {
              request_delete_task (&create_task_data->task);
              free (tsk_uuid);
              SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("create_task"));
              create_task_data_reset (create_task_data);
              set_client_state (CLIENT_AUTHENTIC);
              break;
            }
          else if (config == 0)
            {
              request_delete_task (&create_task_data->task);
              free (tsk_uuid);
              if (send_find_error_to_client ("create_task",
                                             "config",
                                             create_task_data->config))
                {
                  error_send_to_client (error);
                  return;
                }
              create_task_data_reset (create_task_data);
              set_client_state (CLIENT_AUTHENTIC);
              break;
            }
          else if (find_target (create_task_data->target, &target))
            {
              request_delete_task (&create_task_data->task);
              free (tsk_uuid);
              SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("create_task"));
              create_task_data_reset (create_task_data);
              set_client_state (CLIENT_AUTHENTIC);
              break;
            }
          else if (target == 0)
            {
              request_delete_task (&create_task_data->task);
              free (tsk_uuid);
              if (send_find_error_to_client ("create_task",
                                             "target",
                                             create_task_data->target))
                {
                  // Out of space
                  error_send_to_client (error);
                  return;
                }
              create_task_data_reset (create_task_data);
              set_client_state (CLIENT_AUTHENTIC);
              break;
            }
          else
            {
              set_task_config (create_task_data->task, config);
              set_task_target (create_task_data->task, target);

              /* Generate the rcfile in the task. */

              if (make_task_rcfile (create_task_data->task))
                {
                  request_delete_task (&create_task_data->task);
                  free (tsk_uuid);
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_SYNTAX ("create_task",
                                      "Failed to generate task rcfile"));
                  create_task_data_reset (create_task_data);
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
          create_task_data_reset (create_task_data);
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
        if (create_task_data->task)
          {
            gsize out_len;
            guchar* out;
            char* description = task_description (create_task_data->task);
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
            set_task_description (create_task_data->task, (char*) out, out_len);
            set_client_state (CLIENT_CREATE_TASK);
          }
        break;
      case CLIENT_CREATE_TASK_TARGET:
        assert (strcasecmp ("TARGET", element_name) == 0);
        set_client_state (CLIENT_CREATE_TASK);
        break;
      case CLIENT_CREATE_TASK_SCHEDULE:
        assert (strcasecmp ("SCHEDULE", element_name) == 0);
        set_client_state (CLIENT_CREATE_TASK);
        break;

      case CLIENT_MODIFY_NOTE:
        {
          task_t task = 0;
          result_t result = 0;
          note_t note = 0;

          assert (strcasecmp ("MODIFY_NOTE", element_name) == 0);

          if (modify_note_data->note_id == NULL)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("modify_note",
                                "MODIFY_NOTE requires a note_id attribute"));
          else if (modify_note_data->text == NULL)
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("modify_note",
                                "MODIFY_NOTE requires a TEXT entity"));
          else if (find_note (modify_note_data->note_id, &note))
            SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("modify_note"));
          else if (note == 0)
            {
              if (send_find_error_to_client ("modify_note",
                                             "note",
                                             modify_note_data->note_id))
                {
                  error_send_to_client (error);
                  return;
                }
            }
          else if (modify_note_data->task
                   && find_task (modify_note_data->task, &task))
            SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("modify_note"));
          else if (modify_note_data->task && task == 0)
            {
              if (send_find_error_to_client ("modify_note",
                                             "task",
                                             modify_note_data->task))
                {
                  error_send_to_client (error);
                  return;
                }
            }
          else if (modify_note_data->result
                   && find_result (modify_note_data->result, &result))
            SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("modify_note"));
          else if (modify_note_data->result && result == 0)
            {
              if (send_find_error_to_client ("modify_note",
                                             "result",
                                             modify_note_data->result))
                {
                  error_send_to_client (error);
                  return;
                }
            }
          else switch (modify_note (note,
                                    modify_note_data->text,
                                    modify_note_data->hosts,
                                    modify_note_data->port,
                                    modify_note_data->threat,
                                    task,
                                    result))
            {
              case 0:
                SENDF_TO_CLIENT_OR_FAIL (XML_OK ("modify_note"));
                break;
              case -1:
                SEND_TO_CLIENT_OR_FAIL
                 (XML_INTERNAL_ERROR ("modify_note"));
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
      case CLIENT_MODIFY_NOTE_HOSTS:
        assert (strcasecmp ("HOSTS", element_name) == 0);
        set_client_state (CLIENT_MODIFY_NOTE);
        break;
      case CLIENT_MODIFY_NOTE_PORT:
        assert (strcasecmp ("PORT", element_name) == 0);
        set_client_state (CLIENT_MODIFY_NOTE);
        break;
      case CLIENT_MODIFY_NOTE_RESULT:
        assert (strcasecmp ("RESULT", element_name) == 0);
        set_client_state (CLIENT_MODIFY_NOTE);
        break;
      case CLIENT_MODIFY_NOTE_TASK:
        assert (strcasecmp ("TASK", element_name) == 0);
        set_client_state (CLIENT_MODIFY_NOTE);
        break;
      case CLIENT_MODIFY_NOTE_TEXT:
        assert (strcasecmp ("TEXT", element_name) == 0);
        set_client_state (CLIENT_MODIFY_NOTE);
        break;
      case CLIENT_MODIFY_NOTE_THREAT:
        assert (strcasecmp ("THREAT", element_name) == 0);
        set_client_state (CLIENT_MODIFY_NOTE);
        break;

      case CLIENT_TEST_ESCALATOR:
        if (test_escalator_data->name)
          {
            escalator_t escalator;
            task_t task;

            if (find_escalator (test_escalator_data->name, &escalator))
              SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("test_escalator"));
            else if (escalator == 0)
              {
                if (send_find_error_to_client ("test_escalator",
                                               "escalator",
                                               test_escalator_data->name))
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
          }
        else
          SEND_TO_CLIENT_OR_FAIL
           (XML_ERROR_SYNTAX ("test_escalator",
                              "TEST_ESCALATOR requires a name element"));
        test_escalator_data_reset (test_escalator_data);
        set_client_state (CLIENT_AUTHENTIC);
        break;
      case CLIENT_TEST_ESCALATOR_NAME:
        assert (strcasecmp ("NAME", element_name) == 0);
        set_client_state (CLIENT_TEST_ESCALATOR);
        break;

      case CLIENT_PAUSE_TASK:
        if (pause_task_data->task_id)
          {
            task_t task;
            assert (current_client_task == (task_t) 0);
            if (find_task (pause_task_data->task_id, &task))
              SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("pause_task"));
            else if (task == 0)
              {
                if (send_find_error_to_client ("pause_task",
                                               "task",
                                               pause_task_data->task_id))
                  {
                    error_send_to_client (error);
                    return;
                  }
              }
            else switch (pause_task (task))
              {
                case 0:   /* Paused. */
                  SEND_TO_CLIENT_OR_FAIL (XML_OK ("pause_task"));
                  break;
                case 1:   /* Pause requested. */
                  SEND_TO_CLIENT_OR_FAIL (XML_OK_REQUESTED ("pause_task"));
                  break;
                default:  /* Programming error. */
                  assert (0);
                case -1:
                  /* to_scanner is full. */
                  // FIX revert parsing for retry
                  // process_omp_client_input must return -2
                  abort ();
              }
          }
        else
          SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("pause_task"));
        pause_task_data_reset (pause_task_data);
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_RESUME_OR_START_TASK:
        if (resume_or_start_task_data->task_id)
          {
            task_t task;
            assert (current_client_task == (task_t) 0);
            if (find_task (resume_or_start_task_data->task_id, &task))
              SEND_TO_CLIENT_OR_FAIL
               (XML_INTERNAL_ERROR ("resume_or_start_task"));
            else if (task == 0)
              {
                if (send_find_error_to_client
                     ("resume_or_start_task",
                      "task",
                      resume_or_start_task_data->task_id))
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
                switch (resume_or_start_task (task, &report_id))
                  {
                    case 0:
                      {
                        gchar *msg;
                        msg = g_strdup_printf
                               ("<resume_or_start_task_response"
                                " status=\"" STATUS_OK_REQUESTED "\""
                                " status_text=\""
                                STATUS_OK_REQUESTED_TEXT
                                "\">"
                                "<report_id>%s</report_id>"
                                "</resume_or_start_task_response>",
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
                       (XML_ERROR_SYNTAX ("resume_or_start_task",
                                          "Task is active already"));
                      break;
                    case 22:
                      SEND_TO_CLIENT_OR_FAIL
                       (XML_ERROR_SYNTAX ("resume_or_start_task",
                                          "Task must be in \"Stopped\" state"));
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
                       (XML_ERROR_SYNTAX ("resume_or_start_task",
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
                    case -1:
                    case -3: /* Failed to create report. */
                      SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("resume_or_start_task"));
                      break;
                    default: /* Programming error. */
                      assert (0);
                      SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("resume_or_start_task"));
                      break;
                  }
              }
          }
        else
          SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("resume_or_start_task"));
        resume_or_start_task_data_reset (resume_or_start_task_data);
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_RESUME_PAUSED_TASK:
        if (resume_paused_task_data->task_id)
          {
            task_t task;
            assert (current_client_task == (task_t) 0);
            if (find_task (resume_paused_task_data->task_id, &task))
              SEND_TO_CLIENT_OR_FAIL
               (XML_INTERNAL_ERROR ("resume_paused_task"));
            else if (task == 0)
              {
                if (send_find_error_to_client
                     ("resume_paused_task",
                      "task",
                      resume_paused_task_data->task_id))
                  {
                    error_send_to_client (error);
                    return;
                  }
              }
            else switch (resume_paused_task (task))
              {
                case 0:   /* Resumed. */
                  SEND_TO_CLIENT_OR_FAIL (XML_OK ("resume_paused_task"));
                  break;
                case 1:   /* Resume requested. */
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_OK_REQUESTED ("resume_paused_task"));
                  break;
                default:  /* Programming error. */
                  assert (0);
                case -1:
                  /* to_scanner is full. */
                  // FIX revert parsing for retry
                  // process_omp_client_input must return -2
                  abort ();
              }
          }
        else
          SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("resume_paused_task"));
        resume_paused_task_data_reset (resume_paused_task_data);
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_RESUME_STOPPED_TASK:
        if (resume_stopped_task_data->task_id)
          {
            task_t task;
            assert (current_client_task == (task_t) 0);
            if (find_task (resume_stopped_task_data->task_id, &task))
              SEND_TO_CLIENT_OR_FAIL
               (XML_INTERNAL_ERROR ("resume_stopped_task"));
            else if (task == 0)
              {
                if (send_find_error_to_client ("resume_stopped_task",
                                               "task",
                                               resume_stopped_task_data->task_id))
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
                switch (resume_stopped_task (task, &report_id))
                  {
                    case 0:
                      {
                        gchar *msg;
                        msg = g_strdup_printf
                               ("<resume_stopped_task_response"
                                " status=\"" STATUS_OK_REQUESTED "\""
                                " status_text=\""
                                STATUS_OK_REQUESTED_TEXT
                                "\">"
                                "<report_id>%s</report_id>"
                                "</resume_stopped_task_response>",
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
                       (XML_ERROR_SYNTAX ("resume_stopped_task",
                                          "Task is active already"));
                      break;
                    case 22:
                      SEND_TO_CLIENT_OR_FAIL
                       (XML_ERROR_SYNTAX ("resume_stopped_task",
                                          "Task must be in \"Stopped\" state"));
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
                       (XML_ERROR_SYNTAX ("resume_stopped_task",
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
                    case -1:
                    case -3: /* Failed to create report. */
                      SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("resume_stopped_task"));
                      break;
                    default: /* Programming error. */
                      assert (0);
                      SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("resume_stopped_task"));
                      break;
                  }
              }
          }
        else
          SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("resume_stopped_task"));
        resume_stopped_task_data_reset (resume_stopped_task_data);
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_START_TASK:
        if (start_task_data->task_id)
          {
            task_t task;
            assert (current_client_task == (task_t) 0);
            if (find_task (start_task_data->task_id, &task))
              SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("start_task"));
            else if (task == 0)
              {
                if (send_find_error_to_client ("start_task",
                                               "task",
                                               start_task_data->task_id))
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
          }
        else
          SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("start_task"));
        start_task_data_reset (start_task_data);
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
                    target_t target;
                    char *name, *config, *escalator, *task_target_name, *hosts;
                    char *task_schedule_uuid, *task_schedule_name, *comment;
                    gchar *first_report_id, *first_report;
                    char* description;
                    gchar *description64, *last_report_id, *last_report;
                    gchar *second_last_report_id, *second_last_report;
                    report_t running_report;
                    schedule_t schedule;
                    time_t next_time;

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

                    running_report = task_current_report (task);
                    if (running_report)
                      {
                        long total = 0;
                        int num_hosts = 0, total_progress;
                        iterator_t hosts;
                        GString *string = g_string_new ("");

                        init_host_iterator (&hosts, running_report, NULL);
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
                    comment = task_comment (task);
                    escalator = task_escalator_name (task);
                    config = task_config_name (task);
                    task_target_name = target_name (target);
                    schedule = task_schedule (task);
                    if (schedule)
                      {
                        task_schedule_uuid = schedule_uuid (schedule);
                        task_schedule_name = schedule_name (schedule);
                      }
                    else
                      {
                        task_schedule_uuid = (char*) g_strdup ("");
                        task_schedule_name = (char*) g_strdup ("");
                      }
                    next_time = task_schedule_next_time (task);
                    response = g_strdup_printf
                                ("<get_status_response"
                                 " status=\"" STATUS_OK "\""
                                 " status_text=\"" STATUS_OK_TEXT "\">"
                                 "<task id=\"%s\">"
                                 "<name>%s</name>"
                                 "<comment>%s</comment>"
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
                                 "<trend>%s</trend>"
                                 "<schedule id=\"%s\">"
                                 "<name>%s</name>"
                                 "<next_time>%s</next_time>"
                                 "</schedule>"
                                 "%s%s%s",
                                 tsk_uuid,
                                 name,
                                 comment,
                                 config ? config : "",
                                 escalator ? escalator : "",
                                 task_target_name ? task_target_name : "",
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
                                 task_trend (task),
                                 task_schedule_uuid,
                                 task_schedule_name,
                                 (next_time == 0
                                   ? "over"
                                   : ctime_strip_newline (&next_time)),
                                 first_report,
                                 last_report,
                                 second_last_report);
                    free (config);
                    free (escalator);
                    free (task_target_name);
                    g_free (progress_xml);
                    g_free (last_report);
                    g_free (second_last_report);
                    ret = send_to_client (response);
                    g_free (response);
                    g_free (name);
                    g_free (comment);
                    g_free (description64);
                    free (tsk_uuid);
                    free (task_schedule_uuid);
                    free (task_schedule_name);
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
                char *comment = task_comment (index);
                target_t target;
                char *tsk_uuid, *config, *escalator, *task_target_name, *hosts;
                char *task_schedule_uuid, *task_schedule_name;
                gchar *first_report_id, *first_report;
                char *description;
                gchar *description64, *last_report_id, *last_report;
                gchar *second_last_report_id, *second_last_report;
                report_t running_report;
                int maximum_hosts;
                schedule_t schedule;
                time_t next_time;

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

                running_report = task_current_report (index);
                if (running_report)
                  {
                    long total = 0;
                    int num_hosts = 0, total_progress;
                    iterator_t hosts;
                    GString *string = g_string_new ("");

                    init_host_iterator (&hosts, running_report, NULL);
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

                config = task_config_name (index);
                escalator = task_escalator_name (index);
                task_target_name = target_name (target);
                schedule = task_schedule (index);
                if (schedule)
                  {
                    task_schedule_uuid = schedule_uuid (schedule);
                    task_schedule_name = schedule_name (schedule);
                  }
                else
                  {
                    task_schedule_uuid = (char*) g_strdup ("");
                    task_schedule_name = (char*) g_strdup ("");
                  }
                next_time = task_schedule_next_time (index);
                line = g_strdup_printf ("<task"
                                        " id=\"%s\">"
                                        "<name>%s</name>"
                                        "<comment>%s</comment>"
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
                                        "<trend>%s</trend>"
                                        "<schedule id=\"%s\">"
                                        "<name>%s</name>"
                                        "<next_time>%s</next_time>"
                                        "</schedule>"
                                        "%s%s%s"
                                        "</task>",
                                        tsk_uuid,
                                        name,
                                        comment,
                                        config ? config : "",
                                        escalator ? escalator : "",
                                        task_target_name ? task_target_name : "",
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
                                        task_trend (index),
                                        task_schedule_uuid,
                                        task_schedule_name,
                                        (next_time == 0
                                          ? "over"
                                          : ctime_strip_newline (&next_time)),
                                        first_report,
                                        last_report,
                                        second_last_report);
                free (config);
                free (escalator);
                free (task_target_name);
                g_free (progress_xml);
                g_free (last_report);
                g_free (second_last_report);
                free (name);
                free (comment);
                g_free (description64);
                free (tsk_uuid);
                free (task_schedule_uuid);
                free (task_schedule_name);
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
          agent_t agent = 0;

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
          else if (current_uuid && find_agent (current_uuid, &agent))
            SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_agents"));
          else if (current_uuid && agent == 0)
            {
              if (send_find_error_to_client ("get_agents",
                                             "agent",
                                             current_uuid))
                {
                  error_send_to_client (error);
                  return;
                }
            }
          else
            {
              SEND_TO_CLIENT_OR_FAIL ("<get_agents_response"
                                      " status=\"" STATUS_OK "\""
                                      " status_text=\"" STATUS_OK_TEXT "\">");
              init_agent_iterator (&targets,
                                   agent,
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
          config_t request_config = 0;
          iterator_t configs;

          assert (strcasecmp ("GET_CONFIGS", element_name) == 0);

          if (current_name && find_config (current_name, &request_config))
            SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_configs"));
          else if (current_name && (request_config == 0))
            {
              if (send_find_error_to_client ("get_configs",
                                             "config",
                                             current_name))
                {
                  error_send_to_client (error);
                  return;
                }
            }
          else
            {
              SEND_TO_CLIENT_OR_FAIL ("<get_configs_response"
                                      " status=\"" STATUS_OK "\""
                                      " status_text=\"" STATUS_OK_TEXT "\">");
              init_config_iterator (&configs,
                                    request_config,
                                    current_int_2,      /* Attribute sort_order. */
                                    current_format);    /* Attribute sort_field. */
              while (next (&configs))
                {
                  int config_nvts_growing, config_families_growing;
                  const char *selector;
                  config_t config;
                  iterator_t tasks;

                  /** @todo This should really be an nvt_selector_t. */
                  selector = config_iterator_nvt_selector (&configs);
                  config = config_iterator_config (&configs);
                  config_nvts_growing = config_iterator_nvts_growing (&configs);
                  config_families_growing
                    = config_iterator_families_growing (&configs);

                  if (current_int_4)
                    /* The "export" attribute was true. */
                    SENDF_TO_CLIENT_OR_FAIL ("<config>"
                                             "<name>%s</name>"
                                             "<comment>%s</comment>",
                                             config_iterator_name (&configs),
                                             config_iterator_comment
                                              (&configs));
                  else
                    {
                      SENDF_TO_CLIENT_OR_FAIL ("<config>"
                                               "<name>%s</name>"
                                               "<comment>%s</comment>"
                                               "<family_count>"
                                               "%i<growing>%i</growing>"
                                               "</family_count>"
                                               /* The number of NVT's selected
                                                * by the selector. */
                                               "<nvt_count>"
                                               "%i<growing>%i</growing>"
                                               "</nvt_count>"
                                               "<in_use>%i</in_use>"
                                               "<tasks>",
                                               config_iterator_name (&configs),
                                               config_iterator_comment
                                                (&configs),
                                               config_family_count (config),
                                               config_families_growing,
                                               config_nvt_count (config),
                                               config_nvts_growing,
                                               config_in_use (config));

                      init_config_task_iterator (&tasks,
                                                 config,
                                                 /* Attribute sort_order. */
                                                 current_int_2);
                      while (next (&tasks))
                        SENDF_TO_CLIENT_OR_FAIL
                         ("<task id=\"%s\">"
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
                              int family_growing, family_max;
                              int family_selected_count;
                              const char *family;

                              family = family_iterator_name (&families);
                              if (family)
                                {
                                  family_growing = nvt_selector_family_growing
                                                    (selector,
                                                     family,
                                                     config_families_growing);
                                  family_max = family_nvt_count (family);
                                  family_selected_count
                                    = nvt_selector_nvt_count (selector,
                                                              family,
                                                              family_growing);
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
                      }

                  if (current_int_3 || current_int_4)
                    {
                      iterator_t prefs;
                      config_t config = config_iterator_config (&configs);

                      assert (config);

                      /* The "preferences" and/or "export" attribute was
                       * true. */

                      SEND_TO_CLIENT_OR_FAIL ("<preferences>");

                      init_nvt_preference_iterator (&prefs, NULL);
                      while (next (&prefs))
                        {
                          GString *buffer = g_string_new ("");
                          buffer_config_preference_xml (buffer, &prefs, config);
                          SEND_TO_CLIENT_OR_FAIL (buffer->str);
                          g_string_free (buffer, TRUE);
                        }
                      cleanup_iterator (&prefs);

                      SEND_TO_CLIENT_OR_FAIL ("</preferences>");
                    }

                  if (current_int_4)
                    {
                      iterator_t selectors;

                      /* The "export" attribute was true. */

                      SEND_TO_CLIENT_OR_FAIL ("<nvt_selectors>");

                      init_nvt_selector_iterator (&selectors,
                                                  NULL,
                                                  config,
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
                              ? ""
                              : nvt_selector_iterator_nvt (&selectors)));
                        }
                      cleanup_iterator (&selectors);

                      SEND_TO_CLIENT_OR_FAIL ("</nvt_selectors>");
                    }

                  SENDF_TO_CLIENT_OR_FAIL ("</config>");
                }
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
          escalator_t escalator = 0;

          assert (strcasecmp ("GET_ESCALATORS", element_name) == 0);

          if (current_name && find_escalator (current_name, &escalator))
            SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_escalators"));
          else if (current_name && escalator == 0)
            {
              if (send_find_error_to_client ("get_escalators",
                                             "escalator",
                                             current_name))
                {
                  error_send_to_client (error);
                  return;
                }
            }
          else
            {
              iterator_t escalators;

              SEND_TO_CLIENT_OR_FAIL ("<get_escalators_response"
                                      " status=\"" STATUS_OK "\""
                                      " status_text=\"" STATUS_OK_TEXT "\">");
              init_escalator_iterator (&escalators,
                                       escalator,
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

                  if (escalator)
                    {
                      iterator_t tasks;

                      SEND_TO_CLIENT_OR_FAIL ("<tasks>");
                      init_escalator_task_iterator (&tasks,
                                                    escalator,
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
            }
          openvas_free_string_var (&current_format);
          openvas_free_string_var (&current_name);
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }

      case CLIENT_GET_LSC_CREDENTIALS:
        {
          iterator_t credentials;
          int format;
          lsc_credential_t lsc_credential = 0;

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
          else if (current_uuid
                   && find_lsc_credential (current_uuid, &lsc_credential))
            SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_lsc_credentials"));
          else if (current_uuid && (lsc_credential == 0))
            {
              if (send_find_error_to_client ("get_lsc_credentials",
                                             "lsc_credential",
                                             current_uuid))
                {
                  error_send_to_client (error);
                  return;
                }
            }
          else
            {
              SEND_TO_CLIENT_OR_FAIL ("<get_lsc_credentials_response"
                                      " status=\"" STATUS_OK "\""
                                      " status_text=\"" STATUS_OK_TEXT "\">");
              init_lsc_credential_iterator (&credentials,
                                            lsc_credential,
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
                          iterator_t targets;

                          SENDF_TO_CLIENT_OR_FAIL
                           ("<lsc_credential>"
                            "<name>%s</name>"
                            "<login>%s</login>"
                            "<comment>%s</comment>"
                            "<in_use>%i</in_use>"
                            "<type>%s</type>"
                            "<targets>",
                            lsc_credential_iterator_name (&credentials),
                            lsc_credential_iterator_login (&credentials),
                            lsc_credential_iterator_comment (&credentials),
                            lsc_credential_iterator_in_use (&credentials),
                            lsc_credential_iterator_public_key (&credentials)
                              ? "gen" : "pass");

                          init_lsc_credential_target_iterator
                           (&targets,
                            lsc_credential_iterator_lsc_credential
                             (&credentials),
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
          openvas_free_string_var (&current_uuid);
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }

      case CLIENT_GET_SYSTEM_REPORTS:
        {
          assert (strcasecmp ("GET_SYSTEM_REPORTS", element_name) == 0);

          if (get_system_reports_data->name
              && (strcasecmp (get_system_reports_data->name,
                              "types")
                  == 0))
            {
              report_type_iterator_t types;

              if (init_system_report_type_iterator (&types))
                SEND_TO_CLIENT_OR_FAIL
                 (XML_INTERNAL_ERROR ("get_system_reports"));
              else
                {
                  SEND_TO_CLIENT_OR_FAIL ("<get_system_reports_response"
                                          " status=\"" STATUS_OK "\""
                                          " status_text=\"" STATUS_OK_TEXT "\">"
                                          "<system_report>"
                                          "<name>types</name>"
                                          "<report>");
                  while (next_report_type (&types))
                    SENDF_TO_CLIENT_OR_FAIL
                     ("<system_report>"
                      "<name>%s</name>"
                      "<title>%s</title>"
                      "</system_report>",
                      report_type_iterator_name (&types),
                      report_type_iterator_title (&types));
                  cleanup_report_type_iterator (&types);
                  SEND_TO_CLIENT_OR_FAIL
                   ("</report>"
                    "</system_report>"
                    "</get_system_reports_response>");
                }
            }
          else
            {
              char *report;

              SEND_TO_CLIENT_OR_FAIL
               ("<get_system_reports_response"
                " status=\"" STATUS_OK "\""
                " status_text=\"" STATUS_OK_TEXT "\">");

              if (manage_system_report (get_system_reports_data->name,
                                        get_system_reports_data->duration,
                                        &report))
                SEND_TO_CLIENT_OR_FAIL
                 (XML_INTERNAL_ERROR ("get_system_reports"));
              else if (report)
                {
                  SENDF_TO_CLIENT_OR_FAIL
                   ("<system_report>"
                    "<name>%s</name>"
                    "<report format=\"png\" duration=\"%s\">"
                    "%s"
                    "</report>"
                    "</system_report>",
                    get_system_reports_data->name,
                    get_system_reports_data->duration,
                    report);
                  free (report);
                }
              else
                SEND_TO_CLIENT_OR_FAIL
                 (XML_ERROR_SYNTAX ("get_system_reports",
                                    "Failed to find report with given name"));
              SEND_TO_CLIENT_OR_FAIL ("</get_system_reports_response>");
            }
          get_system_reports_data_reset (get_system_reports_data);
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }

      case CLIENT_GET_TARGETS:
        {
          target_t target = 0;

          assert (strcasecmp ("GET_TARGETS", element_name) == 0);

          if (current_name && find_target (current_name, &target))
            SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_targets"));
          else if (current_name && target == 0)
            {
              if (send_find_error_to_client ("get_targets",
                                             "target",
                                             current_name))
                {
                  error_send_to_client (error);
                  return;
                }
            }
          else
            {
              iterator_t targets, tasks;

              SEND_TO_CLIENT_OR_FAIL ("<get_targets_response"
                                      " status=\"" STATUS_OK "\""
                                      " status_text=\"" STATUS_OK_TEXT "\">");
              init_target_iterator (&targets,
                                    target,
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
                                            (target_iterator_target (&targets)),
                                           lsc_name ? lsc_name : "");

                  if (target)
                    {
                      init_target_task_iterator (&tasks,
                                                 target,
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
            }
          openvas_free_string_var (&current_format);
          openvas_free_string_var (&current_name);
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
        openvas_append_text (&modify_config_data->name, text, text_len);
        break;

      case CLIENT_MODIFY_CONFIG_NVT_SELECTION_FAMILY:
        openvas_append_text (&modify_config_data->nvt_selection_family,
                             text,
                             text_len);
        break;

      case CLIENT_MODIFY_CONFIG_FAMILY_SELECTION_FAMILY_ALL:
        openvas_append_text
         (&modify_config_data->family_selection_family_all_text,
          text,
          text_len);
        break;
      case CLIENT_MODIFY_CONFIG_FAMILY_SELECTION_FAMILY_GROWING:
        openvas_append_text
         (&modify_config_data->family_selection_family_growing_text,
          text,
          text_len);
        break;
      case CLIENT_MODIFY_CONFIG_FAMILY_SELECTION_FAMILY_NAME:
        openvas_append_text (&modify_config_data->family_selection_family_name,
                             text,
                             text_len);
        break;
      case CLIENT_MODIFY_CONFIG_FAMILY_SELECTION_GROWING:
        openvas_append_text (&modify_config_data->family_selection_growing_text,
                             text,
                             text_len);
        break;

      case CLIENT_MODIFY_CONFIG_PREFERENCE_NAME:
        openvas_append_text (&modify_config_data->preference_name,
                             text,
                             text_len);
        break;
      case CLIENT_MODIFY_CONFIG_PREFERENCE_VALUE:
        openvas_append_text (&modify_config_data->preference_value,
                             text,
                             text_len);
        break;

      case CLIENT_MODIFY_REPORT_PARAMETER:
        openvas_append_text (&modify_report_data->parameter_value,
                             text,
                             text_len);
        break;

      case CLIENT_MODIFY_TASK_COMMENT:
        openvas_append_text (&modify_task_data->comment, text, text_len);
        break;
      case CLIENT_MODIFY_TASK_NAME:
        openvas_append_text (&modify_task_data->name, text, text_len);
        break;
      case CLIENT_MODIFY_TASK_PARAMETER:
        openvas_append_text (&modify_task_data->value, text, text_len);
        break;
      case CLIENT_MODIFY_TASK_RCFILE:
        openvas_append_text (&modify_task_data->rcfile, text, text_len);
        break;
      case CLIENT_MODIFY_TASK_FILE:
        openvas_append_text (&modify_task_data->file, text, text_len);
        break;

      case CLIENT_CREDENTIALS_USERNAME:
        append_to_credentials_username (&current_credentials, text, text_len);
        break;
      case CLIENT_CREDENTIALS_PASSWORD:
        append_to_credentials_password (&current_credentials, text, text_len);
        break;

      case CLIENT_CREATE_AGENT_COMMENT:
        openvas_append_text (&create_agent_data->comment, text, text_len);
        break;
      case CLIENT_CREATE_AGENT_HOWTO_INSTALL:
        openvas_append_text (&create_agent_data->howto_install, text, text_len);
        break;
      case CLIENT_CREATE_AGENT_HOWTO_USE:
        openvas_append_text (&create_agent_data->howto_use, text, text_len);
        break;
      case CLIENT_CREATE_AGENT_INSTALLER:
        openvas_append_text (&create_agent_data->installer, text, text_len);
        break;
      case CLIENT_CREATE_AGENT_NAME:
        openvas_append_text (&create_agent_data->name, text, text_len);
        break;

      case CLIENT_CREATE_CONFIG_COMMENT:
        openvas_append_text (&create_config_data->comment, text, text_len);
        break;
      case CLIENT_CREATE_CONFIG_COPY:
        openvas_append_text (&create_config_data->copy, text, text_len);
        break;
      case CLIENT_CREATE_CONFIG_NAME:
        openvas_append_text (&create_config_data->name, text, text_len);
        break;
      case CLIENT_CREATE_CONFIG_RCFILE:
        openvas_append_text (&create_config_data->rcfile, text, text_len);
        break;

      case CLIENT_C_C_GCR_CONFIG_COMMENT:
        openvas_append_text (&(import_config_data->comment),
                             text,
                             text_len);
        break;
      case CLIENT_C_C_GCR_CONFIG_NAME:
        openvas_append_text (&(import_config_data->name),
                             text,
                             text_len);
        break;
      case CLIENT_C_C_GCR_CONFIG_NVT_SELECTORS_NVT_SELECTOR_INCLUDE:
        openvas_append_text (&(import_config_data->nvt_selector_include),
                             text,
                             text_len);
        break;
      case CLIENT_C_C_GCR_CONFIG_NVT_SELECTORS_NVT_SELECTOR_NAME:
        openvas_append_text (&(import_config_data->nvt_selector_name),
                             text,
                             text_len);
        break;
      case CLIENT_C_C_GCR_CONFIG_NVT_SELECTORS_NVT_SELECTOR_TYPE:
        openvas_append_text (&(import_config_data->nvt_selector_type),
                             text,
                             text_len);
        break;
      case CLIENT_C_C_GCR_CONFIG_NVT_SELECTORS_NVT_SELECTOR_FAMILY_OR_NVT:
        openvas_append_text (&(import_config_data->nvt_selector_family_or_nvt),
                             text,
                             text_len);
        break;
      case CLIENT_C_C_GCR_CONFIG_PREFERENCES_PREFERENCE_ALT:
        openvas_append_text (&(import_config_data->preference_alt),
                             text,
                             text_len);
        break;
      case CLIENT_C_C_GCR_CONFIG_PREFERENCES_PREFERENCE_NAME:
        openvas_append_text (&(import_config_data->preference_name),
                             text,
                             text_len);
        break;
      case CLIENT_C_C_GCR_CONFIG_PREFERENCES_PREFERENCE_NVT_NAME:
        openvas_append_text (&(import_config_data->preference_nvt_name),
                             text,
                             text_len);
        break;
      case CLIENT_C_C_GCR_CONFIG_PREFERENCES_PREFERENCE_TYPE:
        openvas_append_text (&(import_config_data->preference_type),
                             text,
                             text_len);
        break;
      case CLIENT_C_C_GCR_CONFIG_PREFERENCES_PREFERENCE_VALUE:
        openvas_append_text (&(import_config_data->preference_value),
                             text,
                             text_len);
        break;

      case CLIENT_CREATE_LSC_CREDENTIAL_COMMENT:
        openvas_append_text (&create_lsc_credential_data->comment,
                             text,
                             text_len);
        break;
      case CLIENT_CREATE_LSC_CREDENTIAL_LOGIN:
        openvas_append_text (&create_lsc_credential_data->login,
                             text,
                             text_len);
        break;
      case CLIENT_CREATE_LSC_CREDENTIAL_NAME:
        openvas_append_text (&create_lsc_credential_data->name,
                             text,
                             text_len);
        break;
      case CLIENT_CREATE_LSC_CREDENTIAL_PASSWORD:
        openvas_append_text (&create_lsc_credential_data->password,
                             text,
                             text_len);
        break;

      case CLIENT_CREATE_ESCALATOR_COMMENT:
        openvas_append_text (&create_escalator_data->comment, text, text_len);
        break;
      case CLIENT_CREATE_ESCALATOR_CONDITION:
        openvas_append_text (&create_escalator_data->condition, text, text_len);
        break;
      case CLIENT_CREATE_ESCALATOR_EVENT:
        openvas_append_text (&create_escalator_data->event, text, text_len);
        break;
      case CLIENT_CREATE_ESCALATOR_METHOD:
        openvas_append_text (&create_escalator_data->method, text, text_len);
        break;
      case CLIENT_CREATE_ESCALATOR_NAME:
        openvas_append_text (&create_escalator_data->name, text, text_len);
        break;

      case CLIENT_CREATE_ESCALATOR_CONDITION_DATA:
        openvas_append_text (&create_escalator_data->part_data, text, text_len);
        break;
      case CLIENT_CREATE_ESCALATOR_EVENT_DATA:
        openvas_append_text (&create_escalator_data->part_data, text, text_len);
        break;
      case CLIENT_CREATE_ESCALATOR_METHOD_DATA:
        openvas_append_text (&create_escalator_data->part_data, text, text_len);
        break;

      case CLIENT_CREATE_ESCALATOR_CONDITION_DATA_NAME:
        openvas_append_text (&create_escalator_data->part_name, text, text_len);
        break;
      case CLIENT_CREATE_ESCALATOR_EVENT_DATA_NAME:
        openvas_append_text (&create_escalator_data->part_name, text, text_len);
        break;
      case CLIENT_CREATE_ESCALATOR_METHOD_DATA_NAME:
        openvas_append_text (&create_escalator_data->part_name, text, text_len);
        break;

      case CLIENT_CREATE_NOTE_HOSTS:
        openvas_append_text (&create_note_data->hosts, text, text_len);
        break;
      case CLIENT_CREATE_NOTE_NVT:
        openvas_append_text (&create_note_data->nvt, text, text_len);
        break;
      case CLIENT_CREATE_NOTE_PORT:
        openvas_append_text (&create_note_data->port, text, text_len);
        break;
      case CLIENT_CREATE_NOTE_RESULT:
        openvas_append_text (&create_note_data->result, text, text_len);
        break;
      case CLIENT_CREATE_NOTE_TASK:
        openvas_append_text (&create_note_data->task, text, text_len);
        break;
      case CLIENT_CREATE_NOTE_TEXT:
        openvas_append_text (&create_note_data->text, text, text_len);
        break;
      case CLIENT_CREATE_NOTE_THREAT:
        openvas_append_text (&create_note_data->threat, text, text_len);
        break;

      case CLIENT_CREATE_SCHEDULE_COMMENT:
        openvas_append_text (&create_schedule_data->comment, text, text_len);
        break;
      case CLIENT_CREATE_SCHEDULE_DURATION:
        openvas_append_text (&create_schedule_data->duration, text, text_len);
        break;
      case CLIENT_CREATE_SCHEDULE_DURATION_UNIT:
        openvas_append_text (&create_schedule_data->duration_unit,
                             text,
                             text_len);
        break;
      case CLIENT_CREATE_SCHEDULE_FIRST_TIME_DAY_OF_MONTH:
        openvas_append_text (&create_schedule_data->first_time_day_of_month,
                             text,
                             text_len);
        break;
      case CLIENT_CREATE_SCHEDULE_FIRST_TIME_HOUR:
        openvas_append_text (&create_schedule_data->first_time_hour,
                             text,
                             text_len);
        break;
      case CLIENT_CREATE_SCHEDULE_FIRST_TIME_MINUTE:
        openvas_append_text (&create_schedule_data->first_time_minute,
                             text,
                             text_len);
        break;
      case CLIENT_CREATE_SCHEDULE_FIRST_TIME_MONTH:
        openvas_append_text (&create_schedule_data->first_time_month,
                             text,
                             text_len);
        break;
      case CLIENT_CREATE_SCHEDULE_FIRST_TIME_YEAR:
        openvas_append_text (&create_schedule_data->first_time_year,
                             text,
                             text_len);
        break;
      case CLIENT_CREATE_SCHEDULE_NAME:
        openvas_append_text (&create_schedule_data->name, text, text_len);
        break;
      case CLIENT_CREATE_SCHEDULE_PERIOD:
        openvas_append_text (&create_schedule_data->period, text, text_len);
        break;
      case CLIENT_CREATE_SCHEDULE_PERIOD_UNIT:
        openvas_append_text (&create_schedule_data->period_unit,
                             text,
                             text_len);
        break;

      case CLIENT_CREATE_TARGET_COMMENT:
        openvas_append_text (&create_target_data->comment, text, text_len);
        break;
      case CLIENT_CREATE_TARGET_HOSTS:
        openvas_append_text (&create_target_data->hosts, text, text_len);
        break;
      case CLIENT_CREATE_TARGET_LSC_CREDENTIAL:
        openvas_append_text (&create_target_data->lsc_credential,
                             text,
                             text_len);
        break;
      case CLIENT_CREATE_TARGET_NAME:
        openvas_append_text (&create_target_data->name, text, text_len);
        break;

      case CLIENT_CREATE_TASK_COMMENT:
        append_to_task_comment (create_task_data->task, text, text_len);
        break;
      case CLIENT_CREATE_TASK_CONFIG:
        openvas_append_text (&create_task_data->config, text, text_len);
        break;
      case CLIENT_CREATE_TASK_ESCALATOR:
        openvas_append_text (&create_task_data->escalator, text, text_len);
        break;
      case CLIENT_CREATE_TASK_NAME:
        append_to_task_name (create_task_data->task, text, text_len);
        break;
      case CLIENT_CREATE_TASK_RCFILE:
        /* Append the text to the task description. */
        if (add_task_description_line (create_task_data->task,
                                       text,
                                       text_len))
          abort (); // FIX out of mem
        break;
      case CLIENT_CREATE_TASK_SCHEDULE:
        openvas_append_text (&create_task_data->schedule, text, text_len);
        break;
      case CLIENT_CREATE_TASK_TARGET:
        openvas_append_text (&create_task_data->target, text, text_len);
        break;

      case CLIENT_DELETE_AGENT_NAME:
        openvas_append_text (&delete_agent_data->name, text, text_len);
        break;

      case CLIENT_DELETE_CONFIG_NAME:
        openvas_append_text (&delete_config_data->name, text, text_len);
        break;

      case CLIENT_DELETE_ESCALATOR_NAME:
        openvas_append_text (&delete_escalator_data->name, text, text_len);
        break;

      case CLIENT_DELETE_LSC_CREDENTIAL_NAME:
        openvas_append_text (&delete_lsc_credential_data->name, text, text_len);
        break;

      case CLIENT_DELETE_TARGET_NAME:
        openvas_append_text (&delete_target_data->name, text, text_len);
        break;

      case CLIENT_TEST_ESCALATOR_NAME:
        openvas_append_text (&modify_task_name, text, text_len);
        break;

      case CLIENT_MODIFY_NOTE_HOSTS:
        openvas_append_text (&modify_note_data->hosts, text, text_len);
        break;
      case CLIENT_MODIFY_NOTE_PORT:
        openvas_append_text (&modify_note_data->port, text, text_len);
        break;
      case CLIENT_MODIFY_NOTE_RESULT:
        openvas_append_text (&modify_note_data->result, text, text_len);
        break;
      case CLIENT_MODIFY_NOTE_TASK:
        openvas_append_text (&modify_note_data->task, text, text_len);
        break;
      case CLIENT_MODIFY_NOTE_TEXT:
        openvas_append_text (&modify_note_data->text, text, text_len);
        break;
      case CLIENT_MODIFY_NOTE_THREAT:
        openvas_append_text (&modify_note_data->threat, text, text_len);
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
  command_data_init (&command_data);
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


/* OMP change processor. */

/**
 * @brief Deal with any changes caused by other processes.
 *
 * @return 0 success, 1 did something, -1 too little space in the scanner
 *         output buffer.
 */
int
process_omp_change ()
{
  return manage_check_current_task ();
}
