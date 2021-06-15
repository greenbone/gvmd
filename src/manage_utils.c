/* Copyright (C) 2014-2020 Greenbone Networks GmbH
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
 * @file manage_utils.c
 * @brief Module for Greenbone Vulnerability Manager: Manage library utilities.
 */

#include "manage_utils.h"

#include <assert.h> /* for assert */
#include <ctype.h>
#include <stdlib.h> /* for getenv */
#include <stdio.h>  /* for sscanf */
#include <string.h> /* for strcmp */

#include <gvm/base/hosts.h>
#include <gvm/util/uuidutils.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md  utils"

/**
 * @brief Number of seconds in a day.
 */
#define SECS_PER_DAY 86400

/**
 * @file  manage_utils.c
 * @brief The Greenbone Vulnerability Manager management library.
 *
 * Utilities used by the manage library that do not depend on anything.
 */

/**
 * @brief Get the current offset from UTC of a timezone.
 *
 * @param[in]  zone  Timezone, or NULL for UTC.
 *
 * @return Seconds east of UTC.
 */
long
current_offset (const char *zone)
{
  gchar *tz;
  long offset;
  time_t now;
  struct tm now_broken;

  if (zone == NULL)
    return 0;

  /* Store current TZ. */
  tz = getenv ("TZ") ? g_strdup (getenv ("TZ")) : NULL;

  if (setenv ("TZ", zone, 1) == -1)
    {
      g_warning ("%s: Failed to switch to timezone", __func__);
      if (tz != NULL)
        setenv ("TZ", tz, 1);
      g_free (tz);
      return 0;
    }

  tzset ();

  time (&now);
  if (localtime_r (&now, &now_broken) == NULL)
    {
      g_warning ("%s: localtime failed", __func__);
      if (tz != NULL)
        setenv ("TZ", tz, 1);
      g_free (tz);
      return 0;
    }
  if (setenv ("TZ", "UTC", 1) == -1)
    {
      g_warning ("%s: Failed to switch to UTC", __func__);
      if (tz != NULL)
        setenv ("TZ", tz, 1);
      g_free (tz);
      return 0;
    }
  tzset ();
  offset = - (now - mktime (&now_broken));

  /* Revert to stored TZ. */
  if (tz)
    {
      if (setenv ("TZ", tz, 1) == -1)
        {
          g_warning ("%s: Failed to switch to original TZ", __func__);
          g_free (tz);
          return 0;
        }
    }
  else
    unsetenv ("TZ");

  g_free (tz);
  return offset;
}

/**
 * @brief Add months to a time.
 *
 * @param[in]  time    Time.
 * @param[in]  months  Months.
 *
 * @return Time plus given number of months.
 */
time_t
add_months (time_t time, int months)
{
  struct tm broken;
  
  if (localtime_r (&time, &broken) == NULL)
    {
      g_warning ("%s: localtime failed", __func__);
      return 0;
    }
  broken.tm_mon += months;
  return mktime (&broken);
}

/**
 * @brief Return number of hosts described by a hosts string.
 *
 * @param[in]  given_hosts      String describing hosts.
 * @param[in]  exclude_hosts    String describing hosts excluded from given set.
 * @param[in]  max_hosts        Max hosts.
 *
 * @return Number of hosts, or -1 on error.
 */
int
manage_count_hosts_max (const char *given_hosts, const char *exclude_hosts,
                        int max_hosts)
{
  int count;
  gvm_hosts_t *hosts;
  gchar *clean_hosts;
  
  clean_hosts = clean_hosts_string (given_hosts);

  hosts = gvm_hosts_new_with_max (clean_hosts, max_hosts);
  if (hosts == NULL)
    {
      g_free (clean_hosts);
      return -1;
    }

  if (exclude_hosts)
    {
      gchar *clean_exclude_hosts;

      clean_exclude_hosts = clean_hosts_string (exclude_hosts);
      if (gvm_hosts_exclude_with_max (hosts,
                                      clean_exclude_hosts,
                                      max_hosts)
          < 0)
        {
          g_free (clean_hosts);
          g_free (clean_exclude_hosts);
          return -1;
        }
      g_free (clean_exclude_hosts);
    }

  count = gvm_hosts_count (hosts);
  gvm_hosts_free (hosts);
  g_free (clean_hosts);

  return count;
}

/**
 * @brief Get the minimum severity for a severity level.
 *
 * This function has a database equivalent in manage_pg_server.c.
 * These two functions must stay in sync.
 *
 * @param[in] level  The name of the severity level.
 *
 * @return The minimum severity.
 */
double
level_min_severity (const char *level)
{
  if (strcasecmp (level, "Log") == 0)
    return SEVERITY_LOG;
  else if (strcasecmp (level, "False Positive") == 0)
    return SEVERITY_FP;
  else if (strcasecmp (level, "Error") == 0)
    return SEVERITY_ERROR;

  if (strcasecmp (level, "high") == 0)
    return 7.0;
  else if (strcasecmp (level, "medium") == 0)
    return 4.0;
  else if (strcasecmp (level, "low") == 0)
    return 0.1;
  else
    return SEVERITY_UNDEFINED;
}

/**
 * @brief Get the maximum severity for a severity level.
 *
 * This function has a database equivalent in manage_pg_server.c.
 * These two functions must stay in sync.
 *
 * @param[in] level  The name of the severity level.
 *
 * @return The maximunm severity.
 */
double
level_max_severity (const char *level)
{
  if (strcasecmp (level, "Log") == 0)
    return SEVERITY_LOG;
  else if (strcasecmp (level, "False Positive") == 0)
    return SEVERITY_FP;
  else if (strcasecmp (level, "Error") == 0)
    return SEVERITY_ERROR;

  if (strcasecmp (level, "high") == 0)
    return 10.0;
  else if (strcasecmp (level, "medium") == 0)
    return 6.9;
  else if (strcasecmp (level, "low") == 0)
    return 3.9;
  else
    return SEVERITY_UNDEFINED;
}

/**
 * @brief Returns whether a host has an equal host in a hosts string.
 *
 * For example, 192.168.10.1 has an equal in a hosts string
 * "192.168.10.1-5, 192.168.10.10-20" string while 192.168.10.7 doesn't.
 *
 * @param[in] hosts_str      Hosts string to check.
 * @param[in] find_host_str  The host to find.
 * @param[in] max_hosts      Maximum number of hosts allowed in hosts_str.
 *
 * @return 1 if host has equal in hosts_str, 0 otherwise.
 */
int
hosts_str_contains (const char* hosts_str, const char* find_host_str,
                    int max_hosts)
{
  gvm_hosts_t *hosts, *find_hosts;

  hosts = gvm_hosts_new_with_max (hosts_str, max_hosts);
  find_hosts = gvm_hosts_new_with_max (find_host_str, 1);

  if (hosts == NULL || find_hosts == NULL || find_hosts->count != 1)
    {
      gvm_hosts_free (hosts);
      gvm_hosts_free (find_hosts);
      return 0;
    }

  int ret = gvm_host_in_hosts (find_hosts->hosts[0], NULL, hosts);
  gvm_hosts_free (hosts);
  gvm_hosts_free (find_hosts);
  return ret;
}

/**
 * @brief Check whether a resource type table name is valid.
 *
 * @param[in]  type  Type of resource.
 *
 * @return 1 yes, 0 no.
 */
int
valid_db_resource_type (const char* type)
{
  if (type == NULL)
    return 0;

  return (strcasecmp (type, "alert") == 0)
         || (strcasecmp (type, "config") == 0)
         || (strcasecmp (type, "cpe") == 0)
         || (strcasecmp (type, "credential") == 0)
         || (strcasecmp (type, "cve") == 0)
         || (strcasecmp (type, "cert_bund_adv") == 0)
         || (strcasecmp (type, "dfn_cert_adv") == 0)
         || (strcasecmp (type, "filter") == 0)
         || (strcasecmp (type, "group") == 0)
         || (strcasecmp (type, "host") == 0)
         || (strcasecmp (type, "os") == 0)
         || (strcasecmp (type, "note") == 0)
         || (strcasecmp (type, "nvt") == 0)
         || (strcasecmp (type, "ovaldef") == 0)
         || (strcasecmp (type, "override") == 0)
         || (strcasecmp (type, "port_list") == 0)
         || (strcasecmp (type, "permission") == 0)
         || (strcasecmp (type, "report") == 0)
         || (strcasecmp (type, "report_format") == 0)
         || (strcasecmp (type, "result") == 0)
         || (strcasecmp (type, "role") == 0)
         || (strcasecmp (type, "scanner") == 0)
         || (strcasecmp (type, "schedule") == 0)
         || (strcasecmp (type, "tag") == 0)
         || (strcasecmp (type, "target") == 0)
         || (strcasecmp (type, "task") == 0)
         || (strcasecmp (type, "ticket") == 0)
         || (strcasecmp (type, "tls_certificate") == 0)
         || (strcasecmp (type, "user") == 0);
}

/** @brief Replace any control characters in string with spaces.
 *
 * @param[in,out]  string  String to replace in.
 */
void
blank_control_chars (char *string)
{
  for (; *string; string++)
    if (iscntrl (*string) && *string != '\n') *string = ' ';
}

/**
 * @brief GVM product ID.
 */
#define GVM_PRODID "-//Greenbone.net//NONSGML Greenbone Security Manager " \
                   GVMD_VERSION "//EN"

/**
 * @brief Try to get a built-in libical timezone from a tzid or city name.
 *
 * @param[in]  tzid  The tzid or Olson city name.
 *
 * @return The built-in timezone if found, else NULL.
 */
icaltimezone*
icalendar_timezone_from_string (const char *tzid)
{
  if (tzid)
    {
      icaltimezone *tz;

      tz = icaltimezone_get_builtin_timezone_from_tzid (tzid);
      if (tz == NULL)
        tz = icaltimezone_get_builtin_timezone (tzid);
      return tz;
    }

  return NULL;
}

/**
 * @brief Create an iCalendar component from old schedule data.
 *
 * @param[in]  first_time     The first run time.
 * @param[in]  period         The period in seconds.
 * @param[in]  period_months  The period in months.
 * @param[in]  duration       The duration in seconds.
 * @param[in]  byday_mask     The byday mask.
 *
 * @return  The generated iCalendar component.
 */
icalcomponent *
icalendar_from_old_schedule_data (time_t first_time,
                                  time_t period, time_t period_months,
                                  time_t duration,
                                  int byday_mask)
{
  gchar *uid;
  icalcomponent *ical_new, *vevent;
  icaltimetype dtstart, dtstamp;
  int has_recurrence;
  struct icalrecurrencetype recurrence;
  struct icaldurationtype ical_duration;

  // Setup base calendar component
  ical_new = icalcomponent_new_vcalendar ();
  icalcomponent_add_property (ical_new, icalproperty_new_version ("2.0"));
  icalcomponent_add_property (ical_new,
                              icalproperty_new_prodid (GVM_PRODID));

  // Create event component
  vevent = icalcomponent_new_vevent ();
  icalcomponent_add_component (ical_new, vevent);

  // Generate UID for event
  uid = gvm_uuid_make ();
  icalcomponent_set_uid (vevent, uid);
  g_free (uid);
  uid = NULL;

  // Set timestamp
  dtstamp = icaltime_current_time_with_zone (icaltimezone_get_utc_timezone ());
  icalcomponent_set_dtstamp (vevent, dtstamp);

  // Get timezone and set first start time
  dtstart = icaltime_from_timet_with_zone (first_time, 0,
                                           icaltimezone_get_utc_timezone ());

  icalcomponent_set_dtstart (vevent, dtstart);

  // Get recurrence rule if applicable
  icalrecurrencetype_clear (&recurrence);
  if (period_months)
    {
      if (period_months % 12 == 0)
        {
          recurrence.freq = ICAL_YEARLY_RECURRENCE;
          recurrence.interval = period_months / 12;
        }
      else
        {
          recurrence.freq = ICAL_MONTHLY_RECURRENCE;
          recurrence.interval = period_months;
        }
      has_recurrence = 1;
    }
  else if (period)
    {
      if (period % 604800 == 0)
        {
          recurrence.freq = ICAL_WEEKLY_RECURRENCE;
          recurrence.interval = period / 604800;
        }
      else if (period % 86400 == 0)
        {
          recurrence.freq = ICAL_DAILY_RECURRENCE;
          recurrence.interval = period / 86400;
        }
      else if (period % 3600 == 0)
        {
          recurrence.freq = ICAL_HOURLY_RECURRENCE;
          recurrence.interval = period / 3600;
        }
      else if (period % 60 == 0)
        {
          recurrence.freq = ICAL_MINUTELY_RECURRENCE;
          recurrence.interval = period / 60;
        }
      else
        {
          recurrence.freq = ICAL_SECONDLY_RECURRENCE;
          recurrence.interval = period;
        }

      has_recurrence = 1;
    }
  else
    has_recurrence = 0;

  // Add set by_day and add the RRULE if applicable
  if (has_recurrence)
    {
      if (byday_mask)
        {
          int ical_day, array_pos;

          // iterate over libical days starting at 1 for Sunday.
          array_pos = 0;
          for (ical_day = 1; ical_day <= 7; ical_day++)
            {
              int mask_bit;
              // Convert to GVM byday mask bit index starting at 0 for Monday.
              mask_bit = (ical_day == 1) ? 1 : (ical_day - 2);
              if (byday_mask & (1 << mask_bit))
                {
                  recurrence.by_day[array_pos] = ical_day;
                  array_pos ++;
                }
            }
        }

      icalcomponent_add_property (vevent,
                                  icalproperty_new_rrule (recurrence));
    }

  // Add duration
  if (duration)
    {
      ical_duration = icaldurationtype_from_int (duration);
      icalcomponent_set_duration (vevent, ical_duration);
    }

  return ical_new;
}

/**
 * @brief Simplify an VEVENT iCal component.
 *
 * @param[in]  vevent          The VEVENT component to simplify.
 * @param[in]  zone            Timezone.
 * @param[out] error           Output of iCal errors or warnings.
 * @param[out] warnings_buffer GString buffer to write warnings to.
 *
 * @return  A newly allocated, simplified VEVENT component.
 */
static icalcomponent *
icalendar_simplify_vevent (icalcomponent *vevent, icaltimezone *zone,
                           gchar **error, GString *warnings_buffer)
{
  icalproperty *error_prop;
  gchar *uid;
  icalcomponent *vevent_simplified;
  icaltimetype original_dtstart, dtstart, dtstamp;
  struct icaldurationtype duration;
  icalproperty *rrule_prop, *rdate_prop, *exdate_prop, *exrule_prop;

  // Only handle VEVENT components
  assert (icalcomponent_isa (vevent) == ICAL_VEVENT_COMPONENT);

  // Check for errors
  icalrestriction_check (vevent);
  error_prop = icalcomponent_get_first_property (vevent,
                                                 ICAL_XLICERROR_PROPERTY);
  if (error_prop)
    {
      if (error)
        *error = g_strdup_printf ("Error in VEVENT: %s",
                                  icalproperty_get_xlicerror (error_prop));
      return NULL;
    }

  // Get mandatory first start time
  original_dtstart = icalcomponent_get_dtstart (vevent);
  if (icaltime_is_null_time (original_dtstart))
    {
      if (error)
        *error = g_strdup_printf ("VEVENT must have a dtstart property");
      return NULL;
    }

  dtstart = icaltime_convert_to_zone (original_dtstart, zone);

  // Get duration or try to calculate it from end time
  duration = icalcomponent_get_duration (vevent);
  if (icaldurationtype_is_null_duration (duration))
    {
      icaltimetype original_dtend;
      original_dtend = icalcomponent_get_dtend (vevent);

      if (icaltime_is_null_time (original_dtend))
        {
          duration = icaldurationtype_null_duration ();
        }
      else
        {
          icaltimetype dtend_zone;

          dtend_zone = icaltime_convert_to_zone (original_dtend, zone);

          duration = icaltime_subtract (dtend_zone, dtstart);
        }
    }

  /*
   * Try to get only the first recurrence rule and ignore any others.
   * Technically there can be multiple ones but behavior is undefined in
   *  the iCalendar specification.
   */
  rrule_prop = icalcomponent_get_first_property (vevent,
                                                 ICAL_RRULE_PROPERTY);

  // Warn about EXRULE being deprecated
  exrule_prop = icalcomponent_get_first_property (vevent,
                                                  ICAL_EXRULE_PROPERTY);
  if (exrule_prop)
    {
      g_string_append_printf (warnings_buffer,
                              "<warning>"
                              "VEVENT contains the deprecated EXRULE property,"
                              " which will be ignored."
                              "</warning>");
    }

  // Create new, simplified VEVENT from collected data.
  vevent_simplified = icalcomponent_new_vevent ();
  icalcomponent_set_dtstart (vevent_simplified, dtstart);
  icalcomponent_set_duration (vevent_simplified, duration);
  if (rrule_prop)
    {
      icalproperty *prop_clone = icalproperty_new_clone (rrule_prop);
      icalcomponent_add_property (vevent_simplified, prop_clone);
    }

  // Simplify and copy RDATE properties
  rdate_prop = icalcomponent_get_first_property (vevent,
                                                 ICAL_RDATE_PROPERTY);
  while (rdate_prop)
    {
      struct icaldatetimeperiodtype old_datetimeperiod, new_datetimeperiod;
      icalproperty *new_rdate;

      old_datetimeperiod = icalproperty_get_rdate (rdate_prop);

      // Reduce period to a simple date or datetime.
      new_datetimeperiod.period = icalperiodtype_null_period ();
      if (icalperiodtype_is_null_period (old_datetimeperiod.period))
        {
          new_datetimeperiod.time
            = icaltime_convert_to_zone (old_datetimeperiod.time, zone);
        }
      else
        {
          new_datetimeperiod.time
            = icaltime_convert_to_zone (old_datetimeperiod.period.start, zone);
        }
      new_rdate = icalproperty_new_rdate (new_datetimeperiod);
      icalcomponent_add_property (vevent_simplified, new_rdate);

      rdate_prop
        = icalcomponent_get_next_property (vevent, ICAL_RDATE_PROPERTY);
    }

  // Copy EXDATE properties
  exdate_prop = icalcomponent_get_first_property (vevent,
                                                  ICAL_EXDATE_PROPERTY);
  while (exdate_prop)
    {
      icaltimetype original_exdate_time, exdate_time;
      icalproperty *prop_clone;

      original_exdate_time = icalproperty_get_exdate (exdate_prop);
      exdate_time
        = icaltime_convert_to_zone (original_exdate_time, zone);

      prop_clone = icalproperty_new_exdate (exdate_time);
      icalcomponent_add_property (vevent_simplified, prop_clone);

      exdate_prop
        = icalcomponent_get_next_property (vevent, ICAL_EXDATE_PROPERTY);
    }

  // Generate UID for event
  uid = gvm_uuid_make ();
  icalcomponent_set_uid (vevent_simplified, uid);
  g_free (uid);
  uid = NULL;

  // Set timestamp
  dtstamp = icaltime_current_time_with_zone (zone);
  icalcomponent_set_dtstamp (vevent_simplified, dtstamp);

  return vevent_simplified;
}

/**
 * @brief Error return for icalendar_from_string.
 */
#define ICAL_RETURN_ERROR(message)              \
  do                                            \
    {                                           \
      if (error)                                \
        *error = message;                       \
      icalcomponent_free (ical_parsed);         \
      icalcomponent_free (ical_new);            \
      g_string_free (warnings_buffer, TRUE);    \
      return NULL;                              \
    }                                           \
  while (0)

/**
 * @brief Creates a new, simplified VCALENDAR component from a string.
 *
 * @param[in]  ical_string  The ical_string to create the component from.
 * @param[in]  zone         Timezone.
 * @param[out] error        Output of iCal errors or warnings.
 *
 * @return  A newly allocated, simplified VCALENDAR component.
 */
icalcomponent *
icalendar_from_string (const char *ical_string, icaltimezone *zone,
                       gchar **error)
{
  icalcomponent *ical_new, *ical_parsed, *timezone_component;
  icalproperty *error_prop;
  GString *warnings_buffer;
  int vevent_count = 0;
  int other_component_count = 0;
  icalcompiter ical_iter;

  // Parse the iCalendar string
  ical_parsed = icalcomponent_new_from_string (ical_string);
  if (ical_parsed == NULL)
    {
      if (error)
        *error = g_strdup_printf ("Could not parse iCalendar string");
      return NULL;
    }

  // Check for errors
  icalrestriction_check (ical_parsed);
  error_prop = icalcomponent_get_first_property (ical_parsed,
                                                 ICAL_XLICERROR_PROPERTY);
  if (error_prop)
    {
      if (error)
        *error = g_strdup_printf ("Error in root component: %s",
                                  icalproperty_get_xlicerror (error_prop));
      icalcomponent_free (ical_parsed);
      return NULL;
    }

  // Create buffers and new VCALENDAR
  warnings_buffer = g_string_new ("");

  ical_new = icalcomponent_new_vcalendar ();
  icalcomponent_add_property (ical_new, icalproperty_new_version ("2.0"));
  icalcomponent_add_property (ical_new,
                              icalproperty_new_prodid (GVM_PRODID));

  timezone_component
    = icalcomponent_new_clone (icaltimezone_get_component (zone));
  icalcomponent_add_component (ical_new, timezone_component);

  switch (icalcomponent_isa (ical_parsed))
    {
      case ICAL_NO_COMPONENT:
        // The text must contain valid iCalendar component
        ICAL_RETURN_ERROR
            (g_strdup_printf ("String contains no iCalendar component"));
        break;
      case ICAL_XROOT_COMPONENT:
      case ICAL_VCALENDAR_COMPONENT:
        // Check multiple components
        ical_iter = icalcomponent_begin_component (ical_parsed,
                                                   ICAL_ANY_COMPONENT);
        icalcomponent *subcomp;
        while ((subcomp = icalcompiter_deref (&ical_iter)))
          {
            icalcomponent *new_vevent;
            switch (icalcomponent_isa (subcomp))
              {
                case ICAL_VEVENT_COMPONENT:
                  // Copy and simplify only the first VEVENT, ignoring all
                  //  following ones.
                  if (vevent_count == 0)
                    {
                      new_vevent = icalendar_simplify_vevent
                                      (subcomp,
                                       zone,
                                       error,
                                       warnings_buffer);
                      if (new_vevent == NULL)
                        ICAL_RETURN_ERROR (*error);
                      icalcomponent_add_component (ical_new, new_vevent);
                    }
                  vevent_count ++;
                  break;
                case ICAL_VTIMEZONE_COMPONENT:
                  // Timezones are collected separately
                  break;
                case ICAL_VJOURNAL_COMPONENT:
                case ICAL_VTODO_COMPONENT:
                  // VJOURNAL and VTODO components are ignored
                  other_component_count ++;
                  break;
                default:
                  // Unexpected components
                  ICAL_RETURN_ERROR
                      (g_strdup_printf ("Unexpected component type: %s",
                                        icalcomponent_kind_to_string
                                            (icalcomponent_isa (subcomp))));
              }
            icalcompiter_next (&ical_iter);
          }

        if (vevent_count == 0)
          {
            ICAL_RETURN_ERROR
                (g_strdup_printf ("iCalendar string must contain a VEVENT"));
          }
        else if (vevent_count > 1)
          {
            g_string_append_printf (warnings_buffer,
                                    "<warning>"
                                    "iCalendar contains %d VEVENT components"
                                    " but only the first one will be used"
                                    "</warning>",
                                    vevent_count);
          }

        if (other_component_count)
          {
            g_string_append_printf (warnings_buffer,
                                    "<warning>"
                                    "iCalendar contains %d VTODO and/or"
                                    " VJOURNAL component(s) which will be"
                                    " ignored"
                                    "</warning>",
                                    other_component_count);
          }
        break;
      case ICAL_VEVENT_COMPONENT:
        {
          icalcomponent *new_vevent;

          new_vevent = icalendar_simplify_vevent (ical_parsed,
                                                  zone,
                                                  error,
                                                  warnings_buffer);
          if (new_vevent == NULL)
            ICAL_RETURN_ERROR (*error);
          icalcomponent_add_component (ical_new, new_vevent);
        }
        break;
      default:
        ICAL_RETURN_ERROR
            (g_strdup_printf ("iCalendar string must be a VCALENDAR or VEVENT"
                              " component or consist of multiple elements."));
        break;
    }

  icalcomponent_free (ical_parsed);

  if (error)
    *error = g_string_free (warnings_buffer, FALSE);
  else
    g_string_free (warnings_buffer, TRUE);

  return ical_new;
}

/**
 * @brief Approximate the recurrence of a VCALENDAR as classic schedule data.
 * The VCALENDAR must have simplified with icalendar_from_string for this to
 *  work reliably.
 *
 * @param[in]  vcalendar       The VCALENDAR component to get the data from.
 * @param[out] period          Output of the period in seconds.
 * @param[out] period_months   Output of the period in months.
 * @param[out] byday_mask      Output of the GVM byday mask.
 *
 * @return 0 success, 1 invalid vcalendar.
 */
int
icalendar_approximate_rrule_from_vcalendar (icalcomponent *vcalendar,
                                            time_t *period,
                                            time_t *period_months,
                                            int *byday_mask)
{
  icalcomponent *vevent;
  icalproperty *rrule_prop;


  assert (period);
  assert (period_months);
  assert (byday_mask);

  *period = 0;
  *period_months = 0;
  *byday_mask = 0;

  // Component must be a VCALENDAR
  if (vcalendar == NULL
      || icalcomponent_isa (vcalendar) != ICAL_VCALENDAR_COMPONENT)
    return 1;

  // Process only the first VEVENT
  // Others should be removed by icalendar_from_string
  vevent = icalcomponent_get_first_component (vcalendar,
                                              ICAL_VEVENT_COMPONENT);
  if (vevent == NULL)
    return -1;

  // Process only first RRULE.
  rrule_prop = icalcomponent_get_first_property (vevent,
                                                 ICAL_RRULE_PROPERTY);
  if (rrule_prop)
    {
      struct icalrecurrencetype recurrence;
      recurrence = icalproperty_get_rrule (rrule_prop);
      int array_pos;

      // Get period or period_months
      switch (recurrence.freq)
        {
          case ICAL_YEARLY_RECURRENCE:
            *period_months = recurrence.interval * 12;
            break;
          case ICAL_MONTHLY_RECURRENCE:
            *period_months = recurrence.interval;
            break;
          case ICAL_WEEKLY_RECURRENCE:
            *period = recurrence.interval * 604800;
            break;
          case ICAL_DAILY_RECURRENCE:
            *period = recurrence.interval * 86400;
            break;
          case ICAL_HOURLY_RECURRENCE:
            *period = recurrence.interval * 3600;
            break;
          case ICAL_MINUTELY_RECURRENCE:
            *period = recurrence.interval * 60;
            break;
          case ICAL_SECONDLY_RECURRENCE:
            *period = recurrence.interval;
          case ICAL_NO_RECURRENCE:
            break;
          default:
            return -1;
        }

      /*
       * Try to approximate byday mask
       * - libical days start at 1 for Sunday.
       * - GVM byday mask bit index starts at 0 for Monday -> Sunday = 6
       */
      array_pos = 0;
      while (recurrence.by_day[array_pos] != ICAL_RECURRENCE_ARRAY_MAX)
        {
          int ical_day = icalrecurrencetype_day_day_of_week
                            (recurrence.by_day[array_pos]);
          int mask_bit = -1;

          if (ical_day == 1)
            mask_bit = 6;
          else if (ical_day)
            mask_bit = ical_day - 2;

          if (mask_bit != -1)
            {
              *byday_mask |= (1 << mask_bit);
            }
          array_pos ++;
        }
    }

  return 0;
}

/**
 * @brief Collect the times of EXDATE or RDATE properties from an VEVENT.
 * The returned GPtrArray will contain pointers to icaltimetype structs, which
 *  will be freed with g_ptr_array_free.
 *
 * @param[in]  vevent  The VEVENT component to collect times.
 * @param[in]  type    The property to get the times from.
 *
 * @return  GPtrArray with pointers to collected times or NULL on error.
 */
static GPtrArray*
icalendar_times_from_vevent (icalcomponent *vevent, icalproperty_kind type)
{
  GPtrArray* times;
  icalproperty *date_prop;

  if (icalcomponent_isa (vevent) != ICAL_VEVENT_COMPONENT
      || (type != ICAL_EXDATE_PROPERTY && type != ICAL_RDATE_PROPERTY))
    return NULL;

  times = g_ptr_array_new_with_free_func (g_free);

  date_prop = icalcomponent_get_first_property (vevent, type);
  while (date_prop)
    {
      icaltimetype *time;
      time = g_malloc0 (sizeof (icaltimetype));
      if (type == ICAL_EXDATE_PROPERTY)
        {
          *time = icalproperty_get_exdate (date_prop);
        }
      else if (type == ICAL_RDATE_PROPERTY)
        {
          struct icaldatetimeperiodtype datetimeperiod;
          datetimeperiod = icalproperty_get_rdate (date_prop);
          // Assume periods have been converted to date or datetime
          *time = datetimeperiod.time;
        }
      g_ptr_array_insert (times, -1, time);
      date_prop = icalcomponent_get_next_property (vevent, type);
    }

  return times;
}

/**
 * @brief  Tests if an icaltimetype matches one in a GPtrArray.
 * When an icaltimetype is a date, only the date must match, otherwise both
 *  date and time must match.
 *
 * @param[in]  time         The icaltimetype to try to find a match of.
 * @param[in]  times_array  Array of pointers to check for a matching time.
 *
 * @return  Whether a match was found.
 */
static gboolean
icalendar_time_matches_array (icaltimetype time, GPtrArray *times_array)
{
  gboolean found = FALSE;
  int index;

  if (times_array == NULL)
    return FALSE;

  for (index = 0;
       found == FALSE && index < times_array->len;
       index++)
    {
      int compare_result;
      icaltimetype *array_time = g_ptr_array_index (times_array, index);

      if (array_time->is_date)
        compare_result = icaltime_compare_date_only (time, *array_time);
      else
        compare_result = icaltime_compare (time, *array_time);

      if (compare_result == 0)
        found = TRUE;
    }
  return found;
}

/**
 * @brief  Get the next or previous time from a list of RDATEs.
 *
 * @param[in]  rdates         The list of RDATEs.
 * @param[in]  tz             The icaltimezone to use.
 * @param[in]  ref_time_ical  The reference time (usually the current time).
 * @param[in]  periods_offset 0 for next, -1 for previous from/before reference.
 *
 * @return  The next or previous time as time_t.
 */
static time_t
icalendar_next_time_from_rdates (GPtrArray *rdates,
                                 icaltimetype ref_time_ical,
                                 icaltimezone *tz,
                                 int periods_offset)
{
  int index;
  time_t ref_time, closest_time;
  int old_diff;

  closest_time = 0;
  ref_time = icaltime_as_timet_with_zone (ref_time_ical, tz);
  if (periods_offset < 0)
    old_diff = INT_MIN;
  else
    old_diff = INT_MAX;

  for (index = 0; index < rdates->len; index++)
    {
      icaltimetype *iter_time_ical;
      time_t iter_time;
      int time_diff;

      iter_time_ical = g_ptr_array_index (rdates, index);
      iter_time = icaltime_as_timet_with_zone (*iter_time_ical, tz);
      time_diff = iter_time - ref_time;

      // Cases: previous (offset -1): latest before reference
      //        next     (offset  0): earliest after reference
      if ((periods_offset == -1 && time_diff < 0 && time_diff > old_diff)
          || (periods_offset == 0 && time_diff > 0 && time_diff < old_diff))
        {
          closest_time = iter_time;
          old_diff = time_diff;
        }
    }

  return closest_time;
}

/**
 * @brief Calculate the next time of a recurrence
 *
 * @param[in]  recurrence     The recurrence rule to evaluate.
 * @param[in]  dtstart        The start time of the recurrence.
 * @param[in]  reference_time The reference time (usually the current time).
 * @param[in]  tz             The icaltimezone to use.
 * @param[in]  exdates        GList of EXDATE dates or datetimes to skip.
 * @param[in]  rdates         GList of RDATE datetimes to include.
 * @param[in]  periods_offset 0 for next, -1 for previous from/before reference.
 *
 * @return  The next time.
 */
static time_t
icalendar_next_time_from_recurrence (struct icalrecurrencetype recurrence,
                                     icaltimetype dtstart,
                                     icaltimetype reference_time,
                                     icaltimezone *tz,
                                     GPtrArray *exdates,
                                     GPtrArray *rdates,
                                     int periods_offset)
{
  icalrecur_iterator *recur_iter;
  icaltimetype recur_time, prev_time, next_time;
  time_t rdates_time;

  // Start iterating over rule-based times
  recur_iter = icalrecur_iterator_new (recurrence, dtstart);
  recur_time = icalrecur_iterator_next (recur_iter);

  if (icaltime_is_null_time (recur_time))
    {
      // Use DTSTART if there are no recurrence rule times
      if (icaltime_compare (dtstart, reference_time) < 0)
        {
          prev_time = dtstart;
          next_time = icaltime_null_time ();
        }
      else
        {
          prev_time = icaltime_null_time ();
          next_time = dtstart;
        }
    }
  else
    {
      /* Handle rule-based recurrence times:
       * Get the first rule-based recurrence time, skipping ahead in case
       *  DTSTART is excluded by EXDATEs.  */

      while (icaltime_is_null_time (recur_time) == FALSE
             && icalendar_time_matches_array (recur_time, exdates))
        {
          recur_time = icalrecur_iterator_next (recur_iter);
        }

      // Set the first recur_time as either the previous or next time.
      if (icaltime_compare (recur_time, reference_time) < 0)
        {
          prev_time = recur_time;
        }
      else
        {
          prev_time = icaltime_null_time ();
        }

      /* Iterate over rule-based recurrences up to first time after
       * reference time */
      while (icaltime_is_null_time (recur_time) == FALSE
             && icaltime_compare (recur_time, reference_time) < 0)
        {
          if (icalendar_time_matches_array (recur_time, exdates) == FALSE)
            prev_time = recur_time;

          recur_time = icalrecur_iterator_next (recur_iter);
        }

      // Skip further ahead if last recurrence time is in EXDATEs
      while (icaltime_is_null_time (recur_time) == FALSE
             && icalendar_time_matches_array (recur_time, exdates))
        {
          recur_time = icalrecur_iterator_next (recur_iter);
        }

      // Select last recur_time as the next_time
      next_time = recur_time;
    }

  // Get time from RDATEs
  rdates_time = icalendar_next_time_from_rdates (rdates, reference_time, tz,
                                                 periods_offset);

  // Select appropriate time as the RRULE time, compare it to the RDATEs time
  //  and return the appropriate time.
  if (periods_offset == -1)
    {
      time_t rrule_time;

      rrule_time = icaltime_as_timet_with_zone (prev_time, tz);
      if (rdates_time == 0 || rrule_time - rdates_time > 0)
        return rrule_time;
      else
        return rdates_time;
    }
  else
    {
      time_t rrule_time;

      rrule_time = icaltime_as_timet_with_zone (next_time, tz);
      if (rdates_time == 0 || rrule_time - rdates_time < 0)
        return rrule_time;
      else
        return rdates_time;
    }
}

/**
 * @brief  Get the next or previous due time from a VCALENDAR component.
 * The VCALENDAR must have simplified with icalendar_from_string for this to
 *  work reliably.
 *
 * @param[in]  vcalendar       The VCALENDAR component to get the time from.
 * @param[in]  default_tzid    Timezone id to use if none is set in the iCal.
 * @param[in]  periods_offset  0 for next, -1 for previous from/before now.
 *
 * @return The next or previous time as a time_t.
 */
time_t
icalendar_next_time_from_vcalendar (icalcomponent *vcalendar,
                                    const char *default_tzid,
                                    int periods_offset)
{
  icalcomponent *vevent;
  icaltimetype dtstart, dtstart_with_tz, ical_now;
  icaltimezone *tz;
  icalproperty *rrule_prop;
  struct icalrecurrencetype recurrence;
  GPtrArray *exdates, *rdates;
  time_t next_time = 0;

  // Only offsets -1 and 0 will work properly
  if (periods_offset < -1 || periods_offset > 0)
    return 0;

  // Component must be a VCALENDAR
  if (vcalendar == NULL
      || icalcomponent_isa (vcalendar) != ICAL_VCALENDAR_COMPONENT)
    return 0;

  // Process only the first VEVENT
  // Others should be removed by icalendar_from_string
  vevent = icalcomponent_get_first_component (vcalendar,
                                              ICAL_VEVENT_COMPONENT);
  if (vevent == NULL)
    return 0;

  // Get start time and timezone
  dtstart = icalcomponent_get_dtstart (vevent);
  if (icaltime_is_null_time (dtstart))
    return 0;

  tz = (icaltimezone*) icaltime_get_timezone (dtstart);
  if (tz == NULL)
    {
      tz = icalendar_timezone_from_string (default_tzid);
      if (tz == NULL)
        tz = icaltimezone_get_utc_timezone ();
    }

  dtstart_with_tz = dtstart;
  // Set timezone in case the original DTSTART did not have any set.
  icaltime_set_timezone (&dtstart_with_tz, tz);

  // Get current time
  ical_now = icaltime_current_time_with_zone (tz);
  // Set timezone explicitly because icaltime_current_time_with_zone doesn't.
  icaltime_set_timezone (&ical_now, tz);
  if (ical_now.zone == NULL)
    {
      ical_now.zone = tz;
    }

  // Get EXDATEs and RDATEs
  exdates = icalendar_times_from_vevent (vevent, ICAL_EXDATE_PROPERTY);
  rdates = icalendar_times_from_vevent (vevent, ICAL_RDATE_PROPERTY);

  // Try to get the recurrence from the RRULE property
  rrule_prop = icalcomponent_get_first_property (vevent, ICAL_RRULE_PROPERTY);
  if (rrule_prop)
    recurrence = icalproperty_get_rrule (rrule_prop);
  else
    icalrecurrencetype_clear (&recurrence);

  // Calculate next time.
  next_time = icalendar_next_time_from_recurrence (recurrence,
                                                   dtstart_with_tz,
                                                   ical_now, tz,
                                                   exdates, rdates,
                                                   periods_offset);

  // Cleanup
  g_ptr_array_free (exdates, TRUE);
  g_ptr_array_free (rdates, TRUE);

  return next_time;
}

/**
 * @brief  Get the next or previous due time from a VCALENDAR string.
 * The string must be a VCALENDAR simplified with icalendar_from_string for
 *  this to work reliably.
 *
 * @param[in]  ical_string     The VCALENDAR string to get the time from.
 * @param[in]  default_tzid    Timezone id to use if none is set in the iCal.
 * @param[in]  periods_offset  0 for next, -1 for previous from/before now.
 *
 * @return The next or previous time as a time_t.
 */
time_t
icalendar_next_time_from_string (const char *ical_string,
                                 const char *default_tzid,
                                 int periods_offset)
{
  time_t next_time;
  icalcomponent *ical_parsed;

  ical_parsed = icalcomponent_new_from_string (ical_string);
  next_time = icalendar_next_time_from_vcalendar (ical_parsed, default_tzid,
                                                  periods_offset);
  icalcomponent_free (ical_parsed);
  return next_time;
}

/**
 * @brief  Get the duration VCALENDAR component.
 * The VCALENDAR must have simplified with icalendar_from_string for this to
 *  work reliably.
 *
 * @param[in]  vcalendar       The VCALENDAR component to get the time from.
 *
 * @return The duration in seconds.
 */
int
icalendar_duration_from_vcalendar (icalcomponent *vcalendar)
{
  icalcomponent *vevent;
  struct icaldurationtype duration;

  // Component must be a VCALENDAR
  if (vcalendar == NULL
      || icalcomponent_isa (vcalendar) != ICAL_VCALENDAR_COMPONENT)
    return 0;

  // Process only the first VEVENT
  // Others should be removed by icalendar_from_string
  vevent = icalcomponent_get_first_component (vcalendar,
                                              ICAL_VEVENT_COMPONENT);
  if (vevent == NULL)
    return 0;

  // Get the duration
  duration = icalcomponent_get_duration (vevent);

  // Convert to time_t
  return icaldurationtype_as_int (duration);
}

/**
 * @brief  Get the first time from a VCALENDAR component.
 * The VCALENDAR must have simplified with icalendar_from_string for this to
 *  work reliably.
 *
 * @param[in]  vcalendar       The VCALENDAR component to get the time from.
 * @param[in]  default_tz      Timezone to use if none is set in the iCal.
 *
 * @return The first time as a time_t.
 */
time_t
icalendar_first_time_from_vcalendar (icalcomponent *vcalendar,
                                     icaltimezone *default_tz)
{
  icalcomponent *vevent;
  icaltimetype dtstart;
  icaltimezone *tz;

  // Component must be a VCALENDAR
  if (vcalendar == NULL
      || icalcomponent_isa (vcalendar) != ICAL_VCALENDAR_COMPONENT)
    return 0;

  // Process only the first VEVENT
  // Others should be removed by icalendar_from_string
  vevent = icalcomponent_get_first_component (vcalendar,
                                              ICAL_VEVENT_COMPONENT);
  if (vevent == NULL)
    return 0;

  // Get start time and timezone
  dtstart = icalcomponent_get_dtstart (vevent);
  if (icaltime_is_null_time (dtstart))
    return 0;

  tz = (icaltimezone*) icaltime_get_timezone (dtstart);
  if (tz == NULL)
    tz = default_tz;

  // Convert to time_t
  return icaltime_as_timet_with_zone (dtstart, tz);
}

/**
 * @brief Cleans up a hosts string, removing extra zeroes from IPv4 addresses.
 *
 * @param[in]  hosts  The hosts string to clean.
 *
 * @return  The newly allocated, cleaned up hosts string.
 */
gchar *
clean_hosts_string (const char *hosts)
{
  gchar **hosts_split, **item;
  GString *new_hosts;
  GRegex *ipv4_match_regex, *ipv4_replace_regex;

  if (hosts == NULL)
    return NULL;

  /*
   * Regular expression for matching candidates for IPv4 addresses
   * (four groups of digits separated by a dot "."),
   * with optional extensions for ranges:
   * - Another IP address candidate, separated with a hyphen "-"
   *   (e.g. "192.168.123.001-192.168.123.005)"
   * - A final group of digits, separated with a hyphen "-"
   *   (short form address range, e.g. "192.168.123.001-005)
   * - A final group of digits, separated with a slash "-"
   *   (CIDR notation, e.g. "192.168.123.001/027)
   */
  ipv4_match_regex
    = g_regex_new ("^[0-9]+(?:\\.[0-9]+){3}"
                   "(?:\\/[0-9]+|-[0-9]+(?:(?:\\.[0-9]+){3})?)?$",
                   0, 0, NULL);
  /*
   * Regular expression matching leading zeroes in groups of digits
   * separated by dots or other characters.
   * First line matches zeroes before non-zero numbers, e.g. "000" in "000120"
   * Second line matches groups of all zeroes except one, e.g. "00" in "000"
   */
  ipv4_replace_regex 
    = g_regex_new ("(?<=\\D|^)(0+)(?=(?:(?:[1-9]\\d*)(?:\\D|$)))"
                   "|(?<=\\D|^)(0+)(?=0(?:\\D|$))",
                   0, 0, NULL);
  new_hosts = g_string_new ("");

  hosts_split = g_strsplit (hosts, ",", -1);
  item = hosts_split;
  while (*item)
    {
      g_strstrip (*item);
      if (g_regex_match (ipv4_match_regex, *item, 0, 0))
        {
          // IPv4 address, address range or CIDR notation
          gchar *new_item;
          /* Remove leading zeroes in each group of digits by replacing them
           * with empty strings,
           * e.g. "000.001.002.003-004" becomes "0.1.2.3-4"
           */
          new_item = g_regex_replace (ipv4_replace_regex,
                                      *item, -1, 0, "", 0, NULL);
          g_string_append (new_hosts, new_item);
          g_free (new_item);
        }
      else
        g_string_append (new_hosts, *item);

      if (*(item + 1))
        g_string_append (new_hosts, ", ");
      item++;
    }
  g_strfreev (hosts_split);

  g_regex_unref (ipv4_match_regex);
  g_regex_unref (ipv4_replace_regex);
  
  return g_string_free (new_hosts, FALSE);
}
