/* OpenVAS Manager
 * $Id$
 * Description: Module for OpenVAS Manager: Manage library utilities.
 *
 * Authors:
 * Matthew Mundell <matthew.mundell@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2014 Greenbone Networks GmbH
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
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

#include "manage_utils.h"

#include <assert.h>

#include <openvas/base/openvas_hosts.h>

/**
 * @file  manage_utils.c
 * @brief The OpenVAS Manager management library.
 *
 * Utilities used by the manage library that do not depend on anything.
 */

/**
 * @brief Get the offset from UTC of a timezone at a particular time.
 *
 * @param[in]  zone  Timezone, or NULL for UTC.
 * @param[in]  time  Time.
 *
 * @return Seconds east of UTC.
 */
long
time_offset (const char *zone, time_t time)
{
  gchar *tz;
  struct tm *time_broken;
  int mins;
  char buf[100];

  if (zone == NULL || strcmp (zone, "UTC") == 0)
    return 0;

  /* Store current TZ. */
  tz = getenv ("TZ") ? g_strdup (getenv ("TZ")) : NULL;

  if (setenv ("TZ", zone, 1) == -1)
    {
      g_warning ("%s: Failed to switch to timezone", __FUNCTION__);
      if (tz != NULL)
        setenv ("TZ", tz, 1);
      g_free (tz);
      return 0;
    }

  tzset ();

  time_broken = localtime (&time);
  if (strftime (buf, 100, "%z", time_broken) == 0)
    {
      g_warning ("%s: Failed to format timezone", __FUNCTION__);
      if (tz != NULL)
        setenv ("TZ", tz, 1);
      g_free (tz);
      return 0;
    }

  if (strlen (buf) >= 3)
    {
      mins = atoi (buf);
      mins /= 100;
      mins *= 60;
      mins += atoi (buf + 3);
    }
  else
    mins = 0;

  /* Revert to stored TZ. */
  if (tz)
    {
      if (setenv ("TZ", tz, 1) == -1)
        {
          g_warning ("%s: Failed to switch to original TZ", __FUNCTION__);
          g_free (tz);
          return mins * 60;
        }
    }
  else
    unsetenv ("TZ");

  g_free (tz);
  return mins * 60;
}

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
  struct tm *now_broken;

  if (zone == NULL)
    return 0;

  /* Store current TZ. */
  tz = getenv ("TZ") ? g_strdup (getenv ("TZ")) : NULL;

  if (setenv ("TZ", zone, 1) == -1)
    {
      g_warning ("%s: Failed to switch to timezone", __FUNCTION__);
      if (tz != NULL)
        setenv ("TZ", tz, 1);
      g_free (tz);
      return 0;
    }

  tzset ();

  time (&now);
  now_broken = localtime (&now);
  if (setenv ("TZ", "UTC", 1) == -1)
    {
      g_warning ("%s: Failed to switch to UTC", __FUNCTION__);
      if (tz != NULL)
        setenv ("TZ", tz, 1);
      g_free (tz);
      return 0;
    }
  tzset ();
  offset = - (now - mktime (now_broken));

  /* Revert to stored TZ. */
  if (tz)
    {
      if (setenv ("TZ", tz, 1) == -1)
        {
          g_warning ("%s: Failed to switch to original TZ", __FUNCTION__);
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
 * @brief Code fragment for months_between.
 */
#define MONTHS_WITHIN_YEAR()                                 \
  (same_month                                                \
    ? 0                                                      \
    : ((broken2->tm_mon - broken1.tm_mon)                    \
       - (same_day                                           \
           ? (same_hour                                      \
               ? (same_minute                                \
                   ? (same_second                            \
                       ? 0                                   \
                       : (broken2->tm_sec < broken1.tm_sec)) \
                   : (broken2->tm_min < broken1.tm_min))     \
               : (broken2->tm_hour < broken1.tm_hour))       \
           : (broken2->tm_mday < broken1.tm_mday))))

/**
 * @brief Count number of full months between two times.
 *
 * There are two full months between 0h00.00 1 February 2010 and 0h00.00 1
 * April 2010.  There is one full month between 0h00.00 1 February 2010 and
 * 23h59.59 31 March 2010.
 *
 * @param[in]  time1  Earlier time.
 * @param[in]  time2  Later time.
 *
 * @return Number of full months between time1 and time2.
 */
time_t
months_between (time_t time1, time_t time2)
{
  struct tm broken1, *broken2;
  int same_year, same_month, same_day, same_hour, same_minute, same_second;
  int month1_less, day1_less, hour1_less, minute1_less;
  int second1_less;

  assert (time1 <= time2);

  localtime_r (&time1, &broken1);
  broken2 = localtime (&time2);

  same_year = (broken1.tm_year == broken2->tm_year);
  same_month = (broken1.tm_mon == broken2->tm_mon);
  same_day = (broken1.tm_mday == broken2->tm_mday);
  same_hour = (broken1.tm_hour == broken2->tm_hour);
  same_minute = (broken1.tm_min == broken2->tm_min);
  same_second = (broken1.tm_sec == broken2->tm_sec);

  month1_less = (broken1.tm_mon < broken2->tm_mon);
  day1_less = (broken1.tm_mday < broken2->tm_mday);
  hour1_less = (broken1.tm_hour < broken2->tm_hour);
  minute1_less = (broken1.tm_min < broken2->tm_min);
  second1_less = (broken1.tm_sec < broken2->tm_sec);

  return
    (same_year
      ? MONTHS_WITHIN_YEAR ()
      : ((month1_less
          || (same_month
              && (day1_less
                  || (same_day
                      && (hour1_less
                          || (same_hour
                              && (minute1_less
                                  || (same_minute
                                      && second1_less))))))))
         ? (/* time1 is earlier in the year than time2. */
            ((broken2->tm_year - broken1.tm_year) * 12)
            + MONTHS_WITHIN_YEAR ())
         : (/* time1 is later in the year than time2. */
            ((broken2->tm_year - broken1.tm_year - 1) * 12)
            /* Months left in year of time1. */
            + (11 - broken1.tm_mon)
            /* Months past in year of time2. */
            + broken2->tm_mon
            /* Possible extra month due to position in month of each time. */
            + (day1_less
               || (same_day
                   && (hour1_less
                       || (same_hour
                           && (minute1_less
                               || (same_minute
                                   && second1_less)))))))));
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
  struct tm *broken = localtime (&time);
  broken->tm_mon += months;
  return mktime (broken);
}

/**
 * @brief Calculate the next time from now given a start time and a period.
 *
 * @param[in] first         The first time.
 * @param[in] period        The period in seconds.
 * @param[in] period_months The period in months.
 * @param[in] timezone      The timezone to use.
 * @param[in] periods_offset  Number of periods to offset.
 *                            e.g. 0 = next time, -1 current/last time
 *
 * @return  the next time a schedule with the given times is due.
 */
time_t
next_time (time_t first, int period, int period_months, const char* timezone,
           int periods_offset)
{
  int periods_diff;
  time_t now = time (NULL);
  long offset_diff;
  if (timezone)
    {
      long first_offset_val, current_offset_val;
      first_offset_val = time_offset (timezone, first);
      current_offset_val = current_offset (timezone);
      offset_diff = current_offset_val - first_offset_val;
    }
  else
    {
      offset_diff = 0;
    }

  if (first >= now)
    {
      return first;
    }
  else if (period > 0)
    {
      return first
              + ((((now - first + offset_diff) / period) + 1 + periods_offset)
                 * period)
              - offset_diff;
    }
  else if (period_months > 0)
    {
      time_t ret;
      gchar *tz;

      /* Store current TZ. */
      tz = getenv ("TZ") ? g_strdup (getenv ("TZ")) : NULL;

      if (setenv ("TZ", timezone ? timezone : "UTC", 1) == -1)
        {
          g_warning ("%s: Failed to switch to timezone", __FUNCTION__);
          if (tz != NULL)
            setenv ("TZ", tz, 1);
          g_free (tz);
          return 0;
        }

      tzset ();

      /* Calculate new time */
      periods_diff = months_between (first, now) / period_months;
      periods_diff += periods_offset;
      ret = add_months (first, (periods_diff + 1) * period_months);
      ret -= offset_diff;

      /* Revert to stored TZ. */
      if (tz)
        {
          if (setenv ("TZ", tz, 1) == -1)
            {
              g_warning ("%s: Failed to switch to original TZ", __FUNCTION__);
              g_free (tz);
            }
        }
      else
        unsetenv ("TZ");

      g_free (tz);

      return ret;
    }
  else if (periods_offset == -1)
    {
      return first;
    }
  return 0;
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
  openvas_hosts_t *hosts;

  hosts = openvas_hosts_new_with_max (given_hosts, max_hosts);
  if (hosts == NULL)
    return -1;

  if (exclude_hosts)
    /* Don't resolve hostnames in excluded hosts. */
    openvas_hosts_exclude (hosts, exclude_hosts, 0);

  count = openvas_hosts_count (hosts);
  openvas_hosts_free (hosts);

  return count;
}

/**
 * @brief Get the minimum severity for a severity level and class.
 *
 * @param[in] level  The name of the severity level.
 * @param[in] class  The severity class, NULL to get from current user setting.
 *
 * @return The minimum severity.
 */
double
level_min_severity (const char *level, const char *class)
{
  if (strcasecmp (level, "Log") == 0)
    return SEVERITY_LOG;
  else if (strcasecmp (level, "False Positive") == 0)
    return SEVERITY_FP;
  else if (strcasecmp (level, "Debug") == 0)
    return SEVERITY_DEBUG;
  else if (strcasecmp (level, "Error") == 0)
    return SEVERITY_ERROR;
  else if (strcasecmp (class, "classic") == 0)
    {
      if (strcasecmp (level, "high") == 0)
        return 5.1;
      else if (strcasecmp (level, "medium") == 0)
        return 2.1;
      else if (strcasecmp (level, "low") == 0)
        return 0.1;
      else
        return SEVERITY_UNDEFINED;
    }
  else if (strcasecmp (class, "pci-dss") == 0)
    {
      if (strcasecmp (level, "high") == 0)
        return 4.0;
      else
        return SEVERITY_UNDEFINED;
    }
  else
    {
      /* NIST/BSI. */
      if (strcasecmp (level, "high") == 0)
        return 7.0;
      else if (strcasecmp (level, "medium") == 0)
        return 4.0;
      else if (strcasecmp (level, "low") == 0)
        return 0.1;
      else
        return SEVERITY_UNDEFINED;
    }
}

/**
 * @brief Get the minimum severity for a severity level and class.
 *
 * @param[in] level  The name of the severity level.
 * @param[in] class  The severity class.
 *
 * @return The minimum severity.
 */
double
level_max_severity (const char *level, const char *class)
{
  if (strcasecmp (level, "Log") == 0)
    return SEVERITY_LOG;
  else if (strcasecmp (level, "False Positive") == 0)
    return SEVERITY_FP;
  else if (strcasecmp (level, "Debug") == 0)
    return SEVERITY_DEBUG;
  else if (strcasecmp (level, "Error") == 0)
    return SEVERITY_ERROR;
  else if (strcasecmp (class, "classic") == 0)
    {
      if (strcasecmp (level, "high") == 0)
        return 10.0;
      else if (strcasecmp (level, "medium") == 0)
        return 5.0;
      else if (strcasecmp (level, "low") == 0)
        return 2.0;
      else
        return SEVERITY_UNDEFINED;
    }
  else if (strcasecmp (class, "pci-dss") == 0)
    {
      if (strcasecmp (level, "high") == 0)
        return 10.0;
      else
        return SEVERITY_UNDEFINED;
    }
  else
    {
      /* NIST/BSI. */
      if (strcasecmp (level, "high") == 0)
        return 10.0;
      else if (strcasecmp (level, "medium") == 0)
        return 6.9;
      else if (strcasecmp (level, "low") == 0)
        return 3.9;
      else
        return SEVERITY_UNDEFINED;
    }
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

  return (strcasecmp (type, "agent") == 0)
         || (strcasecmp (type, "alert") == 0)
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
         || (strcasecmp (type, "slave") == 0)
         || (strcasecmp (type, "tag") == 0)
         || (strcasecmp (type, "target") == 0)
         || (strcasecmp (type, "task") == 0)
         || (strcasecmp (type, "user") == 0);
}
