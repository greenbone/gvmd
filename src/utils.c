/* OpenVAS Manager
 * $Id$
 * Description: OpenVAS Manager: General utilities.
 *
 * Authors:
 * Matthew Mundell <matthew.mundell@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2016 Greenbone Networks GmbH
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

/* This is so that time.h includes strptime. */
#define _XOPEN_SOURCE

#include "utils.h"

#include <errno.h>
#include <glib.h>
#include <stdlib.h>
#include <string.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"


/* Sleep. */

/**
 * @brief Sleep for some number of microseconds, handling interrupts.
 *
 * @param[in] microseconds  Number of microseconds.
 *
 * @return 0 success, -1 error (with errno set).
 */
int
openvas_usleep (unsigned int microseconds)
{
  struct timespec a, b, *requested, *remaining;
  int ret;

  requested = &a;
  remaining = &b;

  requested->tv_sec = microseconds / 1000000;
  requested->tv_nsec = (microseconds % 1000000) * 1000;

  while ((ret = nanosleep (requested, remaining)) && (errno == EINTR))
    {
      struct timespec *temp;
      temp = requested;
      requested = remaining;
      remaining = temp;
    }
  if (ret)
    return -1;
  return 0;
}

/**
 * @brief Sleep for some number of seconds, handling interrupts.
 *
 * @param[in] seconds  Number of seconds.
 *
 * @return 0 success, -1 error (with errno set).
 */
int
openvas_sleep (unsigned int seconds)
{
  return openvas_usleep (seconds * 1000000);
}


/* Time. */

/**
 * @brief Convert a UTC time into seconds since epoch.
 *
 * @param[in]  format     Format of time.
 * @param[in]  text_time  Time as text.
 *
 * @return Time since epoch.  0 on error.
 */
int
parse_utc_time (const char *format, const char *text_time)
{
  int epoch_time;
  struct tm tm;
  gchar *tz;

  /* Scanner sends UTC in ctime format: "Wed Jun 30 21:49:08 1993". */

  /* Store current TZ. */
  tz = getenv ("TZ") ? g_strdup (getenv ("TZ")) : NULL;

  if (setenv ("TZ", "UTC", 1) == -1)
    {
      g_warning ("%s: Failed to switch to UTC", __FUNCTION__);
      if (tz != NULL)
        setenv ("TZ", tz, 1);
      g_free (tz);
      return 0;
    }

  g_debug ("%s: text_time: %s", __FUNCTION__, text_time);
  g_debug ("%s: format: %s", __FUNCTION__, format);
  memset (&tm, 0, sizeof (struct tm));
  if (strptime ((char*) text_time, format, &tm) == NULL)
    {
      g_warning ("%s: Failed to parse time", __FUNCTION__);
      if (tz != NULL)
        setenv ("TZ", tz, 1);
      g_free (tz);
      return 0;
    }
  epoch_time = mktime (&tm);
  if (epoch_time == -1)
    {
      g_warning ("%s: Failed to make time", __FUNCTION__);
      if (tz != NULL)
        setenv ("TZ", tz, 1);
      g_free (tz);
      return 0;
    }

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
  return epoch_time;
}

/**
 * @brief Convert an OTP time into seconds since epoch.
 *
 * Use UTC as timezone.
 *
 * @param[in]  text_time  Time as text in ctime format.
 *
 * @return Time since epoch.  0 on error.
 */
int
parse_otp_time (const char *text_time)
{
  return parse_utc_time ("%a %b %d %H:%M:%S %Y", text_time);
}

/**
 * @brief Convert a feed timestamp into seconds since epoch.
 *
 * @param[in]  text_time  Time as text in ctime format.
 *
 * @return Time since epoch.  0 on error.
 */
int
parse_feed_timestamp (const char *text_time)
{
  return parse_utc_time ("%Y%m%d", text_time);
}

/**
 * @brief Convert a ctime into seconds since epoch.
 *
 * Use the current timezone.
 *
 * @param[in]  text_time  Time as text in ctime format.
 *
 * @return Time since epoch.
 */
int
parse_ctime (const char *text_time)
{
  int epoch_time;
  struct tm tm;

  /* ctime format: "Wed Jun 30 21:49:08 1993". */

  memset (&tm, 0, sizeof (struct tm));
  if (strptime ((char*) text_time, "%a %b %d %H:%M:%S %Y", &tm) == NULL)
    {
      g_warning ("%s: Failed to parse time '%s'", __FUNCTION__, text_time);
      return 0;
    }
  epoch_time = mktime (&tm);
  if (epoch_time == -1)
    {
      g_warning ("%s: Failed to make time '%s'", __FUNCTION__, text_time);
      return 0;
    }

  return epoch_time;
}

/**
 * @brief Calculate difference between now and epoch_time in days
 *
 * @param[in]  epoch_time  Time in seconds from epoch.
 *
 * @return Int days bettween now and epoch_time or -1 if epoch_time is in the
 * past
 */
int
days_from_now (time_t *epoch_time)
{
  time_t now = time (NULL);
  int diff = *epoch_time - now;

  if (diff < 0) return -1;
  return diff / 86400; /* 60 sec * 60 min * 24 h */
}

/**
 * @brief Create an ISO time from seconds since epoch.
 *
 * @param[in]  epoch_time  Time in seconds from epoch.
 * @param[out] abbrev      Abbreviation for current timezone.
 *
 * @return Pointer to ISO time in static memory, or NULL on error.
 */
static char *
iso_time_internal (time_t *epoch_time, const char **abbrev)
{
  struct tm *tm;
  static char time_string[100];

  tm = localtime (epoch_time);
#ifdef __FreeBSD__
  if (tm->tm_gmtoff == 0)
#else
  if (timezone == 0)
#endif
    {
      if (strftime (time_string, 98, "%FT%TZ", tm) == 0)
        return NULL;

      if (abbrev)
        *abbrev = "UTC";
    }
  else
    {
      int len;

      if (strftime (time_string, 98, "%FT%T%z", tm) == 0)
        return NULL;

      /* Insert the ISO 8601 colon by hand. */
      len = strlen (time_string);
      time_string[len + 1] = '\0';
      time_string[len] = time_string[len - 1];
      time_string[len - 1] = time_string[len - 2];
      time_string[len - 2] = ':';

      if (abbrev)
        {
          static char abbrev_string[100];
          if (strftime (abbrev_string, 98, "%Z", tm) == 0)
            return NULL;
          *abbrev = abbrev_string;
        }
    }

  return time_string;
}

/**
 * @brief Create an ISO time from seconds since epoch.
 *
 * @param[in]  epoch_time  Time in seconds from epoch.
 *
 * @return Pointer to ISO time in static memory, or NULL on error.
 */
char *
iso_time (time_t *epoch_time)
{
  return iso_time_internal (epoch_time, NULL);
}

/**
 * @brief Create an ISO time from seconds since epoch, given a timezone.
 *
 * @param[in]  epoch_time  Time in seconds from epoch.
 * @param[in]  timezone    Timezone.
 * @param[out] abbrev      Timezone abbreviation.
 *
 * @return Pointer to ISO time in static memory, or NULL on error.
 */
char *
iso_time_tz (time_t *epoch_time, const char *timezone, const char **abbrev)
{
  gchar *tz;
  char *ret;

  if (timezone == NULL)
    return iso_time (epoch_time);

  /* Store current TZ. */
  tz = getenv ("TZ") ? g_strdup (getenv ("TZ")) : NULL;

  if (setenv ("TZ", timezone, 1) == -1)
    {
      g_warning ("%s: Failed to switch to timezone", __FUNCTION__);
      if (tz != NULL)
        setenv ("TZ", tz, 1);
      g_free (tz);
      return iso_time (epoch_time);
    }

  tzset ();
  ret = iso_time_internal (epoch_time, abbrev);

  /* Revert to stored TZ. */
  if (tz)
    {
      if (setenv ("TZ", tz, 1) == -1)
        {
          g_warning ("%s: Failed to switch to original TZ", __FUNCTION__);
          g_free (tz);
          return ret;
        }
    }
  else
    unsetenv ("TZ");

  g_free (tz);
  return ret;
}
