/* Copyright (C) 2016-2022 Greenbone AG
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
 * @file
 * @brief Generic utilities
 *
 * Generic helper utilities.  None of these are GVM specific.  They could
 * be used anywhere.
 */

/**
 * @brief Enable extra functions.
 *
 * time.h in glibc2 needs this for strptime.
 */
#define _XOPEN_SOURCE

/**
 * @brief Needed for nanosleep.
 */
#define _POSIX_C_SOURCE 199309L

#include "utils.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <gvm/base/gvm_sentry.h>

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
gvm_usleep (unsigned int microseconds)
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
gvm_sleep (unsigned int seconds)
{
  return gvm_usleep (seconds * 1000000);
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
static int
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
      g_warning ("%s: Failed to switch to UTC", __func__);
      if (tz != NULL)
        setenv ("TZ", tz, 1);
      g_free (tz);
      return 0;
    }

  memset (&tm, 0, sizeof (struct tm));
  if (strptime ((char*) text_time, format, &tm) == NULL)
    {
      g_warning ("%s: Failed to parse time", __func__);
      if (tz != NULL)
        setenv ("TZ", tz, 1);
      g_free (tz);
      return 0;
    }
  epoch_time = mktime (&tm);
  if (epoch_time == -1)
    {
      g_warning ("%s: Failed to make time", __func__);
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
          g_warning ("%s: Failed to switch to original TZ", __func__);
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
 * @brief Parses a time string using strptime, resetting the data structure.
 *
 * @param[in]  text_time  The time string to parse.
 * @param[in]  format     The format string.
 * @param[out] tm         The tm date structure to write to.
 *
 * @return Pointer to first character not processed by strptime.
 */
static char *
strptime_with_reset (const char *text_time, const char *format, struct tm* tm)
{
  memset (tm, 0, sizeof (struct tm));
  tm->tm_isdst = -1;
  return strptime ((char*) text_time, format, tm);
}

/**
 * @brief Converts a tm struct into seconds since epoch with a given timezone.
 *
 * @param[in]  tm       The time data structure.
 * @param[in]  new_tz   The timezone to use or NULL for UTC.
 *
 * @return The seconds since epoch from the given time data.
 */
static time_t
mktime_with_tz (struct tm *tm, const char *new_tz)
{
  gchar *tz;
  int epoch_time;

  /* Store current TZ. */
  tz = getenv ("TZ") ? g_strdup (getenv ("TZ")) : NULL;

  /* Set new TZ */
  if (setenv ("TZ",
              new_tz
                ? new_tz
                : "UTC",
              1)
      == -1)
    {
      g_warning ("%s: Failed to switch to timezone %s",
                 __func__, new_tz);
      if (tz != NULL)
        setenv ("TZ", tz, 1);
      g_free (tz);
      return 0;
    }

  /* Get the time */
  epoch_time = mktime (tm);

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

  return epoch_time;
}

/**
 * @brief Convert a UTC ctime string into seconds since the epoch.
 *
 * @param[in]  text_time  Time as text in ctime format.
 *
 * @return Time since epoch.  0 on error.
 */
int
parse_utc_ctime (const char *text_time)
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
      g_warning ("%s: Failed to parse time '%s'", __func__, text_time);
      return 0;
    }
  epoch_time = mktime (&tm);
  if (epoch_time == -1)
    {
      g_warning ("%s: Failed to make time '%s'", __func__, text_time);
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
 * @brief Convert an ISO time into seconds since epoch.
 *
 * If no offset is specified, the given timezone is used (UTC in case of NULL).
 *
 * @param[in]  text_time  Time as text in ISO format: 2011-11-03T09:23:28+02:00.
 * @param[in]  fallback_tz  The fallback timezone if offset is missing.
 *
 * @return Time since epoch.  0 on error.
 */
time_t
parse_iso_time_tz (const char *text_time, const char *fallback_tz)
{
  static GRegex *regex = NULL;
  GMatchInfo *match_info;
  struct tm tm;
  int epoch_time;

  epoch_time = 0;

  if (regex == NULL)
    regex = g_regex_new ("^([0-9]{4}\\-[0-9]{2}\\-[0-9]{2})"
                         "[T ]([0-9]{2}:[0-9]{2})"
                         "(:[0-9]{2})?(?:\\.[0-9]+)?"
                         "(Z|[+-][0-9]{2}:?[0-9]{2})?$",
                         0, 0, NULL);

  if (g_regex_match (regex, text_time, 0, &match_info))
    {
      gchar *date_str, *time_str, *secs_str, *offset_str, *cleaned_text_time;

      /* Converting the date-time string to a more strictly defined format
       *  makes it easier to parse variants of the ISO time:
       * - Using a space to separate the date and time instead of "T"
       * - Omitting the seconds
       * - Having fractional seconds
       */
      date_str = g_match_info_fetch (match_info, 1);
      time_str = g_match_info_fetch (match_info, 2);
      secs_str = g_match_info_fetch (match_info, 3);
      offset_str = g_match_info_fetch (match_info, 4);
      cleaned_text_time
        = g_strdup_printf ("%sT%s%s%s",
                           date_str ? date_str : "",
                           time_str ? time_str : "",
                           secs_str && strcmp (secs_str, "")
                            ? secs_str : ":00",
                           offset_str ? offset_str : "");
      #if !defined(__GLIBC__)
        if (strptime_with_reset ((char*) cleaned_text_time, "%Y-%m-%dT%T", &tm))
      #else
        if (strptime_with_reset ((char*) cleaned_text_time, "%FT%T%z", &tm))
      #endif
        {
          /* ISO time with numeric offset (e.g. 2020-06-01T01:02:03+04:30) */
          tm.tm_sec = tm.tm_sec - tm.tm_gmtoff;
          tm.tm_gmtoff = 0;
          epoch_time = mktime_with_tz (&tm, "UTC");
        }
      #if !defined(__GLIBC__)
        else if (strptime_with_reset ((char*) cleaned_text_time, "%Y-%m-%dT%T", &tm))
      #else
        else if (strptime_with_reset ((char*) cleaned_text_time, "%FT%TZ", &tm))
      #endif
        {
          /* ISO time with "Z" for UTC timezone (e.g. 2020-06-01T01:02:03Z) */
          epoch_time = mktime_with_tz (&tm, "UTC");
        }
      #if !defined(__GLIBC__)
        else if (strptime_with_reset ((char*) cleaned_text_time, "%Y-%m-%dT%T", &tm))
      #else
        else if (strptime_with_reset ((char*) cleaned_text_time, "%FT%T", &tm))
      #endif
        {
          /* ISO time without timezone suffix (e.g. 2020-06-01T01:02:03) */
          epoch_time = mktime_with_tz (&tm, fallback_tz ? fallback_tz : "UTC");
        }
      else
        g_warning ("%s: Could not parse time %s", __func__, text_time);

      g_free (date_str);
      g_free (time_str);
      g_free (secs_str);
      g_free (offset_str);
      g_free (cleaned_text_time);
    }
  else
    g_warning ("%s: Could not parse time %s", __func__, text_time);

  g_match_info_free (match_info);

  if (epoch_time == -1)
    {
      g_warning ("%s: mktime failed for time %s", __func__, text_time);
      return 0;
    }

  return epoch_time;
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
  struct tm tm;
  static char time_string[100];

  if (localtime_r (epoch_time, &tm) == NULL)
    return NULL;
#ifdef __FreeBSD__
  if (tm.tm_gmtoff == 0)
#else
  if (timezone == 0)
#endif
    {
      #if !defined(__GLIBC__)
        if (strftime (time_string, 98, "%Y-%m-%dT%T", &tm) == 0)
      #else
        if (strftime (time_string, 98, "%FT%TZ", &tm) == 0)
      #endif
        return NULL;

      if (abbrev)
        *abbrev = "UTC";
    }
  else
    {
      int len;

      #if !defined(__GLIBC__)
        if (strftime (time_string, 98, "%Y-%m-%dT%T", &tm) == 0)
      #else
        if (strftime (time_string, 98, "%FT%T%z", &tm) == 0)
      #endif
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
          if (strftime (abbrev_string, 98, "%Z", &tm) == 0)
            return NULL;
          *abbrev = abbrev_string;
        }
    }

  return time_string;
}

/**
 * @brief Create an ISO time from seconds since epoch.
 *
 * @param[in]  epoch_time  Pointer to time in seconds from epoch.
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
 * @param[in]  epoch_time  Pointer to time in seconds from epoch.
 * @param[in]  zone        Timezone.
 * @param[out] abbrev      Timezone abbreviation.
 *
 * @return Pointer to ISO time in static memory, or NULL on error.
 */
char *
iso_time_tz (time_t *epoch_time, const char *zone, const char **abbrev)
{
  gchar *tz;
  char *ret;

  if (zone == NULL)
    return iso_time (epoch_time);

  /* Store current TZ. */
  tz = getenv ("TZ") ? g_strdup (getenv ("TZ")) : NULL;

  if (setenv ("TZ", zone, 1) == -1)
    {
      g_warning ("%s: Failed to switch to zone", __func__);
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
          g_warning ("%s: Failed to switch to original TZ", __func__);
          g_free (tz);
          return ret;
        }
    }
  else
    unsetenv ("TZ");

  g_free (tz);
  return ret;
}

/**
 * @brief Create an ISO time from seconds since epoch, with a 0 check.
 *
 * @param[in]  epoch_time  Time in seconds from epoch.
 *
 * @return ISO time string in static memory.  If epoch_time is 0 then string is empty.
 */
char *
iso_if_time (time_t epoch_time)
{
  static char *empty = "";
  if (epoch_time)
    {
      char *ret;

      ret = iso_time (&epoch_time);
      if (ret)
        return ret;
    }
  return empty;
}


/* Locks. */

/**
 * @brief Lock a file.
 *
 * @param[in]  lockfile           Lockfile.
 * @param[in]  lockfile_name      Basename or full path of lock file.
 * @param[in]  operation          LOCK_EX (exclusive) or LOCK_SH (shared).
 *                                Maybe ORd with LOCK_NB to prevent blocking.
 * @param[in]  name_is_full_path  Whether the name is a full path.
 *
 * @return 0 success, 1 already locked, -1 error
 */
static int
lock_internal (lockfile_t *lockfile, const gchar *lockfile_name,
               int operation, gboolean name_is_full_path)
{
  mode_t old_umask;
  int fd;
  gchar *full_name;

  /* Open the lock file. */

  if (name_is_full_path)
    full_name = g_strdup (lockfile_name);
  else
    full_name = g_build_filename (GVMD_STATE_DIR, lockfile_name, NULL);

  old_umask = umask (0);
  fd = open (full_name, O_RDWR | O_CREAT,
             /* "-rw-rw-r--" */
             S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
  if (fd == -1)
    {
      g_warning ("Failed to open lock file '%s': %s", full_name,
                 strerror (errno));
      umask (old_umask);
      lockfile->name = NULL;
      g_free (full_name);
      return -1;
    }
  umask (old_umask);

  /* Lock the lockfile. */

  if (flock (fd, operation))  /* Blocks, unless operation includes LOCK_NB. */
    {
      int flock_errno;

      flock_errno = errno;
      lockfile->name = NULL;
      g_free (full_name);
      if (close (fd))
        g_warning ("%s: failed to close lock file fd: %s",
                   __func__,
                   strerror (errno));
      if (flock_errno == EWOULDBLOCK)
        return 1;
      g_warning ("%s: flock: %s", __func__, strerror (flock_errno));
      return -1;
    }

  lockfile->fd = fd;
  lockfile->name = full_name;

  return 0;
}

/**
 * @brief Lock a file exclusively.
 *
 * Block until file is locked.
 *
 * @param[in]  lockfile           Lockfile.
 * @param[in]  lockfile_basename  Basename of lock file.
 *
 * @return 0 success, 1 already locked, -1 error
 */
int
lockfile_lock (lockfile_t *lockfile, const gchar *lockfile_basename)
{
  g_debug ("%s: lock '%s'", __func__, lockfile_basename);
  return lock_internal (lockfile, lockfile_basename, LOCK_EX, FALSE);
}

/**
 * @brief Lock a file exclusively, without blocking.
 *
 * @param[in]  lockfile           Lockfile.
 * @param[in]  lockfile_basename  Basename of lock file.
 *
 * @return 0 success, 1 already locked, -1 error
 */
int
lockfile_lock_nb (lockfile_t *lockfile, const gchar *lockfile_basename)
{
  g_debug ("%s: lock '%s'", __func__, lockfile_basename);
  return lock_internal (lockfile, lockfile_basename, LOCK_EX | LOCK_NB, FALSE);
}

/**
 * @brief Lock a file exclusively, without blocking, given a full path.
 *
 * @param[in]  lockfile       Lockfile.
 * @param[in]  lockfile_path  Full path of lock file.
 *
 * @return 0 success, 1 already locked, -1 error
 */
int
lockfile_lock_path_nb (lockfile_t *lockfile, const gchar *lockfile_path)
{
  g_debug ("%s: lock '%s'", __func__, lockfile_path);
  return lock_internal (lockfile, lockfile_path, LOCK_EX | LOCK_NB, TRUE);
}

/**
 * @brief Lock a file with a shared lock.
 *
 * @param[in]  lockfile           Lockfile.
 * @param[in]  lockfile_basename  Basename of lock file.
 *
 * @return 0 success, 1 already locked, -1 error
 */
int
lockfile_lock_shared_nb (lockfile_t *lockfile, const gchar *lockfile_basename)
{
  g_debug ("%s: lock '%s'", __func__, lockfile_basename);
  return lock_internal (lockfile, lockfile_basename, LOCK_SH | LOCK_NB, FALSE);
}

/**
 * @brief Unlock a file.
 *
 * @param[in]  lockfile  Lockfile.
 *
 * @return 0 success, -1 error
 */
int
lockfile_unlock (lockfile_t *lockfile)
{
  if (lockfile->name == NULL)
    return 0;

  assert (lockfile->fd);

  g_debug ("%s: unlock '%s'", __func__, lockfile->name);

  /* Close the lock file. */

  if (close (lockfile->fd))
    {
      g_free (lockfile->name);
      lockfile->name = NULL;
      g_warning ("Failed to close lock file: %s", strerror (errno));
      return -1;
    }

  /* Clear the lock file data. */

  g_free (lockfile->name);
  lockfile->name = NULL;

  return 0;
}

/**
 * @brief Check if a file is locked.
 *
 * @param[in]  lockfile_basename  Basename of lock file.
 *
 * @return 0 free, 1 locked, -1 error
 */
int
lockfile_locked (const gchar *lockfile_basename)
{
  int ret;
  lockfile_t lockfile;

  g_debug ("%s: check '%s'", __func__, lockfile_basename);

  ret = lockfile_lock_nb (&lockfile, lockfile_basename);
  if ((ret == 0) && lockfile_unlock (&lockfile))
    return -1;
  return ret;
}


/* UUIDs. */

/**
 * @brief Check whether a string is a UUID.
 *
 * @param[in]  uuid  Potential UUID.
 *
 * @return 1 yes, 0 no.
 */
int
is_uuid (const char *uuid)
{
  while (*uuid) if (isxdigit (*uuid) || (*uuid == '-')) uuid++; else return 0;
  return 1;
}


/* Strings. */

/**
 * @brief Escape a string with exceptions for UTF-8 if it is valid UTF-8.
 *
 * If the string is valid UTF-8, characters in the range 0x80 - 0xFF
 * are excluded so non-ASCII UTF-8 characters and any characters in the
 * extra_exceptions are not escaped.
 * This leaves the characters 0x01 - 0x1F and 0x7F to be escaped if they are
 * not in the given extra_exceptions.
 *
 * For strings that are not valid UTF-8 all characters in the ranges
 *
 * @param[in]  str               The string to escape.
 * @param[in]  extra_exceptions  Extra exc.
 *
 * @return Newly allocated escaped copy of the string.
 */
gchar *
strescape_check_utf8 (const char *str, const char *extra_exceptions)
{
  if (g_utf8_validate (str, -1, NULL))
    return strescape_without_utf8 (str, extra_exceptions);
  else
    return g_strescape (str, extra_exceptions);
}

/**
 * @brief Escape control characters in a string with exceptions for UTF-8.
 *
 * Characters in the range 0x80 - 0xFF are excluded so non-ASCII UTF-8
 * characters are not escaped.
 * This leaves the characters 0x01 - 0x1F and 0x7F to be escaped if they are
 * not in the given extra_exceptions.
 *
 * @param[in]  str               The string to escape.
 * @param[in]  extra_exceptions  Extra exceptions to the escaping.
 *
 * @return Newly allocated escaped copy of the string.
 */
gchar *
strescape_without_utf8 (const char *str, const char *extra_exceptions)
{
  static const char *base_exceptions =
    "\200\201\202\203\204\205\206\207\210\211\212\213\214\215\216\217"
    "\220\221\222\223\224\225\226\227\230\231\232\233\234\235\236\237"
    "\240\241\242\243\244\245\246\247\250\251\252\253\254\255\256\257"
    "\260\261\262\263\264\265\266\267\270\271\272\273\274\275\276\277"
    "\300\301\302\303\304\305\306\307\310\311\312\313\314\315\316\317"
    "\320\321\322\323\324\325\326\327\330\331\332\333\334\335\336\337"
    "\340\341\342\343\344\345\346\347\350\351\352\353\354\355\356\357"
    "\360\361\362\363\364\365\366\367\370\371\372\373\374\375\376\377";
  gchar *exceptions = NULL;
  gchar *escaped;

  if (extra_exceptions && strcmp (extra_exceptions, ""))
    {
      exceptions = g_strconcat (base_exceptions,
                                extra_exceptions ? extra_exceptions : "",
                                NULL);
    }
  escaped = g_strescape (str, exceptions ? exceptions : base_exceptions);
  g_free (exceptions);
  return escaped;
}


/* XML. */

/**
 * @brief Create entity from XML file.
 *
 * @param[in]  path    Path to XML.
 * @param[out] config  Config tree.
 *
 * @return 0 success, -1 error.
 */
int
parse_xml_file (const gchar *path, entity_t *config)
{
  gsize xml_len;
  char *xml;
  GError *error;

  /* Buffer the file. */

  error = NULL;
  g_file_get_contents (path,
                       &xml,
                       &xml_len,
                       &error);
  if (error)
    {
      g_warning ("%s: Failed to read file: %s",
                  __func__,
                  error->message);
      g_error_free (error);
      return -1;
    }

  /* Parse the buffer into an entity. */

  if (parse_entity (xml, config))
    {
      g_free (xml);
      g_warning ("%s: Failed to parse XML", __func__);
      return -1;
    }
  g_free (xml);

  return 0;
}


/* Signals. */

/**
 * @brief Setup signal handler.
 *
 * Exit on failure.
 *
 * @param[in]  signal   Signal.
 * @param[in]  handler  Handler.
 * @param[in]  block    Whether to block all other signals during handler.
 */
void
setup_signal_handler (int signal, void (*handler) (int), int block)
{
  struct sigaction action;

  memset (&action, '\0', sizeof (action));
  if (block)
    sigfillset (&action.sa_mask);
  else
    sigemptyset (&action.sa_mask);
  action.sa_handler = handler;
  if (sigaction (signal, &action, NULL) == -1)
    {
      g_critical ("%s: failed to register %s handler",
                  __func__, strsignal (signal));
      gvm_close_sentry ();
      exit (EXIT_FAILURE);
    }
}

/**
 * @brief Setup signal handler.
 *
 * Exit on failure.
 *
 * @param[in]  signal   Signal.
 * @param[in]  handler  Handler.
 * @param[in]  block    Whether to block all other signals during handler.
 */
void
setup_signal_handler_info (int signal,
                           void (*handler) (int, siginfo_t *, void *),
                           int block)
{
  struct sigaction action;

  memset (&action, '\0', sizeof (action));
  if (block)
    sigfillset (&action.sa_mask);
  else
    sigemptyset (&action.sa_mask);
  action.sa_flags |= SA_SIGINFO;
  action.sa_sigaction = handler;
  if (sigaction (signal, &action, NULL) == -1)
    {
      g_critical ("%s: failed to register %s handler",
                  __func__, strsignal (signal));
      gvm_close_sentry ();
      exit (EXIT_FAILURE);
    }
}


/* Forking. */

/**
 * @brief Fork, setting default handlers for TERM, INT and QUIT in child.
 *
 * This should be used for pretty much all processes forked directly from
 * the main gvmd process, because the main process's signal handlers will
 * not longer work, because the child does not use the pselect loop.
 *
 * @return PID from fork.
 */
int
fork_with_handlers ()
{
  pid_t pid;

  pid = fork ();
  if (pid == 0)
    {
      setup_signal_handler (SIGTERM, SIG_DFL, 0);
      setup_signal_handler (SIGINT, SIG_DFL, 0);
      setup_signal_handler (SIGQUIT, SIG_DFL, 0);
    }
  return pid;
}

/**
 * @brief Waits for a process with the given PID, retrying if interrupted.
 *
 * If the wait is interrupted or the process does not exist, only debug
 *  messages are logged.
 *
 * @param[in]  pid      The pid to wait for.
 * @param[in]  context  Short context desciption for error and debug messages.
 */
void
wait_for_pid (pid_t pid, const char *context)
{
  gboolean retry = TRUE;
  const char *shown_context = context ? context : "unknown context";
  if (pid <= 0)
    {
      g_message ("%s: No PID given (%s)", __func__, shown_context);
      return;
    }

  while (retry)
    {
      retry = FALSE;
      pid_t ret = waitpid (pid, NULL, 0);
      if (ret <= 0)
        {
          int err = errno;
          if (errno == ECHILD)
            {
              g_debug ("%s: process with PID %d (%s) does not exist",
                       __func__, pid, shown_context);
            }
          else if (errno == EINTR)
            {
              g_debug ("%s: waitpid interrupted for PID %d (%s), retrying...",
                       __func__, pid, shown_context);
              retry = TRUE;
            }
          else
            {
              g_warning ("%s: waitpid failed for PID %d (%s): %s",
                         __func__, pid, shown_context, strerror(err));
            }
        }
      else
        {
          g_debug ("%s: wait for PID %d (%s) successful",
                   __func__, pid, shown_context);
        }
    }
}

/**
 * @brief Get the available physical memory in bytes.
 *
 * @return The available memory
 */
guint64
phys_mem_available ()
{
  return (unsigned long long)(sysconf(_SC_AVPHYS_PAGES))
    * sysconf(_SC_PAGESIZE);
}

/**
 * @brief Get the total physical memory in bytes.
 *
 * @return The total memory
 */
guint64
phys_mem_total ()
{
  return sysconf(_SC_PHYS_PAGES) * sysconf(_SC_PAGESIZE);
}


/* Arrays. */

/**
 * @brief Ensure a string is in an array.
 *
 * @param[in]  array   Array.
 * @param[in]  string  String.  Copied into array.
 */
void
array_add_new_string (array_t *array, const gchar *string)
{
  guint index;
  for (index = 0; index < array->len; index++)
    if (strcmp (g_ptr_array_index (array, index), string) == 0)
      return;
  array_add (array, g_strdup (string));
}
