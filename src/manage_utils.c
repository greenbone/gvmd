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

  assert (time1 < time2);

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
 *
 * @return  the next time a schedule with the given times is due.
 */
time_t
next_time (time_t first, int period, int period_months)
{
  int periods_diff;
  time_t now = time (NULL);

  if (first >= now)
    {
      return first;
    }
  else if (period > 0)
    {
      return first + ((((now - first) / period) + 1) * period);
    }
  else if (period_months > 0)
    {
      periods_diff = months_between (first, now) / period_months;
      if (add_months (first, (periods_diff + 1) * period_months)
          >= now)
        return add_months (first, (periods_diff + 1) * period_months);
      else
        return add_months (first, periods_diff * period_months);
    }
  return 0;
}

/**
 * @brief Return number of hosts described by a hosts string.
 *
 * @param[in]  given_hosts      String describing hosts.
 * @param[in]  exclude_hosts    String describing hosts excluded from given set.
 *
 * @return Number of hosts, or -1 on error.
 */
int
manage_count_hosts_FIX (const char *given_hosts, const char *exclude_hosts)
{
  int count;
  openvas_hosts_t *hosts;

  // FIX 4095 s/b manage_max_host () but this is used on pg side
  hosts = openvas_hosts_new_with_max (given_hosts, 4095);
  if (hosts == NULL)
    return -1;

  if (exclude_hosts)
    /* Don't resolve hostnames in excluded hosts. */
    openvas_hosts_exclude (hosts, exclude_hosts, 0);

  count = openvas_hosts_count (hosts);
  openvas_hosts_free (hosts);

  return count;
}
