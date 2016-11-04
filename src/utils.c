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

#include "utils.h"

#include <errno.h>
#include <time.h>

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
