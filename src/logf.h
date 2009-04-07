/* OpenVAS Manager log printing facility.
 * $Id$
 * Description: A printf like macro for logging communication.
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
 * @file logf.h
 * @brief A printf like macro for logging communication.
 */

#ifndef OPENVAS_MANAGER_LOG_H
#define OPENVAS_MANAGER_LOG_H

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

/**
 * @brief Logging flag.
 *
 * All data transfered to and from the client is logged to a file.  If 0 then
 * logging is turned off.
 */
#define LOG 1

/**
 * @brief Installation prefix.
 */
#ifndef PREFIX
#define PREFIX ""
#endif

/**
 * @brief Name of log file.
 */
#define LOG_FILE PREFIX "/var/log/openvas/openvasmd.log"

#if LOG
extern FILE* log_stream;

/**
 * @brief Formatted logging output.
 *
 * Print the printf style \a args to log_stream, preceded by the process ID.
 */
#define logf(args...)                               \
  do {                                              \
    fprintf (log_stream, "%7i  ", (int) getpid());  \
    fprintf (log_stream, args);                     \
    if (fflush (log_stream) == EOF) abort ();       \
  } while (0)
#else
/**
 * @brief Dummy macro, enabled with \ref LOG.
 */
#define logf(format, args...)
#endif

#endif
