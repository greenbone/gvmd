/* OpenVAS Manager log printing facility.
 * $Id$
 * Description: A printf like macro for logging communication.
 *
 * Authors:
 * Matthew Mundell <matthew.mundell@greenbone.net>
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
#include <glib.h>

/**
 * @brief Logging flag.
 *
 * All data transfered to and from the client is logged to a file.  If 0 then
 * logging is turned off.
 */
#define LOG 0

/**
 * @brief Name of log file.
 */
#define LOG_FILE OPENVAS_LOG_DIR "/openvasmd.comm"

#if LOG
extern FILE* log_stream;

/**
 * @brief Formatted logging output.
 *
 * Print the printf style \a args to log_stream, preceded by the process ID.
 */
#define logf(args...)                                   \
  do {                                                  \
    if (log_stream)                                     \
      {                                                 \
        fprintf (log_stream, "%7i  ", (int) getpid());  \
        fprintf (log_stream, args);                     \
        if (fflush (log_stream) == EOF)                 \
          {                                             \
            fclose (log_stream);                        \
            log_stream = 0;                             \
            g_warning ("%s: fflush failed, so turned off comm logging: %s\n", \
                       __FUNCTION__,                    \
                       strerror (errno));               \
          }                                             \
      }                                                 \
  } while (0)
#else
/**
 * @brief Dummy macro, enabled with \ref LOG.
 */
#define logf(format, args...)
#endif

#endif
