/* Test 0 of OMP OMP_VERSION.
 * $Id$
 * Description: Test the OMP OMP_VERSION command.
 *
 * Authors:
 * Matthew Mundell <matt@mundell.ukfsn.org>
 *
 * Copyright:
 * Copyright (C) 2009 Intevation GmbH
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TRACE 1

#include "common.h"
#include "../tracef.h"

int
main ()
{
  int socket;
  gnutls_session_t session;

  socket = connect_to_manager (&session);
  if (socket == -1) return EXIT_FAILURE;

  /* Send a version request. */

  if (send_to_manager (&session, "<omp_version/>\n") == -1)
    {
      gnutls_bye (session, GNUTLS_SHUT_RDWR);
      close (socket);
      return EXIT_FAILURE;
    }

  /* Read the response. */

  char* entity = read_entity (&session);
  tracef ("entity: %s\n", entity);

  /* Cleanup. */

  gnutls_bye (session, GNUTLS_SHUT_RDWR);
  close (socket);

  /* Compare. */

  if (strcmp (entity, "omp_version_response") == 0)
    return EXIT_SUCCESS;

  return EXIT_FAILURE;
}
