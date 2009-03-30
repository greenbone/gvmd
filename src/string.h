/* OpenVAS Manager string utilities.
 * $Id$
 * Description: String utilities for the manager.
 *
 * Authors:
 * Matthew Mundell <matt@mundell.ukfsn.org>
 * Jan-Oliver Wagner <jan-oliver.wagner@intevation.de>
 *
 * Copyright:
 * Copyright (C) 2008, 2009 Intevation GmbH
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

#ifndef OPENVAS_MANAGER_STRING_H
#define OPENVAS_MANAGER_STRING_H

#include <glib.h>

typedef /*@only@*/ /*@null@*/ gchar* string;

void
append_string (string*, const gchar*);

void
append_text (string*, const gchar*, gsize);

void
free_string_var (string*);

/*@shared@*/ char*
strip_space (/*@shared@*/ char*, /*@shared@*/ char*);

#endif
