/* Copyright (C) 2022 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _GVMD_MANAGE_AUTHENTICATION_H
#define _GVMD_MANAGE_AUTHENTICATION_H


enum manage_authentication_rc
{
  GMA_SUCCESS,
  GMA_HASH_VALID_BUT_DATED,
  GMA_HASH_INVALID,
  GMA_ERR,
};

enum manage_authentication_rc
manage_authentication_setup (const char *pepper, unsigned int pepper_size,
                             unsigned int count, char *prefix);
char *
manage_authentication_hash (const char *password);

enum manage_authentication_rc
manage_authentication_verify (const char *hash, const char *password);

#endif

