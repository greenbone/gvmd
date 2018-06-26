#!/bin/bash
#
# gvm-lsc-rpm-creator.sh
# This script generates an RPM package that creates a user for GVM
#  local security checks.
#
# Authors:
# Timo Pollmeier <timo.pollmeier@greenbone.net>
#
# Copyright (C) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

#
# Variables
#

# Command line paramaters
USERNAME=$1
PUBKEY_FILE=$2
TEMP_DIR=$3
OUTPUT_PATH=$4

if [ -z "${USERNAME}" ]
then
  echo "No username given" >&2
  exit 1
fi

if [ -z "${PUBKEY_FILE}" ]
then
  echo "No pubkey path given" >&2
  exit 1
fi

if [ -z "${TEMP_DIR}" ]
then
  echo "No temp dir path given" >&2
  exit 1
fi

if [ -z "${OUTPUT_PATH}" ]
then
  echo "No output path given" >&2
  exit 1
fi

# Constants
# Package data
PACKAGE_NAME="gvm-lsc-target-${USERNAME}"
PACKAGE_VERSION="0.5"
PACKAGE_RELEASE="1"
PACKAGE_NAME_VERSION="${PACKAGE_NAME}-${PACKAGE_VERSION}-${PACKAGE_RELEASE}"

USER_COMMENT="GVM Local Security Checks"
# specify in case characters reserved by grep are used
USER_COMMENT_GREP="GVM\\ Local\\ Security\\ Checks"

PACKAGE_BASE_DIR="${TEMP_DIR}/${PACKAGE_NAME_VERSION}"

# Build directories
BUILD_ROOT_DIR="${PACKAGE_BASE_DIR}/build"
HOME_SUBDIR="home/${USERNAME}"
HOME_DATA_DIR="${BUILD_ROOT_DIR}/${HOME_SUBDIR}"
SSH_DATA_DIR="${HOME_DATA_DIR}/.ssh"

# Spec file directory
SPEC_DIR="${TEMP_DIR}"

#
# Test dependencies
#
if [ -z $(which fakeroot) ]
then
  echo "fakeroot not found" >&2
  exit 1
fi

if [ -z $(which rpmbuild) ]
then
  echo "rpmbuild not found" >&2
  exit 1
fi

#
# Create data files
#

# Create .ssh directory
mkdir -p "${SSH_DATA_DIR}"
if [ 0 -ne "$?" ]
then
  exit 1
fi

# Copy public key
AUTH_KEYS_FILE="${SSH_DATA_DIR}/authorized_keys"
cp "${PUBKEY_FILE}" "${AUTH_KEYS_FILE}"

#
# Create spec file
#

# Create directory
mkdir -p "${SPEC_DIR}"

# Create spec file basic info
SPEC_FILE="${SPEC_DIR}/${PACKAGE_NAME_VERSION}.spec"
echo "Name: ${PACKAGE_NAME}" > ${SPEC_FILE}
echo "Version: ${PACKAGE_VERSION}" >> ${SPEC_FILE}
echo "Release: ${PACKAGE_RELEASE}" >> ${SPEC_FILE}
echo "Group: Application/Misc" >> ${SPEC_FILE}
echo "Summary: OpenVAS local security check preparation" >> ${SPEC_FILE}
echo "License: GPL2+" >> ${SPEC_FILE}
echo "BuildArch: noarch" >> ${SPEC_FILE}

# Put output in current directory
echo "%define _rpmdir %(pwd)" >> ${SPEC_FILE}

# Create description section
echo "%description" >> ${SPEC_FILE}
echo "This package prepares a system for GVM local security checks." >> ${SPEC_FILE}
echo "A user is created with a specific SSH authorized key." >> ${SPEC_FILE}
echo "The corresponding private key is located at the respective" >> ${SPEC_FILE}
echo "GVM installation." >> ${SPEC_FILE}

# Create files section
echo "%files" >> ${SPEC_FILE}

echo "/${HOME_SUBDIR}" >> ${SPEC_FILE}

# Create "pre" section run before installation
echo "%pre" >> ${SPEC_FILE}
echo "#!/bin/sh" >> ${SPEC_FILE}
echo "set -e  # abort on errors" >> ${SPEC_FILE}
echo "useradd -c \"${USER_COMMENT}\" -d /home/${USERNAME} -m -s /bin/bash ${USERNAME}" >> ${SPEC_FILE}

# Create "post" section run after installation
echo "%post" >> ${SPEC_FILE}
echo "#!/bin/sh" >> ${SPEC_FILE}
echo "set -e  # abort on errors" >> ${SPEC_FILE}
echo "chown -R ${USERNAME}:${USERNAME} /home/${USERNAME}" >> ${SPEC_FILE}
echo "chmod 500 /home/${USERNAME}/.ssh" >> ${SPEC_FILE}
echo "chmod 400 /home/${USERNAME}/.ssh/authorized_keys" >> ${SPEC_FILE}

# Create "postun" section run after removal or on error
echo "%postun" >> ${SPEC_FILE}
echo "#!/bin/sh" >> ${SPEC_FILE}
echo "# Remove user only if it was created by this package." >> ${SPEC_FILE}
echo "# The debian package will run the postun script in case of errors" >> ${SPEC_FILE}
echo "# (e.g. user already existed)." >> ${SPEC_FILE}
echo "# Delete the user only if /etc/passwd lists content that suggests" >> ${SPEC_FILE}
echo "# that the user was created by this package." >> ${SPEC_FILE}
#echo "set -e  # abort on errors" >> ${SPEC_FILE}
echo "grep \"${USERNAME}.*${USER_COMMENT_GREP}\" /etc/passwd && userdel -f ${USERNAME}" >> ${SPEC_FILE}

#
# Build package
#

# Build package
cd "$TEMP_DIR"
fakeroot -- rpmbuild --bb "${SPEC_FILE}" --buildroot "${BUILD_ROOT_DIR}"

# Move package to new destination
mv "${TEMP_DIR}/noarch/${PACKAGE_NAME_VERSION}.noarch.rpm" "${OUTPUT_PATH}"
