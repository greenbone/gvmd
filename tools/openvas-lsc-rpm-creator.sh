#!/bin/sh
# This script was generated using Makeself 2.1.5

CRCsum="989516589"
MD5="001440a0272902dbcf1a6e242c26124c"
TMPROOT=${TMPDIR:=/tmp}

label="OpenVAS LSC RPM creator"
script="./create-rpm.sh"
scriptargs=""
targetdir="blubber"
filesizes="163840"
keep=y

print_cmd_arg=""
if type printf > /dev/null; then
    print_cmd="printf"
elif test -x /usr/ucb/echo; then
    print_cmd="/usr/ucb/echo"
else
    print_cmd="echo"
fi

unset CDPATH

MS_Printf()
{
    $print_cmd $print_cmd_arg "$1"
}

MS_Progress()
{
    while read a; do
	MS_Printf .
    done
}

MS_diskspace()
{
	(
	if test -d /usr/xpg4/bin; then
		PATH=/usr/xpg4/bin:$PATH
	fi
	df -kP "$1" | tail -1 | awk '{print $4}'
	)
}

MS_dd()
{
    blocks=`expr $3 / 1024`
    bytes=`expr $3 % 1024`
    dd if="$1" ibs=$2 skip=1 obs=1024 conv=sync 2> /dev/null | \
    { test $blocks -gt 0 && dd ibs=1024 obs=1024 count=$blocks ; \
      test $bytes  -gt 0 && dd ibs=1 obs=1024 count=$bytes ; } 2> /dev/null
}

MS_Help()
{
    cat << EOH >&2
Makeself version 2.1.5
 1) Getting help or info about $0 :
  $0 --help   Print this message
  $0 --info   Print embedded info : title, default target directory, embedded script ...
  $0 --lsm    Print embedded lsm entry (or no LSM)
  $0 --list   Print the list of files in the archive
  $0 --check  Checks integrity of the archive
 
 2) Running $0 :
  $0 [options] [--] [additional arguments to embedded script]
  with following options (in that order)
  --confirm             Ask before running embedded script
  --noexec              Do not run embedded script
  --keep                Do not erase target directory after running
			the embedded script
  --nox11               Do not spawn an xterm
  --nochown             Do not give the extracted files to the current user
  --target NewDirectory Extract in NewDirectory
  --tar arg1 [arg2 ...] Access the contents of the archive through the tar command
  --                    Following arguments will be passed to the embedded script
EOH
}

MS_Check()
{
    OLD_PATH="$PATH"
    PATH=${GUESS_MD5_PATH:-"$OLD_PATH:/bin:/usr/bin:/sbin:/usr/local/ssl/bin:/usr/local/bin:/opt/openssl/bin"}
	MD5_ARG=""
    MD5_PATH=`exec <&- 2>&-; which md5sum || type md5sum`
    test -x "$MD5_PATH" || MD5_PATH=`exec <&- 2>&-; which md5 || type md5`
	test -x "$MD5_PATH" || MD5_PATH=`exec <&- 2>&-; which digest || type digest`
    PATH="$OLD_PATH"

    MS_Printf "Verifying archive integrity..."
    offset=`head -n 404 "$1" | wc -c | tr -d " "`
    verb=$2
    i=1
    for s in $filesizes
    do
		crc=`echo $CRCsum | cut -d" " -f$i`
		if test -x "$MD5_PATH"; then
			if test `basename $MD5_PATH` = digest; then
				MD5_ARG="-a md5"
			fi
			md5=`echo $MD5 | cut -d" " -f$i`
			if test $md5 = "00000000000000000000000000000000"; then
				test x$verb = xy && echo " $1 does not contain an embedded MD5 checksum." >&2
			else
				md5sum=`MS_dd "$1" $offset $s | eval "$MD5_PATH $MD5_ARG" | cut -b-32`;
				if test "$md5sum" != "$md5"; then
					echo "Error in MD5 checksums: $md5sum is different from $md5" >&2
					exit 2
				else
					test x$verb = xy && MS_Printf " MD5 checksums are OK." >&2
				fi
				crc="0000000000"; verb=n
			fi
		fi
		if test $crc = "0000000000"; then
			test x$verb = xy && echo " $1 does not contain a CRC checksum." >&2
		else
			sum1=`MS_dd "$1" $offset $s | CMD_ENV=xpg4 cksum | awk '{print $1}'`
			if test "$sum1" = "$crc"; then
				test x$verb = xy && MS_Printf " CRC checksums are OK." >&2
			else
				echo "Error in checksums: $sum1 is different from $crc"
				exit 2;
			fi
		fi
		i=`expr $i + 1`
		offset=`expr $offset + $s`
    done
    echo " All good."
}

UnTAR()
{
    tar $1vf - 2>&1 || { echo Extraction failed. > /dev/tty; kill -15 $$; }
}

finish=true
xterm_loop=
nox11=y
copy=none
ownership=y
verbose=n

initargs="$@"

while true
do
    case "$1" in
    -h | --help)
	MS_Help
	exit 0
	;;
    --info)
	echo Identification: "$label"
	echo Target directory: "$targetdir"
	echo Uncompressed size: 220 KB
	echo Compression: none
	echo Date of packaging: Wed Jul 14 09:25:13 CEST 2010
	echo Built with Makeself version 2.1.5 on linux-gnu
	echo Build command was: "./makeself-2.1.5/makeself.sh \\
    \"--nox11\" \\
    \"--notemp\" \\
    \"--nocomp\" \\
    \"/tmp/blubber\" \\
    \"openvas-lsc-rpm-creator.sh\" \\
    \"OpenVAS LSC RPM creator\" \\
    \"./create-rpm.sh\""
	if test x$script != x; then
	    echo Script run after extraction:
	    echo "    " $script $scriptargs
	fi
	if test x"" = xcopy; then
		echo "Archive will copy itself to a temporary location"
	fi
	if test x"y" = xy; then
	    echo "directory $targetdir is permanent"
	else
	    echo "$targetdir will be removed after extraction"
	fi
	exit 0
	;;
    --dumpconf)
	echo LABEL=\"$label\"
	echo SCRIPT=\"$script\"
	echo SCRIPTARGS=\"$scriptargs\"
	echo archdirname=\"blubber\"
	echo KEEP=y
	echo COMPRESS=none
	echo filesizes=\"$filesizes\"
	echo CRCsum=\"$CRCsum\"
	echo MD5sum=\"$MD5\"
	echo OLDUSIZE=220
	echo OLDSKIP=405
	exit 0
	;;
    --lsm)
cat << EOLSM
No LSM.
EOLSM
	exit 0
	;;
    --list)
	echo Target directory: $targetdir
	offset=`head -n 404 "$0" | wc -c | tr -d " "`
	for s in $filesizes
	do
	    MS_dd "$0" $offset $s | eval "cat" | UnTAR t
	    offset=`expr $offset + $s`
	done
	exit 0
	;;
	--tar)
	offset=`head -n 404 "$0" | wc -c | tr -d " "`
	arg1="$2"
	shift 2
	for s in $filesizes
	do
	    MS_dd "$0" $offset $s | eval "cat" | tar "$arg1" - $*
	    offset=`expr $offset + $s`
	done
	exit 0
	;;
    --check)
	MS_Check "$0" y
	exit 0
	;;
    --confirm)
	verbose=y
	shift
	;;
	--noexec)
	script=""
	shift
	;;
    --keep)
	keep=y
	shift
	;;
    --target)
	keep=y
	targetdir=${2:-.}
	shift 2
	;;
    --nox11)
	nox11=y
	shift
	;;
    --nochown)
	ownership=n
	shift
	;;
    --xwin)
	finish="echo Press Return to close this window...; read junk"
	xterm_loop=1
	shift
	;;
    --phase2)
	copy=phase2
	shift
	;;
    --)
	shift
	break ;;
    -*)
	echo Unrecognized flag : "$1" >&2
	MS_Help
	exit 1
	;;
    *)
	break ;;
    esac
done

case "$copy" in
copy)
    tmpdir=$TMPROOT/makeself.$RANDOM.`date +"%y%m%d%H%M%S"`.$$
    mkdir "$tmpdir" || {
	echo "Could not create temporary directory $tmpdir" >&2
	exit 1
    }
    SCRIPT_COPY="$tmpdir/makeself"
    echo "Copying to a temporary location..." >&2
    cp "$0" "$SCRIPT_COPY"
    chmod +x "$SCRIPT_COPY"
    cd "$TMPROOT"
    exec "$SCRIPT_COPY" --phase2 -- $initargs
    ;;
phase2)
    finish="$finish ; rm -rf `dirname $0`"
    ;;
esac

if test "$nox11" = "n"; then
    if tty -s; then                 # Do we have a terminal?
	:
    else
        if test x"$DISPLAY" != x -a x"$xterm_loop" = x; then  # No, but do we have X?
            if xset q > /dev/null 2>&1; then # Check for valid DISPLAY variable
                GUESS_XTERMS="xterm rxvt dtterm eterm Eterm kvt konsole aterm"
                for a in $GUESS_XTERMS; do
                    if type $a >/dev/null 2>&1; then
                        XTERM=$a
                        break
                    fi
                done
                chmod a+x $0 || echo Please add execution rights on $0
                if test `echo "$0" | cut -c1` = "/"; then # Spawn a terminal!
                    exec $XTERM -title "$label" -e "$0" --xwin "$initargs"
                else
                    exec $XTERM -title "$label" -e "./$0" --xwin "$initargs"
                fi
            fi
        fi
    fi
fi

if test "$targetdir" = "."; then
    tmpdir="."
else
    if test "$keep" = y; then
	echo "Creating directory $targetdir" >&2
	tmpdir="$targetdir"
	dashp="-p"
    else
	tmpdir="$TMPROOT/selfgz$$$RANDOM"
	dashp=""
    fi
    mkdir $dashp $tmpdir || {
	echo 'Cannot create target directory' $tmpdir >&2
	echo 'You should try option --target OtherDirectory' >&2
	eval $finish
	exit 1
    }
fi

location="`pwd`"
if test x$SETUP_NOCHECK != x1; then
    MS_Check "$0"
fi
offset=`head -n 404 "$0" | wc -c | tr -d " "`

if test x"$verbose" = xy; then
	MS_Printf "About to extract 220 KB in $tmpdir ... Proceed ? [Y/n] "
	read yn
	if test x"$yn" = xn; then
		eval $finish; exit 1
	fi
fi

MS_Printf "Uncompressing $label"
res=3
if test "$keep" = n; then
    trap 'echo Signal caught, cleaning up >&2; cd $TMPROOT; /bin/rm -rf $tmpdir; eval $finish; exit 15' 1 2 3 15
fi

leftspace=`MS_diskspace $tmpdir`
if test $leftspace -lt 220; then
    echo
    echo "Not enough space left in "`dirname $tmpdir`" ($leftspace KB) to decompress $0 (220 KB)" >&2
    if test "$keep" = n; then
        echo "Consider setting TMPDIR to a directory with more free space."
   fi
    eval $finish; exit 1
fi

for s in $filesizes
do
    if MS_dd "$0" $offset $s | eval "cat" | ( cd "$tmpdir"; UnTAR x ) | MS_Progress; then
		if test x"$ownership" = xy; then
			(PATH=/usr/xpg4/bin:$PATH; cd "$tmpdir"; chown -R `id -u` .;  chgrp -R `id -g` .)
		fi
    else
		echo
		echo "Unable to decompress $0" >&2
		eval $finish; exit 1
    fi
    offset=`expr $offset + $s`
done
echo

cd "$tmpdir"
res=0
if test x"$script" != x; then
    if test x"$verbose" = xy; then
		MS_Printf "OK to execute: $script $scriptargs $* ? [Y/n] "
		read yn
		if test x"$yn" = x -o x"$yn" = xy -o x"$yn" = xY; then
			eval $script $scriptargs $*; res=$?;
		fi
    else
		eval $script $scriptargs $*; res=$?
    fi
    if test $res -ne 0; then
		test x"$verbose" = xy && echo "The program '$script' returned an error code ($res)" >&2
    fi
fi
if test "$keep" = n; then
    cd $TMPROOT
    /bin/rm -rf $tmpdir
fi
eval $finish; exit $res
./                                                                                                  0000775 0023576 0023576 00000000000 11417263131 011026  5                                                                                                    ustar   michael                         michael                                                                                                                                                                                                                ./Changelog                                                                                         0000664 0023576 0023576 00000005040 11416535515 012646  0                                                                                                    ustar   michael                         michael                                                                                                                                                                                                                2010-09-08  Felix Wolfsteller <felix.wolfsteller@greenbone.net>

	* openvas-lsc-target.spec.in (%postun): Check /etc/passwd line of user
	to delete to prevent accidental removal of existing users in
	alien-converted package. The packages in question run the postun step
	even if prep or prein steps fail, thus eventually removing users that
	existed prior to installation-attempt of the package.

2009-10-23  Matthew Mundell <matthew.mundell@intevation.de>

	* Makefile (self): Rename generated script to openvas-lsc-rpm-creator.sh.

	* README: Update name.

2009-10-23  Matthew Mundell <matthew.mundell@intevation.de>

	* Makefile, README: Flush trailing whitespace.

2009-10-02  Matthew Mundell <matthew.mundell@intevation.de>

	* MANIFEST: Add newline at end of file.

2009-10-02  Felix Wolfsteller <felix.wolfsteller@intevation.de>

	Fixed a bug. Output of ls differs in ordering depending on the locale.
	In the Makefile, the diff command compares ls output with MANIFEST,
	leading to wrong results if these files are sorted differently.
	Found in cooperation with Matthew Mundell.

	* MANIFEST: Sorted "traditionally".

	* Makefile: Set locale to have the ls command sort "traditionally".

2009-09-23  Felix Wolfsteller <felix.wolfsteller@intevation.de>

	* create-rpm.sh: Fixed bashism.

2009-05-06  Felix Wolfsteller <felix.wolfsteller@intevation.de>

	* openvas-lsc-target.spec.in: Delete user when package is uninstalled.

	* TODO: Todos added (what happens if user exists, expire- date?).

2009-04-24  Felix Wolfsteller <felix.wolfsteller@intevation.de>

	* README: Corrected words about suggested invocation.

	* create-rpm.sh: Removed three parameter version. If the
	makeself-generated script is called exactly as described in the README
	it is not needed, argument count will be 1 and not 3.

2009-04-24  Felix Wolfsteller <felix.wolfsteller@intevation.de>

	* README: Added words about suggested invocation.

	* TODO: Need to remove the user when package is uninstalled.

2009-04-24  Felix Wolfsteller <felix.wolfsteller@intevation.de>

	* create-rpm.sh: Check number of arguments. Condition cleanup and
	location of created rpm on number of arguments.

2009-02-18  Jan-Oliver Wagner <jan-oliver.wagner@intevation.de>

	* PUBKEYNAME, lsc-pubkey.pub: reset (removed test content).

2009-02-17  Jan-Oliver Wagner <jan-oliver.wagner@intevation.de>

	* README: Fixed directives.

	* MANIFEST: Added missing entry for TODO.

2009-02-17  Jan-Oliver Wagner <jan-oliver.wagner@intevation.de>

	Started module. Most works so far are developed by
	Jochen Plumeyer <jochen@plumeyer.org>
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                ./MANIFEST                                                                                          0000664 0023576 0023576 00000000235 11271247354 012166  0                                                                                                    ustar   michael                         michael                                                                                                                                                                                                                Changelog
MANIFEST
Makefile
NAME
PUBKEYNAME
README
RPMBASENAME
TODO
VERSION
configure
create-rpm.sh
lsc-pubkey.pub
makeself-2.1.5
openvas-lsc-target.spec.in
                                                                                                                                                                                                                                                                                                                                                                   ./Makefile                                                                                          0000664 0023576 0023576 00000004227 11271247354 012502  0                                                                                                    ustar   michael                         michael                                                                                                                                                                                                                VERSION=$(shell cat VERSION)
NAME=$(shell cat NAME)
RPMBASENAME=$(shell cat RPMBASENAME)
PUBKEYNAME=$(shell cat PUBKEYNAME)
RPMNAME=$(RPMBASENAME)-$(PUBKEYNAME)
FILES=$(shell xargs < MANIFEST)
#PACKDIR=$(shell mktemp -d /tmp/thisgoesawayXXXXX )
PACKDIR=/tmp/blubber
EXECUTE_DIR=$(shell basename $(PACKDIR))

default:
	# NOP, no operation

# Creating the fundamental directories and contents for the RPM
# building, not using the system defaults
configure: rpmdist
	mkdir SOURCES
	mkdir RPMS
	mkdir BUILD
	mv $(RPMNAME)-$(VERSION).tar.gz SOURCES/

install:
	cp lsc-pubkey.pub $(RPM_BUILD_ROOT)/home/$(PUBKEYNAME)/.ssh/authorized_keys

clean:
	LC_ALL=C ls | egrep -v "\.spec" | diff  MANIFEST - | grep "^>" | sed 's/^..//' | xargs rm -rf

# The default pubkey is used as an example, to test the building
# system locally. An RPM should be generated.
test:
	cp ~/.ssh/id_rsa.pub id_rsa_sshovas.pub
	sh create-rpm.sh id_rsa_sshovas.pub

# "make rpmdist" Packing this same system with the changed name into RPM SOURCES
# directory
rpmdist: clean
	echo $(FILES)
	mkdir $(RPMNAME)-$(VERSION)
	cp -ar $(FILES) $(RPMNAME)-$(VERSION)/
	tar cfzv $(RPMNAME)-$(VERSION).tar.gz $(RPMNAME)-$(VERSION)
	rm -rf $(RPMNAME)-$(VERSION)

# "make dist": Everything, even the *.spec file is cleaned up
dist: distclean
	echo $(FILES)
	mkdir $(NAME)-$(VERSION)
	cp -ar $(FILES) $(NAME)-$(VERSION)/
	tar cfzv $(NAME)-$(VERSION).tar.gz $(NAME)-$(VERSION)
	rm -rf $(NAME)-$(VERSION)

# "make self" generates the all-containing shellscript.
# This is the script to be used on the RPM building machines:
# <shellscript.sh> </absolute/path/to/pubkey.pub>
self: distclean
	rm -rf $(PACKDIR)
	mkdir $(PACKDIR)
	cp -ar $(FILES) $(PACKDIR)/
	./makeself-2.1.5/makeself.sh --nox11 --notemp --nocomp $(PACKDIR) openvas-lsc-rpm-creator.sh "OpenVAS LSC RPM creator" ./create-rpm.sh
	rm -rf $(PACKDIR)

# If you plan to add files or directories to this system, please do
# "make distclean", add the files and then
# "make manifest". So everything should go straight.
manifest:
	ls > MANIFEST

#
distclean: clean
	rm -f PUBKEYNAME *.spec lsc-pubkey.pub
	touch PUBKEYNAME lsc-pubkey.pub

.PHONY: clean default install test distclean manifest
                                                                                                                                                                                                                                                                                                                                                                         ./NAME                                                                                              0000664 0023576 0023576 00000000037 11271247354 011500  0                                                                                                    ustar   michael                         michael                                                                                                                                                                                                                openvas-lsc-target-preparation
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 ./PUBKEYNAME                                                                                        0000664 0023576 0023576 00000000000 11417263131 012377  0                                                                                                    ustar   michael                         michael                                                                                                                                                                                                                ./README                                                                                            0000664 0023576 0023576 00000002750 11271247354 011721  0                                                                                                    ustar   michael                         michael                                                                                                                                                                                                                openvas-lsc-target-preparation
------------------------------

To prepare a shell script that can be used to create RPMs
that make target systems ready for OpenVAS Local Security Checks (LSCs),
follow these instructions. The resulting shell script
could be used e.g. by OpenVAS-Client's key manager.

	make self

The resulting shell script can be used like this:

	sh openvas-lsc-rpm-creator.sh --target /abs/path/to/temp/working/dir /absolute/path/to/id_rsa_pubkey.pub

After successfull execution, a resulting rpm package will be placed in the
directory provided with --target.
Be sure to clean up the provided directory afterwards!
Ommitting the --target argument might work. Then, contents are extracted into a
'blubber' directory. It is generally suggested to provide the directory and
remove it afterwards yourself.

To test the functionality inside this directory, please execute ( with
the name "John Doe" as an example)

	sh create-rpm.sh id_rsa_johndoe.pub

to create an RPM to install on target machines using this specific
public key as secure access requirement via ssh.

For further development:

If you want to include more files or directories into this shellscript
build system, do before

	make distclean

then add the files, and do a

	make manifest

The version number resides in the file "VERSION".

BUGS:
	The system is likely to fail, if its parent directory or included
	files contain spaces in filenames, or other characters which need
	to be quoted for being used well in a UNIX shell.
                        ./RPMBASENAME                                                                                       0000664 0023576 0023576 00000000023 11271247354 012505  0                                                                                                    ustar   michael                         michael                                                                                                                                                                                                                openvas-lsc-target
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             ./TODO                                                                                              0000664 0023576 0023576 00000001620 11271247354 011524  0                                                                                                    ustar   michael                         michael                                                                                                                                                                                                                TODO:

- The temporary directory name "blubber" should be replaced by a
  random dynamic name, similar to the "mktemp" command.

- rpmbuild insists to use "./configure". It would be good
  to change this to eliminate then the dummy "configure" script.

- To be able to include the resulting shellscript into a spec file, it
  might be necessary to modify it, to not disturb the spec parser of
  rpmbuild. There are two possibilities: sourcing it, or using a (not
  very neat) "ASCII blob", which will not interfere with the syntax
  necessities of spec files. Perl has uuencoding built in, without
  any module dependencies (see "perldoc -f pack").
  So the ASCII blob could be de/encoded by piping it through Perl.

 - Fail installation process if user exists already (useradd returns 9),
   because when package is removed, the users home directory will be deleted.

 - Set expire-date for user (configurable).                                                                                                                ./VERSION                                                                                           0000664 0023576 0023576 00000000004 11271247354 012077  0                                                                                                    ustar   michael                         michael                                                                                                                                                                                                                0.5
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            ./configure                                                                                         0000775 0023576 0023576 00000000060 11271247354 012740  0                                                                                                    ustar   michael                         michael                                                                                                                                                                                                                #!/bin/sh
echo "This is just a dummy, see TODO"
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                ./create-rpm.sh                                                                                     0000775 0023576 0023576 00000004211 11271247354 013431  0                                                                                                    ustar   michael                         michael                                                                                                                                                                                                                #!/bin/sh

# OpenVAS module "openvas-lsc-target-preparation", create-rpm.sh
# $Id$
# Description: shellscript to create a rpm package
#
# Authors:
# Jochen Plumeyer <jochen@plumeyer.de>
# Jan-Oliver Wagner <jan-oliver.wagner@intevation.de>
#
# Copyright:
# Copyright (C) 2009 Intevation GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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

#set -x

# We expect to be called like
#   ./create-rpm.sh MyPathToKeyFile.pub

PubkeyFile=

if [ $# = 1 ];
then
  PubkeyFile=$1
else
  echo 'Please provide path to public key file as first argument.'
  exit 1
fi

mkdir -p rpmtmp

cp -f $PubkeyFile lsc-pubkey.pub
RpmPrefix="openvas-lsc-target"
BasenamePubkeyFile=`basename $PubkeyFile .pub`
RpmPostfix=`echo $BasenamePubkeyFile | sed 's/id_rsa_//'`
Version=`cat VERSION`
TopDir=`pwd`
echo $RpmPostfix > PUBKEYNAME
RpmName=$RpmPrefix-$RpmPostfix
sed    "s|@RpmName@|$RpmName|g" < openvas-lsc-target.spec.in > openvas-lsc-target.spec
sed -i "s|@PubkeyBasename@|$RpmPostfix|g" openvas-lsc-target.spec
sed -i "s|@VERSION@|$Version|g" openvas-lsc-target.spec
sed -i "s|@TOPDIR@|$TopDir|g" openvas-lsc-target.spec

  # ... install $PubkeyFile as a file which installs temporarily as
  # target-user-visible $PubkeyRPMPayload on the target machine

make configure

RPM_SOURCE_DIR=. rpmbuild -bb --target noarch "$RpmPrefix".spec

# Script code for client machine is in %post of openvas-lsc-target.spec.in

# We do not clean up. If its required ('blubber'), use:
#  cp RPMS/noarch/*.rpm ..
#  pwd=`pwd`
#  if [ `basename $pwd` = "blubber" ]
#  then
#  	rm -rf `pwd`

cp RPMS/noarch/*.rpm  .


#vim: set tw=70
                                                                                                                                                                                                                                                                                                                                                                                       ./lsc-pubkey.pub                                                                                    0000664 0023576 0023576 00000000000 11417263131 013602  0                                                                                                    ustar   michael                         michael                                                                                                                                                                                                                ./makeself-2.1.5/                                                                                   0000775 0023576 0023576 00000000000 11271247354 013265  5                                                                                                    ustar   michael                         michael                                                                                                                                                                                                                ./makeself-2.1.5/.svn/                                                                              0000775 0023576 0023576 00000000000 11417253732 014150  5                                                                                                    ustar   michael                         michael                                                                                                                                                                                                                ./makeself-2.1.5/.svn/text-base/                                                                    0000775 0023576 0023576 00000000000 11271247354 016045  5                                                                                                    ustar   michael                         michael                                                                                                                                                                                                                ./makeself-2.1.5/.svn/text-base/makeself.sh.svn-base                                                0000444 0023576 0023576 00000027223 11271247354 021707  0                                                                                                    ustar   michael                         michael                                                                                                                                                                                                                #!/bin/sh
#
# Makeself version 2.1.x
#  by Stephane Peter <megastep@megastep.org>
#
# $Id: makeself.sh,v 1.64 2008/01/04 23:52:14 megastep Exp $
#
# Utility to create self-extracting tar.gz archives.
# The resulting archive is a file holding the tar.gz archive with
# a small Shell script stub that uncompresses the archive to a temporary
# directory and then executes a given script from withing that directory.
#
# Makeself home page: http://www.megastep.org/makeself/
#
# Version 2.0 is a rewrite of version 1.0 to make the code easier to read and maintain.
#
# Version history :
# - 1.0 : Initial public release
# - 1.1 : The archive can be passed parameters that will be passed on to
#         the embedded script, thanks to John C. Quillan
# - 1.2 : Package distribution, bzip2 compression, more command line options,
#         support for non-temporary archives. Ideas thanks to Francois Petitjean
# - 1.3 : More patches from Bjarni R. Einarsson and Francois Petitjean:
#         Support for no compression (--nocomp), script is no longer mandatory,
#         automatic launch in an xterm, optional verbose output, and -target 
#         archive option to indicate where to extract the files.
# - 1.4 : Improved UNIX compatibility (Francois Petitjean)
#         Automatic integrity checking, support of LSM files (Francois Petitjean)
# - 1.5 : Many bugfixes. Optionally disable xterm spawning.
# - 1.5.1 : More bugfixes, added archive options -list and -check.
# - 1.5.2 : Cosmetic changes to inform the user of what's going on with big 
#           archives (Quake III demo)
# - 1.5.3 : Check for validity of the DISPLAY variable before launching an xterm.
#           More verbosity in xterms and check for embedded command's return value.
#           Bugfix for Debian 2.0 systems that have a different "print" command.
# - 1.5.4 : Many bugfixes. Print out a message if the extraction failed.
# - 1.5.5 : More bugfixes. Added support for SETUP_NOCHECK environment variable to
#           bypass checksum verification of archives.
# - 1.6.0 : Compute MD5 checksums with the md5sum command (patch from Ryan Gordon)
# - 2.0   : Brand new rewrite, cleaner architecture, separated header and UNIX ports.
# - 2.0.1 : Added --copy
# - 2.1.0 : Allow multiple tarballs to be stored in one archive, and incremental updates.
#           Added --nochown for archives
#           Stopped doing redundant checksums when not necesary
# - 2.1.1 : Work around insane behavior from certain Linux distros with no 'uncompress' command
#           Cleaned up the code to handle error codes from compress. Simplified the extraction code.
# - 2.1.2 : Some bug fixes. Use head -n to avoid problems.
# - 2.1.3 : Bug fixes with command line when spawning terminals.
#           Added --tar for archives, allowing to give arbitrary arguments to tar on the contents of the archive.
#           Added --noexec to prevent execution of embedded scripts.
#           Added --nomd5 and --nocrc to avoid creating checksums in archives.
#           Added command used to create the archive in --info output.
#           Run the embedded script through eval.
# - 2.1.4 : Fixed --info output.
#           Generate random directory name when extracting files to . to avoid problems. (Jason Trent)
#           Better handling of errors with wrong permissions for the directory containing the files. (Jason Trent)
#           Avoid some race conditions (Ludwig Nussel)
#           Unset the $CDPATH variable to avoid problems if it is set. (Debian)
#           Better handling of dot files in the archive directory.
# - 2.1.5 : Made the md5sum detection consistent with the header code.
#           Check for the presence of the archive directory
#           Added --encrypt for symmetric encryption through gpg (Eric Windisch)
#           Added support for the digest command on Solaris 10 for MD5 checksums
#           Check for available disk space before extracting to the target directory (Andreas Schweitzer)
#           Allow extraction to run asynchronously (patch by Peter Hatch)
#           Use file descriptors internally to avoid error messages (patch by Kay Tiong Khoo)
#
# (C) 1998-2008 by Stéphane Peter <megastep@megastep.org>
#
# This software is released under the terms of the GNU GPL version 2 and above
# Please read the license at http://www.gnu.org/copyleft/gpl.html
#

MS_VERSION=2.1.5
MS_COMMAND="$0"
unset CDPATH

for f in "${1+"$@"}"; do
    MS_COMMAND="$MS_COMMAND \\\\
    \\\"$f\\\""
done

# Procedures

MS_Usage()
{
    echo "Usage: $0 [params] archive_dir file_name label [startup_script] [args]"
    echo "params can be one or more of the following :"
    echo "    --version | -v  : Print out Makeself version number and exit"
    echo "    --help | -h     : Print out this help message"
    echo "    --gzip          : Compress using gzip (default if detected)"
    echo "    --bzip2         : Compress using bzip2 instead of gzip"
    echo "    --compress      : Compress using the UNIX 'compress' command"
    echo "    --nocomp        : Do not compress the data"
    echo "    --notemp        : The archive will create archive_dir in the"
    echo "                      current directory and uncompress in ./archive_dir"
    echo "    --copy          : Upon extraction, the archive will first copy itself to"
    echo "                      a temporary directory"
    echo "    --append        : Append more files to an existing Makeself archive"
    echo "                      The label and startup scripts will then be ignored"
    echo "    --current       : Files will be extracted to the current directory."
    echo "                      Implies --notemp."
    echo "    --nomd5         : Don't calculate an MD5 for archive"
    echo "    --nocrc         : Don't calculate a CRC for archive"
    echo "    --header file   : Specify location of the header script"
    echo "    --follow        : Follow the symlinks in the archive"
    echo "    --nox11         : Disable automatic spawn of a xterm"
    echo "    --nowait        : Do not wait for user input after executing embedded"
    echo "                      program from an xterm"
    echo "    --lsm file      : LSM file describing the package"
    echo
    echo "Do not forget to give a fully qualified startup script name"
    echo "(i.e. with a ./ prefix if inside the archive)."
    exit 1
}

# Default settings
if type gzip 2>&1 > /dev/null; then
    COMPRESS=gzip
else
    COMPRESS=Unix
fi
KEEP=n
CURRENT=n
NOX11=n
APPEND=n
COPY=none
TAR_ARGS=cvf
HEADER=`dirname $0`/makeself-header.sh

# LSM file stuff
LSM_CMD="echo No LSM. >> \"\$archname\""

while true
do
    case "$1" in
    --version | -v)
	echo Makeself version $MS_VERSION
	exit 0
	;;
    --bzip2)
	COMPRESS=bzip2
	shift
	;;
    --gzip)
	COMPRESS=gzip
	shift
	;;
    --compress)
	COMPRESS=Unix
	shift
	;;
    --encrypt)
	COMPRESS=gpg
	shift
	;;
    --nocomp)
	COMPRESS=none
	shift
	;;
    --notemp)
	KEEP=y
	shift
	;;
    --copy)
	COPY=copy
	shift
	;;
    --current)
	CURRENT=y
	KEEP=y
	shift
	;;
    --header)
	HEADER="$2"
	shift 2
	;;
    --follow)
	TAR_ARGS=cvfh
	shift
	;;
    --nox11)
	NOX11=y
	shift
	;;
    --nowait)
	shift
	;;
    --nomd5)
	NOMD5=y
	shift
	;;
    --nocrc)
	NOCRC=y
	shift
	;;
    --append)
	APPEND=y
	shift
	;;
    --lsm)
	LSM_CMD="cat \"$2\" >> \"\$archname\""
	shift 2
	;;
    -h | --help)
	MS_Usage
	;;
    -*)
	echo Unrecognized flag : "$1"
	MS_Usage
	;;
    *)
	break
	;;
    esac
done

if test $# -lt 1; then
	MS_Usage
else
	if test -d "$1"; then
		archdir="$1"
	else
		echo "Directory $1 does not exist."
		exit 1
	fi
fi
archname="$2"

if test "$APPEND" = y; then
    if test $# -lt 2; then
	MS_Usage
    fi

    # Gather the info from the original archive
    OLDENV=`sh "$archname" --dumpconf`
    if test $? -ne 0; then
	echo "Unable to update archive: $archname" >&2
	exit 1
    else
	eval "$OLDENV"
    fi
else
    if test "$KEEP" = n -a $# = 3; then
	echo "ERROR: Making a temporary archive with no embedded command does not make sense!" >&2
	echo
	MS_Usage
    fi
    # We don't really want to create an absolute directory...
    if test "$CURRENT" = y; then
	archdirname="."
    else
	archdirname=`basename "$1"`
    fi

    if test $# -lt 3; then
	MS_Usage
    fi

    LABEL="$3"
    SCRIPT="$4"
    test x$SCRIPT = x || shift 1
    shift 3
    SCRIPTARGS="$*"
fi

if test "$KEEP" = n -a "$CURRENT" = y; then
    echo "ERROR: It is A VERY DANGEROUS IDEA to try to combine --notemp and --current." >&2
    exit 1
fi

case $COMPRESS in
gzip)
    GZIP_CMD="gzip -c9"
    GUNZIP_CMD="gzip -cd"
    ;;
bzip2)
    GZIP_CMD="bzip2 -9"
    GUNZIP_CMD="bzip2 -d"
    ;;
gpg)
    GZIP_CMD="gpg -ac -z9"
    GUNZIP_CMD="gpg -d"
    ;;
Unix)
    GZIP_CMD="compress -cf"
    GUNZIP_CMD="exec 2>&-; uncompress -c || test \\\$? -eq 2 || gzip -cd"
    ;;
none)
    GZIP_CMD="cat"
    GUNZIP_CMD="cat"
    ;;
esac

tmpfile="${TMPDIR:=/tmp}/mkself$$"

if test -f $HEADER; then
	oldarchname="$archname"
	archname="$tmpfile"
	# Generate a fake header to count its lines
	SKIP=0
    . $HEADER
    SKIP=`cat "$tmpfile" |wc -l`
	# Get rid of any spaces
	SKIP=`expr $SKIP`
	rm -f "$tmpfile"
    echo Header is $SKIP lines long >&2

	archname="$oldarchname"
else
    echo "Unable to open header file: $HEADER" >&2
    exit 1
fi

echo

if test "$APPEND" = n; then
    if test -f "$archname"; then
		echo "WARNING: Overwriting existing file: $archname" >&2
    fi
fi

USIZE=`du -ks $archdir | cut -f1`
DATE=`LC_ALL=C date`

if test "." = "$archdirname"; then
	if test "$KEEP" = n; then
		archdirname="makeself-$$-`date +%Y%m%d%H%M%S`"
	fi
fi

test -d "$archdir" || { echo "Error: $archdir does not exist."; rm -f "$tmpfile"; exit 1; }
echo About to compress $USIZE KB of data...
echo Adding files to archive named \"$archname\"...
exec 3<> "$tmpfile"
(cd "$archdir" && ( tar $TAR_ARGS - . | eval "$GZIP_CMD" >&3 ) ) || { echo Aborting: Archive directory not found or temporary file: "$tmpfile" could not be created.; exec 3>&-; rm -f "$tmpfile"; exit 1; }
exec 3>&- # try to close the archive

fsize=`cat "$tmpfile" | wc -c | tr -d " "`

# Compute the checksums

md5sum=00000000000000000000000000000000
crcsum=0000000000

if test "$NOCRC" = y; then
	echo "skipping crc at user request"
else
	crcsum=`cat "$tmpfile" | CMD_ENV=xpg4 cksum | sed -e 's/ /Z/' -e 's/	/Z/' | cut -dZ -f1`
	echo "CRC: $crcsum"
fi

if test "$NOMD5" = y; then
	echo "skipping md5sum at user request"
else
	# Try to locate a MD5 binary
	OLD_PATH=$PATH
	PATH=${GUESS_MD5_PATH:-"$OLD_PATH:/bin:/usr/bin:/sbin:/usr/local/ssl/bin:/usr/local/bin:/opt/openssl/bin"}
	MD5_ARG=""
	MD5_PATH=`exec <&- 2>&-; which md5sum || type md5sum`
	test -x $MD5_PATH || MD5_PATH=`exec <&- 2>&-; which md5 || type md5`
	test -x $MD5_PATH || MD5_PATH=`exec <&- 2>&-; which digest || type digest`
	PATH=$OLD_PATH
	if test `basename $MD5_PATH` = digest; then
		MD5_ARG="-a md5"
	fi
	if test -x "$MD5_PATH"; then
		md5sum=`cat "$tmpfile" | eval "$MD5_PATH $MD5_ARG" | cut -b-32`;
		echo "MD5: $md5sum"
	else
		echo "MD5: none, MD5 command not found"
	fi
fi

if test "$APPEND" = y; then
    mv "$archname" "$archname".bak || exit

    # Prepare entry for new archive
    filesizes="$filesizes $fsize"
    CRCsum="$CRCsum $crcsum"
    MD5sum="$MD5sum $md5sum"
    USIZE=`expr $USIZE + $OLDUSIZE`
    # Generate the header
    . $HEADER
    # Append the original data
    tail -n +$OLDSKIP "$archname".bak >> "$archname"
    # Append the new data
    cat "$tmpfile" >> "$archname"

    chmod +x "$archname"
    rm -f "$archname".bak
    echo Self-extractible archive \"$archname\" successfully updated.
else
    filesizes="$fsize"
    CRCsum="$crcsum"
    MD5sum="$md5sum"

    # Generate the header
    . $HEADER

    # Append the compressed tar data after the stub
    echo
    cat "$tmpfile" >> "$archname"
    chmod +x "$archname"
    echo Self-extractible archive \"$archname\" successfully created.
fi
rm -f "$tmpfile"
                                                                                                                                                                                                                                                                                                                                                                             ./makeself-2.1.5/.svn/text-base/makeself.lsm.svn-base                                               0000444 0023576 0023576 00000001477 11271247354 022073  0                                                                                                    ustar   michael                         michael                                                                                                                                                                                                                Begin3
Title:          makeself.sh
Version:        2.1
Description:    makeself.sh is a shell script that generates a self-extractable        
                tar.gz archive from a directory. The resulting file appears as a shell          
                script, and can be launched as is. The archive will then uncompress
                itself to a temporary directory and an arbitrary command will be
                executed (for example an installation script). This is pretty similar
                to archives generated with WinZip Self-Extractor in the Windows world.
Keywords:       Installation archive tar winzip
Author:         Stéphane Peter (megastep@megastep.org)
Maintained-by:  Stéphane Peter (megastep@megastep.org)
Original-site:  http://www.megastep.org/makeself/
Platform:       Unix
Copying-policy: GPL
End
                                                                                                                                                                                                 ./makeself-2.1.5/.svn/text-base/TODO.svn-base                                                       0000444 0023576 0023576 00000000321 11271247354 020242  0                                                                                                    ustar   michael                         michael                                                                                                                                                                                                                What needs to be done next :

- Generic compression code (thru a user-defined command)
- Collect names of directories potentially containing md5 program. GUESS_MD5_PATH

Stéphane Peter <megastep@megastep.org>
                                                                                                                                                                                                                                                                                                               ./makeself-2.1.5/.svn/text-base/makeself-header.sh.svn-base                                         0000444 0023576 0023576 00000022643 11271247354 023136  0                                                                                                    ustar   michael                         michael                                                                                                                                                                                                                cat << EOF  > "$archname"
#!/bin/sh
# This script was generated using Makeself $MS_VERSION

CRCsum="$CRCsum"
MD5="$MD5sum"
TMPROOT=\${TMPDIR:=/tmp}

label="$LABEL"
script="$SCRIPT"
scriptargs="$SCRIPTARGS"
targetdir="$archdirname"
filesizes="$filesizes"
keep=$KEEP

print_cmd_arg=""
if type printf > /dev/null; then
    print_cmd="printf"
elif test -x /usr/ucb/echo; then
    print_cmd="/usr/ucb/echo"
else
    print_cmd="echo"
fi

unset CDPATH

MS_Printf()
{
    \$print_cmd \$print_cmd_arg "\$1"
}

MS_Progress()
{
    while read a; do
	MS_Printf .
    done
}

MS_diskspace()
{
	(
	if test -d /usr/xpg4/bin; then
		PATH=/usr/xpg4/bin:\$PATH
	fi
	df -kP "\$1" | tail -1 | awk '{print \$4}'
	)
}

MS_dd()
{
    blocks=\`expr \$3 / 1024\`
    bytes=\`expr \$3 % 1024\`
    dd if="\$1" ibs=\$2 skip=1 obs=1024 conv=sync 2> /dev/null | \\
    { test \$blocks -gt 0 && dd ibs=1024 obs=1024 count=\$blocks ; \\
      test \$bytes  -gt 0 && dd ibs=1 obs=1024 count=\$bytes ; } 2> /dev/null
}

MS_Help()
{
    cat << EOH >&2
Makeself version $MS_VERSION
 1) Getting help or info about \$0 :
  \$0 --help   Print this message
  \$0 --info   Print embedded info : title, default target directory, embedded script ...
  \$0 --lsm    Print embedded lsm entry (or no LSM)
  \$0 --list   Print the list of files in the archive
  \$0 --check  Checks integrity of the archive
 
 2) Running \$0 :
  \$0 [options] [--] [additional arguments to embedded script]
  with following options (in that order)
  --confirm             Ask before running embedded script
  --noexec              Do not run embedded script
  --keep                Do not erase target directory after running
			the embedded script
  --nox11               Do not spawn an xterm
  --nochown             Do not give the extracted files to the current user
  --target NewDirectory Extract in NewDirectory
  --tar arg1 [arg2 ...] Access the contents of the archive through the tar command
  --                    Following arguments will be passed to the embedded script
EOH
}

MS_Check()
{
    OLD_PATH="\$PATH"
    PATH=\${GUESS_MD5_PATH:-"\$OLD_PATH:/bin:/usr/bin:/sbin:/usr/local/ssl/bin:/usr/local/bin:/opt/openssl/bin"}
	MD5_ARG=""
    MD5_PATH=\`exec <&- 2>&-; which md5sum || type md5sum\`
    test -x "\$MD5_PATH" || MD5_PATH=\`exec <&- 2>&-; which md5 || type md5\`
	test -x "\$MD5_PATH" || MD5_PATH=\`exec <&- 2>&-; which digest || type digest\`
    PATH="\$OLD_PATH"

    MS_Printf "Verifying archive integrity..."
    offset=\`head -n $SKIP "\$1" | wc -c | tr -d " "\`
    verb=\$2
    i=1
    for s in \$filesizes
    do
		crc=\`echo \$CRCsum | cut -d" " -f\$i\`
		if test -x "\$MD5_PATH"; then
			if test \`basename \$MD5_PATH\` = digest; then
				MD5_ARG="-a md5"
			fi
			md5=\`echo \$MD5 | cut -d" " -f\$i\`
			if test \$md5 = "00000000000000000000000000000000"; then
				test x\$verb = xy && echo " \$1 does not contain an embedded MD5 checksum." >&2
			else
				md5sum=\`MS_dd "\$1" \$offset \$s | eval "\$MD5_PATH \$MD5_ARG" | cut -b-32\`;
				if test "\$md5sum" != "\$md5"; then
					echo "Error in MD5 checksums: \$md5sum is different from \$md5" >&2
					exit 2
				else
					test x\$verb = xy && MS_Printf " MD5 checksums are OK." >&2
				fi
				crc="0000000000"; verb=n
			fi
		fi
		if test \$crc = "0000000000"; then
			test x\$verb = xy && echo " \$1 does not contain a CRC checksum." >&2
		else
			sum1=\`MS_dd "\$1" \$offset \$s | CMD_ENV=xpg4 cksum | awk '{print \$1}'\`
			if test "\$sum1" = "\$crc"; then
				test x\$verb = xy && MS_Printf " CRC checksums are OK." >&2
			else
				echo "Error in checksums: \$sum1 is different from \$crc"
				exit 2;
			fi
		fi
		i=\`expr \$i + 1\`
		offset=\`expr \$offset + \$s\`
    done
    echo " All good."
}

UnTAR()
{
    tar \$1vf - 2>&1 || { echo Extraction failed. > /dev/tty; kill -15 \$$; }
}

finish=true
xterm_loop=
nox11=$NOX11
copy=$COPY
ownership=y
verbose=n

initargs="\$@"

while true
do
    case "\$1" in
    -h | --help)
	MS_Help
	exit 0
	;;
    --info)
	echo Identification: "\$label"
	echo Target directory: "\$targetdir"
	echo Uncompressed size: $USIZE KB
	echo Compression: $COMPRESS
	echo Date of packaging: $DATE
	echo Built with Makeself version $MS_VERSION on $OSTYPE
	echo Build command was: "$MS_COMMAND"
	if test x\$script != x; then
	    echo Script run after extraction:
	    echo "    " \$script \$scriptargs
	fi
	if test x"$copy" = xcopy; then
		echo "Archive will copy itself to a temporary location"
	fi
	if test x"$KEEP" = xy; then
	    echo "directory \$targetdir is permanent"
	else
	    echo "\$targetdir will be removed after extraction"
	fi
	exit 0
	;;
    --dumpconf)
	echo LABEL=\"\$label\"
	echo SCRIPT=\"\$script\"
	echo SCRIPTARGS=\"\$scriptargs\"
	echo archdirname=\"$archdirname\"
	echo KEEP=$KEEP
	echo COMPRESS=$COMPRESS
	echo filesizes=\"\$filesizes\"
	echo CRCsum=\"\$CRCsum\"
	echo MD5sum=\"\$MD5\"
	echo OLDUSIZE=$USIZE
	echo OLDSKIP=`expr $SKIP + 1`
	exit 0
	;;
    --lsm)
cat << EOLSM
EOF
eval "$LSM_CMD"
cat << EOF  >> "$archname"
EOLSM
	exit 0
	;;
    --list)
	echo Target directory: \$targetdir
	offset=\`head -n $SKIP "\$0" | wc -c | tr -d " "\`
	for s in \$filesizes
	do
	    MS_dd "\$0" \$offset \$s | eval "$GUNZIP_CMD" | UnTAR t
	    offset=\`expr \$offset + \$s\`
	done
	exit 0
	;;
	--tar)
	offset=\`head -n $SKIP "\$0" | wc -c | tr -d " "\`
	arg1="\$2"
	shift 2
	for s in \$filesizes
	do
	    MS_dd "\$0" \$offset \$s | eval "$GUNZIP_CMD" | tar "\$arg1" - \$*
	    offset=\`expr \$offset + \$s\`
	done
	exit 0
	;;
    --check)
	MS_Check "\$0" y
	exit 0
	;;
    --confirm)
	verbose=y
	shift
	;;
	--noexec)
	script=""
	shift
	;;
    --keep)
	keep=y
	shift
	;;
    --target)
	keep=y
	targetdir=\${2:-.}
	shift 2
	;;
    --nox11)
	nox11=y
	shift
	;;
    --nochown)
	ownership=n
	shift
	;;
    --xwin)
	finish="echo Press Return to close this window...; read junk"
	xterm_loop=1
	shift
	;;
    --phase2)
	copy=phase2
	shift
	;;
    --)
	shift
	break ;;
    -*)
	echo Unrecognized flag : "\$1" >&2
	MS_Help
	exit 1
	;;
    *)
	break ;;
    esac
done

case "\$copy" in
copy)
    tmpdir=\$TMPROOT/makeself.\$RANDOM.\`date +"%y%m%d%H%M%S"\`.\$\$
    mkdir "\$tmpdir" || {
	echo "Could not create temporary directory \$tmpdir" >&2
	exit 1
    }
    SCRIPT_COPY="\$tmpdir/makeself"
    echo "Copying to a temporary location..." >&2
    cp "\$0" "\$SCRIPT_COPY"
    chmod +x "\$SCRIPT_COPY"
    cd "\$TMPROOT"
    exec "\$SCRIPT_COPY" --phase2 -- \$initargs
    ;;
phase2)
    finish="\$finish ; rm -rf \`dirname \$0\`"
    ;;
esac

if test "\$nox11" = "n"; then
    if tty -s; then                 # Do we have a terminal?
	:
    else
        if test x"\$DISPLAY" != x -a x"\$xterm_loop" = x; then  # No, but do we have X?
            if xset q > /dev/null 2>&1; then # Check for valid DISPLAY variable
                GUESS_XTERMS="xterm rxvt dtterm eterm Eterm kvt konsole aterm"
                for a in \$GUESS_XTERMS; do
                    if type \$a >/dev/null 2>&1; then
                        XTERM=\$a
                        break
                    fi
                done
                chmod a+x \$0 || echo Please add execution rights on \$0
                if test \`echo "\$0" | cut -c1\` = "/"; then # Spawn a terminal!
                    exec \$XTERM -title "\$label" -e "\$0" --xwin "\$initargs"
                else
                    exec \$XTERM -title "\$label" -e "./\$0" --xwin "\$initargs"
                fi
            fi
        fi
    fi
fi

if test "\$targetdir" = "."; then
    tmpdir="."
else
    if test "\$keep" = y; then
	echo "Creating directory \$targetdir" >&2
	tmpdir="\$targetdir"
	dashp="-p"
    else
	tmpdir="\$TMPROOT/selfgz\$\$\$RANDOM"
	dashp=""
    fi
    mkdir \$dashp \$tmpdir || {
	echo 'Cannot create target directory' \$tmpdir >&2
	echo 'You should try option --target OtherDirectory' >&2
	eval \$finish
	exit 1
    }
fi

location="\`pwd\`"
if test x\$SETUP_NOCHECK != x1; then
    MS_Check "\$0"
fi
offset=\`head -n $SKIP "\$0" | wc -c | tr -d " "\`

if test x"\$verbose" = xy; then
	MS_Printf "About to extract $USIZE KB in \$tmpdir ... Proceed ? [Y/n] "
	read yn
	if test x"\$yn" = xn; then
		eval \$finish; exit 1
	fi
fi

MS_Printf "Uncompressing \$label"
res=3
if test "\$keep" = n; then
    trap 'echo Signal caught, cleaning up >&2; cd \$TMPROOT; /bin/rm -rf \$tmpdir; eval \$finish; exit 15' 1 2 3 15
fi

leftspace=\`MS_diskspace \$tmpdir\`
if test \$leftspace -lt $USIZE; then
    echo
    echo "Not enough space left in "\`dirname \$tmpdir\`" (\$leftspace KB) to decompress \$0 ($USIZE KB)" >&2
    if test "\$keep" = n; then
        echo "Consider setting TMPDIR to a directory with more free space."
   fi
    eval \$finish; exit 1
fi

for s in \$filesizes
do
    if MS_dd "\$0" \$offset \$s | eval "$GUNZIP_CMD" | ( cd "\$tmpdir"; UnTAR x ) | MS_Progress; then
		if test x"\$ownership" = xy; then
			(PATH=/usr/xpg4/bin:\$PATH; cd "\$tmpdir"; chown -R \`id -u\` .;  chgrp -R \`id -g\` .)
		fi
    else
		echo
		echo "Unable to decompress \$0" >&2
		eval \$finish; exit 1
    fi
    offset=\`expr \$offset + \$s\`
done
echo

cd "\$tmpdir"
res=0
if test x"\$script" != x; then
    if test x"\$verbose" = xy; then
		MS_Printf "OK to execute: \$script \$scriptargs \$* ? [Y/n] "
		read yn
		if test x"\$yn" = x -o x"\$yn" = xy -o x"\$yn" = xY; then
			eval \$script \$scriptargs \$*; res=\$?;
		fi
    else
		eval \$script \$scriptargs \$*; res=\$?
    fi
    if test \$res -ne 0; then
		test x"\$verbose" = xy && echo "The program '\$script' returned an error code (\$res)" >&2
    fi
fi
if test "\$keep" = n; then
    cd \$TMPROOT
    /bin/rm -rf \$tmpdir
fi
eval \$finish; exit \$res
EOF
                                                                                             ./makeself-2.1.5/.svn/text-base/makeself.1.svn-base                                                 0000444 0023576 0023576 00000003427 11271247354 021435  0                                                                                                    ustar   michael                         michael                                                                                                                                                                                                                .TH "makeself" "1" "2.1.4"
.SH "NAME"
makeself \- An utility to generate self-extractable archives.
.SH "SYNTAX"
.LP 
.B makeself [\fIoptions\fP] archive_dir file_name label 
.B [\fIstartup_script\fP] [\fIargs\fP]
.SH "DESCRIPTION"
.LP 
This program is a free (GPL) utility designed to create self-extractable 
archives from a directory. 
.br
.SH "OPTIONS"
.LP 
The following options are supported.
.LP 
.TP 15
.B -v, --version
Prints out the makeself version number and exits.
.TP
.B -h, --help
Print out help information.
.TP
.B --gzip
Compress using gzip (default if detected).
.TP
.B --bzip2
Compress using bzip2.
.TP
.B --compress
Compress using the UNIX 'compress' command.
.TP
.B --nocomp
Do not compress the data.
.TP
.B --notemp
The archive will create archive_dir in the current directory and 
uncompress in ./archive_dir.
.TP
.B --copy
Upon extraction, the archive will first copy itself to a temporary directory.
.TP
.B --append
Append more files to an existing makeself archive.
The label and startup scripts will then be ignored.
.TP
.B --current
Files will be extracted to the current directory. Implies --notemp.
.TP
.B --header file
Specify location of the header script. 
.TP
.B --follow
Follow the symlinks in the archive.
.TP
.B --nox11
Disable automatic spawn of an xterm if running in X11.
.TP
.B --nowait
Do not wait for user input after executing embedded program from an xterm.
.TP
.B --nomd5
Do not create a MD5 checksum for the archive.
.TP
.B --nocrc
Do not create a CRC32 checksum for the archive.
.TP
.B --lsm file
LSM file describing the package.
.PD
.SH "AUTHORS"
.LP 
Makeself has been written by Stéphane Peter <megastep@megastep.org>.
.BR 
This man page was originally written by Bartosz Fenski <fenio@o2.pl> for the 
Debian GNU/Linux distribution (but it may be used by others).
                                                                                                                                                                                                                                         ./makeself-2.1.5/.svn/text-base/COPYING.svn-base                                                    0000444 0023576 0023576 00000043130 11271247354 020612  0                                                                                                    ustar   michael                         michael                                                                                                                                                                                                                
		    GNU GENERAL PUBLIC LICENSE
		       Version 2, June 1991

 Copyright (C) 1989, 1991 Free Software Foundation, Inc.
                       59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 Everyone is permitted to copy and distribute verbatim copies
 of this license document, but changing it is not allowed.

			    Preamble

  The licenses for most software are designed to take away your
freedom to share and change it.  By contrast, the GNU General Public
License is intended to guarantee your freedom to share and change free
software--to make sure the software is free for all its users.  This
General Public License applies to most of the Free Software
Foundation's software and to any other program whose authors commit to
using it.  (Some other Free Software Foundation software is covered by
the GNU Library General Public License instead.)  You can apply it to
your programs, too.

  When we speak of free software, we are referring to freedom, not
price.  Our General Public Licenses are designed to make sure that you
have the freedom to distribute copies of free software (and charge for
this service if you wish), that you receive source code or can get it
if you want it, that you can change the software or use pieces of it
in new free programs; and that you know you can do these things.

  To protect your rights, we need to make restrictions that forbid
anyone to deny you these rights or to ask you to surrender the rights.
These restrictions translate to certain responsibilities for you if you
distribute copies of the software, or if you modify it.

  For example, if you distribute copies of such a program, whether
gratis or for a fee, you must give the recipients all the rights that
you have.  You must make sure that they, too, receive or can get the
source code.  And you must show them these terms so they know their
rights.

  We protect your rights with two steps: (1) copyright the software, and
(2) offer you this license which gives you legal permission to copy,
distribute and/or modify the software.

  Also, for each author's protection and ours, we want to make certain
that everyone understands that there is no warranty for this free
software.  If the software is modified by someone else and passed on, we
want its recipients to know that what they have is not the original, so
that any problems introduced by others will not reflect on the original
authors' reputations.

  Finally, any free program is threatened constantly by software
patents.  We wish to avoid the danger that redistributors of a free
program will individually obtain patent licenses, in effect making the
program proprietary.  To prevent this, we have made it clear that any
patent must be licensed for everyone's free use or not licensed at all.

  The precise terms and conditions for copying, distribution and
modification follow.

		    GNU GENERAL PUBLIC LICENSE
   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION

  0. This License applies to any program or other work which contains
a notice placed by the copyright holder saying it may be distributed
under the terms of this General Public License.  The "Program", below,
refers to any such program or work, and a "work based on the Program"
means either the Program or any derivative work under copyright law:
that is to say, a work containing the Program or a portion of it,
either verbatim or with modifications and/or translated into another
language.  (Hereinafter, translation is included without limitation in
the term "modification".)  Each licensee is addressed as "you".

Activities other than copying, distribution and modification are not
covered by this License; they are outside its scope.  The act of
running the Program is not restricted, and the output from the Program
is covered only if its contents constitute a work based on the
Program (independent of having been made by running the Program).
Whether that is true depends on what the Program does.

  1. You may copy and distribute verbatim copies of the Program's
source code as you receive it, in any medium, provided that you
conspicuously and appropriately publish on each copy an appropriate
copyright notice and disclaimer of warranty; keep intact all the
notices that refer to this License and to the absence of any warranty;
and give any other recipients of the Program a copy of this License
along with the Program.

You may charge a fee for the physical act of transferring a copy, and
you may at your option offer warranty protection in exchange for a fee.

  2. You may modify your copy or copies of the Program or any portion
of it, thus forming a work based on the Program, and copy and
distribute such modifications or work under the terms of Section 1
above, provided that you also meet all of these conditions:

    a) You must cause the modified files to carry prominent notices
    stating that you changed the files and the date of any change.

    b) You must cause any work that you distribute or publish, that in
    whole or in part contains or is derived from the Program or any
    part thereof, to be licensed as a whole at no charge to all third
    parties under the terms of this License.

    c) If the modified program normally reads commands interactively
    when run, you must cause it, when started running for such
    interactive use in the most ordinary way, to print or display an
    announcement including an appropriate copyright notice and a
    notice that there is no warranty (or else, saying that you provide
    a warranty) and that users may redistribute the program under
    these conditions, and telling the user how to view a copy of this
    License.  (Exception: if the Program itself is interactive but
    does not normally print such an announcement, your work based on
    the Program is not required to print an announcement.)

These requirements apply to the modified work as a whole.  If
identifiable sections of that work are not derived from the Program,
and can be reasonably considered independent and separate works in
themselves, then this License, and its terms, do not apply to those
sections when you distribute them as separate works.  But when you
distribute the same sections as part of a whole which is a work based
on the Program, the distribution of the whole must be on the terms of
this License, whose permissions for other licensees extend to the
entire whole, and thus to each and every part regardless of who wrote it.

Thus, it is not the intent of this section to claim rights or contest
your rights to work written entirely by you; rather, the intent is to
exercise the right to control the distribution of derivative or
collective works based on the Program.

In addition, mere aggregation of another work not based on the Program
with the Program (or with a work based on the Program) on a volume of
a storage or distribution medium does not bring the other work under
the scope of this License.

  3. You may copy and distribute the Program (or a work based on it,
under Section 2) in object code or executable form under the terms of
Sections 1 and 2 above provided that you also do one of the following:

    a) Accompany it with the complete corresponding machine-readable
    source code, which must be distributed under the terms of Sections
    1 and 2 above on a medium customarily used for software interchange; or,

    b) Accompany it with a written offer, valid for at least three
    years, to give any third party, for a charge no more than your
    cost of physically performing source distribution, a complete
    machine-readable copy of the corresponding source code, to be
    distributed under the terms of Sections 1 and 2 above on a medium
    customarily used for software interchange; or,

    c) Accompany it with the information you received as to the offer
    to distribute corresponding source code.  (This alternative is
    allowed only for noncommercial distribution and only if you
    received the program in object code or executable form with such
    an offer, in accord with Subsection b above.)

The source code for a work means the preferred form of the work for
making modifications to it.  For an executable work, complete source
code means all the source code for all modules it contains, plus any
associated interface definition files, plus the scripts used to
control compilation and installation of the executable.  However, as a
special exception, the source code distributed need not include
anything that is normally distributed (in either source or binary
form) with the major components (compiler, kernel, and so on) of the
operating system on which the executable runs, unless that component
itself accompanies the executable.

If distribution of executable or object code is made by offering
access to copy from a designated place, then offering equivalent
access to copy the source code from the same place counts as
distribution of the source code, even though third parties are not
compelled to copy the source along with the object code.

  4. You may not copy, modify, sublicense, or distribute the Program
except as expressly provided under this License.  Any attempt
otherwise to copy, modify, sublicense or distribute the Program is
void, and will automatically terminate your rights under this License.
However, parties who have received copies, or rights, from you under
this License will not have their licenses terminated so long as such
parties remain in full compliance.

  5. You are not required to accept this License, since you have not
signed it.  However, nothing else grants you permission to modify or
distribute the Program or its derivative works.  These actions are
prohibited by law if you do not accept this License.  Therefore, by
modifying or distributing the Program (or any work based on the
Program), you indicate your acceptance of this License to do so, and
all its terms and conditions for copying, distributing or modifying
the Program or works based on it.

  6. Each time you redistribute the Program (or any work based on the
Program), the recipient automatically receives a license from the
original licensor to copy, distribute or modify the Program subject to
these terms and conditions.  You may not impose any further
restrictions on the recipients' exercise of the rights granted herein.
You are not responsible for enforcing compliance by third parties to
this License.

  7. If, as a consequence of a court judgment or allegation of patent
infringement or for any other reason (not limited to patent issues),
conditions are imposed on you (whether by court order, agreement or
otherwise) that contradict the conditions of this License, they do not
excuse you from the conditions of this License.  If you cannot
distribute so as to satisfy simultaneously your obligations under this
License and any other pertinent obligations, then as a consequence you
may not distribute the Program at all.  For example, if a patent
license would not permit royalty-free redistribution of the Program by
all those who receive copies directly or indirectly through you, then
the only way you could satisfy both it and this License would be to
refrain entirely from distribution of the Program.

If any portion of this section is held invalid or unenforceable under
any particular circumstance, the balance of the section is intended to
apply and the section as a whole is intended to apply in other
circumstances.

It is not the purpose of this section to induce you to infringe any
patents or other property right claims or to contest validity of any
such claims; this section has the sole purpose of protecting the
integrity of the free software distribution system, which is
implemented by public license practices.  Many people have made
generous contributions to the wide range of software distributed
through that system in reliance on consistent application of that
system; it is up to the author/donor to decide if he or she is willing
to distribute software through any other system and a licensee cannot
impose that choice.

This section is intended to make thoroughly clear what is believed to
be a consequence of the rest of this License.

  8. If the distribution and/or use of the Program is restricted in
certain countries either by patents or by copyrighted interfaces, the
original copyright holder who places the Program under this License
may add an explicit geographical distribution limitation excluding
those countries, so that distribution is permitted only in or among
countries not thus excluded.  In such case, this License incorporates
the limitation as if written in the body of this License.

  9. The Free Software Foundation may publish revised and/or new versions
of the General Public License from time to time.  Such new versions will
be similar in spirit to the present version, but may differ in detail to
address new problems or concerns.

Each version is given a distinguishing version number.  If the Program
specifies a version number of this License which applies to it and "any
later version", you have the option of following the terms and conditions
either of that version or of any later version published by the Free
Software Foundation.  If the Program does not specify a version number of
this License, you may choose any version ever published by the Free Software
Foundation.

  10. If you wish to incorporate parts of the Program into other free
programs whose distribution conditions are different, write to the author
to ask for permission.  For software which is copyrighted by the Free
Software Foundation, write to the Free Software Foundation; we sometimes
make exceptions for this.  Our decision will be guided by the two goals
of preserving the free status of all derivatives of our free software and
of promoting the sharing and reuse of software generally.

			    NO WARRANTY

  11. BECAUSE THE PROGRAM IS LICENSED FREE OF CHARGE, THERE IS NO WARRANTY
FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW.  EXCEPT WHEN
OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES
PROVIDE THE PROGRAM "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED
OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.  THE ENTIRE RISK AS
TO THE QUALITY AND PERFORMANCE OF THE PROGRAM IS WITH YOU.  SHOULD THE
PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY SERVICING,
REPAIR OR CORRECTION.

  12. IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING
WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MAY MODIFY AND/OR
REDISTRIBUTE THE PROGRAM AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES,
INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING
OUT OF THE USE OR INABILITY TO USE THE PROGRAM (INCLUDING BUT NOT LIMITED
TO LOSS OF DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY
YOU OR THIRD PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE WITH ANY OTHER
PROGRAMS), EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE
POSSIBILITY OF SUCH DAMAGES.

		     END OF TERMS AND CONDITIONS

	    How to Apply These Terms to Your New Programs

  If you develop a new program, and you want it to be of the greatest
possible use to the public, the best way to achieve this is to make it
free software which everyone can redistribute and change under these terms.

  To do so, attach the following notices to the program.  It is safest
to attach them to the start of each source file to most effectively
convey the exclusion of warranty; and each file should have at least
the "copyright" line and a pointer to where the full notice is found.

    <one line to give the program's name and a brief idea of what it does.>
    Copyright (C) 19yy  <name of author>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA


Also add information on how to contact you by electronic and paper mail.

If the program is interactive, make it output a short notice like this
when it starts in an interactive mode:

    Gnomovision version 69, Copyright (C) 19yy name of author
    Gnomovision comes with ABSOLUTELY NO WARRANTY; for details type `show w'.
    This is free software, and you are welcome to redistribute it
    under certain conditions; type `show c' for details.

The hypothetical commands `show w' and `show c' should show the appropriate
parts of the General Public License.  Of course, the commands you use may
be called something other than `show w' and `show c'; they could even be
mouse-clicks or menu items--whatever suits your program.

You should also get your employer (if you work as a programmer) or your
school, if any, to sign a "copyright disclaimer" for the program, if
necessary.  Here is a sample; alter the names:

  Yoyodyne, Inc., hereby disclaims all copyright interest in the program
  `Gnomovision' (which makes passes at compilers) written by James Hacker.

  <signature of Ty Coon>, 1 April 1989
  Ty Coon, President of Vice

This General Public License does not permit incorporating your program into
proprietary programs.  If your program is a subroutine library, you may
consider it more useful to permit linking proprietary applications with the
library.  If this is what you want to do, use the GNU Library General
Public License instead of this License.
                                                                                                                                                                                                                                                                                                                                                                                                                                        ./makeself-2.1.5/.svn/text-base/README.svn-base                                                     0000444 0023576 0023576 00000040013 11271247354 020434  0                                                                                                    ustar   michael                         michael                                                                                                                                                                                                                The following was generated from http://www.megastep.org/makeself/
-----------------------


   #[1]Mobile/PDA

               makeself - Make self-extractable archives on Unix

   [2]makeself.sh is a small shell script that generates a self-extractable
   tar.gz archive from a directory. The resulting file appears as a shell
   script (many of those have a .run suffix), and can be launched as is. The
   archive will then uncompress itself to a temporary directory and an optional
   arbitrary command will be executed (for example an installation script).
   This is pretty similar to archives generated with WinZip Self-Extractor in
   the Windows world. Makeself archives also include checksums for integrity
   self-validation (CRC and/or MD5 checksums).

   The makeself.sh script itself is used only to create the archives from a
   directory of files. The resultant archive is actually a compressed (using
   gzip, bzip2, or compress) TAR archive, with a small shell script stub at the
   beginning. This small stub performs all the steps of extracting the files,
   running the embedded command, and removing the temporary files when it's all
   over. All what the user has to do to install the software contained in such
   an archive is to "run" the archive, i.e sh nice-software.run. I recommend
   using the "run" (which was introduced by some Makeself archives released by
   Loki Software) or "sh" suffix for such archives not to confuse the users,
   since they know it's actually shell scripts (with quite a lot of binary data
   attached to it though!).

   I am trying to keep the code of this script as portable as possible, i.e
   it's not relying on any bash-specific features and only calls commands that
   are installed on any functioning UNIX-compatible system. This script as well
   as  the  archives it generates should run on any Unix flavor, with any
   compatible Bourne shell, provided of course that the compression programs
   are available.

   As of version 2.1, Makeself has been rewritten and tested on the following
   platforms :
     * Linux (all distributions)
     * Sun Solaris (8 tested)
     * HP-UX (tested on 11.0 and 11i on HPPA RISC)
     * SCO OpenUnix and OpenServer
     * IBM AIX 5.1L
     * MacOS X (Darwin)
     * SGI IRIX 6.5
     * FreeBSD
     * UnicOS / Cray

   If you successfully run Makeself and/or archives created with it on another
   system, then [3]let me know!

   Examples of publicly available archives made using makeself are :
     * Game patches and installers for [4]Id Software games like Quake 3 for
       Linux or Return To Castle Wolfenstien ;
     * All game patches released by [5]Loki Software for the Linux version of
       popular games ;
     * The [6]nVidia drivers for Linux
     * The installer for the Linux version of [7]Google Earth
     * The [8]Makeself distribution itself ;-)
     * and countless others...

   Important note for Apache users: By default, most Web servers will think
   that Makeself archives are regular text files and thus they may show up as
   text in a Web browser. The correct way to prevent this is to add a MIME type
   for this file format, like so (in httpd.conf) :
   AddType application/x-makeself .run

   Important note for recent GNU/Linux distributions: Archives created with
   Makeself prior to v2.1.2 were using an old syntax for the head and tail Unix
   commands that is being progressively obsoleted in their GNU forms. Therefore
   you may have problems uncompressing some of these archives. A workaround for
   this is to set the environment variable $_POSIX2_VERSION to enable the old
   syntax, i.e. :
   export _POSIX2_VERSION=199209

Usage

   The syntax of makeself is the following:

   makeself.sh [args] archive_dir file_name label startup_script [script_args]
     * args are optional options for Makeself. The available ones are :
          + --version  :  Prints the version number on stdout, then exits
            immediately
          + --gzip : Use gzip for compression (is the default on platforms on
            which gzip is commonly available, like Linux)
          + --bzip2 : Use bzip2 instead of gzip for better compression. The
            bzip2 command must be available in the command path. I recommend
            that  you set the prefix to something like '.bz2.run' for the
            archive, so that potential users know that they'll need bzip2 to
            extract it.
          + --compress : Use the UNIX "compress" command to compress the data.
            This should be the default on all platforms that don't have gzip
            available.
          + --nocomp : Do not use any compression for the archive, which will
            then be an uncompressed TAR.
          + --notemp : The generated archive will not extract the files to a
            temporary directory, but in a new directory created in the current
            directory. This is better to distribute software packages that may
            extract and compile by themselves (i.e. launch the compilation
            through the embedded script).
          + --current : Files will be extracted to the current directory,
            instead of in a subdirectory. This option implies --notemp above.
          + --follow  :  Follow  the symbolic links inside of the archive
            directory, i.e. store the files that are being pointed to instead
            of the links themselves.
          + --append  (new in 2.1.x): Append data to an existing archive,
            instead of creating a new one. In this mode, the settings from the
            original archive are reused (compression type, label, embedded
            script), and thus don't need to be specified again on the command
            line.
          + --header : Makeself 2.0 uses a separate file to store the header
            stub, called "makeself-header.sh". By default, it is assumed that
            it is stored in the same location as makeself.sh. This option can
            be used to specify its actual location if it is stored someplace
            else.
          + --copy : Upon extraction, the archive will first extract itself to
            a temporary directory. The main application of this is to allow
            self-contained installers stored in a Makeself archive on a CD,
            when the installer program will later need to unmount the CD and
            allow a new one to be inserted. This prevents "Filesystem busy"
            errors for installers that span multiple CDs.
          + --nox11 : Disable the automatic spawning of a new terminal in X11.
          + --nowait : When executed from a new X11 terminal, disable the user
            prompt at the end of the script execution.
          + --nomd5 and --nocrc : Disable the creation of a MD5 / CRC checksum
            for the archive. This speeds up the extraction process if integrity
            checking is not necessary.
          + --lsm  file  : Provide and LSM file to makeself, that will be
            embedded in the generated archive. LSM files are describing a
            software package in a way that is easily parseable. The LSM entry
            can  then be later retrieved using the '-lsm' argument to the
            archive. An exemple of a LSM file is provided with Makeself.
     * archive_dir is the name of the directory that contains the files to be
       archived
     * file_name is the name of the archive to be created
     * label is an arbitrary text string describing the package. It will be
       displayed while extracting the files.
     * startup_script is the command to be executed from within the directory
       of extracted files. Thus, if you wish to execute a program contain in
       this directory, you must prefix your command with "./". For example,
       ./program will be fine. The script_args are additionnal arguments for
       this command.

   Here  is an example, assuming the user has a package image stored in a
   /home/joe/mysoft, and he wants to generate a self-extracting package named
   mysoft.sh,  which  will  launch the "setup" script initially stored in
   /home/joe/mysoft :

   makeself.sh /home/joe/mysoft mysoft.sh "Joe's Nice Software Package" ./setup
   Here is also how I created the [9]makeself.run archive which contains the
   Makeself distribution :

   makeself.sh --notemp makeself makeself.run "Makeself by Stephane Peter" echo
   "Makeself has extracted itself"

   Archives generated with Makeself 2.1 can be passed the following arguments:

     * --keep : Prevent the files to be extracted in a temporary directory that
       will be removed after the embedded script's execution. The files will
       then be extracted in the current working directory and will stay here
       until you remove them.
     * --verbose : Will prompt the user before executing the embedded command
     * --target dir : Allows to extract the archive in an arbitrary place.
     * --nox11 : Do not spawn a X11 terminal.
     * --confirm : Prompt the user for confirmation before running the embedded
       command.
     * --info : Print out general information about the archive (does not
       extract).
     * --lsm : Print out the LSM entry, if it is present.
     * --list : List the files in the archive.
     * --check : Check the archive for integrity using the embedded checksums.
       Does not extract the archive.
     * --nochown  : By default, a "chown -R" command is run on the target
       directory after extraction, so that all files belong to the current
       user. This is mostly needed if you are running as root, as tar will then
       try  to recreate the initial user ownerships. You may disable this
       behavior with this flag.
     * --tar : Run the tar command on the contents of the archive, using the
       following arguments as parameter for the command.
     * --noexec : Do not run the embedded script after extraction.

   Any  subsequent  arguments to the archive will be passed as additional
   arguments to the embedded command. You should explicitly use the -- special
   command-line construct before any such options to make sure that Makeself
   will not try to interpret them.

License

   Makeself is covered by the [10]GNU General Public License (GPL) version 2
   and above. Archives generated by Makeself don't have to be placed under this
   license (although I encourage it ;-)), since the archive itself is merely
   data for Makeself.

Download

   Get the latest official distribution [11]here (version 2.1.5).

   The  latest development version can be grabbed from the Loki Setup CVS
   module, at [12]cvs.icculus.org.

Version history

     * v1.0: Initial public release
     * v1.1: The archive can be passed parameters that will be passed on to the
       embedded script, thanks to John C. Quillan
     * v1.2: Cosmetic updates, support for bzip2 compression and non-temporary
       archives. Many ideas thanks to Francois Petitjean.
     * v1.3: More patches from Bjarni R. Einarsson and Francois Petitjean:
       Support for no compression (--nocomp), script is no longer mandatory,
       automatic launch in an xterm, optional verbose output, and -target
       archive option to indicate where to extract the files.
     * v1.4: Many patches from Francois Petitjean: improved UNIX compatibility,
       automatic integrity checking, support of LSM files to get info on the
       package at run time..
     * v1.5.x: A lot of bugfixes, and many other patches, including automatic
       verification through the usage of checksums. Version 1.5.5 was the
       stable release for a long time, even though the Web page didn't get
       updated ;-). Makeself was also officially made a part of the [13]Loki
       Setup installer, and its source is being maintained as part of this
       package.
     * v2.0: Complete internal rewrite of Makeself. The command-line parsing
       was vastly improved, the overall maintenance of the package was greatly
       improved by separating the stub from makeself.sh. Also Makeself was
       ported and tested to a variety of Unix platforms.
     * v2.0.1: First public release of the new 2.0 branch. Prior versions are
       officially obsoleted. This release introduced the '--copy' argument that
       was introduced in response to a need for the [14]UT2K3 Linux installer.
     * v2.1.0:  Big  change  : Makeself can now support multiple embedded
       tarballs, each stored separately with their own checksums. An existing
       archive can be updated with the --append flag. Checksums are also better
       managed, and the --nochown option for archives appeared.
     * v2.1.1: Fixes related to the Unix compression (compress command). Some
       Linux distributions made the insane choice to make it unavailable, even
       though gzip is capable of uncompressing these files, plus some more
       bugfixes in the extraction and checksum code.
     * v2.1.2:  Some  bug fixes. Use head -n to avoid problems with POSIX
       conformance.
     * v2.1.3: Bug fixes with the command line when spawning terminals. Added
       --tar,  --noexec  for archives. Added --nomd5 and --nocrc to avoid
       creating checksums in archives. The embedded script is now run through
       "eval". The --info output now includes the command used to create the
       archive. A man page was contributed by Bartosz Fenski.
     * v2.1.4:  Fixed  --info output. Generate random directory name when
       extracting files to . to avoid problems. Better handling of errors with
       wrong permissions for the directory containing the files. Avoid some
       race conditions, Unset the $CDPATH variable to avoid problems if it is
       set. Better handling of dot files in the archive directory.
     * v2.1.5: Made the md5sum detection consistent with the header code. Check
       for the presence of the archive directory. Added --encrypt for symmetric
       encryption through gpg (Eric Windisch). Added support for the digest
       command on Solaris 10 for MD5 checksums. Check for available disk space
       before extracting to the target directory (Andreas Schweitzer). Allow
       extraction  to run asynchronously (patch by Peter Hatch). Use file
       descriptors internally to avoid error messages (patch by Kay Tiong
       Khoo).

Links

     * Check out the [15]"Loki setup" installer, used to install many Linux
       games and other applications, and of which I am the co-author. Since the
       demise of Loki, I am now the official maintainer of the project, and it
       is now being hosted on [16]icculus.org, as well as a bunch of other
       ex-Loki projects (and a lot of other good stuff!).
     * Bjarni R. Einarsson also wrote the setup.sh installer script, inspired
       by Makeself. [17]Check it out !

Contact

   This script was written by [18]StÃ©phane Peter (megastep at megastep.org) I
   welcome any enhancements and suggestions.

   Contributions were included from John C. Quillan, Bjarni R. Einarsson,
   Francois Petitjean, and Ryan C. Gordon, thanks to them! If you think I
   forgot your name, don't hesitate to contact me.

   icculus.org also has a [19]Bugzilla server available that allows bug reports
   to be submitted for Loki setup, and since Makeself is a part of Loki setup,
   you can submit bug reports from there!
     _________________________________________________________________


    [20]StÃ©phane Peter

   Last modified: Fri Jan 4 15:51:05 PST 2008

References

   1. http://mowser.com/web/megastep.org/makeself/
   2. http://www.megastep.org/makeself/makeself.run
   3. mailto:megastep@REMOVEME.megastep.org
   4. http://www.idsoftware.com/
   5. http://www.lokigames.com/products/myth2/updates.php3
   6. http://www.nvidia.com/
   7. http://earth.google.com/
   8. http://www.megastep.org/makeself/makeself.run
   9. http://www.megastep.org/makeself/makeself.run
  10. http://www.gnu.org/copyleft/gpl.html
  11. http://www.megastep.org/makeself/makeself-2.1.5.run
  12. http://cvs.icculus.org/
  13. http://www.icculus.org/loki_setup/
  14. http://www.unrealtournament2003.com/
  15. http://www.icculus.org/loki_setup/
  16. http://www.icculus.org/
  17. http://www.mmedia.is/~bre/programs/setup.sh/
  18. mailto:megastep@@megastep.org
  19. https://bugzilla.icculus.org/
  20. mailto:megastep@@megastep.org
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     ./makeself-2.1.5/.svn/prop-base/                                                                    0000775 0023576 0023576 00000000000 11271247354 016041  5                                                                                                    ustar   michael                         michael                                                                                                                                                                                                                ./makeself-2.1.5/.svn/prop-base/makeself.sh.svn-base                                                0000444 0023576 0023576 00000000036 11271247354 021674  0                                                                                                    ustar   michael                         michael                                                                                                                                                                                                                K 14
svn:executable
V 1
*
END
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  ./makeself-2.1.5/.svn/prop-base/makeself-header.sh.svn-base                                         0000444 0023576 0023576 00000000036 11271247354 023122  0                                                                                                    ustar   michael                         michael                                                                                                                                                                                                                K 14
svn:executable
V 1
*
END
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  ./makeself-2.1.5/.svn/props/                                                                        0000775 0023576 0023576 00000000000 11271247354 015314  5                                                                                                    ustar   michael                         michael                                                                                                                                                                                                                ./makeself-2.1.5/.svn/tmp/                                                                          0000775 0023576 0023576 00000000000 11417253732 014750  5                                                                                                    ustar   michael                         michael                                                                                                                                                                                                                ./makeself-2.1.5/.svn/tmp/text-base/                                                                0000775 0023576 0023576 00000000000 11271247354 016645  5                                                                                                    ustar   michael                         michael                                                                                                                                                                                                                ./makeself-2.1.5/.svn/tmp/prop-base/                                                                0000775 0023576 0023576 00000000000 11271247354 016641  5                                                                                                    ustar   michael                         michael                                                                                                                                                                                                                ./makeself-2.1.5/.svn/tmp/props/                                                                    0000775 0023576 0023576 00000000000 11271247354 016114  5                                                                                                    ustar   michael                         michael                                                                                                                                                                                                                ./makeself-2.1.5/.svn/entries                                                                       0000444 0023576 0023576 00000002500 11417253732 015535  0                                                                                                    ustar   michael                         michael                                                                                                                                                                                                                9

dir
8390
svn+ssh://mwiegand@svn.wald.intevation.org/openvas/trunk/tools/openvas-lsc-target-preparation/makeself-2.1.5
svn+ssh://mwiegand@svn.wald.intevation.org/openvas



2009-02-17T21:22:15.648627Z
2519
jan


svn:special svn:externals svn:needs-lock











423fd1db-d629-0410-8442-d21db03e70f4

makeself.sh
file




2009-10-26T07:25:32.186571Z
fbfa1c23609b3f7f1f7d9d9f96de54cd
2009-02-17T21:22:15.648627Z
2519
jan
has-props




















11923

makeself.lsm
file




2009-10-26T07:25:32.186571Z
d561c470b811579fa4e7ecbf6401a7c9
2009-02-17T21:22:15.648627Z
2519
jan





















831

TODO
file




2009-10-26T07:25:32.190558Z
3789dfb37e9785018a1e6d45cb2c2e3c
2009-02-17T21:22:15.648627Z
2519
jan





















209

makeself-header.sh
file




2009-10-26T07:25:32.190558Z
e9bf3281b312436539e4558614b7b72b
2009-02-17T21:22:15.648627Z
2519
jan
has-props




















9635

makeself.1
file




2009-10-26T07:25:32.190558Z
35d6f5eec5fea68623e84124b7a45de6
2009-02-17T21:22:15.648627Z
2519
jan





















1815

COPYING
file




2009-10-26T07:25:32.190558Z
ea5bed2f60d357618ca161ad539f7c0a
2009-02-17T21:22:15.648627Z
2519
jan





















18008

README
file




2009-10-26T07:25:32.206571Z
ecff162be39edf6df2fe2fbee6182ba3
2009-02-17T21:22:15.648627Z
2519
jan





















16395

                                                                                                                                                                                                ./makeself-2.1.5/.svn/format                                                                        0000444 0023576 0023576 00000000002 11271247354 015350  0                                                                                                    ustar   michael                         michael                                                                                                                                                                                                                9
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              ./makeself-2.1.5/makeself.sh                                                                        0000775 0023576 0023576 00000027223 11271247354 015421  0                                                                                                    ustar   michael                         michael                                                                                                                                                                                                                #!/bin/sh
#
# Makeself version 2.1.x
#  by Stephane Peter <megastep@megastep.org>
#
# $Id: makeself.sh,v 1.64 2008/01/04 23:52:14 megastep Exp $
#
# Utility to create self-extracting tar.gz archives.
# The resulting archive is a file holding the tar.gz archive with
# a small Shell script stub that uncompresses the archive to a temporary
# directory and then executes a given script from withing that directory.
#
# Makeself home page: http://www.megastep.org/makeself/
#
# Version 2.0 is a rewrite of version 1.0 to make the code easier to read and maintain.
#
# Version history :
# - 1.0 : Initial public release
# - 1.1 : The archive can be passed parameters that will be passed on to
#         the embedded script, thanks to John C. Quillan
# - 1.2 : Package distribution, bzip2 compression, more command line options,
#         support for non-temporary archives. Ideas thanks to Francois Petitjean
# - 1.3 : More patches from Bjarni R. Einarsson and Francois Petitjean:
#         Support for no compression (--nocomp), script is no longer mandatory,
#         automatic launch in an xterm, optional verbose output, and -target 
#         archive option to indicate where to extract the files.
# - 1.4 : Improved UNIX compatibility (Francois Petitjean)
#         Automatic integrity checking, support of LSM files (Francois Petitjean)
# - 1.5 : Many bugfixes. Optionally disable xterm spawning.
# - 1.5.1 : More bugfixes, added archive options -list and -check.
# - 1.5.2 : Cosmetic changes to inform the user of what's going on with big 
#           archives (Quake III demo)
# - 1.5.3 : Check for validity of the DISPLAY variable before launching an xterm.
#           More verbosity in xterms and check for embedded command's return value.
#           Bugfix for Debian 2.0 systems that have a different "print" command.
# - 1.5.4 : Many bugfixes. Print out a message if the extraction failed.
# - 1.5.5 : More bugfixes. Added support for SETUP_NOCHECK environment variable to
#           bypass checksum verification of archives.
# - 1.6.0 : Compute MD5 checksums with the md5sum command (patch from Ryan Gordon)
# - 2.0   : Brand new rewrite, cleaner architecture, separated header and UNIX ports.
# - 2.0.1 : Added --copy
# - 2.1.0 : Allow multiple tarballs to be stored in one archive, and incremental updates.
#           Added --nochown for archives
#           Stopped doing redundant checksums when not necesary
# - 2.1.1 : Work around insane behavior from certain Linux distros with no 'uncompress' command
#           Cleaned up the code to handle error codes from compress. Simplified the extraction code.
# - 2.1.2 : Some bug fixes. Use head -n to avoid problems.
# - 2.1.3 : Bug fixes with command line when spawning terminals.
#           Added --tar for archives, allowing to give arbitrary arguments to tar on the contents of the archive.
#           Added --noexec to prevent execution of embedded scripts.
#           Added --nomd5 and --nocrc to avoid creating checksums in archives.
#           Added command used to create the archive in --info output.
#           Run the embedded script through eval.
# - 2.1.4 : Fixed --info output.
#           Generate random directory name when extracting files to . to avoid problems. (Jason Trent)
#           Better handling of errors with wrong permissions for the directory containing the files. (Jason Trent)
#           Avoid some race conditions (Ludwig Nussel)
#           Unset the $CDPATH variable to avoid problems if it is set. (Debian)
#           Better handling of dot files in the archive directory.
# - 2.1.5 : Made the md5sum detection consistent with the header code.
#           Check for the presence of the archive directory
#           Added --encrypt for symmetric encryption through gpg (Eric Windisch)
#           Added support for the digest command on Solaris 10 for MD5 checksums
#           Check for available disk space before extracting to the target directory (Andreas Schweitzer)
#           Allow extraction to run asynchronously (patch by Peter Hatch)
#           Use file descriptors internally to avoid error messages (patch by Kay Tiong Khoo)
#
# (C) 1998-2008 by Stéphane Peter <megastep@megastep.org>
#
# This software is released under the terms of the GNU GPL version 2 and above
# Please read the license at http://www.gnu.org/copyleft/gpl.html
#

MS_VERSION=2.1.5
MS_COMMAND="$0"
unset CDPATH

for f in "${1+"$@"}"; do
    MS_COMMAND="$MS_COMMAND \\\\
    \\\"$f\\\""
done

# Procedures

MS_Usage()
{
    echo "Usage: $0 [params] archive_dir file_name label [startup_script] [args]"
    echo "params can be one or more of the following :"
    echo "    --version | -v  : Print out Makeself version number and exit"
    echo "    --help | -h     : Print out this help message"
    echo "    --gzip          : Compress using gzip (default if detected)"
    echo "    --bzip2         : Compress using bzip2 instead of gzip"
    echo "    --compress      : Compress using the UNIX 'compress' command"
    echo "    --nocomp        : Do not compress the data"
    echo "    --notemp        : The archive will create archive_dir in the"
    echo "                      current directory and uncompress in ./archive_dir"
    echo "    --copy          : Upon extraction, the archive will first copy itself to"
    echo "                      a temporary directory"
    echo "    --append        : Append more files to an existing Makeself archive"
    echo "                      The label and startup scripts will then be ignored"
    echo "    --current       : Files will be extracted to the current directory."
    echo "                      Implies --notemp."
    echo "    --nomd5         : Don't calculate an MD5 for archive"
    echo "    --nocrc         : Don't calculate a CRC for archive"
    echo "    --header file   : Specify location of the header script"
    echo "    --follow        : Follow the symlinks in the archive"
    echo "    --nox11         : Disable automatic spawn of a xterm"
    echo "    --nowait        : Do not wait for user input after executing embedded"
    echo "                      program from an xterm"
    echo "    --lsm file      : LSM file describing the package"
    echo
    echo "Do not forget to give a fully qualified startup script name"
    echo "(i.e. with a ./ prefix if inside the archive)."
    exit 1
}

# Default settings
if type gzip 2>&1 > /dev/null; then
    COMPRESS=gzip
else
    COMPRESS=Unix
fi
KEEP=n
CURRENT=n
NOX11=n
APPEND=n
COPY=none
TAR_ARGS=cvf
HEADER=`dirname $0`/makeself-header.sh

# LSM file stuff
LSM_CMD="echo No LSM. >> \"\$archname\""

while true
do
    case "$1" in
    --version | -v)
	echo Makeself version $MS_VERSION
	exit 0
	;;
    --bzip2)
	COMPRESS=bzip2
	shift
	;;
    --gzip)
	COMPRESS=gzip
	shift
	;;
    --compress)
	COMPRESS=Unix
	shift
	;;
    --encrypt)
	COMPRESS=gpg
	shift
	;;
    --nocomp)
	COMPRESS=none
	shift
	;;
    --notemp)
	KEEP=y
	shift
	;;
    --copy)
	COPY=copy
	shift
	;;
    --current)
	CURRENT=y
	KEEP=y
	shift
	;;
    --header)
	HEADER="$2"
	shift 2
	;;
    --follow)
	TAR_ARGS=cvfh
	shift
	;;
    --nox11)
	NOX11=y
	shift
	;;
    --nowait)
	shift
	;;
    --nomd5)
	NOMD5=y
	shift
	;;
    --nocrc)
	NOCRC=y
	shift
	;;
    --append)
	APPEND=y
	shift
	;;
    --lsm)
	LSM_CMD="cat \"$2\" >> \"\$archname\""
	shift 2
	;;
    -h | --help)
	MS_Usage
	;;
    -*)
	echo Unrecognized flag : "$1"
	MS_Usage
	;;
    *)
	break
	;;
    esac
done

if test $# -lt 1; then
	MS_Usage
else
	if test -d "$1"; then
		archdir="$1"
	else
		echo "Directory $1 does not exist."
		exit 1
	fi
fi
archname="$2"

if test "$APPEND" = y; then
    if test $# -lt 2; then
	MS_Usage
    fi

    # Gather the info from the original archive
    OLDENV=`sh "$archname" --dumpconf`
    if test $? -ne 0; then
	echo "Unable to update archive: $archname" >&2
	exit 1
    else
	eval "$OLDENV"
    fi
else
    if test "$KEEP" = n -a $# = 3; then
	echo "ERROR: Making a temporary archive with no embedded command does not make sense!" >&2
	echo
	MS_Usage
    fi
    # We don't really want to create an absolute directory...
    if test "$CURRENT" = y; then
	archdirname="."
    else
	archdirname=`basename "$1"`
    fi

    if test $# -lt 3; then
	MS_Usage
    fi

    LABEL="$3"
    SCRIPT="$4"
    test x$SCRIPT = x || shift 1
    shift 3
    SCRIPTARGS="$*"
fi

if test "$KEEP" = n -a "$CURRENT" = y; then
    echo "ERROR: It is A VERY DANGEROUS IDEA to try to combine --notemp and --current." >&2
    exit 1
fi

case $COMPRESS in
gzip)
    GZIP_CMD="gzip -c9"
    GUNZIP_CMD="gzip -cd"
    ;;
bzip2)
    GZIP_CMD="bzip2 -9"
    GUNZIP_CMD="bzip2 -d"
    ;;
gpg)
    GZIP_CMD="gpg -ac -z9"
    GUNZIP_CMD="gpg -d"
    ;;
Unix)
    GZIP_CMD="compress -cf"
    GUNZIP_CMD="exec 2>&-; uncompress -c || test \\\$? -eq 2 || gzip -cd"
    ;;
none)
    GZIP_CMD="cat"
    GUNZIP_CMD="cat"
    ;;
esac

tmpfile="${TMPDIR:=/tmp}/mkself$$"

if test -f $HEADER; then
	oldarchname="$archname"
	archname="$tmpfile"
	# Generate a fake header to count its lines
	SKIP=0
    . $HEADER
    SKIP=`cat "$tmpfile" |wc -l`
	# Get rid of any spaces
	SKIP=`expr $SKIP`
	rm -f "$tmpfile"
    echo Header is $SKIP lines long >&2

	archname="$oldarchname"
else
    echo "Unable to open header file: $HEADER" >&2
    exit 1
fi

echo

if test "$APPEND" = n; then
    if test -f "$archname"; then
		echo "WARNING: Overwriting existing file: $archname" >&2
    fi
fi

USIZE=`du -ks $archdir | cut -f1`
DATE=`LC_ALL=C date`

if test "." = "$archdirname"; then
	if test "$KEEP" = n; then
		archdirname="makeself-$$-`date +%Y%m%d%H%M%S`"
	fi
fi

test -d "$archdir" || { echo "Error: $archdir does not exist."; rm -f "$tmpfile"; exit 1; }
echo About to compress $USIZE KB of data...
echo Adding files to archive named \"$archname\"...
exec 3<> "$tmpfile"
(cd "$archdir" && ( tar $TAR_ARGS - . | eval "$GZIP_CMD" >&3 ) ) || { echo Aborting: Archive directory not found or temporary file: "$tmpfile" could not be created.; exec 3>&-; rm -f "$tmpfile"; exit 1; }
exec 3>&- # try to close the archive

fsize=`cat "$tmpfile" | wc -c | tr -d " "`

# Compute the checksums

md5sum=00000000000000000000000000000000
crcsum=0000000000

if test "$NOCRC" = y; then
	echo "skipping crc at user request"
else
	crcsum=`cat "$tmpfile" | CMD_ENV=xpg4 cksum | sed -e 's/ /Z/' -e 's/	/Z/' | cut -dZ -f1`
	echo "CRC: $crcsum"
fi

if test "$NOMD5" = y; then
	echo "skipping md5sum at user request"
else
	# Try to locate a MD5 binary
	OLD_PATH=$PATH
	PATH=${GUESS_MD5_PATH:-"$OLD_PATH:/bin:/usr/bin:/sbin:/usr/local/ssl/bin:/usr/local/bin:/opt/openssl/bin"}
	MD5_ARG=""
	MD5_PATH=`exec <&- 2>&-; which md5sum || type md5sum`
	test -x $MD5_PATH || MD5_PATH=`exec <&- 2>&-; which md5 || type md5`
	test -x $MD5_PATH || MD5_PATH=`exec <&- 2>&-; which digest || type digest`
	PATH=$OLD_PATH
	if test `basename $MD5_PATH` = digest; then
		MD5_ARG="-a md5"
	fi
	if test -x "$MD5_PATH"; then
		md5sum=`cat "$tmpfile" | eval "$MD5_PATH $MD5_ARG" | cut -b-32`;
		echo "MD5: $md5sum"
	else
		echo "MD5: none, MD5 command not found"
	fi
fi

if test "$APPEND" = y; then
    mv "$archname" "$archname".bak || exit

    # Prepare entry for new archive
    filesizes="$filesizes $fsize"
    CRCsum="$CRCsum $crcsum"
    MD5sum="$MD5sum $md5sum"
    USIZE=`expr $USIZE + $OLDUSIZE`
    # Generate the header
    . $HEADER
    # Append the original data
    tail -n +$OLDSKIP "$archname".bak >> "$archname"
    # Append the new data
    cat "$tmpfile" >> "$archname"

    chmod +x "$archname"
    rm -f "$archname".bak
    echo Self-extractible archive \"$archname\" successfully updated.
else
    filesizes="$fsize"
    CRCsum="$crcsum"
    MD5sum="$md5sum"

    # Generate the header
    . $HEADER

    # Append the compressed tar data after the stub
    echo
    cat "$tmpfile" >> "$archname"
    chmod +x "$archname"
    echo Self-extractible archive \"$archname\" successfully created.
fi
rm -f "$tmpfile"
                                                                                                                                                                                                                                                                                                                                                                             ./makeself-2.1.5/makeself.lsm                                                                       0000664 0023576 0023576 00000001477 11271247354 015602  0                                                                                                    ustar   michael                         michael                                                                                                                                                                                                                Begin3
Title:          makeself.sh
Version:        2.1
Description:    makeself.sh is a shell script that generates a self-extractable        
                tar.gz archive from a directory. The resulting file appears as a shell          
                script, and can be launched as is. The archive will then uncompress
                itself to a temporary directory and an arbitrary command will be
                executed (for example an installation script). This is pretty similar
                to archives generated with WinZip Self-Extractor in the Windows world.
Keywords:       Installation archive tar winzip
Author:         Stéphane Peter (megastep@megastep.org)
Maintained-by:  Stéphane Peter (megastep@megastep.org)
Original-site:  http://www.megastep.org/makeself/
Platform:       Unix
Copying-policy: GPL
End
                                                                                                                                                                                                 ./makeself-2.1.5/TODO                                                                               0000664 0023576 0023576 00000000321 11271247354 013751  0                                                                                                    ustar   michael                         michael                                                                                                                                                                                                                What needs to be done next :

- Generic compression code (thru a user-defined command)
- Collect names of directories potentially containing md5 program. GUESS_MD5_PATH

Stéphane Peter <megastep@megastep.org>
                                                                                                                                                                                                                                                                                                               ./makeself-2.1.5/makeself-header.sh                                                                 0000775 0023576 0023576 00000022643 11271247354 016650  0                                                                                                    ustar   michael                         michael                                                                                                                                                                                                                cat << EOF  > "$archname"
#!/bin/sh
# This script was generated using Makeself $MS_VERSION

CRCsum="$CRCsum"
MD5="$MD5sum"
TMPROOT=\${TMPDIR:=/tmp}

label="$LABEL"
script="$SCRIPT"
scriptargs="$SCRIPTARGS"
targetdir="$archdirname"
filesizes="$filesizes"
keep=$KEEP

print_cmd_arg=""
if type printf > /dev/null; then
    print_cmd="printf"
elif test -x /usr/ucb/echo; then
    print_cmd="/usr/ucb/echo"
else
    print_cmd="echo"
fi

unset CDPATH

MS_Printf()
{
    \$print_cmd \$print_cmd_arg "\$1"
}

MS_Progress()
{
    while read a; do
	MS_Printf .
    done
}

MS_diskspace()
{
	(
	if test -d /usr/xpg4/bin; then
		PATH=/usr/xpg4/bin:\$PATH
	fi
	df -kP "\$1" | tail -1 | awk '{print \$4}'
	)
}

MS_dd()
{
    blocks=\`expr \$3 / 1024\`
    bytes=\`expr \$3 % 1024\`
    dd if="\$1" ibs=\$2 skip=1 obs=1024 conv=sync 2> /dev/null | \\
    { test \$blocks -gt 0 && dd ibs=1024 obs=1024 count=\$blocks ; \\
      test \$bytes  -gt 0 && dd ibs=1 obs=1024 count=\$bytes ; } 2> /dev/null
}

MS_Help()
{
    cat << EOH >&2
Makeself version $MS_VERSION
 1) Getting help or info about \$0 :
  \$0 --help   Print this message
  \$0 --info   Print embedded info : title, default target directory, embedded script ...
  \$0 --lsm    Print embedded lsm entry (or no LSM)
  \$0 --list   Print the list of files in the archive
  \$0 --check  Checks integrity of the archive
 
 2) Running \$0 :
  \$0 [options] [--] [additional arguments to embedded script]
  with following options (in that order)
  --confirm             Ask before running embedded script
  --noexec              Do not run embedded script
  --keep                Do not erase target directory after running
			the embedded script
  --nox11               Do not spawn an xterm
  --nochown             Do not give the extracted files to the current user
  --target NewDirectory Extract in NewDirectory
  --tar arg1 [arg2 ...] Access the contents of the archive through the tar command
  --                    Following arguments will be passed to the embedded script
EOH
}

MS_Check()
{
    OLD_PATH="\$PATH"
    PATH=\${GUESS_MD5_PATH:-"\$OLD_PATH:/bin:/usr/bin:/sbin:/usr/local/ssl/bin:/usr/local/bin:/opt/openssl/bin"}
	MD5_ARG=""
    MD5_PATH=\`exec <&- 2>&-; which md5sum || type md5sum\`
    test -x "\$MD5_PATH" || MD5_PATH=\`exec <&- 2>&-; which md5 || type md5\`
	test -x "\$MD5_PATH" || MD5_PATH=\`exec <&- 2>&-; which digest || type digest\`
    PATH="\$OLD_PATH"

    MS_Printf "Verifying archive integrity..."
    offset=\`head -n $SKIP "\$1" | wc -c | tr -d " "\`
    verb=\$2
    i=1
    for s in \$filesizes
    do
		crc=\`echo \$CRCsum | cut -d" " -f\$i\`
		if test -x "\$MD5_PATH"; then
			if test \`basename \$MD5_PATH\` = digest; then
				MD5_ARG="-a md5"
			fi
			md5=\`echo \$MD5 | cut -d" " -f\$i\`
			if test \$md5 = "00000000000000000000000000000000"; then
				test x\$verb = xy && echo " \$1 does not contain an embedded MD5 checksum." >&2
			else
				md5sum=\`MS_dd "\$1" \$offset \$s | eval "\$MD5_PATH \$MD5_ARG" | cut -b-32\`;
				if test "\$md5sum" != "\$md5"; then
					echo "Error in MD5 checksums: \$md5sum is different from \$md5" >&2
					exit 2
				else
					test x\$verb = xy && MS_Printf " MD5 checksums are OK." >&2
				fi
				crc="0000000000"; verb=n
			fi
		fi
		if test \$crc = "0000000000"; then
			test x\$verb = xy && echo " \$1 does not contain a CRC checksum." >&2
		else
			sum1=\`MS_dd "\$1" \$offset \$s | CMD_ENV=xpg4 cksum | awk '{print \$1}'\`
			if test "\$sum1" = "\$crc"; then
				test x\$verb = xy && MS_Printf " CRC checksums are OK." >&2
			else
				echo "Error in checksums: \$sum1 is different from \$crc"
				exit 2;
			fi
		fi
		i=\`expr \$i + 1\`
		offset=\`expr \$offset + \$s\`
    done
    echo " All good."
}

UnTAR()
{
    tar \$1vf - 2>&1 || { echo Extraction failed. > /dev/tty; kill -15 \$$; }
}

finish=true
xterm_loop=
nox11=$NOX11
copy=$COPY
ownership=y
verbose=n

initargs="\$@"

while true
do
    case "\$1" in
    -h | --help)
	MS_Help
	exit 0
	;;
    --info)
	echo Identification: "\$label"
	echo Target directory: "\$targetdir"
	echo Uncompressed size: $USIZE KB
	echo Compression: $COMPRESS
	echo Date of packaging: $DATE
	echo Built with Makeself version $MS_VERSION on $OSTYPE
	echo Build command was: "$MS_COMMAND"
	if test x\$script != x; then
	    echo Script run after extraction:
	    echo "    " \$script \$scriptargs
	fi
	if test x"$copy" = xcopy; then
		echo "Archive will copy itself to a temporary location"
	fi
	if test x"$KEEP" = xy; then
	    echo "directory \$targetdir is permanent"
	else
	    echo "\$targetdir will be removed after extraction"
	fi
	exit 0
	;;
    --dumpconf)
	echo LABEL=\"\$label\"
	echo SCRIPT=\"\$script\"
	echo SCRIPTARGS=\"\$scriptargs\"
	echo archdirname=\"$archdirname\"
	echo KEEP=$KEEP
	echo COMPRESS=$COMPRESS
	echo filesizes=\"\$filesizes\"
	echo CRCsum=\"\$CRCsum\"
	echo MD5sum=\"\$MD5\"
	echo OLDUSIZE=$USIZE
	echo OLDSKIP=`expr $SKIP + 1`
	exit 0
	;;
    --lsm)
cat << EOLSM
EOF
eval "$LSM_CMD"
cat << EOF  >> "$archname"
EOLSM
	exit 0
	;;
    --list)
	echo Target directory: \$targetdir
	offset=\`head -n $SKIP "\$0" | wc -c | tr -d " "\`
	for s in \$filesizes
	do
	    MS_dd "\$0" \$offset \$s | eval "$GUNZIP_CMD" | UnTAR t
	    offset=\`expr \$offset + \$s\`
	done
	exit 0
	;;
	--tar)
	offset=\`head -n $SKIP "\$0" | wc -c | tr -d " "\`
	arg1="\$2"
	shift 2
	for s in \$filesizes
	do
	    MS_dd "\$0" \$offset \$s | eval "$GUNZIP_CMD" | tar "\$arg1" - \$*
	    offset=\`expr \$offset + \$s\`
	done
	exit 0
	;;
    --check)
	MS_Check "\$0" y
	exit 0
	;;
    --confirm)
	verbose=y
	shift
	;;
	--noexec)
	script=""
	shift
	;;
    --keep)
	keep=y
	shift
	;;
    --target)
	keep=y
	targetdir=\${2:-.}
	shift 2
	;;
    --nox11)
	nox11=y
	shift
	;;
    --nochown)
	ownership=n
	shift
	;;
    --xwin)
	finish="echo Press Return to close this window...; read junk"
	xterm_loop=1
	shift
	;;
    --phase2)
	copy=phase2
	shift
	;;
    --)
	shift
	break ;;
    -*)
	echo Unrecognized flag : "\$1" >&2
	MS_Help
	exit 1
	;;
    *)
	break ;;
    esac
done

case "\$copy" in
copy)
    tmpdir=\$TMPROOT/makeself.\$RANDOM.\`date +"%y%m%d%H%M%S"\`.\$\$
    mkdir "\$tmpdir" || {
	echo "Could not create temporary directory \$tmpdir" >&2
	exit 1
    }
    SCRIPT_COPY="\$tmpdir/makeself"
    echo "Copying to a temporary location..." >&2
    cp "\$0" "\$SCRIPT_COPY"
    chmod +x "\$SCRIPT_COPY"
    cd "\$TMPROOT"
    exec "\$SCRIPT_COPY" --phase2 -- \$initargs
    ;;
phase2)
    finish="\$finish ; rm -rf \`dirname \$0\`"
    ;;
esac

if test "\$nox11" = "n"; then
    if tty -s; then                 # Do we have a terminal?
	:
    else
        if test x"\$DISPLAY" != x -a x"\$xterm_loop" = x; then  # No, but do we have X?
            if xset q > /dev/null 2>&1; then # Check for valid DISPLAY variable
                GUESS_XTERMS="xterm rxvt dtterm eterm Eterm kvt konsole aterm"
                for a in \$GUESS_XTERMS; do
                    if type \$a >/dev/null 2>&1; then
                        XTERM=\$a
                        break
                    fi
                done
                chmod a+x \$0 || echo Please add execution rights on \$0
                if test \`echo "\$0" | cut -c1\` = "/"; then # Spawn a terminal!
                    exec \$XTERM -title "\$label" -e "\$0" --xwin "\$initargs"
                else
                    exec \$XTERM -title "\$label" -e "./\$0" --xwin "\$initargs"
                fi
            fi
        fi
    fi
fi

if test "\$targetdir" = "."; then
    tmpdir="."
else
    if test "\$keep" = y; then
	echo "Creating directory \$targetdir" >&2
	tmpdir="\$targetdir"
	dashp="-p"
    else
	tmpdir="\$TMPROOT/selfgz\$\$\$RANDOM"
	dashp=""
    fi
    mkdir \$dashp \$tmpdir || {
	echo 'Cannot create target directory' \$tmpdir >&2
	echo 'You should try option --target OtherDirectory' >&2
	eval \$finish
	exit 1
    }
fi

location="\`pwd\`"
if test x\$SETUP_NOCHECK != x1; then
    MS_Check "\$0"
fi
offset=\`head -n $SKIP "\$0" | wc -c | tr -d " "\`

if test x"\$verbose" = xy; then
	MS_Printf "About to extract $USIZE KB in \$tmpdir ... Proceed ? [Y/n] "
	read yn
	if test x"\$yn" = xn; then
		eval \$finish; exit 1
	fi
fi

MS_Printf "Uncompressing \$label"
res=3
if test "\$keep" = n; then
    trap 'echo Signal caught, cleaning up >&2; cd \$TMPROOT; /bin/rm -rf \$tmpdir; eval \$finish; exit 15' 1 2 3 15
fi

leftspace=\`MS_diskspace \$tmpdir\`
if test \$leftspace -lt $USIZE; then
    echo
    echo "Not enough space left in "\`dirname \$tmpdir\`" (\$leftspace KB) to decompress \$0 ($USIZE KB)" >&2
    if test "\$keep" = n; then
        echo "Consider setting TMPDIR to a directory with more free space."
   fi
    eval \$finish; exit 1
fi

for s in \$filesizes
do
    if MS_dd "\$0" \$offset \$s | eval "$GUNZIP_CMD" | ( cd "\$tmpdir"; UnTAR x ) | MS_Progress; then
		if test x"\$ownership" = xy; then
			(PATH=/usr/xpg4/bin:\$PATH; cd "\$tmpdir"; chown -R \`id -u\` .;  chgrp -R \`id -g\` .)
		fi
    else
		echo
		echo "Unable to decompress \$0" >&2
		eval \$finish; exit 1
    fi
    offset=\`expr \$offset + \$s\`
done
echo

cd "\$tmpdir"
res=0
if test x"\$script" != x; then
    if test x"\$verbose" = xy; then
		MS_Printf "OK to execute: \$script \$scriptargs \$* ? [Y/n] "
		read yn
		if test x"\$yn" = x -o x"\$yn" = xy -o x"\$yn" = xY; then
			eval \$script \$scriptargs \$*; res=\$?;
		fi
    else
		eval \$script \$scriptargs \$*; res=\$?
    fi
    if test \$res -ne 0; then
		test x"\$verbose" = xy && echo "The program '\$script' returned an error code (\$res)" >&2
    fi
fi
if test "\$keep" = n; then
    cd \$TMPROOT
    /bin/rm -rf \$tmpdir
fi
eval \$finish; exit \$res
EOF
                                                                                             ./makeself-2.1.5/makeself.1                                                                         0000664 0023576 0023576 00000003427 11271247354 015144  0                                                                                                    ustar   michael                         michael                                                                                                                                                                                                                .TH "makeself" "1" "2.1.4"
.SH "NAME"
makeself \- An utility to generate self-extractable archives.
.SH "SYNTAX"
.LP 
.B makeself [\fIoptions\fP] archive_dir file_name label 
.B [\fIstartup_script\fP] [\fIargs\fP]
.SH "DESCRIPTION"
.LP 
This program is a free (GPL) utility designed to create self-extractable 
archives from a directory. 
.br
.SH "OPTIONS"
.LP 
The following options are supported.
.LP 
.TP 15
.B -v, --version
Prints out the makeself version number and exits.
.TP
.B -h, --help
Print out help information.
.TP
.B --gzip
Compress using gzip (default if detected).
.TP
.B --bzip2
Compress using bzip2.
.TP
.B --compress
Compress using the UNIX 'compress' command.
.TP
.B --nocomp
Do not compress the data.
.TP
.B --notemp
The archive will create archive_dir in the current directory and 
uncompress in ./archive_dir.
.TP
.B --copy
Upon extraction, the archive will first copy itself to a temporary directory.
.TP
.B --append
Append more files to an existing makeself archive.
The label and startup scripts will then be ignored.
.TP
.B --current
Files will be extracted to the current directory. Implies --notemp.
.TP
.B --header file
Specify location of the header script. 
.TP
.B --follow
Follow the symlinks in the archive.
.TP
.B --nox11
Disable automatic spawn of an xterm if running in X11.
.TP
.B --nowait
Do not wait for user input after executing embedded program from an xterm.
.TP
.B --nomd5
Do not create a MD5 checksum for the archive.
.TP
.B --nocrc
Do not create a CRC32 checksum for the archive.
.TP
.B --lsm file
LSM file describing the package.
.PD
.SH "AUTHORS"
.LP 
Makeself has been written by Stéphane Peter <megastep@megastep.org>.
.BR 
This man page was originally written by Bartosz Fenski <fenio@o2.pl> for the 
Debian GNU/Linux distribution (but it may be used by others).
                                                                                                                                                                                                                                         ./makeself-2.1.5/COPYING                                                                            0000664 0023576 0023576 00000043130 11271247354 014321  0                                                                                                    ustar   michael                         michael                                                                                                                                                                                                                
		    GNU GENERAL PUBLIC LICENSE
		       Version 2, June 1991

 Copyright (C) 1989, 1991 Free Software Foundation, Inc.
                       59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 Everyone is permitted to copy and distribute verbatim copies
 of this license document, but changing it is not allowed.

			    Preamble

  The licenses for most software are designed to take away your
freedom to share and change it.  By contrast, the GNU General Public
License is intended to guarantee your freedom to share and change free
software--to make sure the software is free for all its users.  This
General Public License applies to most of the Free Software
Foundation's software and to any other program whose authors commit to
using it.  (Some other Free Software Foundation software is covered by
the GNU Library General Public License instead.)  You can apply it to
your programs, too.

  When we speak of free software, we are referring to freedom, not
price.  Our General Public Licenses are designed to make sure that you
have the freedom to distribute copies of free software (and charge for
this service if you wish), that you receive source code or can get it
if you want it, that you can change the software or use pieces of it
in new free programs; and that you know you can do these things.

  To protect your rights, we need to make restrictions that forbid
anyone to deny you these rights or to ask you to surrender the rights.
These restrictions translate to certain responsibilities for you if you
distribute copies of the software, or if you modify it.

  For example, if you distribute copies of such a program, whether
gratis or for a fee, you must give the recipients all the rights that
you have.  You must make sure that they, too, receive or can get the
source code.  And you must show them these terms so they know their
rights.

  We protect your rights with two steps: (1) copyright the software, and
(2) offer you this license which gives you legal permission to copy,
distribute and/or modify the software.

  Also, for each author's protection and ours, we want to make certain
that everyone understands that there is no warranty for this free
software.  If the software is modified by someone else and passed on, we
want its recipients to know that what they have is not the original, so
that any problems introduced by others will not reflect on the original
authors' reputations.

  Finally, any free program is threatened constantly by software
patents.  We wish to avoid the danger that redistributors of a free
program will individually obtain patent licenses, in effect making the
program proprietary.  To prevent this, we have made it clear that any
patent must be licensed for everyone's free use or not licensed at all.

  The precise terms and conditions for copying, distribution and
modification follow.

		    GNU GENERAL PUBLIC LICENSE
   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION

  0. This License applies to any program or other work which contains
a notice placed by the copyright holder saying it may be distributed
under the terms of this General Public License.  The "Program", below,
refers to any such program or work, and a "work based on the Program"
means either the Program or any derivative work under copyright law:
that is to say, a work containing the Program or a portion of it,
either verbatim or with modifications and/or translated into another
language.  (Hereinafter, translation is included without limitation in
the term "modification".)  Each licensee is addressed as "you".

Activities other than copying, distribution and modification are not
covered by this License; they are outside its scope.  The act of
running the Program is not restricted, and the output from the Program
is covered only if its contents constitute a work based on the
Program (independent of having been made by running the Program).
Whether that is true depends on what the Program does.

  1. You may copy and distribute verbatim copies of the Program's
source code as you receive it, in any medium, provided that you
conspicuously and appropriately publish on each copy an appropriate
copyright notice and disclaimer of warranty; keep intact all the
notices that refer to this License and to the absence of any warranty;
and give any other recipients of the Program a copy of this License
along with the Program.

You may charge a fee for the physical act of transferring a copy, and
you may at your option offer warranty protection in exchange for a fee.

  2. You may modify your copy or copies of the Program or any portion
of it, thus forming a work based on the Program, and copy and
distribute such modifications or work under the terms of Section 1
above, provided that you also meet all of these conditions:

    a) You must cause the modified files to carry prominent notices
    stating that you changed the files and the date of any change.

    b) You must cause any work that you distribute or publish, that in
    whole or in part contains or is derived from the Program or any
    part thereof, to be licensed as a whole at no charge to all third
    parties under the terms of this License.

    c) If the modified program normally reads commands interactively
    when run, you must cause it, when started running for such
    interactive use in the most ordinary way, to print or display an
    announcement including an appropriate copyright notice and a
    notice that there is no warranty (or else, saying that you provide
    a warranty) and that users may redistribute the program under
    these conditions, and telling the user how to view a copy of this
    License.  (Exception: if the Program itself is interactive but
    does not normally print such an announcement, your work based on
    the Program is not required to print an announcement.)

These requirements apply to the modified work as a whole.  If
identifiable sections of that work are not derived from the Program,
and can be reasonably considered independent and separate works in
themselves, then this License, and its terms, do not apply to those
sections when you distribute them as separate works.  But when you
distribute the same sections as part of a whole which is a work based
on the Program, the distribution of the whole must be on the terms of
this License, whose permissions for other licensees extend to the
entire whole, and thus to each and every part regardless of who wrote it.

Thus, it is not the intent of this section to claim rights or contest
your rights to work written entirely by you; rather, the intent is to
exercise the right to control the distribution of derivative or
collective works based on the Program.

In addition, mere aggregation of another work not based on the Program
with the Program (or with a work based on the Program) on a volume of
a storage or distribution medium does not bring the other work under
the scope of this License.

  3. You may copy and distribute the Program (or a work based on it,
under Section 2) in object code or executable form under the terms of
Sections 1 and 2 above provided that you also do one of the following:

    a) Accompany it with the complete corresponding machine-readable
    source code, which must be distributed under the terms of Sections
    1 and 2 above on a medium customarily used for software interchange; or,

    b) Accompany it with a written offer, valid for at least three
    years, to give any third party, for a charge no more than your
    cost of physically performing source distribution, a complete
    machine-readable copy of the corresponding source code, to be
    distributed under the terms of Sections 1 and 2 above on a medium
    customarily used for software interchange; or,

    c) Accompany it with the information you received as to the offer
    to distribute corresponding source code.  (This alternative is
    allowed only for noncommercial distribution and only if you
    received the program in object code or executable form with such
    an offer, in accord with Subsection b above.)

The source code for a work means the preferred form of the work for
making modifications to it.  For an executable work, complete source
code means all the source code for all modules it contains, plus any
associated interface definition files, plus the scripts used to
control compilation and installation of the executable.  However, as a
special exception, the source code distributed need not include
anything that is normally distributed (in either source or binary
form) with the major components (compiler, kernel, and so on) of the
operating system on which the executable runs, unless that component
itself accompanies the executable.

If distribution of executable or object code is made by offering
access to copy from a designated place, then offering equivalent
access to copy the source code from the same place counts as
distribution of the source code, even though third parties are not
compelled to copy the source along with the object code.

  4. You may not copy, modify, sublicense, or distribute the Program
except as expressly provided under this License.  Any attempt
otherwise to copy, modify, sublicense or distribute the Program is
void, and will automatically terminate your rights under this License.
However, parties who have received copies, or rights, from you under
this License will not have their licenses terminated so long as such
parties remain in full compliance.

  5. You are not required to accept this License, since you have not
signed it.  However, nothing else grants you permission to modify or
distribute the Program or its derivative works.  These actions are
prohibited by law if you do not accept this License.  Therefore, by
modifying or distributing the Program (or any work based on the
Program), you indicate your acceptance of this License to do so, and
all its terms and conditions for copying, distributing or modifying
the Program or works based on it.

  6. Each time you redistribute the Program (or any work based on the
Program), the recipient automatically receives a license from the
original licensor to copy, distribute or modify the Program subject to
these terms and conditions.  You may not impose any further
restrictions on the recipients' exercise of the rights granted herein.
You are not responsible for enforcing compliance by third parties to
this License.

  7. If, as a consequence of a court judgment or allegation of patent
infringement or for any other reason (not limited to patent issues),
conditions are imposed on you (whether by court order, agreement or
otherwise) that contradict the conditions of this License, they do not
excuse you from the conditions of this License.  If you cannot
distribute so as to satisfy simultaneously your obligations under this
License and any other pertinent obligations, then as a consequence you
may not distribute the Program at all.  For example, if a patent
license would not permit royalty-free redistribution of the Program by
all those who receive copies directly or indirectly through you, then
the only way you could satisfy both it and this License would be to
refrain entirely from distribution of the Program.

If any portion of this section is held invalid or unenforceable under
any particular circumstance, the balance of the section is intended to
apply and the section as a whole is intended to apply in other
circumstances.

It is not the purpose of this section to induce you to infringe any
patents or other property right claims or to contest validity of any
such claims; this section has the sole purpose of protecting the
integrity of the free software distribution system, which is
implemented by public license practices.  Many people have made
generous contributions to the wide range of software distributed
through that system in reliance on consistent application of that
system; it is up to the author/donor to decide if he or she is willing
to distribute software through any other system and a licensee cannot
impose that choice.

This section is intended to make thoroughly clear what is believed to
be a consequence of the rest of this License.

  8. If the distribution and/or use of the Program is restricted in
certain countries either by patents or by copyrighted interfaces, the
original copyright holder who places the Program under this License
may add an explicit geographical distribution limitation excluding
those countries, so that distribution is permitted only in or among
countries not thus excluded.  In such case, this License incorporates
the limitation as if written in the body of this License.

  9. The Free Software Foundation may publish revised and/or new versions
of the General Public License from time to time.  Such new versions will
be similar in spirit to the present version, but may differ in detail to
address new problems or concerns.

Each version is given a distinguishing version number.  If the Program
specifies a version number of this License which applies to it and "any
later version", you have the option of following the terms and conditions
either of that version or of any later version published by the Free
Software Foundation.  If the Program does not specify a version number of
this License, you may choose any version ever published by the Free Software
Foundation.

  10. If you wish to incorporate parts of the Program into other free
programs whose distribution conditions are different, write to the author
to ask for permission.  For software which is copyrighted by the Free
Software Foundation, write to the Free Software Foundation; we sometimes
make exceptions for this.  Our decision will be guided by the two goals
of preserving the free status of all derivatives of our free software and
of promoting the sharing and reuse of software generally.

			    NO WARRANTY

  11. BECAUSE THE PROGRAM IS LICENSED FREE OF CHARGE, THERE IS NO WARRANTY
FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW.  EXCEPT WHEN
OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES
PROVIDE THE PROGRAM "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED
OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.  THE ENTIRE RISK AS
TO THE QUALITY AND PERFORMANCE OF THE PROGRAM IS WITH YOU.  SHOULD THE
PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY SERVICING,
REPAIR OR CORRECTION.

  12. IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING
WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MAY MODIFY AND/OR
REDISTRIBUTE THE PROGRAM AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES,
INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING
OUT OF THE USE OR INABILITY TO USE THE PROGRAM (INCLUDING BUT NOT LIMITED
TO LOSS OF DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY
YOU OR THIRD PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE WITH ANY OTHER
PROGRAMS), EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE
POSSIBILITY OF SUCH DAMAGES.

		     END OF TERMS AND CONDITIONS

	    How to Apply These Terms to Your New Programs

  If you develop a new program, and you want it to be of the greatest
possible use to the public, the best way to achieve this is to make it
free software which everyone can redistribute and change under these terms.

  To do so, attach the following notices to the program.  It is safest
to attach them to the start of each source file to most effectively
convey the exclusion of warranty; and each file should have at least
the "copyright" line and a pointer to where the full notice is found.

    <one line to give the program's name and a brief idea of what it does.>
    Copyright (C) 19yy  <name of author>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA


Also add information on how to contact you by electronic and paper mail.

If the program is interactive, make it output a short notice like this
when it starts in an interactive mode:

    Gnomovision version 69, Copyright (C) 19yy name of author
    Gnomovision comes with ABSOLUTELY NO WARRANTY; for details type `show w'.
    This is free software, and you are welcome to redistribute it
    under certain conditions; type `show c' for details.

The hypothetical commands `show w' and `show c' should show the appropriate
parts of the General Public License.  Of course, the commands you use may
be called something other than `show w' and `show c'; they could even be
mouse-clicks or menu items--whatever suits your program.

You should also get your employer (if you work as a programmer) or your
school, if any, to sign a "copyright disclaimer" for the program, if
necessary.  Here is a sample; alter the names:

  Yoyodyne, Inc., hereby disclaims all copyright interest in the program
  `Gnomovision' (which makes passes at compilers) written by James Hacker.

  <signature of Ty Coon>, 1 April 1989
  Ty Coon, President of Vice

This General Public License does not permit incorporating your program into
proprietary programs.  If your program is a subroutine library, you may
consider it more useful to permit linking proprietary applications with the
library.  If this is what you want to do, use the GNU Library General
Public License instead of this License.
                                                                                                                                                                                                                                                                                                                                                                                                                                        ./makeself-2.1.5/README                                                                             0000664 0023576 0023576 00000040013 11271247354 014143  0                                                                                                    ustar   michael                         michael                                                                                                                                                                                                                The following was generated from http://www.megastep.org/makeself/
-----------------------


   #[1]Mobile/PDA

               makeself - Make self-extractable archives on Unix

   [2]makeself.sh is a small shell script that generates a self-extractable
   tar.gz archive from a directory. The resulting file appears as a shell
   script (many of those have a .run suffix), and can be launched as is. The
   archive will then uncompress itself to a temporary directory and an optional
   arbitrary command will be executed (for example an installation script).
   This is pretty similar to archives generated with WinZip Self-Extractor in
   the Windows world. Makeself archives also include checksums for integrity
   self-validation (CRC and/or MD5 checksums).

   The makeself.sh script itself is used only to create the archives from a
   directory of files. The resultant archive is actually a compressed (using
   gzip, bzip2, or compress) TAR archive, with a small shell script stub at the
   beginning. This small stub performs all the steps of extracting the files,
   running the embedded command, and removing the temporary files when it's all
   over. All what the user has to do to install the software contained in such
   an archive is to "run" the archive, i.e sh nice-software.run. I recommend
   using the "run" (which was introduced by some Makeself archives released by
   Loki Software) or "sh" suffix for such archives not to confuse the users,
   since they know it's actually shell scripts (with quite a lot of binary data
   attached to it though!).

   I am trying to keep the code of this script as portable as possible, i.e
   it's not relying on any bash-specific features and only calls commands that
   are installed on any functioning UNIX-compatible system. This script as well
   as  the  archives it generates should run on any Unix flavor, with any
   compatible Bourne shell, provided of course that the compression programs
   are available.

   As of version 2.1, Makeself has been rewritten and tested on the following
   platforms :
     * Linux (all distributions)
     * Sun Solaris (8 tested)
     * HP-UX (tested on 11.0 and 11i on HPPA RISC)
     * SCO OpenUnix and OpenServer
     * IBM AIX 5.1L
     * MacOS X (Darwin)
     * SGI IRIX 6.5
     * FreeBSD
     * UnicOS / Cray

   If you successfully run Makeself and/or archives created with it on another
   system, then [3]let me know!

   Examples of publicly available archives made using makeself are :
     * Game patches and installers for [4]Id Software games like Quake 3 for
       Linux or Return To Castle Wolfenstien ;
     * All game patches released by [5]Loki Software for the Linux version of
       popular games ;
     * The [6]nVidia drivers for Linux
     * The installer for the Linux version of [7]Google Earth
     * The [8]Makeself distribution itself ;-)
     * and countless others...

   Important note for Apache users: By default, most Web servers will think
   that Makeself archives are regular text files and thus they may show up as
   text in a Web browser. The correct way to prevent this is to add a MIME type
   for this file format, like so (in httpd.conf) :
   AddType application/x-makeself .run

   Important note for recent GNU/Linux distributions: Archives created with
   Makeself prior to v2.1.2 were using an old syntax for the head and tail Unix
   commands that is being progressively obsoleted in their GNU forms. Therefore
   you may have problems uncompressing some of these archives. A workaround for
   this is to set the environment variable $_POSIX2_VERSION to enable the old
   syntax, i.e. :
   export _POSIX2_VERSION=199209

Usage

   The syntax of makeself is the following:

   makeself.sh [args] archive_dir file_name label startup_script [script_args]
     * args are optional options for Makeself. The available ones are :
          + --version  :  Prints the version number on stdout, then exits
            immediately
          + --gzip : Use gzip for compression (is the default on platforms on
            which gzip is commonly available, like Linux)
          + --bzip2 : Use bzip2 instead of gzip for better compression. The
            bzip2 command must be available in the command path. I recommend
            that  you set the prefix to something like '.bz2.run' for the
            archive, so that potential users know that they'll need bzip2 to
            extract it.
          + --compress : Use the UNIX "compress" command to compress the data.
            This should be the default on all platforms that don't have gzip
            available.
          + --nocomp : Do not use any compression for the archive, which will
            then be an uncompressed TAR.
          + --notemp : The generated archive will not extract the files to a
            temporary directory, but in a new directory created in the current
            directory. This is better to distribute software packages that may
            extract and compile by themselves (i.e. launch the compilation
            through the embedded script).
          + --current : Files will be extracted to the current directory,
            instead of in a subdirectory. This option implies --notemp above.
          + --follow  :  Follow  the symbolic links inside of the archive
            directory, i.e. store the files that are being pointed to instead
            of the links themselves.
          + --append  (new in 2.1.x): Append data to an existing archive,
            instead of creating a new one. In this mode, the settings from the
            original archive are reused (compression type, label, embedded
            script), and thus don't need to be specified again on the command
            line.
          + --header : Makeself 2.0 uses a separate file to store the header
            stub, called "makeself-header.sh". By default, it is assumed that
            it is stored in the same location as makeself.sh. This option can
            be used to specify its actual location if it is stored someplace
            else.
          + --copy : Upon extraction, the archive will first extract itself to
            a temporary directory. The main application of this is to allow
            self-contained installers stored in a Makeself archive on a CD,
            when the installer program will later need to unmount the CD and
            allow a new one to be inserted. This prevents "Filesystem busy"
            errors for installers that span multiple CDs.
          + --nox11 : Disable the automatic spawning of a new terminal in X11.
          + --nowait : When executed from a new X11 terminal, disable the user
            prompt at the end of the script execution.
          + --nomd5 and --nocrc : Disable the creation of a MD5 / CRC checksum
            for the archive. This speeds up the extraction process if integrity
            checking is not necessary.
          + --lsm  file  : Provide and LSM file to makeself, that will be
            embedded in the generated archive. LSM files are describing a
            software package in a way that is easily parseable. The LSM entry
            can  then be later retrieved using the '-lsm' argument to the
            archive. An exemple of a LSM file is provided with Makeself.
     * archive_dir is the name of the directory that contains the files to be
       archived
     * file_name is the name of the archive to be created
     * label is an arbitrary text string describing the package. It will be
       displayed while extracting the files.
     * startup_script is the command to be executed from within the directory
       of extracted files. Thus, if you wish to execute a program contain in
       this directory, you must prefix your command with "./". For example,
       ./program will be fine. The script_args are additionnal arguments for
       this command.

   Here  is an example, assuming the user has a package image stored in a
   /home/joe/mysoft, and he wants to generate a self-extracting package named
   mysoft.sh,  which  will  launch the "setup" script initially stored in
   /home/joe/mysoft :

   makeself.sh /home/joe/mysoft mysoft.sh "Joe's Nice Software Package" ./setup
   Here is also how I created the [9]makeself.run archive which contains the
   Makeself distribution :

   makeself.sh --notemp makeself makeself.run "Makeself by Stephane Peter" echo
   "Makeself has extracted itself"

   Archives generated with Makeself 2.1 can be passed the following arguments:

     * --keep : Prevent the files to be extracted in a temporary directory that
       will be removed after the embedded script's execution. The files will
       then be extracted in the current working directory and will stay here
       until you remove them.
     * --verbose : Will prompt the user before executing the embedded command
     * --target dir : Allows to extract the archive in an arbitrary place.
     * --nox11 : Do not spawn a X11 terminal.
     * --confirm : Prompt the user for confirmation before running the embedded
       command.
     * --info : Print out general information about the archive (does not
       extract).
     * --lsm : Print out the LSM entry, if it is present.
     * --list : List the files in the archive.
     * --check : Check the archive for integrity using the embedded checksums.
       Does not extract the archive.
     * --nochown  : By default, a "chown -R" command is run on the target
       directory after extraction, so that all files belong to the current
       user. This is mostly needed if you are running as root, as tar will then
       try  to recreate the initial user ownerships. You may disable this
       behavior with this flag.
     * --tar : Run the tar command on the contents of the archive, using the
       following arguments as parameter for the command.
     * --noexec : Do not run the embedded script after extraction.

   Any  subsequent  arguments to the archive will be passed as additional
   arguments to the embedded command. You should explicitly use the -- special
   command-line construct before any such options to make sure that Makeself
   will not try to interpret them.

License

   Makeself is covered by the [10]GNU General Public License (GPL) version 2
   and above. Archives generated by Makeself don't have to be placed under this
   license (although I encourage it ;-)), since the archive itself is merely
   data for Makeself.

Download

   Get the latest official distribution [11]here (version 2.1.5).

   The  latest development version can be grabbed from the Loki Setup CVS
   module, at [12]cvs.icculus.org.

Version history

     * v1.0: Initial public release
     * v1.1: The archive can be passed parameters that will be passed on to the
       embedded script, thanks to John C. Quillan
     * v1.2: Cosmetic updates, support for bzip2 compression and non-temporary
       archives. Many ideas thanks to Francois Petitjean.
     * v1.3: More patches from Bjarni R. Einarsson and Francois Petitjean:
       Support for no compression (--nocomp), script is no longer mandatory,
       automatic launch in an xterm, optional verbose output, and -target
       archive option to indicate where to extract the files.
     * v1.4: Many patches from Francois Petitjean: improved UNIX compatibility,
       automatic integrity checking, support of LSM files to get info on the
       package at run time..
     * v1.5.x: A lot of bugfixes, and many other patches, including automatic
       verification through the usage of checksums. Version 1.5.5 was the
       stable release for a long time, even though the Web page didn't get
       updated ;-). Makeself was also officially made a part of the [13]Loki
       Setup installer, and its source is being maintained as part of this
       package.
     * v2.0: Complete internal rewrite of Makeself. The command-line parsing
       was vastly improved, the overall maintenance of the package was greatly
       improved by separating the stub from makeself.sh. Also Makeself was
       ported and tested to a variety of Unix platforms.
     * v2.0.1: First public release of the new 2.0 branch. Prior versions are
       officially obsoleted. This release introduced the '--copy' argument that
       was introduced in response to a need for the [14]UT2K3 Linux installer.
     * v2.1.0:  Big  change  : Makeself can now support multiple embedded
       tarballs, each stored separately with their own checksums. An existing
       archive can be updated with the --append flag. Checksums are also better
       managed, and the --nochown option for archives appeared.
     * v2.1.1: Fixes related to the Unix compression (compress command). Some
       Linux distributions made the insane choice to make it unavailable, even
       though gzip is capable of uncompressing these files, plus some more
       bugfixes in the extraction and checksum code.
     * v2.1.2:  Some  bug fixes. Use head -n to avoid problems with POSIX
       conformance.
     * v2.1.3: Bug fixes with the command line when spawning terminals. Added
       --tar,  --noexec  for archives. Added --nomd5 and --nocrc to avoid
       creating checksums in archives. The embedded script is now run through
       "eval". The --info output now includes the command used to create the
       archive. A man page was contributed by Bartosz Fenski.
     * v2.1.4:  Fixed  --info output. Generate random directory name when
       extracting files to . to avoid problems. Better handling of errors with
       wrong permissions for the directory containing the files. Avoid some
       race conditions, Unset the $CDPATH variable to avoid problems if it is
       set. Better handling of dot files in the archive directory.
     * v2.1.5: Made the md5sum detection consistent with the header code. Check
       for the presence of the archive directory. Added --encrypt for symmetric
       encryption through gpg (Eric Windisch). Added support for the digest
       command on Solaris 10 for MD5 checksums. Check for available disk space
       before extracting to the target directory (Andreas Schweitzer). Allow
       extraction  to run asynchronously (patch by Peter Hatch). Use file
       descriptors internally to avoid error messages (patch by Kay Tiong
       Khoo).

Links

     * Check out the [15]"Loki setup" installer, used to install many Linux
       games and other applications, and of which I am the co-author. Since the
       demise of Loki, I am now the official maintainer of the project, and it
       is now being hosted on [16]icculus.org, as well as a bunch of other
       ex-Loki projects (and a lot of other good stuff!).
     * Bjarni R. Einarsson also wrote the setup.sh installer script, inspired
       by Makeself. [17]Check it out !

Contact

   This script was written by [18]StÃ©phane Peter (megastep at megastep.org) I
   welcome any enhancements and suggestions.

   Contributions were included from John C. Quillan, Bjarni R. Einarsson,
   Francois Petitjean, and Ryan C. Gordon, thanks to them! If you think I
   forgot your name, don't hesitate to contact me.

   icculus.org also has a [19]Bugzilla server available that allows bug reports
   to be submitted for Loki setup, and since Makeself is a part of Loki setup,
   you can submit bug reports from there!
     _________________________________________________________________


    [20]StÃ©phane Peter

   Last modified: Fri Jan 4 15:51:05 PST 2008

References

   1. http://mowser.com/web/megastep.org/makeself/
   2. http://www.megastep.org/makeself/makeself.run
   3. mailto:megastep@REMOVEME.megastep.org
   4. http://www.idsoftware.com/
   5. http://www.lokigames.com/products/myth2/updates.php3
   6. http://www.nvidia.com/
   7. http://earth.google.com/
   8. http://www.megastep.org/makeself/makeself.run
   9. http://www.megastep.org/makeself/makeself.run
  10. http://www.gnu.org/copyleft/gpl.html
  11. http://www.megastep.org/makeself/makeself-2.1.5.run
  12. http://cvs.icculus.org/
  13. http://www.icculus.org/loki_setup/
  14. http://www.unrealtournament2003.com/
  15. http://www.icculus.org/loki_setup/
  16. http://www.icculus.org/
  17. http://www.mmedia.is/~bre/programs/setup.sh/
  18. mailto:megastep@@megastep.org
  19. https://bugzilla.icculus.org/
  20. mailto:megastep@@megastep.org
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     ./openvas-lsc-target.spec.in                                                                        0000664 0023576 0023576 00000004217 11416535515 016040  0                                                                                                    ustar   michael                         michael                                                                                                                                                                                                                %define name @RpmName@
%define PubkeyBasename @PubkeyBasename@ 
%define version @VERSION@
%define release 1
%define _topdir @TOPDIR@
%define _tmppath @TOPDIR@/rpmtmp
%define manifest %{_builddir}/%{name}-%{version}-%{release}.manifest

# required items
Name: %{name}
Version: %{version}
Release: %{release}
License: GPL
Group: Application/Misc

Source: %{name}-%{version}.tar.gz
#Prefix: /usr
BuildRoot: /var/tmp/%{name}-%{version}

Summary: OpenVAS local security check preparation

%description
This package prepares a system for OpenVAS local security checks.
A user is created with a specific SSH authorized key.
The corresponding private key is located at the respective
OpenVAS installation.

%prep
%setup -q
#%patch0 -p1

%build
make

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/home/%{PubkeyBasename}/.ssh/
%makeinstall

# __os_install_post is implicitly expanded after the
# %install section... do it now, and then disable it,
# so all work is done before building manifest.

%{?__os_install_post}
%define __os_install_post %{nil}

# build the file list automagically into %{manifest}

cd $RPM_BUILD_ROOT
rm -f %{manifest}
find . -type d \
        | sed '1,2d;s,^\.,\%attr(-\,root\,root) \%dir ,' >> %{manifest}
find . -type f \
        | sed 's,^\.,\%attr(-\,root\,root) ,' >> %{manifest}
find . -type l \
        | sed 's,^\.,\%attr(-\,root\,root) ,' >> %{manifest}

%pre
useradd -c "OpenVAS Local Security Checks" -d /home/%{PubkeyBasename} -m -s /bin/bash %{PubkeyBasename}

%post
chown -R %{PubkeyBasename} /home/%{PubkeyBasename}/.ssh
chmod 500 /home/%{PubkeyBasename}/.ssh
chmod 400 /home/%{PubkeyBasename}/.ssh/authorized_keys


#%preun
%postun
# Remove user only if it was created by this package.
# The alien-converted debian package will run the postun script in case of
# errors (e.g. user already existed). Delete the user only if /etc/passwd lists
# content that suggests that the user was created by this package.
grep "%{PubkeyBasename}.*OpenVAS\ Local\ Security\ Checks" /etc/passwd && userdel -f %{PubkeyBasename}

%clean
rm -f %{manifest}
rm -rf $RPM_BUILD_ROOT

%files -f %{manifest}
%defattr(-,root,root)
#%doc README
#%docdir
#%config

%changelog
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 