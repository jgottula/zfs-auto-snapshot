#!/bin/zsh

# zfs-auto-snapshot for Linux
# Automatically create, rotate, and destroy periodic ZFS snapshots.
# Copyright 2011 Darik Horn <dajhorn@vanadac.com>
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation; either version 2 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 59 Temple
# Place, Suite 330, Boston, MA  02111-1307  USA
#

zmodload zsh/param/private # zsh: 'private': better version of 'local' that doesn't let function callees see callers' locals

setopt c_bases            # zsh: print non-decimal numbers (hex) like real C programmers, dammit
setopt rematch_pcre       # zsh: use PCRE syntax for regex
setopt local_loops        # zsh: warn and disallow break/continue across function scopes
setopt warn_create_global # zsh: warn when functions create new global vars
setopt warn_nested_var    # zsh: warn when functions assign to global vars or local vars from outer functions etc

# Set the field separator to a literal tab and newline.
IFS="	
"

# Set default program options.
opt_backup_full=''
opt_backup_incremental=''
opt_default_include=''
opt_dry_run=''
opt_event_is_set=''
opt_event=''
opt_fast_zfs_list=''
opt_keep=''
opt_label=''
opt_prefix='auto'
opt_recursive=''
opt_sep='_'
opt_setauto=''
opt_syslog=''
opt_skip_scrub=''
opt_skip_recv=''
opt_verbose=''
opt_pre_snapshot=''
opt_post_snapshot=''
opt_do_snapshots=1
opt_min_size=0

# Global summary statistics.
DESTRUCTION_COUNT='0'
SNAPSHOT_COUNT='0'
WARNING_COUNT='0'

# Other global variables.
SNAPSHOTS_OLD=''

# Regex: valid characters for snapshot names (technically ' ' is okay, but we will disallow it)
# See: lib/libzfs/libzfs_dataset.c, module/zcommon/zfs_namecheck.c
RE_VALID_ANYLEN='^[[:alnum:]-_.:]*$'
RE_VALID_SINGLE='^[[:alnum:]-_.:]$'


typeset -A T1 T2 DT

t1 ()
{
	T1[$1]=$(date -u '+%s%N')
}

t2 ()
{
	[[ -v T1[$1] ]] || return # problem!

	T2[$1]=$(date -u '+%s%N')

	private DTI=$(( T2[$1] - T1[$1] )) # ; echo >&2 "t2: DTI=$DTI"
	(( DTI >= 0 )) || (( DTI = 0 ))    # ; echo >&2 "t2: DTI=$DTI"

	# accumulate globally, to allow doing [ t1...t2 t1...t2 t1...t2 dt ] with cumulative results
	(( DT[$1] += DTI ))

	unset "T1[$1]"
	unset "T2[$1]"
}

dt ()
{
	private PREC=$2

	[[ -v DT[$1] ]] || return # problem!

	private DIV_NSEC=$(( 10 **   9          ))
	private DIV_PREC=$(( 10 **       PREC   ))
	private DIV_PINV=$(( 10 ** ( 9 - PREC ) ))

	private DT_SEC_WHOL=$((   DT[$1] / DIV_NSEC              ))
	private DT_SEC_FRAC=$(( ( DT[$1] / DIV_PINV ) % DIV_PREC ))

	private DT_MIN=$(( DT_SEC_WHOL / 60 ))
	private DT_SEC=$(( DT_SEC_WHOL % 60 ))

	if (( $PREC > 0 )); then
		printf '%u:%02u.%0*u\n' "$DT_MIN" "$DT_SEC" "$PREC" "$DT_SEC_FRAC"
	else
		printf '%u:%02u\n' "$DT_MIN" "$DT_SEC"
	fi
}


print_usage ()
{
	echo "Usage: zfs-auto-snapshot [options] [-l label] <'//' | name [name...]>

  --default-include  Include datasets if com.sun:auto-snapshot is unset.
  -d, --debug        Print debugging messages.
  -e, --event=EVENT  Set the com.sun:auto-snapshot-desc property to EVENT.
      --fast         Use a faster zfs list invocation.
  -n, --dry-run      Print actions without actually doing anything.
  -s, --skip-scrub   Do not snapshot filesystems in scrubbing pools.
      --skip-recv    Skip datasets that are being received with resume token.
  -h, --help         Print this usage message.
  -k, --keep=NUM     Keep NUM recent snapshots and destroy older snapshots.
  -l, --label=LAB    LAB is usually 'hourly', 'daily', or 'monthly'.
  -p, --prefix=PRE   PRE is 'auto' by default.
  -q, --quiet        Suppress warnings and notices at the console.
      --send-full=F  Send zfs full backup. Unimplemented.
      --send-incr=F  Send zfs incremental backup. Unimplemented.
      --sep=CHAR     Use CHAR to separate date stamps in snapshot names.
  -g, --syslog       Write messages into the system log.
  -r, --recursive    Snapshot named filesystem and all descendants.
  -v, --verbose      Print info messages.
      --destroy-only Only destroy older snapshots, do not create new ones.
      --min-size=MIN Snapshot only if >= MIN KiB written since prior snapshot.
      name           Filesystem and volume names, or '//' for all ZFS datasets.

Refer to the zfs-auto-snapshot(8) man page for additional information.
(Parameters not covered here include: --pre-snapshot, --post-snapshot)
"
}


print_log () # level, message, ...
{
	private LEVEL=$1
	shift 1

	private TAG="zfs-auto-snapshot"
	[[ -n "$opt_label" ]] && TAG+="<$opt_label>"

	case $LEVEL in
		(eme*)
			[[ -n "$opt_syslog" ]] && logger --id=$$ -t $TAG -p daemon.emerge $* ||
				echo Emergency: $* 1>&2
			;;
		(ale*)
			[[ -n "$opt_syslog" ]] && logger --id=$$ -t $TAG -p daemon.alert $* ||
				echo Alert: $* 1>&2
			;;
		(cri*)
			[[ -n "$opt_syslog" ]] && logger --id=$$ -t $TAG -p daemon.crit $* ||
				echo Critical: $* 1>&2
			;;
		(err*)
			[[ -n "$opt_syslog" ]] && logger --id=$$ -t $TAG -p daemon.err $* ||
				echo Error: $* 1>&2
			;;
		(war*)
			[[ -n "$opt_syslog" ]] && logger --id=$$ -t $TAG -p daemon.warning $* ||
				{ [[ -z "$opt_quiet" ]] && echo Warning: $* 1>&2 ; }
			;;
		(not*)
			[[ -n "$opt_syslog" ]] && logger --id=$$ -t $TAG -p daemon.notice $* ||
				{ [[ -z "$opt_quiet" ]] && echo $* 1>&2 ; }
			;;
		(inf*)
			if [[ -n "$opt_verbose" ]]; then
				[[ -n "$opt_syslog" ]] && logger --id=$$ -t $TAG -p daemon.info $* ||
					{ [[ -z "$opt_quiet" ]] && echo $* 1>&2 ; }
			fi
			;;
		(deb*)
			if [[ -n "$opt_debug" ]]; then
				[[ -n "$opt_syslog" ]] && logger --id=$$ -t $TAG -p daemon.debug $* ||
					{ [[ -z "$opt_quiet" ]] && echo Debug: $* 1>&2 ; }
			fi
			;;
		(*)
			[[ -n "$opt_syslog" ]] && logger --id=$$ -t $TAG $* ||
				{ [[ -z "$opt_quiet" ]] && echo $* 1>&2 ; }
			;;
	esac
}


do_run () # [argv]
{
	if [ -n "$opt_dry_run" ]
	then
		echo $*
		private RC="$?"
	else
		eval $*
		private RC="$?"
		if [ "$RC" -eq '0' ]
		then
			print_log debug "$*"
		else
			print_log warning "$* returned $RC"
		fi
	fi
	return "$RC"
}


do_snapshots () # properties, flags, snapname, [targets...]
{
	private PROPS="$1"
	private FLAGS="$2"
	private NAME="$3"
	private TARGETS=("${@:4}")
	private KEEP=''
	private RUNSNAP=1

	# global DESTRUCTION_COUNT
	# global SNAPSHOT_COUNT
	# global WARNING_COUNT
	# global SNAPSHOTS_OLD

	# RE_OLD is the regular expression that old snapshots must match against.
	# Here, we precompute RE_OLD_BASE, which contains the non-dataset-specific parts that won't change.
	# We must escape any characters in the valid char set so they will still match literally.
	# In practice, the only such character we need to worry about is '.'.
	private RE_OLD_PREFIX=${opt_prefix:+$opt_prefix$opt_sep}
	private RE_OLD_DATE='\d{4}-\d{2}-\d{2}-\d{4}'
	private RE_OLD_LABEL=${opt_label:+$opt_sep$opt_label}
	private RE_OLD_BASE=${RE_OLD_PREFIX//./\\.}${RE_OLD_DATE}${RE_OLD_LABEL//./\\.}

	private ii
	for ii in "${TARGETS[@]}"
	do
		# Check if size check is > 0
		private size_check_skip=0
		if [ "$opt_min_size" -gt 0 ]
		then
			private bytes_written=`zfs get -Hp -o value written $ii`
			private kb_written=$(( $bytes_written / 1024 ))
			if [ "$kb_written" -lt "$opt_min_size" ]
			then
				size_check_skip=1
				if [ $opt_verbose -gt 0 ]
				then
					echo "Skipping target $ii, only $kb_written kB written since last snap. opt_min_size is $opt_min_size"
				fi
			fi
		fi

		if [ -n "$opt_do_snapshots" -a "$size_check_skip" -eq 0 ]
		then
			if [ "$opt_pre_snapshot" != "" ]
			then
				do_run "$opt_pre_snapshot $ii $NAME" || RUNSNAP=0
			fi
			if [ $RUNSNAP -eq 1 ] && do_run "zfs snapshot ${PROPS:+$PROPS }${FLAGS:+$FLAGS }'$ii@$NAME'"
			then
				[ "$opt_post_snapshot" != "" ] && do_run "$opt_post_snapshot $ii $NAME"
				SNAPSHOT_COUNT=$(( $SNAPSHOT_COUNT + 1 ))
			else
				WARNING_COUNT=$(( $WARNING_COUNT + 1 ))
				continue
			fi
		fi

		# Retain at most $opt_keep number of old snapshots of this filesystem,
		# including the one that was just recently created.
		test -z "$opt_keep" && continue
		KEEP="$opt_keep"

		private RE_OLD='^'${ii//./\\.}'@'${RE_OLD_BASE}'$'

		# ASSERT: The old snapshot list is sorted by increasing age.
		for jj in "${SNAPSHOTS_OLD[@]}"
		do
			# Check whether this is an old snapshot of the filesystem.
			if [[ "$jj" =~ $RE_OLD ]]
			then
				KEEP=$(( $KEEP - 1 ))
				if [ "$KEEP" -le '0' ]
				then
					if do_run "zfs destroy -d ${FLAGS:+$FLAGS }'$jj'"
					then
						DESTRUCTION_COUNT=$(( $DESTRUCTION_COUNT + 1 ))
					else
						WARNING_COUNT=$(( $WARNING_COUNT + 1 ))
					fi
				fi
			fi
		done
	done
}


# main ()
# {

# Save the original command line parameters, because we will parse them twice:
# once before taking the flock, and then again once holding the flock
# (this is messy, but it's necessary for stuff like --help to work immediately without blocking on the flock)
ARGS_PRELOCK=("$@")

if [ "$(uname)" = "Darwin" ]; then
  GETOPT_BIN="$(brew --prefix gnu-getopt 2> /dev/null || echo /usr/local)/bin/getopt"
else
  GETOPT_BIN="getopt"
fi

GETOPT=$($GETOPT_BIN \
  --longoptions=default-include,dry-run,fast,skip-scrub,skip-recv,recursive \
  --longoptions=event:,keep:,label:,prefix:,sep: \
  --longoptions=debug,help,quiet,syslog,verbose \
  --longoptions=pre-snapshot:,post-snapshot:,destroy-only \
  --longoptions=min-size: \
  --options=dnshe:l:k:p:rs:qgvm: \
  -- "$@" ) \
  || exit 128

eval set -- "$GETOPT"

while [ "$#" -gt '0' ]
do
	case "$1" in
		(-d|--debug)
			opt_debug='1'
			opt_quiet=''
			opt_verbose='1'
			shift 1
			;;
		(--default-include)
			opt_default_include='1'
			shift 1
			;;
		(-e|--event)
			if [ "${#2}" -gt '1024' ]
			then
				print_log error "The $1 parameter must be less than 1025 characters."
				exit 139
			fi
			opt_event_is_set='1'
			opt_event="$2"
			shift 2
			;;
		(--fast)
			opt_fast_zfs_list='1'
			shift 1
			;;
		(-n|--dry-run)
			opt_dry_run='1'
			shift 1
			;;
		(-s|--skip-scrub)
			opt_skip_scrub='1'
			shift 1
			;;
		(--skip-recv)
			opt_skip_recv='1'
			shift 1
			;;
		(-h|--help)
			print_usage
			exit 0
			;;
		(-k|--keep)
			if ! test "$2" -gt '0' 2>/dev/null
			then
				print_log error "The $1 parameter must be a positive integer."
				exit 129
			fi
			opt_keep="$2"
			shift 2
			;;
		(-l|--label)
			if [[ ! "$2" =~ $RE_VALID_ANYLEN ]]
			then
				print_log error "The $1 parameter must be alphanumeric."
				exit 202
			fi
			opt_label="$2"
			shift 2
			;;
		(-m|--min-size)
			if ! test "$2" -ge '0' 2>/dev/null
			then
				print_log error "The $1 parameter must be a nonnegative integer."
				exit 201
			fi
			opt_min_size="$2"
			shift 2
			;;
		(-p|--prefix)
			if [[ ! "$2" =~ $RE_VALID_ANYLEN ]]
			then
				print_log error "The $1 parameter must be alphanumeric."
				exit 130
			fi
			opt_prefix="$2"
			shift 2
			;;
		(-q|--quiet)
			opt_debug=''
			opt_quiet='1'
			opt_verbose=''
			shift 1
			;;
		(-r|--recursive)
			opt_recursive='1'
			shift 1
			;;
		(--sep)
			if [[ "$2" == "" ]]
			then
				print_log error "The $1 parameter must be non-empty."
				exit 131
			elif [[ ! "$2" =~ $RE_VALID_SINGLE ]]
			then
				print_log error "The $1 parameter must be one alphanumeric character."
				exit 132
			fi
			opt_sep="$2"
			shift 2
			;;
		(-g|--syslog)
			opt_syslog='1'
			shift 1
			;;
		(-v|--verbose)
			opt_quiet=''
			opt_verbose='1'
			shift 1
			;;
		(--pre-snapshot)
			opt_pre_snapshot="$2"
			shift 2
			;;
		(--post-snapshot)
			opt_post_snapshot="$2"
			shift 2
			;;
		(--destroy-only)
			opt_do_snapshots=''
			shift 1
			;;
		(--)
			shift 1
			break
			;;
	esac
done

if [ "$#" -eq '0' ]
then
	print_log error "The filesystem argument list is empty."
	exit 133
fi

# Count the number of times '//' appears on the command line.
SLASHIES='0'
for ii in "$@"
do
	test "$ii" = '//' && SLASHIES=$(( $SLASHIES + 1 ))
done

if [ "$#" -gt '1' -a "$SLASHIES" -gt '0' ]
then
	print_log error "The // must be the only argument if it is given."
	exit 134
fi


# ISO style date; fifteen characters: YYYY-MM-DD-HHMM
# On Solaris %H%M expands to 12h34.
# We use the shortform -u here because --utc is not supported on macos.
# NOTE: we now grab this BEFORE running any time-consuming zpool/zfs commands!
#       (and actually also BEFORE we do the flock stuff as well... slightly sketchy but nicer looking at least...)
# NOTE: we set DATE_PRELOCK here (twice actually); but when we're flock'd, DATE will be pre-set in the environment
DATE_PRELOCK=$(date -u +%F-%H%M)

# We use a per-label flock: this means that instances can run in parallel, so long as they are for different labels
# If a label is specified: /var/lock/zfs-auto-snapshot-LABEL
# Otherwise:               /var/lock/zfs-auto-snapshot
FLOCK_PATH="/var/lock/zfs-auto-snapshot${opt_label:+-$opt_label}"

# Only allow one instance of zfs-auto-snapshot, per-label, to run (besides option parsing) at any given time
# (to avoid possible race conditions due to multiple different runs with the same 'label' happening at once)
# NOTE: this is an adaptation of the example code straight out of 'man 1 flock'
if [[ "$FLOCKER" != "$FLOCK_PATH" ]]; then
	t1 FLOCK
	exec env FLOCKER="$FLOCK_PATH" DATE="$DATE_PRELOCK" T1_FLOCK="$T1[FLOCK]" flock --exclusive "$FLOCK_PATH" "$0" "${ARGS_PRELOCK[@]}"
	# TODO: is there a good way to 'serialize' the T1/T2/DT associative arrays for sending across the exec?
	# there must be... surely one of those parameter expansion flags lets us print the associative array as a string that can be passed directly to exec or whatever
else
	T1[FLOCK]=$T1_FLOCK
	t2 FLOCK
	print_log notice "time spent waiting on flock: $(dt FLOCK 2)"
fi


##########################################################################################################
##########################################################################################################
##                                                                                                      ##
##  file-level code above this point is executed WITHOUT flock; below is executed with the flock HELD!  ##
##                                                                                                      ##
##########################################################################################################
##########################################################################################################


# These are the only times that `zpool status` or `zfs list` are invoked, so
# this program for Linux has a much better runtime complexity than the similar
# Solaris implementation.

t1 ZPOOL_STATUS
ZPOOL_STATUS=$(env LC_ALL=C zpool status 2>&1 ) \
  || { print_log error "zpool status $?: $ZPOOL_STATUS"; exit 135; }
t2 ZPOOL_STATUS
print_log notice "time spent on 'zpool status': $(dt ZPOOL_STATUS 2)"


t1 ZFS_LIST1
ZFS_LIST=$(env LC_ALL=C zfs list -H -t filesystem,volume -s name \
  -o name,receive_resume_token,com.sun:auto-snapshot${opt_label:+,com.sun:auto-snapshot:"$opt_label"}) \
  || { print_log error "zfs list $?: $ZFS_LIST"; exit 136; }
t2 ZFS_LIST1
print_log notice "time spent on 'zfs list' (datasets): $(dt ZFS_LIST1 2)"

t1 ZFS_LIST2
if [ -n "$opt_fast_zfs_list" ]
then
	SNAPSHOTS_OLD=($(env LC_ALL=C zfs list -H -t snapshot -o name -s name | \
	  grep -P '@'"${opt_prefix:+${opt_prefix//./\\.}${opt_sep//./\\.}}"'\d{4}-\d{2}-\d{2}-\d{4}'"${opt_label:+${opt_sep//./\\.}${opt_label//./\\.}}"'$' | \
	  sort -t'@' -k2r,2 -k1,1)) \
	  || { print_log error "zfs list $?: $SNAPSHOTS_OLD"; exit 137; }
else
	SNAPSHOTS_OLD=($(env LC_ALL=C zfs list -H -t snapshot -S creation -o name)) \
	  || { print_log error "zfs list $?: $SNAPSHOTS_OLD"; exit 137; }
fi
t2 ZFS_LIST2
print_log notice "time spent on 'zfs list' (snapshots): $(dt ZFS_LIST2 2)"

# Verify that each argument is a filesystem or volume.
for ii in "$@"
do
	test "$ii" = '//' && continue 1
	while read NAME PROPERTIES
	do
		test "$ii" = "$NAME" && continue 2
	done <<-HERE
	$ZFS_LIST
	HERE
	print_log error "$ii is not a ZFS filesystem or volume."
	exit 138
done

# Get a list of pools that are being scrubbed.
ZPOOLS_SCRUBBING=($(echo "$ZPOOL_STATUS" | awk -F ': ' \
  '$1 ~ /^ *pool$/ { pool = $2 } ; \
   $1 ~ /^ *scan$/ && $2 ~ /scrub in progress/ { print pool }' \
  | sort))

# Get a list of pools that cannot do a snapshot.
ZPOOLS_NOTREADY=($(echo "$ZPOOL_STATUS" | awk -F ': ' \
  '$1 ~ /^ *pool$/ { pool = $2 } ; \
   $1 ~ /^ *state$/ && $2 !~ /ONLINE|DEGRADED/ { print pool } ' \
  | sort))

# Get a list of datasets for which snapshots are explicitly disabled.
if [ -n "$opt_label" ]
then
	NOAUTO=($(echo "$ZFS_LIST" | awk -F '\t' \
	  'tolower($3) ~ /false/ || tolower($4) ~ /false/ {print $1}'))
else
	NOAUTO=($(echo "$ZFS_LIST" | awk -F '\t' \
	  'tolower($3) ~ /false/ {print $1}'))
fi

# Get a list of datasets that are identified as actively receiving right now
# (i.e. they have property receive_resume_token set to something).
# Note that this will only detect cases where 'zfs recv -s' is being used.
RECEIVING=($(echo "$ZFS_LIST" | awk -F '\t' \
	'$2 !~ /^-$/ {print $1}'))
NOAUTO+=(${RECEIVING[@]})

# If the --default-include flag is set, then include all datasets that lack
# an explicit com.sun:auto-snapshot* property. Otherwise, exclude them.
if [ -z "$opt_default_include" ]
then
	# Get a list of datasets for which snapshots are explicitly enabled.
	if [ -n "$opt_label" ]
	then
		CANDIDATES=($(echo "$ZFS_LIST" | awk -F '\t' \
		  'tolower($3) ~ /true/ && tolower($4) ~ /true/ {print $1}'))
	else
		CANDIDATES=($(echo "$ZFS_LIST" | awk -F '\t' \
		  'tolower($3) ~ /true/ {print $1}'))
	fi
else
	# Get a list of datasets for which snapshots are not explicitly disabled.
	if [ -n "$opt_label" ]
	then
		CANDIDATES=($(echo "$ZFS_LIST" | awk -F '\t' \
		  'tolower($3) !~ /false/ && tolower($4) !~ /false/ {print $1}'))
	else
		CANDIDATES=($(echo "$ZFS_LIST" | awk -F '\t' \
		  'tolower($3) !~ /false/ {print $1}'))
	fi
fi

# Initialize the list of datasets that will get a recursive snapshot.
TARGETS_RECURSIVE=()

# Initialize the list of datasets that will get a non-recursive snapshot.
TARGETS_REGULAR=()

for ii in "${CANDIDATES[@]}"
do
	# Qualify dataset names so variable globbing works properly.
	# Suppose ii=tanker/foo and jj=tank sometime during the loop.
	# Just testing "$ii" != ${ii#$jj} would incorrectly match.
	iii="$ii/"


	# Exclude datasets
	# * that are not named on the command line or
	# * those whose prefix is not on the command line (if --recursive flag is set)
	IN_ARGS='0'
	for jj in "$@"
	do
		# Ibid regarding iii.
		jjj="$jj/"

		if [ "$jj" = '//' -o "$jj" = "$ii" ]
		then
			IN_ARGS=$(( $IN_ARGS + 1 ))
		elif [ -n "$opt_recursive" -a "$iii" != "${iii#$jjj}" ]
		then
			IN_ARGS=$(( $IN_ARGS + 1 ))
		fi
	done
	if [ "$IN_ARGS" -eq '0' ]
	then
		continue
	fi

	# Exclude datasets in pools that cannot do a snapshot.
	for jj in "${ZPOOLS_NOTREADY[@]}"
	do
		# Ibid regarding iii.
		jjj="$jj/"

		# Check whether the pool name is a prefix of the dataset name.
		if [ "$iii" != "${iii#$jjj}" ]
		then
			print_log info "Excluding $ii because pool $jj is not ready."
			continue 2
		fi
	done

	# Exclude datasets in scrubbing pools if the --skip-scrub flag is set.
	test -n "$opt_skip_scrub" && for jj in "${ZPOOLS_SCRUBBING[@]}"
	do
		# Ibid regarding iii.
		jjj="$jj/"

		# Check whether the pool name is a prefix of the dataset name.
		if [ "$iii" != "${iii#$jjj}" ]
		then
			print_log info "Excluding $ii because pool $jj is scrubbing."
			continue 2
		fi
	done

	# Exclude datasets that are undergoing a receive operation
	# (i.e. property receive_resume_token is set)
	# if the --skip-recv flag is set.
	test -n "$opt_skip_recv" && for jj in "${RECEIVING[@]}"
	do
		if [ "$iii" = "$jj/" ]
		then
			print_log info "Excluding $ii because it is currently being received."
			continue 2
		fi
	done

	for jj in "${NOAUTO[@]}"
	do
		# Ibid regarding iii.
		jjj="$jj/"

		# The --recursive switch only matters for non-wild arguments.
		if [ -z "$opt_recursive" -a "$1" != '//' ]
		then
			# Snapshot this dataset non-recursively.
			print_log debug "Including $ii for regular snapshot."
			TARGETS_REGULAR+=("$ii")
			continue 2
		# Check whether the candidate name is a prefix of any excluded dataset name.
		elif [ "$jjj" != "${jjj#$iii}" ]
		then
			# Snapshot this dataset non-recursively.
			print_log debug "Including $ii for regular snapshot."
			TARGETS_REGULAR+=("$ii")
			continue 2
		fi
	done

	for jj in "${TARGETS_RECURSIVE[@]}"
	do
		# Ibid regarding iii.
		jjj="$jj/"

		# Check whether any included dataset is a prefix of the candidate name.
		if [ "$iii" != "${iii#$jjj}" ]
		then
			print_log debug "Excluding $ii because $jj includes it recursively."
			continue 2
		fi
	done

	# Append this candidate to the recursive snapshot list because it:
	#
	#   * Does not have an exclusionary property.
	#   * Is in a pool that can currently do snapshots.
	#   * Is not currently undergoing a receive operation.
	#   * Does not have an excluded descendent filesystem.
	#   * Is not the descendant of an already included filesystem.
	#
	print_log debug "Including $ii for recursive snapshot."
	TARGETS_RECURSIVE+=("$ii")
done

# Only actually set the com.sun:auto-snapshot-desc property if we were
# explicitly given a value to use (which can be ''); otherwise, don't set it.
if [ -n "$opt_event_is_set" ]
then
	SNAPPROP="-o com.sun:auto-snapshot-desc='$opt_event'"
else
	SNAPPROP=""
fi

# The snapshot name after the @ symbol.
SNAPNAME="${opt_prefix:+$opt_prefix$opt_sep}$DATE${opt_label:+$opt_sep$opt_label}"

if [ -n "$opt_do_snapshots" ]
then
	test -n "$TARGETS_REGULAR" \
	  && print_log info "Doing regular snapshots of ${TARGETS_REGULAR[@]}"

	test -n "$TARGETS_RECURSIVE" \
	  && print_log info "Doing recursive snapshots of ${TARGETS_RECURSIVE[@]}"

	if test -n "$opt_keep" && [ "$opt_keep" -ge "1" ]
	then
		print_log info "Destroying all but the newest $opt_keep snapshots of each dataset."
	fi
elif test -n "$opt_keep" && [ "$opt_keep" -ge "1" ]
then
	test -n "$TARGETS_REGULAR" \
	  && print_log info "Destroying all but the newest $opt_keep snapshots of ${TARGETS_REGULAR[@]}"

	test -n "$TARGETS_RECURSIVE" \
	  && print_log info "Recursively destroying all but the newest $opt_keep snapshots of ${TARGETS_RECURSIVE[@]}"
else
	print_log notice "Only destroying snapshots, but count of snapshots to preserve not given. Nothing to do."
fi

test -n "$opt_dry_run" \
  && print_log info "Doing a dry run. Not running these commands..."

t1 DO_SNAPS
do_snapshots "$SNAPPROP" ""   "$SNAPNAME" "${TARGETS_REGULAR[@]}"
t2 DO_SNAPS
print_log notice "time spent doing snapshots (regular): $(dt DO_SNAPS 2)"

t1 DO_SNAPS_R
do_snapshots "$SNAPPROP" "-r" "$SNAPNAME" "${TARGETS_RECURSIVE[@]}"
t2 DO_SNAPS_R
print_log notice "time spent doing snapshots (recursive): $(dt DO_SNAPS_R 2)"

print_log notice "@$SNAPNAME," \
  "$SNAPSHOT_COUNT created," \
  "$DESTRUCTION_COUNT destroyed," \
  "$WARNING_COUNT warnings."

exit 0
# }
