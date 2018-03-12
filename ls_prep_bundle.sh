#!/bin/bash

usage() {
	cat - 1>&2 <<EOF
Usage: $0 <bundle> [ -r <name> ] [ <file> ... ]"

Unzip a zipped bundle of LearningSuite submissions for an assigment, each with
its own directory, named numerically (e.g., "001_...", "002_...", etc.).  Copy
the submission and any other files specified on the command line to the
appropriate directory, e.g., for building, testing, grading, etc.  If the
submitted file ends in tar, tar.gz, or tgz, then the file is also
untarred/gzipped in the new directory.  If the -r option is used, then the copy
of the file in the directory is renamed using the name specified.
EOF
}

RENAME=
while getopts "r:" opt; do
	case $opt in
		r)
			RENAME=$OPTARG
			;;
		*)
			usage
			exit 1
			;;
	esac
done
shift $((OPTIND - 1))

BUNDLE="$1"
if [ "x$BUNDLE" = "x" ]; then
	usage
	exit 1
fi
shift

unzip -q "$BUNDLE" || exit 1
i=0
for f in *; do
	if [ "$f" = "$BUNDLE" ]; then
		continue
	fi
	if [ "$f" = "$0" ]; then
		continue
	fi

	base=""
	if [ "$f" != "${f%.tar.gz}" -o "$f" != "${f%.tgz}" ]; then
		base=`basename "$f" .tar.gz`
		cmd="tar -zxf"
	elif [ "$f" != "${f%.tar}" ]; then
		base=`basename "$f" .tar`
		cmd="tar -xf"
	elif [ "$f" != "${f%.zip}" ]; then
		base=`basename "$f" .zip`
		cmd="unzip -q"
	elif [ "$f" != "${f%.c}" ]; then
		base=`basename "$f" .c`
		cmd="echo"
	else
		if ! echo "$@" | grep -q "\(^\|[[:space:]]\)$f\([[:space:]]\|\$\)"; then
			echo -e "\033[33mWarning\033[0m: Undefined extension $f" 1>&2
		fi
		continue
	fi
	dir="`printf %.3d $i`_$base"
	mkdir "$dir"
	mv "$f" "$dir"
	for (( j=1; $j<=$#; j++ )); do
		cp -p "${!j}" "$dir"
	done
	cd "$dir"
	$cmd "$f"
	if (( $? != 0 )); then
		echo -e "\033[33mError\033[0m: troubling extracting $f" 1>&2
	fi
	if [ "x$RENAME" != "x" ]; then
		mv "$f" "$RENAME"
	fi
	cd ../
	(( i++ ))
done
