#!/bin/sh

function usage {
	local k

	if [ "x$1" != "x" ]; then
		echo "error: $1"
		echo
	fi

	echo "usage: testsuite-dir.sh [-h] [-t<validation-type>] dir"
	echo "  -h                  Display help"
	echo "  -t, --schema-type   Use the schema type provided."

	echo "Run a testsuite on a whole directory"

	echo

	exit 5
}

TYPE=""
TYPE_ARG=""

while true; do
	case "$1" in
		-h ) usage ;;
		-- ) shift; break ;;
		--schema-type | -t )
			TYPE="$2";
			TYPE_ARG="--schema-type=$TYPE"
			shift 2 ;;
		-* ) usage "unknown option '$1'"; break ;;
		* ) break ;;
	esac
done

DIR="$1"

TOOL="${TOP_BUILDDIR}/src/fyjs-tool"
# first count the number of test-cases
count=0
for f in ${DIR}/*.json; do
	this_count=`${TOOL} -q --testsuite --count-tests "$f"`
	if [ "x$this_count" != "x" ]; then
		count=`expr $count + $this_count`
	fi
done

# output plan
echo
echo 1..$count

start=1
for f in ${DIR}/*.json; do
	this_count=`${TOOL} -q --testsuite --count-tests "$f"`
	if [ "x$this_count" = "x" ] ; then
		continue
	fi
	end=`expr $start + $this_count - 1`
	for i in `seq $start $end`; do
		${TOOL} --testsuite ${TYPE_ARG} -q --execute ${i} \
			--tap --tap-start=${start} --tap-plan-disable \
			-r "http://localhost:1234/,test-suite-data/remotes/" "$f"
		if [ $? -ne 0 ]; then
			echo -n "not "
			${TOOL} -q --testsuite --dry-run --execute ${i} \
				--tap --tap-start=${start} --tap-plan-disable \
				-r "http://localhost:1234/,test-suite-data/remotes/" "$f"
		fi
	done
	start=`expr $start + $this_count`
done
