#!/bin/sh

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
		${TOOL} --testsuite -q --execute ${i} \
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
