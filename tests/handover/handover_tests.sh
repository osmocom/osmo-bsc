#!/bin/sh
set -e
tests_dir="${1:-.}"
build_dir="${2:-.}"
update="$3"
test -d "$tests_dir"
test -d "$build_dir"

if [ -n "$update" -a "x$update" != "x-u" -a "x$update" != "x-U" ]; then
	echo "unknown argument: $update"
	exit 1
fi

one_test() {
	test_path="$1"
	test_name="$(basename "$test_path")"
	got_out="$(mktemp "tmp.$test_name.stdout.XXXXX")"
	got_err="$(mktemp "tmp.$test_name.stderr.XXXXX")"
	set +e
	"$build_dir"/handover_test "$test_path" > "$got_out" 2> "$got_err"
	rc=$?
	expect_out="$test_path.ok"
	expect_err="$test_path.err"
	if [ "x$rc" = "x0" -a  "x$update" = "x-U" ]; then
		cp "$got_out" "$expect_out"
		cp "$got_err" "$expect_err"
	else
		if [ -f "$expect_out" ]; then
			diff -u "$expect_out" "$got_out" >&2
		fi
		if [ -f "$expect_err" ]; then
			diff -u "$expect_err" "$got_err" >&2
		fi
	fi
	rm "$got_out"
	rm "$got_err"
	set -e
	return $rc
}

results="$(mktemp "tmp.handover_test_results.XXXXX")"
for test_path in "$tests_dir"/test*.ho_vty ; do
	test_name="$(basename "$test_path")"
	if one_test "$test_path"; then
		echo "pass $test_name" >> "$results"
	else
		echo "FAIL $test_name" >> "$results"
	fi
done
set +e
cat "$results"
failed="$(grep FAIL "$results")"
if [ -z "$failed" -a "x$update" != "x" ]; then
	cp "$results" "$tests_dir"/handover_tests.ok
fi
rm "$results"
if [ -n "$failed" ]; then
	echo "tests failed"
	exit 1
fi
exit 0
