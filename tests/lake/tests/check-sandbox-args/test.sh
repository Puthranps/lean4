#!/usr/bin/env bash
source ../common.sh

export LAKE_SANDBOX_TEST_PASS=inherited
export LAKE_SANDBOX_TEST_DELETE=deleted
export LAKE_SANDBOX_TEST_SECRET=secret
unset LAKE_SANDBOX_TEST_MISSING

test_run env lean --run Test.lean
