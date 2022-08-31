#!/bin/bash

trap cleanup EXIT

function cleanup() {
    rm scripts/generated-diffcheck.txt
}

diff openssl v2/openssl > scripts/generated-diffcheck.txt

DIFF_OUTPUT=$(diff scripts/generated-diff.txt scripts/generated-diffcheck.txt)
if [ "$DIFF_OUTPUT" ]; then
    echo "Modifications have been made to the generated diff. Please review and update the diff."
    exit 1
fi