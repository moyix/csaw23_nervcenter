#!/bin/bash

while true; do
    touch /tmp/tamper.txt
    inotifywait -e close_write /tmp/tamper.txt

    # Remove old results
    rm -f /tmp/tamper_d.txt

    echo "Launching attack on:"
    cat /tmp/tamper.txt
    echo
    tmpfile=$(mktemp)
    ../RsaCtfTool/RsaCtfTool.py\
        --timeout 60 \
        --publickey /tmp/tamper.txt \
        --attack composite_key \
        --private 2>&1 | tee "$tmpfile"
    if grep -q SUCCESS "$tmpfile"; then
        echo "Attack succeeded!"
        grep SUCCESS "$tmpfile" | awk '{ print $NF }' > /tmp/tamper_d.txt
        rm -f "$tmpfile"
        break
    else
        echo "Attack did not succeed."
        rm -f "$tmpfile"
    fi
done