#!/bin/bash

BITS=6
CODING="c2"

source_file="test-files/$1"
archive="test-files/output.bin"
decoded="test-files/decoded.txt"

echo -n "Encoding..."
time ./encode $BITS $CODING $source_file

echo -n "Decoding..."
time ./decode $archive

echo "Original: "
ls -l $source_file
sha256sum $source_file
echo "Decoded: "
ls -l $decoded
sha256sum $decoded
echo "Archive: "
ls -l $archive