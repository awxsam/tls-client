#!/bin/sh

# This build.sh file was created on a OSX host system. If you are running on windows / unix you need to adjust the commands accordingly.

echo 'Build OSX'
GOOS=darwin CGO_ENABLED=1 GOARCH=arm64 go build -buildmode=c-shared -o ./dist/tls-client-arm64.dylib

