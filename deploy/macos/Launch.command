#!/bin/sh
# Fixed entrypoint for Terminal; never interpolate request data or arguments.
[ "$#" -eq 0 ] || exit 64
exec /usr/local/libexec/op-bridge/op-bridge _serve
