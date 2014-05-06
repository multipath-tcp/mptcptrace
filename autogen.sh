#!/bin/sh

[ ! -d "m4" ] && mkdir m4

autoreconf --install || exit 1

./configure $@
