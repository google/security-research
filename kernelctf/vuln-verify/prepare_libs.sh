#!/bin/bash
USERLAND=userland
SRC=/mnt/diskimage
LIBDIR=/usr/lib/x86_64-linux-gnu

mkdir -p $USERLAND/lib64/
cp -Lp $SRC/lib/x86_64-linux-gnu/ld-2.31.so $USERLAND/lib64/ld-linux-x86-64.so.2

mkdir -p $USERLAND/usr/bin/
cp -Lp $SRC/usr/bin/objcopy $USERLAND/usr/bin/

rm -rf $USERLAND/$LIBDIR/
mkdir -p $USERLAND/$LIBDIR/
for f in libbfd-2.34-system.so libc.so.6 libz.so.1 libdl.so.2; do
  cp -Lp "$SRC/$LIBDIR/$f" "$USERLAND/$LIBDIR/";
done

mkdir -p $USERLAND/etc/
echo "$LIBDIR" > $USERLAND/etc/ld.so.conf
