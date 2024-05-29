This is experimental code to test if we can automatically scan for chicken
bits that might avoid a problematic CPU behaviour.

The problem is that setting or unsetting chicken bits often introduces
immediate system instability, so we can't just set them all and see what
happens.

This is sample code for scanning for useful chicken bits, with a list of
known-unstable bits blocked. The theory is we can automatically flip a bit,
check if that changed the behaviour we were interested in, and then flip it
back.

A human would that manually examine the result to see if it's interesting.

This code is intended specifically for CPU research on dedicated test hardware.
