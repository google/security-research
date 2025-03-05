RFLAGS=--keep-aspect-ratio

.PHONY: clean

all: $(patsubst %.svg,%.png,$(wildcard *.svg))

# Per-image overrides
patchram.png: RFLAGS+=--width=640

%.png: %.svg
	rsvg-convert $(RFLAGS) --output=$@ $<

clean:
	rm -f $(patsubst %.svg,%.png,$(wildcard *.svg))
