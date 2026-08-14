# egress_guard — build the loopback-only connect(2) supervisor.
#
# No external dependency: raw seccomp BPF + the kernel uapi headers, so there is no libseccomp to
# install and nothing to pin. `make` here is the whole build.
CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -Wno-unused-parameter
BIN     := egress_guard

.PHONY: all clean check

all: $(BIN)

$(BIN): egress_guard.c
	$(CC) $(CFLAGS) -o $@ $<

# A build that cannot block egress is worse than no build: it would report "guarded" while a tool
# walked out. `check` is the smoke that the binary actually refuses a non-loopback connect AND still
# permits loopback — the two halves of a detector that is worth trusting.
check: $(BIN)
	@set -e; \
	./$(BIN) --log /dev/stdout -- python3 -c \
	  "import socket;\ntry: socket.create_connection(('1.1.1.1',80),3)\nexcept Exception: pass" \
	  | grep -q "BLOCKED connect -> 1.1.1.1:80" \
	  && echo "check: blocks non-loopback  OK" || { echo "check: FAILED to block egress"; exit 1; }

clean:
	rm -f $(BIN)
