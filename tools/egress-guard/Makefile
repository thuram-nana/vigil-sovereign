# egress_guard — build the loopback-only connect(2)/sendto(2)/sendmsg(2) supervisor.
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
# walked out. `check` is the smoke that the binary actually refuses a non-loopback send AND still
# permits loopback — the two halves of a detector worth trusting.
#
# The first version of this recipe was written as a one-line `python3 -c` with literal \n escapes
# inside a double-quoted shell string, so python received backslash-n and died with a SyntaxError on
# EVERY invocation — it failed against a perfectly working guard, and it never ran the loopback half
# its own comment claimed. Each case is now a separate file-free statement, and both halves are real.
check: $(BIN)
	@set -e; \
	printf 'refusal:  '; \
	./$(BIN) --log /dev/null -- python3 -c 'import socket;\
	 s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM);\
	 print("LEAKED" if s.sendto(b"x",("1.1.1.1",53))>0 else "?")' 2>/dev/null | grep -q LEAKED \
	  && { echo "FAILED — a non-loopback datagram left the host"; exit 1; } \
	  || echo "ok (non-loopback send refused)"; \
	printf 'loopback: '; \
	./$(BIN) --log /dev/null -- python3 -c 'import socket, threading;\
	 srv=socket.socket(); srv.bind(("127.0.0.1",0)); srv.listen(1); p=srv.getsockname()[1];\
	 threading.Thread(target=lambda: srv.accept()[0].sendall(b"hi"), daemon=True).start();\
	 c=socket.create_connection(("127.0.0.1",p),3); print("OK" if c.recv(2)==b"hi" else "BROKEN")' \
	  | grep -q OK \
	  && echo "ok (loopback still works)" \
	  || { echo "FAILED — the guard broke a loopback connection"; exit 1; }

clean:
	rm -f $(BIN)
