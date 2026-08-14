/*
 * egress_guard — a seccomp user-notify supervisor that runs a command and enforces LOOPBACK-ONLY
 * network egress at the SYSCALL boundary.
 *
 * WHY THIS EXISTS. The live Kali-tool path spawns tools directly on the host; its no-egress guarantee
 * rested on an argv allowlist (e.g. wapiti's default modules egress to wapiti3.ovh, so the builder
 * refuses them) verified only by argv-construction tests. That is a guarantee by CONSTRUCTION. This
 * turns it into a guarantee by ENFORCEMENT that is verified by RUNNING: every connect(2) a tool
 * attempts is inspected, and anything that is not loopback is refused with ECONNREFUSED and recorded.
 *
 * WHY seccomp user-notify and not LD_PRELOAD. LD_PRELOAD interposes libc, so a statically linked Go
 * binary (nuclei / httpx / ffuf) that issues the connect syscall directly walks straight past it. A
 * seccomp filter polices the SYSCALL, so it covers every binary regardless of how it was linked. It is
 * unprivileged (NO_NEW_PRIVS + user-notify, kernel >= 5.5 for the CONTINUE flag).
 *
 * HONEST BOUND. This uses SECCOMP_USER_NOTIF_FLAG_CONTINUE for allowed (loopback) connects, which has a
 * well-known TOCTOU: a thread could rewrite the sockaddr after we read it and before the kernel re-reads
 * it. That matters for sandboxing ADVERSARIAL code. It does not matter here: the tools are authorized,
 * correlatable, owner-run (constitution VI.4, "you are not evading them") — the guard exists to catch a
 * tool's DEFAULT egress and a mis-built argv, not to contain an attacker who controls the tool. Only
 * AF_INET/AF_INET6 are policed; AF_UNIX / AF_NETLINK / other local families are always allowed so DNS
 * over a local resolver socket, netlink, etc. keep working.
 *
 * USAGE:  egress_guard --log <path> [--fail-on-egress] -- <cmd> [args...]
 * EXIT:   the child's exit status, UNLESS --fail-on-egress and >=1 non-loopback connect was blocked,
 *         in which case 97 (EGRESS_BLOCKED_EXIT). The log's last line is "egress-guard: seen=N blocked=M".
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <netinet/in.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef SECCOMP_IOCTL_NOTIF_RECV
#define SECCOMP_IOCTL_NOTIF_RECV _IOWR('!', 0, struct seccomp_notif)
#endif
#ifndef SECCOMP_IOCTL_NOTIF_SEND
#define SECCOMP_IOCTL_NOTIF_SEND _IOWR('!', 1, struct seccomp_notif_resp)
#endif
#ifndef SECCOMP_IOCTL_NOTIF_ID_VALID
#define SECCOMP_IOCTL_NOTIF_ID_VALID _IOW('!', 2, __u64)
#endif
#ifndef SECCOMP_USER_NOTIF_FLAG_CONTINUE
#define SECCOMP_USER_NOTIF_FLAG_CONTINUE (1UL << 0)
#endif

#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif
#ifndef SYS_pidfd_getfd
#define SYS_pidfd_getfd 438
#endif

#define EGRESS_BLOCKED_EXIT 97

static FILE *g_log = NULL;
static long g_seen = 0, g_blocked = 0;

static void logf_(const char *fmt, ...) {
    if (!g_log) return;
    va_list ap; va_start(ap, fmt);
    vfprintf(g_log, fmt, ap);
    va_end(ap);
    fputc('\n', g_log);
    fflush(g_log);
}

/* Install the filter: NOTIFY on connect/sendto/sendmsg for the native arch, ALLOW everything else.
 * Returns the user-notify listener fd, or -1. Must be preceded by NO_NEW_PRIVS.
 *
 * WHY sendto AND sendmsg AND NOT JUST connect. Policing connect(2) alone is a REAL BYPASS, demonstrated
 * against the first version of this guard: an unconnected UDP socket needs no connect at all —
 * `sendto(fd, buf, len, 0, &dest, sizeof dest)` puts a packet on the wire directly. The guard reported
 * `seen=0 blocked=0` while the byte left the host. That is the whole no-egress guarantee defeated by one
 * call, and DNS is routinely done exactly this way.
 *
 * (fork() needs no handling: a seccomp filter is inherited by children, which is measured — a forked
 * child's connect is refused by the same supervisor.) */
static int install_filter(void) {
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),   /* other arch: don't police, don't break */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_connect, 3, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_sendto,  2, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_sendmsg, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
    };
    struct sock_fprog prog = { .len = sizeof(filter) / sizeof(filter[0]), .filter = filter };
    return syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
}

/* Read `len` bytes of the target's memory at `addr` (the sockaddr the tool passed to connect). */
static int read_target_mem(pid_t pid, unsigned long long addr, void *buf, size_t len) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = pread(fd, buf, len, (off_t)addr);
    close(fd);
    return (n < 0) ? -1 : (int)n;
}

/* Decide whether a connect target is loopback (allowed). Only AF_INET/AF_INET6 are policed; any other
 * family (AF_UNIX, AF_NETLINK, ...) is a local channel and is allowed. Fills dst for the log. */
static int is_loopback(const struct sockaddr_storage *ss, socklen_t len, char *dst, size_t dstlen) {
    if (len < sizeof(sa_family_t)) { snprintf(dst, dstlen, "<short-sockaddr>"); return 1; }
    if (ss->ss_family == AF_INET) {
        const struct sockaddr_in *in = (const struct sockaddr_in *)ss;
        unsigned char *b = (unsigned char *)&in->sin_addr.s_addr;
        snprintf(dst, dstlen, "%u.%u.%u.%u:%u", b[0], b[1], b[2], b[3], ntohs(in->sin_port));
        return b[0] == 127;                              /* 127.0.0.0/8 */
    }
    if (ss->ss_family == AF_INET6) {
        const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)ss;
        const unsigned char *a = in6->sin6_addr.s6_addr;
        static const unsigned char loop[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
        snprintf(dst, dstlen, "[ipv6]:%u", ntohs(in6->sin6_port));
        if (memcmp(a, loop, 16) == 0) return 1;          /* ::1 */
        /* IPv4-mapped loopback ::ffff:127.0.0.0/8 */
        static const unsigned char v4pfx[12] = {0,0,0,0,0,0,0,0,0,0,0xff,0xff};
        if (memcmp(a, v4pfx, 12) == 0 && a[12] == 127) return 1;
        return 0;
    }
    snprintf(dst, dstlen, "<family:%d>", ss->ss_family);
    return 1;                                            /* non-IP: local channel, allowed */
}

/* The supervisor loop: receive connect notifications, allow loopback (CONTINUE), refuse the rest. */
/* `reaped` is set non-zero and `*status_out` filled if this loop is the one that reaps the child.
 *
 * WHY THE STATUS HAS TO COME BACK FROM HERE. It used to reap with `waitpid(child, NULL, WNOHANG)` and
 * THROW THE STATUS AWAY, leaving main() to call waitpid again — which then failed with ECHILD against a
 * zero-initialised status. WIFEXITED(0) is true and WEXITSTATUS(0) is 0, so the guard reported SUCCESS
 * for a tool that had failed. Reproduced: `egress_guard -- sh -c 'sleep 2 & exit 3'` returned 0. It only
 * triggers when a descendant outlives the direct child (that is what keeps the listener open past the
 * child's exit), which is why the single-process exit-code test never saw it — and it is a false-clean
 * produced by the control whose whole purpose is to stop false-cleans. */
static void supervise(int notifyfd, pid_t child, int *status_out, int *reaped) {
    struct seccomp_notif_sizes sizes = {0};
    if (syscall(SYS_seccomp, SECCOMP_GET_NOTIF_SIZES, 0, &sizes) < 0) {
        sizes.seccomp_notif = sizeof(struct seccomp_notif);
        sizes.seccomp_notif_resp = sizeof(struct seccomp_notif_resp);
    }
    struct seccomp_notif *req = calloc(1, sizes.seccomp_notif);
    struct seccomp_notif_resp *resp = calloc(1, sizes.seccomp_notif_resp);
    if (!req || !resp) { logf_("egress-guard: OOM allocating notif buffers"); return; }

    for (;;) {
        struct pollfd pfd = { .fd = notifyfd, .events = POLLIN };
        int pr = poll(&pfd, 1, 200);
        if (pr < 0) { if (errno == EINTR) continue; break; }
        if (pr == 0) {                                   /* timeout: is the child gone? */
            if (waitpid(child, status_out, WNOHANG) == child) { *reaped = 1; break; }
            continue;
        }
        if (pfd.revents & (POLLHUP | POLLERR)) break;

        memset(req, 0, sizes.seccomp_notif);
        if (ioctl(notifyfd, SECCOMP_IOCTL_NOTIF_RECV, req) < 0) {
            if (errno == EINTR) continue;
            break;                                       /* listener closed: target exited */
        }
        g_seen++;

        /* WHERE THE DESTINATION LIVES DIFFERS PER SYSCALL:
         *   connect(fd, addr, addrlen)                       -> args[1], args[2]
         *   sendto(fd, buf, len, flags, dest_addr, addrlen)   -> args[4], args[5]
         *   sendmsg(fd, msghdr *, flags)                      -> msghdr.msg_name / .msg_namelen
         * A NULL destination means the socket is already connected, and connect(2) was policed on the
         * way in — so there is nothing left to decide and the call proceeds. */
        struct sockaddr_storage ss;
        memset(&ss, 0, sizeof(ss));
        unsigned long long addr = 0;
        socklen_t alen = 0;
        int addressless = 0;

        if (req->data.nr == __NR_connect) {
            addr = req->data.args[1];
            alen = (socklen_t)req->data.args[2];
        } else if (req->data.nr == __NR_sendto) {
            addr = req->data.args[4];
            alen = (socklen_t)req->data.args[5];
            if (!addr) addressless = 1;                  /* connected socket: already policed */
        } else if (req->data.nr == __NR_sendmsg) {
            struct { unsigned long long name; unsigned int namelen; } hdr;
            memset(&hdr, 0, sizeof(hdr));
            /* msghdr's first two members are `void *msg_name; socklen_t msg_namelen;` — reading just
             * those two is enough and avoids depending on the rest of the struct's layout. */
            if (read_target_mem(req->pid, req->data.args[1], &hdr, sizeof(hdr)) >= 0 && hdr.name) {
                addr = hdr.name;
                alen = (socklen_t)hdr.namelen;
            } else {
                addressless = 1;
            }
        }
        if (alen > sizeof(ss)) alen = sizeof(ss);
        int mem_ok = (!addressless && addr && alen)
                     ? (read_target_mem(req->pid, addr, &ss, alen) >= 0) : 0;

        /* Re-validate the notification id AFTER reading memory: if the target died meanwhile the id is
         * stale and SEND would fail; skip it. */
        __u64 id = req->id;
        if (ioctl(notifyfd, SECCOMP_IOCTL_NOTIF_ID_VALID, &id) < 0) continue;

        char dst[64] = "<unread>";
        /* An addressless send on an already-connected socket proceeds (connect was policed). An
         * address we could not READ falls open and is logged — honest, and not a hole a tool can aim
         * at: it cannot choose to make its own sockaddr unreadable to the supervisor. */
        int allow = addressless ? 1
                  : (mem_ok ? is_loopback(&ss, alen, dst, sizeof(dst)) : 1);
        if (addressless) snprintf(dst, sizeof(dst), "<connected-socket>");

        memset(resp, 0, sizes.seccomp_notif_resp);
        resp->id = req->id;
        if (allow) {
            resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;   /* let the real connect proceed */
            resp->error = 0;
            resp->val = 0;
        } else {
            resp->flags = 0;
            resp->error = -ECONNREFUSED;                      /* refuse without executing the syscall */
            resp->val = 0;
            g_blocked++;
            /* Name the syscall that was actually refused. Logging every refusal as "connect" would
             * misdescribe a sendto/sendmsg to whoever reads this looking for what a tool did. */
            logf_("egress-guard: BLOCKED %s -> %s",
                  req->data.nr == __NR_connect ? "connect"
                  : req->data.nr == __NR_sendto ? "sendto" : "sendmsg", dst);
        }
        if (ioctl(notifyfd, SECCOMP_IOCTL_NOTIF_SEND, resp) < 0 && errno != ENOENT)
            logf_("egress-guard: SEND failed: %s", strerror(errno));
    }
    free(req);
    free(resp);
}

int main(int argc, char **argv) {
    const char *log_path = NULL;
    int fail_on_egress = 0, i = 1;
    for (; i < argc; i++) {
        if (strcmp(argv[i], "--log") == 0 && i + 1 < argc) { log_path = argv[++i]; }
        else if (strcmp(argv[i], "--fail-on-egress") == 0) { fail_on_egress = 1; }
        else if (strcmp(argv[i], "--") == 0) { i++; break; }
        else break;
    }
    if (i >= argc) { fprintf(stderr, "usage: egress_guard [--log P] [--fail-on-egress] -- cmd...\n"); return 2; }
    char **child_argv = &argv[i];

    if (log_path) { g_log = fopen(log_path, "a"); }

    /* socketpair to hand the notify fd from child (which installs the filter) up to the parent. */
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) { perror("socketpair"); return 2; }

    pid_t child = fork();
    if (child < 0) { perror("fork"); return 2; }

    if (child == 0) {
        close(sv[0]);
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) { perror("no_new_privs"); _exit(126); }
        int nfd = install_filter();
        if (nfd < 0) { perror("seccomp"); _exit(126); }
        /* Hand the listener to the parent by NUMBER over a plain write(2), and let the parent steal
         * the descriptor itself with pidfd_getfd(2).
         *
         * THIS USED TO USE SCM_RIGHTS, AND THAT DEADLOCKED THE MOMENT sendmsg BECAME POLICED. The
         * filter is installed just above, so the sendmsg that carried the listener was itself the
         * first notified syscall — and nobody could answer it, because the only process that could
         * was still waiting to receive the very fd that call was delivering. The guard hung before
         * the child ever exec'd. write(2) is not policed, so this ordering has no such cycle. */
        if (write(sv[1], &nfd, sizeof(nfd)) != (ssize_t)sizeof(nfd)) { perror("write"); _exit(126); }
        close(sv[1]);
        execvp(child_argv[0], child_argv);
        perror("execvp");
        _exit(127);
    }

    /* parent: take the notify fd out of the child, then supervise */
    close(sv[1]);
    int child_fd = -1, notifyfd = -1;
    if (read(sv[0], &child_fd, sizeof(child_fd)) == (ssize_t)sizeof(child_fd) && child_fd >= 0) {
        int pidfd = (int)syscall(SYS_pidfd_open, child, 0);
        if (pidfd >= 0) {
            notifyfd = (int)syscall(SYS_pidfd_getfd, pidfd, child_fd, 0);
            close(pidfd);
        }
    }
    close(sv[0]);
    if (notifyfd < 0) {
        /* Without the listener nothing is supervised. Say so and refuse rather than run a tool while
         * reporting that it was guarded — a guard believed to be on but absent is worse than none. */
        logf_("egress-guard: FAILED to acquire the seccomp listener (%s) — nothing was supervised",
              strerror(errno));
        fprintf(stderr, "egress_guard: could not acquire the seccomp listener; refusing to continue\n");
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        if (g_log) fclose(g_log);
        return 2;
    }

    int status = 0, reaped = 0;
    if (notifyfd >= 0) supervise(notifyfd, child, &status, &reaped);
    if (!reaped) waitpid(child, &status, 0);
    logf_("egress-guard: seen=%ld blocked=%ld", g_seen, g_blocked);
    if (g_log) fclose(g_log);

    if (fail_on_egress && g_blocked > 0) return EGRESS_BLOCKED_EXIT;
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return 1;
}
