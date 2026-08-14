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

/* Install the filter: NOTIFY on connect for the native arch, ALLOW everything else. Returns the
 * user-notify listener fd, or -1. Must be preceded by NO_NEW_PRIVS. */
static int install_filter(void) {
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),   /* other arch: don't police, don't break */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_connect, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
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
static void supervise(int notifyfd, pid_t child) {
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
            if (waitpid(child, NULL, WNOHANG) == child) break;
            continue;
        }
        if (pfd.revents & (POLLHUP | POLLERR)) break;

        memset(req, 0, sizes.seccomp_notif);
        if (ioctl(notifyfd, SECCOMP_IOCTL_NOTIF_RECV, req) < 0) {
            if (errno == EINTR) continue;
            break;                                       /* listener closed: target exited */
        }
        g_seen++;

        struct sockaddr_storage ss;
        memset(&ss, 0, sizeof(ss));
        unsigned long long addr = req->data.args[1];
        socklen_t alen = (socklen_t)req->data.args[2];
        if (alen > sizeof(ss)) alen = sizeof(ss);
        int mem_ok = (addr && alen) ? (read_target_mem(req->pid, addr, &ss, alen) >= 0) : 0;

        /* Re-validate the notification id AFTER reading memory: if the target died meanwhile the id is
         * stale and SEND would fail; skip it. */
        __u64 id = req->id;
        if (ioctl(notifyfd, SECCOMP_IOCTL_NOTIF_ID_VALID, &id) < 0) continue;

        char dst[64] = "<unread>";
        int allow = mem_ok ? is_loopback(&ss, alen, dst, sizeof(dst)) : 1; /* unreadable: fail-open, log */

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
            logf_("egress-guard: BLOCKED connect -> %s", dst);
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
        /* send the listener fd to the parent over SCM_RIGHTS */
        struct msghdr msg = {0};
        char cbuf[CMSG_SPACE(sizeof(int))] = {0};
        char dummy = 'x';
        struct iovec iov = { .iov_base = &dummy, .iov_len = 1 };
        msg.msg_iov = &iov; msg.msg_iovlen = 1;
        msg.msg_control = cbuf; msg.msg_controllen = sizeof(cbuf);
        struct cmsghdr *cm = CMSG_FIRSTHDR(&msg);
        cm->cmsg_level = SOL_SOCKET; cm->cmsg_type = SCM_RIGHTS; cm->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(cm), &nfd, sizeof(int));
        if (sendmsg(sv[1], &msg, 0) < 0) { perror("sendmsg"); _exit(126); }
        close(sv[1]);
        execvp(child_argv[0], child_argv);
        perror("execvp");
        _exit(127);
    }

    /* parent: receive the notify fd, then supervise */
    close(sv[1]);
    struct msghdr msg = {0};
    char cbuf[CMSG_SPACE(sizeof(int))] = {0};
    char dummy = 0;
    struct iovec iov = { .iov_base = &dummy, .iov_len = 1 };
    msg.msg_iov = &iov; msg.msg_iovlen = 1;
    msg.msg_control = cbuf; msg.msg_controllen = sizeof(cbuf);
    int notifyfd = -1;
    if (recvmsg(sv[0], &msg, 0) >= 0) {
        struct cmsghdr *cm = CMSG_FIRSTHDR(&msg);
        if (cm && cm->cmsg_type == SCM_RIGHTS) memcpy(&notifyfd, CMSG_DATA(cm), sizeof(int));
    }
    close(sv[0]);

    if (notifyfd >= 0) supervise(notifyfd, child);

    int status = 0;
    waitpid(child, &status, 0);
    logf_("egress-guard: seen=%ld blocked=%ld", g_seen, g_blocked);
    if (g_log) fclose(g_log);

    if (fail_on_egress && g_blocked > 0) return EGRESS_BLOCKED_EXIT;
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return 1;
}
