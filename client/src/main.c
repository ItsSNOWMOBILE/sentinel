/*
 * sentinel-client — usermode control utility for the Sentinel driver.
 *
 * Usage:
 *   sentinel-client protect   <pid>
 *   sentinel-client unprotect <pid>
 *   sentinel-client list
 *
 * The driver must be loaded and the symbolic link \\.\Sentinel must be
 * present before any of these commands will succeed.  Run as administrator
 * or from an elevated prompt; CreateFile on a kernel device object requires
 * SeLoadDriverPrivilege-equivalent access only when opening with write rights,
 * which FILE_ANY_ACCESS on the IOCTL definition avoids.
 *
 * Error messages are written to stderr; on success the process exits with 0.
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "..\..\shared\ioctl.h"

/* ── helpers ──────────────────────────────────────────────────────────────── */

static HANDLE
open_device(void)
{
    HANDLE h = CreateFileW(
        L"\\\\.\\Sentinel",
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (h == INVALID_HANDLE_VALUE) {
        fprintf(stderr,
            "error: cannot open \\\\.\\Sentinel (0x%08lX)\n"
            "       Is the driver loaded?  "
            "Try: sc start sentinel\n",
            GetLastError());
    }

    return h;
}

/*
 * Parse a decimal PID from the string pointed to by s.  Returns TRUE and
 * writes to *out_pid on success; prints an error and returns FALSE otherwise.
 */
static BOOL
parse_pid(const char *s, ULONG *out_pid)
{
    char   *end;
    unsigned long v;

    errno = 0;
    v     = strtoul(s, &end, 10);

    if (errno != 0 || end == s || *end != '\0' || v == 0) {
        fprintf(stderr, "error: '%s' is not a valid PID\n", s);
        return FALSE;
    }

    *out_pid = (ULONG)v;
    return TRUE;
}

/* ── sub-commands ─────────────────────────────────────────────────────────── */

static int
cmd_protect(const char *pid_str)
{
    ULONG                 pid;
    SENTINEL_PID_REQUEST  req;
    DWORD                 bytes;
    HANDLE                h;

    if (!parse_pid(pid_str, &pid))
        return 1;

    h = open_device();
    if (h == INVALID_HANDLE_VALUE)
        return 1;

    req.ProcessId = pid;

    if (!DeviceIoControl(h, IOCTL_SENTINEL_PROTECT,
                         &req, sizeof(req),
                         NULL, 0, &bytes, NULL))
    {
        DWORD err = GetLastError();
        if (err == ERROR_ALREADY_EXISTS)
            fprintf(stderr, "notice: PID %lu is already protected\n", pid);
        else if (err == ERROR_NOT_ENOUGH_QUOTA)
            fprintf(stderr,
                "error: protected-process list is full "
                "(%u entries maximum)\n", SENTINEL_MAX_PIDS);
        else
            fprintf(stderr, "error: IOCTL_SENTINEL_PROTECT failed (0x%08lX)\n", err);

        CloseHandle(h);
        return 1;
    }

    printf("protected: PID %lu\n", pid);
    CloseHandle(h);
    return 0;
}

static int
cmd_unprotect(const char *pid_str)
{
    ULONG                 pid;
    SENTINEL_PID_REQUEST  req;
    DWORD                 bytes;
    HANDLE                h;

    if (!parse_pid(pid_str, &pid))
        return 1;

    h = open_device();
    if (h == INVALID_HANDLE_VALUE)
        return 1;

    req.ProcessId = pid;

    if (!DeviceIoControl(h, IOCTL_SENTINEL_UNPROTECT,
                         &req, sizeof(req),
                         NULL, 0, &bytes, NULL))
    {
        DWORD err = GetLastError();
        if (err == ERROR_NOT_FOUND)
            fprintf(stderr, "notice: PID %lu was not protected\n", pid);
        else
            fprintf(stderr,
                "error: IOCTL_SENTINEL_UNPROTECT failed (0x%08lX)\n", err);

        CloseHandle(h);
        return 1;
    }

    printf("unprotected: PID %lu\n", pid);
    CloseHandle(h);
    return 0;
}

static int
cmd_list(void)
{
    SENTINEL_QUERY_RESPONSE  resp;
    DWORD                    bytes;
    HANDLE                   h;
    ULONG                    i;

    h = open_device();
    if (h == INVALID_HANDLE_VALUE)
        return 1;

    if (!DeviceIoControl(h, IOCTL_SENTINEL_QUERY,
                         NULL, 0,
                         &resp, sizeof(resp), &bytes, NULL))
    {
        fprintf(stderr,
            "error: IOCTL_SENTINEL_QUERY failed (0x%08lX)\n",
            GetLastError());
        CloseHandle(h);
        return 1;
    }

    if (resp.Count == 0) {
        printf("no protected processes\n");
    } else {
        printf("%lu protected process%s:\n",
               resp.Count, resp.Count == 1 ? "" : "es");
        for (i = 0; i < resp.Count; i++)
            printf("  %lu\n", resp.ProcessIds[i]);
    }

    CloseHandle(h);
    return 0;
}

/* ── entry point ──────────────────────────────────────────────────────────── */

static void
usage(const char *argv0)
{
    fprintf(stderr,
        "usage:\n"
        "  %s protect   <pid>   add a process to the protected list\n"
        "  %s unprotect <pid>   remove a process from the protected list\n"
        "  %s list              show all currently protected PIDs\n",
        argv0, argv0, argv0);
}

int
main(int argc, char *argv[])
{
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "protect") == 0) {
        if (argc != 3) { usage(argv[0]); return 1; }
        return cmd_protect(argv[2]);
    }

    if (strcmp(argv[1], "unprotect") == 0) {
        if (argc != 3) { usage(argv[0]); return 1; }
        return cmd_unprotect(argv[2]);
    }

    if (strcmp(argv[1], "list") == 0) {
        if (argc != 2) { usage(argv[0]); return 1; }
        return cmd_list();
    }

    fprintf(stderr, "error: unknown command '%s'\n", argv[1]);
    usage(argv[0]);
    return 1;
}
