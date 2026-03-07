/*
 * ioctl.h — IOCTL codes and request/response types shared between the
 *            kernel driver and the usermode client.
 *
 * Include after the relevant system header:
 *   kernel : #include <ntddk.h>
 *   usermode: #include <Windows.h>
 */
#pragma once

#define SENTINEL_DEVICE_WIN32   L"\\\\.\\Sentinel"
#define SENTINEL_MAX_PIDS       64

/*
 * Function codes 0x800–0xFFF are reserved for vendor use (bit 11 set).
 * METHOD_BUFFERED is used throughout: the I/O manager copies the caller's
 * buffer into kernel memory before the dispatch routine runs, and copies
 * the output buffer back on completion — no need to probe/lock user pages.
 */
#define IOCTL_SENTINEL_PROTECT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_SENTINEL_UNPROTECT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_SENTINEL_QUERY \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

#pragma pack(push, 1)

typedef struct _SENTINEL_PID_REQUEST {
    ULONG ProcessId;
} SENTINEL_PID_REQUEST, *PSENTINEL_PID_REQUEST;

typedef struct _SENTINEL_QUERY_RESPONSE {
    ULONG Count;
    ULONG ProcessIds[SENTINEL_MAX_PIDS];
} SENTINEL_QUERY_RESPONSE, *PSENTINEL_QUERY_RESPONSE;

#pragma pack(pop)
