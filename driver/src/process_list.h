#pragma once
#include <ntddk.h>
#include "ioctl.h"

/*
 * Fixed-size array of protected PIDs guarded by a spin lock.
 *
 * A spin lock (rather than a FAST_MUTEX or ERESOURCE) is chosen because
 * ProcessListContains is called from the ObCallback pre-operation routine,
 * which can be invoked at APC_LEVEL.  Acquiring a spin lock raises IRQL to
 * DISPATCH_LEVEL and is safe from any IRQL <= DISPATCH_LEVEL.
 *
 * The list is sized at SENTINEL_MAX_PIDS (64).  Slots are reclaimed by
 * zeroing the entry; PID 0 is never a valid Windows process identifier.
 */
typedef struct _PROTECTED_LIST {
    KSPIN_LOCK Lock;
    ULONG      Pids[SENTINEL_MAX_PIDS];
    ULONG      Count;
} PROTECTED_LIST, *PPROTECTED_LIST;

VOID     ProcessListInit(_Out_ PPROTECTED_LIST List);

/* STATUS_OBJECT_NAME_COLLISION — PID already present               */
/* STATUS_QUOTA_EXCEEDED        — list is full                      */
NTSTATUS ProcessListAdd(_Inout_ PPROTECTED_LIST List, _In_ ULONG Pid);

/* STATUS_NOT_FOUND — PID was not in the list                       */
NTSTATUS ProcessListRemove(_Inout_ PPROTECTED_LIST List, _In_ ULONG Pid);

BOOLEAN  ProcessListContains(_In_ PPROTECTED_LIST List, _In_ ULONG Pid);

/* Returns the number of PIDs written into OutPids (up to Capacity). */
ULONG    ProcessListSnapshot(
             _In_                               PPROTECTED_LIST List,
             _Out_writes_to_(Capacity, return)  PULONG          OutPids,
             _In_                               ULONG           Capacity);
