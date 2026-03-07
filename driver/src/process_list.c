#include "process_list.h"

VOID
ProcessListInit(
    _Out_ PPROTECTED_LIST List
)
{
    RtlZeroMemory(List, sizeof(*List));
    KeInitializeSpinLock(&List->Lock);
}

NTSTATUS
ProcessListAdd(
    _Inout_ PPROTECTED_LIST List,
    _In_    ULONG           Pid
)
{
    KIRQL    irql;
    NTSTATUS status = STATUS_QUOTA_EXCEEDED;

    KeAcquireSpinLock(&List->Lock, &irql);

    for (ULONG i = 0; i < SENTINEL_MAX_PIDS; i++) {
        if (List->Pids[i] == Pid) {
            status = STATUS_OBJECT_NAME_COLLISION;
            goto release;
        }
    }

    for (ULONG i = 0; i < SENTINEL_MAX_PIDS; i++) {
        if (List->Pids[i] == 0) {
            List->Pids[i] = Pid;
            List->Count++;
            status = STATUS_SUCCESS;
            goto release;
        }
    }

release:
    KeReleaseSpinLock(&List->Lock, irql);
    return status;
}

NTSTATUS
ProcessListRemove(
    _Inout_ PPROTECTED_LIST List,
    _In_    ULONG           Pid
)
{
    KIRQL    irql;
    NTSTATUS status = STATUS_NOT_FOUND;

    KeAcquireSpinLock(&List->Lock, &irql);

    for (ULONG i = 0; i < SENTINEL_MAX_PIDS; i++) {
        if (List->Pids[i] == Pid) {
            List->Pids[i] = 0;
            List->Count--;
            status = STATUS_SUCCESS;
            break;
        }
    }

    KeReleaseSpinLock(&List->Lock, irql);
    return status;
}

BOOLEAN
ProcessListContains(
    _In_ PPROTECTED_LIST List,
    _In_ ULONG           Pid
)
{
    KIRQL   irql;
    BOOLEAN found = FALSE;

    KeAcquireSpinLock(&List->Lock, &irql);

    for (ULONG i = 0; i < SENTINEL_MAX_PIDS; i++) {
        if (List->Pids[i] == Pid) {
            found = TRUE;
            break;
        }
    }

    KeReleaseSpinLock(&List->Lock, irql);
    return found;
}

ULONG
ProcessListSnapshot(
    _In_                              PPROTECTED_LIST List,
    _Out_writes_to_(Capacity, return) PULONG          OutPids,
    _In_                              ULONG           Capacity
)
{
    KIRQL irql;
    ULONG count = 0;

    KeAcquireSpinLock(&List->Lock, &irql);

    for (ULONG i = 0; i < SENTINEL_MAX_PIDS && count < Capacity; i++) {
        if (List->Pids[i] != 0) {
            OutPids[count++] = List->Pids[i];
        }
    }

    KeReleaseSpinLock(&List->Lock, irql);
    return count;
}
