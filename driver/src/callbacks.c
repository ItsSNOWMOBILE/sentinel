#include "callbacks.h"
#include "driver.h"
#include "process_list.h"

/*
 * Access rights stripped from handles opened to a protected process by any
 * caller other than the process itself.
 */
#define SENTINEL_DENIED_PROCESS_ACCESS (        \
    PROCESS_TERMINATE       |   /* TerminateProcess                     */  \
    PROCESS_VM_WRITE        |   /* WriteProcessMemory                   */  \
    PROCESS_VM_READ         |   /* ReadProcessMemory                    */  \
    PROCESS_VM_OPERATION    |   /* VirtualAllocEx / VirtualFreeEx       */  \
    PROCESS_CREATE_THREAD   |   /* CreateRemoteThread                   */  \
    PROCESS_DUP_HANDLE      |   /* DuplicateHandle                      */  \
    PROCESS_SUSPEND_RESUME      /* NtSuspendProcess / NtResumeProcess   */  \
)

/*
 * Access rights stripped from handles opened to threads that belong to a
 * protected process.
 */
#define SENTINEL_DENIED_THREAD_ACCESS (         \
    THREAD_TERMINATE        |   /* TerminateThread                      */  \
    THREAD_SUSPEND_RESUME   |   /* SuspendThread / ResumeThread         */  \
    THREAD_SET_CONTEXT          /* SetThreadContext (classic injection)  */  \
)

/* ── ObRegisterCallbacks ──────────────────────────────────────────────────── */

static PVOID g_ObHandle = NULL;

static OB_PREOP_CALLBACK_STATUS
PreOpCallback(
    _In_    PVOID                         RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION Info
)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    /* Kernel-originated handles are trusted; never touch them. */
    if (Info->KernelHandle)
        return OB_PREOP_SUCCESS;

    ULONG callerPid = HandleToUlong(PsGetCurrentProcessId());

    if (Info->ObjectType == *PsProcessType) {

        ULONG targetPid = HandleToUlong(PsGetProcessId((PEPROCESS)Info->Object));

        if (!ProcessListContains(&g_ProtectedList, targetPid) ||
            callerPid == targetPid)
            return OB_PREOP_SUCCESS;

        if (Info->Operation == OB_OPERATION_HANDLE_CREATE) {
            Info->Parameters->CreateHandleInformation.DesiredAccess
                &= ~SENTINEL_DENIED_PROCESS_ACCESS;
        } else {
            Info->Parameters->DuplicateHandleInformation.DesiredAccess
                &= ~SENTINEL_DENIED_PROCESS_ACCESS;
        }

    } else if (Info->ObjectType == *PsThreadType) {

        ULONG ownerPid = HandleToUlong(
            PsGetThreadProcessId((PETHREAD)Info->Object));

        if (!ProcessListContains(&g_ProtectedList, ownerPid) ||
            callerPid == ownerPid)
            return OB_PREOP_SUCCESS;

        if (Info->Operation == OB_OPERATION_HANDLE_CREATE) {
            Info->Parameters->CreateHandleInformation.DesiredAccess
                &= ~SENTINEL_DENIED_THREAD_ACCESS;
        } else {
            Info->Parameters->DuplicateHandleInformation.DesiredAccess
                &= ~SENTINEL_DENIED_THREAD_ACCESS;
        }
    }

    return OB_PREOP_SUCCESS;
}

NTSTATUS
CallbacksRegisterObCallbacks(VOID)
{
    OB_OPERATION_REGISTRATION ops[2] = {
        {
            PsProcessType,
            OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE,
            PreOpCallback,
            NULL
        },
        {
            PsThreadType,
            OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE,
            PreOpCallback,
            NULL
        }
    };

    OB_CALLBACK_REGISTRATION reg = {
        OB_FLT_REGISTRATION_VERSION,
        2,
        RTL_CONSTANT_STRING(L"321000"),
        NULL,
        ops
    };

    return ObRegisterCallbacks(&reg, &g_ObHandle);
}

VOID
CallbacksUnregisterObCallbacks(VOID)
{
    if (g_ObHandle) {
        ObUnRegisterCallbacks(g_ObHandle);
        g_ObHandle = NULL;
    }
}

/* ── Process creation/exit notifications ─────────────────────────────────── */

static VOID
ProcessNotify(
    _In_     PEPROCESS              Process,
    _In_     HANDLE                 ProcessId,
    _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
    UNREFERENCED_PARAMETER(Process);

    /* CreateInfo != NULL → creation; we only act on exit. */
    if (CreateInfo != NULL)
        return;

    ULONG pid = HandleToUlong(ProcessId);
    if (ProcessListRemove(&g_ProtectedList, pid) == STATUS_SUCCESS)
        KdPrint(("[Sentinel] pid %lu exited, removed from protected list\n", pid));
}

NTSTATUS
CallbacksRegisterProcessNotify(VOID)
{
    return PsSetCreateProcessNotifyRoutineEx(ProcessNotify, FALSE);
}

VOID
CallbacksUnregisterProcessNotify(VOID)
{
    PsSetCreateProcessNotifyRoutineEx(ProcessNotify, TRUE);
}

/* ── Thread creation notifications ───────────────────────────────────────── */

static VOID
ThreadNotify(
    _In_ HANDLE  ProcessId,
    _In_ HANDLE  ThreadId,
    _In_ BOOLEAN Create
)
{
    UNREFERENCED_PARAMETER(ThreadId);

    if (!Create)
        return;

    ULONG targetPid = HandleToUlong(ProcessId);
    ULONG callerPid = HandleToUlong(PsGetCurrentProcessId());

    /*
     * If a thread is being created inside a protected process by a different
     * process, log it.  Actual prevention relies on PROCESS_CREATE_THREAD
     * having been stripped from the caller's handle by the ObCallback.
     */
    if (ProcessListContains(&g_ProtectedList, targetPid) &&
        callerPid != targetPid)
    {
        KdPrint(("[Sentinel] remote thread creation into pid %lu from pid %lu"
                 " (handle rights stripped)\n", targetPid, callerPid));
    }
}

NTSTATUS
CallbacksRegisterThreadNotify(VOID)
{
    return PsSetCreateThreadNotifyRoutine(ThreadNotify);
}

VOID
CallbacksUnregisterThreadNotify(VOID)
{
    PsRemoveCreateThreadNotifyRoutine(ThreadNotify);
}
