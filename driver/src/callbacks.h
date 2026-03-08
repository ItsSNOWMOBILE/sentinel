#pragma once
#include <ntddk.h>

/*
 * ObRegisterCallbacks — strips dangerous access rights from handles opened
 * or duplicated against protected processes and their threads.
 *
 * Requires IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY (/INTEGRITYCHECK) and,
 * on production machines, a Microsoft-signed binary.  On test machines with
 * bcdedit /set testsigning on, a self-signed test certificate is sufficient.
 */
NTSTATUS CallbacksRegisterObCallbacks(VOID);
VOID     CallbacksUnregisterObCallbacks(VOID);

/*
 * PsSetCreateProcessNotifyRoutineEx — removes a PID from the protected list
 * when the process exits, so stale entries never accumulate.
 *
 * Requires IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY.
 */
NTSTATUS CallbacksRegisterProcessNotify(VOID);
VOID     CallbacksUnregisterProcessNotify(VOID);

/*
 * PsSetCreateThreadNotifyRoutine — logs remote thread creation attempts into
 * protected processes via KdPrint / WinDbg.
 *
 * Note: this callback fires after the thread is created.  It cannot block
 * the creation; actual enforcement relies on the THREAD_CREATE access right
 * being stripped from process handles by the ObCallback above.
 */
NTSTATUS CallbacksRegisterThreadNotify(VOID);
VOID     CallbacksUnregisterThreadNotify(VOID);
