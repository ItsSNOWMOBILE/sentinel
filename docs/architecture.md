# Architecture

## Overview

Sentinel is a Windows kernel driver that prevents a set of user-nominated
processes from being tampered with by other user-mode processes.  Protection
is enforced entirely at the kernel level; a process cannot opt out once
another process has placed its PID in the protected list.

```
 ┌─────────────────────┐     IOCTL      ┌─────────────────────────────────┐
 │  sentinel-client    │ ─────────────▶ │         sentinel.sys            │
 │  (user mode)        │                │                                 │
 └─────────────────────┘                │  ┌──────────────────────────┐   │
                                        │  │  PROTECTED_LIST           │   │
  protect <pid>  ───────────────────────┼─▶│  (KSPIN_LOCK-guarded     │   │
  unprotect <pid>────────────────────── ┼─▶│   array of ULONG PIDs)   │   │
  list           ───────────────────────┼─▶│                          │   │
                                        │  └──────────┬───────────────┘   │
                                        │             │                    │
                                        │  ┌──────────▼───────────────┐   │
                                        │  │  ObRegisterCallbacks     │   │
                                        │  │  (pre-op, handle create  │   │
                                        │  │   and duplicate)         │   │
                                        │  └──────────────────────────┘   │
                                        │                                 │
                                        │  ┌──────────────────────────┐   │
                                        │  │  PsSetCreateProcess-     │   │
                                        │  │  NotifyRoutineEx         │   │
                                        │  │  (auto-expire on exit)   │   │
                                        │  └──────────────────────────┘   │
                                        │                                 │
                                        │  ┌──────────────────────────┐   │
                                        │  │  PsSetCreateThread-      │   │
                                        │  │  NotifyRoutine           │   │
                                        │  │  (log injection attempts)│   │
                                        │  └──────────────────────────┘   │
                                        └─────────────────────────────────┘
```

## Threat model

**Protected:**

| Attack                          | Mechanism used         |
|---------------------------------|------------------------|
| `TerminateProcess`              | Strip `PROCESS_TERMINATE` from the handle at open/duplicate time via `ObRegisterCallbacks` |
| `WriteProcessMemory`            | Strip `PROCESS_VM_WRITE` + `PROCESS_VM_OPERATION` |
| `ReadProcessMemory`             | Strip `PROCESS_VM_READ` |
| `VirtualAllocEx` / `VirtualFreeEx` | Strip `PROCESS_VM_OPERATION` |
| `CreateRemoteThread`            | Strip `PROCESS_CREATE_THREAD` from the *process* handle; `THREAD_SET_CONTEXT` from the *thread* handle |
| `DuplicateHandle` exfiltration  | Both `OB_OPERATION_HANDLE_CREATE` and `OB_OPERATION_HANDLE_DUPLICATE` are hooked |
| `NtSuspendProcess`              | Strip `PROCESS_SUSPEND_RESUME` |
| Thread hijack (`SetThreadContext`) | Strip `THREAD_SET_CONTEXT` |
| Stale list entry after crash    | `PsSetCreateProcessNotifyRoutineEx` removes the PID when the process exits |

**Not protected (known limitations):**

- **Kernel-mode callers** — handles opened from kernel mode (`KernelHandle == TRUE`)
  are never touched.  Another kernel driver loaded by an administrator can bypass
  all protections.  This is an inherent limitation of the Windows security model;
  Sentinel is not a rootkit detector.

- **Handle inheritance** — a process may inherit a handle with full rights from
  its parent before Sentinel's callback is registered or before the PID is added
  to the protected list.  Protect processes at launch or immediately after.

- **Re-opening with lower rights first** — the callback strips rights from the
  *requested* access.  If a caller deliberately opens with fewer rights than those
  stripped, the resulting handle retains those lower rights.  This is the correct
  SSDT behaviour; it is not a bug.

- **Privileged callers (`SeDebugPrivilege`)** — the kernel may grant additional
  access rights to callers holding `SeDebugPrivilege` before the ObCallback fires.
  The callback strips rights from whatever the kernel decided to grant, so a
  `SeDebugPrivilege` caller still loses the dangerous rights.  However, a sufficiently
  privileged process that *already* holds a handle opened before protection was
  enabled is unaffected.

- **PROCESS_QUERY_INFORMATION / PROCESS_QUERY_LIMITED_INFORMATION** — intentionally
  not stripped.  Diagnostic tools (Task Manager, Process Explorer) query process
  information without posing a tamper risk.

## Component breakdown

### `shared/ioctl.h`

Definitions shared by the driver and the client without duplication.
Three `CTL_CODE`-defined IOCTL codes, two request/response structures,
and the `SENTINEL_MAX_PIDS` capacity constant (64).  Using `METHOD_BUFFERED`
keeps the device code simple: the I/O Manager copies the input buffer to
kernel space before the handler runs and copies the output buffer back
afterwards.

### `driver/src/process_list.c`

A fixed-size array of `ULONG` PIDs protected by a `KSPIN_LOCK`.
`KSPIN_LOCK` was chosen over `ERESOURCE` or `FAST_MUTEX` because
`ObRegisterCallbacks` pre-operation callbacks can be invoked at
`APC_LEVEL`, and `FAST_MUTEX` / `ERESOURCE` require `IRQL < APC_LEVEL`.
The lock is acquired at `DISPATCH_LEVEL` for writes and at the same level
for reads, which is safe from any IRQL at or below `DISPATCH_LEVEL`.

### `driver/src/device.c`

Creates the named device object (`\Device\Sentinel`) and a DOS symbolic
link (`\DosDevices\Sentinel`, i.e., `\\.\Sentinel`).  `DO_BUFFERED_IO`
is set on the device object so the I/O Manager handles buffer marshalling.
`IRP_MJ_CREATE` and `IRP_MJ_CLOSE` complete trivially; `IRP_MJ_DEVICE_CONTROL`
dispatches the three IOCTL codes.

### `driver/src/callbacks.c`

**ObRegisterCallbacks** (`PreOpCallback`):

The callback receives a `POB_PRE_OPERATION_INFORMATION` that describes the
handle operation in flight.  For process handles it checks whether the target
PID is in the protected list.  For thread handles it checks the owning process.
Kernel handles and self-handles (caller PID == target PID) are let through
unconditionally.  Dangerous rights are cleared with a bitwise AND of the
inverse mask.

**PsSetCreateProcessNotifyRoutineEx** (`ProcessNotify`):

Called on both process creation and exit.  The callback ignores creation events
(`CreateInfo != NULL`) and removes the PID from the protected list on exit.
This prevents a PID from being recycled by a new, unrelated process that happens
to receive the same numeric identifier.

**PsSetCreateThreadNotifyRoutine** (`ThreadNotify`):

Called after thread creation.  Cannot veto creation; it is used solely for
logging (via `KdPrint`) when a thread is created inside a protected process by
an external caller.  Actual prevention relies on `PROCESS_CREATE_THREAD` having
been stripped by the ObCallback before the `CreateRemoteThread` call was issued.

### `client/src/main.c`

Thin Win32 console application.  Opens the device with `CreateFile`, issues
`DeviceIoControl`, and maps Win32 error codes returned by the I/O Manager to
human-readable messages.  The `protect` and `unprotect` commands accept a
decimal PID; `list` takes no argument.

## Data flow: protecting a process

```
sentinel-client protect 1234
  │
  ├─ CreateFile("\\\\.\\Sentinel") → HANDLE h
  │
  ├─ DeviceIoControl(h, IOCTL_SENTINEL_PROTECT, &{.ProcessId=1234}, ...)
  │    │
  │    └─ IRP_MJ_DEVICE_CONTROL → DispatchIoctl()
  │         │
  │         └─ ProcessListAdd(&g_ProtectedList, 1234)
  │              │
  │              ├─ KeAcquireSpinLock
  │              ├─ check for duplicate → STATUS_OBJECT_NAME_COLLISION
  │              ├─ check for capacity  → STATUS_QUOTA_EXCEEDED
  │              ├─ append PID
  │              └─ KeReleaseSpinLock
  │
  └─ exit 0
```

## Data flow: handle stripping

```
attacker.exe calls OpenProcess(PROCESS_TERMINATE, FALSE, 1234)
  │
  └─ kernel validates access, prepares handle
       │
       └─ PreOpCallback fires (OB_OPERATION_HANDLE_CREATE)
            │
            ├─ KernelHandle? → pass through
            ├─ target PID 1234 in protected list? → yes
            ├─ caller PID == 1234? → no
            └─ DesiredAccess &= ~SENTINEL_DENIED_PROCESS_ACCESS
                 │
                 └─ PROCESS_TERMINATE bit cleared
                      │
                      └─ handle opened with reduced rights
                           │
                           └─ TerminateProcess(handle, ...) → ACCESS_DENIED
```
