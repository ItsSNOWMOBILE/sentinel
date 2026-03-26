# Sentinel

A Windows x64 kernel-mode driver that protects processes from termination, memory injection, and handle theft.

Sentinel intercepts handle operations at the kernel level using `ObRegisterCallbacks`, stripping dangerous access rights before they reach user-mode callers. Once a process is protected, no user-mode process can terminate it, read or write its memory, inject threads, or hijack existing threads — even with administrator privileges.

> **This driver is intended for test environments only.** It requires test-signing mode or a valid EV code-signing certificate. Never load unsigned kernel code on a production machine.

## How It Works

When a PID is added to the protected list via the client utility, the driver registers a pre-operation callback on every `OpenProcess` and `DuplicateHandle` call targeting that process. Before the handle is returned, the callback strips the following access rights:

### Process Handle Rights Stripped

| Right stripped             | Attack prevented                                    |
|----------------------------|-----------------------------------------------------|
| `PROCESS_TERMINATE`        | `TerminateProcess`                                  |
| `PROCESS_VM_WRITE`         | `WriteProcessMemory`                                |
| `PROCESS_VM_READ`          | `ReadProcessMemory`                                 |
| `PROCESS_VM_OPERATION`     | `VirtualAllocEx`, `VirtualFreeEx`                    |
| `PROCESS_CREATE_THREAD`    | `CreateRemoteThread`                                 |
| `PROCESS_DUP_HANDLE`       | Handle exfiltration via `DuplicateHandle`            |
| `PROCESS_SUSPEND_RESUME`   | `NtSuspendProcess`, `NtResumeProcess`                |

### Thread Handle Rights Stripped

| Right stripped             | Attack prevented                                     |
|----------------------------|------------------------------------------------------|
| `THREAD_TERMINATE`         | `TerminateThread`                                    |
| `THREAD_SUSPEND_RESUME`    | `NtSuspendThread`, `NtResumeThread`                  |
| `THREAD_SET_CONTEXT`       | Thread hijacking via `SetThreadContext`               |

Kernel handles are never modified — they are trusted by design. A protected process retains full access to itself.

## Architecture

```
┌─────────────────────┐     IOCTL      ┌──────────────────────────────────┐
│  sentinel-client    │ ─────────────▶ │           sentinel.sys           │
│  (user mode)        │                │                                  │
└─────────────────────┘                │  ┌───────────────────────────┐   │
                                       │  │  PROTECTED_LIST            │   │
 protect <pid>  ───────────────────────┼─▶│  KSPIN_LOCK-guarded array  │   │
 unprotect <pid>───────────────────────┼─▶│  of up to 64 PIDs         │   │
 list           ───────────────────────┼─▶│                           │   │
                                       │  └────────────┬──────────────┘   │
                                       │               │                   │
                                       │  ┌────────────▼──────────────┐   │
                                       │  │  ObRegisterCallbacks      │   │
                                       │  │  Pre-op handle stripping  │   │
                                       │  └───────────────────────────┘   │
                                       │                                  │
                                       │  ┌───────────────────────────┐   │
                                       │  │  PsSetCreateProcess-      │   │
                                       │  │  NotifyRoutineEx          │   │
                                       │  │  Auto-expire on exit      │   │
                                       │  └───────────────────────────┘   │
                                       │                                  │
                                       │  ┌───────────────────────────┐   │
                                       │  │  PsSetCreateThread-       │   │
                                       │  │  NotifyRoutine            │   │
                                       │  │  Remote thread logging    │   │
                                       │  └───────────────────────────┘   │
                                       └──────────────────────────────────┘
```

The driver registers three independent callback systems:

1. **ObRegisterCallbacks** — intercepts handle creation and duplication. Strips dangerous access rights from handles targeting protected processes and their threads. This is the core enforcement mechanism.

2. **PsSetCreateProcessNotifyRoutineEx** — monitors process lifecycle. When a protected process exits, its PID is automatically removed from the list. This prevents stale entries and PID recycling issues.

3. **PsSetCreateThreadNotifyRoutine** — logs remote thread creation attempts against protected processes. This is diagnostic only; actual prevention is handled by stripping `PROCESS_CREATE_THREAD` in the ObCallback.

For a deeper walkthrough including data flow diagrams and component breakdowns, see [docs/architecture.md](docs/architecture.md).

## Requirements

| Component      | Version                              |
|----------------|--------------------------------------|
| Windows        | 10 / 11 x64 (VM strongly recommended) |
| Visual Studio  | 2022 (v143 toolset)                  |
| WDK            | Windows 11 22H2 or later            |
| Target machine | Test-signing enabled                 |

## Building

Open `sentinel.sln` in Visual Studio 2022, select **Release | x64**, and build. Output:

```
driver\x64\Release\sentinel.sys
client\x64\Release\sentinel-client.exe
```

The driver binary is linked with `/INTEGRITYCHECK`, which sets the `IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY` PE flag — a hard requirement for `ObRegisterCallbacks`. The CI pipeline validates this automatically.

## Installation

Full VM setup instructions, kernel debugging configuration, and the test certificate workflow are documented in [docs/setup.md](docs/setup.md).

```bat
:: Register the driver as a kernel service
sc create sentinel type= kernel start= demand binPath= C:\Drivers\sentinel.sys

:: Load it
sc start sentinel

:: Verify
sc query sentinel
```

## Usage

```
sentinel-client protect <pid>       Add a process to the protected list
sentinel-client unprotect <pid>     Remove a process from the protected list
sentinel-client list                Show all currently protected PIDs
```

Example session:

```bat
:: Protect a running process
sentinel-client protect 5678

:: Verify it's protected
sentinel-client list

:: Attempt to kill it — this will fail with "Access is denied"
taskkill /PID 5678 /F

:: Remove protection when done
sentinel-client unprotect 5678

:: Unload the driver
sc stop sentinel
sc delete sentinel
```

## Limitations

This driver defends against **user-mode tampering only**. It is not an anti-cheat, anti-rootkit, or comprehensive security solution. The following are known limitations:

- **Kernel-mode callers are not blocked.** Any other kernel driver loaded by an administrator can bypass all protections. Handles opened from kernel mode (`KernelHandle == TRUE`) are never modified. Sentinel is not a rootkit detector — it operates within the Windows security model, not above it.

- **Pre-existing handles are not revoked.** If a process already holds a handle with dangerous access rights before the target PID is added to the protected list, that handle remains valid. For best results, protect processes immediately after creation.

- **Handle inheritance is not intercepted.** A child process may inherit a full-access handle from its parent before Sentinel's callback fires. The same mitigation applies: protect early.

- **SeDebugPrivilege holders may retain prior handles.** The callback strips rights from whatever access the kernel grants, so `SeDebugPrivilege` callers still lose dangerous rights on *new* handle requests. However, a privileged process that opened a handle before protection was enabled keeps it.

- **Query rights are intentionally preserved.** `PROCESS_QUERY_INFORMATION` and `PROCESS_QUERY_LIMITED_INFORMATION` are not stripped. Diagnostic tools like Task Manager and Process Explorer need these to function, and they do not enable process tampering.

- **Fixed capacity of 64 PIDs.** The protected list is a fixed-size array. Attempting to protect a 65th process will fail with a quota error. This is a deliberate design choice to avoid dynamic memory allocation in a spin lock context.

- **No persistence across reboots.** The protected list is in-memory only. If the driver is unloaded or the system reboots, all protection is lost. There is no registry or file-backed state.

- **Test-signing required.** Without a valid EV code-signing certificate and Microsoft cross-signature, the driver can only be loaded on machines with test-signing enabled. This limits deployment to development and testing environments.

## License

MIT
