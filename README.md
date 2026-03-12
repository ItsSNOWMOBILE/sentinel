# Sentinel

A Windows x64 kernel-mode driver that protects a target process from
termination, memory injection, and handle theft.

Built on top of `ObRegisterCallbacks` for handle access stripping and
`PsSetCreateProcessNotifyRoutineEx` / `PsSetCreateThreadNotifyRoutine`
for lifecycle and injection telemetry.

> **Test environments only.** Requires test-signing mode or a valid EV
> code-signing certificate. Never deploy unsigned kernel code to a
> production machine.

## What it does

When a PID is added to the protected list, Sentinel intercepts every
`OpenProcess` and `DuplicateHandle` call targeting that process and strips
the following access rights from the returned handle:

| Right | Prevents |
|---|---|
| `PROCESS_TERMINATE` | `TerminateProcess` |
| `PROCESS_VM_WRITE` | `WriteProcessMemory` |
| `PROCESS_VM_READ` | `ReadProcessMemory` |
| `PROCESS_VM_OPERATION` | `VirtualAllocEx`, `VirtualFreeEx` |
| `PROCESS_CREATE_THREAD` | `CreateRemoteThread` |
| `PROCESS_DUP_HANDLE` | `DuplicateHandle` |
| `PROCESS_SUSPEND_RESUME` | `NtSuspendProcess` |

Threads belonging to a protected process receive the same treatment for:
`THREAD_TERMINATE`, `THREAD_SUSPEND_RESUME`, `THREAD_SET_CONTEXT`.

The process is allowed full access to itself. Kernel handles are never
stripped (they are trusted by design).

## Architecture

See [docs/architecture.md](docs/architecture.md).

## Requirements

| Component | Version |
|---|---|
| Windows | 10 / 11 x64 (VM recommended) |
| Visual Studio | 2022 17.x |
| WDK | Windows 11 22H2 or later |
| Target machine | Test-signing enabled (see setup) |

## Build

Open `sentinel.sln` in Visual Studio 2022, select the **Release | x64**
configuration, then **Build → Build Solution**.

Output lands in `driver\x64\Release\` and `client\x64\Release\`:
`sentinel.sys`, `sentinel-client.exe`.

## Installation

See [docs/setup.md](docs/setup.md) for VM setup, kernel debugging, and the
test certificate workflow.

```bat
sc create sentinel type= kernel binPath= C:\path\to\sentinel.sys
sc start sentinel
```

## Usage

```
sentinel-client protect   <pid>
sentinel-client unprotect <pid>
sentinel-client list
```

## Limitations

See the [threat model](docs/architecture.md#threat-model) in the
architecture doc for a full discussion of what this driver cannot protect
against and known bypass techniques.

## License

MIT
