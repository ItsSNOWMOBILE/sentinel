# Setup and testing guide

Sentinel requires a test-signing environment because it uses
`ObRegisterCallbacks` and `PsSetCreateProcessNotifyRoutineEx`, both of which
require the driver binary to carry the `IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY`
characteristic and be signed with a trusted certificate.  On a development
machine the easiest path is a Hyper-V VM with test signing enabled.

**Never load this driver on a production or primary-use machine.**

---

## 1. Prepare the test VM

### 1a. Create the VM

1. Open **Hyper-V Manager** → New → Virtual Machine.
2. Generation 2, ≥ 4 GB RAM, ≥ 60 GB disk.
3. Install **Windows 10 or 11 (x64)** from an ISO.  An evaluation ISO from
   Microsoft is sufficient.

### 1b. Enable test signing

Inside the VM, from an **elevated command prompt**:

```cmd
bcdedit /set testsigning on
bcdedit /set nointegritychecks off
shutdown /r /t 0
```

After reboot, the desktop shows a "Test Mode" watermark in the lower-right
corner confirming the setting is active.

### 1c. Enable kernel debugging (optional but recommended)

On the VM:

```cmd
bcdedit /debug on
bcdedit /dbgsettings serial debugport:1 baudrate:115200
```

On the host, connect WinDbg to the VM's named pipe or serial port.  Sentinel
uses `KdPrint` for all diagnostic output; those messages appear in the WinDbg
output window (or `DebugView` if a kernel debugger is not attached).

---

## 2. Build

Requirements on the **host** (not the VM):

- Visual Studio 2022 with the **Desktop development with C++** workload
- **Windows Driver Kit (WDK)** for Windows 11, matching the VS version

Open `sentinel.sln` in Visual Studio.  The solution contains two projects:

| Project          | Output                  | Description                    |
|------------------|-------------------------|--------------------------------|
| `driver`         | `sentinel.sys`          | Kernel-mode WDM driver         |
| `client`         | `sentinel-client.exe`   | Usermode control utility       |

Build both in **Release|x64** configuration.  The driver project has
`<IntegrityCheck>true</IntegrityCheck>` in the vcxproj which passes
`/INTEGRITYCHECK` to the linker, setting the required PE characteristic.

Build artefacts land in `x64\Release\` under each project directory.

---

## 3. Sign the driver

Test signing requires a self-signed test certificate.  From a **Developer
Command Prompt for VS 2022** on the host:

```cmd
rem Create a self-signed certificate and install it into the test store.
makecert -r -pe -ss PrivateCertStore -n "CN=SentinelTestCert" SentinelTest.cer
certmgr /add SentinelTest.cer /s /r localMachine root
certmgr /add SentinelTest.cer /s /r localMachine trustedpublisher

rem Sign the driver.
signtool sign /v /s PrivateCertStore /n "SentinelTestCert" ^
    /t http://timestamp.digicert.com ^
    driver\x64\Release\sentinel.sys
```

Copy `SentinelTest.cer` to the VM and install it into **Trusted Root
Certification Authorities** and **Trusted Publishers** for the local machine
(not the current user):

```cmd
certmgr /add SentinelTest.cer /s /r localMachine root
certmgr /add SentinelTest.cer /s /r localMachine trustedpublisher
```

---

## 4. Install and load the driver

Copy `sentinel.sys` and `sentinel-client.exe` to the VM (shared folder,
network share, or drag-and-drop in Hyper-V).

From an **elevated command prompt** on the VM:

```cmd
rem Register the service.
sc create sentinel type= kernel start= demand binPath= "C:\Drivers\sentinel.sys"

rem Start it.
sc start sentinel

rem Verify it loaded.
sc query sentinel
```

Expected output from `sc query`:

```
STATE              : 4  RUNNING
```

If the driver fails to start, `sc query` shows an error code.  Common causes:

| Error    | Likely cause |
|----------|--------------|
| `0xC0000428` (`STATUS_INVALID_IMAGE_HASH`) | Driver not signed / certificate not in Trusted Publishers |
| `0xC0000022` (`STATUS_ACCESS_DENIED`) | `ObRegisterCallbacks` failed — integrity check bit missing from the binary |
| `0xC000003B` (`STATUS_OBJECT_PATH_NOT_FOUND`) | Wrong path in `binPath=` |

### Alternative: pnputil

```cmd
pnputil /add-driver sentinel.inf /install
```

This uses the INF to install the package and register the service.  After
installation, `sc start sentinel` loads the driver.

---

## 5. Test with sentinel-client

```cmd
rem Protect Notepad (replace 5678 with the actual PID).
tasklist | findstr notepad
sentinel-client protect 5678

rem Verify the list.
sentinel-client list

rem From a second elevated prompt, attempt to terminate:
taskkill /PID 5678 /F
rem Expected: ERROR: The process with PID 5678 could not be terminated.
rem Reason: Access is denied.

rem Remove protection.
sentinel-client unprotect 5678
```

### Kernel debug output

If a kernel debugger is attached (WinDbg), or if `DbgView` (from Sysinternals)
is running with kernel capture enabled, Sentinel prints:

```
[Sentinel] loaded
[Sentinel] pid 5678 protected
[Sentinel] remote thread creation into pid 5678 from pid 9012 (handle rights stripped)
[Sentinel] pid 5678 exited, removed from protected list
[Sentinel] unloaded
```

---

## 6. Unload the driver

```cmd
sc stop sentinel
sc delete sentinel
```

`SentinelUnload` is called on `sc stop` and unregisters all callbacks in
reverse order before returning.

---

## 7. Troubleshooting

**The device object is not present (`\\.\Sentinel` cannot be opened)**

The driver may have failed to create the device.  Check `sc query sentinel`
for a non-running state and review the kernel debug output for the error code
logged by `DeviceCreate`.

**`sentinel-client` prints `0xC0000034` (NAME_NOT_FOUND)**

The driver is loaded but `DeviceCreate` failed.  This should not happen under
normal conditions; attach a kernel debugger and check for `[Sentinel] DeviceCreate`
log lines.

**Test-mode watermark is gone after rebooting the VM**

Hyper-V checkpoints can restore a snapshot taken before `bcdedit /set testsigning on`.
Re-apply the bcdedit commands and reboot.

**`ObRegisterCallbacks` returns `0xC0000022` (ACCESS_DENIED)**

The `IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY` bit is not set in the driver
binary.  Rebuild with the `/INTEGRITYCHECK` linker flag (already configured in
`driver\sentinel.vcxproj`).  A common mistake is running `signtool` on a binary
that was not built with this flag; signing after the fact does not add the
characteristic — the linker must set it at build time.
