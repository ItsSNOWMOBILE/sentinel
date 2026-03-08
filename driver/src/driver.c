#include "driver.h"
#include "device.h"
#include "callbacks.h"
#include "process_list.h"

PROTECTED_LIST g_ProtectedList;

static VOID
SentinelUnload(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    /*
     * Unregister in reverse order.  Thread/process notify must be removed
     * before the ObCallback, and the ObCallback before the device, so that
     * no callback can fire against a partially torn-down state.
     */
    CallbacksUnregisterThreadNotify();
    CallbacksUnregisterProcessNotify();
    CallbacksUnregisterObCallbacks();
    DeviceDestroy(DriverObject);
    KdPrint(("[Sentinel] unloaded\n"));
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status;

    DriverObject->DriverUnload = SentinelUnload;
    ProcessListInit(&g_ProtectedList);

    status = DeviceCreate(DriverObject);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[Sentinel] DeviceCreate: %08X\n", status));
        return status;
    }

    status = CallbacksRegisterObCallbacks();
    if (!NT_SUCCESS(status)) {
        KdPrint(("[Sentinel] ObRegisterCallbacks: %08X\n", status));
        goto cleanup_device;
    }

    status = CallbacksRegisterProcessNotify();
    if (!NT_SUCCESS(status)) {
        KdPrint(("[Sentinel] PsSetCreateProcessNotifyRoutineEx: %08X\n", status));
        goto cleanup_ob;
    }

    status = CallbacksRegisterThreadNotify();
    if (!NT_SUCCESS(status)) {
        KdPrint(("[Sentinel] PsSetCreateThreadNotifyRoutine: %08X\n", status));
        goto cleanup_process;
    }

    KdPrint(("[Sentinel] loaded\n"));
    return STATUS_SUCCESS;

cleanup_process:
    CallbacksUnregisterProcessNotify();
cleanup_ob:
    CallbacksUnregisterObCallbacks();
cleanup_device:
    DeviceDestroy(DriverObject);
    return status;
}
