#include "device.h"
#include "driver.h"
#include "process_list.h"
#include "ioctl.h"

#define SENTINEL_DEVICE_NAME    L"\\Device\\Sentinel"
#define SENTINEL_DOS_NAME       L"\\DosDevices\\Sentinel"

static PDEVICE_OBJECT g_DeviceObject = NULL;

/* ── IRP dispatch ─────────────────────────────────────────────────────────── */

static NTSTATUS
DispatchCreateClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP           Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS
HandleProtect(
    _In_reads_bytes_(InLen) PVOID In,
    _In_                    ULONG InLen
)
{
    if (InLen < sizeof(SENTINEL_PID_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;

    ULONG    pid    = ((PSENTINEL_PID_REQUEST)In)->ProcessId;
    NTSTATUS status = ProcessListAdd(&g_ProtectedList, pid);

    if (NT_SUCCESS(status))
        KdPrint(("[Sentinel] now protecting pid %lu\n", pid));

    return status;
}

static NTSTATUS
HandleUnprotect(
    _In_reads_bytes_(InLen) PVOID In,
    _In_                    ULONG InLen
)
{
    if (InLen < sizeof(SENTINEL_PID_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;

    ULONG pid = ((PSENTINEL_PID_REQUEST)In)->ProcessId;
    return ProcessListRemove(&g_ProtectedList, pid);
}

static NTSTATUS
HandleQuery(
    _Out_writes_bytes_to_(OutLen, *Written) PVOID  Out,
    _In_                                    ULONG  OutLen,
    _Out_                                   PULONG Written
)
{
    if (OutLen < sizeof(SENTINEL_QUERY_RESPONSE))
        return STATUS_BUFFER_TOO_SMALL;

    PSENTINEL_QUERY_RESPONSE resp = (PSENTINEL_QUERY_RESPONSE)Out;
    resp->Count = ProcessListSnapshot(&g_ProtectedList,
                                      resp->ProcessIds,
                                      SENTINEL_MAX_PIDS);
    *Written = sizeof(SENTINEL_QUERY_RESPONSE);
    return STATUS_SUCCESS;
}

static NTSTATUS
DispatchDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP           Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION stack   = IoGetCurrentIrpStackLocation(Irp);
    PVOID              buf     = Irp->AssociatedIrp.SystemBuffer;
    ULONG              inLen   = stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG              outLen  = stack->Parameters.DeviceIoControl.OutputBufferLength;
    ULONG              written = 0;
    NTSTATUS           status;

    switch (stack->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_SENTINEL_PROTECT:
        status = HandleProtect(buf, inLen);
        break;
    case IOCTL_SENTINEL_UNPROTECT:
        status = HandleUnprotect(buf, inLen);
        break;
    case IOCTL_SENTINEL_QUERY:
        status = HandleQuery(buf, outLen, &written);
        break;
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status      = status;
    Irp->IoStatus.Information = written;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

/* ── Device lifecycle ─────────────────────────────────────────────────────── */

NTSTATUS
DeviceCreate(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    UNICODE_STRING devName = RTL_CONSTANT_STRING(SENTINEL_DEVICE_NAME);
    UNICODE_STRING dosName = RTL_CONSTANT_STRING(SENTINEL_DOS_NAME);

    NTSTATUS status = IoCreateDevice(
        DriverObject,
        0,
        &devName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_DeviceObject
    );
    if (!NT_SUCCESS(status))
        return status;

    /*
     * DO_BUFFERED_IO: the I/O manager allocates a system buffer and copies
     * caller data in/out.  Simplest and safest for a non-performance-critical
     * control path.
     */
    g_DeviceObject->Flags |= DO_BUFFERED_IO;
    g_DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    status = IoCreateSymbolicLink(&dosName, &devName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE]         = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;

    return STATUS_SUCCESS;
}

VOID
DeviceDestroy(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    UNREFERENCED_PARAMETER(DriverObject);

    UNICODE_STRING dosName = RTL_CONSTANT_STRING(SENTINEL_DOS_NAME);
    IoDeleteSymbolicLink(&dosName);

    if (g_DeviceObject) {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
    }
}
