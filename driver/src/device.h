#pragma once
#include <ntddk.h>

/*
 * Creates \Device\Sentinel and the \DosDevices\Sentinel symbolic link,
 * and registers the IRP_MJ_CREATE / IRP_MJ_CLOSE / IRP_MJ_DEVICE_CONTROL
 * dispatch routines on DriverObject.
 */
NTSTATUS DeviceCreate(_In_ PDRIVER_OBJECT DriverObject);

/* Deletes the symbolic link and the device object. */
VOID DeviceDestroy(_In_ PDRIVER_OBJECT DriverObject);
