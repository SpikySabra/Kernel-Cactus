#include "MIOBCommon.h"

void UnloadProtectionDriver(PDRIVER_OBJECT);
__declspec(dllexport) NTSTATUS CompleteRequest(PIRP, NTSTATUS, ULONG_PTR);
__declspec(dllexport) NTSTATUS MalIOBlockCreateClose(PDEVICE_OBJECT, PIRP);


NTSTATUS DriverEntry(DRIVER_OBJECT DriverObject, PUNICODE_STRING RegisterEntry) {
	
	UNREFERENCED_PARAMETER(RegisterEntry);
	
	// Driver Loading
	DbgPrint(DRIVER_PREFIX "Malicious IO Requests Blocker - Powered By @SpikySabra\n");
	DbgPrint(DRIVER_PREFIX "@0xs0ns3 , @T045T3\n");

	// Driver Info Initializition
	DriverObject.DriverUnload = UnloadProtectionDriver;
	DriverObject.MajorFunction[IRP_MJ_CLOSE] = MalIOBlockCreateClose;
	DriverObject.MajorFunction[IRP_MJ_CREATE] = MalIOBlockCreateClose;

	NTSTATUS status;
	PDEVICE_OBJECT DeviceObject = NULL;
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\MalIoBlock");
	BOOLEAN symLinkCreated = FALSE;
	do {
		UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\MalIoBlock");
		status = IoCreateDevice(&DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, 0, TRUE, &DeviceObject);
		if (!NT_SUCCESS(status)) {
			DbgPrint(DRIVER_PREFIX "Failed to create device\n");
			break;
		}

		status = IoCreateSymbolicLink(&symLink, &devName);
		if (!NT_SUCCESS(status)) {
			DbgPrint(DRIVER_PREFIX "Failed to create symbolic link\n");
			break;
		}
		symLinkCreated = TRUE;

	} while (FALSE);


	// If something break during the initialization - cleanin up
	if (!NT_SUCCESS(status)) {

		if (DeviceObject)
			IoDeleteDevice(DeviceObject);

		if (symLinkCreated)
			IoDeleteSymbolicLink(&symLink);

	}
	status = InstallVulnerDriverHook(FALSE);
	if (!NT_SUCCESS(status)) {

		DbgPrint(DRIVER_PREFIX "Hooking major func failed\n");

	}

	return STATUS_SUCCESS;

}

// Functions Definitions

void UnloadProtectionDriver(PDRIVER_OBJECT DriverObject) {

	DbgPrint("Unloading IO Requests Blocker\n");
	InstallVulnerDriverHook(TRUE);
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\MalIoBlock");
	IoDeleteSymbolicLink(&symLink);
	IoDeleteDevice(DriverObject->DeviceObject);

}


__declspec(dllexport) NTSTATUS CompleteRequest(PIRP Irp, NTSTATUS status, ULONG_PTR info) {

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = info;
	IoCompleteRequest(Irp, 0);

	return status;

}


__declspec(dllexport) NTSTATUS MalIOBlockCreateClose(PDEVICE_OBJECT DeviceObject, PIRP irp) {
	UNREFERENCED_PARAMETER(DeviceObject);
	IoCancelIrp(irp);
	NTSTATUS status = STATUS_CANCELLED;
	ULONG_PTR info = 0;
	return CompleteRequest(irp, status, info);

}

