#include "MIOBCommon.h"


NTSTATUS(*oldDevMajorFunc)(PDEVICE_OBJECT DeviceObject, PIRP irp) = NULL;


// IRP is here since this is the hook for completing the IRP
__declspec(dllexport) VOID Prevention(HANDLE processId, PIRP irp) {

	HANDLE hProc = NULL;
	NTSTATUS status = STATUS_SUCCESS;
	OBJECT_ATTRIBUTES obj_attr;
	CLIENT_ID cid;

	cid.UniqueProcess = processId;
	cid.UniqueThread = NULL;

	InitializeObjectAttributes(&obj_attr, NULL, 0, NULL, NULL);

	ZwOpenProcess(&hProc, PROCESS_ALL_ACCESS, &obj_attr, &cid);
	if (!hProc) {

		DbgPrint(DRIVER_PREFIX "Prevention failed - Handle\n");
		return;

	}

	ZwTerminateProcess(hProc, status);
	if (!NT_SUCCESS(status)) {

		DbgPrint(DRIVER_PREFIX "Prevention failed - Termination\n");
		return;

	}

	DbgPrint(DRIVER_PREFIX "Process sent for termination\n");

}


__declspec(dllexport) NTSTATUS HookedUp(PDEVICE_OBJECT DeviceObject, PIRP irp) {

	PETHREAD eThread;
	HANDLE processId;
	LONG res = 0;

	PIO_STACK_LOCATION irpStack;

	eThread = irp->Tail.Overlay.Thread;
	processId = PsGetThreadProcessId(eThread);

	irpStack = IoGetCurrentIrpStackLocation(irp);
	switch (irpStack->MajorFunction) {

	case IRP_MJ_DEVICE_CONTROL:

		if (irpStack->Parameters.DeviceIoControl.IoControlCode == DBUTIL_WRITE_IOCTL) {
			Prevention(processId, irp);
			DbgPrint(DRIVER_PREFIX "DBUTIL_WRITE_IOCTL | Write - Kill Process | Requested by: %d\n", processId);
			return MalIOBlockCreateClose(DeviceObject, irp);
		}
		break;


	default:
		DbgPrint(DRIVER_PREFIX "MajorFunction does not related to DeviceIoControl operation: %x\n", irpStack->MajorFunction);
		return oldDevMajorFunc(DeviceObject, irp);
	}

	return oldDevMajorFunc(DeviceObject, irp);

}


NTSTATUS InstallVulnerDriverHook(BOOLEAN REMOVE) {

	NTSTATUS ntStatus;
	UNICODE_STRING devVulString;
	WCHAR devVulNameBuffer[] = L"\\Device\\DBUtil_2_3";
	PFILE_OBJECT pFile_vul = NULL;
	PDEVICE_OBJECT pDev_vul = NULL;
	PDRIVER_OBJECT pDrv_vul = NULL;

	RtlInitUnicodeString(&devVulString, devVulNameBuffer);

	ntStatus = IoGetDeviceObjectPointer(&devVulString, FILE_READ_DATA, &pFile_vul, &pDev_vul);
	if (!NT_SUCCESS(ntStatus)) {
		DbgPrint(DRIVER_PREFIX "Failed getting Device Object\n");
		return ntStatus;
	}

	if (REMOVE) {

		pDrv_vul = pDev_vul->DriverObject;
		PVOID res = NULL;
		res = InterlockedExchangePointer((PVOID)&pDrv_vul->MajorFunction[IRP_MJ_DEVICE_CONTROL], (PVOID)oldDevMajorFunc);
		if (!res) {

			DbgPrint(DRIVER_PREFIX "Failed to remove hook\n");
			ObDereferenceObject(pDev_vul);
			ObDereferenceObject(pFile_vul);
			return STATUS_FAIL_CHECK;

		}

		DbgPrint(DRIVER_PREFIX "Hooking Removed\n");
		ObDereferenceObject(pDev_vul);
		ObDereferenceObject(pFile_vul);
		return STATUS_SUCCESS;

	}

	pDrv_vul = pDev_vul->DriverObject;
	oldDevMajorFunc = pDrv_vul->MajorFunction[IRP_MJ_DEVICE_CONTROL];

	if (oldDevMajorFunc) {
		PVOID res = NULL;
		res = InterlockedExchangePointer((PVOID)&pDrv_vul->MajorFunction[IRP_MJ_DEVICE_CONTROL], (PVOID)HookedUp);
		if (!res) {

			DbgPrint(DRIVER_PREFIX "Hooking Failed\n");
			return STATUS_FAIL_CHECK;

		}

	}

	DbgPrint(DRIVER_PREFIX "Hooking Complete\n");
	ObDereferenceObject(pDev_vul);
	ObDereferenceObject(pFile_vul);

	return STATUS_SUCCESS;
}
