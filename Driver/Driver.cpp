
#include "Globals.h"

VOID UnloadRoutine(PDRIVER_OBJECT pDrv)
{
	Callbacks::UnregisterCallbacks();

	ImpCall(IoDeleteDevice, pDrv->DeviceObject);
}

NTSTATUS Create(PDEVICE_OBJECT pDevObj, PIRP Irp)
{
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	ImpCall(IofCompleteRequest, Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS Close(PDEVICE_OBJECT pDevObj, PIRP Irp)
{
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	ImpCall(IofCompleteRequest, Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDrv, PUNICODE_STRING pRegPath)
{
	UNREFERENCED_PARAMETER(pRegPath);

	NTSTATUS Status = STATUS_ENTRYPOINT_NOT_FOUND;

	pDrv->DriverUnload = UnloadRoutine;

	if (!SetImports())
		return Status;

	UNICODE_STRING DevName;
	PDEVICE_OBJECT pDevObj;

	ImpCall(RtlInitUnicodeString, &DevName, L"\\Device\\WolfyZ_NtDrv");
	ImpCall(IoCreateDevice, pDrv, 0, &DevName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDevObj);

	pDrv->MajorFunction[IRP_MJ_CREATE] = Create;
	pDrv->MajorFunction[IRP_MJ_CLOSE] = Close;
	pDrv->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IO_Handler;

	Status = Callbacks::RegisterCallbacks(pDrv);

	if (NT_SUCCESS(Status))
		Log("Callbacks registered!\n");
	else
		Log("Failed to register callbacks: 0x%llX\n", Status);

	return Status;
}