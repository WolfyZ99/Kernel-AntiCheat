#pragma once

NTSTATUS IO_Handler(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	NTSTATUS Status = STATUS_SUCCESS;
	ULONG Bytes = 0;

	PIO_STACK_LOCATION IO = ImpCall(IoGetCurrentIrpStackLocation, Irp);

	uint32_t CurrentPID = (uint32_t)ImpCall(PsGetCurrentProcessId);

	if (CurrentPID == GamePID || CurrentPID == ClientPID)
	{
		switch (IO->Parameters.DeviceIoControl.IoControlCode)
		{
			case IO_GETSTATUS:
			{
				pIO_GetStatus Struct = (pIO_GetStatus)Irp->AssociatedIrp.SystemBuffer;
				Bytes = sizeof(IO_GetStatus);

				Struct->Recv = Struct->Send * 2;

			} break;

			case IO_SENDOFFSETS:
			{
				pIO_SendOffsets Struct = (pIO_SendOffsets)Irp->AssociatedIrp.SystemBuffer;
				Bytes = sizeof(IO_SendOffsets);

				KeResumeThreadOffset = Struct->KeResumeThread;
				KeSuspendThreadOffset = Struct->KeSuspendThread;

			} break;

			case IO_SCANDETECTIONS:
			{
				PSCAN_RESULTS Struct = (PSCAN_RESULTS)Irp->AssociatedIrp.SystemBuffer;
				Bytes = sizeof(SCAN_RESULTS);

				ImpCall(RtlSecureZeroMemory, &Detections::ScanResults, sizeof(SCAN_RESULTS));

				Detections::ScanSystemThreads();
				Detections::ValidateDispatches();

				/*We don't need to use ntoskrnl.exe's memcpy import cause VisualStudio uses it's own API for mem funcs*/
				memcpy(Struct, &Detections::ScanResults, sizeof(SCAN_RESULTS));

			} break;

			default:
				break;
		}
	}

	Irp->IoStatus.Status = Status;
	Irp->IoStatus.Information = Bytes;
	ImpCall(IofCompleteRequest, Irp, IO_NO_INCREMENT);

	return Status;
}

