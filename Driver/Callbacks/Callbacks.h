#pragma once

namespace Callbacks
{
	PVOID hRegistration = NULL;

	VOID LoadImageNotifyRoutine(PUNICODE_STRING FullImageName, HANDLE ProcessID, PIMAGE_INFO ImageInfo)
	{
		UNREFERENCED_PARAMETER(ImageInfo);

		if (ImpCall(wcsstr, FullImageName->Buffer, skCrypt(L"\\ProtectionTest.exe")))
		{
			const BYTE DigestBuffer[] = { 0x83, 0x65, 0x52, 0x4F, 0x61, 0x49, 0xA3, 0x34, 0xD7, 0xF5, 0x6C, 0xE1, 0x16, 0xBF, 0xA1, 0xC1, 0x2E, 0x87, 0xE2, 0x64 };

			if (Utils::AuthenticateApplication(FullImageName, (PVOID)DigestBuffer, 1))
			{
				GamePID = (uint32_t)ProcessID;
				Log("\n");
			}
		}
	}

	OB_PREOP_CALLBACK_STATUS PreObCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation)
	{
		UNREFERENCED_PARAMETER(RegistrationContext);
		PEPROCESS OpenedProcess = (PEPROCESS)OperationInformation->Object;

		if (GamePID < 1)
			return OB_PREOP_SUCCESS;

		if (OperationInformation->KernelHandle)
			return OB_PREOP_SUCCESS;

		if ((int)ImpCall(PsGetCurrentProcessId) == GamePID)
			return OB_PREOP_SUCCESS;

		if (ImpCall(PsIsSystemProcess, OpenedProcess) || ImpCall(PsIsProtectedProcess, OpenedProcess))
			return OB_PREOP_SUCCESS;

		uint32_t RequestPID = (uint32_t)ImpCall(PsGetProcessId, (PEPROCESS)OperationInformation->Object);

		if (RequestPID == GamePID)
		{
			if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE || OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
			{
				if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_TERMINATE) == PROCESS_TERMINATE)
					OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
			
				if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_OPERATION) == PROCESS_VM_OPERATION)
					OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_OPERATION;
			
				if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_READ) == PROCESS_VM_READ)
					OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_READ;
			
				if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_WRITE) == PROCESS_VM_WRITE)
					OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_WRITE;
			}
		}

		return OB_PREOP_SUCCESS;
	}

	NTSTATUS RegisterCallbacks(PDRIVER_OBJECT pDrv)
	{
		NTSTATUS Status = STATUS_UNSUCCESSFUL;

		PKLDR_DATA_TABLE_ENTRY Entry = (PKLDR_DATA_TABLE_ENTRY)pDrv->DriverSection;
		Entry->Flags |= 0x20;

		Status = ImpCall(PsSetLoadImageNotifyRoutine, LoadImageNotifyRoutine);

		if (!NT_SUCCESS(Status))
			return Status;

		OB_CALLBACK_REGISTRATION obRegistration = { 0, };
		OB_OPERATION_REGISTRATION opRegistration = { 0, };

		obRegistration.Version = ImpCall(ObGetFilterVersion);
		obRegistration.OperationRegistrationCount = 1;
		ImpCall(RtlInitUnicodeString, &obRegistration.Altitude, L"320070");
		obRegistration.RegistrationContext = NULL;

		opRegistration.ObjectType = PsProcessType;
		opRegistration.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
		opRegistration.PreOperation = PreObCallback;
		opRegistration.PostOperation = NULL;
		obRegistration.OperationRegistration = &opRegistration;

		Status = ImpCall(ObRegisterCallbacks, &obRegistration, &hRegistration);

		if (!NT_SUCCESS(Status))
		{
			if (hRegistration)
				ImpCall(ObUnRegisterCallbacks, hRegistration);

			Log("Failed to register PreObCallback: 0x%llX\n", Status);
		}

		return Status;
	}

	VOID UnregisterCallbacks()
	{
		ImpCall(PsRemoveLoadImageNotifyRoutine, LoadImageNotifyRoutine);

		if (hRegistration)
			ImpCall(ObUnRegisterCallbacks, hRegistration);
	}
}