#pragma once

namespace Detections
{
	SCAN_RESULTS ScanResults = { 0 };

	void ScanSystemThreads()
	{
		PRTL_PROCESS_MODULES pModList = (PRTL_PROCESS_MODULES)Utils::GetDriversList();

		if (!pModList)
		{
			Log("Failed to retrieve Modules List\n");
			return;
		}

		for (ULONG ThreadID = 4; ThreadID < 0x30000; ThreadID += 4)
		{
			PETHREAD pThread = 0;

			if (!NT_SUCCESS(ImpCall(PsLookupThreadByThreadId, reinterpret_cast<HANDLE>(ThreadID), &pThread)))
				continue;

			if (ImpCall(KeGetCurrentThread) == pThread || !ImpCall(PsIsSystemThread, pThread))
				continue;

			uint64_t StartAddress = Utils::GetThreadStartAddress(pThread);

			if (!Utils::IsAddressInDriversList(StartAddress, pModList))
			{
				Log("Thread StartAddress out of legit drivers! pETHREAD: 0x%llX, Address: 0x%llX\n", pThread, StartAddress);
				ScanResults.InvalidThreads++;
			}

			if (StartAddress && !memcmp((PVOID)StartAddress, "\xFF\xE1", 2))
			{
				Log("Thread StartAddress trampoline detected! pETHREAD: 0x%llX\n", pThread);
				ScanResults.TrampolineThreads++;
			}

			StackWalkList WalkResults[0x20];
			RtlZeroMemory(&WalkResults[0], sizeof(WalkResults));

			Utils::StackWalkThread(pThread, &WalkResults[0]);

			bool IsStackAdded = false;

			for (int i = 0; i < 0x20; i++)
			{
				if (WalkResults[i].Rsp == 0)
					break;

				if (!Utils::IsAddressInDriversList(WalkResults[i].Rip, pModList))
				{
					Log("Thread stack out of legit drivers!\n");
					bool IsStackInvalid = false;
					Utils::ScanBigPool(WalkResults[i].Rip, &IsStackInvalid);

					if (IsStackInvalid && !IsStackAdded)
					{
						ScanResults.InvalidStacks++;
						IsStackAdded = true;
					}
				}
			} 
		}

		ImpCall(ExFreePoolWithTag, pModList, 0);
	}

	void ValidateDispatches()
	{
		HANDLE hDir = NULL;
		UNICODE_STRING DriverString;
		OBJECT_ATTRIBUTES ObjAttr;
		PVOID Object;

		ImpCall(RtlInitUnicodeString, &DriverString, L"\\Driver");
		InitializeObjectAttributes(&ObjAttr, &DriverString, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

		if (!NT_SUCCESS(ImpCall(ZwOpenDirectoryObject, &hDir, DIRECTORY_QUERY, &ObjAttr)))
		{
			Log("Failed to open \\Driver directory\n");
			return;
		}

		if (!NT_SUCCESS(ImpCall(ObReferenceObjectByHandle, hDir, DIRECTORY_QUERY, nullptr, KernelMode, &Object, nullptr)))
		{
			Log("Failed to reference \\Driver directory\n");
			return;
		}

		ImpCall(ZwClose, hDir);

		POBJECT_TYPE ObjType = ImpCall(ObGetObjectType, Object);
		ImpCall(ObfDereferenceObject, Object);
		
		HANDLE hObj = NULL;

		if (!NT_SUCCESS(ImpCall(ObOpenObjectByName, &ObjAttr, ObjType, KernelMode, NULL, DIRECTORY_QUERY, nullptr, &hObj)))
		{
			Log("Failed to open object!\n");
			return;
		}

		PRTL_PROCESS_MODULES pModList = (PRTL_PROCESS_MODULES)Utils::GetDriversList();

		PDIRECTORY_BASIC_INFORMATION DirInfo = (PDIRECTORY_BASIC_INFORMATION)ImpCall(ExAllocatePool, NonPagedPool, PAGE_SIZE);
		ULONG Ctx = 0, RetBytes = 0;

		while (NT_SUCCESS(ImpCall(ZwQueryDirectoryObject, hObj, DirInfo, PAGE_SIZE, TRUE, FALSE, &Ctx, &RetBytes)))
		{
			PDRIVER_OBJECT pDrv;
			UNICODE_STRING ObjName;

			wchar_t wsDriverName[100] = L"\\Driver\\";
			wcscat(wsDriverName, DirInfo->ObjectName.Buffer);

			ObjName.Length = ObjName.MaximumLength = wcslen(wsDriverName) * 2;
			ObjName.Buffer = wsDriverName;

			if (NT_SUCCESS(ImpCall(ObReferenceObjectByName, &ObjName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
				NULL, NULL, *IoDriverObjectType, KernelMode, nullptr, (PVOID*)&pDrv)))
			{
				if (!Utils::IsAddressInDriversList(reinterpret_cast<uint64_t>(pDrv->MajorFunction[IRP_MJ_DEVICE_CONTROL]), pModList))
				{
					Log("Dispatch of driver %wZ is hijacked: 0x%llX\n", pDrv->DriverName,
						reinterpret_cast<uint64_t>(pDrv->MajorFunction[IRP_MJ_DEVICE_CONTROL]));
					ScanResults.InvalidDispatches++;
				}

				if (!Utils::IsAddressInDriversList(reinterpret_cast<uint64_t>(pDrv->DriverStart), pModList))
				{
					Log("Driver start of driver %wZ is hijacked!\n", pDrv->DriverName);
					ScanResults.InvalidDispatches++;
				}

				if (!Utils::IsAddressInDriversList(reinterpret_cast<uint64_t>(pDrv->FastIoDispatch), pModList))
				{
					Log("FastIoDispatch of driver %wZ is hijacked!\n", pDrv->DriverName);
					ScanResults.InvalidDispatches++;
				}

				if (reinterpret_cast<uint64_t>(pDrv->MajorFunction[IRP_MJ_DEVICE_CONTROL]) < 
					reinterpret_cast<uint64_t>(pDrv->DriverStart) ||
					reinterpret_cast<uint64_t>(pDrv->MajorFunction[IRP_MJ_DEVICE_CONTROL]) > 
					(reinterpret_cast<uint64_t>(pDrv->DriverStart) + pDrv->DriverSize))
				{
					Log("Dispatch of driver %wZ is hijacked!\n", pDrv->DriverName);
					ScanResults.InvalidDispatches++;
				}
			}
		}

		ImpCall(ZwClose, hObj);
		ImpCall(ExFreePoolWithTag, pModList, 0);
	}

	void ScanPiDDBCache()
	{
		PERESOURCE PiDDBLock;
		PRTL_AVL_TABLE Table;

		if (!Utils::LocatePiDDB(&PiDDBLock, &Table))
			return;

		ExAcquireResourceExclusiveLite(PiDDBLock, TRUE);

		for (PiDDBCacheEntry* p = (PiDDBCacheEntry*)RtlEnumerateGenericTableAvl(Table, TRUE);
			p != NULL; p = (PiDDBCacheEntry*)RtlEnumerateGenericTableAvl(Table, FALSE))
		{
			if (p->TimeDateStamp == 0x5284EAC3)
			{
				Log("iqvw64e.sys timestamp detected, DrvName: %wZ\n", p->DriverName);
				ScanResults.PiDDB_VulnerableDriver = true;
			}

			if (p->TimeDateStamp == 0x57CD1415)
			{
				Log("Capcom.sys timestamp detected, DrvName: %wZ\n", p->DriverName);
				ScanResults.PiDDB_VulnerableDriver = true;
			}
		}
	}
}