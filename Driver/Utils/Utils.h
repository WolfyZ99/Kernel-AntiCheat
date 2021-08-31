#pragma once

namespace Utils
{
	bool inRange(const BYTE* rangeStartAddr, const BYTE* rangeEndAddr, const BYTE* addrToCheck)
	{
		if (addrToCheck > rangeEndAddr || addrToCheck < rangeStartAddr)
		{
			return false;
		}

		return true;
	}

	bool AuthenticateApplication(PCUNICODE_STRING ImageFileName, PVOID DigestBuffer, int SHAtype)
	{
		IO_STATUS_BLOCK IoBlock = { 0 };
		OBJECT_ATTRIBUTES ObjAttr = { 0 }, ObjAttr2 = { 0 };
		HANDLE FileHandle = NULL, SectionHandle = NULL;
		PVOID SectionObject = NULL, BaseAddress = NULL;
		SIZE_T BaseSize = NULL;

		InitializeObjectAttributes(&ObjAttr, const_cast<PUNICODE_STRING>(ImageFileName), OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);

		NTSTATUS Status = ImpCall(ZwOpenFile, &FileHandle, SYNCHRONIZE | FILE_READ_DATA, &ObjAttr, &IoBlock, FILE_SHARE_READ, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);

		if (!NT_SUCCESS(Status) || !NT_SUCCESS(IoBlock.Status) || !FileHandle)
		{
			Log("Failed to open file: 0x%llX | 0x%llX\n", Status, IoBlock.Status);
			return false;
		}

		InitializeObjectAttributes(&ObjAttr2, nullptr, OBJ_KERNEL_HANDLE, nullptr, nullptr);

		Status = ImpCall(ZwCreateSection, &SectionHandle, SECTION_MAP_READ, &ObjAttr2, nullptr, PAGE_READONLY, SEC_COMMIT, FileHandle);
		ImpCall(ZwClose, FileHandle);

		if (!NT_SUCCESS(Status) || !SectionHandle)
		{
			Log("Failed to create section: 0x%llX\n", Status);
			return false;
		}

		Status = ImpCall(ObReferenceObjectByHandle, SectionHandle, SECTION_MAP_READ, nullptr, KernelMode, &SectionObject, nullptr);

		if (!NT_SUCCESS(Status))
		{
			Log("Failed to reference object: 0x%llX\n", Status);
			return false;
		}

		ImpCall(ZwClose, SectionHandle);

		Status = ImpCall(MmMapViewInSystemSpace, SectionObject, &BaseAddress, &BaseSize);
		ImpCall(ObfDereferenceObject, SectionObject);

		if (!NT_SUCCESS(Status))
		{
			Log("Failed to map section: 0x%llX\n", Status);
			return false;
		}

		ULONG SecurityDirectoryEntrySize = NULL;
		PVOID SecurityDirectoryEntry = ImpCall(RtlImageDirectoryEntryToData, BaseAddress, TRUE, 4, &SecurityDirectoryEntrySize);

		if (!SecurityDirectoryEntry)
		{
			Log("Failed to get security directory!\n");
			ImpCall(MmUnmapViewInSystemSpace, BaseAddress);
			return false;
		}

		const BYTE* EndOfFileAddress = static_cast<BYTE*>(BaseAddress) + BaseSize;
		const BYTE* EndOfSecurityDirectory = static_cast<BYTE*>(SecurityDirectoryEntry) + SecurityDirectoryEntrySize;

		if (EndOfSecurityDirectory > EndOfFileAddress || SecurityDirectoryEntry < BaseAddress)
		{
			Log("Security Directory is not contained in the file view!\n");
			ImpCall(MmUnmapViewInSystemSpace, BaseAddress);
			return false;
		}

		LPWIN_CERTIFICATE WinCert = static_cast<LPWIN_CERTIFICATE>(SecurityDirectoryEntry);

		PolicyInfo SignerPolicyInfo, TAPolicyInfo;
		LARGE_INTEGER SigningTime = { 0 };
		const int DigestSize = SHAtype == 1? 20 : 32; // SHA1 / SHA256 size
		const int DigestIdentifier = SHAtype == 1 ? 0x8004 : 0x800C; // SHA1 / SHA256 identifier

		Status = CiCall(CiCheckSignedFile, DigestBuffer, DigestSize, DigestIdentifier, WinCert, SecurityDirectoryEntrySize, &SignerPolicyInfo, &SigningTime, &TAPolicyInfo);

		if (NT_SUCCESS(Status))
		{
			Log("Signed file found!\n");
			ImpCall(MmUnmapViewInSystemSpace, BaseAddress);

			if (DebugEnabled)
			{
				const pCertChainInfoHeader ChainInfoHeader = SignerPolicyInfo.certChainInfo;
				const BYTE* StartOfCertChainInfo = (BYTE*)ChainInfoHeader;
				const BYTE* EndOfCertChainInfo = (BYTE*)SignerPolicyInfo.certChainInfo + ChainInfoHeader->bufferSize;

				if (!inRange(StartOfCertChainInfo, EndOfCertChainInfo, (BYTE*)ChainInfoHeader->ptrToCertChainMembers))
					return true;

				if (!inRange(StartOfCertChainInfo, EndOfCertChainInfo, (BYTE*)ChainInfoHeader->ptrToCertChainMembers + sizeof(CertChainMember)))
					return true;
				
				pCertChainMember SignerChainMember = ChainInfoHeader->ptrToCertChainMembers;

				Log("Subject: %.*s\nIssuer: %.*s\n", SignerChainMember->subjectName.nameLen, static_cast<char*>(SignerChainMember->subjectName.pointerToName), 
					SignerChainMember->issuerName.nameLen, static_cast<char*>(SignerChainMember->issuerName.pointerToName));
			}

			return true;
		}
		else
			Log("Failed to get signed file0x%llX\n", Status);

		ImpCall(MmUnmapViewInSystemSpace, BaseAddress);
		return false;
	}

	bool ValidateDLL(PUNICODE_STRING FullDllName)
	{
		OBJECT_ATTRIBUTES ObjAttr;
		InitializeObjectAttributes(&ObjAttr, const_cast<PUNICODE_STRING>(FullDllName), OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);
		PVOID Object;
		HANDLE FileHandle;
		IO_STATUS_BLOCK IoBlock;

		NTSTATUS Status = ImpCall(ZwOpenFile, &FileHandle, SYNCHRONIZE | FILE_READ_DATA, &ObjAttr, &IoBlock, FILE_SHARE_READ, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);

		if (!NT_SUCCESS(Status))
		{
			Log("Failed to open file: 0x%llX\n", Status);
			return false;
		}

		Status = ImpCall(ObReferenceObjectByHandle, FileHandle, FILE_READ_DATA, *IoFileObjectType, KernelMode, &Object, NULL);

		if (!NT_SUCCESS(Status))
		{
			Log("Failed to reference object: 0x%llX\n", Status);
			ImpCall(ObCloseHandle, FileHandle, KernelMode);

			return false;
		}

		PFILE_OBJECT FileObject = (PFILE_OBJECT)Object;

		PolicyInfo SignerPolicyInfo, TSAPolicyInfo;
		LARGE_INTEGER SigningTime = { 0 };
		int DigestSize = 64, DigestIdentifier = 0;
		BYTE DigestBuffer[64] = { 0 };

		Status = CiCall(CiValidateFileObject, FileObject, 0, 0, &SignerPolicyInfo, &TSAPolicyInfo, &SigningTime, DigestBuffer, &DigestSize, &DigestIdentifier);
		ImpCall(ObCloseHandle, FileHandle, KernelMode);

		if (NT_SUCCESS(Status))
		{
			if (DebugEnabled)
			{
				const pCertChainInfoHeader ChainInfoHeader = SignerPolicyInfo.certChainInfo;
				const BYTE* StartOfCertChainInfo = (BYTE*)ChainInfoHeader;
				const BYTE* EndOfCertChainInfo = (BYTE*)SignerPolicyInfo.certChainInfo + ChainInfoHeader->bufferSize;

				if (!inRange(StartOfCertChainInfo, EndOfCertChainInfo, (BYTE*)ChainInfoHeader->ptrToCertChainMembers))
				{
					CiCall(CiFreePolicyInfo, &SignerPolicyInfo);
					CiCall(CiFreePolicyInfo, &TSAPolicyInfo);
					return true;
				}

				if (!inRange(StartOfCertChainInfo, EndOfCertChainInfo, (BYTE*)ChainInfoHeader->ptrToCertChainMembers + sizeof(CertChainMember)))
				{
					CiCall(CiFreePolicyInfo, &SignerPolicyInfo);
					CiCall(CiFreePolicyInfo, &TSAPolicyInfo);
					return true;
				}

				pCertChainMember SignerChainMember = ChainInfoHeader->ptrToCertChainMembers;

				Log("DLL: %ws\nSubject: %.*s\nIssuer: %.*s\n\n", FullDllName->Buffer, SignerChainMember->subjectName.nameLen, static_cast<char*>(SignerChainMember->subjectName.pointerToName), SignerChainMember->issuerName.nameLen, static_cast<char*>(SignerChainMember->issuerName.pointerToName));
			}

			CiCall(CiFreePolicyInfo, &SignerPolicyInfo);
			CiCall(CiFreePolicyInfo, &TSAPolicyInfo);

			return true;
		}

		CiCall(CiFreePolicyInfo, &SignerPolicyInfo);
		CiCall(CiFreePolicyInfo, &TSAPolicyInfo);

		Log("Failed to validate file object: 0x%llX\n", Status);

		return false;
	}

	NTSTATUS BBSearchPattern(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PVOID* ppFound, int index = 0)
	{
		ASSERT(ppFound != NULL && pattern != NULL && base != NULL);
		if (ppFound == NULL || pattern == NULL || base == NULL)
			return STATUS_ACCESS_DENIED;
		int cIndex = 0;
		for (ULONG_PTR i = 0; i < size - len; i++)
		{
			BOOLEAN found = TRUE;
			for (ULONG_PTR j = 0; j < len; j++)
			{
				if (pattern[j] != wildcard && pattern[j] != ((PCUCHAR)base)[i + j])
				{
					found = FALSE;
					break;
				}
			}

			if (found != FALSE && cIndex++ == index)
			{
				*ppFound = (PUCHAR)base + i;
				return STATUS_SUCCESS;
			}
		}

		return STATUS_NOT_FOUND;
	}

	NTSTATUS BBScanSection(IN PCCHAR section, IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, OUT PVOID* ppFound, PVOID base = nullptr)
	{
		if (ppFound == NULL)
			return STATUS_ACCESS_DENIED;

		if (nullptr == base)
			base = NtBase;
		if (base == nullptr)
			return STATUS_ACCESS_DENIED;

		PIMAGE_NT_HEADERS64 pHdr = ImpCall(RtlImageNtHeader, base);
		if (!pHdr)
			return STATUS_ACCESS_DENIED;

		PIMAGE_SECTION_HEADER pFirstSection = (PIMAGE_SECTION_HEADER)((uintptr_t)&pHdr->FileHeader + pHdr->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER));

		for (PIMAGE_SECTION_HEADER pSection = pFirstSection; pSection < pFirstSection + pHdr->FileHeader.NumberOfSections; pSection++)
		{
			ANSI_STRING s1, s2;
			ImpCall(RtlInitAnsiString, &s1, section);
			ImpCall(RtlInitAnsiString, &s2, (PCCHAR)pSection->Name);

			if (ImpCall(RtlCompareString, &s1, &s2, TRUE) == 0)
			{
				PVOID ptr = NULL;
				NTSTATUS status = BBSearchPattern(pattern, wildcard, len, (PUCHAR)base + pSection->VirtualAddress, pSection->VirtualSize, &ptr);
				if (NT_SUCCESS(status)) 
				{
					*(PULONG64)ppFound = (ULONG_PTR)(ptr);
					return status;
				}
			}
		}

		return STATUS_ACCESS_DENIED;
	}

	PVOID ResolveRelativeAddress(
		_In_ PVOID Instruction,
		_In_ ULONG OffsetOffset,
		_In_ ULONG InstructionSize
	)
	{
		ULONG_PTR Instr = (ULONG_PTR)Instruction;
		LONG RipOffset = *(PLONG)(Instr + OffsetOffset);
		PVOID ResolvedAddr = (PVOID)(Instr + InstructionSize + RipOffset);

		return ResolvedAddr;
	}

	PVOID GetDriversList()
	{
		ULONG RequiredSize = 0;
		ImpCall(ZwQuerySystemInformation, SystemModuleInformation, 0, 0, &RequiredSize);

		RequiredSize += (10 * 1024);

		PVOID pModList = ImpCall(ExAllocatePool, NonPagedPool, RequiredSize);

		if (!pModList)
			return 0;

		ImpCall(ZwQuerySystemInformation, SystemModuleInformation, pModList, RequiredSize, &RequiredSize);

		return pModList;
	}

	bool IsAddressInDriversList(uint64_t Address, PRTL_PROCESS_MODULES pDrvList)
	{
		if (!pDrvList)
			return false;

		if (!Address)
			return true;

		for (uint32_t i = 0; i < pDrvList->NumberOfModules; i++)
		{
			PRTL_PROCESS_MODULE_INFORMATION pMod = &pDrvList->Modules[i];

			if (Address >= (uint64_t)pMod->ImageBase &&
				Address < ((uint64_t)pMod->ImageBase + pMod->ImageSize))
				return true;
		}

		return false;
	}

	ULONG GetThreadStackBaseOffset()
	{
		UNICODE_STRING s = RTL_CONSTANT_STRING(L"PsGetCurrentThreadStackBase");

		auto CurrentThreadStackBase = (uint64_t(NTAPI*)())ImpCall(MmGetSystemRoutineAddress, &s);
		auto CurrentThread = (uint64_t)ImpCall(PsGetCurrentThread);
		auto CurrentStack = CurrentThreadStackBase();

		ULONG Offset = NULL;
		while (*(uint64_t*)(CurrentThread + Offset) != CurrentStack)
			Offset += 8;

		return Offset;
	}

	ULONG GetThreadStackLimitOffset()
	{
		UNICODE_STRING s = RTL_CONSTANT_STRING(L"PsGetCurrentThreadStackLimit");

		auto CurrentThreadStackLimit = (uint64_t(NTAPI*)())ImpCall(MmGetSystemRoutineAddress, &s);
		auto CurrentThread = (uint64_t)ImpCall(PsGetCurrentThread);
		auto CurrentStack = CurrentThreadStackLimit();

		ULONG Offset = NULL;
		while (*(uint64_t*)(CurrentThread + Offset) != CurrentStack)
			Offset += 8;

		return Offset;
	}

	ULONG GetInitialThreadStackOffset()
	{
		UNICODE_STRING s = RTL_CONSTANT_STRING(L"IoGetInitialStack");

		auto CurrentThreadStack = (uint64_t(NTAPI*)())ImpCall(MmGetSystemRoutineAddress, &s);
		auto CurrentThread = (uint64_t)ImpCall(PsGetCurrentThread);
		auto CurrentStack = CurrentThreadStack();

		ULONG Offset = NULL;
		while (*(uint64_t*)(CurrentThread + Offset) != CurrentStack)
			Offset += 8;

		return Offset;
	}

	ULONG GetThreadCurrentStackLocationOffset(uint64_t pThreadObj, ULONG StackBaseOffset, ULONG StackLimitOffset, ULONG InitialStackOffset)
	{
		auto ThreadStackBase = StackBaseOffset ? *(uint64_t*)(pThreadObj + StackBaseOffset) : 0;
		auto ThreadStackLimit = StackLimitOffset ? *(uint64_t*)(pThreadObj + StackLimitOffset) : 0;

		if (!ThreadStackBase || !ThreadStackLimit || !InitialStackOffset)
			return 0;

		ULONG Offset = 0;

		while (Offset < 0x2F8) 
		{
			if (Offset != InitialStackOffset && *(uint64_t*)(pThreadObj + Offset) < ThreadStackBase && *(uint64_t*)(pThreadObj + Offset) > ThreadStackLimit)
				return Offset;

			Offset += 8;
		}

		return 0;
	}

	uint64_t GetThreadStartAddress(PETHREAD pThread)
	{
		NTSTATUS Status = STATUS_SUCCESS;
		uint64_t StartAddress = NULL;
		HANDLE hThread = NULL;
		ULONG RetBytes = NULL;

		Status = ImpCall(ObOpenObjectByPointer, pThread, OBJ_KERNEL_HANDLE, nullptr, GENERIC_READ, *PsThreadType, KernelMode, &hThread);

		if (!NT_SUCCESS(Status))
		{
			Log("Failed to open object: 0x%llX\n", Status);
			return StartAddress;
		}

		Status = ImpCall(ZwQueryInformationThread, hThread, ThreadQuerySetWin32StartAddress, &StartAddress, sizeof(StartAddress), &RetBytes);
		
		if (!NT_SUCCESS(Status))
			Log("Failed to query thread info: 0x%llX\n", Status);

		ImpCall(ZwClose, hThread);

		return StartAddress;
	}
	
	ULONG CopyStack(PETHREAD pThread, PVOID CopiedStack, ULONG StackBufferLen)
	{
		RtlZeroMemory(CopiedStack, StackBufferLen);

		ULONG StackBaseOffset = GetThreadStackBaseOffset();
		ULONG StackLimitOffset = GetThreadStackLimitOffset();
		ULONG InitialStackOffset = GetInitialThreadStackOffset();

		auto StackBase = StackBaseOffset ? *(uint64_t*)((uint64_t)pThread + StackBaseOffset) : 0;
		auto StackLimit = StackLimitOffset ? *(uint64_t*)((uint64_t)pThread + StackLimitOffset) : 0;
		auto InitialStack = InitialStackOffset ? *(uint64_t*)((uint64_t)pThread + InitialStackOffset) : 0;
		auto CurrentStackLocationOffset = GetThreadCurrentStackLocationOffset((uint64_t)pThread, StackBaseOffset, StackLimitOffset, InitialStackOffset);
		auto pCurrentStackLocation = CurrentStackLocationOffset ? (uint64_t*)((uint64_t)pThread + CurrentStackLocationOffset) : nullptr;

		if (pThread == ImpCall(KeGetCurrentThread) || !StackBase || !StackLimit || !InitialStack || !CurrentStackLocationOffset || ImpCall(PsIsThreadTerminating, pThread) || pCurrentStackLocation == nullptr)
			return NULL;

		ThreadProtoDef KeSuspendThread = (ThreadProtoDef)((uint64_t)NtBase + KeSuspendThreadOffset);
		ThreadProtoDef KeResumeThread = (ThreadProtoDef)((uint64_t)NtBase + KeResumeThreadOffset);

		KeSuspendThread(pThread);

		auto CurrentStackLocation = *pCurrentStackLocation;
		auto CurrentStackSize = StackBase - CurrentStackLocation;

		if (CurrentStackLocation > StackLimit && CurrentStackLocation < StackBase && ImpCall(MmGetPhysicalAddress, (PVOID)CurrentStackLocation).QuadPart) 
		{
			if (CurrentStackSize > StackBufferLen)
				CurrentStackSize = StackBufferLen;

			if (!ImpCall(MmIsAddressValid, (PVOID)CurrentStackLocation))
			{
				KeResumeThread(pThread);
				return NULL;
			}

			memmove(CopiedStack, (PVOID)CurrentStackLocation, CurrentStackSize);
		}
		else
			CurrentStackSize = NULL;

		KeResumeThread(pThread);

		return CurrentStackSize;
	}

	uint64_t GetNtTextSection(ULONG* Len)
	{
		PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)NtBase;
		PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pDos + pDos->e_lfanew);

		uint64_t StartAddress = 0;

		uint64_t HeaderOffset = (uint64_t)IMAGE_FIRST_SECTION(pNtHeaders);

		for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; ++i)
		{
			PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)HeaderOffset;

			if (StrICmp(pSection->Name, ".text", false))
			{
				StartAddress = pSection->PointerToRawData;
				*Len = pSection->SizeOfRawData;

				return StartAddress;
			}

			HeaderOffset += sizeof(IMAGE_SECTION_HEADER);
		}

		return StartAddress;
	}

	void StackWalkThread(PETHREAD pThread, StackWalkList* Results)
	{
		BYTE CopiedStack[0x1000];

		if (ULONG StackLen = CopyStack(pThread, CopiedStack, sizeof(CopiedStack)))
		{
			if (StackLen >= 0x48 && StackLen != 0x1000)
			{
				int FuncCount = 0;
				CONTEXT Ctx;

				RtlZeroMemory(&Ctx, sizeof(Ctx));

				Ctx.Rip = *(uint64_t*)(&CopiedStack[0] + 0x38);
				Ctx.Rsp = reinterpret_cast<uint64_t>(&CopiedStack[0] + 0x40);

				ULONG TextLen = 0;
				uint64_t TextAddress = GetNtTextSection(&TextLen);

				if (!TextAddress || !TextLen)
					return;

				static bool IsLogged = false;

				if (!IsLogged)
				{
					Log("NTOS .text Address: 0x%llX | Size: 0x%lX\n", TextAddress, TextLen);
					IsLogged = true;
				}

				if (Ctx.Rip >= TextAddress && Ctx.Rip < (TextAddress + TextLen))
				{
					__try
					{
						do
						{
							if (Ctx.Rip < reinterpret_cast<uint64_t>(MmSystemRangeStart) || Ctx.Rsp < reinterpret_cast<uint64_t>(MmSystemRangeStart))
								break;

							if (!ImpCall(MmIsAddressValid, (PVOID)Ctx.Rip) || !ImpCall(MmIsAddressValid, (PVOID)Ctx.Rsp))
								break;

							Results[FuncCount].Rip = Ctx.Rip;
							Results[FuncCount].Rsp = Ctx.Rsp;
							
							uint64_t ImageBase = 0;
							
							auto OldIRQL = ImpCall(KeRaiseIrqlToDpcLevel);
							auto Func = ImpCall(RtlLookupFunctionEntry, Ctx.Rip, &ImageBase, NULL);
							ImpCall(KeLowerIrql, OldIRQL);

							if (!Func)
								break;

							PVOID HandlerData = 0;
							uint64_t EstablisherFrame = 0;

							RtlVirtualUnwind(NULL, ImageBase, Ctx.Rip, Func, &Ctx, &HandlerData, &EstablisherFrame, nullptr);

							++FuncCount;

							if (!Ctx.Rip)
								break;

						} while (FuncCount < 0x20);
					}
					__except (EXCEPTION_EXECUTE_HANDLER)
					{
						Log("Exception thrown while walking stack for thread 0x%llX\n", (uint64_t)pThread);
					}
				}
			}
		}
	}

	void ScanBigPool(uint64_t Address, bool* Result)
	{
		ULONG Length = 4 * 1024 * 1024;

		PVOID MemPool = ImpCall(ExAllocatePool, NonPagedPool, Length);

		if (NT_SUCCESS(ImpCall(ZwQuerySystemInformation, SystemBigPoolInformation, MemPool, Length, &Length)))
		{
			PSYSTEM_BIGPOOL_INFORMATION pBuf = reinterpret_cast<PSYSTEM_BIGPOOL_INFORMATION>(MemPool);

			for (ULONG i = 0; i < pBuf->Count; i++)
			{
				if ((pBuf->AllocatedInfo->TagUlong == 'enoN' || pBuf->AllocatedInfo->TagUlong == 'tnoC') && Address >= pBuf->AllocatedInfo->VirtualAddress && Address < (pBuf->AllocatedInfo->VirtualAddress + pBuf->AllocatedInfo->SizeInBytes))
				{
					__try
					{
						BYTE ZeroHeaders[0x1000]{};		
						PHYSICAL_ADDRESS phAddress = ImpCall(MmGetPhysicalAddress, (PVOID)pBuf->AllocatedInfo[i].VirtualAddress);

						if (auto PeHeader = ImpCall(MmMapIoSpace, phAddress, PAGE_SIZE, MmNonCached))
						{
							if (memcmp(PeHeader, ZeroHeaders, PAGE_SIZE))
							{
								Log("System thread running in a mapped memory region\n");
								*Result = true;
							}

							ImpCall(MmUnmapIoSpace, PeHeader, PAGE_SIZE);
						}
						else
						{
							Log("Unable to map physmem, but thread is still running in an invalid region!\n");
							*Result = true;
						}
					}
					__except (EXCEPTION_EXECUTE_HANDLER)
					{
						Log("Exception thrown while scanning bigpoolinfo\n");
					}
				}
			}
		}
	}

	bool LocatePiDDB(PERESOURCE* lock, PRTL_AVL_TABLE* table)
	{
		PVOID PiDDBLockPtr = nullptr, PiDDBCacheTablePtr = nullptr;
		if (!NT_SUCCESS(BBScanSection("PAGE", PiDDBLockPtr_sig, 0, sizeof(PiDDBLockPtr_sig) - 1, reinterpret_cast<PVOID*>(&PiDDBLockPtr)))) 
		{
			Log("Unable to find PiDDBLockPtr sig.\n");
			return false;
		}

		if (!NT_SUCCESS(BBScanSection("PAGE", PiDDBCacheTablePtr_sig, 0, sizeof(PiDDBCacheTablePtr_sig) - 1, reinterpret_cast<PVOID*>(&PiDDBCacheTablePtr))))
		{
			Log("Unable to find PiDDBCacheTablePtr sig.\n");
			return false;
		}

		PiDDBCacheTablePtr = PVOID((uintptr_t)PiDDBCacheTablePtr + 3);

		*lock = (PERESOURCE)(ResolveRelativeAddress(PiDDBLockPtr, 3, 7));
		*table = (PRTL_AVL_TABLE)(ResolveRelativeAddress(PiDDBCacheTablePtr, 3, 7));

		return true;
	}
}
