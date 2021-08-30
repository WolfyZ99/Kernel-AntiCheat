#pragma once

#define NT_HEADER(ModBase) (PIMAGE_NT_HEADERS)((ULONG64)(ModBase) + ((PIMAGE_DOS_HEADER)(ModBase))->e_lfanew)

template <typename Type>
__forceinline Type EPtr(Type Ptr)
{
	auto Key = (ULONG64)SharedUserData->Cookie *
		SharedUserData->Cookie *
		SharedUserData->Cookie *
		SharedUserData->Cookie;
	return (Type)((ULONG64)Ptr ^ Key);
}

template <typename StrType, typename StrType2>
__forceinline bool StrICmp(StrType Str, StrType2 InStr, bool Two)
{
#define ToLower(Char) ((Char >= 'A' && Char <= 'Z') ? (Char + 32) : Char)

	if (!Str || !InStr)
		return false;

	wchar_t c1, c2; do
	{
		c1 = *Str++; c2 = *InStr++;
		c1 = ToLower(c1); c2 = ToLower(c2);
		if (!c1 && (Two ? !c2 : 1))
			return true;
	} while (c1 == c2);

	return false;
}

PVOID GetProcAdress(PVOID ModBase, const char* Name)
{
	PIMAGE_NT_HEADERS NT_Head = NT_HEADER(ModBase);
	PIMAGE_EXPORT_DIRECTORY ExportDir = (PIMAGE_EXPORT_DIRECTORY)((ULONG64)ModBase + NT_Head->OptionalHeader.DataDirectory[0].VirtualAddress);

	for (ULONG i = 0; i < ExportDir->NumberOfNames; i++)
	{
		USHORT Ordinal = ((USHORT*)((ULONG64)ModBase + ExportDir->AddressOfNameOrdinals))[i];
		const char* ExpName = (const char*)ModBase + ((ULONG*)((ULONG64)ModBase + ExportDir->AddressOfNames))[i];

		if (StrICmp(Name, ExpName, true))
			return (PVOID)((ULONG64)ModBase + ((ULONG*)((ULONG64)ModBase + ExportDir->AddressOfFunctions))[Ordinal]);
	}

	return nullptr;
}

#define ImpSet(a) a##Fn = (a##Def)EPtr(GetProcAdress(NtBase, skCrypt(#a)));
#define ImpDef(a) using a##Def = decltype(&a); a##Def a##Fn = nullptr;
#define ImpCall(a, ...) ((a##Def)EPtr(a##Fn))(__VA_ARGS__)

#define CiSet(a) a##Fn = (a##Def)EPtr(GetProcAdress(CiBase, skCrypt(#a)));
#define CiDef(a) using a##Def = decltype(&a); a##Def a##Fn = nullptr;
#define CiCall(a, ...) ((a##Def)EPtr(a##Fn))(__VA_ARGS__)

ImpDef(KeAttachProcess); ImpDef(KeDetachProcess); ImpDef(memcpy); ImpDef(ZwOpenFile);
ImpDef(PsLookupProcessByProcessId); ImpDef(MmCopyVirtualMemory); ImpDef(PsGetProcessId);
ImpDef(MmCopyMemory); ImpDef(PsLookupThreadByThreadId); ImpDef(PsIsSystemThread);
ImpDef(RtlInitUnicodeString); ImpDef(IoCreateDevice); ImpDef(PsIsSystemProcess);
ImpDef(IoDeleteSymbolicLink); ImpDef(IoDeleteDevice); ImpDef(IofCompleteRequest);
ImpDef(MmIsAddressValid); ImpDef(PsGetProcessImageFileName); ImpDef(ZwClose); ImpDef(wcsstr);
ImpDef(KeDelayExecutionThread); ImpDef(ExAllocatePool); ImpDef(ExFreePoolWithTag);
ImpDef(IoGetCurrentProcess); ImpDef(DbgPrintEx); ImpDef(PsSetLoadImageNotifyRoutine);
ImpDef(PsRemoveLoadImageNotifyRoutine); ImpDef(PsIsProtectedProcess); ImpDef(ZwCreateSection);
ImpDef(ObGetFilterVersion); ImpDef(ObRegisterCallbacks); ImpDef(ObUnRegisterCallbacks);
ImpDef(ObReferenceObjectByHandle); ImpDef(MmMapViewInSystemSpace); ImpDef(ObfDereferenceObject);
ImpDef(RtlImageDirectoryEntryToData); ImpDef(MmUnmapViewInSystemSpace); ImpDef(IoCreateFileEx);
ImpDef(PsSetCreateProcessNotifyRoutineEx); ImpDef(PsGetCurrentProcessId); ImpDef(KeGetCurrentThread)
ImpDef(ObCloseHandle); ImpDef(ZwQuerySystemInformation); ImpDef(MmGetSystemRoutineAddress);
ImpDef(PsGetCurrentThread); ImpDef(ObOpenObjectByPointer); ImpDef(NtQueryInformationThread);
ImpDef(PsIsThreadTerminating); ImpDef(MmGetPhysicalAddress); ImpDef(MmMapIoSpace);
ImpDef(MmUnmapIoSpace); ImpDef(ZwOpenDirectoryObject); ImpDef(RtlImageNtHeader);
ImpDef(RtlInitAnsiString); ImpDef(RtlCompareString); ImpDef(ZwQueryInformationThread);
ImpDef(IoGetCurrentIrpStackLocation); ImpDef(RtlSecureZeroMemory); ImpDef(KeRaiseIrqlToDpcLevel);
ImpDef(RtlLookupFunctionEntry); ImpDef(KeLowerIrql); ImpDef(ObGetObjectType); 
ImpDef(ObOpenObjectByName); ImpDef(ZwQueryDirectoryObject); ImpDef(ObReferenceObjectByName);

CiDef(CiCheckSignedFile); CiDef(CiFreePolicyInfo); CiDef(CiValidateFileObject);


bool SetImports()
{
	if (!NtBase)
	{
		ULONG Size = 0;
		NTSTATUS Status = 0;

	retry:

		Status = ZwQuerySystemInformation(SystemModuleInformation, 0, 0, &Size);

		if (STATUS_INFO_LENGTH_MISMATCH != Status)
			return false;


		PRTL_PROCESS_MODULES Modules = (PRTL_PROCESS_MODULES)ExAllocatePool(NonPagedPool, Size);
		if (!Modules)
			return false;


		if (!NT_SUCCESS(Status = ZwQuerySystemInformation(SystemModuleInformation, Modules, Size, 0)))
		{
			ExFreePoolWithTag(Modules, 0);

			if (Status == STATUS_INFO_LENGTH_MISMATCH)
				goto retry;
			else
				return false;
		}

		for (ULONG i = 0; i < Modules->NumberOfModules; ++i)
		{
			RTL_PROCESS_MODULE_INFORMATION m = Modules->Modules[i];

			if (strstr((PCHAR)m.FullPathName, skCrypt("ntoskrnl.exe")))
				NtBase = m.ImageBase;

			if (strstr((PCHAR)m.FullPathName, skCrypt("CI.dll")))
				CiBase = m.ImageBase;

			if (NtBase && CiBase)
				break;
		}

		ExFreePoolWithTag(Modules, 0);
	}

	if (!NtBase || !CiBase)
		return false;

	ImpSet(KeAttachProcess); ImpSet(KeDetachProcess); ImpSet(memcpy); ImpSet(ZwOpenFile);
	ImpSet(PsLookupProcessByProcessId); ImpSet(MmCopyVirtualMemory); ImpSet(PsGetProcessId);
	ImpSet(MmCopyMemory); ImpSet(PsLookupThreadByThreadId); ImpSet(PsIsSystemThread);
	ImpSet(RtlInitUnicodeString); ImpSet(IoCreateDevice); ImpSet(PsIsSystemProcess);
	ImpSet(IoDeleteSymbolicLink); ImpSet(IoDeleteDevice); ImpSet(IofCompleteRequest);
	ImpSet(MmIsAddressValid); ImpSet(PsGetProcessImageFileName); ImpSet(ZwClose); ImpSet(wcsstr);
	ImpSet(KeDelayExecutionThread); ImpSet(ExAllocatePool); ImpSet(ExFreePoolWithTag);
	ImpSet(IoGetCurrentProcess); ImpSet(DbgPrintEx); ImpSet(PsSetLoadImageNotifyRoutine);
	ImpSet(PsRemoveLoadImageNotifyRoutine); ImpSet(PsIsProtectedProcess); ImpSet(ZwCreateSection);
	ImpSet(ObGetFilterVersion); ImpSet(ObRegisterCallbacks); ImpSet(ObUnRegisterCallbacks);
	ImpSet(ObReferenceObjectByHandle); ImpSet(MmMapViewInSystemSpace); ImpSet(ObfDereferenceObject);
	ImpSet(RtlImageDirectoryEntryToData); ImpSet(MmUnmapViewInSystemSpace); ImpSet(IoCreateFileEx);
	ImpSet(PsSetCreateProcessNotifyRoutineEx); ImpSet(PsGetCurrentProcessId); ImpSet(KeGetCurrentThread)
	ImpSet(ObCloseHandle); ImpSet(ZwQuerySystemInformation); ImpSet(MmGetSystemRoutineAddress);
	ImpSet(PsGetCurrentThread); ImpSet(ObOpenObjectByPointer); ImpSet(NtQueryInformationThread);
	ImpSet(PsIsThreadTerminating); ImpSet(MmGetPhysicalAddress); ImpSet(MmMapIoSpace);
	ImpSet(MmUnmapIoSpace); ImpSet(ZwOpenDirectoryObject); ImpSet(RtlImageNtHeader);
	ImpSet(RtlInitAnsiString); ImpSet(RtlCompareString); ImpSet(ZwQueryInformationThread);
	ImpSet(IoGetCurrentIrpStackLocation); ImpSet(RtlSecureZeroMemory); ImpSet(KeRaiseIrqlToDpcLevel);
	ImpSet(RtlLookupFunctionEntry); ImpSet(KeLowerIrql); ImpSet(ObGetObjectType);
	ImpSet(ObOpenObjectByName); ImpSet(ZwQueryDirectoryObject); ImpSet(ObReferenceObjectByName);


	CiSet(CiCheckSignedFile); CiSet(CiFreePolicyInfo); CiSet(CiValidateFileObject);

	return true;
}