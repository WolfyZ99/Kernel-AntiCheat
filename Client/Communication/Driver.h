#pragma once

namespace Driver
{
	HANDLE Drv = NULL;

	__forceinline void SecureIO(uint32_t Code, void* InBuf, uint32_t InBufSize, void* OutBuf, uint32_t OutBufSize)
	{
		IO_STATUS_BLOCK IO;
		NtDeviceIoControlFile(Drv, 0, 0, 0, &IO, Code, InBuf, InBufSize, OutBuf, OutBufSize);
	}

	bool GetStatus()
	{
		OBJECT_ATTRIBUTES Params; IO_STATUS_BLOCK IO;
		UNICODE_STRING Device = { 40, 42, (PWSTR)(L"\\Device\\WolfyZ_NtDrv") };
		InitializeObjectAttributes(&Params, &Device, OBJ_CASE_INSENSITIVE, nullptr, nullptr);
		NtOpenFile(&Drv, 0x100003, &Params, &IO, 0x7, FILE_NON_DIRECTORY_FILE);

		IO_GetStatus Struct = { 0 };
		Struct.Send = getRand() % 100000;
		SecureIO(IO_GETSTATUS, &Struct, sizeof(IO_GetStatus), &Struct, sizeof(IO_GetStatus));

		if ((Struct.Send * 2) != Struct.Recv)
		{
			NtClose(Drv);
			return false;
		}

		return true;
	}

	void SendNtOffsets()
	{
		IO_SendOffsets Struct = { 0 };

		SymParser Parser;
		if (!Parser.IsInitialized())
			return;

		Parser.LoadModule(L"C:\\Windows\\System32\\ntoskrnl.exe");

		SymParser::SYM_INFO Info = {};

		Parser.DumpSymbol(L"KeSuspendThread", Info);
	//	std::wcout << L"KeSuspendThread offset = 0x" << std::hex << Info.Offset << std::endl;

		Struct.KeSuspendThread = Info.Offset;

		Parser.DumpSymbol(L"KeResumeThread", Info);
	//	std::wcout << L"KeResumeThread offset = 0x" << std::hex << Info.Offset << std::endl;

		Struct.KeResumeThread = Info.Offset;

		SecureIO(IO_SENDOFFSETS, &Struct, sizeof(IO_SendOffsets), &Struct, sizeof(IO_SendOffsets));
	}

	SCAN_RESULTS ScanKernelDetections()
	{
		SCAN_RESULTS Struct = { 0 };
		SecureIO(IO_SCANDETECTIONS, &Struct, sizeof(SCAN_RESULTS), &Struct, sizeof(SCAN_RESULTS));

		return Struct;
	}
}