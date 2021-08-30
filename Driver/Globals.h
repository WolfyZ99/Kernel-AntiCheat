#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include <intrin.h>
#include <ntstrsafe.h>

#include "Utils/stdint.h"

PVOID NtBase = 0, CiBase = 0;
const bool DebugEnabled = true;

uint32_t GamePID = 0, ClientPID = 0;

PEPROCESS GameProcess = 0, ClientProcess = 0;

uint64_t KeSuspendThreadOffset = 0, KeResumeThreadOffset = 0;

LARGE_INTEGER Timeout;

#include "Utils/Defs.h"
#include "Utils/skCrypt.h"
#include "Utils/HideImports.h"

#define Log(a, ...) if (DebugEnabled) ImpCall(DbgPrintEx, 0, 0, skCrypt(a), __VA_ARGS__)
#define Sleep(a) Timeout.QuadPart = a; ImpCall(KeDelayExecutionThread, KernelMode, FALSE, &Timeout); Timeout.QuadPart = 0;

#include "Utils/Utils.h"
#include "Detections/Detections.h"
#include "Communication/IO_Handler.h"
#include "Callbacks/Callbacks.h"
