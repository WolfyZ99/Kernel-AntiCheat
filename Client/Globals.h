#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include "framework.h"
#include "Client.h"

#include <Windows.h>
#include <stdint.h>
#include <winternl.h>
#include <iostream>
#include <intrin.h>
#include <Psapi.h>
#include <fstream>
#include <vector>
#include <assert.h>
#include <ntstatus.h>
#include <TlHelp32.h>
#include <Uxtheme.h>
#include <dwmapi.h>
#include <string>
#include <winioctl.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <mscat.h>
#include <SoftPub.h>
#include <winsock.h>
#include <thread>

#pragma comment(lib, "wintrust")
#pragma comment(lib, "ws2_32.lib")

int GamePID = -1;

HWND OverlayWindow = 0;

#include "Utils/xorstr.h"
#include "Utils/Defs.h"
#include "Utils/HideImports.h"
#include "Utils/SymParser.h"
#include "Utils/Utils.h"
#include "Communication/Driver.h"
#include "Detection/OverlayScan.h"
#include "Communication/Server.h"
#include "Utils/Loader.h"