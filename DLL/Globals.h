#pragma once
#include <Windows.h>
#include <winternl.h>
#include <intrin.h>
#include <stdio.h>
#include <cfloat>
#include <TlHelp32.h>
#include <cstdlib>
#include <stdint.h>
#include <Psapi.h>
#include <mutex>
#include <sstream>
#include <iostream>
#include <vector>
#include <Uxtheme.h>
#include <dwmapi.h>
#include <assert.h>
#include <fstream>
#include <ostream>
#include <wincrypt.h>
#include <wintrust.h>
#include <mscat.h>
#include <SoftPub.h>

#pragma comment(lib, "MinHook.x64.lib")
#pragma comment(lib, "wintrust")

const bool DebugEnabled = true;

#include "Utils/xorstr.h"
#include "Utils/Defs.h"
#include "Utils/HideImports.h"

#define printf(a, ...) if (DebugEnabled) printf(E(a), __VA_ARGS__)

#include "Utils/Utils.h"
#include "Hooks/MinHook.h"
#include "Hooks/Hooks.h"