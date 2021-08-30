#pragma once

typedef struct _SCAN_RESULTS
{
	uint32_t InvalidThreads;
	uint32_t TrampolineThreads;
	uint32_t InvalidStacks;
	uint32_t InvalidDispatches;
	bool PiDDB_VulnerableDriver;
} SCAN_RESULTS, * PSCAN_RESULTS;

typedef struct _WINDOW_STRUCT
{
	char WindowName[50];
	char ClassName[50];
	char ProcessName[40];
	bool IsSigned;
	LONG Style;
	LONG ExStyle;
	RECT Rect;
} WINDOW_STRUCT, * PWINDOW_STRUCT;

typedef struct _OVERLAY_RESULTS
{
	WINDOW_STRUCT Windows[15];
} OVERLAY_RESULTS, * POVERLAY_RESULTS;

typedef struct _SERVER_INFO
{
	char Username[30];
	RECT GameWindowRect;
	SCAN_RESULTS KernelDetections;
	OVERLAY_RESULTS OverlayInfo;
} SERVER_INFO, * PSERVER_INFO;
