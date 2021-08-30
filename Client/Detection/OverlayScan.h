#pragma once

namespace OverlayDetection
{
	OVERLAY_RESULTS Enumerate()
	{
		OVERLAY_RESULTS Struct = { 0 };
		uint32_t WindowsFound = 0;

		HWND TopWindow = GetTopWindow(0);

		if (TopWindow)
		{
			while (TopWindow && TopWindow != OverlayWindow && WindowsFound < 15)
			{
				Struct.Windows[WindowsFound].Style = GetWindowLongA(TopWindow, GWL_STYLE);

				if (Struct.Windows[WindowsFound].Style & WS_VISIBLE)
				{
					GetWindowTextA(TopWindow, Struct.Windows[WindowsFound].WindowName, 50);
					GetClassNameA(TopWindow, Struct.Windows[WindowsFound].ClassName, 50);

					DWORD pID = 0;
					GetWindowThreadProcessId(TopWindow, &pID);

					const wchar_t* ProcessName = Utils::GetProcessName(pID);
					wcstombs(Struct.Windows[WindowsFound].ProcessName, ProcessName, 40);

					HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pID);

					if (hProc)
					{
						wchar_t FullImageName[1024];
						DWORD TrashRet = 1024;

						if (QueryFullProcessImageNameW(hProc, 0, FullImageName, &TrashRet))
						{
							if (Utils::IsFileAllowed(FullImageName))
								Struct.Windows[WindowsFound].IsSigned = true;
							else
								Struct.Windows[WindowsFound].IsSigned = false;
						} 

						NtClose(hProc);
					}

					Struct.Windows[WindowsFound].ExStyle = GetWindowLongA(TopWindow, GWL_EXSTYLE);
					GetWindowRect(TopWindow, &Struct.Windows[WindowsFound].Rect);

					printf("Window (0x%lX): Name - %s, Class - %s, Process - %s, Style - 0x%llX, ExStyle - 0x%llX\n", TopWindow,
						Struct.Windows[WindowsFound].WindowName, Struct.Windows[WindowsFound].ClassName, Struct.Windows[WindowsFound].ProcessName,
						Struct.Windows[WindowsFound].Style, Struct.Windows[WindowsFound].ExStyle);

					WindowsFound++;
				}

				TopWindow = GetWindow(TopWindow, GW_HWNDNEXT);
			}
		}

		return Struct;
	}
}


