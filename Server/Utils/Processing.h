#pragma once

namespace Processing
{
	void CalcScore(PSERVER_INFO pInfo, int* DetectionScore)
	{
		int Score = 0;

		int GameWindowSizeX = pInfo->GameWindowRect.right - pInfo->GameWindowRect.left;
		int GameWindowSizeY = pInfo->GameWindowRect.bottom - pInfo->GameWindowRect.top;

		for (int i = 0; i < 15; i++)
		{
			int PreScore = 0;

			WINDOW_STRUCT Struct = pInfo->OverlayInfo.Windows[i];

			int WindowSizeX = Struct.Rect.right - Struct.Rect.left;
			int WindowSizeY = Struct.Rect.bottom - Struct.Rect.top;

			if (Struct.IsSigned == false)
				PreScore += 3;

			if ((Struct.ExStyle & WS_EX_TRANSPARENT) && (Struct.ExStyle & WS_EX_TOPMOST) && (Struct.ExStyle & WS_EX_LAYERED))
				PreScore += 4;
			else if ((Struct.ExStyle & WS_EX_TRANSPARENT) && (Struct.ExStyle & WS_EX_LAYERED))
				PreScore += 5;
			else if ((Struct.ExStyle & WS_EX_TOPMOST) && (Struct.ExStyle & WS_EX_LAYERED))
				PreScore += 3;
			else if (Struct.ExStyle & WS_EX_LAYERED)
				PreScore += 2;

			if ((GameWindowSizeX - WindowSizeX) < 200 && (GameWindowSizeY - WindowSizeY) < 200)
				PreScore *= 2;

			if (PreScore > Score)
				Score = PreScore;
		}

		SCAN_RESULTS Struct = pInfo->KernelDetections;

		if (Struct.InvalidDispatches)
			Score += 5;

		if (Struct.InvalidThreads)
			Score += 5;

		if (Struct.InvalidStacks)
			Score += 2;

		if (Struct.TrampolineThreads)
			Score += 3;

		if (Struct.PiDDB_VulnerableDriver)
			Score += 8;

		*DetectionScore = Score;
	}

	void SendInfo(PSERVER_INFO pInfo, int DetectionScore)
	{
		std::string Username = pInfo->Username;

		int Ban = 0;

		if (DetectionScore >= 15)
			Ban = 1;

		std::string Req1 = ("SELECT `Score` FROM `DetectionScore` WHERE `Username`='") + Username +("'");
		std::string Ret1 = SQL::MySQL_Ret(Req1);

		if (Ret1 != "E" && Ret1.size() > 0)
		{
			int DetSc = atoi(Ret1.c_str());

			if (DetSc < DetectionScore)
			{
				std::string Req2 = ("UPDATE `DetectionScore` SET `Score` = '") + std::to_string(DetectionScore) + ("',`IsBanned` = '") + std::to_string(Ban) + ("' WHERE `Username` = '") + Username + "'";
				SQL::MySQL(Req2);
			}
		}
		else
		{
			std::string Req2 = ("INSERT INTO `DetectionScore` (`Username`, `IsBanned`, `Score`) VALUES ('") + Username + ("', '") + std::to_string(Ban) + ("', '") + std::to_string(DetectionScore) + ("')");
			SQL::MySQL(Req2);
		}
	
		for (int i = 0; i < 15; i++)
		{
			std::string WindowName = pInfo->OverlayInfo.Windows[i].WindowName;
			std::string ClassName = pInfo->OverlayInfo.Windows[i].ClassName;
			std::string ProcessName = pInfo->OverlayInfo.Windows[i].ProcessName;

			if (ProcessName.size() < 3)
				continue;

			std::string Req3 = ("SELECT `ExStyle` FROM `Overlays` WHERE `Username`='") + Username + ("' AND `Name`='") + WindowName + ("' AND `Class`='") + ClassName + ("' AND `Process`='") + ProcessName + "'";
			std::string Ret3 = SQL::MySQL_Ret(Req3);

			if (Ret3.size() < 5)
			{
				int SizeX = pInfo->OverlayInfo.Windows[i].Rect.right - pInfo->OverlayInfo.Windows[i].Rect.left;
				int SizeY = pInfo->OverlayInfo.Windows[i].Rect.bottom - pInfo->OverlayInfo.Windows[i].Rect.top;

				std::string Size = std::to_string(SizeX) + "/" + std::to_string(SizeY);
				std::string Style = std::to_string(pInfo->OverlayInfo.Windows[i].Style);
				std::string ExStyle = std::to_string(pInfo->OverlayInfo.Windows[i].ExStyle);

				std::string Req4 = ("INSERT INTO `Overlays` (`Username`, `Process`, `Name`, `Class`, `Style`, `ExStyle`, `Size`, `IsSigned`) VALUES ('") + Username + ("', '") + ProcessName + ("', '") + WindowName + 
					("', '") + ClassName + ("', '") + Style + ("', '") + ExStyle + ("', '") + Size + ("', '") + std::to_string(pInfo->OverlayInfo.Windows[i].IsSigned) + ("')");

				SQL::MySQL(Req4);
			}
		}
	}
}

