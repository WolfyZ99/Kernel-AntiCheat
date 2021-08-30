#pragma once

namespace Server
{
	void EncDec(char* Buff, uint32_t Size)
	{
		for (uint32_t i = 0; i < Size; i++)
			Buff[i] = (char)(Buff[i] ^ ((i + 13 * i + 93) + 46 + i));
	}

	bool SendInfo(SERVER_INFO Output)
	{
		WSADATA WSAData;
		SOCKET server;
		SOCKADDR_IN addr;
		WSAStartup(MAKEWORD(2, 0), &WSAData);

		if ((server = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
		{
			WSACleanup();
			return false;
		}

		addr.sin_addr.s_addr = inet_addr(xorstr_("127.0.0.1"));
		addr.sin_family = AF_INET;
		addr.sin_port = htons(3768);

		if (connect(server, (SOCKADDR*)&addr, sizeof(addr)) == SOCKET_ERROR)
		{
			WSACleanup();
			printf("Failed to connect\n");
			return false;
		}

		char OutBuf[3184] = { 0 };
		memcpy(&OutBuf, &Output, sizeof(SERVER_INFO));
		EncDec(OutBuf, sizeof(SERVER_INFO));

		send(server, OutBuf, sizeof(SERVER_INFO), 0);

		char InpBuf[8] = { 0 };
		recv(server, InpBuf, sizeof(InpBuf), 0);
		EncDec(InpBuf, sizeof(uint64_t));

		closesocket(server);
		WSACleanup();

		return true;
	}

	void SendThread()
	{
		const char* UserName = "TestUser2";

		while (TRUE)
		{
			SERVER_INFO Info = { 0 };
			Info.OverlayInfo = OverlayDetection::Enumerate();
			Info.KernelDetections = Driver::ScanKernelDetections();

			strncpy(Info.Username, UserName, strlen(UserName));

			if (!SendInfo(Info))
				printf("Failed to send info to the server!\n");

			std::this_thread::sleep_for(std::chrono::minutes(1));
		}
	}
}