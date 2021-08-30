#pragma once

void EncDec(char* Buff, uint32_t Size)
{
	for (uint32_t i = 0; i < Size; i++)
		Buff[i] = (char)(Buff[i] ^ ((i + 13 * i + 93) + 46 + i));
}

namespace
{
	class ClientConnection1 : public TCPServerConnection
	{
	public:
		ClientConnection1(const StreamSocket& s) : TCPServerConnection(s)
		{
		}

		void run()
		{
			StreamSocket& ss = socket();
			try
			{
				char InpBuf[3192];
				char OutBuf[8];

				int n = ss.receiveBytes(InpBuf, sizeof(InpBuf));

				while (n > 0)
				{
					uint64_t Success = 1337;

					SERVER_INFO Input = { 0 };
					EncDec(InpBuf, sizeof(SERVER_INFO));
					memcpy(&Input, &InpBuf, sizeof(SERVER_INFO));

					int DetectionScore = 0;
					Processing::CalcScore(&Input, &DetectionScore);

					if (SQL::Connect())
					{
						Processing::SendInfo(&Input, DetectionScore);
						SQL::Disconnect();
					}

					memcpy(&OutBuf, &Success, sizeof(uint64_t));
					EncDec(OutBuf, sizeof(uint64_t));

					ss.sendBytes(OutBuf, sizeof(uint64_t), 0);

					n = ss.receiveBytes(InpBuf, sizeof(InpBuf));
				}

			}
			catch (Exception& exc)
			{
				std::cerr << ("ClientConnection: ") << exc.displayText() << std::endl;
			}
		}
	};

	typedef TCPServerConnectionFactoryImpl<ClientConnection1> TCPFactory1;

#if defined(POCO_OS_FAMILY_WINDOWS)
	NamedEvent terminator(ProcessImpl::terminationEventName(Process::id()));
#else
	Event terminator;
#endif
}