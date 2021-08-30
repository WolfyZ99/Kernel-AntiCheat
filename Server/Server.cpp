
#include "Globals.h"

int main()
{
	try
	{
		Poco::UInt16 port = 3768;

		TCPServer srv(new TCPFactory1(), port);
		srv.start();

		std::cout << "TCP server listening on port " << port << '.'
			<< std::endl << "Press Ctrl-C to quit." << std::endl;

		terminator.wait();
	}
	catch (Exception& exc)
	{
		std::cerr << exc.displayText() << std::endl;
		return 1;
	}
}
