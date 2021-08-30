#pragma once

namespace Loader
{
	bool LoadDriver(std::string DriverPath, std::string DriverName)
	{
		SC_HANDLE SCM_Handle = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);

		if (!SCM_Handle)
			return false;

		SC_HANDLE ServiceHandle = CreateServiceA(SCM_Handle, DriverName.c_str(), DriverName.c_str(), SERVICE_START | SERVICE_STOP | DELETE,
			SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, DriverPath.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);

		if (!ServiceHandle)
		{
			ServiceHandle = OpenServiceA(SCM_Handle, DriverName.c_str(), SERVICE_START);

			if (!ServiceHandle)
			{
				CloseServiceHandle(SCM_Handle);
				return false;
			}
		}

		bool Result = StartServiceA(ServiceHandle, 0, nullptr);

		if (!Result)
			std::cout << GetLastError() << std::endl;

		CloseServiceHandle(ServiceHandle);
		CloseServiceHandle(SCM_Handle);

		return Result;
	}

	bool UnloadDriver(std::string DriverName)
	{
		SC_HANDLE SCM_Handle = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);

		if (!SCM_Handle)
			return false;

		SC_HANDLE ServiceHandle = OpenServiceA(SCM_Handle, DriverName.c_str(), SERVICE_STOP | DELETE);

		if (!ServiceHandle)
		{
			CloseServiceHandle(SCM_Handle);
			return false;
		}

		SERVICE_STATUS Status = { 0 };
		bool Result = ControlService(ServiceHandle, SERVICE_CONTROL_STOP, &Status) && DeleteService(ServiceHandle);

		CloseServiceHandle(ServiceHandle);
		CloseServiceHandle(SCM_Handle);

		return Result;
	}
}