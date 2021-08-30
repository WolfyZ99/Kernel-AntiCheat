#define _CRT_SECURE_NO_WARNINGS
#define HAVE_STRUCT_TIMESPEC

#pragma comment(lib, "C:\\Program Files\\MySQL\\MySQL Server 5.7\\lib\\libmysql.lib")
#pragma once
#include <Windows.h>
#include <stdio.h>
#include <string>
#include <iostream>
#include <conio.h>
#include <cstring>
//#include <my_global.h>
#include <mysql.h>
#include <time.h>
#include <sstream>
#include <urlmon.h>
#include <wincrypt.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment (lib, "urlmon.lib")

namespace SQL
{
	MYSQL* Link;
	MYSQL_RES* Result = 0;
	MYSQL_ROW Row;

	std::string Host = ("CENSORED");
	std::string User = ("CENSORED");
	std::string Pass = ("CENSORED");
	std::string DBase = ("CENSORED");

	bool Connect()
	{
		Link = mysql_init(0);

		if (!mysql_real_connect(Link, Host.c_str(), User.c_str(), Pass.c_str(), DBase.c_str(), 0, 0, 0))
			return false;

		return true;
	}

	void Disconnect()
	{
		mysql_close(Link);
	}

	inline std::string MySQL_Ret(std::string Request)
	{
		if (mysql_query(Link, Request.c_str()))
			return ("E");

		std::string RetVal;
		Result = mysql_store_result(Link);

		if (Result)
			while (Row = mysql_fetch_row(Result))
				RetVal += Row[0];
		else
			RetVal = ("E");

		return RetVal;
	}

	inline bool MySQL(std::string Request)
	{
		if (mysql_query(Link, Request.c_str()))
			return false;

		return true;
	}
}