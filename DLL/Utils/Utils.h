#pragma once

namespace Utils
{
#define SafeDeleteArraySize(pData) { if(pData){delete []pData;pData=NULL;} }

	bool RedirectionCreateFile(const wchar_t* FilePath, HANDLE& hFile)
	{
		bool Ret = false;

		if (!FilePath)
			return Ret;

		PVOID OldVal = NULL;
		bool Val = Wow64DisableWow64FsRedirection(&OldVal);

		hFile = CreateFileW(FilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

		if (hFile != INVALID_HANDLE_VALUE)
			return true;

		OldVal = NULL;

		if (Val)
			Wow64RevertWow64FsRedirection(&OldVal);

		return Val;
	}

	wchar_t* GetCertName(const wchar_t* FilePath)
	{
		CERT_INFO CertInfo;
		memset(&CertInfo, sizeof(CertInfo));

		if (IsBadReadPtr(FilePath, sizeof(DWORD)))
			return NULL;

		wchar_t* CertName = NULL;
		PCCERT_CONTEXT pCertContext = NULL;
		HCERTSTORE hStore = NULL;
		HCRYPTMSG hMsg = NULL;

		do
		{
			DWORD NumberOfBytesRead = 0;
			HANDLE hFile = INVALID_HANDLE_VALUE;

			if (!RedirectionCreateFile(FilePath, hFile))
				break;

			DWORD FileSize = GetFileSize(hFile, NULL);
			BYTE* pBuff = new BYTE[FileSize + 1];

			if (!pBuff)
				break;

			RtlZeroMemory(pBuff, FileSize + 1);

			BOOL Status = ReadFile(hFile, pBuff, FileSize, &NumberOfBytesRead, NULL);
			CloseHandle(hFile);

			if (!Status)
				break;

			CERT_BLOB Object = { 0 };
			Object.cbData = FileSize;
			Object.pbData = pBuff;

			DWORD dwEncoding = 0, dwContentType = 0, dwFormatType = 0;

			Status = CryptQueryObject(CERT_QUERY_OBJECT_FILE, FilePath, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_FORMAT_FLAG_BINARY, 0, &dwEncoding, &dwContentType, &dwFormatType, &hStore, &hMsg, NULL);

			if (!Status)
			{
				PVOID OldVal = 0;
				BOOL IsDisabled = Wow64DisableWow64FsRedirection(&OldVal);
				OldVal = 0;

				Status = CryptQueryObject(CERT_QUERY_OBJECT_FILE, FilePath, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_FORMAT_FLAG_BINARY, 0, &dwEncoding, &dwContentType, &dwFormatType, &hStore, &hMsg, NULL);

				if (Status)
					Wow64RevertWow64FsRedirection(&OldVal);

				if (!Status)
					break;
			}

			DWORD dwSignerInfo = 0;
			Status = CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, NULL, &dwSignerInfo);

			if (!Status)
				break;

			PCMSG_SIGNER_INFO pSignerInfo = (PCMSG_SIGNER_INFO)new char[dwSignerInfo];

			if (!pSignerInfo)
				break;

			ZeroMemory(pSignerInfo, dwSignerInfo);

			Status = CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, (PVOID)pSignerInfo, &dwSignerInfo);

			if (!Status)
				break;

			CertInfo.Issuer = pSignerInfo->Issuer;
			CertInfo.SerialNumber = pSignerInfo->SerialNumber;

			pCertContext = CertFindCertificateInStore(hStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_SUBJECT_CERT, (PVOID)&CertInfo, NULL);

			if (!pCertContext)
				break;

			DWORD dwData = CertGetNameStringW(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, NULL, 0);
			if (1 >= dwData)
				break;

			CertName = new wchar_t[dwData + 1];

			if (!CertName)
				break;

			ZeroMemory(CertName, (dwData + 1) * sizeof(wchar_t));

			if (!(CertGetNameStringW(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, CertName, dwData)))
				break;

		} while (false);

		if (pCertContext != NULL)
			CertFreeCertificateContext(pCertContext);

		if (hStore != NULL)
			CertCloseStore(hStore, 0);

		if (hMsg != NULL)
			CryptMsgClose(hMsg);

		return CertName;
	}

	wchar_t* GetFileCat(wchar_t* lpFileName)
	{
		WINTRUST_DATA wd = { 0 };
		WINTRUST_FILE_INFO wfi = { 0 };
		WINTRUST_CATALOG_INFO wci = { 0 };
		CATALOG_INFO ci = { 0 };
		HCATADMIN hCatAdmin = NULL;
		HANDLE hFile = INVALID_HANDLE_VALUE;
		DWORD dwCnt = 0;
		PBYTE pbyHash = NULL;
		wchar_t* pszMemberTag = NULL;
		HCATINFO hCatInfo = NULL;
		HRESULT hr;
		static GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
		const GUID gSubsystem = DRIVER_ACTION_VERIFY;
		wchar_t* pCatalogFile = NULL;

		do
		{

			if (!CryptCATAdminAcquireContext(&hCatAdmin, &gSubsystem, 0))
				break;

			if (!RedirectionCreateFile(lpFileName, hFile))
				break;

			if (CryptCATAdminCalcHashFromFileHandle(hFile, &dwCnt, pbyHash, 0) && dwCnt > 0 && ERROR_INSUFFICIENT_BUFFER == GetLastError())
			{
				pbyHash = new BYTE[dwCnt];
				ZeroMemory(pbyHash, dwCnt);
				if (CryptCATAdminCalcHashFromFileHandle(hFile, &dwCnt, pbyHash, 0) == FALSE)
				{
					CloseHandle(hFile);
					break;
				}
			}
			else
			{
				CloseHandle(hFile);
				break;
			}

			CloseHandle(hFile);

			hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, pbyHash, dwCnt, 0, NULL);

			if (NULL == hCatInfo)
			{
				wfi.cbStruct = sizeof(WINTRUST_FILE_INFO);
				wfi.pcwszFilePath = lpFileName;
				wfi.hFile = NULL;
				wfi.pgKnownSubject = NULL;
				wd.cbStruct = sizeof(WINTRUST_DATA);
				wd.dwUnionChoice = WTD_CHOICE_FILE;
				wd.pFile = &wfi;
				wd.dwUIChoice = WTD_UI_NONE;
				wd.fdwRevocationChecks = WTD_REVOKE_NONE;
				wd.dwStateAction = WTD_STATEACTION_IGNORE;
				wd.dwProvFlags = WTD_SAFER_FLAG;
				wd.hWVTStateData = NULL;
				wd.pwszURLReference = NULL;
			}
			else
			{
				if (CryptCATCatalogInfoFromContext(hCatInfo, &ci, 0))
				{
					pszMemberTag = new wchar_t[dwCnt * 2 + 1];
					ZeroMemory(pszMemberTag, (dwCnt * 2 + 1) * sizeof(wchar_t));

					for (DWORD dw = 0; dw < dwCnt; ++dw)
						wsprintfW(&pszMemberTag[dw * 2], L"%02X", pbyHash[dw]);

					wci.cbStruct = sizeof(WINTRUST_CATALOG_INFO);
					wci.pcwszCatalogFilePath = ci.wszCatalogFile;
					wci.pcwszMemberFilePath = lpFileName;
					wci.pcwszMemberTag = pszMemberTag;

					wd.cbStruct = sizeof(WINTRUST_DATA);
					wd.pCatalog = &wci;
					wd.dwUIChoice = WTD_UI_NONE;
					wd.dwUnionChoice = WTD_CHOICE_CATALOG;
					wd.fdwRevocationChecks = WTD_STATEACTION_VERIFY;
					wd.dwStateAction = WTD_STATEACTION_VERIFY;
					wd.dwProvFlags = 0;
					wd.hWVTStateData = NULL;
					wd.pwszURLReference = NULL;

				}
			}

			hr = WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &action, &wd);

			if (SUCCEEDED(hr) || wcslen(ci.wszCatalogFile) > 0)
			{
				pCatalogFile = new wchar_t[MAX_PATH];
				ZeroMemory(pCatalogFile, MAX_PATH * sizeof(wchar_t));
				CopyMemory(pCatalogFile, ci.wszCatalogFile, wcslen(ci.wszCatalogFile) * sizeof(wchar_t));
			}

			if (NULL != hCatInfo)
				CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);


		} while (FALSE);


		if (hCatAdmin)
			CryptCATAdminReleaseContext(hCatAdmin, 0);

		SafeDeleteArraySize(pbyHash);
		SafeDeleteArraySize(pszMemberTag);
		return pCatalogFile;
	}

	wchar_t* GetFileCertName(wchar_t* pFilePath)
	{
		wchar_t* pCertName = NULL;
		wchar_t* pCatFilePath = NULL;

		pCertName = GetCertName(pFilePath);

		if (pCertName == NULL)
		{
			pCatFilePath = GetFileCat(pFilePath);

			if (pCatFilePath)
				pCertName = GetCertName(pCatFilePath);
		}

		SafeDeleteArraySize(pCatFilePath);
		return pCertName;
	}

	bool IsFileAllowed(wchar_t* pFilePath)
	{
		HANDLE hFile = NULL;

		if (!RedirectionCreateFile(pFilePath, hFile))
			return false;

		if (GetFileCertName(pFilePath) == NULL)
			return false;

		return true;
	}
}