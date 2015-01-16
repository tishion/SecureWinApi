// Generator.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"


#include "..\SecureWinApi\SecureWinApi\SecureWinApi.h"

// Put all code into the same section
#pragma code_seg(push, seg_original, ".sccode")
#define SECURE_WIN_API_GENERATOR
#include "..\SecureWinApi\SecureWinApi\SecureWinApiTable.h"
#include "..\SecureWinApi\SecureWinApi\WinNtApi.h"
#include "..\SecureWinApi\SecureWinApi\Win32Api.h"
#pragma code_seg(pop, seg_original)


#define IfFalseGoExit(x) { br=(x); if (!br) goto _ErrorExit; }
#define MakePointer(t, p, offset) ((t)((ULONG)(p) + offset))
BOOL GetSelfPESection(LPCSTR pSectionName, PUCHAR* ppSectionBase, PULONG pSectionSize)
{
	BOOL br = FALSE;
	HMODULE hModExe = ::GetModuleHandle(NULL);
	if (NULL == hModExe)
	{
		return FALSE;
	}

	PIMAGE_DOS_HEADER pImageDosHeader = NULL;
	PIMAGE_NT_HEADERS32 pImageNtHeader = NULL;
	LPVOID pImageBase = NULL;

	LPVOID pVirutalMemoryBase = NULL;
	ULONG ulVirtuallMemorySize = 0;

	pImageDosHeader = (PIMAGE_DOS_HEADER)hModExe;

	// 对比MZ签名
	IfFalseGoExit(IMAGE_DOS_SIGNATURE == pImageDosHeader->e_magic);

	// 对比PE签名
	DWORD dwE_lfanew = pImageDosHeader->e_lfanew;
	PDWORD pdwPESignature = MakePointer(PDWORD, pImageDosHeader, dwE_lfanew);
	IfFalseGoExit(IMAGE_NT_SIGNATURE == *pdwPESignature);

	// 获取IMAGE_FILE_HEADER，然后判断目标平台CPU类型
	PIMAGE_FILE_HEADER pImageFileHeader = 
		MakePointer(PIMAGE_FILE_HEADER, pdwPESignature, sizeof(IMAGE_NT_SIGNATURE));

	IfFalseGoExit(IMAGE_FILE_MACHINE_I386 == pImageFileHeader->Machine);

	pImageNtHeader = MakePointer(PIMAGE_NT_HEADERS32, pdwPESignature, 0);

	IfFalseGoExit(
		IMAGE_NT_OPTIONAL_HDR32_MAGIC == pImageNtHeader->OptionalHeader.Magic);

	int nNumberOfSections = pImageNtHeader->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER pImageSectionHeader = MakePointer(
		PIMAGE_SECTION_HEADER, pImageNtHeader, sizeof(IMAGE_NT_HEADERS32));

	for (int i = 0; i < nNumberOfSections; ++ i)
	{
		if (0 == strcmp((const char*)pImageSectionHeader[i].Name, pSectionName))
		{
			*ppSectionBase = (PUCHAR)((DWORD)hModExe + (DWORD)(pImageSectionHeader[i].VirtualAddress));
			*pSectionSize = pImageSectionHeader[i].Misc.VirtualSize;
			break;
		}
	}

_ErrorExit:
	return br;
}

BOOL GetHexData(LPVOID pBase, DWORD dwLen, CString& strHexData)
{
	if (NULL == pBase)
	{
		return FALSE;
	}

	PBYTE pByte = (PBYTE)pBase;
	strHexData.Empty();
	
	CString strByte;
	for (int i=0; i < dwLen; i++)
	{
		if (0x0 == (i % 0x10))
		{
			strHexData.Append(_T("\t"));
		}

		strByte.Format(_T("0x%02X, "), pByte[i]);
		strHexData.Append(strByte);
		
		if (0x0f == (i % 0x10))
		{
			strHexData.Append(_T("\r\n"));
		}
	}
	strHexData.TrimRight(_T("\r\n"));
	strHexData.TrimRight(_T(", "));

	return TRUE;
}

void MakeShellCodeDataStruct(CString &strShellCodeData)
{
	TCHAR *pInfo = 
		_T("/************************************************\\\r\n")
		_T(" *        SecureWinApi ShellCode Data           *\r\n")
		_T("\\************************************************/\r\n");

	ULONG ulSectionSize = 0;
	PUCHAR pSectionBase = NULL;

	if (FALSE == GetSelfPESection(".sccode", &pSectionBase, &ulSectionSize))
	{
		_tprintf(_T("Failed at GetSelfPESection\r\n"));
		return;
	}

	CString strHeader;
	strHeader.Format(_T("unsigned char SecureWinApi_ShellCode_Data[%d] = {"), ulSectionSize);

	CString strHexData;
	if (FALSE == GetHexData(pSectionBase, ulSectionSize, strHexData))
	{
		_tprintf(_T("Failed at GetHexData\r\n"));
		return;
	}

	CString strTail;
	strTail.Format(_T("};\r\n"));

	strShellCodeData.Format(
		_T("%s\r\n")
		_T("%s\r\n")
		_T("%s\r\n")
		_T("%s\r\n"),
		pInfo,
		strHeader,
		strHexData,
		strTail);

	return;
}

int _tmain(int argc, _TCHAR* argv[])
{

	CString strShellCodeData;
	CStringA strShellCodeDataAnsi;

	MakeShellCodeDataStruct(strShellCodeData);

	_tprintf(
		_T("%s")
		_T("Shell code data has been generated Done!\r\n")
		_T("Press any key to save it into file.\r\n"),
		strShellCodeData.GetString());

	_gettch();

	CAtlFile file;
	HRESULT hr = E_FAIL;

	hr = file.Create(_T(".\\SecureWinApi_SC.cpp"), 
		GENERIC_WRITE, FILE_SHARE_READ, CREATE_ALWAYS);

	if (SUCCEEDED(hr))
	{
		_tprintf(_T("Create File SecureWinApi_SC.cpp OK!\r\n"));
	}
	else
	{
		_tprintf(_T("Failed at Create File.\r\n"));
		goto _Exit;
	}

	{
		USES_CONVERSION;
		strShellCodeDataAnsi = T2A(strShellCodeData.GetString());
	}

	hr = file.Write(
		strShellCodeDataAnsi.GetString(), 
		strShellCodeDataAnsi.GetLength() * sizeof(CHAR));

	if (SUCCEEDED(hr))
	{
		_tprintf(_T("Write File SecureWinApi_SC.cpp OK!\r\n"));
	}
	else
	{
		_tprintf(_T("Failed at Write File.\r\n"));
		goto _Exit;
	}

	file.Flush();

_Exit:
	_gettch();

	return 0;
}

