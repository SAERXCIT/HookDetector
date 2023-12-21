#include "common.h"

BOOL MapFromKnownDLLs(
	LPWSTR wszModuleName, 
	PBYTE* ppModuleData,
	PHANDLE phFileToClose
) {

	NTSTATUS STATUS = 0;
	HANDLE hSection = NULL;
	WCHAR wszKnownDllName[MAX_PATH] = { 0 };
	OBJECT_ATTRIBUTES oaKnownDll = { 0 };
	UNICODE_STRING usKnownDllName = { 0 };

	fnNtOpenSection pNtOpenSection = (fnNtOpenSection)GetProcAddress(GetModuleHandleA("ntdll"), "NtOpenSection");

#ifdef _WIN64
	wcscat_s(wszKnownDllName, MAX_PATH, L"\\KnownDlls\\");
#else
	wcscat_s(wszKnownDllName, MAX_PATH, L"\\KnownDlls32\\");
#endif

	wcscat_s(wszKnownDllName, MAX_PATH, wszModuleName);

	usKnownDllName.Buffer = wszKnownDllName;
	usKnownDllName.Length = wcsnlen_s(wszKnownDllName, MAX_PATH) * sizeof(WCHAR);
	usKnownDllName.MaximumLength = usKnownDllName.Length + sizeof(WCHAR);

	InitializeObjectAttributes(&oaKnownDll, &usKnownDllName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	STATUS = pNtOpenSection(&hSection, SECTION_MAP_READ, &oaKnownDll);
	if (!NT_SUCCESS(STATUS)) {
		//wprintf(L"[-] Couldn't open handle to section of module %ws in KnownDLLs: %x\n", wszModuleName, STATUS);
		return FALSE;
	}

	*ppModuleData = MapViewOfFile(hSection, FILE_MAP_READ, 0, 0, 0);
	if (*ppModuleData == NULL) {

		wprintf(L"[-] MapViewOfFile failed for KnownDLL module %ws: %d\n", wszModuleName, GetLastError());
		CloseHandle(hSection);
		return FALSE;

	}

	*phFileToClose = hSection;

	return TRUE;

}

BOOL MapFromFileSystem(
	LPWSTR wszModuleName,
	PBYTE* ppModuleData,
	PHANDLE phFileToClose,
	PHANDLE phFileMappingToClose
) {

	BOOL bSTATE = TRUE;
	WCHAR wszModulePath[MAX_PATH] = { 0 };
	HANDLE hFile = INVALID_HANDLE_VALUE;
	HANDLE hFileMapping = NULL;

	GetWindowsDirectoryW(wszModulePath, MAX_PATH);

#ifdef _WIN64
	wcscat_s(wszModulePath, MAX_PATH, L"\\System32\\");
#else
	wcscat_s(wszModulePath, MAX_PATH, L"\\SysWOW64\\");
#endif

	wcscat_s(wszModulePath, MAX_PATH, wszModuleName);

	hFile = CreateFileW(wszModulePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		//wprintf(L"[-] Cannot open handle to file %ws: %d\n", wszModulePath, GetLastError());
		bSTATE = FALSE; goto _Cleanup;
	}

	hFileMapping = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (hFileMapping == NULL) {
		wprintf(L"[-] Cannot create mapping to file %ws: %d\n", wszModulePath, GetLastError());
		bSTATE = FALSE; goto _Cleanup;
	}

	*ppModuleData = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
	if (*ppModuleData == NULL) {
		wprintf(L"[-] MapViewOfFile failed for KnownDLL module %ws: %d\n", wszModuleName, GetLastError());
		bSTATE = FALSE; goto _Cleanup;
	}

	*phFileToClose = hFile;
	*phFileMappingToClose = hFileMapping;

	return bSTATE;


_Cleanup:
	if (hFileMapping != NULL && hFileMapping != INVALID_HANDLE_VALUE)
		CloseHandle(hFileMapping);
	if (hFile != NULL && hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);

	return bSTATE;

}

BOOL MapTargetModule(
	LPWSTR wszModuleName,
	PBYTE* ppMappedAddress,
	PBOOL pbIsManuallyMapped,
	PHANDLE phFileToClose,
	PHANDLE phFileMappingToClose
) {

	BOOL bSTATE = TRUE;

	if (MapFromKnownDLLs(wszModuleName, ppMappedAddress, phFileToClose)) {
		*pbIsManuallyMapped = FALSE;
		return TRUE;
	}

	// x86 limitation: lots of false positives when mapping module from disk
	// due to the absence of RIP-relative addressing and the numerous relocations it incurs
	// for now we just skip any non-KnownDLL module
	// TODO: process relocations ?
#ifdef _WIN64
	if (MapFromFileSystem(wszModuleName, ppMappedAddress, phFileToClose, phFileMappingToClose)) {
		*pbIsManuallyMapped = TRUE;
		return TRUE;
	}
#endif

	return FALSE;

}