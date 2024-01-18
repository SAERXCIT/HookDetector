#pragma once

#include <Windows.h>
#include <stdio.h>
#include <winternl.h>

typedef struct _MODULE_INFO {
	LPWSTR wszModuleName;
	PVOID pModuleAddress;
} MODULE_INFO, * PMODULE_INFO;

typedef struct _MODULE_LIST {
	WORD wCount;
	MODULE_INFO pModuleList[ANYSIZE_ARRAY];
} MODULE_LIST, * PMODULE_LIST;

typedef struct _HOOK_INFO {
	DWORD dwDifferenceRVA;
	DWORD dwBestCandidateRVA;
	LPSTR szBestCandidateName;
} HOOK_INFO, * PHOOK_INFO;

typedef struct _HOOK_LIST {
	WORD wCount;
	HOOK_INFO pHookList[ANYSIZE_ARRAY];
} HOOK_LIST, * PHOOK_LIST;


BOOL GetLoadedModuleList(
	PMODULE_LIST* ppsctModuleList
);
BOOL GetModuleSectionHeader(
	PBYTE pModuleAddress,
	LPCSTR szSectionName,
	PIMAGE_SECTION_HEADER* ppImgSectionHdr
);
BOOL FindFunctionsFromRVAs(
	PBYTE pModuleAddress,
	BOOL bIsManuallyMapped,
	PHOOK_LIST psctHookList
);
DWORD RvaToRaw(
	PBYTE pMappedModule,
	DWORD dwRva
);

BOOL MapFromKnownDLLs(
	LPWSTR wszModuleName,
	PBYTE* ppModuleData,
	PHANDLE phFileToClose
);
BOOL MapFromFileSystem(
	LPWSTR wszModuleName,
	PBYTE* ppModuleData,
	PHANDLE phFileToClose,
	PHANDLE phFileMappingToClose
);
BOOL MapTargetModule(
	LPWSTR wszModuleName,
	PBYTE* ppMappedAddress,
	PBOOL pbIsManuallyMapped,
	PHANDLE phFileToClose,
	PHANDLE phFileMappingToClose
);

BOOL ProcessModuleComparison(
	PBYTE pLoadedModuleAddress,
	PBYTE pMappedModuleAddress,
	BOOL bIsManuallyMapped,
	PHOOK_LIST* ppsctHookList
);
BOOL CompareBytes(
	PBYTE pLoadedBase,
	PBYTE pLoadedText,
	PBYTE pMappedText,
	DWORD dwTextSize,
	PHOOK_LIST* ppsctHookList
);

VOID StuffIAT(
	void
);


typedef NTSTATUS(NTAPI* fnNtOpenSection)(
	_Out_ PHANDLE SectionHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes
);