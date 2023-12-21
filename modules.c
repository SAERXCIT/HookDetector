#include "common.h"


BOOL GetLoadedModuleList(
	PMODULE_LIST* ppsctModuleList
) {

	BOOL bSTATE = TRUE;
	PPEB pPEB = NULL;
	PLDR_DATA_TABLE_ENTRY pDte = NULL;
	DWORD dwListSize = 0;
	PMODULE_LIST pTmp = NULL;

#ifdef _WIN64

	pPEB = (PPEB)__readgsqword(0x60);

#else

	pPEB = (PPEB)__readfsdword(0x30);

#endif

	pDte = (PLDR_DATA_TABLE_ENTRY)(pPEB->Ldr->InMemoryOrderModuleList.Flink);

	while (pDte) {

		if (pDte->FullDllName.Length != 0) {

			if (_wcsnicmp(
				&(pDte->FullDllName.Buffer[(pDte->FullDllName.Length / sizeof(WCHAR)) - 4]), // Find the address of the last 4 characters in the module name
				L".DLL",
				4
			) != 0) {

				pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);
				continue;

			}

			if (*ppsctModuleList == NULL) {

				dwListSize = sizeof(MODULE_LIST);
				pTmp = (PMODULE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwListSize);

			}
			else {

				dwListSize += sizeof(MODULE_INFO);
				pTmp = (PMODULE_LIST)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, *ppsctModuleList, dwListSize);

			}

			if (pTmp == NULL) {

				printf("[-] Error allocating memory for module list: %d\n", GetLastError());

				if (*ppsctModuleList != NULL) {
					HeapFree(GetProcessHeap(), 0, *ppsctModuleList);
				}
				return FALSE;

			}


			pTmp->pModuleList[pTmp->wCount].pModuleAddress = (PVOID)pDte->Reserved2[0];
			pTmp->pModuleList[pTmp->wCount].wszModuleName = pDte->FullDllName.Buffer;
			pTmp->wCount++;

			*ppsctModuleList = pTmp;
			pTmp = NULL;

			pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);

		}
		else {

			break;

		}

	}

	return TRUE;

}

BOOL GetModuleSectionHeader(
	PBYTE pModuleAddress,
	LPCSTR szSectionName,
	PIMAGE_SECTION_HEADER* ppImgSectionHdr
) {

	PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)((PBYTE)pModuleAddress + ((PIMAGE_DOS_HEADER)pModuleAddress)->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE) {
		return FALSE;
	}

	PIMAGE_SECTION_HEADER pImgSectionHdr = (PIMAGE_SECTION_HEADER)((PBYTE)pImgNtHdrs + sizeof(IMAGE_NT_HEADERS));

	for (WORD wLoop = 0; wLoop < pImgNtHdrs->FileHeader.NumberOfSections; wLoop++) {

		if (_stricmp(pImgSectionHdr->Name, szSectionName) == 0) {

			*ppImgSectionHdr = pImgSectionHdr;
			return TRUE;

		}

		pImgSectionHdr = (PIMAGE_SECTION_HEADER)((PBYTE)pImgSectionHdr + sizeof(IMAGE_SECTION_HEADER));

	}

	return FALSE;

}

BOOL FindFunctionsFromRVAs(
	PBYTE pModuleAddress,
	BOOL bIsManuallyMapped,
	PHOOK_LIST psctHookList
) {

	DWORD dwLoop = 0;
	WORD wLoop = 0;
	WORD wCurrentFunctionOrdinal = 0;
	DWORD dwCurrentFunctionRVA = 0;
	DWORD dwBestCandidateRVA = 0;
	LPSTR szBestCandidateName = NULL;
	PIMAGE_EXPORT_DIRECTORY pImgExportDir = NULL;
	PWORD pwArrayOfOrdinals = NULL;
	PDWORD pdwArrayOfNames = NULL;
	PDWORD pdwArrayOfRVAs = NULL;

	PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pModuleAddress + ((PIMAGE_DOS_HEADER)pModuleAddress)->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE) {
		return FALSE;
	}

	if (bIsManuallyMapped) {

		pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pModuleAddress + RvaToRaw(pModuleAddress, pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));
		pwArrayOfOrdinals = (PWORD)(pModuleAddress + RvaToRaw(pModuleAddress, pImgExportDir->AddressOfNameOrdinals));
		pdwArrayOfNames = (PDWORD)(pModuleAddress + RvaToRaw(pModuleAddress, pImgExportDir->AddressOfNames));
		pdwArrayOfRVAs = (PDWORD)(pModuleAddress + RvaToRaw(pModuleAddress, pImgExportDir->AddressOfFunctions));

	}
	else {

		pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pModuleAddress + pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
		pwArrayOfOrdinals = (PWORD)(pModuleAddress + pImgExportDir->AddressOfNameOrdinals);
		pdwArrayOfNames = (PDWORD)(pModuleAddress + pImgExportDir->AddressOfNames);
		pdwArrayOfRVAs = (PDWORD)(pModuleAddress + pImgExportDir->AddressOfFunctions);

	}

	// For each function in the module's export directory
	for (dwLoop = 0; dwLoop < pImgExportDir->NumberOfFunctions; dwLoop++) {

		wCurrentFunctionOrdinal = pwArrayOfOrdinals[dwLoop];
		dwCurrentFunctionRVA = pdwArrayOfRVAs[wCurrentFunctionOrdinal];

		// For each mismatch found previously
		for (wLoop = 0; wLoop < psctHookList->wCount; wLoop++) {

			// If the current exported function's RVA is closer to the current closest found, but still before the mismatch address
			if (   dwCurrentFunctionRVA >  psctHookList->pHookList[wLoop].dwBestCandidateRVA
				&& dwCurrentFunctionRVA <= psctHookList->pHookList[wLoop].dwDifferenceRVA) {

				psctHookList->pHookList[wLoop].dwBestCandidateRVA = dwCurrentFunctionRVA;

				if (bIsManuallyMapped) {
					psctHookList->pHookList[wLoop].szBestCandidateName = (LPSTR)(pModuleAddress + RvaToRaw(pModuleAddress, pdwArrayOfNames[dwLoop]));
				}
				else {
					psctHookList->pHookList[wLoop].szBestCandidateName = (LPSTR)(pModuleAddress + pdwArrayOfNames[dwLoop]);
				}

			}

		}

	}

	return TRUE;

}

DWORD RvaToRaw(
	PBYTE pModuleAddress,
	DWORD dwRva
) {

	DWORD dwSectionRawAddr = 0;

	PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pModuleAddress + ((PIMAGE_DOS_HEADER)pModuleAddress)->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE) {
		return FALSE;
	}

	PIMAGE_SECTION_HEADER pImgSectionHdr = (PIMAGE_SECTION_HEADER)((PBYTE)pImgNtHdrs + sizeof(IMAGE_NT_HEADERS));

	// Find the PE section in which the RVA is located
	for (WORD wLoop = 0; wLoop < pImgNtHdrs->FileHeader.NumberOfSections; wLoop++) {

		if(dwRva >= pImgSectionHdr->VirtualAddress && dwRva < pImgSectionHdr->VirtualAddress + pImgSectionHdr->SizeOfRawData){

			// http://www.rohitab.com/discuss/topic/42001-how-to-convert-rva-to-raw-offset/
			return dwRva - pImgSectionHdr->VirtualAddress + pImgSectionHdr->PointerToRawData;

		}

		pImgSectionHdr = (PIMAGE_SECTION_HEADER)((PBYTE)pImgSectionHdr + sizeof(IMAGE_SECTION_HEADER));

	}

	return 0;

}