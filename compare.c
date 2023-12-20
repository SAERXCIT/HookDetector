#include "common.h"

BOOL ProcessModuleComparison(
	PBYTE pLoadedModuleAddress,
	PBYTE pMappedModuleAddress,
	BOOL bIsManuallyMapped,
	PHOOK_LIST* ppsctHookList
) {

	BOOL bSTATE = TRUE;

	PIMAGE_SECTION_HEADER pImgSecHdr = NULL;

	PBYTE pLoadedTextAddress = NULL;
	DWORD dwLoadedTextSize = 0;

	PBYTE pMappedTextAddress = NULL;
	DWORD dwMappedTextSize = 0;
	

	if (!GetModuleSectionHeader(pLoadedModuleAddress, ".text", &pImgSecHdr)) {
		wprintf(L"[-] Could not get .text section address for loaded module\n");
		return FALSE;
	}

	pLoadedTextAddress = pLoadedModuleAddress + pImgSecHdr->VirtualAddress;
	dwLoadedTextSize = pImgSecHdr->SizeOfRawData;

	//wprintf(L"Loaded module:\n\tBase address: %p\n\t.text address: %p\n\t.text size: %x\n\n", pLoadedModuleAddress, pLoadedTextAddress, dwLoadedTextSize);


	if (!GetModuleSectionHeader(pMappedModuleAddress, ".text", &pImgSecHdr)) {
		wprintf(L"[-] Could not get .text section address for mapped module\n");
		return FALSE;
	}

	if (bIsManuallyMapped) {
		pMappedTextAddress = pMappedModuleAddress + pImgSecHdr->PointerToRawData;
	}
	else {
		pMappedTextAddress = pMappedModuleAddress + pImgSecHdr->VirtualAddress;
	}
	dwMappedTextSize = pImgSecHdr->SizeOfRawData;

	//wprintf(L"Mapped module:\n\tBase address: %p\n\t.text address: %p\n\t.text size: %x\n\n", pMappedModuleAddress, pMappedTextAddress, dwMappedTextSize);


	if (!CompareBytes(pLoadedModuleAddress, pLoadedTextAddress, pMappedTextAddress, dwLoadedTextSize, ppsctHookList)) {
		wprintf(L"[-] Error performing comparison for module\n");
		return FALSE;
	}

	return TRUE;

}

BOOL CompareBytes(
	PBYTE pLoadedBase,
	PBYTE pLoadedText,
	PBYTE pMappedText,
	DWORD dwTextSize,
	PHOOK_LIST* ppsctHookList
) {

	DWORD dwLoop = 0;
	DWORD dwListSize = 0;
	PHOOK_LIST pTmp = NULL;

	do {

		if (pLoadedText[dwLoop] != pMappedText[dwLoop]) {

			if (*ppsctHookList == NULL) {

				dwListSize = sizeof(HOOK_LIST);
				pTmp = (PHOOK_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwListSize);

			}
			else {

				dwListSize += sizeof(HOOK_INFO);
				pTmp = (PHOOK_LIST)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, *ppsctHookList, dwListSize);

			}

			if (pTmp == NULL) {

				printf("[-] Error allocating memory for diff list: %d\n", GetLastError());

				if (*ppsctHookList != NULL) {
					HeapFree(GetProcessHeap(), 0, *ppsctHookList);
				}
				return FALSE;

			}

			pTmp->pHookList[pTmp->wCount].dwDifferenceRVA = (PBYTE)(&pLoadedText[dwLoop]) - pLoadedBase;
			pTmp->wCount++;
			*ppsctHookList = pTmp;
			pTmp = NULL;

			dwLoop += 14; // Skip the next 15 bytes when finding a difference (max x86/x64 instruction size), to not return the same hook multiple times
		}

		dwLoop++;

	} while (dwLoop < dwTextSize);

	return TRUE;

}