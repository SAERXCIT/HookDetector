#include "common.h"

BOOL ProcessModule(MODULE_INFO sctModuleInfo) {

	BOOL bSTATE = TRUE;
	BOOL bIsManuallyMapped = FALSE;

	PBYTE pMappedAddress = NULL;

	HANDLE hFileToClose = INVALID_HANDLE_VALUE;
	HANDLE hFileMappingToClose = NULL;

	PHOOK_LIST psctHookList = NULL;

	WORD wLoop = 0;

	if (!MapTargetModule(sctModuleInfo.wszModuleName, &pMappedAddress, &bIsManuallyMapped , &hFileToClose, &hFileMappingToClose) || pMappedAddress == NULL) {

		wprintf(L"[-] Could not map target module %ws in memory\n", sctModuleInfo.wszModuleName);
		bSTATE = FALSE; goto _EndOfFunc;

	}

	if (!ProcessModuleComparison(sctModuleInfo.pModuleAddress, pMappedAddress, bIsManuallyMapped, &psctHookList)) {

		wprintf(L"[-] Could not process differences for module %ws\n", sctModuleInfo.wszModuleName);
		bSTATE = FALSE; goto _EndOfFunc;

	}

	if (psctHookList != NULL) {

		if (!FindFunctionsFromRVAs(pMappedAddress, bIsManuallyMapped, psctHookList)) {

			wprintf(L"[-] Could not find functions for RVAs in module %ws\n", sctModuleInfo.wszModuleName);
			bSTATE = FALSE; goto _EndOfFunc;

		}

		wprintf(L"[+] In module %ws: \n", sctModuleInfo.wszModuleName);

		for (wLoop = 0; wLoop < psctHookList->wCount; wLoop++) {

			if (psctHookList->pHookList[wLoop].szBestCandidateName != NULL) {
				printf("\t[*] Hook found at RVA 0x%x in function %s (at RVA 0x%x)\n", psctHookList->pHookList[wLoop].dwDifferenceRVA,
					   psctHookList->pHookList[wLoop].szBestCandidateName, psctHookList->pHookList[wLoop].dwBestCandidateRVA);
			}
			else {
				printf("\t[*] Hook found at RVA 0x%x in unknown function\n", psctHookList->pHookList[wLoop].dwDifferenceRVA);
			}

		}

	}

_EndOfFunc:
	if (pMappedAddress != NULL && pMappedAddress != INVALID_HANDLE_VALUE)
		UnmapViewOfFile(pMappedAddress);
	if (hFileMappingToClose != NULL && hFileMappingToClose != INVALID_HANDLE_VALUE)
		CloseHandle(hFileMappingToClose);
	if (hFileToClose != NULL && hFileToClose != INVALID_HANDLE_VALUE)
		CloseHandle(hFileToClose);
	if (psctHookList != NULL)
		HeapFree(GetProcessHeap(), 0, psctHookList);

	return bSTATE;

}

int wmain(int argc, wchar_t** argv) {

	PMODULE_LIST psctModuleList = NULL;
	WORD wLoop = 0;

	wprintf(L"[*] Sleeping for 2 seconds to let all initialization and hooking happen...\n");
	Sleep(2000);

	if (!GetLoadedModuleList(&psctModuleList) || psctModuleList == NULL) {

		wprintf(L"[-] Could not get the list of loaded modules\n");
		return -1;

	}

	for (wLoop = 0; wLoop < psctModuleList->wCount; wLoop++) {

		wprintf(L"[*] Analyzing module %ws...\n", psctModuleList->pModuleList[wLoop].wszModuleName);
		ProcessModule(psctModuleList->pModuleList[wLoop]);

	}

	HeapFree(GetProcessHeap(), 0, psctModuleList);

	return 0;

}