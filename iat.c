#include "common.h"
#define SECURITY_WIN32
#include <security.h>
#include <ShlObj.h>
#include <bcrypt.h>
#include <wincrypt.h>
#define PSAPI_VERSION 1
#include <psapi.h>
#include <winsock.h>

#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "Ws2_32.lib")

VOID StuffIAT(
	void
) {

	// The address of this function will never be 0xFFFFFF[...]
	// But the compiler won't realize that and won't optimize this block out
	if ((PVOID)(&StuffIAT) > (PVOID)-2) {

		MessageBoxA(NULL, NULL, NULL, 0);	// user32.dll
		CopySid(0, NULL, NULL);				// Secur32.dll
		GetUserNameExA(0, NULL, NULL);			// advapi32.dll
		SHGetSettings(NULL, 0);					// shell32.dll
		BCryptCreateContext(0, NULL, NULL);		// bcrypt.dll
		CryptMemAlloc(0);						// crypt32.dll
		GetPerformanceInfo(NULL, 0);			// psapi.dll
		WSAGetLastError();		// ws2_32.dll

	}

}