#if defined(WIN32) || defined(WIN64)

#include <Windows.h>
#include <stdio.h>

void get_machine_guid()
{
	HKEY hKey = 0;
	char buf[255] = { 0 };
	DWORD dwType = 0;
	DWORD dwBufSize = 255;
	const wchar_t* subkey = L"Software\\Microsoft\\Cryptography";

	if (RegOpenKey(HKEY_LOCAL_MACHINE, subkey, &hKey) == ERROR_SUCCESS)
	{
		dwType = REG_SZ;
		if (RegQueryValueEx(hKey, L"MachineGuid", 0, &dwType, (BYTE*)buf, &dwBufSize) == ERROR_SUCCESS)
		{
			printf("MachineGuid: %s\n", buf);
		}
		else
			printf("Can not query for key value\n");

		RegCloseKey(hKey);
	}
	else {
		printf("Can not open key\n");
	}
}

#endif