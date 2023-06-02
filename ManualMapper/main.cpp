#include"injection.h"


//? use double slash for declaring full path instead of single slash
//! because one single slash does not indicate CHAR but a BYTE instead
//! Though note that in many programming languages like C, C++, Java, C#, Python, PHP, Perl, a backslash works 
//! as an escape character in string literals. As such, it needs to be escaped itself (usually with 
//! another backslash). So in these languages, you usually need to use a double backslash in the string literal
//!  to actually get a single backslash for a path. So for example in C++ code, the following string literal 
//! is actually interpreted as C:\Personal\MyFolder\MyFile.jpg: var path = "C:\\Personal\\MyFolder\\MyFile.jpg";
//todo  backslash is an escape character; double backslash as backslash itself can be escaped with another backslash
//todo a double backslash is just the way you write a single backslash in C++. ONLY FOR PROGRAM CODE
//todo "\\" - this string is a single backslash. "\\\\" - this string is a double backslash.

const char szDLLFile[] = "E:\\GameMod\\crackme\\earlier crackmes assorted\\HelloWorldDll\\hello-world-x64.dll";

const char szProc[] = "Test Console.exe";

//? Change to Multibyte character set and disable Incermental linking in Linker option
//! Manifest option in linker to be changed as require  Admin
int main()
{
	PROCESSENTRY32 PE32{};
	PE32.dwSize = sizeof(PE32);

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE)
	{
		DWORD Err = GetLastError();
		printf("CreateToolhelp32Snapshot failed: %d\n", Err);
		system("PAUSE");
		return 0;
	}
	DWORD PID = 0;
	BOOL bRet = Process32First(hSnap, &PE32);
	while (bRet)
	{

		if (!strcmp(szProc, PE32.szExeFile))
		{
			PID = PE32.th32ProcessID;
			break;

		}

		bRet = Process32Next(hSnap, &PE32);
	}

	CloseHandle(hSnap);
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
	if (!hProc)
	{
		DWORD Err = GetLastError();
		printf("OpenProcess failed: %d\n", Err);
		system("PAUSE");
		return 0;
	}
	if (!ManualMap(hProc, szDLLFile))
	{
		CloseHandle(hProc);
		printf(" Manual map function failed for some reason.\n");
		//!This is a Windows-specific command, which tells the OS to run the pause program.This program waits 
		//! to be terminated, and halts the exceution of the parent C++ program.Only after the 
		//! pause program is terminated, will the original program continue.
		system("PAUSE");
		return 0;

	}


}