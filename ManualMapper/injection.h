#pragma once
#include<windows.h>
#include<iostream>
#include<fstream>
#include<TlHelp32.h>

//! "typedef decltype(&MyFunction) MyFunctionPtrAlias; 
//! "evaluates to just what we’d expect :"typedef void (*MyFunctionPtrAlias)(int arg1, int arg2);

using f_LoadLibraryA = HMODULE(WINAPI*)(_In_ LPCSTR lpLibFileName); // LoadLibraryA function poiter typedef alias

using f_GetProcAddress = FARPROC(WINAPI*)(_In_ HMODULE hModule, LPCSTR lpProcName); //GetProcAddres function pointer typedef alias

using f_DLL_ENTRY_POINT = BOOL(WINAPI*)(void* hDll, DWORD dwReason, void* pReserved);


// ! manual mapping data is struct containing function pointers and and 
struct MANUAL_MAPPING_DATA
{
	f_LoadLibraryA pLoadLibraryA{};
	f_GetProcAddress pGetProcAddress{};
	HMODULE hModule{};

};

bool ManualMap(HANDLE hProc, const char* szDllFile); // szDllfile is full dll path