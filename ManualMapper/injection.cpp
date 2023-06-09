#include"injection.h"

//! Create a ShellCode Funtion taking pointer to manual mapping data

void __stdcall ShellCode(MANUAL_MAPPING_DATA* pData);





bool ManualMap(HANDLE hProc, const char* szDllFile)
{
	BYTE*					pSrcData			= nullptr;
	IMAGE_NT_HEADERS*		pOldNtHeader		= nullptr;
	IMAGE_OPTIONAL_HEADER*	pOldOptHeader		= nullptr;
	IMAGE_FILE_HEADER*		pOldFileHeader		= nullptr;
	BYTE*					pTargetBase			= nullptr;
	
//x IMAGE_SECTION_HEADER*      pSectionHeader         = nullptr;
	//! Check if file exists and path szDllFile is actually valid
	

	if (!GetFileAttributesA(szDllFile))
	{
		printf("File does not exist \n");
		return false;
	}
	//! Creates and "opens automatically"  an ifstream File object with szDllFile buffer_path 
	//!Creates In binary mode and seeks to the end of stream object with parameter std::ios::ate
	std::ifstream File{ szDllFile,std::ios::binary | std::ios::ate }; 

	if (File.fail())
	{
	printf("Opening the file failed: %X\n", (DWORD)File.rdstate()); //!Return currently set flag of Filestate
	return false;
	}

	//!Initialize filesize variable and check for its size
	auto FileSize = File.tellg(); //!tellg() returns absolute position of file pointer
	if (FileSize < 0x1000) //? Why fileSize should be graeter than 4096 bytes a size of normal page???
	{
		printf(" Fileszie is invalid.\n");
		File.close(); //! close() member function closes file object explicitly
		return false;

	}
//! Dynamically heap allocate memory for the size of File-view
//! Dynamic Memory allocation with new for mapping dll File-view 
//! Processes read from and write to the file view using pointers, 
//! just as they would with dynamically allocated memory
//! 	BYTE* pSrcData has been assigned an array of BYTE using new BYTE[] arary form of new
	pSrcData = new BYTE[static_cast<UINT_PTR>(FileSize)];
	if (!pSrcData)
	{
		printf("Dynamic array  Memory allocation with new 'type' [] for mapping dll File-view failed");
		File.close(); //! close the file object
		return false;
	}

	File.seekg(0, std::ios::beg); //! setting the file pointer to the beginning of the file

	//! Use ifstream object associated with File  to read from File and copy contents to  allocated array of BYTE named pSrcData
	File.read(reinterpret_cast<char*>(pSrcData), FileSize);

	File.close(); // Close the file opened automatically by constructor of ifStream object

	//! Check the copid file data in BYTE array to be an actual Dll file
	if (reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_magic != 0x5A4D) //! magic number MZ
	{
		printf("Invalid file read from szDllFile to pSrcData dynamically allocated buffer.\n");
		delete[]pSrcData;
		return false;
	}
	//! assign the file offset e_elfanew (a file pointer where PE/NT header will be found) to pOldNTHeader variable:: will point to NtHeader
	pOldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(pSrcData + reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_lfanew);
	pOldOptHeader = &(pOldNtHeader->OptionalHeader);//? why the addressof(&) operand is used when pOldNtHeader is itself a pointer. Prob bcoz '->' Member access from object ptr operator precdence is before '&' operator
	pOldFileHeader = &(pOldNtHeader->FileHeader); //! Gives pointer to embedded(not pointed to)IMAGE_FILEHEADER structure
#ifdef _WIN64
	//! Check for word field Machine of IMAGE_FILE_HEADER to determine the arch 32/64 bit of binary
	if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_AMD64)
	{
		printf("Inavalid paltform\n");
		delete[] pSrcData;
		return false;
	}

#else
	if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_I386)
	{
		printf(" Invald platform\n");
		delete[] pSrcData;
		return false;
	}

#endif
	//! alllocating memory in target process
	//! The memory allocated will be at preffered image base of the Dll to match the original dlll
	//! The size allocated will be the size mentioned in OptionalHaeder amount of contiguous memory reserved to laod the binary into memory
	pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, reinterpret_cast<void*>(pOldOptHeader->ImageBase), pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

	if (!pTargetBase) //! If the memory cannot be allocated at preffered imagebase allocate it to some free space in target process as decided  by Os
	{
		pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
		if (!pTargetBase)
		{
			printf("Memory Allocation failed (ex) 0x%X\n", GetLastError());
			delete[]pSrcData;
			return false;
		}

	}

	//! now map and allocate the section headers for original dll file; Initilaize manual mappind data struct
	
	MANUAL_MAPPING_DATA data{};
	data.pLoadLibraryA = &LoadLibraryA; //! & operator can be ommited as function name implicitly convert to function pointers
	// ! The function address of GetProcAddress casted to f_GetProcAddress type of function pointer alias
	data.pGetProcAddress = reinterpret_cast<f_GetProcAddress> (&GetProcAddress);
	//! Mapping of section header as per loaction in Pe file structure
	//!// IMAGE_FIRST_SECTION doesn't need 32/64 versions since the file header is the same either way.
	//! macro used: IMAGE_FIRST_SECTION see reference
	//xauto* pFirstSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader); OR else

	WORD sizeOfOptionalHeader = pOldFileHeader->SizeOfOptionalHeader; //! gives the end size of optional header
	WORD numberOfSections = pOldFileHeader->NumberOfSections;

	PIMAGE_SECTION_HEADER pSectionHeader{};

	//! Recasting to (PBYTE) is a must for Pointer arithmetic as we want to advance BYTE by BYTE
	//! This will give loaction first byte pointer to first section header in pe file
	pSectionHeader = reinterpret_cast<PIMAGE_SECTION_HEADER>(reinterpret_cast<PBYTE>(pOldOptHeader) + sizeOfOptionalHeader);

	//! Loop through all sections for parsing
	
	for (size_t i{0}; i != numberOfSections; ++i, ++pSectionHeader)// USES POINTER ARITHMETIC FOR ADVANCING AHEAD EACH SECTION ON pFirstSectionHEader
	{
		//?? Copying will be only done when section header is having sizeOfRawData field non-null
		if (pSectionHeader->SizeOfRawData)
		{
		//! VirtualAddress field of section header is RVA of section realtive to OPTIONAL_HEADER.ImageBase in mapped file
		//! So we wiil write our section information at that point in allocated memory
		//! Section information data  will be at relative file offset from begiining of file infrmation
		//! This is actually PointertoRawData field of the SectionHeader structure
		//! Size of section will sizeofRawData field Use WPM now
			if (!WriteProcessMemory(hProc, pTargetBase + pSectionHeader->VirtualAddress, pSrcData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, nullptr))

			{
				//! Error checking on failure
				
				printf(" Cant map sections: 0x%X\n", GetLastError());
				delete[]pSrcData;
				VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);

			}
		}


	}

	//? We shall be using pData member as baseaddress or new Base 
	// for it to be mapped as module in shellcode and other actualdata 
	//! So we need to write pData in pTargetBase  address
	//! copy the maual mapping data to sourcedata psrcData where our dll file information has been copied by ifstream file object
	memcpy(pSrcData, &data, sizeof(data));

	//? Why 0x1000 bytes of memorysize choosen to write the pSrcData
	//! WPM will write the copied file object pSrcData to the Target Base address
	WriteProcessMemory(hProc, pTargetBase,pSrcData, 0x1000, nullptr);

	//! After copyig of sections BYTE array pSrcData can be deleted as no use now
	delete[] pSrcData;

	//!Alloacte memory for storing of shellCode data 
	void* pShellCode = VirtualAllocEx(hProc, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	
	if (!pShellCode) //! if memory alocation fails then error checking
	{
		printf("Memory allocation failed.(ex)0x%X\n", GetLastError());
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		return false;

	}
	
	//!Write the ShellCode function address to pShellCode allocated memory
	WriteProcessMemory(hProc, pShellCode, ShellCode, 0x1000, nullptr);

	//! Execute the ShellCode function in target process by craeting a remote thread
	HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellCode), pTargetBase, 0, nullptr);
	if (!hThread)
	{
		printf("Thread creation to inject shellCode failed.error:0x%X\n", GetLastError());
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		return false;
	}
	CloseHandle(hThread);

	//! Check if the data writing of hModule at end of ShellCode function 
	//! has been completed by initializing a data_checked variable
	
	HINSTANCE hCheck = NULL;
	while (!hCheck)
	{
		MANUAL_MAPPING_DATA data_checked{ 0 };
		ReadProcessMemory(hProc, pTargetBase, &data_checked, sizeof(data_checked), nullptr);
		hCheck = data_checked.hModule;
		Sleep(10);

	}

	VirtualFreeEx(hProc, pShellCode, 0, MEM_RELEASE);

	return true;
}
//? The calling convention is __stdcall why ??
//! Going to inject shellcode to we can't call any function directly
//? So we have to pass all the functions we need through the structuse  pData 
//! From the structure we can GRAB the functions in form of function pointer
//! Otherwise we will have to relaocte our shellcode???????
//! Pass the address to function using manual Mapping data structure


//! Define Macro to check for type of Relocation Flags in IMAGE_BASE_RELOC structure block s per architecture
#define RELOC_FLAG32(RelInfo) ((RelInfo>>0x0c)==IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo>>0x0c)==IMAGE_REL_BASED_DIR64)
#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif


void __stdcall ShellCode(MANUAL_MAPPING_DATA* pData)
{
	if (!pData)
		return;
	BYTE* pBase = reinterpret_cast<BYTE*>(pData);
	//? Why the pBase aCASTED IN  BYTE* of manual map data is made pDos_HEader
	auto* pOpt = &(reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>(pData)->e_lfanew)->OptionalHeader);

	//! As we are injecting the shell code we cannot call any function
	//? All the functions called are through pData structure to avoid relocation in shellCode
	f_LoadLibraryA _LoadLibraryA   = pData->pLoadLibraryA;
    f_GetProcAddress _GetProcAddress = pData->pGetProcAddress;
	//! DLLMain will be the entry point of DLL
	//!AddressOfEntryPoint is the relative address from base addeess to dll entry point
	f_DLL_ENTRY_POINT _DllMain = reinterpret_cast<f_DLL_ENTRY_POINT>(pBase + pOpt->AddressOfEntryPoint);

	//! Calculate the relocation data If the image was aslred

	BYTE* LocationDelta = pBase - pOpt->ImageBase;

	if (LocationDelta) //! If locationDElta is non-null then image is Aslred
	{
		if (!pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)//! If size of.reloc data directory is Zero it means Image cannot be relocated
			return;

		//! virtual Address is RVa or relative offset from base address of Image 
		//! to first IMAGE_BASE_RELOACTION structure 
		IMAGE_BASE_RELOCATION* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		while (pRelocData->VirtualAddress)// Loop continues till Virtualaddress field is nonZero
		{
			//! Calcuate the amount of base relocation entry in each IMAGE_BASE_RELOC Block structure
			//! //Check life of Binaries PDF to get the formula
			UINT AmountofEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

			//! We are calculating offset of WORD sized RELOCATION TARGET info from pRelocData
			//!Can also be done by casting pRelocData to BYTE* and  adding 8(sizeof(IMAGE_BASE_RELOCATION) to it for Pointer arithmetic
			// WORD* pRelocationTargetInfo = reinterpret_cast<WORD*>((BYTE*)pRelocData+8);
			WORD* pRelocationTargetInfo = reinterpret_cast<WORD*>(pRelocData + 1);
			for (size_t i = 0; i != AmountofEntries; ++i, ++pRelocationTargetInfo)
			{
				if (RELOC_FLAG(*pRelocationTargetInfo))//! Check for type of Relocation flags
				{
					//! Relative offset to add are lower 12 bits of relocatation info word data
					//! The line calculates the actual place in memroy where relocation has to be applied
					UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + ((*pRelocationTargetInfo) & 0xfff));
					//! Following line adds the delta to the reloacation address found in above line
					*pPatch = *(pPatch)+reinterpret_cast<UINT_PTR>(LocationDelta);
					//x or can be rewritten as *pPatch+=reinterpret_cast<UINT_PTR>(LocationDelta);

				}
			}
			//! Increment instruction for while loop to advance to next relocation block array to get its relocation data
			pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
		}
	}
   
	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
	{
		//! Get the IMAGE_IMPORT_DESCRIPTOR structure at The Virtual address field of IMAGE_DIRECTORY_ENTRY_IMPORT data_directory
		IMAGE_IMPORT_DESCRIPTOR* pImportDesc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (pImportDesc->Name)//!An RVA which point to specific name of module from which imports are taken
		{
			char* szMod = reinterpret_cast<char*>(pBase + pImportDesc->Name);
			HINSTANCE hDll = _LoadLibraryA(szMod);
			//! Both OrigFirstThunk and FirstThunk are pointing to as arrays of IMAGE_THUNK_DATA structures
			ULONG_PTR* pOrgThunkRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDesc->OriginalFirstThunk);
			ULONG_PTR* pFirstThunkRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDesc->FirstThunk);
			if (!pOrgThunkRef)
				pOrgThunkRef = pFirstThunkRef;
			for (; *pOrgThunkRef; ++pOrgThunkRef, pFirstThunkRef)
			{
				if (IMAGE_SNAP_BY_ORDINAL(*pOrgThunkRef))
				{
					//! Casting the GetProcaddres to UINT_ptr as its return type is FARPROC 
					//! 2nd parameter casted to char because _GetProcAddress takes a char*
					*pFirstThunkRef = (UINT_PTR)_GetProcAddress(hDll, reinterpret_cast<char*>(*pOrgThunkRef & 0xffff));
				}
				else
				{
					//! If image is imported by name and not ordinals find IMAGE_IMPORT_BY_NAME stucture and create a pointer to it
					IMAGE_IMPORT_BY_NAME* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + (*pOrgThunkRef));
					*pFirstThunkRef = (UINT_PTR)_GetProcAddress(hDll, pImport->Name);
				}
			}
			//!IMAGE_DIRECTORY_ENTRY_IMPORT virtualaddrs field is RVA pointing to array of IMAGE_IMPORT_DESCRIPTORS
			++pImportDesc; //! Increment instruction for while loop to advance in Importdesc array

		}

	}

	//! Write the Thread local storage callback data if it is Non-null
	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
	{
		IMAGE_TLS_DIRECTORY* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		//! pCallBack is pointer to PIMAGE_TLS_CALLBACK routine functions which is absoulte VA
		//! Callbacks are stored in an array format
		auto* pCallBack = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
		for (; pCallBack && *pCallBack; ++pCallBack)
			(*pCallBack)(pBase, DLL_PROCESS_ATTACH, nullptr);
	}

	//todo to check the below two steps as these may be resulting in exception accessing invalid memory

	_DllMain(pBase, DLL_PROCESS_ATTACH, nullptr); // write the Dll Main entry point function

	//! Assign the manual Mapping Data to pBase
	pData->hModule = reinterpret_cast<HINSTANCE>(pBase);

}
