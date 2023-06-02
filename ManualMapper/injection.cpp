#include"injection.h"

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
	pSrcData = new BYTE[static_cast<UINT_PTR>(FileSize)];
	if (!pSrcData)
	{
		printf("Dynamic Memory allocation with new for mapping dll File-view failed");
		File.close(); //! close the file object
		return false;
	}

	File.seekg(0, std::ios::beg); //! setting the file pointer to the beginning of the file
	//! Read the ifstream FIle object  
	File.read(reinterpret_cast<char*>(pSrcData), FileSize);
	File.close(); // Close the file opened automatically 

	//! Check the file to be an actual Dll file
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

	if (pTargetBase)
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
	data.pLoadLibraryA = &LoadLibraryA; //! & operatorcan be ommited as function name implicitly convert to function pointers
	data.pGetProcAddress = &GetProcAddress;
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

}