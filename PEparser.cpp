#include <Windows.h>
#include <ostream>
#include <iostream>
#include <fstream>
#include <string.h>
#include <winnt.h>
#include <inttypes.h>
#include <vector>

// x86_64-w64-mingw32-g++ PEparser.cpp -o pe.exe -fpermissive -Wint-to-pointer-cast

int main()
{
    std::string fileName;
    std:: cout << "[+] Path to your PE file : ";
    std::cin >> fileName ;

    LPCSTR lpcstrFileName = fileName.c_str();

    HANDLE file = CreateFileA(lpcstrFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if(file == INVALID_HANDLE_VALUE)
    {
        std::cout << "[+] Failed to open the file :)" << std::endl;
    }

    DWORD fileSize = GetFileSize(file, NULL);
    LPVOID fileData = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, fileSize);

    DWORD bytesRead;
    BOOL x = ReadFile(file, fileData, fileSize, &bytesRead, NULL);
    if(!x) std::cout  << "[+] Failed to read the file :)" << std::endl;

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileData;

    printf("\n-----------------------------\n");
    printf("|        Dos Header         |\n");
    printf("-----------------------------\n");
    printf("0x%x\te_magic\t\tMagic number\n", dosHeader -> e_magic);
    printf("0x%x\te_cblp\t\tBytes on last page of file\n", dosHeader -> e_cblp);
    printf("0x%x\te_cp\t\tPages in file\n", dosHeader -> e_cp);
    printf("0x%x\te_crlc\t\tRelocations\n", dosHeader -> e_crlc);
    printf("0x%x\te_cparhdr\tSize of header in paragraphs\n", dosHeader->e_cparhdr);
    printf("0x%x\te_minalloc\tMinimum extra paragraphs needed\n", dosHeader -> e_minalloc);
    printf("0x%x\te_maxalloc\tMaximum extra paragraphs needed\n", dosHeader -> e_maxalloc);
    printf("0x%x\te_ss\t\tInitial(relative) Stack Segment value\n", dosHeader -> e_ss);
    printf("0x%x\te_sp\t\tInitial SP Register value\n", dosHeader -> e_sp);
    printf("0x%x\te_csum\t\tChecksum\n", dosHeader -> e_csum);
    printf("0x%x\te_ip\t\tInitial IP value\n", dosHeader -> e_ip);
    printf("0x%x\te_cs\t\tInitial(relative) CS value\n", dosHeader -> e_cs);
    printf("0x%x\te_lfarlc\tFile address of relocation table\n", dosHeader -> e_lfarlc);
    printf("0x%x\te_ovno\t\tOverlay number\n", dosHeader -> e_ovno);
    printf("0x%x\te_oemid\t\tOEM identifier\n", dosHeader -> e_oemid);
    printf("0x%x\te_oeminfo\tOEM information\n", dosHeader -> e_oeminfo);
    printf("0x%x\te_lfanew\tFile address of new exe header\n", dosHeader -> e_lfanew);

    PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((char *)fileData + dosHeader -> e_lfanew);

    printf("\n-----------------------------\n");
    printf("|         Nt Header         |\n");
    printf("-----------------------------\n");
    printf("0x%x\tSignature\tSignature identifying the file as a PE image\n", imageNTHeaders -> Signature);

    PIMAGE_FILE_HEADER fileHeader = reinterpret_cast<PIMAGE_FILE_HEADER>(&imageNTHeaders -> FileHeader);

    printf("\n-----------------------------\n");
    printf("|        File Header        |\n");
    printf("-----------------------------\n");

    std::string machine;
    int machineInt = fileHeader -> Machine;
    if(machineInt == 332)
    {
        machine = "IMAGE_FILE_MACHINE_I386(x86)";
    }else if (machineInt == 512)
    {
        machine = "IMAGE_FILE_MACHINE_IA64(Intel)";
    }else if (machineInt == 34404)
    {
        machine = "IMAGE_FILE_MACHINE_AMD64(x64)";
    }
    printf("0x%x\t%s\tTarget machine for this executable\n", fileHeader -> Machine, machine.c_str());
    printf("0x%x\tNumberOfSections\n", fileHeader -> NumberOfSections);
    printf("0x%x\tSizeOfOptionalHeader\n", fileHeader -> SizeOfOptionalHeader);
    printf("0x%x\tCharacteristics of the image\n", fileHeader -> Characteristics);
    
    IMAGE_OPTIONAL_HEADER optionalHeader = (IMAGE_OPTIONAL_HEADER)(imageNTHeaders->OptionalHeader);
    printf("\n-----------------------------\n");
    printf("|      Optional Header      |\n");
    printf("-----------------------------\n");
    
    WORD magic = optionalHeader.Magic;
    std::string magicValue;
    switch (magic)
    {
    case 0x10b:
        magicValue = "IMAGE_NT_OPTIONAL_HDR32_MAGIC";
        break;
    case 0x20b:
        magicValue = "IMAGE_NT_OPTIONAL_HDR64_MAGIC";
        break;
    case 0x107:
        magicValue = "IMAGE_ROM_OPTIONAL_HDR_MAGIC";
        break;
    default:
        magicValue = "default case";
        break;
    }

    printf("0x%x\t\t%s\tMagic\n", magic, magicValue.c_str());
    printf("0x%x\t\tMajorLinkerVersion\n", optionalHeader.MajorLinkerVersion);
    printf("0x%x\t\tMinorLinkerVersion\n", optionalHeader.MinorLinkerVersion);
    printf("0x%x\t\tSizeOfCode\n", optionalHeader.MinorLinkerVersion);
    printf("0x%x\t\tSizeOfInitializedData\n", optionalHeader.SizeOfInitializedData);
    printf("0x%x\t\tSizeOfUnintializedData\n", optionalHeader.SizeOfUninitializedData);
    printf("0x%x\t\tAddressOfEntryPoint\n", optionalHeader.AddressOfEntryPoint);
    printf("0x%x\t\tBaseOfCode\n", optionalHeader.BaseOfCode);
    // printf("0x%x\tBaseOfData\n", optionalHeader.BaseOfData);
    printf("0x%x\tImageBase\n", optionalHeader.ImageBase);
    printf("0x%x\t\tSectionAlignment\n", optionalHeader.SectionAlignment);
    printf("0x%x\t\tFileAlignment\n", optionalHeader.FileAlignment);
    printf("0x%x\t\tMajorOperatingSystemVersion\n", optionalHeader.MajorOperatingSystemVersion);
    printf("0x%x\t\tMinorOperatingSystemVersion\n", optionalHeader.MinorOperatingSystemVersion);
    printf("0x%x\t\tMajorImageVersion\n", optionalHeader.MajorImageVersion);
    printf("0x%x\t\tMinorImageVersion\n", optionalHeader.MinorImageVersion);
    printf("0c%x\t\tMajorSubsytemVersion\n", optionalHeader.MajorSubsystemVersion);
    printf("0x%x\t\tMinorSubsystemVersion\n", optionalHeader.MinorSubsystemVersion);
    printf("0x%x\t\tWin32VersionValue\n", optionalHeader.Win32VersionValue);
    printf("0x%x\t\tSizeOfImage\n", optionalHeader.SizeOfImage);
    printf("0x%x\t\tSizeOfHeaders\n", optionalHeader.SizeOfHeaders);
    printf("0x%x\t\tCheckSum\n", optionalHeader.CheckSum);
    printf("0x%x\t\tSubsystem\n", optionalHeader.Subsystem);
    printf("0x%x\t\tDllCharacteristics\n", optionalHeader.DllCharacteristics);
    printf("0x%x\tSizeOfStackReserve\n", optionalHeader.SizeOfStackReserve);
    printf("0x%x\t\tSizeOfStackCommit\n", optionalHeader.SizeOfStackCommit);
    printf("0x%x\tSizeOfHeapReserve\n", optionalHeader.SizeOfHeapReserve);
    printf("0x%x\t\tSizeOfHeapCommit\n", optionalHeader.SizeOfHeapCommit);
    printf("0x%x\t\tLoaderFlags\n", optionalHeader.LoaderFlags);
    printf("0x%x\t\tNumberOfRvaAndSizes\n", optionalHeader.NumberOfRvaAndSizes);
    printf("0x%x\tDataDirectory\n", optionalHeader.DataDirectory);

    PIMAGE_DATA_DIRECTORY dataDirectory = (PIMAGE_DATA_DIRECTORY)(optionalHeader.DataDirectory);
    printf("\nAddress\tSize\tData Directory\n");
    printf("-------\t----\t--------------\n");
    printf("0x%x\t0x%x\tExport Directory\n", dataDirectory[0].VirtualAddress, dataDirectory[0].Size);
    printf("0x%x\t0x%x\tImport Directory\n", dataDirectory[1].VirtualAddress, dataDirectory[1].Size);
    printf("0x%x\t0x%x\tResource Directory\n", dataDirectory[2].VirtualAddress, dataDirectory[2].Size);
    printf("0x%x\t0x%x\tException Directory\n", dataDirectory[3].VirtualAddress, dataDirectory[3].Size);
    printf("0x%x\t0x%x\tSecurity Directory\n", dataDirectory[4].VirtualAddress, dataDirectory[4].Size);
    printf("0x%x\t0x%x\tBase Relocation Table\n", dataDirectory[5].VirtualAddress, dataDirectory[5].Size);
    printf("0x%x\t0x%x\tDebug Directory\n", dataDirectory[6].VirtualAddress, dataDirectory[6].Size);
    printf("0x%x\t0x%x\tArchitecture Specific Data\n", dataDirectory[7].VirtualAddress, dataDirectory[7].Size);
    printf("0x%x\t0x%x\tRVA of GlobalPtr\n", dataDirectory[8].VirtualAddress, dataDirectory[8].Size);
    printf("0x%x\t0x%x\tTLS Directory\n", dataDirectory[9].VirtualAddress, dataDirectory[9].Size);
    printf("0x%x\t0x%x\tLoad Configuration Directory\n", dataDirectory[10].VirtualAddress, dataDirectory[10].Size);
    printf("0x%x\t0x%x\tBound Import Directory in Headers\n", dataDirectory[11].VirtualAddress, dataDirectory[11].Size);
    printf("0x%x\t0x%x\tImport Address Table\n", dataDirectory[12].VirtualAddress, dataDirectory[12].Size);
    printf("0x%x\t0x%x\tDelay Load Import Descriptors\n", dataDirectory[13].VirtualAddress, dataDirectory[13].Size);
    printf("0x%x\t0x%x\t.Net header\n", dataDirectory[14].VirtualAddress, dataDirectory[14].Size);

    

    DWORD sectionLocation = (DWORD)imageNTHeaders + sizeof(DWORD) + (DWORD)(sizeof(IMAGE_FILE_HEADER)) + (DWORD)imageNTHeaders->FileHeader.SizeOfOptionalHeader;
    DWORD sectionSize = (DWORD)sizeof(IMAGE_SECTION_HEADER);

    DWORD importDirectoryRVA = dataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

    printf("\n-----------------------------\n");
    printf("|       Section Header      |\n");
    printf("-----------------------------\n");

    printf("Name\tRaw Addr\tRaw Size\t Virtual Addr\tVirtual Size\tCharc\t\tPtr to Reloc\tNo of Reloc\tNo of Linear\n");

    PIMAGE_SECTION_HEADER importSection = {};
    for(int i=0; i<imageNTHeaders->FileHeader.NumberOfSections; i++)
    {
        PIMAGE_SECTION_HEADER sectionHeader = reinterpret_cast<PIMAGE_SECTION_HEADER>(sectionLocation);
        printf("%s\t%x\t\t%x\t\t%x\t\t%x\t\t%x\t\t%x\t\t%x\t\t%x\n", sectionHeader->Name, sectionHeader->PointerToRawData, sectionHeader->SizeOfRawData, sectionHeader->VirtualAddress, sectionHeader->Misc.VirtualSize, sectionHeader->Characteristics, sectionHeader->PointerToRelocations, sectionHeader->NumberOfRelocations, sectionHeader->NumberOfLinenumbers);
        
        if(importDirectoryRVA >= sectionHeader->VirtualAddress && importDirectoryRVA < sectionHeader->VirtualAddress + sectionHeader->Misc.VirtualSize)
        {
            importSection = sectionHeader;
        }
        sectionLocation += sectionSize;
    }

    DWORD rawOffset = (DWORD)fileData + importSection->PointerToRawData;
    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(rawOffset + (importDirectoryRVA-importSection->VirtualAddress));


    printf("\n-----------------------------\n");
    printf("|      Imports and DLLs      |\n");
    printf("-----------------------------\n");
    for(; importDescriptor->Name != 0; importDescriptor++)
    {
        printf("\n%s\t%d\t0x%x\t%d\t0x%x\t0x%x\n\n", rawOffset+importDescriptor->Name-importSection->VirtualAddress, importDescriptor->Characteristics, importDescriptor->OriginalFirstThunk, importDescriptor->TimeDateStamp, importDescriptor->ForwarderChain, importDescriptor->FirstThunk);

        DWORD thunk = importDescriptor->OriginalFirstThunk == 0 ? importDescriptor->FirstThunk : importDescriptor->OriginalFirstThunk;
        PIMAGE_THUNK_DATA thunkData = (PIMAGE_THUNK_DATA)(rawOffset + (thunk - importSection->VirtualAddress));

        for(; thunkData->u1.AddressOfData != 0; thunkData++)
        {
            if(thunkData->u1.AddressOfData>0x80000000)
            {
                printf("0x%x\n", (WORD)thunkData->u1.AddressOfData);
            }else
            {
                printf("%s\n", (rawOffset+(thunkData->u1.AddressOfData-importSection->VirtualAddress+2)));
            }
        }
    }

    return 0;
}
