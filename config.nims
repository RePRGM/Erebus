#
# NimScript build file for Erebus
# Run with "nim build"
#

switch("verbosity", "1")
switch("warnings", "off")
switch("hints", "off")

task build, "Build Erebus":
    echo "Building Erebus..."
    exec "nim c -d:noRes -d:release --cpu:amd64 --opt:size erebus.nim"

task dependencies, "Install Dependencies":
    echo "Installing Dependencies..."

    echo "Installing Winim"
    exec "nimble install winim"

    echo "Installing ptr_math"
    exec "nimble install ptr_math"

    echo "Installing argparse"
    exec "nimble install argparse"

    echo "Installing nimcrypto"
    exec "nimble install nimcrypto"