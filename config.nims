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