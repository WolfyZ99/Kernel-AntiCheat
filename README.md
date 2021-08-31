# KernelMode AntiCheat Demo Project
---------------------------------------------------------------------------------------------------------

Just a sample of how you can code a basic AntiCheat nowadays. Please note that this project is completely unfinished as it was just a part of my Bachelor's Final Project.
This shit has been developed in less that a week so don't expect something serious here as I only made basic process protection as well as basic manually mapped drivers detection.
I'll probably contribute more in the future if I'll get more free time.

# What's done here?

## Driver
- Uses IOCTL for UM client to communicate with the Driver (access allowed for Client & Game only)
- Dynamic imports resolver for both ntoskrnl.exe & CI.dll
- Strip handles for Protected Process via PreObCallback
- Runtime Protected Process pickup via LoadImage Callback
- Protected Process validation by verifying it's Digital Signature via MS Code Integrity (CI.dll) -> honestly the most interesting part here.
- Various System Threads scans for mapped drivers (Win32StartAddress + KernelStack)
- Driver Dispatch scanning for mapped drivers
- PiDDBCache scanning (doing this in 2021 is pretty meme but who cares lol)

### TODO:
MINIFILTER!!! Never do that shitty LoadLibrary hooking in UM I've done here!
The only reason I made it this way is that I had no time to develop proper MiniFilter.
That's probably the first thing I should fix in this project.

## Client
- Load the Driver, spawning Protected Process
- Dump ntoskrnl's PDB for some offsets
- Send requests for Driver to collect Kernel Detection info
- Scan and collect all Windows on-top of test "Game" Window
- Send all the info to the server via sockets

## Server
- Multithreaded TCP done via Poco Library
- Receive data from Clients and update SQL DB using collected data

## DLL
- The most useless part here as only thing it does is just hooking LoadLibrary
- No real internal detection were done here


