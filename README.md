# Offensive-PowerShell
Collection of powershell scripts to be used during an offensive operation.   

## Set-FilelessBypassUac
Bypass the Windows User Account Control (UAC) with fileless methods.

Based on “Fileless” UAC Bypass Using eventvwr.exe and Registry Hijacking technique from Matt Nelson (@enigma0x3).
https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/

METHODS:

* mscfile - Matt Nelson (@enigma0x3) method using CompMgmtLauncher.exe to replace eventvwr.exe.
    Working on:
    *  Microsoft Windows 7;
    *  Microsoft Windows 8;
    *  Microsoft Windows 8.1;
    *  Microsoft Windows 10 (UNTIL the build 15025.rs2)
    *  Microsoft Windows 2008;
    *  Microsoft Windows 2008 R2;
    *  Microsoft Windows 2016.

* ms-settings - NEW method using ms-settings registry key with DelegateExecute and fodhelper.exe.
    Working on:
    *  Microsoft Windows 10 (tested with successful until the build 15031.rs2)
    *  Microsoft Windows 2016.
