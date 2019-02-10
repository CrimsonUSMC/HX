##Created by Patrick Cartos
##2/9/2019
##e-mail - cartos8992@gmail.com
##github - https://github.com/CrimsonUSMC
##Works with appliance version 4.7 and below and Agent version 29 and below

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()

Function Ignore-SelfSignedCerts {
# Enables the use of Self Signed Certs
    try
    {
 
        Write-Host "Adding TrustAllCertsPolicy type." -ForegroundColor White
        Add-Type -TypeDefinition  @"
        using System.Net;
        using System.Security.Cryptography.X509Certificates;
        public class TrustAllCertsPolicy : ICertificatePolicy
        {
                public bool CheckValidationResult(
                ServicePoint srvPoint, X509Certificate certificate,
                WebRequest request, int certificateProblem)
                {
                    return true;
            }
        }
"@
 
        Write-Host "TrustAllCertsPolicy type added." -ForegroundColor White
        }
    catch
        {
        Write-Host $_ -ForegroundColor "Yellow"
        }
 
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    }

Function HX-Auth {
# Authenticates to the HX Server and returns a user Token
 
    # Prompts for and processes API user creds   
    $c = Get-Credential
    $global:username = $c.username
    $cpair = "$($c.username):$($c.GetNetworkCredential().Password)"
    $key = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($cpair))
   
    # Required Header info
    $header = @{
        "Accept" = "application/json"
        "Authorization" = "Basic $key"
        }
    
    # Authenticates to the HX server
    $gettoken = Invoke-WebRequest -Uri "$FireEyeUrl/hx/api/v3/token" -Headers $header -Method Get -UseBasicParsing
 
    $token = $gettoken.Headers.'X-FeApi-Token'
    $token
 

    ##Other Authentication Methods
        #$global:Server = "10.27.4.76" 
        #$global:Port = "3000"

        #param(
        #    [string]$Server,
        #    [string]$Port
        #    )

    }

Function saveFile($initialDirectory,$Title,$SaveAs){
    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") |
    Out-Null
 
    $SaveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
    $SaveFileDialog.Title = "$Title"
    $SaveFileDialog.initialDirectory = $initialDirectory
    $SaveFileDialog.FileName = "$SaveAs"
    $SaveFileDialog.filter = "All files (*.*)|*.*"
    $SaveFileDialog.ShowDialog() | Out-Null
    $SaveFileDialog.ShowHelp = $true
    $SaveFileDialog.filename
}
 
Function HX-DeAuth($token) {
# Logs off API user of supplied Token
 
    # Required Header info
    $header = @{
        "Accept" = "application/json"
        "X-FeApi-Token" = "$global:Token"
        }
   
    $apiLogOff = Invoke-WebRequest -Uri "$FireEyeUrl/hx/api/v3/token" -Headers $header -Method Delete -UseBasicParsing
 
    $apiLogOff
 
    }
  
Function HX-Get-Hosts($token) {
# Gets Info for All hosts in HX
 
    # Required Header info
    $header = @{
        "Accept" = "application/json"
        "X-FeApi-Token" = "$global:Token"
        }
    # Gets info on all hosts in HX (Notice the "...?limit=35000" and
    # increase/decrease depending on number of agents in HX)    #
    $FireEyeHosts = Invoke-RestMethod -Uri "$FireEyeUrl/hx/api/v3/hosts?limit=35000" -Headers $header -Method Get
 
    $FireEyeHosts
 
    }

Function HX-Get-Alerts($token) {
# Gets Info for All hosts in HX
 
    # Required Header info
    $header = @{
        "Accept" = "application/json"
        "X-FeApi-Token" = "$global:Token"
        }
    # Gets info on all hosts in HX (Notice the "...?limit=35000" and
    # increase/decrease depending on number of agents in HX)    #
    $FireEyeAlerts = Invoke-RestMethod -Uri "$FireEyeUrl/hx/api/v3/alerts" -Headers $header -Method Get
 
    $FireEyeAlerts
 
    }

Function HX-Get-Indicators($token) {
# Gets Info for All hosts in HX
 
    # Required Header info
    $header = @{
        "Accept" = "application/json"
        "X-FeApi-Token" = "$global:Token"
        }
    # Gets info on all hosts in HX (Notice the "...?limit=35000" and
    # increase/decrease depending on number of agents in HX)    #
    $FireEyeindicators = Invoke-RestMethod -Uri "$FireEyeUrl/hx/api/v3/indicators/" -Headers $header -Method Get
 
    $FireEyeindicators
 
    }

Function HX-Get-scripts($token) {
# Gets Info for All hosts in HX
 
    # Required Header info
    $header = @{
        "Accept" = "application/json"
        "X-FeApi-Token" = "$global:Token"
        }
    # Gets info on all hosts in HX (Notice the "...?limit=35000" and
    # increase/decrease depending on number of agents in HX)    #
    $FireEyescripts = Invoke-RestMethod -Uri "$FireEyeUrl/hx/api/v3/scripts?limit=35000" -Headers $header -Method Get
 
    $FireEyescripts
 
    }

Function HX-Get-directory($token) {
# Gets Info for All hosts in HX
 
    # Required Header info
    $header = @{
        "Accept" = "application/json"
        "X-FeApi-Token" = "$global:Token"
        }
    # Gets info on all hosts in HX (Notice the "...?limit=35000" and
    # increase/decrease depending on number of agents in HX)    #
    $FireEyedirectory = Invoke-RestMethod -Uri "$FireEyeUrl/hx/api/v3/indicators/Custom" -Headers $header -Method Put
 
    $FireEyedirectory
 
    }

Function HX-Delete-Host($AgentID,$token){
# Delete Host based off Agent ID
 
    $header = @{
        "Accept" = "application/json"
        "X-FeApi-Token" = "$global:Token"
        }
   
    $DeleteHost = Invoke-RestMethod -Uri "$FireEyeUrl/hx/api/v3/hosts/$AgentID" -Headers $header -Method Delete
       
    $DeleteHost.StatusCode
    }
 
Function Get-Dedup-Hosts{

    $hxGet = HX-Get-Hosts -Token $global:Token
 
    # Creates and Organizes a usful host list from the data recieved
    Write-Host "Getting Host info from HX" -ForegroundColor Cyan
    $hosts = $hxGet.data.entries | select _id,agent_version,hostname,last_audit_timestamp |
        Sort-Object -Property hostname #, last_audit_timestamp -Descending
 
    # Identifies unique hosts   
    $uniqueHosts = $hosts | Sort-Object -Unique hostname #-Descending
 
    # Creates a list of just the duplicate hosts
    $fhosts= @()
    $c1 = 0
    Foreach($h in $hosts){
   
        $c1++
        Write-Progress -Activity "Identifying Duplicates" -Status "Processing" -PercentComplete (($c1 / $hosts.Count)*100)
 
        if($h -notin $uniqueHosts){
            $fhosts += $h
            }
           
        }
    $fhosts = $fhosts | Sort-Object hostname -Unique
    $rhosts = @()

    foreach($r in $fhosts){

    $rhosts += ($hosts | ?{$_.hostname -match $r.hostname} | Sort-Object last_audit_timestamp -Descending | Select-Object -Skip 1)

    }

    $dedupbox.text = $rhosts
}

Function HX-Dedup-Hosts{

    $hxGet = HX-Get-Hosts -Token $global:Token
 
    # Creates and Organizes a usful host list from the data recieved
    Write-Host "Getting Host info from HX" -ForegroundColor Cyan
    $hosts = $hxGet.data.entries | select _id,agent_version,hostname,last_audit_timestamp |
        Sort-Object -Property hostname #, last_audit_timestamp -Descending
 
    # Identifies unique hosts   
    $uniqueHosts = $hosts | Sort-Object -Unique hostname #-Descending
 
    # Creates a list of just the duplicate hosts
    $fhosts= @()
    $c1 = 0
    Foreach($h in $hosts){
   
        $c1++
        Write-Progress -Activity "Identifying Duplicates" -Status "Processing" -PercentComplete (($c1 / $hosts.Count)*100)
 
        if($h -notin $uniqueHosts){
            $fhosts += $h
            }
           
        }
    $fhosts = $fhosts | Sort-Object hostname -Unique
    $rhosts = @()

    foreach($r in $fhosts){

    $rhosts += ($hosts | ?{$_.hostname -match $r.hostname} | Sort-Object last_audit_timestamp -Descending | Select-Object -Skip 1)

    }
  
    # Verifies that you would like to remove the hosts from HX and saves a log file if you continue.
    Write-Host "You are about to remove $($rhosts.Count) hosts from HX." -ForegroundColor Red
    $continue = Read-Host "Do you wish to continue? (y/n): "

 
    if($continue -ieq 'y'){
        # Removes hosts
        $c2 = 0
        Foreach($id in $rhosts._id){
   
            $c2++
            Write-Progress -Activity "Removing Hosts from HX" -Status "Processing" -PercentComplete (($c2 / $rhosts.Count)*100)
 
            HX-Delete-Host -AgentID $id -Token $global:Token
 
            }
        Write-Host "Removed $($rhosts.Count) hosts from HX" -ForegroundColor Green
   
        # Saves Log File
        $sfile = saveFile -Title "Save Log File As" -SaveAs "HostsRemovedFromHX-$timestamp.csv"
        $rhosts | Export-Csv -Path $sfile -NoTypeInformation
        }
    Else{
        Write-Host "Process Aborted: $timestamp" -ForegroundColor Red
        $rhosts
        }

}

Function IndicatorFunction{
##Begin Menu
    
    $menu.Hide()
    $menu.Close()

    Makeform
    }

Function Cancel{$HXinfo.Close()
Close}
    
Function Menu{

$menu.Visible = $true

}

Function Get-Info{

    $global:Server = $ipaddress.Text
    $global:Port = $port.Text
    $FireEyeUrl = "https://$global:Server"+":$global:Port"
    $timestamp = Get-Date -Format yyyyMMdd-HHmm
    $HXinfo.Close()

        # Authenticates to the HX Server and returns a user Token
        Ignore-SelfSignedCerts
   
        $global:Token = HX-Auth
    Makeform

    }

##Begin Indicators Form
Function Makeform{

[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")
[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")

Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()

$mainform = new-object System.Windows.Forms.Form
$mainform.text = "GUI for HX Indicators"
$mainform.Width = 600
$mainform.Height = 400
$mainform.AutoSize = $true
$mainform.StartPosition = "CenterScreen"

$mainform2 = new-object System.Windows.Forms.Form
$mainform2.text = "GUI for HX Indicators"
$mainform2.Width = 600
$mainform2.Height = 400
$mainform2.AutoSize = $true

    $header = @{
        "Accept" = "application/json"
        "Content-Type" = "application/json"  #MUST BE THERE TO POST!
        "X-FeApi-Token" = "$global:Token"
        }

$existingindicator =  Invoke-RestMethod -Uri "$FireEyeUrl/hx/api/v3/indicators/Custom/" -Headers $header -Method Get -UseBasicParsing
$existingindicator = $existingindicator.data.entries.name


$operator = @("equal"
"contains"
"starts-with"
"ends-with"
"matches"
"greater-than"
"less-than"
"between")

$integer = @("dnsLookupEvent/pid"
            "fileWriteEvent/lowestFileOffsetSeen"
            "fileWriteEvent/numBytesSeenWritten"
            "fileWriteEvent/pid"
            "fileWriteEvent/size"
            "fileWriteEvent/writes"
            "imageLoadEvent/parentPid"
            "imageLoadEvent/pid"
            "ipv4NetworkEvent/localPort"
            "ipv4NetworkEvent/pid"
            "ipv4NetworkEvent/remotePort"
            "processEvent/parentPid"
            "processEvent/pid"
            "regKeyEvent/pid"
            "urlMonitorEvent/localPort"
            "urlMonitorEvent/pid"
            "urlMonitorEvent/remotePort"
            )

$tokenname= @("addressNotificationEvent/address"
            "dnsLookupEvent/hostname"
            "dnsLookupEvent/pid"
            "dnsLookupEvent/process"
            "dnsLookupEvent/processPath"
            "dnsLookupEvent/username"
            "fileWriteEvent/closed"
            "fileWriteEvent/dataAtLowestOffset"
            "fileWriteEvent/devicePath"
            "fileWriteEvent/drive"
            "fileWriteEvent/fileExtension"
            "fileWriteEvent/fileName"
            "fileWriteEvent/filePath"
            "fileWriteEvent/fullPath"
            "fileWriteEvent/lowestFileOffsetSeen"
            "fileWriteEvent/md5"
            "fileWriteEvent/numBytesSeenWritten"
            "fileWriteEvent/pid"
            "fileWriteEvent/process"
            "fileWriteEvent/processPath"
            "fileWriteEvent/size"
            "fileWriteEvent/textAtLowestOffset"
            "fileWriteEvent/username"
            "fileWriteEvent/writes"
            "imageLoadEvent/devicePath"
            "imageLoadEvent/drive"
            "imageLoadEvent/fileExtension"
            "imageLoadEvent/fileName"
            "imageLoadEvent/filePath"
            "imageLoadEvent/fullPath"
            "imageLoadEvent/parentPid"
            "imageLoadEvent/pid"
            "imageLoadEvent/process"
            "imageLoadEvent/processPath"
            "imageLoadEvent/username"
            "ipv4NetworkEvent/localIP"
            "ipv4NetworkEvent/localPort"
            "ipv4NetworkEvent/pid"
            "ipv4NetworkEvent/process"
            "ipv4NetworkEvent/processPath"
            "ipv4NetworkEvent/protocol"
            "ipv4NetworkEvent/remoteIP"
            "ipv4NetworkEvent/remotePort"
            "ipv4NetworkEvent/username"
            "processEvent/eventType"
            "processEvent/md5"
            "processEvent/parentPid"
            "processEvent/parentProcess"
            "processEvent/parentProcessPath"
            "processEvent/pid"
            "processEvent/process"
            "processEvent/processCmdLine"
            "processEvent/processPath"
            "processEvent/startTime"
            "processEvent/username"
            "regKeyEvent/eventType"
            "regKeyEvent/hive"
            "regKeyEvent/keyPath"
            "regKeyEvent/originalPath"
            "regKeyEvent/path"
            "regKeyEvent/pid"
            "regKeyEvent/process"
            "regKeyEvent/processPath"
            "regKeyEvent/text"
            "regKeyEvent/username"
            "regKeyEvent/value"
            "regKeyEvent/valueName"
            "regKeyEvent/valueType"
            "urlMonitorEvent/hostname"
            "urlMonitorEvent/httpHeader"
            "urlMonitorEvent/localPort"
            "urlMonitorEvent/pid"
            "urlMonitorEvent/process"
            "urlMonitorEvent/processPath"
            "urlMonitorEvent/remoteIpAddress"
            "urlMonitorEvent/remotePort"
            "urlMonitorEvent/requestUrl"
            "urlMonitorEvent/timeStamp"
            "urlMonitorEvent/urlMethod"
            "urlMonitorEvent/userAgent"
            "urlMonitorEvent/username")

Function Authenticate{
    #Ignore-SelfSignedCerts
    #$Token = HX-Auth
    }

Function return-dropdown{
    $tok = $Dropdownbox2.selecteditem.tostring()
    $Outputbox.text = $tok
    }

Function test{Write-host $textboxverify.text}

Function Submit{



    $hope = $textboxverify.text

    $hope = ($hope -split "\s+")

    $a = '{"tests":['
    $b = '{"token":'
    $c = ',"type":'
    $d = ',"value":'
    $e = ',"operator":'
    $but = ',"negate":true'
    $and = '},'
    $md5var = "md5"
    $intvar = "integer"
    $textvar = "text"
    $rangevar = "range"

    $boolean = @('-AND-','-OR-','-NOT-')

    $newrequest = '{"tests":['

    foreach($h in $hope){

        if($newrequest -match ('replace1' -or 'replace2' -or 'replace3')){

            if($tokenname -contains $h){
        
                $newrequest = $newrequest.Replace('replace1', $b + '"' + $h + '"')
    
                if($h -match "md5"){$newrequest = $newrequest.replace('replace2', $c + '"' + $md5var + '"')}

                elseif($h -eq "regKeyEvent/eventType"){$newrequest = $newrequest.replace('replace2', $c + '"' + $intvar + '"')}

                elseif($integer -contains $h){$newrequest = $newrequest.replace('replace2', $c + '"' + $intvar + '"')}

                else{$newrequest = $newrequest.replace('replace2', $c + '"' + $textvar + '"')}
   
                }

            elseif($boolean -contains $h){
                if($h -eq "-AND-"){$newrequest += $and}
                elseif($h -eq "-OR-"){$newrequest += $or}
                else{$newrequest += 'replace1' + 'replace2' + 'replace3' +$but}
                }
            elseif($operator -contains $h){
                $newrequest += $e + '"' + $h +'"'
                }

            else{
                $newrequest = $newrequest.replace('replace3', $d + '"' + $h + '"')
                    
                }
            }
        else{
            if($tokenname -contains $h){
        
                $newrequest += $b + '"' + $h + '"'
    
                if($h -match "md5"){$newrequest += $c + '"' + $md5var + '"'}

                elseif($h -eq "regKeyEvent/eventType"){$newrequest += $c + '"' + $intvar + '"'}

                elseif($integer -contains $h){$newrequest += $c + '"' + $intvar + '"'}

                else{$newrequest += $c + '"' + $textvar + '"'}
   
                }

            elseif($boolean -contains $h){
                if($h -eq "-AND-"){$newrequest += $and}
                elseif($h -eq "-OR-"){$newrequest += $or}
                else{$newrequest += 'replace1'  + 'replace2' + 'replace3'  +$but}
                }
                elseif($operator -contains $h){
                $newrequest += $e + '"' + $h +'"'
                }
            else{
                                
                if($h -ne ""){$newrequest += $d + '"' + $h + '"'}

    
            }
    
        }
    }

    $newrequest = $newrequest -Replace ('"integer","type":')
    $newrequest = $newrequest.Replace('"{"operator','"},{"operator')
    $newrequest = $newrequest.Replace(":true{",":true},{")
    $newrequest = $newrequest.Replace('"{"','"},{"')
    $newrequest += '}]}'

    Write-host $newrequest

    if($RadioButton1.Checked -eq $true){
    $event = $Dropdownbox1.selecteditem.ToString()
    $name = $Dropdownbox1.selecteditem.ToString()
    }
    if($RadioButton2.Checked -eq $true){
    $event = $Dropdownbox3.selecteditem.ToString()
    $name = $textbox2.text
    $newindicator = $ExecutionContext.InvokeCommand.ExpandString('{"create_text":"$global:username","description":"$name","platforms":["win"]}')
    $textbox4.text += curl "$FireEyeUrl/hx/api/v3/indicators/Custom/$name" -Method PUT -Body $newindicator -Headers $header -UseBasicParsing | Out-String 

    }

    if($event -match "fileWriteEvent"){$dir = "presence"}
    else{$dir = "execution"}

    $textbox4.text += curl "$FireEyeUrl/hx/api/v3/indicators/custom/$name/conditions/$dir" -Headers $header -Method POST -Body $newrequest -UseBasicParsing| Out-String

    $nothing = ""

    $textboxverify.text = "$nothing"

}

function Help{
    [void] $mainform2.ShowDialog()
    }

Function Radio1{

    if($RadioButton1.Checked -eq $true){
        $Dropdownbox1.Enabled = $true
        $Dropdownbox2.Enabled = $true
        $textbox1.Enabled = $true
        $pop1.Enabled = $true
        $operatorbox1.enabled = $true
        $and1.Enabled = $true
        $not1.Enabled = $true
        $help1.Enabled = $true
        $textbox2.Enabled = $false
        $Dropdownbox3.Enabled = $false
        $textbox3.Enabled = $false
        $pop2.Enabled = $false
        $operatorbox2.enabled = $false
        $submit2.Enabled = $true
        $and2.Enabled = $false
        $not2.Enabled = $false
        $help2.Enabled = $false
            }
    }

Function Radio2{

    if($RadioButton2.Checked -eq $true){
        $textbox2.Enabled = $true
        $Dropdownbox3.Enabled = $true
        $textbox3.Enabled = $true
        $pop2.Enabled = $true
        $submit2.Enabled = $true
        $operatorbox2.Enabled = $true
        $help2.Enabled = $true
        $Dropdownbox1.Enabled = $false
        $Dropdownbox2.Enabled = $false
        $textbox1.Enabled = $false
        $pop1.Enabled = $false
        $operatorbox1.enabled = $false
        $and1.Enabled = $false
        $not1.Enabled = $false
        $help1.Enabled = $false
            }

    }

Function New_Indicator{
    $newindicator = $textbox2.text.tostring()
    $Outputbox.Text = $newindicator

    $testnewindicator = $ExecutionContext.InvokeCommand.ExpandString('{"create_text":"$global:username","description":"$newindicator","platforms":["win"]}')

    #curl "$FireEyeUrl/hx/api/v3/indicators/Custom/$newindicator" -Method PUT -Body $testmd5 -Credential cpt701api -Headers $header

    $header = @{
            "Accept" = "application/json"
            "Content-Type" = "application/json"  #MUST BE THERE TO POST!
            "X-FeApi-Token" = "$global:Token"
            }

    $textbox4.text += curl "$FireEyeUrl/hx/api/v3/indicators/Custom/$newindicator" -Method PUT -Body $testnewindicator -Headers $header -UseBasicParsing

            if($Dropdownbox3.selecteditem -ne $null){
            
                $tok = $Dropdownbox3.selecteditem.ToString()
                $Outputbox2.Text = $tok

                $value = $textbox3.Text.ToString()
                $Outputbox3.Text = $value

                #$type = (($Outputbox2.Text).Split("/")[1])
                $token = $Outputbox2.Text

                    if($token -match "md5"){$type = "md5"}

                        elseif($token -eq "regKeyEvent/eventType"){$type = "integer"}

                        elseif($integer -contains $token){

                            if($value -match "-"){$type = "range"}
                            else{$type = "integer"}

                            }
                    else{$type = "text"}

                    if($token -match "fileWriteEvent"){$dir = "presence"}
                    else{$dir = "execution"}
            
            
                $condition = $ExecutionContext.InvokeCommand.ExpandString('{"tests":[{"token":"$token","type":"$type","operator":"equal","value":"$value"}]}')

                $FireEyeUrl = $FireEyeUrl + "/hx/api/v3/indicators/custom/$newindicator/conditions/" + $dir
                $textbox4.text += curl "$FireEyeUrl" -Headers $header -Method POST -Body $condition | Out-String

            
            
                }
            
    }

Function Existing_Indicator{
    $tok = $Dropdownbox2.selecteditem.ToString()
    $Outputbox.text = $tok

    $indicator = $Dropdownbox1.SelectedItem.tostring()
    $Outputbox2.text = $indicator
    $indicator = $Outputbox2.text

    $value = $textbox1.Text.ToString()
    $Outputbox3.Text = $value
    $value = $Outputbox3.text

    $type = (($Outputbox.Text).Split("/")[1])
    $name = $Outputbox.Text
    $testmd5 = $ExecutionContext.InvokeCommand.ExpandString('{"tests":[{"token":"$name","type":"$type","operator":"equal","value":"$value"}]}')
    $header = @{
            "Accept" = "application/json"
            "Content-Type" = "application/json"  #MUST BE THERE TO POST!
            "X-FeApi-Token" = "$global:Token"
            }

    $FireEyeUrl = $FireEyeUrl + "/hx/api/v3/indicators/custom/$indicator/conditions/presence"
    $textbox4.text = curl "$FireEyeUrl" -Headers $header -Method POST -Body $testmd5 | Out-String

    }

Function Refresh{
    $mainform.close()
    $mainform.Dispose()
    Makeform
    }

Function Verify1{

    $pop1.Enabled = $false
    #$or1.Enabled = $true
    $and1.Enabled = $true
    $not1.Enabled = $true
    $clear.Enabled = $true

    $Dropdownbox1.Enabled = $false

    $idk = $dropdownbox2.Text.ToString()

    #$textboxverify.text += $idk -join "`r`n"

    $idk2 = $dropdownbox2.text.tostring()
    $idk3 = $operatorbox1.text.tostring()
    $idk4 = $textbox1.text.tostring()

    $textboxverify.text += 
"
    $idk2
        $idk3
            $idk4

"}

Function Verify2{
    
    $pop2.Enabled = $false
    #$or2.Enabled = $true
    $and2.Enabled = $true
    $not2.Enabled = $true
    $clear.Enabled = $true

    $textbox2.Enabled = $false

    $idk = $textbox2.Text.ToString()

    #$textboxverify.text += $idk -join "`r`n"

    $idk2 = $dropdownbox3.text.tostring()
    $idk3 = $operatorbox2.text.tostring()
    $idk4 = $textbox3.text.tostring()

    $textboxverify.text += 
"
    $idk2
        $idk3
            $idk4
"

    }

Function And1{

    $and = "-AND-"

    $textboxverify.text += "
    $and

    "
    $pop1.Enabled = $true
    $and1.Enabled = $false
    $not1.Enabled = $false
    }

Function And2{

    $and = "-AND-"

    $textboxverify.text += "
    $and

    "
    $pop2.Enabled = $true
    $and2.Enabled = $false
    $not2.Enabled = $false
    }

Function Not1{

    $not = "-NOT-"

    $textboxverify.text += "
    $not

    "
    $pop1.Enabled = $true
    $and1.Enabled = $false
    $not1.Enabled = $false
    }

Function Not2{

    $not = "-NOT-"

    $textboxverify.text += "
    $not

    "
    $pop2.Enabled = $true
    $and2.Enabled = $false
    $not2.Enabled = $false
    }

Function ClearVerify{
    $nothing = ""

    $textboxverify.text = "$nothing"

    if($RadioButton1.Checked -eq $true){
    $pop1.Enabled = $true
    $dropdownbox1.Enabled = $true
    }
    else{$pop2.Enabled = $true
    $textbox2.Enabled = $true
    }


    }

Function Radioimport1{

    if($RadioButton1.Checked -eq $true){
        
        $indicatorname.Enabled = $true
        $indicatorname.Font = 'Microsoft Sans Sherif,10,style=Bold'
        $Dropdownboximport.Enabled = $false

        }
    }

Function Radioimport2{

    if($RadioButton2.Checked -eq $true){
        $existingindicator =  Invoke-RestMethod -Uri "$FireEyeUrl/hx/api/v3/indicators/Custom/" -Headers $header -Method Get -UseBasicParsing
        $existingindicator = $existingindicator.data.entries.name

        foreach($e in $existingindicator){

            $Dropdownboximport.Items.Add($e)

            }

        $indicatorname.Enabled = $false
        $Dropdownboximport.Enabled = $true
        #$Dropdownboximport.Font = 'Microsoft Sans Sherif,10,style=Bold'

        }
    }

Function Get-FileName($initialDirectory){   
    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") |
    Out-Null

    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.initialDirectory = $initialDirectory
    #$OpenFileDialog.filter = "All files (*.*)| *.*"
    #$OpenFileDialog.Filter = "Text Documents (*.txt) | *.txt"
    $OpenFileDialog.Filter = "Comma delimited (*.csv) | *.csv"
    $OpenFileDialog.ShowDialog() | Out-Null
    $csvpath.text = $OpenFileDialog.filename
}

Function ImportForm{
    
    $Importfunction = new-object System.Windows.Forms.Form
    $Importfunction.text = "Import CSV"
    $Importfunction.Width = 445
    $Importfunction.Height = 175
    $Importfunction.AutoSize = $true
    $Importfunction.StartPosition = "CenterScreen"
    
    $RadioButton1 = New-Object System.Windows.Forms.RadioButton
    #$RadioButton1.text = 'This section will create a new condition based on an existing Indicator (Check one)'
    $RadioButton1.Autosize = $true
    $RadioButton1.Location = New-Object System.Drawing.Point (10,20)
    $RadioButton1.Font = 'Microsoft Sans Sherif,10,style=Bold'
    $RadioButton1.add_click({RadioImport1})
    $Importfunction.Controls.Add($RadioButton1)
    
    $indicatorlabel = New-Object System.Windows.Forms.Label
    $indicatorlabel.Text = 'Enter New Indicator Name:'
    $indicatorlabel.Location = New-Object System.Drawing.Point(30,20)
    $indicatorlabel.AutoSize = $true
    $Importfunction.Controls.add($indicatorlabel)

    $indicatorname = New-Object System.Windows.Forms.TextBox
    $indicatorname.multiline = $false
    $indicatorname.Size = New-Object System.Drawing.Size(245,10)
    $indicatorname.location = New-Object System.Drawing.Point (170,18)
    $indicatorname.Enabled = $false
    $indicatorname.MaxLength = 100
    $Importfunction.Controls.addrange(@($indicatorname))
    
    $radiobutton2 = New-Object System.Windows.Forms.RadioButton
    #$radiobutton2.text = 'This section will create a new condition based on an existing Indicator (Check one)'
    $radiobutton2.Autosize = $true
    $radiobutton2.Location = New-Object System.Drawing.Point (10,65)
    $radiobutton2.Font = 'Microsoft Sans Sherif,10,style=Bold'
    $radiobutton2.add_click({RadioImport2})
    $Importfunction.Controls.Add($radiobutton2)

    $indicatorexisting= New-Object System.Windows.Forms.Label
    $indicatorexisting.Text = 'Select Existing Indicator'
    $indicatorexisting.Location = New-Object System.Drawing.Point(30,65)
    $indicatorexisting.AutoSize = $true
    $Importfunction.Controls.add($indicatorexisting)

    $Dropdownboximport = New-Object System.Windows.Forms.ComboBox
    $Dropdownboximport.Location = New-Object System.Drawing.Point(170,62)  #(Horizontal,Vertical)
    $Dropdownboximport.Size = New-Object System.Drawing.Size(245,10)
    $Dropdownboximport.DropDownHeight = 200
    $Dropdownboximport.Enabled = $false
    $Dropdownboximport.MaxLength = 100
    $Importfunction.Controls.Add($Dropdownboximport)
    
    $csvlabel= New-Object System.Windows.Forms.Label
    $csvlabel.Text = 'Select CSV to upload:'
    $csvlabel.Location = New-Object System.Drawing.Point(10,110)
    $csvlabel.AutoSize = $true
    $Importfunction.Controls.add($csvlabel)

    $csvpath = New-Object System.Windows.Forms.TextBox
    $csvpath.multiline = $false
    $csvpath.Size = New-Object System.Drawing.Size(245,10)
    $csvpath.location = New-Object System.Drawing.Point (170,108)
    $csvpath.Enabled = $true
    $csvpath.MaxLength = 100
    $csvpath.AutoCompleteMode = 'SuggestAppend'
    $csvpath.AutoCompleteSource = 'Filesystem'
    $csvpath.TabIndex = 0
    $Importfunction.Controls.addrange(@($csvpath))

    $importopen = New-Object System.Windows.Forms.Button
    $importopen.Location = New-Object System.Drawing.Size(430,106)  #(Horizontal,Vertical)
    $importopen.Size = New-Object System.Drawing.Size(75,24)
    $importopen.Text = "Open"
    $importopen.Font = 'Microsoft Sans Sherif,10,style=Bold'
    $importopen.add_click({Get-Filename})
    $importopen.Enabled = $true
    $ImportFunction.Controls.Add($importopen)
        
    $importsubmit = New-Object System.Windows.Forms.Button
    $importsubmit.Location = New-Object System.Drawing.Size(355,145)  #(Horizontal,Vertical)
    $importsubmit.Size = New-Object System.Drawing.Size(150,40)
    $importsubmit.Text = "Import"
    $importsubmit.Font = 'Microsoft Sans Sherif,10,style=Bold'
    $importsubmit.add_click({ImportCSV})
    $importsubmit.Enabled = $true
    $ImportFunction.Controls.Add($importsubmit)

    $Importfunction.ShowDialog()

}

Function ImportCSV{
    
    $file = $csvpath.text

    $ioclist = Import-Csv $file

    $ioclist = ($ioclist | ?{($_.'ipv4NetworkEvent/remoteIP' -ne '' -or $_.'dnsLookupEvent/hostname' -ne '' -or  $_.'fileWriteEvent/md5' -ne '') -or ($_.'regKeyEvent/keyPath' -ne '' -and $_.'regKeyEvent/value' -ne '')})

    if($RadioButton1.Checked -eq $true){

    $name = $indicatorname.text

    $newindicator = $ExecutionContext.InvokeCommand.ExpandString('{"create_text":"$global:username","description":"$name","platforms":["win"]}')

    $header = @{
            "Accept" = "application/json"
            "Content-Type" = "application/json"  #MUST BE THERE TO POST!
            "X-FeApi-Token" = "$global:Token"
            }

    curl "$FireEyeUrl/hx/api/v3/indicators/Custom/$name" -Method PUT -Body $newindicator -Headers $header -UseBasicParsing


    }

    elseif($RadioButton2.Checked -eq $true){

    $name = $Dropdownboximport.text

    }
    
    foreach($ioc in $ioclist){

        if($ioc.'ipv4NetworkEvent/remoteIP' -ne ""){
        $value = $ioc.'ipv4NetworkEvent/remoteIP'
        $iocingest += $ExecutionContext.InvokeCommand.ExpandString('{"tests":[{"operator":"equal","token":"ipv4NetworkEvent/remoteIP","type":"text","value":"$value"}]}')
        }

        if($ioc.'dnsLookupEvent/hostname' -ne ""){
        $value = $ioc.'dnsLookupEvent/hostname'
        $iocingest += $ExecutionContext.InvokeCommand.ExpandString('{"tests":[{"operator":"equal","token":"dnsLookupEvent/hostname","type":"text","value":"$value"}]}')
        }

        if($ioc.'fileWriteEvent/fileName' -ne "" -or $ioc.'fileWriteEvent/md5' -ne ""){

            if($ioc.'fileWriteEvent/fileName' -ne ""){
            $value = $ioc.'fileWriteEvent/fileName'
            $filewrite += $ExecutionContext.InvokeCommand.ExpandString('{"operator":"equal","token":"fileWriteEvent/fileName","type":"text","value":"$value"}')
            }
            if($ioc -match 'fileWriteEvent/filePath' -and $ioc.'fileWriteEvent/filePath' -ne ""){
            $value = $ioc.'fileWriteEvent/filePath' -replace ("\\","\\")
            $filewrite += $ExecutionContext.InvokeCommand.ExpandString('{"operator":"equal","token":"fileWriteEvent/filePath","type":"text","value":"$value"}')
            }
            if($ioc.'fileWriteEvent/md5' -ne ""){
            $value = $ioc.'fileWriteEvent/md5'
            $filewrite += $ExecutionContext.InvokeCommand.ExpandString('{"operator":"equal","token":"fileWriteEvent/md5","type":"md5","value":"$value"}')
            }
            if($ioc -match 'fileWriteEvent/size' -and $ioc.'fileWriteEvent/size' -ne ""){
            $value = $ioc.'fileWriteEvent/size'
            $filewrite += $ExecutionContext.InvokeCommand.ExpandString('{"operator":"equal","token":"fileWriteEvent/size","type":"integer","value":"$value"}')
            }
            if($filewrite -match "}{"){
            $filewrite = $filewrite -replace ('}{','},{')
            }
            if($filewrite -match "operator"){
            $filewrite = '{"tests":[' + $filewrite + ']}
            '
            $iocingest += $filewrite
            $filewrite = ""
            }
        }
        if($ioc.'regKeyEvent/keyPath' -ne "" -or $ioc.'regKeyEvent/value' -ne ""){
            if($ioc.'regKeyEvent/keyPath' -ne ""){
            $value = $ioc.'regKeyEvent/keyPath' -replace ("\\","\\")
            $regevent += $ExecutionContext.InvokeCommand.ExpandString('{"operator":"equal","token":"regKeyEvent/keyPath","type":"text","value":"$value"}')
            }
            if($ioc.'regKeyEvent/value' -ne ""){
            $value = $ioc.'regKeyEvent/value' -replace ("\\","\\")
            $regevent += $ExecutionContext.InvokeCommand.ExpandString('{"operator":"equal","token":"regKeyEvent/valueName","type":"text","value":"$value"}')
            }
            if($regevent -match "}{"){
            $regevent = $regevent -replace ('}{','},{')
            }
            if($regevent -match "operator"){
            $regevent = '{"tests":[' + $regevent + ']}
            '
            $iocingest += $regevent
            $regevent = ""
            }

        }
        else{}
    }
    

    ##comment the below line out when test is complete
    
    $iocingest = $iocingest -split "\s+\s+"
    $iocingest = $iocingest -split ("}]}{")
    
        foreach($ioc in $iocingest){
       
            if($ioc -notmatch '^[{]'){$ioc = '{' + $ioc}
            if($ioc -notmatch '[]}]$'){$ioc= $ioc + '}]}'}
            [array]$iocs += $ioc
            }

    
    $header = @{
            "Accept" = "application/json"
            "Content-Type" = "application/json"  #MUST BE THERE TO POST!
            "X-FeApi-Token" = "$global:Token"
            }
    $num = 0
    $total = $iocs.count
    foreach($ioc in $iocs){
        $num++
        Write-Progress -Activity "Sending Conditions to HX" -Status "Loading $num of $total total IOCs in spreadsheet" -PercentComplete (($num / $total)*100)

        if($ioc -match "fileWriteEvent"){$dir = "presence"}
        else{$dir = "execution"}

        if($ioc -eq '{}]}'){}
        elseif($ioc -match '"value":""'){}
        else{
        Write-host "$FireEyeUrl/hx/api/v3/indicators/custom/$name/conditions/$dir" -Headers $header -Method POST -Body $ioc
        curl "$FireEyeUrl/hx/api/v3/indicators/custom/$name/conditions/$dir" -Headers $header -Method POST -Body $ioc -UseBasicParsing | Out-String
            }
            }
        Write-progress -Activity "Completed Conditions" -Completed
    $iocingest = ""
    $iocs = ""
        
}

Function Close{

    HX-DeAuth
    $mainform.Close()

    }


   # $existingindicator =  Invoke-RestMethod -Uri "$FireEyeUrl/hx/api/v3/indicators/Custom/" -Headers $header -Method Get
   # $existingindicator = $existingindicator.data.entries.name

        ##Existing Indicator
        $Dropdownbox1 = New-Object System.Windows.Forms.ComboBox
        $Dropdownbox1.Location = New-Object System.Drawing.Point(120,50)  #(Horizontal,Vertical)
        $Dropdownbox1.Size = New-Object System.Drawing.Size(200,10)
        $Dropdownbox1.DropDownHeight = 200
        $Dropdownbox1.Enabled = $false
        $Dropdownbox1.MaxLength = 100
        $mainform.Controls.Add($Dropdownbox1)

        ## Token Names
        $Dropdownbox2 = New-Object System.Windows.Forms.ComboBox
        $Dropdownbox2.Location = New-Object System.Drawing.Point(120,100)
        $Dropdownbox2.Size = New-Object System.Drawing.Size(200,10)
        $Dropdownbox2.DropDownHeight = 200
        $Dropdownbox2.Enabled = $false
        $Dropdownbox2.MaxLength = 100
        $mainform.Controls.Add($Dropdownbox2)

        $Dropdownbox3 = New-Object System.Windows.Forms.ComboBox
        $Dropdownbox3.Location = New-Object System.Drawing.Point(120,300)
        $Dropdownbox3.Size = New-Object System.Drawing.Size(200,10)
        $Dropdownbox3.DropDownHeight = 200
        $Dropdownbox3.Enabled = $false
        $Dropdownbox3.MaxLength = 100
        $mainform.Controls.Add($Dropdownbox3)

        $operatorbox1 = New-Object System.Windows.Forms.ComboBox
        $operatorbox1.Location = New-Object System.Drawing.Point(120,150)  #(Horizontal,Vertical)
        $operatorbox1.Size = New-Object System.Drawing.Size(200,10)
        $operatorbox1.DropDownHeight = 200
        $operatorbox1.Enabled = $false
        $operatorbox1.MaxLength = 100
        $mainform.Controls.Add($operatorbox1)

        $operatorbox2 = New-Object System.Windows.Forms.ComboBox
        $operatorbox2.Location = New-Object System.Drawing.Point(120,350)  #(Horizontal,Vertical)
        $operatorbox2.Size = New-Object System.Drawing.Size(200,10)
        $operatorbox2.DropDownHeight = 200
        $operatorbox2.Enabled = $false
        $operatorbox2.MaxLength = 100
        $mainform.Controls.Add($operatorbox2)





foreach($t in $tokenname){

    $Dropdownbox2.Items.Add($t)
    $Dropdownbox3.Items.Add($t)

    }

    $header = @{
            "Accept" = "application/json"
            "Content-Type" = "application/json"  #MUST BE THERE TO POST!
            "X-FeApi-Token" = "$global:Token"
            }


foreach($e in $existingindicator){

    $Dropdownbox1.Items.Add($e)

    }

foreach($o in $operator){$operatorbox1.Items.Add($o)}

foreach($o in $operator){$operatorbox2.Items.Add($o)}

    $label1 = New-Object System.Windows.Forms.Label
    $label1.Text = 'Existing Indicator'
    $label1.Location = New-Object System.Drawing.Point(10,50)
    $label1.AutoSize = $true
    $mainform.Controls.add($label1)

    $label2 = New-Object System.Windows.Forms.Label
    $label2.Text = 'Token Name'
    $label2.Location = New-Object System.Drawing.Point(10,100)
    $label2.AutoSize = $true
    $mainform.Controls.add($label2)

    $label4 = New-Object System.Windows.Forms.Label
    $label4.Text = 'Value'
    $label4.Location = New-Object System.Drawing.Point(10,200)
    $label4.AutoSize = $true
    $mainform.Controls.add($label4)

    $operatorlabel1 = New-Object System.Windows.Forms.Label
    $operatorlabel1.Text = 'Operator'
    $operatorlabel1.Location = New-Object System.Drawing.Point(10,150)
    $operatorlabel1.AutoSize = $true
    $mainform.Controls.add($operatorlabel1)

    $operatorlabel2 = New-Object System.Windows.Forms.Label
    $operatorlabel2.Text = 'Operator'
    $operatorlabel2.Location = New-Object System.Drawing.Point(10,350)
    $operatorlabel2.AutoSize = $true
    $mainform.Controls.add($operatorlabel2)

    $textbox1 = New-Object System.Windows.Forms.TextBox
    $textbox1.multiline = $false
    $textbox1.Size = New-Object System.Drawing.Size(200,10)
    $textbox1.location = New-Object System.Drawing.Point (120,200)
    $textbox1.Enabled = $false
    $textbox1.MaxLength = 100
    $mainform.Controls.addrange(@($textbox1))

    $label6 = New-Object System.Windows.Forms.Label
    $label6.Text = 'Indicator Name'
    $label6.Location = New-Object System.Drawing.Point(10,250)
    $label6.AutoSize = $true
    $mainform.Controls.add($label6)

    $label7 = New-Object System.Windows.Forms.Label
    $label7.Text = 'Token Name'
    $label7.Location = New-Object System.Drawing.Point(10,300)
    $label7.AutoSize = $true
    $mainform.Controls.add($label7)

    $label8 = New-Object System.Windows.Forms.Label
    $label8.Text = 'Value'
    $label8.Location = New-Object System.Drawing.Point(10,400)
    $label8.AutoSize = $true
    $mainform.Controls.add($label8)

    $loginname = New-Object System.Windows.Forms.Label
    $loginname.Text = "You are authenticated as  $global:username"
    $loginname.Location = New-Object System.Drawing.Point(495,0)
    $loginname.Size = New-Object System.Drawing.Size(495,20)
    $loginname.AutoSize = $false
    $loginname.TextAlign = "BottomRight"
    $loginname.BackColor = "SkyBlue"
    $loginname.Font = "Elephant,10"
    $mainform.Controls.add($loginname)

    $Formname = New-Object System.Windows.Forms.Label
    $Formname.Text = "Simon"
    $Formname.Location = New-Object System.Drawing.Point(0,0)
    $Formname.Size = New-Object System.Drawing.Size(495,20)
    $Formname.AutoSize = $false
    $Formname.TextAlign = "TopLeft"
    $Formname.BackColor = "SkyBlue"
    $Formname.Font = "Elephant,10"
    $mainform.Controls.add($Formname)

    $textbox2 = New-Object System.Windows.Forms.TextBox
    $textbox2.multiline = $false
    $textbox2.Size = New-Object System.Drawing.Size(200,10)
    $textbox2.location = New-Object System.Drawing.Point (120,250)
    $textbox2.Enabled = $false
    $textbox2.MaxLength = 100
    $mainform.Controls.addrange(@($textbox2))

    $textbox3 = New-Object System.Windows.Forms.TextBox
    $textbox3.multiline = $false
    $textbox3.Size = New-Object System.Drawing.Size(200,10)          #(Length,Height)
    $textbox3.location = New-Object System.Drawing.Point (120,400)   #(Horizontal,Vertical)
    $textbox3.Enabled = $false
    $textbox3.MaxLength = 100
    $mainform.Controls.addrange(@($textbox3))

    $label9 = New-Object System.Windows.Forms.Label
    $label9.Text = 'Output of Command'
    $label9.Location = New-Object System.Drawing.Point(10,450)
    $label9.AutoSize = $true
    $label9.Font = 'Microsoft Sans Sherif,10,style=Bold'
    $mainform.Controls.add($label9)

    $textbox4 = New-Object System.Windows.Forms.TextBox
    $textbox4.multiline = $true
    $textbox4.Size = New-Object System.Drawing.Size(580,400)
    $textbox4.location = New-Object System.Drawing.Point (10,470)
    $textbox4.ScrollBars = "Vertical"
    $textbox4.Enabled = $true
    $textbox4.ReadOnly = $true
    $textbox4.UseWaitCursor = $false
    $textbox4.BackColor = "White"
    $mainform.Controls.addrange(@($textbox4))

    $textboxverify = New-Object System.Windows.Forms.TextBox
    $textboxverify.multiline = $true
    $textboxverify.Size = New-Object System.Drawing.Size(370,810)
    $textboxverify.location = New-Object System.Drawing.Point (620,20)
    $textboxverify.Enabled = $false
    $textboxverify.BackColor = "White"
    $textboxverify.SendToBack()
    $mainform.Controls.addrange(@($textboxverify))

    #DropDownbox1
    $Outputbox = new-object System.Windows.Forms.TextBox
    
    #DropDownbox2
    $Outputbox2 = new-object System.Windows.Forms.TextBox
    
    #textbox1
    $Outputbox3 = new-object System.Windows.Forms.TextBox 

    #verify
    $outputbox4 = new-object System.Windows.Forms.TextBox 
        
    $RadioButton1 = New-Object System.Windows.Forms.RadioButton
    $RadioButton1.text = 'This section will create a new condition based on an existing Indicator (Check one)'
    $RadioButton1.Autosize = $true
    $RadioButton1.Location = New-Object System.Drawing.Point (10,20)
    $RadioButton1.Font = 'Microsoft Sans Sherif,10,style=Bold'
    $RadioButton1.add_click({Radio1})
    $mainform.Controls.Add($RadioButton1)
    
    $RadioButton2 = New-Object System.Windows.Forms.RadioButton
    $RadioButton2.text = 'This section will create a new indicator and conditions (Check one)'
    $RadioButton2.Autosize = $true
    $RadioButton2.Location = New-Object System.Drawing.Point (10,220)
    $RadioButton2.Font = 'Microsoft Sans Sherif,10,style=Bold'
    $RadioButton2.add_click({Radio2})
    $mainform.Controls.Add($RadioButton2)

    $submit2 = New-Object System.Windows.Forms.Button
    $submit2.Location = New-Object System.Drawing.Size(790,890)  #(Horizontal,Vertical)
    $submit2.Size = New-Object System.Drawing.Size(200,40)
    $submit2.Text = "Submit"
    $submit2.Font = 'Microsoft Sans Sherif,10,style=Bold'
    $submit2.add_click({test;Submit})
    $submit2.Enabled = $false
    $mainform.Controls.Add($submit2)

    $pop1 = New-Object System.Windows.Forms.Button
    $pop1.Location = New-Object System.Drawing.Size(400,100)    #(Horizontal,Vertical)
    $pop1.Size = New-Object System.Drawing.Size(200,20)
    $pop1.Text = ">>"
    $pop1.Font = 'Microsoft Sans Sherif,10,style=Bold'
    $pop1.add_click({Verify1})
    $pop1.Enabled = $false
    $mainform.Controls.Add($pop1)

    $pop2 = New-Object System.Windows.Forms.Button
    $pop2.Location = New-Object System.Drawing.Size(400,300)    #(Horizontal,Vertical)
    $pop2.Size = New-Object System.Drawing.Size(200,20)
    $pop2.Text = ">>"
    $pop2.Font = 'Microsoft Sans Sherif,10,style=Bold'
    $pop2.add_click({Verify2})
    $pop2.Enabled = $false
    $mainform.Controls.Add($pop2)

    $help1 = New-Object System.Windows.Forms.Button
    $help1.Location = New-Object System.Drawing.Size(270,170)    #(Horizontal,Vertical)
    $help1.Size = New-Object System.Drawing.Size(50,20)
    $help1.Text = "Help"
    $help1.Font = 'Microsoft Sans Sherif,10,style=Bold'
    $help1.add_click({Help})
    $help1.Enabled = $false
    $mainform.Controls.Add($help1)

    $help2 = New-Object System.Windows.Forms.Button
    $help2.Location = New-Object System.Drawing.Size(270,370)    #(Horizontal,Vertical)
    $help2.Size = New-Object System.Drawing.Size(50,20)
    $help2.Text = "Help"
    $help2.Font = 'Microsoft Sans Sherif,10,style=Bold'
    $help2.add_click({Help})
    $help2.Enabled = $false
    $mainform.Controls.Add($help2)

    $and1 = New-Object System.Windows.Forms.Button
    $and1.Location = New-Object System.Drawing.Size(475,150)    #(Horizontal,Vertical)
    $and1.Size = New-Object System.Drawing.Size(50,20)
    $and1.Text = "AND"
    $and1.Font = 'Microsoft Sans Sherif,10,style=Bold'
    $and1.add_click({And1})
    $and1.Enabled = $false
    $mainform.Controls.Add($and1)

    $and2 = New-Object System.Windows.Forms.Button
    $and2.Location = New-Object System.Drawing.Size(475,350)    #(Horizontal,Vertical)
    $and2.Size = New-Object System.Drawing.Size(50,20)
    $and2.Text = "AND"
    $and2.Font = 'Microsoft Sans Sherif,10,style=Bold'
    $and2.add_click({And2})
    $and2.Enabled = $false
    $mainform.Controls.Add($and2)

    $not1 = New-Object System.Windows.Forms.Button
    $not1.Location = New-Object System.Drawing.Size(550,150)    #(Horizontal,Vertical)
    $not1.Size = New-Object System.Drawing.Size(50,20)
    $not1.Text = "NOT"
    $not1.Font = 'Microsoft Sans Sherif,10,style=Bold'
    $not1.add_click({Not1})
    $not1.Enabled = $false
    $mainform.Controls.Add($not1)

    $not2 = New-Object System.Windows.Forms.Button
    $not2.Location = New-Object System.Drawing.Size(550,350)    #(Horizontal,Vertical)
    $not2.Size = New-Object System.Drawing.Size(50,20)
    $not2.Text = "NOT"
    $not2.Font = 'Microsoft Sans Sherif,10,style=Bold'
    $not2.add_click({Not2})
    $not2.Enabled = $false
    $mainform.Controls.Add($not2)

    $importfile = New-Object System.Windows.Forms.Button
    $importfile.Location = New-Object System.Drawing.Size(400,425)    #(Horizontal,Vertical)
    $importfile.Size = New-Object System.Drawing.Size(200,20)
    $importfile.Text = "Import CSV File"
    $importfile.Font = 'Microsoft Sans Sherif,10,style=Bold'
    $importfile.add_click({ImportForm})
    #$importfile.add_click({Get-Filename})
    #$importfile.add_click({ImportForm})
    $importfile.Enabled = $true
    $mainform.Controls.Add($importfile)

    $clear = New-Object System.Windows.Forms.Button
    $clear.Location = New-Object System.Drawing.Size(620,830)    #(Horizontal,Vertical)
    $clear.Size = New-Object System.Drawing.Size(370,40)
    $clear.Text = "Clear"
    $clear.Font = 'Microsoft Sans Sherif,10,style=Bold'
    $clear.BringToFront()
    $clear.add_click({ClearVerify})
    $clear.Enabled = $false
    $mainform.Controls.Add($clear)

    $refresh = New-Object System.Windows.Forms.Button
    $refresh.Location = New-Object System.Drawing.Size(10,890)  #(Horizontal,Vertical)
    $refresh.Size = New-Object System.Drawing.Size(200,40)
    $refresh.Text = "Refresh"
    $refresh.Font = 'Microsoft Sans Sherif,10,style=Bold'
    $refresh.add_click({Refresh})
    $mainform.Controls.Add($refresh)

    $close = New-Object System.Windows.Forms.Button
    $close.Location = New-Object System.Drawing.Size(410,890)  #(Horizontal,Vertical)
    $close.Size = New-Object System.Drawing.Size(200,40)
    $close.Font = 'Microsoft Sans Sherif,10,style=Bold'
    $close.Text = "Close"
    $close.add_click({close})
    $mainform.Controls.Add($close)

    ##On second page
    $label10 = New-Object System.Windows.Forms.Label
    $label10.Text = 'Help'
    $label10.Location = New-Object System.Drawing.Point(10,10)
    $label10.AutoSize = $true
    $label10.Font = 'Microsoft Sans Sherif,10,style=Bold'
    $mainform2.Controls.add($label10)

    $help = New-Object System.Windows.Forms.TextBox
    $help.multiline = $true
    $help.Size = New-Object System.Drawing.Size(580,400)
    $help.location = New-Object System.Drawing.Point (10,30)
    $help.Enabled = $true
    $help.ReadOnly = $true
    $help.BackColor = "White"
    $help.text=
        "Types    Operators                                         Value                                      
        md5      equal                                             '<any md5 hash>'                            
        text     equal, contains, starts-with, ends-with,matches   '<any string>'                              
        integer  equal, greater-than, less-than                    '<any integer value>'                       
        range    between                                           '<any integer value> TO <any integer value>'"
    
$mainform2.Controls.addrange(@($help))

$mainform.add_shown({$mainform.Activate()})
[void] $mainform.ShowDialog()

}


    $HXinfo = new-object System.Windows.Forms.Form
    $HXinfo.text = "HX information"
    $HXinfo.Width = 400
    $HXinfo.Height = 230
    $HXinfo.AutoSize = $false
    $HXinfo.StartPosition = "CenterScreen"

    $ipaddress = New-Object System.Windows.Forms.TextBox
    $ipaddress.multiline = $false
    $ipaddress.Size = New-Object System.Drawing.Size(200,10)          #(Length,Height)
    $ipaddress.location = New-Object System.Drawing.Point (175,50)   #(Horizontal,Vertical)
    $ipaddress.Enabled = $true
    $ipaddress.MaxLength = 15
    $HXinfo.Controls.addrange(@($ipaddress))

    $port = New-Object System.Windows.Forms.TextBox
    $port.multiline = $false
    $port.Size = New-Object System.Drawing.Size(200,10)          #(Length,Height)
    $port.location = New-Object System.Drawing.Point (175,100)   #(Horizontal,Vertical)
    $port.Enabled = $true
    $port.MaxLength = 5
    $HXinfo.Controls.addrange(@($port))

    $toplabel = New-Object System.Windows.Forms.Label
    $toplabel.Text = ''
    $toplabel.Location = New-Object System.Drawing.Point(0,0)
    $toplabel.AutoSize = $false
    $toplabel.Size = New-Object System.Drawing.Size(400,40)
    $toplabel.BackColor = "SkyBlue"
    $toplabel.text = 'HX Authentication'
    $toplabel.Font = "Elephant,14"
    $toplabel.TextAlign = "MiddleCenter"
    $HXinfo.Controls.add($toplabel)

    $ipaddresslabel = New-Object System.Windows.Forms.Label
    $ipaddresslabel.Text = 'Enter HX IP address:'
    $ipaddresslabel.Location = New-Object System.Drawing.Point(10,50)
    $ipaddresslabel.AutoSize = $true
    $HXinfo.Controls.add($ipaddresslabel)

    $portlabel = New-Object System.Windows.Forms.Label
    $portlabel.Text = 'Enter Port:'
    $portlabel.Location = New-Object System.Drawing.Point(10,100)
    $portlabel.AutoSize = $true
    $HXinfo.Controls.add($portlabel)

    $info = New-Object System.Windows.Forms.Button
    $info.Location = New-Object System.Drawing.Size(250,150)    #(Horizontal,Vertical)
    $info.Size = New-Object System.Drawing.Size(125,20)
    $info.Text = "Connect"
    $info.add_click({Get-Info})
    $info.Enabled = $true
    $info.BackColor = "ControlDark"
    $HXinfo.Controls.Add($info)

    $cancel = New-Object System.Windows.Forms.Button
    $cancel.Location = New-Object System.Drawing.Size(20,150)    #(Horizontal,Vertical)
    $cancel.Size = New-Object System.Drawing.Size(125,20)
    $cancel.Text = "Cancel"
    $cancel.add_click({Cancel})
    $cancel.Enabled = $true
    $HXinfo.Controls.Add($cancel)
    
    $HXinfo.ShowDialog()
    
    $FireEyeUrl = "https://$global:Server"+":$global:Port"
    $timestamp = Get-Date -Format yyyyMMdd-HHmm

    $menu = new-object System.Windows.Forms.Form
    $menu.text = "Menu Screen"
    $menu.Width = 500
    $menu.Height = 250
    $menu.AutoSize = $true
    $menu.TopMost = $true
    $menu.StartPosition = "CenterScreen"

    $option = New-Object System.Windows.Forms.Label
    $option.Text = 'Pick one'
    $option.Location = New-Object System.Drawing.Point(215,50)
    $option.AutoSize = $true
    $option.Font = 'Microsoft Sans Sherif,10,style=Bold'
    $menu.Controls.add($option)

    $indicatorsform = New-Object System.Windows.Forms.Button
    $indicatorsform.Location = New-Object System.Drawing.Size(30,100)    #(Horizontal,Vertical)
    $indicatorsform.Size = New-Object System.Drawing.Size(175,40)
    $indicatorsform.Text = "Create Indicators"
    $indicatorsform.Font = 'Microsoft Sans Sherif,10,style=Bold'
    $indicatorsform.add_click({IndicatorFunction})
    $indicatorsform.Enabled = $true
    $menu.Controls.Add($indicatorsform)

    $dedupform = New-Object System.Windows.Forms.Button
    $dedupform.Location = New-Object System.Drawing.Size(290,100)    #(Horizontal,Vertical)
    $dedupform.Size = New-Object System.Drawing.Size(175,40)
    $dedupform.Text = "Get/Dedup Hosts"
    $dedupform.Font = 'Microsoft Sans Sherif,10,style=Bold'
    $dedupform.add_click({dedupform})
    $dedupform.Enabled = $false
    $menu.Controls.Add($dedupform)

Ignore-SelfSignedCerts

#Makeform

