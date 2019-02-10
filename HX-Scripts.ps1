##Created by Patrick Cartos
##2/9/2019
##e-mail - cartos8992@gmail.com
##github - https://github.com/CrimsonUSMC
##Works with appliance version 4.7 and below and Agent version 29 and below

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()

##Enable the use of Self Signed Certs
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

##Authenticate to HX Server and returns a Token (This is ran in the HX-Get-Info Function)
Function HX-Auth {
# Authenticates to the HX Server and returns a user Token
 
    # Prompts for and processes API user creds   
    $c = Get-Credential
    $global:username = $c.username
    $cpair = "$($c.username):$($c.GetNetworkCredential().Password)"
    $key = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($cpair))
   
    # Required Header info
    $authheader = @{
        "Accept" = "application/json"
        "Authorization" = "Basic $key"
        }
    
    # Authenticates to the HX server
    $global:gettoken = Invoke-WebRequest -Uri "$global:FireEyeUrl/hx/api/v3/token" -Headers $authheader -Method Get -UseBasicParsing
 
    $global:token = $global:gettoken.Headers.'X-FeApi-Token'
    $global:token

    $global:header = @{
        "Accept" = "application/json"
        "Content-Type" = "application/json"
        "X-FeApi-Token" = "$global:Token"
        }
 

    ##Other Authentication Methods
        #$global:Server = "10.27.4.76" 
        #$global:Port = "3000"

        #param(
        #    [string]$Server,
        #    [string]$Port
        #    )

    }

##Deauthenticates from the HX Server - Run this when you are done working
Function HX-DeAuth($global:token) {
# Logs off API user of supplied Token
 
    $apiLogOff = Invoke-WebRequest -Uri "$global:FireEyeUrl/hx/api/v3/token" -Headers $header -Method Delete -UseBasicParsing
 
    $apiLogOff
 
    }

##Output of HX Version
Function Get-HX-Version{

    $global:FireEyeVersion = Invoke-restmethod -Uri "$global:FireEyeUrl/hx/api/v3/version" -Headers $header -Method Get
    
    ($global:FireEyeVersion).data

}

##Obtains a list of Hosts on the Server  
Function HX-Get-Hosts($global:token) {
# Gets Info for All hosts in HX

    # Gets info on all hosts in HX (Notice the "...?limit=35000" and
    # increase/decrease depending on number of agents in HX)    #
    $global:FireEyeHosts = Invoke-RestMethod -Uri "$global:FireEyeUrl/hx/api/v3/hosts?limit=35000" -Headers $header -Method Get
 
    $global:FireEyeHosts

    $hosts = ($global:FireEyeHosts).data.entries[0]._id

    #$test = Invoke-RestMethod -uri $FireEyeUrl/hx/api/v3/hosts/$hosts/configuration/actual.json -Headers $header -method Get
    #$test = Invoke-RestMethod -uri $FireEyeUrl/hx/api/v3/hosts/$hosts/files -Headers $header -method Get
    #$test = Invoke-RestMethod -uri $FireEyeUrl/hx/api/v3/acqs/files -Headers $header -method Get

    #$test = Invoke-RestMethod -Uri "$global:FireEyeUrl/hx/api/v3/hosts?search=JIB-B6DH9AL" -Headers $header -Method Get
 
    }

##Gets a list of Host Sets
Function HX-Get-HostSets{
param($hostname=@())
    $global:FireEyeHostSets = Invoke-RestMethod -Uri "$global:FireEyeUrl/hx/api/v3/Host_sets?limit=35000" -Headers $header -Method Get
    $hostsets = ($global:FireEyeHostSets).data.entries
    $total = $hostsets.count
    $num = 0
    $starttime = Get-Date
    foreach($set in $hostsets){
        $hostsetname = $set.name
        $num++
        $secondselapsed = ((Get-Date) - $starttime).totalseconds
        $secondsremaining = ($secondselapsed / ($num / $total)) - $secondselapsed
        $url = $set.url
        $gethostset = Invoke-RestMethod -Uri "$global:FireEyeUrl/$url/hosts?limit=35000" -Headers $header -Method Get
                
            foreach($hosts in $hostname){
                Write-Progress -Activity " Processing $num of $($total) HostSets" -PercentComplete (($num/$($hostsets.count)) * 100) -CurrentOperation "$("{0:N2}" -f ((($num/$($total)) *100),2))% Complete" -SecondsRemaining $secondsremaining
                if((Invoke-RestMethod -Uri "$global:FireEyeUrl/$url/hosts/?search=$hosts" -Headers $header -Method Get).data.total -ne 0){
                $Obj = New-Object psobject
                $Obj | Add-Member -MemberType NoteProperty -Name Hostname $hosts
                $Obj | Add-Member -MemberType NoteProperty -Name HostsetName $hostsetname
                $Obj | Select-Object Hostname, HostSetName | Export-Csv -Append c:\Users\cartospa\Desktop\HostSets-test.csv -NoTypeInformation
                }
            }
    }
}

##Obtains a list of Alerts on the Server
Function HX-Get-Alerts($global:token) {
Measure-command{# Gets Info for All hosts in HX

    # Gets info on all hosts in HX (Notice the "...?limit=35000" and
    # increase/decrease depending on number of agents in HX)    #
    $global:FireEyeAlerts = Invoke-RestMethod -Uri "$global:FireEyeUrl/hx/api/v3/alerts?limit=35000&sort=event_at+desc" -Headers $header -Method Get
 
    #$global:FireEyeAlerts
 
#HX-Get-Info
#HX-Get-Alerts

$alerts = $global:FireEyeAlerts.data.entries
$num = 0
$total = $alerts.count
$starttime = Get-Date

    foreach($alert in $alerts){

        $num++
        $secondselapsed = ((Get-Date) - $starttime).totalseconds
        $secondsremaining = ($secondselapsed / ($num / $total)) - $secondselapsed
        Write-Progress -Activity " Processing $num of $($total) alerts" -PercentComplete (($num/$($alerts.count)) * 100) -CurrentOperation "$("{0:N2}" -f ((($num/$($total)) *100),2))% Complete" -SecondsRemaining $secondsremaining
        #Write-Progress -Activity "Collecting Alert Information" -Status "Processing $num out of $total" -PercentComplete (($num / $total)*100)

        $conditionid = $alert.condition._id
        $url = $alert.agent.url
        $condition = (Invoke-restmethod -uri "$global:FireEyeUrl/hx/api/v3/conditions/$conditionid" -Headers $header).data.tests
        $hostname = (Invoke-restmethod -uri "$global:FireEyeUrl/$url" -Headers $header -Method Get).data.hostname
        $token = $condition.token

        $Obj = New-Object psobject
        $Obj | Add-Member -MemberType NoteProperty -Name TimeStamp $alert.event_at
        $Obj | Add-Member -MemberType NoteProperty -Name IndicatorName $alert.indicator.uri_name
        $Obj | Add-Member -MemberType NoteProperty -Name Token $token
        $Obj | Add-Member -MemberType NoteProperty -Name Operator $condition.operator
        $Obj | Add-Member -MemberType NoteProperty -Name Value $condition.value
        $Obj | Add-Member -MemberType NoteProperty -Name Hostname $hostname
        $Obj | Add-Member -MemberType NoteProperty -Name Alerted_on $alert.event_values.$token
        $Obj | Select-Object TimeStamp,IndicatorName, Token, Operator, Value, Hostname, Alerted_on | Export-Csv -Append c:\Users\cartospa\Desktop\HX-Alert-test.csv -NoTypeInformation

        }

    }> c:\users\cartospa\Desktop\measure.txt} 

##Obtains a list of Alerts Conditions on the Server
Function HX-Get-Conditions($global:token) {
# Gets Info for All hosts in HX

    # Gets info on all hosts in HX (Notice the "...?limit=35000" and
    # increase/decrease depending on number of agents in HX)    #
    $global:FireEyeConditions = Invoke-RestMethod -Uri "$global:FireEyeUrl/hx/api/v3/conditions?limit=35000" -Headers $header -Method Get
 
    $global:FireEyeConditions
 
    }

##Obtains a list of Searches for all hosts
Function HX-Get-Searches($global:token) {
# Gets Info for All hosts in HX

    # Gets info on all hosts in HX (Notice the "...?limit=35000" and
    # increase/decrease depending on number of agents in HX)    #
    $global:FireEyeSearches = Invoke-RestMethod -Uri "$global:FireEyeUrl/hx/api/v3/searches?limit=35000" -Headers $header -Method Get
    $global:FireEyeSearchCounts = Invoke-RestMethod -Uri "$global:FireEyeUrl/hx/api/v3/searches/counts?limit=35000" -Headers $header -Method Get

    $global:FireEyeSearches
 
    }


##Obtains a list of Indicators and their conditions on Server
Function HX-Get-Indicators($global:token) {
# Gets Info for All hosts in HX

    # Gets info on all hosts in HX (Notice the "...?limit=35000" and
    # increase/decrease depending on number of agents in HX)    #
    $global:FireEyeIndicators = Invoke-RestMethod -Uri "$global:FireEyeUrl/hx/api/v3/indicators?limit=35000" -Headers $header -Method Get
 
   # $global:FireEyeIndicators

    $indicators = $global:FireEyeindicators.data.entries
    
        foreach($indicator in $indicators){
        $url = $indicator.url
        $condition = Invoke-RestMethod -Uri "$global:FireEyeUrl/$url/conditions?limit=35000" -Headers $header -Method Get
        $tests = $condition.data.entries.tests

            foreach($t in $tests){
                $Obj = New-Object psobject
                $Obj | Add-Member -MemberType NoteProperty -Name IndicatorName $indicator.uri_name
                $Obj | Add-Member -MemberType NoteProperty -Name Token $t.token
                $Obj | Add-Member -MemberType NoteProperty -Name Operator $t.operator
                $Obj | Add-Member -MemberType NoteProperty -Name Value $t.value
                $Obj | Select-Object IndicatorName, Token, Operator, Value | Export-Csv -Append c:\Users\cartospa\Desktop\HX-indicators-test.csv -NoTypeInformation
            }
        }
 
    }

##Obtains a list of Indicator Categories
Function HX-Get-Indicator_Categories($global:token) {
# Gets Info for All hosts in HX

    # Gets info on all hosts in HX (Notice the "...?limit=35000" and
    # increase/decrease depending on number of agents in HX)    #
    $global:FireEyeCategories = Invoke-RestMethod -Uri "$global:FireEyeUrl/hx/api/v3/indicator_categories?limit=35000" -Headers $header -Method Get
    #$global:scripts = Invoke-webrequest -Uri "$global:FireEyeUrl/hx/api/v3/scripts/" -Headers $header 

    $global:FireEyeCategories

    
    $urls = $FireEyeCategories.data.entries.url

    foreach($url in $urls){
    $url = ($url -split ("/"))[5]
    $test = Invoke-RestMethod -uri $FireEyeUrl/hx/api/v3/indicators/$url -Headers $header -Method Get
    $test
    $url
    }

    
        }
 
##Obtains a list of Scripts on Server
Function HX-Get-Scripts($global:token) {
# Gets Info for All hosts in HX

    # Gets info on all hosts in HX (Notice the "...?limit=35000" and
    # increase/decrease depending on number of agents in HX)    #
    $global:FireEyescripts = Invoke-RestMethod -Uri "$global:FireEyeUrl/hx/api/v3/scripts?limit=35000" -Headers $header -Method Get
    #$global:scripts = Invoke-webrequest -Uri "$global:FireEyeUrl/hx/api/v3/scripts/" -Headers $header 

    $global:FireEyescripts

    foreach($script in $FireEyescripts){

        $script = ($script -split ("/"))[5]

        Invoke-WebRequest -Uri "$global:FireEyeUrl/hx/api/v3/scripts" -Headers $header -Method Get

        }
 
    }

##Obtains a list of CUSTOM IOCs
Function HX-Get-Directory($global:token) {
# Gets Info for All hosts in HX

    # Gets info on all hosts in HX (Notice the "...?limit=35000" and
    # increase/decrease depending on number of agents in HX)    #
    $global:FireEyeDirectory = Invoke-RestMethod -Uri "$global:FireEyeUrl/hx/api/v3/indicators/Custom?limit=35000" -Headers $header -Method Get
 
    $global:FireEyeDirectory
 
    }
    
##Deletes a Host(s) from the Server
Function HX-Delete-Host($AgentID,$global:token){
# Delete Host based off Agent ID
   
    $DeleteHost = Invoke-RestMethod -Uri "$global:FireEyeUrl/hx/api/v3/hosts/$AgentID" -Headers $header -Method Delete
       
    $DeleteHost.StatusCode
    }
 
 ##Will find duplicate agents on Server
Function HX-Get-Dedup-Hosts{

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

##Remove Duplicate Agents
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

##Function to authenticate to server (Run this Function to authenticate)
Function HX-Get-Info{

    $global:Server = Read-Host -Prompt "Enter FirEye HX IP"
    $global:Port = Read-host -Prompt "Enter FireEye HX Port"
    $global:FireEyeUrl = "https://$global:Server"+":$global:Port"
    $timestamp = Get-Date -Format yyyyMMdd-HHmm
   
        # Authenticates to the HX Server and returns a user Token
        Ignore-SelfSignedCerts
   
    $global:Token = HX-Auth
    
    }

## This will Authenticate to the HX server that you specify
HX-Get-Info

