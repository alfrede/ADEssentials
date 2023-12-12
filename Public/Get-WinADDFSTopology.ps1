﻿function Get-WinADDFSTopology {
    [cmdletbinding()]
    param(
        [alias('ForestName')][string] $Forest,
        [string[]] $ExcludeDomains,
        [alias('Domain', 'Domains')][string[]] $IncludeDomains,
        [ValidateSet('MissingAtLeastOne', 'MissingAll', 'All')][string] $Type = 'All'
    )
    $ForestInformation = Get-WinADForestDetails -Forest $Forest -IncludeDomains $IncludeDomains -ExcludeDomains $ExcludeDomains

    $Properties = @(
        'Name', 'msDFSR-ComputerReference', 'msDFSR-MemberReferenceBL',
        'ProtectedFromAccidentalDeletion', 'serverReference',
        'WhenChanged', 'WhenCreated',
        'DistinguishedName'
    )

    foreach ($Domain in $ForestInformation.Domains) {
        $DomainDN = ConvertTo-DistinguishedName -CanonicalName $Domain -ToDomain
        $QueryServer = $ForestInformation['QueryServers'][$Domain].HostName[0]
        $ObjectsInOu = Get-ADObject -LDAPFilter "(ObjectClass=msDFSR-Member)" -Properties $Properties -SearchBase "CN=Topology,CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=System,$DomainDN" -Server $QueryServer
        #$Data = $ObjectsInOu | Select-Object -Property Name, msDFSR-ComputerReference, msDFSR-MemberReferenceBL, ProtectedFromAccidentalDeletion, serverReference, WhenChanged, WhenCreated, DistinguishedName
        foreach ($Object in $ObjectsInOu) {
            if ($null -eq $Object.'msDFSR-ComputerReference' -and ($null -eq $Object.'msDFSR-MemberReferenceBL' -or $Object.'msDFSR-MemberReferenceBL'.Count -eq 0) -and $null -eq $Object.serverReference) {
                $Status = 'MissingAll'
            } elseif ($null -eq $Object.serverReference) {
                $Status = 'MissingAtLeastOne'
            } elseif ($null -eq $Object.'msDFSR-ComputerReference') {
                $Status = 'MissingAtLeastOne'
            } elseif ($null -eq $Object.'msDFSR-MemberReferenceBL' -or $Object.'msDFSR-MemberReferenceBL'.Count -eq 0) {
                $Status = 'MissingAtLeastOne'
            } else {
                $Status = 'OK'
            }

            $DataObject = [PSCustomObject] @{
                'Name'                            = $Object.Name
                'Status'                          = $Status
                'Domain'                          = $Domain
                'msDFSR-ComputerReference'        = $Object.'msDFSR-ComputerReference'
                'msDFSR-MemberReferenceBL'        = $Object.'msDFSR-MemberReferenceBL'
                'ServerReference'                 = $Object.serverReference
                'ProtectedFromAccidentalDeletion' = $Object.ProtectedFromAccidentalDeletion
                'WhenChanged'                     = $Object.WhenChanged
                'WhenCreated'                     = $Object.WhenCreated
                'DistinguishedName'               = $Object.DistinguishedName
                'QueryServer'                     = $QueryServer
            }

            if ($Type -eq 'MissingAll') {
                if ($Status -eq 'MissingAll') {
                    $DataObject
                }
            } elseif ($Type -eq 'MissingComputerReference') {
                if ($Status -eq 'MissingComputerReference') {
                    $DataObject
                }
            } elseif ($Type -eq 'MissingMemberReferenceBL') {
                if ($Status -eq 'MissingMemberReferenceBL') {
                    $DataObject
                }
            } elseif ($Type -eq 'MissingServerReference') {
                if ($Status -eq 'MissingServerReference') {
                    $DataObject
                }
            } else {
                $DataObject
            }
        }
    }
}