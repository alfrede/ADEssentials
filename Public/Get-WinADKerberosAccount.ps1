﻿function Get-WinADKerberosAccount {
    [CmdletBinding()]
    param(
        [alias('ForestName')][string] $Forest,
        [string[]] $ExcludeDomains,
        [alias('Domain', 'Domains')][string[]] $IncludeDomains
    )
    $Today = Get-Date
    $Accounts = [ordered] @{}
    Write-Verbose -Message "Get-WinADKerberosAccount - Gathering information about forest"
    $ForestInformation = Get-WinADForestDetails -Forest $Forest -IncludeDomains $IncludeDomains -ExcludeDomains $ExcludeDomains -PreferWritable
    foreach ($Domain in $ForestInformation.Domains) {
        $Accounts["$Domain"] = [ordered] @{}
    }
    $DomainCount = 0
    $DomainCountTotal = $ForestInformation.Domains.Count
    foreach ($Domain in $ForestInformation.Domains) {
        $DomainCount++
        $ProcessingText = "[Domain: $DomainCount/$DomainCountTotal]"
        Write-Verbose -Message "Get-WinADKerberosAccount - $ProcessingText Processing domain $Domain"
        $QueryServer = $ForestInformation['QueryServers']["$Domain"].HostName[0]

        $Properties = @(
            'Name', 'SamAccountName', 'msDS-KrbTgtLinkBl',
            'Enabled',
            'PasswordLastSet', 'WhenCreated', 'WhenChanged'
            'AllowReversiblePasswordEncryption', 'BadLogonCount', 'AccountNotDelegated'
            'SID', 'SIDHistory'
        )

        $CountK = 0
        try {
            [Array] $KerberosPasswords = Get-ADUser -Filter "Name -like 'krbtgt*'" -Server $QueryServer -Properties $Properties -ErrorAction Stop
        } catch {
            Write-Warning -Message "Get-WinADKerberosAccount - $ProcessingText Processing domain $Domain - unable to get Kerberos accounts. Error: $($_.Exception.Message)"
            continue
        }
        foreach ($Account in $KerberosPasswords) {
            $CountK++
            $ProcessingText = "[Domain: $DomainCount/$DomainCountTotal / Account: $CountK/$($KerberosPasswords.Count)]"
            Write-Verbose -Message "Get-WinADKerberosAccount - $ProcessingText Processing domain $Domain \ Kerberos account ($CountK/$($KerberosPasswords.Count)) $($Account.SamAccountName) \ DC"

            if ($Account.SamAccountName -like "*_*" -and -not $Account.'msDS-KrbTgtLinkBl') {
                Write-Warning -Message "Get-WinADKerberosAccount - Processing domain $Domain \ Kerberos account $($Account.SamAccountName) \ DC - Skipping"
                continue
            }

            $CachedServers = [ordered] @{}
            $CountDC = 0
            $CountDCTotal = $ForestInformation.DomainDomainControllers[$Domain].Count
            foreach ($DC in $ForestInformation.DomainDomainControllers[$Domain]) {
                $CountDC++
                $Server = $DC.HostName
                $ProcessingText = "[Domain: $DomainCount/$DomainCountTotal / Account: $CountK/$($KerberosPasswords.Count), DC: $CountDC/$CountDCTotal]"
                Write-Verbose -Message "Get-WinADKerberosAccount - $ProcessingText Processing domain $Domain \ Kerberos account $($Account.SamAccountName) \ DC Server $Server"
                try {
                    $ServerData = Get-ADUser -Identity $Account.DistinguishedName -Server $Server -Properties 'msDS-KrbTgtLinkBl', 'PasswordLastSet', 'WhenCreated', 'WhenChanged' -ErrorAction Stop
                    $WhenChangedDaysAgo = ($Today) - $ServerData.WhenChanged
                    $PasswordLastSetAgo = ($Today) - $ServerData.PasswordLastSet

                    $CachedServers[$Server] = [PSCustomObject] @{
                        'Server'              = $Server
                        'Name'                = $ServerData.Name
                        'PasswordLastSet'     = $ServerData.'PasswordLastSet'
                        'PasswordLastSetDays' = $PasswordLastSetAgo.Days
                        'WhenChangedDays'     = $WhenChangedDaysAgo.Days
                        'WhenChanged'         = $ServerData.'WhenChanged'
                        'WhenCreated'         = $ServerData.'WhenCreated'
                        'msDS-KrbTgtLinkBl'   = $ServerData.'msDS-KrbTgtLinkBl'
                        'Status'              = 'OK'
                    }
                } catch {
                    Write-Warning -Message "Get-WinADKerberosAccount - Processing domain $Domain $ProcessingText \ Kerberos account $($Account.SamAccountName) \ DC Server $Server - Error: $($_.Exception.Message)"
                    $CachedServers[$Server] = [PSCustomObject] @{
                        'Server'              = $Server
                        'Name'                = $Server
                        'PasswordLastSet'     = $null
                        'PasswordLastSetDays' = $null
                        'WhenChangedDays'     = $null
                        'WhenChanged'         = $null
                        'WhenCreated'         = $null
                        'msDS-KrbTgtLinkBl'   = $ServerData.'msDS-KrbTgtLinkBl'
                        'Status'              = $_.Exception.Message
                    }
                }
            }

            Write-Verbose -Message "Get-WinADKerberosAccount - Gathering information about forest for Global Catalogs"
            $ForestInformationGC = Get-WinADForestDetails -Forest $Forest
            $ProcessingText = "[Domain: $DomainCount/$DomainCountTotal / Account: $CountK/$($KerberosPasswords.Count)]"
            Write-Verbose -Message "Get-WinADKerberosAccount - $ProcessingText Processing domain $Domain \ Kerberos account $($Account.SamAccountName) \ GC"
            $GlobalCatalogs = [ordered] @{}
            $GlobalCatalogCount = 0
            $GlobalCatalogCountTotal = $ForestInformationGC.ForestDomainControllers.Count
            foreach ($DC in $ForestInformationGC.ForestDomainControllers) {
                $GlobalCatalogCount++

                $Server = $DC.HostName
                $ProcessingText = "[Domain: $DomainCount/$DomainCountTotal / Account: $CountK/$($KerberosPasswords.Count), GC: $GlobalCatalogCount/$GlobalCatalogCountTotal]"
                Write-Verbose -Message "Get-WinADKerberosAccount - $ProcessingText Processing domain $Domain \ Kerberos account $($Account.SamAccountName) \ GC Server $Server"

                if ($DC.IsGlobalCatalog ) {
                    try {
                        $ServerData = Get-ADUser -Identity $Account.DistinguishedName -Server "$($Server):3268" -Properties 'msDS-KrbTgtLinkBl', 'PasswordLastSet', 'WhenCreated', 'WhenChanged' -ErrorAction Stop

                        $WhenChangedDaysAgo = ($Today) - $ServerData.WhenChanged
                        $PasswordLastSetAgo = ($Today) - $ServerData.PasswordLastSet

                        $GlobalCatalogs[$Server] = [PSCustomObject] @{
                            'Server'              = $Server
                            'Name'                = $ServerData.Name
                            'PasswordLastSet'     = $ServerData.'PasswordLastSet'
                            'PasswordLastSetDays' = $PasswordLastSetAgo.Days
                            'WhenChangedDays'     = $WhenChangedDaysAgo.Days
                            'WhenChanged'         = $ServerData.'WhenChanged'
                            'WhenCreated'         = $ServerData.'WhenCreated'
                            'msDS-KrbTgtLinkBl'   = $ServerData.'msDS-KrbTgtLinkBl'
                            'Status'              = $_.Exception.Message
                        }
                    } catch {
                        Write-Warning -Message "Get-WinADKerberosAccount - Processing domain $Domain $ProcessingText \ Kerberos account $($Account.SamAccountName) \ GC Server $Server - Error: $($_.Exception.Message)"
                        $GlobalCatalogs[$Server] = [PSCustomObject] @{
                            'Server'              = $Server
                            'Name'                = $Server
                            'PasswordLastSet'     = $null
                            'PasswordLastSetDays' = $null
                            'WhenChangedDays'     = $null
                            'WhenChanged'         = $null
                            'WhenCreated'         = $null
                            'msDS-KrbTgtLinkBl'   = $null
                            'Status'              = $_.Exception.Message
                        }
                    }
                }
            }

            $PasswordLastSetAgo = ($Today) - $Account.PasswordLastSet
            $WhenChangedDaysAgo = ($Today) - $Account.WhenChanged
            $Accounts["$Domain"][$Account.SamAccountName] = @{
                FullInformation   = [PSCustomObject] @{
                    'Name'                              = $Account.Name
                    'SamAccountName'                    = $Account.SamAccountName
                    'Enabled'                           = $Account.Enabled
                    'PasswordLastSet'                   = $Account.PasswordLastSet
                    'PasswordLastSetDays'               = $PasswordLastSetAgo.Days
                    'WhenChangedDays'                   = $WhenChangedDaysAgo.Days
                    'WhenChanged'                       = $Account.WhenChanged
                    'WhenCreated'                       = $Account.WhenCreated
                    'AllowReversiblePasswordEncryption' = $Account.AllowReversiblePasswordEncryption
                    'BadLogonCount'                     = $Account.BadLogonCount
                    'AccountNotDelegated'               = $Account.AccountNotDelegated
                    'SID'                               = $Account.SID
                    'SIDHistory'                        = $Account.SIDHistory
                }
                DomainControllers = $CachedServers
                GlobalCatalogs    = $GlobalCatalogs
            }
        }
    }
    $Accounts
}