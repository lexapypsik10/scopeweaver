# Read-only normalized collector. Requires Windows RSAT ActiveDirectory module.
# Not an ACL/RBCD/effective-policy collector; see output collection_notes.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Server,
    [Parameter(Mandatory = $true)][string]$Output
)
$ErrorActionPreference = 'Stop'
if (Test-Path -LiteralPath $Output) { throw 'Output already exists; choose a new path.' }
Import-Module ActiveDirectory
$domain = Get-ADDomain -Server $Server
$policy = Get-ADDefaultDomainPasswordPolicy -Server $Server -Identity $domain.DNSRoot
$properties = @('userAccountControl', 'servicePrincipalName', 'msDS-AllowedToDelegateTo',
                'msDS-SupportedEncryptionTypes', 'adminCount')
$directoryAccounts = @()
$directoryAccounts += @(Get-ADUser -Filter * -Server $Server -Properties $properties)
$directoryAccounts += @(Get-ADComputer -Filter * -Server $Server -Properties $properties)
$directoryAccounts += @(Get-ADServiceAccount -Filter * -Server $Server -Properties $properties)
$directoryAccounts = @($directoryAccounts | Sort-Object -Property { $_.SID.Value } -Unique)
$directoryGroups = @(Get-ADGroup -Filter * -Server $Server -Properties Members)
$dnToSid = @{}
foreach ($entry in @($directoryAccounts) + @($directoryGroups)) {
    $dnToSid[$entry.DistinguishedName] = $entry.SID.Value
}
$accounts = @(
    foreach ($entry in $directoryAccounts) {
        $uac = [int]$entry.userAccountControl
        $kind = 'user'
        if ($entry.ObjectClass -eq 'computer') { $kind = 'computer' }
        if ($entry.ObjectClass -like '*ManagedServiceAccount') { $kind = 'service' }
        if (($uac -band 8192) -ne 0) { $kind = 'domain_controller' }
        $enc = $null
        if ($null -ne $entry.'msDS-SupportedEncryptionTypes') {
            $enc = [int]$entry.'msDS-SupportedEncryptionTypes'
        }
        @{
            id = $entry.SID.Value; name = $entry.SamAccountName; kind = $kind
            enabled = (($uac -band 2) -eq 0); user_account_control = $uac
            encryption_types = $enc; admin_count = $entry.adminCount
            spns = @($entry.servicePrincipalName | Where-Object { $null -ne $_ })
            allowed_to_delegate_to = @($entry.'msDS-AllowedToDelegateTo' | Where-Object { $null -ne $_ })
        }
    }
)
$builtinPrivileged = @('S-1-5-32-544', 'S-1-5-32-548', 'S-1-5-32-549',
                       'S-1-5-32-550', 'S-1-5-32-551')
$groups = @(
    foreach ($entry in $directoryGroups) {
        $sid = $entry.SID.Value
        $members = @(
            foreach ($memberDn in $entry.Members) {
                if ($dnToSid.ContainsKey($memberDn)) { $dnToSid[$memberDn] }
                else { $memberDn }
            }
        )
        @{
            id = $sid; name = $entry.Name; members = $members
            privileged = (($sid -match '-(512|518|519|520)$') -or ($sid -in $builtinPrivileged))
        }
    }
)
$export = @{
    schema_version = '1.0'; domain = $domain.DNSRoot
    policy = @{
        minimum_length = [int]$policy.MinPasswordLength
        composition_required = [bool]$policy.ComplexityEnabled
        periodic_rotation_required = ($policy.MaxPasswordAge.TotalSeconds -gt 0)
        reversible_encryption = [bool]$policy.ReversibleEncryptionEnabled
        lockout_threshold = [int]$policy.LockoutThreshold
    }
    accounts = $accounts; groups = $groups; permissions = @()
    collection_notes = @(
        "Read-only RSAT collection from explicitly selected server: $Server"
        'ACLs and RBCD descriptors were not collected; absence is unknown.'
        'Fine-grained resultant policies, MFA and blocklist controls were not collected.'
        'Privileged groups use selected standard SIDs; review custom administrative groups.'
    )
}
$export | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $Output -Encoding UTF8
Write-Output "Exported normalized metadata to $Output"
