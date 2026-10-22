# Offline Active Directory exports

The auditor consumes normalized JSON: `schema_version: "1.0"`, `domain`, `policy`,
`accounts`, `groups`, `permissions` and optional `collection_notes`. It never connects
to LDAP, SMB, WinRM, a KDC or a domain controller. See `examples/ad-synthetic.json` and
`examples/schemas/ad-export.schema.json`.

Use consistent stable IDs, preferably canonical SID strings. Group members refer to
account/group IDs, not display names. Mark your organization's privileged groups
explicitly; names and language are not used to guess membership.

| Record | Required fields | Additional evidence |
| --- | --- | --- |
| Account | `id`, `name`, `enabled`, integer `user_account_control` | `kind`, `encryption_types`, `admin_count`, `spns`, `allowed_to_delegate_to`, `rbcd_principals` |
| Group | `id`, `name`, `privileged`, `members` | Nested groups are supported; unknown IDs are reported |
| Permission | `principal`, `target`, `rights`, `access_type`, `privileged_target` | Normalize object-specific GUID rights before export |
| Policy | Any known PasswordPolicy fields | Omit unknown controls rather than invent defaults |

Recognized rights are `GenericAll`, `GenericWrite`, `WriteDacl`, `WriteOwner`,
`ForceChangePassword`, `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All`.
Right names are case-insensitive. Allow ACEs on declared privileged targets are reviewed;
the auditor does not calculate effective access or merge deny ACEs into access decisions.

Zero/missing encryption settings are not proof of RC4 use. Domain controllers are excluded
from the non-DC unconstrained-delegation rule. Disabled accounts are excluded from active
account-risk rules while remaining in membership inventory.

## Optional read-only collector

On a permitted Windows administration host with the RSAT ActiveDirectory module:

```powershell
.\examples\export_ad.ps1 -Server dc01.lab.example -Output .\ad-export.json
```

The script performs directory reads against the explicitly chosen server and does not
extract credentials or change settings. RSAT collection is separate from the Python
transport; approve its collection scope independently. Its execution was not tested in
the local Linux environment used to validate the Python framework.

It exports domain policy, users, computers, managed service accounts and group membership.
ACLs, RBCD descriptors and fine-grained resultant policies are **not** collected; the output
records these gaps in `collection_notes`. Normalize approved supplemental data into
`permissions`/`rbcd_principals` as needed. Review custom privileged-group classification.

Protect exports and reports as administrative metadata. Never add password values, hashes,
tickets or private keys. Unknown schema fields fail validation.
