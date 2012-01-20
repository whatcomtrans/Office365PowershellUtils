

<#
.SYNOPSIS
Filters objects returned by Get-MsolUser for users which have a particular license AccountSkuId.

.EXAMPLE
Get-MsolUser | Find-MsolUsersWithLicense "whatcomtrans:ENTERPRISEPACK"
#>
function Find-MsolUsersWithLicense {
	[CmdletBinding(SupportsShouldProcess=$false)]
	Param(
		[Parameter(Mandatory=$true,Position=0,HelpMessage="Enter the AccountSkuId to filter users for (see Get-MsolAccountSku).")] [string]$AccountSkuId,
		[Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=1,HelpMessage="Object from Get-MsolUser.")] [Object]$msoluser
	)
	Process {
		foreach ($lic in $msoluser.Licenses) {
			Write-Debug $lic
			if ($lic.AccountSkuId -eq $AccountSkuId) {
				$msoluser
			}
		}
	}
}

Export-ModuleMember -Function "Find-MsolUsersWithLicense"