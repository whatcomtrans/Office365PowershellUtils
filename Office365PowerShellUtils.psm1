
Import-Module MSOnline
Import-Module ActiveDirectory

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

<#
.SYNOPSIS
Performs one-way sync of user license assignment with group membership.

.EXAMPLE
TODO
#>
function Update-MsolLicensedUsersFromGroup {
	[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact="High",DefaultParameterSetName="SKUFromList")]
	Param(
		[Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=0,HelpMessage="Group(s)")] [Object[]]$ADGroup,
		[Parameter(Mandatory=$true,Position=1,ParameterSetName="SKUFromList",HelpMessage="The AccountSkuId(s) to match group membership against(see Get-MsolAccountSku).  If more then one value provided they are stepped through for each group provided.  If all groups should reference one sku, provide only one.  If each group should match a different sku, provide a sku for each group in same order of groups.")] [String[]]$AccountSkuId,
		[Parameter(Mandatory=$true,Position=1,ParameterSetName="SKUFromGroup",HelpMessage="The AD Group property to retrieve the AccountSkuId to match group membership against(see Get-MsolAccountSku).  Use instead of AccountSkuID.  Defaults to the info/note attribute.")] [alias("Property")] [Object]$GroupSKUProperty = "info"
	)
	Begin {
		$groupCounter = 0
		if ($AccountSkuId) {
			#use array
			$skuByArray = $true
		} else {
			#use group property
			$skuByArray = $false
		}
		$changes = @{}
		$skuid = ""
		$groupsUsers = @()
		$msolLicUsers = ""
		
		$ChangeTypeScriptBlock = {
			if ($_.RemoveSkuID -ne "" -and $_.AddSkuID -eq "") {
				Return "Remove"
			} elseif ($_.RemoveSkuID -ne "" -and $_.AddSkuID -ne "") {
				Return "Transfer"
			} elseif ($_.RemoveSkuID -eq "" -and $_.AddSkuID -ne "") {
				Return "Add"
			} elseif ($_.RemoveSkuID -eq "" -and $_.AddSkuID -eq "") {
				Return "None"
			}
		}
		
		$SortOrderScriptBlock = {
			switch ($this.ChangeType) {
				Remove {Return 1}
				Transfer {Return 2}
				Add {Return 3}
				default {Return 0}
			}
		}

		$CommandScriptBlock = {
			switch ($this.ChangeType) {
				Remove {Return "Set-MsolUserLicense -UserPrincipalName " + $this.UserPrincipalName + " -RemoveLicenses " + $this.RemoveSkuID}
				Transfer {Return "Set-MsolUserLicense -UserPrincipalName " + $this.UserPrincipalName + " -AddLicenses " + $this.AddSkuID + " -RemoveLicenses " + $this.RemoveSkuID}
				Add {Return "Set-MsolUserLicense -UserPrincipalName " + $this.UserPrincipalName + " -AddLicenses " + $this.AddSkuID}
				default {Return "#No change for user: " + $this.UserPrincipalName}
			}
		}
	}
	Process {
		#For each group
		foreach($valADGroup in $ADGroup) {
			#Get ADGroup, but first make sure it is null so we can detect failure
			$objADGroup = $null
			#If value is a string or somother object passable to Get-ADGroup
			if ($skuByArray) {
				$objADGroup = Get-ADGroup -Identity $valADGroup
			} else {
				$objADGroup = Get-ADGroup -Identity $valADGroup -Properties $GroupSKUProperty
			}
			if ($objADGroup) {	#Group exists
				#Track accross process calls group count
				$groupCounter++
				#Get the skuid
				if ($skuByArray) {	#Using array instead of group property
					if ($AccountSkuId[($groupCounter - 1)]) {
						#only change skuid if there is antoher value in array, this allows for one skuid to match multiple groups
						$newskuid = $AccountSkuId[($groupCounter - 1)]
					}
				} else {			#Using group property instead of array
					if ($objADGroup.$GroupSKUProperty) {$newskuid = $objADGroup.$GroupSKUProperty}
				}
				if ($newskuid) {	#Found skuid, could be from last time
					if ($newskuid -ne $skuid) {	#moving on to new skuid
						$skuid = $newskuid
						$groupsUsers = @()
						#Get licensed users
						$msolLicUsers = Get-MsolUser | Find-MsolUsersWithLicense $skuid
					}
					
					#Get group members
					$groupMembers = Get-ADGroupMember -Identity $objADGroup -Recursive | Get-ADUser -Properties UserPrincipalName
					$groupsUsers = $groupsUsers + $groupMembers
					
					
					#Get differences
					$compareResults = Compare-Object -ReferenceObject $groupsUsers -DifferenceObject $msolLicUsers -PassThru -Property UserPrincipalName
					
					foreach ($user in $compareResults) {
						if (!$changes.ContainsKey($user.UserPrincipalName)) {
							$newObj = New-Object -TypeName PSObject -Property @{UserPrincipalName = $user.UserPrincipalName; RemoveSkuID = ""; AddSkuID = ""}
							Add-Member -InputObject $newObj -Name 'SortOrder' -Value $SortOrderScriptBlock -MemberType ScriptProperty
							Add-Member -InputObject $newObj -Name 'Command' -Value $CommandScriptBlock -MemberType ScriptProperty
							Add-Member -InputObject $newObj -Name 'ChangeType' -Value $ChangeTypeScriptBlock -MemberType ScriptProperty
							$changes.Add($user.UserPrincipalName, $newObj)
						}
						if ($user.SideIndicator -eq '=>') {	#remove
							($changes.Item($user.UserPrincipalName)).RemoveSkuID = $skuid
						} else {	#add
							($changes.Item($user.UserPrincipalName)).AddSkuID = $skuid
						}
					}
				} else {
					throw "Could not find AccountSkuId with associated group $valADGroup."
				}
			} else {
				throw "Could not find AD group $valADGroup."
			}
		}
	}
	End {
		$ProcessScriptBlock = {
			if ($PSCmdlet.ShouldProcess($_.UserPrincipalName)) {
				Invoke-Expression $_.Command
				Write-Verbose $_.Command
			} else {
				Write-Host $_.Command
			}
		}
		
		$arrayOfChanges = @()
		
		#Convert to simple array
		$changes.GetEnumerator() | ForEach-Object {$arrayOfChanges += $_.Value}
		
		#Execute the commands
		$arrayOfChanges | Sort-Object -Property SortOrder | ForEach-Object $ProcessScriptBlock
	}
}

<#
.SYNOPSIS
Performs one-way sync of user license assignment with group membership.

.EXAMPLE
TODO
#>
function Update-MsolUserUsageLocation {
	[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact="High",DefaultParameterSetName="UsageLocationFromList")]
	Param(
		[Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=0,HelpMessage="Group(s)")] [Object[]]$ADGroup,
		[Parameter(Mandatory=$true,Position=1,ParameterSetName="UsageLocationFromList",HelpMessage="The UsageLocation(s) to set for group membership.  If more then one value provided they are stepped through for each group provided.  If all groups should reference one sku, provide only one.  If each group should match a different UsageLocation, provide a value for each group in same order of groups.")] [String[]]$UsageLocation = @("US"),
		[Parameter(Mandatory=$true,Position=1,ParameterSetName="UsageLocationFromGroup",HelpMessage="The AD Group property to retrieve the UsageLocation value from.  Defaults to the info/note attribute.")] [alias("Property")] [Object]$GroupUsageLocationProperty = "info"
	)
	Begin {
		$newUsageLocation = ""
		$groupCounter = 0
		if ($UsageLocation) {
			#use array
			$locationByArray = $true
		} else {
			#use group property
			$locationByArray = $false
		}
		$ProcessScriptBlock = {
			$cmdString = "Set-MSOLUser -UsageLocation '" + $UsageLocation + "' -UserPrincipalName " + $_.UserPrincipalName
			Write-Verbose $cmdString
			if ($PSCmdlet.ShouldProcess($_.UserPrincipalName)) {
				Invoke-Expression $cmdString
			}
		}
	}
	Process {
		#TODO Get group and property if using group property value TODO
		
		foreach($valADGroup in $ADGroup) {
			#Get ADGroup, but first make sure it is null so we can detect failure
			$objADGroup = $null
			#If value is a string or somother object passable to Get-ADGroup
			if ($locationByArray) {
				$objADGroup = Get-ADGroup -Identity $valADGroup
			} else {
				$objADGroup = Get-ADGroup -Identity $valADGroup -Properties $GroupSKUProperty
			}
			if ($objADGroup) {	#Group exists
				#Track accross process calls group count
				$groupCounter++
				#Get the skuid
				if ($locationByArray) {	#Using array instead of group property
					if ($UsageLocation[($groupCounter - 1)]) {
						#only change skuid if there is antoher value in array, this allows for one skuid to match multiple groups
						$newUsageLocation = $UsageLocation[($groupCounter - 1)]
					}
				} else {				#Using group property instead of array
					if ($objADGroup.$GroupUsageLocationProperty) {$newUsageLocation = $objADGroup.$GroupUsageLocationProperty}
				}
		
				Get-ADGroupMember -Identity $objADGroup -Recursive | Get-ADUser -Properties UserPrincipalName | ForEach-Object $ProcessScriptBlock		
			}
		}
	}
	End {
	}
}

Echo "Module Loaded"
Export-ModuleMember -Function "Find-MsolUsersWithLicense", "Update-MsolLicensedUsersFromGroup", "Update-MsolUserUsageLocation"
