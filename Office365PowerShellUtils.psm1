<#
.SYNOPSIS
Filters objects returned by Get-MsolUser for users which have a particular license AccountSkuId.  Requires MSOnline module and active connection to MSOL services.

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
Performs one-way sync of user license assignment with group membership.  Requires ActiveDirectory and MSOnline modules and active connection to MSOL services.

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
						if (!$user.UserPrincipalName) {
							Write-Verbose "Unable to find UserPrincipalName for $user"
						} else {
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
				Invoke-Expression $_.Command -ErrorAction continue
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
Performs one-way sync of user usage location based on group membership.  Requires ActiveDirectory and MSOnline modules and active connection to MSOL services.

.EXAMPLE
TODO
#>
function Update-MsolUserUsageLocation {
	[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact="High",DefaultParameterSetName="UsageLocationFromList")]
	Param(
		[Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=0,HelpMessage="Group(s)")] [Object[]]$ADGroup,
		[Parameter(Mandatory=$true,Position=1,ParameterSetName="UsageLocationFromList",HelpMessage="The UsageLocation(s) to set for group membership.  If more then one value provided they are stepped through for each group provided.  If all groups should reference one location, provide only one.  If each group should match a different UsageLocation, provide a value for each group in same order of groups.")] [String[]]$UsageLocation,
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
				Invoke-Expression $cmdString -ErrorAction continue
			} else {
				Write-Host $cmdString
			}
		}
	}
	Process {
		#TODO Get group and property if using group property value TODO
		
		foreach($valADGroup in $ADGroup) {
			#Get ADGroup, but first make sure it is null so we can detect failure
			$objADGroup = $null
			#If value is a string or some other object passable to Get-ADGroup
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

<#
.SYNOPSIS
Makes it easy to set proxyAddress values in local Active Directory (used with DirSync).  ProxyAddresses can be Added, Removed or just set as Default.

.EXAMPLE
Change-ProxyAddress -Identity TestProxy -ProxyAddress "testproxy1@ridewta.com" -IsDefault -Add -Confirm
#>
function Change-ProxyAddress {
    [CmdletBinding(SupportsShouldProcess=$true,DefaultParameterSetName="Add")]
    param(
        [Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true,HelpMessage="Identity of user to change, takes same as Set-ADUser or pipe a User object.")]
        $Identity,
        [Parameter(Mandatory=$true,Position=1,ValueFromPipeline=$false,HelpMessage="The proxy address to add, without the prefix.  Example, johndoe@domain.com")]
        [String]$ProxyAddress,
        [Parameter(Mandatory=$false,Position=4,ValueFromPipeline=$false,HelpMessage="The proxy address to add, without the prefix.  Example, johndoe@domain.com")]
        [String]$Prefix="smtp",
        [Parameter(Mandatory=$false,Position=3,ValueFromPipeline=$true,HelpMessage="Identity of user to change, takes same as Set-ADUser or pipe a User object.")]
        [Switch] $IsDefault,
        [Parameter(Mandatory=$false,Position=2,ValueFromPipeline=$true,ParameterSetName="Add",HelpMessage="Add the ProxyAddress with the specified Prefix.")]
        [Switch] $Add,
        [Parameter(Mandatory=$false,Position=2,ValueFromPipeline=$true,ParameterSetName="Remove",HelpMessage="Remove the ProxyAddress with the specified Prefix.")]
        [Switch] $Remove
    )

    process {
        $_identity = $Identity
        [String] $_changeaddress = $ProxyAddress
        [boolean] $_isDefault = $IsDefault
        [String] $_prefix = $Prefix


        [boolean] $_exists = $false

        if ($_isDefault) {
            $_prefix = $_prefix.ToUpper()
        }
        [String] $_changeproxyaddress = $_prefix + ":" + $_changeaddress

        #Get all of the existing proxy addresses
        [System.Collections.ArrayList] $_addresses = (Get-ADUser $_identity -Properties proxyAddresses).proxyAddresses


        for ($i=0; $i -lt $_addresses.Count; $i++) {
            [String] $_address = $_addresses[$i]
            if ($_address -Like ($_prefix + ":*")) {
                #Found a proxy address with matching prefix
                if ($_address -like $_changeproxyaddress) {
                    #already exists
                    #if it should not be the default, change it
                    if (!$_isDefault -and ($_address -CLike ($_prefix.ToUpper() + ":*"))) {
                        #found the current default, need to change
                        $_addresses[$i] = $_address.Replace($_prefix.ToUpper(), $_prefix)
                    }

                    #if it should be the default and it is not, change it
                    if ($_isDefault -and ($_address -CLike ($_prefix.ToLower() + ":*"))) {
                        #found the current default, need to change
                        $_addresses[$i] = $_address.Replace($_prefix.ToLower(), $_prefix)
                    }

                    #note that it exists so that Add does not run
                    $_exists = $true
            
                    #if this is a remove process, remove it
                    if ($Remove) {
                        #Remove it
                        $_addresses.RemoveAt($i)
                    }
                } else {
                    #a different proxy with same prefix
                    if ($_isDefault -and ($_address -CLike ($_prefix + ":*"))) {
                        #found the current default, need to change
                        $_addresses[$i] = $_address.Replace($_prefix, $_prefix.ToLower())
                    }
                }
            }
        }
        if (($_exists -eq $false) -and $Add) {
                #proxy not found, add it
                $_addresses += $_changeproxyaddress
        }

        [Array] $_changedaddresses = $_addresses.ToArray()
        $_changedaddresses
        if ($_addresses.Count -gt 0) {
            Set-ADUser $_identity -Replace @{proxyAddresses=$_changedaddresses}
        } else {
            Set-ADUser $_identity -Clear proxyAddresses
        }
    }
}

Echo "Module Loaded"
Export-ModuleMember -Function "Find-MsolUsersWithLicense", "Update-MsolLicensedUsersFromGroup", "Update-MsolUserUsageLocation", "Change-ProxyAddress"
