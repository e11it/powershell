# Get-UsersAndGroups.ps1
# Written by Bill Stewart (bstewart@iname.com)

#requires -version 2

<#
.SYNOPSIS
Retreves users, and group membership for each user, from Active Directory.

.DESCRIPTION
Retreves users, and group membership for each user, from Active Directory. Note that each user's primary group is included in the output, and caching is used to improve performance.

.PARAMETER SearchLocation
Distinnguished name (DN) of where to begin searching for user accounts; e.g. "OU=Information Technology,DC=fabrikam,DC=com". If you omit this parameter, the default is the current domain (e.g., "DC=fabrikam,DC=com").

.PARAMETER SearchScope
Specifies the scope for the Active Directory search. Must be one of the following values: Base (Limit the search to the base object, not used), OneLevel (Searches the immediate child objects of the base object), or Subtree (Searches the whole subtree, including the base object and all its child objects). The default value is Subtree. To search only a location but not its children, specify OneLevel.

.OUTPUTS
PSObjects containing the following properties:
  DN        The user's distinguished name
  CN        The user's common name
  UserName  The user's logon name
  Disabled  True if the user is disabled; false otherwise
  Group     The groups the user is a member of (one object per group)
#>

[CmdletBinding()]
param(
  [parameter(Position=0,ValueFromPipeline=$TRUE)]
    [String[]] $SearchLocation="",
    [String][ValidateSet("Base","OneLevel","Subtree")] $SearchScope="Subtree"
)

begin {
  $ADS_NAME_INITTYPE_GC = 3
  $ADS_SETTYPE_DN = 4
  $ADS_NAME_TYPE_1779 = 1
  $ADS_NAME_TYPE_NT4 = 3
  $ADS_UF_ACCOUNTDISABLE = 2

  # Assume pipeline input if SearchLocation is unbound and doesn't exist.
  $PIPELINEINPUT = (-not $PSBOUNDPARAMETERS.ContainsKey("SearchLocation")) -and (-not $SearchLocation)
  # If -SearchLocation is a single-element array containing an emty string
  # (i.e., -SearchLocation not specified and no pipeline), then populate with
  # distinguished name of current domain. In this case, input is not coming
  # from the pipeline.
  if (($SearchLocation.Count -eq 1) -and ($SearchLocation[0] -eq "")) {
    try {
      $SearchLocation[0] = ([ADSI] "").distinguishedname[0]
    }
    catch [System.Management.Automation.RuntimeException] {
      throw "Unable to retrieve the distinguished name for the current domain."
    }
    $PIPELINEINPUT = $FALSE
  }

  # These hash tables cache primary groups and group names for performance.
  $PrimaryGroups = @{}
  $Groups = @{}

  # Create and initialize a NameTranslate object. If it fails, throw an error.
  $NameTranslate = new-object -comobject "NameTranslate"

  try {
    [Void] $NameTranslate.GetType().InvokeMember("Init", "InvokeMethod", $NULL, $NameTranslate, ($ADS_NAME_INITTYPE_GC, $NULL))
  }
  catch [System.Management.Automation.MethodInvocationException] {
    throw $_
  }

  # Create a Pathname object.
  $Pathname = new-object -comobject "Pathname"

  # Returns the last two elements of the DN using the Pathname object.
  function get-rootname([String] $dn) {
    [Void] $Pathname.GetType().InvokeMember("Set", "InvokeMethod", $NULL, $Pathname, ($dn, $ADS_SETTYPE_DN))
    $numElements = $Pathname.GetType().InvokeMember("GetNumElements", "InvokeMethod", $NULL, $Pathname, $NULL)
    $rootName = ""
    ($numElements - 2)..($numElements - 1) | foreach-object {
      $element = $Pathname.GetType().InvokeMember("GetElement", "InvokeMethod", $NULL, $Pathname, $_)
      if ($rootName -eq "") {
        $rootName = $element
      }
      else {
        $rootName += ",$element"
      }
    }
    $rootName
  }

  # Returns an "escaped" copy of the specified DN using the Pathname object.
  function get-escaped([String] $dn) {
    [Void] $Pathname.GetType().InvokeMember("Set", "InvokeMethod", $NULL, $Pathname, ($dn, $ADS_SETTYPE_DN))
    $numElements = $Pathname.GetType().InvokeMember("GetNumElements", "InvokeMethod", $NULL, $Pathname, $NULL)
    $escapedDN = ""
    for ($n = 0; $n -lt $numElements; $n++) {
      $element = $Pathname.GetType().InvokeMember("GetElement", "InvokeMethod", $NULL, $Pathname, $n)
      $escapedElement = $Pathname.GetType().InvokeMember("GetEscapedElement", "InvokeMethod", $NULL, $Pathname, (0, $element))
      if ($escapedDN -eq "") {
        $escapedDN = $escapedElement
      }
      else {
        $escapedDN += ",$escapedElement"
      }
    }
    $escapedDN
  }

  # Return the primary group name for a user. Algorithm taken from
  # http://support.microsoft.com/kb/321360
  function get-primarygroupname([String] $dn) {
    # Pass DN of user to NameTranslate object.
    [Void] $NameTranslate.GetType().InvokeMember("Set", "InvokeMethod", $NULL, $NameTranslate, ($ADS_NAME_TYPE_1779, $dn))
    # Get NT4-style name of user from NameTranslate object.
    $nt4Name = $NameTranslate.GetType().InvokeMember("Get", "InvokeMethod", $NULL, $NameTranslate, $ADS_NAME_TYPE_NT4)
    # Bind to user using ADSI's WinNT provider and get primary group ID.
    $user = [ADSI] "WinNT://$($nt4Name.Replace('\', '/')),User"
    $primaryGroupID = $user.primaryGroupID[0]
    # Retrieve user's groups (primary group is included using WinNT).
    $groupNames = $user.Groups() | foreach-object {
      $_.GetType().InvokeMember("Name", "GetProperty", $NULL, $_, $NULL)
    }
    # Query string is sAMAccountName attribute for each group.
    $queryFilter = "(|"
    $groupNames | foreach-object { $queryFilter += "(sAMAccountName=$($_))" }
    $queryFilter += ")"
    # Build a DirectorySearcher object.
    $searchRootDN = get-escaped (get-rootname $dn)
    $searcher = [ADSISearcher] $queryFilter
    $searcher.SearchRoot = [ADSI] "LDAP://$searchRootDN"
    $searcher.PageSize = 128
    $searcher.SearchScope = "Subtree"
    [Void] $searcher.PropertiesToLoad.Add("samaccountname")
    [Void] $searcher.PropertiesToLoad.Add("primarygrouptoken")
    # Find the group whose primaryGroupToken attribute matches user's
    # primaryGroupID attribute.
    foreach ($searchResult in $searcher.FindAll()) {
      $properties = $searchResult.Properties
      if ($properties["primarygrouptoken"][0] -eq $primaryGroupID) {
        $groupName = $properties["samaccountname"][0]
        return $groupName
      }
    }
  }

  # Return a DN's sAMAccount name based on the distinguished name.
  function get-samaccountname([String] $dn) {
    # Pass DN of group to NameTranslate object.
    [Void] $NameTranslate.GetType().InvokeMember("Set", "InvokeMethod", $NULL, $NameTranslate, ($ADS_NAME_TYPE_1779, $dn))
    # Return the NT4-style name of the group without the domain name.
    $nt4Name = $NameTranslate.GetType().InvokeMember("Get", "InvokeMethod", $NULL, $NameTranslate, $ADS_NAME_TYPE_NT4)
    $nt4Name.Substring($nt4Name.IndexOf("\") + 1)
  }

  function get-usersandgroups2($location) {
    # Finds user objects.
    $searcher = [ADSISearcher] "(&(objectCategory=User)(objectClass=User))"
    $searcher.SearchRoot = [ADSI] "LDAP://$(get-escaped $location)"

    # Setting the PageSize property prevents limiting of search results.
    $searcher.PageSize = 128
    $searcher.SearchScope = $SearchScope

    # Specify which attributes to retrieve ([Void] prevents output).
    [Void] $searcher.PropertiesToLoad.Add("distinguishedname")
    [Void] $searcher.PropertiesToLoad.Add("cn")
    [Void] $searcher.PropertiesToLoad.Add("samaccountname")
    [Void] $searcher.PropertiesToLoad.Add("useraccountcontrol")
    [Void] $searcher.PropertiesToLoad.Add("primarygroupid")
    [Void] $searcher.PropertiesToLoad.Add("memberof")
    # Sort results by CN attribute.
    $searcher.Sort = new-object System.DirectoryServices.SortOption
    $searcher.Sort.PropertyName = "cn"

    foreach ($searchResult in $searcher.FindAll()) {
      $properties = $searchResult.Properties
      $dn = $properties["distinguishedname"][0]
      write-progress "Get-UsersAndGroups" "Searching $location" -currentoperation $dn
      $cn = $properties["cn"][0]
      $userName = $properties["samaccountname"][0]
      $disabled = ($properties["useraccountcontrol"][0] -band $ADS_UF_ACCOUNTDISABLE) -ne 0
      # Create an ArrayList containing user's group memberships.
      $memberOf = new-object System.Collections.ArrayList
      $primaryGroupID = $properties["primarygroupid"][0]
      # If primary group is already cached, add the name to the array;
      # otherwise, find out the primary group name and cache it.
      if ($PrimaryGroups.ContainsKey($primaryGroupID)) {
        [Void] $memberOf.Add($PrimaryGroups[$primaryGroupID])
      }
      else {
        $primaryGroupName = get-primarygroupname $dn
        $PrimaryGroups.Add($primaryGroupID, $primaryGroupName)
        [Void] $memberOf.Add($primaryGroupName)
      }
      # If the user's memberOf attribute is defined, find the group names.
      if ($properties["memberof"]) {
        foreach ($groupDN in $properties["memberof"]) {
          # If the group name is aleady cached, add it to the array;
          # otherwise, find out the group name and cache it.
          if ($Groups.ContainsKey($groupDN)) {
            [Void] $memberOf.Add($Groups[$groupDN])
          }
          else {
            $groupName = get-samaccountname $groupDN
            $Groups.Add($groupDN, $groupName)
            [Void] $memberOf.Add($groupName)
          }
        }
      }
      # Sort the ArrayList and output one object per group.
      $memberOf.Sort()
      foreach ($groupName in $memberOf) {
        $output = new-object PSObject
        $output | add-member NoteProperty "DN" $dn
        $output | add-member NoteProperty "CN" $cn
        $output | add-member NoteProperty "UserName" $userName
        $output | add-member NoteProperty "Disabled" $disabled
        $output | add-member NoteProperty "Group" $groupName
        $output
      }
    }
  }
}

process {
  if ($PIPELINEINPUT) {
    get-usersandgroups2 $_
  }
  else {
    $SearchLocation | foreach-object {
      get-usersandgroups2 $_
    }
  }
}
