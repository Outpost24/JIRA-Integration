<#
Project Name: OP24-SWAT-Jira-Tasks.ps1
      Author: Eren Cihangir
        Date: 01/26/2022
     Purpose: Import OP24 SWAT findings from specified app and create default Tasks in the specified JIRA instance/project using API v3.
              In addition, identify and update existing Tasks with latest information.
      Inputs: 
          [required fields]:
                jiraUser   : username for account in JIRA
                jiraPw     : API Token generated at https://id.atlassian.com/manage-profile/security/api-tokens for account in JIRA
                jiraUri    : uri for JIRA instance. 
                   Examples:
                      https://your-domain.atlassian.net/rest/
                       http://localhost:2990/jira/rest/
                project    : Project Key to dump new findings into
                   Examples: Typically short set of capital letters 
                               NH, AMP, TUR
                op24user   : username for account in OP24
                op24pw     : password for account in OP24
              
          [optional fields]:
                fileImport : [bool] Flag to enable importing from local CSV file. Default is $False
                logFile    : [switch] Flag to enable logging and exporting of Findings to CSV file. Default is $False
                swatApp    : name of SWAT application to filter for
                newStatus  : String description of Jira "New" status for a ticket. Example: "Backlog". Must not be null if doneStatus is defined.
                doneStatus : String description of Jira "Done" status for a ticket. Example: "Done". Must not be null if newStatus is defined.
                setLabel   : String description of Jira "label" for a ticket. At this time only a single label is available, and will overwrite each time this run.
                code       : Add MFA code if needed. This is the token generated via SMS or Authenticator.


       Usage: OP24-SWAT-Jira-Tasks.ps1 -jiraUri "https://your-domain.atlassian.net/rest/" -jiraUser <youruser> -jiraPw <hidden> -project <yourprojectkey> -op24user <youruser> -op24pw <hidden> -swatApp <appname> -fileImport $false -newStatus <string> -doneStatus <string> -setLabel <string>
              

       12/05/19: Creation
       12/19/19: Primary functionality
       12/20/19: Built for auto-updating in basic workflow, more documentation. Added, more to come.
       09/02/20: Added logic to handle automatic assignment of "New" and "Done" ticket status. User can provide string to define these using "newStatus" and "doneStatus" arguments
       09/21/20: Fixed logic to handle larger counts of findings, handle "New" and "Done" status better
       10/01/20: Findings now include swatAppName in title, fixed issue with encoding (now encodes utf8)
       10/22/20: Added URL to description, findings will no longer move to "new" if they haven't changed status
       07/18/21: Added "setStatus" to allow user to set transition status for all findings in current scope
       07/19/21: Added "setLabel" to add a custom label to all findings in scope
       07/29/21: Updated documentation
       08/24/21: Added logfile name to include SWAT App, output logfile path and name to log
       08/26/21: Removed "setStatus", will revisit later
       01/17/22: Updated jiraPw description to reflect API token requirement instead of deprecated Basic Auth
       01/17/22: Added MFA token support using -code parameter. "code" is the token generated via SMS or Authenticator.
       01/18/22: Added progress counter, additional logging, and secure password input
       01/26/22: Fixed some logic errors with transition IDs when creating/updating tickets. Added support for SWAT App name to identify SWAT Instances


    Usage Notes: When findings exist in multiple projects, done/new/set status values will only apply based on selected project identifier
                   - If using setStatus and no transitions are found, the finding will remain in its current transition
    
    
    Comments: Some additional work to be done at this time. Need to do following:
                - Support for additional templates
                - cannot distinguish between instances currently, need a way to do this in the API
                - logic to handle one-time passwords (MFA)

Intended Use: Intended to be ad-hoc updating and inserting of vulnerabilities into JIRA. Built to run repeatedly & automatically.
               - In addition, later updates include
               --- link to verify finding within ticket
               --- comments to provide references for ticket history
               - Final iteration (TBD) will come from Development team, hopefully full Atlassian app!
#>

param (
    [Parameter(Mandatory=$False)][string]$jiraUser,
    [Parameter(Mandatory=$False)][string]$jiraPw,
    [Parameter(Mandatory=$False)][string]$jiraUri,
    [Parameter(Mandatory=$False)][string]$project,
    [Parameter(Mandatory=$False)][string]$op24user,
    [Parameter(Mandatory=$False)][string]$op24pw,
    [Parameter(Mandatory=$False)][bool]$testRun = $false,
    [Parameter(Mandatory=$False)][bool]$fileImport,
    [Parameter(Mandatory=$False)][switch]$logFile = $false,
    [Parameter(Mandatory=$False)][string]$swatApp,
    [Parameter(Mandatory=$False)][string]$newStatus,
    [Parameter(Mandatory=$False)][string]$doneStatus,
    [Parameter(Mandatory=$False)][string]$setLabel = $null,
    [Parameter(Mandatory=$False)][string]$code

)

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Add-Type -AssemblyName System.Web
$PSDefaultParameterValues['Out-File:Encoding'] = 'utf16'

# Import function definitions
. ".\OP24-SWAT-Jira-Import.ps1"
. ".\OP24-SWAT-Jira-Import_2.ps1"

# URI for Outpost24 production SaaS
$uri = "https://outscan.outpost24.com"

# Logging
if ($logFile -eq $true) { 
    # Initialize strings and start logging
    $datetime = Get-Date -Format yyyy-MM-ddTHH-mm-ss-ff
    $logname = ".\OP24-Jira-$project-$datetime"
    Start-Transcript -Path "$logname.log" -Force 

    $pwd = Get-Location
    $pwd = $pwd.Path.TrimEnd($pwd.Path.Length,1)
    write-host "Output file located here: $pwd\$logname.log"
    }

# Request Jira credentials if not provided
if ($jiraUser -like $null) {
        $jiraUser = Read-Host -Prompt 'Please input the Jira Account Username'
    }
if ($jiraPw -like $null) {
        $jiraPw = Read-Host -Prompt 'Please input the Jira API Key'
    }
if ($jiraUri -like $null) {
        $jiraUri = Read-Host -Prompt 'Please input the Jira URI (like https://yourdomain.atlassian.net/rest/)'
    }
if ($project -like $null) {
        $project = Read-Host -Prompt 'Please input the Jira Project ID'
    }



# Initialize URI for Jira REST API and log in
$headers = Get-HttpBasicHeader $jiraUser $jiraPw
try {
    $response=(Invoke-RestMethod -uri ($jiraUri +"api/3/issue/createmeta?expand=projects.issuetypes.fields") -Headers $headers -Method GET) 
}
catch {
    write-host "Jira credentials don't work, please try again."
    $Error[0]
    Stop-Transcript
    exit
}


# Test to ensure project ID exists
$projectID = findProjectID($project)
if ($projectID -eq $null) {
    write-host "No project exists with that ID, please try again."
    $Error[0]
    Stop-Transcript
    exit
}


# Decide whether to use file import or Outpost24 API
if ($fileImport -eq $true) {
    # Do file import instead
    # Get the filepath
    Write-host "Please Note: Only .CSV files will be accepted at this time."
    $importFile = Read-Host -Prompt 'Input the path of your import file'

    # Test if file is accessible
    if (!(Test-Path $importFile)) {
        Write-Host "Failed to import file. Please try again."
        $Error[0]
        Stop-Transcript
        exit
    }

    # Test if file is the right type
    if (([System.IO.Path]::GetExtension($importFile)) -notlike ".csv") {
        Write-Host "Wrong file type. Please try again with a CSV file."
        $Error[0]
        Stop-Transcript
        exit
    }

    # If the file is accessible, we can import it here
    Write-Host "File valid! Importing..."
    $findings = Import-Csv $importFile
}
else {
    # Do API import
    # Check if credentials have been supplied. If not, ask for them:
    if ($op24user -like $null) {
        $op24user = Read-Host -Prompt 'Please input the Outpost24 Username'
    }
    if ($op24pw -like $null) {
        $secureop24pw = Read-Host -Prompt  'Please input the Outpost24 Password/Key' -AsSecureString
        $op24pw = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureop24pw))
    }

    # Interact with OP24 API
    $creds = 'username=' + 
                ([System.Web.HttpUtility]::UrlEncode([System.Web.HttpUtility]::UrlDecode($op24user))) + 
                '&password=' + 
                ([System.Web.HttpUtility]::UrlEncode([System.Web.HttpUtility]::UrlDecode($op24pw)))
    if ($code -notlike $null) {
        $creds = $creds + '&code=' + ([System.Web.HttpUtility]::UrlEncode([System.Web.HttpUtility]::UrlDecode($code)))
    }

    try {
        # Log in to get a token
        $response = Invoke-WebRequest -uri ($uri+'/opi/rest/auth/login') -Method post -Body $creds
        
        if ($response.content.contains("TOTP")) {
            write-host "Please provide the MFA Code/token: "
            $code = read-host -Prompt 'Code'
            $creds = $creds + '&code=' + ([System.Web.HttpUtility]::UrlEncode([System.Web.HttpUtility]::UrlDecode($code)))
            $response = Invoke-WebRequest -uri ($uri+'/opi/rest/auth/login') -Method post -Body $creds
        }

        $token = $response.Content
    }
    catch {
        write-host "Credentials for OutPost24 don't work, please try again."
        $Error[0]
        Stop-Transcript
        exit
    }
}

# If login successful, grab findings and start working
write-host "Getting SWAT Findings from Outpost24..."
$findings = Get-OP24WebFindings -token $token -uri "https://outscan.outpost24.com"


# Filter findings to only include SWAT App, if defined
if ($swatApp -notlike "") {
    #Deprecated solution
    #$findings = $findings | where {$_.swatAppName -like $swatApp}

    # Define array for SWAT Schedules and variable for final swatAppID
    $swatSchedules = @()
    $swatAppID

    # Loop though all findings to gather SWAT schedule information
    $swatIDs = $findings | Select-Object swatAppID -Unique
    write-host "LIST OF SWAT IDs": $swatIDs
    foreach ($swatID in $swatIDs) {
        $data = Invoke-WebRequest -uri ($uri + '/opi/rest/swat-schedules/' + $swatID.swatAppID) -Header @{Authorization = "Bearer "+ $token }
        # Convert the data from JSON into powershell object and return it
        $swatSchedule = convertfrom-json $data.content
        $swatSchedules += $swatSchedule
    }

    write-host "COUNT OF SWAT SCHEDULES FOUND": $swatSchedules.count

    # Now that we have all of the SWAT Schedules within the account, loop through them and find the first swatScheduleID with a name like the one provided.
    # If we find one, set the final SWAT App ID to filter findings on, and then gather all of the findings for that SWAT App/Instance
    foreach ($swatSchedule in $swatSchedules) {
        if ($swatSchedule.name -like $swatApp) {
            write-host "HERE IS THE SWAT APP ID" $swatSchedule.id
            $swatAppID = $swatSchedule.id
            break
        }
    }

    if ($swatAppID -notlike $null) {
        # Call webfindings with the filter
        $data = Invoke-WebRequest -uri ($uri + "/opi/rest/webfindings?filter=%5B%7B%22field%22%3A%22scheduleId%22%2C%22value%22%3A" + $swatAppID) -Header @{Authorization = "Bearer "+ $token }
    
        # Convert the data from JSON into powershell object and return it
        $findings = convertfrom-json $data.content
        }
    else {
        write-host "No SWAT app or instance was found with that name. Please try again."
        exit
    }
}


# Finally loop over each finding to add in a field for the associated URLs
write-host "Processing findings..."
foreach ($finding in $findings) {
    # Retrieve the first URL returned from this and add it as a property to the finding
    $URLs = get_SWAT_URLs -token $token -findingID $finding.id
    $finding.description = "\nAffected URL: \n" + $URLs[0].url + '\n\n' + $finding.description
}

$i = 0

# Loop over OP24 findings, and for each one attempt to update the record in Jira
foreach ($finding in $findings) {

    # Search Jira for any tickets 
    $existingFinding = get_existing_finding -swatID $finding.id

    # Check if the results yielded anything. If so, keep going
    if ($existingFinding.total -gt 0) {
        
        # At this point we know Jira has at least one issue related to this finding. If it's more than one, we should update all of them.
        foreach ($result in $existingFinding.issues) {

            # Set up basic data
            $issueID = $result.id
            $projectID = $result.fields.project.id
            $issueTypeID = $result.fields.issuetype.id            
            
            # For each record, identify the transition IDs for workflow (new/done/etc)
            # If these have not been provided, set the transition IDs to null and do not attempt to change ticket status
            if ($newStatus -notlike $null) { $newStatusID = (get_transitionID -issueID $result.id -ticketStatus $newStatus) } else { $newStatusID = $null }
            if ($doneStatus -notlike $null) { $doneStatusID = (get_transitionID -issueID $result.id -ticketStatus $doneStatus) } else { $doneStatusID = $null }


            # For each record, push an update to that issueID with the latest Finding data
            update_issue -finding $finding -projectid $projectId -issueID $issueId -issuetypeID $issueTypeID
            write-Host "Ticket Data Updated:" -ForegroundColor Yellow -NoNewline; Write-Host '('$finding.id')' $finding.name "updated to reflect latest data."

            # Check for and add label if defined in script call
            if ($setLabel -notlike $null) {
                add_issue_label $issueID $setLabel
            }

            
            # Also update this item to reflect the current status if applicable
            if (($newStatusID -like $null -or $doneStatusID -like $null) -and ($newStatus -notlike $null -or $doneStatus -notlike $null)) {
                write-host "Status Not Updated: " -ForegroundColor Magenta -NoNewline; Write-Host '('$finding.id')' "does not have a matching workflow status, skipping ticket status..."
                continue
            }

            # If we've made it here, decide if the issue should stay in whatever queue it is in, or be moved to "Fixed"
            if ($finding.fixed -like "False") {
                # do nothing

            }
            # If we've made it here, then the finding must have been fixed but we should only attempt to update the transition if a doneStatus was found.
            elseif (($finding.fixed -like "True") -and ($doneStatusID -notlike $null)){
                update_issue_transition -transitionID $doneStatusID -issueID $result.id
            }
            else {
                write-host "Something went wrong with issue: " + $result.id
                $Error[0]
                Stop-Transcript
                exit
            }

        }

    }


    # If there were no results, then this must be a new issue. Create a new issue in Jira
    else {
        
        # Create a new issue for this finding

        $projectID = findProjectID($project)
        $basicIssueTypeID = findBasicIssueTypeID($projectID)
        try{
            $newTicket = create_basic_issue -projectid $projectID -finding $finding -issuetypeID $basicIssueTypeID
        }
        catch {
            write-host "Could not create ticket because: " $_.Exception
            continue
        }
        
        write-Host "New: " -ForegroundColor Green -NoNewline; Write-Host '('$finding.id')' $finding.name  "is new."
        write-host "Ticket ID"$newTicket -ForegroundColor Green -NoNewline;  write-host " has been created in Jira under project $project."

        # For each new record, identify the transition IDs for workflow (new/done/etc)
        try { 
            $newStatusID = (get_transitionID -issueID $newTicket -ticketStatus $newStatus)
            }
        catch {
            # No transition ID was found
            $newStatusID = $null 
            }
        
        try {
        $doneStatusID = (get_transitionID -issueID $newTicket -ticketStatus $doneStatus)
            }
        catch { 
            # No transition ID was found
            $doneStatusID = $null 
            }


        # If either of the Transitions were entered wrong, notify the user
        if (($newStatusID -like $null -or $doneStatusID -like $null) -and ($newStatus -notlike $null -or $doneStatus -notlike $null)) {
                write-host "Ticket Status Update Error: " -ForegroundColor Magenta -NoNewline; Write-Host '('$finding.id')' $finding.name "does not have a matching workflow status, skipping ticket status..."
                continue
            }

        # If they've provided new & done status IDs, and they were found, then update the newly-created tickets to reflect those statuses.
        if (($finding.fixed -like "False") -and ($newStatusID -notlike $null)) {
                update_issue_transition -transitionID $newStatusID -issueID $newTicket
            }
        elseif (($finding.fixed -like "True") -and ($doneStatusID -notlike $null)) {
                update_issue_transition -transitionID $doneStatusID -issueID $newTicket
            }
        else {
            # Do nothing
            }
    }
    $i++
    Write-Progress -activity "Going through list of findings..." -status "Finding: $i of $($findings.Count)" -percentComplete (($i / $findings.Count)  * 100)
}

try {Stop-Transcript} catch {Write-Host "No transcript to close."}