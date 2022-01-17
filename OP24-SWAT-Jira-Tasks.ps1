<#
Project Name: OP24-SWAT-Jira-Tasks.ps1
      Author: Eren Cihangir
        Date: 01/17/2022
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
                logFile    : [bool] Flag to enable logging and exporting of Findings to CSV file. Default is $False
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
    [Parameter(Mandatory=$True)][string]$jiraUser,
    [Parameter(Mandatory=$True)][string]$jiraPw,
    [Parameter(Mandatory=$False)][string]$jiraUri,
    [Parameter(Mandatory=$True)][string]$project,
    [Parameter(Mandatory=$False)][string]$op24user,
    [Parameter(Mandatory=$False)][string]$op24pw,
    [Parameter(Mandatory=$False)][bool]$testRun = $False,
    [Parameter(Mandatory=$False)][bool]$fileImport,
    [Parameter(Mandatory=$False)][bool]$logFile = $False,
    [Parameter(Mandatory=$False)][string]$swatApp,
    [Parameter(Mandatory=$False)][string]$newStatus,
    [Parameter(Mandatory=$False)][string]$doneStatus,
    [Parameter(Mandatory=$False)][string]$setLabel = $null,
    [Parameter(Mandatory=$False)][string]$code

)

$failresponse

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
    $logname = ".\OP24-Jira-$project-$swatApp-$datetime"
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
        $jiraUri = Read-Host -Prompt 'Please input the Jira URI'
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
        $op24pw = Read-Host -Prompt 'Please input the Outpost24 Password/Key'
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
        $response = curl -uri ($uri+'/opi/rest/auth/login') -Method post -Body $creds
        
        if ($response.content.contains("TOTP")) {
            write-host "Please provide the MFA Code/token: "
            $code = read-host -Prompt 'Code'
            $creds = $creds + '&code=' + ([System.Web.HttpUtility]::UrlEncode([System.Web.HttpUtility]::UrlDecode($code)))
            $response = curl -uri ($uri+'/opi/rest/auth/login') -Method post -Body $creds
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
$findings = Get-OP24WebFindings -token $token -uri "https://outscan.outpost24.com"


# Filter findings to only include SWAT App, if defined
if ($swatApp -notlike "") {
    $findings = $findings | where {$_.swatAppName -like $swatApp}
}


# Finally loop over each finding to add in a field for the associated URLs
foreach ($finding in $findings) {
    # Retrieve the first URL returned from this and add it as a property to the finding
    $URLs = get_SWAT_URLs -token $token -findingID $finding.id
    $finding.description = "\nAffected URL: \n" + $URLs[0].url + '\n\n' + $finding.description
}


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
            if ($newStatusID -like $null -or $doneStatusID -like $null) {
                write-host "Status Not Updated: " -ForegroundColor Magenta -NoNewline; Write-Host '('$finding.id')' "does not have a matching workflow status."
                continue
            }

            # If we've made it here, decide if the issue should stay in whatever queue it is in, or be moved to "Fixed"
            if ($finding.fixed -like "False") {
                # do nothing

            }
            elseif ($finding.fixed -like "True") {
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
        $newStatusID = (get_transitionID -issueID $newTicket -ticketStatus $newStatus)
        $doneStatusID = (get_transitionID -issueID $newTicket -ticketStatus $doneStatus)

        if ($newStatusID -like $null -or $doneStatusID -like $null) {
                write-host "Ticket Status Update Error: " -ForegroundColor Magenta -NoNewline; Write-Host '('$finding.id')' $finding.name "does not have a matching workflow status, skipping..."
                continue
            }

        if ($finding.fixed -like "False") {
                update_issue_transition -transitionID $newStatusID -issueID $newTicket
            }
            elseif ($finding.fixed -like "True") {
                update_issue_transition -transitionID $doneStatusID -issueID $newTicket
            }
            else {write-host "Something went wrong with issue: " + $result.id}
    }
}

try {Stop-Transcript} catch {Write-Host "No transcript to close."}