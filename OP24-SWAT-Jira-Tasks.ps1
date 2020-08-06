<#
Project Name: OP24-SWAT-Jira-Tasks.ps1
      Author: Eren Cihangir
        Date: 12/19/2019
     Purpose: Import OP24 SWAT findings from specified app and create default Tasks in the specified JIRA instance/project using API v3.
              In addition, identify and update existing Tasks with latest information.
   Inputs: 
              [required fields]:
                jiraUser   : username for account in JIRA
                jiraPw     : password for account in JIRA
                jiraUri    : uri for JIRA instance. 
                   Examples:
                      https://your-domain.atlassian.net/rest/
                       http://localhost:2990/jira/rest/
                project    : Project Key to dump new findings
                   Examples: Typically short set of capital letters 
                               NH, AMP, TUR
                op24user   : username for account in OP24
                op24pw     : password for account in OP24
              
              [optional fields]:
                fileImport : [bool] Flag to enable importing from local CSV file. Default is $False
                logFile    : [bool] Flag to enable logging and exporting of Findings to CSV file. Default is $False
                swatApp    : name of SWAT application to filter for


       Usage: OP24-SWAT-JiraTasks.ps1 -jiraUri "https://your-domain.atlassian.net/rest/" -jiraUser <youruser> -jiraPw <hidden> -project <yourprojectkey> -op24user <youruser> -op24pw <hidden> -swatApp <appname> -fileImport $false
              

       12/05: Creation
       12/19: Primary functionality
       12/20: Built for auto-updating in basic workflow, more documentation. Added, more to come.


    Comments: Some additional work to be done at this time. Need to do following:
                - Support for additional templates
                - cannot distinguish between instances currently, need a way to  do this in the API
                - logic to handle one-time passwords (MFA)

Intended Use: Intended to be ad-hoc updating and inserting of vulnerabilities into JIRA. Built to run repeatedly & automatically.
               - In addition, later updates include
               --- support for workflow and custom defined issue types
               --- link to verify finding within ticket
               --- comments to provide references for ticket history
               - Final iteration (TBD) will come from Development team, hopefully full Atlassian app!

#>
param (
    [Parameter(Mandatory=$True)][string]$jiraUser,
    [Parameter(Mandatory=$True)][string]$password,
    [Parameter(Mandatory=$False)][string]$jiraUri = "https://turksmash.atlassian.net/rest/",
    [Parameter(Mandatory=$True)][string]$project,
    [Parameter(Mandatory=$False)][string]$op24user,
    [Parameter(Mandatory=$False)][string]$op24pw,
    [Parameter(Mandatory=$False)][bool]$testRun = $False,
    [Parameter(Mandatory=$False)][bool]$fileImport,
    [Parameter(Mandatory=$False)][bool]$logFile = $False,
    [Parameter(Mandatory=$False)][string]$swatApp

)

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Add-Type -AssemblyName System.Web

# Import function definitions
. ".\OP24-PS-Jira-Import.ps1"
. ".\OP24-PS-Jira-Import_2.ps1"


# Initialize strings and start logging
$datetime = Get-Date -Format yyyy-MM-ddTHH-mm-ss-ff
$logname = ".\OP24-Jira-$project-$datetime"

if ($logFile -eq $true) { Start-Transcript -Path "$logname.log" -Force }


# Initialize URI for Jira REST API and log in
$headers = Get-HttpBasicHeader $jiraUser $password
try {$response=(Invoke-RestMethod -uri ($jiraUri +"api/3/issue/createmeta?expand=projects.issuetypes.fields") -Headers $headers -Method GET) }
catch {
    write-host "Jira credentials don't work, please try again."
    $Error[0]
    break
}


# Test to ensure project ID exists
$projectID = findProjectID($project)
if ($projectID -eq $null) {
    write-host "No project exists with that ID, please try again."
    break
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
        Stop-Transcript
        exit
    }

    # Test if file is the right type
    if (([System.IO.Path]::GetExtension($importFile)) -notlike ".csv") {
        Write-Host "Wrong file type. Please try again with a CSV file."
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
        try {
            $findings = Get-OP24WebFindings -creds $creds -uri "https://outscan.outpost24.com"
        }
        catch {
            write-host "Credentials for OP24 don't work, please try again."
            break
        }
}


# Filter findings to only include SWAT App, if defined
if ($swatApp -notlike "") {
    $findings = $findings | where {$_.swatAppName -like $swatApp}
}


# Now that we have the OP24 findings, it's time to get the existing Jira tickets
$jiraRecords = get_existing_findings
$sortedJiraRecords = sort_jira_tickets -jiraTickets $jiraRecords.issues


# Loop over findings and identify which ones exist in Jira
foreach ($finding in $findings) {

    # At this point we want to pull from all records and see if there are any Findings with the FindingIDs in Jira
    $results = $sortedJiraRecords | where {$_.findingId -match $finding.id}

    
    # If we yield results, make sure to iterate over them
    if ($results -notlike $null) {

        # Upon iteration, update the existing jira record with the latest information for that finding
        foreach ($result in $results) {
            # Determine if the Fixed Status needs to be changed
            if ($result.currentFixed -notlike $finding.fixed) {
                # In this case, the fixed status needs to be updated
                update_issue -finding $finding -projectid $result.projectId -issueID $result.issueId -issuetypeID $result.issueTypeID
                write-Host "Changed: " -ForegroundColor Yellow -NoNewline; Write-Host '('$finding.id')' $finding.name "updated."
            }
            else {
            # In this case, the fixed status doesn't need to be updated
            write-Host "Unchanged:" '('$finding.id')' $finding.name "has not changed."
            }    
        
        }
    }
    else {
        # If no results, create a new jira record with that finding and set the status as appropriately as possible
        $projectID = findProjectID($project)
        $basicIssueTypeID = findBasicIssueTypeID($projectID)
        $newTicket = create_basic_issue -projectid $projectID -finding $finding -issuetypeID $basicIssueTypeID
        write-Host "New: " -ForegroundColor Green -NoNewline; Write-Host '('$finding.id')' $finding.name  "is new."
        write-host "Ticket ID"$newTicket -ForegroundColor Green -NoNewline;  write-host " has been created in Jira under project $project."
    }
}


try {Stop-Transcript} catch {Write-Host "No transcript to close."}
