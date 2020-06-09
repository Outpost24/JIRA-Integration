# OP24-PS-Jira-Interactor.ps1
# *********************************************************************************************************************************************
# *                                                             General Functions                                                             *
# *********************************************************************************************************************************************
# Function that just converts a string into 64bit encoded bytes
function ConvertTo-Base64($string) {
    $bytes  = [System.Text.Encoding]::UTF8.GetBytes($string);
    $encoded = [System.Convert]::ToBase64String($bytes);
    return $encoded;
}

# Format paragraph to ADF (atlassian document format) to submit into comments or multi-line fields
function format_ADFText($text) {
    # Clean up line terminators
    $text = $text.Replace("`r`n","\n")

    # Create content array for paragraph to contain description
    $content1 = New-Object System.Collections.ArrayList
    $content1 += @{text = $text; type = "text"}
    
    # Define paragraph object using content array in content1
    $paragraph = @{
        type = "paragraph";
        content = $content1
    }
    
    # Define content array using paragraph
    $content2 = New-Object System.Collections.ArrayList
    $content2 += $paragraph
    
    # Define description using content array content2
    $returnText = @{
        type = "doc";
        version = 1;
        content = $content2
    }

    # Return object containing the text
    return $returnText
}

# Function to create the HTTP Header for Jira
function Get-HttpBasicHeader([string]$username, [string]$password, $Headers = @{}) {
    $b64 = ConvertTo-Base64 "$($username):$($Password)"
    $Headers["Authorization"] = "Basic $b64"
    $Headers["X-Atlassian-Token"] = "nocheck"
    return $Headers
}


# *********************************************************************************************************************************************
# *                                                          OP24 API Functions                                                               *
# *********************************************************************************************************************************************
# Function to obtain all of the regular findings from Outpost24 to create issues from
function Get-OP24WebFindings ([string]$creds, [string]$uri) {
    # Start off by logging in (this should be handled separately)
    $response = curl -uri ($uri+'/opi/rest/auth/login') -Method post -Body $creds
    $token = $response.Content
    $data = curl -uri ($uri + '/opi/rest/webfindings') -Header @{Authorization = "Bearer "+ $token }
    
    # Convert the data from JSON into powershell object and return it
    $findings = convertfrom-json $data.content
    return  $findings
}


# *********************************************************************************************************************************************
# *                                                          Jira API Functions                                                               *
# *********************************************************************************************************************************************
# Function to add comments into existing issues

# Function to list all of the project that exist
function enumerate_projects() {
    $response=(Invoke-RestMethod -uri ($jiraUri +"api/3/project") -Headers $headers -Method GET)   
    return $response
}

# Function to list all of the issue creation metadata
function get_createMeta() {
    $response=(Invoke-RestMethod -uri ($jiraUri +"api/3/issue/createmeta?expand=projects.issuetypes.fields") -Headers $headers -Method GET)   
    foreach ($project in $response.projects) {
        write-host $project.name
        $project.issuetypes
    }
    return $response.projects
}

# Function to list all of the issue creation metadata
function get_issue([int]$issueID) {
    $response=(Invoke-RestMethod -uri ($jiraUri +"api/3/issue/$issueID`?expand=projects.issuetypes.fields") -Headers $headers -Method GET)
    return $response
}

# Function to find a project ID based on provided string
function findProjectID([string]$projectName) {
    # Get list of projects from Jira
    $response=(Invoke-RestMethod -uri ($jiraUri +"api/3/project") -Headers $headers -Method GET)

    # For each item in the list of Jira projects, check if the submitted project name exists
    #   If it does, return that project ID
    #   If not, return null
    for($i=0; $i-le $response.Count; $i++) {
        if ($response[$i].name -like $projectName -or $response[$i].key -like $projectName) {
            return $response[$i].id
        }
    }
    return $null
}

# Function to find a project ID based on provided string
function findBasicIssueTypeID([string]$projectID) {
    # Get list of projects from Jira
    $response=(Invoke-RestMethod -uri ($jiraUri +"api/3/issue/createmeta?" + $projectID) -Headers $headers -Method GET)

    # Looking at the list of projects, we must determine which one is the correct project by looking at the ID
    foreach ($project in $response.projects) {
        # if the project's ID is the one submitted, then let's check the issue types
        if ($project.id -eq $projectID) {
            # for each issue type, let's check if the type is called "Task"
            foreach ($issueType in $project.issueTypes) {
                # if the issue type is called "Task", let's return the id of this issue type
                if ($issueType.name -like "Task") {
                    return $issueType.id
                }
            }
        }
    }
    return $null
}

# Function to create issue using basic issue template
function create_basic_issue {
    Param
    (
         [Parameter(Mandatory=$true, Position=0)]
         $finding,
         [Parameter(Mandatory=$true, Position=1)]
         [string] $projectid,
         [Parameter(Mandatory=$false, Position=2)]
         [string] $issuetypeID
    )

    # Define a vulnerability object
    $vulnerability = New-Object System.Object
    $update = New-Object System.Object
    
    
    $description = format_ADFText ("[Description]:\n" + $finding.description + 
                                   "\n\n[FindingID]: " + $finding.id +
                                   "\n[Web App Name]: " + $finding.swatAppName +
                                   "\n[First Seen]: " + $finding.firstSeen +
                                   "\n[CVSSv3 Score]: " + $finding.cvssV3Score +
                                   "\n[Risk Level]: " + $finding.riskLevel +
                                   "\n[Impact]: " + $finding.impact +
                                   "\n[Port]: " + $finding.port +
                                   "\n[Fixed?]: " + $finding.fixed +
                                   "\n[Exploits?]: " + $finding.hasExploits +
                                   "\n[WASC]: " + $finding.wasc +
                                   "\n[WASC Name]: " + $finding.wascName +
                                   "\n[WASC Reference]: " + $finding.wascReference +
                                   "\n[SANS Top 25]: " + $finding.sansTop25 +
                                   "\n\n[Solution]:\n" + $finding.solution + 
                                   "\n\n[Recreation Flow]:\n" + $finding.recreationFlow + 
                                   "\n\n[Outpost24 Link]:\nhttps://outscan.outpost24.com/portal/en/#/webfindings/" + $finding.id)
    
    # Define the "Fields" within the issue request
    $fields = @{ 
            summary = $finding.name;
            issuetype = @{id = $issuetypeID};
            description = $description;
            project = @{id = $projectid}
    }

    # Attach the properties of the finding to our Vulnerability object
    $vulnerability | Add-Member -type NoteProperty -name update -Value $update
    $vulnerability | Add-Member -type NoteProperty -name fields -Value $fields

    # Creating an object for the vulnerability to nest into, then convert to JSON
    $body = ConvertTo-Json $vulnerability -Depth 10
    $body = $body.replace('\\n','\n')

    # Execute API command to create issue, then return the newly created Issue ID
    $issue = (Invoke-RestMethod -uri ($jiraUri +"api/3/issue/") -Headers $headers -Method POST -ContentType "application/json" -Body $body).id
    return $issue
}

