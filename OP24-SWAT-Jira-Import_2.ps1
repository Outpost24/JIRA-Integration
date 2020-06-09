# OP24-SWAT-Jira-Import_2.ps1
# *********************************************************************************************************************************************
# *                                                             General Functions                                                             *
# *********************************************************************************************************************************************
# Function to update an existing issue using basic issue template
function update_issue {
    Param
    (
         [Parameter(Mandatory=$true, Position=0)]
         $finding,
         [Parameter(Mandatory=$true, Position=1)]
         [string] $projectid,
         [Parameter(Mandatory=$false, Position=2)]
         [string] $issuetypeID,
         [Parameter(Mandatory=$true, Position=3)]
         [string] $issueID
    )

    # Define a vulnerability object
    $vulnerability = New-Object System.Object
    
    # Write out the whole description from the Finding data
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
    
    # Set items to update
    $update = @{ 
    }

    # Define the "Fields" within the issue request
    $fields = @{ 
            summary = $finding.name;
            description = $description
    }

    # Attach the properties of the finding to our Vulnerability object
    $vulnerability | Add-Member -type NoteProperty -name update -Value $update
    $vulnerability | Add-Member -type NoteProperty -name fields -Value $fields

    # Creating an object for the vulnerability to nest into, then convert to JSON
    $body = ConvertTo-Json $vulnerability -Depth 10
    $body = $body.replace('\\n','\n')

    # Execute API command to update issue
    $issue = (Invoke-RestMethod -uri ($jiraUri +"api/3/issue/" + $issueID) -Headers $headers -Method PUT -ContentType "application/json" -Body $body)
    return $issue
}

# Update a given issue to the correct transition point
function update_issue_transition {
    Param
    (
         [Parameter(Mandatory=$true, Position=0)]
         [string] $issueID,
         [Parameter(Mandatory=$true, Position=1)]
         [string] $transitionID
    )

    # Define a request object
    $request = New-Object System.Object
    
    # Write out the whole description from the Finding data
    $description = ""
    
    # Set items to update (null)
    $update = @{ 
    }

    # Define the "Fields" within the issue request (null)
    $fields = @{ 
    }

    # Define the transition to set
    $transition = @{ 
        id = $transitionID
    }

    # Attach the properties of the finding to our Vulnerability object
    $request | Add-Member -type NoteProperty -name update -Value $update
    $request | Add-Member -type NoteProperty -name fields -Value $fields
    $request | Add-Member -type NoteProperty -name transition -Value $transition

    # Creating an object for the vulnerability to nest into, then convert to JSON
    $body = ConvertTo-Json $request -Depth 10
    $body = $body.replace('\\n','\n')

    $body

    $response = (Invoke-RestMethod -uri ($jiraUri +"api/3/issue/$issueID/transitions") -Headers $headers -Method POST -ContentType "application/json" -Body $body)
    $response
}

# Get transition ID for given finding and status to set it to
function get_transitionID {
    Param
    (
         [Parameter(Mandatory=$true, Position=0)]
         [string] $issueID,
         [Parameter(Mandatory=$true, Position=1)]
         [string] $ticketStatus
    )

    # Get all transitions for the issue
    $response=(Invoke-RestMethod -uri ($jiraUri +"api/3/issue/$issueID/transitions") -Headers $headers -Method GET)
    
    # Return the transition for the specified status
    return ($response.transitions | where {$_.name -like $ticketStatus}).id
}


function get_project_issues {
    Param
    (
         [Parameter(Mandatory=$true, Position=0)]
         [string] $projectid
    )

    $response=(Invoke-RestMethod -uri ($jiraUri +"api/3/issue/picker?currentProjectID=$projectID") -Headers $headers -Method GET)
    return $response

}



function get_existing_findings {
#   Param
#   (
#        [Parameter(Mandatory=$true, Position=0)]
#        [string] $project
#   )
#
    # Get full list of Jira issues for given project
    $response=(Invoke-RestMethod -uri ($jiraUri +"api/3/search?jql=description~%22FindingID%22") -Headers $headers -Method GET)
    return $response
}

# Function to add a comment into an issue
#not working atm
function add_comment {
    Param
    (
         [Parameter(Mandatory=$true, Position=0)]
         [string]$issueID,
         [Parameter(Mandatory=$true, Position=1)]
         [string]$comment
    )
    $body = ('{"body": "'+$comment+'"}')
    $resp = 
       (Invoke-RestMethod -uri ($jiraUri +"api/3/issue/$issueID/comment") -Headers $headers -Method POST -ContentType "application/json" -Body $body).id    
    return $resp
}


function sort_jira_tickets {
    Param
    (
         [Parameter(Mandatory=$true, Position=0)]
         $jiraTickets
    )

#    $vulnerability | Add-Member -type NoteProperty -name update -Value $update
    $sortedTickets = @()
    

    # Basically start with extracting the data for each finding and tracking what finding IDs exist already
    # Need to capture FindingID, fixed status reflected in ticket, current status in Jira, projectID, and issue ID for each issue.
    foreach ($jiraTicket in $jiraTickets) {
        $string = $jiraTicket.fields.description.content[0].content[0].text
        $findingID = $string.Substring($string.IndexOf('[FindingID]')+13, 10)
        $currentFixedStatus = $string.Substring($string.IndexOf('[Fixed?]')+10, 5)
        $ticketStatus = $jiraTicket.fields.status.name
        $issueID = $jiraTicket.id
        $projectID = $jiraTicket.fields.project.id
        $issueTypeID = $jiraTicket.fields.issuetype.id

        $sortedTickets += [pscustomobject]@{findingId   =$findingID; 
                                           currentfixed =$currentFixedStatus; 
                                           ticketStatus =$ticketStatus; 
                                           issueID      =$issueID;
                                           issueTypeID  =$issueTypeID;
                                           projectID    =$issueTypeID
                                           
                                           }


    }
    return $sortedTickets
}