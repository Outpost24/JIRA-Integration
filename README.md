# jira-integration

Instructional video on usage:
https://youtu.be/lb24ohz7yew

    Project Name: OP24-SWAT-Jira-Tasks.ps1
          Author: Eren Cihangir
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


       Usage: OP24-SWAT-Jira-Tasks.ps1 -jiraUri "https://your-domain.atlassian.net/rest/" -jiraUser <youruser> -jiraPw <hidden> -project <yourprojectkey> -op24user <youruser> -op24pw <hidden> -swatApp <appname> -fileImport $fals
