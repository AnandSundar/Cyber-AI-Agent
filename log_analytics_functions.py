"""
Module for querying Azure Log Analytics and processing log data.

This module provides functionality to connect to an Azure Log Analytics workspace,
execute KQL queries across various tables (like AzureActivity, SigninLogs),
and process the results into DataFrames or CSV format.
"""

from datetime import timedelta
from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient
import pandas as pd

LOG_ANALYTICS_WORKSPACE_ID = "60c7f53e-249a-4077-b68e-55a4ae877d7c"

# Available Tables: DeviceLogonEvents, AzureNetworkAnalytics_CL, AzureActivity, SigninLogs
TABLE_NAME = "AzureActivity"

FIELDS = {
    "DeviceLogonEvents": (
        "TimeGenerated, AccountName, DeviceName, ActionType, RemoteIP, RemoteDeviceName"
    ),
    "AzureNetworkAnalytics_CL": (
        "TimeGenerated, FlowType_s, SrcPublicIPs_s, DestIP_s, DestPort_d, VM_s, "
        "AllowedInFlows_d, AllowedOutFlows_d, DeniedInFlows_d, DeniedOutFlows_d"
    ),
    "AzureActivity": (
        "TimeGenerated, OperationNameValue, ActivityStatusValue, "
        "ResourceGroup, Caller, CallerIpAddress, Category"
    ),
    "SigninLogs": (
        "TimeGenerated, UserPrincipalName, OperationName, Category, ResultSignature, "
        "ResultDescription, AppDisplayName, IPAddress, LocationDetails"
    ),
}

HOURS_AGO = 1

# Need Azure CLI:
# https://learn.microsoft.com/en-us/cli/azure/install-azure-cli-windows?view=azure-cli-latest&pivots=msi

log_analytics_client = LogsQueryClient(credential=DefaultAzureCredential())


def query_log_analytics(client, workspace_id, table, fields, timespan_hours_ago):
    """
    Queries an Azure Log Analytics workspace using KQL.

    Args:
        client: The LogsQueryClient to use for the query.
        workspace_id: The ID of the Log Analytics workspace.
        table: The name of the table to query.
        fields: The fields to project in the query.
        timespan_hours_ago: The number of hours back to query.

    Returns:
        The results of the query as a table.
    """

    kql_query = f"""
    {table}
    | project {fields}
    """

    print(kql_query)

    response = client.query_workspace(
        workspace_id=workspace_id,
        query=kql_query,
        timespan=timedelta(hours=timespan_hours_ago),
    )

    # Extract the table
    table_results = response.tables[0]

    return table_results


results = query_log_analytics(
    log_analytics_client,
    LOG_ANALYTICS_WORKSPACE_ID,
    TABLE_NAME,
    FIELDS[TABLE_NAME],
    HOURS_AGO,
)

if len(results.rows) == 0:
    print("No data returned from Log Analytics.")
    exit


# Extract columns and rows using dot notation
columns = results.columns  # Already a list of strings
rows = results.rows  # List of row data

df = pd.DataFrame(rows, columns=columns)
records = df.to_csv(index=False)

print(records)

print("fin.")
