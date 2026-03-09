"""Executor module for threat hunting and log analytics operations.

This module provides functions for interacting with Microsoft Defender for Endpoint,
Azure Log Analytics, and OpenAI for threat hunting operations.
"""

# Standard library
import re
from datetime import timedelta
import json
import urllib.parse

# Third-party libraries
import pandas as pd
import requests
from colorama import Fore, Style
from openai import RateLimitError, OpenAIError
from azure.identity import DefaultAzureCredential

# Local modules
import prompt_management


def get_bearer_token():
    """
    Get an Azure bearer token for Microsoft Defender API authentication.

    Uses DefaultAzureCredential to obtain a token for the Microsoft Defender
    API endpoint.

    Returns:
        The authentication token object from Azure Identity.
    """
    credential = DefaultAzureCredential()
    token = credential.get_token("https://api.securitycenter.microsoft.com/.default")
    return token


def get_mde_workstation_id_from_name(token, device_name):
    """
    Look up a Defender for Endpoint machine ID by device name.

    Works if the user provides either the FQDN or just the short hostname.

    Args:
        token: An Azure Identity token (DefaultAzureCredential or similar).
        device_name (str): Short hostname or full FQDN string.

    Returns:
        str: The machine ID.

    Raises:
        ValueError: If no matches are found.
    """
    headers = {"Authorization": f"Bearer {token.token}"}

    # Use 'startswith' so "linux-target-1" will match
    # "linux-target-1.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"
    filter_q = urllib.parse.quote(f"startswith(computerDnsName,'{device_name}')")
    url = f"https://api.securitycenter.microsoft.com/api/machines?$filter={filter_q}"

    resp = requests.get(url, headers=headers, timeout=30)
    resp.raise_for_status()

    machines = resp.json().get("value", [])
    if not machines:
        raise ValueError(f"No machine found starting with {device_name}")

    # If multiple machines match, pick the first.
    # You could add logic here (e.g., choose the most recent 'lastSeen').
    machine_id = machines[0]["id"]
    return machine_id


def quarantine_virtual_machine(token, machine_id):
    """
    Quarantine a virtual machine by isolating it in Microsoft Defender.

    Args:
        token: An Azure Identity token for authentication.
        machine_id (str): The Microsoft Defender machine ID to isolate.

    Returns:
        bool: True if isolation was successful, False otherwise.
    """
    headers = {
        "Authorization": f"Bearer {token.token}",
        "Content-Type": "application/json",
    }

    # Example: Isolate a machine
    payload = {
        "Comment": "Isolation via Python Agentic AI using DefaultAzureCredential",
        "IsolationType": "Full",
    }

    resp = requests.post(
        f"https://api.securitycenter.microsoft.com/api/machines/{machine_id}/isolate",
        headers=headers,
        json=payload,
        timeout=30,
    )

    if resp.status_code in (200, 201):
        return True
    return False


def hunt(
    openai_client, threat_hunt_system_message, threat_hunt_user_message, openai_model
):
    """
    Run the threat hunting flow with OpenAI.

    This function:
    1. Formats the logs into a string
    2. Selects appropriate system prompt from context
    3. Passes logs + role to model
    4. Parses and returns a raw array

    Handles rate-limit/token overage errors gracefully.

    Args:
        openai_client: The OpenAI client instance.
        threat_hunt_system_message: The system message for threat hunting.
        threat_hunt_user_message: The user message containing logs/context.
        openai_model (str): The OpenAI model to use.

    Returns:
        dict or None: Parsed JSON results from the model, or None on error.
    """
    results = []

    messages = [threat_hunt_system_message, threat_hunt_user_message]

    try:
        response = openai_client.chat.completions.create(
            model=openai_model,
            messages=messages,
            response_format={"type": "json_object"},
        )

        results = json.loads(response.choices[0].message.content)
        return results

    except RateLimitError as e:
        error_msg = str(e)

        # Print dark red warning
        print(
            f"{Fore.LIGHTRED_EX}{Style.BRIGHT}"
            f"🚨ERROR: Rate limit or token overage detected!{Style.RESET_ALL}"
        )
        print(
            f"{Fore.LIGHTRED_EX}{Style.BRIGHT}"
            f"The input was too large for this model or hit rate limits."
        )
        print(f"{Style.RESET_ALL}——————————\nRaw Error:\n{error_msg}\n——————————")
        print(f"{Fore.WHITE}Suggestions:")
        print("- Use fewer logs or reduce input size.")
        print("- Switch to a model with a larger context window.")
        print("- Retry later if rate-limited.\n")

        return None  # You can also choose to raise again or exit

    except OpenAIError as e:
        print(f"{Fore.RED}Unexpected OpenAI API error:\n{e}")
        return None


def get_query_context(openai_client, user_message, model):
    """
    Extract and parse the function call selected by the LLM.

    This tool call is part of OpenAI's function calling feature, where the model
    chooses a tool (function) from the provided list, and returns the arguments
    it wants to use to call it.

    Args:
        openai_client: The OpenAI client instance.
        user_message: The user's message/request.
        model (str): The OpenAI model to use.

    Returns:
        dict: The parsed arguments for the selected tool.

    See: https://platform.openai.com/docs/guides/function-calling
    """
    print(
        f"{Fore.LIGHTGREEN_EX}\nDeciding log search parameters "
        f"based on user request...\n"
    )

    system_message = prompt_management.SYSTEM_PROMPT_TOOL_SELECTION

    response = openai_client.chat.completions.create(
        model=model,
        messages=[system_message, user_message],
        tools=prompt_management.TOOLS,
        tool_choice="required",
    )

    # Check if tool calls exist in the response
    if response.choices[0].message.tool_calls:
        function_call = response.choices[0].message.tool_calls[0]
        args = json.loads(function_call.function.arguments)
    else:
        # Handle case where no tool call is returned
        args = {
            "table_name": "",
            "device_name": "",
            "caller": "",
            "user_principal_name": "",
            "time_range_hours": 96,
            "fields": [],
            "about_individual_user": False,
            "about_individual_host": False,
            "about_network_security_group": False,
            "rationale": "No specific query context could be determined from the user's input",
        }

    return args  # or return function_call, args


def query_log_analytics(
    log_analytics_client,
    workspace_id,
    timerange_hours,
    table_name,
    device_name,
    fields,
    caller,
    user_principal_name,
):
    """
    Query Azure Log Analytics for threat hunting data.

    Constructs and executes a KQL query based on the specified parameters.

    Args:
        log_analytics_client: The Azure Log Analytics client.
        workspace_id (str): The Log Analytics workspace ID.
        timerange_hours (int): Number of hours to query back.
        table_name (str): The table to query.
        device_name (str): Device name to filter by.
        fields (str): Comma-separated list of fields to project.
        caller (str): Caller to filter by for AzureActivity table.
        user_principal_name (str): User principal name for SigninLogs.

    Returns:
        dict: Contains 'records' (CSV string) and 'count' (number of records).
    """
    if table_name == "AzureNetworkAnalytics_CL":
        user_query = f"""{table_name}
| where FlowType_s == "MaliciousFlow"
| project {fields}"""

    elif table_name == "AzureActivity":
        user_query = f"""{table_name}
| where isnotempty(Caller) and Caller !in ("d37a587a-4ef3-464f-a288-445e60ed248c","ef669d55-9245-4118-8ba7-f78e3e7d0212","3e4fe3d2-24ff-4972-92b3-35518d6e6462")
| where Caller startswith "{caller}"
| project {fields}"""

    elif table_name == "SigninLogs":
        user_query = f"""{table_name}
| where UserPrincipalName startswith "{user_principal_name}"
| project {fields}"""

    else:
        user_query = f"""{table_name}
| where DeviceName startswith "{device_name}"
| project {fields}"""

    print(f"{Fore.LIGHTGREEN_EX}Constructed KQL Query:")
    print(f"{Fore.WHITE}{user_query}\n")

    print(
        f"{Fore.LIGHTGREEN_EX}Querying Log Analytics Workspace ID: "
        f"'{workspace_id}'..."
    )

    response = log_analytics_client.query_workspace(
        workspace_id=workspace_id,
        query=user_query,
        timespan=timedelta(hours=timerange_hours),
    )

    if len(response.tables[0].rows) == 0:
        print(f"{Fore.WHITE}No data returned from Log Analytics.")
        return {"records": "", "count": 0}

    # Extract the table
    table = response.tables[0]

    # TODO: Handle if returns 0 events
    record_count = len(response.tables[0].rows)

    # Extract columns and rows using dot notation
    columns = table.columns  # Already a list of strings
    rows = table.rows  # List of row data

    df = pd.DataFrame(rows, columns=columns)
    records = df.to_csv(index=False)

    return {"records": records, "count": record_count}


def detect_ioc_type(ioc: str) -> str:
    """Detect the type of IOC based on its format.

    Args:
        ioc: The indicator of compromise to classify

    Returns:
        str: Type of IOC ('ip', 'hash', 'domain', 'filename', 'process', 'location', 'username', 'metadata', 'guid')
    """
    # First, strip common prefixes that GPT adds to IOCs
    clean_ioc = ioc
    prefixes_to_strip = [
        # Basic prefixes
        "Username: ",
        "Usernames: ",
        "IP: ",
        "IPs: ",
        "Location: ",
        "Timestamp: ",
        "Timestamps: ",
        "Timestamp(s): ",
        "App: ",
        "Multiple usernames: ",
        "Multiple timestamps ",
        # Azure/Entra ID prefixes
        "UserId: ",
        "TenantId: ",
        "ASN: ",
        "DeviceIds seen: ",
        "AppId: ",
        "ResourceServicePrincipalId(s): ",
        "SignInIds: ",
        "UserAgent: ",
        "HomeTenantId: ",
        "Device/Session IDs: ",
        "ServicePrincipalId: ",
        "DeviceDetail: ",
        "Session/Correlation IDs: ",
        "IP Address: ",
        "Sample Sign-in Ids (SignIn.Id): ",
        "Sample AppIds: ",
        "Sample App IDs: ",
        "Sample Device/Session IDs: ",
        "Authentication detail: ",
    ]

    for prefix in prefixes_to_strip:
        if ioc.startswith(prefix):
            clean_ioc = ioc[len(prefix) :]
            # Determine type from prefix
            if any(x in prefix for x in ["Username", "UserId"]) or "@" in clean_ioc:
                return "username"
            if "IP" in prefix or "Address" in prefix:
                return "ip"
            if "Location" in prefix:
                return "location"
            if "ASN" in prefix:
                return "ip"  # ASN can be used to look up IP ranges
            if any(
                x in prefix
                for x in [
                    "Timestamp",
                    "App:",
                    "Authentication",
                    "DeviceDetail",
                    "UserAgent",
                ]
            ):
                return "metadata"  # Skip these - not useful for pivoting
            if any(
                x in prefix
                for x in [
                    "TenantId",
                    "AppId",
                    "DeviceIds",
                    "SignInIds",
                    "ServicePrincipalId",
                    "Session",
                    "Correlation",
                    "Sample",
                ]
            ):
                return "guid"  # These are Azure IDs - could be useful for pivoting
            break

    # Use the cleaned IOC for pattern matching
    ioc_to_check = clean_ioc.strip()

    # IPv4 pattern (including if it's after a prefix)
    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", ioc_to_check):
        return "ip"

    # IPv6 pattern
    if re.match(r"^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$", ioc_to_check):
        return "ip"

    # Also match partial IPv6
    if ":" in ioc_to_check and re.match(r"^[0-9a-fA-F:]+$", ioc_to_check):
        return "ip"

    # SHA256 hash (64 hex characters)
    if re.match(r"^[a-fA-F0-9]{64}$", ioc_to_check):
        return "hash"

    # SHA1 hash (40 hex characters)
    if re.match(r"^[a-fA-F0-9]{40}$", ioc_to_check):
        return "hash"

    # MD5 hash (32 hex characters)
    if re.match(r"^[a-fA-F0-9]{32}$", ioc_to_check):
        return "hash"

    # GUID/UUID pattern (8-4-4-4-12 hex format)
    if re.match(
        r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
        ioc_to_check,
    ):
        return "guid"

    # Domain pattern
    if re.match(
        r"^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,}$", ioc_to_check
    ):
        return "domain"

    # Email pattern (contains @)
    if "@" in ioc_to_check and "." in ioc_to_check:
        return "username"

    # Location/address pattern (e.g., "Houston, Texas, US" or "New York")
    if re.match(r"^[A-Za-z\s]+,?\s+[A-Za-z]+,?\s+[A-Z]{2}$", ioc_to_check):
        return "location"
    if re.match(r"^[A-Za-z\s]+,?\s+[A-Za-z]+$", ioc_to_check):
        if len(ioc_to_check) < 30:
            return "location"

    # US state pattern or country code
    if re.match(r"^[A-Z]{2}$", ioc_to_check) and ioc_to_check not in ["IP", "ID", "OK"]:
        return "location"

    # Skip metadata types - not useful for pivoting
    if "timestamp" in ioc.lower() or "app:" in ioc.lower():
        return "metadata"

    # Skip "Multiple" entries
    if ioc.startswith("Multiple"):
        return "metadata"

    return "process"  # Default assumption


def generate_ioc_pivot_query(
    ioc: str, ioc_type: str, original_table: str, time_range_hours: int = 24
) -> dict:
    """Generate a KQL query to pivot on an IOC.

    Args:
        ioc: The indicator of compromise (IP, hash, domain, etc.)
        ioc_type: Type of IOC ('ip', 'hash', 'domain', 'filename', 'process', 'location', 'username', 'guid')
        original_table: The table that contained this IOC
        time_range_hours: Time window for follow-up queries

    Returns:
        dict: Query parameters for the pivot search
    """
    # Strip prefixes to get clean IOC value
    clean_ioc = ioc
    prefixes_to_strip = [
        "Username: ",
        "Usernames: ",
        "IP: ",
        "IPs: ",
        "Location: ",
        "UserId: ",
        "TenantId: ",
        "AppId: ",
        "IP Address: ",
    ]
    for prefix in prefixes_to_strip:
        if ioc.startswith(prefix):
            clean_ioc = ioc[len(prefix) :]
            break

    # Handle parentheses with location info (e.g., "103.232.162.106 (Essendon, Victoria, AU)")
    if "(" in clean_ioc:
        clean_ioc = clean_ioc.split("(")[0].strip()

    # Handle multiple values - take first one
    if "," in clean_ioc:
        clean_ioc = clean_ioc.split(",")[0].strip()

    # Handle partial values like "c54012928a03..."
    if "..." in clean_ioc:
        clean_ioc = clean_ioc.split("...")[0].strip()

    # Handle GUIDs - extract just the GUID part
    guid_match = re.search(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        clean_ioc,
    )
    if guid_match:
        clean_ioc = guid_match.group(0)

    pivot_queries = {
        "ip": {
            "DeviceNetworkEvents": f"""DeviceNetworkEvents
| where RemoteIP == "{clean_ioc}" or LocalIP == "{clean_ioc}"
| where TimeGenerated > ago({time_range_hours}h)
""",
            "SigninLogs": f"""SigninLogs
| where IPAddress == "{clean_ioc}"
| where TimeGenerated > ago({time_range_hours}h)
""",
        },
        "hash": {
            "DeviceProcessEvents": f"""DeviceProcessEvents
| where InitiatingProcessSHA256 == "{clean_ioc}" or SHA256 == "{clean_ioc}"
| where TimeGenerated > ago({time_range_hours}h)
""",
            "DeviceFileEvents": f"""DeviceFileEvents
| where SHA256 == "{clean_ioc}"
| where TimeGenerated > ago({time_range_hours}h)
""",
        },
        "domain": {
            "DeviceNetworkEvents": f"""DeviceNetworkEvents
| where Domain == "{clean_ioc}"
| where TimeGenerated > ago({time_range_hours}h)
"""
        },
        "filename": {
            "DeviceProcessEvents": f"""DeviceProcessEvents
| where FileName == "{clean_ioc}" or ProcessCommandLine contains "{clean_ioc}"
| where TimeGenerated > ago({time_range_hours}h)
"""
        },
        "process": {
            "DeviceProcessEvents": f"""DeviceProcessEvents
| where ProcessCommandLine contains "{clean_ioc}"
| where TimeGenerated > ago({time_range_hours}h)
"""
        },
        "location": {
            "SigninLogs": f"""SigninLogs
| where Location == "{clean_ioc}"
| where TimeGenerated > ago({time_range_hours}h)
"""
        },
        "username": {
            "DeviceLogonEvents": f"""DeviceLogonEvents
| where AccountName == "{clean_ioc}" or InitiatingProcessAccountName == "{clean_ioc}"
| where TimeGenerated > ago({time_range_hours}h)
""",
            "SigninLogs": f"""SigninLogs
| where UserPrincipalName == "{clean_ioc}" or UserId == "{clean_ioc}"
| where TimeGenerated > ago({time_range_hours}h)
""",
        },
        "guid": {
            "SigninLogs": f"""SigninLogs
| where UserId == "{clean_ioc}" or AppId == "{clean_ioc}"
| where TimeGenerated > ago({time_range_hours}h)
"""
        },
    }

    # Return the most relevant query based on IOC type
    return {
        "query": pivot_queries.get(ioc_type, {}).get(original_table, ""),
        "ioc": ioc,
        "ioc_type": ioc_type,
        "clean_ioc": clean_ioc,
        "time_range_hours": time_range_hours,
    }


def query_log_analytics_with_ioc(
    log_analytics_client, workspace_id: str, kql_query: str, time_range_hours: int
):
    """Execute a custom KQL query for IOC pivoting.

    Args:
        log_analytics_client: The Azure Log Analytics client
        workspace_id: The workspace ID
        kql_query: The KQL query string
        time_range_hours: Time window

    Returns:
        dict: Records and count
    """
    print(f"{Fore.CYAN}[IOC PIVOT] Executing: {kql_query[:100]}...")

    response = log_analytics_client.query_workspace(
        workspace_id=workspace_id,
        query=kql_query,
        timespan=timedelta(hours=time_range_hours),
    )

    if len(response.tables[0].rows) == 0:
        return {"records": "", "count": 0}

    table = response.tables[0]
    columns = table.columns
    rows = table.rows
    df = pd.DataFrame(rows, columns=columns)
    records = df.to_csv(index=False)

    return {"records": records, "count": len(rows)}


def iterative_hunt(
    openai_client,
    log_analytics_client,
    workspace_id,
    initial_findings: list,
    original_query_context: dict,
    openai_model: str,
    max_iterations: int = 3,
):
    """Perform iterative threat hunting by pivoting on discovered IOCs.

    Args:
        openai_client: OpenAI client
        log_analytics_client: Azure Log Analytics client
        workspace_id: Workspace ID
        initial_findings: Findings from the initial hunt
        original_query_context: Original query parameters
        openai_model: Model to use
        max_iterations: Maximum pivot rounds

    Returns:
        list: All findings including pivoted results
    """
    all_findings = list(initial_findings)
    processed_iocs = set()

    # Summary of initial findings
    print(
        f"\n{Fore.LIGHTYELLOW_EX}=== Starting Iterative Hunting (max {max_iterations} iterations) ===\n"
    )
    print(
        f"{Fore.WHITE}Initial hunt found {Fore.LIGHTRED_EX}{len(initial_findings)}{Fore.WHITE} threat(s)\n"
    )

    # Extract and display all IOCs from initial findings
    print(f"{Fore.CYAN}--- Extracting IOCs from initial findings ---")
    all_iocs = []
    for idx, finding in enumerate(initial_findings, 1):
        iocs = finding.get("indicators_of_compromise", [])
        title = finding.get("title", "Unknown")[:50]
        print(f"{Fore.WHITE}  Finding #{idx}: {title}")
        if iocs:
            print(f"{Fore.WHITE}    IOCs: {', '.join(iocs[:5])}")
            if len(iocs) > 5:
                print(f"{Fore.WHITE}    ... and {len(iocs) - 5} more")
        else:
            print(f"{Fore.LIGHTBLACK_EX}    No IOCs found")
        all_iocs.extend(iocs)

    unique_iocs = list(set(all_iocs))
    print(f"{Fore.GREEN}Total unique IOCs to pivot on: {len(unique_iocs)}\n")

    for iteration in range(max_iterations):
        print(
            f"\n{Fore.LIGHTYELLOW_EX}=== Iteration {iteration + 1} of {max_iterations} ===\n"
        )

        new_findings = []
        iocs_processed_this_round = 0

        # Process each finding from previous iteration
        findings_to_process = all_findings[-10:] if iteration > 0 else initial_findings
        print(
            f"{Fore.CYAN}Processing {len(findings_to_process)} findings for IOC pivots...\n"
        )

        for finding in findings_to_process:
            iocs = finding.get("indicators_of_compromise", [])
            finding_title = finding.get("title", "Unknown")[:40]

            for ioc in iocs:
                if ioc in processed_iocs:
                    continue

                processed_iocs.add(ioc)
                ioc_type = detect_ioc_type(ioc)
                iocs_processed_this_round += 1

                # Skip metadata types - not useful for pivoting
                if ioc_type == "metadata":
                    print(
                        f"{Fore.LIGHTBLACK_EX}[{iocs_processed_this_round}] Skipping metadata IOC: {ioc[:50]}..."
                    )
                    continue

                print(
                    f"{Fore.MAGENTA}[{iocs_processed_this_round}] Pivoting on IOC: {Fore.WHITE}{ioc[:60]}"
                )
                print(
                    f"{Fore.LIGHTBLACK_EX}    Type: {ioc_type} | Related to: {finding_title}"
                )

                # Generate pivot query
                pivot = generate_ioc_pivot_query(
                    ioc=ioc,
                    ioc_type=ioc_type,
                    original_table=original_query_context.get(
                        "table_name", "DeviceProcessEvents"
                    ),
                    time_range_hours=original_query_context.get("time_range_hours", 96),
                )

                if not pivot["query"]:
                    print(
                        f"{Fore.LIGHTBLACK_EX}    No pivot query available for this IOC type"
                    )
                    continue

                # Display the KQL query that will be executed
                print(f"{Fore.CYAN}    Executing KQL Query:")
                for line in pivot["query"].strip().split("\n"):
                    print(f"{Fore.WHITE}      {line}")

                # Execute pivot query
                pivot_results = query_log_analytics_with_ioc(
                    log_analytics_client=log_analytics_client,
                    workspace_id=workspace_id,
                    kql_query=pivot["query"],
                    time_range_hours=pivot["time_range_hours"],
                )

                if int(pivot_results["count"]) == 0:
                    print(f"{Fore.LIGHTBLACK_EX}    Result: No matching events found")
                    continue

                print(
                    f"{Fore.GREEN}    Result: Found {int(pivot_results['count'])} related events"
                )

                # Show sample of the data found
                if int(pivot_results["count"]) > 0:
                    print(
                        f"{Fore.CYAN}    Analyzing {min(int(pivot_results['count']), 5)} event(s) with GPT..."
                    )

                # Analyze pivot results
                pivot_system_msg = prompt_management.SYSTEM_PROMPT_THREAT_HUNT
                pivot_user_msg = prompt_management.build_threat_hunt_prompt(
                    user_prompt=f"Search for related threats. IOC being pivoted: {ioc}",
                    table_name=original_query_context.get(
                        "table_name", "DeviceProcessEvents"
                    ),
                    log_data=str(pivot_results["records"]),
                )

                # Run analysis on pivot data
                try:
                    response = openai_client.chat.completions.create(
                        model=openai_model,
                        messages=[pivot_system_msg, pivot_user_msg],
                        response_format={"type": "json_object"},
                    )

                    pivot_findings = json.loads(response.choices[0].message.content)
                    findings_list = pivot_findings.get("findings", [])

                    for pf in findings_list:
                        pf["pivot_source_ioc"] = ioc
                        pf["pivot_iteration"] = iteration + 1
                        pf["related_to_finding"] = finding.get("title", "Unknown")

                    new_findings.extend(findings_list)

                    if findings_list:
                        print(
                            f"{Fore.GREEN}    Analysis: Found {len(findings_list)} new threat(s):"
                        )
                        for nf_idx, nf in enumerate(findings_list, 1):
                            nf_title = nf.get("title", "Unknown")[:50]
                            nf_confidence = nf.get("confidence", "Unknown")
                            print(
                                f"{Fore.WHITE}      {nf_idx}. {nf_title} ({nf_confidence} confidence)"
                            )
                    else:
                        print(
                            f"{Fore.YELLOW}    Analysis: No additional threats detected"
                        )

                except Exception as e:
                    print(f"{Fore.RED}    Error analyzing pivot: {e}")

        print(f"\n{Fore.CYAN}--- Iteration {iteration + 1} Summary ---")
        print(f"{Fore.WHITE}IOCs processed this round: {iocs_processed_this_round}")
        print(f"{Fore.WHITE}New threats discovered: {len(new_findings)}")

        if not new_findings:
            print(
                f"{Fore.YELLOW}No new findings in iteration {iteration + 1}, stopping."
            )
            break

        all_findings.extend(new_findings)

    print(f"\n{Fore.LIGHTGREEN_EX}=== Iterative Hunting Complete ===")
    print(f"{Fore.WHITE}Total findings: {Fore.LIGHTGREEN_EX}{len(all_findings)}")
    print(f"{Fore.WHITE}  - Initial: {len(initial_findings)}")
    print(f"{Fore.WHITE}  - From pivots: {len(all_findings) - len(initial_findings)}")
    print(f"{Fore.WHITE}Total unique IOCs processed: {len(processed_iocs)}\n")

    return all_findings
