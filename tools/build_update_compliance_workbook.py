"""
Build the Windows Update Compliance Dashboard workbook.

Outputs two files:
  - <out>/UpdateComplianceDashboard.workbook.json  (paste into Workbook > Edit > Advanced Editor > Gallery Template)
  - <out>/UpdateComplianceDashboard.arm.json       (deploy as an ARM template)

Every query is pinned to a {Workspace} parameter, so the workbook no longer
depends on how it was opened ("No Log Analytics workspace resources are selected").

Usage:
  python tools/build_update_compliance_workbook.py
  python tools/build_update_compliance_workbook.py --workspace-id "/subscriptions/.../workspaces/<name>"
"""

import argparse
import copy
import json
import uuid
from pathlib import Path

LA = "microsoft.operationalinsights/workspaces"
WS = "{Workspace}"
TIME = "TimeRange"
_NS = uuid.UUID("6f1c7a52-6a57-4c38-9d7e-1f6f0f7f0a11")
_seen = {}


def _id(name):
    # Stable IDs so rebuilds diff cleanly; a counter keeps repeated names unique
    _seen[name] = _seen.get(name, 0) + 1
    return str(uuid.uuid5(_NS, f"{name}#{_seen[name]}"))


# ---------------------------------------------------------------- item helpers

def text(name, md, style=None, **kw):
    content = {"json": md.strip("\n")}
    if style:
        content["style"] = style
    return {"type": 1, "content": content, "name": name, **kw}


def query(name, kql, time=TIME, **content_kw):
    """KQL item against the selected workspace. time=None -> no time filter, int -> fixed ms."""
    item_kw = {k: content_kw.pop(k) for k in ("customWidth", "conditionalVisibility", "styleSettings") if k in content_kw}
    content = {"version": "KqlItem/1.0", "query": kql.strip("\n")}
    content.update(content_kw)
    if time == TIME:
        content["timeContextFromParameter"] = TIME
    elif isinstance(time, int):
        content["timeContext"] = {"durationMs": time}
    content["queryType"] = 0
    content["resourceType"] = LA
    content["crossComponentResources"] = [WS]
    return {"type": 3, "content": content, "name": name, **item_kw}


def params(name, parameters, **kw):
    return {
        "type": 9,
        "content": {"version": "KqlParameterItem/1.0", "parameters": parameters, "style": "pills",
                    "queryType": 0, "resourceType": LA},
        "name": name, **kw,
    }


def kql_param(name, kql=None, ptype=1, time=TIME, **kw):
    p = {"id": _id("param:" + name), "version": "KqlParameterItem/1.0",
         "name": name, "type": ptype}
    p.update(kw)
    if kql is not None:
        p["query"] = kql.strip("\n")
        p["crossComponentResources"] = [WS]
        p["queryType"] = 0
        p["resourceType"] = LA
        if time == TIME:
            p["timeContext"] = {"durationMs": 7776000000}
            p["timeContextFromParameter"] = TIME
        elif isinstance(time, int):
            p["timeContext"] = {"durationMs": time}
    return p


def hidden_flag(name, kql, time=TIME):
    return kql_param(name, kql, ptype=1, time=time, isHiddenWhenLocked=True)


def multi_all(name, kql, label=None, time=TIME):
    """Multi-select dropdown with an 'All' option that expands to '*'."""
    kw = dict(isRequired=True, multiSelect=True, quote="'", delimiter=",",
              typeSettings={"additionalResourceOptions": ["value::all"], "selectAllValue": "*", "showDefault": False},
              defaultValue="value::all", value=["value::all"])
    if label:
        kw["label"] = label
    return kql_param(name, kql, ptype=2, time=time, **kw)


def group(name, items, tab=None, **kw):
    g = {"type": 12, "content": {"version": "NotebookGroup/1.0", "groupType": "editable", "items": items},
         "name": name}
    if tab:
        g["conditionalVisibility"] = {"parameterName": "selectedTab", "comparison": "isEqualTo", "value": tab}
    g.update(kw)
    return g


def when(param, value="True", equal=True):
    return {"parameterName": param, "comparison": "isEqualTo" if equal else "isNotEqualTo", "value": value}


def icons(*rules, default="success"):
    grid = [{"operator": op, "thresholdValue": v, "representation": r, "text": "{0}{1}"} for op, v, r in rules]
    grid.append({"operator": "Default", "thresholdValue": None, "representation": default, "text": "{0}{1}"})
    return {"formatter": 18, "formatOptions": {"thresholdsOptions": "icons", "thresholdsGrid": grid}}


def col(match, **kw):
    return {"columnMatch": match, **kw}


DEPLOYMENT_STATUS_ICONS = col("DeploymentStatus", **icons(
    ("==", "Update completed", "success"), ("==", "Failed", "failed"), ("==", "Unknown", "unknown"),
    ("==", "In progress", "pending"), ("==", "On hold", "stopped"), default="question"))

HIDE = {"formatter": 5}


# ---------------------------------------------------------------- shared KQL

# ClientSubstate values are CamelCase (RebootRequired, DownloadStart...), so `has` never matched them.
# `contains` does a substring match, which is what was intended.
STATUS = r"""
| extend
    ReleaseName = coalesce(TargetKBNumber, TargetVersion),
    DeploymentStatus = case(
        ClientState == "Installed" or ClientSubstate == "UpdateInstalled", "Update completed",
        ClientState == "Failed",                                            "Failed",
        ClientState == "Installing",                                        "In progress",
        ClientState == "OnHold",                                            "On hold",
        "Unknown"),
    DetailedStatus = case(
        ClientState == "Installed" or ClientSubstate == "UpdateInstalled", "UpdateSuccessful",
        ClientSubstate contains "Reboot" or ClientSubstate contains "Restart", "Reboot pending",
        ClientSubstate contains "Download",                                 "Download started",
        ClientSubstate contains "Install",                                  "Install started",
        ClientSubstate contains "Commit",                                   "Commit",
        "Unknown")"""

SECURITY_QU = 'UpdateCategory == "WindowsQualityUpdate" and UpdateClassification == "Security"'

INTUNE_NAMES = r"""
let IntuneNames = IntuneDevices
    | summarize arg_max(TimeGenerated, *) by ReferenceId
    | project ReferenceId, IntuneName = DeviceName, IntuneDeviceId = DeviceId;"""

DEVICE_FILTER = r"""| where "{DeviceName:escape}" in ("", "*", "All devices") or Computer contains "{DeviceName:escape}""" + '"'

# Quality updates released in the last 60 days that active devices still don't have.
MISSING_PATCHES_BASE = r"""
let RecentReleases = UCClientUpdateStatus
    | where """ + SECURITY_QU + r"""
    | where UpdateReleaseTime between (ago(60d) .. now())
    | extend ReleaseName = coalesce(TargetKBNumber, TargetVersion)
    | distinct ReleaseName;
let ActiveIntune = IntuneDevices
    | summarize arg_max(TimeGenerated, *) by ReferenceId
    | where todatetime(LastContact) > ago(30d)
    | project ReferenceId, IntuneName = DeviceName, IntuneDeviceId = DeviceId;
UCClientUpdateStatus
| where """ + SECURITY_QU + STATUS + r"""
| where ReleaseName in (RecentReleases)
| where isnotempty(UpdateReleaseTime) and isnotempty(AzureADDeviceId)
| summarize arg_max(TimeGenerated, *) by AzureADDeviceId, ReleaseName
| where DetailedStatus != "UpdateSuccessful"
| join kind=inner ActiveIntune on $left.AzureADDeviceId == $right.ReferenceId
| extend Computer = coalesce(IntuneName, DeviceName)
| where isnotempty(Computer) and Computer != "#""" + '"'

# Active feature update alerts on devices where the feature update hasn't completed.
FU_ISSUES_BASE = r"""
let FUStatus = UCClientUpdateStatus
    | where UpdateCategory == "WindowsFeatureUpdate""" + '"' + STATUS.replace("\n", "\n    ") + r"""
    | summarize arg_max(TimeGenerated, *) by AzureADDeviceId
    | project AzureADDeviceId, DeploymentStatus;
let Intune = IntuneDevices
    | summarize arg_max(TimeGenerated, *) by ReferenceId
    | project ReferenceId, LastContact, IntuneName = DeviceName, IntuneDeviceId = DeviceId, IntuneOSVersion = OSVersion,
              UserName, UserEmail, JoinType, Manufacturer, Model, SerialNumber;
UCUpdateAlert
| where UpdateCategory == "WindowsFeatureUpdate"
| summarize arg_max(TimeGenerated, *) by AzureADDeviceId, DeploymentId, AlertSubtype, ServiceSubstate, ClientSubstate
| where AlertStatus == "Active"
| join kind=inner Intune on $left.AzureADDeviceId == $right.ReferenceId
| join kind=inner FUStatus on AzureADDeviceId
| where DeploymentStatus != "Update completed""" + '"'

SAFEGUARD_BASE = r"""
UCUpdateAlert
| where UpdateCategory == "WindowsFeatureUpdate"
| where AlertSubtype == "SafeguardHold" or ServiceSubstate == "SafeguardHold"
| summarize arg_max(TimeGenerated, *) by AzureADDeviceId, DeploymentId
| where AlertStatus == "Active""" + '"'

POLICY_ISSUES_BASE = r"""
IntuneDevices
| where OS == "Windows"
| where todatetime(LastContact) > ago(30d)
| distinct ReferenceId
| join kind=innerunique (UCUpdateAlert
    | where UpdateCategory == "WindowsFeatureUpdate"
    | extend TargetVersion = case(isempty(TargetVersion), "Unknown TargetVersion", TargetVersion startswith "Win", TargetVersion, strcat("Windows 10-", TargetVersion))
    | extend DeploymentName = strcat(TargetVersion, " (", DeploymentId, ")")
    | project TimeGenerated, DeploymentName, AzureADDeviceId, ServiceSubstate, ClientSubstate, StartTime, ResolvedTime, AlertStatus
    | where isnotempty(StartTime)
    ) on $left.ReferenceId == $right.AzureADDeviceId
| where ServiceSubstate == "RemovedFromDeployment" or ClientSubstate == "RemovedFromDeployment"
| project TimeGenerated, AzureADDeviceId, DeploymentName, ServiceSubstate, StartTime, ResolvedTime
| summarize arg_min(TimeGenerated, *) by AzureADDeviceId, DeploymentName, ServiceSubstate, StartTime, ResolvedTime
| mv-expand TimeRange = range(bin(StartTime, 1d), coalesce(ResolvedTime, now()), 1d)"""

# Readiness: treat devices already on Windows 11 as "Upgraded".
READINESS = r"""iff(OSName contains "Windows 11" or OSVersion contains "Win11" or OSVersion contains "Windows 11", "Upgraded", ReadinessStatus)"""

W11_FILTERS = r"""| where '*' in ({OSBuild}) or OSBuild in ({OSBuild})
| where "{TargetOSBuild}" in ("", "*") or TargetOSBuild == "{TargetOSBuild}""" + '"'

# Deployment names come from UCServiceUpdateStatus instead of a hard-coded list of IDs.
DEPLOYMENT_NAMES = r"""
let DeploymentNames = UCServiceUpdateStatus
    | where isnotempty(DeploymentId) and isnotempty(DeploymentName)
    | summarize arg_max(TimeGenerated, DeploymentName) by DeploymentId
    | project DeploymentId, FriendlyName = DeploymentName;"""
DEPLOYMENT_JOIN = "| join kind=leftouter DeploymentNames on DeploymentId"
DEPLOYMENT_NAME = r"""case(isempty(DeploymentId), "No Deployment Assigned", coalesce(FriendlyName, strcat(TargetVersion, " (", DeploymentId, ")")))"""


def quality_history(title, name, window, comment):
    kql = r"""
UCClientUpdateStatus
// """ + comment + r"""
| where """ + window + r"""
| where """ + SECURITY_QU + STATUS + r"""
| where isnotempty(AzureADDeviceId)
| extend KBNumberRaw = tostring(split(ReleaseName, " ")[0])
// Latest status for each device
| summarize arg_max(TimeGenerated, *) by AzureADDeviceId, KBNumberRaw
| summarize
      Total           = dcount(AzureADDeviceId),
      InstallSuccess  = dcountif(AzureADDeviceId, DeploymentStatus == "Update completed"),
      InstallProgress = dcountif(AzureADDeviceId, DeploymentStatus == "In progress"),
      InstallFailed   = dcountif(AzureADDeviceId, DeploymentStatus == "Failed"),
      AnyBuild        = any(TargetBuild),
      AnyDate         = any(UpdateReleaseTime)
  by KBNumberRaw
| extend SuccessRate = 100.0 * todouble(InstallSuccess) / iif(Total == 0, 1, Total)
// Strip any KB prefix so it isn't doubled up
| extend CleanKB = trim_start("KB", KBNumberRaw)
| extend ReleaseName = strcat("KB", CleanKB, iif(isnotempty(AnyBuild), strcat(" (", AnyBuild, ")"), ""), " - ", format_datetime(AnyDate, "yyyy/MM/dd"))
| extend ["Support URL"] = strcat("https://support.microsoft.com/KB/", CleanKB)
| project SuccessRate, ReleaseName, Total,
    ['Update completed'] = InstallSuccess,
    ['In progress']      = InstallProgress,
    ['Failed']           = InstallFailed,
    ["Support URL"], AnyDate
| order by AnyDate desc"""
    return query(name, kql, time=None, size=3, title=title, showExportToExcel=True, exportToExcelOptions="all",
                 gridSettings={"formatters": [
                     col("SuccessRate", formatter=8, formatOptions={"min": 0, "max": 100, "palette": "redGreen"},
                         numberFormat={"unit": 1, "options": {"style": "decimal", "useGrouping": False}}),
                     col("Total", formatter=4, formatOptions={"palette": "redGreen"}),
                     col("Support URL", formatter=7, formatOptions={"linkTarget": "Url"}),
                     col("AnyDate", **HIDE)]})


def status_tiles(name, kql):
    return query(name, kql, size=3, showAnalytics=True, title="Deployment Overview", showRefreshButton=True,
                 exportFieldName="DetailedStatus", exportParameterName="DetailedStatus", exportDefaultValue="Total",
                 showExportToExcel=True, visualization="tiles",
                 tileSettings={"titleContent": col("DetailedStatus", formatter=1),
                               "leftContent": col("DeviceCount", formatter=12, formatOptions={"palette": "coldHot"},
                                                  numberFormat={"unit": 17, "options": {"style": "decimal", "maximumFractionDigits": 2, "maximumSignificantDigits": 3}}),
                               "secondaryContent": col("buttonText", formatter=1), "showBorder": False},
                 styleSettings={"margin": "0px", "padding": "0px"})


TILE_TAIL = r"""
data
| summarize DeviceCount = count() by DetailedStatus
| union (data | summarize DeviceCount = count() | extend DetailedStatus = 'Total')
| order by DeviceCount desc
| extend buttonText = '{0}'"""


# ---------------------------------------------------------------- top of workbook

def top_items():
    workspace_params = [
        {"id": _id("param:Subscription"), "version": "KqlParameterItem/1.0", "name": "Subscription",
         "type": 6, "isRequired": True, "multiSelect": True, "quote": "'", "delimiter": ",",
         "typeSettings": {"additionalResourceOptions": ["value::all"], "includeAll": True, "showDefault": False},
         "defaultValue": "value::all", "value": ["value::all"]},
        {"id": _id("param:Workspace"), "version": "KqlParameterItem/1.0", "name": "Workspace",
         "label": "Log Analytics workspace", "type": 5, "isRequired": True,
         "query": "resources\n| where type =~ 'microsoft.operationalinsights/workspaces'\n| project value = id, label = name\n| order by label asc",
         "crossComponentResources": ["{Subscription}"],
         "typeSettings": {"additionalResourceOptions": [], "showDefault": False},
         "queryType": 1, "resourceType": "microsoft.resourcegraph/resources"},
    ]

    log_dates = r"""
// Last time each Windows Update for Business reports table received data
union isfuzzy=true UCClient, UCClientReadinessStatus, UCClientUpdateStatus, UCDeviceAlert,
    UCServiceUpdateStatus, UCUpdateAlert, UCDOAggregatedStatus, UCDOStatus
| summarize TimeGenerated = max(TimeGenerated) by Type
| extend URL = strcat("https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/", tolower(Type))
| extend LogDeltaCheck = iif(TimeGenerated > ago(3d), "Service OK", "Service Issues")
| project Type, TimeGenerated, URL, LogDeltaCheck
| sort by TimeGenerated desc"""

    hw_flag = r"""
union isfuzzy=true (print x = 0 | where x == 1), (DeviceInventory_CL | take 1 | project x = 1)
| summarize c = count()
| project Available = iif(c > 0, "True", "False")"""

    app_flag = hw_flag.replace("DeviceInventory_CL", "AppInventory_CL")

    return [
        text("Header Logo ", """
# Windows Update Compliance Dashboard
---

An update compliance reporting solution for Windows client devices. Built by Getronics based on work from Jan Ketil Skanke, Sandy Zeng and Maurice Daly."""),
        params("Workspace Selection", workspace_params),
        text("Text - Workbook Summary", """The purpose of this dashboard is to give you full oversight of your Windows client device patching health. This includes;

1. Patch compliance state over time
2. Feature update state, including support
3. Patch content source, and download figures per category
4. Patching issues reported

**Note:** Values are based on information obtained from multiple logs. The last update time for each log is shown opposite.

### &#9888; Important - Onboarding URL Documentation
In order for clients to communicate with Microsoft telemetry services, please ensure that endpoints listed in the following documentation links are available through your firewall / proxy servers;

https://docs.microsoft.com/en-us/windows/privacy/manage-windows-1809-endpoints#windows-update<br>
https://docs.microsoft.com/en-us/windows/deployment/update/update-compliance-configuration-manual#required-endpoints<br>
https://docs.microsoft.com/en-us/mem/intune/protect/windows-10-expedite-updates
""", customWidth="60"),
        query("Data Grid - Log Dates", log_dates, time=604800000, size=3,
              gridSettings={"formatters": [
                  col("Type", formatter=1, formatOptions={"linkColumn": "URL", "linkTarget": "Url"},
                      tooltipFormat={"tooltip": "Click here to view the Microsoft documentation on this log type"}),
                  col("URL", **HIDE),
                  col("LogDeltaCheck", **icons(("==", "Service Issues", "2")))],
                  "labelSettings": [{"columnId": "Type", "label": "Log File Name"},
                                    {"columnId": "TimeGenerated", "label": "Last Updated"},
                                    {"columnId": "LogDeltaCheck", "label": "Service Status"}]},
              customWidth="40"),
        params("Report Time Range", [
            {"id": _id("param:TimeRange"), "version": "KqlParameterItem/1.0", "name": TIME, "label": "Time Range",
             "type": 4, "value": {"durationMs": 7776000000},
             "typeSettings": {"selectableValues": [{"durationMs": d} for d in (
                 86400000, 172800000, 259200000, 604800000, 1209600000, 2419200000, 2592000000, 5184000000, 7776000000)]}},
            hidden_flag("ActiveClientCount", r"""
IntuneDevices
| where OS == "Windows"
| where todatetime(LastContact) > ago(30d)
| summarize toint(dcount(DeviceId))""", time=None),
            hidden_flag("PatchingThreshold", r"""
IntuneDevices
| where OS == "Windows"
| where todatetime(LastContact) > ago(30d)
| summarize c = dcount(DeviceId)
| project toint(c * 95 / 100)"""),
            hidden_flag("CustomHWLogs", hw_flag),
            hidden_flag("ApplicationLogs", app_flag),
        ]),
        {"type": 11, "content": {"version": "LinkItem/1.0", "style": "tabs", "links": [
            {"id": _id("tab:" + sub), "cellValue": "selectedTab", "linkTarget": "parameter", "linkLabel": label,
             "subTarget": sub, "style": "link"}
            for label, sub in [
                ("Update Summary", "Summary"), ("Quality Update History", "ByQualityUpdates"),
                ("Details by Device", "ByDevice"), ("Details by Update", "ByUpdate"),
                ("Update Issues", "ByComplianceIssue"), ("Delivery Optimization", "ByDeliveryOptimisation"),
                ("Feature Updates", "ByFeatureUpdate"), ("Windows 11 Readiness", "ByWindows11"),
                ("Secure Boot Readiness", "SecureBoot")]]},
         "name": "Parameters "},
    ]


QU_INTRO = """----
## Quality Update Deployment details by {0}

Quality updates deliver both security and non-security fixes to Windows. Quality updates include security updates, critical updates, servicing stack updates, and driver updates. They are typically released on the second Tuesday of each month, though they can be released at any time. The second-Tuesday releases are the ones that focus on security updates. Quality updates are cumulative, so installing the latest quality update is sufficient to get all the available fixes for a specific Windows feature update, including any out-of-band security fixes and any servicing stack updates that might have been released previously.

More information can be found here - https://docs.microsoft.com/en-us/windows/deployment/update/get-started-updates-channels-tools """


DETAIL_GRID = {
    "formatters": [
        DEPLOYMENT_STATUS_ICONS,
        col("DetailedStatus", **icons(("contains", "Commit", "Commit"), ("contains", "Download", "Download"),
                                      ("contains", "Reboot", "2"), ("==", "Unknown", "unknown"))),
        col("ReleaseName", formatter=1, formatOptions={"linkColumn": "MSSupportURL", "linkTarget": "Url"}),
        col("MSSupportURL", **HIDE)],
    "filter": True,
    "labelSettings": [
        {"columnId": "TimeGenerated", "label": "Time Generated"},
        {"columnId": "DeploymentStatus", "label": "Deployment Status"},
        {"columnId": "DetailedStatus", "label": "Last Status"},
        {"columnId": "ReleaseName", "label": "Microsoft KB"},
        {"columnId": "UpdateReleaseTime", "label": "Update Release Date"}]}


# ---------------------------------------------------------------- tab: update summary

ACTIVE_UC_CLIENTS = r"""
let ActiveDevices = IntuneDevices
    | where OS == "Windows"
    | summarize arg_max(TimeGenerated, *) by ReferenceId
    | where todatetime(LastContact) > ago(30d)
    | project ReferenceId;
let Clients = UCClient
    | where AzureADDeviceId in (ActiveDevices)
    | summarize arg_max(TimeGenerated, *) by AzureADDeviceId;"""


def tab_summary():
    status_pie = lambda name, title, column, labels: query(name, ACTIVE_UC_CLIENTS + r"""
Clients
| summarize Devices = count() by """ + column, size=3, title=title, visualization="piechart",
        chartSettings={"seriesLabelSettings": [{"seriesName": k, "label": l, "color": c} for k, l, c in labels]},
        customWidth="33")

    return group("Group - Summary", [
        text("Summary Header", """----
## Update Summary

Security update compliance for Windows devices that have checked in to Intune in the last 30 days.
Target: **{PatchingThreshold}** of **{ActiveClientCount}** active devices (95%) on the latest security update."""),
        query("Summary Tiles", ACTIVE_UC_CLIENTS + r"""
Clients
| summarize
    ["Active devices"] = count(),
    ["On latest security update"] = countif(OSSecurityUpdateStatus == "Latest"),
    ["Missing latest update"] = countif(OSSecurityUpdateStatus == "NotLatest"),
    ["Missing multiple updates"] = countif(OSSecurityUpdateStatus == "MultipleSecurityUpdatesMissing"),
    ["Unsupported Windows build"] = countif(OSFeatureUpdateStatus == "EndOfService")
| evaluate narrow()
| project Metric = Column, Value = todouble(Value)""", size=3, visualization="tiles",
              tileSettings={"titleContent": col("Metric", formatter=1),
                            "leftContent": col("Value", formatter=12, formatOptions={"palette": "auto"},
                                               numberFormat={"unit": 17, "options": {"maximumSignificantDigits": 3, "maximumFractionDigits": 2}}),
                            "showBorder": False}),
        query("Security Compliance Trend", r"""
UCClient
| summarize Status = take_any(OSSecurityUpdateStatus) by Day = bin(TimeGenerated, 1d), AzureADDeviceId
| summarize Devices = count() by Day, Status
| order by Day asc""", size=1, aggregation=3, title="Security update compliance over time - {TimeRange}",
              visualization="areachart",
              chartSettings={"xAxis": "Day", "yAxis": ["Devices"], "group": "Status", "createOtherGroup": None,
                             "showLegend": True,
                             "seriesLabelSettings": [
                                 {"seriesName": "Latest", "label": "On latest", "color": "green"},
                                 {"seriesName": "NotLatest", "label": "Missing latest", "color": "orange"},
                                 {"seriesName": "MultipleSecurityUpdatesMissing", "label": "Missing multiple", "color": "redBright"}]}),
        status_pie("Security Status Pie", "Security update status", "OSSecurityUpdateStatus", [
            ("Latest", "On latest", "green"), ("NotLatest", "Missing latest", "orange"),
            ("MultipleSecurityUpdatesMissing", "Missing multiple", "redBright")]),
        status_pie("Quality Status Pie", "Quality update status (incl. non-security)", "OSQualityUpdateStatus", [
            ("Latest", "On latest", "green"), ("NotLatest", "Not on latest", "orange")]),
        status_pie("Feature Status Pie", "Windows build support", "OSFeatureUpdateStatus", [
            ("InService", "Supported build", "green"), ("EndOfService", "Unsupported build", "red"),
            ("Unknown", "Unknown", "gray")]),
    ], tab="Summary")


# ---------------------------------------------------------------- tab: details by update

def tab_by_update():
    qu_filter = "| where '*' in ({QualityUpdate}) or ReleaseName in ({QualityUpdate})"

    return group("Group - ByUpdates", [
        text("text - 4", QU_INTRO.format("Updates")),
        params("parameters - 5 - Copy", [multi_all("QualityUpdate", r"""
UCClientUpdateStatus
| where """ + SECURITY_QU + r"""
| where isnotempty(UpdateReleaseTime) and isnotempty(DeviceName)
| extend ReleaseName = coalesce(TargetKBNumber, TargetVersion)
| summarize ReleaseDate = max(UpdateReleaseTime) by ReleaseName
| sort by ReleaseDate desc
| project Value = ReleaseName, Label = strcat(ReleaseName, ' - ', format_datetime(ReleaseDate, 'yyyy/MM/dd'))""",
                                                            label="Quality Update")]),
        query("query - 12", r"""
UCClientUpdateStatus
| where """ + SECURITY_QU + STATUS + "\n" + qu_filter + r"""
| summarize count_ = dcount(AzureADDeviceId) by bin(TimeGenerated, 1d), DetailedStatus
| order by TimeGenerated asc""", size=1, aggregation=3, visualization="areachart",
              chartSettings={"xAxis": "TimeGenerated", "yAxis": ["count_"], "group": "DetailedStatus",
                             "createOtherGroup": None, "showLegend": True,
                             "seriesLabelSettings": [{"seriesName": "Unknown", "color": "gray"},
                                                     {"seriesName": "UpdateSuccessful", "color": "green"}]}),
        status_tiles("Deployment Overview", r"""
let data = UCClientUpdateStatus
    | where """ + SECURITY_QU + STATUS.replace("\n", "\n    ") + "\n    " + qu_filter + r"""
    | summarize arg_max(TimeGenerated, *) by AzureADDeviceId, ReleaseName;""" + TILE_TAIL.format("deployment")),
        query("query - 4", INTUNE_NAMES + r"""
UCClientUpdateStatus
| where """ + SECURITY_QU + STATUS + r"""
| where isnotempty(UpdateReleaseTime)
""" + qu_filter + r"""
| join kind=leftouter IntuneNames on $left.AzureADDeviceId == $right.ReferenceId
| extend Computer = coalesce(IntuneName, DeviceName, AzureADDeviceId)
| where isnotempty(Computer) and Computer != "#"
| summarize arg_max(TimeGenerated, *) by AzureADDeviceId, ReleaseName
| where DetailedStatus == "{DetailedStatus}" or "{DetailedStatus}" in ("Total", "")
| extend MSSupportURL = strcat("https://support.microsoft.com/KB/", trim_start("KB", tostring(split(ReleaseName, " ")[0])))
| project TimeGenerated, Computer, DeploymentStatus, DetailedStatus, ClientSubstate, ReleaseName, TargetBuild, UpdateReleaseTime, MSSupportURL
| sort by UpdateReleaseTime desc, Computer asc""",
              size=0, showAnalytics=True, title="DetailedStatus - {DetailedStatus}", showRefreshButton=True,
              exportedParameters=[{"fieldName": "Computer", "parameterName": "SelectedDevice", "defaultValue": "(none)"}],
              showExportToExcel=True, visualization="table", gridSettings=DETAIL_GRID),
        query("Deployment details", r"""
UCClientUpdateStatus
| where """ + SECURITY_QU + STATUS + "\n" + qu_filter + r"""
| where isnotempty(AzureADDeviceId)
// One record per device per update
| summarize arg_max(TimeGenerated, *) by AzureADDeviceId, ReleaseName
| extend ReleaseDateStr = format_datetime(UpdateReleaseTime, 'yyyy/MM/dd')
| summarize
    Total = dcount(AzureADDeviceId),
    SuccessCount = dcountif(AzureADDeviceId, DeploymentStatus == "Update completed")
    by ReleaseName, TargetVersion, ReleaseDateStr
| extend ReleaseName = strcat(ReleaseName, " (", TargetVersion, ") - ", ReleaseDateStr)
| extend SuccessRate = iff(Total > 0, todouble(SuccessCount) * 100.0 / Total, 0.0)
| project SuccessRate, ReleaseName, Total, ['Update completed'] = SuccessCount
| order by ReleaseName desc""", size=3, title="All Deployment details", showExportToExcel=True,
              gridSettings={"formatters": [
                  col("SuccessRate", formatter=8, formatOptions={"min": 0, "max": 100, "palette": "redGreen"},
                      numberFormat={"unit": 1, "options": {"style": "decimal", "useGrouping": False}}),
                  col("Total", formatter=4, formatOptions={"palette": "redGreen"})]}),
    ], tab="ByUpdate")


# ---------------------------------------------------------------- tab: details by device

def tab_by_device():
    dev_filter = '| where AzureADDeviceId == "{DeviceId}"'
    base = r"""
UCClientUpdateStatus
| where """ + SECURITY_QU + STATUS + r"""
""" + dev_filter + r"""
| where isnotempty(UpdateReleaseTime)
| summarize arg_max(TimeGenerated, *) by AzureADDeviceId, ReleaseName"""

    return group("Group - ByDevice", [
        text("text - 4", QU_INTRO.format("Device")),
        params("parameters - 5 - Copy", [kql_param("DeviceId", r"""
let clientDevices = UCClient
    | where isnotempty(AzureADDeviceId)
    | summarize arg_max(TimeGenerated, *) by AzureADDeviceId
    | project AzureADDeviceId, UCName = iff(DeviceName == "#", "", DeviceName);
IntuneDevices
| summarize arg_max(TimeGenerated, *) by ReferenceId
| project ReferenceId, IntuneName = DeviceName
| join kind=inner clientDevices on $left.ReferenceId == $right.AzureADDeviceId
| project value = AzureADDeviceId, label = coalesce(IntuneName, UCName, AzureADDeviceId)
| where isnotempty(label) and label != "#"
| order by label asc""", ptype=2, label="Device", isGlobal=True, isRequired=True,
                                                     typeSettings={"additionalResourceOptions": [], "showDefault": False})]),
        status_tiles("Deployment Overview Tiles", "let data = " + base.strip("\n").replace("\n", "\n    ") + ";"
                     + TILE_TAIL.format("Deployment(s)")),
        query("Quality Update Deployment Device Details", base + r"""
| where DetailedStatus == "{DetailedStatus}" or "{DetailedStatus}" in ("Total", "")
| extend MSSupportURL = strcat("https://support.microsoft.com/KB/", trim_start("KB", tostring(split(ReleaseName, " ")[0])))
| project TimeGenerated, Computer = DeviceName, DeploymentStatus, DetailedStatus, ClientSubstate, ReleaseName, TargetBuild, UpdateReleaseTime, MSSupportURL
| sort by UpdateReleaseTime desc""",
              size=0, showAnalytics=True, title="DetailedStatus - {DetailedStatus}", showRefreshButton=True,
              exportedParameters=[{"fieldName": "Computer", "parameterName": "DeviceName_s", "defaultValue": "(none)"},
                                  {"fieldName": "ReleaseName", "parameterName": "ReleaseName_s", "parameterType": 1},
                                  {"fieldName": "DeploymentStatus", "parameterName": "DeploymentStatus_s", "parameterType": 1}],
              showExportToExcel=True, visualization="table", gridSettings=DETAIL_GRID),
        query("Deployment details", base + r"""
| extend ReleaseName = strcat(ReleaseName, ' - ', format_datetime(UpdateReleaseTime, 'yyyy/MM/dd'))
| summarize Total = count(),
    ['Update completed'] = countif(DeploymentStatus == "Update completed"),
    ['In progress'] = countif(DeploymentStatus == "In progress"),
    ['Failed'] = countif(DeploymentStatus == "Failed"),
    ['Unknown'] = countif(DeploymentStatus == "Unknown")
    by ReleaseName
| extend SuccessRate = iff(Total > 0, ['Update completed'] * 100.0 / Total, 0.0)
| project-reorder SuccessRate
| order by ReleaseName desc""", size=3, title="All Deployment details", showExportToExcel=True,
              gridSettings={"formatters": [
                  col("SuccessRate", formatter=8, formatOptions={"min": 0, "max": 100, "palette": "redGreen"},
                      numberFormat={"unit": 1, "options": {"style": "decimal", "useGrouping": False}}),
                  col("Total", formatter=4, formatOptions={"palette": "redGreen"})]}),
    ], tab="ByDevice")


# ---------------------------------------------------------------- tab: feature updates

WINDOWS_BUILDS = r"""
let WindowsBuilds1 = UCClient
| where TimeGenerated > ago(30d)
| extend var_OSBuild = tostring(extract_all(@"(10.0.[0-9]*)", OSBuild)[0])
| extend OSVersion = case(isempty(OSVersion), "Windows Insider Program", OSVersion !has "Windows", strcat("Windows 10-", OSVersion), OSVersion)
| extend var_OSVersion = replace_string(OSVersion, "version_ ", "")
| distinct var_OSVersion, var_OSBuild;
let WindowsBuilds2 = UCClientUpdateStatus
| where TimeGenerated > ago(180d)
| distinct TargetVersion, TargetBuild
| extend var_OSBuild = tostring(extract_all(@"(10.0.[0-9]*)", TargetBuild)[0])
| extend var_OSVersion = case(TargetVersion has "Win11", replace_string(TargetVersion, "Win11", "Windows 11"), TargetVersion !has "Windows", strcat("Windows 10-", TargetVersion), TargetVersion)
| distinct var_OSVersion, var_OSBuild;
let WindowsBuilds = WindowsBuilds1
| union WindowsBuilds2
| distinct var_OSBuild, var_OSVersion;
let IntuneBuilds = IntuneDevices
| where todatetime(LastContact) > ago(30d) and OS contains "Windows"
| summarize arg_max(TimeGenerated, *) by ReferenceId
| extend var_OSBuild = tostring(extract_all(@"(10.0.[0-9]{5})", OSVersion)[0])
| join kind=leftouter WindowsBuilds on var_OSBuild
| extend OSBuild = OSVersion, OSVersion = var_OSVersion
| where isnotempty(OSVersion);"""

# Same as above but keeps every daily snapshot, for the trend chart
WINDOWS_BUILDS_ALL_SNAPSHOTS = WINDOWS_BUILDS.replace("| summarize arg_max(TimeGenerated, *) by ReferenceId\n", "")
assert WINDOWS_BUILDS_ALL_SNAPSHOTS != WINDOWS_BUILDS

HW_GRID_SKU = {"formatters": [
    col("Enterprise", formatter=4, formatOptions={"palette": "green"}),
    col("Pro", formatter=4, formatOptions={"palette": "yellow"}),
    col("Education", formatter=4, formatOptions={"palette": "blue"}),
    col("Enterprise Insider Preview", formatter=4, formatOptions={"palette": "purple"}),
    col("_Empty", **HIDE)]}

HW_GRID_OS = {"formatters": [col("OSName", **HIDE), col("_Empty", **HIDE)],
              "hierarchySettings": {"treeType": 1, "groupBy": ["OSName"], "expandTopLevel": True}}


def custom_hardware_group():
    latest = r"""
DeviceInventory_CL
| summarize arg_max(TimeGenerated, *) by SerialNumber_s, SMBIOSUUID_g
| where isnotempty(WindowsVersion_s) and isnotempty(OSName_s)"""
    mfr = '| where Manufacturer_s == "{Manufacturer}"'
    return group("Custom Hardware Feature Update Reports", [
        text("Hardware HR 1", "-------\n\n<br>"),
        text("text - 2", "## Custom Hardware Reports\n\nYou are currently collecting custom hardware logs. Below are reports which take into account OEM specific information.", style="success"),
        query("Windows Build - By Manufacturer", latest + r"""
| extend OSReleaseName = strcat(trim_start("Microsoft ", OSName_s), " - ", WindowsVersion_s)
| extend OSName = tostring(extract_all(@'(Windows\s\d.)', OSName_s)[0])
| project Manufacturer = Manufacturer_s, OSReleaseName, OSName
| evaluate pivot(Manufacturer)""", size=3, showAnalytics=True, title="Windows Build - By Manufacturer",
              showExportToExcel=True, visualization="table", gridSettings=HW_GRID_OS),
        text("Break", "<br>"),
        query("Windows Edition - By Manufacturer", latest + r"""
| extend OSSku = tostring(extract_all(@'(.*\d.)(.*)', OSName_s)[0][1])
| project Manufacturer = Manufacturer_s, OSSku
| evaluate pivot(OSSku)""", size=3, showAnalytics=True, title="Windows Edition - By Manufacturer",
              showExportToExcel=True, visualization="table", gridSettings=HW_GRID_SKU,
              styleSettings={"maxWidth": "30%"}),
        query("Windows Build - By Manufacturer - Piechart", latest + "\n| summarize count() by Manufacturer_s",
              size=3, showAnalytics=True, title="Devices by Manufacturer", showExportToExcel=True,
              visualization="piechart", styleSettings={"maxWidth": "30%"}),
        text("Hardware HR 3 ", "<br>\n\n-------\n\n<br>"),
        text("text - 2 - Copy", "## Manufacturer Specific Information"),
        {"type": 9, "content": {"version": "KqlParameterItem/1.0", "parameters": [kql_param("Manufacturer", r"""
DeviceInventory_CL
| distinct Manufacturer_s
| order by Manufacturer_s asc""", ptype=2, isRequired=True,
            typeSettings={"additionalResourceOptions": ["value::1"], "showDefault": False}, defaultValue="value::1")],
            "style": "toolbar", "queryType": 0, "resourceType": LA},
         "name": "ManufacturerFilter", "styleSettings": {"maxWidth": "20%"}},
        query("Model Count", r"""
DeviceInventory_CL
""" + mfr + r"""
| summarize dcount(Model_s)
| project count_ = dcount_Model_s, Header = "Unique {Manufacturer} Models""" + '"', size=3, visualization="tiles",
              tileSettings={"titleContent": col("Header", formatter=1),
                            "leftContent": col("count_", formatter=12, formatOptions={"palette": "auto"},
                                               numberFormat={"unit": 17, "options": {"maximumSignificantDigits": 3, "maximumFractionDigits": 2}}),
                            "showBorder": False},
              conditionalVisibility={"parameterName": "Manufacturer", "comparison": "isNotEqualTo"},
              styleSettings={"maxWidth": "20%"}),
        query("Windows Build - By Model", latest + "\n" + mfr + r"""
| extend OSReleaseName = strcat(trim_start("Microsoft ", OSName_s), " - ", WindowsVersion_s)
| extend OSName = tostring(extract_all(@'(Windows\s\d.)', OSName_s)[0])
| project Model = Model_s, OSReleaseName, OSName
| evaluate pivot(Model)""", size=3, showAnalytics=True, title="Windows Build - By Model", showExportToExcel=True,
              visualization="table", gridSettings=HW_GRID_OS,
              conditionalVisibility={"parameterName": "Manufacturer", "comparison": "isNotEqualTo"}),
        text("Break", "<br>"),
        query("Windows Edition - By Model", latest + "\n" + mfr + r"""
| extend OSSku = tostring(extract_all(@'(.*\d.)(.*)', OSName_s)[0][1])
| project Model = Model_s, OSSku
| evaluate pivot(OSSku)""", size=3, showAnalytics=True, title="Windows Edition - By Model", showExportToExcel=True,
              visualization="table", gridSettings=HW_GRID_SKU, styleSettings={"maxWidth": "40%"}),
        query("Windows Build - By Model - Piechart", latest + "\n" + mfr + "\n| summarize count() by Model_s",
              size=3, showAnalytics=True, title="Devices by Model", showExportToExcel=True,
              visualization="piechart", styleSettings={"maxWidth": "30%"}),
        text("Hardware HR 2", "<br>\n\n-------"),
    ], conditionalVisibility=when("CustomHWLogs"))


def tab_feature_updates():
    return group("group - Feature Updates", [
        text("text - 7", """# Feature Updates
-----

Windows 11 feature updates follow an annual cadence, with new releases arriving in the second half of each calendar year. Each Enterprise feature update receives 36 months of servicing, including monthly cumulative security and quality updates.
More information can be found here:
https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information""", style="upsell"),
        params("parameters - 6", [multi_all("ReleaseName", r"""
UCClientUpdateStatus
| where UpdateCategory == "WindowsFeatureUpdate"
| where isnotempty(TargetVersion)
| distinct TargetVersion
| sort by TargetVersion desc""", label="Target Version")]),
        group("Feature Update Piecharts", [
            query("Windows Supported Build Count", WINDOWS_BUILDS + r"""
IntuneBuilds
| join kind=leftouter (UCClient
    | summarize arg_max(TimeGenerated, *) by AzureADDeviceId
    | project AzureADDeviceId, OSFeatureUpdateStatus
    ) on $left.ReferenceId == $right.AzureADDeviceId
| where isnotempty(OSFeatureUpdateStatus)
| summarize dcount(DeviceId) by OSFeatureUpdateStatus""", size=3, title="Windows Supported Build Count",
                  visualization="piechart",
                  chartSettings={"seriesLabelSettings": [
                      {"seriesName": "InService", "label": "Supported Build", "color": "green"},
                      {"seriesName": "EndOfService", "label": "Unsupported Build", "color": "red"},
                      {"seriesName": "Unknown", "label": "Unknown", "color": "gray"}]},
                  customWidth="33", styleSettings={"maxWidth": "50%"}),
            query("Windows Build Versions", WINDOWS_BUILDS + r"""
IntuneBuilds
| summarize dcount(DeviceId) by OSVersion""", size=3, title="Windows Build Versions", visualization="piechart",
                  customWidth="33", styleSettings={"maxWidth": "50%"}),
            query("Feature Update Deployment States", r"""
let data = UCClientUpdateStatus
    | where UpdateCategory == "WindowsFeatureUpdate"
    | where '*' in ({ReleaseName}) or TargetVersion in ({ReleaseName})""" + STATUS.replace("\n", "\n    ") + r"""
    | summarize arg_max(TimeGenerated, *) by AzureADDeviceId, ReleaseName;""" + TILE_TAIL.format("Deployments"),
                  size=3, title="Feature Update Deployment States",
                  exportFieldName="DetailedStatus", exportParameterName="DetailedStatus", exportDefaultValue="Total",
                  visualization="tiles",
                  tileSettings={"titleContent": col("DetailedStatus", formatter=1),
                                "leftContent": col("DeviceCount", formatter=12, formatOptions={"palette": "auto"},
                                                   numberFormat={"unit": 17, "options": {"maximumSignificantDigits": 3, "maximumFractionDigits": 2}}),
                                "secondaryContent": col("buttonText", formatter=1), "showBorder": False},
                  customWidth="33"),
        ]),
        query("Feature Update Trend ", WINDOWS_BUILDS_ALL_SNAPSHOTS + r"""
IntuneBuilds
| summarize dcount(DeviceId) by bin(TimeGenerated, 1d), OSVersion""",
              size=1, aggregation=2, title="Feature Update Trend - {TimeRange}", visualization="areachart",
              chartSettings={"xAxis": "TimeGenerated", "group": "OSVersion", "createOtherGroup": None},
              customWidth="50"),
        query("Timeline - Feature Update Policy Assignment", DEPLOYMENT_NAMES + r"""
UCClientUpdateStatus
| where UpdateCategory == "WindowsFeatureUpdate"
""" + DEPLOYMENT_JOIN + r"""
| extend DeploymentName = """ + DEPLOYMENT_NAME + r"""
| summarize dcount(AzureADDeviceId) by bin(TimeGenerated, 1d), DeploymentName""",
              size=1, aggregation=2, title="Trending - Feature Update Policy Assignment", visualization="areachart",
              chartSettings={"showLegend": True}, customWidth="50"),
        query("Timeline - Feature Update Install States", r"""
UCClientUpdateStatus
| where UpdateCategory == "WindowsFeatureUpdate" and ClientState == "Installing"
| summarize dcount(AzureADDeviceId) by ClientSubstate, bin(TimeGenerated, 1d)""",
              size=1, aggregation=2, title="Feature Update - Installation States - {TimeRange}",
              visualization="barchart"),
        custom_hardware_group(),
        query("Feature Update Details", INTUNE_NAMES + r"""
UCClientUpdateStatus
| where UpdateCategory == "WindowsFeatureUpdate"
| where isempty(TargetKBNumber)
| where TargetVersion !contains "Windows 10"
// TargetBuild is a string (10.0.22631.x); TargetBuildNumber holds the major build as an int
| where TargetBuildNumber >= 22000 or TargetVersion contains "Windows 11"
| where '*' in ({ReleaseName}) or TargetVersion in ({ReleaseName})""" + STATUS + r"""
| join kind=leftouter IntuneNames on $left.AzureADDeviceId == $right.ReferenceId
| extend Computer = coalesce(IntuneName, DeviceName, AzureADDeviceId)
| where isnotempty(Computer) and Computer != "#"
| summarize arg_max(TimeGenerated, *) by AzureADDeviceId, ReleaseName
| project TimeGenerated, Computer, DeploymentStatus, DetailedStatus, ClientSubstate,
    CurrentOS = iif(DeploymentStatus == "Update completed", ReleaseName, "Upgrading..."),
    TargetOS = ReleaseName, TargetBuild
| sort by Computer asc""", size=0, showAnalytics=True, title="Full Details - Feature Update Information",
              showExportToExcel=True, gridSettings={"formatters": [DEPLOYMENT_STATUS_ICONS], "filter": True}),
    ], tab="ByFeatureUpdate")


# ---------------------------------------------------------------- tab: delivery optimisation

def tab_delivery_optimisation():
    latest_agg = "UCDOAggregatedStatus\n| summarize arg_max(TimeGenerated, *) by ContentType"
    return group("Group - ByDeliveryOptimisation", [group("Group - Content Distribution", [group("DeliveryColumnLeft", [
        text("text - 0", """# Update Sources - {TimeRange}
-----
The below statistics show the sources for update content across all devices. Downloads from the CDN and peers are determined by delivery optimisation policies on your clients.

More information on delivery optimisation can be found here - https://docs.microsoft.com/en-us/windows/deployment/update/waas-delivery-optimization """, style="info"),
        group("Delivery Optimization Piecharts", [
            query("Delivery Optimization Type Piechart", latest_agg + r"""
| project ContentType, TotalBytes = BytesFromCDN + BytesFromPeers
| sort by TotalBytes desc""", size=3, showAnalytics=True, title="Content Types", visualization="piechart",
                  chartSettings={"yAxis": ["TotalBytes"], "showMetrics": False, "showLegend": True},
                  customWidth="33"),
            query("Delivery Optimization Mode Piechart", r"""
UCDOStatus
| summarize Count = dcount(AzureADDeviceId) by DownloadMode, DownloadModeSrc
| project ["Download Mode"] = DownloadMode, ["Download Source"] = DownloadModeSrc, ["Device Count"] = Count
| order by ["Device Count"] desc""", size=3, showAnalytics=True, title="Delivery Optimisation Mode",
                  visualization="piechart", customWidth="33"),
            query("Delivery Optimization Source Piechart", latest_agg + r"""
| summarize CDN = sum(BytesFromCDN), Peers = sum(BytesFromPeers)
| extend Total = todouble(CDN + Peers)
| project pCDN = iff(Total > 0, CDN * 100.0 / Total, 0.0), pPeers = iff(Total > 0, Peers * 100.0 / Total, 0.0)
| evaluate narrow()
| project Column, Value = todouble(Value)""", size=3, title="Content Distribution", visualization="piechart",
                  chartSettings={"seriesLabelSettings": [
                      {"seriesName": "pCDN", "label": "CDN Distribution", "color": "orange"},
                      {"seriesName": "pPeers", "label": "Peer Distribution", "color": "green"}],
                      "ySettings": {"numberFormatSettings": {"unit": 1, "options": {"style": "decimal", "useGrouping": True, "maximumSignificantDigits": 2}}}},
                  customWidth="33"),
        ]),
        group("Delivery Optimization Details", [
            text("Delivery Optimisation HR 1", "<br>"),
            query("Delivery Optmization Table", latest_agg + r"""
| sort by BytesFromCDN desc
| project ["Content Type"] = ContentType,
    ["Bytes from CDN"] = format_bytes(BytesFromCDN, 2),
    ["Bytes from Peers"] = format_bytes(BytesFromPeers, 2),
    ["Total Bytes"] = format_bytes(BytesFromCDN + BytesFromPeers, 2),
    ["Device Count"] = DeviceCount""", size=3, showAnalytics=True, title="Content Break Down",
                  visualization="table",
                  gridSettings={"formatters": [col("Device Count", formatter=4, formatOptions={"palette": "blue"})]}),
            text("Delivery Optimisation HR 2", "<br>\n\n---------------\n\n<br>"),
            query("query - 5", latest_agg + "\n| project ContentType, BytesFromCDN, BytesFromPeers\n| sort by BytesFromCDN desc",
                  size=0, title="Content Types - By Source", visualization="barchart",
                  chartSettings={"xAxis": "ContentType", "seriesLabelSettings": [
                      {"seriesName": "BytesFromCDN", "label": "Bytes from CDN", "color": "orange"},
                      {"seriesName": "BytesFromPeers", "label": "Bytes from Peers", "color": "green"}]}),
            text("Delivery Optimization Network Breakdown - HR", "<br>\n\n----\n\n<br>",
                 conditionalVisibility=when("CustomHWLogs")),
            text("Delivery Optimization Network Breakdown",
                 "## Delivery Optimization Network Breakdown\n\nCustom hardware logs are available, and below is a breakdown of content distribution per subnet.",
                 style="success", conditionalVisibility=when("CustomHWLogs")),
            query("Delivery Optimization By IP Range", r"""
UCDOStatus
| summarize arg_max(TimeGenerated, *) by AzureADDeviceId, ContentType
| join kind=inner (IntuneDevices
    | summarize arg_max(TimeGenerated, *) by ReferenceId
    | project ReferenceId, IntuneDeviceId = DeviceId
    ) on $left.AzureADDeviceId == $right.ReferenceId
| join kind=inner (DeviceInventory_CL
    | summarize arg_max(TimeGenerated, *) by ManagedDeviceID_g
    | project ManagedDeviceID_g, NetworkAdapters_s
    ) on $left.IntuneDeviceId == $right.ManagedDeviceID_g
| extend Gateway = tostring(parse_json(NetworkAdapters_s)[0].NetIPv4DefaultGateway)
| where isnotempty(Gateway)
| summarize PeerBytes = sum(BytesFromPeers), CDNBytes = sum(BytesFromCDN),
    PeerOK = sum(PeersSuccessCount), PeerErrors = sum(PeersCannotConnectCount) by Gateway
| extend Total = todouble(PeerBytes + CDNBytes)
| project ["Network Gateway"] = Gateway, ["Peer Connections"] = PeerOK, ["Peer Errors"] = PeerErrors,
    ["GB from Peers"] = PeerBytes, ["GB from CDN"] = CDNBytes,
    ["Peer Percentage"] = iff(Total > 0, PeerBytes * 100.0 / Total, 0.0),
    ["CDN Percentage"] = iff(Total > 0, CDNBytes * 100.0 / Total, 0.0)
| order by ["GB from Peers"] desc""", size=0, title="Delivery Optimization By IP Range",
                  gridSettings={"formatters": [
                      col("Peer Connections", formatter=4, formatOptions={"palette": "green"}),
                      col("Peer Errors", formatter=4, formatOptions={"palette": "red"}),
                      col("GB from Peers", formatter=4, formatOptions={"palette": "green"},
                          numberFormat={"unit": 2, "options": {"style": "decimal", "useGrouping": True, "maximumFractionDigits": 2}}),
                      col("GB from CDN", formatter=4, formatOptions={"palette": "orange"},
                          numberFormat={"unit": 2, "options": {"style": "decimal", "useGrouping": True, "maximumFractionDigits": 2}}),
                      col("Peer Percentage", formatter=4, formatOptions={"min": 0, "max": 100, "palette": "green"},
                          numberFormat={"unit": 1, "options": {"style": "decimal"}}),
                      col("CDN Percentage", formatter=4, formatOptions={"min": 0, "max": 100, "palette": "orange"},
                          numberFormat={"unit": 1, "options": {"style": "decimal"}})]},
                  conditionalVisibility=when("CustomHWLogs")),
        ]),
    ])])], tab="ByDeliveryOptimisation")


# ---------------------------------------------------------------- tab: windows 11 readiness

def tab_windows11():
    tile = lambda palette, icon: {
        "titleContent": col("Description", **icons(default=icon)),
        "leftContent": col("count_", formatter=12, formatOptions={"min": 0, "palette": palette},
                           numberFormat={"unit": 17, "options": {"style": "decimal", "maximumFractionDigits": 2, "maximumSignificantDigits": 3}}),
        "secondaryContent": col("Summary"), "showBorder": False, "size": "auto"}

    readiness_intune = r"""
UCClientReadinessStatus
| summarize arg_max(TimeGenerated, *) by AzureADDeviceId
""" + W11_FILTERS + r"""
| extend Readiness = """ + READINESS + r"""
| join kind=inner (IntuneDevices
    | summarize arg_max(TimeGenerated, *) by ReferenceId
    | project ReferenceId, Manufacturer
    ) on $left.AzureADDeviceId == $right.ReferenceId"""

    summary = group("Windows 11 Summary", [
        text("Summary Number Header", "## Windows 11 Upgrade Summary\n\nBelow are summary stats on your environment"),
        query("Windows 11 Capable", readiness_intune + r"""
| where Readiness == "Capable"
| summarize count_ = count()
| project count_, Description = "Windows 11 Capable", Summary = "Intune managed devices ({TimeRange})""" + '"',
              size=3, visualization="tiles", tileSettings=tile("green", "success")),
        query("Windows 11 Not Capable", readiness_intune + r"""
| where Readiness == "NotCapable"
| summarize count_ = count()
| project count_, Description = "Windows 11 Not Capable", Summary = "Intune managed devices ({TimeRange})""" + '"',
              size=3, visualization="tiles", tileSettings=tile("red", "3")),
        text("Numbers Rule 2", "------\n<br>"),
        params("Windows 11 Check", [hidden_flag("Windows11Devices", r"""
UCClient
| summarize arg_max(TimeGenerated, *) by AzureADDeviceId
| where OSVersion contains "11"
| summarize c = count()
| project iif(c > 0, "True", "False")""")]),
        text("Windows 11 Builds", "## Windows 11 Builds\n\nGreat news, Windows 11 is already in use in your environment. Below are the builds of Windows 11 currently in use within your environment",
             style="success", conditionalVisibility=when("Windows11Devices")),
        query("Windows 11 Devices", r"""
UCClient
| summarize arg_max(TimeGenerated, *) by AzureADDeviceId
| where OSVersion contains "11"
| summarize count_ = toint(count())
| project count_, Description = "Windows 11 Device Count", Summary = "Managed devices ({TimeRange})""" + '"',
              size=3, visualization="tiles", tileSettings=tile("green", "success")),
        query("Windows 11 Builds Grid", r"""
UCClient
| summarize arg_max(TimeGenerated, *) by AzureADDeviceId
| where OSVersion contains "11"
| summarize count() by OSBuild
| order by count_ desc""", size=3,
              gridSettings={"formatters": [col("count_", formatter=4, formatOptions={"palette": "green", "customColumnWidthSetting": "20ch"})],
                            "labelSettings": [{"columnId": "OSBuild", "label": "Windows 11 Build"},
                                              {"columnId": "count_", "label": "Device Count"}]},
              conditionalVisibility=when("Windows11Devices")),
    ], customWidth="30", styleSettings={"margin": "20px", "padding": "20px", "showBorder": True})

    details = group("Windows 11 Upgrade Details", [
        query("Windows 11 Upgrade Piechart", readiness_intune + r"""
| where isnotempty(Manufacturer)
| summarize count() by Readiness""", size=3, showAnalytics=True, title="Windows 11 Readiness Status",
              visualization="piechart",
              chartSettings={"seriesLabelSettings": [
                  {"seriesName": "Capable", "color": "green"}, {"seriesName": "Unknown", "color": "orange"},
                  {"seriesName": "NotCapable", "color": "red"}, {"seriesName": "Upgraded", "color": "blue"}]}),
        query("Windows 11 Datagrid", readiness_intune + r"""
| where isnotempty(Manufacturer)
| extend Readiness = iff(isempty(Readiness), "Unknown", Readiness)
| project Manufacturer, Readiness
| evaluate pivot(Readiness, count())
| extend _order = column_ifexists("Upgraded", 0)
| order by _order desc
| project-away _order""", size=0, showAnalytics=True, title="Windows 11 Readiness Scan Status by Manufacturer",
              showExportToExcel=True, visualization="table",
              gridSettings={"formatters": [
                  col("NotCapable", formatter=4, formatOptions={"palette": "orangeRed", "customColumnWidthSetting": "120px"}),
                  col("Unknown", formatter=4, formatOptions={"palette": "orange", "customColumnWidthSetting": "100px"}),
                  col("Upgraded", formatter=4, formatOptions={"palette": "green"}),
                  col("Capable", formatter=8, formatOptions={"palette": "blueGreen"})],
                  "labelSettings": [{"columnId": "NotCapable", "label": "Not Capable"}]}),
        query("query - 6", readiness_intune + r"""
| where ReadinessStatus == "NotCapable"
| extend ReadinessReason = trim_end(";", tostring(ReadinessReason))
| project ReadinessReason, Manufacturer
| evaluate pivot(Manufacturer)""", size=0, showAnalytics=True, title="Windows 11 Not Capable - Reasons by Manufacturer",
              showExportToExcel=True, visualization="barchart",
              chartSettings={"showMetrics": False, "showLegend": True}),
    ], customWidth="70", styleSettings={"maxWidth": "70%"})

    detail_params = params("Windows 11 Detail Parameters", [
        kql_param("Windows11Readiness", r"""
UCClientReadinessStatus
| extend Readiness = """ + READINESS + r"""
| where isnotempty(Readiness)
| distinct Readiness""", ptype=2, label="Windows 11 Readiness", isRequired=False,
                  typeSettings={"additionalResourceOptions": [], "showDefault": False}, value=None),
        kql_param("DeviceName", label="Device Name", value=""),
        kql_param("UPN", label="User Principal Name", value=""),
        multi_all("Manufacturer", r"""
IntuneDevices
| where OS == "Windows" and isnotempty(Manufacturer)
| distinct Manufacturer
| order by Manufacturer asc"""),
        kql_param("ReadinessReason", r"""
UCClientReadinessStatus
| summarize arg_max(TimeGenerated, *) by AzureADDeviceId
| where ReadinessStatus == "NotCapable"
| mv-expand Reason = split(ReadinessReason, ";")
| extend Reason = trim(" ", tostring(Reason))
| where isnotempty(Reason)
| distinct Reason""", ptype=2, label="Readiness Reason", isRequired=False,
                  typeSettings={"additionalResourceOptions": [], "showDefault": False}, value=None),
    ])

    full = group("group - NotCapable", [query("Windows 11 Capable - Full Details", r"""
let IntuneData = IntuneDevices
    | summarize arg_max(TimeGenerated, *) by ReferenceId
    | project ReferenceId, IntuneName = DeviceName, IntuneDeviceId = DeviceId, Manufacturer, Model, UPN, LastContact;
UCClientReadinessStatus
| summarize arg_max(TimeGenerated, *) by AzureADDeviceId
| extend Readiness = """ + READINESS + r"""
| where "{Windows11Readiness}" == "" or Readiness == "{Windows11Readiness}"
| where "{ReadinessReason:escape}" == "" or ReadinessReason contains "{ReadinessReason:escape}"
| join kind=leftouter IntuneData on $left.AzureADDeviceId == $right.ReferenceId
| where '*' in ({Manufacturer}) or Manufacturer in ({Manufacturer})
| extend ComputerName = coalesce(IntuneName, DeviceName)
| where isnotempty(ComputerName) and ComputerName != "#"
| where "{DeviceName:escape}" == "" or ComputerName contains "{DeviceName:escape}"
| where "{UPN:escape}" == "" or UPN contains "{UPN:escape}"
| extend DeviceUrl = strcat("https://intune.microsoft.com/#view/Microsoft_Intune_Devices/DeviceSettingsMenuBlade/~/overview/mdmDeviceId/", IntuneDeviceId)
| project ComputerName, UPN, Manufacturer, Model, CurrentOS = OSVersion, CurrentBuild = OSBuild,
    ReadinessStatus = Readiness, ReadinessReason = coalesce(ReadinessReason, "None/Capable"),
    LastSeen = LastContact, DeviceUrl
| order by ComputerName asc""", size=3, showAnalytics=True, showExportToExcel=True,
        gridSettings={"formatters": [
            col("ComputerName", formatter=1, formatOptions={"linkColumn": "DeviceUrl", "linkTarget": "Url"}),
            col("ReadinessStatus", **icons(("==", "NotCapable", "4"))),
            col("DeviceUrl", **HIDE)], "rowLimit": 100, "filter": True})])

    return group("Group - Windows 11 Readiness", [
        text("text - 7", """# Windows 11 Readiness Status
-----

This report shows which devices in your environment meet the [hardware requirements](https://www.microsoft.com/en-us/windows/windows-11-specifications) for Windows 11""", style="info"),
        params("Windows 11 Parameters", [
            multi_all("OSBuild", r"""
UCClientReadinessStatus
| extend MainBuild = tostring(split(OSBuild, ".")[0])
| summarize by MainBuild, OSBuild
| project value = OSBuild, label = OSBuild, group = MainBuild
| sort by group""", label="Current Build"),
            kql_param("TargetOSBuild", r"""
UCClientReadinessStatus
| where isnotempty(TargetOSBuild)
| distinct TargetOSBuild
| sort by TargetOSBuild desc""", ptype=2, label="Target Build", isRequired=True,
                      typeSettings={"additionalResourceOptions": ["value::all"], "selectAllValue": "*", "showDefault": False},
                      defaultValue="value::all", value="value::all"),
        ]),
        summary, details,
        text("text - 8", "## Windows 11 Readiness Details", style="info"),
        detail_params, full,
    ], tab="ByWindows11")


# ---------------------------------------------------------------- tab: update issues

def tab_update_issues():
    qu_issues = r"""
UCClientUpdateStatus
| where """ + SECURITY_QU + STATUS + r"""
| where isnotempty(UpdateReleaseTime)
| where DeploymentStatus != "Update completed""" + '"'

    return group("ByComplianceIssue", [
        text("text - 4", """----
## Quality Update Deployment Issues

This page provides an oversight as to devices which are failing to update, along with a description of the update failure, and overall exceptions charts.""", style="warning"),
        params("parameters - 5 - Copy - Copy", [kql_param("DeviceName", label="Device Name", value="")]),
        query("Update Exception Piechart", qu_issues + r"""
| extend Computer = DeviceName
""" + DEVICE_FILTER + r"""
| summarize arg_max(TimeGenerated, *) by AzureADDeviceId, ReleaseName
| summarize Count = dcount(AzureADDeviceId) by DetailedStatus""", size=3, title="Deployment State",
              visualization="piechart",
              chartSettings={"seriesLabelSettings": [{"seriesName": "Commit", "color": "blue"},
                                                     {"seriesName": "Install started", "color": "green"},
                                                     {"seriesName": "Reboot pending", "color": "orange"}]},
              customWidth="33"),
        query("Deployment Status Issue Piechart", qu_issues + r"""
| extend Computer = DeviceName
""" + DEVICE_FILTER + r"""
| summarize arg_max(TimeGenerated, *) by AzureADDeviceId, ReleaseName
| summarize Count = count() by DeploymentStatus""", size=3, title="Deployment Status", visualization="piechart",
              chartSettings={"seriesLabelSettings": [{"seriesName": "Update completed", "color": "green"},
                                                     {"seriesName": "In progress", "color": "yellow"},
                                                     {"seriesName": "On hold", "color": "orange"},
                                                     {"seriesName": "Failed", "color": "red"}]},
              customWidth="33"),
        query("Update Activity Chart", r"""
// Pause state comes from the device's Windows Update policy in UCClient
let PauseStates = UCClient
    | summarize arg_max(TimeGenerated, WUQualityPauseState) by AzureADDeviceId;""" + qu_issues + r"""
| extend Computer = DeviceName
""" + DEVICE_FILTER + r"""
| summarize arg_max(TimeGenerated, *) by AzureADDeviceId, ReleaseName
| join kind=leftouter PauseStates on AzureADDeviceId
| extend UpdatesActive = iff(WUQualityPauseState == "Paused", "Paused", "Active")
| summarize Count = dcount(AzureADDeviceId) by UpdatesActive""", size=3, title="Update Status",
              visualization="piechart",
              chartSettings={"seriesLabelSettings": [{"seriesName": "Active", "color": "green"},
                                                     {"seriesName": "Paused", "color": "orange"}]},
              customWidth="33"),
        params("Patching Alert Parameters", [
            hidden_flag("MissingPatches", MISSING_PATCHES_BASE + r"""
| summarize c = count()
| project iif(c > 0, "True", "False")"""),
            hidden_flag("FeatureUpdateIssues", FU_ISSUES_BASE + r"""
| summarize c = count()
| project iif(c > 0, "True", "False")"""),
            hidden_flag("FeaturePolicyIssues", POLICY_ISSUES_BASE + r"""
| summarize c = count()
| project iif(c > 0, "True", "False")"""),
            hidden_flag("SafeGuardIssues", SAFEGUARD_BASE + r"""
| summarize c = count()
| project iif(c > 0, "True", "False")"""),
        ]),
        text("Missing Patches", """## Missing Patch Alert

The following devices are active but missing vital patches at the time of the query.
* Please note that data is only gathered every 25 hours and due to this some machines might already have remediated their patching state.""",
             style="warning", conditionalVisibility=when("MissingPatches")),
        text("No Missing Patches ", "## Missing Patch Alert\n\nGreat news. No missing patch warnings are present",
             style="success", conditionalVisibility=when("MissingPatches", equal=False)),
        query("Grid - Patches Missed", MISSING_PATCHES_BASE + r"""
| extend DeviceUrl = strcat("https://intune.microsoft.com/#view/Microsoft_Intune_Devices/DeviceSettingsMenuBlade/~/overview/mdmDeviceId/", IntuneDeviceId)
| extend KBUrl = strcat("https://www.catalog.update.microsoft.com/Search.aspx?q=", tostring(split(ReleaseName, " ")[0]))
| project TimeGenerated, Computer, ReleaseName, UpdateReleaseTime, UpdateClassification, TargetVersion, TargetBuild,
    DetailedStatus, ClientSubstate, DeviceUrl, KBUrl
| sort by TimeGenerated desc, Computer asc""", size=0, title="Missing Patches - {TimeRange}",
              showExportToExcel=True, exportToExcelOptions="all",
              gridSettings={"formatters": [
                  col("Computer", formatter=1, formatOptions={"linkColumn": "DeviceUrl", "linkTarget": "Url"},
                      tooltipFormat={"tooltip": "Click here to view the device in the Intune admin center"}),
                  col("ReleaseName", formatter=1, formatOptions={"linkColumn": "KBUrl", "linkTarget": "Url"},
                      tooltipFormat={"tooltip": "Click here to view the KB in the Microsoft Update Catalog site"}),
                  col("DeviceUrl", **HIDE),
                  col("DetailedStatus", **icons(("==", "Reboot pending", "2"), ("==", "Install started", "success"), default="1")),
                  col("KBUrl", **HIDE)], "rowLimit": 50, "filter": True},
              conditionalVisibility=when("MissingPatches")),
        text("Update Issues", "## Update Issues\nThe following devices are active but have alerts that could prevent security patching from being completed.",
             style="warning"),
        query("query - 5", INTUNE_NAMES + qu_issues + r"""
| join kind=leftouter IntuneNames on $left.AzureADDeviceId == $right.ReferenceId
| extend Computer = coalesce(IntuneName, DeviceName, AzureADDeviceId)
| where Computer != "#" and isnotempty(Computer)
""" + DEVICE_FILTER + r"""
| summarize arg_max(TimeGenerated, *) by AzureADDeviceId, ReleaseName
| project Computer, DeploymentStatus, DetailedStatus, ClientSubstate, ReleaseName, TargetBuild, UpdateReleaseTime, TimeGenerated
| sort by TimeGenerated desc, Computer desc""", size=3, showExportToExcel=True,
              gridSettings={"formatters": [
                  col("DeploymentStatus", **icons(("contains", "Failed", "4"), ("==", "On hold", "2"), ("==", "In progress", "1"))),
                  col("DetailedStatus", **icons(("contains", "Reboot", "2")))],
                  "rowLimit": 25, "filter": True,
                  "hierarchySettings": {"treeType": 1, "groupBy": ["DeploymentStatus"], "expandTopLevel": True}}),
        text("text - 11", "<br>"),
        text("Feature Update Issues", """## Feature Update Issues

Windows feature updates are the major release of the operating system, released annually. More information on the current Windows release cycle can be found here - https://docs.microsoft.com/en-us/windows/release-health/release-information
""", style="warning", conditionalVisibility=when("FeatureUpdateIssues")),
        text("No Feature Update Issues ", "## Feature Update Issues\n\nWindows feature updates are rolling out successfully. No issues detected!",
             style="success", conditionalVisibility=when("FeatureUpdateIssues", equal=False)),
        query("Graph - Feature Update Failures - Descriptions", FU_ISSUES_BASE + r"""
| where isnotempty(Description)
| summarize DeviceCount = dcount(AzureADDeviceId) by Description""", size=3, title="Update Error Descriptions",
              visualization="table",
              gridSettings={"formatters": [
                  col("Description", formatter=0, formatOptions={"customColumnWidthSetting": "500px"}),
                  col("DeviceCount", formatter=4, formatOptions={"palette": "blue", "customColumnWidthSetting": "150px"})],
                  "labelSettings": [{"columnId": "DeviceCount", "label": "Device Count"}]},
              conditionalVisibility=when("FeatureUpdateIssues"), styleSettings={"maxWidth": "50%"}),
        query("Graph - Feature Update Failures - Alerts", r"""
UCUpdateAlert
| where UpdateCategory == "WindowsFeatureUpdate"
| summarize arg_max(TimeGenerated, *) by AzureADDeviceId, DeploymentId, AlertSubtype, ServiceSubstate, ClientSubstate
| where AlertStatus == "Active"
| where isnotempty(ErrorSymName)
| summarize DeviceCount = dcount(AzureADDeviceId) by ErrorSymName""", size=3, title="Update Error Types",
              visualization="table",
              gridSettings={"labelSettings": [{"columnId": "DeviceCount", "label": "Device Count"}]},
              conditionalVisibility=when("FeatureUpdateIssues"), styleSettings={"maxWidth": "50%"}),
        query("Update Issues - Feature Updates", FU_ISSUES_BASE + r"""
| extend DeviceUrl = strcat("https://intune.microsoft.com/#view/Microsoft_Intune_Devices/DeviceSettingsMenuBlade/~/overview/mdmDeviceId/", IntuneDeviceId)
| project TimeGenerated, LastContact, DeviceName = IntuneName, CurrentOSVersion = IntuneOSVersion,
    TargetVersion, TargetBuild, Description, Recommendation, ErrorCode, ErrorSymName, AlertData,
    DeploymentStatus, UpdateCategory, UpdateClassification, UserName, UserEmail, JoinType,
    Manufacturer, Model, SerialNumber, DeviceUrl, AlertSubtype, ServiceSubstate, ClientSubstate""",
              size=0, showExportToExcel=True,
              gridSettings={"formatters": [
                  col("DeviceName", formatter=1, formatOptions={"linkColumn": "DeviceUrl", "linkTarget": "Url"}),
                  col("DeploymentStatus", **icons(("==", "Unknown", "2"), ("==", "Failed", "4"))),
                  col("DeviceUrl", **HIDE)],
                  "labelSettings": [{"columnId": "ErrorCode", "label": "Error Code"},
                                    {"columnId": "UpdateCategory", "label": "Update Category"},
                                    {"columnId": "UpdateClassification", "label": "Update Classification"}]},
              conditionalVisibility=when("FeatureUpdateIssues")),
        text("Feature Policy Issues", """## Feature Update Policy Issues

Devices listed in the below grid currently have no feature update policy in effect. This could be due to issues with device registration with the Windows Update telemetry service.""",
             style="error", conditionalVisibility=when("FeaturePolicyIssues")),
        text("No Feature Policy Issues", "## Feature Update Policy Issues\n\nNo feature update policy assignment issues at present.",
             style="success", conditionalVisibility=when("FeaturePolicyIssues", equal=False)),
        query("Timeline - Feature Update Policy Issue ", POLICY_ISSUES_BASE + r"""
| summarize DeviceCount = count() by TimeRange = bin(todatetime(TimeRange), 1d), DeploymentName
| as Results
| make-series SumCount = sum(DeviceCount) default=0 on TimeRange in range(toscalar(Results | summarize min(TimeRange)), now(), 1d) by DeploymentName""",
              size=1, aggregation=2, title="Trending - Feature Update Policy Issues", color="red",
              visualization="timechart", conditionalVisibility=when("FeaturePolicyIssues")),
        query("Grid - Feature Update Policy Issue", DEPLOYMENT_NAMES + r"""
let onboardedclients = UCServiceUpdateStatus
    | summarize arg_max(TimeGenerated, *) by AzureADDeviceId, UpdateCategory, ServiceSubstate, DeploymentId
    | where UpdateCategory == "WindowsFeatureUpdate" and ServiceSubstate != "RemovedFromDeployment"
    | distinct AzureADDeviceId;
UCClientUpdateStatus
| summarize arg_max(TimeGenerated, *) by AzureADDeviceId, UpdateCategory
| where UpdateCategory == "WindowsFeatureUpdate" and AzureADDeviceId !in~ (onboardedclients)
| join kind=inner (IntuneDevices
    | summarize arg_max(TimeGenerated, *) by ReferenceId
    | project ReferenceId, IntuneName = DeviceName, IntuneDeviceId = DeviceId
    ) on $left.AzureADDeviceId == $right.ReferenceId
| extend DeviceUrl = strcat("https://intune.microsoft.com/#view/Microsoft_Intune_Devices/DeviceSettingsMenuBlade/~/overview/mdmDeviceId/", IntuneDeviceId)
""" + DEPLOYMENT_JOIN + r"""
| extend DeploymentName = """ + DEPLOYMENT_NAME + r"""
| project TimeGenerated, AzureADDeviceId, GlobalDeviceId, ["Device Name"] = IntuneName, TargetVersion, ClientState,
    FurthestClientSubstate, UpdateSource, DeviceUrl, DeploymentId, DeploymentName
| order by TimeGenerated desc""", size=3, title="Feature Update Policy Issues Details", showExportToExcel=True,
              gridSettings={"formatters": [
                  col("AzureADDeviceId", **HIDE), col("GlobalDeviceId", **HIDE),
                  col("Device Name", formatter=1, formatOptions={"linkColumn": "DeviceUrl", "linkTarget": "Url"}),
                  col("DeviceUrl", **HIDE), col("DeploymentId", **HIDE)],
                  "rowLimit": 50,
                  "labelSettings": [{"columnId": "TargetVersion", "label": "Target Version"},
                                    {"columnId": "ClientState", "label": "State"},
                                    {"columnId": "FurthestClientSubstate", "label": "Detailed State"},
                                    {"columnId": "UpdateSource", "label": "Update Source"},
                                    {"columnId": "DeploymentName", "label": "Deployment Name"}]},
              conditionalVisibility=when("FeaturePolicyIssues")),
        query("Grid - Removed and Unassigned", r"""
let DeploymentNames = UCClientUpdateStatus
    | where isnotempty(TargetVersion)
    | summarize FriendlyUpdateName = any(coalesce(TargetKBNumber, TargetVersion)) by DeploymentId;
UCServiceUpdateStatus
| summarize arg_max(TimeGenerated, *) by AzureADDeviceId, DeploymentId, ServiceSubstate, TargetVersion
| where UpdateCategory == "WindowsFeatureUpdate"
| extend State = iff(ServiceSubstate != "RemovedFromDeployment", "Good", "Bad")
| as TotalResults
| where State == "Good"
| distinct AzureADDeviceId
| join kind=rightanti TotalResults on AzureADDeviceId
| join kind=leftouter (IntuneDevices
    | summarize arg_max(TimeGenerated, *) by ReferenceId
    | project ReferenceId, IntuneName = DeviceName, UPN, LastContact
    ) on $left.AzureADDeviceId == $right.ReferenceId
| join kind=leftouter DeploymentNames on DeploymentId
| extend FriendlyDeployment = coalesce(DeploymentName, FriendlyUpdateName, DeploymentId)
| project TimeGenerated, State, FriendlyDeployment, DeviceName = IntuneName, UPN, TargetVersion, ServiceSubstate
| order by TimeGenerated desc""", size=3, title="Feature Update Policy Removed & Unassigned",
              showExportToExcel=True, conditionalVisibility=when("FeaturePolicyIssues")),
        text("SafeGuard Hold", """
## Safeguard Hold Detected

Safeguard holds prevent a device with a known issue from being offered a new operating system version.

Microsoft uses quality and compatibility data to identify issues that might cause a Windows client feature update to fail or roll back. When we find such an issue, we might apply safeguard holds to the updating service to prevent affected devices from installing the update in order to safeguard them from these experiences. We also use safeguard holds when a customer, a partner, or Microsoft internal validation finds an issue that would cause severe impact (for example, rollback of the update, data loss, loss of connectivity, or loss of key functionality) and when a workaround is not immediately available.

More information can be found here - https://docs.microsoft.com/en-us/windows/deployment/update/safeguard-holds<br>
The Windows Health Dashboard could also contain information on Safeguard holds - https://docs.microsoft.com/en-us/windows/release-health/""",
             style="error", conditionalVisibility=when("SafeGuardIssues")),
        text("No SafeGuard Hold ", "\n## Safeguard Hold Issues\n\nNo safeguard holds have been detected.",
             style="success", conditionalVisibility=when("SafeGuardIssues", equal=False)),
        query("query - 21", r"""
UCUpdateAlert
| where UpdateCategory == "WindowsFeatureUpdate"
| where AlertSubtype == "SafeguardHold" or ServiceSubstate == "SafeguardHold"
| where AlertStatus == "Active"
| summarize SafeguardHold = dcount(AzureADDeviceId) by bin(TimeGenerated, 1d)""", size=1,
              visualization="areachart",
              chartSettings={"seriesLabelSettings": [{"seriesName": "SafeguardHold", "label": "Safeguard Hold", "color": "red"}]},
              conditionalVisibility=when("SafeGuardIssues")),
        query("query - 10", INTUNE_NAMES + SAFEGUARD_BASE + r"""
| join kind=leftouter IntuneNames on $left.AzureADDeviceId == $right.ReferenceId
| project TimeGenerated, Computer = coalesce(IntuneName, DeviceName), TargetVersion, TargetBuild,
    AlertSubtype, ServiceSubstate, Description, Recommendation, AlertData, StartTime""",
              size=0, showExportToExcel=True, visualization="table",
              gridSettings={"filter": True,
                            "hierarchySettings": {"treeType": 1, "groupBy": ["TargetVersion"], "expandTopLevel": True}},
              conditionalVisibility=when("SafeGuardIssues")),
    ], tab="ByComplianceIssue")


# ---------------------------------------------------------------- tab: quality update history

def tab_quality_history():
    return group("ByQualityUpdates", [group("Quality Update Details", [
        text("text - 0", """--------

## Quality Update History

This tab displays Windows client updates per build of Windows 10/11 within monthly deployment cycles, including the success and failure rates per KB.
"""),
        text("text - 10", "### Critical Security Updates - By Age\n-------\n"),
        quality_history("Updates 0-30 Days", "query - 5", "UpdateReleaseTime > ago(30d)",
                        "Updates released in the last 30 days"),
        quality_history("Updates 31-60 Days", "query - 6", "UpdateReleaseTime between (ago(60d) .. ago(31d))",
                        "Updates released between 31 and 60 days ago"),
        quality_history("Updates 61-90 Days", "query - 7", "UpdateReleaseTime between (ago(90d) .. ago(61d))",
                        "Updates released between 61 and 90 days ago"),
        quality_history("Updates 91 - 120 Days", "query - 8", "UpdateReleaseTime between (ago(120d) .. ago(91d))",
                        "Updates released between 91 and 120 days ago"),
        quality_history("Updates 120 Days +", "query - 9", "UpdateReleaseTime < ago(120d)",
                        "Updates released more than 120 days ago"),
    ])], tab="ByQualityUpdates")


# ---------------------------------------------------------------- tab: secure boot

def tab_secure_boot():
    return group("Group - SecureBoot", [text("Secure Boot Info", """## Secure Boot Readiness
-----

The Microsoft Secure Boot certificates from 2011 (KEK CA 2011, UEFI CA 2011 and Windows Production PCA 2011) start expiring from June 2026. Devices need the 2023 certificates before then to keep receiving boot security updates.

The Windows Update for Business reports tables (UC*) do not include Secure Boot certificate data, so this workbook can't report on it yet. Use one of these instead:

1. **Intune admin center** > **Reports** > **Windows Autopatch** > **Windows quality updates** > **Reports** > **Secure Boot status**. More detail: https://learn.microsoft.com/windows/deployment/windows-autopatch/monitor/secure-boot-status-report
2. Collect the Secure Boot state with an Intune remediation or custom inventory script, send it to this workspace as a custom log, and add the reports here.

Microsoft guidance: https://learn.microsoft.com/troubleshoot/windows-client/windows-security/update-secure-boot-certificates""",
                                             style="info")], tab="SecureBoot")


# ---------------------------------------------------------------- assembly

def build_workbook(workspace_id=None):
    items = top_items() + [
        tab_summary(),
        tab_by_update(),
        tab_by_device(),
        tab_feature_updates(),
        tab_delivery_optimisation(),
        tab_windows11(),
        tab_update_issues(),
        tab_quality_history(),
        tab_secure_boot(),
    ]
    wb = {"version": "Notebook/1.0", "items": items, "isLocked": False,
          "fallbackResourceIds": [workspace_id or "Azure Monitor"]}
    if workspace_id:
        ws_param = items[1]["content"]["parameters"][1]
        ws_param["value"] = workspace_id
    return wb


def build_arm(workbook, workspace_id=None, display_name="Windows Update Compliance Dashboard"):
    return {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "parameters": {
            "workbookDisplayName": {"type": "string", "defaultValue": display_name,
                                    "metadata": {"description": "The friendly name for the workbook. Must be unique within a resource group."}},
            "workbookType": {"type": "string", "defaultValue": "workbook"},
            "workbookSourceId": {"type": "string", "defaultValue": workspace_id or "Azure Monitor",
                                 "metadata": {"description": "Resource ID of the Log Analytics workspace the workbook is linked to."}},
            "workbookId": {"type": "string", "defaultValue": "[newGuid()]"},
        },
        "resources": [{
            "name": "[parameters('workbookId')]",
            "type": "microsoft.insights/workbooks",
            "location": "[resourceGroup().location]",
            "apiVersion": "2022-04-01",
            "kind": "shared",
            "properties": {
                "displayName": "[parameters('workbookDisplayName')]",
                "serializedData": json.dumps(workbook, ensure_ascii=False),
                "version": "1.0",
                "sourceId": "[parameters('workbookSourceId')]",
                "category": "[parameters('workbookType')]",
            },
        }],
        "outputs": {"workbookId": {"type": "string",
                                   "value": "[resourceId('microsoft.insights/workbooks', parameters('workbookId'))]"}},
    }


def validate(workbook):
    """Catch the mistakes that broke the original: queries with no workspace, stray escapes, unknown columns."""
    problems = []

    def walk(items, path):
        for it in items:
            p = f"{path}/{it.get('name')}"
            c = it.get("content", {})
            if it["type"] == 3:
                if c.get("crossComponentResources") != [WS]:
                    problems.append(f"{p}: query not pinned to {WS}")
                check_kql(c["query"], p)
            if it["type"] == 9:
                for prm in c["parameters"]:
                    if "query" in prm and prm.get("queryType") == 0:
                        if prm.get("crossComponentResources") != [WS]:
                            problems.append(f"{p}/{prm['name']}: parameter query not pinned to {WS}")
                        check_kql(prm["query"], f"{p}/{prm['name']}")
            if it["type"] == 12:
                walk(c["items"], p)

    def check_kql(q, p):
        if '\\"' in q:
            problems.append(f"{p}: stray backslash-quote in KQL")
        for bad in ("Northwest Bank", "coalesce(DeviceName, Computer)", "coalesce(GlobalDeviceId, ComputerID)",
                    "TargetOSVersion)", 'has "Reboot"', 'has "Download"'):
            if bad in q:
                problems.append(f"{p}: contains '{bad}'")
        if q.count("(") != q.count(")"):
            problems.append(f"{p}: unbalanced parentheses")

    walk(workbook["items"], "")
    return problems


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workspace-id", help="Full resource ID of the Log Analytics workspace to preselect")
    ap.add_argument("--out", default="workbooks", help="Output folder (default: workbooks)")
    args = ap.parse_args()

    wb = build_workbook(args.workspace_id)
    problems = validate(wb)
    if problems:
        raise SystemExit("Validation failed:\n  " + "\n  ".join(problems))

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "UpdateComplianceDashboard.workbook.json").write_text(json.dumps(wb, indent=2, ensure_ascii=False), encoding="utf-8")
    (out / "UpdateComplianceDashboard.arm.json").write_text(json.dumps(build_arm(wb, args.workspace_id), indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Wrote {out / 'UpdateComplianceDashboard.workbook.json'}")
    print(f"Wrote {out / 'UpdateComplianceDashboard.arm.json'}")


if __name__ == "__main__":
    main()
