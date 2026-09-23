// Syntax + schema check for every KQL query in a workbook, using Microsoft's Kusto language service.
// Catches unknown columns/tables, stray escapes and parse errors before you paste into Azure.
//
// One-off setup:  npm install --prefix tools @kusto/language-service-next
// Usage:          node tools/check_workbook_kql.js workbooks/UpdateComplianceDashboard.workbook.json
//
// Table schemas below are from https://learn.microsoft.com/azure/azure-monitor/reference/tables/
// DeviceInventory_CL / AppInventory_CL are custom logs, so only the columns the workbook uses are listed.
require("@kusto/language-service-next/bridge.js");
require("@kusto/language-service-next/Kusto.Language.Bridge.js");
const fs = require("fs");
const K = global.Kusto.Language;

const common = "TimeGenerated:datetime, Type:string, TenantId:string, SourceSystem:string";
const schemas = {
  UCClient: "AzureADDeviceId:string, AzureADTenantId:string, City:string, Country:string, DeviceFamily:string, DeviceFormFactor:string, DeviceManufacturer:string, DeviceModel:string, DeviceName:string, GlobalDeviceId:string, IsVirtual:bool, LastCensusScanTime:datetime, LastWUScanTime:datetime, OSArchitecture:string, OSBuild:string, OSBuildNumber:int, OSEdition:string, OSFeatureUpdateComplianceStatus:string, OSFeatureUpdateEOSTime:datetime, OSFeatureUpdateReleaseTime:datetime, OSFeatureUpdateStatus:string, OSQualityUpdateComplianceStatus:string, OSQualityUpdateReleaseTime:datetime, OSQualityUpdateStatus:string, OSRevisionNumber:int, OSSecurityUpdateComplianceStatus:string, OSSecurityUpdateStatus:string, OSServicingChannel:string, OSVersion:string, PrimaryDiskFreeCapacityMb:int, SCCMClientId:string, UpdateConnectivityLevel:string, WUDODownloadMode:string, WUFeaturePauseState:string, WUQualityPauseState:string, WUQualityDeferralDays:int, WUFeatureDeferralDays:int",
  UCClientUpdateStatus: "AzureADDeviceId:string, AzureADTenantId:string, CatalogId:string, ClientState:string, ClientSubstate:string, ClientSubstateRank:int, ClientSubstateTime:datetime, DeploymentId:string, DeviceName:string, EventData:string, FurthestClientSubstate:string, FurthestClientSubstateRank:int, GlobalDeviceId:string, IsUpdateHealthy:bool, OfferReceivedTime:datetime, RestartRequiredTime:datetime, SCCMClientId:string, TargetBuild:string, TargetBuildNumber:int, TargetKBNumber:string, TargetRevisionNumber:int, TargetVersion:string, UpdateCategory:string, UpdateClassification:string, UpdateConnectivityLevel:string, UpdateDisplayName:string, UpdateId:string, UpdateInstalledTime:datetime, UpdateManufacturer:string, UpdateReleaseTime:datetime, UpdateSource:string",
  UCUpdateAlert: "AlertClassification:string, AlertData:string, AlertId:string, AlertRank:int, AlertStatus:string, AlertSubtype:string, AlertType:string, AzureADDeviceId:string, AzureADTenantId:string, CatalogId:string, ClientSubstate:string, ClientSubstateRank:int, DeploymentId:string, Description:string, DeviceName:string, ErrorCode:string, ErrorSymName:string, GlobalDeviceId:string, Recommendation:string, ResolvedTime:datetime, SCCMClientId:string, ServiceSubstate:string, ServiceSubstateRank:int, StartTime:datetime, TargetBuild:string, TargetVersion:string, UpdateCategory:string, UpdateClassification:string, UpdateId:string, URL:string",
  UCClientReadinessStatus: "AzureADDeviceId:string, AzureADTenantId:string, DeviceName:string, GlobalDeviceId:string, OSBuild:string, OSName:string, OSVersion:string, ReadinessExpiryTime:datetime, ReadinessReason:string, ReadinessScanTime:datetime, ReadinessStatus:string, SCCMClientId:string, TargetOSBuild:string, TargetOSName:string, TargetOSVersion:string",
  UCDOStatus: "AzureADDeviceId:string, AzureADTenantId:string, BWOptPercent28Days:real, BWOptPercent7Days:real, BytesFromCache:long, BytesFromCDN:long, BytesFromGroupPeers:long, BytesFromIntPeers:long, BytesFromPeers:long, City:string, ContentDownloadMode:int, ContentType:string, Country:string, DeviceName:string, DOStatusDescription:string, DownloadMode:string, DownloadModeSrc:string, GlobalDeviceId:string, GroupID:string, ISP:string, LastCensusSeenTime:datetime, NoPeersCount:long, OSVersion:string, PeerEligibleTransfers:long, PeeringStatus:string, PeersCannotConnectCount:long, PeersSuccessCount:long, PeersUnknownCount:long, TotalTimeForDownload:string, TotalTransfers:long",
  UCDOAggregatedStatus: "AzureADDeviceId:string, AzureADTenantId:string, BWOptPercent28Days:real, BytesFromCache:long, BytesFromCDN:long, BytesFromGroupPeers:long, BytesFromIntPeers:long, BytesFromPeers:long, ContentType:string, DeviceCount:long",
  UCServiceUpdateStatus: "AzureADDeviceId:string, AzureADTenantId:string, CatalogId:string, DeploymentApprovedTime:datetime, DeploymentId:string, DeploymentIsExpedited:bool, DeploymentName:string, GlobalDeviceId:string, OfferReadyTime:datetime, PolicyId:string, PolicyName:string, ServiceState:string, ServiceSubstate:string, ServiceSubstateRank:int, ServiceSubstateTime:datetime, TargetBuild:string, TargetVersion:string, UpdateCategory:string, UpdateClassification:string, UpdateDisplayName:string, UpdateId:string, UpdateReleaseTime:datetime",
  UCDeviceAlert: "AzureADDeviceId:string, AlertStatus:string",
  IntuneDevices: "AADTenantId:string, CategoryName:string, CompliantState:string, CreatedDate:string, DeviceId:string, DeviceName:string, DeviceRegistrationState:string, DeviceState:string, EncryptionStatusString:string, IntuneAccountId:string, JoinType:string, LastContact:string, ManagedBy:string, ManagedDeviceName:string, Manufacturer:string, Model:string, OS:string, OSVersion:string, Ownership:string, PrimaryUser:string, ReferenceId:string, SerialNumber:string, SkuFamily:string, UPN:string, UserEmail:string, UserName:string",
  DeviceInventory_CL: "SerialNumber_s:string, SMBIOSUUID_g:string, WindowsVersion_s:string, OSName_s:string, OSBuild_s:string, Manufacturer_s:string, Model_s:string, ManagedDeviceID_g:string, NetworkAdapters_s:string",
  AppInventory_CL: "AppName_s:string",
};
const tables = Object.entries(schemas).map(([n, c]) => K.Symbols.TableSymbol.From(`(${common}, ${c})`).WithName(n));
const db = new K.Symbols.DatabaseSymbol.$ctor1("workspace", tables);
const cluster = new K.Symbols.ClusterSymbol.$ctor1("cluster", [db]);
const globals = K.GlobalState.Default.WithCluster(cluster).WithDatabase(db);

// Sample values for workbook parameters
const multi = new Set(["QualityUpdate", "ReleaseName", "OSBuild", "Manufacturer"]);
const sample = { DeviceId: "00000000-0000-0000-0000-000000000000", DetailedStatus: "Total", TargetOSBuild: "*",
                 TimeRange: "Last 90 days", Windows11Readiness: "", DeviceName: "", UPN: "", ReadinessReason: "" };
function substitute(q) {
  return q.replace(/\{(\w+)(:\w+)?\}/g, (m, name) => {
    if (multi.has(name) && !/"[^"\n]*$/.test(q.slice(0, q.indexOf(m)).split("\n").pop())) return "'*'";
    if (name in sample) return sample[name];
    if (multi.has(name)) return "HP";
    return m;
  });
}

let failures = 0, checked = 0;
function check(path, q) {
  checked++;
  const code = K.KustoCode.ParseAndAnalyze(substitute(q), globals);
  const diags = code.GetDiagnostics();
  const errs = [];
  for (let i = 0; i < diags.Count; i++) {
    const d = diags.getItem(i);
    if (d.Severity === "Error") errs.push(`${d.Code}: ${d.Message} @${d.Start}`);
  }
  if (errs.length) { failures++; console.log(`FAIL ${path}\n  ${errs.join("\n  ")}`); }
}
function walk(items, path) {
  for (const it of items) {
    const p = `${path}/${it.name}`;
    const c = it.content || {};
    if (it.type === 3) check(p, c.query);
    if (it.type === 9) for (const prm of c.parameters) if (prm.query && prm.queryType === 0) check(`${p}/${prm.name}`, prm.query);
    if (it.type === 12) walk(c.items, p);
  }
}
walk(JSON.parse(fs.readFileSync(process.argv[2], "utf8")).items, "");
console.log(`\n${checked} queries checked, ${failures} with errors`);
process.exit(failures ? 1 : 0);
