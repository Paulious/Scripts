using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security;

namespace MspTap
{
    public class NotifyBase : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;
        protected void Raise(string name)
        {
            PropertyChangedEventHandler h = PropertyChanged;
            if (h != null) h(this, new PropertyChangedEventArgs(name));
        }
        public void RefreshAll() { Raise(""); }
    }

    // A user in the work queue / lookup results.
    public class UserRow : NotifyBase
    {
        bool selected; string status = "Pending"; string detail = ""; string id = ""; string displayName = "";
        public bool Selected { get { return selected; } set { selected = value; Raise("Selected"); } }
        public string UserPrincipalName { get; set; }
        public string DisplayName { get { return displayName; } set { displayName = value; Raise("DisplayName"); } }
        public string Department { get; set; }
        public string JobTitle { get; set; }
        public string Source { get; set; }
        public string Id { get { return id; } set { id = value; Raise("Id"); } }
        public string Status { get { return status; } set { status = value; Raise("Status"); } }
        public string Detail { get { return detail; } set { detail = value; Raise("Detail"); } }
    }

    // A generated (or failed) TAP. The pass itself is held in a SecureString and only
    // materialised as plain text while "Reveal" is on or when copying/exporting.
    public class TapRow : NotifyBase
    {
        const string Mask = "••••••••••";
        SecureString tap; bool reveal; string status = ""; string error = ""; int tapLength;
        public string UserPrincipalName { get; set; }
        public string DisplayName { get; set; }
        public int TapLength { get { return tapLength; } set { tapLength = value; Raise("TapLength"); } }
        public string Lifetime { get; set; }
        public bool OneTimeUse { get; set; }
        public DateTime? StartUtc { get; set; }
        public DateTime? ExpiryUtc { get; set; }
        public DateTime? CreatedUtc { get; set; }
        public string Created { get { return CreatedUtc.HasValue ? CreatedUtc.Value.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss") : ""; } }
        public string Status { get { return status; } set { status = value; Raise("Status"); } }
        public string Error { get { return error; } set { error = value; Raise("Error"); } }
        public bool HasTap { get { return tap != null; } }
        public SecureString Tap
        {
            get { return tap; }
            set { if (tap != null) tap.Dispose(); tap = value; Raise("Tap"); Raise("TapDisplay"); Raise("HasTap"); }
        }
        public bool Reveal { get { return reveal; } set { reveal = value; Raise("Reveal"); Raise("TapDisplay"); } }
        public string TapDisplay
        {
            get
            {
                if (tap == null) return Status == "Cleared" ? "(cleared)" : "";
                return reveal ? GetPlain() : Mask;
            }
        }
        public string GetPlain()
        {
            if (tap == null) return "";
            IntPtr p = Marshal.SecureStringToGlobalAllocUnicode(tap);
            try { return Marshal.PtrToStringUni(p); }
            finally { Marshal.ZeroFreeGlobalAllocUnicode(p); }
        }
        public void ClearTap()
        {
            if (tap != null) { tap.Dispose(); tap = null; }
            reveal = false;
            if (status == "Success") Status = "Cleared";
            Raise("Tap"); Raise("TapDisplay"); Raise("HasTap"); Raise("Reveal");
        }
    }
}
