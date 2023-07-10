using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

namespace AIDIALabs.Security.AccessControl
{
    public static class Permission
    {
        private static string ApplicationFolderPath { get; set; }
        private static string ManufactureFolderPath { get; set; }
        private static string SpecialFolder { get; set; }

        public static bool Set(Environment.SpecialFolder specialFolder, string manufacture, string applicationName, out string reason)
        {
            SpecialFolder = Environment.GetFolderPath(specialFolder);
            ManufactureFolderPath = Path.Combine(SpecialFolder, manufacture);
            ApplicationFolderPath = Path.Combine(ManufactureFolderPath, applicationName);
            try
            {
                DirectoryInfo directoryInfo;
                DirectorySecurity directorySecurity;
                AccessRule rule;
                bool modified = false;
                SecurityIdentifier securityIdentifier = new(WellKnownSidType.BuiltinUsersSid, null);

                if (Directory.Exists(ManufactureFolderPath))
                {
                    directoryInfo = new(ManufactureFolderPath);
                    directorySecurity = directoryInfo.GetAccessControl();
                    rule = new FileSystemAccessRule(
                            securityIdentifier,
                            FileSystemRights.Write |
                            FileSystemRights.ReadAndExecute |
                            FileSystemRights.Modify,
                            AccessControlType.Allow);
                    directorySecurity.ModifyAccessRule(AccessControlModification.Add, rule, out modified);
                    directoryInfo.SetAccessControl(directorySecurity);

                    if (Directory.Exists(ApplicationFolderPath))
                    {
                        directoryInfo = new(ApplicationFolderPath);
                        directorySecurity = directoryInfo.GetAccessControl();
                        rule = new FileSystemAccessRule(
                            securityIdentifier,
                            FileSystemRights.Write |
                            FileSystemRights.ReadAndExecute |
                            FileSystemRights.Modify,
                            InheritanceFlags.ContainerInherit |
                            InheritanceFlags.ObjectInherit,
                            PropagationFlags.InheritOnly,
                            AccessControlType.Allow);
                        directorySecurity.ModifyAccessRule(AccessControlModification.Add, rule, out modified);
                        directoryInfo.SetAccessControl(directorySecurity);
                        reason = string.Empty;
                        return true;
                    }
                    else
                    {
                        reason = "Application folder is not found";
                        return false;
                    }
                }
                else
                {
                    reason = "Manufacture folder is not found";
                    return false;
                }
            }
            catch (Exception ex)
            {
                reason = $"Something went wrong. Exception: {ex}";
                return false;
            }
        }
    }
}
