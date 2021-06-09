using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.ActiveDirectory;
using System.Runtime.InteropServices;

namespace TheSprayer.Helpers
{
    public static class DomainHelpers
    {
        public static string GetCurrentDomain()
        {
            try
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    return System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().DomainName;
                }
            }
            catch {}

            return null;
        }

        public static string GetDomainController(string domainName)
        {
            try 
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    var domainContext = new DirectoryContext(DirectoryContextType.Domain, domainName);

                    var domain = Domain.GetDomain(domainContext);
                    var controller = domain.FindDomainController();
                    return controller.IPAddress;
                }
            }
            catch {}

            return null;
        }

        public static bool IsImplicitUserValid(string dc)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                using var context = new PrincipalContext(ContextType.Domain, dc);
                return context.ValidateCredentials(null, null);
            }
            return false;
        }
    }
}
