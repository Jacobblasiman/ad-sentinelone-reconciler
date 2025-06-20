using System;
using System.Collections.Generic;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net;
using System.Text.Json;
using System.Threading.Tasks;
using System.IO;

class Program
{
    static async Task Main()
    {
        Console.Write("Enter SentinelOne tenant domain (e.g. yourtenant.sentinelone.net): ");
        string sentinelOneDomain = Console.ReadLine().Trim();

        Console.Write("Enter SentinelOne API Token: ");
        string sentinelOneApiToken = Console.ReadLine().Trim();

        string domainName = Domain.GetCurrentDomain().Name;
        Console.WriteLine($"[INFO] Detected domain: {domainName}");

        string domainController = domainName;

        Console.Write("Enter comma separated AD groups to include (leave blank for all computers): ");
        var includeInput = Console.ReadLine().Trim();
        var includeGroups = string.IsNullOrWhiteSpace(includeInput)
            ? new List<string>()
            : includeInput.Split(',').Select(g => g.Trim()).Where(g => !string.IsNullOrEmpty(g)).ToList();

        Console.Write("Enter comma separated AD groups to exclude (leave blank for none): ");
        var excludeInput = Console.ReadLine().Trim();
        var excludeGroups = string.IsNullOrWhiteSpace(excludeInput)
            ? new List<string>()
            : excludeInput.Split(',').Select(g => g.Trim()).Where(g => !string.IsNullOrEmpty(g)).ToList();

        NetworkCredential credential = null;
        Console.Write("Use different credentials to query AD? (y/N): ");
        var credAnswer = Console.ReadLine().Trim();
        if (credAnswer.Equals("y", StringComparison.OrdinalIgnoreCase))
        {
            Console.Write("Enter username: ");
            var user = Console.ReadLine().Trim();
            Console.Write("Enter password: ");
            var pass = Console.ReadLine();
            credential = new NetworkCredential(user, pass);
        }

        Console.WriteLine("[INFO] Querying Active Directory...");
        var adDevices = GetActiveDirectoryDevices(domainController, domainName, credential, includeGroups, excludeGroups);

        Console.WriteLine($"[INFO] Found {adDevices.Count} devices in Active Directory:");
        foreach (var dev in adDevices)
        {
            Console.WriteLine($"[AD] {dev}");
        }

        Console.WriteLine("[INFO] Querying SentinelOne...");
        var s1Devices = await GetSentinelOneDevicesAsync(sentinelOneDomain, sentinelOneApiToken);

        Console.WriteLine($"[INFO] Found {s1Devices.Count} devices in SentinelOne:");
        foreach (var dev in s1Devices)
        {
            Console.WriteLine($"[S1] {dev}");
        }

        Console.WriteLine("[INFO] Starting reconciliation...");

        var adDeviceNames = new HashSet<string>(adDevices, StringComparer.OrdinalIgnoreCase);
        var s1DeviceNames = new HashSet<string>(s1Devices, StringComparer.OrdinalIgnoreCase);

        int missingCount = 0;
        var missingDevices = new List<string>();

        foreach (var adDevice in adDeviceNames)
        {
            if (!s1DeviceNames.Contains(adDevice))
            {
                Console.WriteLine($"[MISSING] {adDevice} found in AD but not reporting to SentinelOne");
                missingDevices.Add(adDevice);
                missingCount++;
            }
            else
            {
                Console.WriteLine($"[OK] {adDevice} found in both AD and SentinelOne.");
            }
        }

        Console.WriteLine();
        Console.WriteLine($"[SUMMARY] Total AD devices: {adDevices.Count}");
        Console.WriteLine($"[SUMMARY] Total S1 devices: {s1Devices.Count}");
        Console.WriteLine($"[SUMMARY] Total missing devices: {missingCount}");

        if (missingDevices.Count > 0)
        {
            string selectedFolder = PromptFolderPath();
            if (!string.IsNullOrEmpty(selectedFolder))
            {
                string csvPath = Path.Combine(selectedFolder, "MissingDevices.csv");
                File.WriteAllLines(csvPath, missingDevices);
                Console.WriteLine($"[SUCCESS] Missing devices exported to: {csvPath}");
            }
            else
            {
                Console.WriteLine("[WARN] No valid folder path provided. Skipping CSV export.");
            }
        }
        else
        {
            Console.WriteLine("[INFO] No missing devices to export.");
        }

        Console.WriteLine("Press any key to exit...");
        Console.ReadKey();
    }

    static string PromptFolderPath()
    {
        while (true)
        {
            Console.Write("Enter full path to folder where CSV should be saved: ");
            string folderPath = Console.ReadLine().Trim();
            if (Directory.Exists(folderPath))
            {
                return folderPath;
            }
            else
            {
                Console.WriteLine("[ERROR] Folder does not exist. Please enter a valid path.");
            }
        }
    }

    static List<string> GetActiveDirectoryDevices(
        string dc,
        string domainName,
        NetworkCredential credential,
        List<string> includeGroups,
        List<string> excludeGroups)
    {
        var devices = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        try
        {
            long fileTimeThreshold = DateTime.UtcNow.AddDays(-30).ToFileTimeUtc();
            string searchBase = string.Join(",", domainName.Split('.').Select(part => $"DC={part}"));

            using (var ldapConnection = new LdapConnection(new LdapDirectoryIdentifier(dc)))
            {
                ldapConnection.AuthType = AuthType.Negotiate;
                ldapConnection.SessionOptions.ProtocolVersion = 3;
                if (credential != null)
                {
                    ldapConnection.Credential = credential;
                }

                if (includeGroups != null && includeGroups.Count > 0)
                {
                    foreach (var group in includeGroups)
                    {
                        foreach (var name in GetGroupMembers(ldapConnection, searchBase, group, fileTimeThreshold))
                        {
                            devices.Add(name);
                        }
                    }
                }
                else
                {
                    foreach (var name in QueryAllComputers(ldapConnection, searchBase, fileTimeThreshold))
                    {
                        devices.Add(name);
                    }
                }

                if (excludeGroups != null && excludeGroups.Count > 0)
                {
                    foreach (var group in excludeGroups)
                    {
                        foreach (var name in GetGroupMembers(ldapConnection, searchBase, group, fileTimeThreshold))
                        {
                            devices.Remove(name);
                        }
                    }
                }

            }
        }
        catch (LdapException ldapEx)
        {
            Console.WriteLine($"[ERROR] LDAP Exception: {ldapEx.Message}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ERROR] General Exception: {ex.Message}");
        }

        return devices;
    }

    static IEnumerable<string> QueryAllComputers(LdapConnection connection, string searchBase, long threshold)
    {
        var list = new List<string>();
        string filter = $"(&(objectClass=computer)(lastLogonTimestamp>={threshold}))";
        Console.WriteLine($"[DEBUG] Using LDAP search base: {searchBase}");
        Console.WriteLine($"[DEBUG] LDAP Filter: {filter}");
        var searchRequest = new SearchRequest(searchBase, filter, SearchScope.Subtree, new[] { "dNSHostName" });
        var searchResponse = (SearchResponse)connection.SendRequest(searchRequest);
        foreach (SearchResultEntry entry in searchResponse.Entries)
        {
            if (entry.Attributes.Contains("dNSHostName"))
            {
                var fullName = entry.Attributes["dNSHostName"][0].ToString();
                var name = fullName.Split('.')[0];
                list.Add(name);
            }
        }
        return list;
    }

    static IEnumerable<string> GetGroupMembers(LdapConnection connection, string searchBase, string groupName, long threshold)
    {
        var list = new List<string>();
        try
        {
            string groupFilter = $"(&(objectClass=group)(cn={groupName}))";
            var groupRequest = new SearchRequest(searchBase, groupFilter, SearchScope.Subtree);
            var groupResponse = (SearchResponse)connection.SendRequest(groupRequest);
            if (groupResponse.Entries.Count == 0)
            {
                Console.WriteLine($"[WARN] Group '{groupName}' not found.");
                return list;
            }

            foreach (SearchResultEntry grp in groupResponse.Entries)
            {
                string groupDn = grp.DistinguishedName;
                string compFilter = $"(&(objectClass=computer)(memberOf={groupDn})(lastLogonTimestamp>={threshold}))";
                var compRequest = new SearchRequest(searchBase, compFilter, SearchScope.Subtree, new[] { "dNSHostName" });
                var compResponse = (SearchResponse)connection.SendRequest(compRequest);
                foreach (SearchResultEntry entry in compResponse.Entries)
                {
                    if (entry.Attributes.Contains("dNSHostName"))
                    {
                        var fullName = entry.Attributes["dNSHostName"][0].ToString();
                        var name = fullName.Split('.')[0];
                        list.Add(name);
                    }
                }
            }
        }
        catch (LdapException ldapEx)
        {
            Console.WriteLine($"[ERROR] LDAP Exception while getting group '{groupName}': {ldapEx.Message}");
        }
        return list;
    }

    static async Task<List<string>> GetSentinelOneDevicesAsync(string baseDomain, string apiToken)
    {
        var list = new List<string>();
        using (var client = new HttpClient())
        {
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("ApiToken", apiToken);
            string thirtyDaysAgoIso = DateTime.UtcNow.AddDays(-30).ToString("yyyy-MM-ddTHH:mm:ssZ");

            string urlBase = $"https://{baseDomain}/web/api/v2.1/agents?lastActiveDate__gte={thirtyDaysAgoIso}&limit=1000";
            string nextCursor = null;

            do
            {
                string url = urlBase;
                if (!string.IsNullOrEmpty(nextCursor))
                {
                    url += $"&cursor={nextCursor}";
                }

                Console.WriteLine($"[DEBUG] Calling S1 URL: {url}");
                var response = await client.GetAsync(url);

                if (!response.IsSuccessStatusCode)
                {
                    string errorBody = await response.Content.ReadAsStringAsync();
                    Console.WriteLine("[ERROR] API Request failed:");
                    Console.WriteLine(errorBody);
                    throw new Exception($"API request failed: {response.StatusCode}");
                }

                var responseBody = await response.Content.ReadAsStringAsync();
                using var doc = JsonDocument.Parse(responseBody);
                var root = doc.RootElement;

                var agents = root.GetProperty("data").EnumerateArray();

                foreach (var agent in agents)
                {
                    var name = agent.GetProperty("computerName").GetString();
                    list.Add(name);
                }

                if (root.TryGetProperty("pagination", out var pagination))
                {
                    nextCursor = pagination.GetProperty("nextCursor").GetString();
                    if (string.IsNullOrEmpty(nextCursor))
                    {
                        nextCursor = null;
                    }
                }
                else
                {
                    nextCursor = null;
                }

            } while (nextCursor != null);
        }

        return list;
    }
}
