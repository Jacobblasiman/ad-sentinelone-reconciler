using System;
using System.Collections.Generic;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

class Program
{
    public sealed record S1CredentialsRecord(
        int Version,
        string Scope,
        string EntropyHint,
        string EncryptedDomainBase64,
        string EncryptedTokenBase64
    );

    static readonly string CredentialPath = BuildCredentialPath();

    static string BuildCredentialPath()
    {
        string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        if (string.IsNullOrEmpty(appData))
            throw new InvalidOperationException("Could not resolve the ApplicationData folder. Ensure the environment is configured correctly.");
        return Path.Combine(appData, "S1CLIData", "s1-credentials.json");
    }

    static async Task Main(string[] args)
    {
        // Handle --reset flag: delete stored credentials
        if (args.Contains("--reset", StringComparer.OrdinalIgnoreCase))
        {
            if (File.Exists(CredentialPath))
            {
                File.Delete(CredentialPath);
                Console.WriteLine($"[INFO] Stored credentials deleted: {CredentialPath}");
            }
            else
            {
                Console.WriteLine("[INFO] No stored credentials found to reset.");
            }

            Console.Write("Continue with new credentials? (y/N): ");
            string continueAnswer = (Console.ReadLine() ?? "").Trim();
            if (!continueAnswer.Equals("y", StringComparison.OrdinalIgnoreCase))
            {
                Console.WriteLine("[INFO] Exiting.");
                return;
            }
        }

        string domain;
        string token;

        if (File.Exists(CredentialPath))
        {
            Console.WriteLine($"[INFO] Found saved credentials: {CredentialPath}");
            Console.Write("Enter decryption password (or type 'reset' to wipe saved credentials): ");
            string pwInput = (Console.ReadLine() ?? "").Trim();

            if (pwInput.Equals("reset", StringComparison.OrdinalIgnoreCase))
            {
                File.Delete(CredentialPath);
                Console.WriteLine("[INFO] Stored credentials deleted.");
            }
            else
            {
                (domain, token) = DecryptCredentials(pwInput);
                goto credentialsReady;
            }
        }

        {
            // Prompt for credentials
            string inputDomain = PromptRequired("Enter SentinelOne tenant domain (e.g. yourtenant.sentinelone.net): ");
            string inputToken = PromptRequired("Enter SentinelOne API Token: ");

            Console.Write("Save URL and API Token for future use? (y/N): ");
            string saveAnswer = Console.ReadLine()?.Trim() ?? "";

            if (saveAnswer.Equals("y", StringComparison.OrdinalIgnoreCase))
            {
                string entropyPw = PromptRequired("Provide PW for Encryption: ");
                SaveCredentials(inputDomain, inputToken, entropyPw);
                Console.WriteLine($"[INFO] Saved credentials to: {CredentialPath}");
            }

            domain = inputDomain;
            token = inputToken;
        }

        credentialsReady:
        string domainName = Domain.GetCurrentDomain().Name;
        Console.WriteLine($"[INFO] Detected domain: {domainName}");

        string domainController = domainName;

        Console.Write("Enter comma separated AD groups to include (leave blank for all computers): ");
        var includeInput = (Console.ReadLine() ?? "").Trim();
        var includeGroups = string.IsNullOrWhiteSpace(includeInput)
            ? new List<string>()
            : includeInput.Split(',').Select(g => g.Trim()).Where(g => !string.IsNullOrEmpty(g)).ToList();

        Console.Write("Enter comma separated AD groups to exclude (leave blank for none): ");
        var excludeInput = (Console.ReadLine() ?? "").Trim();
        var excludeGroups = string.IsNullOrWhiteSpace(excludeInput)
            ? new List<string>()
            : excludeInput.Split(',').Select(g => g.Trim()).Where(g => !string.IsNullOrEmpty(g)).ToList();

        NetworkCredential credential = null;
        Console.Write("Use different credentials to query AD? (y/N): ");
        var credAnswer = (Console.ReadLine() ?? "").Trim();
        if (credAnswer.Equals("y", StringComparison.OrdinalIgnoreCase))
        {
            var user = PromptRequired("Enter username: ");
            var pass = PromptRequired("Enter password: ");
            credential = new NetworkCredential(user, pass);
        }

        Console.WriteLine($"[INFO] Verifying domain controller reachability: {domainController}...");
        if (!IsDomainControllerReachable(domainController))
        {
            Console.WriteLine($"[ERROR] Domain controller '{domainController}' is not reachable on port 389 (LDAP).");
            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();
            return;
        }
        Console.WriteLine("[INFO] Domain controller is reachable.");

        Console.WriteLine("[INFO] Querying Active Directory...");
        var (adDevices, adQuerySuccess) = GetActiveDirectoryDevices(domainController, domainName, credential, includeGroups, excludeGroups);

        if (!adQuerySuccess)
        {
            Console.WriteLine("[WARN] AD query encountered errors. Results may be incomplete.");
        }

        Console.WriteLine($"[INFO] Found {adDevices.Count} devices in Active Directory:");
        foreach (var dev in adDevices)
        {
            Console.WriteLine($"[AD] {dev}");
        }

        Console.WriteLine("[INFO] Querying SentinelOne...");
        var s1Devices = await GetSentinelOneDevicesAsync(domain, token);

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

    static string PromptRequired(string prompt)
    {
        while (true)
        {
            Console.Write(prompt);
            string? input = Console.ReadLine()?.Trim();
            if (!string.IsNullOrWhiteSpace(input))
                return input;
            Console.WriteLine("[ERROR] Input cannot be empty.");
        }
    }

    static void SaveCredentials(string domainValue, string tokenValue, string entropyPw)
    {
        byte[] entropy = Encoding.UTF8.GetBytes(entropyPw);
        byte[] encryptedDomain = ProtectedData.Protect(Encoding.UTF8.GetBytes(domainValue), entropy, DataProtectionScope.CurrentUser);
        byte[] encryptedToken = ProtectedData.Protect(Encoding.UTF8.GetBytes(tokenValue), entropy, DataProtectionScope.CurrentUser);

        var record = new S1CredentialsRecord(
            Version: 1,
            Scope: "CurrentUser",
            EntropyHint: Environment.MachineName,
            EncryptedDomainBase64: Convert.ToBase64String(encryptedDomain),
            EncryptedTokenBase64: Convert.ToBase64String(encryptedToken)
        );

        string json = JsonSerializer.Serialize(record, new JsonSerializerOptions { WriteIndented = true });
        Directory.CreateDirectory(Path.GetDirectoryName(CredentialPath)!);
        File.WriteAllText(CredentialPath, json);
    }

    static (string domain, string token) DecryptCredentials(string password)
    {
        string json = File.ReadAllText(CredentialPath);
        var record = JsonSerializer.Deserialize<S1CredentialsRecord>(json)
                     ?? throw new InvalidOperationException("Credential file was empty or invalid.");

        byte[] entropy = Encoding.UTF8.GetBytes(password);

        try
        {
            string domain = Encoding.UTF8.GetString(
                ProtectedData.Unprotect(Convert.FromBase64String(record.EncryptedDomainBase64), entropy, DataProtectionScope.CurrentUser)
            );
            string token = Encoding.UTF8.GetString(
                ProtectedData.Unprotect(Convert.FromBase64String(record.EncryptedTokenBase64), entropy, DataProtectionScope.CurrentUser)
            );
            return (domain, token);
        }
        catch (CryptographicException)
        {
            Console.WriteLine("[ERROR] Decryption failed — wrong password or credentials were stored on a different machine.");
            Console.WriteLine("[HINT] Type 'reset' at the password prompt or run with --reset to clear stored credentials.");
            Environment.Exit(1);
            throw; // unreachable, satisfies compiler
        }
    }

    static string PromptFolderPath()
    {
        while (true)
        {
            Console.Write("Enter full path to folder where CSV should be saved (or 'skip' to cancel): ");
            string folderPath = (Console.ReadLine() ?? "").Trim();
            if (folderPath.Equals("skip", StringComparison.OrdinalIgnoreCase))
                return "";
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

    static bool IsDomainControllerReachable(string dc, int port = 389, int timeoutMs = 3000)
    {
        try
        {
            using var cts = new System.Threading.CancellationTokenSource(timeoutMs);
            using var tcp = new System.Net.Sockets.TcpClient();
            tcp.ConnectAsync(dc, port).Wait(cts.Token);
            return tcp.Connected;
        }
        catch (OperationCanceledException)
        {
            return false;
        }
        catch
        {
            return false;
        }
    }

    static string LdapEscape(string input)
    {
        var sb = new StringBuilder(input.Length);
        foreach (char c in input)
        {
            switch (c)
            {
                case '\\': sb.Append("\\5c"); break;
                case '*':  sb.Append("\\2a"); break;
                case '(':  sb.Append("\\28"); break;
                case ')':  sb.Append("\\29"); break;
                case '\0': sb.Append("\\00"); break;
                default:   sb.Append(c); break;
            }
        }
        return sb.ToString();
    }

    static (HashSet<string> devices, bool success) GetActiveDirectoryDevices(
        string dc,
        string domainName,
        NetworkCredential credential,
        List<string> includeGroups,
        List<string> excludeGroups)
    {
        var devices = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        bool success = true;

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
            success = false;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ERROR] General Exception: {ex.Message}");
            success = false;
        }

        return (devices, success);
    }

    static IEnumerable<string> QueryAllComputers(LdapConnection connection, string searchBase, long threshold)
    {
        string filter = $"(&(objectClass=computer)(lastLogonTimestamp>={threshold}))";
        Console.WriteLine($"[DEBUG] Using LDAP search base: {searchBase}");
        Console.WriteLine($"[DEBUG] LDAP Filter: {filter}");
        return PagedLdapSearchHostnames(connection, searchBase, filter);
    }

    static List<string> PagedLdapSearchHostnames(LdapConnection connection, string searchBase, string filter, int pageSize = 1000)
    {
        var list = new List<string>();
        var searchRequest = new SearchRequest(searchBase, filter, SearchScope.Subtree, new[] { "dNSHostName" });
        var pageControl = new PageResultRequestControl(pageSize);
        searchRequest.Controls.Add(pageControl);

        while (true)
        {
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

            var responseControl = searchResponse.Controls
                .OfType<PageResultResponseControl>()
                .FirstOrDefault();

            if (responseControl == null || responseControl.Cookie == null || responseControl.Cookie.Length == 0)
                break;

            pageControl.Cookie = responseControl.Cookie;
        }

        return list;
    }

    static IEnumerable<string> GetGroupMembers(LdapConnection connection, string searchBase, string groupName, long threshold)
    {
        var list = new List<string>();
        try
        {
            string safeGroupName = LdapEscape(groupName);
            string groupFilter = $"(&(objectClass=group)(cn={safeGroupName}))";
            var groupRequest = new SearchRequest(searchBase, groupFilter, SearchScope.Subtree);
            var groupResponse = (SearchResponse)connection.SendRequest(groupRequest);
            if (groupResponse.Entries.Count == 0)
            {
                Console.WriteLine($"[WARN] Group '{groupName}' not found.");
                return list;
            }

            foreach (SearchResultEntry grp in groupResponse.Entries)
            {
                string groupDn = LdapEscape(grp.DistinguishedName);
                string compFilter = $"(&(objectClass=computer)(memberOf={groupDn})(lastLogonTimestamp>={threshold}))";
                list.AddRange(PagedLdapSearchHostnames(connection, searchBase, compFilter));
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
        using (var client = new HttpClient { Timeout = TimeSpan.FromSeconds(30) })
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
                    if (agent.TryGetProperty("computerName", out var nameProp))
                    {
                        string? name = nameProp.GetString();
                        if (!string.IsNullOrEmpty(name))
                            list.Add(name);
                    }
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

