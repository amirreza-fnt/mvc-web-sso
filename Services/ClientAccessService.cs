using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Channels;
using Dapper;
using Npgsql;

namespace SSOLoginService.Web.Services;

public record ApiClientIdentity(int ClientId, int? ApiKeyId);

public record ApiRequestLogEntry(
    int? ClientId,
    int? ApiKeyId,
    string? Origin,
    string Path,
    int StatusCode,
    string? Ip,
    DateTime CreatedAt);

/// <summary>
/// Read-only view of the sso-panel database (clients, API keys, allowed domains).
/// Data is held in an in-memory snapshot refreshed by <see cref="ClientAccessRefresher"/>,
/// so lookups never hit the database on the request path.
/// </summary>
public class ClientAccessService
{
    private readonly ILogger<ClientAccessService> _logger;
    private readonly Channel<ApiRequestLogEntry> _logChannel =
        Channel.CreateBounded<ApiRequestLogEntry>(new BoundedChannelOptions(10_000)
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            SingleReader = true
        });
    private readonly ConcurrentDictionary<int, DateTime> _keyUsage = new();

    private volatile Snapshot _snapshot = Snapshot.Empty;

    public ClientAccessService(IConfiguration configuration, ILogger<ClientAccessService> logger)
    {
        _logger = logger;
        ConnectionString = configuration.GetConnectionString("SsoPanel");
        Enforce = configuration.GetValue("ClientAccess:Enforce", false);
        RefreshInterval = TimeSpan.FromSeconds(Math.Max(5, configuration.GetValue("ClientAccess:CacheSeconds", 60)));
    }

    public string? ConnectionString { get; }

    public bool IsEnabled => !string.IsNullOrWhiteSpace(ConnectionString);

    /// <summary>When false, unauthorized /api calls are only logged, not rejected.</summary>
    public bool Enforce { get; }

    public TimeSpan RefreshInterval { get; }

    public bool HasLoaded => _snapshot.LoadedAt != null;

    public bool IsOriginAllowed(string? origin) => MatchOrigin(origin) != null;

    public ApiClientIdentity? MatchOrigin(string? origin)
    {
        if (string.IsNullOrWhiteSpace(origin) || !Uri.TryCreate(origin, UriKind.Absolute, out var uri))
            return null;

        var clientId = _snapshot.MatchDomain(uri);
        return clientId.HasValue ? new ApiClientIdentity(clientId.Value, null) : null;
    }

    public bool IsCallbackAllowed(Uri target) =>
        target.IsAbsoluteUri && _snapshot.MatchDomain(target).HasValue;

    public ApiClientIdentity? ValidateApiKey(string? plainKey)
    {
        if (string.IsNullOrWhiteSpace(plainKey) || plainKey.Length > 200)
            return null;

        var hash = HashKey(plainKey.Trim());
        if (!_snapshot.Keys.TryGetValue(hash, out var key))
            return null;

        if (key.ExpiresAt.HasValue && key.ExpiresAt.Value <= DateTime.UtcNow)
            return null;

        _keyUsage[key.KeyId] = DateTime.UtcNow;
        return new ApiClientIdentity(key.ClientId, key.KeyId);
    }

    public void EnqueueLog(ApiRequestLogEntry entry)
    {
        if (IsEnabled)
            _logChannel.Writer.TryWrite(entry);
    }

    /// <summary>Must match ApiKeyGenerator.Hash in sso-panel.</summary>
    public static string HashKey(string plainKey) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(plainKey))).ToLowerInvariant();

    internal async Task RefreshAsync(CancellationToken ct)
    {
        await using var conn = new NpgsqlConnection(ConnectionString);
        await conn.OpenAsync(ct);

        var keys = await conn.QueryAsync<KeyRow>(new CommandDefinition(
            """
            SELECT k.id AS KeyId, k.client_id AS ClientId, k.key_hash AS KeyHash, k.expires_at AS ExpiresAt
            FROM api_keys k
            JOIN clients c ON c.id = k.client_id
            WHERE c.is_active AND k.revoked_at IS NULL
              AND (k.expires_at IS NULL OR k.expires_at > now())
            """, cancellationToken: ct));

        var domains = await conn.QueryAsync<DomainRow>(new CommandDefinition(
            """
            SELECT d.client_id AS ClientId, d.origin AS Origin, d.allow_subdomains AS AllowSubdomains
            FROM allowed_domains d
            JOIN clients c ON c.id = d.client_id
            WHERE c.is_active AND d.is_active
            """, cancellationToken: ct));

        var snapshot = Snapshot.Build(keys, domains);
        _snapshot = snapshot;
        _logger.LogDebug(
            "Client access snapshot refreshed: {Keys} keys, {Domains} domains",
            snapshot.Keys.Count, snapshot.DomainCount);
    }

    internal async Task FlushAsync(CancellationToken ct)
    {
        var batch = new List<ApiRequestLogEntry>();
        while (batch.Count < 1000 && _logChannel.Reader.TryRead(out var entry))
            batch.Add(entry);

        var usage = _keyUsage.ToArray();
        foreach (var (id, _) in usage)
            _keyUsage.TryRemove(id, out _);

        if (batch.Count == 0 && usage.Length == 0)
            return;

        await using var conn = new NpgsqlConnection(ConnectionString);
        await conn.OpenAsync(ct);
        await using var tx = await conn.BeginTransactionAsync(ct);

        if (batch.Count > 0)
        {
            await conn.ExecuteAsync(new CommandDefinition(
                """
                INSERT INTO api_request_logs (client_id, api_key_id, origin, path, status_code, ip, created_at)
                VALUES (@ClientId, @ApiKeyId, @Origin, @Path, @StatusCode, @Ip, @CreatedAt)
                """, batch.Select(e => new
                {
                    e.ClientId,
                    e.ApiKeyId,
                    Origin = Truncate(e.Origin, 300),
                    Path = Truncate(e.Path, 500)!,
                    e.StatusCode,
                    Ip = Truncate(e.Ip, 64),
                    e.CreatedAt
                }), tx, cancellationToken: ct));
        }

        if (usage.Length > 0)
        {
            await conn.ExecuteAsync(new CommandDefinition(
                "UPDATE api_keys SET last_used_at = @UsedAt WHERE id = @Id AND (last_used_at IS NULL OR last_used_at < @UsedAt)",
                usage.Select(u => new { Id = u.Key, UsedAt = u.Value }), tx, cancellationToken: ct));
        }

        await tx.CommitAsync(ct);
    }

    internal bool HasPendingWrites => _logChannel.Reader.Count > 0 || !_keyUsage.IsEmpty;

    private static string? Truncate(string? value, int max) =>
        value == null || value.Length <= max ? value : value[..max];

    private sealed class KeyRow
    {
        public int KeyId { get; set; }
        public int ClientId { get; set; }
        public string KeyHash { get; set; } = string.Empty;
        public DateTime? ExpiresAt { get; set; }
    }

    private sealed class DomainRow
    {
        public int ClientId { get; set; }
        public string Origin { get; set; } = string.Empty;
        public bool AllowSubdomains { get; set; }
    }

    private sealed record KeyEntry(int KeyId, int ClientId, DateTime? ExpiresAt);

    private sealed record DomainEntry(int ClientId, string Scheme, string Host, int Port, bool AllowSubdomains);

    private sealed class Snapshot
    {
        public static readonly Snapshot Empty = new(
            new Dictionary<string, KeyEntry>(), new Dictionary<string, DomainEntry>(), Array.Empty<DomainEntry>(), null);

        private readonly Dictionary<string, DomainEntry> _exactOrigins;
        private readonly DomainEntry[] _wildcards;

        private Snapshot(
            Dictionary<string, KeyEntry> keys,
            Dictionary<string, DomainEntry> exactOrigins,
            DomainEntry[] wildcards,
            DateTime? loadedAt)
        {
            Keys = keys;
            _exactOrigins = exactOrigins;
            _wildcards = wildcards;
            LoadedAt = loadedAt;
        }

        public Dictionary<string, KeyEntry> Keys { get; }
        public DateTime? LoadedAt { get; }
        public int DomainCount => _exactOrigins.Count;

        public static Snapshot Build(IEnumerable<KeyRow> keys, IEnumerable<DomainRow> domains)
        {
            var keyMap = new Dictionary<string, KeyEntry>(StringComparer.Ordinal);
            foreach (var k in keys)
                keyMap[k.KeyHash.ToLowerInvariant()] = new KeyEntry(k.KeyId, k.ClientId, k.ExpiresAt);

            var exact = new Dictionary<string, DomainEntry>(StringComparer.OrdinalIgnoreCase);
            var wildcards = new List<DomainEntry>();
            foreach (var d in domains)
            {
                if (!Uri.TryCreate(d.Origin, UriKind.Absolute, out var uri))
                    continue;

                var entry = new DomainEntry(d.ClientId, uri.Scheme, uri.Host.ToLowerInvariant(), uri.Port, d.AllowSubdomains);
                exact[OriginKey(uri.Scheme, entry.Host, uri.Port)] = entry;
                if (d.AllowSubdomains)
                    wildcards.Add(entry);
            }

            return new Snapshot(keyMap, exact, wildcards.ToArray(), DateTime.UtcNow);
        }

        public int? MatchDomain(Uri uri)
        {
            var host = uri.Host.ToLowerInvariant();
            if (_exactOrigins.TryGetValue(OriginKey(uri.Scheme, host, uri.Port), out var exact))
                return exact.ClientId;

            foreach (var w in _wildcards)
            {
                if (w.Port == uri.Port
                    && string.Equals(w.Scheme, uri.Scheme, StringComparison.OrdinalIgnoreCase)
                    && host.EndsWith("." + w.Host, StringComparison.Ordinal))
                {
                    return w.ClientId;
                }
            }

            return null;
        }

        private static string OriginKey(string scheme, string host, int port) =>
            $"{scheme.ToLowerInvariant()}://{host}:{port}";
    }
}

public class ClientAccessRefresher : BackgroundService
{
    private static readonly TimeSpan FlushInterval = TimeSpan.FromSeconds(3);

    private readonly ClientAccessService _access;
    private readonly ILogger<ClientAccessRefresher> _logger;

    public ClientAccessRefresher(ClientAccessService access, ILogger<ClientAccessRefresher> logger)
    {
        _access = access;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_access.IsEnabled)
        {
            _logger.LogWarning("ConnectionStrings:SsoPanel is not set; API key / domain checks are disabled.");
            return;
        }

        var nextRefresh = DateTime.MinValue;
        using var timer = new PeriodicTimer(FlushInterval);

        do
        {
            if (DateTime.UtcNow >= nextRefresh)
            {
                try
                {
                    await _access.RefreshAsync(stoppingToken);
                    nextRefresh = DateTime.UtcNow + _access.RefreshInterval;
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _logger.LogError(ex, "Failed to refresh client access data from sso-panel database; keeping previous snapshot");
                    nextRefresh = DateTime.UtcNow + TimeSpan.FromSeconds(10);
                }
            }

            await FlushSafeAsync(stoppingToken);
        }
        while (await WaitAsync(timer, stoppingToken));

        await FlushSafeAsync(CancellationToken.None);
    }

    private async Task FlushSafeAsync(CancellationToken ct)
    {
        try
        {
            while (_access.HasPendingWrites)
                await _access.FlushAsync(ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex, "Failed to write API request logs to sso-panel database");
        }
    }

    private static async Task<bool> WaitAsync(PeriodicTimer timer, CancellationToken ct)
    {
        try
        {
            return await timer.WaitForNextTickAsync(ct);
        }
        catch (OperationCanceledException)
        {
            return false;
        }
    }
}
