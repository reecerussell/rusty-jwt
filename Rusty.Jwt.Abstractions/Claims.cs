namespace Rusty.Jwt;

public class Claims : Dictionary<string, object>
{
    public string? Issuer
    {
        get => (string?)GetValue(JwtClaimTypes.Issuer);
        set => SetValue(JwtClaimTypes.Issuer, value);
    }

    public string? Audience
    {
        get => (string?)GetValue(JwtClaimTypes.Audience);
        set => SetValue(JwtClaimTypes.Audience, value);
    }

    public string? Subject
    {
        get => (string?)GetValue(JwtClaimTypes.Subject);
        set => SetValue(JwtClaimTypes.Subject, value);
    }

    public DateTimeOffset? Expiry
    {
        get => GetTimeStamp(JwtClaimTypes.Expiry);
        set => SetValue(JwtClaimTypes.Expiry, value?.ToUnixTimeSeconds());
    }
    
    public DateTimeOffset? NotBefore
    {
        get => GetTimeStamp(JwtClaimTypes.NotBefore);
        set => SetValue(JwtClaimTypes.NotBefore, value?.ToUnixTimeSeconds());
    }
    
    public DateTimeOffset? IssuedAt
    {
        get => GetTimeStamp(JwtClaimTypes.IssuedAt);
        set => SetValue(JwtClaimTypes.IssuedAt, value?.ToUnixTimeSeconds());
    }

    private DateTimeOffset? GetTimeStamp(string key)
    {
        if (!ContainsKey(key) ||
            !int.TryParse($"{this[key]}", out var value))
        {
            return null;
        }
        
        return DateTimeOffset.UnixEpoch.AddSeconds(value);
    }

    private object? GetValue(string key)
    {
        return ContainsKey(key) ? this[key] : null;
    }

    private void SetValue(string key, object? value)
    {
        if (value == null)
        {
            Remove(key);
        }
        else
        {
            this[key] = value;
        }
    }
}