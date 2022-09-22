namespace Rusty.Jwt;

public class Header : Dictionary<string, string>
{
    public string? Id
    {
        get => GetValue(JwtHeaderClaimTypes.Id);
        set => SetValue(JwtHeaderClaimTypes.Id, value);
    }
    
    public string? KeyId
    {
        get => GetValue(JwtHeaderClaimTypes.KeyId);
        set => SetValue(JwtHeaderClaimTypes.KeyId, value);
    }
    
    public string? Algorithm
    {
        get => GetValue(JwtHeaderClaimTypes.Algorithm);
        set => SetValue(JwtHeaderClaimTypes.Algorithm, value);
    }

    public Header()
    {
        this[JwtHeaderClaimTypes.Type] = "jwt";
    }
    
    private string? GetValue(string key)
    {
        return ContainsKey(key) ? this[key] : null;
    }

    private void SetValue(string key, string? value)
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