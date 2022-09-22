using System.Text;
using Base64Extensions;
using Newtonsoft.Json;
using Rusty.Jwt.Keys;

namespace Rusty.Jwt;

public class JwtFactory : IJwtFactory
{
    private readonly IKeyRing _keys;
    private readonly JsonSerializerSettings _jsonSerializerSettings;

    public JwtFactory(IKeyRing keys)
    {
        _keys = keys;
        _jsonSerializerSettings = new JsonSerializerSettings
        {
            NullValueHandling = NullValueHandling.Ignore
        };
    }
    
    public Task<Jwt> CreateAsync(Action<Claims> claimsBuilder, CancellationToken cancellationToken = default)
    {
        var key = _keys.GetSigningKey();

        return InternalCreateAsync(key, claimsBuilder, cancellationToken);
    }
    
    public Task<Jwt> CreateAsync(Action<Claims> claimsBuilder, string keyName, CancellationToken cancellationToken = default)
    {
        var key = _keys.GetSigningKey(keyName);

        return InternalCreateAsync(key, claimsBuilder, cancellationToken);
    }

    private async Task<Jwt> InternalCreateAsync(ISigningKey key, Action<Claims> claimsBuilder, CancellationToken cancellationToken)
    {
        var header = new Header
        {
            Id = Guid.NewGuid().ToString(),
            KeyId = key.Id,
            Algorithm = key.Algorithm.GetPrefix() + key.HashAlgorithm.GetHashSize()
        };
        var claims = new Claims();
        claimsBuilder(claims);

        var headerBytes = ConvertToBase64Json(header);
        var claimsBytes = ConvertToBase64Json(claims);
        var dataLength = headerBytes.Length + 1 + claimsBytes.Length;
        var token = new byte[dataLength];

        var index = headerBytes.Length;
        Buffer.BlockCopy(headerBytes, 0, token, 0, headerBytes.Length);
        token[index] = (byte) '.';
        index++;
        
        Buffer.BlockCopy(claimsBytes, 0, token, index, claimsBytes.Length);
        index += claimsBytes.Length;

        var signature = await key.SignAsync(token, cancellationToken);
        var signatureBase64 = Base64Convert.Encode(signature, true, out var signatureLength);
        Array.Resize(ref token, dataLength + 1 + signatureLength);
        token[index] = (byte) '.';
        index++;
        Buffer.BlockCopy(signatureBase64, 0, token, index, signatureLength);

        return new Jwt
        {
            Id = header.Id,
            Token = Encoding.UTF8.GetString(token),
            ExpiresIn = (long?) claims.Expiry?.Subtract(DateTimeOffset.UtcNow).TotalSeconds ?? 0
        };
    }

    private byte[] ConvertToBase64Json(object value)
    {
        var json = JsonConvert.SerializeObject(value, _jsonSerializerSettings);
        var jsonBytes = Encoding.UTF8.GetBytes(json);
        
        return Base64Convert.Encode(jsonBytes, true);
    }
}