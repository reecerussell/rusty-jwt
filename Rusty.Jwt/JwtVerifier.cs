using System.Text;
using Base64Extensions;
using Newtonsoft.Json;
using Rusty.Jwt.Caching;
using Rusty.Jwt.Keys;

namespace Rusty.Jwt;

public class JwtVerifier : IJwtVerifier
{
    /// <summary>
    /// The default cache timing in minutes.
    /// </summary>
    public const int DefaultCacheMinutes = 5;
    
    private readonly IKeyRing _keyRing;
    private readonly ITokenCache _tokenCache;
    private readonly ISystemClock _systemClock;

    public JwtVerifier(IKeyRing keyRing,
        ITokenCache tokenCache,
        ISystemClock systemClock)
    {
        _keyRing = keyRing;
        _tokenCache = tokenCache;
        _systemClock = systemClock;
    }
    
    public async Task<Claims> VerifyAsync(string token, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            throw new InvalidTokenException("token is empty");
        }

        var parts = token.Split('.');
        if (parts.Length != 3)
        {
            throw new InvalidTokenException("invalid token structure");
        }

        var header = Deserialize<Header>(parts[0]);
        var (algorithm, hashAlgorithm) = ReadTokenAlgorithm(header.Algorithm!);
        
        var cacheResult = await _tokenCache.GetAsync(token, cancellationToken);
        if (cacheResult is { } result)
        {
            if (!result.Valid)
            {
                throw new InvalidTokenException("token is invalid");
            }
            
            return Deserialize<Claims>(parts[1]);
        }
        
        IVerificationKey key;
        if (header.KeyId != null)
        {
            var verificationKey = _keyRing.GetVerificationKey(header.KeyId!);
            key = verificationKey ?? _keyRing.GetVerificationKey(algorithm, hashAlgorithm);
        }
        else
        {
            key = _keyRing.GetVerificationKey(algorithm, hashAlgorithm);
        }

        var data = Encoding.UTF8.GetBytes(parts[0] + "." + parts[1]);
        var signature = Base64Convert.Decode(Encoding.UTF8.GetBytes(parts[2]));
        var valid = await key.VerifyAsync(data, signature, cancellationToken);
        if (!valid)
        {
            await CacheInvalidTokenAsync(token, cancellationToken);
            
            throw new InvalidTokenException("token is invalid");
        }

        try
        {
            var claims = Deserialize<Claims>(parts[1]);
            await CacheValidTokenAsync(token, claims, cancellationToken);

            return claims;
        }
        catch (InvalidTokenException)
        {
            await CacheInvalidTokenAsync(token, cancellationToken);

            throw;
        }
    }

    private Task CacheValidTokenAsync(string token, Claims claims, CancellationToken cancellationToken)
    {
        var expiry = claims.Expiry ?? _systemClock.Now.AddMinutes(DefaultCacheMinutes);
        
        return _tokenCache.SetAsync(token, new TokenCacheValue
        {
            Valid = true,
            Expiry = expiry.DateTime
        }, cancellationToken);
    }

    private Task CacheInvalidTokenAsync(string token, CancellationToken cancellationToken)
    {
        return _tokenCache.SetAsync(token, new TokenCacheValue
        {
            Valid = false,
            Expiry = _systemClock.Now.AddMinutes(DefaultCacheMinutes)
        }, cancellationToken);
    }

    private static T Deserialize<T>(string base64Json)
    {
        try
        {
            var json = Base64Convert.Decode(base64Json)!;
            var value = JsonConvert.DeserializeObject<T>(json);
            if (value == null)
            {
                throw new InvalidTokenException("invalid token structure");
            }

            return value;
        }
        catch (Exception)
        {
            throw new InvalidTokenException("invalid token structure");
        }
    }

    private (SigningKeyAlgorithm algorithm, HashAlgorithm hashAlgorithm) ReadTokenAlgorithm(string alg)
    {
        var algorithm = alg[0] switch
        {
            'H' => SigningKeyAlgorithm.Hmac,
            'E' => SigningKeyAlgorithm.EllipticCurve,
            'R' => SigningKeyAlgorithm.Rsa,
            _ => throw new InvalidTokenException("unsupported algorithm")
        };

        var hashAlgorithm = alg[1..] switch
        {
            "S256" => HashAlgorithm.SHA256,
            "S384" => HashAlgorithm.SHA384,
            "S512" => HashAlgorithm.SHA512,
            _ => throw new InvalidTokenException("unsupported hash algorithm")
        };

        return (algorithm, hashAlgorithm);
    }
}