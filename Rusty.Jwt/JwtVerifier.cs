using System.Text;
using Base64Extensions;
using Newtonsoft.Json;
using Rusty.Jwt.Keys;

namespace Rusty.Jwt;

public class JwtVerifier : IJwtVerifier
{
    private readonly IKeyRing _keyRing;

    public JwtVerifier(IKeyRing keyRing)
    {
        _keyRing = keyRing;
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
            throw new InvalidTokenException("token is invalid");
        }
        
        return Deserialize<Claims>(parts[1]);
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