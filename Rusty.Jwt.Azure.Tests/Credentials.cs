using Azure.Core;
using Azure.Identity;

namespace Rusty.Jwt.Azure.Tests;

public static class Credentials
{
    public static TokenCredential Default
    {
        get
        {
            // Set this to false to test with explicit credentials.
            if (true)
            {
                return new DefaultAzureCredential();
            }

            return new ClientSecretCredential(
                "<tenant id>",
                "<client id>",
                "<client secret>");
        }
    }
}