using Amazon;
using Amazon.Lambda.APIGatewayEvents;
using Amazon.Lambda.Core;
using Amazon.Runtime.Internal.Endpoints.StandardLibrary;
using Amazon.Runtime.Internal.Transform;
using Amazon.SecretsManager;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text.Json;

[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.SystemTextJson.DefaultLambdaJsonSerializer))]


namespace LambdaAuthorizers
{

    public class Authorizer
    {
        public async Task<APIGatewayCustomAuthorizerResponse> Auth(APIGatewayCustomAuthorizerRequest request)
        {

            var idToken = request.QueryStringParameters?["token"];
            Console.WriteLine($"Token is {idToken}");
            var idTokenDetails = new JwtSecurityToken(idToken);

            var signingKey = idTokenDetails.Header["kid"].ToString();

            var issuer = idTokenDetails.Claims.First(x => x.Type == "iss").Value;
            var audience = idTokenDetails.Claims.First(x => x.Type == "aud").Value;
            var userId = idTokenDetails.Claims.First(x => x.Type == "sub").Value;

            var response = new APIGatewayCustomAuthorizerResponse()
            {
                PrincipalID = userId,
                PolicyDocument = new APIGatewayCustomAuthorizerPolicy()
                {
                    Version = "2012-10-17",
                    Statement = new List<APIGatewayCustomAuthorizerPolicy.IAMPolicyStatement>()
                    {
                      new APIGatewayCustomAuthorizerPolicy.IAMPolicyStatement()
                      {
                          Action = new HashSet<string>(){"execute-api:Invoke"},
                          Effect = "Allow",
                          Resource = new HashSet<string>(){request.MethodArn}
                      }
                    }
                }
            };

            var secretsClient = new AmazonSecretsManagerClient(RegionEndpoint.GetBySystemName("ap-south-1"));
            //Calling secret manager
            var secret = await secretsClient.GetSecretValueAsync(new Amazon.SecretsManager.Model.GetSecretValueRequest
            {
                SecretId = "hotelCognitoKey"
            });
            var publicKeys = secret.SecretString; // data keys from secret manager

            Console.WriteLine($"JWKS set: {publicKeys}");
            var jwks = new JsonWebKeySet(publicKeys);

            var publicKey = jwks.Keys.First(x => x.Kid == signingKey);
            var handler = new JwtSecurityTokenHandler();
            var results = await handler.ValidateTokenAsync(idToken, new TokenValidationParameters()
            {
                ValidIssuer = issuer,
                ValidAudience = audience,
                IssuerSigningKey = publicKey,
                ValidateLifetime = true,

            });
            if (!results.IsValid)
            {
                throw new UnauthorizedAccessException("Token not valid");
            }
            var apiGroupMapping = new Dictionary<string, string>
            {
                {"listadminhotels", "Admin"},
                {"admin", "Admin" }
            };
            var expectedGroup = apiGroupMapping.Where(x => request.Path.Contains(x.Key, StringComparison.InvariantCultureIgnoreCase));
            if (expectedGroup.Any())
            {
                var userGroup = idTokenDetails.Claims.First(x => x.Type == "cognito:groups").Value;
                if (!string.Equals(userGroup, expectedGroup.FirstOrDefault().Value, StringComparison.InvariantCultureIgnoreCase))
                {
                    //UNAUTHORIZED
                    response.PolicyDocument.Statement[0].Effect = "Deny";
                }
            }

            return response;
        }
    }
}
