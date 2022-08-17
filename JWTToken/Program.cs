using JWT;
using JWT.Algorithms;
using JWT.Builder;
using JWT.Exceptions;
using JWT.Serializers;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace JWTToken
{
    class Program
    {
        private static RSA certificate;

        static void Main(string[] args)
        {
            const string secret = "yourSecret";

            var token = JwtBuilder.Create()
                .WithAlgorithm(new HMACSHA256Algorithm())
                .WithSecret(secret)
                .AddClaim("exp", DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds())
                .AddClaim("Primeiro", 1)
                .AddClaim("Segundo", "Mxtheuz")
                .Encode();

            Console.WriteLine(token);

            try
            {
                IJsonSerializer serializer = new JsonNetSerializer();
                IDateTimeProvider provider = new UtcDateTimeProvider();
                IJwtValidator validator = new JwtValidator(serializer, provider);
                IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
                IJwtAlgorithm algorithm = new HMACSHA256Algorithm();
                IJwtDecoder decoder = new JwtDecoder(serializer, validator, urlEncoder, algorithm);

                var payload = decoder.DecodeToObject<IDictionary<string, object>>(token);
                Console.WriteLine(payload["Segundo"]);
            }
            catch (TokenNotYetValidException)
            {
                Console.WriteLine("Token is not valid yet");
            }
            catch (TokenExpiredException)
            {
                Console.WriteLine("Token has expired");
            }
            catch (SignatureVerificationException)
            {
                Console.WriteLine("Token has invalid signature");
            }
        }
    }
}
