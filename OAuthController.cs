using Autodesk.Forge;
using System;
using System.Threading.Task;
using System.Web.Configuration;
using System.Web.Http;

namespace forgesample.Controllers 
{
    public class OAuthController : ApiController
    {
        private static dynamic InternalToken { get; set; }
        private static dynamic PublicToken { get; set; }

        [HttpGet]
        [Route("api/forge/oauth/token")]
        public async Task<dynamic> getPublicAsync()
        {
            if (PublicToken == null || PublicToken.ExpiresAt < DateTime.UtcNow)
            {
                PublicToken = await Get2LeggedTokenAsync(new Scope[] { Scope.ViewablesRead});
                PublicToken.ExpiresAt = DateTime.UtcNow.AddSeconds(PublicToken.expires_in);
            }
            return PublicToken;
        }

        public static async Task<dynamic> GetInternalAsync()
        {
            if (InternalToken == null || InternalToken.ExpiresAt < DateTime.UtcNow)
            {
                InternalToken = await Get2LeggedTokenAsync(new Scope[] { Scope.BucketCreate, Scope.BucketCreate, Scope.DataRead, Scope.DataCreate});
                InternalToken.ExpiresAt = DateTime.UtcNow.AddSeconds(InternalToken.expires_in);
            }

            return InternalToken;
        }

        private static async Task<dynamic> Get2LeggedTokenAsync(Scope[] scopes)
        {
            TwoLeggedApi oauth = new TwoLeggedApi();
            string grantType = "client_credentials";
            dynamic bearer = await oauth.AuthenticateAsync(
                GetAppSetting("FORGE_CLIENT_ID"),
                GetAppSetting("FORGE_CLIENT_SECRET"),
                grantType,
                scopes);
            return bearer;
        }

        public static string GetAppSetting(string settingKey)
        {
            return WebConfigurationManager.AppSettings[settingKey];
        }
    }
}