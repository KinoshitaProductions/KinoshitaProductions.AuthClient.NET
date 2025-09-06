#if WINDOWS_UWP
using Windows.Web.Http;
#else
using System.Net;
#endif
using KinoshitaProductions.Common.Interfaces.AppInfo;
using KinoshitaProductions.Common.Services;
using KinoshitaProductions.Common.Enums;
using Newtonsoft.Json;
using Serilog;

// ReSharper disable MemberCanBePrivate.Global
// ReSharper disable UnusedMember.Global

namespace KinoshitaProductions.AuthClient.Services
{
    // ReSharper disable once ClassNeverInstantiated.Global
    public sealed class AuthManager
    {
        private static readonly JwtTokenKind[] AllTokenKinds = { JwtTokenKind.Elevated, JwtTokenKind.App, JwtTokenKind.Session };
        //private JwtTokenKind forcingTokensRenewal;
        public void FlagForRenewal(JwtTokenKind tokenKinds)
        {
            if (tokenKinds.HasFlag(JwtTokenKind.Elevated))
                throw new ArgumentException("renewing an elevated token is disallowed for security reasons");
            foreach (var tokenKind in AllTokenKinds)
                _credentialStore.GetToken(tokenKind)?.FlagForRenewal(tokenKinds.HasFlag(tokenKind));
        }
        public bool HasPendingToPersistTokens { get; private set; }
        public bool HasElevatedPermissions => _credentialStore.HasToken(JwtTokenKind.Elevated);
        private readonly JwtCredentialsStore _credentialStore = new ();
        private readonly IJwtAuthenticatedServiceAppInfo _appInfo;

        public event Func<Task>? LoggedIn;
        public event Func<Task>? RestoredSession;
        public event Func<Task>? LoggedOut;

        public AuthManager(IJwtAuthenticatedServiceAppInfo appInfo)
        {
            _appInfo = appInfo;
            _credentialStore.LinkToAppInfo(_appInfo);
        }
        public bool ScheduledToPersistAnyChanges() => HasPendingToPersistTokens;
        public async Task PersistChangesAsync()
        {
            HasPendingToPersistTokens |=
                !await SettingsManager.TrySavingJson(_credentialStore.WithoutElevatedTokenForStoring(), "___adt",
                    CompressionAlgorithm.GZip);
        }
        //private Token? GetMainToken() => new [] { _credentialStore.GetToken(JwtTokenKind.App), _credentialStore.GetToken(JwtTokenKind.Elevated) }.FirstOrDefault(x => x?.IsValid == true);
        public bool ScheduledToRenewAnyToken() => _credentialStore.GetToken(JwtTokenKind.App)?.NeedsRenewal == true ||
                                             _credentialStore.GetToken(JwtTokenKind.Session)?.NeedsRenewal == true;
        public async Task<AuthOperationResult> RenewTokensAsync(bool permissionsChanged = false)
        {
            var renewalToken = GetRenewalToken();
            var sessionToken = _credentialStore.GetToken(JwtTokenKind.Session);
            if (renewalToken == null && sessionToken?.IsValid != true) return AuthOperationResult.Unauthorized; // no valid tokens available
            if (renewalToken == null) return AuthOperationResult.NoOp; // without a renewalToken, the only option is for the session token to expire
            if (renewalToken.NeedsRenewal || permissionsChanged)
                return await RenewTokenAsync(renewalToken, renewalToken.Kind, permissionsChanged);
            if (sessionToken == null || sessionToken.NeedsRenewal)
                return await RenewTokenAsync(renewalToken, JwtTokenKind.Session);
            return AuthOperationResult.NoOp;
        }

        private Token? GetRenewalToken()
        {
            var token = _credentialStore.GetToken(JwtTokenKind.App);
            if (token?.IsValid == true) return token;
            token = _credentialStore.GetToken(JwtTokenKind.Elevated);
            return token?.IsValid == true ? token : null;
        }
        
        /// <summary>
        /// On app initialization, this should be called to load the credentials if possible.
        /// </summary>
        /// <returns></returns>
        public async Task<bool> LoadCredentialsAsync()
        {
            var filePresence = await SettingsManager.ExistsAsync("___adt").ConfigureAwait(false);
            if (filePresence == FilePresence.NotFound) return false;
            var storedCredentials = await SettingsManager.TryLoadingJson<JwtTokenResponse>("___adt", filePresence, CompressionAlgorithm.GZip).ConfigureAwait(false);
            try
            {
                if (storedCredentials == null) return false; // couldn't parse
                _credentialStore.MergeTokensFrom(storedCredentials.Sanitize());
                return true;
            }
            finally
            {
                if (RestoredSession != null)
                    await RestoredSession.Invoke().ConfigureAwait(false);
            }
        }
        private async Task MergeAndSaveCredentialsAsync(JwtTokenResponse response)
        {
            _credentialStore.MergeTokensFrom(response.Sanitize());
            HasPendingToPersistTokens |=
                !await SettingsManager.TrySavingJson(_credentialStore.WithoutElevatedTokenForStoring(), "___adt",
                    CompressionAlgorithm.GZip);
        }
        public async Task<AuthRequestCreated?> CreateAuthRequestAsync(string appName)
        {
            using var request = _appInfo.PostHttpRequestTo(new Uri($"{_appInfo.ApiUrl}/auth/request/create"),
                       new AuthRequestCreation(appName: appName));
            var response = await Web.ResolveRequestAsRestResponse<AuthRequestCreated>(_appInfo.HttpClient, request)
                    .ConfigureAwait(false);
            return response.Status switch
            {
#if WINDOWS_UWP
                HttpStatusCode.Ok => response.Result,
#else
                HttpStatusCode.OK => response.Result,
#endif
                _ => null,
            };
        }

        public async Task<AuthRequestChecked?> CheckAuthRequestAsync(AuthRequestCreated created)
        {
            using var request = _appInfo.PostHttpRequestTo(new Uri($"{_appInfo.ApiUrl}/auth/request/check"),
                       new AuthRequestCheck(requestId: created.RequestId, checkKey: created.CheckKey));
            var response = await Web.ResolveRequestAsRestResponse<AuthRequestChecked>(_appInfo.HttpClient, request)
                    .ConfigureAwait(false);
            return response.Status switch
            {
#if WINDOWS_UWP
                HttpStatusCode.Ok => response.Result,
#else
                HttpStatusCode.OK => response.Result,
#endif
                _ => null,
            };
        }

        public async Task<AuthOperationResult> CompleteAuthRequestAsync(AuthRequestCreated created)
        {
            using var request = _appInfo.PostHttpRequestTo(new Uri($"{_appInfo.ApiUrl}/auth/request/complete"),
                new AuthRequestCompletion(requestId: created.RequestId, requestKey: created.RequestKey));
            var response = await Web.ResolveRequestAsRestResponse<AuthRequestCompleted>(_appInfo.HttpClient, request)
                .ConfigureAwait(false);
#if WINDOWS_UWP
            if (response is not { Status: HttpStatusCode.Ok, Result: not null })
#else
            if (response is not { Status: HttpStatusCode.OK, Result: not null })
#endif
                return response.Status == HttpStatusCode.Conflict ? AuthOperationResult.Unauthorized : AuthOperationResult.ErrorCannotDetermine;
            var authResponse = JsonConvert.DeserializeObject<JwtTokenResponse>(response.Result.Token);
            if (authResponse == null) return AuthOperationResult.ErrorCannotDetermine;
            await MergeAndSaveCredentialsAsync(authResponse);
            if (LoggedIn != null)
                await LoggedIn.Invoke().ConfigureAwait(false);
            return AuthOperationResult.Success;
        }

        public async Task<AuthOperationResult> LogInWithDeviceAsync(long deviceId)
        {
            if (_appInfo.AuthenticationTypeSet == AuthenticationType.None)
                return AuthOperationResult.Unauthorized; // not logged in
            try
            {
                var deviceInfo = new DeviceTokenRequest(deviceId: deviceId);
                using var request =
                    _appInfo.PostAuthenticatedHttpRequestTo(new Uri($"{_appInfo.ApiUrl}/auth/device-token"), deviceInfo,
                        JwtTokenKind.App);
                var response = await Web.ResolveRequestAsRestResponse<JwtTokenResponse>(_appInfo.HttpClient, request)
                    .ConfigureAwait(false);
#if WINDOWS_UWP
                if (response is { Status: HttpStatusCode.Ok, Result: not null })
#else
                if (response is not { Status: HttpStatusCode.OK, Result: not null }) 
#endif
                    return AuthOperationResult.Unauthorized;
                if (response.Result == null) return AuthOperationResult.ErrorCannotDetermine;
                await MergeAndSaveCredentialsAsync(response.Result).ConfigureAwait(false);
                return AuthOperationResult.Success;
            }
            catch (Exception ex)
            {
                Log.Debug(ex, "Failed to log in with device");
                return AuthOperationResult.ErrorCannotDetermine;
            }
        }
        private async Task<AuthOperationResult> RenewTokenAsync(Token renewalToken, JwtTokenKind tokenKindToRenew, bool permissionsChanged = false)
        {
            using var request = _appInfo.GetAuthenticatedHttpRequestTo(new Uri($"{_appInfo.ApiUrl}{(permissionsChanged ? "/auth/permissions-changed-renew-token" : tokenKindToRenew == JwtTokenKind.Session ? "/auth/new-session-token" : "/auth/renew-token")}"), renewalToken.Kind);
            var response = await Web.ResolveRequestAsRestResponse<JwtTokenResponse>(_appInfo.HttpClient, request).ConfigureAwait(false);
#if WINDOWS_UWP
            if (response is { Status: HttpStatusCode.Ok, Result: not null })
#else
            if (response is { Status: HttpStatusCode.OK, Result: not null })
#endif
            {
                // TODO: didn't check if could read before merge?
                await MergeAndSaveCredentialsAsync(response.Result).ConfigureAwait(false);
                return AuthOperationResult.Success;
            }

            return response.Status switch
            {
                HttpStatusCode.Unauthorized => AuthOperationResult.Unauthorized,
                HttpStatusCode.BadRequest => AuthOperationResult.NoOp,
                _ => AuthOperationResult.ErrorCannotDetermine,
            };
        }
        public async Task<AuthOperationResult> LogOutAsync()
        {
            // TODO: We should set up in the API a relation, so if either the elevated or the app token is sent, both work for logout, and logging out from one, logs out from both
            if (_appInfo.AuthenticationTypeSet == AuthenticationType.None) return AuthOperationResult.Unauthorized; // not logged in
            try
            {
                HttpStatusCode status = 
#if WINDOWS_UWP
                        HttpStatusCode.Ok
#else
                        HttpStatusCode.OK
#endif
                        ;
                foreach (var token in new[]
                         {
                             _credentialStore.GetToken(JwtTokenKind.Elevated),
                             _credentialStore.GetToken(JwtTokenKind.App)
                         }.Where(token => token?.IsValid == true))
                {
                    if (token == null) return AuthOperationResult.Unauthorized;
                    using var request =
                        _appInfo.GetAuthenticatedHttpRequestTo(new Uri($"{_appInfo.ApiUrl}/auth/logout"), token.Kind);
                    var response = await Web.ResolveRequestAsRestResponse(_appInfo.HttpClient, request)
                        .ConfigureAwait(false);
                    if (response.Status > 0 && response.Status != 
#if WINDOWS_UWP
                        HttpStatusCode.Ok
#else
                        HttpStatusCode.OK
#endif
                        ) status = response.Status;
                }

                return status switch
                {
#if WINDOWS_UWP
                    HttpStatusCode.Ok => AuthOperationResult.Success,
#else
                    HttpStatusCode.OK => AuthOperationResult.Success,
#endif
                    HttpStatusCode.Unauthorized => AuthOperationResult.Unauthorized | AuthOperationResult.NoOp,
                    _ => AuthOperationResult.ErrorCannotDetermine,
                };
            }
            finally
            {
                _credentialStore.Clear();
                await _appInfo.ClearAuthenticationCredentials(deletePersistedCredentials: true);
                if (LoggedOut != null)
                    await LoggedOut.Invoke().ConfigureAwait(false);
            }
        }

        public async Task<AuthOperationResult> ValidateTokenAsync(JwtTokenKind kind)
        {
            if (_appInfo.AuthenticationTypeSet == AuthenticationType.None || _credentialStore.GetToken(kind)?.IsValid != true)
                return AuthOperationResult.Unauthorized; // not logged in
            using var request = _appInfo.GetAuthenticatedHttpRequestTo(new Uri($"{_appInfo.ApiUrl}/auth/validate-token"), kind);
            var response = await Web.ResolveRequestAsRestResponse(_appInfo.HttpClient, request).ConfigureAwait(false);
            if (response.Status is HttpStatusCode.Unauthorized) _credentialStore.GetToken(kind)?.FlagForRenewal(true, isInvalid: true);
            return response.Status switch
            {
#if WINDOWS_UWP
                HttpStatusCode.Ok => AuthOperationResult.Success,
#else
                HttpStatusCode.OK => AuthOperationResult.Success,
#endif
                HttpStatusCode.Unauthorized => AuthOperationResult.Unauthorized,
                _ => AuthOperationResult.ErrorCannotDetermine,
            };
        }
    }
}