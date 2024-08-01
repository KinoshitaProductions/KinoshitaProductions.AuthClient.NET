#if WINDOWS_UWP
using Windows.Web.Http;
#else
using System.Net;
using KinoshitaProductions.AuthClient.Enums;
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
        public bool HasPendingToPersistTokens;
        public bool HasElevatedPermissions => _credentialStore.HasToken(JwtTokenKind.Elevated);
        private readonly JwtTokenResponse _credentialStore;
        private readonly IJwtAuthenticatedServiceAppInfo _appInfo;

        public event Func<Task>? LoggedIn;
        public event Func<Task>? RestoredSession;
        public event Func<Task>? LoggedOut;

        public AuthManager(IJwtAuthenticatedServiceAppInfo appInfo)
        {
            _appInfo = appInfo;
            _credentialStore = new JwtTokenResponse(_appInfo);
        }
        public bool ScheduledToPersistAnyChanges() => HasPendingToPersistTokens;
        public async Task PersistChangesAsync()
        {
            HasPendingToPersistTokens |=
                !await SettingsManager.TrySavingJson(_credentialStore.WithoutElevatedToken(), "___adt",
                    CompressionAlgorithm.GZip);
        }
        private Token? GetMainToken() => new [] { _credentialStore.GetToken(JwtTokenKind.App), _credentialStore.GetToken(JwtTokenKind.Elevated) }.FirstOrDefault(x => x?.IsValid == true);
        public bool ScheduledToRenewAnyToken() => GetMainToken()?.ShouldConsiderRenewal == true ||
                                             _credentialStore.GetToken(JwtTokenKind.Session)?.ShouldConsiderRenewal == true;
        public async Task<AuthOperationResult> RenewTokensAsync()
        {
            if (GetMainToken()?.ShouldConsiderRenewal == true)
                return await RenewMainTokenAsync();
            if (_credentialStore.GetToken(JwtTokenKind.Session)?.ShouldConsiderRenewal == true)
                return await GetNewSessionTokenAsync();
            return AuthOperationResult.NoOp;
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
                if (storedCredentials?.CanRead() != true) return false; // couldn't parse
                _credentialStore.MergeTokensFrom(storedCredentials);
                return true;
            }
            finally
            {
                // TODO: Is this really needed? We probably want to wait for it in all cases
                if (RestoredSession != null)
                    await RestoredSession.Invoke().ConfigureAwait(false);
            }
        }
        private async Task MergeAndSaveCredentialsAsync(JwtTokenResponse response)
        {
            _credentialStore.MergeTokensFrom(response);
            HasPendingToPersistTokens |=
                !await SettingsManager.TrySavingJson(_credentialStore.WithoutElevatedToken(), "___adt",
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
            if (authResponse?.CanRead() != true) return AuthOperationResult.Unauthorized;
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
                if (response.Result.CanRead() != true) return AuthOperationResult.ErrorCannotDetermine;
                await MergeAndSaveCredentialsAsync(response.Result).ConfigureAwait(false);
                return AuthOperationResult.Success;
            }
            catch (Exception ex)
            {
                Log.Debug(ex, "Failed to log in with device");
                return AuthOperationResult.ErrorCannotDetermine;
            }
        }
        public async Task<AuthOperationResult> RenewMainTokenAsync(bool permissionsChanged = false)
        {
            var mainToken = GetMainToken();
            if (mainToken == null) return AuthOperationResult.Unauthorized;
            using var request = _appInfo.GetAuthenticatedHttpRequestTo(new Uri(permissionsChanged ? $"{_appInfo.ApiUrl}/auth/permissions-changed-renew-token" : $"{_appInfo.ApiUrl}/auth/renew-token"), mainToken.Kind);
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
        public async Task<AuthOperationResult> GetNewSessionTokenAsync()
        {
            var mainToken = GetMainToken();
            if (mainToken == null) return AuthOperationResult.Unauthorized;
            using var request = _appInfo.GetAuthenticatedHttpRequestTo(new Uri($"{_appInfo.ApiUrl}/auth/new-session-token"), mainToken.Kind);
            var response = await Web.ResolveRequestAsRestResponse<JwtTokenResponse>(_appInfo.HttpClient, request)
                .ConfigureAwait(false);
#if WINDOWS_UWP
            if (response is { Status: HttpStatusCode.Ok, Result: not null })
#else
            if (response is { Status: HttpStatusCode.OK, Result: not null })
#endif
            {
                // TODO: Didn't try parse?
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
            var mainToken = GetMainToken();
            if (mainToken == null) return AuthOperationResult.Unauthorized;
            using var request = _appInfo.GetAuthenticatedHttpRequestTo(new Uri($"{_appInfo.ApiUrl}/auth/logout"));
            var response = await Web.ResolveRequestAsRestResponse(_appInfo.HttpClient, request)
                .ConfigureAwait(false);
            await _appInfo.ClearAuthenticationCredentials(deletePersistedCredentials: true);
            if (LoggedOut != null)
                await LoggedOut.Invoke().ConfigureAwait(false);
            return response.Status switch
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

        public async Task<AuthOperationResult> ValidateTokenAsync(JwtTokenKind kind)
        {
            if (_appInfo.AuthenticationTypeSet == AuthenticationType.None)
                return AuthOperationResult.Unauthorized; // not logged in
            using var request = _appInfo.GetAuthenticatedHttpRequestTo(new Uri($"{_appInfo.ApiUrl}/auth/validate-token"), kind);
            var response = await Web.ResolveRequestAsRestResponse(_appInfo.HttpClient, request).ConfigureAwait(false);
            if (response.Status is HttpStatusCode.Unauthorized) _credentialStore.GetToken(kind)?.FlagForRenewal();
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