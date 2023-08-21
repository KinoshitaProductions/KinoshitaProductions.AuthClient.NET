#if WINDOWS_UWP
using Windows.Web.Http;
#else
using System.Net;
#endif
using KinoshitaProductions.Common.Interfaces.AppInfo;
using KinoshitaProductions.Common.Services;
using KinoshitaProductions.Common.Enums;
using Newtonsoft.Json;
// ReSharper disable MemberCanBePrivate.Global
// ReSharper disable UnusedMember.Global

namespace KinoshitaProductions.AuthClient.Services
{
    // ReSharper disable once ClassNeverInstantiated.Global
    public sealed class AuthManager
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        public bool HasElevatedPermissions => _credentials?.ElevatedToken != null;
        private JwtTokenResponse? _credentials;
        private readonly bool _isTemporaryOnly;
        private readonly IJwtAuthenticatedServiceAppInfo _appInfo;

        public event Func<Task>? LoggedIn;
        public event Func<Task>? RestoredSession;
        public event Func<Task>? LoggedOut;

        public AuthManager(IJwtAuthenticatedServiceAppInfo appInfo, bool isTemporaryOnly = false)
        {
            _appInfo = appInfo;
            _isTemporaryOnly = isTemporaryOnly;
        }

        private async Task<bool> IsValidOrCanRenewAppToken()
        {
            if (_credentials == null) return false;
            // we can start trying to renew the app token after 37 days
            if (_credentials.AppTokenExpirationDate != null && DateTime.Now + TimeSpan.FromDays(37) > _credentials.AppTokenExpirationDate)
            {
                // we apply our tokens here for this operation
                _appInfo.SetJwtAuthenticationCredentials(null, _credentials.AppToken, null /* we'll get a new session token for it */);

                // we can only renew if there is an AppToken
                if (await RenewCredentials(JwtTokenKind.App) == false)
                {
                    return false; // it's expired
                }
            }
            return true;
        }

        private async Task<bool> IsValidOrCanRenewSessionToken()
        {
            if (_credentials == null) return false;
            // we can start trying to renew the session token after 3 days
            if (_credentials.AppTokenExpirationDate != null && DateTime.Now + TimeSpan.FromDays(4) > _credentials.SessionTokenExpirationDate)
            {
                // we apply our tokens here for this operation
                _appInfo.SetJwtAuthenticationCredentials(null, _credentials.AppToken, null /* this will cause the session to be considered expired, but we are asking for a new token anyways! */);

                // let's try asking for a new token
                if (await GetNewSessionToken() != true)
                {
                    // we apply our tokens here for this operation
                    _appInfo.SetJwtAuthenticationCredentials(null, _credentials.AppToken, _credentials.SessionToken /* now we will try checking for the session validity*/);

                    // we can only renew if there is an AppToken
                    // should optimize this? We possibly actually call 3 times GetNewSessionToken() here
                    if (await ValidateOrRenewSession() == false)
                    {
                        return false; // it's expired
                    }
                }
            }
            return true;
        }
        
        /// <summary>
        /// On app initialization, this should be called to load the credentials if possible.
        /// </summary>
        /// <returns></returns>
        public async Task<bool> LoadCredentials()
        {
            var filePresence = _isTemporaryOnly /* for elevated login, do not load or save */ ? FilePresence.NotFound : await SettingsManager.ExistsAsync("___adt").ConfigureAwait(false);

            if (filePresence == FilePresence.NotFound)
                return false;

            _credentials = await SettingsManager.TryLoadingJson<JwtTokenResponse>("___adt", filePresence, CompressionAlgorithm.GZip).ConfigureAwait(false);
            
            if (_credentials == null) return false; // couldn't parse
            // if we are at 1 day before expiration or less, we can read it
            if (DateTime.Now + TimeSpan.FromDays(1) < _credentials.AppTokenExpirationDate || DateTime.Now < _credentials.SessionTokenExpirationDate)
            {
                if (!await IsValidOrCanRenewAppToken()) return false;
                
                if (!await IsValidOrCanRenewSessionToken()) return false;
               
                _appInfo.SetJwtAuthenticationCredentials(null, _credentials.AppToken, DateTime.Now < _credentials.SessionTokenExpirationDate ? _credentials.SessionToken : null);
                if (RestoredSession != null)
                    await RestoredSession.Invoke().ConfigureAwait(false);
                return true;
            }
            // else, it's expired, need new credentials
            else
            {
                return false;
            }
        }
        private Task SaveAndSetCredentials(JwtTokenResponse response)
        {
            _credentials = response;

            _appInfo.SetJwtAuthenticationCredentials(_credentials.ElevatedToken, _credentials.AppToken, _credentials.SessionToken);

            if (_isTemporaryOnly /* for elevated login, do not load or save */)
                return Task.CompletedTask;

            return SettingsManager.TrySavingJson(response.WithoutElevatedToken(), "___adt", CompressionAlgorithm.GZip);
        }
        private async Task MergeAndSetCredentials(JwtTokenResponse response)
        {
            _credentials ??= new JwtTokenResponse();
            _credentials.ElevatedToken = response.ElevatedToken ?? _credentials.ElevatedToken;
            _credentials.ElevatedTokenExpirationDate = response.ElevatedTokenExpirationDate ?? _credentials.ElevatedTokenExpirationDate;
            // ReSharper disable once NullCoalescingConditionIsAlwaysNotNullAccordingToAPIContract
            _credentials.AppToken = response.AppToken ?? _credentials.AppToken;
            _credentials.AppTokenExpirationDate = response.AppTokenExpirationDate ?? _credentials.AppTokenExpirationDate;
            _credentials.SessionToken = response.SessionToken ?? _credentials.SessionToken;
            _credentials.SessionTokenExpirationDate = response.SessionTokenExpirationDate ?? _credentials.SessionTokenExpirationDate;

            _appInfo.SetJwtAuthenticationCredentials(_credentials.ElevatedToken, _credentials.AppToken, _credentials.SessionToken);

            if (_isTemporaryOnly /* for elevated login, do not load or save */)
                return;

            // if the user didn't set "RememberMe", it would force him to remember him
            // check if the token had been saved, if not, don't save it here either
            if (await SettingsManager.ExistsAsync("___adt") != FilePresence.Found)
                return;

            await SettingsManager.TrySavingJson(response.WithoutElevatedToken(), "___adt", CompressionAlgorithm.GZip);
        }
        public async Task<AuthRequestCreated?> CreateAuthRequest(string appName)
        {
            using var request = _appInfo.PostHttpRequestTo(new Uri($"{_appInfo.ApiUrl}/auth/request/create"),
                       new AuthRequestCreation(appName: appName));
            var response = await Web.ResolveRequestAsRestResponse<AuthRequestCreated>(_appInfo.HttpClient, request)
                    .ConfigureAwait(false);
            switch (response.Status)
            {
#if WINDOWS_UWP
                case HttpStatusCode.Ok:
#else
                case HttpStatusCode.OK:
#endif
                    return response.Result;
                default:
                    return null;
            }
            
        }

        public async Task<AuthRequestChecked?> CheckAuthRequest(AuthRequestCreated created)
        {
            using var request = _appInfo.PostHttpRequestTo(new Uri($"{_appInfo.ApiUrl}/auth/request/check"),
                       new AuthRequestCheck(requestId: created.RequestId, checkKey: created.CheckKey));
            var response = await Web.ResolveRequestAsRestResponse<AuthRequestChecked>(_appInfo.HttpClient, request)
                    .ConfigureAwait(false);
            switch (response.Status)
                {
#if WINDOWS_UWP
                    case HttpStatusCode.Ok:
#else
                    case HttpStatusCode.OK:
#endif
                        return response.Result;
                    default:
                        return null;
                }
            
        }

        public async Task<bool?> CompleteAuthRequest(AuthRequestCreated created)
        {
            using var request = _appInfo.PostHttpRequestTo(new Uri($"{_appInfo.ApiUrl}/auth/request/complete"),
                new AuthRequestCompletion(requestId: created.RequestId, requestKey: created.RequestKey));
            var response = await Web.ResolveRequestAsRestResponse<AuthRequestCompleted>(_appInfo.HttpClient, request)
                .ConfigureAwait(false);
#if WINDOWS_UWP
            if (response is { Status: HttpStatusCode.Ok, Result: { } })
#else
            if (response is { Status: HttpStatusCode.OK, Result: { } })
#endif
            {
                var authResponse = JsonConvert.DeserializeObject<JwtTokenResponse>(response.Result.Token);
                if (authResponse == null) return false;
                _appInfo.SetJwtAuthenticationCredentials(authResponse.ElevatedToken, authResponse.AppToken,
                    authResponse.SessionToken);
                _credentials = authResponse;
                await SaveAndSetCredentials(response: authResponse).ConfigureAwait(false);
                if (LoggedIn != null)
                    await LoggedIn.Invoke().ConfigureAwait(false);
                return true;
            }
            if (response.Status is HttpStatusCode.Conflict)
            {
                return false;
            }

            return null;
        }

        public async Task<bool> TryLoggingInWithDeviceAsync(long deviceId)
        {
            if (_appInfo.AuthenticationTypeSet == AuthenticationType.None)
                return false; // not logged in

            var deviceInfo = new DeviceTokenRequest(deviceId: deviceId);

            using var request =
                   _appInfo.PostAuthenticatedHttpRequestTo(new Uri($"{_appInfo.ApiUrl}/auth/device-token"), deviceInfo,
                       JwtTokenKind.App);
                var response = await Web.ResolveRequestAsRestResponse<JwtTokenResponse>(_appInfo.HttpClient, request)
                    .ConfigureAwait(false);
#if WINDOWS_UWP
                if (response is { Status: HttpStatusCode.Ok, Result: { } })
#else
                if (response is { Status: HttpStatusCode.OK, Result: { } })
#endif
                {
                    await MergeAndSetCredentials(response.Result).ConfigureAwait(false);
                    return true;
                }
                else
                {
                    return false;
                }
        }
        public async Task<bool?> RenewCredentials(JwtTokenKind jwtTokenKind)
        {
            using var request = _appInfo.GetAuthenticatedHttpRequestTo(new Uri($"{_appInfo.ApiUrl}/auth/renew-token"), jwtTokenKind);

            var response = await Web.ResolveRequestAsRestResponse<JwtTokenResponse>(_appInfo.HttpClient, request)
                .ConfigureAwait(false);
            
#if WINDOWS_UWP
            if (response is { Status: HttpStatusCode.Ok, Result: { } })
#else
            if (response is { Status: HttpStatusCode.OK, Result: { } })
#endif
            {
                await MergeAndSetCredentials(response.Result).ConfigureAwait(false);
                return true;
            }
            if (response.Status is HttpStatusCode.Unauthorized or HttpStatusCode.BadRequest)
            {
                return false;
            }
            return null;
        }
        public async Task<bool?> GetNewSessionToken()
        {
            if (_credentials == null) return false;
            using var request = _appInfo.GetAuthenticatedHttpRequestTo(
                new Uri($"{_appInfo.ApiUrl}/auth/new-session-token"),
                // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
                _credentials.AppToken != null ? JwtTokenKind.App : JwtTokenKind.Elevated);
      
            var response = await Web.ResolveRequestAsRestResponse<JwtTokenResponse>(_appInfo.HttpClient, request)
                .ConfigureAwait(false);

            if (response.Status is HttpStatusCode.Unauthorized or HttpStatusCode.BadRequest)
            {
                return false;
            }
#if WINDOWS_UWP
            if (response is { Status: HttpStatusCode.Ok, Result: { } })
#else
            if (response is { Status: HttpStatusCode.OK, Result: { } })
#endif
            {
                await MergeAndSetCredentials(response.Result).ConfigureAwait(false);
                return true;
            }
            return null; // need to retry, but we can trust cache, possibly we need to add a check to see if cache is expired?
        }
        public async Task<bool?> PermissionsChangedRenewCredentials(JwtTokenKind jwtTokenKind)
        {
            using var request =
                _appInfo.GetAuthenticatedHttpRequestTo(
                    new Uri($"{_appInfo.ApiUrl}/auth/permissions-changed-renew-token"), jwtTokenKind);
            var response = await Web.ResolveRequestAsRestResponse<JwtTokenResponse>(_appInfo.HttpClient, request);

#if WINDOWS_UWP
            if (response is { Status: HttpStatusCode.Ok, Result: { } })
#else
            if (response is { Status: HttpStatusCode.OK, Result: { } })
#endif
            {
                await MergeAndSetCredentials(response.Result).ConfigureAwait(false);
                return true;
            }
            // appToken has newest permissions, while sessionToken has old permissions, request a new session token instead!
            if (response.Status is HttpStatusCode.Unauthorized or HttpStatusCode.BadRequest)
            {
                return await GetNewSessionToken();
            }
            return false;
        }
        public async Task<bool> TryLoggingOut()
        {
            using var request = _appInfo.GetAuthenticatedHttpRequestTo(new Uri($"{_appInfo.ApiUrl}/auth/logout"));
            var response = await Web.ResolveRequestAsRestResponse(_appInfo.HttpClient, request).ConfigureAwait(false);
#if WINDOWS_UWP
            if (response.Status is HttpStatusCode.Ok or HttpStatusCode.Unauthorized)
#else
            if (response.Status is HttpStatusCode.OK or HttpStatusCode.Unauthorized)
#endif
            {
                await _appInfo.ClearAuthenticationCredentials().ConfigureAwait(false);
                _credentials = null; // clear this cache
                if (LoggedOut != null)
                    await LoggedOut.Invoke().ConfigureAwait(false);
                return true;
            }

            return false;
        }
        public async Task<bool?> ValidateOrRenewSession()
        {
            // not logged in
            if (_appInfo.AuthenticationTypeSet == AuthenticationType.None)
                return false;

            if (_appInfo.IsExpiredSession)
            {
                var gotNewSessionToken = await GetNewSessionToken();
                if (gotNewSessionToken == false)
                {
                    await _appInfo.ClearAuthenticationCredentials().ConfigureAwait(false);
                    return false;
                }
                return gotNewSessionToken;
            }

            // check if session is still valid, since if it's not near renewal, it regularly won't revalidate it
            using var request =
                _appInfo.GetAuthenticatedHttpRequestTo(new Uri($"{_appInfo.ApiUrl}/auth/validate-session"));
            var response = await Web.ResolveRequestAsRestResponse(_appInfo.HttpClient, request)
                .ConfigureAwait(false);
            if (response.Status == HttpStatusCode.Unauthorized || response.Status == HttpStatusCode.BadRequest)
            {
                // retry getting a new token
                if (await GetNewSessionToken() ==
                    false) // NOTE: This clears the authentication credentials files TWICE
                {
                    await _appInfo.ClearAuthenticationCredentials().ConfigureAwait(false);
                    return false;
                }
            }
#if WINDOWS_UWP
            else if (response.Status == HttpStatusCode.Ok)
#else
            else if (response.Status == HttpStatusCode.OK)
#endif
            {
                return true;
            }

            return null; // need to retry, but we can trust cache
        }
    }
}