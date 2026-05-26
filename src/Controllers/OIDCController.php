<?php

namespace LittleSkin\YggdrasilConnect\Controllers;

use App\Models\User as BaseUser;
use Carbon\Carbon;
use Defuse\Crypto\Crypto;
use Defuse\Crypto\Exception\CryptoException;
use Illuminate\Contracts\View\View;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Validator;
use Laravel\Passport\AuthCode;
use Laravel\Passport\Client;
use LittleSkin\YggdrasilConnect\Exceptions\OAuth\AccessDeniedException;
use LittleSkin\YggdrasilConnect\Exceptions\OAuth\InvalidRequestException;
use LittleSkin\YggdrasilConnect\Exceptions\OAuth\OAuthException;
use LittleSkin\YggdrasilConnect\Models\Profile;
use LittleSkin\YggdrasilConnect\Models\User;
use LittleSkin\YggdrasilConnect\Models\UUID;
use LittleSkin\YggdrasilConnect\OIDC\OIDCException;
use LittleSkin\YggdrasilConnect\OIDC\OIDCService;
use LittleSkin\YggdrasilConnect\Scope;

class OIDCController extends Controller
{
    private OIDCService $oidc;

    public function __construct(OIDCService $oidc)
    {
        $this->oidc = $oidc;
    }

    public function discovery(): JsonResponse
    {
        return response()->json($this->oidc->getDiscoveryConfig());
    }

    public function jwks(): JsonResponse
    {
        return response()->json($this->oidc->getJWKS());
    }

    public function authorization(Request $request)
    {
        try {
            $authRequest = $this->oidc->validateAuthorizationRequest($request->all());
        } catch (OIDCException $e) {
            if ($e->redirectUri) {
                $separator = in_array('code', $e->responseTypes) ? '?' : '#';
                return redirect()->away($e->redirectUri.$separator.http_build_query($e->toArray()));
            }

            return response()->json($e->toArray(), Response::HTTP_BAD_REQUEST);
        }

        if (Auth::check()) {
            // Reject unverified users
            if (!Auth::user()->verified) {
                $separator = in_array('code', $authRequest['response_types']) ? '?' : '#';
                $errorParams = [
                    'error' => 'access_denied',
                    'error_description' => 'User email is not verified',
                ];
                if ($authRequest['state'] !== null) {
                    $errorParams['state'] = $authRequest['state'];
                }

                return redirect()->away($authRequest['redirect_uri'].$separator.http_build_query($errorParams));
            }

            return $this->handleAuthenticatedUser($authRequest, Auth::user());
        }

        // prompt=none requires an authenticated user
        if (in_array('none', $authRequest['prompt'])) {
            $separator = in_array('code', $authRequest['response_types']) ? '?' : '#';
            $errorParams = [
                'error' => 'login_required',
                'error_description' => 'The user is not authenticated and prompt=none was requested',
            ];
            if ($authRequest['state'] !== null) {
                $errorParams['state'] = $authRequest['state'];
            }

            return redirect()->away($authRequest['redirect_uri'].$separator.http_build_query($errorParams));
        }

        $interactionId = $this->oidc->createInteraction($authRequest);

        return redirect()->to($this->oidc->getIssuer()."/yggc/interaction/$interactionId");
    }

    private function handleAuthenticatedUser(array $authRequest, BaseUser $user)
    {
        $clientId = (string) $authRequest['client']->id;
        $accountId = (string) $user->uid;
        $scopes = $authRequest['scopes'];
        $prompt = $authRequest['prompt'] ?? [];

        $existingGrant = $this->findExistingGrant($clientId, $accountId);

        // prompt=consent forces the consent screen even if a valid grant exists
        // prompt=login forces re-authentication (redirect to login page)
        $forceConsent = in_array('consent', $prompt);
        $forceLogin = in_array('login', $prompt);

        if ($forceLogin) {
            Auth::logout();
            $interactionId = $this->oidc->createInteraction($authRequest);

            return redirect()->to($this->oidc->getIssuer()."/yggc/interaction/$interactionId");
        }

        if ($existingGrant && $this->grantCoversScopes($existingGrant, $scopes) && !$forceConsent) {
            return $this->completeAuthorization($authRequest, $user, $existingGrant['id']);
        }

        return redirect()->to(option('site_url').'/oauth/authorize?'.http_build_query([
            'client_id' => $clientId,
            'response_type' => 'code',
            'scope' => implode(' ', array_unique($scopes)),
            'redirect_uri' => option('site_url').'/yggc/callback',
            'state' => $this->oidc->createInteraction($authRequest),
            'prompt' => 'consent',
        ]));
    }

    private function findExistingGrant(string $clientId, string $accountId): ?array
    {
        $grants = DB::table('yggc_grants')->get();
        foreach ($grants as $grant) {
            $payload = json_decode($grant->payload, true);
            if ($payload['clientId'] === $clientId && $payload['accountId'] === $accountId) {
                $grantExpiresIn = intval(option('ygg_grant_expires_in', 86400));
                $createdAt = Carbon::parse($grant->created_at);
                if ($createdAt->addSeconds($grantExpiresIn)->isPast()) {
                    DB::table('yggc_grants')->where('id', $grant->id)->delete();
                    continue;
                }
                $payload['id'] = $grant->id;
                return $payload;
            }
        }

        return null;
    }

    private function grantCoversScopes(array $grant, array $requestedScopes): bool
    {
        $grantedScopes = $grant['scopes'] ?? [];
        foreach ($requestedScopes as $scope) {
            if (!in_array($scope, $grantedScopes)) {
                return false;
            }
        }

        return true;
    }

    private function completeAuthorization(array $authRequest, BaseUser $user, string $grantId)
    {
        $scopes = $authRequest['scopes'];

        if (in_array(Scope::PROFILE_SELECT, $scopes)) {
            $grant = $this->oidc->findGrant($grantId);
            if (!$grant || empty($grant['selectedProfile'])) {
                $bsUser = User::find($user->uid);
                return view('LittleSkin\YggdrasilConnect::select-profile', [
                    'name' => $this->formatClientName($authRequest['client']),
                    'code_id' => $grantId,
                    'state' => $authRequest['state'] ?? '',
                    'availableProfiles' => Profile::getAvailableProfiles($bsUser),
                ]);
            }
        }

        $code = $this->oidc->createAuthorizationCode(
            (string) $authRequest['client']->id,
            (string) $user->uid,
            $authRequest['redirect_uri'],
            $scopes,
            $authRequest['nonce'],
            $authRequest['code_challenge'],
            $authRequest['code_challenge_method'],
            $grantId
        );

        $redirectUri = $authRequest['redirect_uri'];
        $separator = in_array('code', $authRequest['response_types']) ? '?' : '#';
        $params = ['code' => $code];
        if ($authRequest['state'] !== null) {
            $params['state'] = $authRequest['state'];
        }

        return redirect()->away($redirectUri.$separator.http_build_query($params));
    }

    public function token(Request $request): JsonResponse
    {
        try {
            $result = $this->oidc->validateTokenRequest($request->all());
        } catch (OIDCException $e) {
            $statusCode = match ($e->error) {
                'invalid_client' => Response::HTTP_UNAUTHORIZED,
                'authorization_pending' => Response::HTTP_BAD_REQUEST,
                'slow_down' => Response::HTTP_BAD_REQUEST,
                'expired_token' => Response::HTTP_BAD_REQUEST,
                'access_denied' => Response::HTTP_BAD_REQUEST,
                default => Response::HTTP_BAD_REQUEST,
            };

            return response()->json($e->toArray(), $statusCode);
        } catch (\Throwable $e) {
            Log::channel('ygg')->error('OIDC server error: '.$e->getMessage(), [
                'file' => $e->getFile().':'.$e->getLine(),
                'trace' => $e->getTraceAsString(),
            ]);

            return response()->json([
                'error' => 'server_error',
                'error_description' => 'Internal server error',
            ], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        return response()->json($result);
    }

    public function userinfo(Request $request): JsonResponse
    {
        $bearerToken = $request->bearerToken();
        if (!$bearerToken) {
            return response()->json([
                'error' => 'invalid_token',
                'error_description' => 'No bearer token provided',
            ], Response::HTTP_UNAUTHORIZED)->withHeaders([
                'WWW-Authenticate' => 'Bearer realm="yggdrasil", error="invalid_token", error_description="No bearer token provided"',
            ]);
        }

        try {
            $userInfo = $this->oidc->getUserInfo($bearerToken);
        } catch (OIDCException $e) {
            return response()->json($e->toArray(), Response::HTTP_UNAUTHORIZED)->withHeaders([
                'WWW-Authenticate' => 'Bearer realm="yggdrasil", error="'.$e->error.'", error_description="'.$e->errorDescription.'"',
            ]);
        }

        return response()->json($userInfo);
    }

    public function revocation(Request $request): JsonResponse
    {
        try {
            $result = $this->oidc->validateRevocationRequest($request->all());
        } catch (OIDCException $e) {
            $statusCode = match ($e->error) {
                'invalid_client' => Response::HTTP_UNAUTHORIZED,
                default => Response::HTTP_BAD_REQUEST,
            };

            return response()->json($e->toArray(), $statusCode);
        }

        return response()->json($result);
    }

    public function deviceAuthorization(Request $request): JsonResponse
    {
        $clientId = $request->input('client_id');
        $clientSecret = $request->input('client_secret');
        $scope = $request->input('scope');
        if (empty($scope)) {
            return response()->json([
                'error' => 'invalid_request',
                'error_description' => 'Missing required parameter: scope',
            ], Response::HTTP_BAD_REQUEST);
        }

        $scopes = explode(' ', $scope);
        if (!in_array(Scope::OPENID, $scopes)) {
            return response()->json([
                'error' => 'invalid_scope',
                'error_description' => 'The openid scope is required',
            ], Response::HTTP_BAD_REQUEST);
        }

        $client = Client::where('id', $clientId)->where('revoked', false)->first();
        if (!$client) {
            return response()->json([
                'error' => 'invalid_client',
                'error_description' => 'Client not found',
            ], Response::HTTP_UNAUTHORIZED);
        }

        $siteUrl = option('site_url');
        $publicRedirect = "$siteUrl/yggc/client/public";
        $redirectUris = array_map('trim', explode(',', $client->redirect));
        $isPublicClient = in_array($publicRedirect, $redirectUris);

        if (!$isPublicClient) {
            if (empty($clientSecret) || !$client->secret || !hash_equals($client->secret, $clientSecret)) {
                return response()->json([
                    'error' => 'invalid_client',
                    'error_description' => 'Client authentication failed',
                ], Response::HTTP_UNAUTHORIZED);
            }
        }

        $validScopes = Scope::getAllScopes();
        foreach ($scopes as $s) {
            if (!in_array($s, $validScopes)) {
                return response()->json([
                    'error' => 'invalid_scope',
                    'error_description' => "Invalid scope: $s",
                ], Response::HTTP_BAD_REQUEST);
            }
        }

        $result = $this->oidc->createDeviceCode($clientId, $scopes);

        return response()->json($result);
    }

    public function deviceVerify(Request $request): View|RedirectResponse
    {
        $userCode = $request->input('user_code');

        if ($request->isMethod('POST')) {
            $request->validate([
                'user_code' => 'required|string',
            ]);

            $user = auth()->user();
            if (!$user) {
                return redirect()->route('login');
            }

            // 用户拒绝设备授权
            if ($request->has('deny')) {
                $this->oidc->denyDeviceCode($request->input('user_code'));

                return view('LittleSkin\YggdrasilConnect::device', [
                    'denied' => true,
                ]);
            }

            $record = DB::table('yggc_device_codes')->where('userCode', $request->input('user_code'))->first();
            if (!$record) {
                return view('LittleSkin\YggdrasilConnect::device', [
                    'error' => trans('LittleSkin\\YggdrasilConnect::front-end.device.invalid-code'),
                ]);
            }

            $payload = json_decode($record->payload, true);
            $scopes = $payload['scopes'] ?? ['openid'];

            if (in_array(Scope::PROFILE_SELECT, $scopes) && !$request->has('profile_uuid')) {
                $bsUser = User::find($user->uid);
                $profiles = Profile::getAvailableProfiles($bsUser);

                if (count($profiles) > 1) {
                    return view('LittleSkin\YggdrasilConnect::device', [
                        'select_profile' => true,
                        'user_code' => $request->input('user_code'),
                        'availableProfiles' => $profiles,
                    ]);
                }

                if (count($profiles) === 1) {
                    $profileUuid = $profiles[0]['id'];
                    $success = $this->oidc->verifyDeviceCode($request->input('user_code'), $user, $scopes, $profileUuid);

                    if ($success) {
                        return view('LittleSkin\YggdrasilConnect::device', [
                            'success' => true,
                        ]);
                    }

                    return view('LittleSkin\YggdrasilConnect::device', [
                        'error' => trans('LittleSkin\\YggdrasilConnect::front-end.device.invalid-code'),
                    ]);
                }

                if (count($profiles) === 0) {
                    return view('LittleSkin\YggdrasilConnect::device', [
                        'error' => trans('LittleSkin\\YggdrasilConnect::front-end.select-profile.no-available-profiles'),
                    ]);
                }
            }

            $profileUuid = $request->input('profile_uuid');
            $success = $this->oidc->verifyDeviceCode($request->input('user_code'), $user, $scopes, $profileUuid);

            if ($success) {
                return view('LittleSkin\YggdrasilConnect::device', [
                    'success' => true,
                ]);
            }

            return view('LittleSkin\YggdrasilConnect::device', [
                'error' => trans('LittleSkin\\YggdrasilConnect::front-end.device.invalid-code'),
            ]);
        }

        return view('LittleSkin\YggdrasilConnect::device', [
            'user_code' => $userCode,
        ]);
    }

    public function interaction(Request $request, string $uid)
    {
        $interaction = $this->oidc->getInteraction($uid);
        if (!$interaction) {
            abort(Response::HTTP_NOT_FOUND);
        }

        $params = $interaction['params'];

        return redirect()->to(option('site_url').'/oauth/authorize?'.http_build_query([
            'client_id' => $params['client_id'],
            'response_type' => 'code',
            'scope' => $params['scope'],
            'redirect_uri' => option('site_url').'/yggc/callback',
            'state' => $uid,
            'prompt' => 'consent',
        ]));
    }

    public function interactionCallback(Request $request, string $uid)
    {
        $interaction = $this->oidc->getInteraction($uid);
        if (!$interaction) {
            abort(Response::HTTP_NOT_FOUND);
        }

        $params = $interaction['params'];

        if ($request->has('error')) {
            $redirectUri = $params['redirect_uri'];
            $separator = in_array('code', explode(' ', $params['response_type'])) ? '?' : '#';
            $errorParams = [
                'error' => $request->input('error', 'access_denied'),
                'error_description' => $request->input('error_description', 'The user denied the authorization request.'),
            ];
            if (!empty($params['state'])) {
                $errorParams['state'] = $params['state'];
            }

            return redirect()->away($redirectUri.$separator.http_build_query($errorParams));
        }

        $code = $request->input('code');
        if (empty($code)) {
            return redirect()->away($params['redirect_uri'].'?'.http_build_query([
                'error' => 'invalid_grant',
                'error_description' => 'No authorization code provided',
                'state' => $params['state'] ?? null,
            ]));
        }

        $authCode = AuthCode::where('id', $code)->where('revoked', false)->first();
        if (!$authCode || $authCode->expires_at->isPast()) {
            return redirect()->away($params['redirect_uri'].'?'.http_build_query([
                'error' => 'invalid_grant',
                'error_description' => 'Invalid or expired authorization code',
                'state' => $params['state'] ?? null,
            ]));
        }

        $user = BaseUser::where('uid', $authCode->user_id)
            ->where('verified', true)
            ->where('permission', '!=', -1)
            ->first();

        if (!$user) {
            return redirect()->away($params['redirect_uri'].'?'.http_build_query([
                'error' => 'invalid_grant',
                'error_description' => 'User not found or not verified',
                'state' => $params['state'] ?? null,
            ]));
        }

        $scopesInSession = explode(' ', $params['scope']);
        $scopesInBSAuth = json_decode($authCode->scopes, true) ?? [];
        $scopes = array_values(array_intersect($scopesInSession, $scopesInBSAuth));

        $profileUuid = null;
        $existingGrant = $this->oidc->findGrantByInteractionId($code);
        if (in_array(Scope::PROFILE_SELECT, $scopes)) {
            if (!$existingGrant || empty($existingGrant['selectedProfile'])) {
                return redirect()->away($params['redirect_uri'].'?'.http_build_query([
                    'error' => 'invalid_grant',
                    'error_description' => 'Profile not selected',
                    'state' => $params['state'] ?? null,
                ]));
            }
            $profileUuid = $existingGrant['selectedProfile'];
        }

        if ($existingGrant) {
            $grantId = $existingGrant['id'];
        } else {
            $grantId = $this->oidc->createGrant($params['client_id'], (string) $user->uid, $scopes, $code, $profileUuid);
        }

        $authCode->revoked = true;
        $authCode->save();

        $oidcCode = $this->oidc->createAuthorizationCode(
            $params['client_id'],
            (string) $user->uid,
            $params['redirect_uri'],
            $scopes,
            $params['nonce'] ?? null,
            $params['code_challenge'] ?? null,
            $params['code_challenge_method'] ?? null,
            $grantId
        );

        $redirectUri = $params['redirect_uri'];
        $separator = in_array('code', explode(' ', $params['response_type'])) ? '?' : '#';
        $callbackParams = ['code' => $oidcCode];
        if (!empty($params['state'])) {
            $callbackParams['state'] = $params['state'];
        }

        return redirect()->away($redirectUri.$separator.http_build_query($callbackParams));
    }

    public function passportCallback(Request $request): RedirectResponse|View
    {
        $validation = Validator::make($request->all(), [
            'code' => ['required_without:error', 'string'],
            'state' => ['required', 'string'],
            'error' => ['required_without:code', 'string'],
            'error_description' => ['required_with:error', 'string'],
        ]);

        if ($validation->fails()) {
            abort(Response::HTTP_FORBIDDEN, trans('LittleSkin\\YggdrasilConnect::exceptions.yggc.callback-request-invalid'));
        }

        $code = $request->input('code');
        $state = $request->input('state');

        if ($request->has('error')) {
            return $this->interactionErrorRedirect($state, $request->input('error'), $request->input('error_description'));
        }

        try {
            $codeDecrypted = json_decode(Crypto::decryptWithPassword($code, Crypt::getKey()));

            $authCode = AuthCode::where(['id' => $codeDecrypted->auth_code_id, 'revoked' => false])->first();
            $user = auth()->user();
            if (empty($authCode) || $authCode->user_id != $user->uid || $authCode->expires_at->isPast() || $authCode->revoked) {
                throw new InvalidRequestException(trans('LittleSkin\\YggdrasilConnect::exceptions.yggc.authorization-code-invalid'));
            }

            $client = Client::where('id', $authCode->client_id)->first();
            if (empty($client)) {
                throw new InvalidRequestException(trans('LittleSkin\\YggdrasilConnect::exceptions.yggc.authorization-code-invalid'));
            }

            $codeId = $authCode->id;
            $scopes = json_decode($authCode->scopes);
            if (in_array(Scope::PROFILE_SELECT, $scopes)) {
                $grantId = $this->oidc->createGrant(
                    (string) $client->id,
                    (string) $user->uid,
                    $scopes,
                    $authCode->id
                );

                return view('LittleSkin\YggdrasilConnect::select-profile', [
                    'name' => $this->formatClientName($client),
                    'code_id' => $grantId,
                    'state' => $state,
                    'availableProfiles' => Profile::getAvailableProfiles($user),
                ]);
            }

            return $this->interactionSuccessRedirect($state, $codeId);
        } catch (CryptoException|InvalidRequestException $e) {
            if ($e instanceof OAuthException) {
                return $this->interactionErrorRedirect($state, $e->error, $e->getMessage());
            }
            $exception = new InvalidRequestException(trans('LittleSkin\\YggdrasilConnect::exceptions.yggc.authorization-code-invalid'));

            return $this->interactionErrorRedirect($state, $exception->error, $exception->getMessage());
        }
    }

    public function selectProfile(Request $request): RedirectResponse
    {
        $validation = Validator::make($request->all(), [
            'code_id' => ['required', 'string'],
            'state' => ['required', 'string'],
            'selectedProfile' => ['required', 'string'],
        ]);

        if ($validation->fails()) {
            abort(Response::HTTP_FORBIDDEN, trans('LittleSkin\\YggdrasilConnect::exceptions.yggc.callback-request-invalid'));
        }

        try {
            $codeId = $request->input('code_id');
            $state = $request->input('state');
            $selectedProfile = $request->input('selectedProfile');

            $user = auth()->user();

            $uuid = UUID::where('uuid', $selectedProfile)->first();
            if (empty($uuid) || $uuid->player->uid != $user->uid) {
                throw new InvalidRequestException(trans('LittleSkin\\YggdrasilConnect::exceptions.yggc.authorization-code-invalid'));
            }

            $grant = $this->oidc->findGrant($codeId);
            if (!$grant) {
                throw new InvalidRequestException(trans('LittleSkin\\YggdrasilConnect::exceptions.yggc.authorization-code-invalid'));
            }

            $grant['selectedProfile'] = $uuid->uuid;
            $this->oidc->updateGrant($codeId, $grant);

            return $this->interactionSuccessRedirect($state, $grant['interactionId']);
        } catch (InvalidRequestException $e) {
            return $this->interactionErrorRedirect($request->input('state'), $e->error, $e->getMessage());
        }
    }

    public function cancel(Request $request): RedirectResponse
    {
        $validation = Validator::make($request->all(), [
            'code_id' => ['required', 'string'],
            'state' => ['required', 'string'],
        ]);

        if ($validation->fails()) {
            abort(Response::HTTP_FORBIDDEN, trans('LittleSkin\\YggdrasilConnect::exceptions.yggc.callback-request-invalid'));
        }

        $authCode = AuthCode::where('id', $request->input('code_id'))->first();
        if ($authCode) {
            $authCode->revoked = true;
            $authCode->save();
        }

        $state = $request->input('state');

        return $this->interactionErrorRedirect($state, 'access_denied', trans('LittleSkin\\YggdrasilConnect::exceptions.yggc.access-denied'));
    }

    private function interactionSuccessRedirect(string $state, string $code): RedirectResponse
    {
        $issuer = $this->oidc->getIssuer();
        $callbackUrl = "$issuer/yggc/interaction/$state/callback";

        return redirect()->away("$callbackUrl?".http_build_query(['code' => $code, 'state' => $state]));
    }

    private function interactionErrorRedirect(string $state, string $error, string $errorDescription): RedirectResponse
    {
        $issuer = $this->oidc->getIssuer();
        $callbackUrl = "$issuer/yggc/interaction/$state/callback";

        return redirect()->away("$callbackUrl?".http_build_query([
            'error' => $error,
            'error_description' => $errorDescription,
            'state' => $state,
        ]));
    }

    public function getUserInfo()
    {
        $bearerToken = request()->bearerToken();
        if ($bearerToken) {
            try {
                $userInfo = $this->oidc->getUserInfo($bearerToken);

                return response()->json($userInfo);
            } catch (OIDCException $e) {
            }
        }

        /** @var User */
        $user = auth()->user();

        if (!$user->verified) {
            return response()->json([
                'error' => 'invalid_token',
                'error_description' => 'User email is not verified',
            ], Response::HTTP_UNAUTHORIZED);
        }

        $resp = [
            'sub' => strval($user->uid),
        ];

        if ($user->tokenCan(Scope::PROFILE)) {
            $resp['name'] = $user->nickname;
            $resp['preferred_username'] = $user->nickname;
            $resp['nickname'] = $user->nickname;
            $resp['picture'] = url('avatar/user', $user->uid);
        }

        if ($user->tokenCan(Scope::EMAIL)) {
            $resp['email'] = $user->email;
            $resp['email_verified'] = true;
        }

        if ($user->tokenCan(Scope::PROFILE_SELECT)) {
            $profile = Profile::createFromUuid($user->yggdrasilToken()->selectedProfile);
            $resp['selectedProfile'] = [
                'id' => $profile->uuid,
                'name' => $profile->name,
            ];
        }

        if ($user->tokenCan(Scope::PROFILE_READ)) {
            $resp['availableProfiles'] = Profile::getAvailableProfiles($user);
        }

        return response()->json($resp);
    }

    private function formatClientName(Client $client): string
    {
        $name = $client->name;
        $redirect = $client->redirect;
        if ($redirect) {
            $urls = array_map('trim', explode(',', $redirect));
            // Skip internal/yggc redirect URLs
            foreach ($urls as $url) {
                $host = parse_url($url, PHP_URL_HOST);
                if ($host && !str_starts_with($url, option('site_url').'/yggc/')) {
                    return "$name ($host)";
                }
            }
        }

        return $name;
    }
}
