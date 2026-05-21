<?php

namespace LittleSkin\YggdrasilConnect\OIDC;

use App\Models\User as BaseUser;
use App\Services\Facades\Option;
use Carbon\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Laravel\Passport\Client;
use Laravel\Passport\TokenRepository;
use Lcobucci\JWT;
use Lcobucci\JWT\Signer\Key\InMemory;
use LittleSkin\YggdrasilConnect\Models\Profile;
use LittleSkin\YggdrasilConnect\Models\UUID;
use LittleSkin\YggdrasilConnect\Scope;

class OIDCService
{
    public const BS_RESOURCE_INDICATOR = 'https://github.com/bs-community/blessing-skin-server';
    public const ACCESS_TOKEN_NAME = 'Yggdrasil Connect';

    private JWT\Configuration $jwtConfig;

    public function __construct()
    {
        $this->jwtConfig = JWT\Configuration::forAsymmetricSigner(
            new JWT\Signer\Rsa\Sha256(),
            InMemory::file(storage_path('oauth-private.key')),
            InMemory::file(storage_path('oauth-public.key'))
        );
    }

    public function getIssuer(): string
    {
        $issuer = option('ygg_connect_server_url');
        if (empty($issuer)) {
            $issuer = option('site_url');
        }

        return rtrim($issuer, '/');
    }

    public function getDiscoveryConfig(): array
    {
        $issuer = $this->getIssuer();

        return [
            'issuer' => $issuer,
            'authorization_endpoint' => "$issuer/auth",
            'token_endpoint' => "$issuer/token",
            'userinfo_endpoint' => "$issuer/userinfo",
            'jwks_uri' => "$issuer/jwks",
            'registration_endpoint' => null,
            'scopes_supported' => [
                'openid',
                'profile',
                'email',
                'offline_access',
                Scope::PROFILE_READ,
                Scope::PROFILE_SELECT,
                Scope::SERVER_JOIN,
            ],
            'claims_supported' => [
                'sub',
                'iss',
                'aud',
                'exp',
                'iat',
                'auth_time',
                'nonce',
                'acr',
                'amr',
                'azp',
                'nickname',
                'picture',
                'email',
                'email_verified',
                'selectedProfile',
                'availableProfiles',
            ],
            'response_types_supported' => ['code', 'id_token', 'code id_token'],
            'response_modes_supported' => ['query', 'fragment'],
            'grant_types_supported' => ['authorization_code', 'implicit', 'refresh_token', 'urn:ietf:params:oauth:grant-type:device_code'],
            'subject_types_supported' => ['public'],
            'id_token_signing_alg_values_supported' => ['RS256'],
            'token_endpoint_auth_methods_supported' => ['client_secret_post', 'none'],
            'claims_parameter_supported' => false,
            'request_parameter_supported' => false,
            'request_uri_parameter_supported' => false,
            'require_request_uri_registration' => false,
            'revocation_endpoint' => "$issuer/revoke",
            'revocation_endpoint_auth_methods_supported' => ['client_secret_post', 'none'],
            'end_session_endpoint' => null,
            'device_authorization_endpoint' => "$issuer/device/auth",
            'code_challenge_methods_supported' => ['S256'],
            'token_endpoint_auth_signing_alg_values_supported' => ['RS256'],
        ];
    }

    public function getJWKS(): array
    {
        $publicKey = file_get_contents(storage_path('oauth-public.key'));
        $key = openssl_pkey_get_public($publicKey);
        $details = openssl_pkey_get_details($key);

        $n = rtrim(strtr(base64_encode($details['rsa']['n']), '+/', '-_'), '=');
        $e = rtrim(strtr(base64_encode($details['rsa']['e']), '+/', '-_'), '=');

        $thumbprint = $this->computeJWKThumbprint($n, $e);

        return [
            'keys' => [
                [
                    'kty' => 'RSA',
                    'use' => 'sig',
                    'alg' => 'RS256',
                    'kid' => $thumbprint,
                    'n' => $n,
                    'e' => $e,
                ],
            ],
        ];
    }

    private function computeJWKThumbprint(string $n, string $e): string
    {
        $jwk = json_encode([
            'e' => $e,
            'kty' => 'RSA',
            'n' => $n,
        ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        return rtrim(strtr(base64_encode(hash('sha256', $jwk, true)), '+/', '-_'), '=');
    }

    public function validateAuthorizationRequest(array $params): array
    {
        $required = ['client_id', 'response_type', 'redirect_uri'];
        foreach ($required as $field) {
            if (empty($params[$field])) {
                throw new OIDCException('invalid_request', "Missing required parameter: $field");
            }
        }

        $client = Client::where('id', $params['client_id'])->where('revoked', false)->first();
        if (!$client) {
            throw new OIDCException('invalid_client', 'Client not found or is revoked');
        }

        $redirectUris = array_map('trim', explode(',', $client->redirect));
        if (!in_array($params['redirect_uri'], $redirectUris)) {
            throw new OIDCException('invalid_request', 'Redirect URI not registered for this client');
        }

        $responseTypes = explode(' ', $params['response_type']);
        $validResponseTypes = ['code', 'id_token'];
        foreach ($responseTypes as $rt) {
            if (!in_array($rt, $validResponseTypes)) {
                throw new OIDCException('unsupported_response_type', "Unsupported response type: $rt", $params['state'] ?? null);
            }
        }

        $scopes = isset($params['scope']) ? explode(' ', $params['scope']) : ['openid'];
        if (!in_array('openid', $scopes)) {
            $scopes[] = 'openid';
        }

        $validScopes = Scope::getAllScopes();
        foreach ($scopes as $scope) {
            if (!in_array($scope, $validScopes)) {
                throw new OIDCException('invalid_scope', "Invalid scope: $scope", $params['state'] ?? null);
            }
        }

        if (in_array(Scope::PROFILE_SELECT, $scopes) && in_array(Scope::PROFILE_READ, $scopes)) {
            throw new OIDCException('invalid_scope', 'Cannot request both PROFILE_SELECT and PROFILE_READ', $params['state'] ?? null);
        }

        if (in_array(Scope::SERVER_JOIN, $scopes) && !in_array(Scope::PROFILE_SELECT, $scopes)) {
            throw new OIDCException('invalid_scope', 'SERVER_JOIN requires PROFILE_SELECT', $params['state'] ?? null);
        }

        return [
            'client' => $client,
            'scopes' => $scopes,
            'response_types' => $responseTypes,
            'redirect_uri' => $params['redirect_uri'],
            'state' => $params['state'] ?? null,
            'nonce' => $params['nonce'] ?? null,
            'code_challenge' => $params['code_challenge'] ?? null,
            'code_challenge_method' => $params['code_challenge_method'] ?? null,
        ];
    }

    public function createInteraction(array $authRequest): string
    {
        $uid = bin2hex(random_bytes(16));

        $payload = [
            'params' => [
                'client_id' => (string) $authRequest['client']->id,
                'scope' => implode(' ', $authRequest['scopes']),
                'response_type' => implode(' ', $authRequest['response_types']),
                'redirect_uri' => $authRequest['redirect_uri'],
                'state' => $authRequest['state'],
                'nonce' => $authRequest['nonce'],
                'code_challenge' => $authRequest['code_challenge'],
                'code_challenge_method' => $authRequest['code_challenge_method'],
            ],
            'prompt' => [
                'name' => 'login',
            ],
            'lastSubmission' => null,
            'created_at' => Carbon::now()->toIso8601String(),
        ];

        DB::table('yggc_interactions')->insert([
            'id' => $uid,
            'payload' => json_encode($payload),
            'uid' => $uid,
            'created_at' => Carbon::now(),
            'updated_at' => Carbon::now(),
        ]);

        return $uid;
    }

    public function getInteraction(string $uid): ?array
    {
        $record = DB::table('yggc_interactions')->where('id', $uid)->first();
        if (!$record) {
            return null;
        }

        return json_decode($record->payload, true);
    }

    public function createGrant(string $clientId, string $accountId, array $scopes, string $interactionId): string
    {
        $grantId = bin2hex(random_bytes(16));

        $payload = [
            'clientId' => $clientId,
            'accountId' => $accountId,
            'scopes' => $scopes,
            'resources' => [
                self::BS_RESOURCE_INDICATOR => implode(' ', $scopes),
            ],
            'created_at' => Carbon::now()->toIso8601String(),
        ];

        DB::table('yggc_grants')->insert([
            'id' => $grantId,
            'payload' => json_encode($payload),
            'uid' => $interactionId,
            'created_at' => Carbon::now(),
            'updated_at' => Carbon::now(),
        ]);

        return $grantId;
    }

    public function findGrant(string $grantId): ?array
    {
        $record = DB::table('yggc_grants')->where('id', $grantId)->first();
        if (!$record) {
            return null;
        }

        return json_decode($record->payload, true);
    }

    public function createAuthorizationCode(string $clientId, string $accountId, string $redirectUri, array $scopes, ?string $nonce, ?string $codeChallenge, ?string $codeChallengeMethod, string $grantId): string
    {
        $code = bin2hex(random_bytes(32));

        $payload = [
            'clientId' => $clientId,
            'accountId' => $accountId,
            'redirectUri' => $redirectUri,
            'scopes' => $scopes,
            'nonce' => $nonce,
            'codeChallenge' => $codeChallenge,
            'codeChallengeMethod' => $codeChallengeMethod,
            'grantId' => $grantId,
            'consumed' => false,
            'created_at' => Carbon::now()->toIso8601String(),
        ];

        DB::table('yggc_authorization_codes')->insert([
            'id' => $code,
            'payload' => json_encode($payload),
            'uid' => null,
            'consumed' => false,
            'created_at' => Carbon::now(),
            'updated_at' => Carbon::now(),
        ]);

        return $code;
    }

    public function consumeAuthorizationCode(string $code): ?array
    {
        $record = DB::table('yggc_authorization_codes')->where('id', $code)->first();
        if (!$record) {
            return null;
        }

        $payload = json_decode($record->payload, true);
        if ($payload['consumed']) {
            return null;
        }

        $createdAt = Carbon::parse($record->created_at);
        if ($createdAt->addMinutes(10)->isPast()) {
            return null;
        }

        DB::table('yggc_authorization_codes')->where('id', $code)->update([
            'consumed' => true,
            'updated_at' => Carbon::now(),
        ]);

        return $payload;
    }

    public function validateTokenRequest(array $params): array
    {
        if (empty($params['grant_type'])) {
            throw new OIDCException('invalid_request', 'Missing grant_type');
        }

        $supportedGrants = ['authorization_code', 'refresh_token', 'urn:ietf:params:oauth:grant-type:device_code'];
        if (!in_array($params['grant_type'], $supportedGrants)) {
            throw new OIDCException('unsupported_grant_type', "Unsupported grant type: {$params['grant_type']}");
        }

        if ($params['grant_type'] === 'authorization_code') {
            return $this->handleAuthorizationCodeGrant($params);
        }

        if ($params['grant_type'] === 'refresh_token') {
            return $this->handleRefreshTokenGrant($params);
        }

        if ($params['grant_type'] === 'urn:ietf:params:oauth:grant-type:device_code') {
            return $this->handleDeviceCodeGrant($params);
        }

        throw new OIDCException('unsupported_grant_type', 'Unsupported grant type');
    }

    private function handleAuthorizationCodeGrant(array $params): array
    {
        if (empty($params['code'])) {
            throw new OIDCException('invalid_request', 'Missing code parameter');
        }

        $codeData = $this->consumeAuthorizationCode($params['code']);
        if (!$codeData) {
            throw new OIDCException('invalid_grant', 'Invalid or expired authorization code');
        }

        $client = $this->authenticateClient($params);
        if (!$client || (string) $client->id !== $codeData['clientId']) {
            throw new OIDCException('invalid_client', 'Client authentication failed');
        }

        if (!empty($params['redirect_uri']) && $params['redirect_uri'] !== $codeData['redirectUri']) {
            throw new OIDCException('invalid_grant', 'Redirect URI mismatch');
        }

        if (!empty($codeData['codeChallenge'])) {
            if (empty($params['code_verifier'])) {
                throw new OIDCException('invalid_request', 'Code verifier is required');
            }
            if (!$this->verifyCodeChallenge($params['code_verifier'], $codeData['codeChallenge'], $codeData['codeChallengeMethod'])) {
                throw new OIDCException('invalid_grant', 'Code verifier does not match code challenge');
            }
        }

        $user = BaseUser::where('uid', $codeData['accountId'])
            ->where('verified', true)
            ->where('permission', '!=', -1)
            ->first();
        if (!$user) {
            throw new OIDCException('invalid_grant', 'User not found or not verified');
        }

        return $this->issueTokenSet($user, $codeData['clientId'], $codeData['scopes'], $codeData['nonce'], $codeData['grantId']);
    }

    private function handleRefreshTokenGrant(array $params): array
    {
        if (empty($params['refresh_token'])) {
            throw new OIDCException('invalid_request', 'Missing refresh_token parameter');
        }

        $client = $this->authenticateClient($params);
        if (!$client) {
            throw new OIDCException('invalid_client', 'Client authentication failed');
        }

        $rtRecord = DB::table('yggc_refresh_tokens')->where('id', $params['refresh_token'])->first();
        if (!$rtRecord) {
            throw new OIDCException('invalid_grant', 'Invalid refresh token');
        }

        $rtPayload = json_decode($rtRecord->payload, true);
        if ($rtPayload['consumed']) {
            $this->revokeDescendants($rtPayload['grantId'], $params['refresh_token']);
            throw new OIDCException('invalid_grant', 'Refresh token has been used');
        }

        if ((string) $client->id !== $rtPayload['clientId']) {
            throw new OIDCException('invalid_client', 'Client mismatch');
        }

        $createdAt = Carbon::parse($rtRecord->created_at);
        $expiresIn2 = intval(option('ygg_token_expire_2', 604800));
        if ($createdAt->addSeconds($expiresIn2)->isPast()) {
            throw new OIDCException('invalid_grant', 'Refresh token expired');
        }

        DB::table('yggc_refresh_tokens')->where('id', $params['refresh_token'])->update([
            'consumed' => true,
            'updated_at' => Carbon::now(),
        ]);

        $this->revokePassportAccessTokenByRefreshToken($params['refresh_token']);

        $user = BaseUser::where('uid', $rtPayload['accountId'])
            ->where('verified', true)
            ->where('permission', '!=', -1)
            ->first();
        if (!$user) {
            throw new OIDCException('invalid_grant', 'User not found or not verified');
        }

        $scopes = $rtPayload['scopes'];
        if (!empty($params['scope'])) {
            $requestedScopes = explode(' ', $params['scope']);
            $scopes = array_values(array_intersect($scopes, $requestedScopes));
        }

        return $this->issueTokenSet($user, $rtPayload['clientId'], $scopes, null, $rtPayload['grantId']);
    }

    private function handleDeviceCodeGrant(array $params): array
    {
        if (empty($params['device_code'])) {
            throw new OIDCException('invalid_request', 'Missing device_code parameter');
        }

        $client = $this->authenticateClient($params);
        if (!$client) {
            throw new OIDCException('invalid_client', 'Client authentication failed');
        }

        $dcRecord = DB::table('yggc_device_codes')->where('id', $params['device_code'])->first();
        if (!$dcRecord) {
            throw new OIDCException('invalid_grant', 'Invalid device code');
        }

        $dcPayload = json_decode($dcRecord->payload, true);
        if ((string) $client->id !== $dcPayload['clientId']) {
            throw new OIDCException('invalid_client', 'Client mismatch');
        }

        if (empty($dcPayload['accountId'])) {
            throw new OIDCException('authorization_pending', 'The user has not yet completed the device flow');
        }

        if ($dcPayload['consumed']) {
            throw new OIDCException('expired_token', 'Device code already used');
        }

        $createdAt = Carbon::parse($dcRecord->created_at);
        $deviceCodeExpiresIn = intval(option('ygg_device_code_expires_in', 600));
        if ($createdAt->addSeconds($deviceCodeExpiresIn)->isPast()) {
            throw new OIDCException('expired_token', 'Device code expired');
        }

        DB::table('yggc_device_codes')->where('id', $params['device_code'])->update([
            'consumed' => true,
            'updated_at' => Carbon::now(),
        ]);

        $user = BaseUser::where('uid', $dcPayload['accountId'])
            ->where('verified', true)
            ->where('permission', '!=', -1)
            ->first();
        if (!$user) {
            throw new OIDCException('invalid_grant', 'User not found or not verified');
        }

        return $this->issueTokenSet($user, $dcPayload['clientId'], $dcPayload['scopes'], null, $dcPayload['grantId']);
    }

    public function issueTokenSet(BaseUser $user, string $clientId, array $scopes, ?string $nonce, string $grantId): array
    {
        $expiresIn1 = intval(option('ygg_token_expire_1', 259200));
        $expiresIn2 = intval(option('ygg_token_expire_2', 604800));
        $now = Carbon::now();

        $accessToken = $this->issueAccessToken($user, $clientId, $scopes, $grantId, $expiresIn1);
        $refreshToken = $this->issueRefreshToken($user, $clientId, $scopes, $grantId, $expiresIn2);
        $idToken = $this->issueIdToken($user, $clientId, $scopes, $nonce, $grantId);

        $this->syncAccessTokenToPassport($accessToken, $user, $clientId, $scopes, $expiresIn1);
        $this->syncRefreshTokenToPassport($refreshToken, $accessToken['jti']);

        $result = [
            'access_token' => $accessToken['jwt'],
            'token_type' => 'Bearer',
            'expires_in' => $expiresIn1,
            'refresh_token' => $refreshToken['jwt'],
            'scope' => implode(' ', $scopes),
            'id_token' => $idToken,
        ];

        return $result;
    }

    private function issueAccessToken(BaseUser $user, string $clientId, array $scopes, string $grantId, int $expiresIn): array
    {
        $jti = bin2hex(random_bytes(16));
        $now = Carbon::now();
        $issuer = $this->getIssuer();

        $selectedProfile = null;
        if (in_array(Scope::PROFILE_SELECT, $scopes)) {
            $codeIdToUUID = DB::table('code_id_to_uuid')->where('code_id', $grantId)->first();
            if ($codeIdToUUID) {
                $selectedProfile = $codeIdToUUID->uuid;
            }
        }

        $builder = $this->jwtConfig->builder()
            ->identifiedBy($jti)
            ->issuedAt($now->toDateTimeImmutable())
            ->expiresAt($now->addSeconds($expiresIn)->toDateTimeImmutable())
            ->permittedFor($clientId)
            ->relatedTo((string) $user->uid)
            ->issuedBy($issuer)
            ->withClaim('scope', implode(' ', $scopes))
            ->withClaim('scopes', $scopes)
            ->withClaim('client_id', $clientId)
            ->withClaim('sub', (string) $user->uid)
            ->withClaim('aud', $clientId)
            ->withClaim('iss', $issuer)
            ->withClaim('grant_id', $grantId);

        if ($selectedProfile) {
            $builder->withClaim('selectedProfile', $selectedProfile);
        }

        $jwt = $builder->getToken($this->jwtConfig->signer(), $this->jwtConfig->signingKey())->toString();

        return [
            'jti' => $jti,
            'jwt' => $jwt,
            'clientId' => $clientId,
            'accountId' => (string) $user->uid,
            'scopes' => $scopes,
            'grantId' => $grantId,
            'expiresIn' => $expiresIn,
        ];
    }

    private function issueRefreshToken(BaseUser $user, string $clientId, array $scopes, string $grantId, int $expiresIn): array
    {
        $jti = bin2hex(random_bytes(16));
        $now = Carbon::now();

        $payload = [
            'jti' => $jti,
            'clientId' => $clientId,
            'accountId' => (string) $user->uid,
            'scopes' => $scopes,
            'grantId' => $grantId,
            'consumed' => false,
            'created_at' => $now->toIso8601String(),
        ];

        DB::table('yggc_refresh_tokens')->insert([
            'id' => $jti,
            'payload' => json_encode($payload),
            'uid' => null,
            'consumed' => false,
            'created_at' => $now,
            'updated_at' => $now,
        ]);

        $builder = $this->jwtConfig->builder()
            ->identifiedBy($jti)
            ->issuedAt($now->toDateTimeImmutable())
            ->expiresAt($now->addSeconds($expiresIn)->toDateTimeImmutable())
            ->permittedFor($clientId)
            ->relatedTo((string) $user->uid)
            ->issuedBy($this->getIssuer())
            ->withClaim('scope', implode(' ', $scopes))
            ->withClaim('client_id', $clientId)
            ->withClaim('grant_id', $grantId);

        $jwt = $builder->getToken($this->jwtConfig->signer(), $this->jwtConfig->signingKey())->toString();

        return [
            'jti' => $jti,
            'jwt' => $jwt,
            'clientId' => $clientId,
            'accountId' => (string) $user->uid,
            'scopes' => $scopes,
            'grantId' => $grantId,
        ];
    }

    private function issueIdToken(BaseUser $user, string $clientId, array $scopes, ?string $nonce, string $grantId): string
    {
        $now = Carbon::now();
        $issuer = $this->getIssuer();

        $claims = [
            'sub' => (string) $user->uid,
        ];

        if (in_array(Scope::PROFILE, $scopes)) {
            $claims['nickname'] = $user->nickname;
            $claims['picture'] = url('avatar/user', $user->uid);
        }

        if (in_array(Scope::EMAIL, $scopes)) {
            $claims['email'] = $user->email;
            $claims['email_verified'] = true;
        }

        if (in_array(Scope::PROFILE_SELECT, $scopes)) {
            $codeIdToUUID = DB::table('code_id_to_uuid')->where('code_id', $grantId)->first();
            if ($codeIdToUUID) {
                $uuid = UUID::where('uuid', $codeIdToUUID->uuid)->first();
                if ($uuid && $uuid->player) {
                    $claims['selectedProfile'] = [
                        'id' => $uuid->uuid,
                        'name' => $uuid->player->name,
                    ];
                }
            }
        }

        if (in_array(Scope::PROFILE_READ, $scopes)) {
            $claims['availableProfiles'] = Profile::getAvailableProfiles(\LittleSkin\YggdrasilConnect\Models\User::find($user->uid));
        }

        $builder = $this->jwtConfig->builder()
            ->identifiedBy(bin2hex(random_bytes(16)))
            ->issuedAt($now->toDateTimeImmutable())
            ->expiresAt($now->addSeconds(intval(option('ygg_token_expire_1', 259200)))->toDateTimeImmutable())
            ->permittedFor($clientId)
            ->relatedTo((string) $user->uid)
            ->issuedBy($issuer);

        if ($nonce !== null) {
            $builder->withClaim('nonce', $nonce);
        }

        foreach ($claims as $key => $value) {
            if ($key !== 'sub') {
                $builder->withClaim($key, $value);
            }
        }

        return $builder->getToken($this->jwtConfig->signer(), $this->jwtConfig->signingKey())->toString();
    }

    private function syncAccessTokenToPassport(array $accessToken, BaseUser $user, string $clientId, array $scopes, int $expiresIn): void
    {
        $now = Carbon::now();
        $maxTokenCount = intval(option('ygg_tokens_limit', 5));

        $existingTokens = DB::table('oauth_access_tokens')
            ->where('client_id', $clientId)
            ->where('user_id', $user->uid)
            ->where('name', self::ACCESS_TOKEN_NAME)
            ->where('revoked', false)
            ->where('expires_at', '>=', $now)
            ->get();

        if ($existingTokens->count() >= $maxTokenCount) {
            $toRevoke = $existingTokens->take($existingTokens->count() - $maxTokenCount + 1);
            foreach ($toRevoke as $token) {
                DB::table('oauth_access_tokens')->where('id', $token->id)->update(['revoked' => true]);
            }
        }

        DB::table('oauth_access_tokens')->insert([
            'id' => $accessToken['jti'],
            'user_id' => $user->uid,
            'client_id' => $clientId,
            'name' => self::ACCESS_TOKEN_NAME,
            'scopes' => json_encode($scopes),
            'revoked' => false,
            'created_at' => $now,
            'updated_at' => $now,
            'expires_at' => $now->addSeconds($expiresIn),
        ]);
    }

    private function syncRefreshTokenToPassport(array $refreshToken, string $accessTokenJti): void
    {
        $existing = DB::table('oauth_refresh_tokens')->where('id', $refreshToken['jti'])->first();
        if ($existing) {
            DB::table('oauth_refresh_tokens')->where('id', $refreshToken['jti'])->update([
                'access_token_id' => $accessTokenJti,
            ]);
        } else {
            DB::table('oauth_refresh_tokens')->insert([
                'id' => $refreshToken['jti'],
                'access_token_id' => $accessTokenJti,
                'revoked' => false,
                'expires_at' => Carbon::now()->addSeconds(intval(option('ygg_token_expire_2', 604800))),
            ]);
        }
    }

    private function revokePassportAccessTokenByRefreshToken(string $refreshTokenId): void
    {
        $rt = DB::table('oauth_refresh_tokens')->where('id', $refreshTokenId)->first();
        if ($rt) {
            DB::table('oauth_access_tokens')->where('id', $rt->access_token_id)->update(['revoked' => true]);
            DB::table('oauth_refresh_tokens')->where('id', $refreshTokenId)->update(['revoked' => true]);
        }
    }

    private function revokeDescendants(string $grantId, string $usedRefreshTokenId): void
    {
        $rts = DB::table('yggc_refresh_tokens')
            ->where('id', '!=', $usedRefreshTokenId)
            ->get();

        foreach ($rts as $rt) {
            $payload = json_decode($rt->payload, true);
            if (isset($payload['grantId']) && $payload['grantId'] === $grantId) {
                DB::table('yggc_refresh_tokens')->where('id', $rt->id)->update(['consumed' => true]);
            }
        }
    }

    private function authenticateClient(array $params): ?Client
    {
        $clientId = $params['client_id'] ?? null;
        $clientSecret = $params['client_secret'] ?? null;

        if (empty($clientId)) {
            return null;
        }

        $client = Client::where('id', $clientId)->where('revoked', false)->first();
        if (!$client) {
            return null;
        }

        $siteUrl = option('site_url');
        $publicRedirect = "$siteUrl/yggc/client/public";
        $redirectUris = array_map('trim', explode(',', $client->redirect));

        if (in_array($publicRedirect, $redirectUris)) {
            return $client;
        }

        if (!empty($clientSecret)) {
            if ($client->secret && hash_equals($client->secret, $clientSecret)) {
                return $client;
            }
            return null;
        }

        return null;
    }

    private function verifyCodeChallenge(string $verifier, string $challenge, string $method): bool
    {
        if ($method === 'S256') {
            $computed = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
        } else {
            $computed = $verifier;
        }

        return hash_equals($challenge, $computed);
    }

    public function createDeviceCode(string $clientId, array $scopes): array
    {
        $deviceCode = bin2hex(random_bytes(32));
        $userCode = strtoupper(substr(bin2hex(random_bytes(4)), 0, 4).'-'.substr(bin2hex(random_bytes(4)), 0, 4));

        $payload = [
            'clientId' => $clientId,
            'scopes' => $scopes,
            'accountId' => null,
            'grantId' => null,
            'consumed' => false,
            'created_at' => Carbon::now()->toIso8601String(),
        ];

        DB::table('yggc_device_codes')->insert([
            'id' => $deviceCode,
            'payload' => json_encode($payload),
            'userCode' => $userCode,
            'uid' => null,
            'consumed' => false,
            'created_at' => Carbon::now(),
            'updated_at' => Carbon::now(),
        ]);

        $expiresIn = intval(option('ygg_device_code_expires_in', 600));

        return [
            'device_code' => $deviceCode,
            'user_code' => $userCode,
            'verification_uri' => $this->getIssuer().'/device',
            'verification_uri_complete' => $this->getIssuer().'/device?user_code='.$userCode,
            'expires_in' => $expiresIn,
            'interval' => 5,
        ];
    }

    public function verifyDeviceCode(string $userCode, BaseUser $user, array $scopes): bool
    {
        $record = DB::table('yggc_device_codes')->where('userCode', $userCode)->first();
        if (!$record) {
            return false;
        }

        $payload = json_decode($record->payload, true);
        if ($payload['consumed'] || !empty($payload['accountId'])) {
            return false;
        }

        $createdAt = Carbon::parse($record->created_at);
        $deviceCodeExpiresIn = intval(option('ygg_device_code_expires_in', 600));
        if ($createdAt->addSeconds($deviceCodeExpiresIn)->isPast()) {
            return false;
        }

        $grantId = $this->createGrant($payload['clientId'], (string) $user->uid, $scopes, $record->id);

        $payload['accountId'] = (string) $user->uid;
        $payload['grantId'] = $grantId;

        DB::table('yggc_device_codes')->where('id', $record->id)->update([
            'payload' => json_encode($payload),
            'updated_at' => Carbon::now(),
        ]);

        return true;
    }

    public function validateRevocationRequest(array $params): array
    {
        $token = $params['token'] ?? null;
        $tokenTypeHint = $params['token_type_hint'] ?? null;

        if (empty($token)) {
            throw new OIDCException('invalid_request', 'Missing token parameter');
        }

        $client = $this->authenticateClient($params);
        if (!$client) {
            throw new OIDCException('invalid_client', 'Client authentication failed');
        }

        if ($tokenTypeHint === 'refresh_token') {
            $rt = DB::table('yggc_refresh_tokens')->where('id', $token)->first();
            if ($rt) {
                $payload = json_decode($rt->payload, true);
                if ($payload['clientId'] === (string) $client->id) {
                    DB::table('yggc_refresh_tokens')->where('id', $token)->update(['consumed' => true]);
                    return ['revoked' => true];
                }
            }
        }

        $at = DB::table('oauth_access_tokens')->where('id', $token)->first();
        if ($at) {
            if ((string) $at->client_id === (string) $client->id) {
                DB::table('oauth_access_tokens')->where('id', $token)->update(['revoked' => true]);
                return ['revoked' => true];
            }
        }

        if ($tokenTypeHint !== 'refresh_token') {
            $rt = DB::table('yggc_refresh_tokens')->where('id', $token)->first();
            if ($rt) {
                $payload = json_decode($rt->payload, true);
                if ($payload['clientId'] === (string) $client->id) {
                    DB::table('yggc_refresh_tokens')->where('id', $token)->update(['consumed' => true]);
                    return ['revoked' => true];
                }
            }
        }

        return ['revoked' => false];
    }

    public function getUserInfo(string $accessToken): array
    {
        try {
            $parsed = $this->jwtConfig->parser()->parse($accessToken);
        } catch (\Exception $e) {
            throw new OIDCException('invalid_token', 'Invalid access token');
        }

        $jti = $parsed->claims()->get('jti');
        $passportToken = DB::table('oauth_access_tokens')->where('id', $jti)->where('revoked', false)->first();
        if (!$passportToken) {
            throw new OIDCException('invalid_token', 'Token not found or revoked');
        }

        if (Carbon::parse($passportToken->expires_at)->isPast()) {
            throw new OIDCException('invalid_token', 'Token expired');
        }

        $userId = $parsed->claims()->get('sub');
        $user = BaseUser::where('uid', $userId)->first();
        if (!$user || $user->permission == -1) {
            throw new OIDCException('invalid_token', 'User not found or banned');
        }

        $scopes = $parsed->claims()->get('scopes') ?? explode(' ', $parsed->claims()->get('scope', ''));
        if (is_string($scopes)) {
            $scopes = explode(' ', $scopes);
        }

        $userInfo = [
            'sub' => (string) $user->uid,
        ];

        if (in_array(Scope::PROFILE, $scopes)) {
            $userInfo['nickname'] = $user->nickname;
            $userInfo['picture'] = url('avatar/user', $user->uid);
        }

        if (in_array(Scope::EMAIL, $scopes)) {
            $userInfo['email'] = $user->email;
            $userInfo['email_verified'] = true;
        }

        if (in_array(Scope::PROFILE_SELECT, $scopes)) {
            $selectedProfile = $parsed->claims()->get('selectedProfile');
            if ($selectedProfile) {
                $profile = Profile::createFromUuid($selectedProfile);
                if ($profile) {
                    $userInfo['selectedProfile'] = [
                        'id' => $profile->uuid,
                        'name' => $profile->name,
                    ];
                }
            }
        }

        if (in_array(Scope::PROFILE_READ, $scopes)) {
            $userInfo['availableProfiles'] = Profile::getAvailableProfiles(\LittleSkin\YggdrasilConnect\Models\User::find($user->uid));
        }

        return $userInfo;
    }
}
