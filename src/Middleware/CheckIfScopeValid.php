<?php

namespace LittleSkin\YggdrasilConnect\Middleware;

use Illuminate\Http\Request;
use LittleSkin\YggdrasilConnect\Exceptions\OAuth\InvalidScopeException;
use LittleSkin\YggdrasilConnect\Scope;

class CheckIfScopeValid
{
    public function handle(Request $request, \Closure $next)
    {
        $scope = $request->input('scope');
        $redirectUri = $request->input('redirect_uri');

        // scope is required per YggC spec
        if (!$scope) {
            return $this->scopeError($redirectUri, $request->input('state'));
        }

        $scopes = explode(' ', $scope);

        // Determine specific error
        $error = null;
        if (array_intersect($scopes, Scope::getAllScopes()) && !in_array(Scope::OPENID, $scopes)) {
            $error = 'Yggdrasil scopes require openid';
        } elseif (in_array(Scope::PROFILE_SELECT, $scopes) && in_array(Scope::PROFILE_READ, $scopes)) {
            $error = 'Cannot request both PROFILE_SELECT and PROFILE_READ';
        } elseif (in_array(Scope::SERVER_JOIN, $scopes) && !in_array(Scope::PROFILE_SELECT, $scopes)) {
            $error = 'SERVER_JOIN requires PROFILE_SELECT';
        }

        if ($error !== null) {
            return $this->scopeError($redirectUri, $request->input('state'), $error);
        }

        return $next($request);
    }

    private function scopeError(?string $redirectUri, ?string $state, string $description = null): mixed
    {
        $exception = new InvalidScopeException($description);
        $query = $exception->toArray();
        if ($state !== null) {
            $query['state'] = $state;
        }

        return redirect()->away($redirectUri.'?'.http_build_query($query));
    }
}
