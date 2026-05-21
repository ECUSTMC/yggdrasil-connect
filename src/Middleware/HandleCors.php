<?php

namespace LittleSkin\YggdrasilConnect\Middleware;

use Illuminate\Http\Request;
use Illuminate\Http\Response;

class HandleCors
{
    public function handle(Request $request, \Closure $next)
    {
        $corsPaths = [
            'yggc/userinfo',
            '.well-known/openid-configuration',
            'jwks',
            'token',
            'revoke',
            'device/auth',
        ];

        $shouldCors = false;
        foreach ($corsPaths as $path) {
            if ($request->is($path)) {
                $shouldCors = true;
                break;
            }
        }

        if (!$shouldCors) {
            return $next($request);
        }

        if ($this->isPreflightRequest($request)) {
            return response(null)->setStatusCode(Response::HTTP_NO_CONTENT)
                ->header('Access-Control-Allow-Origin', '*')
                ->header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
                ->header('Access-Control-Allow-Headers', '*');
        }

        $response = $next($request);
        $response->header('Access-Control-Allow-Origin', '*');

        return $response;
    }

    private function isPreflightRequest(Request $request): bool
    {
        return $request->isMethod('OPTIONS') && ($request->headers->has('Access-Control-Request-Method') || $request->headers->has('Access-Control-Request-Headers'));
    }
}
