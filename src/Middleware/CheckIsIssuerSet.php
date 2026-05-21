<?php

namespace LittleSkin\YggdrasilConnect\Middleware;

use Illuminate\Http\Request;
use Illuminate\Http\Response;

class CheckIsIssuerSet
{
    public function handle(Request $request, \Closure $next)
    {
        if (empty(option('site_url'))) {
            abort(Response::HTTP_INTERNAL_SERVER_ERROR, trans('LittleSkin\\YggdrasilConnect::exceptions.yggc.issuer-not-set'));
        }

        return $next($request);
    }
}
