<?php

namespace LittleSkin\YggdrasilConnect\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;

class VerifyCnbCallback
{
    /**
     * 校验 CNB 流水线回调请求。
     *
     * 流水线在合并并推送上游更新后，会携带 X-CNB-Callback-Token 请求
     * /api/cnb/sync-callback；本中间件校验该 token 与配置的
     * cnb_callback_secret 一致，防止未授权请求触发本地 git 强制同步。
     */
    public function handle(Request $request, Closure $next)
    {
        $secret = (string) option('cnb_callback_secret');
        if ($secret === '') {
            // 未配置时与校验失败表现一致，避免向匿名请求者泄露配置状态
            Log::channel('ygg')->warning('CNB callback: cnb_callback_secret is not configured.');

            return response()->json(['code' => 1, 'message' => 'forbidden'], 403);
        }

        $token = $request->header('X-CNB-Callback-Token', '');
        if (!hash_equals($token, $secret)) {
            // 失败时短暂延迟，减缓在线暴力尝试
            usleep(300000);
            Log::channel('ygg')->warning('CNB callback: invalid token.');

            return response()->json(['code' => 1, 'message' => 'forbidden'], 403);
        }

        return $next($request);
    }
}
