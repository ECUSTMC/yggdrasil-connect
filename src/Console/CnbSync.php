<?php

namespace LittleSkin\YggdrasilConnect\Console;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class CnbSync extends Command
{
    protected $signature = 'yggc:cnb-sync';

    protected $description = 'Trigger CNB pipeline to merge upstream. The plugin is updated via callback.';

    /**
     * CNB OpenAPI 端点。
     * 参考 https://api.cnb.cool/swagger.json
     */
    protected const CNB_API_BASE = 'https://api.cnb.cool';

    public function handle(): void
    {
        $token = (string) option('cnb_token');
        if ($token === '') {
            Log::channel('ygg')->error('CNB update: cnb_token is not configured.');
            $this->error('cnb_token is not configured.');

            return;
        }

        $repo = (string) option('cnb_repo');
        $branch = (string) option('cnb_branch') ?: 'master';

        // CLI 命令没有 HTTP 请求上下文，url() 会回退到 APP_URL/localhost；
        // 回调地址必须以 site_url 为基准生成，否则流水线无法访问本站
        $siteUrl = rtrim((string) option('site_url'), '/');
        if ($siteUrl === '') {
            Log::channel('ygg')->error('CNB update: site_url is not configured, cannot build callback URL.');
            $this->error('site_url is not configured, cannot build callback URL.');

            return;
        }
        $callbackUrl = $siteUrl.'/api/cnb/sync-callback';

        // 触发合并上游的流水线
        $start = Http::withToken($token)
            ->acceptJson()
            ->post(''.self::CNB_API_BASE."/$repo/-/build/start", [
                'event' => 'api_trigger_upstream_sync',
                'branch' => $branch,
                'env' => [
                    'UPSTREAM_URL' => (string) option('cnb_upstream'),
                    'UPSTREAM_REF' => (string) option('cnb_upstream_ref'),
                    'CALLBACK_URL' => $callbackUrl,
                ],
                'sync' => 'false',
            ]);

        if (!$start->ok()) {
            Log::channel('ygg')->error('CNB update: build trigger failed.', [
                'status' => $start->status(),
            ]);
            $this->error("CNB build trigger failed with status {$start->status()}.");

            return;
        }

        $body = $start->json();
        $sn = $body['sn'] ?? null;
        if (!$sn) {
            Log::channel('ygg')->error('CNB update: build trigger response missing sn.');
            $this->error('CNB build trigger response missing sn.');

            return;
        }

        Log::channel('ygg')->info('CNB update: build triggered.', ['sn' => $sn]);
        $this->info("CNB build triggered: $sn");
        $this->info('Plugin will be updated via callback after the pipeline succeeds.');
    }
}
