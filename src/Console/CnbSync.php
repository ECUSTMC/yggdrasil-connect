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

        // 触发合并上游的流水线
        $start = Http::withToken($token)
            ->acceptJson()
            ->post(''.self::CNB_API_BASE."/$repo/-/build/start", [
                'event' => 'api_trigger_upstream_sync',
                'branch' => $branch,
                'env' => [
                    'UPSTREAM_URL' => (string) option('cnb_upstream'),
                    'UPSTREAM_REF' => (string) option('cnb_upstream_ref'),
                    'CALLBACK_URL' => url('/api/cnb/sync-callback'),
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
