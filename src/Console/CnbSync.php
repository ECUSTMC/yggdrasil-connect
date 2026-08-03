<?php

namespace LittleSkin\YggdrasilConnect\Console;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class CnbSync extends Command
{
    protected $signature = 'yggc:cnb-sync';

    protected $description = 'Trigger CNB pipeline to merge upstream and pull the update locally.';

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

        // 1. 触发合并上游的流水线
        $start = Http::withToken($token)
            ->acceptJson()
            ->post(''.self::CNB_API_BASE."/$repo/-/build/start", [
                'event' => 'api_trigger_upstream_sync',
                'branch' => $branch,
                'env' => [
                    'UPSTREAM_URL' => (string) option('cnb_upstream'),
                    'UPSTREAM_REF' => (string) option('cnb_upstream_ref'),
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

        // 2. 轮询构建状态，最多等待 10 分钟（与流水线构建耗时匹配）
        $deadline = time() + 600;
        $status = null;
        $lastHttpOk = false;
        $reachedTerminal = false;
        while (time() < $deadline) {
            $res = Http::withToken($token)
                ->acceptJson()
                ->get(''.self::CNB_API_BASE."/$repo/-/build/status/$sn");

            if ($res->ok()) {
                $lastHttpOk = true;
                $status = $res->json('status') ?: null;
                // 终态：success / error / cancel
                if (in_array($status, ['success', 'error', 'cancel', 'failed'], true)) {
                    $reachedTerminal = true;
                    break;
                }
            } else {
                Log::channel('ygg')->warning('CNB update: build status request failed.', [
                    'status' => $res->status(),
                    'sn' => $sn,
                ]);
            }
            sleep(5);
        }

        if ($status !== 'success') {
            if (!$reachedTerminal || !$lastHttpOk) {
                // 始终无法查询到状态，或构建未在期限内到达终态，视为超时
                Log::channel('ygg')->error('CNB update: build status unreachable or timed out.', [
                    'sn' => $sn,
                ]);
                $this->error("CNB build status unreachable or timed out (sn=$sn).");

                return;
            }
            // 构建失败（含合并冲突，冲突时流水线会创建 Issue）
            Log::channel('ygg')->error('CNB update: build did not succeed.', [
                'status' => $status,
                'sn' => $sn,
            ]);
            $this->error("CNB build did not succeed (status=$status, sn=$sn).");

            return;
        }

        // 3. 本地 git pull 应用更新
        if (!$this->gitPull()) {
            Log::channel('ygg')->error('CNB update: git pull failed, plugin not updated.', [
                'sn' => $sn,
            ]);
            $this->error('git pull failed, plugin not updated.');

            return;
        }
        Log::channel('ygg')->info('CNB update: plugin updated successfully.', [
            'repo' => $repo,
            'branch' => $branch,
            'sn' => $sn,
        ]);
        $this->info('CNB update completed.');
    }

    /**
     * 在插件目录执行 git pull 拉取已合并的更新。
     * 仅在流水线构建成功（上游已合并并推送）后调用。
     */
    protected function gitPull(): bool
    {
        $dir = plugin('yggdrasil-connect')->getPath();

        // 校验本地仓库与配置的 CNB 仓库/分支一致，避免 pull 到错误对象
        $branch = (string) option('cnb_branch') ?: 'master';
        $repo = (string) option('cnb_repo');

        $ok = $this->runGit($dir, ['rev-parse', '--abbrev-ref', 'HEAD'], function (string $out) use ($branch) {
            if (trim($out) !== $branch) {
                Log::channel('ygg')->error('CNB update: local branch does not match cnb_branch.', [
                    'branch' => trim($out),
                ]);
                $this->error('Local plugin branch does not match cnb_branch.');

                return false;
            }

            return true;
        }, function () {
            $this->error('git rev-parse failed.');
        });
        if (!$ok) {
            return false;
        }

        if ($repo !== '') {
            $ok = $this->runGit($dir, ['remote', 'get-url', 'origin'], function (string $out) use ($repo) {
                $url = strtolower(trim($out));
                // 规范化：去掉协议/认证/主机与 .git 后缀，仅比对仓库路径
                $path = parse_url($url, PHP_URL_PATH) ?: $url;
                $path = preg_replace('/\.git$/', '', rtrim($path, '/'));
                $path = ltrim($path, '/');
                $expected = strtolower(trim($repo, '/'));
                if ($path !== $expected) {
                    Log::channel('ygg')->error('CNB update: local origin does not match cnb_repo.', [
                        'origin' => $path,
                    ]);
                    $this->error('Local plugin origin does not match cnb_repo.');

                    return false;
                }

                return true;
            }, function () {
                $this->error('git remote get-url failed.');
            });
            if (!$ok) {
                return false;
            }
        }

        $ok = $this->runGit($dir, ['pull', '--ff-only'], null, function (string $stderr) {
            Log::channel('ygg')->error('CNB update: git pull failed.', ['stderr' => $stderr]);
            $this->error('git pull failed.');
        });

        return $ok;
    }

    /**
     * 执行 git 命令，可选 stdout/stderr 回调。
     * 返回 false 表示命令失败或 onStdout 回调返回 false。
     */
    protected function runGit(string $dir, array $args, ?callable $onStdout = null, ?callable $onError = null): bool
    {
        $cmd = array_merge(['git', '-C', $dir], $args);
        $proc = proc_open($cmd, [
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ], $pipes);

        if (!is_resource($proc)) {
            $this->error('Failed to start git command.');

            return false;
        }

        $stdout = stream_get_contents($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $code = proc_close($proc);

        if ($code !== 0) {
            if ($onError !== null) {
                $onError($stderr);
            } else {
                Log::channel('ygg')->error('CNB update: git command failed.', ['stderr' => $stderr]);
            }

            return false;
        }

        if ($onStdout !== null) {
            $result = $onStdout($stdout);
            if ($result === false) {
                return false;
            }
        }

        return true;
    }
}
