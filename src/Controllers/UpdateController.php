<?php

namespace LittleSkin\YggdrasilConnect\Controllers;

use Illuminate\Routing\Controller;
use App\Services\Plugin;
use App\Services\PluginManager;
use App\Services\Unzip;
use Composer\CaBundle\CaBundle;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class UpdateController extends Controller {
    /**
     * 处理联盟下发的「更新插件」请求。
     *
     * 当开启 cnb_enable 时：
     *   立即向联盟返回 200（受理成功），并通过后台 artisan 命令
     *   （yggc:cnb-sync）触发 CNB 流水线合并上游，成功后本地 git pull。
     *   冲突/失败由 CNB 流水线自动建 Issue，插件仅记录日志。
     * 未开启 cnb_enable 时保持原有行为：下载 zip 覆盖插件目录。
     */
    public function update(Request $request, PluginManager $manager, Unzip $unzip) {
        if (!option('union_enable_update')) {
            // 与旧版行为保持一致：禁用更新时静默返回，不向联盟报错
            return;
        }

        $data = $request->validate(['url' => 'required|url:http,https', 'plugin' => 'filled|string']);

        // MODIFICATION: CNB-GIT-UPDATE
        if (option('cnb_enable')) {
            $this->dispatchCnbSync();
            return;
        }

        $path = tempnam(sys_get_temp_dir(), 'wget-plugin');
        $response = Http::withOptions([
            'sink' => $path,
            'verify' => CaBundle::getSystemCaRootBundlePath(),
        ])->get($data['url']);

        if ($response->ok()) {
            $unzip->extract($path, $manager->getPluginsDirs()->first());
            $plugin = plugin('yggdrasil-connect');
            $manager->disable($plugin);
            $manager->enable($plugin);
            return;
        }
        abort($response->status());
    }

    /**
     * 以后台进程方式启动 yggc:cnb-sync 命令并立即返回。
     * 优先用 exec + nohup 实现完全脱离（避免 PHP-FPM 下子进程变僵尸）；
     * 若 exec 不可用则回退 proc_open（stdin/stdout/stderr 指向文件，不等待）。
     */
    protected function dispatchCnbSync(): void
    {
        $token = (string) option('cnb_token');
        if ($token === '') {
            abort(500, 'CNB update enabled but cnb_token is not configured.');
        }

        $php = (string) option('cnb_php_path') ?: 'php';
        $artisan = base_path('artisan');
        $logPath = storage_path('logs/ygg-cnb-sync.log');

        $isWindows = PHP_OS_FAMILY === 'Windows';

        // 1) 首选 exec + nohup：子进程完全脱离父进程，退出后不会变僵尸。
        //    nohup/`>> &` 是 POSIX shell 语法，仅 Linux/macOS 可用。
        if (!$isWindows) {
            $cmd = 'nohup '.escapeshellarg($php).' '.escapeshellarg($artisan).' yggc:cnb-sync >> '.escapeshellarg($logPath).' 2>&1 &';

            $execDisabled = in_array('exec', array_map('trim', explode(',', ini_get('disable_functions'))), true);

            if (!$execDisabled && function_exists('exec')) {
                exec($cmd, $output, $code);
                if ($code === 0) {
                    Log::channel('ygg')->info('CNB update: yggc:cnb-sync dispatched (exec).', [
                        'php' => $php,
                        'log' => $logPath,
                    ]);

                    return;
                }
                Log::channel('ygg')->warning('CNB update: exec dispatch failed, falling back to proc_open.', [
                    'code' => $code,
                ]);
            }
        }

        // 2) 回退 proc_open：描述符指向文件，子进程不因管道阻塞；
        //    不调用 proc_close()（会阻塞等待子进程退出）。
        $nullDev = $isWindows ? 'NUL' : '/dev/null';
        $proc = proc_open([$php, $artisan, 'yggc:cnb-sync'], [
            0 => ['file', $nullDev, 'r'],
            1 => ['file', $logPath, 'a'],
            2 => ['file', $logPath, 'a'],
        ], $pipes);

        if (!is_resource($proc)) {
            Log::channel('ygg')->error('CNB update: failed to start yggc:cnb-sync.', ['cmd' => [$php, $artisan]]);
            abort(500, 'Failed to start CNB sync process.');
        }

        Log::channel('ygg')->info('CNB update: yggc:cnb-sync dispatched (proc_open).', [
            'php' => $php,
            'log' => $logPath,
        ]);
    }

    /**
     * CNB 流水线合并并推送上游更新后回调本端点。
     * 校验由 VerifyCnbCallback 中间件完成；这里直接执行本地 git pull。
     */
    public function cnbCallback(Request $request)
    {
        $this->gitPull();

        return response()->json(['code' => 0, 'message' => 'ok']);
    }

    /**
     * 在插件目录执行 git pull 拉取已合并的更新。
     * 校验本地分支/远端与配置一致，避免 pull 到错误对象。
     */
    protected function gitPull(): void
    {
        $dir = plugin('yggdrasil-connect')->getPath();
        if (empty($dir)) {
            Log::channel('ygg')->error('CNB update: plugin path is empty.');
            abort(500, 'Plugin path is empty.');
        }

        $branch = (string) option('cnb_branch') ?: 'master';
        $repo = (string) option('cnb_repo');
        if ($repo === '') {
            Log::channel('ygg')->error('CNB update: cnb_repo is not configured.');
            abort(500, 'cnb_repo is not configured.');
        }

        $ok = $this->runGit($dir, ['rev-parse', '--abbrev-ref', 'HEAD'], function (string $out) use ($branch) {
            if (trim($out) !== $branch) {
                Log::channel('ygg')->error('CNB update: local branch does not match cnb_branch.', [
                    'branch' => trim($out),
                ]);
                abort(500, 'Local plugin branch does not match cnb_branch.');
            }
        });
        if (!$ok) {
            abort(500, 'git rev-parse failed.');
        }

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
                abort(500, 'Local plugin origin does not match cnb_repo.');
            }
        });
        if (!$ok) {
            abort(500, 'git remote get-url failed.');
        }

        $ok = $this->runGit($dir, ['pull', '--ff-only'], null, function (string $stderr) {
            Log::channel('ygg')->error('CNB update: git pull failed.', ['stderr' => $stderr]);
            abort(500, 'git pull failed.');
        });
        if (!$ok) {
            abort(500, 'git pull failed.');
        }
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
            Log::channel('ygg')->error('CNB update: failed to start git command.', ['args' => $args]);
            abort(500, 'Failed to start git command.');
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
