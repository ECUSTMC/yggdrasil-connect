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
}
