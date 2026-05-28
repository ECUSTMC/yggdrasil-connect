<?php

require __DIR__.'/src/Utils/helpers.php';

use App\Events\PluginWasDisabled;
use App\Events\PluginWasEnabled;
use App\Models\Scope;
use App\Services\Facades\Option;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use LittleSkin\YggdrasilConnect\Scope as OpenIDScope;

return [
    PluginWasEnabled::class => function () {
        if (!Scope::where('name', 'openid')->exists()) {
            Scope::create([
                'name' => 'openid',
                'description' => 'LittleSkin\\YggdrasilConnect::scopes.openid',
            ]);
        }

        if (!Scope::where('name', 'profile')->exists()) {
            Scope::create([
                'name' => 'profile',
                'description' => 'LittleSkin\\YggdrasilConnect::scopes.profile',
            ]);
        }

        if (!Scope::where('name', 'offline_access')->exists()) {
            Scope::create([
                'name' => 'offline_access',
                'description' => 'LittleSkin\\YggdrasilConnect::scopes.offline-access',
            ]);
        }

        if (!Scope::where('name', 'email')->exists()) {
            Scope::create([
                'name' => 'email',
                'description' => 'LittleSkin\\YggdrasilConnect::scopes.email',
            ]);
        }

        if (!Scope::where('name', 'campus_status')->exists()) {
            Scope::create([
                'name' => 'campus_status',
                'description' => 'LittleSkin\\YggdrasilConnect::scopes.campus-status',
            ]);
        }

        if (!Scope::where('name', 'Yggdrasil.PlayerProfiles.Read')->exists()) {
            Scope::create([
                'name' => 'Yggdrasil.PlayerProfiles.Read',
                'description' => 'LittleSkin\\YggdrasilConnect::scopes.player-profiles.read',
            ]);
        }

        if (!Scope::where('name', 'Yggdrasil.PlayerProfiles.Select')->exists()) {
            Scope::create([
                'name' => 'Yggdrasil.PlayerProfiles.Select',
                'description' => 'LittleSkin\\YggdrasilConnect::scopes.player-profiles.select',
            ]);
        }

        if (!Scope::where('name', 'Yggdrasil.Server.Join')->exists()) {
            Scope::create([
                'name' => 'Yggdrasil.Server.Join',
                'description' => 'LittleSkin\\YggdrasilConnect::scopes.server.join',
            ]);
        }

        if (!Schema::hasTable('uuid')) {
            Schema::create('uuid', function (Blueprint $table) {
                $table->increments('id');
                $table->unsignedInteger('pid')->unique();
                $table->foreign('pid')->references('pid')->on('players')->cascadeOnDelete();
                $table->string('name')->unique();
                $table->string('uuid', 255)->unique();
                $table->timestamps();
            });
        }

        if (!Schema::hasTable('ygg_log')) {
            Schema::create('ygg_log', function (Blueprint $table) {
                $table->increments('id');
                $table->string('action');
                $table->integer('user_id');
                $table->integer('player_id');
                $table->string('parameters', 2048)->default('');
                $table->string('ip')->default('');
                $table->dateTime('time');
            });
        }

        if (!Schema::hasTable('campus_status_records')) {
            Schema::create('campus_status_records', function (Blueprint $table) {
                $table->unsignedInteger('uid')->primary();
                $table->string('ip', 45)->nullable();
                $table->timestamp('verified_at')->nullable();
                $table->timestamp('expires_at')->nullable();
            });
        }

        if (!Schema::hasTable('code_id_to_uuid')) {
            Schema::create('code_id_to_uuid', function (Blueprint $table) {
                $table->increments('id');
                $table->string('code_id')->unique();
                $table->foreign('code_id')->references('id')->on('oauth_auth_codes')->cascadeOnDelete();
                $table->string('uuid');
                $table->timestamp('created_at')->useCurrent();
            });
        }

        if (!Schema::hasTable('yggc_authorization_codes')) {
            Schema::create('yggc_authorization_codes', function (Blueprint $table) {
                $table->string('id', 255)->primary();
                $table->json('payload');
                $table->string('uid', 255)->nullable()->unique();
                $table->boolean('consumed')->default(false);
                $table->timestamp('created_at')->useCurrent();
                $table->timestamp('updated_at')->useCurrent()->useCurrentOnUpdate();
            });
        }

        if (!Schema::hasTable('yggc_device_codes')) {
            Schema::create('yggc_device_codes', function (Blueprint $table) {
                $table->string('id', 255)->primary();
                $table->json('payload');
                $table->string('userCode', 191)->nullable();
                $table->string('uid', 255)->nullable()->unique();
                $table->boolean('consumed')->default(false);
                $table->timestamp('created_at')->useCurrent();
                $table->timestamp('updated_at')->useCurrent()->useCurrentOnUpdate();
            });
        }

        if (!Schema::hasTable('yggc_refresh_tokens')) {
            Schema::create('yggc_refresh_tokens', function (Blueprint $table) {
                $table->string('id', 255)->primary();
                $table->json('payload');
                $table->string('uid', 255)->nullable()->unique();
                $table->boolean('consumed')->default(false);
                $table->timestamp('created_at')->useCurrent();
                $table->timestamp('updated_at')->useCurrent()->useCurrentOnUpdate();
            });
        }

        if (!Schema::hasTable('yggc_grants')) {
            Schema::create('yggc_grants', function (Blueprint $table) {
                $table->string('id', 255)->primary();
                $table->json('payload');
                $table->string('uid', 255)->nullable()->unique();
                $table->timestamp('created_at')->useCurrent();
                $table->timestamp('updated_at')->useCurrent()->useCurrentOnUpdate();
            });
        }

        if (!Schema::hasTable('yggc_interactions')) {
            Schema::create('yggc_interactions', function (Blueprint $table) {
                $table->string('id', 255)->primary();
                $table->json('payload');
                $table->string('uid', 255)->nullable()->unique();
                $table->timestamp('created_at')->useCurrent();
                $table->timestamp('updated_at')->useCurrent()->useCurrentOnUpdate();
            });
        }

        if (!Schema::hasTable('yggc_sessions')) {
            Schema::create('yggc_sessions', function (Blueprint $table) {
                $table->string('id', 255)->primary();
                $table->json('payload');
                $table->string('uid', 255)->nullable()->unique();
                $table->timestamp('created_at')->useCurrent();
                $table->timestamp('updated_at')->useCurrent()->useCurrentOnUpdate();
            });
        }

        $items = [
            'ygg_uuid_algorithm' => 'v3',
            'ygg_token_expire_1' => '259200',
            'ygg_token_expire_2' => '604800',
            'ygg_tokens_limit' => '10',
            'ygg_rate_limit' => '1000',
            'ygg_skin_domain' => '',
            'ygg_search_profile_max' => '5',
            'ygg_private_key' => '',
            'ygg_show_config_section' => 'true',
            'ygg_show_activities_section' => 'true',
            'ygg_enable_ali' => 'true',
            'ygg_disable_authserver' => 'false',
            'ygg_device_code_expires_in' => '600',
            'ygg_grant_expires_in' => '86400',
            'ygg_shared_client_id' => '',
            'ygg_enable_campus_status' => 'false',
            'union_api_root' => 'https://skin.mualliance.ltd/api/union',       // MODIFICATION: UNION
            'union_server_list' => '{}',
            'union_member_key' => '',
            'union_server_list_version' => '0',
            'union_private_key_version' => '0',
            'union_enable_update' => true,
            'union_enable_oauth2' => true,
            //'union_use_blacklist_locally' => true
        ];

        foreach ($items as $key => $value) {
            if (!Option::get($key)) {
                Option::set($key, $value);
            }
        }

        $originalDefaultValue = [
            'ygg_token_expire_1' => '600',
            'ygg_token_expire_2' => '1200',
        ];

        // 原来的令牌过期时间默认值太低了，调高点
        foreach ($originalDefaultValue as $key => $value) {
            if (Option::get($key) == $value) {
                Option::set($key, $items[$key]);
            }
        }

        if (!env('YGG_VERBOSE_LOG')) {
            @unlink(storage_path('logs/yggdrasil.log'));
        }

        // 从旧版升级上来的默认继续使用旧的 UUID 生成算法
        if (DB::table('uuid')->count() > 0 && !Option::get('ygg_uuid_algorithm')) {
            Option::set('ygg_uuid_algorithm', 'v4');
        }

        // 初次使用自动生成私钥
        if (option('ygg_private_key') == '') {
            option(['ygg_private_key' => ygg_generate_rsa_keys()['private']]);
        }

        if (option('union_oauth2_sig_private_key', '') === '' || option('union_oauth2_sig_public_key', '') === '') {
            $rsa_keys = ygg_generate_rsa_keys();
            option(['union_oauth2_sig_private_key' => $rsa_keys['private'], 'union_oauth2_sig_public_key' => $rsa_keys['public']]);
        }
    },

    PluginWasDisabled::class => function () {
        Scope::whereIn('name', OpenIDScope::getAllScopes())->get()->each->delete();
    },
];
