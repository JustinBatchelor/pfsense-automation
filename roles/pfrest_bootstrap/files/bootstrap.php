<?php
// JSON in/out. Secrets are only sent via stdin/stdout inside no_log Ansible tasks.
require_once 'RESTAPI/autoloader.inc';

use RESTAPI\Core\Auth;
use RESTAPI\Models\User;
use RESTAPI\Models\RESTAPIKey;
use RESTAPI\Models\RESTAPISettings;

function atomic_json($path, $value) {
    $tmp = $path . '.tmp.' . getmypid();
    $old = umask(0077);
    file_put_contents($tmp, json_encode($value), LOCK_EX);
    chmod($tmp, 0600);
    rename($tmp, $path);
    umask($old);
}

try {
    $input = json_decode(stream_get_contents(STDIN), true, flags: JSON_THROW_ON_ERROR);
    $check = $input['check'];
    $marker = '/conf/aap-pfsense-dns-ownership.json';
    $pending_file = '/conf/aap-pfsense-dns-pending.json';
    $key = $input['api_key'];
    $changed = false;
    $settings = new RESTAPISettings();
    $current = $settings->to_representation();
    $desired = [
        'enabled' => true, 'read_only' => false, 'keep_backup' => true,
        'login_protection' => true,
        'auth_methods' => array_values(array_unique(array_merge($current['auth_methods'], ['KeyAuth']))),
        'allowed_interfaces' => array_values(array_unique(array_merge($current['allowed_interfaces'], $input['interfaces']))),
    ];
    $delta = [];
    foreach ($desired as $field => $value) {
        if ($current[$field] !== $value) { $delta[$field] = $value; }
    }
    if ($delta) {
        $changed = true;
        if (!$check) {
            $settings->from_representation($delta);
            $settings->update();
        }
    }
    if ($input['managed']) {
        $username = $input['username'];
        $privileges = [
            'api-v2-services-dns-resolver-host-overrides-get',
            'api-v2-services-dns-resolver-host-override-get',
            'api-v2-services-dns-resolver-host-override-post',
            'api-v2-services-dns-resolver-host-override-patch',
            'api-v2-services-dns-resolver-host-override-delete',
            'api-v2-services-dns-resolver-apply-get',
            'api-v2-services-dns-resolver-apply-post',
        ];
        $description = $input['owner'];
        $users = User::query(['name' => $username]);
        if (!$users->exists()) {
            $changed = true;
            if (!$check) {
                $user = new User(data: ['name'=>$username, 'password'=>bin2hex(random_bytes(32)),
                                       'priv'=>$privileges, 'descr'=>$description]);
                $user->create();
            }
        } else {
            $user = $users->first();
            $representation = $user->to_representation();
            if ($representation['descr'] !== $description) {
                throw new Exception('Refusing to take over a preexisting service account');
            }
            $actual_privileges = $representation['priv'];
            sort($actual_privileges); $expected_privileges = $privileges; sort($expected_privileges);
            if ($actual_privileges !== $expected_privileges || $representation['disabled']) {
                $changed = true;
                if (!$check) {
                    $user->from_representation(['priv'=>$privileges, 'disabled'=>false]);
                    $user->update();
                }
            }
        }
        $pending = is_file($pending_file) ? json_decode(file_get_contents($pending_file), true) : null;
        if (!$key && $pending && $pending['owner'] === $input['owner']) {
            $key = $pending['api_key'];
        }
        $valid = false;
        foreach (RESTAPIKey::query(['username'=>$username])->model_objects as $candidate) {
            if ($key && $candidate->authenticate($key)) { $valid = true; break; }
        }
        if (!$valid) {
            if ($key) { throw new Exception('Supplied managed API key is invalid; explicit credential recovery required'); }
            $ownership = json_decode(file_get_contents($marker), true);
            if (($ownership['status'] ?? '') === 'enrolled') {
                throw new Exception('Enrolled installation requires its existing AAP credential; refusing automatic key rotation');
            }
            $changed = true;
            if (!$check) {
                $client = new Auth(); $client->username = $username; $client->ip_address = '127.0.0.1';
                $model = new RESTAPIKey(data: ['descr'=>$description, 'length_bytes'=>32], client: $client);
                $model->create();
                $key = $model->key->value;
                atomic_json($pending_file, ['owner'=>$input['owner'], 'api_key'=>$key]);
            }
        }
        if ($input['commit'] && !$check) {
            if (!$key) { throw new Exception('Cannot commit enrollment without a usable key'); }
            $ownership = json_decode(file_get_contents($marker), true);
            if (($ownership['status'] ?? '') !== 'enrolled') {
                atomic_json($marker, ['owner'=>$input['owner'], 'status'=>'enrolled']);
                $changed = true;
            }
            if (is_file($pending_file)) { unlink($pending_file); }
        }
    }
    echo json_encode(['changed'=>$changed, 'api_key'=>$key, 'enrollment_required'=>is_file($pending_file)]);
} catch (Throwable $exception) {
    echo json_encode(['failed'=>true, 'msg'=>$exception->getMessage()]);
    exit(0);
}
