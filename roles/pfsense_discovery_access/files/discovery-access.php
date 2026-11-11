<?php
// Model operations only: never change REST API settings, DNS, DHCP, or existing users.
require_once 'RESTAPI/autoloader.inc';

use RESTAPI\Core\Auth;
use RESTAPI\Models\User;
use RESTAPI\Models\RESTAPIKey;

try {
    $input = json_decode(stream_get_contents(STDIN), true, flags: JSON_THROW_ON_ERROR);
    $users = User::query(['name' => $input['username']]);
    $user = $users->exists() ? $users->first() : null;
    $keys = RESTAPIKey::query(['username' => $input['username']])->model_objects;
    $operation = $input['operation'];
    if ($operation === 'inspect') {
        $result = ['user' => null, 'keys' => [], 'valid_key_fingerprint' => null];
        if ($user) {
            $groups = [];
            foreach (config_get_path('system/group', []) as $group) {
                if (in_array((string)$user->uid->value, array_map('strval', (array)($group['member'] ?? [])), true)) {
                    $groups[] = $group['name'];
                }
            }
            $result['user'] = ['owner' => $user->descr->value, 'privileges' => $user->priv->value,
                               'disabled' => $user->disabled->value, 'groups' => $groups];
        }
        foreach ($keys as $key) {
            $result['keys'][] = ['fingerprint' => hash('sha256', $key->hash->value), 'owner' => $key->descr->value];
            if ($input['api_key'] && $key->authenticate($input['api_key'])) {
                $result['valid_key_fingerprint'] = hash('sha256', $key->hash->value);
            }
        }
    } elseif ($operation === 'create_user') {
        if ($user || count($keys)) { throw new Exception('Account appeared concurrently'); }
        $user = new User(data: ['name' => $input['username'], 'password' => bin2hex(random_bytes(32)),
                               'priv' => $input['privileges'], 'descr' => $input['owner']]);
        $user->create();
        $result = new stdClass();
    } elseif ($operation === 'create_key') {
        if (!$user || $user->descr->value !== $input['owner'] || count($keys)) {
            throw new Exception('Account or keys changed concurrently');
        }
        $actual = $user->priv->value; $expected = $input['privileges'];
        sort($actual); sort($expected);
        if ($actual !== $expected || $user->disabled->value) { throw new Exception('Account drift'); }
        $client = new Auth(); $client->username = $input['username']; $client->ip_address = '127.0.0.1';
        $key = new RESTAPIKey(data: ['descr' => $input['owner'], 'length_bytes' => 32], client: $client);
        $key->create();
        $result = ['key_fingerprint' => hash('sha256', $key->hash->value), 'api_key' => $key->key->value];
    } else {
        throw new Exception('Unknown discovery operation');
    }
    echo json_encode($result, JSON_THROW_ON_ERROR);
} catch (Throwable $exception) {
    echo json_encode(['failed' => true]);
}
