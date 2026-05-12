<?php

namespace App\Protocols;

use App\Models\Server;
use App\Support\AbstractProtocol;
use App\Utils\Helper;

class Anywhere extends AbstractProtocol
{
    public $flags = ['anywhere'];

    public $allowedProtocols = [
        Server::TYPE_VLESS,
        Server::TYPE_HYSTERIA,
        Server::TYPE_TROJAN,
        Server::TYPE_SHADOWSOCKS,
        Server::TYPE_SOCKS,
    ];

    protected $protocolRequirements = [
        '*.hysteria.protocol_settings.version' => [
            'whitelist' => [2],
            'strict' => true,
        ],
    ];

    public function handle()
    {
        $servers = $this->servers;
        $user = $this->user;
        $uri = '';

        foreach ($servers as $item) {
            $uri .= match ($item['type']) {
                Server::TYPE_SHADOWSOCKS => self::buildShadowsocks($item['password'], $item),
                Server::TYPE_VLESS => self::buildVLESS($item['password'], $item),
                Server::TYPE_TROJAN => self::buildTrojan($item['password'], $item),
                Server::TYPE_HYSTERIA => self::buildHysteria($item['password'], $item),
                Server::TYPE_SOCKS => self::buildSOCKS($item['password'], $item),
                default => '',
            };
        }

        return response(base64_encode($uri))
            ->header('content-type', 'text/plain')
            ->header('subscription-userinfo', "upload={$user['u']}; download={$user['d']}; total={$user['transfer_enable']}; expire={$user['expired_at']}");
    }

    public static function buildShadowsocks($password, $server)
    {
        $protocol_settings = $server['protocol_settings'];
        $name = rawurlencode($server['name']);
        $password = data_get($server, 'password', $password);
        $userInfo = str_replace(
            ['+', '/', '='],
            ['-', '_', ''],
            base64_encode(data_get($protocol_settings, 'cipher') . ":{$password}")
        );
        $addr = Helper::wrapIPv6($server['host']);
        return "ss://{$userInfo}@{$addr}:{$server['port']}#{$name}\r\n";
    }

    public static function buildVLESS($uuid, $server)
    {
        $protocol_settings = $server['protocol_settings'];
        $network = data_get($protocol_settings, 'network', 'tcp');
        
        $supportedTransports = ['tcp', 'ws', 'httpupgrade', 'grpc', 'xhttp'];
        if ($network !== null && $network !== '' && !in_array($network, $supportedTransports, true)) {
            return '';
        }

        $config = [
            'encryption' => match (data_get($protocol_settings, 'encryption.enabled')) {
                true => data_get($protocol_settings, 'encryption.encryption', 'none'),
                default => 'none',
            },
            'type' => $network ?: 'tcp',
        ];

        if ($flow = data_get($protocol_settings, 'flow')) {
            $config['flow'] = $flow;
        }

        switch ((int) data_get($protocol_settings, 'tls', 0)) {
            case 1:
                $config['security'] = 'tls';
                if ($sni = data_get($protocol_settings, 'tls_settings.server_name')) {
                    $config['sni'] = $sni;
                }
                if ($fp = Helper::getTlsFingerprint(data_get($protocol_settings, 'utls'))) {
                    $config['fp'] = $fp;
                }
                break;
            case 2:
                $config['security'] = 'reality';
                if ($sni = data_get($protocol_settings, 'reality_settings.server_name')) {
                    $config['sni'] = $sni;
                }
                if ($pbk = data_get($protocol_settings, 'reality_settings.public_key')) {
                    $config['pbk'] = $pbk;
                }
                if ($sid = data_get($protocol_settings, 'reality_settings.short_id')) {
                    $config['sid'] = $sid;
                }
                if ($fp = Helper::getTlsFingerprint(data_get($protocol_settings, 'utls'))) {
                    $config['fp'] = $fp;
                }
                break;
            default:
                $config['security'] = 'none';
                break;
        }

        switch ($network) {
            case 'ws':
                if ($path = data_get($protocol_settings, 'network_settings.path')) {
                    $config['path'] = $path;
                }
                if ($host = data_get($protocol_settings, 'network_settings.headers.Host')) {
                    $config['host'] = $host;
                }
                break;
            case 'httpupgrade':
                if ($path = data_get($protocol_settings, 'network_settings.path')) {
                    $config['path'] = $path;
                }
                if ($host = data_get($protocol_settings, 'network_settings.host', $server['host'])) {
                    $config['host'] = $host;
                }
                break;
            case 'grpc':
                if ($serviceName = data_get($protocol_settings, 'network_settings.serviceName')) {
                    $config['serviceName'] = $serviceName;
                }
                break;
            case 'xhttp':
                if ($path = data_get($protocol_settings, 'network_settings.path')) {
                    $config['path'] = $path;
                }
                if ($host = data_get($protocol_settings, 'network_settings.host', $server['host'])) {
                    $config['host'] = $host;
                }
                if ($mode = data_get($protocol_settings, 'network_settings.mode', 'auto')) {
                    $config['mode'] = $mode;
                }
                break;
        }

        $addr = Helper::wrapIPv6($server['host']);
        $query = http_build_query($config);
        $name = rawurlencode($server['name']);
        return "vless://{$uuid}@{$addr}:{$server['port']}?{$query}#{$name}\r\n";
    }

    public static function buildTrojan($password, $server)
    {
        $protocol_settings = $server['protocol_settings'];
        $network = data_get($protocol_settings, 'network');
        
        if ($network !== null && $network !== '' && $network !== 'tcp') {
            return '';
        }
        if ((int) data_get($protocol_settings, 'tls', 1) === 2) {
            return '';
        }

        $params = [];
        if ($sni = data_get($protocol_settings, 'tls_settings.server_name')) {
            $params['sni'] = $sni;
            $params['peer'] = $sni;
        }
        if ($fp = Helper::getTlsFingerprint(data_get($protocol_settings, 'utls'))) {
            $params['fp'] = $fp;
        }

        $addr = Helper::wrapIPv6($server['host']);
        $name = rawurlencode($server['name']);
        $query = http_build_query($params);
        $separator = $query !== '' ? '?' : '';
        return "trojan://{$password}@{$addr}:{$server['port']}{$separator}{$query}#{$name}\r\n";
    }

    public static function buildHysteria($password, $server)
    {
        $protocol_settings = $server['protocol_settings'];
        $params = [];
        if ($sni = data_get($protocol_settings, 'tls.server_name')) {
            $params['sni'] = $sni;
        }
        if ($upMbps = data_get($protocol_settings, 'bandwidth.up')) {
            $params['upmbps'] = $upMbps;
        }
        if (data_get($protocol_settings, 'obfs.open') && ($obfsPassword = data_get($protocol_settings, 'obfs.password'))) {
            $params['obfs'] = data_get($protocol_settings, 'obfs.type', 'salamander');
            $params['obfs-password'] = $obfsPassword;
        }
        if (isset($server['ports'])) {
            $params['mport'] = $server['ports'];
        }

        $addr = Helper::wrapIPv6($server['host']);
        $name = rawurlencode($server['name']);
        $query = http_build_query($params);
        $separator = $query !== '' ? '?' : '';
        return "hysteria2://{$password}@{$addr}:{$server['port']}{$separator}{$query}#{$name}\r\n";
    }

    public static function buildSOCKS($password, $server)
    {
        $name = rawurlencode($server['name']);
        $addr = Helper::wrapIPv6($server['host']);
        $userInfo = rawurlencode($password) . ':' . rawurlencode($password);
        return "socks5://{$userInfo}@{$addr}:{$server['port']}#{$name}\r\n";
    }
}
