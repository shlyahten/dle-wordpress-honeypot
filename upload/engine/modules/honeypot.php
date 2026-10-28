<?php
/*
=====================================================
 WordPress Honeypot & Threat Intelligence for DLE
-----------------------------------------------------
 Use: Core detection, mimicry and mitigation engine
 (Compliant with DLE Topic 72 Module Architecture)
-----------------------------------------------------
 License: MIT License
=====================================================
*/

if (!defined('ROOT_DIR')) {
    define('ROOT_DIR', dirname(dirname(__DIR__)));
}
if (!defined('ENGINE_DIR')) {
    define('ENGINE_DIR', ROOT_DIR . '/engine');
}

class SiteHoneypot
{
    private static $configFile = ENGINE_DIR . '/data/honeypot_config.json';
    private static $logFile    = ENGINE_DIR . '/data/honeypot.log';
    private static $gzipFile   = ROOT_DIR . '/wp-admin/admin.gzip';

    /**
     * Get or initialize configuration
     */
    public static function getConfig(): array
    {
        $defaultConfig = [
            'mode'           => 'hybrid', // 'hybrid' | 'bomb' | 'tarpit' | 'deception'
            'tarpit_seconds' => 15,
            'log_enabled'    => true,
            'block_in_dle'   => false,
        ];

        if (file_exists(self::$configFile)) {
            $data = @json_decode(file_get_contents(self::$configFile), true);
            if (is_array($data)) {
                return array_merge($defaultConfig, $data);
            }
        }

        return $defaultConfig;
    }

    /**
     * Save configuration
     */
    public static function saveConfig(array $config): bool
    {
        $existing = self::getConfig();
        $merged = array_merge($existing, $config);
        return (bool) @file_put_contents(
            self::$configFile,
            json_encode($merged, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE),
            LOCK_EX
        );
    }

    /**
     * Check if client is a legitimate search engine or crawler
     */
    public static function isSearchEngine(?string $ua = null): bool
    {
        $ua = $ua ?? ($_SERVER['HTTP_USER_AGENT'] ?? '');
        if (empty($ua)) {
            return false;
        }

        $crawlers = [
            'googlebot', 'google-extended', 'mediapartners-google', 'adsbot-google',
            'yandexbot', 'yandeximages', 'yandexaccessibilitybot', 'yandexmobilebot', 'yandexmetrika',
            'bingbot', 'msnbot', 'bingpreview',
            'duckduckbot', 'baiduspider', 'sogou', 'seznam', 'mail.ru_bot',
            'applebot', 'applebot-extended',
            'gptbot', 'chatgpt-user', 'claudebot', 'anthropic-ai', 'perplexitybot'
        ];

        $pattern = '/' . implode('|', $crawlers) . '/i';
        return (bool) preg_match($pattern, $ua);
    }

    /**
     * Get real client IP address considering reverse proxies & Cloudflare
     */
    public static function getRealIP(): string
    {
        $headers = [
            'HTTP_CF_CONNECTING_IP',
            'HTTP_X_REAL_IP',
            'HTTP_X_FORWARDED_FOR',
            'REMOTE_ADDR'
        ];

        foreach ($headers as $header) {
            if (!empty($_SERVER[$header])) {
                $ip = trim($_SERVER[$header]);
                if (str_contains($ip, ',')) {
                    $ip = trim(explode(',', $ip)[0]);
                }
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }

        return '127.0.0.1';
    }

    /**
     * Write attack log entry safely with rotation
     */
    public static function logAttack(string $type, array $data = []): void
    {
        $config = self::getConfig();
        if (empty($config['log_enabled'])) {
            return;
        }

        $ip = self::getRealIP();
        $date = date('Y-m-d H:i:s');
        $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
        $uri = $_SERVER['REQUEST_URI'] ?? '/';
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
        $user = $data['user'] ?? '-';
        $pass = $data['pass'] ?? '-';
        $action = $data['action'] ?? $type;

        $logLine = sprintf(
            "[%s] IP: %s | METHOD: %s | URI: %s | LOGIN: %s | PASS: %s | ACTION: %s | UA: %s\n",
            $date, $ip, $method, $uri, $user, $pass, $action, $ua
        );

        @file_put_contents(self::$logFile, $logLine, FILE_APPEND | LOCK_EX);

        // Simple log rotation if larger than 5MB
        if (@filesize(self::$logFile) > 5 * 1024 * 1024) {
            self::rotateLog();
        }
    }

    /**
     * Rotate log keeping the last 2000 lines
     */
    private static function rotateLog(): void
    {
        if (!file_exists(self::$logFile)) {
            return;
        }

        $lines = @file(self::$logFile);
        if ($lines && count($lines) > 2000) {
            $keep = array_slice($lines, -2000);
            @file_put_contents(self::$logFile, implode('', $keep), LOCK_EX);
        }
    }

    /**
     * Read attack log with optional limit and search
     */
    public static function getLog(int $limit = 50, ?string $search = null): array
    {
        if (!file_exists(self::$logFile)) {
            return [];
        }

        $lines = @file(self::$logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if (!$lines) {
            return [];
        }

        $results = [];
        $pattern = '/^\[(.*?)\] IP: (.*?) \| METHOD: (.*?) \| URI: (.*?) \| LOGIN: (.*?) \| PASS: (.*?) \| ACTION: (.*?) \| UA: (.*?)$/';

        for ($i = count($lines) - 1; $i >= 0; $i--) {
            $line = $lines[$i];
            if ($search && stripos($line, $search) === false) {
                continue;
            }

            if (preg_match($pattern, $line, $m)) {
                $results[] = [
                    'date'   => $m[1],
                    'ip'     => $m[2],
                    'method' => $m[3],
                    'uri'    => $m[4],
                    'login'  => $m[5],
                    'pass'   => $m[6],
                    'action' => $m[7],
                    'ua'     => $m[8],
                ];
            }

            if (count($results) >= $limit) {
                break;
            }
        }

        return $results;
    }

    /**
     * Get aggregate statistics from log
     */
    public static function getStats(): array
    {
        if (!file_exists(self::$logFile)) {
            return [
                'total_attacks' => 0,
                'unique_ips'    => 0,
                'log_size'      => 0,
                'top_ips'       => [],
                'top_passwords' => [],
                'top_logins'    => [],
            ];
        }

        $lines = @file(self::$logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if (!$lines) {
            return [
                'total_attacks' => 0,
                'unique_ips'    => 0,
                'log_size'      => @filesize(self::$logFile) ?: 0,
                'top_ips'       => [],
                'top_passwords' => [],
                'top_logins'    => [],
            ];
        }

        $ips = [];
        $logins = [];
        $passwords = [];
        $pattern = '/^\[(.*?)\] IP: (.*?) \| METHOD: (.*?) \| URI: (.*?) \| LOGIN: (.*?) \| PASS: (.*?) \| ACTION: (.*?) \| UA: (.*?)$/';

        foreach ($lines as $line) {
            if (preg_match($pattern, $line, $m)) {
                $ip = $m[2];
                $login = $m[5];
                $pass = $m[6];

                $ips[$ip] = ($ips[$ip] ?? 0) + 1;
                if ($login !== '-') {
                    $logins[$login] = ($logins[$login] ?? 0) + 1;
                }
                if ($pass !== '-') {
                    $passwords[$pass] = ($passwords[$pass] ?? 0) + 1;
                }
            }
        }

        arsort($ips);
        arsort($logins);
        arsort($passwords);

        return [
            'total_attacks' => count($lines),
            'unique_ips'    => count($ips),
            'log_size'      => @filesize(self::$logFile) ?: 0,
            'top_ips'       => array_slice($ips, 0, 10, true),
            'top_logins'    => array_slice($logins, 0, 10, true),
            'top_passwords' => array_slice($passwords, 0, 10, true),
        ];
    }

    /**
     * Clear attack log
     */
    public static function clearLog(): bool
    {
        if (file_exists(self::$logFile)) {
            return (bool) @file_put_contents(self::$logFile, '', LOCK_EX) !== false;
        }
        return true;
    }

    /**
     * Detonate gzip bomb if client supports gzip, otherwise serve standard block
     */
    public static function serveGzipBomb(): void
    {
        $acceptEncoding = $_SERVER['HTTP_ACCEPT_ENCODING'] ?? '';

        if (stripos($acceptEncoding, 'gzip') !== false && file_exists(self::$gzipFile)) {
            $size = @filesize(self::$gzipFile);
            header("Content-Encoding: gzip");
            header("Content-Type: text/html; charset=UTF-8");
            if ($size) {
                header("Content-Length: " . $size);
            }
            while (ob_get_level()) {
                ob_end_clean();
            }
            @readfile(self::$gzipFile);
            exit;
        }

        // If client doesn't accept gzip, don't waste 10MB of bandwidth!
        http_response_code(403);
        header("Content-Type: text/html; charset=UTF-8");
        echo '<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body><h1>403 Forbidden</h1><p>Access denied.</p></body></html>';
        exit;
    }

    /**
     * HTTP Tarpit (Slowloris defense) — holds connection open, wasting bot worker threads
     */
    public static function serveTarpit(int $seconds = 15): void
    {
        @ini_set('output_buffering', 'off');
        @ini_set('zlib.output_compression', 'off');
        while (ob_get_level()) {
            ob_end_clean();
        }

        http_response_code(200);
        header("Content-Type: text/html; charset=UTF-8");
        header("Transfer-Encoding: chunked");
        header("X-Accel-Buffering: no");

        $start = time();
        while (time() - $start < $seconds) {
            echo " \r\n";
            @flush();
            sleep(2);
        }

        echo "0\r\n\r\n";
        exit;
    }

    /**
     * Render authentic WordPress 6.x Login Form
     */
    public static function renderLoginForm(?string $errorMsg = null): void
    {
        header("Content-Type: text/html; charset=UTF-8");
        header("X-Powered-By: PHP/" . PHP_VERSION);
        header("X-Robots-Tag: noindex, nofollow");
        setcookie('wordpress_test_cookie', 'WP+Cookie+check', time() + 3600, '/', '', false, true);

        $errorHtml = '';
        if ($errorMsg) {
            $errorHtml = '<div id="login_error" class="notice notice-error"><p>' . htmlspecialchars($errorMsg, ENT_QUOTES, 'UTF-8') . '</p></div>';
        }

        $siteName = htmlspecialchars($_SERVER['HTTP_HOST'] ?? 'WordPress', ENT_QUOTES, 'UTF-8');

        echo <<<HTML
<!DOCTYPE html>
<html lang="ru-RU">
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <title>Войти &lsaquo; {$siteName} &mdash; WordPress</title>
    <meta name="robots" content="max-image-preview:large, noindex, nofollow" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <style>
        body {
            background: #f0f0f1;
            color: #3c434a;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif;
            font-size: 13px;
            line-height: 1.4;
            margin: 0;
            padding: 0;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
        }
        #login {
            width: 320px;
            padding: 8% 0 0;
            margin: auto;
        }
        .login-logo {
            text-align: center;
            margin-bottom: 25px;
        }
        .login-logo svg {
            width: 84px;
            height: 84px;
            fill: #0073aa;
        }
        .login form {
            background: #fff;
            border: 1px solid #c3c4c7;
            box-shadow: 0 1px 3px rgba(0,0,0,.04);
            padding: 26px 24px 34px;
            margin-bottom: 16px;
        }
        .login label {
            color: #2c3338;
            font-size: 14px;
            display: block;
            margin-bottom: 8px;
        }
        .login input[type="text"], .login input[type="password"] {
            font-size: 24px;
            line-height: 1.33333333;
            width: 100%;
            border: 1px solid #8c8f94;
            padding: 3px 5px;
            margin: 0 6px 16px 0;
            box-sizing: border-box;
            border-radius: 4px;
        }
        .login input[type="text"]:focus, .login input[type="password"]:focus {
            border-color: #2271b1;
            box-shadow: 0 0 0 1px #2271b1;
            outline: 2px solid transparent;
        }
        .forgetmenot {
            float: left;
            font-weight: 400;
        }
        .submit {
            float: right;
            margin: 0;
        }
        .button-primary {
            background: #2271b1;
            border-color: #2271b1;
            color: #fff;
            padding: 4px 12px;
            font-size: 13px;
            min-height: 32px;
            border-radius: 3px;
            cursor: pointer;
            border-width: 1px;
            border-style: solid;
        }
        .button-primary:hover {
            background: #135e96;
            border-color: #135e96;
        }
        .notice-error {
            background: #fff;
            border-left: 4px solid #d63638;
            box-shadow: 0 1px 1px 0 rgba(0,0,0,.1);
            margin: 0 0 16px;
            padding: 12px;
        }
        #nav, #backtoblog {
            font-size: 13px;
            padding: 0 24px 12px;
            text-align: center;
        }
        #nav a, #backtoblog a {
            color: #50575e;
            text-decoration: none;
        }
        #nav a:hover, #backtoblog a:hover {
            color: #135e96;
        }
        .clear { clear: both; }
    </style>
</head>
<body class="login">
<div id="login">
    <div class="login-logo">
        <a href="https://wordpress.org/">
            <svg viewBox="0 0 1000 1000" xmlns="http://www.w3.org/2000/svg">
                <path d="M10 500a490 490 0 1 0 980 0 490 490 0 0 0-980 0zm38 0c0-67 15-131 43-189l261 715A452 452 0 0 1 48 500zm452 452c-46 0-90-7-131-20l140-406 143 392c0 2-5 13-7 15a450 450 0 0 1-145 19zm73-581c19-1 37-3 37-3 17-2 15-27-2-26 0 0-54 4-89 4-33 0-88-4-88-4-17-1-19 25-2 26 0 0 18 2 35 3l52 143-74 222-126-365c19-1 37-3 37-3 17-2 15-27-2-26 0 0-54 4-89 4-10 0-23 0-36-1 74-123 207-206 360-206 82 0 158 24 222 66-5 1-10 1-15 1-33 0-57 29-57 59 0 26 15 48 31 74 13 22 29 49 29 90 0 32-12 70-30 115l-33 97zm173-131c38 64 61 138 61 218 0 85-26 163-71 228l-145-420c24-69 41-118 41-144 0-33-12-50-25-66-18-22-35-43-35-77 0-6 1-12 2-18 84 56 148 144 172 279z"/>
            </svg>
        </a>
    </div>
    {$errorHtml}
    <form name="loginform" id="loginform" action="/wp-login.php" method="post">
        <p>
            <label for="user_login">Имя пользователя или e-mail</label>
            <input type="text" name="log" id="user_login" class="input" value="" size="20" autocapitalize="off" autocomplete="username" required="required" />
        </p>
        <p>
            <label for="user_pass">Пароль</label>
            <input type="password" name="pwd" id="user_pass" class="input password-input" value="" size="20" autocomplete="current-password" required="required" />
        </p>
        <p class="forgetmenot">
            <label><input name="rememberme" type="checkbox" id="rememberme" value="forever" /> Запомнить меня</label>
        </p>
        <p class="submit">
            <input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="Войти" />
        </p>
        <div class="clear"></div>
    </form>
    <p id="nav"><a href="/wp-login.php?action=lostpassword">Забыли пароль?</a></p>
    <p id="backtoblog"><a href="/">&larr; Перейти к {$siteName}</a></p>
</div>
</body>
</html>
HTML;
        exit;
    }

    /**
     * Handle WordPress XML-RPC endpoint (/xmlrpc.php)
     */
    public static function handleXMLRPC(): void
    {
        if (self::isSearchEngine()) {
            http_response_code(404);
            header("X-Robots-Tag: noindex, nofollow");
            echo "Not Found";
            exit;
        }

        $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

        if ($method === 'GET') {
            header("Content-Type: text/plain; charset=UTF-8");
            header("X-Robots-Tag: noindex, nofollow");
            echo "XML-RPC server accepts POST requests only.";
            exit;
        }

        // On POST: parse payload to inspect what the attacker is probing
        $rawPost = @file_get_contents('php://input');
        $probedMethod = 'unknown';
        $user = '-';
        $pass = '-';

        if ($rawPost) {
            if (preg_match('/<methodName>(.*?)<\/methodName>/i', $rawPost, $m)) {
                $probedMethod = trim($m[1]);
            }
            // Check for credentials in multicall or wp.getUsersBlogs
            if (preg_match_all('/<string>(.*?)<\/string>/i', $rawPost, $matches)) {
                $strings = $matches[1];
                if (count($strings) >= 2) {
                    $user = $strings[0];
                    $pass = $strings[1];
                }
            }
        }

        self::logAttack('XMLRPC_BRUTE', [
            'user'   => $user,
            'pass'   => $pass,
            'action' => 'XMLRPC:' . $probedMethod,
        ]);

        $config = self::getConfig();
        $mode = $config['mode'] ?? 'hybrid';

        if ($mode === 'tarpit') {
            self::serveTarpit((int) ($config['tarpit_seconds'] ?? 15));
        }

        if ($mode === 'bomb' || $mode === 'hybrid') {
            self::serveGzipBomb();
        }

        // Realistic XML-RPC fault
        header("Content-Type: text/xml; charset=UTF-8");
        echo <<<XML
<?xml version="1.0" encoding="UTF-8"?>
<methodResponse>
  <fault>
    <value>
      <struct>
        <member>
          <name>faultCode</name>
          <value><int>403</int></value>
        </member>
        <member>
          <name>faultString</name>
          <value><string>Incorrect username or password.</string></value>
        </member>
      </struct>
    </value>
  </fault>
</methodResponse>
XML;
        exit;
    }

    /**
     * Unified handler for external entry points
     */
    public static function handle(string $endpoint): void
    {
        // 1. Search engine protection: always serve clean 404 to legitimate search crawlers
        if (self::isSearchEngine()) {
            http_response_code(404);
            header("X-Robots-Tag: noindex, nofollow");
            echo "<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>404 Not Found</h1></body></html>";
            exit;
        }

        $config = self::getConfig();
        $mode   = $config['mode'] ?? 'hybrid';
        $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

        // 2. Handle /wp-admin/ redirect
        if ($endpoint === 'wp-admin') {
            self::logAttack('WP_ADMIN_PROBE', ['action' => 'REDIRECT_302']);
            header("Location: /wp-login.php?redirect_to=%2Fwp-admin%2F&reauth=1", true, 302);
            exit;
        }

        // 3. Handle XML-RPC
        if ($endpoint === 'xmlrpc') {
            self::handleXMLRPC();
            return;
        }

        // 4. Handle /wp-login.php
        if ($endpoint === 'wp-login') {
            if ($method === 'GET') {
                if ($mode === 'bomb') {
                    self::logAttack('LOGIN_GET', ['action' => 'GZIP_BOMB']);
                    self::serveGzipBomb();
                }

                if ($mode === 'tarpit') {
                    self::logAttack('LOGIN_GET', ['action' => 'TARPIT']);
                    self::serveTarpit((int) ($config['tarpit_seconds'] ?? 15));
                }

                // Default hybrid & deception: render authentic WordPress login page
                self::renderLoginForm();
                return;
            }

            if ($method === 'POST') {
                $user = trim($_POST['log'] ?? '');
                $pass = trim($_POST['pwd'] ?? '');

                self::logAttack('LOGIN_BRUTEFORCE', [
                    'user'   => $user ?: '-',
                    'pass'   => $pass ?: '-',
                    'action' => 'HARVEST_CREDENTIALS',
                ]);

                if ($mode === 'tarpit') {
                    self::serveTarpit((int) ($config['tarpit_seconds'] ?? 15));
                }

                if ($mode === 'hybrid' || $mode === 'bomb') {
                    // Detonate gzip bomb
                    self::serveGzipBomb();
                }

                // Deception fallback: show authentic WP error
                $errorMsg = 'ОШИБКА: Неверное имя пользователя или пароль. Потеряли пароль?';
                self::renderLoginForm($errorMsg);
                return;
            }
        }

        // Generic fallback
        http_response_code(404);
        echo "Not Found";
        exit;
    }
}
