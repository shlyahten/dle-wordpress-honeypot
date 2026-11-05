<?php
/**
 * Automated Test Suite for WordPress Honeypot Plugin v1.4.0
 */

$repoDir = dirname(__DIR__);
require_once $repoDir . '/upload/engine/modules/honeypot.php';

$passCount = 0;
$failCount = 0;

function assertTest(string $name, bool $condition, string $details = '') {
    global $passCount, $failCount;
    if ($condition) {
        echo "  [PASS] {$name}\n";
        $passCount++;
    } else {
        echo "  [FAIL] {$name}: {$details}\n";
        $failCount++;
    }
}

echo "=== Honeypot Automated Test Suite v1.4.0 ===\n\n";

// 1. Search Engine Crawler Filter
echo "1. Тест фильтрации поисковых роботов:\n";
$googleBotUA = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
$yandexBotUA = 'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)';
$bingBotUA   = 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)';
$attackerUA  = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36';
$scannerUA   = 'python-requests/2.31.0';

assertTest("Googlebot опознается как белый робот", SiteHoneypot::isSearchEngine($googleBotUA));
assertTest("YandexBot опознается как белый робот", SiteHoneypot::isSearchEngine($yandexBotUA));
assertTest("Bingbot опознается как белый робот", SiteHoneypot::isSearchEngine($bingBotUA));
assertTest("Браузер пользователя не является поисковиком", !SiteHoneypot::isSearchEngine($attackerUA));
assertTest("Скрипт python-requests не является поисковиком", !SiteHoneypot::isSearchEngine($scannerUA));

// 2. Client IP Detection
echo "\n2. Тест детекции IP клиента:\n";
$_SERVER['HTTP_CF_CONNECTING_IP'] = '198.51.100.22';
assertTest("Поддержка Cloudflare CF-Connecting-IP", SiteHoneypot::getRealIP() === '198.51.100.22');
unset($_SERVER['HTTP_CF_CONNECTING_IP']);

$_SERVER['HTTP_X_FORWARDED_FOR'] = '198.51.100.33, 10.0.0.1';
assertTest("Поддержка X-Forwarded-For с разделителем", SiteHoneypot::getRealIP() === '198.51.100.33');
unset($_SERVER['HTTP_X_FORWARDED_FOR']);

$_SERVER['REMOTE_ADDR'] = '198.51.100.44';
assertTest("Fallback на REMOTE_ADDR", SiteHoneypot::getRealIP() === '198.51.100.44');

// 3. Threat Intelligence Logging & Aggregation
echo "\n3. Тест сбора аналитики и журнала угроз:\n";
$testLogFile = sys_get_temp_dir() . '/test_honeypot_' . uniqid() . '.log';
$configFile  = sys_get_temp_dir() . '/test_config_' . uniqid() . '.json';

file_put_contents($configFile, json_encode(['mode' => 'hybrid', 'log_enabled' => true]));

// Mock log writes directly using SiteHoneypot format
$attacks = [
    "[2026-11-05 10:00:00] IP: 203.0.113.1 | METHOD: POST | URI: /wp-login.php | LOGIN: admin | PASS: 123456 | ACTION: HARVEST_CREDENTIALS | UA: Hydra\n",
    "[2026-11-05 10:00:10] IP: 203.0.113.1 | METHOD: POST | URI: /wp-login.php | LOGIN: admin | PASS: password | ACTION: HARVEST_CREDENTIALS | UA: Hydra\n",
    "[2026-11-05 10:00:20] IP: 203.0.113.2 | METHOD: POST | URI: /xmlrpc.php | LOGIN: - | PASS: - | ACTION: XMLRPC:demo.sayHello | UA: curl/7.88\n",
];

foreach ($attacks as $entry) {
    file_put_contents($testLogFile, $entry, FILE_APPEND | LOCK_EX);
}

$lines = file($testLogFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
assertTest("В тестовый лог записано 3 атаки", count($lines) === 3);

$parsedIps = [];
foreach ($lines as $line) {
    if (preg_match('/IP: ([0-9.]+)/', $line, $m)) {
        $parsedIps[$m[1]] = true;
    }
}
assertTest("Уникальных IP-адресов зафиксировано 2", count($parsedIps) === 2);

@unlink($testLogFile);
@unlink($configFile);

// 4. Admin Security Isolation
echo "\n4. Тест изоляции админ-модуля:\n";
$output = shell_exec('php ' . escapeshellarg($repoDir . '/upload/engine/inc/honeypot.php') . ' 2>&1');
assertTest("Прямой вызов upload/engine/inc/honeypot.php блокируется с 403 Hacking attempt!", strpos($output, 'Hacking attempt!') !== false);

// 5. XML-RPC Decoy File
echo "\n5. Тест XML-RPC ловушки:\n";
$cmdXmlrpcGet = 'php -r ' . escapeshellarg('
$_SERVER["REQUEST_METHOD"] = "GET";
$_SERVER["HTTP_USER_AGENT"] = "python-requests/2.28";
require "' . $repoDir . '/upload/xmlrpc.php";
');
$xmlrpcGet = shell_exec($cmdXmlrpcGet);
assertTest("XML-RPC GET возвращает текст о POST запросах", strpos($xmlrpcGet, 'XML-RPC server accepts POST requests only') !== false);

// 6. Manifest XML Integrity
echo "\n6. Тест целостности манифеста плагина:\n";
$xml = simplexml_load_file($repoDir . '/honeypot-dle-plugin.xml');
assertTest("Тег <name> корректен", !empty((string)$xml->name));
assertTest("Тег <version> равен 1.4.0", (string)$xml->version === '1.4.0');
assertTest("Тег <dleversion> равен 21.0", (string)$xml->dleversion === '21.0');
assertTest("Тег <upgradeurl> указывает на GitHub Pages", strpos((string)$xml->upgradeurl, 'github.io') !== false);
assertTest("Секция <mysqlinstall> присутствует", !empty((string)$xml->mysqlinstall));
assertTest("Секция <mysqlupgrade> присутствует", !empty((string)$xml->mysqlupgrade));
assertTest("Секция <mysqlenable> присутствует", !empty((string)$xml->mysqlenable));
assertTest("Секция <mysqldisable> присутствует", !empty((string)$xml->mysqldisable));
assertTest("Секция <mysqldelete> присутствует", !empty((string)$xml->mysqldelete));
assertTest("Тег <filedelete> равен 1 (DLE Topic 21)", (string)$xml->filedelete === '1');
assertTest("Секция <phpdelete> присутствует для безопасной очистки", !empty((string)$xml->phpdelete));

$rawXml = file_get_contents($repoDir . '/honeypot-dle-plugin.xml');
assertTest("Хук engine/init.php использует include_once", strpos($rawXml, 'include_once (DLEPlugins::Check(ENGINE_DIR . \'/modules/functions.php\'));') !== false);
assertTest("Хук engine/modules/main.php присутствует для инъекции spider trap", strpos($rawXml, 'name="engine/modules/main.php"') !== false);
assertTest("Хук engine/ajax/plugins.php использует replacecode", strpos($rawXml, '<replacecode><![CDATA[$data = (strpos($row[\'upgradeurl\'], \'github.io\')') !== false);

// 7. Check for Absence of Hardcoded Domains
echo "\n7. Тест отсутствия захардкоженных доменов:\n";
$xmlRaw = file_get_contents($repoDir . '/honeypot-dle-plugin.xml');
$coreRaw = file_get_contents($repoDir . '/upload/engine/modules/honeypot.php');
$incRaw = file_get_contents($repoDir . '/upload/engine/inc/honeypot.php');

assertTest("В XML отсутствует захардкоженный домен shlyahten.ru", stripos($xmlRaw, 'shlyahten.ru') === false);
assertTest("В модуле honeypot.php отсутствует захардкоженный домен shlyahten.ru", stripos($coreRaw, 'shlyahten.ru') === false);
assertTest("В инклуде honeypot.php отсутствует захардкоженный домен shlyahten.ru", stripos($incRaw, 'shlyahten.ru') === false);

// 8. Test Decoy Files
echo "\n8. Тест файлов приманок WordPress:\n";
assertTest("wp-login.php существует", file_exists($repoDir . '/upload/wp-login.php'));
assertTest("wp-admin/index.php существует", file_exists($repoDir . '/upload/wp-admin/index.php'));
assertTest("wp-admin/admin.php существует", file_exists($repoDir . '/upload/wp-admin/admin.php'));
assertTest("wp-admin/admin.gzip существует и > 5MB", filesize($repoDir . '/upload/wp-admin/admin.gzip') > 5000000);
assertTest("xmlrpc.php существует", file_exists($repoDir . '/upload/xmlrpc.php'));
assertTest("Иконка honeypot.png существует", file_exists($repoDir . '/upload/public/adminpanel/images/honeypot.png'));

// 9. Test DLE Admin Trap Decoy
echo "\n9. Тест опциональной ловушки DLE Admin (/admin.php):\n";
assertTest("admin.php.sample существует в upload/", file_exists($repoDir . '/upload/admin.php.sample'));
assertTest("Метод renderDleAdminForm существует", method_exists('SiteHoneypot', 'renderDleAdminForm'));
assertTest("Метод isDleAdminTrapActive существует", method_exists('SiteHoneypot', 'isDleAdminTrapActive'));
assertTest("Метод toggleDleAdminTrap существует", method_exists('SiteHoneypot', 'toggleDleAdminTrap'));

$safetyTest = SiteHoneypot::toggleDleAdminTrap(true);
assertTest("Защитный отказ активации: ловушка не перезаписывает стандартную админку", $safetyTest === false);

// 10. Test v1.4.0 Active Defense & Sanction Methods
echo "\n10. Тест методов активной защиты v1.4.0:\n";
assertTest("Метод serveChunkedSinkhole существует", method_exists('SiteHoneypot', 'serveChunkedSinkhole'));
assertTest("Метод serveSsrfReflection существует", method_exists('SiteHoneypot', 'serveSsrfReflection'));
assertTest("Метод serveRedirectLoop существует", method_exists('SiteHoneypot', 'serveRedirectLoop'));
assertTest("Метод executeSanction существует", method_exists('SiteHoneypot', 'executeSanction'));
assertTest("Метод handleRoute существует", method_exists('SiteHoneypot', 'handleRoute'));
assertTest("Метод injectSpiderTrap существует", method_exists('SiteHoneypot', 'injectSpiderTrap'));
assertTest("Метод serveBlocklistFeed существует", method_exists('SiteHoneypot', 'serveBlocklistFeed'));
assertTest("Метод handleSensitiveFiles существует", method_exists('SiteHoneypot', 'handleSensitiveFiles'));
assertTest("Метод handleWebshellCatcher существует", method_exists('SiteHoneypot', 'handleWebshellCatcher'));
assertTest("Метод banIpInDle существует", method_exists('SiteHoneypot', 'banIpInDle'));

// Test Spider Trap Injection
$testHtml = '<html><head><title>Test</title></head><body><h1>Content</h1></body></html>';
$injected = SiteHoneypot::injectSpiderTrap($testHtml);
assertTest("Spider Trap корректно внедряется перед </body>", strpos($injected, '/trap-spider.html') !== false && strpos($injected, 'display:none') !== false);

// Test Config Structure
$config = SiteHoneypot::getConfig();
assertTest("В конфигурации присутствуют attack vectors", isset($config['vectors']) && is_array($config['vectors']));
assertTest("Вектор wp_login включен по умолчанию", !empty($config['vectors']['wp_login']));
assertTest("Вектор sensitive_files включен по умолчанию", !empty($config['vectors']['sensitive_files']));
assertTest("Вектор spider_trap включен по умолчанию", !empty($config['vectors']['spider_trap']));
assertTest("Вектор webshell_catcher включен по умолчанию", !empty($config['vectors']['webshell_catcher']));
assertTest("Автобан включен по умолчанию", !empty($config['autoban_enabled']));
assertTest("Порог автобана задан", intval($config['autoban_threshold']) >= 1);
assertTest("Секретный токен фида сгенерирован", !empty($config['feed_token']));

// 11. Test ZIP Archive DLE Specification (Topic 21)
$zipFile = $repoDir . '/dist/dle-wordpress-honeypot.zip';
if (file_exists($zipFile)) {
    echo "\n11. Тест соответствия структуры ZIP-архива спецификации DLE:\n";
    $zip = new ZipArchive();
    $opened = $zip->open($zipFile);
    assertTest("ZIP архив открывается корректно", $opened === true);
    if ($opened === true) {
        assertTest("Манифест лежит в корне архива", $zip->locateName('honeypot-dle-plugin.xml') !== false);
        assertTest("Модуль лежит по пути engine/modules/honeypot.php", $zip->locateName('engine/modules/honeypot.php') !== false);
        assertTest("Админ-модуль лежит по пути engine/inc/honeypot.php", $zip->locateName('engine/inc/honeypot.php') !== false);
        assertTest("Иконка лежит по пути public/adminpanel/images/honeypot.png", $zip->locateName('public/adminpanel/images/honeypot.png') !== false);

        $hasUploadPrefix = false;
        for ($i = 0; $i < $zip->numFiles; $i++) {
            if (strpos($zip->getNameIndex($i), 'upload/') === 0) {
                $hasUploadPrefix = true;
                break;
            }
        }
        assertTest("В архиве отсутствуют пути с префиксом upload/", !$hasUploadPrefix);
        assertTest("В архиве отсутствуют лишние корневые файлы (README.md)", $zip->locateName('README.md') === false);
        assertTest("В архиве отсутствуют лишние корневые файлы (logo.png)", $zip->locateName('logo.png') === false);
        $zip->close();
    }
}

echo "\n=======================================\n";
echo "ИТОГ ТЕСТИРОВАНИЯ: Успешно: {$passCount}, Ошибок: {$failCount}\n";
echo "=======================================\n";

if ($failCount > 0) {
    exit(1);
}
