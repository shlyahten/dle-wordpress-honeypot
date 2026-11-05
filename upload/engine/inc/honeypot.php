<?php
/*
=====================================================
 WordPress Honeypot & Threat Intelligence for DLE
-----------------------------------------------------
 Use: Administration panel, threat analytics & control
 (Compliant with DLE Topic 73 Module Architecture)
-----------------------------------------------------
 License: MIT License
=====================================================
*/

if (!defined('DATALIFEENGINE') || !defined('LOGGED_IN')) {
    header("HTTP/1.1 403 Forbidden");
    header('Location: ../../');
    die("Hacking attempt!");
}

if ($member_id['user_group'] != 1) {
    msg("error", $lang['index_denied'], $lang['index_denied']);
}

require_once DLEPlugins::Check(ENGINE_DIR . '/modules/honeypot.php');

$action = $_REQUEST['action'] ?? '';
$user_hash = $_REQUEST['user_hash'] ?? '';
$activeTab = $_REQUEST['active_tab'] ?? '#tab-analytics';
$message = '';
$messageType = 'success';

// CSRF validation helper
$checkCsrf = function() use ($user_hash, $dle_login_hash) {
    if (!$user_hash || $user_hash !== $dle_login_hash) {
        die("Hacking attempt! Invalid security token.");
    }
};

// 1. Action: Save Attack Vectors
if ($action === 'save_vectors') {
    $checkCsrf();
    $vectors = [
        'wp_login'         => !empty($_POST['vector_wp_login']),
        'wp_admin'         => !empty($_POST['vector_wp_admin']),
        'wp_xmlrpc'        => !empty($_POST['vector_wp_xmlrpc']),
        'wp_rest_users'    => !empty($_POST['vector_wp_rest_users']),
        'sensitive_files'  => !empty($_POST['vector_sensitive_files']),
        'spider_trap'      => !empty($_POST['vector_spider_trap']),
        'webshell_catcher' => !empty($_POST['vector_webshell_catcher']),
    ];

    SiteHoneypot::saveConfig(['vectors' => $vectors]);
    $message = "Настройки векторов перехвата успешно сохранены.";
    $activeTab = '#tab-vectors';
}

// 2. Action: Save Sanctions & Auto-ban
if ($action === 'save_sanctions') {
    $checkCsrf();
    $allowedModes = ['hybrid', 'bomb', 'tarpit', 'sinkhole', 'ssrf', 'loop', 'deception'];
    $newMode = $_POST['mode'] ?? 'hybrid';
    if (!in_array($newMode, $allowedModes, true)) {
        $newMode = 'hybrid';
    }

    $tarpitSeconds = max(5, min(60, intval($_POST['tarpit_seconds'] ?? 15)));
    $logEnabled = !empty($_POST['log_enabled']);
    $autobanEnabled = !empty($_POST['autoban_enabled']);
    $autobanThreshold = max(1, min(100, intval($_POST['autoban_threshold'] ?? 3)));
    $autobanDays = max(0, min(365, intval($_POST['autoban_days'] ?? 0)));

    SiteHoneypot::saveConfig([
        'mode'              => $newMode,
        'tarpit_seconds'    => $tarpitSeconds,
        'log_enabled'       => $logEnabled,
        'autoban_enabled'   => $autobanEnabled,
        'autoban_threshold' => $autobanThreshold,
        'autoban_days'      => $autobanDays,
    ]);

    $message = "Параметры противодействия и правила автобана успешно обновлены.";
    $activeTab = '#tab-sanctions';
}

// 3. Action: Save Integrations & Feed
if ($action === 'save_integrations') {
    $checkCsrf();
    $feedEnabled = !empty($_POST['feed_enabled']);
    $feedFormat = in_array($_POST['feed_format'] ?? '', ['plain', 'nginx'], true) ? $_POST['feed_format'] : 'plain';
    $feedToken = preg_replace('/[^a-zA-Z0-9_-]/', '', trim($_POST['feed_token'] ?? ''));
    if (empty($feedToken)) {
        $feedToken = 'hp_' . bin2hex(random_bytes(12));
    }

    $abuseipdbEnabled = !empty($_POST['abuseipdb_enabled']);
    $abuseipdbKey = trim($_POST['abuseipdb_key'] ?? '');

    SiteHoneypot::saveConfig([
        'feed_enabled'      => $feedEnabled,
        'feed_format'       => $feedFormat,
        'feed_token'        => $feedToken,
        'abuseipdb_enabled' => $abuseipdbEnabled,
        'abuseipdb_key'     => $abuseipdbKey,
    ]);

    $message = "Параметры экспорта и внешних интеграций успешно сохранены.";
    $activeTab = '#tab-integrations';
}

// 4. Action: Regenerate Threat Feed Token
if ($action === 'regen_feed_token') {
    $checkCsrf();
    $newToken = 'hp_' . bin2hex(random_bytes(16));
    SiteHoneypot::saveConfig(['feed_token' => $newToken]);
    $message = "Сгенерирован новый секретный ключ фида угроз.";
    $activeTab = '#tab-integrations';
}

// 5. Action: Clear Attack Log
if ($action === 'clear_log') {
    $checkCsrf();
    SiteHoneypot::clearLog();
    $message = "Журнал перехваченных атак успешно очищен.";
    $activeTab = '#tab-analytics';
}

// 6. Action: Block IP directly in DLE Banned Table
if ($action === 'block_ip') {
    $checkCsrf();
    $ipToBlock = trim($_POST['ip'] ?? '');
    if ($ipToBlock && filter_var($ipToBlock, FILTER_VALIDATE_IP)) {
        $banned = SiteHoneypot::banIpInDle($ipToBlock, 0, "Ручной бан из WordPress Honeypot (" . $member_id['name'] . ")");
        if ($banned) {
            $message = "IP-адрес {$ipToBlock} успешно добавлен в список блокировок DLE.";
        } else {
            $message = "IP-адрес {$ipToBlock} уже находится в списке заблокированных DLE.";
            $messageType = 'warning';
        }
    } else {
        $message = "Указан некорректный IP-адрес.";
        $messageType = 'error';
    }
    $activeTab = '#tab-analytics';
}

// 7. Action: Unblock IP in DLE Banned Table
if ($action === 'unblock_ip') {
    $checkCsrf();
    $ipToUnblock = trim($_POST['ip'] ?? '');
    if ($ipToUnblock && filter_var($ipToUnblock, FILTER_VALIDATE_IP)) {
        $ipSafe = $db->safesql($ipToUnblock);
        $prefix = defined('USERPREFIX') ? USERPREFIX : (defined('PREFIX') ? PREFIX : 'dle');
        $db->query("DELETE FROM " . $prefix . "_banned WHERE ip = '{$ipSafe}'");
        @unlink(ENGINE_DIR . '/cache/system/banned.json');
        $message = "IP-адрес {$ipToUnblock} удален из списка блокировок DLE.";
    }
    $activeTab = '#tab-analytics';
}

// 8. Action: Toggle DLE admin.php decoy trap
if ($action === 'toggle_dle_admin') {
    $checkCsrf();
    $enable = !empty($_POST['enable']);
    $success = SiteHoneypot::toggleDleAdminTrap($enable);
    if ($success) {
        $message = $enable 
            ? "Ловушка на стандартном адресе /admin.php успешно активирована!" 
            : "Ловушка /admin.php успешно отключена.";
    } else {
        $message = "Не удалось активировать ловушку /admin.php: панель управления не переименована в настройках или указан путь по умолчанию.";
        $messageType = "error";
    }
    $activeTab = '#tab-vectors';
}

// Fetch current state
$dleAdminPath = $config['admin_path'] ?? 'admin.php';
$isRenamed = ($dleAdminPath !== 'admin.php' && !empty($dleAdminPath));
$isTrapActive = SiteHoneypot::isDleAdminTrapActive();

$hpConfig = SiteHoneypot::getConfig();
$vectors = $hpConfig['vectors'] ?? [];
$stats = SiteHoneypot::getStats();
$recentAttacks = SiteHoneypot::getLog(50);
$logSizeKb = round($stats['log_size'] / 1024, 1);

// Check which top IPs are already banned in DLE
$bannedIps = [];
if (!empty($stats['top_ips'])) {
    $ipListSql = "'" . implode("','", array_map([$db, 'safesql'], array_keys($stats['top_ips']))) . "'";
    $prefix = defined('USERPREFIX') ? USERPREFIX : (defined('PREFIX') ? PREFIX : 'dle');
    $db->query("SELECT ip FROM " . $prefix . "_banned WHERE ip IN ({$ipListSql})");
    while ($row = $db->get_row()) {
        $bannedIps[$row['ip']] = true;
    }
}

// Feed URL
$siteUrl = rtrim($config['http_home_url'] ?? ('http://' . ($_SERVER['HTTP_HOST'] ?? 'localhost')), '/');
$feedUrl = $siteUrl . '/honeypot-feed.txt?token=' . urlencode($hpConfig['feed_token'] ?? '');

echoheader(
    "<i class=\"fa fa-shield position-left\"></i><span class=\"text-semibold\">WordPress Honeypot &amp; Threat Intelligence</span>",
    "Центр активной защиты, перехвата атак и аналитики угроз (v1.4.0)"
);

if ($message) {
    $alertClass = $messageType === 'error' ? 'alert-danger' : ($messageType === 'warning' ? 'alert-warning' : 'alert-success');
    echo "<div class=\"alert {$alertClass} alert-styled-left alert-arrow-left alert-bordered\">" . htmlspecialchars($message, ENT_QUOTES, 'UTF-8') . "</div>";
}
?>

<div class="panel panel-default">
    <div class="panel-heading">
        <ul class="nav nav-tabs nav-tabs-highlight" role="tablist">
            <li class="<?= $activeTab === '#tab-analytics' ? 'active' : '' ?>">
                <a href="#tab-analytics" data-toggle="tab"><i class="fa fa-line-chart position-left"></i>Аналитика и журнал</a>
            </li>
            <li class="<?= $activeTab === '#tab-vectors' ? 'active' : '' ?>">
                <a href="#tab-vectors" data-toggle="tab"><i class="fa fa-crosshairs position-left"></i>Векторы перехвата</a>
            </li>
            <li class="<?= $activeTab === '#tab-sanctions' ? 'active' : '' ?>">
                <a href="#tab-sanctions" data-toggle="tab"><i class="fa fa-shield position-left"></i>Меры противодействия и автобан</a>
            </li>
            <li class="<?= $activeTab === '#tab-integrations' ? 'active' : '' ?>">
                <a href="#tab-integrations" data-toggle="tab"><i class="fa fa-plug position-left"></i>Экспорт и интеграции</a>
            </li>
        </ul>
    </div>

    <div class="panel-body">
        <div class="tab-content">
            
            <!-- ================= TAB 1: ANALYTICS & LOG ================= -->
            <div class="tab-pane <?= $activeTab === '#tab-analytics' ? 'active' : '' ?>" id="tab-analytics">
                
                <!-- Metric Cards -->
                <div class="row">
                    <div class="col-sm-3">
                        <div class="panel panel-default border-top-primary">
                            <div class="panel-heading"><h6 class="panel-title text-uppercase font-size-xs text-muted">Всего перехвачено атак</h6></div>
                            <div class="panel-body text-center">
                                <h2 class="text-primary no-margin font-weight-semibold"><?= number_format($stats['total_attacks'], 0, '.', ' ') ?></h2>
                            </div>
                        </div>
                    </div>
                    <div class="col-sm-3">
                        <div class="panel panel-default border-top-danger">
                            <div class="panel-heading"><h6 class="panel-title text-uppercase font-size-xs text-muted">Уникальных IP ботов</h6></div>
                            <div class="panel-body text-center">
                                <h2 class="text-danger no-margin font-weight-semibold"><?= number_format($stats['unique_ips'], 0, '.', ' ') ?></h2>
                            </div>
                        </div>
                    </div>
                    <div class="col-sm-3">
                        <div class="panel panel-default border-top-warning">
                            <div class="panel-heading"><h6 class="panel-title text-uppercase font-size-xs text-muted">Активная санкция</h6></div>
                            <div class="panel-body text-center">
                                <h4 class="no-margin text-semibold text-uppercase text-slate">
                                    <?php
                                    $modeLabels = [
                                        'hybrid'    => 'Гибридный',
                                        'bomb'      => 'Gzip-бомба',
                                        'tarpit'    => 'Tarpit',
                                        'sinkhole'  => 'Sinkhole',
                                        'ssrf'      => 'SSRF Loopback',
                                        'loop'      => 'Loop Carousel',
                                        'deception' => 'Дезинформация',
                                    ];
                                    echo htmlspecialchars($modeLabels[$hpConfig['mode']] ?? $hpConfig['mode'], ENT_QUOTES, 'UTF-8');
                                    ?>
                                </h4>
                            </div>
                        </div>
                    </div>
                    <div class="col-sm-3">
                        <div class="panel panel-default border-top-success">
                            <div class="panel-heading"><h6 class="panel-title text-uppercase font-size-xs text-muted">Размер журнала атак</h6></div>
                            <div class="panel-body text-center">
                                <h2 class="text-success no-margin font-weight-semibold"><?= $logSizeKb ?> КБ</h2>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="row">
                    <!-- Top IPs with Direct DLE Ban button -->
                    <div class="col-md-7">
                        <div class="panel panel-default">
                            <div class="panel-heading">
                                <h6 class="panel-title"><i class="fa fa-crosshairs position-left"></i>Топ атакующих IP-адресов</h6>
                            </div>
                            <div class="table-responsive">
                                <?php if (empty($stats['top_ips'])): ?>
                                    <p class="text-muted text-center" style="padding: 25px 0;">Атак пока не зафиксировано.</p>
                                <?php else: ?>
                                    <table class="table table-striped table-hover table-condensed font-size-sm">
                                        <thead>
                                            <tr>
                                                <th>IP-адрес бота</th>
                                                <th class="text-center">Атак</th>
                                                <th class="text-center">Статус DLE</th>
                                                <th class="text-right">Действие</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <?php foreach ($stats['top_ips'] as $ip => $count): ?>
                                                <?php $isBanned = !empty($bannedIps[$ip]); ?>
                                                <tr>
                                                    <td>
                                                        <strong><?= htmlspecialchars($ip, ENT_QUOTES, 'UTF-8') ?></strong>
                                                        <a href="https://whois.domaintools.com/<?= urlencode($ip) ?>" target="_blank" class="text-muted ml-5 font-size-xs" title="Whois lookup"><i class="fa fa-external-link"></i></a>
                                                    </td>
                                                    <td class="text-center"><span class="badge badge-primary"><?= $count ?></span></td>
                                                    <td class="text-center">
                                                        <?php if ($isBanned): ?>
                                                            <span class="label label-danger">Заблокирован</span>
                                                        <?php else: ?>
                                                            <span class="label label-default">Не заблокирован</span>
                                                        <?php endif; ?>
                                                    </td>
                                                    <td class="text-right">
                                                        <?php if ($isBanned): ?>
                                                            <form action="?mod=honeypot&action=unblock_ip" method="post" style="display:inline-block;">
                                                                <input type="hidden" name="user_hash" value="<?= $dle_login_hash ?>">
                                                                <input type="hidden" name="ip" value="<?= htmlspecialchars($ip, ENT_QUOTES, 'UTF-8') ?>">
                                                                <button type="submit" class="btn btn-xs btn-default"><i class="fa fa-unlock position-left"></i>Разбанить</button>
                                                            </form>
                                                        <?php else: ?>
                                                            <form action="?mod=honeypot&action=block_ip" method="post" style="display:inline-block;">
                                                                <input type="hidden" name="user_hash" value="<?= $dle_login_hash ?>">
                                                                <input type="hidden" name="ip" value="<?= htmlspecialchars($ip, ENT_QUOTES, 'UTF-8') ?>">
                                                                <button type="submit" class="btn btn-xs btn-danger"><i class="fa fa-ban position-left"></i>В бан DLE</button>
                                                            </form>
                                                        <?php endif; ?>
                                                    </td>
                                                </tr>
                                            <?php endforeach; ?>
                                        </tbody>
                                    </table>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>

                    <!-- Threat Intelligence: Top Passwords -->
                    <div class="col-md-5">
                        <div class="panel panel-default">
                            <div class="panel-heading">
                                <h6 class="panel-title"><i class="fa fa-key position-left"></i>Словарь паролей ботов</h6>
                            </div>
                            <div class="panel-body" style="padding: 10px 15px;">
                                <?php if (empty($stats['top_passwords'])): ?>
                                    <p class="text-muted text-center" style="padding: 25px 0;">Пока нет зафиксированных попыток ввода паролей.</p>
                                <?php else: ?>
                                    <table class="table table-xs table-striped">
                                        <thead>
                                            <tr>
                                                <th>Пароль из словаря</th>
                                                <th class="text-right" style="width: 80px;">Попыток</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <?php foreach ($stats['top_passwords'] as $pass => $count): ?>
                                                <tr>
                                                    <td><code><?= htmlspecialchars($pass, ENT_QUOTES, 'UTF-8') ?></code></td>
                                                    <td class="text-right"><span class="badge badge-danger"><?= $count ?></span></td>
                                                </tr>
                                            <?php endforeach; ?>
                                        </tbody>
                                    </table>
                                <?php endif; ?>

                                <div class="text-right" style="margin-top: 15px;">
                                    <form action="?mod=honeypot&action=clear_log" method="post" onsubmit="return confirm('Вы уверены, что хотите очистить журнал атак?');" style="display:inline-block;">
                                        <input type="hidden" name="user_hash" value="<?= $dle_login_hash ?>">
                                        <button type="submit" class="btn btn-default btn-sm text-danger"><i class="fa fa-trash position-left"></i>Очистить журнал атак</button>
                                    </form>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Recent Attacks Feed -->
                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h6 class="panel-title"><i class="fa fa-list position-left"></i>Последние 50 перехваченных атак</h6>
                    </div>
                    <div class="table-responsive">
                        <?php if (empty($recentAttacks)): ?>
                            <p class="text-muted text-center" style="padding: 25px 0;">Журнал пуст.</p>
                        <?php else: ?>
                            <table class="table table-striped table-hover font-size-xs">
                                <thead>
                                    <tr>
                                        <th>Дата и время</th>
                                        <th>IP-адрес</th>
                                        <th>Метод и URI</th>
                                        <th>Логин</th>
                                        <th>Пароль / Данные</th>
                                        <th>Примененная мера</th>
                                        <th>User-Agent сканера</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($recentAttacks as $attack): ?>
                                        <tr>
                                            <td class="text-nowrap"><?= htmlspecialchars($attack['date'], ENT_QUOTES, 'UTF-8') ?></td>
                                            <td class="text-nowrap"><strong><?= htmlspecialchars($attack['ip'], ENT_QUOTES, 'UTF-8') ?></strong></td>
                                            <td class="text-nowrap"><span class="label label-default"><?= htmlspecialchars($attack['method'], ENT_QUOTES, 'UTF-8') ?></span> <code><?= htmlspecialchars($attack['uri'], ENT_QUOTES, 'UTF-8') ?></code></td>
                                            <td><?= $attack['login'] !== '-' ? '<b>' . htmlspecialchars($attack['login'], ENT_QUOTES, 'UTF-8') . '</b>' : '<span class="text-muted">-</span>' ?></td>
                                            <td><?= $attack['pass'] !== '-' ? '<code class="text-danger">' . htmlspecialchars($attack['pass'], ENT_QUOTES, 'UTF-8') . '</code>' : '<span class="text-muted">-</span>' ?></td>
                                            <td><span class="label label-info"><?= htmlspecialchars($attack['action'], ENT_QUOTES, 'UTF-8') ?></span></td>
                                            <td class="text-muted" style="max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="<?= htmlspecialchars($attack['ua'], ENT_QUOTES, 'UTF-8') ?>">
                                                <?= htmlspecialchars($attack['ua'], ENT_QUOTES, 'UTF-8') ?>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        <?php endif; ?>
                    </div>
                </div>

            </div>

            <!-- ================= TAB 2: ATTACK VECTORS ================= -->
            <div class="tab-pane <?= $activeTab === '#tab-vectors' ? 'active' : '' ?>" id="tab-vectors">
                <div class="alert alert-info alert-styled-left">
                    <h6 class="text-semibold" style="margin-top: 0;"><i class="fa fa-crosshairs position-left"></i>Управление активными ловушками и векторами атак</h6>
                    Выберите, какие точки проникновения и приманки будут активны на сайте. Запросы к активным векторам мгновенно перехватываются, логируются и нейтрализуются выбранной санкцией.
                </div>

                <form action="?mod=honeypot&action=save_vectors" method="post" class="form-horizontal">
                    <input type="hidden" name="user_hash" value="<?= $dle_login_hash ?>">
                    <input type="hidden" name="active_tab" value="#tab-vectors">

                    <table class="table table-bordered table-striped">
                        <thead>
                            <tr>
                                <th style="width: 60px;" class="text-center">Вкл</th>
                                <th>Вектор атаки / Приманка</th>
                                <th>URL адрес / Паттерн</th>
                                <th>Описание механизма перехвата</th>
                            </tr>
                        </thead>
                        <tbody>
                            <!-- 1. WP Login -->
                            <tr>
                                <td class="text-center">
                                    <input type="checkbox" name="vector_wp_login" value="1" <?= !empty($vectors['wp_login']) ? 'checked' : '' ?>>
                                </td>
                                <td><strong>WordPress Login</strong><br><span class="label label-primary font-size-xs">CMS Mimicry</span></td>
                                <td><code>/wp-login.php</code></td>
                                <td class="text-muted font-size-sm">Имитирует официальную страницу авторизации WordPress 6.x. Перехватывает POST-запросы подбора логинов/паролей и применяет санкцию.</td>
                            </tr>

                            <!-- 2. WP Admin -->
                            <tr>
                                <td class="text-center">
                                    <input type="checkbox" name="vector_wp_admin" value="1" <?= !empty($vectors['wp_admin']) ? 'checked' : '' ?>>
                                </td>
                                <td><strong>WordPress Admin Directory</strong><br><span class="label label-default font-size-xs">Probe Redirection</span></td>
                                <td><code>/wp-admin/</code></td>
                                <td class="text-muted font-size-sm">Ловит ботов, проверяющих наличие папки панели управления WP, и перенаправляет их в ловушку входа.</td>
                            </tr>

                            <!-- 3. WP XML-RPC -->
                            <tr>
                                <td class="text-center">
                                    <input type="checkbox" name="vector_wp_xmlrpc" value="1" <?= !empty($vectors['wp_xmlrpc']) ? 'checked' : '' ?>>
                                </td>
                                <td><strong>WordPress XML-RPC API</strong><br><span class="label label-warning font-size-xs">Bruteforce / Pingback</span></td>
                                <td><code>/xmlrpc.php</code></td>
                                <td class="text-muted font-size-sm">Перехватывает атаки через <code>system.multicall</code> и <code>wp.getUsersBlogs</code>, собирает перебираемые пароли и возвращает XML-RPC ошибку или бомбу.</td>
                            </tr>

                            <!-- 4. WP REST API Users -->
                            <tr>
                                <td class="text-center">
                                    <input type="checkbox" name="vector_wp_rest_users" value="1" <?= !empty($vectors['wp_rest_users']) ? 'checked' : '' ?>>
                                </td>
                                <td><strong>WP REST API Enumeration</strong><br><span class="label label-info font-size-xs">Recon Trap</span></td>
                                <td><code>/wp-json/wp/v2/users</code></td>
                                <td class="text-muted font-size-sm">Скармливает автоматизированным сканерам (WPScan) фейковый профиль администратора <code>admin</code>, заманивая их в ловушку брутфорса.</td>
                            </tr>

                            <!-- 5. Sensitive & Backup Files -->
                            <tr>
                                <td class="text-center">
                                    <input type="checkbox" name="vector_sensitive_files" value="1" <?= !empty($vectors['sensitive_files']) ? 'checked' : '' ?>>
                                </td>
                                <td><strong>Sensitive &amp; Backup Files</strong><br><span class="label label-danger font-size-xs">Canary Token Trap</span></td>
                                <td><code>/.env</code>, <code>/.git/config</code>, <code>dump.sql</code>, <code>wp-config.php.bak</code></td>
                                <td class="text-muted font-size-sm">Перехватывает запросы к бэкапам и файлам конфигураций. Возвращает фейковые файлы с canary-токенами, отравляя базы данных атакующего.</td>
                            </tr>

                            <!-- 6. Spider Trap -->
                            <tr>
                                <td class="text-center">
                                    <input type="checkbox" name="vector_spider_trap" value="1" <?= !empty($vectors['spider_trap']) ? 'checked' : '' ?>>
                                </td>
                                <td><strong>Spider Trap (Паутинная ловушка)</strong><br><span class="label label-primary font-size-xs">Bot Harvester</span></td>
                                <td><code>/trap-spider.html</code> (скрытая ссылка в DOM)</td>
                                <td class="text-muted font-size-sm">Внедряет в код страниц невидимую для людей ссылку. Любой бот или парсер, перешедший по ней, немедленно идентифицируется как вредоносный.</td>
                            </tr>

                            <!-- 7. Webshell Catcher -->
                            <tr>
                                <td class="text-center">
                                    <input type="checkbox" name="vector_webshell_catcher" value="1" <?= !empty($vectors['webshell_catcher']) ? 'checked' : '' ?>>
                                </td>
                                <td><strong>Webshell Catcher &amp; Quarantine</strong><br><span class="label label-danger font-size-xs">Exploit Sandbox</span></td>
                                <td><code>/wp-admin/async-upload.php</code></td>
                                <td class="text-muted font-size-sm">Ловит попытки загрузки PHP-вебшеллов ботами. Безопасно изолирует загруженный файл в защищенный карантин (<code>engine/data/quarantine/</code>, права 0600, исполнение отключено).</td>
                            </tr>
                        </tbody>
                    </table>

                    <div class="text-right" style="margin-top: 15px;">
                        <button type="submit" class="btn btn-primary"><i class="fa fa-floppy-o position-left"></i>Сохранить векторы перехвата</button>
                    </div>
                </form>

                <hr>

                <!-- DLE Default admin.php Trap Panel -->
                <div class="panel panel-default" style="margin-top: 20px;">
                    <div class="panel-heading">
                        <h6 class="panel-title"><i class="fa fa-user-secret position-left"></i>Ловушка стандартного адреса DLE (/admin.php)</h6>
                    </div>
                    <div class="panel-body">
                        <?php if (!$isRenamed): ?>
                            <div class="alert alert-warning alert-styled-left">
                                <h6 class="text-semibold" style="margin-top: 0;"><i class="fa fa-exclamation-triangle position-left"></i>Панель управления не переименована</h6>
                                <p>Ваш сайт использует стандартный адрес админпанели: <code>admin.php</code>.</p>
                                <p class="font-size-sm text-muted" style="margin-top: 5px;">
                                    Чтобы превратить <code>/admin.php</code> в приманку для ботов, сначала измените адрес админки в <b>Настройках системы DLE</b> (параметр <i>"Файл административной панели"</i>, например на <code>secret_admin.php</code>) и физически переименуйте файл на сервере. После этого здесь станет доступна активация ловушки.
                                </p>
                            </div>
                            <button type="button" class="btn btn-default" disabled title="Сначала переименуйте файл админки в настройках системы">
                                <i class="fa fa-shield position-left"></i>Включить ловушку /admin.php (Недоступно)
                            </button>
                        <?php else: ?>
                            <div class="alert alert-info alert-styled-left">
                                <h6 class="text-semibold" style="margin-top: 0;"><i class="fa fa-check-circle position-left"></i>Адрес админпанели безопасно изменен</h6>
                                <p>Реальная панель управления находится по адресу: <code><?= htmlspecialchars($dleAdminPath, ENT_QUOTES, 'UTF-8') ?></code>.</p>
                                <p class="font-size-sm" style="margin-top: 5px;">
                                    Стандартный адрес <code>/admin.php</code> свободен и может использоваться как приманка. Боты, сканирующие DLE, увидят аутентичную страницу входа DLE, а их попытки подбора логинов и паролей будут нейтрализованы.
                                </p>
                            </div>
                            <div class="row">
                                <div class="col-sm-6">
                                    <p style="margin-top: 5px;">Текущий статус: 
                                        <?php if ($isTrapActive): ?>
                                            <span class="label label-success font-size-sm"><i class="fa fa-check position-left"></i>Ловушка активна</span>
                                        <?php else: ?>
                                            <span class="label label-default font-size-sm"><i class="fa fa-power-off position-left"></i>Ловушка выключена</span>
                                        <?php endif; ?>
                                    </p>
                                </div>
                                <div class="col-sm-6 text-right">
                                    <form action="?mod=honeypot&action=toggle_dle_admin" method="post" style="display:inline-block;">
                                        <input type="hidden" name="user_hash" value="<?= $dle_login_hash ?>">
                                        <input type="hidden" name="active_tab" value="#tab-vectors">
                                        <?php if ($isTrapActive): ?>
                                            <input type="hidden" name="enable" value="0">
                                            <button type="submit" class="btn btn-warning btn-sm"><i class="fa fa-power-off position-left"></i>Отключить ловушку /admin.php</button>
                                        <?php else: ?>
                                            <input type="hidden" name="enable" value="1">
                                            <button type="submit" class="btn btn-primary btn-sm"><i class="fa fa-shield position-left"></i>Включить ловушку /admin.php</button>
                                        <?php endif; ?>
                                    </form>
                                </div>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>

            </div>

            <!-- ================= TAB 3: SANCTIONS & AUTOBAN ================= -->
            <div class="tab-pane <?= $activeTab === '#tab-sanctions' ? 'active' : '' ?>" id="tab-sanctions">
                <div class="alert alert-info alert-styled-left">
                    <h6 class="text-semibold" style="margin-top: 0;"><i class="fa fa-shield position-left"></i>Выбор санкции и автоматический бан атакующих</h6>
                    Выберите основную тактику нейтрализации ботов, атакующих перехватываемые ловушки, и настройте автоматический бан в системе DLE.
                </div>

                <form action="?mod=honeypot&action=save_sanctions" method="post" class="form-horizontal">
                    <input type="hidden" name="user_hash" value="<?= $dle_login_hash ?>">
                    <input type="hidden" name="active_tab" value="#tab-sanctions">

                    <div class="panel panel-default">
                        <div class="panel-heading">
                            <h6 class="panel-title"><i class="fa fa-flash position-left"></i>Стратегия противодействия (Режим реакции)</h6>
                        </div>
                        <div class="panel-body">
                            <div class="radio">
                                <label>
                                    <input type="radio" name="mode" value="hybrid" <?= ($hpConfig['mode'] === 'hybrid' ? 'checked' : '') ?>>
                                    <b>🛡️ Гибридный режим (Рекомендуется)</b>: На GET-запросы отдавать реалистичную страницу авторизации (~3 КБ); на POST-запросы логировать учетные данные брутфорса и взрывать Gzip-бомбой.
                                </label>
                            </div>
                            <div class="radio">
                                <label>
                                    <input type="radio" name="mode" value="bomb" <?= ($hpConfig['mode'] === 'bomb' ? 'checked' : '') ?>>
                                    <b>💣 Мгновенная Gzip-бомба</b>: Сразу детонировать 10 ГБ несжатых данных при любых запросах к ловушкам (только если клиент поддерживает gzip, иначе 403 без расхода трафика).
                                </label>
                            </div>
                            <div class="radio">
                                <label>
                                    <input type="radio" name="mode" value="tarpit" <?= ($hpConfig['mode'] === 'tarpit' ? 'checked' : '') ?>>
                                    <b>⏳ HTTP Tarpit (Вязкая смола)</b>: Удерживать соединение открытым 15–30 секунд по 1 байту, зависая воркеры сканеров без расхода серверных ресурсов.
                                </label>
                            </div>
                            <div class="radio">
                                <label>
                                    <input type="radio" name="mode" value="sinkhole" <?= ($hpConfig['mode'] === 'sinkhole' ? 'checked' : '') ?>>
                                    <b>🕳️ Endless Chunked Sinkhole</b>: Непрерывный поток чанков до таймаута сканера (утилизирует сетевые сокеты и память атакующего).
                                </label>
                            </div>
                            <div class="radio">
                                <label>
                                    <input type="radio" name="mode" value="ssrf" <?= ($hpConfig['mode'] === 'ssrf' ? 'checked' : '') ?>>
                                    <b>🔄 SSRF Reflection Loopback</b>: Редирект атакующего на <code>http://127.0.0.1:80/</code> или облачный метадата-сервис (отравляет прокси и внутренние сканеры).
                                </label>
                            </div>
                            <div class="radio">
                                <label>
                                    <input type="radio" name="mode" value="loop" <?= ($hpConfig['mode'] === 'loop' ? 'checked' : '') ?>>
                                    <b>🔁 Redirect Carousel (Петля редиректов)</b>: Бесконечный циклический редирект (HTTP 302), истощающий лимит перенаправлений парсеров.
                                </label>
                            </div>
                            <div class="radio">
                                <label>
                                    <input type="radio" name="mode" value="deception" <?= ($hpConfig['mode'] === 'deception' ? 'checked' : '') ?>>
                                    <b>🎭 Чистая дезинформация</b>: Собирать пароли и отдавать стандартную ошибку входа или фейковые canary-данные без активных контратак.
                                </label>
                            </div>

                            <hr>

                            <div class="form-group" style="margin-top: 15px;">
                                <label class="control-label col-sm-4 text-semibold">Время удержания соединения Tarpit (сек):</label>
                                <div class="col-sm-3">
                                    <input type="number" name="tarpit_seconds" min="5" max="60" class="form-control" value="<?= intval($hpConfig['tarpit_seconds'] ?? 15) ?>">
                                    <span class="help-block font-size-xs text-muted">Рекомендуется от 10 до 30 секунд.</span>
                                </div>
                            </div>

                            <div class="form-group">
                                <label class="control-label col-sm-4 text-semibold">Журналирование атак:</label>
                                <div class="col-sm-8">
                                    <label class="checkbox-inline">
                                        <input type="checkbox" name="log_enabled" value="1" <?= (!empty($hpConfig['log_enabled']) ? 'checked' : '') ?>> Вести журнал атак с ротацией (до 2000 записей)
                                    </label>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Auto-ban Section -->
                    <div class="panel panel-default">
                        <div class="panel-heading">
                            <h6 class="panel-title"><i class="fa fa-ban position-left"></i>Автоматический бан в DataLife Engine</h6>
                        </div>
                        <div class="panel-body">
                            <div class="form-group">
                                <label class="control-label col-sm-4 text-semibold">Автобан в DLE:</label>
                                <div class="col-sm-8">
                                    <label class="checkbox-inline">
                                        <input type="checkbox" name="autoban_enabled" value="1" <?= (!empty($hpConfig['autoban_enabled']) ? 'checked' : '') ?>>
                                        <b>Автоматически блокировать IP</b> при превышении порога атак
                                    </label>
                                    <span class="help-block font-size-xs text-muted">Заносит IP в штатную таблицу <code>dle_banned</code> и мгновенно сбрасывает кэш банов DLE.</span>
                                </div>
                            </div>

                            <div class="form-group">
                                <label class="control-label col-sm-4 text-semibold">Порог атак для автобана:</label>
                                <div class="col-sm-3">
                                    <input type="number" name="autoban_threshold" min="1" max="50" class="form-control" value="<?= intval($hpConfig['autoban_threshold'] ?? 3) ?>">
                                    <span class="help-block font-size-xs text-muted">Количество пойманных запросов до активации бана (по умолч. 3).</span>
                                </div>
                            </div>

                            <div class="form-group">
                                <label class="control-label col-sm-4 text-semibold">Срок действия бана:</label>
                                <div class="col-sm-4">
                                    <select name="autoban_days" class="form-control">
                                        <option value="0" <?= intval($hpConfig['autoban_days'] ?? 0) === 0 ? 'selected' : '' ?>>Навсегда (0 дней)</option>
                                        <option value="1" <?= intval($hpConfig['autoban_days'] ?? 0) === 1 ? 'selected' : '' ?>>1 день</option>
                                        <option value="7" <?= intval($hpConfig['autoban_days'] ?? 0) === 7 ? 'selected' : '' ?>>7 дней</option>
                                        <option value="30" <?= intval($hpConfig['autoban_days'] ?? 0) === 30 ? 'selected' : '' ?>>30 дней</option>
                                        <option value="90" <?= intval($hpConfig['autoban_days'] ?? 0) === 90 ? 'selected' : '' ?>>90 дней</option>
                                    </select>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="text-right">
                        <button type="submit" class="btn btn-primary"><i class="fa fa-floppy-o position-left"></i>Сохранить параметры противодействия</button>
                    </div>
                </form>
            </div>

            <!-- ================= TAB 4: INTEGRATIONS & EXPORT ================= -->
            <div class="tab-pane <?= $activeTab === '#tab-integrations' ? 'active' : '' ?>" id="tab-integrations">
                <div class="alert alert-info alert-styled-left">
                    <h6 class="text-semibold" style="margin-top: 0;"><i class="fa fa-plug position-left"></i>Экспорт фида угроз и внешние интеграции</h6>
                    Подключите список вредоносных IP в сетевые экраны (Nginx, Fail2ban, MikroTik, Cloudflare) или настройте автоматическую отправку жалоб в глобальную базу AbuseIPDB.
                </div>

                <form action="?mod=honeypot&action=save_integrations" method="post" class="form-horizontal">
                    <input type="hidden" name="user_hash" value="<?= $dle_login_hash ?>">
                    <input type="hidden" name="active_tab" value="#tab-integrations">

                    <!-- Dynamic Feed Panel -->
                    <div class="panel panel-default">
                        <div class="panel-heading">
                            <h6 class="panel-title"><i class="fa fa-rss position-left"></i>Динамический IP Blocklist Feed (Threat Intelligence)</h6>
                        </div>
                        <div class="panel-body">
                            <div class="form-group">
                                <label class="control-label col-sm-4 text-semibold">Публикация фида:</label>
                                <div class="col-sm-8">
                                    <label class="checkbox-inline">
                                        <input type="checkbox" name="feed_enabled" value="1" <?= (!empty($hpConfig['feed_enabled']) ? 'checked' : '') ?>>
                                        Включить динамический фид вредоносных IP по секретному токену
                                    </label>
                                </div>
                            </div>

                            <div class="form-group">
                                <label class="control-label col-sm-4 text-semibold">Формат вывода:</label>
                                <div class="col-sm-5">
                                    <div class="radio">
                                        <label>
                                            <input type="radio" name="feed_format" value="plain" <?= (($hpConfig['feed_format'] ?? 'plain') === 'plain' ? 'checked' : '') ?>>
                                            <b>Plain Text</b> (IP-адреса по одному на строку для Fail2ban, MikroTik, pfSense)
                                        </label>
                                    </div>
                                    <div class="radio">
                                        <label>
                                            <input type="radio" name="feed_format" value="nginx" <?= (($hpConfig['feed_format'] ?? '') === 'nginx' ? 'checked' : '') ?>>
                                            <b>Nginx Deny format</b> (<code>deny 1.2.3.4;</code> для прямого <code>include</code> в Nginx)
                                        </label>
                                    </div>
                                </div>
                            </div>

                            <div class="form-group">
                                <label class="control-label col-sm-4 text-semibold">Секретный токен фида:</label>
                                <div class="col-sm-6">
                                    <div class="input-group">
                                        <input type="text" name="feed_token" class="form-control" value="<?= htmlspecialchars($hpConfig['feed_token'] ?? '', ENT_QUOTES, 'UTF-8') ?>" required>
                                        <span class="input-group-btn">
                                            <button type="submit" formaction="?mod=honeypot&action=regen_feed_token" class="btn btn-default" title="Сгенерировать новый ключ"><i class="fa fa-refresh"></i> Новый ключ</button>
                                        </span>
                                    </div>
                                    <span class="help-block font-size-xs text-muted">Защищает фид от публичного сканирования сторонними лицами.</span>
                                </div>
                            </div>

                            <div class="form-group">
                                <label class="control-label col-sm-4 text-semibold">URL-адрес фида:</label>
                                <div class="col-sm-8">
                                    <div class="input-group">
                                        <input type="text" readonly class="form-control" id="feedUrlInput" value="<?= htmlspecialchars($feedUrl, ENT_QUOTES, 'UTF-8') ?>">
                                        <span class="input-group-btn">
                                            <a href="<?= htmlspecialchars($feedUrl, ENT_QUOTES, 'UTF-8') ?>" target="_blank" class="btn btn-default" title="Открыть в браузере"><i class="fa fa-external-link"></i></a>
                                        </span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- AbuseIPDB Panel -->
                    <div class="panel panel-default">
                        <div class="panel-heading">
                            <h6 class="panel-title"><i class="fa fa-globe position-left"></i>Интеграция с базой угроз AbuseIPDB</h6>
                        </div>
                        <div class="panel-body">
                            <div class="form-group">
                                <label class="control-label col-sm-4 text-semibold">Авто-репортинг в AbuseIPDB:</label>
                                <div class="col-sm-8">
                                    <label class="checkbox-inline">
                                        <input type="checkbox" name="abuseipdb_enabled" value="1" <?= (!empty($hpConfig['abuseipdb_enabled']) ? 'checked' : '') ?>>
                                        Отправлять отчеты в глобальную базу AbuseIPDB при автобане IP
                                    </label>
                                </div>
                            </div>

                            <div class="form-group">
                                <label class="control-label col-sm-4 text-semibold">AbuseIPDB API v2 Key:</label>
                                <div class="col-sm-6">
                                    <input type="password" name="abuseipdb_key" class="form-control" value="<?= htmlspecialchars($hpConfig['abuseipdb_key'] ?? '', ENT_QUOTES, 'UTF-8') ?>" placeholder="80-значный API ключ с abuseipdb.com">
                                    <span class="help-block font-size-xs text-muted">Ключ можно бесплатно получить на <a href="https://www.abuseipdb.com/account/api" target="_blank">abuseipdb.com/account/api</a>.</span>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="text-right">
                        <button type="submit" class="btn btn-primary"><i class="fa fa-floppy-o position-left"></i>Сохранить интеграции</button>
                    </div>
                </form>
            </div>

        </div>
    </div>
</div>

<script>
$(function() {
    var activeTab = '<?= htmlspecialchars($activeTab, ENT_QUOTES, 'UTF-8') ?>';
    if (window.location.hash) {
        activeTab = window.location.hash;
    }
    if (activeTab) {
        $('.nav-tabs a[href="' + activeTab + '"]').tab('show');
    }
    $('.nav-tabs a').on('shown.bs.tab', function (e) {
        window.location.hash = e.target.hash;
    });
});
</script>

<?php
echofooter();
?>