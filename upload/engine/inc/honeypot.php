<?php
/*
=====================================================
 DataLife Engine - by SoftNews Media Group 
-----------------------------------------------------
 https://dle-news.ru/
-----------------------------------------------------
 Copyright (c) 2004-2026 SoftNews Media Group
=====================================================
 File: honeypot.php
-----------------------------------------------------
 Use: WordPress Honeypot & Threat Intelligence Admin
 (Compliant with DLE Topic 73 Module Architecture)
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
$message = '';
$messageType = 'success';

// CSRF validation helper
$checkCsrf = function() use ($user_hash, $dle_login_hash) {
    if (!$user_hash || $user_hash !== $dle_login_hash) {
        die("Hacking attempt! Invalid security token.");
    }
};

// 1. Action: Save Configuration
if ($action === 'save_config') {
    $checkCsrf();
    $newMode = $_POST['mode'] ?? 'hybrid';
    if (!in_array($newMode, ['hybrid', 'bomb', 'tarpit', 'deception'])) {
        $newMode = 'hybrid';
    }
    $tarpitSeconds = max(5, min(60, intval($_POST['tarpit_seconds'] ?? 15)));
    $logEnabled = !empty($_POST['log_enabled']);

    SiteHoneypot::saveConfig([
        'mode'           => $newMode,
        'tarpit_seconds' => $tarpitSeconds,
        'log_enabled'    => $logEnabled,
    ]);

    $message = "Настройки Honeypot успешно сохранены.";
}

// 2. Action: Clear Log
if ($action === 'clear_log') {
    $checkCsrf();
    SiteHoneypot::clearLog();
    $message = "Журнал атак успешно очищен.";
}

// 3. Action: Block IP directly in DLE Banned Table
if ($action === 'block_ip') {
    $checkCsrf();
    $ipToBlock = trim($_POST['ip'] ?? '');
    if ($ipToBlock && filter_var($ipToBlock, FILTER_VALIDATE_IP)) {
        $ipSafe = $db->safesql($ipToBlock);
        $row = $db->super_query("SELECT id FROM " . USERPREFIX . "_banned WHERE ip = '{$ipSafe}'");
        if (!$row['id']) {
            $descr = $db->safesql("WordPress Honeypot auto-ban");
            $bannedFrom = $db->safesql($member_id['name']);
            $db->query("INSERT INTO " . USERPREFIX . "_banned (descr, date, days, ip, banned_from) VALUES ('{$descr}', '0', '0', '{$ipSafe}', '{$bannedFrom}')");
            @unlink(ENGINE_DIR . '/cache/system/banned.json');
            $message = "IP-адрес {$ipToBlock} успешно заблокирован в системе DLE.";
        } else {
            $message = "IP-адрес {$ipToBlock} уже находится в списке заблокированных DLE.";
            $messageType = 'warning';
        }
    } else {
        $message = "Некорректный IP-адрес.";
        $messageType = 'error';
    }
}

$config = SiteHoneypot::getConfig();
$stats = SiteHoneypot::getStats();
$recentAttacks = SiteHoneypot::getLog(50);
$logSizeKb = round($stats['log_size'] / 1024, 1);

echoheader(
    "<i class=\"fa fa-shield position-left\"></i><span class=\"text-semibold\">WordPress Honeypot</span>",
    "Управление ловушками ботов и анализ угроз"
);

if ($message) {
    $alertClass = $messageType === 'error' ? 'alert-danger' : ($messageType === 'warning' ? 'alert-warning' : 'alert-success');
    echo "<div class=\"alert {$alertClass} alert-styled-left alert-arrow-left alert-bordered\">" . htmlspecialchars($message, ENT_QUOTES, 'UTF-8') . "</div>";
}
?>

<div class="row">
    <!-- Statistics Cards -->
    <div class="col-sm-3">
        <div class="panel panel-default">
            <div class="panel-heading"><h6 class="panel-title text-uppercase font-size-xs text-muted">Всего перехвачено атак</h6></div>
            <div class="panel-body text-center">
                <h2 class="text-primary no-margin font-weight-semibold"><?= number_format($stats['total_attacks'], 0, '.', ' ') ?></h2>
            </div>
        </div>
    </div>
    <div class="col-sm-3">
        <div class="panel panel-default">
            <div class="panel-heading"><h6 class="panel-title text-uppercase font-size-xs text-muted">Уникальных IP ботов</h6></div>
            <div class="panel-body text-center">
                <h2 class="text-danger no-margin font-weight-semibold"><?= number_format($stats['unique_ips'], 0, '.', ' ') ?></h2>
            </div>
        </div>
    </div>
    <div class="col-sm-3">
        <div class="panel panel-default">
            <div class="panel-heading"><h6 class="panel-title text-uppercase font-size-xs text-muted">Текущий режим реакции</h6></div>
            <div class="panel-body text-center">
                <h3 class="no-margin text-semibold text-uppercase text-slate">
                    <?php
                    $modeLabels = [
                        'hybrid'    => 'Гибридный (Мимикрия + Бомба)',
                        'bomb'      => 'Мгновенная Gzip-бомба',
                        'tarpit'    => 'Tarpit (Замедление)',
                        'deception' => 'Мимикрия (Без бомбы)',
                    ];
                    echo htmlspecialchars($modeLabels[$config['mode']] ?? $config['mode'], ENT_QUOTES, 'UTF-8');
                    ?>
                </h3>
            </div>
        </div>
    </div>
    <div class="col-sm-3">
        <div class="panel panel-default">
            <div class="panel-heading"><h6 class="panel-title text-uppercase font-size-xs text-muted">Размер журнала атак</h6></div>
            <div class="panel-body text-center">
                <h2 class="text-success no-margin font-weight-semibold"><?= $logSizeKb ?> КБ</h2>
            </div>
        </div>
    </div>
</div>

<div class="row">
    <!-- Settings Form -->
    <div class="col-md-6">
        <div class="panel panel-default">
            <div class="panel-heading">
                <h6 class="panel-title"><i class="fa fa-cogs position-left"></i>Режим работы Honeypot</h6>
            </div>
            <div class="panel-body">
                <form action="?mod=honeypot&action=save_config" method="post" class="form-horizontal">
                    <input type="hidden" name="user_hash" value="<?= $dle_login_hash ?>">
                    
                    <div class="form-group">
                        <label class="control-label col-sm-4 text-semibold">Стратегия нейтрализации:</label>
                        <div class="col-sm-8">
                            <div class="radio">
                                <label>
                                    <input type="radio" name="mode" value="hybrid" <?= ($config['mode'] === 'hybrid' ? 'checked' : '') ?>>
                                    <b>Гибридный (Рекомендуется)</b>: на GET отдавать страницу входа WP 6.x (~3 КБ); на POST логировать учетные данные брутфорса и взрывать Gzip-бомбой.
                                </label>
                            </div>
                            <div class="radio">
                                <label>
                                    <input type="radio" name="mode" value="bomb" <?= ($config['mode'] === 'bomb' ? 'checked' : '') ?>>
                                    <b>Мгновенная Gzip-бомба</b>: сразу детонировать 10 ГБ архив при любых запросах (только если клиент поддерживает gzip).
                                </label>
                            </div>
                            <div class="radio">
                                <label>
                                    <input type="radio" name="mode" value="tarpit" <?= ($config['mode'] === 'tarpit' ? 'checked' : '') ?>>
                                    <b>Tarpit (Вязкая смола)</b>: удерживать соединение 15-30 сек по 1 байту, зависая потоки сканеров без расхода трафика.
                                </label>
                            </div>
                            <div class="radio">
                                <label>
                                    <input type="radio" name="mode" value="deception" <?= ($config['mode'] === 'deception' ? 'checked' : '') ?>>
                                    <b>Чистая дезинформация</b>: собирать пароли и возвращать стандартную ошибку входа WordPress.
                                </label>
                            </div>
                        </div>
                    </div>

                    <div class="form-group">
                        <label class="control-label col-sm-4">Время удержания Tarpit (сек):</label>
                        <div class="col-sm-4">
                            <input type="number" name="tarpit_seconds" min="5" max="60" class="form-control" value="<?= intval($config['tarpit_seconds'] ?? 15) ?>">
                        </div>
                    </div>

                    <div class="form-group">
                        <label class="control-label col-sm-4">Журналирование атак:</label>
                        <div class="col-sm-8">
                            <label class="checkbox-inline">
                                <input type="checkbox" name="log_enabled" value="1" <?= (!empty($config['log_enabled']) ? 'checked' : '') ?>> Вести защищенный лог попыток входа
                            </label>
                        </div>
                    </div>

                    <div class="text-right">
                        <button type="submit" class="btn btn-primary"><i class="fa fa-floppy-o position-left"></i>Сохранить настройки</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <!-- Threat Intelligence: Top Passwords & Actions -->
    <div class="col-md-6">
        <div class="panel panel-default">
            <div class="panel-heading">
                <h6 class="panel-title"><i class="fa fa-key position-left"></i>Топ перехваченных паролей ботов</h6>
            </div>
            <div class="panel-body">
                <?php if (empty($stats['top_passwords'])): ?>
                    <p class="text-muted text-center" style="padding: 20px 0;">Пока нет зафиксированных попыток подбора паролей.</p>
                <?php else: ?>
                    <table class="table table-xs table-striped">
                        <thead>
                            <tr>
                                <th>Пароль из словаря бота</th>
                                <th class="text-right" style="width: 100px;">Попыток</th>
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

<!-- Top IPs with Direct DLE Ban button -->
<div class="panel panel-default">
    <div class="panel-heading">
        <h6 class="panel-title"><i class="fa fa-crosshairs position-left"></i>Топ атакующих IP-адресов</h6>
    </div>
    <div class="table-responsive">
        <?php if (empty($stats['top_ips'])): ?>
            <p class="text-muted text-center" style="padding: 20px 0;">Атак пока не зафиксировано.</p>
        <?php else: ?>
            <table class="table table-striped table-hover">
                <thead>
                    <tr>
                        <th>IP-адрес бота</th>
                        <th class="text-center">Количество атак</th>
                        <th class="text-right">Быстрое действие</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($stats['top_ips'] as $ip => $count): ?>
                        <tr>
                            <td>
                                <strong><?= htmlspecialchars($ip, ENT_QUOTES, 'UTF-8') ?></strong>
                                <a href="https://whois.domaintools.com/<?= urlencode($ip) ?>" target="_blank" class="text-muted ml-5 font-size-xs" title="Whois lookup"><i class="fa fa-external-link"></i></a>
                            </td>
                            <td class="text-center"><span class="badge badge-primary"><?= $count ?></span></td>
                            <td class="text-right">
                                <form action="?mod=honeypot&action=block_ip" method="post" style="display:inline-block;">
                                    <input type="hidden" name="user_hash" value="<?= $dle_login_hash ?>">
                                    <input type="hidden" name="ip" value="<?= htmlspecialchars($ip, ENT_QUOTES, 'UTF-8') ?>">
                                    <button type="submit" class="btn btn-xs btn-danger"><i class="fa fa-ban position-left"></i>В бан-лист DLE</button>
                                </form>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </div>
</div>

<!-- Recent Attacks Feed -->
<div class="panel panel-default">
    <div class="panel-heading">
        <h6 class="panel-title"><i class="fa fa-list position-left"></i>Последние 50 перехваченных атак</h6>
    </div>
    <div class="table-responsive">
        <?php if (empty($recentAttacks)): ?>
            <p class="text-muted text-center" style="padding: 20px 0;">Журнал пуст.</p>
        <?php else: ?>
            <table class="table table-striped table-hover font-size-xs">
                <thead>
                    <tr>
                        <th>Дата и время</th>
                        <th>IP-адрес</th>
                        <th>Метод и URI</th>
                        <th>Логин</th>
                        <th>Пароль</th>
                        <th>Примененная санкция</th>
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

<?php
echofooter();
?>
