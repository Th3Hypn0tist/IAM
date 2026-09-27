<?php

declare(strict_types=1);

require_once __DIR__ . '/lib/common.php';
require_once __DIR__ . '/lib/login_view.php';
require_once __DIR__ . '/lib/identity_core.php';
require_once __DIR__ . '/lib/registration_view.php';
require_once __DIR__ . '/lib/email_change.php';

header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');

$pdo = iam_pdo();

if (array_key_exists('email_verify', $_GET)) {
    $verified = iam_verify_email_change(
        $pdo,
        trim((string)$_GET['email_verify'])
    );

    if (!$verified) {
        http_response_code(400);
        header('Content-Type: text/plain; charset=utf-8');
        echo 'Verification link not valid.';
        exit;
    }

    header('Location: /iam', true, 303);
    exit;
}

$route = trim((string)($_GET['route'] ?? ''), '/');

if ($route === 'register' && array_key_exists('token', $_GET)) {
    $inviteToken = trim((string)$_GET['token']);

    if ($inviteToken === '') {
        $context = iam_registration_context('');
        iam_registration_reject_invalid_invite($pdo, $context);
    }

    iam_render_registration_view($pdo, $inviteToken);
    exit;
}

if ($route !== '') {
    $profile = identitycore_public_profile_by_username($pdo, $route);

    if ($profile === null) {
        http_response_code(404);
        header('Content-Type: text/plain; charset=utf-8');
        echo 'User not found';
        exit;
    }

    header('Content-Type: text/html; charset=utf-8');
    ?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title><?= htmlspecialchars($profile['username'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?></title>
<style>
body{font-family:system-ui,sans-serif;max-width:42rem;margin:4rem auto;padding:0 1rem;background:#111;color:#eee}
dl{display:grid;grid-template-columns:max-content 1fr;gap:.5rem 1rem}
dt{color:#aaa}
</style>
</head>
<body>
<h1><?= htmlspecialchars($profile['username'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?></h1>
<?php if ($profile['fields'] === []): ?>
<p>No public profile information.</p>
<?php else: ?>
<dl>
<?php foreach ($profile['fields'] as $field => $value): ?>
<dt><?= htmlspecialchars(str_replace('_', ' ', $field), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?></dt>
<dd><?= htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?></dd>
<?php endforeach; ?>
</dl>
<?php endif; ?>
</body>
</html>
<?php
    exit;
}

$session = null;
$token = iam_bearer_token();
if ($token !== null) {
    $session = iam_session_row($pdo, $token);
}

header('Content-Type: text/html; charset=utf-8');

if ($session === null) {
    ?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>IAM Login</title>
<style>
body{font-family:system-ui,sans-serif;max-width:34rem;margin:4rem auto;padding:0 1rem;background:#111;color:#eee}
form{display:grid;gap:1rem}label{display:grid;gap:.35rem}input,button{font:inherit;padding:.7rem}
button{cursor:pointer}.iam-login-status{min-height:1.5rem}
</style>
</head>
<body>
<h1>Login</h1>
<?php iam_render_login_view(IAM_ROOT_DOMAIN); ?>
</body>
</html>
<?php
    exit;
}

$username = (string)$session['username'];
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>IAM Profile</title>
<style>
body{font-family:system-ui,sans-serif;max-width:42rem;margin:4rem auto;padding:0 1rem;background:#111;color:#eee}
form{display:grid;gap:1rem}.field{display:grid;grid-template-columns:1fr auto;gap:.5rem 1rem;align-items:end}
label{display:grid;gap:.35rem}input,button,select{font:inherit;padding:.7rem}button{cursor:pointer}.status{min-height:1.5rem}
.visibility{display:grid;gap:.35rem}
</style>
</head>
<body>
<h1><?= htmlspecialchars($username, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?></h1>

<button type="button" id="logout">Logout</button>

<section>
<h2>Domains</h2>
<div id="domains"></div>
</section>

<section>
<h2>Account</h2>
<form id="email-change">
<label>
Current email
<input id="current-email" readonly>
</label>
<label>
New email
<input id="new-email" type="email" maxlength="320" autocomplete="email">
</label>
<button type="submit">Change email</button>
<div class="status" id="email-status" role="status"></div>
</form>
</section>

<section>
<h2>Profile</h2>
<form id="profile">
<?php foreach (identitycore_fields() as $field): ?>
<div class="field">
    <label>
        <?= htmlspecialchars(str_replace('_', ' ', $field), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?>
        <input name="<?= htmlspecialchars($field, ENT_QUOTES, 'UTF-8') ?>">
    </label>
    <label class="visibility">
        Visibility
        <select name="<?= htmlspecialchars($field, ENT_QUOTES, 'UTF-8') ?>_visibility">
            <option value="private">Private</option>
            <option value="public">Public</option>
        </select>
    </label>
</div>
<?php endforeach; ?>

<button type="submit">Save profile</button>
<div class="status" id="status" role="status"></div>
</form>
</section>

<script>
const fields = <?= json_encode(identitycore_fields(), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) ?>;
const form = document.getElementById('profile');
const status = document.getElementById('status');
const emailForm = document.getElementById('email-change');
const emailStatus = document.getElementById('email-status');
const currentEmail = document.getElementById('current-email');
const newEmail = document.getElementById('new-email');
const logoutButton = document.getElementById('logout');
const domainsRoot = document.getElementById('domains');

async function loadDomains() {
    const response = await fetch('/iam/api/domains.php', {
        credentials: 'same-origin',
        headers: {'Accept':'application/json'}
    });
    const body = await response.json();

    if (!response.ok || body.ok !== true) {
        throw new Error(body.error || 'Domain load failed');
    }

    domainsRoot.replaceChildren();

    for (const domain of body.domains) {
        const row = document.createElement('div');
        row.textContent =
            domain.id + ' — tier ' + domain.effective_tier;
        domainsRoot.appendChild(row);
    }
}

async function loadProfile() {
    const response = await fetch('/iam/api/profile.php', {
        credentials: 'same-origin',
        headers: {'Accept':'application/json'}
    });
    const body = await response.json();

    if (!response.ok || body.ok !== true) {
        throw new Error(body.error || 'Profile load failed');
    }

    currentEmail.value = body.email ?? '';

    for (const field of fields) {
        form.elements[field].value = body.profile.fields[field] ?? '';
        form.elements[field + '_visibility'].value =
            body.profile.visibility[field] ?? 'private';
    }
}

logoutButton.addEventListener('click', async () => {
    await fetch('/iam/api/logout.php', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {'Accept':'application/json'}
    });

    window.location.replace('/iam');
});

emailForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    emailStatus.textContent = '';

    try {
        const response = await fetch('/iam/api/email.php', {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
                'Content-Type':'application/json',
                'Accept':'application/json'
            },
            body: JSON.stringify({
                email: newEmail.value
            })
        });

        const body = await response.json();

        if (!response.ok || body.ok !== true) {
            throw new Error(body.error || 'Email change failed');
        }

        newEmail.value = '';
        emailStatus.textContent = 'Verification email sent.';
    } catch (error) {
        emailStatus.textContent = error instanceof Error
            ? error.message
            : 'Email change failed';
    }
});

form.addEventListener('submit', async (event) => {
    event.preventDefault();
    status.textContent = '';

    const payload = {fields:{}, visibility:{}};

    for (const field of fields) {
        payload.fields[field] = form.elements[field].value;
        payload.visibility[field] =
            form.elements[field + '_visibility'].value;
    }

    try {
        const response = await fetch('/iam/api/profile.php', {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
                'Content-Type':'application/json',
                'Accept':'application/json'
            },
            body: JSON.stringify(payload)
        });

        const body = await response.json();

        if (!response.ok || body.ok !== true) {
            throw new Error(body.error || 'Profile save failed');
        }

        status.textContent = 'Saved.';
    } catch (error) {
        status.textContent = error instanceof Error
            ? error.message
            : 'Profile save failed';
    }
});

loadDomains().catch((error) => {
    domainsRoot.textContent = error instanceof Error
        ? error.message
        : 'Domain load failed';
});

loadProfile().catch((error) => {
    status.textContent = error instanceof Error
        ? error.message
        : 'Profile load failed';
});
</script>
</body>
</html>
