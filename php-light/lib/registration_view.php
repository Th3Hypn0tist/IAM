<?php

declare(strict_types=1);

require_once __DIR__ . '/registration_guard.php';
require_once __DIR__ . '/invites.php';
require_once __DIR__ . '/login_view.php';

function iam_render_registration_view(
    PDO $pdo,
    string $inviteToken
): void {
    $context = iam_registration_context($inviteToken);

    iam_registration_rate_limit($pdo, $context);

    $invite = iam_registration_require_usable_invite(
        $pdo,
        $context
    );

    $email = (string)$invite['target_email'];

    $existingUser = iam_invite_existing_user_by_email(
        $pdo,
        $email
    );

    if ($existingUser !== null) {
        $session = null;
        $sessionToken = iam_bearer_token();

        if ($sessionToken !== null) {
            $session = iam_session_row($pdo, $sessionToken);
        }

        if ($session === null) {
            header('Content-Type: text/html; charset=utf-8');
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Accept invitation</title>
<style>
body{font-family:system-ui,sans-serif;max-width:34rem;margin:4rem auto;padding:0 1rem;background:#111;color:#eee}
form{display:grid;gap:1rem}label{display:grid;gap:.35rem}input,button{font:inherit;padding:.7rem}
button{cursor:pointer}.iam-login-status{min-height:1.5rem}
</style>
</head>
<body>
<h1>Accept invitation</h1>
<p>Sign in to continue.</p>
<?php iam_render_login_view((string)$invite['domain_id']); ?>
</body>
</html>
<?php
            return;
        }

        if ((string)$session['user_id'] !== (string)$existingUser['user_id']) {
            http_response_code(403);
            header('Content-Type: text/plain; charset=utf-8');
            echo 'Invitation belongs to another account.';
            return;
        }

        iam_accept_invite_for_existing_user(
            $pdo,
            (string)$invite['invite_id'],
            (string)$existingUser['user_id'],
            (string)$invite['domain_id']
        );

        header('Location: /iam', true, 303);
        return;
    }

    $formToken = iam_registration_create_form_state(
        $pdo,
        $invite
    );

    header('Content-Type: text/html; charset=utf-8');
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>IAM registration</title>
<style>
html,body{min-height:100%}
body{margin:0;background:#030202;color:#fff;font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
main{width:min(92vw,420px);margin:0 auto;padding:5vh 0 8vh}
.logo{display:block;max-width:min(70vw,420px);height:auto;margin:0 auto}
.iam-title{text-align:center;margin:0;font-size:clamp(3.5rem,10vw,5rem);font-weight:600;letter-spacing:.08em;color:#fff;position:relative;top:-.65em}
h2{margin:-2.2rem 0 1.5rem;text-align:center;font-weight:500}
form{display:grid;gap:1rem}
label{display:grid;gap:.4rem;font-size:.9rem;color:#bbb}
input{box-sizing:border-box;width:100%;padding:.8rem .9rem;border:1px solid #333;border-radius:.35rem;background:#111;color:#fff;font:inherit}
input:focus{outline:1px solid #fff;outline-offset:1px}
button{padding:.8rem .9rem;border:1px solid #444;border-radius:.35rem;background:#fff;color:#030202;font:inherit;font-weight:600;cursor:pointer}
.status{min-height:1.5rem;color:#bbb;text-align:center}
small{color:#888}
.hp{position:absolute;left:-10000px;width:1px;height:1px;overflow:hidden}
</style>
</head>
<body>
<main>
<img class="logo" src="/images/AIGM-LOGO.png" alt="AIGM">
<h1 class="iam-title">IAM</h1>
<h2>Register</h2>

<form id="register">
<label>
Username
<input
    name="username"
    required
    autocomplete="username"
    minlength="3"
    maxlength="32"
    pattern="[A-Za-z0-9_.-]+"
>
</label>

<label>
Email
<input
    value="<?= htmlspecialchars($email, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?>"
    readonly
    autocomplete="email"
>
</label>

<label>
Password
<input
    name="password"
    type="password"
    required
    autocomplete="new-password"
    minlength="15"
    maxlength="1024"
>
</label>

<small>
Use a long passphrase. Four unrelated words is a good starting point.
</small>

<label>
Repeat password
<input
    name="repeat"
    type="password"
    required
    autocomplete="new-password"
    minlength="15"
    maxlength="1024"
>
</label>

<div class="hp" aria-hidden="true">
<label>
Website
<input name="website" autocomplete="off" tabindex="-1">
</label>
</div>

<button type="submit">Register</button>
<div class="status" id="status" role="status"></div>
</form>

<script>
const form = document.getElementById('register');
const status = document.getElementById('status');

const inviteToken =
    <?= json_encode(
        $inviteToken,
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
    ) ?>;

const formToken =
    <?= json_encode(
        $formToken,
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
    ) ?>;

form.addEventListener('submit', async (event) => {
    event.preventDefault();
    status.textContent = '';

    const data = new FormData(form);

    if (data.get('password') !== data.get('repeat')) {
        status.textContent = 'Passwords do not match.';
        return;
    }

    try {
        const response = await fetch('/iam/api/register.php', {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify({
                invite_code: inviteToken,
                form_token: formToken,
                username: data.get('username'),
                password: data.get('password'),
                website: data.get('website')
            })
        });

        const body = await response.json();

        if (!response.ok || body.ok !== true) {
            throw new Error(
                body.error || 'Registration failed'
            );
        }

        window.location.replace('/iam');
    } catch (error) {
        status.textContent = error instanceof Error
            ? error.message
            : 'Registration failed';
    }
});
</script>
</main>
</body>
</html>
<?php
}
