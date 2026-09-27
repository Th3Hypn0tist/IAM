<?php

declare(strict_types=1);

require_once __DIR__ . '/registration_guard.php';

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

    $formToken = iam_registration_create_form_state(
        $pdo,
        $invite
    );

    $email = (string)$invite['target_email'];

    header('Content-Type: text/html; charset=utf-8');
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>IAM registration</title>
<style>
body{font-family:system-ui,sans-serif;max-width:34rem;margin:4rem auto;padding:0 1rem;background:#111;color:#eee}
form{display:grid;gap:1rem}label{display:grid;gap:.35rem}input,button{font:inherit;padding:.7rem}
button{cursor:pointer}.status{min-height:1.5rem}small{color:#aaa}.hp{position:absolute;left:-10000px;width:1px;height:1px;overflow:hidden}
</style>
</head>
<body>
<h1>Register</h1>

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
</body>
</html>
<?php
}
