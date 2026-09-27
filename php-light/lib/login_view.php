<?php

declare(strict_types=1);

function iam_render_login_view(string $domainId = IAM_ROOT_DOMAIN): void {
    $domainId = iam_domain_id_normalize($domainId);

    if (!iam_domain_id_is_valid($domainId)) {
        throw new InvalidArgumentException('invalid login view domain');
    }

    $encodedDomain = json_encode(
        $domainId,
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
    );
?>
<section class="iam-login" data-iam-login>
    <form class="iam-login-form" autocomplete="on">
        <label>
            Username
            <input
                name="username"
                type="text"
                autocomplete="username"
                required
                maxlength="32"
            >
        </label>

        <label>
            Password
            <input
                name="password"
                type="password"
                autocomplete="current-password"
                required
                maxlength="1024"
            >
        </label>

        <button type="submit">Login</button>
        <div class="iam-login-status" role="status"></div>
    </form>
</section>

<script>
(() => {
    const root = document.currentScript.previousElementSibling;
    if (!root || !root.matches('[data-iam-login]')) return;

    const form = root.querySelector('.iam-login-form');
    const status = root.querySelector('.iam-login-status');
    const domain = <?= $encodedDomain ?>;

    form.addEventListener('submit', async (event) => {
        event.preventDefault();
        status.textContent = '';

        const data = new FormData(form);

        try {
            const response = await fetch('/iam/api/login.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                credentials: 'same-origin',
                body: JSON.stringify({
                    username: data.get('username'),
                    password: data.get('password'),
                    domain
                })
            });

            const body = await response.json();

            if (!response.ok || body.ok !== true) {
                throw new Error(body.error || 'Login failed');
            }

            window.location.reload();
        } catch (error) {
            status.textContent = error instanceof Error
                ? error.message
                : 'Login failed';
        }
    });
})();
</script>
<?php
}
