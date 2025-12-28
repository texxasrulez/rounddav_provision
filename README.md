# rounddav_provision

![Downloads](https://img.shields.io/github/downloads/texxasrulez/rounddav_provision/total?style=plastic&logo=github&logoColor=white&label=Downloads&labelColor=aqua&color=blue)
[![Packagist Downloads](https://img.shields.io/packagist/dt/texxasrulez/rounddav_provision?style=plastic&logo=packagist&logoColor=white&label=Downloads&labelColor=blue&color=gold)](https://packagist.org/packages/texxasrulez/rounddav_provision)
[![Packagist Version](https://img.shields.io/packagist/v/texxasrulez/rounddav_provision?style=plastic&logo=packagist&logoColor=white&label=Version&labelColor=blue&color=limegreen)](https://packagist.org/packages/texxasrulez/rounddav_provision)
[![Github License](https://img.shields.io/github/license/texxasrulez/rounddav_provision?style=plastic&logo=github&label=License&labelColor=blue&color=coral)](https://github.com/texxasrulez/rounddav_provision/LICENSE)
[![GitHub Stars](https://img.shields.io/github/stars/texxasrulez/rounddav_provision?style=plastic&logo=github&label=Stars&labelColor=blue&color=deepskyblue)](https://github.com/texxasrulez/rounddav_provision/stargazers)
[![GitHub Issues](https://img.shields.io/github/issues/texxasrulez/rounddav_provision?style=plastic&logo=github&label=Issues&labelColor=blue&color=aqua)](https://github.com/texxasrulez/rounddav_provision/issues)
[![GitHub Contributors](https://img.shields.io/github/contributors/texxasrulez/rounddav_provision?style=plastic&logo=github&logoColor=white&label=Contributors&labelColor=blue&color=orchid)](https://github.com/texxasrulez/rounddav_provision/graphs/contributors)
[![GitHub Forks](https://img.shields.io/github/forks/texxasrulez/rounddav_provision?style=plastic&logo=github&logoColor=white&label=Forks&labelColor=blue&color=darkorange)](https://github.com/texxasrulez/rounddav_provision/forks)
[![Donate Paypal](https://img.shields.io/badge/Paypal-Money_Please!-blue.svg?style=plastic&labelColor=blue&color=forestgreen&logo=paypal)](https://www.paypal.me/texxasrulez)


Automatic RoundDAV account provisioning and SSO integration for Roundcube.

This plugin binds Roundcube authentication to RoundDAV users, calendars, addressbooks, and the web-based Files UI.

This plugin requires [RoundDAV Server](https://github.com/texxasrulez/rounddav) to function.

Recommended Plugins:

[RoundDAV Files Roundcube Plugin](https://github.com/texxasrulez/rounddav_files)

[RoundDAV Bookmarks Roundcube Plugin](https://github.com/texxasrulez/rounddav_bookmarks)

Check out the [Suite README](README_suite.md) to see what is entailed.

---

## Features

- Creates a RoundDAV user on first Roundcube login
- Ensures default calendar and addressbook exist
- Creates extra calendars and addressbooks per user (config-driven)
- Generates one-shot SSO URLs for the RoundDAV Files UI
- Triggers SSO logout when the user logs out of Roundcube
- Logs everything to the `rounddav` log channel for easy debugging

This is the hub that keeps Roundcube and RoundDAV in sync.

---

## Installation

1. Copy the plugin into Roundcube:

```text
roundcube/plugins/rounddav_provision/
```

2. Enable it in Roundcube config (`config/config.inc.php` or equivalent):

```php
$config['plugins'][] = 'rounddav_provision';
```

3. Copy the default config:

```text
cd roundcube/plugins/rounddav_provision/
cp config.inc.php.dist config.inc.php
```

4. Edit `config.inc.php` and set at least:

```php
$config['rounddav_api_url']   = 'https://your.server/rounddav/public/api.php';
$config['rounddav_base_url']  = 'https://your.server/rounddav/public';
$config['rounddav_sso_secret'] = 'change_me_sso'; // must match RoundDAV config
$config['rounddav_sso_enabled'] = true;
```

---

## Configuration Options

### Core API/SSO

```php
// Where provisioning calls are sent
$config['rounddav_api_url']  = 'https://your.server/rounddav/public/api.php';

// Base URL for browser-facing RoundDAV (SSO, files UI, admin UI)
config['rounddav_base_url']  = 'https://your.server/rounddav/public';

// Shared secret used to HMAC-sign SSO tokens
$config['rounddav_sso_secret'] = 'change_me_sso';

// Toggle SSO integration (if false, rounddav_files falls back to plain URLs)
$config['rounddav_sso_enabled'] = true;
```

### Roundcube Preferences visibility

The plugin exposes a configuration card inside **Settings → Preferences**. Control who can see and
edit it with `rounddav_provision_settings_user_ids`:

```php
// Default: only Roundcube user ID 1 (typically the administrator)
$config['rounddav_provision_settings_user_ids'] = [1];

// Allow everyone
$config['rounddav_provision_settings_user_ids'] = '*';

// Allow a custom list
$config['rounddav_provision_settings_user_ids'] = [1, 7, 12];
```

The page lists the configured API endpoint, SSO state, and lets you edit every `config.inc.php`
option without SSH access (the file is rewritten automatically on save).

### Extra per-user calendars

Define zero or more calendars to be created for each new RoundDAV user:

```php
$config['rounddav_extra_calendars'] = [
    [
        'uri'         => 'personal',
        'displayname' => 'Personal',
        'mode'        => 'events',  // 'events', 'tasks', or 'both'
        'shared'      => false,
    ],
    [
        'uri'         => 'todo',
        'displayname' => 'Tasks',
        'mode'        => 'tasks',
        'shared'      => false,
    ],
];
```

- `uri` (required) – DAV collection URI segment (unique per user, not "default")
- `displayname` – what clients see; defaults to `uri` if omitted
- `mode` – how RoundDAV configures the `components` field:
  - `events` → `VEVENT`
  - `tasks`  → `VTODO`
  - `both`   → `VEVENT,VTODO`
- `shared` – reserved for future global/shared collections support

### Extra per-user addressbooks

```php
$config['rounddav_extra_addressbooks'] = [
    [
        'uri'         => 'work',
        'displayname' => 'Work Contacts',
        'shared'      => false,
    ],
    [
        'uri'         => 'shared',
        'displayname' => 'Shared Contacts',
        'shared'      => true,
    ],
];
```

- `uri` (required) – DAV addressbook URI segment (unique per user, not "default")
- `displayname` – human-readable label
- `shared` – reserved for future global sharing semantics

---

## How It Works Internally

### Hooks

The plugin registers:

- `authenticate($args)` – captures credentials for provisioning
- `login_after($args)` – performs provisioning and prepares SSO URL
- `logout_after($args)` – schedules a browser-side hit to RoundDAV SSO logout

### Provisioning Flow

1. User logs into Roundcube.
2. `authenticate` hook sees the username/password and stores them in `$_SESSION` temporarily.
3. `login_after` fires:
   - Reads credentials from `$_SESSION`.
   - Calls RoundDAV `/api.php?r=provision/user` with JSON payload.
   - Logs the response to `logs/rounddav`.
   - Generates SSO login URL and stores it in `$_SESSION['rounddav_sso_login_url']`.
4. `rounddav_files` later reads that SSO URL and uses it for the Files iframe.

### SSO Token Format

The SSO login URL looks like:

```text
https://your.server/rounddav/public/sso_login.php?user=<user>&ts=<ts>&sig=<sig>
```

Where:

- `ts` – `time()` at generation
- `sig` – `hash_hmac('sha256', "$user|$ts", $secret)`

Logout uses:

```text
https://your.server/rounddav/public/sso_logout.php?user=<user>&ts=<ts>&sig=<sig>
```

with the string `"$user|$ts|logout"` for the HMAC input.

---

## Logging

The plugin logs to the `rounddav` channel inside Roundcube:

- Provisioning calls and responses
- SSO URL generation
- SSO configuration status

This makes it easy to debug misconfigurations without guessing.

---

## Philosophy

`rounddav_provision` is intentionally boring in the best way:

- It doesn’t touch Roundcube core files.
- It uses documented hooks.
- It uses sessions and config like any other plugin.
- It does one job extremely well: keep DAV users in sync with Roundcube users.

Enjoy!

:moneybag: **Donations** :moneybag:

If you use this plugin and would like to show your appreciation by buying me a cup of coffee, I surely would appreciate it. A regular cup of Joe is sufficient, but a Starbucks Coffee would be better ... \
Zelle (Zelle is integrated within many major banks Mobile Apps by default) - Just send to texxasrulez at yahoo dot com \
No Zelle in your banks mobile app, no problem, just click [Paypal](https://paypal.me/texxasrulez?locale.x=en_US) and I can make a Starbucks run ...

I appreciate the interest in this plugin and hope all the best ...
