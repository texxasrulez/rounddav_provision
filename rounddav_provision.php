<?php

/**
 * RoundDAV provision plugin for Roundcube
 *
 * Automatically provisions a RoundDAV user (and default DAV collections)
 * on successful Roundcube login by calling the RoundDAV provisioning API.
 */

class rounddav_provision extends rcube_plugin
{
    public $task = 'login|mail|settings';

    private $rc;
    private $config;
    private $settings_allowed_user_ids = [];
    private $settings_allow_everyone = false;
    private $config_file_path;
    private $config_is_writable = false;
    private $config_schema;

    public function init()
    {
        $this->rc = rcube::get_instance();

        // Load plugin config from config.inc.php in plugin root
        $this->load_config('config.inc.php');
        $this->add_texts('localization/', true);

        // Backward-compatible config lookup. We first use the new
        // rounddav_api_* options, then fall back to older names so the
        // plugin keeps working after upgrades without forcing a config change.
        $api_url = trim((string) $this->rc->config->get('rounddav_api_url', ''));
        if ($api_url === '') {
            $api_url = trim((string) $this->rc->config->get('rounddav_provision_api_url', ''));
        }
        if ($api_url === '') {
            $api_url = trim((string) $this->rc->config->get('rounddav_url', ''));
        }

        $api_token = (string) $this->rc->config->get('rounddav_api_token', '');
        if ($api_token === '') {
            $api_token = (string) $this->rc->config->get('rounddav_provision_api_token', '');
        }
        if ($api_token === '') {
            $api_token = (string) $this->rc->config->get('rounddav_token', '');
        }

        $timeout = (int) $this->rc->config->get('rounddav_api_timeout', 5);
        if ($timeout <= 0) {
            $timeout = (int) $this->rc->config->get('rounddav_provision_api_timeout', $timeout);
        }
        if ($timeout <= 0) {
            $timeout = (int) $this->rc->config->get('rounddav_timeout', 5);
        }

        $verify_ssl_raw = $this->rc->config->get('rounddav_api_verify_ssl', null);
        if ($verify_ssl_raw === null) {
            // Older option names
            $verify_ssl_raw = $this->rc->config->get('rounddav_provision_api_verify_ssl', null);
            if ($verify_ssl_raw === null) {
                $verify_ssl_raw = $this->rc->config->get('rounddav_verify_ssl', true);
            }
        }
        $verify_ssl = (bool) $verify_ssl_raw;

        // SSO-related configuration for RoundDAV web UI.
        $sso_enabled = (bool) $this->rc->config->get('rounddav_sso_enabled', false);
        $sso_base    = rtrim((string) $this->rc->config->get('rounddav_base_url', ''), '/');
        $sso_secret  = (string) $this->rc->config->get('rounddav_sso_secret', '');

        $this->config = [
            'api_url'     => $api_url,
            'api_token'   => $api_token,
            'timeout'     => $timeout,
            'verify_ssl'  => $verify_ssl,
            'sso_enabled' => $sso_enabled,
            'sso_base'    => $sso_base,
            'sso_secret'  => $sso_secret,
        ];

        $this->config_file_path = $this->home . '/config.inc.php';
        $this->config_is_writable = $this->is_path_writable($this->config_file_path);

        $this->init_preferences_acl();

        $this->add_hook('authenticate', [$this, 'authenticate']);
        $this->add_hook('login_after',  [$this, 'login_after']);
        $this->add_hook('logout_after', [$this, 'logout_after']);
        $this->add_hook('rounddav_api_credentials', [$this, 'share_api_credentials']);

        if ($this->rc->task === 'settings') {
            $skin_path = $this->local_skin_path();
            if (!empty($skin_path)) {
                $this->include_stylesheet($skin_path . '/rounddav_provision.css');
            }

            if ($this->is_preferences_accessible()) {
                $this->add_hook('preferences_sections_list', [$this, 'preferences_sections_list']);
                $this->add_hook('preferences_list', [$this, 'preferences_list']);
                $this->add_hook('preferences_save', [$this, 'preferences_save']);
            }
        }
    }

	public function authenticate($args = [])
    {
        // Cache credentials in PHP session so we have the cleartext password
        // available in login_after. Use $_SESSION directly for maximum
        // compatibility across Roundcube versions.
        if (!empty($args['user']) && !empty($args['pass'])) {
            $_SESSION['rounddav_user'] = $args['user'];
            $_SESSION['rounddav_pass'] = $args['pass'];
        }

        return $args;
    }

    public function login_after($args = [])
    {
        if (empty($this->config['api_url']) || empty($this->config['api_token'])) {
            // Silent no-op previously; now log once per request so misconfig
            // is visible in logs instead of silently skipping provisioning.
            rcube::write_log('rounddav', 'rounddav_provision: missing api_url or api_token, skipping provisioning.');
            return $args;
        }

        $username = isset($_SESSION['rounddav_user']) ? $_SESSION['rounddav_user'] : null;
        $password = isset($_SESSION['rounddav_pass']) ? $_SESSION['rounddav_pass'] : null;

        if (empty($username) || empty($password)) {
            return $args; // nothing to provision
        }

        // Reset so we don't keep creds in session longer than necessary
        unset($_SESSION['rounddav_user'], $_SESSION['rounddav_pass']);

        try {
            $this->provision_user($username, $password);
        } catch (Exception $e) {
            // Log but do not block login
            rcube::write_log('rounddav', 'Provisioning error: ' . $e->getMessage());
        }

        // After successful Roundcube login (regardless of provisioning result),
        // prepare a one-shot SSO login URL for the RoundDAV web UI and store it
        // in the Roundcube session. The rounddav_files plugin can then consume
        // this URL to transparently log the user into the RoundDAV Files UI.
        rcube::write_log('rounddav', 'rounddav_provision: login_after called for user=' . $username);

        if (!empty($this->config['sso_enabled']) && !empty($this->config['sso_base']) && !empty($this->config['sso_secret'])) {
            $ts   = (string) time();
            $data = $username . '|' . $ts;
            $sig  = hash_hmac('sha256', $data, $this->config['sso_secret']);

            $sso_login_url = $this->config['sso_base']
                . '/sso_login.php'
                . '?user=' . rawurlencode($username)
                . '&ts='   . rawurlencode($ts)
                . '&sig='  . rawurlencode($sig);

            rcube::write_log('rounddav', 'rounddav_provision: prepared SSO login URL=' . $sso_login_url);

            $_SESSION['rounddav_sso_login_url'] = $sso_login_url;
        } else {
            rcube::write_log('rounddav', 'rounddav_provision: SSO not enabled or misconfigured (sso_enabled='
                . var_export($this->config['sso_enabled'], true)
                . ', sso_base=' . var_export($this->config['sso_base'], true) . ')');
        }

        return $args;
    }

    private function provision_user($username, $password)
    {
        $url = $this->config['api_url'];

        if ($url === '') {
            throw new RuntimeException('RoundDAV API URL is empty');
        }

        // Derive display name/email for provisioning
        list($displayName, $email) = $this->resolve_user_metadata($username);

        // Build provisioning payload, including optional extra DAV collections
        $extra_calendars = $this->rc->config->get('rounddav_extra_calendars', []);
        if (!is_array($extra_calendars)) {
            $extra_calendars = [];
        }

        $extra_addressbooks = $this->rc->config->get('rounddav_extra_addressbooks', []);
        if (!is_array($extra_addressbooks)) {
            $extra_addressbooks = [];
        }

        $payloadArray = [
            'username'           => $username,
            'password'           => $password,
            'displayname'        => $displayName,
            'email'              => $email,
            'extra_calendars'    => $extra_calendars,
            'extra_addressbooks' => $extra_addressbooks,
        ];

        $payload = json_encode($payloadArray);

        if ($payload === false) {
            throw new RuntimeException('Failed to JSON-encode provisioning payload');
        }

        $ch = curl_init($url);
        if ($ch === false) {
            throw new RuntimeException('Failed to initialize cURL');
        }

        $headers = [
            'Content-Type: application/json',
            'X-RoundDAV-Token: ' . $this->config['api_token'],
        ];

        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, $this->config['timeout']);

        if (!$this->config['verify_ssl']) {
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        }

        // Execute request
        $response  = curl_exec($ch);
        $curl_err  = curl_error($ch);
        $httpCode  = curl_getinfo($ch, CURLINFO_HTTP_CODE);

        // Log raw response for debugging (truncate to keep log sane)
        rcube::write_log(
            'rounddav',
            "Provisioning RAW response\n" .
            "URL: {$url}\n" .
            "HTTP code: {$httpCode}\n" .
            "cURL error: " . ($curl_err !== '' ? $curl_err : 'none') . "\n" .
            "Response (first 2000 bytes):\n" . substr((string) $response, 0, 2000)
        );

        if ($response === false) {
            curl_close($ch);
            throw new RuntimeException('cURL error: ' . ($curl_err !== '' ? $curl_err : 'unknown error'));
        }

        curl_close($ch);

        // Decode JSON
        $data = json_decode($response, true);
        if ($data === null && json_last_error() !== JSON_ERROR_NONE) {
            $json_err = json_last_error_msg();
            rcube::write_log(
                'rounddav',
                'Provisioning JSON decode error: ' . $json_err
            );
            throw new RuntimeException('Invalid JSON response from RoundDAV API: ' . $json_err);
        }

        // Check API-level result
        if ($httpCode !== 200 || empty($data['status']) || $data['status'] !== 'ok') {
            $msg = isset($data['message']) ? $data['message'] : 'Unknown error';
            rcube::write_log(
                'rounddav',
                'Provisioning failed (HTTP ' . $httpCode . '): ' . $msg
            );
            throw new RuntimeException('Provisioning failed (HTTP ' . $httpCode . '): ' . $msg);
        }

        // success, no further action needed
        rcube::write_log('rounddav', 'Provisioning succeeded for user: ' . $username);

        $username = $this->rc->get_user_name();
        if (empty($username)) {
            return;
        }

        $ts   = (string) time();
        $data = $username . '|' . $ts . '|logout';
        $sig  = hash_hmac('sha256', $data, $this->config['sso_secret']);

        $sso_logout_url = $this->config['sso_base']
            . '/sso_logout.php'
            . '?user=' . rawurlencode($username)
            . '&ts='   . rawurlencode($ts)
            . '&sig='  . rawurlencode($sig);

        // Use a tiny image request on the logout page so the browser hits
        // the RoundDAV logout URL without blocking the logout flow.
        $this->rc->output->add_script(
            "new Image().src = " . json_encode($sso_logout_url) . ";",
            'foot'
        );

        // Also clear any stored SSO login URL
        unset($_SESSION['rounddav_sso_login_url']);

        return;
    }

    public function logout_after($args = [])
    {
        // On Roundcube logout, send a fire-and-forget ping to RoundDAV to
        // terminate the corresponding SSO session (if configured).
        if (empty($this->config['sso_enabled']) || empty($this->config['sso_base']) || empty($this->config['sso_secret'])) {
            return $args;
        }

        $username = $this->rc->get_user_name();
        if (empty($username)) {
            return $args;
        }

        $ts   = (string) time();
        $data = $username . '|' . $ts . '|logout';
        $sig  = hash_hmac('sha256', $data, $this->config['sso_secret']);

        $sso_logout_url = $this->config['sso_base']
            . '/sso_logout.php'
            . '?user=' . rawurlencode($username)
            . '&ts='   . rawurlencode($ts)
            . '&sig='  . rawurlencode($sig);

        // Use a tiny image request on the logout page so the browser hits
        // the RoundDAV logout URL without blocking the logout flow.
        $this->rc->output->add_script(
            "new Image().src = " . json_encode($sso_logout_url) . ";",
            'foot'
        );

        // Also clear any stored SSO login URL
        unset($_SESSION['rounddav_sso_login_url']);

        return $args;
    }

    public function share_api_credentials($args = [])
    {
        $args['credentials'] = [
            'api_url'    => $this->config['api_url'],
            'api_token'  => $this->config['api_token'],
            'timeout'    => $this->config['timeout'],
            'verify_ssl' => $this->config['verify_ssl'],
            'base_url'   => $this->rc->config->get('rounddav_base_url', ''),
        ];

        if (!empty($this->config['sso_enabled']) && !empty($this->config['sso_base']) && !empty($this->config['sso_secret'])) {
            $args['credentials']['sso'] = [
                'enabled' => true,
                'base'    => $this->config['sso_base'],
                'secret'  => $this->config['sso_secret'],
            ];
        } else {
            $args['credentials']['sso'] = ['enabled' => false];
        }

        return $args;
    }

    public function preferences_sections_list($args)
    {
        if (!$this->is_preferences_accessible()) {
            return $args;
        }

        $args['list']['rounddav_provision'] = [
            'id'      => 'rounddav_provision',
            'section' => $this->gettext('rounddav_provision.preferences_menu'),
            'class'   => 'rounddav_provision',
        ];

        return $args;
    }

    public function preferences_list($args)
    {
        if ($args['section'] !== 'rounddav_provision' || !$this->is_preferences_accessible()) {
            return $args;
        }

        if (empty($args['current'])) {
            $args['blocks']['rounddav_provision']['content'] = true;
            return $args;
        }

        $schema = $this->get_config_schema();
        $values = $this->get_current_config_values($schema);

        $overview = $this->render_preferences_overview();
        $config_block = $this->build_config_block($schema, $values);

        $args['blocks'] = [
            'overview' => [
                'name'    => $this->gettext('rounddav_provision.preferences_overview_block'),
                'content' => $overview,
            ],
            'config' => $config_block,
        ];

        return $args;
    }

    public function preferences_save($args)
    {
        if ($args['section'] !== 'rounddav_provision' || !$this->is_preferences_accessible()) {
            return $args;
        }

        if (!$this->config_is_writable) {
            $args['abort']  = true;
            $args['result'] = false;
            $args['message'] = $this->gettext('rounddav_provision.config_not_writable');
            return $args;
        }

        $schema = $this->get_config_schema();
        $result = $this->collect_config_input($schema);

        if (!$result['success']) {
            $args['abort']  = true;
            $args['result'] = false;
            $args['message'] = $result['message'];
            return $args;
        }

        $saved = $this->save_config_values($result['values']);

        if ($saved) {
            foreach ($result['values'] as $key => $value) {
                $this->rc->config->set($key, $value);
                if (array_key_exists($key, $this->config)) {
                    $this->config[$key] = $value;
                }
            }

            $this->init_preferences_acl();

            $args['abort']  = true;
            $args['result'] = true;
        } else {
            $args['abort']  = true;
            $args['result'] = false;
            $args['message'] = $this->gettext('rounddav_provision.save_error');
        }

        return $args;
    }

    private function init_preferences_acl()
    {
        $allowed = $this->rc->config->get('rounddav_provision_settings_user_ids', [1]);

        if ($allowed === true || $allowed === '*' || $allowed === 'all' || $allowed === 'everyone') {
            $this->settings_allow_everyone = true;
            $this->settings_allowed_user_ids = [];
            return;
        }

        if (is_string($allowed) && strpos($allowed, ',') !== false) {
            $parts = array_filter(array_map('trim', explode(',', $allowed)));
            $allowed = $parts;
        }

        if (!is_array($allowed)) {
            $allowed = [$allowed];
        }

        foreach ($allowed as $value) {
            if ($value === '' || $value === null) {
                continue;
            }

            $int_value = (int) $value;
            if ($int_value > 0) {
                $this->settings_allowed_user_ids[] = $int_value;
            }
        }

        $this->settings_allowed_user_ids = array_values(array_unique($this->settings_allowed_user_ids));
    }

    private function is_preferences_accessible()
    {
        if ($this->settings_allow_everyone) {
            return true;
        }

        if (empty($this->settings_allowed_user_ids) || empty($this->rc->user)) {
            return false;
        }

        $user_id = (int) $this->rc->user->ID;
        if ($user_id <= 0) {
            return false;
        }

        return in_array($user_id, $this->settings_allowed_user_ids, true);
    }

    private function preferences_acl_message()
    {
        if ($this->settings_allow_everyone) {
            return $this->gettext('rounddav_provision.preferences_acl_everyone');
        }

        if (!empty($this->settings_allowed_user_ids)) {
            return sprintf(
                $this->gettext('rounddav_provision.preferences_acl_specific'),
                implode(', ', $this->settings_allowed_user_ids)
            );
        }

        return $this->gettext('rounddav_provision.preferences_acl_none');
    }

    private function render_preferences_overview()
    {
        $intro = html::tag('p', ['class' => 'rdp-intro'], $this->gettext('rounddav_provision.preferences_intro'));

        $status = (!empty($this->config['api_url']) && !empty($this->config['api_token']))
            ? $this->gettext('rounddav_provision.status_enabled')
            : $this->gettext('rounddav_provision.status_disabled');

        $status_block = html::div(
            ['id' => 'rdp-inline-rounddav_provision', 'class' => 'rdp-row'],
            html::tag('span', ['class' => 'rdp-label'], $this->gettext('rounddav_provision.preferences_status_label')) .
            html::tag('span', ['class' => 'rdp-value'], $status)
        );

        $base_url = $this->config['sso_base'];
        if ($base_url === '') {
            $base_url = (string) $this->rc->config->get('rounddav_base_url', '');
        }

        $rows = [];
        $rows[] = [
            'label'      => $this->gettext('rounddav_provision.preferences_api_url'),
            'value'      => $this->config['api_url'] !== '' ? $this->config['api_url'] : $this->gettext('rounddav_provision.not_configured'),
            'allow_html' => false,
        ];
        $rows[] = [
            'label'      => $this->gettext('rounddav_provision.preferences_base_url'),
            'value'      => $base_url !== ''
                ? html::a(
                    [
                        'href'   => $base_url,
                        'target' => '_blank',
                        'rel'    => 'noreferrer noopener',
                    ],
                    rcube::Q($base_url)
                )
                : $this->gettext('rounddav_provision.not_configured'),
            'allow_html' => $base_url !== '',
        ];
        $rows[] = [
            'label'      => $this->gettext('rounddav_provision.preferences_sso_label'),
            'value'      => !empty($this->config['sso_enabled'])
                ? $this->gettext('rounddav_provision.preferences_sso_enabled')
                : $this->gettext('rounddav_provision.preferences_sso_disabled'),
            'allow_html' => false,
        ];
        $rows[] = [
            'label'      => $this->gettext('rounddav_provision.preferences_acl_label'),
            'value'      => $this->preferences_acl_message(),
            'allow_html' => false,
        ];

        $tbody = '';
        foreach ($rows as $row) {
            $value = $row['allow_html'] ? $row['value'] : rcube::Q((string) $row['value']);
            $tbody .= html::tag('tr', [],
                html::tag('th', [], rcube::Q($row['label'])) .
                html::tag('td', [], $value)
            );
        }

        $table = html::tag('table', ['class' => 'propform'], html::tag('tbody', [], $tbody));

        return $intro . $status_block . $table;
    }

    private function build_config_block(array $schema, array $values)
    {
        $options = [];

        foreach ($schema as $key => $meta) {
            $field_id = 'rcmfd_' . $key;
            $label    = html::label($field_id, rcube::Q($meta['label']));
            $content  = $this->render_config_field($key, $meta, $values[$key], $field_id);

            $options[$key] = [
                'title'   => $label,
                'content' => $content,
            ];
        }

        $content = html::tag(
            'p',
            ['class' => 'rdp-config-path'],
            sprintf(
                $this->gettext('rounddav_provision.config_path_label'),
                rcube::Q($this->config_file_path)
            )
        );

        if (!$this->config_is_writable) {
            $content .= html::tag(
                'div',
                ['class' => 'rdp-warning'],
                $this->gettext('rounddav_provision.config_not_writable')
            );
        } else {
            $content .= html::tag(
                'div',
                ['class' => 'rdp-help'],
                $this->gettext('rounddav_provision.config_edit_hint')
            );
        }

        return [
            'name'    => $this->gettext('rounddav_provision.preferences_config_block'),
            'content' => $content,
            'options' => $options,
        ];
    }

    private function get_config_schema()
    {
        if ($this->config_schema !== null) {
            return $this->config_schema;
        }

        $this->config_schema = [
            'rounddav_base_url' => [
                'label'       => $this->gettext('rounddav_provision.field_base_url'),
                'type'        => 'text',
                'required'    => true,
                'rtrim_slash' => true,
            ],
            'rounddav_api_url' => [
                'label'    => $this->gettext('rounddav_provision.field_api_url'),
                'type'     => 'text',
                'required' => true,
            ],
            'rounddav_api_token' => [
                'label' => $this->gettext('rounddav_provision.field_api_token'),
                'type'  => 'text',
            ],
            'rounddav_sso_secret' => [
                'label' => $this->gettext('rounddav_provision.field_sso_secret'),
                'type'  => 'text',
            ],
            'rounddav_sso_enabled' => [
                'label' => $this->gettext('rounddav_provision.field_sso_enabled'),
                'type'  => 'bool',
            ],
            'rounddav_provision_settings_user_ids' => [
                'label'       => $this->gettext('rounddav_provision.field_acl'),
                'type'        => 'user_ids',
                'description' => $this->gettext('rounddav_provision.field_acl_desc'),
            ],
            'rounddav_api_timeout' => [
                'label' => $this->gettext('rounddav_provision.field_timeout'),
                'type'  => 'int',
                'min'   => 1,
            ],
            'rounddav_api_verify_ssl' => [
                'label' => $this->gettext('rounddav_provision.field_verify_ssl'),
                'type'  => 'bool',
            ],
            'rounddav_extra_calendars' => [
                'label'       => $this->gettext('rounddav_provision.field_extra_calendars'),
                'type'        => 'json',
                'rows'        => 6,
                'description' => $this->gettext('rounddav_provision.field_json_hint'),
            ],
            'rounddav_extra_addressbooks' => [
                'label'       => $this->gettext('rounddav_provision.field_extra_addressbooks'),
                'type'        => 'json',
                'rows'        => 6,
                'description' => $this->gettext('rounddav_provision.field_json_hint'),
            ],
        ];

        return $this->config_schema;
    }

    private function get_current_config_values(array $schema)
    {
        $values = [];

        foreach ($schema as $key => $meta) {
            $values[$key] = $this->rc->config->get($key);
        }

        return $values;
    }

    private function render_config_field($key, array $meta, $value, $field_id)
    {
        $name = '_' . $key;
        $content = '';

        switch ($meta['type']) {
            case 'bool':
                $checkbox = new html_checkbox([
                    'name'  => $name,
                    'id'    => $field_id,
                    'value' => 1,
                ]);
                $content = $checkbox->show(!empty($value) ? 1 : 0);
                break;

            case 'int':
                $input = new html_inputfield([
                    'type' => 'number',
                    'name' => $name,
                    'id'   => $field_id,
                    'size' => 8,
                    'min'  => $meta['min'] ?? null,
                ]);
                $content = $input->show((int) $value);
                break;

            case 'json':
                $textarea = new html_textarea([
                    'name' => $name,
                    'id'   => $field_id,
                    'rows' => $meta['rows'] ?? 8,
                    'cols' => 70,
                ]);
                $content = $textarea->show($this->format_json_value($value));
                break;

            case 'user_ids':
                $input = new html_inputfield([
                    'name' => $name,
                    'id'   => $field_id,
                    'size' => 40,
                ]);
                $content = $input->show($this->format_user_ids_value($value));
                break;

            default:
                $input = new html_inputfield([
                    'name' => $name,
                    'id'   => $field_id,
                    'size' => 70,
                    'type' => $meta['input_type'] ?? 'text',
                ]);
                $content = $input->show(is_array($value) ? '' : (string) $value);
                break;
        }

        if (!empty($meta['description'])) {
            $content .= html::tag('div', ['class' => 'rdp-help'], $meta['description']);
        }

        return $content;
    }

    private function collect_config_input(array $schema)
    {
        $values = [];

        foreach ($schema as $key => $meta) {
            $name = '_' . $key;
            switch ($meta['type']) {
                case 'bool':
                    $values[$key] = rcube_utils::get_input_value($name, rcube_utils::INPUT_POST) ? true : false;
                    break;

                case 'int':
                    $raw = rcube_utils::get_input_value($name, rcube_utils::INPUT_POST);
                    $int = (int) $raw;
                    if (isset($meta['min']) && $int < $meta['min']) {
                        return [
                            'success' => false,
                            'message' => sprintf(
                                $this->gettext('rounddav_provision.validation_min'),
                                $meta['label'],
                                $meta['min']
                            ),
                        ];
                    }
                    $values[$key] = $int;
                    break;

                case 'json':
                    $raw = trim((string) rcube_utils::get_input_value($name, rcube_utils::INPUT_POST));
                    if ($raw === '') {
                        $decoded = [];
                    } else {
                        $decoded = json_decode($raw, true);
                        if ($decoded === null && json_last_error() !== JSON_ERROR_NONE) {
                            return [
                                'success' => false,
                                'message' => sprintf(
                                    $this->gettext('rounddav_provision.invalid_json'),
                                    $meta['label'],
                                    json_last_error_msg()
                                ),
                            ];
                        }
                        if (!is_array($decoded)) {
                            return [
                                'success' => false,
                                'message' => sprintf(
                                    $this->gettext('rounddav_provision.invalid_json_type'),
                                    $meta['label']
                                ),
                            ];
                        }
                    }
                    $values[$key] = $decoded;
                    break;

                case 'user_ids':
                    $raw = trim((string) rcube_utils::get_input_value($name, rcube_utils::INPUT_POST));
                    $normalized = $this->parse_user_ids($raw);
                    if ($normalized === null) {
                        return [
                            'success' => false,
                            'message' => $this->gettext('rounddav_provision.invalid_acl'),
                        ];
                    }
                    $values[$key] = $normalized;
                    break;

                default:
                    $raw = trim((string) rcube_utils::get_input_value($name, rcube_utils::INPUT_POST));
                    if (!empty($meta['rtrim_slash'])) {
                        $raw = rtrim($raw, '/');
                    }

                    if (!empty($meta['required']) && $raw === '') {
                        return [
                            'success' => false,
                            'message' => sprintf(
                                $this->gettext('rounddav_provision.required_field'),
                                $meta['label']
                            ),
                        ];
                    }

                    $values[$key] = $raw;
                    break;
            }
        }

        return ['success' => true, 'values' => $values];
    }

    private function resolve_user_metadata(string $username): array
    {
        $displayName = $username;
        $email = null;

        if (!empty($this->rc->user) && is_object($this->rc->user) && method_exists($this->rc->user, 'get_identity')) {
            try {
                $identity = $this->rc->user->get_identity();
            } catch (Throwable $e) {
                $identity = null;
            }

            if (is_array($identity)) {
                if (!empty($identity['name'])) {
                    $displayName = $identity['name'];
                }
                if (!empty($identity['email'])) {
                    $email = $identity['email'];
                }
            }
        }

        if ($email === null && filter_var($username, FILTER_VALIDATE_EMAIL)) {
            $email = $username;
        }

        return [$displayName, $email];
    }

    private function parse_user_ids($raw)
    {
        if ($raw === '') {
            return [];
        }

        $lower = strtolower($raw);
        if ($lower === '*' || $lower === 'all' || $lower === 'everyone') {
            return '*';
        }

        $parts = array_filter(array_map('trim', explode(',', $raw)), 'strlen');
        if (empty($parts)) {
            return [];
        }

        $ids = [];
        foreach ($parts as $part) {
            if (!ctype_digit($part)) {
                return null;
            }
            $int = (int) $part;
            if ($int > 0) {
                $ids[] = $int;
            }
        }

        return array_values(array_unique($ids));
    }

    private function format_user_ids_value($value)
    {
        if ($value === '*' || $this->settings_allow_everyone) {
            return '*';
        }

        if (is_array($value) && !empty($value)) {
            return implode(', ', $value);
        }

        if (is_string($value)) {
            return $value;
        }

        return '';
    }

    private function format_json_value($value)
    {
        if (empty($value)) {
            return "[]";
        }

        $json = json_encode($value, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        if ($json === false) {
            return "[]";
        }

        return $json;
    }

    private function save_config_values(array $values)
    {
        $config = [];
        if (file_exists($this->config_file_path)) {
            $config = [];
            include $this->config_file_path;
            if (!is_array($config)) {
                $config = [];
            }
        }

        foreach ($values as $key => $value) {
            $config[$key] = $value;
        }

        $contents = $this->build_config_file($config);
        $tmp_path = $this->config_file_path . '.tmp';

        if (@file_put_contents($tmp_path, $contents) === false) {
            return false;
        }

        if (@rename($tmp_path, $this->config_file_path) === false) {
            @unlink($tmp_path);
            return false;
        }

        return true;
    }

    private function build_config_file(array $config)
    {
        $lines = [];
        $lines[] = "<?php";
        $lines[] = "";
        $lines[] = "// RoundDAV provision plugin configuration";
        $lines[] = "// Auto-generated on " . date('c') . " via the RoundDAV Provision preferences page.";
        $lines[] = "";

        $lines[] = "// Base URL to RoundDAV API entrypoint (no route parameter).";
        $lines[] = "\$config['rounddav_base_url'] = " . $this->export_php_value($config['rounddav_base_url'] ?? '') . ";";
        $lines[] = "";
        $lines[] = "// Provisioning API endpoint";
        $lines[] = "\$config['rounddav_api_url'] = " . $this->export_php_value($config['rounddav_api_url'] ?? '') . ";";
        $lines[] = "";
        $lines[] = "// Shared secret token, must match 'shared_secret' in RoundDAV's config.php";
        $lines[] = "\$config['rounddav_api_token'] = " . $this->export_php_value($config['rounddav_api_token'] ?? '') . ";";
        $lines[] = "";
        $lines[] = "// Shared SSO token, must match 'shared_secret' in RoundDAV's config.php";
        $lines[] = "\$config['rounddav_sso_secret'] = " . $this->export_php_value($config['rounddav_sso_secret'] ?? '') . ";";
        $lines[] = "\$config['rounddav_sso_enabled'] = " . $this->export_php_value(!empty($config['rounddav_sso_enabled'])) . ";";
        $lines[] = "";
        $lines[] = "// Which Roundcube user IDs can open the RoundDAV Provision settings panel.";
        $lines[] = "\$config['rounddav_provision_settings_user_ids'] = " . $this->export_php_value($config['rounddav_provision_settings_user_ids'] ?? [1]) . ";";
        $lines[] = "";
        $lines[] = "// Timeout in seconds for API requests";
        $lines[] = "\$config['rounddav_api_timeout'] = " . $this->export_php_value((int) ($config['rounddav_api_timeout'] ?? 5)) . ";";
        $lines[] = "";
        $lines[] = "// Whether to verify SSL certificates when using https:// API URLs";
        $lines[] = "\$config['rounddav_api_verify_ssl'] = " . $this->export_php_value(!empty($config['rounddav_api_verify_ssl'])) . ";";
        $lines[] = "";
        $lines[] = "// Optional: extra per-user calendars to create on first login.";
        $lines[] = "\$config['rounddav_extra_calendars'] = " . $this->export_php_value($config['rounddav_extra_calendars'] ?? []) . ";";
        $lines[] = "";
        $lines[] = "// Optional: extra per-user addressbooks to create on first login.";
        $lines[] = "\$config['rounddav_extra_addressbooks'] = " . $this->export_php_value($config['rounddav_extra_addressbooks'] ?? []) . ";";
        $lines[] = "";

        return implode("\n", $lines);
    }

    private function export_php_value($value, $indent = 0)
    {
        if (is_array($value)) {
            if (empty($value)) {
                return '[]';
            }

            $indentStr = str_repeat('    ', $indent);
            $innerIndent = str_repeat('    ', $indent + 1);
            $out = "[\n";
            foreach ($value as $key => $val) {
                $keyPart = is_int($key) ? '' : var_export($key, true) . ' => ';
                $out .= $innerIndent . $keyPart . $this->export_php_value($val, $indent + 1) . ",\n";
            }
            $out .= $indentStr . "]";
            return $out;
        }

        if (is_bool($value)) {
            return $value ? 'true' : 'false';
        }

        if (is_null($value)) {
            return 'null';
        }

        if (is_int($value) || is_float($value)) {
            return (string) $value;
        }

        return var_export((string) $value, true);
    }

    private function is_path_writable($path)
    {
        if (file_exists($path)) {
            return is_writable($path);
        }

        $dir = dirname($path);
        return is_dir($dir) && is_writable($dir);
    }
}
