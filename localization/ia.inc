<?php
/**
 * Localization stub
 * Locale: ia
 * Language: Interlingua
 * Encoding: UTF-8
 *
 * This file is intentionally empty of label keys.
 * Copy keys from en_US.inc when available and translate only the values.
 *
 * Guidelines:
 *  - Keep keys IDENTICAL to en_US.inc.
 *  - Preserve placeholders like %s, %d, and {braced} variables.
 *  - Preserve HTML tags and entities.
 *  - Escape single quotes in values using \' if needed.
 */

$labels = array(
    'rounddav.provision_error' => 'Error provisioning DAV account. Please contact the administrator.',
    'rounddav_provision.preferences_menu' => 'RoundDAV Provision',
    'rounddav_provision.preferences_title' => 'RoundDAV Provisioning',
    'rounddav_provision.preferences_intro' => 'This page summarizes how Roundcube provisions and links your mailbox with RoundDAV.',
    'rounddav_provision.preferences_status_label' => 'Provisioning status',
    'rounddav_provision.status_enabled' => 'Automatic provisioning is enabled.',
    'rounddav_provision.status_disabled' => 'Provisioning is currently disabled or missing credentials.',
    'rounddav_provision.preferences_api_url' => 'Provisioning API endpoint',
    'rounddav_provision.preferences_base_url' => 'RoundDAV base URL',
    'rounddav_provision.preferences_sso_label' => 'Single sign-on',
    'rounddav_provision.preferences_sso_enabled' => 'Enabled (users are logged into RoundDAV automatically)',
    'rounddav_provision.preferences_sso_disabled' => 'Disabled (fall back to plain URLs)',
    'rounddav_provision.preferences_acl_label' => 'Visibility',
    'rounddav_provision.preferences_acl_everyone' => 'All Roundcube users can access this page.',
    'rounddav_provision.preferences_acl_specific' => 'Only the following Roundcube user IDs may access this page: %s',
    'rounddav_provision.preferences_acl_none' => 'No users are currently allowed to access this page.',
    'rounddav_provision.not_configured' => 'Not configured',
    'rounddav_provision.access_denied' => 'You are not allowed to view the RoundDAV preferences.',
    'rounddav_provision.preferences_overview_block' => 'Overview',
    'rounddav_provision.preferences_config_block' => 'Configuration',
    'rounddav_provision.config_path_label' => 'Values are stored in %s.',
    'rounddav_provision.config_not_writable' => 'The config file is not writable. Update file permissions to enable saving from this page.',
    'rounddav_provision.config_edit_hint' => 'Update these fields to change how Roundcube talks to RoundDAV.',
    'rounddav_provision.save_error' => 'Unable to save RoundDAV configuration.',
    'rounddav_provision.field_base_url' => 'RoundDAV Base URL',
    'rounddav_provision.field_api_url' => 'API Endpoint',
    'rounddav_provision.field_api_token' => 'API Token',
    'rounddav_provision.field_sso_secret' => 'SSO Secret',
    'rounddav_provision.field_sso_enabled' => 'Enable SSO integration',
    'rounddav_provision.field_acl' => 'Allowed admin user IDs',
    'rounddav_provision.field_acl_desc' => 'Enter comma-separated Roundcube user IDs or * to allow everyone.',
    'rounddav_provision.field_timeout' => 'API timeout (seconds)',
    'rounddav_provision.field_verify_ssl' => 'Verify SSL certificates',
    'rounddav_provision.field_extra_calendars' => 'Extra calendars (JSON)',
    'rounddav_provision.field_extra_addressbooks' => 'Extra address books (JSON)',
    'rounddav_provision.field_json_hint' => 'Provide a JSON array describing the entries. Leave empty for none.',
    'rounddav_provision.validation_min' => '%s must be at least %d.',
    'rounddav_provision.invalid_json' => 'Invalid JSON in %s: %s',
    'rounddav_provision.invalid_json_type' => '%s must decode to an array.',
    'rounddav_provision.invalid_acl' => 'Enter *, empty, or comma-separated numeric user IDs.',
    'rounddav_provision.required_field' => '%s is required.',
);
