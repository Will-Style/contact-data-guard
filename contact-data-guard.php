<?php
/**
 * Plugin Name:       Contact Data Guard
 * Description:       MW WP Form / Flamingo に保存されるお問い合わせデータを暗号化し、設定した日数を過ぎたデータを自動削除します。
 * Version:           1.0.0
 * Requires at least: 5.5
 * Requires PHP:      7.0
 * Author:            WillStyle
 * License:           GPL-2.0-or-later
 * Text Domain:       contact-data-guard
 */

defined( 'ABSPATH' ) || exit;

define( 'CDG_VERSION', '1.0.0' );
define( 'CDG_FILE', __FILE__ );
define( 'CDG_DIR', __DIR__ );

/** PHP 7 用（str_starts_with / str_contains は PHP 8 から） */
function cdg_starts_with( $haystack, $needle ) {
	return 0 === strncmp( (string) $haystack, (string) $needle, strlen( (string) $needle ) );
}

function cdg_contains( $haystack, $needle ) {
	return false !== strpos( (string) $haystack, (string) $needle );
}

require_once CDG_DIR . '/includes/class-cdg-crypto.php';
require_once CDG_DIR . '/includes/class-cdg-settings.php';
require_once CDG_DIR . '/includes/class-cdg-targets.php';
require_once CDG_DIR . '/includes/class-cdg-encryption-hooks.php';
require_once CDG_DIR . '/includes/class-cdg-retention.php';
require_once CDG_DIR . '/includes/class-cdg-batch.php';

CDG_Encryption_Hooks::init();
CDG_Retention::init();

if ( is_admin() ) {
	require_once CDG_DIR . '/includes/class-cdg-admin.php';
	CDG_Admin::init();
}

if ( defined( 'WP_CLI' ) && WP_CLI ) {
	require_once CDG_DIR . '/includes/class-cdg-cli.php';
	WP_CLI::add_command( 'cdg', 'CDG_CLI' );
}

register_activation_hook( __FILE__, array( 'CDG_Retention', 'schedule' ) );
register_deactivation_hook( __FILE__, array( 'CDG_Retention', 'unschedule' ) );
