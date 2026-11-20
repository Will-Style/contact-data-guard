<?php
/**
 * アンインストール時: 設定のみ削除する。
 * お問い合わせデータ（暗号化済みを含む）は削除しない。
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

delete_option( 'cdg_settings' );
delete_option( 'cdg_last_cleanup' );
wp_clear_scheduled_hook( 'cdg_daily_cleanup' );
