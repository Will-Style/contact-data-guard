<?php
/**
 * 対象となる投稿タイプ・メタキーの判定
 *
 * - MW WP Form : mwf_{フォームID}
 * - Flamingo   : flamingo_inbound（受信メッセージ）, flamingo_contact（アドレス帳）, flamingo_outbound
 */

defined( 'ABSPATH' ) || exit;

final class CDG_Targets {

	const FLAMINGO_TYPES = array( 'flamingo_inbound', 'flamingo_contact', 'flamingo_outbound' );

	/**
	 * 暗号化しないメタキー。
	 * WordPress 本体の管理用メタ、プラグインが絞り込み・並べ替え（meta_query）に使う個人情報でない値。
	 */
	const EXCLUDED_META_KEYS = array(
		'_edit_lock',
		'_edit_last',
		'_encloseme',
		'_pingme',
		'_spam_meta_time',     // Flamingo: スパムの自動ゴミ箱移動（meta_query で数値比較）
		'_hash',               // Flamingo: 重複判定（meta_query）
		'_last_contacted',     // Flamingo: アドレス帳の並べ替え
		'_submission_status',  // Flamingo: 送信ステータス（mail_sent 等）
	);

	public static function is_target_type( $post_type ): bool {
		if ( ! $post_type ) {
			return false;
		}
		$is = in_array( $post_type, self::FLAMINGO_TYPES, true ) || 1 === preg_match( '/^mwf_\d+$/', $post_type );
		return (bool) apply_filters( 'cdg_is_target_post_type', $is, $post_type );
	}

	public static function is_target_post( int $post_id ): bool {
		return $post_id > 0 && self::is_target_type( get_post_type( $post_id ) ?: null );
	}

	public static function is_excluded_meta_key( string $meta_key ): bool {
		$excluded = in_array( $meta_key, self::EXCLUDED_META_KEYS, true )
			|| cdg_starts_with( $meta_key, '_wp_' )
			|| cdg_starts_with( $meta_key, '_cdg_' );
		return (bool) apply_filters( 'cdg_is_excluded_meta_key', $excluded, $meta_key );
	}

	/**
	 * サイト内に存在する対象投稿タイプ（登録済み or データあり）
	 *
	 * @return array<string,string> post_type => 表示名
	 */
	public static function all(): array {
		global $wpdb;
		$types = array();

		foreach ( get_post_types() as $pt ) {
			if ( self::is_target_type( $pt ) ) {
				$types[ $pt ] = true;
			}
		}
		$in_db = $wpdb->get_col(
			"SELECT DISTINCT post_type FROM {$wpdb->posts} WHERE post_type LIKE 'mwf\\_%' OR post_type LIKE 'flamingo\\_%'"
		);
		foreach ( $in_db as $pt ) {
			if ( self::is_target_type( $pt ) ) {
				$types[ $pt ] = true;
			}
		}

		$out = array();
		foreach ( array_keys( $types ) as $pt ) {
			$out[ $pt ] = self::label( $pt );
		}
		ksort( $out, SORT_NATURAL );
		return $out;
	}

	public static function label( string $post_type ): string {
		switch ( $post_type ) {
			case 'flamingo_inbound':
				return 'Flamingo 受信メッセージ';
			case 'flamingo_contact':
				return 'Flamingo アドレス帳';
			case 'flamingo_outbound':
				return 'Flamingo 送信メッセージ';
		}
		if ( preg_match( '/^mwf_(\d+)$/', $post_type, $m ) ) {
			$title = get_the_title( (int) $m[1] );
			return sprintf( 'MW WP Form: %s（フォームID %d）', $title ?: '(削除済みフォーム)', (int) $m[1] );
		}
		return $post_type;
	}
}
