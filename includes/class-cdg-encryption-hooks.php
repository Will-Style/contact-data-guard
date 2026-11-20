<?php
/**
 * 保存時に暗号化し、読み出し時に復号するフック
 *
 * - post meta : add/update/delete/get_post_metadata フィルタで透過的に暗号化・復号
 * - 投稿本体   : wp_insert_post_data で post_title / post_content / post_excerpt を暗号化
 *               post_name（スラッグ）はタイトルから作られ平文が残るためランダム値に置換
 *
 * 鍵がない・復号できない値は暗号文のまま返す。
 * （プラグイン側が読んだ値をそのまま保存し直しても暗号文が壊れないようにするため）
 */

defined( 'ABSPATH' ) || exit;

final class CDG_Encryption_Hooks {

	const SLUG_PREFIX = 'cdg-';

	/** 0 より大きい間は自分自身のフィルタを素通しする（再帰防止） */
	private static $bypass = 0;

	public static function init() {
		add_filter( 'get_post_metadata', array( __CLASS__, 'get_meta' ), 99, 4 );
		add_filter( 'add_post_metadata', array( __CLASS__, 'add_meta' ), 99, 5 );
		add_filter( 'update_post_metadata', array( __CLASS__, 'update_meta' ), 99, 5 );
		add_filter( 'delete_post_metadata', array( __CLASS__, 'delete_meta' ), 99, 5 );

		add_filter( 'wp_insert_post_data', array( __CLASS__, 'insert_post_data' ), 99, 2 );
		add_filter( 'wp_insert_post_empty_content', array( __CLASS__, 'maybe_block_flamingo_contact' ), 10, 2 );

		// 画面表示用の復号
		add_filter( 'the_title', array( __CLASS__, 'display_text' ), 1 );
		add_filter( 'single_post_title', array( __CLASS__, 'display_text' ), 1 );
		add_filter( 'the_content', array( __CLASS__, 'display_text' ), 1 );
		add_filter( 'get_the_excerpt', array( __CLASS__, 'display_text' ), 1 );
		// 編集画面（復号できなければ暗号文のまま＝再保存しても壊れない）
		add_filter( 'edit_post_title', array( __CLASS__, 'edit_text' ), 1 );
		add_filter( 'edit_post_content', array( __CLASS__, 'edit_text' ), 1 );
		add_filter( 'edit_post_excerpt', array( __CLASS__, 'edit_text' ), 1 );
	}

	/* ------------------------------------------------------------------
	 * post meta
	 * ---------------------------------------------------------------- */

	public static function get_meta( $check, $object_id, $meta_key, $single ) {
		if ( null !== $check || self::$bypass > 0 || ! CDG_Targets::is_target_post( (int) $object_id ) ) {
			return $check;
		}

		$raw = self::without_hooks( 'get_metadata_raw', 'post', (int) $object_id, (string) $meta_key, false );
		if ( null === $raw ) {
			return null;
		}

		// get_post_meta( $id ) / get_post_custom(): 生の（serialize された）文字列の配列を返す仕様
		if ( '' === (string) $meta_key ) {
			foreach ( (array) $raw as $key => $values ) {
				foreach ( (array) $values as $i => $v ) {
					if ( CDG_Crypto::is_encrypted( $v ) && CDG_Crypto::try_decrypt( $v, $plain ) ) {
						$raw[ $key ][ $i ] = maybe_serialize( $plain );
					}
				}
			}
			return $raw;
		}

		$values = array_map( array( 'CDG_Crypto', 'maybe_decrypt' ), (array) $raw );
		if ( $single ) {
			return array( $values[0] ?? '' );
		}
		return $values;
	}

	public static function add_meta( $check, $object_id, $meta_key, $meta_value, $unique ) {
		if ( null !== $check || ! self::should_encrypt( (int) $object_id, (string) $meta_key, $meta_value ) ) {
			return $check;
		}
		$encrypted = CDG_Crypto::encrypt( $meta_value );
		return self::without_hooks( 'add_metadata', 'post', (int) $object_id, wp_slash( $meta_key ), $encrypted, $unique );
	}

	public static function update_meta( $check, $object_id, $meta_key, $meta_value, $prev_value ) {
		if ( null !== $check || ! self::should_encrypt( (int) $object_id, (string) $meta_key, $meta_value ) ) {
			return $check;
		}
		$object_id = (int) $object_id;
		$encrypted = CDG_Crypto::encrypt( $meta_value );

		$rows = self::meta_rows( $object_id, (string) $meta_key );
		if ( empty( $rows ) ) {
			return self::without_hooks( 'add_metadata', 'post', $object_id, wp_slash( $meta_key ), $encrypted );
		}

		$has_prev = ! ( '' === $prev_value || null === $prev_value || false === $prev_value );

		// 値が変わっていなければ書き込まない（WordPress 本体と同じ挙動）
		if ( ! $has_prev && 1 === count( $rows ) && self::same_value( self::decode_raw( $rows[0]->meta_value ), $meta_value ) && CDG_Crypto::is_encrypted( $rows[0]->meta_value ) && ! CDG_Crypto::needs_reencrypt( $rows[0]->meta_value ) ) {
			return false;
		}

		$updated = false;
		foreach ( $rows as $row ) {
			if ( $has_prev && ! self::same_value( self::decode_raw( $row->meta_value ), $prev_value ) ) {
				continue;
			}
			$result  = self::without_hooks( 'update_metadata_by_mid', 'post', (int) $row->meta_id, $encrypted );
			$updated = $updated || (bool) $result;
		}
		if ( $updated ) {
			wp_cache_delete( $object_id, 'post_meta' );
		}
		return $updated;
	}

	/** 値を指定した削除（delete_post_meta( $id, $key, $value )）を暗号文に対応させる */
	public static function delete_meta( $check, $object_id, $meta_key, $meta_value, $delete_all ) {
		if ( null !== $check || self::$bypass > 0 || $delete_all ) {
			return $check;
		}
		if ( '' === $meta_value || null === $meta_value || false === $meta_value ) {
			return $check;
		}
		$object_id = (int) $object_id;
		if ( ! CDG_Targets::is_target_post( $object_id ) || CDG_Targets::is_excluded_meta_key( (string) $meta_key ) ) {
			return $check;
		}
		$deleted = false;
		foreach ( self::meta_rows( $object_id, (string) $meta_key ) as $row ) {
			if ( CDG_Crypto::is_encrypted( $row->meta_value ) && self::same_value( self::decode_raw( $row->meta_value ), $meta_value ) ) {
				$deleted = (bool) self::without_hooks( 'delete_metadata_by_mid', 'post', (int) $row->meta_id ) || $deleted;
			}
		}
		// 暗号化されていない古い行が一致する可能性もあるので、通常処理にも回す
		if ( ! $deleted ) {
			return $check;
		}
		self::without_hooks( 'delete_metadata', 'post', $object_id, wp_slash( $meta_key ), wp_slash( $meta_value ) );
		return true;
	}

	/* ------------------------------------------------------------------
	 * 投稿本体
	 * ---------------------------------------------------------------- */

	public static function insert_post_data( $data, $postarr ) {
		if ( ! CDG_Targets::is_target_type( $data['post_type'] ?? null ) ) {
			return $data;
		}

		// スラッグはタイトル（件名やメールアドレス）から作られるため、ランダム値にする
		if ( ! cdg_starts_with( (string) ( $data['post_name'] ?? '' ), self::SLUG_PREFIX ) ) {
			$existing = ! empty( $postarr['ID'] ) ? get_post_field( 'post_name', (int) $postarr['ID'], 'raw' ) : '';
			$data['post_name'] = ( is_string( $existing ) && cdg_starts_with( $existing, self::SLUG_PREFIX ) )
				? $existing
				: self::random_slug();
		}

		if ( ! CDG_Crypto::can_encrypt() ) {
			return $data;
		}
		foreach ( array( 'post_title', 'post_content', 'post_excerpt' ) as $field ) {
			if ( ! isset( $data[ $field ] ) || '' === $data[ $field ] ) {
				continue;
			}
			$plain = wp_unslash( $data[ $field ] );
			if ( CDG_Crypto::is_encrypted( $plain ) ) {
				continue;
			}
			$data[ $field ] = wp_slash( CDG_Crypto::encrypt( (string) $plain ) );
		}
		return $data;
	}

	/** 暗号化すると重複判定（メールアドレス検索）が効かないため、既定ではアドレス帳への新規登録を止める */
	public static function maybe_block_flamingo_contact( $maybe_empty, $postarr ) {
		if (
			'flamingo_contact' === ( $postarr['post_type'] ?? '' )
			&& empty( $postarr['ID'] )
			&& CDG_Settings::get( 'block_flamingo_contact' )
		) {
			return true;
		}
		return $maybe_empty;
	}

	public static function display_text( $text ) {
		if ( ! CDG_Crypto::is_encrypted( $text ) ) {
			return $text;
		}
		return CDG_Crypto::try_decrypt( $text, $plain ) ? (string) $plain : '[暗号化データ：鍵がないため表示できません]';
	}

	public static function edit_text( $text ) {
		return CDG_Crypto::is_encrypted( $text ) ? (string) CDG_Crypto::maybe_decrypt( $text ) : $text;
	}

	/* ------------------------------------------------------------------
	 * helpers
	 * ---------------------------------------------------------------- */

	private static function should_encrypt( int $object_id, string $meta_key, $meta_value ): bool {
		return self::$bypass <= 0
			&& CDG_Crypto::can_encrypt()
			&& ! CDG_Crypto::is_encrypted( $meta_value ) // 既に暗号文なら二重に暗号化しない
			&& ! CDG_Targets::is_excluded_meta_key( $meta_key )
			&& CDG_Targets::is_target_post( $object_id );
	}

	public static function without_hooks( $function, ...$args ) {
		++self::$bypass;
		try {
			return call_user_func_array( $function, $args );
		} finally {
			--self::$bypass;
		}
	}

	/** DB の生の値 → PHP の値（暗号文なら復号） */
	public static function decode_raw( $raw ) {
		if ( CDG_Crypto::is_encrypted( $raw ) ) {
			return CDG_Crypto::try_decrypt( $raw, $plain ) ? $plain : $raw;
		}
		return maybe_unserialize( $raw );
	}

	private static function same_value( $a, $b ): bool {
		return maybe_serialize( $a ) === maybe_serialize( $b );
	}

	private static function meta_rows( int $object_id, string $meta_key ): array {
		global $wpdb;
		return $wpdb->get_results(
			$wpdb->prepare(
				"SELECT meta_id, meta_value FROM {$wpdb->postmeta} WHERE post_id = %d AND meta_key = %s ORDER BY meta_id ASC",
				$object_id,
				$meta_key
			)
		);
	}

	public static function random_slug(): string {
		return self::SLUG_PREFIX . bin2hex( random_bytes( 10 ) );
	}
}
