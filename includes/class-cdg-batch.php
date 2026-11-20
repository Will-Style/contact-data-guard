<?php
/**
 * 既存データの一括暗号化・一括復号
 *
 * encrypt: 平文 → 暗号化。旧鍵で暗号化されたデータは現在の鍵で再暗号化。
 * decrypt: 暗号文 → 平文に戻す（プラグインを外す前など）。
 *
 * ID 順に少しずつ処理し、$after_id を次回に渡して続きから処理する。
 */

defined( 'ABSPATH' ) || exit;

final class CDG_Batch {

	/**
	 * @return array{processed:int,changed:int,errors:int,last_id:int,done:bool}
	 */
	public static function process( string $mode, int $after_id = 0, int $limit = 50 ): array {
		global $wpdb;

		if ( ! in_array( $mode, array( 'encrypt', 'decrypt' ), true ) ) {
			throw new InvalidArgumentException( 'mode must be encrypt or decrypt' );
		}
		if ( 'encrypt' === $mode && ! CDG_Crypto::can_encrypt() ) {
			throw new RuntimeException( '暗号鍵が設定されていないため暗号化できません。' );
		}

		$types = array_keys( CDG_Targets::all() );
		$out   = array(
			'processed' => 0,
			'changed'   => 0,
			'errors'    => 0,
			'last_id'   => $after_id,
			'done'      => true,
		);
		if ( ! $types ) {
			return $out;
		}

		$in    = implode( ',', array_fill( 0, count( $types ), '%s' ) );
		$posts = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT ID, post_title, post_content, post_excerpt, post_name FROM {$wpdb->posts} WHERE post_type IN ($in) AND ID > %d ORDER BY ID ASC LIMIT %d", // phpcs:ignore
				array_merge( $types, array( $after_id, $limit ) )
			)
		);

		foreach ( $posts as $post ) {
			$id      = (int) $post->ID;
			$changed = false;

			// 投稿本体
			$update = array();
			foreach ( array( 'post_title', 'post_content', 'post_excerpt' ) as $field ) {
				$new = self::convert( $mode, $post->$field, false, $out['errors'] );
				if ( null !== $new ) {
					$update[ $field ] = $new;
				}
			}
			if ( 'encrypt' === $mode && ! cdg_starts_with( (string) $post->post_name, CDG_Encryption_Hooks::SLUG_PREFIX ) ) {
				$update['post_name'] = CDG_Encryption_Hooks::random_slug();
			}
			if ( $update ) {
				$wpdb->update( $wpdb->posts, $update, array( 'ID' => $id ) );
				$changed = true;
			}

			// メタ
			$metas = $wpdb->get_results(
				$wpdb->prepare( "SELECT meta_id, meta_key, meta_value FROM {$wpdb->postmeta} WHERE post_id = %d", $id )
			);
			foreach ( $metas as $meta ) {
				if ( CDG_Targets::is_excluded_meta_key( (string) $meta->meta_key ) ) {
					continue;
				}
				$new = self::convert( $mode, $meta->meta_value, true, $out['errors'] );
				if ( null !== $new ) {
					$wpdb->update( $wpdb->postmeta, array( 'meta_value' => $new ), array( 'meta_id' => (int) $meta->meta_id ) );
					$changed = true;
				}
			}

			if ( $changed ) {
				clean_post_cache( $id );
				++$out['changed'];
			}
			++$out['processed'];
			$out['last_id'] = $id;
		}

		$out['done'] = count( $posts ) < $limit;
		return $out;
	}

	/**
	 * 1つの値を変換する。変更不要なら null。
	 *
	 * @param bool $is_meta メタ値（serialize された文字列）かどうか
	 */
	private static function convert( string $mode, $raw, bool $is_meta, int &$errors ) {
		$raw = (string) $raw;

		if ( 'encrypt' === $mode ) {
			if ( CDG_Crypto::is_encrypted( $raw ) ) {
				if ( ! CDG_Crypto::needs_reencrypt( $raw ) ) {
					return null;
				}
				if ( ! CDG_Crypto::try_decrypt( $raw, $plain ) ) {
					++$errors; // 旧鍵が CDG_PREVIOUS_KEYS にない
					return null;
				}
				return CDG_Crypto::encrypt( $plain );
			}
			if ( '' === $raw && ! $is_meta ) {
				return null;
			}
			return CDG_Crypto::encrypt( $is_meta ? maybe_unserialize( $raw ) : $raw );
		}

		// decrypt
		if ( ! CDG_Crypto::is_encrypted( $raw ) ) {
			return null;
		}
		if ( ! CDG_Crypto::try_decrypt( $raw, $plain ) ) {
			++$errors;
			return null;
		}
		return $is_meta ? (string) maybe_serialize( $plain ) : (string) $plain;
	}

	/**
	 * 平文で残っている項目数（目安）
	 *
	 * @return array<string,array{posts:int,plain:int}>
	 */
	public static function status(): array {
		global $wpdb;
		$out = array();
		foreach ( array_keys( CDG_Targets::all() ) as $pt ) {
			$posts = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$wpdb->posts} WHERE post_type = %s", $pt ) );

			$plain = 0;
			$rows  = $wpdb->get_results(
				$wpdb->prepare(
					"SELECT pm.meta_key, COUNT(*) AS c FROM {$wpdb->postmeta} pm INNER JOIN {$wpdb->posts} p ON p.ID = pm.post_id
					 WHERE p.post_type = %s AND pm.meta_value NOT LIKE %s GROUP BY pm.meta_key",
					$pt,
					$wpdb->esc_like( CDG_Crypto::PREFIX ) . '%'
				)
			);
			foreach ( $rows as $row ) {
				if ( ! CDG_Targets::is_excluded_meta_key( (string) $row->meta_key ) ) {
					$plain += (int) $row->c;
				}
			}
			$plain += (int) $wpdb->get_var(
				$wpdb->prepare(
					"SELECT COUNT(*) FROM {$wpdb->posts} WHERE post_type = %s AND post_title <> '' AND post_title NOT LIKE %s",
					$pt,
					$wpdb->esc_like( CDG_Crypto::PREFIX ) . '%'
				)
			);
			$out[ $pt ] = array(
				'posts' => $posts,
				'plain' => $plain,
			);
		}
		return $out;
	}
}
