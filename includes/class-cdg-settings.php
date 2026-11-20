<?php
/**
 * 設定値（wp_options: cdg_settings）
 *
 * days の値:  null/'' = 既定値に従う, 0 = 削除しない, 1以上 = 保存日数
 */

defined( 'ABSPATH' ) || exit;

final class CDG_Settings {

	const OPTION = 'cdg_settings';

	public static function defaults(): array {
		return array(
			'default_days'           => 0,  // 既定は「削除しない」
			'days'                   => array(),
			'block_flamingo_contact' => 1,  // Flamingo アドレス帳への保存を止める
		);
	}

	public static function all(): array {
		$saved = get_option( self::OPTION, array() );
		return array_merge( self::defaults(), is_array( $saved ) ? $saved : array() );
	}

	public static function get( string $key ) {
		return self::all()[ $key ] ?? null;
	}

	/** 投稿タイプごとの保存日数（0 = 削除しない） */
	public static function days_for( string $post_type ): int {
		$s    = self::all();
		$days = $s['days'][ $post_type ] ?? '';
		if ( '' === $days || null === $days ) {
			return max( 0, (int) $s['default_days'] );
		}
		return max( 0, (int) $days );
	}

	public static function sanitize( $input ): array {
		$input = is_array( $input ) ? $input : array();
		$out   = self::defaults();

		$out['default_days']           = max( 0, (int) ( $input['default_days'] ?? 0 ) );
		$out['block_flamingo_contact'] = empty( $input['block_flamingo_contact'] ) ? 0 : 1;

		foreach ( (array) ( $input['days'] ?? array() ) as $post_type => $days ) {
			$post_type = sanitize_key( $post_type );
			if ( ! CDG_Targets::is_target_type( $post_type ) ) {
				continue;
			}
			$days                           = trim( (string) $days );
			$out['days'][ $post_type ] = ( '' === $days ) ? '' : max( 0, (int) $days );
		}
		return $out;
	}
}
