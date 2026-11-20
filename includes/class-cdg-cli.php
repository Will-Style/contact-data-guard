<?php
/**
 * WP-CLI コマンド: wp cdg <subcommand>
 */

defined( 'ABSPATH' ) || exit;

class CDG_CLI {

	/**
	 * 新しい暗号鍵を生成して表示します（保存はしません）。
	 *
	 * ## EXAMPLES
	 *     wp cdg generate-key
	 */
	public function generate_key() {
		WP_CLI::line( "define( 'CDG_ENCRYPTION_KEY', '" . CDG_Crypto::generate_key() . "' );" );
	}

	/**
	 * 暗号化・保存期間の状態を表示します。
	 */
	public function status() {
		WP_CLI::line( '暗号化: ' . ( CDG_Crypto::can_encrypt() ? '有効（鍵ID ' . CDG_Crypto::current_key_id() . '）' : '無効' ) );
		$rows = array();
		foreach ( CDG_Batch::status() as $pt => $st ) {
			$days   = CDG_Settings::days_for( $pt );
			$rows[] = array(
				'post_type' => $pt,
				'label'     => CDG_Targets::label( $pt ),
				'posts'     => $st['posts'],
				'plain'     => $st['plain'],
				'days'      => $days > 0 ? $days : '削除しない',
				'expired'   => $days > 0 ? CDG_Retention::count_expired( $pt, $days ) : '-',
			);
		}
		WP_CLI\Utils\format_items( 'table', $rows, array( 'post_type', 'label', 'posts', 'plain', 'days', 'expired' ) );
	}

	/**
	 * 既存データを暗号化します（旧鍵データは再暗号化）。
	 */
	public function encrypt() {
		$this->run_batch( 'encrypt' );
	}

	/**
	 * 暗号化データをすべて平文に戻します。
	 *
	 * ## OPTIONS
	 * [--yes]
	 * : 確認を省略
	 */
	public function decrypt( $args, $assoc ) {
		WP_CLI::confirm( '全データを平文に戻します。よろしいですか？', $assoc );
		$this->run_batch( 'decrypt' );
	}

	/**
	 * 暗号文を1件復号して表示します（鍵の確認用）。
	 *
	 * ## OPTIONS
	 * <value>
	 * : cdg:v1: で始まる暗号文
	 */
	public function decrypt_value( $args ) {
		if ( ! CDG_Crypto::try_decrypt( $args[0], $plain ) ) {
			WP_CLI::error( '復号できませんでした（鍵が違う・データが壊れている可能性があります）。' );
		}
		WP_CLI::line( is_scalar( $plain ) ? (string) $plain : wp_json_encode( $plain, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT ) );
	}

	/**
	 * 保存期間を過ぎたデータを削除します。
	 *
	 * ## OPTIONS
	 * [--dry-run]
	 * : 削除せず件数だけ表示
	 */
	public function cleanup( $args, $assoc ) {
		$dry    = ! empty( $assoc['dry-run'] );
		$result = CDG_Retention::run( $dry, PHP_INT_MAX );
		foreach ( $result as $pt => $count ) {
			WP_CLI::line( sprintf( '%s: %d 件%s', CDG_Targets::label( $pt ), $count, $dry ? '（削除予定）' : '削除' ) );
		}
		WP_CLI::success( $dry ? 'dry-run 完了' : '削除完了' );
	}

	private function run_batch( string $mode ) {
		$after  = 0;
		$totals = array( 'processed' => 0, 'changed' => 0, 'errors' => 0 );
		try {
			do {
				$r = CDG_Batch::process( $mode, $after, 100 );
				foreach ( $totals as $k => $v ) {
					$totals[ $k ] += $r[ $k ];
				}
				$after = $r['last_id'];
				WP_CLI::log( sprintf( '... %d 件確認 / %d 件変更', $totals['processed'], $totals['changed'] ) );
			} while ( ! $r['done'] );
		} catch ( Throwable $e ) {
			WP_CLI::error( $e->getMessage() );
		}
		if ( $totals['errors'] ) {
			WP_CLI::warning( "復号できなかった項目: {$totals['errors']} 件（旧鍵を CDG_PREVIOUS_KEYS に設定してください）" );
		}
		WP_CLI::success( sprintf( '%d 件確認 / %d 件変更', $totals['processed'], $totals['changed'] ) );
	}
}
