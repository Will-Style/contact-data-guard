<?php
/**
 * 保存期間を過ぎたデータの自動削除（WP-Cron 毎日 3:00 頃）
 *
 * - 受信データは投稿日時（post_date_gmt）で判定
 * - Flamingo アドレス帳は最終更新日時（post_modified_gmt）で判定
 * - ゴミ箱・スパムも含めて完全削除。MW WP Form の添付ファイル（メディア）も削除
 */

defined( 'ABSPATH' ) || exit;

final class CDG_Retention {

	const HOOK       = 'cdg_daily_cleanup';
	const LAST_RUN   = 'cdg_last_cleanup';
	const BATCH_SIZE = 100;
	const MAX_PER_RUN = 3000; // 1回の実行で削除する上限（タイムアウト対策。残りは翌日）

	public static function init() {
		add_action( self::HOOK, array( __CLASS__, 'run_cron' ) );
		add_action( 'admin_init', array( __CLASS__, 'schedule' ) );
	}

	public static function schedule() {
		if ( ! wp_next_scheduled( self::HOOK ) ) {
			$next = new DateTimeImmutable( 'tomorrow 03:00', wp_timezone() );
			wp_schedule_event( $next->getTimestamp(), 'daily', self::HOOK );
		}
	}

	public static function unschedule() {
		wp_clear_scheduled_hook( self::HOOK );
	}

	public static function run_cron() {
		self::run( false );
	}

	/**
	 * @return array<string,int> post_type => 削除（予定）件数
	 */
	public static function run( bool $dry_run = false, int $max = self::MAX_PER_RUN ): array {
		$result = array();
		$total  = 0;

		foreach ( array_keys( CDG_Targets::all() ) as $post_type ) {
			$days = CDG_Settings::days_for( $post_type );
			if ( $days <= 0 ) {
				continue;
			}
			if ( $dry_run ) {
				$result[ $post_type ] = self::count_expired( $post_type, $days );
				continue;
			}

			$deleted = 0;
			while ( $total < $max ) {
				$ids = self::expired_ids( $post_type, $days, min( self::BATCH_SIZE, $max - $total ) );
				if ( ! $ids ) {
					break;
				}
				foreach ( $ids as $id ) {
					self::delete_post( $id );
					++$deleted;
					++$total;
				}
			}
			$result[ $post_type ] = $deleted;
		}

		if ( ! $dry_run ) {
			update_option(
				self::LAST_RUN,
				array(
					'time'    => time(),
					'deleted' => $result,
				),
				false
			);
		}
		return $result;
	}

	public static function count_expired( string $post_type, int $days ): int {
		global $wpdb;
		list( $col, $threshold ) = self::criteria( $post_type, $days );
		return (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$wpdb->posts} WHERE post_type = %s AND {$col} < %s AND {$col} <> '0000-00-00 00:00:00'", // phpcs:ignore
				$post_type,
				$threshold
			)
		);
	}

	/** @return int[] */
	public static function expired_ids( string $post_type, int $days, int $limit ): array {
		global $wpdb;
		list( $col, $threshold ) = self::criteria( $post_type, $days );
		return array_map(
			'intval',
			$wpdb->get_col(
				$wpdb->prepare(
					"SELECT ID FROM {$wpdb->posts} WHERE post_type = %s AND {$col} < %s AND {$col} <> '0000-00-00 00:00:00' ORDER BY ID ASC LIMIT %d", // phpcs:ignore
					$post_type,
					$threshold,
					$limit
				)
			)
		);
	}

	public static function delete_post( int $post_id ) {
		// MW WP Form の添付ファイル（メディアに保存されたもの）も削除
		$attachments = get_children(
			array(
				'post_parent' => $post_id,
				'post_type'   => 'attachment',
				'post_status' => 'any',
				'fields'      => 'ids',
			)
		);
		foreach ( (array) $attachments as $attachment_id ) {
			wp_delete_attachment( (int) $attachment_id, true );
		}
		wp_delete_post( $post_id, true );
	}

	/** @return array{0:string,1:string} [比較カラム, しきい値(GMT)] */
	private static function criteria( string $post_type, int $days ): array {
		$col       = 'flamingo_contact' === $post_type ? 'post_modified_gmt' : 'post_date_gmt';
		$threshold = gmdate( 'Y-m-d H:i:s', time() - $days * DAY_IN_SECONDS );
		return array( $col, $threshold );
	}
}
