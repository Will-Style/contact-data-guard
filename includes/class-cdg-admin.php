<?php
/**
 * 管理画面: 設定 > お問い合わせデータ保護
 */

defined( 'ABSPATH' ) || exit;

final class CDG_Admin {

	const PAGE = 'contact-data-guard';
	const CAP  = 'manage_options';

	public static function init() {
		add_action( 'admin_menu', array( __CLASS__, 'menu' ) );
		add_action( 'admin_init', array( __CLASS__, 'register' ) );
		add_action( 'admin_notices', array( __CLASS__, 'notices' ) );
		add_action( 'admin_post_cdg_cleanup_now', array( __CLASS__, 'handle_cleanup_now' ) );
		add_action( 'wp_ajax_cdg_batch', array( __CLASS__, 'ajax_batch' ) );
		add_filter( 'plugin_action_links_' . plugin_basename( CDG_FILE ), array( __CLASS__, 'action_links' ) );
	}

	public static function menu() {
		add_options_page( 'お問い合わせデータ保護', 'お問い合わせデータ保護', self::CAP, self::PAGE, array( __CLASS__, 'render' ) );
	}

	public static function register() {
		register_setting(
			'cdg_settings_group',
			CDG_Settings::OPTION,
			array(
				'type'              => 'array',
				'sanitize_callback' => array( 'CDG_Settings', 'sanitize' ),
				'default'           => CDG_Settings::defaults(),
			)
		);
	}

	public static function action_links( array $links ): array {
		array_unshift( $links, '<a href="' . esc_url( self::url() ) . '">設定</a>' );
		return $links;
	}

	public static function url( array $args = array() ): string {
		return add_query_arg( array_merge( array( 'page' => self::PAGE ), $args ), admin_url( 'options-general.php' ) );
	}

	public static function notices() {
		if ( ! current_user_can( self::CAP ) ) {
			return;
		}
		$link = '<a href="' . esc_url( self::url() ) . '">設定を確認</a>';
		if ( ! CDG_Crypto::sodium_available() ) {
			echo '<div class="notice notice-error"><p><strong>Contact Data Guard:</strong> PHP の sodium 拡張が無効のため暗号化できません。</p></div>';
		} elseif ( CDG_Crypto::key_defined() && ! CDG_Crypto::key_valid() ) {
			echo '<div class="notice notice-error"><p><strong>Contact Data Guard:</strong> CDG_ENCRYPTION_KEY の形式が正しくありません。お問い合わせデータは暗号化されずに保存されます。' . $link . '</p></div>'; // phpcs:ignore
		} elseif ( ! CDG_Crypto::key_defined() ) {
			echo '<div class="notice notice-warning"><p><strong>Contact Data Guard:</strong> 暗号鍵（CDG_ENCRYPTION_KEY）が未設定のため、お問い合わせデータは暗号化されていません。' . $link . '</p></div>'; // phpcs:ignore
		}
	}

	public static function handle_cleanup_now() {
		if ( ! current_user_can( self::CAP ) ) {
			wp_die( '権限がありません。' );
		}
		check_admin_referer( 'cdg_cleanup_now' );
		$result = CDG_Retention::run( false );
		wp_safe_redirect( self::url( array( 'cdg_deleted' => array_sum( $result ) ) ) );
		exit;
	}

	public static function ajax_batch() {
		if ( ! current_user_can( self::CAP ) ) {
			wp_send_json_error( array( 'message' => '権限がありません。' ), 403 );
		}
		check_ajax_referer( 'cdg_batch' );
		$mode  = sanitize_key( $_POST['mode'] ?? '' );
		$after = absint( $_POST['after'] ?? 0 );
		try {
			wp_send_json_success( CDG_Batch::process( $mode, $after, 50 ) );
		} catch ( Throwable $e ) {
			wp_send_json_error( array( 'message' => $e->getMessage() ) );
		}
	}

	public static function render() {
		if ( ! current_user_can( self::CAP ) ) {
			return;
		}
		$settings = CDG_Settings::all();
		$targets  = CDG_Targets::all();
		$status   = CDG_Batch::status();
		$last_run = get_option( CDG_Retention::LAST_RUN );
		$next_run = wp_next_scheduled( CDG_Retention::HOOK );
		$opt      = CDG_Settings::OPTION;
		?>
		<div class="wrap">
			<h1>お問い合わせデータ保護</h1>

			<?php if ( isset( $_GET['cdg_deleted'] ) ) : // phpcs:ignore ?>
				<div class="notice notice-success is-dismissible"><p><?php echo esc_html( absint( $_GET['cdg_deleted'] ) ); // phpcs:ignore ?> 件のデータを削除しました。</p></div>
			<?php endif; ?>

			<h2>1. 暗号化</h2>
			<table class="form-table" role="presentation">
				<tr>
					<th>状態</th>
					<td>
						<?php if ( CDG_Crypto::can_encrypt() ) : ?>
							<span style="color:#008a20;font-weight:bold;">● 有効</span>
							（鍵ID: <code><?php echo esc_html( (string) CDG_Crypto::current_key_id() ); ?></code>
							<?php $old = count( CDG_Crypto::known_key_ids() ) - 1; ?>
							<?php if ( $old > 0 ) : ?>／旧鍵 <?php echo (int) $old; ?> 件<?php endif; ?>）
							<p class="description">新しく保存されるお問い合わせデータは全項目が暗号化されます。管理画面・CSV出力では自動的に復号して表示されます。</p>
						<?php else : ?>
							<span style="color:#d63638;font-weight:bold;">● 無効</span>
							<p class="description">wp-config.php に暗号鍵を追加すると有効になります（下記参照）。</p>
						<?php endif; ?>
					</td>
				</tr>
				<?php if ( ! CDG_Crypto::key_defined() || ! CDG_Crypto::key_valid() ) : ?>
				<tr>
					<th>鍵の設定方法</th>
					<td>
						<p>次の1行を <code>wp-config.php</code> の「編集が必要なのはここまでです」より上に追加してください（この画面を開くたびに新しい鍵が生成されます）。</p>
						<p><input type="text" class="large-text code" readonly onclick="this.select()" value="<?php echo esc_attr( "define( 'CDG_ENCRYPTION_KEY', '" . CDG_Crypto::generate_key() . "' );" ); ?>"></p>
						<p class="description" style="color:#d63638;"><strong>鍵をなくすと暗号化したデータは二度と復号できません。</strong>パスワード管理ツールなど、サーバーとは別の場所にも必ず保管してください。</p>
					</td>
				</tr>
				<?php endif; ?>
				<tr>
					<th>保存済みデータ</th>
					<td>
						<?php if ( $status ) : ?>
						<table class="widefat striped" style="max-width:720px;">
							<thead><tr><th>対象</th><th>件数</th><th>平文で残っている項目（目安）</th></tr></thead>
							<tbody>
							<?php foreach ( $status as $pt => $st ) : ?>
								<tr>
									<td><?php echo esc_html( $targets[ $pt ] ?? $pt ); ?></td>
									<td><?php echo esc_html( number_format_i18n( $st['posts'] ) ); ?></td>
									<td><?php echo $st['plain'] > 0 ? '<span style="color:#d63638;">' . esc_html( number_format_i18n( $st['plain'] ) ) . '</span>' : '0'; ?></td>
								</tr>
							<?php endforeach; ?>
							</tbody>
						</table>
						<?php else : ?>
							<p>MW WP Form / Flamingo の保存データが見つかりません。</p>
						<?php endif; ?>

						<p style="margin-top:12px;">
							<button type="button" class="button button-primary cdg-batch" data-mode="encrypt" <?php disabled( ! CDG_Crypto::can_encrypt() ); ?>>既存データを暗号化する</button>
							<span class="description">導入前に保存されたデータや、鍵を入れ替えた後の旧鍵データを現在の鍵で暗号化します。</span>
						</p>
						<details style="margin-top:8px;">
							<summary>プラグインを停止・削除する前に（平文に戻す）</summary>
							<p>このプラグインを停止すると、暗号化されたデータは管理画面で読めなくなります。停止・削除する前に平文に戻してください。</p>
							<p><button type="button" class="button cdg-batch" data-mode="decrypt" data-confirm="全データを平文に戻します。よろしいですか？">全データを復号して平文に戻す</button></p>
						</details>
						<p id="cdg-batch-progress" style="font-weight:bold;"></p>
					</td>
				</tr>
			</table>

			<form method="post" action="options.php">
				<?php settings_fields( 'cdg_settings_group' ); ?>

				<h2>2. 保存期間（自動削除）</h2>
				<p>保存から指定日数を過ぎたデータを、毎日 3:00 頃に完全削除します（ゴミ箱・スパムも対象。MW WP Form の添付ファイルも削除）。<br><strong>0 = 削除しない</strong>。空欄の場合は「既定の保存日数」に従います。</p>
				<table class="form-table" role="presentation">
					<tr>
						<th><label for="cdg-default-days">既定の保存日数</label></th>
						<td>
							<input type="number" min="0" step="1" id="cdg-default-days" name="<?php echo esc_attr( $opt ); ?>[default_days]" value="<?php echo esc_attr( (string) $settings['default_days'] ); ?>" class="small-text"> 日
							<p class="description">新しく作成したフォームにも適用されます。</p>
						</td>
					</tr>
					<?php foreach ( $targets as $pt => $label ) : ?>
						<?php
						$val     = $settings['days'][ $pt ] ?? '';
						$days    = CDG_Settings::days_for( $pt );
						$expired = $days > 0 ? CDG_Retention::count_expired( $pt, $days ) : 0;
						?>
						<tr>
							<th><label for="cdg-days-<?php echo esc_attr( $pt ); ?>"><?php echo esc_html( $label ); ?></label></th>
							<td>
								<input type="number" min="0" step="1" id="cdg-days-<?php echo esc_attr( $pt ); ?>" name="<?php echo esc_attr( $opt ); ?>[days][<?php echo esc_attr( $pt ); ?>]" value="<?php echo esc_attr( (string) $val ); ?>" class="small-text" placeholder="既定"> 日
								<span class="description">
									現在の設定: <?php echo $days > 0 ? esc_html( $days . ' 日' ) : '削除しない'; ?>
									<?php if ( $days > 0 ) : ?>／期限切れ: <?php echo esc_html( number_format_i18n( $expired ) ); ?> 件<?php endif; ?>
								</span>
							</td>
						</tr>
					<?php endforeach; ?>
				</table>

				<h2>3. Flamingo アドレス帳</h2>
				<table class="form-table" role="presentation">
					<tr>
						<th>アドレス帳への登録</th>
						<td>
							<label><input type="checkbox" name="<?php echo esc_attr( $opt ); ?>[block_flamingo_contact]" value="1" <?php checked( ! empty( $settings['block_flamingo_contact'] ) ); ?>> 新しい送信者をアドレス帳（flamingo_contact）に登録しない</label>
							<p class="description">暗号化するとメールアドレスで既存の連絡先を検索できず、同じ人が何度も登録されるため、登録しないことを推奨します。受信メッセージの保存には影響しません。</p>
						</td>
					</tr>
				</table>

				<?php submit_button( '設定を保存' ); ?>
			</form>

			<h2>4. 実行状況</h2>
			<table class="form-table" role="presentation">
				<tr>
					<th>次回の自動削除</th>
					<td><?php echo $next_run ? esc_html( wp_date( 'Y-m-d H:i', $next_run ) ) : '未登録'; ?></td>
				</tr>
				<tr>
					<th>前回の自動削除</th>
					<td>
						<?php if ( is_array( $last_run ) ) : ?>
							<?php echo esc_html( wp_date( 'Y-m-d H:i', (int) $last_run['time'] ) ); ?>
							（<?php echo esc_html( number_format_i18n( array_sum( (array) $last_run['deleted'] ) ) ); ?> 件削除）
						<?php else : ?>
							まだ実行されていません
						<?php endif; ?>
					</td>
				</tr>
				<tr>
					<th>手動実行</th>
					<td>
						<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" onsubmit="return confirm('保存期間を過ぎたデータを今すぐ完全削除します。元に戻せません。よろしいですか？');">
							<input type="hidden" name="action" value="cdg_cleanup_now">
							<?php wp_nonce_field( 'cdg_cleanup_now' ); ?>
							<button type="submit" class="button">期限切れデータを今すぐ削除</button>
						</form>
					</td>
				</tr>
			</table>
		</div>

		<script>
		(function () {
			const ajaxUrl = <?php echo wp_json_encode( admin_url( 'admin-ajax.php' ) ); ?>;
			const nonce = <?php echo wp_json_encode( wp_create_nonce( 'cdg_batch' ) ); ?>;
			const progress = document.getElementById('cdg-batch-progress');
			const buttons = document.querySelectorAll('.cdg-batch');

			async function run(mode) {
				let after = 0, processed = 0, changed = 0, errors = 0;
				buttons.forEach(b => b.disabled = true);
				try {
					for (;;) {
						const body = new URLSearchParams({ action: 'cdg_batch', _ajax_nonce: nonce, mode, after: String(after) });
						const res = await fetch(ajaxUrl, { method: 'POST', body, credentials: 'same-origin' });
						const json = await res.json();
						if (!json.success) throw new Error(json.data && json.data.message ? json.data.message : '処理に失敗しました');
						processed += json.data.processed; changed += json.data.changed; errors += json.data.errors; after = json.data.last_id;
						progress.textContent = `処理中… ${processed} 件確認 / ${changed} 件変更`;
						if (json.data.done) break;
					}
					progress.textContent = `完了: ${processed} 件確認 / ${changed} 件変更` + (errors ? ` / 復号できなかった項目 ${errors} 件（旧鍵が未設定の可能性）` : '');
					setTimeout(() => location.reload(), 1500);
				} catch (e) {
					progress.textContent = 'エラー: ' + e.message;
					buttons.forEach(b => b.disabled = false);
				}
			}

			buttons.forEach(btn => btn.addEventListener('click', () => {
				if (btn.dataset.confirm && !window.confirm(btn.dataset.confirm)) return;
				run(btn.dataset.mode);
			}));
		})();
		</script>
		<?php
	}
}
