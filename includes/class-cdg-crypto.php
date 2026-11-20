<?php
/**
 * 暗号化・復号（libsodium / XSalsa20-Poly1305）
 *
 * 暗号文の形式: cdg:v1:{鍵ID 8桁}:{base64(nonce + 暗号文)}
 * 平文は serialize() した値なので、文字列・配列どちらも元の型のまま復元できる。
 *
 * 鍵は wp-config.php に定義する:
 *   define( 'CDG_ENCRYPTION_KEY', 'base64:xxxxxxxx' );
 * 鍵を入れ替えた場合は旧鍵を残しておけば復号できる:
 *   define( 'CDG_PREVIOUS_KEYS', 'base64:aaaa,base64:bbbb' );
 */

defined( 'ABSPATH' ) || exit;

final class CDG_Crypto {

	const PREFIX = 'cdg:v1:';

	/** @var array<string,string>|null 鍵ID => 生の鍵 */
	private static $keys = null;

	private static $current_id = null;

	/** @var array<string,mixed> 復号結果のメモ（同一リクエスト内） */
	private static $memo = array();

	public static function sodium_available(): bool {
		return function_exists( 'sodium_crypto_secretbox' );
	}

	public static function key_defined(): bool {
		return defined( 'CDG_ENCRYPTION_KEY' ) && '' !== (string) CDG_ENCRYPTION_KEY;
	}

	/** 鍵が定義されていて、正しい形式か */
	public static function key_valid(): bool {
		self::load_keys();
		return null !== self::$current_id;
	}

	/** 新規データを暗号化できる状態か */
	public static function can_encrypt(): bool {
		return self::sodium_available() && self::key_valid();
	}

	public static function current_key_id() {
		self::load_keys();
		return self::$current_id;
	}

	/** @return string[] 復号に使える鍵IDの一覧 */
	public static function known_key_ids(): array {
		self::load_keys();
		return array_keys( self::$keys );
	}

	public static function generate_key(): string {
		return 'base64:' . base64_encode( random_bytes( 32 ) );
	}

	public static function is_encrypted( $value ): bool {
		return is_string( $value ) && cdg_starts_with( $value, self::PREFIX );
	}

	public static function key_id_of( string $ciphertext ) {
		if ( ! self::is_encrypted( $ciphertext ) ) {
			return null;
		}
		$rest = substr( $ciphertext, strlen( self::PREFIX ) );
		$pos  = strpos( $rest, ':' );
		return false === $pos ? null : substr( $rest, 0, $pos );
	}

	/** 暗号化済みだが現在の鍵ではない（鍵の入れ替え後に再暗号化が必要） */
	public static function needs_reencrypt( $value ): bool {
		return self::is_encrypted( $value ) && self::key_id_of( $value ) !== self::current_key_id();
	}

	/**
	 * @throws RuntimeException 鍵が使えない場合
	 */
	public static function encrypt( $value ): string {
		self::load_keys();
		if ( ! self::sodium_available() || null === self::$current_id ) {
			throw new RuntimeException( 'Contact Data Guard: 暗号鍵が使用できません。' );
		}
		$nonce = random_bytes( SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
		$box   = sodium_crypto_secretbox( serialize( $value ), $nonce, self::$keys[ self::$current_id ] );
		return self::PREFIX . self::$current_id . ':' . base64_encode( $nonce . $box );
	}

	/**
	 * 復号を試みる。
	 *
	 * @param string $ciphertext 暗号文
	 * @param mixed  $value      復号結果（成功時）
	 * @return bool 成功したか（鍵がない・改ざん等は false）
	 */
	public static function try_decrypt( string $ciphertext, &$value = null ): bool {
		if ( array_key_exists( $ciphertext, self::$memo ) ) {
			$value = self::$memo[ $ciphertext ];
			return true;
		}
		if ( ! self::is_encrypted( $ciphertext ) || ! self::sodium_available() ) {
			return false;
		}
		self::load_keys();
		$key_id = self::key_id_of( $ciphertext );
		if ( null === $key_id || ! isset( self::$keys[ $key_id ] ) ) {
			return false;
		}
		$raw = base64_decode( substr( $ciphertext, strlen( self::PREFIX ) + strlen( $key_id ) + 1 ), true );
		if ( false === $raw || strlen( $raw ) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES + SODIUM_CRYPTO_SECRETBOX_MACBYTES - 1 ) {
			return false;
		}
		$nonce = substr( $raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
		$box   = substr( $raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
		$plain = sodium_crypto_secretbox_open( $box, $nonce, self::$keys[ $key_id ] );
		if ( false === $plain ) {
			return false;
		}
		// 認証付き暗号なので改ざんされていない＝自分で serialize したデータ。念のためクラス生成は禁止。
		$decoded = @unserialize( $plain, array( 'allowed_classes' => false ) ); // phpcs:ignore
		if ( false === $decoded && 'b:0;' !== $plain ) {
			return false;
		}
		if ( count( self::$memo ) > 2000 ) {
			self::$memo = array();
		}
		self::$memo[ $ciphertext ] = $decoded;
		$value                     = $decoded;
		return true;
	}

	/** 復号できればその値、できなければ元の値を返す */
	public static function maybe_decrypt( $value ) {
		if ( self::is_encrypted( $value ) && self::try_decrypt( $value, $plain ) ) {
			return $plain;
		}
		return $value;
	}

	public static function parse_key( $key ) {
		if ( ! is_string( $key ) ) {
			return null;
		}
		$key = trim( $key );
		if ( cdg_starts_with( $key, 'base64:' ) ) {
			$key = substr( $key, 7 );
		}
		$raw = base64_decode( $key, true );
		return ( false !== $raw && 32 === strlen( $raw ) ) ? $raw : null;
	}

	public static function key_id( string $raw_key ): string {
		return substr( hash( 'sha256', 'cdg-key-id|' . $raw_key ), 0, 8 );
	}

	/** テスト用: 読み込んだ鍵をリセット */
	public static function reset() {
		self::$keys       = null;
		self::$current_id = null;
		self::$memo       = array();
	}

	private static function load_keys() {
		if ( null !== self::$keys ) {
			return;
		}
		self::$keys = array();
		if ( ! self::sodium_available() ) {
			return;
		}
		if ( self::key_defined() ) {
			$raw = self::parse_key( CDG_ENCRYPTION_KEY );
			if ( null !== $raw ) {
				$id                = self::key_id( $raw );
				self::$keys[ $id ] = $raw;
				self::$current_id  = $id;
			}
		}
		if ( defined( 'CDG_PREVIOUS_KEYS' ) ) {
			$old = CDG_PREVIOUS_KEYS;
			if ( is_string( $old ) ) {
				$old = explode( ',', $old );
			}
			foreach ( (array) $old as $k ) {
				$raw = self::parse_key( $k );
				if ( null !== $raw ) {
					$id = self::key_id( $raw );
					if ( ! isset( self::$keys[ $id ] ) ) {
						self::$keys[ $id ] = $raw;
					}
				}
			}
		}
	}
}
