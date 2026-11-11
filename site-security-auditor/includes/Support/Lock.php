<?php
// phpcs:disable WordPress.DB.DirectDatabaseQuery -- Private custom tables and atomic locks require direct, fresh, parameterised queries.
namespace SiteSecurityAuditor\Support;

use SiteSecurityAuditor\Persistence\Schema;

final class Lock {
	public static function acquire( string $name ): ?string {
		global $wpdb;
		$token = wp_generate_uuid4();
		$value = ( time() + 120 ) . ':' . $token;
		// add_option() can update an existing row after competing callers both observe no option.
		$inserted = $wpdb->query( $wpdb->prepare( "INSERT IGNORE INTO {$wpdb->options} (option_name, option_value, autoload) VALUES (%s, %s, 'no')", $name, $value ) );
		if ( 1 === $inserted ) {
			wp_cache_delete( $name, 'options' );
			wp_cache_delete( 'notoptions', 'options' );
			return $value;
		}
		$old = $wpdb->get_var( $wpdb->prepare( "SELECT option_value FROM {$wpdb->options} WHERE option_name=%s", $name ) );
		if ( $old && (int) explode( ':', $old, 2 )[0] < time() ) {
			$changed = $wpdb->query( $wpdb->prepare( "UPDATE {$wpdb->options} SET option_value=%s WHERE option_name=%s AND option_value=%s", $value, $name, $old ) );
			wp_cache_delete( $name, 'options' );
			return 1 === $changed ? $value : null;
		}
		return null;
	}
	public static function release( string $name, string $value ): void {
		global $wpdb;
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name=%s AND option_value=%s", $name, $value ) );
		wp_cache_delete( $name, 'options' );
	}
	public static function require_transactional_storage( array $tables ): void {
		global $wpdb;
		foreach ( array_merge( array( $wpdb->options ), $tables ) as $table ) {
			$innodb = Schema::has_innodb_engine( $table );
			if ( null === $innodb ) {
				throw new \RuntimeException( 'storage_failed' );
			}
			if ( ! $innodb ) {
				throw new \RuntimeException( 'transactional_storage_required' );
			}
		}
	}
	public static function with_owner( string $name, string &$value, array $tables, callable $persist ): bool {
		global $wpdb;
		self::require_transactional_storage( $tables );
		$savepoint = 'ssa_' . substr( hash( 'sha256', $name . $value ), 0, 16 );
		// A savepoint probe preserves transactions opened by WordPress tests or another plugin.
		$suppressed = $wpdb->suppress_errors( true );
		try {
			$wpdb->query( "SAVEPOINT {$savepoint}" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Identifier contains only a fixed prefix and hex hash.
			$nested = false !== $wpdb->query( "RELEASE SAVEPOINT {$savepoint}" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Identifier contains only a fixed prefix and hex hash.
		} finally {
			$wpdb->suppress_errors( $suppressed );
		}
		$begin    = $nested ? "SAVEPOINT {$savepoint}" : 'START TRANSACTION';
		$commit   = $nested ? "RELEASE SAVEPOINT {$savepoint}" : 'COMMIT';
		$rollback = $nested ? "ROLLBACK TO SAVEPOINT {$savepoint}" : 'ROLLBACK';
		// Replaying a write after reconnecting would lose this transaction's ownership lock.
		$reconnect_retries       = $wpdb->reconnect_retries;
		$wpdb->reconnect_retries = 0;
		try {
			if ( false === $wpdb->query( $begin ) ) { // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- Fixed transaction statements and a hex savepoint identifier.
				throw new \RuntimeException( 'storage_failed' );
			}
			try {
				$owner = $wpdb->get_var( $wpdb->prepare( "SELECT option_value FROM {$wpdb->options} WHERE option_name=%s FOR UPDATE", $name ) );
				if ( $wpdb->last_error ) {
					throw new \RuntimeException( 'storage_failed' );
				}
				if ( $owner !== $value ) {
					$wpdb->query( $rollback ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- Fixed rollback statement and a hex savepoint identifier.
					if ( $nested ) {
						$wpdb->query( $commit ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- Releases only this helper's savepoint.
					}
					return false;
				}
				$persist();
				$renewed = ( time() + 120 ) . ':' . wp_generate_uuid4();
				if ( 1 !== $wpdb->query( $wpdb->prepare( "UPDATE {$wpdb->options} SET option_value=%s WHERE option_name=%s AND option_value=%s", $renewed, $name, $value ) ) ) {
					throw new \RuntimeException( 'storage_failed' );
				}
				if ( false === $wpdb->query( $commit ) ) { // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- Fixed commit statement and a hex savepoint identifier.
					throw new \RuntimeException( 'storage_failed' );
				}
				$value = $renewed;
				wp_cache_delete( $name, 'options' );
				return true;
			} catch ( \Throwable $error ) {
				$wpdb->query( $rollback ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- Fixed rollback statement and a hex savepoint identifier.
				if ( $nested ) {
					$wpdb->query( $commit ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- Releases only this helper's savepoint.
				}
				throw $error;
			}
		} finally {
			$wpdb->reconnect_retries = $reconnect_retries;
		}
	}
}
