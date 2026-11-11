<?php
namespace SiteSecurityAuditor\Providers;

final class ChecksumProvider {
	public static function checksums( string $version, string $locale ) {
		if ( ! preg_match( '/^\d+\.\d+(?:\.\d+)?$/', $version ) || ! preg_match( '/^[a-zA-Z0-9_-]{2,20}$/', $locale ) ) {
			return new \WP_Error( 'invalid_checksum_query' );
		}
		$settings = get_option( 'ssa_settings', array() );
		if ( ! is_array( $settings ) || true !== ( $settings['core_integrity'] ?? false ) ) {
			return new \WP_Error( 'checksum_disabled' );
		}
		$key    = 'ssa_checksums_' . md5( $version . ':' . $locale );
		$cached = get_transient( $key );
		if ( false !== $cached ) {
			if ( is_array( $cached ) && isset( $cached['error'] ) ) {
				return new \WP_Error( $cached['error'] );
			}
			return self::valid_checksums( $cached ) ? $cached : new \WP_Error( 'checksum_invalid_response' );
		}
		$url      = 'https://api.wordpress.org/core/checksums/1.0/?' . http_build_query(
			array(
				'version' => $version,
				'locale'  => $locale,
			),
			'',
			'&',
			PHP_QUERY_RFC3986
		);
		$response = wp_safe_remote_get(
			$url,
			array(
				'timeout'             => 4,
				'redirection'         => 0,
				'limit_response_size' => 1048576,
				'user-agent'          => 'Site Security Auditor',
				'headers'             => array( 'Accept' => 'application/json' ),
			)
		);
		if ( is_wp_error( $response ) || 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
			return self::negative( $key, 'checksum_unavailable' );
		}
		$body = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( ! is_array( $body ) || ! self::valid_checksums( $body['checksums'] ?? null ) ) {
			return self::negative( $key, 'checksum_invalid_response' );
		}
		set_transient( $key, $body['checksums'], 12 * HOUR_IN_SECONDS );
		return $body['checksums'];
	}
	private static function valid_checksums( $checksums ): bool {
		if ( ! is_array( $checksums ) || ! $checksums || count( $checksums ) > 20000 ) {
			return false;
		}
		foreach ( $checksums as $checksum ) {
			if ( ! is_string( $checksum ) || ! preg_match( '/^[a-f0-9]{32}$/iD', $checksum ) ) {
				return false;
			}
		}
		return true;
	}
	private static function negative( string $key, string $code ) {
		set_transient( $key, array( 'error' => $code ), 900 );
		return new \WP_Error( $code ); }
}
