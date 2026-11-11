<?php
namespace SiteSecurityAuditor\Support;

final class SafeOutput {
	public static function text( $value, int $limit = 2000 ): string {
		if ( ! is_scalar( $value ) && null !== $value ) {
			return '';
		}
		$text = wp_strip_all_tags( (string) $value );
		// Component filenames may be relative; absolute server paths never leave this boundary.
		$text = preg_replace( '~(?:file://|(?<![A-Za-z0-9])[A-Za-z]:[\\\\/]|\\\\\\\\|(?<![A-Za-z0-9:/._-])/)[^\s<>"\']*~i', '[redacted path]', $text );
		return substr( $text, 0, $limit );
	}
	public static function finding( array $input ): array {
		$out = array();
		foreach ( array( 'check_id', 'component_type', 'component_key', 'component_name', 'component_version', 'title', 'summary', 'evidence', 'checked_at', 'source', 'source_updated_at', 'advisory_id', 'affected_range', 'matching_rationale', 'limitations' ) as $key ) {
			$out[ $key ] = self::text( $input[ $key ] ?? '', 'component_key' === $key ? 255 : 2000 );
		}
		foreach ( array(
			'status'   => array( 'pass', 'fail', 'unknown', 'not_applicable' ),
			'severity' => array( 'critical', 'high', 'medium', 'low', 'info', 'unrated' ),
			'kind'     => array( 'confirmed_vulnerability', 'configuration_risk', 'hardening', 'integrity_difference', 'informational', 'unverified' ),
		) as $key => $allowed ) {
			$fallback    = array(
				'status'   => 'unknown',
				'severity' => 'unrated',
				'kind'     => 'unverified',
			);
			$out[ $key ] = in_array( $input[ $key ] ?? '', $allowed, true ) ? $input[ $key ] : $fallback[ $key ];
		}
		$out['remediation']       = array_map( array( self::class, 'text' ), array_slice( (array) ( $input['remediation'] ?? array() ), 0, 20 ) );
		$out['references']        = array_values(
			array_filter(
				array_map(
					static function ( $url ) {
						if ( ! is_string( $url ) || strlen( $url ) > 2048 ) {
							return '';
						}
						$url   = esc_url_raw( $url, array( 'https' ) );
						$parts = wp_parse_url( $url );
						if ( ! is_array( $parts ) || isset( $parts['user'] ) || isset( $parts['pass'] ) || ( isset( $parts['port'] ) && 443 !== $parts['port'] ) ) {
							return '';
						}
						$host = wp_parse_url( $url, PHP_URL_HOST );
						if ( 'github.com' === $host && ! preg_match( '~^/(?:advisories/GHSA-[a-z0-9-]+|[^/]+/[^/]+/security/advisories/GHSA-[a-z0-9-]+)/?$~i', $parts['path'] ?? '' ) ) {
							return '';
						}
						return $host && ( 'wordpress.org' === $host || str_ends_with( $host, '.wordpress.org' ) || in_array( $host, array( 'www.wpvulnerability.com', 'docs.wpvulnerability.com', 'www.cve.org', 'cve.mitre.org', 'nvd.nist.gov', 'www.php.net', 'wpscan.com', 'www.wordfence.com', 'patchstack.com', 'github.com' ), true ) ) ? $url : '';
					},
					array_slice( (array) ( $input['references'] ?? array() ), 0, 10 )
				)
			)
		);
		$out['source_updated_at'] = '' === $out['source_updated_at'] ? null : $out['source_updated_at'];
		return $out;
	}
}
