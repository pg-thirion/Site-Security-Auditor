<?php
namespace SiteSecurityAuditor\Audit\Checks;

use SiteSecurityAuditor\Providers\ChecksumProvider;
use SiteSecurityAuditor\Providers\WPVulnerabilityProvider;

final class ProviderChecks {
	public static function run( int $n, array $c ): array {
		$settings = get_option( 'ssa_settings', array() );
		$settings = is_array( $settings ) ? $settings : array();
		if ( 12 !== $n && true !== ( $settings['vulnerability_intelligence'] ?? false ) ) {
			return array(
				'status'         => 'unknown',
				'reason'         => 'Vulnerability intelligence is disabled in settings.',
				'findings'       => array(),
				'affected_count' => 0,
				'has_unknown'    => true,
			);
		}
		if ( 12 === $n && true !== ( $settings['core_integrity'] ?? false ) ) {
			return array(
				'status'         => 'unknown',
				'reason'         => 'Core integrity verification is disabled in settings.',
				'findings'       => array(),
				'affected_count' => 0,
				'has_unknown'    => true,
			);
		}
		return 12 === $n ? self::integrity( $c ) : self::vulnerabilities( $n, $c );
	}

	private static function vulnerabilities( int $n, array $c ): array {
		$type        = 4 === $n ? 'core' : ( 5 === $n ? 'plugin' : 'theme' );
		$items       = self::components( $type );
		$state       = is_array( $c['cursor'] ?? null ) ? $c['cursor'] : array();
		$fingerprint = hash( 'sha256', wp_json_encode( $items ) );
		$count       = (int) ( $state['count'] ?? 0 );
		if ( isset( $state['fingerprint'] ) && ! hash_equals( (string) $state['fingerprint'], $fingerprint ) ) {
			return array(
				'status'         => 'unknown',
				'reason'         => 'Component inventory changed during this check; run a new audit.',
				'findings'       => array(),
				'affected_count' => $count,
				'has_unknown'    => true,
			);
		}
		$i                = max( 0, (int) ( $state['offset'] ?? 0 ) );
		$advisory_offset  = max( 0, (int) ( $state['advisory_offset'] ?? 0 ) );
		$feed_fingerprint = $state['feed_fingerprint'] ?? null;
		$findings         = array();
		$had_unknown      = ! empty( $state['unknown'] );
		$requests         = 0;
		$emitted          = 0;
		$started          = microtime( true );
		$item_count       = count( $items );
		while ( $i < $item_count && $requests < 5 && $emitted < 100 && microtime( true ) - $started < 8 ) {
			$item = $items[ $i ];
			if ( empty( $item['slug'] ) || empty( $item['version'] ) || empty( $item['verified'] ) ) {
				$had_unknown = true;
				++$i;
				$advisory_offset  = 0;
				$feed_fingerprint = null;
				continue;
			}
			++$requests;
			$lookup = WPVulnerabilityProvider::lookup( $type, $item['slug'], (int) max( 1, floor( 8 - ( microtime( true ) - $started ) ) ) );
			if ( is_wp_error( $lookup ) ) {
				$had_unknown = true;
				++$i;
				$advisory_offset  = 0;
				$feed_fingerprint = null;
				continue;
			}
			$advisories          = $lookup['vulnerabilities'];
			$current_fingerprint = hash( 'sha256', wp_json_encode( $advisories ) );
			if ( $feed_fingerprint && ! hash_equals( (string) $feed_fingerprint, $current_fingerprint ) ) {
				return array(
					'status'         => 'unknown',
					'reason'         => 'Advisory data changed while this component was being checked; run a new audit.',
					'findings'       => $findings,
					'affected_count' => $count,
					'has_unknown'    => true,
				);
			}
			$advisory_count = count( $advisories );
			for ( $j = $advisory_offset; $j < $advisory_count && $emitted < 100; ++$j ) {
				if ( microtime( true ) - $started >= 8 ) {
					break;
				}
				$v = $advisories[ $j ];
				if ( ! is_array( $v ) || ( 'core' !== $type && ! is_array( $v['operator'] ?? null ) ) || ( 'core' === $type && ( $v['name'] ?? null ) !== $item['version'] ) ) {
					$had_unknown = true;
					continue;
				}
				$matches = 'core' === $type ? true : self::affected( $item['version'], $v['operator'] );
				if ( null === $matches ) {
					$had_unknown = true;
					continue;
				}
				if ( ! $matches ) {
					continue;
				}
				$entry = self::normalise_advisory( $v, 'core' === $type ? $item['version'] : null );
				if ( ! $entry ) {
					$had_unknown = true;
					continue;
				}
				++$count;
				++$emitted;
				$rationale  = 'core' === $type ? 'The exact-version core endpoint returned this advisory and echoed the queried version.' : 'Installed version ' . $item['version'] . ' satisfies the provider range operators.';
				$findings[] = array(
					'component_type'     => $type,
					'component_key'      => $item['slug'],
					'component_name'     => substr( wp_strip_all_tags( $item['name'] ), 0, 100 ),
					'component_version'  => substr( $item['version'], 0, 40 ),
					'advisory_id'        => $entry['id'],
					'affected_range'     => $entry['range'],
					'matching_rationale' => $rationale,
					'status'             => 'fail',
					'severity'           => $entry['severity'],
					'kind'               => 'confirmed_vulnerability',
					'title'              => $entry['title'],
					'summary'            => $rationale . ( $entry['fixed'] ? ' A fixed version is ' . $entry['fixed'] . '.' : '' ),
					'evidence'           => 'Advisory ' . $entry['id'] . '; ' . $entry['range'] . '. ' . $rationale,
					'remediation'        => array( 'Review the advisory and update to a fixed release when available.' ),
					'references'         => $entry['url'] ? array( $entry['url'] ) : array(),
					'source'             => 'wpvulnerability',
					'source_updated_at'  => gmdate( 'c', $lookup['updated'] ),
				);
			}
			if ( $j < $advisory_count ) {
				$advisory_offset  = $j;
				$feed_fingerprint = $current_fingerprint;
				break;
			}
			++$i;
			$advisory_offset  = 0;
			$feed_fingerprint = null;
		}
		$cursor = $i < $item_count ? array(
			'offset'           => $i,
			'advisory_offset'  => $advisory_offset,
			'feed_fingerprint' => $feed_fingerprint,
			'count'            => $count,
			'unknown'          => $had_unknown,
			'fingerprint'      => $fingerprint,
		) : null;
		return array(
			'status'         => $count ? 'fail' : ( $had_unknown ? 'unknown' : 'pass' ),
			'reason'         => $cursor ? 'Vulnerability checks are continuing in bounded batches.' : ( $count ? 'Matching published advisories found.' : ( $had_unknown ? 'One or more component lookups could not be verified.' : 'No matching advisories were returned for verified components.' ) ),
			'findings'       => $findings,
			'affected_count' => $count,
			'has_unknown'    => $had_unknown,
			'cursor'         => $cursor,
		);
	}
	private static function components( string $type ): array {
		if ( 'core' === $type ) {
			return array(
				array(
					'slug'     => get_bloginfo( 'version' ),
					'version'  => get_bloginfo( 'version' ),
					'name'     => 'WordPress',
					'verified' => true,
				),
			);
		}
		$out = array();
		if ( 'plugin' === $type ) {
			if ( ! function_exists( 'get_plugins' ) ) {
				require_once ABSPATH . 'wp-admin/includes/plugin.php';
			}
			$updates = get_site_transient( 'update_plugins' );
			foreach ( get_plugins() as $file => $plugin ) {
				$slug = dirname( $file );
				if ( '.' === $slug ) {
					$slug = basename( $file, '.php' );
				}
				$version = (string) ( $plugin['Version'] ?? '' );
				$entry   = null;
				if ( ( is_object( $updates ) && isset( $updates->response[ $file ] ) ) xor ( is_object( $updates ) && isset( $updates->no_update[ $file ] ) ) ) {
					$entry = $updates->response[ $file ] ?? $updates->no_update[ $file ];
				}
				$entry_slug = is_object( $entry ) ? ( $entry->slug ?? '' ) : ( is_array( $entry ) ? ( $entry['slug'] ?? '' ) : '' );
				$verified   = empty( $plugin['UpdateURI'] ) && self::fresh_update_state( $updates ) && isset( $updates->checked[ $file ] ) && (string) $updates->checked[ $file ] === $version && $entry_slug === $slug;
				$out[]      = array(
					'slug'     => $slug,
					'version'  => $version,
					'name'     => (string) ( $plugin['Name'] ?? $slug ),
					'verified' => $verified,
				);
			}
		} else {
			$updates = get_site_transient( 'update_themes' );
			foreach ( wp_get_themes() as $slug => $theme ) {
				$version       = (string) $theme->get( 'Version' );
				$has_response  = is_object( $updates ) && isset( $updates->response[ $slug ] );
				$has_no_update = is_object( $updates ) && isset( $updates->no_update[ $slug ] );
				$verified      = '' === (string) $theme->get( 'UpdateURI' ) && self::fresh_update_state( $updates ) && isset( $updates->checked[ $slug ] ) && (string) $updates->checked[ $slug ] === $version && ( $has_response xor $has_no_update );
				$out[]         = array(
					'slug'     => (string) $slug,
					'version'  => $version,
					'name'     => (string) $theme->get( 'Name' ),
					'verified' => $verified,
				);
			}
		}
		return $out;
	}
	private static function fresh_update_state( $state ): bool {
		if ( ! is_object( $state ) || ! isset( $state->last_checked ) || ! is_numeric( $state->last_checked ) ) {
			return false;
		}
		$age = time() - (int) $state->last_checked;
		return $age >= -300 && $age <= DAY_IN_SECONDS && isset( $state->checked ) && is_array( $state->checked ) && isset( $state->response ) && is_array( $state->response ) && isset( $state->no_update ) && is_array( $state->no_update );
	}

	private static function affected( string $version, array $op ): ?bool {
		$min       = (string) ( $op['min_version'] ?? '' );
		$minop     = strtolower( (string) ( $op['min_operator'] ?? '' ) );
		$max       = (string) ( $op['max_version'] ?? '' );
		$maxop     = strtolower( (string) ( $op['max_operator'] ?? '' ) );
		$operators = array( 'lt', 'le', 'eq', 'ne', 'gt', 'ge' );
		if ( ! preg_match( '/^[0-9][A-Za-z0-9.+_-]{0,39}$/', $version ) || ( ! $min && ! $max ) || ( $min && ! preg_match( '/^[0-9][A-Za-z0-9.+_-]{0,39}$/', $min ) ) || ( $max && ! preg_match( '/^[0-9][A-Za-z0-9.+_-]{0,39}$/', $max ) ) || ( $min && ! in_array( $minop, $operators, true ) ) || ( $max && ! in_array( $maxop, $operators, true ) ) ) {
			return null;
		}
		if ( $min && $max ) {
			$bounds = version_compare( $min, $max );
			if ( $bounds > 0 ) {
				return null;
			}
			$possible_comparisons = 0 === $bounds
				? array( array( -1, -1 ), array( 0, 0 ), array( 1, 1 ) )
				: array( array( -1, -1 ), array( 0, -1 ), array( 1, -1 ), array( 1, 0 ), array( 1, 1 ) );
			$possible             = false;
			foreach ( $possible_comparisons as $comparison ) {
				if ( self::compare( $comparison[0], $minop ) && self::compare( $comparison[1], $maxop ) ) {
					$possible = true;
					break;
				}
			}
			if ( ! $possible ) {
				return null;
			}
		}
		if ( $min && ! self::compare( version_compare( $version, $min ), $minop ) ) {
			return false;
		}
		if ( $max && ! self::compare( version_compare( $version, $max ), $maxop ) ) {
			return false;
		}
		return (bool) ( $min || $max );
	}
	private static function compare( int $cmp, string $op ): bool {
		return array(
			'lt' => $cmp < 0,
			'le' => $cmp <= 0,
			'eq' => 0 === $cmp,
			'ne' => 0 !== $cmp,
			'gt' => $cmp > 0,
			'ge' => $cmp >= 0,
		)[ $op ] ?? false; }
	private static function normalise_advisory( array $v, ?string $core_version = null ): ?array {
		$op     = $v['operator'] ?? array();
		$source = $v['source'] ?? array();
		$id     = '';
		foreach ( (array) $source as $ref ) {
			if ( is_array( $ref ) && preg_match( '/^(?:CVE-\d{4}-\d{4,}|[a-f0-9-]{16,64})$/i', (string) ( $ref['id'] ?? '' ) ) ) {
				$id = (string) $ref['id'];
				break;
			}
		}
		if ( ! $id && preg_match( '/^[a-f0-9]{40,64}$/i', (string) ( $v['uuid'] ?? '' ) ) ) {
			$id = (string) $v['uuid'];
		}
		if ( ! $id ) {
			return null;
		}
		$severity = strtolower( (string) ( $v['impact']['cvss3']['severity'] ?? '' ) );
		$severity = in_array( $severity, array( 'critical', 'high', 'medium', 'low' ), true ) ? $severity : 'unrated';
		$url      = '';
		foreach ( (array) $source as $ref ) {
			if ( is_array( $ref ) && self::safe_url( (string) ( $ref['link'] ?? '' ) ) ) {
				$url = (string) $ref['link'];
				break;
			}
		}
		$range = null !== $core_version ? 'Exact queried WordPress core version ' . $core_version : ( ( ! empty( $op['min_version'] ) ? ( $op['min_operator'] ?? '' ) . ' ' . $op['min_version'] : '' ) . ( ! empty( $op['max_version'] ) ? ' ' . ( $op['max_operator'] ?? '' ) . ' ' . $op['max_version'] : '' ) );
		$title = (string) ( $v['description'] ?? $v['name'] ?? '' );
		return array(
			'id'       => $id,
			'url'      => $url,
			'range'    => substr( trim( $range ), 0, 100 ),
			'fixed'    => null === $core_version && preg_match( '/^\d+(?:\.\d+){0,3}$/', (string) ( $op['max_version'] ?? '' ) ) && 'lt' === ( $op['max_operator'] ?? '' ) ? (string) $op['max_version'] : '',
			'severity' => $severity,
			'title'    => substr( wp_strip_all_tags( $title ? $title : 'Known vulnerability affects installed version' ), 0, 120 ),
		);
	}

	private static function safe_url( string $url ): bool {
		$p = wp_parse_url( $url );
		return is_array( $p ) && 'https' === strtolower( $p['scheme'] ?? '' ) && in_array( strtolower( $p['host'] ?? '' ), array( 'www.cve.org', 'cve.mitre.org', 'wpscan.com', 'www.wordfence.com', 'patchstack.com', 'github.com' ), true ); }

	private static function integrity( array $c ): array {
		$version   = get_bloginfo( 'version' );
		$locale    = get_locale();
		$checksums = ChecksumProvider::checksums( $version, $locale );
		if ( is_wp_error( $checksums ) ) {
			return array(
				'status'         => 'unknown',
				'reason'         => 'Official HTTPS checksum lookup failed.',
				'findings'       => array(),
				'affected_count' => 0,
			);
		}
		$root = realpath( ABSPATH );
		if ( ! $root || is_link( ABSPATH ) ) {
			return array(
				'status'         => 'unknown',
				'reason'         => 'WordPress core directory could not be safely verified.',
				'findings'       => array(),
				'affected_count' => 0,
			);
		}
		$paths = array_keys( $checksums );
		sort( $paths, SORT_STRING );
		$state       = is_array( $c['cursor'] ?? null ) ? $c['cursor'] : array();
		$fingerprint = hash( 'sha256', wp_json_encode( $paths ) . wp_json_encode( $checksums ) );
		if ( isset( $state['fingerprint'] ) && ! hash_equals( (string) $state['fingerprint'], $fingerprint ) ) {
			return array(
				'status'         => 'unknown',
				'reason'         => 'Official checksum list changed during this check; run a new audit.',
				'findings'       => array(),
				'affected_count' => (int) ( $state['count'] ?? 0 ),
				'has_unknown'    => true,
			);
		}
		$i          = max( 0, (int) ( $state['offset'] ?? 0 ) );
		$count      = (int) ( $state['count'] ?? 0 );
		$unknown    = ! empty( $state['unknown'] );
		$issues     = array();
		$limit      = min( 250, max( 1, (int) ( $c['hash_budget'] ?? 250 ) ) );
		$done       = 0;
		$started    = microtime( true );
		$path_count = count( $paths );
		while ( $i < $path_count && $done < $limit && microtime( true ) - $started < 8 ) {
			$rel = $paths[ $i++ ];
			++$done;
			$lower_rel = is_string( $rel ) ? strtolower( $rel ) : '';
			if ( ! is_string( $rel ) || ! preg_match( '~^[A-Za-z0-9_./-]{1,240}$~', $rel ) || preg_match( '~(^|/)\.\.?(/|$)~', $rel ) || str_starts_with( $rel, '/' ) || str_starts_with( $lower_rel, 'wp-content/' ) || 'wp-config.php' === $lower_rel ) {
				$unknown = true;
				continue; }
			$path        = $root . DIRECTORY_SEPARATOR . str_replace( '/', DIRECTORY_SEPARATOR, $rel );
			$cursor_path = $root;
			foreach ( explode( '/', $rel ) as $part ) {
				$cursor_path .= DIRECTORY_SEPARATOR . $part;
				if ( is_link( $cursor_path ) ) {
					$unknown = true;
					continue 2; }
			}
			$real = realpath( $path );
			if ( false === $real ) {
				++$count;
				$issues[] = $rel;
				continue; }
			if ( 0 !== strpos( strtolower( $real ), strtolower( $root . DIRECTORY_SEPARATOR ) ) || ! is_file( $real ) ) {
				$unknown = true;
				continue; }
			$size = @filesize( $real ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Unreadable metadata returns unknown without leaking paths.
			if ( false === $size || $size > 10485760 ) {
				$unknown = true;
				continue; }
			$expected = strtolower( (string) $checksums[ $rel ] );
			if ( ! preg_match( '/^[a-f0-9]{32}$/', $expected ) ) {
				$unknown = true;
				continue; }
			$actual = @md5_file( $real ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Unreadable core files return unknown without leaking paths.
			if ( false === $actual ) {
				$unknown = true;
				continue; }
			if ( ! hash_equals( $expected, strtolower( $actual ) ) ) {
				++$count;
				$issues[] = $rel; }
		}
		if ( $i < count( $paths ) ) {
			return array(
				'status'         => $count ? 'fail' : ( $unknown ? 'unknown' : 'pass' ),
				'reason'         => 'Core checksums are being compared in bounded batches.',
				'findings'       => self::integrity_findings( $issues ),
				'affected_count' => $count,
				'has_unknown'    => $unknown,
				'cursor'         => array(
					'offset'      => $i,
					'count'       => $count,
					'unknown'     => $unknown,
					'fingerprint' => $fingerprint,
				),
			);
		}
		$status = $count ? 'fail' : ( $unknown ? 'unknown' : 'pass' );
		return array(
			'status'         => $status,
			'reason'         => $count ? 'Core files differ from official checksums; differences are not proof of malware.' : ( $unknown ? 'Some core files could not be safely verified.' : 'All checksummed core files matched.' ),
			'findings'       => self::integrity_findings( $issues ),
			'affected_count' => $count,
			'has_unknown'    => $unknown,
		);
	}
	private static function integrity_findings( array $files ): array {
		$out = array();
		foreach ( $files as $rel ) {
			$out[] = array(
				'component_type'    => 'core_file',
				'component_key'     => substr( $rel, 0, 255 ),
				'component_name'    => basename( $rel ),
				'component_version' => '',
				'status'            => 'fail',
				'severity'          => 'high',
				'kind'              => 'integrity_difference',
				'title'             => 'WordPress core file differs from official checksum',
				'summary'           => 'The listed core file is missing or differs from the official checksum. This is not proof of malware.',
				'evidence'          => 'MD5 comparison with checksum provided over HTTPS by WordPress.org.',
				'remediation'       => array( 'Review the file and restore it from a trusted WordPress core package if appropriate.' ),
				'references'        => array( 'https://wordpress.org/documentation/article/faq-troubleshooting/' ),
				'source'            => 'wordpress.org',
				'source_updated_at' => null,
				'checked_at'        => gmdate( 'c' ),
			);
		}
		return $out;
	}
}
