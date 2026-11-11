<?php
namespace SiteSecurityAuditor\Audit\Checks;

final class LocalChecks {
	public static function run( int $n, array $c ): array {
		$findings    = array();
		$status      = 'pass';
		$reason      = 'No issue found in the available WordPress state.';
		$affected    = 0;
		$cursor      = null;
		$has_unknown = false;
		$fail        = static function ( string $title, string $summary, string $severity, string $kind = 'configuration_risk', string $component = '', string $type = '', string $version = '', string $name = '' ) use ( &$findings, &$status, &$affected ) {
			$status = 'fail';
			++$affected;
			$findings[] = self::finding( $title, $summary, $severity, $kind, $component, $type, $version, $name );
		};
		$unknown     = static function ( string $why ) use ( &$status, &$reason, &$has_unknown ) {
			$status      = 'unknown';
			$has_unknown = true;
			$reason      = $why;
		};
		switch ( $n ) {
			case 1:
				$u       = get_site_transient( 'update_core' );
				$checked = (int) ( $c['now'] ?? time() );
				if ( ! is_object( $u ) || empty( $u->last_checked ) || ! is_numeric( $u->last_checked ) || (int) $u->last_checked > $checked + 300 || $checked - (int) $u->last_checked > DAY_IN_SECONDS || (string) ( $u->version_checked ?? '' ) !== (string) get_bloginfo( 'version' ) || ! is_array( $u->updates ?? null ) || empty( $u->updates ) ) {
					$unknown( 'Core update state is missing, stale or incomplete.' );
					break; }
				foreach ( $u->updates as $up ) {
					if ( ! is_object( $up ) || ! in_array( $up->response ?? '', array( 'latest', 'upgrade', 'autoupdate' ), true ) ) {
						$unknown( 'Core update state contains an unsupported response.' );
						break; }
					if ( in_array( $up->response, array( 'upgrade', 'autoupdate' ), true ) ) {
						$fail( 'WordPress core update available', 'WordPress reports a newer core version (' . (string) ( $up->current ?? '' ) . '). Review and apply it after a backup.', 'medium', 'configuration_risk', 'wordpress-core', 'core', (string) get_bloginfo( 'version' ), 'WordPress' );
						break; }
				}
				break;
			case 2:
				$u         = get_site_transient( 'update_plugins' );
				$checked   = (int) ( $c['now'] ?? time() );
				$plugins   = get_plugins();
				$responses = $u->response ?? null;
				$known     = $u->no_update ?? null;
				if ( ! is_object( $u ) || empty( $u->last_checked ) || ! is_numeric( $u->last_checked ) || (int) $u->last_checked > $checked + 300 || $checked - (int) $u->last_checked > DAY_IN_SECONDS || ! is_array( $u->checked ?? null ) || ! is_array( $responses ) || ! is_array( $known ) ) {
					$unknown( 'Plugin update state is missing, stale or incomplete.' );
					break; }
				$state       = is_array( $c['cursor'] ?? null ) ? $c['cursor'] : array();
				$offset      = max( 0, (int) ( $state['offset'] ?? 0 ) );
				$has_unknown = ! empty( $state['unknown'] );
				$fingerprint = hash( 'sha256', wp_json_encode( array_keys( $plugins ) ) );
				if ( isset( $state['fingerprint'] ) && ! hash_equals( (string) $state['fingerprint'], $fingerprint ) ) {
					$unknown( 'Plugin inventory changed during this check.' );
					break; }
				$affected = (int) ( $state['count'] ?? 0 );
				$batch    = array_slice( $plugins, $offset, 100, true );
				foreach ( $batch as $file => $plugin ) {
					if ( ! isset( $u->checked[ $file ] ) || ! hash_equals( (string) ( $plugin['Version'] ?? '' ), (string) $u->checked[ $file ] ) ) {
						$has_unknown = true;
						$status      = 'unknown';
						continue;
					}
					$slug = self::slug( dirname( (string) $file ) );
					if ( ! $slug ) {
						$slug = self::slug( basename( (string) $file, '.php' ) );
					}
					if ( array_key_exists( $file, $responses ) ) {
						$info = $responses[ $file ];
						if ( ! is_object( $info ) || empty( $info->new_version ) ) {
							$has_unknown = true;
							$reason      = 'WordPress returned incomplete plugin update data.';
							continue;
						} ++$affected;
						$findings[] = self::finding( 'Plugin update available', 'An installed plugin has an update reported by WordPress. Offered version: ' . (string) $info->new_version . '.', 'medium', 'configuration_risk', $slug, 'plugin', (string) ( $plugin['Version'] ?? '' ), (string) ( $plugin['Name'] ?? $slug ) ); } elseif ( ! array_key_exists( $file, $known ) ) {
						$has_unknown = true;
						$status      = 'unknown'; }
				}
				if ( $offset + count( $batch ) < count( $plugins ) ) {
					$cursor = array(
						'offset'      => $offset + count( $batch ),
						'count'       => $affected,
						'unknown'     => $has_unknown,
						'fingerprint' => $fingerprint,
					);
				}
				if ( $affected ) {
					$status = 'fail';
				}
				if ( 'unknown' === $status ) {
					$reason = 'One or more installed plugins are missing from the update result.';
				}
				break;
			case 3:
				$u         = get_site_transient( 'update_themes' );
				$checked   = (int) ( $c['now'] ?? time() );
				$themes    = wp_get_themes();
				$responses = $u->response ?? null;
				$known     = $u->no_update ?? null;
				if ( ! is_object( $u ) || empty( $u->last_checked ) || ! is_numeric( $u->last_checked ) || (int) $u->last_checked > $checked + 300 || $checked - (int) $u->last_checked > DAY_IN_SECONDS || ! is_array( $u->checked ?? null ) || ! is_array( $responses ) || ! is_array( $known ) ) {
					$unknown( 'Theme update state is missing, stale or incomplete.' );
					break; }
				$state       = is_array( $c['cursor'] ?? null ) ? $c['cursor'] : array();
				$offset      = max( 0, (int) ( $state['offset'] ?? 0 ) );
				$has_unknown = ! empty( $state['unknown'] );
				$fingerprint = hash( 'sha256', wp_json_encode( array_keys( $themes ) ) );
				if ( isset( $state['fingerprint'] ) && ! hash_equals( (string) $state['fingerprint'], $fingerprint ) ) {
					$unknown( 'Theme inventory changed during this check.' );
					break; }
				$affected = (int) ( $state['count'] ?? 0 );
				$batch    = array_slice( $themes, $offset, 100, true );
				foreach ( $batch as $slug => $theme ) {
					if ( ! isset( $u->checked[ $slug ] ) || ! hash_equals( (string) $theme->get( 'Version' ), (string) $u->checked[ $slug ] ) ) {
						$has_unknown = true;
						$status      = 'unknown';
						continue;
					}
					if ( array_key_exists( $slug, $responses ) ) {
						$info = $responses[ $slug ];
						if ( ! is_object( $info ) || empty( $info->new_version ) ) {
							$has_unknown = true;
							$reason      = 'WordPress returned incomplete theme update data.';
							continue;
						} ++$affected;
						$findings[] = self::finding( 'Theme update available', 'An installed theme has an update reported by WordPress. Offered version: ' . (string) $info->new_version . '.', 'medium', 'configuration_risk', (string) $slug, 'theme', (string) $theme->get( 'Version' ), (string) $theme->get( 'Name' ) ); } elseif ( ! array_key_exists( $slug, $known ) ) {
						$has_unknown = true;
						$status      = 'unknown'; }
				}
				if ( $offset + count( $batch ) < count( $themes ) ) {
					$cursor = array(
						'offset'      => $offset + count( $batch ),
						'count'       => $affected,
						'unknown'     => $has_unknown,
						'fingerprint' => $fingerprint,
					);
				}
				if ( $affected ) {
					$status = 'fail';
				}
				if ( 'unknown' === $status ) {
					$reason = 'One or more installed themes are missing from the update result.';
				}
				break;
			case 7:
				$schemes = array( wp_parse_url( home_url(), PHP_URL_SCHEME ), wp_parse_url( site_url(), PHP_URL_SCHEME ) );
				if ( in_array( false, $schemes, true ) || in_array( null, $schemes, true ) ) {
					$unknown( 'WordPress site URL scheme could not be read.' );
				} elseif ( in_array( 'http', array_map( 'strtolower', $schemes ), true ) ) {
					$fail( 'HTTPS is not configured for every WordPress URL', 'A configured home or site URL uses HTTP. This checks configuration only, not transport or certificate validity.', 'high' );
				}
				break;
			case 8:
				if ( ! function_exists( 'force_ssl_admin' ) ) {
					$unknown( 'WordPress admin SSL state is unavailable.' );
				} elseif ( ! force_ssl_admin() ) {
					$fail( 'Admin SSL hardening is not enabled', 'force_ssl_admin() is false. This is hardening guidance and does not prove admin requests use HTTP.', 'medium', 'hardening' );
				}
				break;
			case 9:
				if ( ! defined( 'WP_DEBUG' ) ) {
					$unknown( 'WP_DEBUG is not defined, so debug output state is not verifiable.' );
				} elseif ( WP_DEBUG && ( ! defined( 'WP_DEBUG_DISPLAY' ) || WP_DEBUG_DISPLAY ) ) {
					$fail( 'Debug output may be displayed', 'WordPress debug output is configured for display. Disable it on a public production site.', 'high' );
				}
				break;
			case 10:
				if ( defined( 'DISALLOW_FILE_MODS' ) && DISALLOW_FILE_MODS ) {
					$reason = 'WordPress file modifications are disabled.';
				} elseif ( ! defined( 'DISALLOW_FILE_EDIT' ) || ! DISALLOW_FILE_EDIT ) {
					$fail( 'Built-in file editor is enabled', 'Set DISALLOW_FILE_EDIT to true to disable editing PHP files from wp-admin.', 'medium', 'hardening' );
				}
				break;
			case 11:
				if ( ! get_option( 'users_can_register' ) ) {
					break;
				}
				$role = get_option( 'default_role' );
				$obj  = get_role( (string) $role );
				if ( ! $obj || ! is_array( $obj->capabilities ?? null ) ) {
					$unknown( 'The default registration role capabilities could not be verified.' );
					break; }
				$caps = array( 'manage_options', 'edit_users', 'create_users', 'delete_users', 'remove_users', 'promote_users', 'install_plugins', 'activate_plugins', 'edit_plugins', 'delete_plugins', 'update_plugins', 'install_themes', 'edit_themes', 'delete_themes', 'update_themes', 'update_core' );
				if ( ! ( defined( 'DISALLOW_UNFILTERED_HTML' ) && DISALLOW_UNFILTERED_HTML ) ) {
					$caps[] = 'unfiltered_html';
				}
				foreach ( $caps as $cap ) {
					if ( ! empty( $obj->capabilities[ $cap ] ) ) {
						$fail( 'Public registration grants privileged capabilities', 'The configured default registration role includes a privileged capability.', 'critical' );
						break; }
				}
				break;
			case 13:
				$path = defined( 'ABSPATH' ) ? ABSPATH . 'wp-config.php' : '';
				if ( $path && ! file_exists( $path ) ) {
					$parent = dirname( ABSPATH ) . DIRECTORY_SEPARATOR;
					// Match wp-load.php's supported parent layout; restricted metadata must remain unknown.
					if ( @file_exists( $parent . 'wp-config.php' ) && ! @file_exists( $parent . 'wp-settings.php' ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Parent metadata may be outside open_basedir; never expose paths in warnings.
						$path = $parent . 'wp-config.php';
					}
				}
				if ( ! $path || ! is_file( $path ) || is_link( $path ) || DIRECTORY_SEPARATOR === '\\' || ! function_exists( 'fileperms' ) ) {
					$unknown( 'Configuration file permissions cannot be verified on this environment.' );
					break; }
				clearstatcache( true, $path );
				$perms = @fileperms( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Metadata read failures return unknown without emitting server paths.
				if ( false === $perms ) {
					$unknown( 'Configuration file permissions are unavailable.' );
					break; }
				if ( 0002 === ( $perms & 0002 ) ) {
					$fail( 'Configuration file is world-writable', 'The wp-config.php permission bits allow writes by other local users.', 'high' );
				}
				break;
			case 14:
				$v      = (string) ( $c['php_version'] ?? PHP_VERSION );
				$branch = implode( '.', array_slice( explode( '.', $v ), 0, 2 ) );
				$eol    = array(
					'5.6' => '2018-12-31',
					'7.0' => '2019-01-10',
					'7.1' => '2019-12-01',
					'7.2' => '2020-11-30',
					'7.3' => '2021-12-06',
					'7.4' => '2022-11-28',
					'8.0' => '2023-11-26',
					'8.1' => '2025-12-31',
					'8.2' => '2026-12-31',
					'8.3' => '2027-12-31',
					'8.4' => '2028-12-31',
					'8.5' => '2029-12-31',
				);
				if ( ! isset( $eol[ $branch ] ) ) {
					$unknown( 'PHP support dates for this branch are not in the maintained schedule.' );
					break; }
				if ( (string) ( $c['today'] ?? gmdate( 'Y-m-d' ) ) > $eol[ $branch ] ) {
					$fail( 'PHP branch is end of life', 'PHP ' . $branch . ' passed its published security-support end date (' . $eol[ $branch ] . ').', 'high' );
				}
				break;
			case 15:
				$plugins     = get_plugins();
				$active      = (array) get_option( 'active_plugins', array() );
				$state       = is_array( $c['cursor'] ?? null ) ? $c['cursor'] : array();
				$offset      = max( 0, (int) ( $state['offset'] ?? 0 ) );
				$affected    = (int) ( $state['count'] ?? 0 );
				$fingerprint = hash( 'sha256', wp_json_encode( array( array_keys( $plugins ), $active ) ) );
				if ( isset( $state['fingerprint'] ) && ! hash_equals( (string) $state['fingerprint'], $fingerprint ) ) {
					$unknown( 'Plugin inventory changed during this check.' );
					break;
				}
				$rows = array_slice( $plugins, $offset, 100, true );
				foreach ( $rows as $file => $p ) {
					if ( ! in_array( $file, $active, true ) ) {
						++$affected;
						$slug = self::slug( dirname( $file ) );
						if ( ! $slug ) {
							$slug = self::slug( basename( $file, '.php' ) );
						} $findings[] = self::finding( 'Inactive plugin installed', 'An installed plugin is inactive; review whether it is still needed.', 'info', 'informational', $slug, 'plugin', (string) ( $p['Version'] ?? '' ), (string) ( $p['Name'] ?? '' ) ); }
				}
				if ( $offset + count( $rows ) < count( $plugins ) ) {
					$cursor = array(
						'offset'      => $offset + count( $rows ),
						'count'       => $affected,
						'fingerprint' => $fingerprint,
					);
				}
				if ( $affected ) {
					$reason = 'Inactive plugins were found for review.'; }
				break;
			case 16:
				$themes        = wp_get_themes();
				$active        = wp_get_theme();
				$active_name   = $active->get_stylesheet();
				$active_parent = $active->get_template();
				$state         = is_array( $c['cursor'] ?? null ) ? $c['cursor'] : array();
				$offset        = max( 0, (int) ( $state['offset'] ?? 0 ) );
				$affected      = (int) ( $state['count'] ?? 0 );
				$fingerprint   = hash( 'sha256', wp_json_encode( array( array_keys( $themes ), $active_name, $active_parent ) ) );
				if ( isset( $state['fingerprint'] ) && ! hash_equals( (string) $state['fingerprint'], $fingerprint ) ) {
					$unknown( 'Theme inventory changed during this check.' );
					break;
				}
				$rows = array_slice( $themes, $offset, 100, true );
				foreach ( $rows as $slug => $theme ) {
					if ( $slug !== $active_name && $slug !== $active_parent ) {
						++$affected;
						$findings[] = self::finding( 'Inactive theme installed', 'An installed theme is inactive; review whether it is still needed.', 'info', 'informational', self::slug( (string) $slug ), 'theme', (string) $theme->get( 'Version' ), (string) $theme->get( 'Name' ) ); }
				}
				if ( $offset + count( $rows ) < count( $themes ) ) {
					$cursor = array(
						'offset'      => $offset + count( $rows ),
						'count'       => $affected,
						'fingerprint' => $fingerprint,
					);
				}
				if ( $affected ) {
					$reason = 'Inactive themes were found for review.';
				}
				break;
			default:
				$status = 'unknown';
				$reason = 'Check is not available.';
		}
		if ( $affected && ! in_array( $n, array( 15, 16 ), true ) ) {
			$status = 'fail';
		} elseif ( $has_unknown ) {
			$status = 'unknown';
		}
		if ( 'fail' === $status && 'No issue found in the available WordPress state.' === $reason ) {
			$reason = 'One or more issues were found in the available WordPress state.';
		}
		return array(
			'status'         => $status,
			'reason'         => $cursor ? 'Check is continuing in bounded batches.' : $reason,
			'findings'       => $findings,
			'affected_count' => $affected,
			'has_unknown'    => $has_unknown,
			'cursor'         => $cursor,
		);
	}

	public static function finding( string $title, string $summary, string $severity, string $kind = 'configuration_risk', string $component = '', string $type = '', string $version = '', string $name = '' ): array {
		return array(
			'component_type'    => $type,
			'component_key'     => self::safe_component( $component ),
			'component_name'    => substr( wp_strip_all_tags( $name ), 0, 100 ),
			'component_version' => substr( wp_strip_all_tags( $version ), 0, 40 ),
			'status'            => 'informational' === $kind ? 'pass' : 'fail',
			'severity'          => $severity,
			'kind'              => $kind,
			'title'             => substr( wp_strip_all_tags( $title ), 0, 120 ),
			'summary'           => substr( wp_strip_all_tags( $summary ), 0, 500 ),
			'evidence'          => substr( wp_strip_all_tags( $summary ), 0, 300 ),
			'remediation'       => array( 'Review the recommendation and apply an appropriate change after a backup.' ),
			'references'        => array(),
			'source'            => 'wordpress',
			'source_updated_at' => null,
			'checked_at'        => gmdate( 'c' ),
		);
	}
	private static function safe_component( string $v ): string {
		return preg_match( '~^[a-z0-9_-]{1,80}(?:/[a-z0-9_.-]{1,80})?$~i', $v ) ? $v : ''; }
	private static function slug( string $v ): string {
		return self::safe_component( trim( $v, '/.' ) ) ? trim( $v, '/.' ) : ''; }
}
