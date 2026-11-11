<?php
/** Run with: php tests/unit/filesystem.php */

namespace SiteSecurityAuditor\Audit\Checks {
	function microtime( $as_float = false ) {
		if ( empty( $GLOBALS['ssa_fake_clock'] ) ) {
			return \microtime( $as_float );
		}
		$now                              = $GLOBALS['ssa_fake_clock_value'];
		$GLOBALS['ssa_fake_clock_value'] += $GLOBALS['ssa_fake_clock_step'];
		return $as_float ? $now : sprintf( '%0.8f %d', $now - floor( $now ), (int) floor( $now ) );
	}
	function md5_file( $filename, $binary = false ) {
		++$GLOBALS['ssa_hash_calls'];
		return \md5_file( $filename, $binary );
	}
}

namespace {
function wp_json_encode( $value ) { return json_encode( $value ); }
function wp_strip_all_tags( $value ) { return strip_tags( $value ); }
	define( 'DAY_IN_SECONDS', 86400 );
	define( 'HOUR_IN_SECONDS', 3600 );

	class WP_Error {
		public function __construct( public string $code = '' ) {}
	}

	function is_wp_error( $value ): bool {
		return $value instanceof WP_Error; }
	function get_option( $key, $default = false ) {
		return $GLOBALS['ssa_options'][ $key ] ?? $default; }
	function get_transient( $key ) {
		return $GLOBALS['ssa_cache'][ $key ] ?? false; }
	function set_transient( $key, $value, $ttl ) {
		$GLOBALS['ssa_cache'][ $key ] = $value;
		return true; }
	function get_bloginfo( $key ) {
		return '6.8.3'; }
	function get_locale() {
		return 'en_US'; }
	function wp_safe_remote_get( $url, $args ) {
		++$GLOBALS['ssa_http_calls'];
		return array(
			'code' => 200,
			'body' => json_encode( array( 'checksums' => $GLOBALS['ssa_checksums'] ) ),
		);
	}
	function wp_remote_retrieve_response_code( $response ) {
		return $response['code']; }
	function wp_remote_retrieve_body( $response ) {
		return $response['body']; }

	function fs_check( bool $ok, string $message ): void {
		++$GLOBALS['ssa_assertions'];
		if ( ! $ok ) {
			throw new \RuntimeException( $message );
		}
	}

	$base = realpath( sys_get_temp_dir() );
	if ( false === $base ) {
		throw new \RuntimeException( 'Temporary directory is unavailable.' );
	}
	$candidate = $base . DIRECTORY_SEPARATOR . 'ssa-filesystem-' . bin2hex( random_bytes( 8 ) );
	if ( ! mkdir( $candidate, 0700 ) ) {
		throw new \RuntimeException( 'Could not create private test directory.' );
	}
	$root = realpath( $candidate );
	if ( false === $root || strcasecmp( dirname( $root ), $base ) !== 0 || ! str_starts_with( basename( $root ), 'ssa-filesystem-' ) ) {
		rmdir( $candidate );
		throw new \RuntimeException( 'Resolved test root escaped its verified temporary parent.' );
	}

	$owned_files               = array();
	$owned_links               = array();
	$owned_dirs                = array( $root );
	$skips                     = array();
	$GLOBALS['ssa_assertions'] = 0;
	$GLOBALS['ssa_hash_calls'] = 0;
	$GLOBALS['ssa_http_calls'] = 0;
	$GLOBALS['ssa_options']    = array( 'ssa_settings' => array( 'core_integrity' => true ) );
	$GLOBALS['ssa_cache']      = array();
	$GLOBALS['ssa_checksums']  = array();

	register_shutdown_function(
		static function () use ( &$owned_files, &$owned_links, &$owned_dirs ): void {
			foreach ( array_reverse( $owned_files ) as $path ) {
				if ( is_file( $path ) && ! is_link( $path ) ) {
					unlink( $path );
				}
			}
			foreach ( array_reverse( $owned_links ) as $path ) {
				if ( is_link( $path ) ) {
					unlink( $path );
				}
			}
			usort( $owned_dirs, static fn( $a, $b ) => strlen( $b ) <=> strlen( $a ) );
			foreach ( $owned_dirs as $path ) {
				if ( is_dir( $path ) && ! is_link( $path ) ) {
					rmdir( $path );
				}
			}
		}
	);

	$sandbox = $root;
	$root   .= DIRECTORY_SEPARATOR . 'wordpress';
	if ( ! mkdir( $root, 0700 ) ) {
		throw new \RuntimeException( 'Could not create isolated WordPress root.' );
	}
	$owned_dirs[] = $root;
	define( 'ABSPATH', $root . DIRECTORY_SEPARATOR );

	$make_dir     = static function ( string $relative ) use ( $root, &$owned_dirs ): string {
		$path = $root . DIRECTORY_SEPARATOR . str_replace( '/', DIRECTORY_SEPARATOR, $relative );
		if ( ! is_dir( $path ) && mkdir( $path, 0700, true ) ) {
			$cursor = $path;
			while ( $cursor !== $root && str_starts_with( $cursor, $root . DIRECTORY_SEPARATOR ) ) {
				if ( ! in_array( $cursor, $owned_dirs, true ) ) {
					$owned_dirs[] = $cursor;
				}
				$cursor = dirname( $cursor );
			}
		}
		return $path;
	};
	$write_file   = static function ( string $relative, string $contents ) use ( $root, &$owned_files, &$owned_dirs ): string {
		$path   = $root . DIRECTORY_SEPARATOR . str_replace( '/', DIRECTORY_SEPARATOR, $relative );
		$parent = dirname( $path );
		if ( ! is_dir( $parent ) ) {
			mkdir( $parent, 0700, true );
		}
		$cursor = $parent;
		while ( $cursor !== $root && str_starts_with( $cursor, $root . DIRECTORY_SEPARATOR ) ) {
			if ( ! in_array( $cursor, $owned_dirs, true ) ) {
				$owned_dirs[] = $cursor;
			}
			$cursor = dirname( $cursor );
		}
		if ( false === file_put_contents( $path, $contents ) ) {
			throw new \RuntimeException( 'Could not create owned test file.' );
		}
		if ( ! in_array( $path, $owned_files, true ) ) {
			$owned_files[] = $path;
		}
		return $path;
	};
	$run_checksum = static function ( array $map, array $context = array() ) {
		$GLOBALS['ssa_checksums'] = $map;
		$GLOBALS['ssa_cache']     = array();
		return \SiteSecurityAuditor\Audit\Checks\ProviderChecks::run( 12, $context );
	};

	require dirname( __DIR__, 2 ) . '/site-security-auditor/includes/Providers/ChecksumProvider.php';
	require dirname( __DIR__, 2 ) . '/site-security-auditor/includes/Audit/Checks/LocalChecks.php';
	require dirname( __DIR__, 2 ) . '/site-security-auditor/includes/Audit/Checks/ProviderChecks.php';

	$make_dir( 'core' );
	$unchanged = $write_file( 'core/unchanged.php', 'trusted core bytes' );
	$pass      = $run_checksum( array( 'core/unchanged.php' => md5_file( $unchanged ) ) );
	fs_check( 'pass' === $pass['status'] && 1 === $GLOBALS['ssa_http_calls'], 'matching local core checksum must pass through the HTTPS adapter contract' );

	$missing = $run_checksum( array( 'core/missing.php' => md5( 'expected' ) ) );
	fs_check( 'fail' === $missing['status'] && 1 === $missing['affected_count'] && 'core/missing.php' === $missing['findings'][0]['component_key'], 'missing allowlisted core file must fail with a relative key' );

	$changed_file = $write_file( 'core/changed.php', 'modified bytes' );
	$changed      = $run_checksum( array( 'core/changed.php' => md5( 'original bytes' ) ) );
	fs_check( 'fail' === $changed['status'] && 'core/changed.php' === $changed['findings'][0]['component_key'], 'changed core file must fail against the supplied checksum' );

	$config   = $write_file( 'wp-config.php', 'test-only configuration marker' );
	$payload  = $write_file( 'wp-content/plugins/test/payload.php', 'test-only payload' );
	$excluded = $run_checksum(
		array(
			'wp-config.php'                       => md5_file( $config ),
			'wp-content/plugins/test/payload.php' => md5_file( $payload ),
		)
	);
	fs_check( 'unknown' === $excluded['status'] && empty( $excluded['findings'] ), 'wp-config.php and wp-content checksum paths must not be read or reported as core files' );

	$traversal_target = $write_file( 'outside.php', 'must not be hashed by a traversal key' );
	$traversal        = $run_checksum( array( '../outside.php' => md5_file( $traversal_target ) ) );
	fs_check( 'unknown' === $traversal['status'] && empty( $traversal['findings'] ), 'parent traversal checksum path must be rejected before hashing' );

	if ( DIRECTORY_SEPARATOR !== '\\' ) {
		$target = $write_file( 'core/target.php', 'symlink target' );
		$leaf   = $root . DIRECTORY_SEPARATOR . 'core' . DIRECTORY_SEPARATOR . 'leaf-link.php';
		if ( function_exists( 'symlink' ) && @symlink( $target, $leaf ) ) {
			$owned_links[] = $leaf;
			$leaf_result   = $run_checksum( array( 'core/leaf-link.php' => md5_file( $target ) ) );
			fs_check( 'unknown' === $leaf_result['status'] && empty( $leaf_result['findings'] ), 'symlink leaf must not be hashed' );
		} else {
			$skips[] = 'symlink leaf (creation unsupported)';
		}

		$real_dir      = $make_dir( 'core/real-dir' );
		$ancestor_file = $write_file( 'core/real-dir/ancestor.php', 'symlink ancestor target' );
		$link_dir      = $root . DIRECTORY_SEPARATOR . 'core' . DIRECTORY_SEPARATOR . 'link-dir';
		if ( function_exists( 'symlink' ) && @symlink( $real_dir, $link_dir ) ) {
			$owned_links[]   = $link_dir;
			$ancestor_result = $run_checksum( array( 'core/link-dir/ancestor.php' => md5_file( $ancestor_file ) ) );
			fs_check( 'unknown' === $ancestor_result['status'] && empty( $ancestor_result['findings'] ), 'symlink ancestor must not be traversed' );
		} else {
			$skips[] = 'symlink ancestor (creation unsupported)';
		}

		if ( function_exists( 'chmod' ) ) {
			if ( @chmod( $config, 0666 ) && 0002 === ( fileperms( $config ) & 0002 ) ) {
				$world_writable = \SiteSecurityAuditor\Audit\Checks\LocalChecks::run( 13, array() );
				fs_check( 'fail' === $world_writable['status'], 'POSIX world-writable wp-config mode must fail' );
				@chmod( $config, 0644 );
				$restricted = \SiteSecurityAuditor\Audit\Checks\LocalChecks::run( 13, array() );
				fs_check( 'pass' === $restricted['status'], 'non-world-writable wp-config mode must pass' );
				$parent_config = $sandbox . DIRECTORY_SEPARATOR . 'wp-config.php';
				file_put_contents( $parent_config, '<?php throw new RuntimeException("Configuration must never execute during audit");' );
				$owned_files[] = $parent_config;
				chmod( $parent_config, 0666 );
				clearstatcache();
				$root_preferred = \SiteSecurityAuditor\Audit\Checks\LocalChecks::run( 13, array() );
				fs_check( 'pass' === $root_preferred['status'], 'root config must take precedence over unsafe parent config' );
				$held_config = $root . DIRECTORY_SEPARATOR . 'wp-config-held.php';
				$owned_files[] = $held_config;
				fs_check( rename( $config, $held_config ), 'could not move owned config fixture aside' );
				clearstatcache();
				$parent_unsafe = \SiteSecurityAuditor\Audit\Checks\LocalChecks::run( 13, array() );
				fs_check( 'fail' === $parent_unsafe['status'], 'world-writable supported parent config must fail' );
				chmod( $parent_config, 0644 );
				clearstatcache();
				$parent_safe = \SiteSecurityAuditor\Audit\Checks\LocalChecks::run( 13, array() );
				fs_check( 'pass' === $parent_safe['status'], 'restricted supported parent config must pass' );
				$parent_settings = $sandbox . DIRECTORY_SEPARATOR . 'wp-settings.php';
				file_put_contents( $parent_settings, 'unrelated installation marker' );
				$owned_files[] = $parent_settings;
				clearstatcache();
				$unrelated = \SiteSecurityAuditor\Audit\Checks\LocalChecks::run( 13, array() );
				fs_check( 'unknown' === $unrelated['status'], 'parent config belonging to another installation must not be audited' );
				fs_check( rename( $held_config, $config ), 'could not restore owned config fixture' );
			} else {
				$skips[] = 'chmod mode assertion (filesystem does not preserve POSIX bits)';
			}
		} else {
			$skips[] = 'chmod (unavailable)';
		}
	} else {
		$skips[]    = 'POSIX permissions and symlink checks (Windows)';
		$permission = \SiteSecurityAuditor\Audit\Checks\LocalChecks::run( 13, array() );
		fs_check( 'unknown' === $permission['status'], 'Windows config permissions must remain unknown' );
	}

	$large  = $root . DIRECTORY_SEPARATOR . 'core' . DIRECTORY_SEPARATOR . 'large.php';
	$handle = fopen( $large, 'c+b' );
	if ( false === $handle || ! ftruncate( $handle, 10485761 ) ) {
		throw new \RuntimeException( 'Could not create bounded-size test file.' );
	}
	fclose( $handle );
	$owned_files[] = $large;
	clearstatcache( true, $large );
	$GLOBALS['ssa_hash_calls'] = 0;
	$oversize                  = $run_checksum( array( 'core/large.php' => str_repeat( 'a', 32 ) ) );
	fs_check( 'unknown' === $oversize['status'] && 0 === $GLOBALS['ssa_hash_calls'], 'files above the 10 MiB cap must remain unknown without hashing' );

	$first                           = $write_file( 'core/deadline-one.php', 'first' );
	$second                          = $write_file( 'core/deadline-two.php', 'second' );
	$GLOBALS['ssa_fake_clock']       = true;
	$GLOBALS['ssa_fake_clock_value'] = 0.0;
	$GLOBALS['ssa_fake_clock_step']  = 4.1;
	$GLOBALS['ssa_hash_calls']       = 0;
	$deadline                        = $run_checksum(
		array(
			'core/deadline-one.php' => md5_file( $first ),
			'core/deadline-two.php' => md5_file( $second ),
		)
	);
	$GLOBALS['ssa_fake_clock']       = false;
	fs_check( isset( $deadline['cursor'] ) && 1 === $deadline['cursor']['offset'] && 1 === $GLOBALS['ssa_hash_calls'], '8-second deadline must return a cursor before starting another hash' );

	echo 'filesystem: ' . $GLOBALS['ssa_assertions'] . ' assertions passed';
	if ( $skips ) {
		echo '; skipped: ' . implode( ', ', $skips );
	}
	echo "\n";
}
