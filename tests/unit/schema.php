<?php
/** Run with: php tests/unit/schema.php */

declare(strict_types=1);

$base = realpath( sys_get_temp_dir() );
if ( false === $base ) {
	throw new RuntimeException( 'Temporary directory is unavailable.' );
}
$candidate = $base . DIRECTORY_SEPARATOR . 'ssa-schema-' . bin2hex( random_bytes( 8 ) );
if ( ! mkdir( $candidate, 0700 ) ) {
	throw new RuntimeException( 'Could not create schema test directory.' );
}
$root = realpath( $candidate );
if ( false === $root || strcasecmp( dirname( $root ), $base ) !== 0 || ! str_starts_with( basename( $root ), 'ssa-schema-' ) ) {
	rmdir( $candidate );
	throw new RuntimeException( 'Resolved schema test directory escaped its temporary parent.' );
}
$upgrade_directory = $root . DIRECTORY_SEPARATOR . 'wp-admin' . DIRECTORY_SEPARATOR . 'includes';
if ( ! mkdir( $upgrade_directory, 0700, true ) || false === file_put_contents( $upgrade_directory . DIRECTORY_SEPARATOR . 'upgrade.php', "<?php\n" ) ) {
	rmdir( $candidate );
	throw new RuntimeException( 'Could not create the WordPress upgrade stub.' );
}
define( 'ABSPATH', $root . DIRECTORY_SEPARATOR );
define( 'ARRAY_A', 'ARRAY_A' );

class SchemaDatabase {
	public string $prefix     = 'wp_';
	public string $options    = 'wp_options';
	public string $last_error = '';
	public array $tables      = array();
	public array $creates     = array();
	public function get_charset_collate(): string {
		return 'DEFAULT CHARACTER SET utf8mb4';
	}
	public function prepare( string $query, string $table ): string {
		return str_replace( '%s', "'{$table}'", $query );
	}
	public function esc_like( string $value ): string {
		return addcslashes( $value, '_%\\' );
	}
	public function get_row( string $query, $output ): ?array {
		$this->last_error = '';
		preg_match( "/LIKE '([^']+)'/", $query, $matches );
		return $this->tables[ stripcslashes( $matches[1] ?? '' ) ] ?? null;
	}
}

class WP_SQLite_DB extends SchemaDatabase {}

class SchemaQueryFailureDatabase extends SchemaDatabase {
	public function get_row( string $query, $output ): ?array {
		$this->last_error = 'SHOW TABLE STATUS failed';
		return null;
	}
}

$GLOBALS['wpdb']                      = new SchemaDatabase();
$GLOBALS['ssa_schema_create_allowed'] = false;
$GLOBALS['ssa_schema_options']        = array();

function dbDelta( string $query ): array {
	global $wpdb;
	preg_match( '/CREATE TABLE ([A-Za-z0-9_]+)/', $query, $matches );
	$table               = $matches[1] ?? '';
	$wpdb->creates[]     = $query;
	$wpdb->last_error     = '';
	if ( ! $GLOBALS['ssa_schema_create_allowed'] ) {
		$wpdb->last_error = 'CREATE command denied';
		return array();
	}
	if ( ! isset( $wpdb->tables[ $table ] ) ) {
		$wpdb->tables[ $table ] = array( 'Engine' => str_contains( $query, 'ENGINE=InnoDB' ) ? 'InnoDB' : 'MyISAM' );
	}
	return array();
}

function update_option( string $key, $value, $autoload = null ): bool {
	$GLOBALS['ssa_schema_options'][ $key ] = $value;
	return true;
}

function schema_check( bool $condition, string $message ): void {
	if ( ! $condition ) {
		throw new RuntimeException( $message );
	}
}

register_shutdown_function(
	static function () use ( $root, $candidate ): void {
		$upgrade_file = $root . DIRECTORY_SEPARATOR . 'wp-admin' . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'upgrade.php';
		if ( is_file( $upgrade_file ) ) {
			unlink( $upgrade_file );
		}
		$includes = dirname( $upgrade_file );
		$admin    = dirname( $includes );
		if ( is_dir( $includes ) ) {
			rmdir( $includes );
		}
		if ( is_dir( $admin ) ) {
			rmdir( $admin );
		}
		if ( is_dir( $root ) ) {
			rmdir( $root );
		}
	}
);

require dirname( __DIR__, 2 ) . '/site-security-auditor/includes/Persistence/Schema.php';
require dirname( __DIR__, 2 ) . '/site-security-auditor/includes/Support/Lock.php';

SiteSecurityAuditor\Persistence\Schema::install();
schema_check( ! isset( $GLOBALS['ssa_schema_options']['ssa_schema_version'] ), 'A failed table creation must leave the schema version unset.' );

$GLOBALS['ssa_schema_create_allowed'] = true;
$GLOBALS['wpdb']->tables['wp_ssa_scans'] = array( 'Engine' => 'MyISAM' );
SiteSecurityAuditor\Persistence\Schema::install();
schema_check( ! isset( $GLOBALS['ssa_schema_options']['ssa_schema_version'] ), 'An existing non-InnoDB table must leave the schema version unset.' );

unset( $GLOBALS['wpdb']->tables['wp_ssa_scans'] );
SiteSecurityAuditor\Persistence\Schema::install();
schema_check( '1' === $GLOBALS['ssa_schema_options']['ssa_schema_version'], 'A successful schema retry must record the version.' );
schema_check( array( 'InnoDB', 'InnoDB' ) === array_column( array_values( $GLOBALS['wpdb']->tables ), 'Engine' ), 'New scan tables must use InnoDB.' );
foreach ( $GLOBALS['wpdb']->creates as $query ) {
	schema_check( str_contains( $query, 'ENGINE=InnoDB' ), 'Each schema statement must request InnoDB.' );
}

$sqlite_database          = new WP_SQLite_DB();
$sqlite_database->tables  = array(
	'wp_options'       => array( 'Engine' => 'InnoDB' ),
	'wp_ssa_scans'     => array( 'Engine' => 'InnoDB' ),
	'wp_ssa_findings'  => array( 'Engine' => 'InnoDB' ),
);
$GLOBALS['wpdb']                  = $sqlite_database;
$GLOBALS['ssa_schema_options']    = array();
SiteSecurityAuditor\Persistence\Schema::install();
schema_check( ! isset( $GLOBALS['ssa_schema_options']['ssa_schema_version'] ), 'A SQLite drop-in must not record an InnoDB schema version.' );

$storage_error = null;
try {
	SiteSecurityAuditor\Support\Lock::require_transactional_storage( array( 'wp_ssa_scans', 'wp_ssa_findings' ) );
} catch ( RuntimeException $error ) {
	$storage_error = $error->getMessage();
}
schema_check( 'transactional_storage_required' === $storage_error, 'A SQLite drop-in that reports InnoDB must be rejected for transactional writes.' );

$GLOBALS['wpdb'] = new SchemaQueryFailureDatabase();
$storage_error   = null;
try {
	SiteSecurityAuditor\Support\Lock::require_transactional_storage( array( 'wp_ssa_scans', 'wp_ssa_findings' ) );
} catch ( RuntimeException $error ) {
	$storage_error = $error->getMessage();
}
schema_check( 'storage_failed' === $storage_error, 'A failed engine query must remain a storage error.' );

echo "schema: failed creation stays unversioned; InnoDB retry installs; SQLite metadata spoof is rejected\n";
