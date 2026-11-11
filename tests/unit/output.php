<?php
/** Standalone privacy regression: php tests/unit/output.php */
function wp_strip_all_tags( $value ) {
	return strip_tags( $value );
}
require dirname( __DIR__, 2 ) . '/site-security-auditor/includes/Support/SafeOutput.php';

use SiteSecurityAuditor\Support\SafeOutput;

foreach ( array( '/data/private.php', '/mnt/secret', '/app/config', '/workspace/site', 'C:\\private\\file', '\\\\server\\share\\secret', 'file:///data/private.php' ) as $value ) {
	if ( '[redacted path]' !== SafeOutput::text( $value ) ) {
		throw new RuntimeException( 'Absolute path escaped the privacy boundary.' );
	}
}
foreach ( array( 'wp-includes/version.php', 'https://wordpress.org/documentation/' ) as $value ) {
	if ( $value !== SafeOutput::text( $value ) ) {
		throw new RuntimeException( 'Safe relative path or URL was damaged.' );
	}
}
if ( '' !== SafeOutput::text( array( 'malformed' ) ) || 'plain' !== SafeOutput::text( '<b>plain</b>' ) ) {
	throw new RuntimeException( 'Unsafe output type or HTML was retained.' );
}
echo "output: all assertions passed\n";
