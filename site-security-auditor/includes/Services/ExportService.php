<?php
// phpcs:disable WordPress.WP.AlternativeFunctions.file_system_operations_fopen, WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- CSV uses an automatically removed temporary stream, without WordPress filesystem credentials.
namespace SiteSecurityAuditor\Services;

final class ExportService {
	public static function csv_cell( $value ): string {
		$value = (string) $value;
		if ( preg_match( '/^[\x00-\x20]*[=+\-@]|^[\x00-\x1f]/', $value ) ) {
			$value = "'" . $value;
		}
		return $value;
	}
	public static function csv( array $scan, array $findings ): string {
		$stream  = fopen( 'php://temp', 'r+' );
		$columns = array( 'check_id', 'status', 'severity', 'component_name', 'component_version', 'title', 'evidence', 'remediation', 'source', 'checked_at' );
		fputcsv( $stream, $columns, ',', '"', '' );
		foreach ( $findings as $finding ) {
			$row = array();
			foreach ( $columns as $column ) {
				$value = $finding[ $column ] ?? '';
				$row[] = self::csv_cell( is_array( $value ) ? implode( '; ', $value ) : $value );
			}
			fputcsv( $stream, $row, ',', '"', '' );
		}
		// Explicit check rows preserve unknown/excluded states even without findings.
		foreach ( $scan['checks'] as $check ) {
			fputcsv( $stream, array( $check['check_id'], $check['status'], '', '', '', 'Check result', self::csv_cell( $check['reason'] ), '', '', $check['checked_at'] ?? '' ), ',', '"', '' );
		}
		rewind( $stream );
		$text = stream_get_contents( $stream );
		fclose( $stream );
		return $text;
	}
}
