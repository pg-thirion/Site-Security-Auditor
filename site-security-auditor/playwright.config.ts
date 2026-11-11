import { defineConfig } from '@playwright/test';

export default defineConfig( {
	testDir: './e2e',
	use: {
		baseURL: process.env.WP_BASE_URL || 'http://localhost:8888',
		viewport: { width: 1280, height: 900 },
	},
} );
