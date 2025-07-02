module.exports = {
  apps: [
    {
      name: 'Kean-OLT-BE',
      script: 'dist/src/main.js',
      instances: 1,
      autorestart: true,
      watch: false,
      time: true,
      ignore_watch: ['src', 'dist'],
      log_date_format: 'YYYY-MM-DD HH:mm Z',
      node_args: '--max-old-space-size=2048',
      watch_options: {
        followSymlinks: false,
        ignored: ['src', 'dist'],
      },
      max_memory_restart: '2G',
      // Default environment (production)
      env: {
        NODE_ENV: 'production',
        // Add other production environment variables here
      },
      // Staging environment
      env_staging: {
        NODE_ENV: 'staging',
        // Add other staging environment variables here
      },
    },
  ],
};
