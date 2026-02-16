/**
 * PM2 Ecosystem - Modo cluster para aprovechar múltiples núcleos.
 * Uso: pm2 start ecosystem.config.js
 * Requiere: npm run build previo
 */
module.exports = {
  apps: [
    {
      name: 'nestjs-auth-api',
      script: 'dist/src/main.js',
      instances: 'max',
      exec_mode: 'cluster',
      autorestart: true,
      watch: false,
      max_memory_restart: '500M',
      env: {
        NODE_ENV: 'development',
      },
      env_production: {
        NODE_ENV: 'production',
      },
    },
  ],
};
