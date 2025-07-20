# Operations Guide

This guide provides production deployment, monitoring, maintenance, and disaster recovery instructions for the Secure OHLCV Downloader.

## 1. Production Deployment

1. **Environment Preparation**
   - Use Python 3.11 or newer.
   - Install dependencies from `requirements-secure.txt` using a virtual environment.
   - Run `python validate_environment.py` to verify required packages.
2. **Configuration**
   - Copy `.env.example` to `.env` and set required variables:
     - `ALPHA_VANTAGE_API_KEY`
     - `OHLCV_ENCRYPTION_KEY`
   - Review `config.py` for tunable parameters (timeouts, retention days, directory permissions).
3. **Initial Setup**
   - Run `python secure_ohlcv_downloader.py --init` to create secure directories and initialize encryption keys.
   - Verify key storage using `keyring` by running `python secure_ohlcv_downloader.py --check-keys`.

## 2. Monitoring and Logging

- Application logs are written to `secure_downloader.log` in the working directory.
- Enable debug mode by setting `OHLCV_LOG_LEVEL=DEBUG`.
- Use standard log rotation tools (e.g., `logrotate` on Linux) to manage log size.
- Monitor system metrics with `psutil` integration in the application. Configure alerts when memory usage exceeds configured limits.
- For API monitoring, review the rate limit logs in `secure_downloader.log` and configure dashboards with your preferred monitoring stack (Prometheus, Grafana).

## 3. Capacity Planning

- Estimate storage requirements based on expected tickers and date ranges. A typical daily dataset is roughly 1–5 KB per ticker per day.
- Ensure at least double the anticipated storage is available for encrypted backups.
- Monitor API usage to avoid hitting provider limits. For heavy workloads consider staggered schedules or multiple API keys.

## 4. Routine Maintenance

- Update dependencies quarterly using `pip install -r requirements-secure.txt --upgrade`.
- Review and rotate encryption keys annually using `python secure_ohlcv_downloader.py --rotate-key`.
- Clean up old data by running `python secure_ohlcv_cli.py --cleanup` or scheduling a cron job.
- Validate backups monthly by decrypting a sample file with `secure_ohlcv_downloader.py --verify-backup`.

## 5. Disaster Recovery

1. **Backups**
   - Schedule regular encrypted backups of the data directory.
   - Store backups in an off-site or cloud location with strong access controls.
2. **Restoration Procedure**
   - Install the application on the target system following the deployment steps.
   - Restore the encrypted data directory from backup.
   - Run `python secure_ohlcv_downloader.py --recover` to re-link encryption keys and verify data integrity.

## 6. Support

For operational issues contact `ops@company.com`. For security incidents refer to the contact information in `SECURITY.md`.

