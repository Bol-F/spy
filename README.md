# System Monitor - Deployment Guide

## Prerequisites

- Windows 10/11
- Python 3.8 or higher
- Administrator privileges (for some features)

## Installation

1. **Clone or download the repository**

```bash
   git clone <repository-url>
   cd system-monitor
```

2. **Run the installation script**

```batch
   install.bat
```

3. **Configure the application**
    - Edit `.env` file with your Telegram bot credentials
    - Adjust monitoring settings as needed

## Configuration Options

### Essential Settings

- `TELEGRAM_TOKEN`: Your Telegram bot token
- `TELEGRAM_CHAT_ID`: Your Telegram chat ID

### Optional Settings

- `IGNORE_PROCS`: Comma-separated list of processes to ignore
- `REPORT_INTERVAL`: Seconds between reports (default: 5)
- `MAX_BUFFER_SIZE`: Maximum keystroke buffer size (default: 1000)
- `RETENTION_DAYS`: Days to keep old files (default: 7)

## Running the Application

### Manual Start

```bash
python monitor.py
```

### As a Windows Service (Optional)

Use NSSM (Non-Sucking Service Manager):

```batch
nssm install SystemMonitor "C:\Python\python.exe" "C:\path\to\monitor.py"
nssm start SystemMonitor
```

### Using Task Scheduler

1. Open Task Scheduler
2. Create Basic Task
3. Set trigger to "At startup"
4. Set action to start `monitor.py`
5. Configure to run with highest privileges

## Monitoring Performance

Run the performance monitor to track resource usage:

```bash
python performance_monitor.py
```

## Testing

Run unit tests:

```bash
python -m unittest test_monitor.py
```

## Troubleshooting

### Common Issues

1. **"Already running" error**
    - The application is designed to run as a single instance
    - Check Task Manager for existing instances

2. **Telegram messages not sending**
    - Verify bot token and chat ID
    - Check internet connection
    - Review logs in `%APPDATA%\SystemHelper\monitor.log`

3. **High CPU usage**
    - Increase `WINDOW_CHECK_INTERVAL` in configuration
    - Add more processes to `IGNORE_PROCS`

## Security Considerations

- Encryption keys are stored using Windows DPAPI
- All sensitive data is encrypted at rest
- Network communication uses HTTPS
- Consider firewall rules for Telegram API access

## Maintenance

- Logs are automatically rotated
- Old files are cleaned up based on `RETENTION_DAYS`
- Monitor disk space in `%APPDATA%\SystemHelper`

## Support

For issues or questions, please check the logs first:

- Application logs: `%APPDATA%\SystemHelper\monitor.log`
- Performance metrics: `performance.json`
