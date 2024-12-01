# PrometheusAlertManager

PrometheusAlertManager is a CLI tool designed to manage and monitor your projects with ease. It integrates with Prometheus to fetch metrics, evaluate rules, and send alerts via Telegram. The tool supports multiple configurations and can be extended to use different databases like MongoDB or File.

## Features
- Load and parse configuration files
- Monitor metrics and send alerts
- Log information and errors
- Send notifications to Telegram
- Support for multiple database backends (file, MongoDB)

## Project Structure
```
.
├── README.md
├── bot.mak
├── cli.py
├── config.cli.yml
├── config.ntjc.yml
├── config.stg.yml
├── config.zenhub.yml
├── docker-compose.yml
├── requirements.txt
├── run.py
└── send.msg.py

0 directories, 11 files
```

## Getting Started
### Prerequisites
- Python 3.x
- Prometheus
- Telegram Bot
- (Optional) MongoDB or File

### Installation
1. Clone the repository:
   ```sh
   git clone https://github.com/yourusername/PrometheusAlertManager.git
   cd PrometheusAlertManager

2. Install the required Python packages:
```
pip install -r requirements.txt
```

3. Configure your project by editing the configuration files (config.cli.yml, config.ntjc.yml, config.stg.yml, config.zenhub.yml).

4. RabbitMQ change password.
```
rabbitmqctl change_password hoanghd rabbitmq_password
```

5. RabbitMQ clean queues.
rabbitmqctl purge_queue telegram_queue

### Usage
Run the CLI tool with the specified project configuration:
```python [run.py](http://_vscodecontentref_/14) --project ntjc```

### Configuration
The configuration files are in YAML format and allow you to specify various settings for your project, including Prometheus queries, alert rules, Telegram bot settings, and database connections.

### Logging
Logs are stored in info.log and error.log files. You can configure the log file paths in the Logger class in run.py.

### Database
The tool supports multiple database backends. You can configure the database type and connection settings in the configuration files.

### Docker
You can use Docker to run the tool. A sample docker-compose.yml is provided in the repository.

### Contributing
Contributions are welcome! Please fork the repository and submit a pull request.

### License
This project is licensed under the MIT License.

### Contact
Author: Hà Đăng Hoàng \
Email: hoanghd@gmail.com \
Website: https://wiki.hoanghd.com \
Mobile: 0962277556