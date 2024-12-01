import pika
import yaml
import json
import requests
import time
import os
import argparse

# Load config file
def load_config(filename):
    with open(filename, 'r') as stream:
        try:
            return yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            print(exc)
            return None

def process_queue():
    # RabbitMQ connection parameters
    global rabbitmq_host, rabbitmq_queue, rabbitmq_username, rabbitmq_password, rabbitmq_enable

    # Connect to RabbitMQ
    credentials = pika.PlainCredentials(rabbitmq_username, rabbitmq_password)
    connection = pika.BlockingConnection(pika.ConnectionParameters(host=rabbitmq_host, credentials=credentials))
    channel = connection.channel()

    # Declare the queue
    channel.queue_declare(queue=rabbitmq_queue, durable=True)

    def callback(ch, method, properties, body):
        message = json.loads(body)
        url = message['url']
        proxies = message['proxies']

        # Send the request to Telegram
        if proxies:
            response = requests.get(url, proxies=proxies)
        else:
            response = requests.get(url)

        print("Telegram status code:", response.status_code)

        if response.status_code == 200:
            # Acknowledge the message
            time.sleep(2)  # Delay before requeuing
            ch.basic_ack(delivery_tag=method.delivery_tag)
        else:
            # Requeue the message with a delay
            time.sleep(2)  # Delay before requeuing
            ch.basic_nack(delivery_tag=method.delivery_tag, requeue=True)

    # Consume messages from the queue
    channel.basic_qos(prefetch_count=1)
    channel.basic_consume(queue=rabbitmq_queue, on_message_callback=callback)

    print('Waiting for messages. To exit press CTRL+C')
    channel.start_consuming()

if __name__ == '__main__':
    os.system('clear')

    # Argument parser
    parser = argparse.ArgumentParser(description='Run the CLI script with a specified project.')
    parser.add_argument('--project', type=str, required=True, help='The project name')
    args = parser.parse_args()

    # Use the provided project name
    CONFIG_FILENAME = f"config.{args.project}.yml"
    config = load_config(CONFIG_FILENAME)

    if config:
        # Telegram connection parameters
        enable_proxy_server = config['default']['msg']['proxies']['enable']
        default_send_msg = config['default']['msg']['send_msg']
        form_send_msg = config['default']['msg']['form_msg']

        # RabbitMQ connection parameters
        rabbitmq_host = config['default']['msg']['rabbitmq']['host']
        rabbitmq_queue = config['default']['msg']['rabbitmq']['queue']
        rabbitmq_username = config['default']['msg']['rabbitmq']['username']
        rabbitmq_password = config['default']['msg']['rabbitmq']['password']
        rabbitmq_enable = config['default']['msg']['rabbitmq']['enable']

        # Database connection parameters
        database_type = config['default']['database']['type']
        database_prefix = config['default']['database']['prefix']
        database_mongodb_host = config['default']['database']['host']
        database_mongodb_port = config['default']['database']['port']
        database_mongodb_username = config['default']['database']['username']
        database_mongodb_password = config['default']['database']['password']

    process_queue()