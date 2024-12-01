import urllib.parse, os, yaml, json, time, socket, base64, logging, requests, traceback
from jinja2 import Template # pip install jinja2
from prettytable import PrettyTable #python3 -m pip install -U prettytable
import argparse
import pika #pip install pika
from pymongo import MongoClient

# Logger class
class Logger:
    # Initialize logger
    def __init__(self, app_log_file='info.log', error_log_file='error.log'):
        self.hostname = socket.gethostname()
        self.app_logger = self.create_logger('app', logging.INFO, app_log_file)
        self.error_logger = self.create_logger('error', logging.ERROR, error_log_file)

    # Create logger
    def create_logger(self, name, level, log_file):
        logger = logging.getLogger(name)

        # Add handlers if not already added
        if not logger.handlers:
            logger.setLevel(level)
            file_handler = logging.FileHandler(log_file)
            console_handler = logging.StreamHandler()
            formatter = logging.Formatter(
                fmt='%(asctime)s {} python[%(process)d]: %(message)s'.format(self.hostname),
                datefmt='%b %d %H:%M:%S'
            )
            file_handler.setFormatter(formatter)
            console_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
            logger.addHandler(console_handler)
        return logger

    # Log info message
    def log_info(self, message):
        self.app_logger.info(message)

    # Log error message
    def log_error(self, e):
        self.error_logger.error(f"Error: {str(e)}")
        self.error_logger.error(traceback.format_exc())

def duration(old_timestamp):
    current_timestamp = time.time()
    duration_seconds = current_timestamp - old_timestamp

    # Constants for time units
    SECONDS_PER_MINUTE = 60
    MINUTES_PER_HOUR = 60
    HOURS_PER_DAY = 24

    # Calculate days, hours, minutes, and seconds
    days = int(duration_seconds / (SECONDS_PER_MINUTE * MINUTES_PER_HOUR * HOURS_PER_DAY))
    duration_seconds %= SECONDS_PER_MINUTE * MINUTES_PER_HOUR * HOURS_PER_DAY

    hours = int(duration_seconds / (SECONDS_PER_MINUTE * MINUTES_PER_HOUR))
    duration_seconds %= SECONDS_PER_MINUTE * MINUTES_PER_HOUR

    minutes = int(duration_seconds / SECONDS_PER_MINUTE)
    seconds = round(duration_seconds % SECONDS_PER_MINUTE, 2)

    # Build the result string using list comprehension
    result = ", ".join(
        f"{value} {name}"
        for value, name in [(days, "days"), (hours, "hours"), (minutes, "minutes"), (seconds, "seconds")]
        if value > 0
    )

    return result

# Load config file
def load_config(filename):
    with open(filename, 'r') as stream:
        try:
            return yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            print(exc)
            return None

# Function to check and initialize file
def check_and_initialize_file(file_path, initial_content):
    if not os.path.exists(file_path):
        with open(file_path, 'w') as file:
            json.dump(initial_content, file)
    else:
        with open(file_path, 'r+') as file:
            content = file.read().strip()
            if not content:
                file.seek(0)
                json.dump(initial_content, file)
                file.truncate()

# Function to create table
def create_table(msg):
    lines = msg.split("\n")
    table = PrettyTable()
    table.field_names = ["Field", "Value"]
    table.align = "l"
    table.header = True
    table.border = True

    # Add rows to table
    for line in lines:
        if ": " in line:
            key, value = line.split(": ", 1)
            table.add_row([key, value])
        elif "---" not in line:
            table.add_row([line, ""])

    return str(table)

def send_request_with_retry(url, proxies=None, max_retries=3, retry_delay=5):
    retries = 0
    while retries < max_retries:
        try:
            if proxies:
                response = requests.get(url, proxies=proxies)
            else:
                response = requests.get(url)
            
            print("Telegram status code:", response.status_code)

            # If the request was successful, return the response
            if response.status_code == 200:
                return response

            # If the request failed, log the status code and retry
            print(f"Request failed with status code {response.status_code}. Retrying...")
            retries += 1
            time.sleep(retry_delay)  # Wait before retrying
        except requests.RequestException as e:
            print(f"An error occurred: {e}. Retrying...")
            retries += 1
            time.sleep(retry_delay)

    # If we reach this point, we have failed to get a successful response
    print(f"Failed to get a successful response after {max_retries} retries.")
    return None

def send_request(url, msg_verify, proxies=None):
    global rabbitmq_host, rabbitmq_queue, rabbitmq_username, rabbitmq_password, rabbitmq_enable
    if rabbitmq_enable:
        # Connect to RabbitMQ
        credentials = pika.PlainCredentials(rabbitmq_username, rabbitmq_password)
        connection = pika.BlockingConnection(pika.ConnectionParameters(host=rabbitmq_host, credentials=credentials))
        channel = connection.channel()

        # Declare the queue
        channel.queue_declare(queue=rabbitmq_queue, durable=True)

        # Create the message payload
        message = {
            'url': url,
            'msg_verify': msg_verify,
            'proxies': proxies
        }

        # Publish the message to the queue
        if config['default']['debug'] == False:
            if msg_verify < count:
                channel.basic_publish(
                    exchange='',
                    routing_key=rabbitmq_queue,
                    body=json.dumps(message),
                    properties=pika.BasicProperties(
                        delivery_mode=2,  # Make message persistent
                    )
                )
        else:
            channel.basic_publish(
                exchange='',
                routing_key=rabbitmq_queue,
                body=json.dumps(message),
                properties=pika.BasicProperties(
                    delivery_mode=2,  # Make message persistent
                )
            )

        # Close the connection
        connection.close()
    else:
        if config['default']['debug'] == False:
            if msg_verify < count:
                send_request_with_retry(url, proxies=proxies)
        else:
            send_request_with_retry(url, proxies=proxies)

# Function to send message to Telegram
def telegram(msg, msg_verify, send_msg, botid, chatid):
    if config['default']['debug'] == True:
        botid = config['default']['msg']['debug_bot']['bot_id']
        chatid = config['default']['msg']['debug_bot']['chat_id']

    if form_send_msg == 'text':
        url = 'https://api.telegram.org/bot{}/sendMessage?chat_id={}&text={}'.format(botid, chatid, msg)
    elif form_send_msg == 'markdown':
        msg = "```\n{}\n```".format(msg)  # Wrap the message in code blocks to preserve formatting
        msg = urllib.parse.quote_plus(msg)  # URL encode the message
        url = 'https://api.telegram.org/bot{}/sendMessage?chat_id={}&text={}&parse_mode=Markdown'.format(botid, chatid, msg)
    elif form_send_msg == 'html':
        msg = create_table(msg)
        msg = "<pre><code>{}</code></pre>".format(create_table(msg))  # Wrap the message in pre and code tags
        msg = urllib.parse.quote_plus(msg)  # URL encode the message
        url = 'https://api.telegram.org/bot{}/sendMessage?chat_id={}&text={}&parse_mode=HTML'.format(botid, chatid, msg)
    if send_msg and default_send_msg:
        send_request(url, msg_verify, proxies if enable_proxy_server else None)

# Function to convert text to base64
def text_to_base64(text):
    bytes_obj = text.encode("utf-8")
    base64_str = base64.b64encode(bytes_obj).decode("utf-8")
    return base64_str

# Function to compare values
def compare_values(value_metric, value_alert, compare):
    comparisons = {
        '>=': float(value_metric) >= float(value_alert),
        '<=': float(value_metric) <= float(value_alert),
        '==': float(value_metric) == float(value_alert),
        '<': float(value_metric) < float(value_alert),
        '>': float(value_metric) > float(value_alert),
        '!=': float(value_metric) != float(value_alert)
    }
    return comparisons.get(compare, False)

# Function to format metric labels
def format_metric_labels(metric_labels):
    metric_labels.pop('__name__', None)
    return "\n".join(f"{key.capitalize()}: {value}" for key, value in metric_labels.items())

######## Using MongoDB to store data ########
def read_db(dbname):
    if database_type == 'mongodb':
        db = client[dbname]
        collection = db[dbname]
        document = collection.find_one({"_id": dbname})
        if document:
            return document['data']
        return []
    elif database_type == 'file':
        if os.path.exists(dbname):
            with open(dbname, 'r') as file:
                return json.load(file)
        return []

def write_db(dbname, data, expire=0):
    if database_type == 'mongodb':
        db = client[dbname]
        collection = db[dbname]
        collection.update_one(
            {"_id": dbname},
            {"$set": {"data": data}},
            upsert=True
        )
    elif database_type == 'file':
        with open(dbname, 'w') as file:
            json.dump(data, file, indent=4)

def check_value_in_threshold_warn(rule_values, value_metric):
    threshold_warn = rule_values.get('threshold_warn', [])
    for item in threshold_warn:
        if value_metric in item:
            return False
    return True

def process_alerts(alerts, value_metric, unit, static_msg, msg_description):
    final_msgs = []
    for alert in alerts:
        severity = alert['severity']
        if "{{ unit }}" in severity:
            severity = severity.replace("{{ unit }}", str(unit))
        send_msg = alert['send_msg']
        telegram_bot_id = alert['telegram']['bot_id']
        telegram_chat_id = alert['telegram']['chat_id']

        if 'description' in alert:
            alert_description = alert['description']
            if isinstance(alert_description, list):
                if len(alert_description) > 1:
                    alert_description = 'Description:\n' + '\n'.join([f" - {desc}" for desc in alert_description])
                else:
                    alert_description = f"Description: {alert_description[0]}"
            elif isinstance(alert_description, dict):
                if len(alert_description) > 1:
                    alert_description = 'Description:\n' + '\n'.join([f" - {key.capitalize()}: {value}" for key, value in alert_description.items()])
                else:
                    key, value = next(iter(alert_description.items()))
                    alert_description = f"Description: {value}"
            else:
                alert_description = False
        else:
            alert_description = False

        if alert_description:
            description = f"\n{alert_description}"
        elif msg_description:
            description = f"\n{msg_description}"
        else:
            description = ""

        if "{{ value }}" in description or "{{ unit }}" in description:
            description = description.replace("{{ value }}", str(value_metric)).replace("{{ unit }}", str(unit))
        
        final_msg = f"{static_msg}Severity: {severity}{description}"
        final_msgs.append((final_msg, send_msg, telegram_bot_id, telegram_chat_id))
    return final_msgs

def update_db(key, id, value_resend, value, rule_compare):
    data = read_db(DB_FILE_PATH)
    entry_found = False
    get_entry_value = None

    for entry in data:
        get_entry_value = entry['value']
        if entry['id'] == id:
            entry['key'] = key
            entry['value'] = value
            entry_found = True
            if entry['resend'] == value_resend:
                entry['resend'] = 1
            else:
                if entry['alert']:
                    entry['resend'] += 1
            break

    if not entry_found:
        data.append({
            "key": key,
            "id": id,
            "verify": 0,
            "resend": 1,
            "value": value,
            "old_value": [],
            "change": False,
            "compare": True,
            "alert": False,
            "count": 0,
            "timestamp": time.time()
        })

    write_db(DB_FILE_PATH, data)
    return get_entry_value

def main(key, id, value_metric, value_resend, get_value_of_compare, compare, value_verify, rule_compare, static_msg, value_alerts, value_contacts, msg_description, unit):
    global log_debug
    log_msg = static_msg.replace("\n", " ") + f'[{value_metric}]'
    
    def add_duration_and_contacts(final_msg, entry):
        return f"{final_msg}\nDuration: {duration(entry['timestamp'])}"

    if compare:
        get_entry_value = update_db(key, id, value_resend, get_value_of_compare, rule_compare)
        alerts = [alert for alert in value_alerts if alert['compare']]
        final_msgs = process_alerts(alerts, value_metric, unit, static_msg, msg_description)
        data = read_db(DB_FILE_PATH)

        for entry in data:
            if entry['id'] == id:
                entry['count'] += 1
                entry['verify'] += 1

                if entry['compare'] and entry['verify'] == value_verify and not entry['alert']:
                    if log_debug:
                        logger.log_info(f"[{DB_FILE_PATH}] Trường hợp 1: [{compare}] [{log_msg}], entry['verify']: {entry['verify']}, value_verify: {value_verify}, entry['alert']: {entry['alert']}")
                    entry['alert'] = True
                    entry['old_value'] = []
                    if get_value_of_compare not in entry['old_value']:
                        entry['old_value'].append(get_value_of_compare)
                    for final_msg, send_msg, telegram_bot_id, telegram_chat_id in final_msgs:
                        if send_msg:
                            logger.log_info(f"[{DB_FILE_PATH}] [{compare}] [{log_msg}] Send message to Telegram")
                            logger.log_info(f"[{DB_FILE_PATH}] {final_msg}\nContacts: {value_contacts}")
                            telegram(f"{final_msg}\nContacts: {value_contacts}", value_verify, send_msg, telegram_bot_id, telegram_chat_id)
                    continue

                if entry['compare'] and entry['resend'] == value_resend:
                    if log_debug:
                        logger.log_info(f"[{DB_FILE_PATH}] Trường hợp 2: [{compare}] [{log_msg}], entry['resend']: {entry['resend']}")
                    entry['resend'] = 1
                    entry['old_value'] = []
                    if get_value_of_compare not in entry['old_value']:
                        entry['old_value'].append(get_value_of_compare)
                    for final_msg, send_msg, telegram_bot_id, telegram_chat_id in final_msgs:
                        if send_msg:
                            logger.log_info(f"[{DB_FILE_PATH}] [{compare}] [{log_msg}] Send message to Telegram")
                            logger.log_info(f"[{DB_FILE_PATH}] {final_msg}\nContacts: {value_contacts}")
                            telegram(f"{final_msg}\nContacts: {value_contacts}", value_verify, send_msg, telegram_bot_id, telegram_chat_id)
                    continue

                if entry['compare'] and entry['alert'] and get_entry_value != get_value_of_compare:
                    if log_debug:
                        logger.log_info(f"[{DB_FILE_PATH}] Trường hợp 3: [{compare}] [{log_msg}], get_entry_value: [{get_entry_value}], get_value_of_compare: [{get_value_of_compare}], entry['alert']: {entry['alert']}, entry['verify']: {entry['verify']}, value_verify: {value_verify}, entry['change']: {entry['change']}")
                    entry['change'] = True

                    if value_metric in entry['old_value']:
                        entry['change'] = False

                    if entry['old_value'][0] != []:
                        if get_value_of_compare in entry['old_value']:
                            entry['change'] = False
                        
                    entry['verify'] = 1
                    continue

                if entry['compare'] and entry['verify'] == value_verify and entry['change']:
                    if log_debug:
                        logger.log_info(f"[{DB_FILE_PATH}] Trường hợp 4: [{compare}] [{log_msg}], entry['verify']: {entry['verify']}, value_verify: {value_verify}, entry['change']: {entry['change']}")
                    entry['change'] = False
                    entry['alert'] = True
                    entry['old_value'] = []
                    if get_value_of_compare not in entry['old_value']:
                        entry['old_value'].append(get_value_of_compare)
                    for final_msg, send_msg, telegram_bot_id, telegram_chat_id in final_msgs:
                        if send_msg and rule_compare not in ['!=']:
                            logger.log_info(f"[{DB_FILE_PATH}] [{compare}] [{log_msg}] Send message to Telegram")
                            logger.log_info(f"[{DB_FILE_PATH}] {final_msg}\nContacts: {value_contacts}")
                            telegram(f"{final_msg}\nContacts: {value_contacts}", value_verify, send_msg, telegram_bot_id, telegram_chat_id)
                    continue

                if not entry['compare']:
                    if log_debug:
                        logger.log_info(f"[{DB_FILE_PATH}] Trường hợp 5: [{compare}] [{log_msg}]")
                    entry['compare'] = True
                    entry['verify'] = 1

                    if value_metric in entry['old_value']:
                        entry['change'] = False
                    else:
                        entry['change'] = True

                    continue
            
        write_db(DB_FILE_PATH, data)

    else:
        alerts = [alert for alert in value_alerts if not alert['compare']]
        final_msgs = process_alerts(alerts, value_metric, unit, static_msg, msg_description)
        data = read_db(DB_FILE_PATH)

        for entry in data:
            if entry['id'] == id:
                entry['count'] += 1
                if entry['compare'] and not entry['alert'] and entry['count'] < value_verify:
                    if log_debug:
                        logger.log_info(f"[{DB_FILE_PATH}] Trường hợp 1: [{compare}] [{log_msg}], entry['count']: {entry['count']}, value_verify: {value_verify}, entry['alert']: {entry['alert']}")
                    data.remove(entry)
                    continue

                if entry['compare'] and entry['count'] > value_verify:
                    if log_debug:
                        logger.log_info(f"[{DB_FILE_PATH}] Trường hợp 2: [{compare}] [{log_msg}], entry['count']: {entry['count']}, value_verify: {value_verify}")
                    entry['verify'] = 0
                    entry['compare'] = False
                    entry['value'] = value_metric
                    continue

                if not entry['compare'] and not entry['alert']:
                    if log_debug:
                        logger.log_info(f"[{DB_FILE_PATH}] Trường hợp 3: [{compare}] [{log_msg}], entry['alert']: {entry['alert']}")
                    entry['verify'] += 1
                    entry['value'] = value_metric
                    continue

                if not entry['compare'] and not entry['alert'] and entry['verify'] == value_verify:
                    if log_debug:
                        logger.log_info(f"[{DB_FILE_PATH}] Trường hợp 4: [{compare}] [{log_msg}], entry['verify']: {entry['verify']}, value_verify: {value_verify}, entry['alert']: {entry['alert']}")
                    data.remove(entry)
                    for final_msg, send_msg, telegram_bot_id, telegram_chat_id in final_msgs:
                        if send_msg:
                            logger.log_info(f"[{DB_FILE_PATH}] [{compare}] [{log_msg}] Send message to Telegram")
                            final_msg = add_duration_and_contacts(final_msg, entry)
                            logger.log_info(f"[{DB_FILE_PATH}] {final_msg}\nContacts: {value_contacts}")
                            telegram(f"{final_msg}\nContacts: {value_contacts}", value_verify, send_msg, telegram_bot_id, telegram_chat_id)
                    continue

                if not entry['compare'] and entry['verify'] != value_verify:
                    if log_debug:
                        logger.log_info(f"[{DB_FILE_PATH}] Trường hợp 5: [{compare}] [{log_msg}], entry['verify']: {entry['verify']}, value_verify: {value_verify}")
                    entry['verify'] += 1
                    entry['value'] = value_metric
                    continue

                if not entry['compare'] and entry['verify'] == value_verify:
                    if log_debug:
                        logger.log_info(f"[{DB_FILE_PATH}] Trường hợp 6: [{compare}] [{log_msg}], entry['verify']: {entry['verify']}, value_verify: {value_verify}")
                    data.remove(entry)
                    for final_msg, send_msg, telegram_bot_id, telegram_chat_id in final_msgs:
                        if send_msg:
                            logger.log_info(f"[{DB_FILE_PATH}] [{compare}] [{log_msg}] Send message to Telegram")
                            final_msg = add_duration_and_contacts(final_msg, entry)
                            logger.log_info(f"[{DB_FILE_PATH}] {final_msg}\nContacts: {value_contacts}")
                            telegram(f"{final_msg}\nContacts: {value_contacts}", value_verify, send_msg, telegram_bot_id, telegram_chat_id)
                    continue

        write_db(DB_FILE_PATH, data)

def find_nearest_numbers(lst, value):
    greater = None
    greater_equal = None
    smaller = None
    smaller_equal = None

    for num in lst:
        if num > value and (greater is None or num < greater):
            greater = num
        if num >= value and (greater_equal is None or num < greater_equal):
            greater_equal = num
        if num < value and (smaller is None or num > smaller):
            smaller = num
        if num <= value and (smaller_equal is None or num > smaller_equal):
            smaller_equal = num

    return greater, greater_equal, smaller, smaller_equal

def get_threshold_values(value_metric, rule_compare, rule_metricname, metric_labels_output, value_resend, value_verify, value_contacts, value_get_unit, get_value_of_compare, rule_title, rule_values, value_alerts, rule_values_threshold_info, description, unit=None):   
    if get_value_of_compare is not None:
        if rule_compare in ["<", "<=", ">", ">="]:
            compare = compare_values(value_metric, get_value_of_compare, rule_compare)
            unit = next((item for item in value_get_unit if get_value_of_compare in item), None)[get_value_of_compare]

        if rule_compare in ["!="]:
            compare = check_value_in_threshold_warn(rule_values, value_metric)

            for threshold in rule_values.values():
                for item in threshold:
                    get_value_of_compare = value_metric
                    if value_metric in item:
                        unit = item[value_metric]
                        break
                    else:
                        if 'threshold_unit' in rule_values:
                            unit = rule_values['threshold_unit'][0]['unit']
                        else:
                            unit = "Null"

                if unit:
                    break

        if rule_compare in ["=="]:
            found = False
            for num in get_value_of_compare:
                if num == value_metric:
                    found = True
                    break
            if found:
                compare = True
                get_value_of_compare = value_metric
            else:
                compare = False
                get_value_of_compare = None

            for threshold in rule_values.values():
                for item in threshold:
                    if value_metric in item:
                        unit = item[value_metric]
                        break
                else:
                    get_value_of_compare = value_metric
                    if rule_values_threshold_info is not None:
                        for item in rule_values_threshold_info:
                            if value_metric in item:
                                unit = item[value_metric]
                                if unit == None:
                                    if 'threshold_unit' in rule_values:
                                        unit = rule_values['threshold_unit'][0]['unit']
                                    else:
                                        unit = "Null"
                                    break
                                break
                    else:
                        if 'threshold_unit' in rule_values:
                            unit = rule_values['threshold_unit'][0]['unit']
                        else:
                            unit = "Null"

                if unit:
                    break
    else:
        compare = False
        if 'threshold_unit' in rule_values:
            unit = rule_values['threshold_unit'][0]['unit']
        else:
            unit = "Null"

    if unit == None:
        if 'threshold_unit' in rule_values:
            unit = rule_values['threshold_unit'][0]['unit']
        else:
            unit = "Null"

    if metric_labels_output == "":
        static_msg = f"{rule_title}\n"
    else:
        static_msg = f"{rule_title}\n{metric_labels_output}\n"
    id = text_to_base64(f"{static_msg}Query: {rule_metricname}\n")
    key = text_to_base64(f"{id}{get_value_of_compare}")
    main(key, id, value_metric, value_resend, get_value_of_compare, compare, value_verify, rule_compare, static_msg, value_alerts, value_contacts, description, unit)

def get_metrics(prometheus_url, rules):
    logger = Logger()
    for rule in rules:
        if rule['enable']:
            rule_metricname = rule['query']
            rule_title = f"---- {rule['title']} ----"
            rule_compare = rule['compare']
            rule_values = rule['values']
            value_verify = rule['msg']['verify']
            value_resend = rule['msg']['resend']
            value_alerts = rule['alerts']
            value_contacts = ', '.join(rule['msg']['contacts'])
            value_msg = rule['msg']

            try:
                metric_results = requests.get(prometheus_url, params={'query': rule_metricname}).json()['data']['result']
            
                if not metric_results:
                    logger.log_info(f"{rule_metricname} returned no results")
                    continue

            except requests.RequestException as e:
                print(f"Error fetching metrics: {e}")
                logger.log_error(e)
                continue

            if 'description' in value_msg:
                description = value_msg['description']
                if isinstance(description, list):
                    if len(description) > 1:
                        description = 'Description:\n' + '\n'.join([f" - {desc}" for desc in description])
                    else:
                        description = f"Description: {description[0]}"
                elif isinstance(description, dict):
                    if len(description) > 1:
                        description = 'Description:\n' + '\n'.join([f" - {key.capitalize()}: {value}" for key, value in description.items()])
                    else:
                        key, value = next(iter(description.items()))
                        description = f"Description: {value}"
                else:
                    description = False
            else:
                description = False

            if 'threshold_warn' in rule_values:
                rule_values_threshold_warn = rule_values['threshold_warn']

            if 'threshold_info' in rule_values:
                rule_values_threshold_info = rule_values['threshold_info']
            else:
                rule_values_threshold_info = None

            for metric_result in metric_results:
                value_threshold_info = []
                metric_labels_output = format_metric_labels(list(metric_result.values())[0])
                value_metric = float(metric_result['value'][1])
                value_get_unit = rule_values_threshold_warn + (value_threshold_info if value_threshold_info is not None else [])
                get_threshold_warn = [list(threshold.keys())[0] for threshold in rule_values_threshold_warn] # Output: [40, 50, 60]
                greater, greater_equal, smaller, smaller_equal = find_nearest_numbers(get_threshold_warn, value_metric)

                if rule_compare == ">":
                    get_value_of_compare = smaller
                    get_threshold_values(value_metric, rule_compare, rule_metricname, metric_labels_output, value_resend, value_verify, value_contacts, value_get_unit, get_value_of_compare, rule_title, rule_values, value_alerts, rule_values_threshold_info, description)

                if rule_compare == ">=":
                    get_value_of_compare = smaller_equal
                    get_threshold_values(value_metric, rule_compare, rule_metricname, metric_labels_output, value_resend, value_verify, value_contacts, value_get_unit, get_value_of_compare, rule_title, rule_values, value_alerts, rule_values_threshold_info, description)

                if rule_compare == "<":
                    get_value_of_compare = greater
                    get_threshold_values(value_metric, rule_compare, rule_metricname, metric_labels_output, value_resend, value_verify, value_contacts, value_get_unit, get_value_of_compare, rule_title, rule_values, value_alerts, rule_values_threshold_info, description)

                if rule_compare == "<=":
                    get_value_of_compare = greater_equal
                    get_threshold_values(value_metric, rule_compare, rule_metricname, metric_labels_output, value_resend, value_verify, value_contacts, value_get_unit, get_value_of_compare, rule_title, rule_values, value_alerts, rule_values_threshold_info, description)
                    
                if rule_compare == "==":
                    get_value_of_compare = get_threshold_warn
                    get_threshold_values(value_metric, rule_compare, rule_metricname, metric_labels_output, value_resend, value_verify, value_contacts, value_get_unit, get_value_of_compare, rule_title, rule_values, value_alerts, rule_values_threshold_info, description)
                    
                if rule_compare == "!=":
                    get_value_of_compare = get_threshold_warn
                    get_threshold_values(value_metric, rule_compare, rule_metricname, metric_labels_output, value_resend, value_verify, value_contacts, value_get_unit, get_value_of_compare, rule_title, rule_values, value_alerts, rule_values_threshold_info, description)

if __name__ == '__main__':
    os.system('clear')
    logger = Logger()
    count = 0
    time_start = time.time()

    # Argument parser
    parser = argparse.ArgumentParser(description='Run the CLI script with a specified project.')
    parser.add_argument('--project', type=str, required=True, help='The project name')
    args = parser.parse_args()

    # Use the provided project name
    CONFIG_FILENAME = f"config.{args.project}.yml"
    config = load_config(CONFIG_FILENAME)

    if config:
        rules = config['rules']
        interval = config['default']['interval']
        prometheus_url = config['default']['prometheus_info']['url']
        log_debug = config['default']['log_debug']

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

        proxies = {
            "http": f"http://{config['default']['msg']['proxies']['ipaddr']}:{config['default']['msg']['proxies']['port']}",
            "https": f"http://{config['default']['msg']['proxies']['ipaddr']}:{config['default']['msg']['proxies']['port']}"
        }

    # Connect to MongoDB
    if database_type == 'mongodb':
        client = MongoClient(f'mongodb://{database_mongodb_username}:{database_mongodb_password}@{database_mongodb_host}:{database_mongodb_port}/')
        DB_FILE_PATH = f"{args.project}"

    if database_type == 'file':
        DB_FILE_PATH = f"db.{args.project}.json"

    welcome_message = f"""
        **************************************************
        *                                                *
        *              WELCOME TO THE CLI TOOL           *
        *                                                *
        **************************************************
        *                                                *
        *  This tool helps you manage and monitor your   *
        *  projects with ease.                           *
        *                                                *
        *  Features:                                     *
        *  - Load and parse configuration files          *
        *  - Monitor metrics and send alerts             *
        *  - Log information and errors                  *
        *  - Send notifications to Telegram              *
        *                                                *
        *  Contact:                                      *
        *  - Author: Hà Đăng Hoàng                       *
        *  - Email: hoanghd3@vng.com.vn                  *
        *  - Mobile: 0962277556                          *
        *                                                *
        *  Please wait while we load your configuration. *
        *                                                *
        **************************************************

        Proect information:
        - Using project: {args.project}
        - Using database file: {DB_FILE_PATH}
        - Using configuration file: {CONFIG_FILENAME}"""
    
    print(welcome_message)
    time.sleep(0)

    print(f"\n--------------------> Start running the script <--------------------\n")
    if config['default']['debug'] == False:
        while True:
            time_start = time.time()

            if database_type == 'file':
                check_and_initialize_file(CONFIG_FILENAME, {})
                check_and_initialize_file(DB_FILE_PATH, [])

            try:
                get_metrics(prometheus_url, rules)
                time_end = time.time()
                count += 1
                log_msg = f"[{DB_FILE_PATH}] Finished for the {count}th ({(time_end - time_start)} seconds)"
                if log_debug:
                    logger.log_info(log_msg)
                print(log_msg)
                time.sleep(interval)
            except Exception as e:
                print(f"Error: {e}")
                logger.log_error(e)
                traceback.print_exc()
    else:
        time_start = time.time()
        get_metrics(prometheus_url, rules)
        time_end = time.time()
        count += 1
        print(f"-> [{DB_FILE_PATH}] Finished for the {count}th ({(time_end - time_start)} seconds)")