#!/usr/bin/python3
import requests, json, argparse, base64, sys, time, socket, yaml
from prettytable import PrettyTable
from prometheus_client import Gauge, start_http_server
from ping3 import ping

class Prometheus:
    def query(self, query):
        response = requests.get('http://localhost:9090/api/v1/query', params={'query': query})
        data = response.json()
        return data

    def icmp_ping(host):
        return ping(host)
    
    def check_ips_from_config(self, config, source):
        with open(config, 'r') as file:
            config = yaml.safe_load(file)

        if config['ip_status']['enabled']:
            targets = config['ip_status']['targets'][args.source]
            results = []
            for target in targets:
                result = Prometheus.icmp_ping(target)
                results.append((target, result))

            return results

    def print_icmp_table(self, results):
        print("-> ICMP Ping Results:")
        table = PrettyTable()
        table.field_names = ["STT", "IP", "Ping Result"]
        for i, result in enumerate(results, start=1):
            table.add_row([i] + list(result))
        print(table)

    def check_ports(self, servers, icmp=False):
        table = PrettyTable()
        ports = list(servers[0].values())[0]
        table.field_names = ["STT", "IP"] + [f"{label}/{port}" for port in ports for label in ["TCP", "Status"]]
        if icmp:
            table.field_names.append("Status/ICMP")
        table.align = "l"

        stt = 0
        for server in servers:
            for ip, ports in server.items():
                stt += 1
                row = [stt, ip]

                for port in ports:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((ip, int(port)))
                    if result == 0:
                        row.extend([port, "Open"])
                    else:
                        row.extend([port, "Closed"])
                    sock.close()

                if icmp:
                    icmp_result = "Open" if self.icmp_ping(ip) else "Closed"
                    row.append(icmp_result)

                table.add_row(row)

        print(table)

    def check_ports_from_config(self, config_file, ports, icmp=False):
        with open(config_file, 'r') as file:
            config = yaml.safe_load(file)

        if config['ip_status']['enabled']:
            servers = [{target: ports} for target in config['ip_status']['targets'][args.source]]
            self.check_ports(servers, icmp)

    def get_targets(self):
        response = requests.get('http://localhost:9090/api/v1/targets')
        data = response.json()
        table = PrettyTable()
        table.field_names = ["Endpoint", "Job", "Health", "Metrics_path", "Metrics_url"]

        for target in data['data']['activeTargets']:
            endpoint = target['labels']['instance']
            job = target['labels']['job']
            health = target['health']
            metrics_path = target['discoveredLabels']['__metrics_path__']
            metrics_url = target['scrapeUrl']
            table.add_row([endpoint, job, health, metrics_path, metrics_url])
        print(table)

    def print_table(self, data):
        if 'data' in data and 'result' in data['data'] and data['data']['result']:
            table = PrettyTable()
            first_result = data['data']['result'][0]
            table.field_names = list(first_result['metric'].keys()) + ['timestamp', 'value']
            for result in data['data']['result']:
                if 'value' in result:
                    table.add_row(list(result['metric'].values()) + [result['value'][0], result['value'][1]])
            print(table)
        else:
            print("-> The query does not exist or returned no results.")

    def print_metric(self, data):
        if 'data' in data and 'result' in data['data'] and data['data']['result']:
            for result in data['data']['result']:
                print(result['metric']['__name__'] + '{' + ', '.join([f'{k}="{v}"' for k, v in result['metric'].items() if k != '__name__']) + '} ' + result['value'][1])
        else:
            print("-> The query does not exist or returned no results.")

    def hex_to_text(self, hex_str):
        bytes_obj = bytes.fromhex(hex_str)
        text = bytes_obj.decode("utf-8")
        return text

    def run_metric(self):
        count = 0
        values = args.run_metric
        total_metric = len(values)
        time_start = time.time()
        exporter_port = 9999
        check_interval = 5
        metric = Gauge('demo_metric', 'Demo metric', ['alias'])

        class demo_metric:
            @staticmethod
            def rocket_cache():
                for i in range(total_metric):
                    metric.labels(alias=f'ceph-exporter-{i}').set(float(values[i]))

        start_http_server(exporter_port)

        while True:
            demo_metric.rocket_cache()
            time_end = time.time()
            count += 1
            print(f"-> Set values = {values}, finished {count} times in {time_end - time_start} seconds")
            time.sleep(check_interval)

    def encoded_password(self, password = sys.argv[1]):
        encoded_password = base64.b64encode(password.encode()).decode()
        print(f"Encoded password: {encoded_password}")

    def decoded_password(self, password = sys.argv[1]):
        decoded_password = base64.b64decode(password).decode()
        print(f"Decoded password: {decoded_password}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('-q', '--query', type=str, help='Query to execute, example: cli -q "ceph_osd_up"')
    parser.add_argument('-j', '--json', action='store_true', help='Output in JSON format, example: cli -j -q "ceph_osd_up"')
    parser.add_argument('-t', '--table', action='store_true', help='Output in table format, example: cli -t -q "ceph_osd_up"')
    parser.add_argument('-m', '--metric', action='store_true', help='Output in metric format, example: cli -m -q "ceph_osd_up"')
    parser.add_argument('-c', '--hextotext', type=str, help='Convert hex to text, example: cli -c "68656c6c6f20776f726c64"')
    parser.add_argument('-d', '--run_metric', type=str, nargs='+', help='Create demo metric, run with cli -d 1 0 80')
    parser.add_argument('-ep', '--encoded_password', type=str, help='Encode password, example: cli -ep "password"')
    parser.add_argument('-dp', '--decoded_password', type=str, help='Decode password, example: cli -dp "cGFzc3dvcmQ="')
    parser.add_argument("--config", help="Path to the configuration file")
    parser.add_argument('-P', '--ports', help="Comma-separated list of ports to check, example: cli --config config.cli.yml -P 80,22,443 -s physical_servers")
    parser.add_argument('--icmp', action='store_true', help='Perform ICMP ping, example: cli --config config.cli.yml --icmp -s physical_servers')
    parser.add_argument('-s', '--source', help='Source of targets to check, e.g., "physical_servers", example: cli --config config.cli.yml -P 80,22,443 -s physical_servers')

    args = parser.parse_args()
    if args.ports:
        ports = [int(port) for port in args.ports.split(',')]
    else:
        ports = []
    prometheus = Prometheus()

    if args.table:
        if args.query:
            data = prometheus.query(args.query)
            prometheus.print_table(data)
        else:
            prometheus.get_targets()
    elif args.metric:
        if args.query:
            data = prometheus.query(args.query)
            prometheus.print_metric(data)
    elif args.json:
        if args.query:
            data = prometheus.query(args.query)
            print(json.dumps(data, indent=4))
    elif args.hextotext:
        if args.hextotext:
            print(prometheus.hex_to_text(args.hextotext))
    elif args.encoded_password:
        prometheus.encoded_password(args.encoded_password)
    elif args.decoded_password:
        prometheus.decoded_password(args.decoded_password)
    elif args.run_metric:
        prometheus.run_metric()
    if args.config and args.ports:
        prometheus.check_ports_from_config(args.config, ports, args.icmp)
    elif args.config and args.icmp and args.source:
        results = prometheus.check_ips_from_config(args.config, args.source)
        prometheus.print_icmp_table(results)