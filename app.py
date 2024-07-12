from flask import Flask, render_template, request, jsonify
import subprocess
import traceback
import time
import ipaddress
import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)

# Scan type definitions
SCAN_TYPES = {
    'intense_scan': '-T4 -A -v',
    'ping_scan': '-sn',
    'quick_scan_plus': '-sV -T4 -O -F --version-light',
    'regular_scan': '',
    'slow_scan': '-sS -sU -T4 -A -v -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script "default or (discovery and safe)"',
    'quick_scan': '-T4 -F',
    'tcp_connect_scan': '-sT',
    'syn_scan': '-sS',
    'udp_scan': '-sU',
    'ack_scan': '-sA',
    'window_scan': '-sW',
    'xmas_scan': '-sX',
    'null_scan': '-sN',
    'idle_scan': '-sI',
    'ip_protocol_scan': '-sO',
    'service_version_scan': '-sV',
    'default_script_scan': '-sC',
    'os_detection_scan': '-O',
    'trace_route_scan': '--traceroute',
    'list_scan': '-sL',
    'dns_scan': '-sS -p 53',
    'fragmentation_scan': '-f',
    'ipv6_scan': '-6',
    'min_rate': '--min-rate <num>',
    'max_rate': '--max-rate <num>'
}

def run_nmap_scan(ip_address, scan_types):
    try:
        command = ["nmap"]

        # Append selected scan types to the command
        for scan_type in scan_types:
            if scan_type in SCAN_TYPES:
                command.append(SCAN_TYPES[scan_type])

        command.append(ip_address)

        app.logger.info(f"Running command: {' '.join(command)}")

        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Set a timeout of 60 seconds
        timeout = 60
        start_time = time.time()
        while process.poll() is None:
            if time.time() - start_time > timeout:
                process.kill()
                app.logger.error(f"Process killed due to timeout for IP: {ip_address}")
                return {"error": "Nmap scan timed out after 60 seconds"}
            time.sleep(0.1)

        output, error = process.communicate()

        if process.returncode != 0:
            app.logger.error(f"Nmap command failed with return code {process.returncode}. Error: {error}")
            return {"error": f"Nmap command failed with return code {process.returncode}. Error: {error}"}
        if not output.strip():
            app.logger.error("No output from nmap command")
            return {"error": "No output from nmap command"}

        app.logger.info(f"Nmap scan completed successfully for IP: {ip_address}")
        return {"result": output}
    except subprocess.SubprocessError as e:
        app.logger.error(f"Subprocess error: {str(e)}")
        app.logger.error(traceback.format_exc())
        return {"error": f"A subprocess error occurred: {str(e)}"}
    except Exception as e:
        app.logger.error(f"Exception occurred: {str(e)}")
        app.logger.error(traceback.format_exc())
        return {"error": f"An unexpected error occurred: {str(e)}"}

@app.route('/')
def index():
    return render_template('index.html', scan_types=SCAN_TYPES)

@app.route('/scan', methods=['POST'])
def scan():
    data = request.json
    ip_address = data.get('ip_address')
    scan_types = data.get('scan_types', [])

    try:
        ipaddress.ip_address(ip_address)
    except ValueError:
        app.logger.error(f"Invalid IP address: {ip_address}")
        return jsonify({"error": "Invalid IP address"}), 400

    if not scan_types:
        app.logger.error("No scan types selected")
        return jsonify({"error": "No scan types selected"}), 400

    app.logger.info(f"Received scan request for IP: {ip_address}, Types: {scan_types}")

    results = run_nmap_scan(ip_address, scan_types)
    return jsonify(results)

if __name__ == '__main__':
    app.run(debug=True)
