from flask import Flask, redirect, render_template, request, send_file, url_for, jsonify  
import requests
import subprocess
import threading
from datetime import datetime
import os
import time
import re
from scapy.all import *
import json
from matplotlib import pyplot as plt
from PIL import Image, ImageDraw, ImageFont
import ipaddress
import math

# Define global variables for packets_per_file and packets_per_connection
packets_per_file = '100'  # Example default value
packets_per_connection = '5'  # Example default value
duration_seconds = '60'  # Default value, which is 60 seconds or 1 minute

app = Flask(__name__)


@app.route('/')
def home():
    return render_template('home.html')

@app.route('/analizerConf')
def analizerConf():    
    ips_warn, dates_warn = create_wanings_ips_list()
    
    if not ips_warn:
        ips_default=None
    else:
        ips_default=ips_warn[0]
        
    ips_b, dates_b = create_block_ips_list()
    
    if not ips_warn:
        ips_default_b=None
    else:
        ips_default_b=ips_warn[0]
    
    return render_template('analizer.html', ips=ips_warn, dates=dates_warn, ips_default=ips_default,ips_default_b=ips_default_b, ips_b=ips_b, dates_b=dates_b )

ip_info_b= None
ip_info_warn= None

@app.route('/show_ip_info', methods=['POST'])
def show_ip_info():
    global ip_info_warn
    if request.method == 'POST':
        ip_to_check = request.form.get('ipInfo')
        print(f'test ip: {ip_to_check}')
        #ip_to_check = "51.89.64.33"
        ip_info= get_ip_location(ip_to_check)
        ip_info_warn=ip_info
        return render_template('analizer.html', ips=ips_warn, dates=dates_warn, ips_default=ip_to_check, ip_info=ip_info, ips_default_b=ips_b[0], ips_b=ips_b, dates_b=dates_b, ip_info_block=ip_info_b )

@app.route('/show_ip_info_blocked', methods=['POST'])
def show_ip_info_blocked():
    global ip_info_b
    if request.method == 'POST':
        ip_to_check = request.form.get('ipInfo_block')
        print(f'test ip: {ip_to_check}')
        #ip_to_check = "51.89.64.33"
        ip_info= get_ip_location(ip_to_check)
        ip_info_b = ip_info
        return render_template('analizer.html', ips_b=ips_b, dates_b=dates_b, ips_default_b=ip_to_check, ip_info_block=ip_info, ips=ips_warn, dates=dates_warn, ips_default=ips_warn[0], ip_info=ip_info_warn)
  
      
@app.route('/show_ip_info/block_ip', methods=['POST'])
def block_ip():
    ip_to_block = request.form.get('ipInfo')
    print(f'block ip {ip_to_block}')
    #ip_to_block="192.168.137.218"
    command = f'netsh advfirewall firewall add rule name="BLOCK IP ADDRESS - {ip_to_block}" dir=out action=block remoteip={ip_to_block}'
    print(command)
    try:
        result = subprocess.run(command, shell=True, check=True)
        #if "Aceptar" in result.stdout:
        print('command accepted')
        current_date = datetime.now()
        date = current_date.strftime("%d_%m_%Y")
        with open('block_list.txt', 'a') as file:
            file.write(f'{ip_to_block} - {date} \n')
    
        with open('warnings_list.txt', 'r') as file:
            lines = file.readlines()
        
        new_lines = [line for line in lines if not line.startswith(ip_to_block)]
        
        with open('warnings_list.txt', 'w') as file:
            file.writelines(new_lines)     
        print(f'if to block {ip_to_block}:_ {new_lines}')
              
        
    except:
        print('error executing command')    
    
    return redirect(url_for("analizerConf"))

@app.route('/show_ip_info/unblock_ip', methods=['POST'])
def unblock_ip():
    ip_to_block = request.form.get('ipInfo')
    print(f'block ip {ip_to_block}')
    #ip_to_block="192.168.137.218"
    command= f'netsh advfirewall firewall delete rule name="BLOCK IP ADDRESS - {ip_to_block}"'
    print(command)
    try:
        result = subprocess.run(command, shell=True, check=True)
        #if "Aceptar" in result.stdout:
        print('command accepted')        
        
        with open('block_list.txt', 'r') as file:
            lines = file.readlines()
        
        new_lines = [line for line in lines if not line.startswith(ip_to_block)]
        
        with open('block_list.txt', 'w') as file:
            file.writelines(new_lines)     
        print(f'if to block {ip_to_block}:_ {new_lines}')
              
        
    except:
        print('error executing command')    
    
    return redirect(url_for("analizerConf"))

@app.route('/start_sampling')
def start_sampling():
    packets_per_file = request.form.get('packets_per_file', '100')  # Default value if not set
    packets_per_connection = request.form.get('packets_per_connection', '5')  # Default value

    # Call the C program with the parameters provided by the user
    #subprocess.run(["./samp.exe", packets_per_file, packets_per_connection])

    # Make sure the indentation of the return statement is aligned with the block it is part of
    return render_template('sampler.html', confirmation_message="Sampling started successfully!")

def run_sampling(packets_per_file, packets_per_connection, duration_seconds):
    # Run your subprocess with the global variables
    subprocess.run(["./samp", packets_per_file, packets_per_connection, duration_seconds])

@app.route('/start_sampling/start', methods=['GET', 'POST'])
def start():
    global packets_per_file, packets_per_connection
    if request.method == 'POST':
        # If form data is sent, update the global variables
        packets_per_file = request.form.get('packets_per_file', '100')  # Default value if not set
        packets_per_connection = request.form.get('packets_per_connection', '5')  # Default value
        duration_seconds = request.form.get('duration', '60')  # Get the duration from the form
        # Start the sampling process in a new thread
        
        # Start the sampling process in a new thread
        thread = threading.Thread(target=run_sampling, args=(packets_per_file, packets_per_connection, duration_seconds))
        thread.start()

        # Return a response to the user
        return render_template('sampler.html', message="Sampling started")

    # If it's a GET request, just render the form
    return render_template('sampler.html')

@app.route('/analyze_folder', methods=['GET', 'POST'])
def analyze_folder():
    current_directory = os.getcwd()
    if request.method == 'POST':
        selected_folder = request.form['folder']        
        base_directory = os.path.join(current_directory, 'sampling')

        # Construct the full path
        #base_directory = r'\sampling'
        full_path = os.path.join(base_directory, selected_folder)

        # Call analyser.py with the full path
        subprocess.run(['python', 'analyser.py', full_path])
        time.sleep(6)
        # Read log files
        #log_base_directory = r'\analyzed'
        log_base_directory = os.path.join(current_directory, 'analyzed')
        miner_log_path = os.path.join(log_base_directory, 'miner_connection.log')
        warning_log_path = os.path.join(log_base_directory, 'warning_connection.log')

        # Read log files
        with open(miner_log_path, 'r') as file:
            miner_log = file.read()

        with open(warning_log_path, 'r') as file:
            warning_log = file.read()

        return render_template('pcapanalyse.html', miner_log=miner_log, warning_log=warning_log)
    
    # Populate folders for dropdown
    sampling_directory = os.path.join(current_directory, 'sampling')
    folders = os.listdir(sampling_directory)
    #folders = os.listdir(r'C:\Users\Andreas\Desktop\tmaproject\sampling')
    return render_template('pcapanalyse.html', folders=folders)

def parse_log(log_path, warning=False):
    connections = []
    with open(log_path, 'r') as file:
        for line in file:
            if warning:
                match = re.search(r'External IP: (\S+), Other IP: (\S+)', line)
                if match:
                    connections.append({'external_ip': match.group(1), 'other_ip': match.group(2)})
            else:
                match = re.search(r'Miner detected! Source IP: (\S+), Destination IP: (\S+)', line)
                if match:
                    connections.append({'source_ip': match.group(1), 'destination_ip': match.group(2)})
    return connections

@app.route('/connection_analysis')
def connection_analysis():
    current_directory = os.getcwd()
    miner_log_path = os.path.join(current_directory, 'analyzed/miner_connection.log')
    warning_log_path = os.path.join(current_directory, 'analyzed/warning_connection.log')

    miner_connections = parse_log(miner_log_path)
    warning_connections = parse_log(warning_log_path, warning=True)

    our_network_ips = extract_unique_ips(miner_connections + warning_connections, '192.168.1.0/24')

    return render_template('track.html', miner_connections=miner_connections, warning_connections=warning_connections, our_network_ips=our_network_ips)

def extract_unique_ips(connections, network_range):
    network = ipaddress.ip_network(network_range)
    unique_ips = set()
    for connection in connections:
        source_ip = connection.get('source_ip') or connection.get('external_ip')
        destination_ip = connection.get('destination_ip') or connection.get('other_ip')
        if source_ip and ipaddress.ip_address(source_ip) in network:
            unique_ips.add(source_ip)
        if destination_ip and ipaddress.ip_address(destination_ip) in network:
            unique_ips.add(destination_ip)
    return list(unique_ips)


@app.route('/track_single_ip', methods=['POST'])
def track_single_ip():
    ip = request.form['ip']
    # Call ./track with the IP
    subprocess.run(['./track', ip], shell=True)
    return jsonify({"message": "Tracking started for IP: {}".format(ip)})

@app.route('/track_connection', methods=['POST'])
def track_connection():
    ip1 = request.form['ip1']
    ip2 = request.form['ip2']
    # Call evaluation.exe with the IPs
    subprocess.run(['./eval', ip1, ip2], shell=True)
    return jsonify({"message": "Tracking started for IPs: {} and {}".format(ip1, ip2)})




#create list of ips from warnings file to display in html page
def create_wanings_ips_list():
    global ips_warn, dates_warn
    with open('warnings_list.txt', 'r') as file:
        content = file.readlines()      
          
    ips_warn = []
    dates_warn = []
    
    # Loop through each line and extract IPs and dates
    for line in content[1:]:  # Skip the header line
        parts = line.strip().split(' - ')
        ip = parts[0]
        date = parts[1]
    
        # Append to the respective lists
        ips_warn.append(ip)
        dates_warn.append(date)
    
    return ips_warn, dates_warn

def create_block_ips_list():
    global ips_b, dates_b
    with open('block_list.txt', 'r') as file:
        content = file.readlines()      
          
    ips_b = []
    dates_b = []
    
    # Loop through each line and extract IPs and dates
    for line in content[1:]:  # Skip the header line
        parts = line.strip().split(' - ')
        ip = parts[0]
        date = parts[1]
    
        # Append to the respective lists
        ips_b.append(ip)
        dates_b.append(date)
    
    return ips_b, dates_b

def get_ip_location(ip_address):
    # Make a request to the ipinfo.io API for location information
    location_response = requests.get(f"https://ipinfo.io/{ip_address}")
    
    # Check if the request for location information was successful (status code 200)
    if location_response.status_code == 200:
        location_data = location_response.json()
        # Extract relevant location information from the response
        ip = location_data.get("ip", "N/A")
        city = location_data.get("city", "N/A")
        region = location_data.get("region", "N/A")
        country = location_data.get("country", "N/A")
        location = location_data.get("loc", "N/A")
        
        # Print the location information
        # print(f"IP: {ip}")
        # print(f"City: {city}")
        # print(f"Region: {region}")
        # print(f"Country: {country}")
        # print(f"Location: {location}")        
        
    else:
        #print(f"Error: Unable to retrieve location information for IP {ip_address}")
        ip_info = {
            'IP': f"Error: Unable to retrieve location information for IP {ip_address}",
            'City': f"Error: Unable to retrieve location information for IP {ip_address}",
            'Region': f"Error: Unable to retrieve location information for IP {ip_address}",
            'Country': f"Error: Unable to retrieve location information for IP {ip_address}",
            'Location': f"Error: Unable to retrieve location information for IP {ip_address}",
            'Host Name': f"Error: Unable to retrieve location information for IP {ip_address}"
        }
        
        return ip_info
        

    # Make a request to the ipinfo.io API for host name information
    host_response = requests.get(f"https://ipinfo.io/{ip_address}/json")
    
    # Check if the request for host name information was successful (status code 200)
    if host_response.status_code == 200:
        host_data = host_response.json()
        # Extract relevant host name information from the response
        host_name = host_data.get("hostname", "N/A")
        
        # Print the host name information
        #print(f"Host Name: {host_name}")
    else:
        #print(f"Error: Unable to retrieve host name information for IP {ip_address}")
        host_name=f"Error: Unable to retrieve host name information for IP {ip_address}"
        
    ip_info = {
        'IP': ip,
        'City': city,
        'Region': region,
        'Country': country,
        'Location': location,
        'Host Name': host_name
    }
    
    return ip_info

############################################################################################################ Last Update
@app.route('/plotsMenu', methods=['POST','GET'])
def plotsMenu():  
    current_directory = os.getcwd()
    miner_log_path = os.path.join(current_directory, 'analyzed\miner_connection.log')
    ips_plot_parsed = parse_log(miner_log_path)
    
   
    folder_path = os.path.join(current_directory, 'tracking')

    # Get the list of files in the folder
    file_list = [file for file in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, file))]

    # Print the list of files
    #print("List of files in the folder:")
    file_list_parsed=[]
    for file in file_list:
        file_name, file_extension = os.path.splitext(file)
        file_list_parsed.append(file_name)
        #print(file_name)    
    
    
    return render_template('monitoring.html',monitor_files= file_list_parsed )





@app.route('/plotsMenu/showPlots', methods=['POST'])
def showPlots():  
    name= request.form.get('plot_ip')
    input_pcap = f"tracking/{name}.pcap"
    ip_parts = name.split('_')
    ip1 = ip_parts[0]
    ip2 = ip_parts[1]
    #Select ip from  your network (in theory ip2)
    ip_address = ip2

    packets_list = filter_and_display_psh_payload(input_pcap, ip_address)
    nonces_dict = extract_nonces_from_packets(packets_list)

    # Print the nonces for each job_id
    for job_id, nonces in nonces_dict.items():
        #print(f"Job ID: {job_id}, Nonces: {nonces}")
        write_hex_list_to_file(f'plottings_data/{name}_nonce.txt', nonces)

    plt.style.use('fivethirtyeight')

    hash = []
    file_path=f'plottings_data/{name}_nonce.txt'
    hashCalculator(hash,file_path)

    clearHash(hash)
    plot_comp=comparisionGPU(sum(hash)/len(hash),name)
    plot_hash=plotGraphic(hash,name)
    
    # Read pcap and get timestamps and lengths
    timestamps, lengths = read_pcap(input_pcap, ip_address)
    band = bandwidth_calculation(timestamps, lengths)
    clear_band(band)
    plot_band = plot_usage(band,name)
    
    #graphics updated    
    tosend = sum(hash)/len(hash)
    with open(f"plottings_data/{name}hashratecalculation.txt", 'w') as f:
        f.write(f"{tosend}")
    
    
    circle_radius = 150
    with open(f"plottings_data/{name}hashratecalculation.txt", 'r') as f:
        hashrate = f.readline()
    hashrate = float(hashrate)
    number_to_display = power_calculation(hashrate)
    output_image_path = f"plots/{name}_power.png"

    plot_power=draw_circle_with_number(circle_radius, number_to_display, output_image_path)

    
    
    
    
    plots=[]
    plots.append(plot_comp)
    plots.append(plot_hash)
    plots.append(plot_band)
    plots.append(plot_power)
    
    return render_template('plotings.html', ips=name, plots=plots)

@app.route('/get_image')
def get_image():
    image = request.args.get('image')
    print(f'get image:::: {image}')
    
    
    return send_file(image,mimetype='image/png',as_attachment=False)

def filter_and_display_psh_payload(input_pcap, ip_address):
    packets = rdpcap(input_pcap)
    data = []

    for packet in packets:
        if IP in packet and TCP in packet:
            if ip_address in (packet[IP].src, packet[IP].dst) and packet[TCP].flags & 0x08:  # check push flag
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                payload = packet[TCP].payload.load.decode('utf-8', 'ignore')
                # print(f"Source IP: {src_ip}, Destination IP: {dst_ip}")
                # print(f"Payload (TCP data): {payload}")
                # print("-" * 30)
                data.append(packet)
                
    return data

def extract_nonces_from_packets(packets_list):
    nonces_dict = {}

    for i in range(len(packets_list)-1):
        packet = packets_list[i]

        if TCP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            payload = packet[TCP].payload.load.decode('utf-8', 'ignore')

            if payload and ("nonce" in payload and "job_id" in payload):
                # print(f"Miner detected! Source IP: {src_ip}, Destination IP: {dst_ip}")
                # print(f"Payload: {payload}")
                payload_json = json.loads(payload)

                nonce = payload_json["params"]["nonce"]
                job_id = payload_json["params"]["job_id"]

                # print(f"Nonce: {nonce}, Job ID: {job_id}")
                # print("-" * 30)

                # Check if job_id already exists in the dictionary
                if job_id in nonces_dict:
                    nonces_dict[job_id].append(nonce)
                else:
                    nonces_dict[job_id] = [nonce]

                # Check if the next packet exists and contains the same job_id
                next_packet = packets_list[i+1]
                if TCP in next_packet:
                    next_payload = next_packet[TCP].payload.load.decode('utf-8', 'ignore')

                    if next_payload and ("nonce" in next_payload and "job_id" in next_payload):
                        next_payload_json = json.loads(next_payload)
                        next_job_id = next_payload_json["params"]["job_id"]

                        # If the job_id in the next packet is the same, save its nonce
                        if next_job_id == job_id:
                            next_nonce = next_payload_json["params"]["nonce"]
                            nonces_dict[job_id].append(next_nonce)

    return nonces_dict   

# Writing a list of hexadecimal integers to a file
def write_hex_list_to_file(file_path, hex_integer_list):
    with open(file_path, 'a') as file:
        file.write('\n'.join(hex_integer_list) + '\n---\n')
        
##### Graphics.py
# Reading multiple lists of hexadecimal integers from a file
def read_hex_lists_from_file(file_path):
    with open(file_path, 'r') as file:
        content = file.read().split('---')
        hex_integer_lists = [
            [int(hex_string, 16) for hex_string in section.strip().split('\n')] for section in content if section.strip()
        ]
    return hex_integer_lists

# Estimating hash velocity
def hashCalculator(hash, file_path):
    all_nonces = read_hex_lists_from_file(file_path)

    for hexlist in all_nonces:
        average = 0.0
        if len(hexlist)<2:
            hash.append(hexlist[0]/500000.0)
        else:
            for i in range(len(hexlist)-1):
                average += (abs(hexlist[i+1]-hexlist[i])/500000.0)
            hash.append(average/(len(hexlist)-1))

def clearHash(hash):
    mean = sum(hash)/len(hash)

    removable = []

    for value in hash:
        if abs(value-mean)>5000:
            removable.append(value)
    
    for trash in removable:
        hash.remove(trash)
        
def comparisionGPU(mean,name):
    GPU = [1.4, 1.7, 3.8, 59, 67, 86, 260, 9000, 10700, 12500, 13000, 13000, 13000, 13000, 13300, 13500, 14000, 14500, 
       15000, 16000, 17000, 17000, 17500, 18000, 20000, 21000, 22000, 22000, 22000, 23000, 23000, 23500, 24000, 
       25000, 26500, 27000, 27600, 30000, 30000, 31500, 33000, 33000, 36500, 37000, 39000, 39500, 39500, 42000, 
       46500, 53000, 57000, 60000, 61000, 80000, 87000, 122000, 1650000, 3800000, 3800000, 6000000, 9000000]
    
    kilo = mega1 = mega2 = mega3 = mega4 = mega5 = mega6 = other = 0

    for number in GPU:
        if number <1000:
            kilo += 1
        if number<10000:
            mega1 += 1
        elif number<20000:
            mega2 += 1
        elif number<30000:
            mega3 += 1
        elif number<40000:
            mega4 += 1
        elif number<50000:
            mega5 += 1
        elif number<100000:
            mega6 += 1
        else:
            other += 1

    data = {'<1000':kilo, '<10000':mega1, '<20000':mega2, '<30000':mega3, '<40000':mega4, '<50000':mega5, '<100000':mega5, '>100000':other,}
    courses = list(data.keys())
    values = list(data.values())
  
  
 
    # creating the bar plot
    fig, ax = plt.subplots(figsize=(6.4, 4.8))  # Set the figure size to 640x480

    ax.bar(courses, values, color='blue', width=0.4)
    fig.autofmt_xdate()
    ax.set_xlabel("GPU rates")
    ax.plot('<1000', kilo, 'ro', label=f'Your hash rate: {math.trunc(mean)}')
    ax.legend()
    ax.set_ylabel("Quantity of GPU")

    plot_comp = f'plots/{name}_compare.png'
    plt.savefig(plot_comp, bbox_inches="tight")
    return plot_comp
    
def plotGraphic(hash,name):
    mean = sum(hash)/len(hash)    
    # Create the plot
    fig, ax = plt.subplots(figsize=(6.4, 4.8))  # Set the figure size to 640x480

    ax.plot(hash, 'o', label='Data Points')
    ax.axhline(y=mean, color='r', linestyle='-', label=f'Mean: {mean:.2f} h/s')

    ax.set_xlabel('Packages read')
    ax.set_ylabel('h/s')
    ax.set_title('Estimation of hash velocity')
    ax.legend()
    plt.tight_layout()

    plot_hash = f'plots/{name}_hash.png'
    plt.savefig(plot_hash, bbox_inches="tight")
    return plot_hash

#### bandwidth estimation
def read_pcap(file_path, target_ip):
    timestamps = []  # List to store timestamps
    lengths = []  # List to store packet lengths
    #print(f'path: {file_path}')
    packets = rdpcap(file_path)  # Read the pcap file

    for packet in packets:
        # Check if the packet has the target IP address
        if IP in packet and (packet[IP].src == target_ip or packet[IP].dst == target_ip):
            # Extract timestamp and length information
            timestamp = float(packet.time)
            length = len(packet)

            # Format the timestamp to display only seconds
            #timestamp_formated = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

            # Append the information to the lists
            timestamps.append(timestamp)
            lengths.append(length)

            # Print the information
            #print(f"Timestamp: {timestamp}, Length: {length} bytes")

    return timestamps, lengths

def bandwidth_calculation(timestamps, lengths):
    bandwidth = []

    for i in range(len(timestamps)):
        if i == 0:
            bandwidth.append(lengths[i]*8/timestamps[i])
        else:
            if timestamps[i]-timestamps[i-1] == 0 and i !=1 :
                bandwidth.append(lengths[i]*8/(timestamps[i]-timestamps[i-2])/1024)
            else:
                bandwidth.append(lengths[i]*8/(timestamps[i]-timestamps[i-1])/1024)
    
    return bandwidth

def clear_band(bandwidth):
    removable = []
    
    for value in bandwidth:
        if value>60:
            removable.append(value)
    
    for trash in removable:
        bandwidth.remove(trash)
        
def plot_usage(bandwidth,name):

    plt.plot(bandwidth, 'o', color ='g', label=f'Total bandwidth: {sum(bandwidth)}')
    plt.xlabel('Packages read')
    plt.ylabel('kb/s')
    plt.title('Estimation of bandwidth usage')
    plt.legend()
    plt.tight_layout()
    plot_band=f'plots/{name}_band.png'
    plt.savefig(plot_band)
    #plt.show()
    return plot_band

def power_calculation(hashrate):
    ratio = 11
    return math.trunc(hashrate * ratio /1000)

def draw_circle_with_number(radius, number, output_path, padding=10, circle_color=(150, 150, 255), image_size=[640, 480], title="Power consumption"):
    # Create a blank image with a white background
    image = Image.new("RGB", (image_size[0], image_size[1]), "white")
    draw = ImageDraw.Draw(image)

    # Add title at the top
    font_size_title = 40
    font_title = ImageFont.truetype("arial.ttf", font_size_title)
    ttitle = title
    title_bbox = draw.textbbox((0, 0), ttitle, font=font_title)
    title_width = title_bbox[2] - title_bbox[0]
    title_height = title_bbox[3] - title_bbox[1]
    title_position = ((image_size[0] - title_width) // 2, padding)
    draw.text(title_position, title, font=font_title, fill="black")  # Make the title more purple

    # Draw a circle with light purple color
    circle_bbox = [(image_size[0]/2-radius, image_size[1]/2-radius), (image_size[0]/2+radius, image_size[1]/2+radius)]
    draw.ellipse(circle_bbox, fill=circle_color, outline=circle_color, width=2)

    # Draw the number in the center of the circle
    font_size = 80
    font = ImageFont.truetype("arial.ttf", font_size)
    text = str(number)  + 'W'
    text_bbox = draw.textbbox((0, 0), text, font=font)
    text_width = text_bbox[2] - text_bbox[0]
    text_height = text_bbox[3] - text_bbox[1]
    text_position = [(image_size[0]/2 - text_width/2), (image_size[1]/2 - text_height)]
    draw.text(text_position, text, font=font, fill="black")

    # Save the image to a PNG file
    image.save(output_path, "PNG")
    
    return output_path

############################################################################################################ Last Update


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=4000, debug=True)
