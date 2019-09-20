# panw-aci-docter

panw-aci-docter.py is a tool that allows Palo Alto Network Panorama to Dynamically Quarantine Infected Guests On Cisco ACI.

The workflow that panw-aci-docter will take to Dynamically Quarantine Infected Guests is:
1. Source machine initiate malicious traffic.
2. Palo Alto Networks NGFW detect the malicious activity.
3. Palo Alto Networks NGFW share logs with Panorama.
4. Panorama initiate API call via [HTTP profile](https://docs.paloaltonetworks.com/pan-os/9-0/pan-os-admin/monitoring/forward-logs-to-an-https-destination.html#) to the panw-aci-docter middleware. The API call from Panorama will include the IP address of the infected workload.
5. Using the IP address, The panw-aci-docter resolves all the relevant information from APIC (I.e. workload MAC address, tenant, app-profile, BD, etc), and move that workload to a new micro EPG. Using [MAC Address Filter](https://www.cisco.com/c/en/us/td/docs/switches/datacenter/aci/apic/sw/3-x/virtualization/b_ACI_Virtualization_Guide_3_0_1/b_ACI_Virtualization_Guide_3_0_1_chapter_0100.html) as selection attribute.
6. The infected workload will move to uEPG and it will be isolated.

Workflow Diagram:
![Workflow](https://raw.githubusercontent.com/mohanadelamin/panw-aci-doctor/master/images/workflow.png)

## Prerequisites

1. Python3
2. The following python modules (see requirements.txt)
	- requests
	- flask
	- flask_restful


## Installation

```
$ git clone https://github.com/mohanadelamin/panw-aci-doctor.git
$ cd panw-aci-doctor
$ pip3 install -r requirements.txt
```
    
## Configuration

### panw-aci-doctor machine configuration

1. In home directry create new folder with the name
	```
    $ mkdir ~/panw-aci-doctor
	```

2. Create new file named .doctor.config
	```
	$ vim .doctor.config
	```

3. Add the following to the .doctor.config file
	```
	[doctor_config]
	USER=
	PASS=
	APIC=
	CERT_PATH=
	KEY_PATH=
	PORT=
	DEBUG=
	```

4. Fill the config file above with the required information:
- **Mandatory fields** 
	USER: ACI APIC username
	PASS: ACI APIC password
	APIC= ACI APIC IP address
- **Optional fields**
	CERT_PATH: add the certificate file path if the connection from panorama need to be over SSL.
	KEY_PATH: add the key file path if the connection from panorama need to be over SSL.
	PORT: add the port in which panw-aci-doctor will listen. (Default is 80 or 443 if SSL is required)
	DEBUG: allowed values are "yes" or "no".

### Palo Alto Networks Panorama configuration

### Step 1: Configure HTTP profile on panorama to send API Calls to panw-aci-doctor
1. Select **Panorama** > **Server Profiles** > **HTTP** and **Add** a new HTTP Server Profile.
2. Enter a descriptive **Name**
3. Select **Add** to provide the details of panw-aci-doctor Manager.
4. Enter a **Name** for panw-aci-doctor.
5. Enter the **IP Address** of the pan-aci-doctor.
6. Select the **Protocol** (HTTP or HTTPS). The default Port is 80 or 443 respectively.
7. Select **POST** under the HTTP Method column.

Example:
![Example1](https://raw.githubusercontent.com/mohanadelamin/panw-aci-doctor/master/images/example1.png)

8. Select **Payload Format** and select the log type **Threat.**
9. Add a descriptive **Name**
10. In the **URI** section add "/api/uepg/$dst"
11. In the **Payload** section enter "Dummy"
12. Click **Ok**

Example:
![Example2](https://raw.githubusercontent.com/mohanadelamin/panw-aci-doctor/master/images/example2.png)

### Step 2: Define the match criteria for when Panorama will trigger the API call to panw-aci-doctor, and attach the HTTP profile.
1. Select **Panorama** > **Log Settings**. 
2. On the **Threat** section click **Add**
3. Add a descriptive **Name**
4. Click **Add** on the **HTTP** section
5. Select the HTTP profile.
6. Click **Ok**

Example:
![Example3](https://raw.githubusercontent.com/mohanadelamin/panw-aci-doctor/master/images/example3.png)


## Running

1. Login to the panw-aci-doctor machine
2. Run the script
```
$ python3 panw-aci-doctor.py
```


## Disclaimer

panw-aci-doctor is for illustrative purposes only. This software is supplied "AS IS" without any warranties and support.