#!/usr/bin/env python3
import os
import os.path
import re
import sys
import json
import requests
import datetime
import logging
from configparser import ConfigParser
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
from flask import Flask, request
from flask_restful import Resource, Api

debug = True

CONFIG_FILENAME = "~/aci/.aci.conf"

app = Flask(__name__)
api = Api(app)

# handler = logging.StreamHandler(sys.stdout)
# handler.setFormatter(logging.Formatter(
#     '%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
#app.logger.addHandler(handler)
app.logger.setLevel(logging.DEBUG)

base_url = ""
# cookies = ""
# tenant = ""

def authenticate(username, password):
	# create credentials structure
	name_pwd = {'aaaUser': {'attributes': {'name': username, 'pwd': password}}}
	json_credentials = json.dumps(name_pwd)

	# log in to API
	login_url = base_url + 'aaaLogin.json'
	post_response = requests.post(login_url, data=json_credentials, verify=False)

	# get token from login response structure
	auth = json.loads(post_response.text)
	login_attributes = auth['imdata'][0]['aaaLogin']['attributes']
	auth_token = login_attributes['token']
	cookies = {}
	cookies['APIC-Cookie'] = auth_token

	return cookies

def get_eps(cookies):
	get_eps_url = base_url + "/class/fvCEp.json"
	get_response = requests.get(get_eps_url, cookies=cookies, verify=False)
	parsed = json.loads(get_response.text)
	return parsed

def find_ep(eps, ip):
	for ep_obj in eps['imdata']:
		for attr_k, attr_v in ep_obj['fvCEp'].items():
			if attr_v['ip'] == ip:
				return attr_v

def get_epg(dn_tenant,dn_app,dn_epg,cookies):
	get_epg_url = base_url + "/node/mo/uni/" + dn_tenant + "/" + dn_app + "/" + dn_epg + ".json?query-target=children&subscription=no"
	get_response = requests.get(get_epg_url, cookies=cookies, verify=False)
	parsed = json.loads(get_response.text)
	return parsed

def create_node_attr(tDn):
	tDn_list = tDn.split("/")
	pod = tDn_list[1]
	node_list = tDn_list[2].split("-")[1:]
	node_attr_str = ""
	for node in node_list:
		node_attr_str += '{"fvRsNodeAtt":{"attributes":{"instrImedcy":"immediate","mode":"regular","tDn":"topology/' + pod + '/node-' + node + '"}}},'
	if node_attr_str:
		node_attr_str = node_attr_str[:-1]
	return node_attr_str
	

def create_uepg(uepg_config_dic,cookies):
	json_uepg = ('{"fvAEPg":{"attributes":{"dn":"' +
			uepg_config_dic['DNPATH'] + '","floodOnEncap":"disabled","isAttrBasedEPg":"yes","matchT":"AtleastOne","name":"' +
			uepg_config_dic['MICROEPGNAME'] + '","pcEnfPref":"unenforced","prefGrMemb":"exclude","prio":"unspecified"},"children":[' +
			uepg_config_dic['NODEATTR'] + ',{"fvRsDomAtt":{"attributes":{"resImedcy":"immediate","tDn":"' +
			uepg_config_dic['DOMAINNAME'] + '"}}},{"fvRsBd":{"attributes":{"tnFvBDName":"' +
			uepg_config_dic['BRIDGEDOMAIN'] + '"}}},{"fvCrtrn":{"attributes":{"descr":"","match":"any","name":"default","nameAlias":"","ownerKey":"","ownerTag":"","prec":"0"},"children":[{"fvMacAttr":{"attributes":{"mac":"' +
			uepg_config_dic['MACADDR'] + ',"name":"' +
			uepg_config_dic['MACADDR'] + '"",}}}]}}]}}' )

	uepg_url = base_url + "/mo/uni.json"
	post_response = requests.post(uepg_url, data=json_uepg, cookies=cookies, verify=False)
	return post_response


def quarantine_ip(target_ip):
	cookies = authenticate(username,password)
	app.logger.debug(cookies)
	eps = get_eps(cookies)
	ep_attr_v = find_ep(eps, target_ip)
	if not ep_attr_v:
		return "IP not found!"
	dn_list = ep_attr_v['dn'].split("/")
	dn_tenant = dn_list[1]
	dn_app = dn_list[2]
	dn_epg = dn_list[3]
	epg_config = get_epg(dn_tenant,dn_app,dn_epg,cookies)
	currentDT = datetime.datetime.now()	
	uepg_config_dic['MICROEPGNAME'] = "q-uepg-" + currentDT.strftime("%y%m%d%H%M%S")
	uepg_config_dic['BRIDGEDOMAIN'] = epg_config['imdata'][0]['fvRsBd']['attributes']['tnFvBDName']
	uepg_config_dic['MACADDR'] = ep_attr_v['mac']
	uepg_config_dic['DNPATH'] = "uni/" + dn_tenant + "/" + dn_app + "/epg-" + uepg_config_dic['MICROEPGNAME']
	uepg_config_dic['DOMAINNAME'] =  epg_config['imdata'][3]['fvRsDomAtt']['attributes']['tDn']
	uepg_config_dic['NODEATTR'] = create_node_attr(epg_config['imdata'][4]['fvRsPathAtt']['attributes']['tDn'])
	response = create_uepg(uepg_config_dic,cookies)
	return response.status_code


class ACIMicroEPG(Resource):
	def get(self,ip_address):
		return ip_address
	# do get something

	def put(self):
		pass
	# do put something

	def delete(self):
		pass
	# do delete something

	def post(self,ip_address):
		response = quarantine_ip(ip_address)
		return response
		# try:
		# 	response = quarantine_ip(ip_address)
		# 	return response
		# except Exception as e:
		# 	print(e)
				

api.add_resource(ACIMicroEPG, '/api/uepg/<string:ip_address>')

if __name__ == '__main__':
	secureConnection = True
	cfgparser = ConfigParser()
	try:
		cfgparser.read(os.path.expanduser(CONFIG_FILENAME))
	except:
		error("Can't parse configuration file {}"
			  "".format(os.path.expanduser(CONFIG_FILENAME)))
		sys.exit(1)
	if ('aci_config' not in cfgparser):
		error("Configuration file {} doesn't contain 'aci_config' section"
			"".format(os.path.expanduser(CONFIG_FILENAME)))
		sys.exit(1)
	elif (('user' not in cfgparser['aci_config']) or
		('pass' not in cfgparser['aci_config']) or
		('apic' not in cfgparser['aci_config'])):
		error("Config file doesn't contain (all) required authentication info")
		sys.exit(1)
	elif (('cert_path' not in cfgparser['aci_config']) or
		('key_path' not in cfgparser['aci_config'])):
		secureConnection = False
	
	config = cfgparser['aci_config']

	username = config["USER"]
	password = config["PASS"]
	apicAddr = config["APIC"]

	if secureConnection:
		cert_path = config["CERT_PATH"]
		key_path = config["KEY_PATH"]
	if 'PORT' in cfgparser['aci_config']:
		port = config["PORT"]
	else:
		port = 443 if secureConnection else 80

	base_url = "https://" + apicAddr + "/api/"
	uepg_config_dic = {
		"MICROEPGNAME" : "",
		"BRIDGEDOMAIN": "",
		"MACADDR": "",
		"DNPATH" : "",
		"DOMAINNAME": "",
		"NODEATTR" : ""
	}
	try:
		if secureConnection:
			app.logger.debug("Certificate and Key file are found. Starting the app with https! on port %s", port)
			context = (os.path.expanduser(cert_path),os.path.expanduser(key_path))
			app.run(debug=debug, host='0.0.0.0', ssl_context=context, port=port)
		else:
			app.logger.debug("Certificate and Key file are not found. Starting theStart app with http! %s", port)
			app.run(debug=debug, host='0.0.0.0', port=port)
	except Exception as e:
		print("Could not start Flask APP!.")
		print(e)