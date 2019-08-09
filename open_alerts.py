#!/usr/bin/python
# Author: Remy van Elst (https://raymii.org)
# License: GNU GPLv2
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import requests
import re
from prettytable import PrettyTable

auth_token = ""
api_url = "https://example.org/librenms/api/v0/"

request_headers = {
	"Accept-Language": "en-US,en;q=0.5",
	"User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0",
	"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
	"X-Auth-Token": auth_token,
	"Connection": "keep-alive" 
}

def is_ipv4(ip):
    pieces = ip.split('.')
    if len(pieces) != 4: return False
    try: return all(0<=int(p)<256 for p in pieces)
    except ValueError: return False

class LibreNMSAPI(object):
	"""Mapping for certain LibreNMS API endpoints
	https://github.com/librenms/librenms/tree/master/doc/API
	"""
	def __init__(self, auth_token=auth_token, request_headers=request_headers, api_url=api_url):
		super(LibreNMSAPI, self).__init__()
		self.api_url = api_url
		self.headers = request_headers
		self.auth_token = auth_token

	def get_alert_rule(self,rule_id):
		req = self.api_url + "rules/" + str(rule_id)
		return requests.get(req, headers=self.headers).json()["rules"][0]

	def get_alert(self, alert_id):
		req = self.api_url + "alert/" + str(alert_id)
		return requests.get(req, headers=self.headers).json()

	def list_alerts(self, state="ALL"):
		if state == "ALL":
			req = self.api_url + "alerts"
		else:
			req = self.api_url + "alerts?state=" + state
		return requests.get(req, headers=self.headers).json()

	def get_device(self, device_id):
		req = self.api_url + "devices/" + str(device_id)
		return requests.get(req, headers=self.headers).json()["devices"][0]

	def list_devices(self):
		req = self.api_url + "devices"
		return requests.get(req, headers=self.headers).json()["devices"]

	def translate_device_ip_to_sysname(self, device):
		"""If hostname is an IPv4, return the sysname, 
		that might be more descriptive"""
		hostname = device["hostname"]
		if is_ipv4(hostname):
			return device["sysName"]
		return device["hostname"]

librenms_api = LibreNMSAPI(auth_token=auth_token, request_headers=request_headers, api_url=api_url)
alerts = librenms_api.list_alerts()
devices = librenms_api.list_devices()

icmp_down_devices = PrettyTable()
icmp_down_devices.field_names = ["Hostname", "Notes", "Down since", "Location"]
critical_alerts = PrettyTable()
critical_alerts.field_names = ["Hostname", "Alert rule", "OS Version", "Location"]
warning_alerts = PrettyTable()
warning_alerts.field_names = ["Hostname", "Alert rule", "OS Version", "Location"]

for device in devices:
	if device["status_reason"] == "icmp":
		if device["ignore"] == 0 or device["disabled"] == 0:
			device_down_since = device["last_ping"]
			device_location = re.sub(r'\[.*\]', '', device["location"]) # remove gps coords
			device_hostname = librenms_api.translate_device_ip_to_sysname(device)
			device_purpose = device["purpose"].rstrip()
			icmp_down_devices.add_row([device_hostname, device_purpose, device_down_since, device_location])

for alert in alerts["alerts"]:
	alert_rule = librenms_api.get_alert_rule(alert["rule_id"])
	device = librenms_api.get_device(alert["device_id"])
	device_status = device["status"]
	device_status_reason = device["status_reason"]
	device_hostname = librenms_api.translate_device_ip_to_sysname(device)
	device_location = re.sub(r'\[.*\]', '', device["location"]) # remove gps coords
	alert_severity = alert["severity"]

	## devices that are down due to ping (not snmp timeout, snmp is flaky for down detection)
	if not device_status_reason == "icmp":
		if alert_severity == "warning":
			warning_alerts.add_row([device_hostname, alert_rule["name"], device["version"], device_location])
		if alert_severity == "critical":
			critical_alerts.add_row([device_hostname, alert_rule["name"], device["version"], device_location])

print("<h2>Devices Down: ({0})</h2> ".format(icmp_down_devices.rowcount))
if icmp_down_devices.rowcount > 0:
	print(icmp_down_devices.get_html_string(attributes={"border":"1"}))

print("<h2>Critical alerts: ({0})</h2>".format(critical_alerts.rowcount))
if critical_alerts.rowcount > 0:
	print(critical_alerts.get_html_string(attributes={"border":"1"}))

print("<h2>Warning alerts: ({0}) </h2>".format(warning_alerts.rowcount))
if warning_alerts.rowcount > 0:
	print(warning_alerts.get_html_string(attributes={"border":"1"}))