This script talks to the LibreNMS API to receive a list of down devices and alerts. The LibreNMS dashboard provides widgets for alerts and host statusses, but there is no easy way to access that output via the API. Using Python I was able to get certain information and output it as HTML or text using PrettyTable. It can be included in other systems or be used in a chain of monitoring customizations. 

### Installation

On Ubuntu you need to install `prettytable` and python:

	apt-get install python-prettytable python

### Usage

Add your API token in the script and change the API URL:

	auth_token = ""
	api_url = "https://example.org/librenms/api/v0/"

Run the script:

	python ./open_alerts.py

Text output example:

	Devices Down: (1): 
	+-----------------------+---------------------+---------------------+-----------------+
	|        Hostname       |    Notes            |      Down since     |      Location   |
	+-----------------------+---------------------+---------------------+-----------------+
	| rtr-4g-01.example.org | 4G Router Groningen | 2018-08-03 14:21:18 |      Groningen  |
	+-----------------------+---------------------+---------------------+-----------------+

	Critical alerts (3):
	+-----------------------+-----------------------+----------------------------------------+-----------------------------+
	|        Hostname       |       Alert rule      |               OS Version               |           Location          |
	+-----------------------+-----------------------+----------------------------------------+-----------------------------+
	|  server1.example.org  | State Sensor Critical |      Server 2008 R2 SP1 (NT 6.1)       |        Papendrecht          |
	|  server2.example.org  | State Sensor Critical | Server 2008 Datacenter R2 SP1 (NT 6.1) |        Benthuizen           |
	|  server3.example.org  |    Disk used > 95%    |          3.0.76-0.11-default           |        Papendrecht          |
	+-----------------------+-----------------------+----------------------------------------+-----------------------------+

	Warning alerts (4):
	+--------------------------+-----------------+-----------------------------+-----------------------------+
	|         Hostname         |    Alert rule   |          OS Version         |        Location             |
	+--------------------------+-----------------+-----------------------------+-----------------------------+
	|    server5.example.org   | Disk used > 85% |   Server 2012 R2 (NT 6.3)   |        Papendrecht          |
	|    server6.example.org   | Disk used > 85% | Server 2008 R2 SP1 (NT 6.1) |        Papendrecht          |
	|    server7.example.org   | Disk used > 85% |      4.4.0-121-generic      |        Middenmeer           |
	|    server8.example.org   | Disk used > 85% |   Server 2012 R2 (NT 6.3)   |        Papendrecht          |
	+--------------------------+-----------------+-----------------------------+-----------------------------+

HTML Example:

<img src="https://raymii.org/s/inc/img/librenms_api.png" />

### License

GNU GPLv2

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.	