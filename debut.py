#!/usr/bin/env python
# MIT License
# 
# Copyright (c) 2022 Sam Johnston <samj@samj.net>
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

import argparse
import json
import requests
import logging
import time

# parse arguments
parser = argparse.ArgumentParser()
#parser.add_argument("-a", "--address", help="device address")
parser.add_argument("address", help="device address")
parser.add_argument("-t", "--target", help="target address", default="bjn.vc")
group = parser.add_mutually_exclusive_group()
group.add_argument("-m", "--make_call", action="store_true")
group.add_argument("-d", "--drop_call", action="store_true")
parser.add_argument("-u", "--username", help="device username", default="admin")
parser.add_argument("-p", "--password", help="device password", default="")
parser.add_argument("-l", "--level", help="http.client debuglevel (e.g. 1)", type=int, default=1)
args = parser.parse_args()

url = "https://" + args.address

# set debug level
try:
    import http.client as http_client
except ImportError:
    # Python 2
    import httplib as http_client
http_client.HTTPConnection.debuglevel = args.level

# set up logging
logging.basicConfig()
logging.getLogger().setLevel(logging.DEBUG)
requests_log = logging.getLogger("requests.packages.urllib3")
requests_log.setLevel(logging.DEBUG)
requests_log.propagate = True

# suppress certificate warning
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# login
pload = {'loginSettings':{'userName':args.username,'password':args.password}}
r = requests.post(url + '/api/settings/login_web_ui', json=pload, verify = False)
cookie = json.loads(r.text)['cookie']
headers = {'Cookie': cookie}

# make call
pload = {"uri":args.target,"rate":2048,"display_name":args.target,"call_type":0}
r = requests.post(url + '/api/calls/make_call', json=pload, headers=headers, verify=False)

# wait
time.sleep(10)

# drop call
r = requests.delete(url + '/api/calls/drop_call', headers=headers, verify=False)
