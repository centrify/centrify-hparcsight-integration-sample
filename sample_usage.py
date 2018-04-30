# Copyright 2018 Centrify Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from cisp import api_sync
from input_configs import config

tenant = config['common']['tenant']
username = config['common']['siem_username']
password = config['common']['siem_password']

access_token = api_sync.fetch_oauth_token(tenant = tenant,
                                          oauth_app_id = 'oauthsiem',
                                          scope = 'siem',
                                          siem_username = username,
                                          siem_password = password)
if access_token is not None:
    # Fetch events for last 24 hours
    query = "Select * from Event where WhenOccurred > datefunc(\'now\', \'-1:00\')"
    query_response = api_sync.query_events(tenant = tenant,
                                           query = query,
                                           access_token = access_token)
    print('Total events: ' + str(query_response.total_events))
    print("CEF formatted event messages:")
    print('-' * 50)
    for cef_message in api_sync.cef_generator(query_response):
        print(cef_message)
        print('-' * 50)
