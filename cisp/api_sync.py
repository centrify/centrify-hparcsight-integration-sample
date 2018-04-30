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

import base64
import json
import requests
import sys
from cisp import event
from cisp import utils
from cisp.query_response import QueryResponse


def fetch_oauth_token(**kwargs):
    """
    This method fetches oauth access token by calling /oauth2/token/<app_id> Rest API
    """
    if 'tenant' not in kwargs or \
                    'oauth_app_id' not in kwargs or \
                    'scope' not in kwargs or \
                    'siem_username' not in kwargs or \
                    'siem_password' not in kwargs:
        print("Some parameters are missing for fetch_oauth_token(). Please check.")
        sys.exit(1)
    try:
        endpoint = 'https://' + kwargs['tenant'] + "/oauth2/token/" + kwargs['oauth_app_id']
        data = {"grant_type": "client_credentials", "scope": kwargs['scope']}
        base64string = base64.b64encode(
                                          (kwargs['siem_username'] +
                                           ":" + kwargs['siem_password']
                                          ).encode()
                                        ).decode()
        header = {"Authorization": "Basic %s" % base64string}
        response = requests.post(endpoint,
                                     data = data,
                                     headers = header)
        if not response.status_code == requests.codes.ok:
            print('Fetching of oauth token failed')
            print('Response status code: ' + str(response.status_code)
                                    +", response.text: "+ response.text)
            sys.exit(1)
        else:
            print('Oauth access token fetched successfully')
        tokens = json.loads(response.text)
        access_token = tokens['access_token']
        return access_token
    except requests.exceptions.RequestException as exc:
        print(exc)
        sys.exit(1)


def query_events(**kwargs):
    """
    This method fetches events data by calling Redrock/query Rest API,
    returns an object of QueryResponse - created after parsing API call response
    """
    if 'tenant' not in kwargs or \
                    'access_token' not in kwargs or \
                    'query' not in kwargs:
        print("Some parameters are missing for query_events(). Please check.")
        sys.exit(1)
    try:
        #Fetching data for query
        endpoint = 'https://' + kwargs['tenant'] + '//Redrock/query'
        data = json.dumps({'Script': kwargs['query']})
        header = {"Authorization": "Bearer " + kwargs['access_token']}
        response = requests.post(endpoint,
                                    data = data,
                                    headers = header)
        if response.status_code == requests.codes.ok:
            print('Successfully fetched events for query')
            redrockquery_response = QueryResponse(response)
            if redrockquery_response.success:
                return redrockquery_response
            else:
                print("Unsuccessful call to Redrock/query API")
                print('Reponse.Message: ' + redrockquery_response.message +
                               '\nReponse.Exception: ' + redrockquery_response.exception)
                return None
        else:
            print("Failure upon Rest API call to Redrock/query")
            print('Response status code: '+ str(response.status_code)+ ' response.text: '+ response.text)
            return None
    except requests.exceptions.RequestException as exc:
        print(exc)
        sys.exit(1)


def cef_generator(query_response):
    """
    This method iterates through the events and yields CEF formatted messages
    """
    if not isinstance(query_response, QueryResponse):
        print("Expecting a parameter of type QueryResponse")
        sys.exit(1)
    try:
        headers = query_response.headers
        for event_row in query_response.events:
            e = event.Event()
            for header in headers:
                if event_row['Row'][header] is not None and str(event_row['Row'][header]).strip() != '':
                    e.properties[header] = str(event_row['Row'][header]).strip()
                # Extract epoch milliseconds from value in formatted "WhenOccurred":"\/Date(1514508438227)\/"
                # whenoccurred_epoch_ms is needed for mapping to Device Receipt Time of an event in CEF format
                if header.strip().lower() == 'whenoccurred':
                    e.properties['whenoccurred_epoch_ms'] = utils.get_millisecond_substr(event_row['Row'][header])
            e.create_cef()
            yield e.cef_message
    except Exception as exc:
        print(exc)
        sys.exit(1)



