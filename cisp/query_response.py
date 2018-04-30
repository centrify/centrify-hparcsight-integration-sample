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

import json


class QueryResponse:
    """ This class represents response of Redrock/query rest API call
    """
    def __init__(self, response):
        response_json = json.loads(response.text)
        self._events = response_json['Result']['Results']
        self._success = response_json['success']
        self._headers = []
        for column in response_json['Result']['Columns']:
            self._headers.append(column['Name'])

        if self._success == 'false':
            """ Below fields will be present only when success=false """
            self._message = response_json['message']
            self._exception = response_json['exception']

    @property
    def total_events(self):
        return len(self._events)

    @property
    def headers(self):
        return self._headers

    @property
    def success(self):
        return self._success

    @property
    def message(self):
        return self._message

    @property
    def exception(self):
        return self._exception

    @property
    def events(self):
        return self._events




