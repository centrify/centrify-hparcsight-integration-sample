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

import socket
from cisp.cef_configs import cef_mappings
from cisp import utils

class Event:
    """ This class represents a CISP event
    """
    def __init__(self):
        self.cef_message = ''
        self.properties = {}
        self.properties['hostname'] = socket.getfqdn()

    def derive_event_category(self):
        # Extract EventCategory from EventType
        event_name = self.properties['EventType']
        # Extract event category from event name
        dots = event_name.count('.')
        if dots >= 2:
            last_dot = event_name.rfind('.')
            event_category = event_name[0:last_dot]
        else:
            event_category = event_name
        self.properties['EventCategory'] = event_category

    def derive_severity(self):
        if 'Level' in self.properties and self.properties['Level'].lower() == 'error':
            self.properties['severity'] = 10
        elif 'Level' in self.properties and self.properties['Level'].lower() == 'warning':
            self.properties['severity'] = 7
        else:  # Info
            self.properties['severity'] = 5

    def create_cef(self):
        self.derive_event_category()
        self.derive_severity()
        def get_key_string(section, key):
            # creates "key=value" string for a key using CEF mappings file section
            try:
                value = ''
                key_string = ''
                delimiter = ' '
                if cef_mappings.has_section(section):
                    if cef_mappings[section][key] is not None and len(cef_mappings[section][key].strip()) != 0:
                        if cef_mappings[section][key].startswith('$'):
                            if cef_mappings[section][key][1:] in self.properties:
                                value = self.properties[cef_mappings[section][key][1:]]
                        else:
                            customStringHasValue = False
                            customStringLabel = False
                            if len(key) == 8 and key[3:] == 'Label' and key[:2] == 'cs':
                                customStringLabel = True
                                # Check if corrosponding custom string has a value in event
                                if cef_mappings[section][key[:3]][1:] in self.properties:
                                    customStringHasValue = True
                            if not customStringLabel or (customStringLabel and customStringHasValue):
                                value = cef_mappings[section][key]
                    if value != '':
                        if '=' in str(value):
                            value = str(value).replace('=','\=')  
                        if section == 'header':
                            key_string += str(value) + '|'
                        else:
                            key_string += key + '=' + str(value) + delimiter
                return key_string
            except Exception as exc:
                print("Problem while including value for key \'" + key + '\' of section \''+section + '\' to the payload')
                raise exc
        try:
            self.cef_message = 'CEF:'
            event_name = self.properties['EventType']
            sections = ['header', 'common', event_name] # the sequence is important
            for section in sections:
                if cef_mappings.has_section(section):
                    for key in cef_mappings[section]:
                        if not (section == 'common' and \
                                      (cef_mappings.has_section(event_name) and
                                               key in cef_mappings[event_name]
                                      )
                                ):
                            self.cef_message += get_key_string(section, key)
            if cef_mappings.has_section(event_name):
                additional_common_section = 'additional_common_with_custom_extension_keys'
            else:
                # If event section is not present then make use of the CEF custom strings keys for additional common properties
                additional_common_section = 'additional_common_with_custom_string_keys'
            if cef_mappings.has_section(additional_common_section):
                for key in cef_mappings[additional_common_section]:
                    self.cef_message += get_key_string(additional_common_section, key)
        except Exception as exc:
            print("Problem while constructing CEF formatted message")
            raise exc
