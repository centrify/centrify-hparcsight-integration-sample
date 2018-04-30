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

import configparser
import os

cef_mappings_file = 'cisp/cef_mapping.ini'
cef_mappings = configparser.ConfigParser()

# Below statement is important because CEF keys are case sensitive
cef_mappings.optionxform = str


def read_cef_mappings():

    if not os.path.isfile(cef_mappings_file):
        raise Exception("\'cef_mapping.ini\' file is missing.")
    else:
        try:
            cef_mappings.read(cef_mappings_file)
        except Exception as e:
            raise Exception("Error while reading cef mappings file. Details: %s" % (e))

    if not cef_mappings.has_section('header'):
        raise Exception("\'header\' section in cef mapping file is missing.")

    validate_cef_header()

    if not cef_mappings.has_section('common'):
        raise Exception("\'common\' section in cef mapping file is missing.")


def validate_cef_header():
    if len(cef_mappings.items('header')) != 7:
        raise Exception("\'header\' section in the cef mapping file is incorrect. "
                        "\n Something is missing. Please take fresh copy.")
    
read_cef_mappings()

