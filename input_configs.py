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

config_file = './config.ini'
config = configparser.RawConfigParser()

def read_config():
    if not os.path.isfile(config_file):
        raise Exception("\'config.ini\' file is missing.")
    else:
        try:
            config.read(config_file)
            validate_config()
        except Exception as e:
            raise Exception("Error while reading cef mappings file. Details: %s" % (e))


def validate_config():
    if not config.has_section('common'):
        raise Exception("\'common\' section in config file is missing.")

    if not config.has_option('common', 'tenant') or not config.has_option('common',
                                                                          'siem_username') or not config.has_option(
            'common', 'siem_password'):
        raise Exception(
            "\'Make sure that following 3 configs are present in config.ini - tenant, siem_username and siem_password.")

    if len(config['common']['tenant']) == 0 or len(config['common']['siem_username']) == 0 or len(
            config['common']['siem_password']) == 0:
        raise Exception(
            "\'Make sure that following 3 configs have values in config.ini - tenant, siem_username and siem_password.")

read_config()