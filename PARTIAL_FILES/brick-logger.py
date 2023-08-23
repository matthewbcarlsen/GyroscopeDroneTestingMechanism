#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
brick-logger
Copyright (C) 2015 Matthias Bolte <matthias@tinkerforge.com>
Copyright (C) 2012, 2014 Roland Dudko <roland.dudko@gmail.com>
Copyright (C) 2012, 2014 Marvin Lutz <marvin.lutz.mail@gmail.com>

Commandline data logger tool for Bricklets and Bricks

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public
License along with this program; if not, write to the
Free Software Foundation, Inc., 59 Temple Place - Suite 330,
Boston, MA 02111-1307, USA.
"""

import sys
if (sys.hexversion & 0xFF000000) != 0x03000000:
    print('Python 3.x required')
    sys.exit(1)

data_logger_version = '2.1.9'
merged_data_logger_modules = True


import csv  # CSV_Writer
from datetime import datetime  # CSV_Data
import os  # CSV_Writer
from shutil import copyfile
import sys  # CSV_Writer
import threading
import queue
import time  # Writer Thread
import math
import locale

if 'merged_data_logger_modules' not in globals():
    from brickv.data_logger.event_logger import EventLogger

def utf8_strftime(timestamp, fmt):
    return datetime.fromtimestamp(timestamp).strftime(fmt)

def timestamp_to_de(timestamp):
    return utf8_strftime(timestamp, '%d.%m.%Y %H:%M:%S')

def timestamp_to_de_msec(timestamp):
    return timestamp_to_de(timestamp) + ',' + ('%.3f' % math.modf(timestamp)[0])[2:]

def timestamp_to_us(timestamp):
    return utf8_strftime(timestamp, '%m/%d/%Y %H:%M:%S')

def timestamp_to_us_msec(timestamp):
    return timestamp_to_us(timestamp) + '.' + ('%.3f' % math.modf(timestamp)[0])[2:]

def timestamp_to_iso(timestamp, milli=False):
    """
    Format a timestamp in ISO 8601 standard
    ISO 8601 = YYYY-MM-DDThh:mm:ss.fff+tz:tz
               2014-09-10T14:12:05.563+02:00
    """

    if time.localtime().tm_isdst and time.daylight:
        offset = -time.altzone / 60
    else:
        offset = -time.timezone / 60

    tz = '%02d:%02d' % (abs(offset) / 60, abs(offset) % 60)

    if offset < 0:
        tz = '-' + tz
    else:
        tz = '+' + tz

    if milli:
        ms = '.' + ('%.3f' % math.modf(timestamp)[0])[2:]
    else:
        ms = ''

    return utf8_strftime(timestamp, '%Y-%m-%dT%H:%M:%S') + ms + tz

def timestamp_to_iso_msec(timestamp):
    return timestamp_to_iso(timestamp, True)

def timestamp_to_unix(timestamp):
    return str(int(timestamp))

def timestamp_to_unix_msec(timestamp):
    return '%.3f' % timestamp

def timestamp_to_strftime(timestamp, time_format):
    try:
        return utf8_strftime(timestamp, time_format)
    except Exception as e:
        return 'Error: ' + str(e).replace('\n', ' ')

class DataLoggerException(Exception):
    # Error Codes
    DL_MISSING_ARGUMENT = -1  # Missing Arguments in Config File
    DL_FAILED_VALIDATION = -2  # Validation found errors in the configuration file
    DL_CRITICAL_ERROR = -42  # For all other critical errors

    def __init__(self, err_code=DL_CRITICAL_ERROR, desc="No Description!"):
        self.value = err_code
        self.description = desc

    def __str__(self):
        return str("ERROR[DL" + str(self.value) + "]: " + str(self.description))


'''
/*---------------------------------------------------------------------------
                                CSVData
 ---------------------------------------------------------------------------*/
 '''


class CSVData:
    """
    This class is used as a temporary save spot for all csv relevant data.
    """

    def __init__(self, timestamp, name, uid, var_name, raw_data, var_unit):
        """
        timestamp -- time data was
        name      -- display name of Brick(let)
        uid       -- UID of Brick(let)
        var_name  -- name of logged value
        raw_data  -- logged value
        var_unit  -- unit of logged value
        """
        self.timestamp = timestamp # datatime object
        self.name = name
        self.uid = uid
        self.var_name = var_name
        self.raw_data = raw_data
        self.var_unit = var_unit

    def __str__(self):
        """
        Simple Debug function for easier display of the object.
        """
        return "[TIME=" + str(self.timestamp) + \
               ";NAME=" + str(self.name) + \
               ";UID=" + str(self.uid) + \
               ";VAR=" + str(self.var_name) + \
               ";RAW=" + str(self.raw_data) + \
               ";UNIT=" + str(self.var_unit) + "]"

'''
/*---------------------------------------------------------------------------
                                LoggerTimer
 ---------------------------------------------------------------------------*/
 '''


class LoggerTimer:
    """This class provides a timer with a repeat functionality based on a interval"""

    def __init__(self, interval, func_name, var_name, device):
        """
        interval -- the repeat interval in seconds
        func -- the function which will be called
        """
        if interval < 0:
            interval = 0

        self._interval = interval # in seconds
        self._func_name = func_name
        self._var_name = var_name
        self._device = device
        self._enable_ref = None
        self._stop_queue = None
        self._thread = None

    def _loop(self, enable_ref, stop_queue):
        monotonic_timestamp = time.monotonic()

        while enable_ref[0]:
            elapsed = time.monotonic() - monotonic_timestamp
            remaining = max(self._interval - elapsed, 0)

            try:
                stop_queue.get(timeout=remaining)
            except queue.Empty:
                pass
            else:
                break

            monotonic_timestamp = time.monotonic()

            if not enable_ref[0]:
                break

            getattr(self._device, self._func_name)(self._var_name)

    def start(self):
        if self._interval == 0:
            return

        if self._thread != None:
            return

        self._enable_ref = [True]
        self._stop_queue = queue.Queue()
        self._thread = threading.Thread(target=self._loop, args=(self._enable_ref, self._stop_queue), daemon=True)
        self._thread.start()

    def stop_and_join(self):
        if self._interval == 0:
            return

        if self._thread == None:
            return

        self._enable_ref[0] = False
        self._stop_queue.put(None)
        self._thread.join(5)

        self._enable_ref = None
        self._stop_queue = None
        self._thread = None

"""
/*---------------------------------------------------------------------------
                                Utilities
 ---------------------------------------------------------------------------*/
"""


class Utilities:
    """
    This class provides some utility functions for the data logger project
    """

    def parse_to_int(string):
        """
        Returns an integer out of a string.
        0(Zero) -- if string is negative or an exception raised during the converting process.
        """
        try:
            ret = int(float(string))
            if ret < 0:
                ret = 0
            return ret
        except ValueError:
            # EventLogger.debug("DataLogger.parse_to_int(" + string + ") could not be parsed! Return 0 for the Timer.")
            return 0

    parse_to_int = staticmethod(parse_to_int)

    def parse_to_bool(bool_string):
        """
        Returns a 'True', if the string is equals to 'true' or 'True'.
        Otherwise it'll return a False
        """
        if bool_string == "true" or bool_string == "True" or bool_string == "TRUE":
            return True
        else:
            return False

    parse_to_bool = staticmethod(parse_to_bool)

    def parse_device_name(device_name):
        tmp = device_name.split("[")
        if len(tmp) == 1:
            return tmp[0], None

        device = tmp[0][:len(tmp[0]) - 1]
        uid = tmp[1][:len(tmp[1]) - 1]

        return device, uid

    parse_device_name = staticmethod(parse_device_name)

    def replace_right(source, target, replacement, replacements=None):
        return replacement.join(source.rsplit(target, replacements))

    replace_right = staticmethod(replace_right)

    def check_file_path_exists(file_path):
        try:
            dir_path = os.path.dirname(file_path)
            if dir_path == "" or dir_path is None:
                if file_path == "" or file_path is None:
                    # no filename - dir
                    return False
                else:
                    # filename - but no dir
                    return True
            elif os.path.isdir(dir_path):
                # dir found
                return True
            return False
        except Exception:
            return False

    check_file_path_exists = staticmethod(check_file_path_exists)

    def is_valid_string(string_value, min_length=0):
        """
        Returns True if 'string_value' is of type str and has at least a size of
        'min_length'
        """
        if not isinstance(string_value, str) or len(string_value) < min_length:
            return False
        return True

    is_valid_string = staticmethod(is_valid_string)


'''
/*---------------------------------------------------------------------------
                                CSVWriter
 ---------------------------------------------------------------------------*/
 '''


class CSVWriter:
    """
    This class provides the actual open/write functions, which are used by the CSVWriterJob class to write logged data into
    a CSV formatted file.
    """

    def __init__(self, file_path, max_file_count=1, max_file_size=0):
        """
        file_path = Path to the csv file
        """
        self._file_path = file_path
        # check if file path exists
        if not Utilities.check_file_path_exists(self._file_path):
            raise Exception("File Path not found! -> " + str(self._file_path))

        self._raw_file = None
        self._csv_file = None

        if max_file_size < 0:
            max_file_size = 0
        self._file_size = max_file_size

        # HINT: create always at least 1 backup file!
        if max_file_count < 1:
            max_file_count = 1

        self._file_count = max_file_count

        self._open_file_A()

    def _open_file_A(self):
        """Opens a file in append mode."""

        # newline problem solved + import sys
        if sys.version_info >= (3, 0, 0):
            self._raw_file = open(self._file_path, 'a', newline='')  # FIXME append or write?!
        else:
            self._raw_file = open(self._file_path, 'ab')

        self._csv_file = csv.writer(self._raw_file, delimiter=";", quotechar='"', quoting=csv.QUOTE_MINIMAL)

        # if the file is empty, create a csv header
        if self._file_is_empty():
            self._write_header()

    def _file_is_empty(self):
        """
        Simple check if the file is empty.
        Return:
            True  - File is empty or missing
            False - File is not empty
        """
        try:
            if os.stat(self._file_path).st_size > 0:
                return False
            else:
                return True
        except OSError:
            return True

    def _write_header(self):
        """Writes a csv header into the file"""
        if not self._file_is_empty():
            EventLogger.debug("File is not empty")
            return

        EventLogger.debug("CSVWriter._write_header() - done")
        self._csv_file.writerow(["TIME"] + ["NAME"] + ["UID"] + ["VAR"] + ["RAW"] + ["UNIT"])
        self._raw_file.flush()

    def write_data_row(self, csv_data):
        """
        Write a row into the csv file.
        Return:
            True  - Row was written into thee file
            False - Row was not written into the File
        """
        if self._raw_file is None or self._csv_file is None:
            return False

        self._csv_file.writerow([csv_data.timestamp] + [csv_data.name] + [csv_data.uid] + [csv_data.var_name] + [str(csv_data.raw_data)] + [csv_data.var_unit])
        self._raw_file.flush()

        if self._file_size > 0:
            self._rolling_file()

        return True

    def set_file_path(self, new_file_path):
        """
        Sets a new file path.
        Return:
            True  - File path was updated and successfully opened
            False - File path could not be updated or opened
        """
        if not self.close_file():
            return False

        self._file_path = new_file_path
        self._open_file_A()
        return True

    def reopen_file(self):
        """
        Tries to reopen a file, if the file was manually closed.
        Return:
            True  - File could be reopened
            False - File could not be reopened
        """
        if self._raw_file is not None and self._csv_file is not None:
            return False

        self._open_file_A()
        return True

    def close_file(self):
        """
        Tries to close the current file.
        Return:
            True  - File was close
            False - File could not be closed
        """
        if self._raw_file is None or self._csv_file is None:
            return False
        try:
            self._raw_file.close()
            self._csv_file = None
            self._raw_file = None
            return True

        except ValueError:
            return False

    def _rolling_file(self):
        f_size = os.path.getsize(self._file_path)
        if f_size > self._file_size:
            EventLogger.info(
                "Max Filesize(" + "%.3f" % (self._file_size / 1024.0 / 1024.0) + " MB) reached! Rolling Files...")
            self._roll_files()

    # FIXME: only files with a . are working!
    def _roll_files(self):
        i = self._file_count

        self.close_file()

        while True:
            if i == 0:
                # first file reached
                break

            tmp_file_name = Utilities.replace_right(self._file_path, ".", "(" + str(i) + ").", 1)

            if os.path.exists(tmp_file_name):
                if i == self._file_count:
                    # max file count -> delete
                    os.remove(tmp_file_name)
                    EventLogger.debug("Rolling Files... removed File(" + str(i) + ")")

                else:
                    # copy file and remove old
                    copyfile(tmp_file_name, Utilities.replace_right(self._file_path, ".", "(" + str(i + 1) + ").", 1))
                    EventLogger.debug("Rolling Files... copied File(" + str(i) + ") into (" + str(i + 1) + ")")
                    os.remove(tmp_file_name)

            i -= 1

        if self._file_count != 0:
            copyfile(self._file_path, Utilities.replace_right(self._file_path, ".", "(" + str(1) + ").", 1))
            EventLogger.debug("Rolling Files... copied original File into File(1)")
        os.remove(self._file_path)
        self._open_file_A()



import json

if 'merged_data_logger_modules' not in globals():
    from brickv.bindings.ip_connection import base58decode
    from brickv.data_logger.event_logger import EventLogger
    from brickv.data_logger.utils import DataLoggerException, Utilities
    from brickv.data_logger.loggable_devices import device_specs
else:
    from tinkerforge.ip_connection import base58decode

def load_and_validate_config(filename):
    EventLogger.info('Loading config from file: {0}'.format(filename))

    try:
        with open(filename, 'r') as f:
            s = f.read()

        config = json.loads(s)
    except Exception as e:
        EventLogger.critical('Could not parse config file as JSON: {0}'.format(e))
        return None

    if not ConfigValidator(config).validate():
        return None

    EventLogger.info('Config successfully loaded from: {0}'.format(filename))

    return config

def save_config(config, filename):
    EventLogger.info('Saving config to file: {0}'.format(filename))

    try:
        s = json.dumps(config, ensure_ascii=False, sort_keys=True, indent=2)

        with open(filename, 'w') as f:
            f.write(s)
    except Exception as e:
        EventLogger.critical('Could not write config file as JSON: {0}'.format(e))
        return False

    EventLogger.info('Config successfully saved to: {0}'.format(filename))

    return True

#---------------------------------------------------------------------------
#                               ConfigValidator
#---------------------------------------------------------------------------

class ConfigValidator:
    """
    This class validates the (JSON) config file
    """
    MIN_INTERVAL = 0

    def __init__(self, config):
        self._error_count = 0
        self._config = config

    def _report_error(self, message):
        self._error_count += 1
        EventLogger.critical(message)

    def validate(self):
        """
        This function performs the validation of the various sections of the JSON
        configuration file
        """
        EventLogger.info("Validating config file")

        self._validate_hosts()
        self._validate_data()
        self._validate_debug()
        self._validate_devices()

        if self._error_count > 0:
            EventLogger.critical("Validation found {0} errors".format(self._error_count))
        else:
            EventLogger.info("Validation successful")

        return self._error_count == 0

    def _validate_hosts(self):
        try:
            hosts = self._config['hosts']
        except KeyError:
            self._report_error('Config has no "hosts" section')
            return

        if not isinstance(hosts, dict):
            self._report_error('"hosts" section is not a dict')
            return

        try:
            hosts['default']
        except KeyError:
            self._report_error('Config has no default host')

        for host_id, host in hosts.items():
            # name
            try:
                name = host['name']
            except KeyError:
                self._report_error('Host "{0}" has no name'.format(host_id))
            else:
                if not isinstance(name, str):
                    self._report_error('Name of host "{0}" is not a string'.format(host_id))
                elif len(name) == 0:
                    self._report_error('Name of host "{0}" is empty'.format(host_id))

            # port
            try:
                port = host['port']
            except KeyError:
                self._report_error('Host "{0}" has no port'.format(host_id))
            else:
                if not isinstance(port, int):
                    self._report_error('Port of host "{0}" is not an int'.format(host_id))
                elif port < 1 or port > 65535:
                    self._report_error('Port of host "{0}" is out-of-range'.format(host_id))

            # secret (optional)
            try:
                secret = host['secret']
            except KeyError:
                host['secret'] = None
            else:
                if secret == None:
                    pass
                elif not isinstance(secret, str):
                    self._report_error('Secret of host "{0}" is not a string'.format(host_id))
                elif len(secret) > 64:
                    self._report_error('Secret of host "{0}" is too long'.format(host_id))

    def _validate_data(self):
        try:
            data = self._config['data']
        except KeyError:
            self._report_error('Config has no "data" section')
            return

        # time_format
        try:
            time_format = data['time_format']
        except KeyError:
            self._report_error('"data" section has no "time_format" member')
        else:
            if not isinstance(time_format, str):
                self._report_error('"data/time_format" is not a string')
            elif time_format not in ['de', 'de-msec', 'us', 'us-msec', 'iso', 'iso-msec', 'unix', 'unix-msec', 'strftime']:
                self._report_error('Invalid "data/time_format" value: {0}'.format(time_format))

        # time_format_strftime (optional)
        try:
            time_format_strftime = data['time_format_strftime']
        except KeyError:
            data['time_format_strftime'] = '%Y%m%d_%H%M%S'
        else:
            if not isinstance(time_format_strftime, str):
                self._report_error('"data/time_format_strftime" is not a string')

        self._validate_data_csv()

    def _validate_data_csv(self):
        try:
            csv = self._config['data']['csv']
        except KeyError:
            self._report_error('Config has no "data/csv" section')
            return

        # enabled
        try:
            enabled = csv['enabled']
        except KeyError:
            self._report_error('"data/csv" section has no "enabled" member')
        else:
            if not isinstance(enabled, bool):
                self._report_error('"data/csv/enabled" is not an bool')

        # file_name
        try:
            file_name = csv['file_name']
        except KeyError:
            self._report_error('"data/csv" section has no "file_name" member')
        else:
            if not isinstance(file_name, str):
                self._report_error('"data/csv/file_name" is not an string')
            elif len(file_name) == 0:
                self._report_error('"data/csv/file_name" is empty')

    def _validate_debug(self):
        try:
            debug = self._config['debug']
        except KeyError:
            self._report_error('Config has no "debug" section')
            return

        # time_format
        try:
            time_format = debug['time_format']
        except KeyError:
            self._report_error('"debug" section has no "time_format" member')
        else:
            if not isinstance(time_format, str):
                self._report_error('"debug/time_format" is not a string')
            elif time_format not in ['de', 'us', 'iso', 'unix']:
                self._report_error('Invalid "debug/time_format" value: {0}'.format(time_format))

        self._validate_debug_log()

    def _validate_debug_log(self):
        try:
            log = self._config['debug']['log']
        except KeyError:
            self._report_error('Config has no "debug/log" section')
            return

        # enabled
        try:
            enabled = log['enabled']
        except KeyError:
            self._report_error('"debug/log" section has no "enabled" member')
        else:
            if not isinstance(enabled, bool):
                self._report_error('"debug/log/enabled" is not an bool')

        # file_name
        try:
            file_name = log['file_name']
        except KeyError:
            self._report_error('"debug/log" section has no "file_name" member')
        else:
            if not isinstance(file_name, str):
                self._report_error('"debug/log/file_name" is not an string')
            elif len(file_name) == 0:
                self._report_error('"debug/log/file_name" is empty')

        # level
        try:
            level = log['level']
        except KeyError:
            self._report_error('"debug/log" section has no "level" member')
        else:
            if not isinstance(level, str):
                self._report_error('"debug/log/level" is not an integer')
            elif level not in ['debug', 'info', 'warning', 'error', 'critical']:
                self._report_error('Invalid "debug/log/level" value: {0}'.format(level))

    def _validate_devices(self):
        try:
            devices = self._config['devices']
        except KeyError:
            self._report_error('Config has no "devices" section')
            return

        if not isinstance(devices, list):
            self._report_error('"devices" section is not a list')
            return

        for device in devices:
            # uid
            try:
                uid = device['uid']
            except KeyError:
                self._report_error('Device has no UID')
                continue

            if not isinstance(uid, str):
                self._report_error('Device UID is not a string')
                continue

            if len(uid) > 0:
                try:
                    decoded_uid = base58decode(uid)
                except Exception as e:
                    self._report_error('Invalid device UID: {0}'.format(uid))
                    continue

                if decoded_uid < 1 or decoded_uid > 0xFFFFFFFF:
                    self._report_error('Device UID is out-of-range: {0}'.format(uid))
                    continue

            # name
            try:
                name = device['name']
            except KeyError:
                self._report_error('Device "{0}" has no name'.format(uid))
                continue

            if not isinstance(name, str):
                self._report_error('Name of device "{0}" is not a string'.format(uid))
                continue
            elif len(name) == 0:
                self._report_error('Device "{0}" has empty name'.format(uid))
                continue
            elif name not in device_specs:
                self._report_error('Device "{0}" has unknwon name: {1}'.format(uid, name))
                continue

            device_spec = device_specs[name]

            # host
            try:
                host = device['host']
            except KeyError:
                self._report_error('Device "{0}" has no host'.format(uid))
            else:
                if not isinstance(host, str):
                    self._report_error('Host of device "{0}" is not a string'.format(uid))
                elif len(host) == 0:
                    self._report_error('Host of device "{0}" is empty'.format(uid))
                elif host not in self._config['hosts']:
                    self._report_error('Host of device "{0}" is unknown: {1}'.format(uid, host))

            # values
            try:
                values = device['values']
            except KeyError:
                self._report_error('Device "{0}" has no values'.format(uid))
            else:
                if not isinstance(values, dict):
                    self._report_error('"values" of device "{0}" is not a dict'.format(uid))
                elif len(values) == 0:
                    self._report_error('"values" of device "{0}" is empty'.format(uid))
                else:
                    for value_spec in device_spec['values']:
                        try:
                            value = values[value_spec['name']]
                        except KeyError:
                            self._report_error('Value "{0}" of device "{1}" is missing'.format(value_spec['name'], uid))
                            continue

                        # interval
                        try:
                            interval = value['interval']
                        except KeyError:
                            self._report_error('Value "{0}" of device "{1}" has no interval'.format(value_spec['name'], uid))
                        else:
                            if not isinstance(interval, int) and not isinstance(interval, float):
                                self._report_error('Interval of value "{0}" of device "{1}" is neiter an int nor a float'.format(value_spec['name'], uid))
                            elif interval < 0:
                                self._report_error('Interval of value "{0}" of device "{1}" is ouf-of-range'.format(value_spec['name'], uid))

                        # subvalues
                        if value_spec['subvalues'] != None:
                            try:
                                subvalues = value['subvalues']
                            except KeyError:
                                self._report_error('Value "{0}" of device "{1}" has no subvalues'.format(value_spec['name'], uid))
                            else:
                                if not isinstance(subvalues, dict):
                                    self._report_error('Subvalues of value "{0}" of device "{1}" is not a dict'.format(value_spec['name'], uid))
                                else:
                                    for subvalue_spec_name in value_spec['subvalues']:
                                        try:
                                            subvalue_value = subvalues[subvalue_spec_name]
                                        except:
                                            self._report_error('Subvalue "{0}" of value "{1}" of device "{2}" is missing'
                                                               .format(subvalue_spec_name, value_spec['name'], uid))
                                            continue

                                        if not isinstance(subvalue_value, bool):
                                            self._report_error('Subvalue "{0}" of value "{1}" of device "{2}" is not a bool'
                                                               .format(subvalue_spec_name, value_spec['name'], uid))

            # options
            if device_spec['options'] != None:
                try:
                    options = device['options']
                except KeyError:
                    self._report_error('Device "{0}" has no options'.format(uid))
                else:
                    if not isinstance(options, dict):
                        self._report_error('"options" of device "{0}" is not a dict'.format(uid))
                    elif len(options) == 0:
                        self._report_error('"options" of device "{0}" is empty'.format(uid))
                    else:
                        for option_spec in device_spec['options']:
                            try:
                                option = options[option_spec['name']]
                            except KeyError:
                                self._report_error('Option "{0}" of device "{1}" is missing'.format(option_spec['name'], uid))
                                continue

                            # value
                            try:
                                value = option['value']
                            except KeyError:
                                self._report_error('Option "{0}" of device "{1}" has no interval'.format(option_spec['name'], uid))
                            else:
                                valid = False

                                if option_spec['type'] == 'choice':
                                    if not isinstance(value, str):
                                        self._report_error('Value of option "{0}" of device "{1}" is not a string'
                                                           .format(option_spec['name'], uid))
                                        continue

                                    for option_value_spec in option_spec['values']:
                                        if option_value_spec[0] == value:
                                            valid = True
                                            break
                                elif option_spec['type'] == 'int':
                                    if not isinstance(value, int):
                                        self._report_error('Value of option "{0}" of device "{1}" is not an int'
                                                           .format(option_spec['name'], uid))
                                        continue

                                    valid = value >= option_spec['minimum'] and value <= option_spec['maximum']
                                elif option_spec['type'] == 'bool':
                                    if not isinstance(value, bool):
                                        self._report_error('Value of option "{0}" of device "{1}" is not a bool'
                                                           .format(option_spec['name'], uid))
                                        continue

                                    valid = True

                                if not valid:
                                    self._report_error('Value of option "{0}" of device "{1}" is invalid: {2}'
                                                       .format(option_spec['name'], uid, value))



""""
/*---------------------------------------------------------------------------
                                LogSpaceCounter
 ---------------------------------------------------------------------------*/
"""


class LogSpaceCounter:
    """
    This class provides functions to count the average lines per second
    which will be written into the log file
    """

    def __init__(self, file_count, file_size):
        """
        file_count -- the amount of logfiles
        file_size -- the size of each file
        """
        self.file_count = file_count
        self.file_size = file_size

        self.lines_per_second = 0.0

    def add_lines_per_second(self, lines):
        self.lines_per_second += lines

    def calculate_time(self):
        """
        This function calculates the time where the logger can
        save data without overwriting old ones.

        18k lines -> 1MB
        """
        if self.lines_per_second <= 0 or self.file_size == 0:
            return 0, 0, 0, 0

        max_available_space = (self.file_count + 1) * ((self.file_size / 1024.0) / 1024.0)
        seconds_for_one_MB = 18000.0 / self.lines_per_second

        sec = seconds_for_one_MB * max_available_space * 1.0

        days = int(sec / 86400.0)
        sec -= 86400.0 * days

        hrs = int(sec / 3600.0)
        sec -= 3600.0 * hrs

        mins = int(sec / 60.0)
        sec -= 60.0 * mins

        return days, hrs, mins, int(sec)



import time
from collections import namedtuple
from queue import Queue, Empty

if 'merged_data_logger_modules' not in globals():
    from brickv.data_logger.event_logger import EventLogger
    from brickv.data_logger.utils import LoggerTimer, CSVData, \
                                         timestamp_to_de, timestamp_to_us, \
                                         timestamp_to_iso, timestamp_to_unix, \
                                         timestamp_to_de_msec, timestamp_to_us_msec, \
                                         timestamp_to_iso_msec, timestamp_to_unix_msec, \
                                         timestamp_to_strftime

    # Bricks
    try:
        from brickv.bindings.brick_dc import BrickDC
        BrickDC_found = True
    except ImportError:
        BrickDC_found = False
    try:
        from brickv.bindings.brick_imu import BrickIMU
        BrickIMU_found = True
    except ImportError:
        BrickIMU_found = False
    try:
        from brickv.bindings.brick_imu_v2 import BrickIMUV2
        BrickIMUV2_found = True
    except ImportError:
        BrickIMUV2_found = False
    try:
        from brickv.bindings.brick_master import BrickMaster
        BrickMaster_found = True
    except ImportError:
        BrickMaster_found = False
    try:
        from brickv.bindings.brick_servo import BrickServo
        BrickServo_found = True
    except ImportError:
        BrickServo_found = False
    try:
        from brickv.bindings.brick_silent_stepper import BrickSilentStepper
        BrickSilentStepper_found = True
    except ImportError:
        BrickSilentStepper_found = False
    try:
        from brickv.bindings.brick_stepper import BrickStepper
        BrickStepper_found = True
    except ImportError:
        BrickStepper_found = False
    try:
        from brickv.bindings.brick_hat import BrickHAT
        BrickHAT_found = True
    except ImportError:
        BrickHAT_found = False
    try:
        from brickv.bindings.brick_hat_zero import BrickHATZero
        BrickHATZero_found = True
    except ImportError:
        BrickHATZero_found = False

    # Bricklets
    try:
        from brickv.bindings.bricklet_accelerometer import BrickletAccelerometer
        BrickletAccelerometer_found = True
    except ImportError:
        BrickletAccelerometer_found = False
    try:
        from brickv.bindings.bricklet_accelerometer_v2 import BrickletAccelerometerV2
        BrickletAccelerometerV2_found = True
    except ImportError:
        BrickletAccelerometerV2_found = False
    try:
        from brickv.bindings.bricklet_air_quality import BrickletAirQuality
        BrickletAirQuality_found = True
    except ImportError:
        BrickletAirQuality_found = False
    try:
        from brickv.bindings.bricklet_ambient_light import BrickletAmbientLight
        BrickletAmbientLight_found = True
    except ImportError:
        BrickletAmbientLight_found = False
    try:
        from brickv.bindings.bricklet_ambient_light_v2 import BrickletAmbientLightV2
        BrickletAmbientLightV2_found = True
    except ImportError:
        BrickletAmbientLightV2_found = False
    try:
        from brickv.bindings.bricklet_ambient_light_v3 import BrickletAmbientLightV3
        BrickletAmbientLightV3_found = True
    except ImportError:
        BrickletAmbientLightV3_found = False
    try:
        from brickv.bindings.bricklet_analog_in import BrickletAnalogIn
        BrickletAnalogIn_found = True
    except ImportError:
        BrickletAnalogIn_found = False
    try:
        from brickv.bindings.bricklet_analog_in_v2 import BrickletAnalogInV2
        BrickletAnalogInV2_found = True
    except ImportError:
        BrickletAnalogInV2_found = False
    try:
        from brickv.bindings.bricklet_analog_in_v3 import BrickletAnalogInV3
        BrickletAnalogInV3_found = True
    except ImportError:
        BrickletAnalogInV3_found = False
    try:
        from brickv.bindings.bricklet_analog_out_v2 import BrickletAnalogOutV2
        BrickletAnalogOutV2_found = True
    except ImportError:
        BrickletAnalogOutV2_found = False
    try:
        from brickv.bindings.bricklet_analog_out_v3 import BrickletAnalogOutV3
        BrickletAnalogOutV3_found = True
    except ImportError:
        BrickletAnalogOutV3_found = False
    try:
        from brickv.bindings.bricklet_barometer import BrickletBarometer
        BrickletBarometer_found = True
    except ImportError:
        BrickletBarometer_found = False
    try:
        from brickv.bindings.bricklet_barometer_v2 import BrickletBarometerV2
        BrickletBarometerV2_found = True
    except ImportError:
        BrickletBarometerV2_found = False
    try:
        from brickv.bindings.bricklet_can import BrickletCAN #NYI FIXME: has to use frame_read callback to get all data
        BrickletCAN_found = True
    except ImportError:
        BrickletCAN_found = False
    try:
        from brickv.bindings.bricklet_can_v2 import BrickletCANV2 #NYI FIXME: has to use frame_read callback to get all data
        BrickletCANV2_found = True
    except ImportError:
        BrickletCANV2_found = False
    try:
        from brickv.bindings.bricklet_co2 import BrickletCO2
        BrickletCO2_found = True
    except ImportError:
        BrickletCO2_found = False
    try:
        from brickv.bindings.bricklet_co2_v2 import BrickletCO2V2
        BrickletCO2V2_found = True
    except ImportError:
        BrickletCO2V2_found = False
    try:
        from brickv.bindings.bricklet_color import BrickletColor
        BrickletColor_found = True
    except ImportError:
        BrickletColor_found = False
    try:
        from brickv.bindings.bricklet_color_v2 import BrickletColorV2
        BrickletColorV2_found = True
    except ImportError:
        BrickletColorV2_found = False
    try:
        from brickv.bindings.bricklet_compass import BrickletCompass
        BrickletCompass_found = True
    except ImportError:
        BrickletCompass_found = False
    try:
        from brickv.bindings.bricklet_current12 import BrickletCurrent12
        BrickletCurrent12_found = True
    except ImportError:
        BrickletCurrent12_found = False
    try:
        from brickv.bindings.bricklet_current25 import BrickletCurrent25
        BrickletCurrent25_found = True
    except ImportError:
        BrickletCurrent25_found = False
    try:
        from brickv.bindings.bricklet_dc_v2 import BrickletDCV2
        BrickletDCV2_found = True
    except ImportError:
        BrickletDCV2_found = False
    try:
        from brickv.bindings.bricklet_distance_ir import BrickletDistanceIR
        BrickletDistanceIR_found = True
    except ImportError:
        BrickletDistanceIR_found = False
    try:
        from brickv.bindings.bricklet_distance_ir_v2 import BrickletDistanceIRV2
        BrickletDistanceIRV2_found = True
    except ImportError:
        BrickletDistanceIRV2_found = False
    try:
        from brickv.bindings.bricklet_distance_us import BrickletDistanceUS
        BrickletDistanceUS_found = True
    except ImportError:
        BrickletDistanceUS_found = False
    try:
        from brickv.bindings.bricklet_distance_us_v2 import BrickletDistanceUSV2
        BrickletDistanceUSV2_found = True
    except ImportError:
        BrickletDistanceUSV2_found = False
    try:
        from brickv.bindings.bricklet_dmx import BrickletDMX
        BrickletDMX_found = True
    except ImportError:
        BrickletDMX_found = False
    try:
        from brickv.bindings.bricklet_dual_button import BrickletDualButton
        BrickletDualButton_found = True
    except ImportError:
        BrickletDualButton_found = False
    try:
        from brickv.bindings.bricklet_dual_button_v2 import BrickletDualButtonV2
        BrickletDualButtonV2_found = True
    except ImportError:
        BrickletDualButtonV2_found = False
    try:
        from brickv.bindings.bricklet_dual_relay import BrickletDualRelay
        BrickletDualRelay_found = True
    except ImportError:
        BrickletDualRelay_found = False
    try:
        from brickv.bindings.bricklet_dust_detector import BrickletDustDetector
        BrickletDustDetector_found = True
    except ImportError:
        BrickletDustDetector_found = False
    try:
        from brickv.bindings.bricklet_energy_monitor import BrickletEnergyMonitor
        BrickletEnergyMonitor_found = True
    except ImportError:
        BrickletEnergyMonitor_found = False
    try:
        from brickv.bindings.bricklet_gps import BrickletGPS
        BrickletGPS_found = True
    except ImportError:
        BrickletGPS_found = False
    try:
        from brickv.bindings.bricklet_gps_v2 import BrickletGPSV2
        BrickletGPSV2_found = True
    except ImportError:
        BrickletGPSV2_found = False
    try:
        from brickv.bindings.bricklet_gps_v3 import BrickletGPSV3
        BrickletGPSV3_found = True
    except ImportError:
        BrickletGPSV3_found = False
    try:
        from brickv.bindings.bricklet_hall_effect import BrickletHallEffect
        BrickletHallEffect_found = True
    except ImportError:
        BrickletHallEffect_found = False
    try:
        from brickv.bindings.bricklet_hall_effect_v2 import BrickletHallEffectV2
        BrickletHallEffectV2_found = True
    except ImportError:
        BrickletHallEffectV2_found = False
    try:
        from brickv.bindings.bricklet_humidity import BrickletHumidity
        BrickletHumidity_found = True
    except ImportError:
        BrickletHumidity_found = False
    try:
        from brickv.bindings.bricklet_humidity_v2 import BrickletHumidityV2
        BrickletHumidityV2_found = True
    except ImportError:
        BrickletHumidityV2_found = False
    try:
        from brickv.bindings.bricklet_imu_v3 import BrickletIMUV3
        BrickletIMUV3_found = True
    except ImportError:
        BrickletIMUV3_found = False
    try:
        from brickv.bindings.bricklet_industrial_counter import BrickletIndustrialCounter
        BrickletIndustrialCounter_found = True
    except ImportError:
        BrickletIndustrialCounter_found = False
    try:
        from brickv.bindings.bricklet_industrial_digital_in_4 import BrickletIndustrialDigitalIn4
        BrickletIndustrialDigitalIn4_found = True
    except ImportError:
        BrickletIndustrialDigitalIn4_found = False
    try:
        from brickv.bindings.bricklet_industrial_digital_in_4_v2 import BrickletIndustrialDigitalIn4V2
        BrickletIndustrialDigitalIn4V2_found = True
    except ImportError:
        BrickletIndustrialDigitalIn4V2_found = False
    try:
        from brickv.bindings.bricklet_industrial_dual_0_20ma import BrickletIndustrialDual020mA
        BrickletIndustrialDual020mA_found = True
    except ImportError:
        BrickletIndustrialDual020mA_found = False
    try:
        from brickv.bindings.bricklet_industrial_dual_0_20ma_v2 import BrickletIndustrialDual020mAV2
        BrickletIndustrialDual020mAV2_found = True
    except ImportError:
        BrickletIndustrialDual020mAV2_found = False
    try:
        from brickv.bindings.bricklet_industrial_dual_ac_relay import BrickletIndustrialDualACRelay
        BrickletIndustrialDualACRelay_found = True
    except ImportError:
        BrickletIndustrialDualACRelay_found = False
    try:
        from brickv.bindings.bricklet_industrial_dual_analog_in import BrickletIndustrialDualAnalogIn
        BrickletIndustrialDualAnalogIn_found = True
    except ImportError:
        BrickletIndustrialDualAnalogIn_found = False
    try:
        from brickv.bindings.bricklet_industrial_dual_analog_in_v2 import BrickletIndustrialDualAnalogInV2
        BrickletIndustrialDualAnalogInV2_found = True
    except ImportError:
        BrickletIndustrialDualAnalogInV2_found = False
    try:
        from brickv.bindings.bricklet_industrial_dual_relay import BrickletIndustrialDualRelay
        BrickletIndustrialDualRelay_found = True
    except ImportError:
        BrickletIndustrialDualRelay_found = False
    try:
        from brickv.bindings.bricklet_industrial_ptc import BrickletIndustrialPTC
        BrickletIndustrialPTC_found = True
    except ImportError:
        BrickletIndustrialPTC_found = False
    try:
        from brickv.bindings.bricklet_industrial_quad_relay import BrickletIndustrialQuadRelay
        BrickletIndustrialQuadRelay_found = True
    except ImportError:
        BrickletIndustrialQuadRelay_found = False
    try:
        from brickv.bindings.bricklet_industrial_quad_relay_v2 import BrickletIndustrialQuadRelayV2
        BrickletIndustrialQuadRelayV2_found = True
    except ImportError:
        BrickletIndustrialQuadRelayV2_found = False
    try:
        from brickv.bindings.bricklet_io16 import BrickletIO16
        BrickletIO16_found = True
    except ImportError:
        BrickletIO16_found = False
    try:
        from brickv.bindings.bricklet_io16_v2 import BrickletIO16V2
        BrickletIO16V2_found = True
    except ImportError:
        BrickletIO16V2_found = False
    try:
        from brickv.bindings.bricklet_io4 import BrickletIO4
        BrickletIO4_found = True
    except ImportError:
        BrickletIO4_found = False
    try:
        from brickv.bindings.bricklet_io4_v2 import BrickletIO4V2
        BrickletIO4V2_found = True
    except ImportError:
        BrickletIO4V2_found = False
    try:
        from brickv.bindings.bricklet_joystick import BrickletJoystick
        BrickletJoystick_found = True
    except ImportError:
        BrickletJoystick_found = False
    try:
        from brickv.bindings.bricklet_joystick_v2 import BrickletJoystickV2
        BrickletJoystickV2_found = True
    except ImportError:
        BrickletJoystickV2_found = False
    try:
        from brickv.bindings.bricklet_laser_range_finder import BrickletLaserRangeFinder #NYI # config: mode, FIXME: special laser handling
        BrickletLaserRangeFinder_found = True
    except ImportError:
        BrickletLaserRangeFinder_found = False
    try:
        from brickv.bindings.bricklet_laser_range_finder_v2 import BrickletLaserRangeFinderV2 #NYI # config: mode, FIXME: special laser handling
        BrickletLaserRangeFinderV2_found = True
    except ImportError:
        BrickletLaserRangeFinderV2_found = False
    try:
        from brickv.bindings.bricklet_led_strip import BrickletLEDStrip
        BrickletLEDStrip_found = True
    except ImportError:
        BrickletLEDStrip_found = False
    try:
        from brickv.bindings.bricklet_led_strip_v2 import BrickletLEDStripV2
        BrickletLEDStripV2_found = True
    except ImportError:
        BrickletLEDStripV2_found = False
    try:
        from brickv.bindings.bricklet_line import BrickletLine
        BrickletLine_found = True
    except ImportError:
        BrickletLine_found = False
    try:
        from brickv.bindings.bricklet_linear_poti import BrickletLinearPoti
        BrickletLinearPoti_found = True
    except ImportError:
        BrickletLinearPoti_found = False
    try:
        from brickv.bindings.bricklet_linear_poti_v2 import BrickletLinearPotiV2
        BrickletLinearPotiV2_found = True
    except ImportError:
        BrickletLinearPotiV2_found = False
    try:
        from brickv.bindings.bricklet_load_cell import BrickletLoadCell
        BrickletLoadCell_found = True
    except ImportError:
        BrickletLoadCell_found = False
    try:
        from brickv.bindings.bricklet_load_cell_v2 import BrickletLoadCellV2
        BrickletLoadCellV2_found = True
    except ImportError:
        BrickletLoadCellV2_found = False
    try:
        from brickv.bindings.bricklet_moisture import BrickletMoisture
        BrickletMoisture_found = True
    except ImportError:
        BrickletMoisture_found = False
    try:
        from brickv.bindings.bricklet_motion_detector import BrickletMotionDetector
        BrickletMotionDetector_found = True
    except ImportError:
        BrickletMotionDetector_found = False
    try:
        from brickv.bindings.bricklet_motion_detector_v2 import BrickletMotionDetectorV2
        BrickletMotionDetectorV2_found = True
    except ImportError:
        BrickletMotionDetectorV2_found = False
    try:
        from brickv.bindings.bricklet_motorized_linear_poti import BrickletMotorizedLinearPoti
        BrickletMotorizedLinearPoti_found = True
    except ImportError:
        BrickletMotorizedLinearPoti_found = False
    try:
        from brickv.bindings.bricklet_multi_touch import BrickletMultiTouch
        BrickletMultiTouch_found = True
    except ImportError:
        BrickletMultiTouch_found = False
    try:
        from brickv.bindings.bricklet_multi_touch_v2 import BrickletMultiTouchV2
        BrickletMultiTouchV2_found = True
    except ImportError:
        BrickletMultiTouchV2_found = False
    try:
        from brickv.bindings.bricklet_nfc import BrickletNFC
        BrickletNFC_found = True
    except ImportError:
        BrickletNFC_found = False
    try:
        from brickv.bindings.bricklet_nfc_rfid import BrickletNFCRFID
        BrickletNFCRFID_found = True
    except ImportError:
        BrickletNFCRFID_found = False
    try:
        from brickv.bindings.bricklet_outdoor_weather import BrickletOutdoorWeather
        BrickletOutdoorWeather_found = True
    except ImportError:
        BrickletOutdoorWeather_found = False
    try:
        from brickv.bindings.bricklet_particulate_matter import BrickletParticulateMatter
        BrickletParticulateMatter_found = True
    except ImportError:
        BrickletParticulateMatter_found = False
    try:
        from brickv.bindings.bricklet_performance_dc import BrickletPerformanceDC
        BrickletPerformanceDC_found = True
    except ImportError:
        BrickletPerformanceDC_found = False
    try:
        from brickv.bindings.bricklet_ptc import BrickletPTC
        BrickletPTC_found = True
    except ImportError:
        BrickletPTC_found = False
    try:
        from brickv.bindings.bricklet_ptc_v2 import BrickletPTCV2
        BrickletPTCV2_found = True
    except ImportError:
        BrickletPTCV2_found = False
    try:
        from brickv.bindings.bricklet_real_time_clock import BrickletRealTimeClock
        BrickletRealTimeClock_found = True
    except ImportError:
        BrickletRealTimeClock_found = False
    try:
        from brickv.bindings.bricklet_real_time_clock_v2 import BrickletRealTimeClockV2
        BrickletRealTimeClockV2_found = True
    except ImportError:
        BrickletRealTimeClockV2_found = False
    try:
        from brickv.bindings.bricklet_remote_switch import BrickletRemoteSwitch
        BrickletRemoteSwitch_found = True
    except ImportError:
        BrickletRemoteSwitch_found = False
    try:
        from brickv.bindings.bricklet_remote_switch_v2 import BrickletRemoteSwitchV2
        BrickletRemoteSwitchV2_found = True
    except ImportError:
        BrickletRemoteSwitchV2_found = False
    try:
        from brickv.bindings.bricklet_rgb_led_button import BrickletRGBLEDButton
        BrickletRGBLEDButton_found = True
    except ImportError:
        BrickletRGBLEDButton_found = False
    try:
        from brickv.bindings.bricklet_rgb_led_matrix import BrickletRGBLEDMatrix
        BrickletRGBLEDMatrix_found = True
    except ImportError:
        BrickletRGBLEDMatrix_found = False
    try:
        from brickv.bindings.bricklet_rotary_encoder import BrickletRotaryEncoder
        BrickletRotaryEncoder_found = True
    except ImportError:
        BrickletRotaryEncoder_found = False
    try:
        from brickv.bindings.bricklet_rotary_encoder_v2 import BrickletRotaryEncoderV2
        BrickletRotaryEncoderV2_found = True
    except ImportError:
        BrickletRotaryEncoderV2_found = False
    try:
        from brickv.bindings.bricklet_rotary_poti import BrickletRotaryPoti
        BrickletRotaryPoti_found = True
    except ImportError:
        BrickletRotaryPoti_found = False
    try:
        from brickv.bindings.bricklet_rotary_poti_v2 import BrickletRotaryPotiV2
        BrickletRotaryPotiV2_found = True
    except ImportError:
        BrickletRotaryPotiV2_found = False
    #from brickv.bindings.bricklet_rs232 import BrickletRS232 #NYI FIXME: has to use read_callback callback to get all data
    try:
        from brickv.bindings.bricklet_rs232_v2 import BrickletRS232V2
        BrickletRS232V2_found = True
    except ImportError:
        BrickletRS232V2_found = False
    try:
        from brickv.bindings.bricklet_rs485 import BrickletRS485
        BrickletRS485_found = True
    except ImportError:
        BrickletRS485_found = False
    try:
        from brickv.bindings.bricklet_segment_display_4x7 import BrickletSegmentDisplay4x7
        BrickletSegmentDisplay4x7_found = True
    except ImportError:
        BrickletSegmentDisplay4x7_found = False
    try:
        from brickv.bindings.bricklet_segment_display_4x7_v2 import BrickletSegmentDisplay4x7V2
        BrickletSegmentDisplay4x7V2_found = True
    except ImportError:
        BrickletSegmentDisplay4x7V2_found = False
    try:
        from brickv.bindings.bricklet_servo_v2 import BrickletServoV2
        BrickletServoV2_found = True
    except ImportError:
        BrickletServoV2_found = False
    try:
        from brickv.bindings.bricklet_silent_stepper_v2 import BrickletSilentStepperV2
        BrickletSilentStepperV2_found = True
    except ImportError:
        BrickletSilentStepperV2_found = False
    try:
        from brickv.bindings.bricklet_solid_state_relay import BrickletSolidStateRelay
        BrickletSolidStateRelay_found = True
    except ImportError:
        BrickletSolidStateRelay_found = False
    try:
        from brickv.bindings.bricklet_solid_state_relay_v2 import BrickletSolidStateRelayV2
        BrickletSolidStateRelayV2_found = True
    except ImportError:
        BrickletSolidStateRelayV2_found = False
    try:
        from brickv.bindings.bricklet_sound_intensity import BrickletSoundIntensity
        BrickletSoundIntensity_found = True
    except ImportError:
        BrickletSoundIntensity_found = False
    try:
        from brickv.bindings.bricklet_sound_pressure_level import BrickletSoundPressureLevel
        BrickletSoundPressureLevel_found = True
    except ImportError:
        BrickletSoundPressureLevel_found = False
    try:
        from brickv.bindings.bricklet_temperature import BrickletTemperature
        BrickletTemperature_found = True
    except ImportError:
        BrickletTemperature_found = False
    try:
        from brickv.bindings.bricklet_temperature_v2 import BrickletTemperatureV2
        BrickletTemperatureV2_found = True
    except ImportError:
        BrickletTemperatureV2_found = False
    try:
        from brickv.bindings.bricklet_temperature_ir import BrickletTemperatureIR
        BrickletTemperatureIR_found = True
    except ImportError:
        BrickletTemperatureIR_found = False
    try:
        from brickv.bindings.bricklet_temperature_ir_v2 import BrickletTemperatureIRV2
        BrickletTemperatureIRV2_found = True
    except ImportError:
        BrickletTemperatureIRV2_found = False
    try:
        from brickv.bindings.bricklet_thermal_imaging import BrickletThermalImaging
        BrickletThermalImaging_found = True
    except ImportError:
        BrickletThermalImaging_found = False
    try:
        from brickv.bindings.bricklet_thermocouple import BrickletThermocouple
        BrickletThermocouple_found = True
    except ImportError:
        BrickletThermocouple_found = False
    try:
        from brickv.bindings.bricklet_thermocouple_v2 import BrickletThermocoupleV2
        BrickletThermocoupleV2_found = True
    except ImportError:
        BrickletThermocoupleV2_found = False
    try:
        from brickv.bindings.bricklet_tilt import BrickletTilt
        BrickletTilt_found = True
    except ImportError:
        BrickletTilt_found = False
    try:
        from brickv.bindings.bricklet_uv_light import BrickletUVLight
        BrickletUVLight_found = True
    except ImportError:
        BrickletUVLight_found = False
    try:
        from brickv.bindings.bricklet_uv_light_v2 import BrickletUVLightV2
        BrickletUVLightV2_found = True
    except ImportError:
        BrickletUVLightV2_found = False
    try:
        from brickv.bindings.bricklet_voltage import BrickletVoltage
        BrickletVoltage_found = True
    except ImportError:
        BrickletVoltage_found = False
    try:
        from brickv.bindings.bricklet_voltage_current import BrickletVoltageCurrent
        BrickletVoltageCurrent_found = True
    except ImportError:
        BrickletVoltageCurrent_found = False
    try:
        from brickv.bindings.bricklet_voltage_current_v2 import BrickletVoltageCurrentV2
        BrickletVoltageCurrentV2_found = True
    except ImportError:
        BrickletVoltageCurrentV2_found = False
else:
    # Bricks
    try:
        from tinkerforge.brick_dc import BrickDC
        BrickDC_found = True
    except ImportError:
        BrickDC_found = False
    try:
        from tinkerforge.brick_imu import BrickIMU
        BrickIMU_found = True
    except ImportError:
        BrickIMU_found = False
    try:
        from tinkerforge.brick_imu_v2 import BrickIMUV2
        BrickIMUV2_found = True
    except ImportError:
        BrickIMUV2_found = False
    try:
        from tinkerforge.brick_master import BrickMaster
        BrickMaster_found = True
    except ImportError:
        BrickMaster_found = False
    try:
        from tinkerforge.brick_servo import BrickServo
        BrickServo_found = True
    except ImportError:
        BrickServo_found = False
    try:
        from tinkerforge.brick_silent_stepper import BrickSilentStepper
        BrickSilentStepper_found = True
    except ImportError:
        BrickSilentStepper_found = False
    try:
        from tinkerforge.brick_stepper import BrickStepper
        BrickStepper_found = True
    except ImportError:
        BrickStepper_found = False
    try:
        from tinkerforge.brick_hat import BrickHAT
        BrickHAT_found = True
    except ImportError:
        BrickHAT_found = False
    try:
        from tinkerforge.brick_hat_zero import BrickHATZero
        BrickHATZero_found = True
    except ImportError:
        BrickHATZero_found = False

    # Bricklets
    try:
        from tinkerforge.bricklet_accelerometer import BrickletAccelerometer
        BrickletAccelerometer_found = True
    except ImportError:
        BrickletAccelerometer_found = False
    try:
        from tinkerforge.bricklet_accelerometer_v2 import BrickletAccelerometerV2
        BrickletAccelerometerV2_found = True
    except ImportError:
        BrickletAccelerometerV2_found = False
    try:
        from tinkerforge.bricklet_air_quality import BrickletAirQuality
        BrickletAirQuality_found = True
    except ImportError:
        BrickletAirQuality_found = False
    try:
        from tinkerforge.bricklet_ambient_light import BrickletAmbientLight
        BrickletAmbientLight_found = True
    except ImportError:
        BrickletAmbientLight_found = False
    try:
        from tinkerforge.bricklet_ambient_light_v2 import BrickletAmbientLightV2
        BrickletAmbientLightV2_found = True
    except ImportError:
        BrickletAmbientLightV2_found = False
    try:
        from tinkerforge.bricklet_ambient_light_v3 import BrickletAmbientLightV3
        BrickletAmbientLightV3_found = True
    except ImportError:
        BrickletAmbientLightV3_found = False
    try:
        from tinkerforge.bricklet_analog_in import BrickletAnalogIn
        BrickletAnalogIn_found = True
    except ImportError:
        BrickletAnalogIn_found = False
    try:
        from tinkerforge.bricklet_analog_in_v2 import BrickletAnalogInV2
        BrickletAnalogInV2_found = True
    except ImportError:
        BrickletAnalogInV2_found = False
    try:
        from tinkerforge.bricklet_analog_in_v3 import BrickletAnalogInV3
        BrickletAnalogInV3_found = True
    except ImportError:
        BrickletAnalogInV3_found = False
    try:
        from tinkerforge.bricklet_analog_out_v2 import BrickletAnalogOutV2
        BrickletAnalogOutV2_found = True
    except ImportError:
        BrickletAnalogOutV2_found = False
    try:
        from tinkerforge.bricklet_analog_out_v3 import BrickletAnalogOutV3
        BrickletAnalogOutV3_found = True
    except ImportError:
        BrickletAnalogOutV3_found = False
    try:
        from tinkerforge.bricklet_barometer import BrickletBarometer
        BrickletBarometer_found = True
    except ImportError:
        BrickletBarometer_found = False
    try:
        from tinkerforge.bricklet_barometer_v2 import BrickletBarometerV2
        BrickletBarometerV2_found = True
    except ImportError:
        BrickletBarometerV2_found = False
    try:
        from tinkerforge.bricklet_can import BrickletCAN #NYI FIXME: has to use frame_read callback to get all data
        BrickletCAN_found = True
    except ImportError:
        BrickletCAN_found = False
    try:
        from tinkerforge.bricklet_can_v2 import BrickletCANV2 #NYI FIXME: has to use frame_read callback to get all data
        BrickletCANV2_found = True
    except ImportError:
        BrickletCANV2_found = False
    try:
        from tinkerforge.bricklet_co2 import BrickletCO2
        BrickletCO2_found = True
    except ImportError:
        BrickletCO2_found = False
    try:
        from tinkerforge.bricklet_co2_v2 import BrickletCO2V2
        BrickletCO2V2_found = True
    except ImportError:
        BrickletCO2V2_found = False
    try:
        from tinkerforge.bricklet_color import BrickletColor
        BrickletColor_found = True
    except ImportError:
        BrickletColor_found = False
    try:
        from tinkerforge.bricklet_color_v2 import BrickletColorV2
        BrickletColorV2_found = True
    except ImportError:
        BrickletColorV2_found = False
    try:
        from tinkerforge.bricklet_compass import BrickletCompass
        BrickletCompass_found = True
    except ImportError:
        BrickletCompass_found = False
    try:
        from tinkerforge.bricklet_current12 import BrickletCurrent12
        BrickletCurrent12_found = True
    except ImportError:
        BrickletCurrent12_found = False
    try:
        from tinkerforge.bricklet_current25 import BrickletCurrent25
        BrickletCurrent25_found = True
    except ImportError:
        BrickletCurrent25_found = False
    try:
        from tinkerforge.bricklet_dc_v2 import BrickletDCV2
        BrickletDCV2_found = True
    except ImportError:
        BrickletDCV2_found = False
    try:
        from tinkerforge.bricklet_distance_ir import BrickletDistanceIR
        BrickletDistanceIR_found = True
    except ImportError:
        BrickletDistanceIR_found = False
    try:
        from tinkerforge.bricklet_distance_ir_v2 import BrickletDistanceIRV2
        BrickletDistanceIRV2_found = True
    except ImportError:
        BrickletDistanceIRV2_found = False
    try:
        from tinkerforge.bricklet_distance_us import BrickletDistanceUS
        BrickletDistanceUS_found = True
    except ImportError:
        BrickletDistanceUS_found = False
    try:
        from tinkerforge.bricklet_distance_us_v2 import BrickletDistanceUSV2
        BrickletDistanceUSV2_found = True
    except ImportError:
        BrickletDistanceUSV2_found = False
    try:
        from tinkerforge.bricklet_dmx import BrickletDMX
        BrickletDMX_found = True
    except ImportError:
        BrickletDMX_found = False
    try:
        from tinkerforge.bricklet_dual_button import BrickletDualButton
        BrickletDualButton_found = True
    except ImportError:
        BrickletDualButton_found = False
    try:
        from tinkerforge.bricklet_dual_button_v2 import BrickletDualButtonV2
        BrickletDualButtonV2_found = True
    except ImportError:
        BrickletDualButtonV2_found = False
    try:
        from tinkerforge.bricklet_dual_relay import BrickletDualRelay
        BrickletDualRelay_found = True
    except ImportError:
        BrickletDualRelay_found = False
    try:
        from tinkerforge.bricklet_dust_detector import BrickletDustDetector
        BrickletDustDetector_found = True
    except ImportError:
        BrickletDustDetector_found = False
    try:
        from tinkerforge.bricklet_energy_monitor import BrickletEnergyMonitor
        BrickletEnergyMonitor_found = True
    except ImportError:
        BrickletEnergyMonitor_found = False
    try:
        from tinkerforge.bricklet_gps import BrickletGPS
        BrickletGPS_found = True
    except ImportError:
        BrickletGPS_found = False
    try:
        from tinkerforge.bricklet_gps_v2 import BrickletGPSV2
        BrickletGPSV2_found = True
    except ImportError:
        BrickletGPSV2_found = False
    try:
        from tinkerforge.bricklet_gps_v3 import BrickletGPSV3
        BrickletGPSV3_found = True
    except ImportError:
        BrickletGPSV3_found = False
    try:
        from tinkerforge.bricklet_hall_effect import BrickletHallEffect
        BrickletHallEffect_found = True
    except ImportError:
        BrickletHallEffect_found = False
    try:
        from tinkerforge.bricklet_hall_effect_v2 import BrickletHallEffectV2
        BrickletHallEffectV2_found = True
    except ImportError:
        BrickletHallEffectV2_found = False
    try:
        from tinkerforge.bricklet_humidity import BrickletHumidity
        BrickletHumidity_found = True
    except ImportError:
        BrickletHumidity_found = False
    try:
        from tinkerforge.bricklet_humidity_v2 import BrickletHumidityV2
        BrickletHumidityV2_found = True
    except ImportError:
        BrickletHumidityV2_found = False
    try:
        from tinkerforge.bindings.bricklet_imu_v3 import BrickletIMUV3
        BrickletIMUV3_found = True
    except ImportError:
        BrickletIMUV3_found = False
    try:
        from tinkerforge.bricklet_industrial_counter import BrickletIndustrialCounter
        BrickletIndustrialCounter_found = True
    except ImportError:
        BrickletIndustrialCounter_found = False
    try:
        from tinkerforge.bricklet_industrial_digital_in_4 import BrickletIndustrialDigitalIn4
        BrickletIndustrialDigitalIn4_found = True
    except ImportError:
        BrickletIndustrialDigitalIn4_found = False
    try:
        from tinkerforge.bricklet_industrial_digital_in_4_v2 import BrickletIndustrialDigitalIn4V2
        BrickletIndustrialDigitalIn4V2_found = True
    except ImportError:
        BrickletIndustrialDigitalIn4V2_found = False
    try:
        from tinkerforge.bricklet_industrial_dual_0_20ma import BrickletIndustrialDual020mA
        BrickletIndustrialDual020mA_found = True
    except ImportError:
        BrickletIndustrialDual020mA_found = False
    try:
        from tinkerforge.bricklet_industrial_dual_0_20ma_v2 import BrickletIndustrialDual020mAV2
        BrickletIndustrialDual020mAV2_found = True
    except ImportError:
        BrickletIndustrialDual020mAV2_found = False
    try:
        from tinkerforge.bricklet_industrial_dual_ac_relay import BrickletIndustrialDualACRelay
        BrickletIndustrialDualACRelay_found = True
    except ImportError:
        BrickletIndustrialDualACRelay_found = False
    try:
        from tinkerforge.bricklet_industrial_dual_analog_in import BrickletIndustrialDualAnalogIn
        BrickletIndustrialDualAnalogIn_found = True
    except ImportError:
        BrickletIndustrialDualAnalogIn_found = False
    try:
        from tinkerforge.bricklet_industrial_dual_analog_in_v2 import BrickletIndustrialDualAnalogInV2
        BrickletIndustrialDualAnalogInV2_found = True
    except ImportError:
        BrickletIndustrialDualAnalogInV2_found = False
    try:
        from tinkerforge.bricklet_industrial_dual_relay import BrickletIndustrialDualRelay
        BrickletIndustrialDualRelay_found = True
    except ImportError:
        BrickletIndustrialDualRelay_found = False
    try:
        from tinkerforge.bricklet_industrial_ptc import BrickletIndustrialPTC
        BrickletIndustrialPTC_found = True
    except ImportError:
        BrickletIndustrialPTC_found = False
    try:
        from tinkerforge.bricklet_industrial_quad_relay import BrickletIndustrialQuadRelay
        BrickletIndustrialQuadRelay_found = True
    except ImportError:
        BrickletIndustrialQuadRelay_found = False
    try:
        from tinkerforge.bricklet_industrial_quad_relay_v2 import BrickletIndustrialQuadRelayV2
        BrickletIndustrialQuadRelayV2_found = True
    except ImportError:
        BrickletIndustrialQuadRelayV2_found = False
    try:
        from tinkerforge.bricklet_io16 import BrickletIO16
        BrickletIO16_found = True
    except ImportError:
        BrickletIO16_found = False
    try:
        from tinkerforge.bricklet_io16_v2 import BrickletIO16V2
        BrickletIO16V2_found = True
    except ImportError:
        BrickletIO16V2_found = False
    try:
        from tinkerforge.bricklet_io4 import BrickletIO4
        BrickletIO4_found = True
    except ImportError:
        BrickletIO4_found = False
    try:
        from tinkerforge.bricklet_io4_v2 import BrickletIO4V2
        BrickletIO4V2_found = True
    except ImportError:
        BrickletIO4V2_found = False
    try:
        from tinkerforge.bricklet_joystick import BrickletJoystick
        BrickletJoystick_found = True
    except ImportError:
        BrickletJoystick_found = False
    try:
        from tinkerforge.bricklet_joystick_v2 import BrickletJoystickV2
        BrickletJoystickV2_found = True
    except ImportError:
        BrickletJoystickV2_found = False
    try:
        from tinkerforge.bricklet_laser_range_finder import BrickletLaserRangeFinder #NYI # config: mode, FIXME: special laser handling
        BrickletLaserRangeFinder_found = True
    except ImportError:
        BrickletLaserRangeFinder_found = False
    try:
        from tinkerforge.bricklet_laser_range_finder_v2 import BrickletLaserRangeFinderV2 #NYI # config: mode, FIXME: special laser handling
        BrickletLaserRangeFinderV2_found = True
    except ImportError:
        BrickletLaserRangeFinderV2_found = False
    try:
        from tinkerforge.bricklet_led_strip import BrickletLEDStrip
        BrickletLEDStrip_found = True
    except ImportError:
        BrickletLEDStrip_found = False
    try:
        from tinkerforge.bricklet_led_strip_v2 import BrickletLEDStripV2
        BrickletLEDStripV2_found = True
    except ImportError:
        BrickletLEDStripV2_found = False
    try:
        from tinkerforge.bricklet_line import BrickletLine
        BrickletLine_found = True
    except ImportError:
        BrickletLine_found = False
    try:
        from tinkerforge.bricklet_linear_poti import BrickletLinearPoti
        BrickletLinearPoti_found = True
    except ImportError:
        BrickletLinearPoti_found = False
    try:
        from tinkerforge.bricklet_linear_poti_v2 import BrickletLinearPotiV2
        BrickletLinearPotiV2_found = True
    except ImportError:
        BrickletLinearPotiV2_found = False
    try:
        from tinkerforge.bricklet_load_cell import BrickletLoadCell
        BrickletLoadCell_found = True
    except ImportError:
        BrickletLoadCell_found = False
    try:
        from tinkerforge.bricklet_load_cell_v2 import BrickletLoadCellV2
        BrickletLoadCellV2_found = True
    except ImportError:
        BrickletLoadCellV2_found = False
    try:
        from tinkerforge.bricklet_moisture import BrickletMoisture
        BrickletMoisture_found = True
    except ImportError:
        BrickletMoisture_found = False
    try:
        from tinkerforge.bricklet_motion_detector import BrickletMotionDetector
        BrickletMotionDetector_found = True
    except ImportError:
        BrickletMotionDetector_found = False
    try:
        from tinkerforge.bricklet_motion_detector_v2 import BrickletMotionDetectorV2
        BrickletMotionDetectorV2_found = True
    except ImportError:
        BrickletMotionDetectorV2_found = False
    try:
        from tinkerforge.bricklet_motorized_linear_poti import BrickletMotorizedLinearPoti
        BrickletMotorizedLinearPoti_found = True
    except ImportError:
        BrickletMotorizedLinearPoti_found = False
    try:
        from tinkerforge.bricklet_multi_touch import BrickletMultiTouch
        BrickletMultiTouch_found = True
    except ImportError:
        BrickletMultiTouch_found = False
    try:
        from tinkerforge.bricklet_multi_touch_v2 import BrickletMultiTouchV2
        BrickletMultiTouchV2_found = True
    except ImportError:
        BrickletMultiTouchV2_found = False
    try:
        from tinkerforge.bricklet_nfc import BrickletNFC
        BrickletNFC_found = True
    except ImportError:
        BrickletNFC_found = False
    try:
        from tinkerforge.bricklet_nfc_rfid import BrickletNFCRFID
        BrickletNFCRFID_found = True
    except ImportError:
        BrickletNFCRFID_found = False
    try:
        from tinkerforge.bricklet_outdoor_weather import BrickletOutdoorWeather
        BrickletOutdoorWeather_found = True
    except ImportError:
        BrickletOutdoorWeather_found = False
    try:
        from tinkerforge.bricklet_particulate_matter import BrickletParticulateMatter
        BrickletParticulateMatter_found = True
    except ImportError:
        BrickletParticulateMatter_found = False
    try:
        from tinkerforge.bricklet_performance_dc import BrickletPerformanceDC
        BrickletPerformanceDC_found = True
    except ImportError:
        BrickletPerformanceDC_found = False
    try:
        from tinkerforge.bricklet_ptc import BrickletPTC
        BrickletPTC_found = True
    except ImportError:
        BrickletPTC_found = False
    try:
        from tinkerforge.bricklet_ptc_v2 import BrickletPTCV2
        BrickletPTCV2_found = True
    except ImportError:
        BrickletPTCV2_found = False
    try:
        from tinkerforge.bricklet_real_time_clock import BrickletRealTimeClock
        BrickletRealTimeClock_found = True
    except ImportError:
        BrickletRealTimeClock_found = False
    try:
        from tinkerforge.bricklet_real_time_clock_v2 import BrickletRealTimeClockV2
        BrickletRealTimeClockV2_found = True
    except ImportError:
        BrickletRealTimeClockV2_found = False
    try:
        from tinkerforge.bricklet_remote_switch import BrickletRemoteSwitch
        BrickletRemoteSwitch_found = True
    except ImportError:
        BrickletRemoteSwitch_found = False
    try:
        from tinkerforge.bricklet_remote_switch_v2 import BrickletRemoteSwitchV2
        BrickletRemoteSwitchV2_found = True
    except ImportError:
        BrickletRemoteSwitchV2_found = False
    try:
        from tinkerforge.bricklet_rgb_led_button import BrickletRGBLEDButton
        BrickletRGBLEDButton_found = True
    except ImportError:
        BrickletRGBLEDButton_found = False
    try:
        from tinkerforge.bricklet_rgb_led_matrix import BrickletRGBLEDMatrix
        BrickletRGBLEDMatrix_found = True
    except ImportError:
        BrickletRGBLEDMatrix_found = False
    try:
        from tinkerforge.bricklet_rotary_encoder import BrickletRotaryEncoder
        BrickletRotaryEncoder_found = True
    except ImportError:
        BrickletRotaryEncoder_found = False
    try:
        from tinkerforge.bricklet_rotary_encoder_v2 import BrickletRotaryEncoderV2
        BrickletRotaryEncoderV2_found = True
    except ImportError:
        BrickletRotaryEncoderV2_found = False
    try:
        from tinkerforge.bricklet_rotary_poti import BrickletRotaryPoti
        BrickletRotaryPoti_found = True
    except ImportError:
        BrickletRotaryPoti_found = False
    try:
        from tinkerforge.bricklet_rotary_poti_v2 import BrickletRotaryPotiV2
        BrickletRotaryPotiV2_found = True
    except ImportError:
        BrickletRotaryPotiV2_found = False
    # from tinkerforge.bricklet_rs232 import BrickletRS232 #NYI FIXME: has to use read_callback callback to get all data
    try:
        from tinkerforge.bricklet_rs232_v2 import BrickletRS232V2
        BrickletRS232V2_found = True
    except ImportError:
        BrickletRS232V2_found = False
    try:
        from tinkerforge.bricklet_rs485 import BrickletRS485
        BrickletRS485_found = True
    except ImportError:
        BrickletRS485_found = False
    try:
        from tinkerforge.bricklet_segment_display_4x7 import BrickletSegmentDisplay4x7
        BrickletSegmentDisplay4x7_found = True
    except ImportError:
        BrickletSegmentDisplay4x7_found = False
    try:
        from tinkerforge.bricklet_segment_display_4x7_v2 import BrickletSegmentDisplay4x7V2
        BrickletSegmentDisplay4x7V2_found = True
    except ImportError:
        BrickletSegmentDisplay4x7V2_found = False
    try:
        from tinkerforge.bricklet_servo_v2 import BrickletServoV2
        BrickletServoV2_found = True
    except ImportError:
        BrickletServoV2_found = False
    try:
        from tinkerforge.bricklet_silent_stepper_v2 import BrickletSilentStepperV2
        BrickletSilentStepperV2_found = True
    except ImportError:
        BrickletSilentStepperV2_found = False
    try:
        from tinkerforge.bricklet_solid_state_relay import BrickletSolidStateRelay
        BrickletSolidStateRelay_found = True
    except ImportError:
        BrickletSolidStateRelay_found = False
    try:
        from tinkerforge.bricklet_solid_state_relay_v2 import BrickletSolidStateRelayV2
        BrickletSolidStateRelayV2_found = True
    except ImportError:
        BrickletSolidStateRelayV2_found = False
    try:
        from tinkerforge.bricklet_sound_intensity import BrickletSoundIntensity
        BrickletSoundIntensity_found = True
    except ImportError:
        BrickletSoundIntensity_found = False
    try:
        from tinkerforge.bricklet_sound_pressure_level import BrickletSoundPressureLevel
        BrickletSoundPressureLevel_found = True
    except ImportError:
        BrickletSoundPressureLevel_found = False
    try:
        from tinkerforge.bricklet_temperature import BrickletTemperature
        BrickletTemperature_found = True
    except ImportError:
        BrickletTemperature_found = False
    try:
        from tinkerforge.bricklet_temperature_v2 import BrickletTemperatureV2
        BrickletTemperatureV2_found = True
    except ImportError:
        BrickletTemperatureV2_found = False
    try:
        from tinkerforge.bricklet_temperature_ir import BrickletTemperatureIR
        BrickletTemperatureIR_found = True
    except ImportError:
        BrickletTemperatureIR_found = False
    try:
        from tinkerforge.bricklet_temperature_ir_v2 import BrickletTemperatureIRV2
        BrickletTemperatureIRV2_found = True
    except ImportError:
        BrickletTemperatureIRV2_found = False
    try:
        from tinkerforge.bricklet_thermal_imaging import BrickletThermalImaging
        BrickletThermalImaging_found = True
    except ImportError:
        BrickletThermalImaging_found = False
    try:
        from tinkerforge.bricklet_thermocouple import BrickletThermocouple
        BrickletThermocouple_found = True
    except ImportError:
        BrickletThermocouple_found = False
    try:
        from tinkerforge.bricklet_thermocouple_v2 import BrickletThermocoupleV2
        BrickletThermocoupleV2_found = True
    except ImportError:
        BrickletThermocoupleV2_found = False
    try:
        from tinkerforge.bricklet_tilt import BrickletTilt
        BrickletTilt_found = True
    except ImportError:
        BrickletTilt_found = False
    try:
        from tinkerforge.bricklet_uv_light import BrickletUVLight
        BrickletUVLight_found = True
    except ImportError:
        BrickletUVLight_found = False
    try:
        from tinkerforge.bricklet_uv_light_v2 import BrickletUVLightV2
        BrickletUVLightV2_found = True
    except ImportError:
        BrickletUVLightV2_found = False
    try:
        from tinkerforge.bricklet_voltage import BrickletVoltage
        BrickletVoltage_found = True
    except ImportError:
        BrickletVoltage_found = False
    try:
        from tinkerforge.bricklet_voltage_current import BrickletVoltageCurrent
        BrickletVoltageCurrent_found = True
    except ImportError:
        BrickletVoltageCurrent_found = False
    try:
        from tinkerforge.bricklet_voltage_current_v2 import BrickletVoltageCurrentV2
        BrickletVoltageCurrentV2_found = True
    except ImportError:
        BrickletVoltageCurrentV2_found = False

def value_to_bits(value, length):
    bits = []

    for i in range(length):
        if (value & (1 << i)) != 0:
            bits.append(1)
        else:
            bits.append(0)

    return bits

# special_* functions are for special Bricks/Bricklets. Some device functions can
# return different values, depending on different situations, e.g. the GPS Bricklet.
# If the GPS Bricklet does not have a fix, then the function will return an Error
# instead of the specified return values.

# BrickletColor
def special_get_color_illuminance(device):
    gain, integration_time = device.get_config()

    if gain == device.GAIN_1X:
        gain_factor = 1
    elif gain == device.GAIN_4X:
        gain_factor = 4
    elif gain == device.GAIN_16X:
        gain_factor = 16
    elif gain == device.GAIN_60X:
        gain_factor = 60

    if integration_time == device.INTEGRATION_TIME_2MS:
        integration_time_factor = 2.4
    elif integration_time == device.INTEGRATION_TIME_24MS:
        integration_time_factor = 24
    elif integration_time == device.INTEGRATION_TIME_101MS:
        integration_time_factor = 101
    elif integration_time == device.INTEGRATION_TIME_154MS:
        integration_time_factor = 154
    elif integration_time == device.INTEGRATION_TIME_700MS:
        integration_time_factor = 700

    illuminance = device.get_illuminance()

    return int(round(illuminance * 700.0 / float(gain_factor) / float(integration_time_factor), 1) * 10)

# BrickletColorV2
def special_get_color_v2_illuminance(device):
    gain, integration_time = device.get_configuration()

    if gain == device.GAIN_1X:
        gain_factor = 1
    elif gain == device.GAIN_4X:
        gain_factor = 4
    elif gain == device.GAIN_16X:
        gain_factor = 16
    elif gain == device.GAIN_60X:
        gain_factor = 60

    if integration_time == device.INTEGRATION_TIME_2MS:
        integration_time_factor = 2.4
    elif integration_time == device.INTEGRATION_TIME_24MS:
        integration_time_factor = 24
    elif integration_time == device.INTEGRATION_TIME_101MS:
        integration_time_factor = 101
    elif integration_time == device.INTEGRATION_TIME_154MS:
        integration_time_factor = 154
    elif integration_time == device.INTEGRATION_TIME_700MS:
        integration_time_factor = 700

    illuminance = device.get_illuminance()

    return int(round(illuminance * 700.0 / float(gain_factor) / float(integration_time_factor), 1) * 10)

# BrickletGPS
def special_get_gps_coordinates(device):
    if device.get_status()[0] == device.FIX_NO_FIX:
        raise Exception('No fix')

    return device.get_coordinates()

def special_get_gps_altitude(device):
    if device.get_status()[0] != device.FIX_3D_FIX:
        raise Exception('No 3D fix')

    return device.get_altitude()

def special_get_gps_motion(device):
    if device.get_status()[0] == device.FIX_NO_FIX:
        raise Exception('No fix')

    return device.get_motion()

# BrickletGPSV2
def special_get_gps_v2_coordinates(device):
    if device.get_satellite_system_status(device.SATELLITE_SYSTEM_GPS).fix == device.FIX_NO_FIX:
        raise Exception('No fix')

    return device.get_coordinates()

def special_get_gps_v2_altitude(device):
    if device.get_satellite_system_status(device.SATELLITE_SYSTEM_GPS).fix != device.FIX_3D_FIX:
        raise Exception('No 3D fix')

    return device.get_altitude()

def special_get_gps_v2_motion(device):
    if device.get_satellite_system_status(device.SATELLITE_SYSTEM_GPS).fix == device.FIX_NO_FIX:
        raise Exception('No fix')

    return device.get_motion()

# BrickletGPSV3
def special_get_gps_v3_coordinates(device):
    if device.get_satellite_system_status(device.SATELLITE_SYSTEM_GPS).fix == device.FIX_NO_FIX:
        raise Exception('No fix')

    return device.get_coordinates()

def special_get_gps_v3_altitude(device):
    if device.get_satellite_system_status(device.SATELLITE_SYSTEM_GPS).fix != device.FIX_3D_FIX:
        raise Exception('No 3D fix')

    return device.get_altitude()

def special_get_gps_v3_motion(device):
    if device.get_satellite_system_status(device.SATELLITE_SYSTEM_GPS).fix == device.FIX_NO_FIX:
        raise Exception('No fix')

    return device.get_motion()

# BrickletMultiTouch
def special_set_multi_touch_options(device, electrode0, electrode1, electrode2, electrode3,
                                    electrode4, electrode5, electrode6, electrode7,
                                    electrode8, electrode9, electrode10, electrode11,
                                    proximity, electrode_sensitivity):
    electrode_config = 0

    if electrode0:
        electrode_config |= 1 << 0

    if electrode1:
        electrode_config |= 1 << 1

    if electrode2:
        electrode_config |= 1 << 2

    if electrode3:
        electrode_config |= 1 << 3

    if electrode4:
        electrode_config |= 1 << 4

    if electrode5:
        electrode_config |= 1 << 5

    if electrode6:
        electrode_config |= 1 << 6

    if electrode7:
        electrode_config |= 1 << 7

    if electrode8:
        electrode_config |= 1 << 8

    if electrode9:
        electrode_config |= 1 << 9

    if electrode10:
        electrode_config |= 1 << 10

    if electrode11:
        electrode_config |= 1 << 11

    if proximity:
        electrode_config |= 1 << 12

    device.set_electrode_config(electrode_config)
    device.set_electrode_sensitivity(electrode_sensitivity)

if BrickletOutdoorWeather_found:
    # BrickletOutdoorWeather
    outdoor_weather_wind_direction_names = {
        BrickletOutdoorWeather.WIND_DIRECTION_N: 'N',
        BrickletOutdoorWeather.WIND_DIRECTION_NNE: 'NNE',
        BrickletOutdoorWeather.WIND_DIRECTION_NE: 'NE',
        BrickletOutdoorWeather.WIND_DIRECTION_ENE: 'ENE',
        BrickletOutdoorWeather.WIND_DIRECTION_E: 'E',
        BrickletOutdoorWeather.WIND_DIRECTION_ESE: 'ESE',
        BrickletOutdoorWeather.WIND_DIRECTION_SE: 'SE',
        BrickletOutdoorWeather.WIND_DIRECTION_SSE: 'SSE',
        BrickletOutdoorWeather.WIND_DIRECTION_S: 'S',
        BrickletOutdoorWeather.WIND_DIRECTION_SSW: 'SSW',
        BrickletOutdoorWeather.WIND_DIRECTION_SW: 'SW',
        BrickletOutdoorWeather.WIND_DIRECTION_WSW: 'WSW',
        BrickletOutdoorWeather.WIND_DIRECTION_W: 'W',
        BrickletOutdoorWeather.WIND_DIRECTION_WNW: 'WNW',
        BrickletOutdoorWeather.WIND_DIRECTION_NW: 'NW',
        BrickletOutdoorWeather.WIND_DIRECTION_NNW: 'NNW',
        BrickletOutdoorWeather.WIND_DIRECTION_ERROR: 'Wind Direction Error',
    }

    OutdoorWeatherGetStationData = namedtuple('StationData',
                                              ['temperature',
                                               'humidity',
                                               'wind_speed',
                                               'gust_speed',
                                               'rain',
                                               'wind_direction',
                                               'battery_low',
                                               'last_change'])

    def special_get_outdoor_weather_station_data(device):
        station_ids = device.get_station_identifiers()

        if len(station_ids) < 1:
            raise Exception('No stations found')

        keyed_station_data = {}

        for station_id in station_ids:
            station_data = device.get_station_data(station_id)

            keyed_station_data[str(station_id)] = OutdoorWeatherGetStationData(temperature=station_data.temperature,
                                                                               humidity=station_data.humidity,
                                                                               wind_speed=station_data.wind_speed,
                                                                               gust_speed=station_data.gust_speed,
                                                                               rain=station_data.rain,
                                                                               wind_direction=outdoor_weather_wind_direction_names[station_data.wind_direction],
                                                                               battery_low=station_data.battery_low,
                                                                               last_change=station_data.last_change)

        return keyed_station_data

    def special_get_outdoor_weather_sensor_data(device):
        sensor_ids = device.get_sensor_identifiers()

        if len(sensor_ids) < 1:
            raise Exception('No sensors found')

        keyed_sensor_data = {}

        for sensor_id in sensor_ids:
            keyed_sensor_data[str(sensor_id)] = device.get_sensor_data(sensor_id)

        return keyed_sensor_data

# Bricklet(Industrial)PTC(V2)
def special_get_ptc_resistance(device):
    if not device.is_sensor_connected():
        raise Exception('No sensor')

    return device.get_resistance()

# Bricklet(Industrial)PTC(V2)
def special_get_ptc_temperature(device):
    if not device.is_sensor_connected():
        raise Exception('No sensor')

    return device.get_temperature()

# BrickletLaserRangeFinderV2
def special_set_laser_range_finder_v2_configuration(device, enable, acquisition_count, enable_quick_termination, threshold_value, enable_auto_freq, measurement_frequency):
    device.set_enable(enable)
    device.set_configuration(acquisition_count, enable_quick_termination, threshold_value, measurement_frequency if not enable_auto_freq else 0)

# BrickletRS232V2
rs232_v2_read_buffers = {}

def rs232_v2_to_ascii(s):
    ascii_ = ''

    for c in s:
        if (ord(c) < 32 or ord(c) > 126) and ord(c) not in (10, 13):
            ascii_ += '.'
        else:
            ascii_ += c
    return ascii_.replace('\\', '\\\\').replace('\n', '\\n').replace('\r', '\\r')

def rs232_v2_to_hextext(s):
    return ' '.join('{:02X}'.format(ord(c)) for c in s) + ' '

def special_rs232_v2_initialize(device, baudrate, parity, stopbits, wordlength, flowcontrol, ascii_):
    rs232_v2_read_buffers[device.uid] = Queue()

    if ascii_:
        device.register_callback(device.CALLBACK_READ, lambda message: rs232_v2_read_buffers[device.uid].put(rs232_v2_to_ascii(message)))
    else:
        device.register_callback(device.CALLBACK_READ, lambda message: rs232_v2_read_buffers[device.uid].put(rs232_v2_to_hextext(message)))

    device.set_configuration(baudrate, parity, stopbits, wordlength, flowcontrol)
    device.enable_read_callback()

def special_rs232_v2_get_input(device):
    queue = rs232_v2_read_buffers[device.uid]
    result = []

    try:
        while True:
            result += queue.get_nowait()
    except Empty:
        return ''.join(result)

device_specs = {}

if BrickletAccelerometer_found:
    device_specs[BrickletAccelerometer.DEVICE_DISPLAY_NAME] = {
        'class': BrickletAccelerometer,
        'values': [
            {
                'name': 'Acceleration',
                'getter': lambda device: device.get_acceleration(),
                'subvalues': ['X', 'Y', 'Z'],
                'unit': ['g/1000', 'g/1000', 'g/1000'],
                'advanced': False
            },
            {
                'name': 'Temperature',
                'getter': lambda device: device.get_temperature(),
                'subvalues': None,
                'unit': '°C',
                'advanced': True
            }
        ],
        'options_setter': lambda device, data_rate, full_scale, filter_bandwidth: device.set_configuration(data_rate, full_scale, filter_bandwidth),
        'options': [
            {
                'name': 'Data Rate',
                'type': 'choice',
                'values': [('Off', BrickletAccelerometer.DATA_RATE_OFF),
                           ('3Hz', BrickletAccelerometer.DATA_RATE_3HZ),
                           ('6Hz', BrickletAccelerometer.DATA_RATE_6HZ),
                           ('12Hz', BrickletAccelerometer.DATA_RATE_12HZ),
                           ('25Hz', BrickletAccelerometer.DATA_RATE_25HZ),
                           ('50Hz', BrickletAccelerometer.DATA_RATE_50HZ),
                           ('100Hz', BrickletAccelerometer.DATA_RATE_100HZ),
                           ('400Hz', BrickletAccelerometer.DATA_RATE_400HZ),
                           ('800Hz', BrickletAccelerometer.DATA_RATE_800HZ),
                           ('1600Hz', BrickletAccelerometer.DATA_RATE_1600HZ)],
                'default': '100Hz'
            },
            {
                'name': 'Full Scale',
                'type': 'choice',
                'values': [('2g', BrickletAccelerometer.FULL_SCALE_2G),
                           ('4g', BrickletAccelerometer.FULL_SCALE_4G),
                           ('6g', BrickletAccelerometer.FULL_SCALE_6G),
                           ('8g', BrickletAccelerometer.FULL_SCALE_8G),
                           ('16g', BrickletAccelerometer.FULL_SCALE_16G)],
                'default': '4g'
            },
            {
                'name': 'Filter Bandwidth',
                'type': 'choice',
                'values': [('800Hz', BrickletAccelerometer.FILTER_BANDWIDTH_800HZ),
                           ('400Hz', BrickletAccelerometer.FILTER_BANDWIDTH_400HZ),
                           ('200Hz', BrickletAccelerometer.FILTER_BANDWIDTH_200HZ),
                           ('50Hz', BrickletAccelerometer.FILTER_BANDWIDTH_50HZ)],
                'default': '200Hz'
            }
        ]
    }
if BrickletAccelerometerV2_found:
    device_specs[BrickletAccelerometerV2.DEVICE_DISPLAY_NAME] = {
        'class': BrickletAccelerometerV2,
        'values': [
            {
                'name': 'Acceleration',
                'getter': lambda device: device.get_acceleration(),
                'subvalues': ['X', 'Y', 'Z'],
                'unit': ['g/10000', 'g/10000', 'g/10000'],
                'advanced': False
            },
            {
                'name': 'Chip Temperature',
                'getter': lambda device: device.get_chip_temperature(),
                'subvalues': None,
                'unit': '°C',
                'advanced': True
            }
        ],
        'options_setter': lambda device, data_rate, full_scale: device.set_configuration(data_rate, full_scale),
        'options': [
            {
                'name': 'Data Rate',
                'type': 'choice',
                'values': [('0.781Hz', BrickletAccelerometerV2.DATA_RATE_0_781HZ),
                           ('1.563Hz', BrickletAccelerometerV2.DATA_RATE_1_563HZ),
                           ('3.125Hz', BrickletAccelerometerV2.DATA_RATE_3_125HZ),
                           ('6.2512Hz', BrickletAccelerometerV2.DATA_RATE_6_2512HZ),
                           ('12.5Hz', BrickletAccelerometerV2.DATA_RATE_12_5HZ),
                           ('25Hz', BrickletAccelerometerV2.DATA_RATE_25HZ),
                           ('50Hz', BrickletAccelerometerV2.DATA_RATE_50HZ),
                           ('100Hz', BrickletAccelerometerV2.DATA_RATE_100HZ),
                           ('200Hz', BrickletAccelerometerV2.DATA_RATE_200HZ),
                           ('400Hz', BrickletAccelerometerV2.DATA_RATE_400HZ),
                           ('800Hz', BrickletAccelerometerV2.DATA_RATE_800HZ),
                           ('1600Hz', BrickletAccelerometerV2.DATA_RATE_1600HZ),
                           ('3200Hz', BrickletAccelerometerV2.DATA_RATE_3200HZ),
                           ('6400Hz', BrickletAccelerometerV2.DATA_RATE_6400HZ),
                           ('12800Hz', BrickletAccelerometerV2.DATA_RATE_12800HZ),
                           ('25600Hz', BrickletAccelerometerV2.DATA_RATE_25600HZ)],
                'default': '100Hz'
            },
            {
                'name': 'Full Scale',
                'type': 'choice',
                'values': [('2g', BrickletAccelerometerV2.FULL_SCALE_2G),
                           ('4g', BrickletAccelerometerV2.FULL_SCALE_4G),
                           ('8g', BrickletAccelerometerV2.FULL_SCALE_8G)],
                'default': '2g'
            }
        ]
    }
if BrickletAirQuality_found:
    device_specs[BrickletAirQuality.DEVICE_DISPLAY_NAME] = {
        'class': BrickletAirQuality,
        'values': [
            {
                'name': 'IAQ Index',
                'getter': lambda device: device.get_iaq_index(),
                'subvalues': ['Value', 'Accuracy'],
                'unit': [None, None],
                'advanced': False
            },
            {
                'name': 'Temperature',
                'getter': lambda device: device.get_temperature(),
                'subvalues': None,
                'unit': '°C/100',
                'advanced': False
            },
            {
                'name': 'Humidity',
                'getter': lambda device: device.get_humidity(),
                'subvalues': None,
                'unit': '%RH/100',
                'advanced': False
            },
            {
                'name': 'Air Pressure',
                'getter': lambda device: device.get_air_pressure(),
                'subvalues': None,
                'unit': 'hPa/100',
                'advanced': False
            },
            {
                'name': 'Chip Temperature',
                'getter': lambda device: device.get_chip_temperature(),
                'subvalues': None,
                'unit': '°C',
                'advanced': True
            }
        ],
        'options_setter': lambda device, temperature_offset: device.set_temperature_offset(temperature_offset),
        'options': [
            {
                'name': 'Temperature Offset',
                'type': 'int',
                'minimum': -2147483648,
                'maximum': 2147483647,
                'suffix': '°C/100',
                'default': 0
            }
        ]
    }
if BrickletAmbientLight_found:
    device_specs[BrickletAmbientLight.DEVICE_DISPLAY_NAME] = {
        'class': BrickletAmbientLight,
        'values': [
            {
                'name': 'Illuminance',
                'getter': lambda device: device.get_illuminance(),
                'subvalues': None,
                'unit': 'lx/10',
                'advanced': False
            },
            {
                'name': 'Analog Value',
                'getter': lambda device: device.get_analog_value(),
                'subvalues': None,
                'unit': None,
                'advanced': True
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletAmbientLightV2_found:
    device_specs[BrickletAmbientLightV2.DEVICE_DISPLAY_NAME] = {
        'class': BrickletAmbientLightV2,
        'values': [
            {
                'name': 'Illuminance',
                'getter': lambda device: device.get_illuminance(),
                'subvalues': None,
                'unit': 'lx/100',
                'advanced': False
            }
        ],
        'options_setter': lambda device, illuminance_range, integration_time: device.set_configuration(illuminance_range, integration_time),
        'options': [
            {
                'name': 'Illuminance Range',
                'type': 'choice',
                'values': [('Unlimited', 6), # FIXME: BrickletAmbientLightV2.ILLUMINANCE_RANGE_UNLIMITED
                           ('64000Lux', BrickletAmbientLightV2.ILLUMINANCE_RANGE_64000LUX),
                           ('32000Lux', BrickletAmbientLightV2.ILLUMINANCE_RANGE_32000LUX),
                           ('16000Lux', BrickletAmbientLightV2.ILLUMINANCE_RANGE_16000LUX),
                           ('8000Lux', BrickletAmbientLightV2.ILLUMINANCE_RANGE_8000LUX),
                           ('1300Lux', BrickletAmbientLightV2.ILLUMINANCE_RANGE_1300LUX),
                           ('600Lux', BrickletAmbientLightV2.ILLUMINANCE_RANGE_600LUX)],
                'default': '8000Lux'
            },
            {
                'name': 'Integration Time',
                'type': 'choice',
                'values': [('50ms', BrickletAmbientLightV2.INTEGRATION_TIME_50MS),
                           ('100ms', BrickletAmbientLightV2.INTEGRATION_TIME_100MS),
                           ('150ms', BrickletAmbientLightV2.INTEGRATION_TIME_150MS),
                           ('200ms', BrickletAmbientLightV2.INTEGRATION_TIME_200MS),
                           ('250ms', BrickletAmbientLightV2.INTEGRATION_TIME_350MS),
                           ('300ms', BrickletAmbientLightV2.INTEGRATION_TIME_300MS),
                           ('350ms', BrickletAmbientLightV2.INTEGRATION_TIME_350MS),
                           ('400ms', BrickletAmbientLightV2.INTEGRATION_TIME_400MS)],
                'default': '200ms'
            }
        ]
    }
if BrickletAmbientLightV3_found:
    device_specs[BrickletAmbientLightV3.DEVICE_DISPLAY_NAME] = {
        'class': BrickletAmbientLightV3,
        'values': [
            {
                'name': 'Illuminance',
                'getter': lambda device: device.get_illuminance(),
                'subvalues': None,
                'unit': 'lx/100',
                'advanced': False
            }
        ],
        'options_setter': lambda device, illuminance_range, integration_time: device.set_configuration(illuminance_range, integration_time),
        'options': [
            {
                'name': 'Illuminance Range',
                'type': 'choice',
                'values': [('Unlimited', BrickletAmbientLightV3.ILLUMINANCE_RANGE_UNLIMITED),
                           ('64000Lux', BrickletAmbientLightV3.ILLUMINANCE_RANGE_64000LUX),
                           ('32000Lux', BrickletAmbientLightV3.ILLUMINANCE_RANGE_32000LUX),
                           ('16000Lux', BrickletAmbientLightV3.ILLUMINANCE_RANGE_16000LUX),
                           ('8000Lux', BrickletAmbientLightV3.ILLUMINANCE_RANGE_8000LUX),
                           ('1300Lux', BrickletAmbientLightV3.ILLUMINANCE_RANGE_1300LUX),
                           ('600Lux', BrickletAmbientLightV3.ILLUMINANCE_RANGE_600LUX)],
                'default': '8000Lux'
            },
            {
                'name': 'Integration Time',
                'type': 'choice',
                'values': [('50ms', BrickletAmbientLightV3.INTEGRATION_TIME_50MS),
                           ('100ms', BrickletAmbientLightV3.INTEGRATION_TIME_100MS),
                           ('150ms', BrickletAmbientLightV3.INTEGRATION_TIME_150MS),
                           ('200ms', BrickletAmbientLightV3.INTEGRATION_TIME_200MS),
                           ('250ms', BrickletAmbientLightV3.INTEGRATION_TIME_350MS),
                           ('300ms', BrickletAmbientLightV3.INTEGRATION_TIME_300MS),
                           ('350ms', BrickletAmbientLightV3.INTEGRATION_TIME_350MS),
                           ('400ms', BrickletAmbientLightV3.INTEGRATION_TIME_400MS)],
                'default': '150ms'
            }
        ]
    }
if BrickletAnalogIn_found:
    device_specs[BrickletAnalogIn.DEVICE_DISPLAY_NAME] = {
        'class': BrickletAnalogIn,
        'values': [
            {
                'name': 'Voltage',
                'getter': lambda device: device.get_voltage(),
                'subvalues': None,
                'unit': 'mV',
                'advanced': False
            },
            {
                'name': 'Analog Value',
                'getter': lambda device: device.get_analog_value(),
                'subvalues': None,
                'unit': None,
                'advanced': True
            }
        ],
        'options_setter': lambda device, voltage_range, average_length: [device.set_range(voltage_range), device.set_averaging(average_length)],
        'options': [
            {
                'name': 'Voltage Range',
                'type': 'choice',
                'values': [('Automatic', BrickletAnalogIn.RANGE_AUTOMATIC),
                           ('3.30V', BrickletAnalogIn.RANGE_UP_TO_3V),
                           ('6.05V', BrickletAnalogIn.RANGE_UP_TO_6V),
                           ('10.32V', BrickletAnalogIn.RANGE_UP_TO_10V),
                           ('36.30V', BrickletAnalogIn.RANGE_UP_TO_36V),
                           ('45.00V', BrickletAnalogIn.RANGE_UP_TO_45V)],
                'default': 'Automatic'
            },
            {
                'name': 'Average Length',
                'type': 'int',
                'minimum': 0,
                'maximum': 255,
                'suffix': None,
                'default': 50
            }
        ]
    }
if BrickletAnalogInV2_found:
    device_specs[BrickletAnalogInV2.DEVICE_DISPLAY_NAME] = {
        'class': BrickletAnalogInV2,
        'values': [
            {
                'name': 'Voltage',
                'getter': lambda device: device.get_voltage(),
                'subvalues': None,
                'unit': 'mV',
                'advanced': False
            },
            {
                'name': 'Analog Value',
                'getter': lambda device: device.get_analog_value(),
                'subvalues': None,
                'unit': None,
                'advanced': True
            }
        ],
        'options_setter': lambda device, moving_average_length: device.set_moving_average(moving_average_length),
        'options': [
            {
                'name': 'Moving Average Length',
                'type': 'int',
                'minimum': 1,
                'maximum': 50,
                'suffix': None,
                'default': 50
            }
        ]
    }
if BrickletAnalogInV3_found:
    device_specs[BrickletAnalogInV3.DEVICE_DISPLAY_NAME] = {
        'class': BrickletAnalogInV3,
        'values': [
            {
                'name': 'Voltage',
                'getter': lambda device: device.get_voltage(),
                'subvalues': None,
                'unit': 'mV',
                'advanced': False
            },
            {
                'name': 'Chip Temperature',
                'getter': lambda device: device.get_chip_temperature(),
                'subvalues': None,
                'unit': '°C/100',
                'advanced': True
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletAnalogOutV2_found:
    device_specs[BrickletAnalogOutV2.DEVICE_DISPLAY_NAME] = {
        'class': BrickletAnalogOutV2,
        'values': [
            {
                'name': 'Input Voltage',
                'getter': lambda device: device.get_input_voltage(),
                'subvalues': None,
                'unit': 'mV',
                'advanced': False
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletAnalogOutV3_found:
    device_specs[BrickletAnalogOutV3.DEVICE_DISPLAY_NAME] = {
        'class': BrickletAnalogOutV3,
        'values': [
            {
                'name': 'Input Voltage',
                'getter': lambda device: device.get_input_voltage(),
                'subvalues': None,
                'unit': 'mV',
                'advanced': False
            },
            {
                'name': 'Chip Temperature',
                'getter': lambda device: device.get_chip_temperature(),
                'subvalues': None,
                'unit': '°C',
                'advanced': True
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletBarometer_found:
    device_specs[BrickletBarometer.DEVICE_DISPLAY_NAME] = {
        'class': BrickletBarometer,
        'values': [
            {
                'name': 'Air Pressure',
                'getter': lambda device: device.get_air_pressure(),
                'subvalues': None,
                'unit': 'hPa/1000',
                'advanced': False
            },
            {
                'name': 'Altitude',
                'getter': lambda device: device.get_altitude(),
                'subvalues': None,
                'unit': 'cm',
                'advanced': False
            },
            {
                'name': 'Chip Temperature',
                'getter': lambda device: device.get_chip_temperature(),
                'subvalues': None,
                'unit': '°C/100',
                'advanced': True
            }
        ],
        'options_setter': lambda device, reference_air_pressure, moving_average_length_air_pressure, \
                                         average_length_air_pressure, average_length_temperature: \
                          [device.set_reference_air_pressure(reference_air_pressure),
                           device.set_averaging(moving_average_length_air_pressure,
                                                average_length_air_pressure,
                                                average_length_temperature)],
        'options': [
            {
                'name': 'Reference Air Pressure',
                'type': 'int',
                'minimum': 10000,
                'maximum': 1200000,
                'suffix': ' hPa/1000',
                'default': 1013250
            },
            {
                'name': 'Moving Average Length (Air Pressure)',
                'type': 'int',
                'minimum': 0,
                'maximum': 25,
                'suffix': None,
                'default': 25
            },
            {
                'name': 'Average Length (Air Pressure)',
                'type': 'int',
                'minimum': 0,
                'maximum': 10,
                'suffix': None,
                'default': 10
            },
            {
                'name': 'Average Length (Temperature)',
                'type': 'int',
                'minimum': 0,
                'maximum': 255,
                'suffix': None,
                'default': 10
            }
        ]
    }
if BrickletBarometerV2_found:
    device_specs[BrickletBarometerV2.DEVICE_DISPLAY_NAME] = {
        'class': BrickletBarometerV2,
        'values': [
            {
                'name': 'Air Pressure',
                'getter': lambda device: device.get_air_pressure(),
                'subvalues': None,
                'unit': 'hPa/1000',
                'advanced': False
            },
            {
                'name': 'Altitude',
                'getter': lambda device: device.get_altitude(),
                'subvalues': None,
                'unit': 'mm',
                'advanced': False
            },
            {
                'name': 'Temperature',
                'getter': lambda device: device.get_temperature(),
                'subvalues': None,
                'unit': '°C/100',
                'advanced': True
            },
            {
                'name': 'Chip Temperature',
                'getter': lambda device: device.get_chip_temperature(),
                'subvalues': None,
                'unit': '°C',
                'advanced': True
            }
        ],
        'options_setter': lambda device,
                                 reference_air_pressure, \
                                 moving_average_length_air_pressure, \
                                 moving_average_length_temperature,
                                 data_rate,
                                 air_pressure_low_pass_filter: \
                          [device.set_reference_air_pressure(reference_air_pressure),
                           device.set_moving_average_configuration(moving_average_length_air_pressure,
                                                                   moving_average_length_temperature),
                           device.set_sensor_configuration(data_rate, air_pressure_low_pass_filter)],
        'options': [
            {
                'name': 'Reference Air Pressure',
                'type': 'int',
                'minimum': 10000,
                'maximum': 1200000,
                'suffix': ' hPa/1000',
                'default': 1013250
            },
            {
                'name': 'Moving Average Length (Air Pressure)',
                'type': 'int',
                'minimum': 1,
                'maximum': 1000,
                'suffix': None,
                'default': 100
            },
            {
                'name': 'Moving Average Length (Temperature)',
                'type': 'int',
                'minimum': 1,
                'maximum': 1000,
                'suffix': None,
                'default': 100
            },
            {
                'name': 'Data Rate',
                'type': 'choice',
                'values': [('Off', BrickletBarometerV2.DATA_RATE_OFF),
                           ('1 Hz', BrickletBarometerV2.DATA_RATE_1HZ),
                           ('10 Hz', BrickletBarometerV2.DATA_RATE_10HZ),
                           ('25 Hz', BrickletBarometerV2.DATA_RATE_25HZ),
                           ('50 Hz', BrickletBarometerV2.DATA_RATE_50HZ),
                           ('75 Hz', BrickletBarometerV2.DATA_RATE_75HZ)],
                'default': '50 Hz'
            },
            {
                'name': 'Air Pressure Low Pass Filter',
                'type': 'choice',
                'values': [('Off', BrickletBarometerV2.LOW_PASS_FILTER_OFF),
                           ('1/9th', BrickletBarometerV2.LOW_PASS_FILTER_1_9TH),
                           ('1/20th', BrickletBarometerV2.LOW_PASS_FILTER_1_20TH)],
                'default': '1/9th'
            }
        ]
    }
if BrickletCAN_found:
    device_specs[BrickletCAN.DEVICE_DISPLAY_NAME] = {
        'class': BrickletCAN,
        'values': [
            {
                'name': 'Error Log',
                'getter': lambda device: device.get_error_log(),
                'subvalues': ['Write Error Level',
                              'Read Error Level',
                              'Transceiver Disabled',
                              'Write Timeout Count',
                              'Read Register Overflow Count',
                              'Read Buffer Overflow Count'],
                'unit': [None, None, None, None, None, None],
                'advanced': True
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletCANV2_found:
    device_specs[BrickletCANV2.DEVICE_DISPLAY_NAME] = {
        'class': BrickletCANV2,
        'values': [
            {
                'name': 'Error Log',
                'getter': lambda device: device.get_error_log(),
                'subvalues': ['Transceiver State',
                              'Transceiver Write Error Level',
                              'Transceiver Read Error Level',
                              'Transceiver Stuffing Error Count',
                              'Transceiver Format Error Count',
                              'Transceiver ACK Error Count',
                              'Transceiver Bit1 Error Count',
                              'Transceiver Bit0 Error Count',
                              'Transceiver CRC Error Count',
                              'Write Buffer Timeout Error Count',
                              'Read Buffer Overflow Error Count',
                              #'Read Buffer Overflow Error Occurred Length',
                              'Read Buffer Overflow Error Occurred',
                              'Read Backlog Overflow Error Count'],
                'unit': [None, None, None, None, None, None, None, None, None, None, None, None, None],
                'advanced': True
            },
            {
                'name': 'Chip Temperature',
                'getter': lambda device: device.get_chip_temperature(),
                'subvalues': None,
                'unit': '°C',
                'advanced': True
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletCO2_found:
    device_specs[BrickletCO2.DEVICE_DISPLAY_NAME] = {
        'class': BrickletCO2,
        'values': [
            {
                'name': 'CO2 Concentration',
                'getter': lambda device: device.get_co2_concentration(),
                'subvalues': None,
                'unit': 'ppm',
                'advanced': False
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletCO2V2_found:
    device_specs[BrickletCO2V2.DEVICE_DISPLAY_NAME] = {
        'class': BrickletCO2V2,
        'values': [
            {
                'name': 'CO2 Concentration',
                'getter': lambda device: device.get_co2_concentration(),
                'subvalues': None,
                'unit': 'ppm',
                'advanced': False
            },
            {
                'name': 'Temperature',
                'getter': lambda device: device.get_temperature(),
                'subvalues': None,
                'unit': '°C/100',
                'advanced': False
            },
            {
                'name': 'Humidity',
                'getter': lambda device: device.get_humidity(),
                'subvalues': None,
                'unit': '%RH/100',
                'advanced': False
            },
            {
                'name': 'All Values',
                'getter': lambda device: device.get_all_values(),
                'subvalues': ['CO2 Concentration', 'Temperature', 'Humidity'],
                'unit': ['ppm', '°C/100', '%RH/100'],
                'advanced': False
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletColor_found:
    device_specs[BrickletColor.DEVICE_DISPLAY_NAME] = {
        'class': BrickletColor,
        'values': [
            {
                'name': 'Color',
                'getter': lambda device: device.get_color(),
                'subvalues': ['Red', 'Green', 'Blue', 'Clear'],
                'unit': [None, None, None, None],
                'advanced': False
            },
            {
                'name': 'Color Temperature',
                'getter': lambda device: device.get_color_temperature(), # FIXME: saturation handling is missing
                'subvalues': None,
                'unit': 'K',
                'advanced': False
            },
            {
                'name': 'Illuminance',
                'getter': special_get_color_illuminance, # FIXME: saturation handling is missing
                'subvalues': None,
                'unit': 'lx/10',
                'advanced': False
            }
        ],
        'options_setter': lambda device, gain, integration_time: device.set_config(gain, integration_time),
        'options': [
            {
                'name': 'Gain',
                'type': 'choice',
                'values': [('1x', BrickletColor.GAIN_1X),
                           ('4x', BrickletColor.GAIN_4X),
                           ('16x', BrickletColor.GAIN_16X),
                           ('60x', BrickletColor.GAIN_60X)],
                'default': '60x'
            },
            {
                'name': 'Integration Time',
                'type': 'choice',
                'values': [('2.4ms', BrickletColor.INTEGRATION_TIME_2MS),
                           ('24ms', BrickletColor.INTEGRATION_TIME_24MS),
                           ('101ms', BrickletColor.INTEGRATION_TIME_101MS),
                           ('154ms', BrickletColor.INTEGRATION_TIME_154MS),
                           ('700ms', BrickletColor.INTEGRATION_TIME_700MS)],
                'default': '154ms'
            }
        ]
    }
if BrickletColorV2_found:
    device_specs[BrickletColorV2.DEVICE_DISPLAY_NAME] = {
        'class': BrickletColorV2,
        'values': [
            {
                'name': 'Color',
                'getter': lambda device: device.get_color(),
                'subvalues': ['Red', 'Green', 'Blue', 'Clear'],
                'unit': [None, None, None, None],
                'advanced': False
            },
            {
                'name': 'Color Temperature',
                'getter': lambda device: device.get_color_temperature(), # FIXME: saturation handling is missing
                'subvalues': None,
                'unit': 'K',
                'advanced': False
            },
            {
                'name': 'Illuminance',
                'getter': special_get_color_v2_illuminance, # FIXME: saturation handling is missing
                'subvalues': None,
                'unit': 'lx/10',
                'advanced': False
            }
        ],
        'options_setter': lambda device, gain, integration_time, enable_light: [device.set_configuration(gain, integration_time), device.set_light(enable_light)],
        'options': [
            {
                'name': 'Gain',
                'type': 'choice',
                'values': [('1x', BrickletColorV2.GAIN_1X),
                           ('4x', BrickletColorV2.GAIN_4X),
                           ('16x', BrickletColorV2.GAIN_16X),
                           ('60x', BrickletColorV2.GAIN_60X)],
                'default': '60x'
            },
            {
                'name': 'Integration Time',
                'type': 'choice',
                'values': [('2.4ms', BrickletColorV2.INTEGRATION_TIME_2MS),
                           ('24ms', BrickletColorV2.INTEGRATION_TIME_24MS),
                           ('101ms', BrickletColorV2.INTEGRATION_TIME_101MS),
                           ('154ms', BrickletColorV2.INTEGRATION_TIME_154MS),
                           ('700ms', BrickletColorV2.INTEGRATION_TIME_700MS)],
                'default': '154ms'
            },
            {
                'name': 'Enable Light',
                'type': 'bool',
                'default': False
            }
        ]
    }
if BrickletCompass_found:
    device_specs[BrickletCompass.DEVICE_DISPLAY_NAME] = {
        'class': BrickletCompass,
        'values': [
            {
                'name': 'Heading',
                'getter': lambda device: device.get_heading(),
                'subvalues': None,
                'unit': '°/10',
                'advanced': False
            },
            {
                'name': 'Magnetic Flux Density',
                'getter': lambda device: device.get_magnetic_flux_density(),
                'subvalues': ['X', 'Y', 'Z'],
                'unit': ['mG/10', 'mG/10', 'mG/10'],
                'advanced': False
            }
        ],
        'options_setter': lambda device, data_rate, background_calibration: device.set_configuration(data_rate, background_calibration),
        'options': [
            {
                'name': 'Data Rate',
                'type': 'choice',
                'values': [('100 Hz', BrickletCompass.DATA_RATE_100HZ),
                           ('200 Hz', BrickletCompass.DATA_RATE_200HZ),
                           ('400 Hz', BrickletCompass.DATA_RATE_400HZ),
                           ('600 Hz', BrickletCompass.DATA_RATE_600HZ)],
                'default': '100 Hz'
            },
            {
                'name': 'Background Calibration',
                'type': 'bool',
                'default': True
            }
        ]
    }
if BrickletCurrent12_found:
    device_specs[BrickletCurrent12.DEVICE_DISPLAY_NAME] = {
        'class': BrickletCurrent12,
        'values': [
            {
                'name': 'Current',
                'getter': lambda device: device.get_current(),
                'subvalues': None,
                'unit': 'mA',
                'advanced': False
            },
            {
                'name': 'Analog Value',
                'getter': lambda device: device.get_analog_value(),
                'subvalues': None,
                'unit': None,
                'advanced': True
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletCurrent25_found:
    device_specs[BrickletCurrent25.DEVICE_DISPLAY_NAME] = {
        'class': BrickletCurrent25,
        'values': [
            {
                'name': 'Current',
                'getter': lambda device: device.get_current(),
                'subvalues': None,
                'unit': 'mA',
                'advanced': False
            },
            {
                'name': 'Analog Value',
                'getter': lambda device: device.get_analog_value(),
                'subvalues': None,
                'unit': None,
                'advanced': True
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletDistanceIR_found:
    device_specs[BrickletDistanceIR.DEVICE_DISPLAY_NAME] = {
        'class': BrickletDistanceIR,
        'values': [
            {
                'name': 'Distance',
                'getter': lambda device: device.get_distance(),
                'subvalues': None,
                'unit': 'mm',
                'advanced': False
            },
            {
                'name': 'Analog Value',
                'getter': lambda device: device.get_analog_value(),
                'subvalues': None,
                'unit': None,
                'advanced': True
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletDistanceIRV2_found:
    device_specs[BrickletDistanceIRV2.DEVICE_DISPLAY_NAME] = {
        'class': BrickletDistanceIRV2,
        'values': [
            {
                'name': 'Distance',
                'getter': lambda device: device.get_distance(),
                'subvalues': None,
                'unit': 'mm',
                'advanced': False
            },
            {
                'name': 'Analog Value',
                'getter': lambda device: device.get_analog_value(),
                'subvalues': None,
                'unit': None,
                'advanced': True
            },
            {
                'name': 'Chip Temperature',
                'getter': lambda device: device.get_chip_temperature(),
                'subvalues': None,
                'unit': '°C',
                'advanced': True
            }
        ],
        'options_setter': lambda device, moving_average_length: device.set_moving_average_configuration(moving_average_length),
        'options': [
            {
                'name': 'Moving Average Length',
                'type': 'int',
                'minimum': 0,
                'maximum': 1000,
                'suffix': None,
                'default': 25
            }
        ]
    }
if BrickletDistanceUS_found:
    device_specs[BrickletDistanceUS.DEVICE_DISPLAY_NAME] = {
        'class': BrickletDistanceUS,
        'values': [
            {
                'name': 'Distance Value',
                'getter': lambda device: device.get_distance_value(),
                'subvalues': None,
                'unit': None,
                'advanced': False
            }
        ],
        'options_setter': lambda device, moving_average_length: device.set_moving_average(moving_average_length),
        'options': [
            {
                'name': 'Moving Average Length',
                'type': 'int',
                'minimum': 0,
                'maximum': 100,
                'suffix': None,
                'default': 20
            }
        ]
    }
if BrickletDistanceUSV2_found:
    device_specs[BrickletDistanceUSV2.DEVICE_DISPLAY_NAME] = {
        'class': BrickletDistanceUSV2,
        'values': [
            {
                'name': 'Distance',
                'getter': lambda device: device.get_distance(),
                'subvalues': None,
                'unit': 'mm',
                'advanced': False
            }
        ],
        'options_setter': lambda device, update_rate: device.set_update_rate(update_rate),
        'options': [
            {
                'name': 'Update Rate',
                'type': 'choice',
                'values': [('2 Hz', BrickletDistanceUSV2.UPDATE_RATE_2_HZ),
                           ('10 Hz', BrickletDistanceUSV2.UPDATE_RATE_10_HZ)],
                'default': '2 Hz'
            }
        ]
    }
if BrickletDualButton_found:
    device_specs[BrickletDualButton.DEVICE_DISPLAY_NAME] = {
        'class': BrickletDualButton,
        'values': [
            {
                'name': 'Button State',
                'getter': lambda device: device.get_button_state(),
                'subvalues': ['Left', 'Right'],
                'unit': [None, None], # FIXME: constants?
                'advanced': False
            },
            {
                'name': 'LED State',
                'getter': lambda device: device.get_led_state(),
                'subvalues': ['Left', 'Right'],
                'unit': [None, None], # FIXME: constants?
                'advanced': False
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletDualButtonV2_found:
    device_specs[BrickletDualButtonV2.DEVICE_DISPLAY_NAME] = {
        'class': BrickletDualButtonV2,
        'values': [
            {
                'name': 'Button State',
                'getter': lambda device: device.get_button_state(),
                'subvalues': ['Left', 'Right'],
                'unit': [None, None], # FIXME: constants?
                'advanced': False
            },
            {
                'name': 'LED State',
                'getter': lambda device: device.get_led_state(),
                'subvalues': ['Left', 'Right'],
                'unit': [None, None], # FIXME: constants?
                'advanced': False
            },
            {
                'name': 'Chip Temperature',
                'getter': lambda device: device.get_chip_temperature(),
                'subvalues': None,
                'unit': '°C',
                'advanced': True
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletDualRelay_found:
    device_specs[BrickletDualRelay.DEVICE_DISPLAY_NAME] = {
        'class': BrickletDualRelay,
        'values': [
            {
                'name': 'State',
                'getter': lambda device: device.get_state(),
                'subvalues': ['Relay1', 'Relay2'],
                'unit': [None, None],
                'advanced': False
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletDustDetector_found:
    device_specs[BrickletDustDetector.DEVICE_DISPLAY_NAME] = {
        'class': BrickletDustDetector,
        'values': [
            {
                'name': 'Dust Density',
                'getter': lambda device: device.get_dust_density(),
                'subvalues': None,
                'unit': 'µg/m³',
                'advanced': False
            }
        ],
        'options_setter': lambda device, moving_average_length: device.set_moving_average(moving_average_length),
        'options': [
            {
                'name': 'Moving Average Length',
                'type': 'int',
                'minimum': 0,
                'maximum': 100,
                'suffix': None,
                'default': 100
            }
        ]
    }
if BrickletEnergyMonitor_found:
    device_specs[BrickletEnergyMonitor.DEVICE_DISPLAY_NAME] = {
        'class': BrickletEnergyMonitor,
        'values': [
            {
                'name': 'Energy Data',
                'getter': lambda device: device.get_energy_data(),
                'subvalues': ['Voltage', 'Current', 'Energy', 'Real Power', 'Apparent Power', 'Reactive Power', 'Power Factor', 'Frequency'],
                'unit': ['10mV', '10mA', '10mWh', '10mW', '10mVA', '10mVAR', '1/1000', '10mHz'],
                'advanced': False
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletGPS_found:
    device_specs[BrickletGPS.DEVICE_DISPLAY_NAME] = {
        'class': BrickletGPS,
        'values': [
            {
                'name': 'Coordinates',
                'getter': special_get_gps_coordinates,
                'subvalues': ['Latitude', 'NS', 'Longitude', 'EW', 'PDOP', 'HDOP', 'VDOP', 'EPE'],
                'unit': ['deg/1000000', None, 'deg/1000000', None, '1/100', '1/100', '1/100', 'cm'],
                'advanced': False
            },
            {
                'name': 'Altitude',
                'getter': special_get_gps_altitude,
                'subvalues': ['Altitude', 'Geoidal Separation'],
                'unit': ['cm', 'cm'],
                'advanced': False
            },
            {
                'name': 'Motion',
                'getter': special_get_gps_motion,
                'subvalues': ['Course', 'Speed'],
                'unit': ['deg/100', '10m/h'],
                'advanced': False
            },
            {
                'name': 'Date Time',
                'getter': lambda device: device.get_date_time(),
                'subvalues': ['Date', 'Time'],
                'unit': ['ddmmyy', 'hhmmss|sss'],
                'advanced': False
            },
            {
                'name': 'Status',
                'getter': lambda device: device.get_status(),
                'subvalues': ['Fix', 'Satellites View', 'Satellites Used'],
                'unit': [None, None, None], # FIXME: fix constants?
                'advanced': False
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletGPSV2_found:
    device_specs[BrickletGPSV2.DEVICE_DISPLAY_NAME] = {
        'class': BrickletGPSV2,
        'values': [
            {
                'name': 'Coordinates',
                'getter': special_get_gps_v2_coordinates,
                'subvalues': ['Latitude', 'NS', 'Longitude', 'EW'],
                'unit': ['deg/1000000', None, 'deg/1000000', None],
                'advanced': False
            },
            {
                'name': 'Altitude',
                'getter': special_get_gps_v2_altitude,
                'subvalues': ['Altitude', 'Geoidal Separation'],
                'unit': ['cm', 'cm'],
                'advanced': False
            },
            {
                'name': 'Motion',
                'getter': special_get_gps_v2_motion,
                'subvalues': ['Course', 'Speed'],
                'unit': ['deg/100', '10m/h'],
                'advanced': False
            },
            {
                'name': 'Date Time',
                'getter': lambda device: device.get_date_time(),
                'subvalues': ['Date', 'Time'],
                'unit': ['ddmmyy', 'hhmmss|sss'],
                'advanced': False
            },
            {
                'name': 'Status',
                'getter': lambda device: device.get_status(),
                'subvalues': ['Fix', 'Satellites View'],
                'unit': [None, None], # FIXME: fix constants?
                'advanced': False
            },
            {
                'name': 'Chip Temperature',
                'getter': lambda device: device.get_chip_temperature(),
                'subvalues': None,
                'unit': '°C',
                'advanced': True
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletGPSV3_found:
    device_specs[BrickletGPSV3.DEVICE_DISPLAY_NAME] = {
        'class': BrickletGPSV3,
        'values': [
            {
                'name': 'Coordinates',
                'getter': special_get_gps_v3_coordinates,
                'subvalues': ['Latitude', 'NS', 'Longitude', 'EW'],
                'unit': ['deg/1000000', None, 'deg/1000000', None],
                'advanced': False
            },
            {
                'name': 'Altitude',
                'getter': special_get_gps_v3_altitude,
                'subvalues': ['Altitude', 'Geoidal Separation'],
                'unit': ['cm', 'cm'],
                'advanced': False
            },
            {
                'name': 'Motion',
                'getter': special_get_gps_v3_motion,
                'subvalues': ['Course', 'Speed'],
                'unit': ['deg/100', '10m/h'],
                'advanced': False
            },
            {
                'name': 'Date Time',
                'getter': lambda device: device.get_date_time(),
                'subvalues': ['Date', 'Time'],
                'unit': ['ddmmyy', 'hhmmss|sss'],
                'advanced': False
            },
            {
                'name': 'Status',
                'getter': lambda device: device.get_status(),
                'subvalues': ['Fix', 'Satellites View'],
                'unit': [None, None], # FIXME: fix constants?
                'advanced': False
            },
            {
                'name': 'Chip Temperature',
                'getter': lambda device: device.get_chip_temperature(),
                'subvalues': None,
                'unit': '°C',
                'advanced': True
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletHallEffect_found:
    device_specs[BrickletHallEffect.DEVICE_DISPLAY_NAME] = {
        'class': BrickletHallEffect,
        'values': [
            {
                'name': 'Value',
                'getter': lambda device: device.get_value(),
                'subvalues': None,
                'unit': None,
                'advanced': False
            },
            {
                'name': 'Edge Count',
                'getter': lambda device: device.get_edge_count(False),
                'subvalues': None,
                'unit': None,
                'advanced': False
            }
        ],
        'options_setter': lambda device, edge_count_type, edge_count_debounce: device.set_edge_count_config(edge_count_type, edge_count_debounce),
        'options': [
            {
                'name': 'Edge Count Type',
                'type': 'choice',
                'values': [('Rising', BrickletHallEffect.EDGE_TYPE_RISING),
                           ('Falling', BrickletHallEffect.EDGE_TYPE_FALLING),
                           ('Both', BrickletHallEffect.EDGE_TYPE_BOTH)],
                'default': 'Rising'
            },
            {
                'name': 'Edge Count Debounce',
                'type': 'int',
                'minimum': 0,
                'maximum': 255,
                'suffix': ' ms',
                'default': 100
            }
        ]
    }
if BrickletHallEffectV2_found:
    device_specs[BrickletHallEffectV2.DEVICE_DISPLAY_NAME] = {
        'class': BrickletHallEffectV2,
        'values': [
            {
                'name': 'Value',
                'getter': lambda device: device.get_magnetic_flux_density(),
                'subvalues': None,
                'unit': 'uT',
                'advanced': False
            },
            {
                'name': 'Count',
                'getter': lambda device: device.get_counter(False),
                'subvalues': None,
                'unit': None,
                'advanced': False
            }
        ],
        'options_setter': lambda device, high_threshold, low_threshold, debounce: device.set_counter_config(high_threshold, low_threshold, debounce),
        'options': [
            {
                'name': 'High Threshold',
                'type': 'int',
                'minimum': -7000,
                'maximum': 7000,
                'suffix': ' uT',
                'default': 2000
            },
            {
                'name': 'Low Threshold',
                'type': 'int',
                'minimum': -7000,
                'maximum': 7000,
                'suffix': ' uT',
                'default': -2000
            },
            {
                'name': ' Debounce',
                'type': 'int',
                'minimum': 0,
                'maximum': 2147483647,
                'suffix': ' us',
                'default': 100000
            }
        ]
    }
if BrickletHumidity_found:
    device_specs[BrickletHumidity.DEVICE_DISPLAY_NAME] = {
        'class': BrickletHumidity,
        'values': [
            {
                'name': 'Humidity',
                'getter': lambda device: device.get_humidity(),
                'subvalues': None,
                'unit': '%RH/10',
                'advanced': False
            },
            {
                'name': 'Analog Value',
                'getter': lambda device: device.get_analog_value(),
                'subvalues': None,
                'unit': None,
                'advanced': True
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletHumidityV2_found:
    device_specs[BrickletHumidityV2.DEVICE_DISPLAY_NAME] = {
        'class': BrickletHumidityV2,
        'values': [
            {
                'name': 'Humidity',
                'getter': lambda device: device.get_humidity(),
                'subvalues': None,
                'unit': '%RH/100',
                'advanced': False
            },
            {
                'name': 'Temperature',
                'getter': lambda device: device.get_temperature(),
                'subvalues': None,
                'unit': '°C/100',
                'advanced': False
            },
            {
                'name': 'Chip Temperature',
                'getter': lambda device: device.get_chip_temperature(),
                'subvalues': None,
                'unit': '°C',
                'advanced': True
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletIMUV3_found:
    device_specs[BrickletIMUV3.DEVICE_DISPLAY_NAME] = {
        'class': BrickletIMUV3,
        'values': [
            {
                'name': 'Orientation',
                'getter': lambda device: device.get_orientation(),
                'subvalues': ['Heading', 'Roll', 'Pitch'],
                'unit': ['°/16', '°/16', '°/16'],
                'advanced': False
            },
            {
                'name': 'Linear Acceleration',
                'getter': lambda device: device.get_linear_acceleration(),
                'subvalues': ['X', 'Y', 'Z'],
                'unit': ['1/100 m/s²', '1/100 m/s²', '1/100 m/s²'],
                'advanced': False
            },
            {
                'name': 'Gravity Vector',
                'getter': lambda device: device.get_gravity_vector(),
                'subvalues': ['X', 'Y', 'Z'],
                'unit': ['1/100 m/s²', '1/100 m/s²', '1/100 m/s²'],
                'advanced': False
            },
            {
                'name': 'Quaternion',
                'getter': lambda device: device.get_quaternion(),
                'subvalues': ['W', 'X', 'Y', 'Z'],
                'unit': ['1/16383', '1/16383', '1/16383', '1/16383'],
                'advanced': False
            },
            {
                'name': 'Acceleration',
                'getter': lambda device: device.get_acceleration(),
                'subvalues': ['X', 'Y', 'Z'],
                'unit': ['1/100 m/s²', '1/100 m/s²', '1/100 m/s²'],
                'advanced': True
            },
            {
                'name': 'Magnetic Field',
                'getter': lambda device: device.get_magnetic_field(),
                'subvalues': ['X', 'Y', 'Z'],
                'unit': ['1/16 µT ', '1/16 µT ', '1/16 µT '],
                'advanced': True
            },
            {
                'name': 'Angular Velocity',
                'getter': lambda device: device.get_angular_velocity(),
                'subvalues': ['X', 'Y', 'Z'],
                'unit': ['1/16 °/s', '1/16 °/s', '1/16 °/s'],
                'advanced': True
            },
            {
                'name': 'Temperature',
                'getter': lambda device: device.get_temperature(),
                'subvalues': None,
                'unit': '°C/100',
                'advanced': True
            },
            #{
            #    'name': 'All Data',
            #    'getter': lambda device: device.get_all_data(),
            #    'subvalues': # FIXME: nested arrays
            #    'unit': # FIXME: nested arrays
            #    'advanced': False
            #},
            {
                'name': 'Chip Temperature',
                'getter': lambda device: device.get_chip_temperature(),
                'subvalues': None,
                'unit': '°C/10',
                'advanced': True
            }
        ],
        'options_setter': None,
        'options': None # FIXME: ranges
    }
if BrickletIndustrialCounter_found:
    device_specs[BrickletIndustrialCounter.DEVICE_DISPLAY_NAME] = {
        'class': BrickletIndustrialCounter,
        'values': [
            {
                'name': 'Count',
                'getter': lambda device: device.get_all_counter(),
                'subvalues': ['Channel0', 'Channel1', 'Channel2', 'Channel3'],
                'unit': [None, None, None, None],
                'advanced': False
            },
            {
                'name': 'Signal Data (Channel0)',
                'getter': lambda device: device.get_signal_data(0),
                'subvalues': ['Duty Cycle', 'Period', 'Frequency', 'Value'],
                'unit': ['1/100%', 'ns', 'mHz', None],
                'advanced': False
            },
            {
                'name': 'Signal Data (Channel1)',
                'getter': lambda device: device.get_signal_data(1),
                'subvalues': ['Duty Cycle', 'Period', 'Frequency', 'Value'],
                'unit': ['1/100%', 'ns', 'mHz', None],
                'advanced': False
            },
            {
                'name': 'Signal Data (Channel2)',
                'getter': lambda device: device.get_signal_data(2),
                'subvalues': ['Duty Cycle', 'Period', 'Frequency', 'Value'],
                'unit': ['1/100%', 'ns', 'mHz', None],
                'advanced': False
            },
            {
                'name': 'Signal Data (Channel3)',
                'getter': lambda device: device.get_signal_data(3),
                'subvalues': ['Duty Cycle', 'Period', 'Frequency', 'Value'],
                'unit': ['1/100%', 'ns', 'mHz', None],
                'advanced': False
            },
            {
                'name': 'Chip Temperature',
                'getter': lambda device: device.get_chip_temperature(),
                'subvalues': None,
                'unit': '°C',
                'advanced': True
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletIndustrialDigitalIn4_found:
    device_specs[BrickletIndustrialDigitalIn4.DEVICE_DISPLAY_NAME] = {
        'class': BrickletIndustrialDigitalIn4,
        'values': [
            {
                'name': 'Value',
                'getter': lambda device: value_to_bits(device.get_value(), 4),
                'subvalues': ['Pin 0', 'Pin 1', 'Pin 2', 'Pin 3'],
                'unit': [None, None, None, None],
                'advanced': False
            },
            {
                'name': 'Edge Count (Pin 0)',
                'getter': lambda device: device.get_edge_count(0, False),
                'subvalues': None,
                'unit': None,
                'advanced': True
            },
            {
                'name': 'Edge Count (Pin 1)',
                'getter': lambda device: device.get_edge_count(1, False),
                'subvalues': None,
                'unit': None,
                'advanced': True
            },
            {
                'name': 'Edge Count (Pin 2)',
                'getter': lambda device: device.get_edge_count(2, False),
                'subvalues': None,
                'unit': None,
                'advanced': True
            },
            {
                'name': 'Edge Count (Pin 3)',
                'getter': lambda device: device.get_edge_count(3, False),
                'subvalues': None,
                'unit': None,
                'advanced': True
            }
        ],
        'options_setter': lambda device, edge_count_type_pin0, edge_count_debounce_pin0, \
                                         edge_count_type_pin1, edge_count_debounce_pin1, \
                                         edge_count_type_pin2, edge_count_debounce_pin2, \
                                         edge_count_type_pin3, edge_count_debounce_pin3: \
                          [device.set_edge_count_config(0b0001, edge_count_type_pin0, edge_count_debounce_pin0),
                           device.set_edge_count_config(0b0010, edge_count_type_pin1, edge_count_debounce_pin1),
                           device.set_edge_count_config(0b0100, edge_count_type_pin2, edge_count_debounce_pin2),
                           device.set_edge_count_config(0b1000, edge_count_type_pin3, edge_count_debounce_pin3)],
        'options': [
            {
                'name': 'Edge Count Type (Pin 0)',
                'type': 'choice',
                'values': [('Rising', BrickletIndustrialDigitalIn4.EDGE_TYPE_RISING),
                           ('Falling', BrickletIndustrialDigitalIn4.EDGE_TYPE_FALLING),
                           ('Both', BrickletIndustrialDigitalIn4.EDGE_TYPE_BOTH)],
                'default': 'Rising'
            },
            {
                'name': 'Edge Count Debounce (Pin 0)',
                'type': 'int',
                'minimum': 0,
                'maximum': 255,
                'suffix': ' ms',
                'default': 100
            },
            {
                'name': 'Edge Count Type (Pin 1)',
                'type': 'choice',
                'values': [('Rising', BrickletIndustrialDigitalIn4.EDGE_TYPE_RISING),
                           ('Falling', BrickletIndustrialDigitalIn4.EDGE_TYPE_FALLING),
                           ('Both', BrickletIndustrialDigitalIn4.EDGE_TYPE_BOTH)],
                'default': 'Rising'
            },
            {
                'name': 'Edge Count Debounce (Pin 1)',
                'type': 'int',
                'minimum': 0,
                'maximum': 255,
                'suffix': ' ms',
                'default': 100
            },
            {
                'name': 'Edge Count Type (Pin 2)',
                'type': 'choice',
                'values': [('Rising', BrickletIndustrialDigitalIn4.EDGE_TYPE_RISING),
                           ('Falling', BrickletIndustrialDigitalIn4.EDGE_TYPE_FALLING),
                           ('Both', BrickletIndustrialDigitalIn4.EDGE_TYPE_BOTH)],
                'default': 'Rising'
            },
            {
                'name': 'Edge Count Debounce (Pin 2)',
                'type': 'int',
                'minimum': 0,
                'maximum': 255,
                'suffix': ' ms',
                'default': 100
            },
            {
                'name': 'Edge Count Type (Pin 3)',
                'type': 'choice',
                'values': [('Rising', BrickletIndustrialDigitalIn4.EDGE_TYPE_RISING),
                           ('Falling', BrickletIndustrialDigitalIn4.EDGE_TYPE_FALLING),
                           ('Both', BrickletIndustrialDigitalIn4.EDGE_TYPE_BOTH)],
                'default': 'Rising'
            },
            {
                'name': 'Edge Count Debounce (Pin 3)',
                'type': 'int',
                'minimum': 0,
                'maximum': 255,
                'suffix': ' ms',
                'default': 100
            }
        ]
    }
if BrickletIndustrialDigitalIn4V2_found:
    device_specs[BrickletIndustrialDigitalIn4V2.DEVICE_DISPLAY_NAME] = {
        'class': BrickletIndustrialDigitalIn4V2,
        'values': [
            {
                'name': 'Value',
                'getter': lambda device: device.get_value(),
                'subvalues': ['Channel0', 'Channel1', 'Channel2', 'Channel3'],
                'unit': [None, None, None, None],
                'advanced': False
            },
            {
                'name': 'Edge Count (Channel0)',
                'getter': lambda device: device.get_edge_count(0, False),
                'subvalues': None,
                'unit': None,
                'advanced': True
            },
            {
                'name': 'Edge Count (Channel1)',
                'getter': lambda device: device.get_edge_count(1, False),
                'subvalues': None,
                'unit': None,
                'advanced': True
            },
            {
                'name': 'Edge Count (Channel2)',
                'getter': lambda device: device.get_edge_count(2, False),
                'subvalues': None,
                'unit': None,
                'advanced': True
            },
            {
                'name': 'Edge Count (Channel3)',
                'getter': lambda device: device.get_edge_count(3, False),
                'subvalues': None,
                'unit': None,
                'advanced': True
            },
            {
                'name': 'Chip Temperature',
                'getter': lambda device: device.get_chip_temperature(),
                'subvalues': None,
                'unit': '°C',
                'advanced': True
            }
        ],
        'options_setter': lambda device, edge_count_type_channel0, edge_count_debounce_channel0, \
                                         edge_count_type_channel1, edge_count_debounce_channel1, \
                                         edge_count_type_channel2, edge_count_debounce_channel2, \
                                         edge_count_type_channel3, edge_count_debounce_channel3: \
                          [device.set_edge_count_configuration(0, edge_count_type_channel0, edge_count_debounce_channel0),
                           device.set_edge_count_configuration(1, edge_count_type_channel1, edge_count_debounce_channel1),
                           device.set_edge_count_configuration(2, edge_count_type_channel2, edge_count_debounce_channel2),
                           device.set_edge_count_configuration(3, edge_count_type_channel3, edge_count_debounce_channel3)],
        'options': [
            {
                'name': 'Edge Count Type (Channel0)',
                'type': 'choice',
                'values': [('Rising', BrickletIndustrialDigitalIn4V2.EDGE_TYPE_RISING),
                           ('Falling', BrickletIndustrialDigitalIn4V2.EDGE_TYPE_FALLING),
                           ('Both', BrickletIndustrialDigitalIn4V2.EDGE_TYPE_BOTH)],
                'default': 'Rising'
            },
            {
                'name': 'Edge Count Debounce (Channel0)',
                'type': 'int',
                'minimum': 0,
                'maximum': 255,
                'suffix': ' ms',
                'default': 100
            },
            {
                'name': 'Edge Count Type (Channel1)',
                'type': 'choice',
                'values': [('Rising', BrickletIndustrialDigitalIn4V2.EDGE_TYPE_RISING),
                           ('Falling', BrickletIndustrialDigitalIn4V2.EDGE_TYPE_FALLING),
                           ('Both', BrickletIndustrialDigitalIn4V2.EDGE_TYPE_BOTH)],
                'default': 'Rising'
            },
            {
                'name': 'Edge Count Debounce (Channel1)',
                'type': 'int',
                'minimum': 0,
                'maximum': 255,
                'suffix': ' ms',
                'default': 100
            },
            {
                'name': 'Edge Count Type (Channel2)',
                'type': 'choice',
                'values': [('Rising', BrickletIndustrialDigitalIn4V2.EDGE_TYPE_RISING),
                           ('Falling', BrickletIndustrialDigitalIn4V2.EDGE_TYPE_FALLING),
                           ('Both', BrickletIndustrialDigitalIn4V2.EDGE_TYPE_BOTH)],
                'default': 'Rising'
            },
            {
                'name': 'Edge Count Debounce (Channel2)',
                'type': 'int',
                'minimum': 0,
                'maximum': 255,
                'suffix': ' ms',
                'default': 100
            },
            {
                'name': 'Edge Count Type (Channel3)',
                'type': 'choice',
                'values': [('Rising', BrickletIndustrialDigitalIn4V2.EDGE_TYPE_RISING),
                           ('Falling', BrickletIndustrialDigitalIn4V2.EDGE_TYPE_FALLING),
                           ('Both', BrickletIndustrialDigitalIn4V2.EDGE_TYPE_BOTH)],
                'default': 'Rising'
            },
            {
                'name': 'Edge Count Debounce (Channel3)',
                'type': 'int',
                'minimum': 0,
                'maximum': 255,
                'suffix': ' ms',
                'default': 100
            }
        ]
    }
if BrickletIndustrialDual020mA_found:
    device_specs[BrickletIndustrialDual020mA.DEVICE_DISPLAY_NAME] = {
        'class': BrickletIndustrialDual020mA,
        'values': [
            {
                'name': 'Current (Sensor 0)',
                'getter': lambda device: device.get_current(0),
                'subvalues': None,
                'unit': 'nA',
                'advanced': False
            },
            {
                'name': 'Current (Sensor 1)',
                'getter': lambda device: device.get_current(1),
                'subvalues': None,
                'unit': 'nA',
                'advanced': False
            }
        ],
        'options_setter': lambda device, sample_rate: device.set_sample_rate(sample_rate),
        'options': [
            {
                'name': 'Sample Rate',
                'type': 'choice',
                'values': [('240 SPS', BrickletIndustrialDual020mA.SAMPLE_RATE_240_SPS),
                           ('60 SPS', BrickletIndustrialDual020mA.SAMPLE_RATE_60_SPS),
                           ('15 SPS', BrickletIndustrialDual020mA.SAMPLE_RATE_15_SPS),
                           ('4 SPS', BrickletIndustrialDual020mA.SAMPLE_RATE_4_SPS)],
                'default': '4 SPS'
            }
        ]
    }
if BrickletIndustrialDual020mAV2_found:
    device_specs[BrickletIndustrialDual020mAV2.DEVICE_DISPLAY_NAME] = {
        'class': BrickletIndustrialDual020mAV2,
        'values': [
            {
                'name': 'Current (Sensor 0)',
                'getter': lambda device: device.get_current(0),
                'subvalues': None,
                'unit': 'nA',
                'advanced': False
            },
            {
                'name': 'Current (Sensor 1)',
                'getter': lambda device: device.get_current(1),
                'subvalues': None,
                'unit': 'nA',
                'advanced': False
            }
        ],
        'options_setter': lambda device, sample_rate, gain: [device.set_sample_rate(sample_rate), device.set_gain(gain)],
        'options': [
            {
                'name': 'Sample Rate',
                'type': 'choice',
                'values': [('240 SPS', BrickletIndustrialDual020mAV2.SAMPLE_RATE_240_SPS),
                           ('60 SPS', BrickletIndustrialDual020mAV2.SAMPLE_RATE_60_SPS),
                           ('15 SPS', BrickletIndustrialDual020mAV2.SAMPLE_RATE_15_SPS),
                           ('4 SPS', BrickletIndustrialDual020mAV2.SAMPLE_RATE_4_SPS)],
                'default': '4 SPS'
            },
            {
                'name': 'Gain',
                'type': 'choice',
                'values': [('1x', BrickletIndustrialDual020mAV2.GAIN_1X),
                           ('2x', BrickletIndustrialDual020mAV2.GAIN_2X),
                           ('4x', BrickletIndustrialDual020mAV2.GAIN_4X),
                           ('8x', BrickletIndustrialDual020mAV2.GAIN_8X)],
                'default': '1x'
            }
        ]
    }
if BrickletIndustrialDualACRelay_found:
    device_specs[BrickletIndustrialDualACRelay.DEVICE_DISPLAY_NAME] = {
        'class': BrickletIndustrialDualACRelay,
        'values': [
            {
                'name': 'State',
                'getter': lambda device: device.get_value(),
                'subvalues': ['Channel0', 'Channel1'],
                'unit': [None, None],
                'advanced': False
            },
            {
                'name': 'Chip Temperature',
                'getter': lambda device: device.get_chip_temperature(),
                'subvalues': None,
                'unit': '°C',
                'advanced': True
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletIndustrialDualAnalogInV2_found:
    device_specs[BrickletIndustrialDualAnalogInV2.DEVICE_DISPLAY_NAME] = {
        'class': BrickletIndustrialDualAnalogInV2,
        'values': [
            {
                'name': 'Voltage (Channel0)',
                'getter': lambda device: device.get_voltage(0),
                'subvalues': None,
                'unit': 'mV',
                'advanced': False
            },
            {
                'name': 'Voltage (Channel1)',
                'getter': lambda device: device.get_voltage(1),
                'subvalues': None,
                'unit': 'mV',
                'advanced': False
            },
            {
                'name': 'ADC Values',
                'getter': lambda device: device.get_adc_values(),
                'subvalues': ['Channel0', 'Channel1'],
                'unit': [None, None],
                'advanced': True
            }
        ],
        'options_setter': lambda device, sample_rate: device.set_sample_rate(sample_rate),
        'options': [
            {
                'name': 'Sample Rate',
                'type': 'choice',
                'values': [('976 SPS', BrickletIndustrialDualAnalogInV2.SAMPLE_RATE_976_SPS),
                           ('488 SPS', BrickletIndustrialDualAnalogInV2.SAMPLE_RATE_488_SPS),
                           ('244 SPS', BrickletIndustrialDualAnalogInV2.SAMPLE_RATE_244_SPS),
                           ('122 SPS', BrickletIndustrialDualAnalogInV2.SAMPLE_RATE_122_SPS),
                           ('61 SPS', BrickletIndustrialDualAnalogInV2.SAMPLE_RATE_61_SPS),
                           ('4 SPS', BrickletIndustrialDualAnalogInV2.SAMPLE_RATE_4_SPS),
                           ('2 SPS', BrickletIndustrialDualAnalogInV2.SAMPLE_RATE_2_SPS),
                           ('1 SPS', BrickletIndustrialDualAnalogInV2.SAMPLE_RATE_1_SPS)],
                'default': '2 SPS'
            }
        ]
    }
if BrickletIndustrialDualAnalogIn_found:
    device_specs[BrickletIndustrialDualAnalogIn.DEVICE_DISPLAY_NAME] = {
        'class': BrickletIndustrialDualAnalogIn,
        'values': [
            {
                'name': 'Voltage (Channel0)',
                'getter': lambda device: device.get_voltage(0),
                'subvalues': None,
                'unit': 'mV',
                'advanced': False
            },
            {
                'name': 'Voltage (Channel1)',
                'getter': lambda device: device.get_voltage(1),
                'subvalues': None,
                'unit': 'mV',
                'advanced': False
            },
            {
                'name': 'ADC Values',
                'getter': lambda device: device.get_adc_values(),
                'subvalues': ['Channel0', 'Channel1'],
                'unit': [None, None],
                'advanced': True
            }
        ],
        'options_setter': lambda device, sample_rate: device.set_sample_rate(sample_rate),
        'options': [
            {
                'name': 'Sample Rate',
                'type': 'choice',
                'values': [('976 SPS', BrickletIndustrialDualAnalogIn.SAMPLE_RATE_976_SPS),
                           ('488 SPS', BrickletIndustrialDualAnalogIn.SAMPLE_RATE_488_SPS),
                           ('244 SPS', BrickletIndustrialDualAnalogIn.SAMPLE_RATE_244_SPS),
                           ('122 SPS', BrickletIndustrialDualAnalogIn.SAMPLE_RATE_122_SPS),
                           ('61 SPS', BrickletIndustrialDualAnalogIn.SAMPLE_RATE_61_SPS),
                           ('4 SPS', BrickletIndustrialDualAnalogIn.SAMPLE_RATE_4_SPS),
                           ('2 SPS', BrickletIndustrialDualAnalogIn.SAMPLE_RATE_2_SPS),
                           ('1 SPS', BrickletIndustrialDualAnalogIn.SAMPLE_RATE_1_SPS)],
                'default': '2 SPS'
            }
        ]
    }
if BrickletIndustrialDualRelay_found:
    device_specs[BrickletIndustrialDualRelay.DEVICE_DISPLAY_NAME] = {
        'class': BrickletIndustrialDualRelay,
        'values': [
            {
                'name': 'State',
                'getter': lambda device: device.get_value(),
                'subvalues': ['Channel0', 'Channel1'],
                'unit': [None, None],
                'advanced': False
            },
            {
                'name': 'Chip Temperature',
                'getter': lambda device: device.get_chip_temperature(),
                'subvalues': None,
                'unit': '°C',
                'advanced': True
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletIndustrialQuadRelay_found:
    device_specs[BrickletIndustrialQuadRelay.DEVICE_DISPLAY_NAME] = {
        'class': BrickletIndustrialQuadRelay,
        'values': [
            {
                'name': 'State',
                'getter': lambda device: value_to_bits(device.get_value(), 4),
                'subvalues': ['Relay1', 'Relay2', 'Relay3', 'Relay4'],
                'unit': [None, None, None, None],
                'advanced': False
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletIndustrialPTC_found:
    device_specs[BrickletIndustrialPTC.DEVICE_DISPLAY_NAME] = {
        'class': BrickletIndustrialPTC,
        'values': [
            {
                'name': 'Temperature',
                'getter': special_get_ptc_temperature,
                'subvalues': None,
                'unit': '°C/100',
                'advanced': False
            },
            {
                'name': 'Resistance',
                'getter': special_get_ptc_resistance,
                'subvalues': None,
                'unit': None,
                'advanced': True
            },
            {
                'name': 'Chip Temperature',
                'getter': lambda device: device.get_chip_temperature(),
                'subvalues': None,
                'unit': '°C',
                'advanced': True
            }
        ],
        'options_setter': lambda device, wire_mode: device.set_wire_mode(wire_mode),
        'options': [
            {
                'name': 'Wire Mode',
                'type': 'choice',
                'values': [('2-Wire', BrickletIndustrialPTC.WIRE_MODE_2),
                           ('3-Wire', BrickletIndustrialPTC.WIRE_MODE_3),
                           ('4-Wire', BrickletIndustrialPTC.WIRE_MODE_4)],
                'default': '2-Wire'
            }
        ]
    }
if BrickletIndustrialQuadRelayV2_found:
    device_specs[BrickletIndustrialQuadRelayV2.DEVICE_DISPLAY_NAME] = {
        'class': BrickletIndustrialQuadRelayV2,
        'values': [
            {
                'name': 'Value',
                'getter': lambda device: device.get_value(),
                'subvalues': ['Channel0', 'Channel1', 'Channel2', 'Channel3'],
                'unit': [None, None, None, None],
                'advanced': False
            },
            {
                'name': 'Chip Temperature',
                'getter': lambda device: device.get_chip_temperature(),
                'subvalues': None,
                'unit': '°C',
                'advanced': True
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletIO16_found:
    device_specs[BrickletIO16.DEVICE_DISPLAY_NAME] = {
        'class': BrickletIO16,
        'values': [
            {
                'name': 'Port A',
                'getter': lambda device: value_to_bits(device.get_port('a'), 8),
                'subvalues': ['Pin 0', 'Pin 1', 'Pin 2', 'Pin 3', 'Pin 4', 'Pin 5', 'Pin 6', 'Pin 7'],
                'unit': [None, None, None, None, None, None, None, None],
                'advanced': False
            },
            {
                'name': 'Port B',
                'getter': lambda device: value_to_bits(device.get_port('b'), 8),
                'subvalues': ['Pin 0', 'Pin 1', 'Pin 2', 'Pin 3', 'Pin 4', 'Pin 5', 'Pin 6', 'Pin 7'],
                'unit': [None, None, None, None, None, None, None, None],
                'advanced': False
            },
            {
                'name': 'Edge Count (Pin A0)',
                'getter': lambda device: device.get_edge_count(0, False),
                'subvalues': None,
                'unit': None,
                'advanced': True
            },
            {
                'name': 'Edge Count (Pin A1)',
                'getter': lambda device: device.get_edge_count(1, False),
                'subvalues': None,
                'unit': None,
                'advanced': True
            }
        ],
        'options_setter': lambda device,
                                 pinA0, pinA1, pinA2, pinA3, pinA4, pinA5, pinA6, pinA7,
                                 pinB0, pinB1, pinB2, pinB3, pinB4, pinB5, pinB6, pinB7,
                                 edge_count_type_pinA0, edge_count_debounce_pinA0, \
                                 edge_count_type_pinA1, edge_count_debounce_pinA1: \
                          [device.set_port_configuration(*pinA0),
                           device.set_port_configuration(*pinA1),
                           device.set_port_configuration(*pinA2),
                           device.set_port_configuration(*pinA3),
                           device.set_port_configuration(*pinA4),
                           device.set_port_configuration(*pinA5),
                           device.set_port_configuration(*pinA6),
                           device.set_port_configuration(*pinA7),
                           device.set_port_configuration(*pinB0),
                           device.set_port_configuration(*pinB1),
                           device.set_port_configuration(*pinB2),
                           device.set_port_configuration(*pinB3),
                           device.set_port_configuration(*pinB4),
                           device.set_port_configuration(*pinB5),
                           device.set_port_configuration(*pinB6),
                           device.set_port_configuration(*pinB7),
                           device.set_edge_count_config(0, edge_count_type_pinA0, edge_count_debounce_pinA0),
                           device.set_edge_count_config(1, edge_count_type_pinA1, edge_count_debounce_pinA1)],
        'options': [
            {
                'name': 'Pin A0',
                'type': 'choice',
                'values': [('Input Pull-Up', ('a', 0b00000001, 'i', True)),
                           ('Input', ('a', 0b00000001, 'i', False)),
                           ('Output High', ('a', 0b00000001, 'o', True)),
                           ('Output Low', ('a', 0b00000001, 'o', False))],
                'default': 'Input Pull-Up'
            },
            {
                'name': 'Pin A1',
                'type': 'choice',
                'values': [('Input Pull-Up', ('a', 0b00000010, 'i', True)),
                           ('Input', ('a', 0b00000010, 'i', False)),
                           ('Output High', ('a', 0b00000010, 'o', True)),
                           ('Output Low', ('a', 0b00000010, 'o', False))],
                'default': 'Input Pull-Up'
            },
            {
                'name': 'Pin A2',
                'type': 'choice',
                'values': [('Input Pull-Up', ('a', 0b00000100, 'i', True)),
                           ('Input', ('a', 0b00000100, 'i', False)),
                           ('Output High', ('a', 0b00000100, 'o', True)),
                           ('Output Low', ('a', 0b00000100, 'o', False))],
                'default': 'Input Pull-Up'
            },
            {
                'name': 'Pin A3',
                'type': 'choice',
                'values': [('Input Pull-Up', ('a', 0b00001000, 'i', True)),
                           ('Input', ('a', 0b00001000, 'i', False)),
                           ('Output High', ('a', 0b00001000, 'o', True)),
                           ('Output Low', ('a', 0b00001000, 'o', False))],
                'default': 'Input Pull-Up'
            },
            {
                'name': 'Pin A4',
                'type': 'choice',
                'values': [('Input Pull-Up', ('a', 0b00010000, 'i', True)),
                           ('Input', ('a', 0b00010000, 'i', False)),
                           ('Output High', ('a', 0b00010000, 'o', True)),
                           ('Output Low', ('a', 0b00010000, 'o', False))],
                'default': 'Input Pull-Up'
            },
            {
                'name': 'Pin A5',
                'type': 'choice',
                'values': [('Input Pull-Up', ('a', 0b00100000, 'i', True)),
                           ('Input', ('a', 0b00100000, 'i', False)),
                           ('Output High', ('a', 0b00100000, 'o', True)),
                           ('Output Low', ('a', 0b00100000, 'o', False))],
                'default': 'Input Pull-Up'
            },
            {
                'name': 'Pin A6',
                'type': 'choice',
                'values': [('Input Pull-Up', ('a', 0b01000000, 'i', True)),
                           ('Input', ('a', 0b01000000, 'i', False)),
                           ('Output High', ('a', 0b01000000, 'o', True)),
                           ('Output Low', ('a', 0b01000000, 'o', False))],
                'default': 'Input Pull-Up'
            },
            {
                'name': 'Pin A7',
                'type': 'choice',
                'values': [('Input Pull-Up', ('a', 0b10000000, 'i', True)),
                           ('Input', ('a', 0b10000000, 'i', False)),
                           ('Output High', ('a', 0b10000000, 'o', True)),
                           ('Output Low', ('a', 0b10000000, 'o', False))],
                'default': 'Input Pull-Up'
            },
            {
                'name': 'Pin B0',
                'type': 'choice',
                'values': [('Input Pull-Up', ('b', 0b00000001, 'i', True)),
                           ('Input', ('b', 0b00000001, 'i', False)),
                           ('Output High', ('b', 0b00000001, 'o', True)),
                           ('Output Low', ('b', 0b00000001, 'o', False))],
                'default': 'Input Pull-Up'
            },
            {
                'name': 'Pin B1',
                'type': 'choice',
                'values': [('Input Pull-Up', ('b', 0b00000010, 'i', True)),
                           ('Input', ('b', 0b00000010, 'i', False)),
                           ('Output High', ('b', 0b00000010, 'o', True)),
                           ('Output Low', ('b', 0b00000010, 'o', False))],
                'default': 'Input Pull-Up'
            },
            {
                'name': 'Pin B2',
                'type': 'choice',
                'values': [('Input Pull-Up', ('b', 0b00000100, 'i', True)),
                           ('Input', ('b', 0b00000100, 'i', False)),
                           ('Output High', ('b', 0b00000100, 'o', True)),
                           ('Output Low', ('b', 0b00000100, 'o', False))],
                'default': 'Input Pull-Up'
            },
            {
                'name': 'Pin B3',
                'type': 'choice',
                'values': [('Input Pull-Up', ('b', 0b00001000, 'i', True)),
                           ('Input', ('b', 0b00001000, 'i', False)),
                           ('Output High', ('b', 0b00001000, 'o', True)),
                           ('Output Low', ('b', 0b00001000, 'o', False))],
                'default': 'Input Pull-Up'
            },
            {
                'name': 'Pin B4',
                'type': 'choice',
                'values': [('Input Pull-Up', ('b', 0b00010000, 'i', True)),
                           ('Input', ('b', 0b00010000, 'i', False)),
                           ('Output High', ('b', 0b00010000, 'o', True)),
                           ('Output Low', ('b', 0b00010000, 'o', False))],
                'default': 'Input Pull-Up'
            },
            {
                'name': 'Pin B5',
                'type': 'choice',
                'values': [('Input Pull-Up', ('b', 0b00100000, 'i', True)),
                           ('Input', ('b', 0b00100000, 'i', False)),
                           ('Output High', ('b', 0b00100000, 'o', True)),
                           ('Output Low', ('b', 0b00100000, 'o', False))],
                'default': 'Input Pull-Up'
            },
            {
                'name': 'Pin B6',
                'type': 'choice',
                'values': [('Input Pull-Up', ('b', 0b01000000, 'i', True)),
                           ('Input', ('b', 0b01000000, 'i', False)),
                           ('Output High', ('b', 0b01000000, 'o', True)),
                           ('Output Low', ('b', 0b01000000, 'o', False))],
                'default': 'Input Pull-Up'
            },
            {
                'name': 'Pin B7',
                'type': 'choice',
                'values': [('Input Pull-Up', ('b', 0b10000000, 'i', True)),
                           ('Input', ('b', 0b10000000, 'i', False)),
                           ('Output High', ('b', 0b10000000, 'o', True)),
                           ('Output Low', ('b', 0b10000000, 'o', False))],
                'default': 'Input Pull-Up'
            },
            {
                'name': 'Edge Count Type (Pin A0)',
                'type': 'choice',
                'values': [('Rising', BrickletIO16.EDGE_TYPE_RISING),
                           ('Falling', BrickletIO16.EDGE_TYPE_FALLING),
                           ('Both', BrickletIO16.EDGE_TYPE_BOTH)],
                'default': 'Rising'
            },
            {
                'name': 'Edge Count Debounce (Pin A0)',
                'type': 'int',
                'minimum': 0,
                'maximum': 255,
                'suffix': ' ms',
                'default': 100
            },
            {
                'name': 'Edge Count Type (Pin A1)',
                'type': 'choice',
                'values': [('Rising', BrickletIO16.EDGE_TYPE_RISING),
                           ('Falling', BrickletIO16.EDGE_TYPE_FALLING),
                           ('Both', BrickletIO16.EDGE_TYPE_BOTH)],
                'default': 'Rising'
            },
            {
                'name': 'Edge Count Debounce (Pin A1)',
                'type': 'int',
                'minimum': 0,
                'maximum': 255,
                'suffix': ' ms',
                'default': 100
            }
        ]
    }
if BrickletIO16V2_found:
    device_specs[BrickletIO16V2.DEVICE_DISPLAY_NAME] = {
        'class': BrickletIO16V2,
        'values': [
            {
                'name': 'Value',
                'getter': lambda device: device.get_value(),
                'subvalues': ['Channel0', 'Channel1', 'Channel2', 'Channel3', 'Channel4', 'Channel5', 'Channel6', 'Channel7', 'Channel8', 'Channel9', 'Channel10', 'Channel11', 'Channel12', 'Channel13', 'Channel14', 'Channel15'],
                'unit': [None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None],
                'advanced': False
            },
            {
                'name': 'Edge Count (Channel0)',
                'getter': lambda device: device.get_edge_count(0, False),
                'subvalues': None,
                'unit': None,
                'advanced': True
            },
            {
                'name': 'Edge Count (Channel1)',
                'getter': lambda device: device.get_edge_count(1, False),
                'subvalues': None,
                'unit': None,
                'advanced': True
            },
            {
                'name': 'Edge Count (Channel2)',
                'getter': lambda device: device.get_edge_count(2, False),
                'subvalues': None,
                'unit': None,
                'advanced': True
            },
            {
                'name': 'Edge Count (Channel3)',
                'getter': lambda device: device.get_edge_count(3, False),
                'subvalues': None,
                'unit': None,
                'advanced': True
            },
            {
                'name': 'Edge Count (Channel4)',
                'getter': lambda device: device.get_edge_count(4, False),
                'subvalues': None,
                'unit': None,
                'advanced': True
            },
            {
                'name': 'Edge Count (Channel5)',
                'getter': lambda device: device.get_edge_count(5, False),
                'subvalues': None,
                'unit': None,
                'advanced': True
            },
            {
                'name': 'Edge Count (Channel6)',
                'getter': lambda device: device.get_edge_count(6, False),
                'subvalues': None,
                'unit': None,
                'advanced': True
            },
            {
                'name': 'Edge Count (Channel7)',
                'getter': lambda device: device.get_edge_count(7, False),
                'subvalues': None,
                'unit': None,
                'advanced': True
            },
            {
                'name': 'Edge Count (Channel8)',
                'getter': lambda device: device.get_edge_count(8, False),
                'subvalues': None,
                'unit': None,
                'advanced': True
            },
            {
                'name': 'Edge Count (Channel9)',
                'getter': lambda device: device.get_edge_count(9, False),
                'subvalues': None,
                'unit': None,
                'advanced': True
            },
            {
                'name': 'Edge Count (Channel10)',
                'getter': lambda device: device.get_edge_count(10, False),
                'subvalues': None,
                'unit': None,
                'advanced': True
            },
            {
                'name': 'Edge Count (Channel11)',
                'getter': lambda device: device.get_edge_count(11, False),
                'subvalues': None,
                'unit': None,
                'advanced': True
            },
            {
                'name': 'Edge Count (Channel12)',
                'getter': lambda device: device.get_edge_count(12, False),
                'subvalues': None,
                'unit': None,
                'advanced': True
            },
            {
                'name': 'Edge Count (Channel13)',
                'getter': lambda device: device.get_edge_count(13, False),
                'subvalues': None,
                'unit': None,
                'advanced': True
            },
            {
                'name': 'Edge Count (Channel14)',
                'getter': lambda device: device.get_edge_count(14, False),
                'subvalues': None,
                'unit': None,
                'advanced': True
            },
            {
                'name': 'Edge Count (Channel15)',
                'getter': lambda device: device.get_edge_count(15, False),
                'subvalues': None,
                'unit': None,
                'advanced': True
            },
            {
                'name': 'Chip Temperature',
                'getter': lambda device: device.get_chip_temperature(),
                'subvalues': None,
                'unit': '°C',
                'advanced': True
            }
        ],
        'options_setter': lambda device,
                                 channel0,
                                 channel1,
                                 channel2,
                                 channel3,
                                 channel4,
                                 channel5,
                                 channel6,
                                 channel7,
                                 channel8,
                                 channel9,
                                 channel10,
                                 channel11,
                                 channel12,
                                 channel13,
                                 channel14,
                                 channel15,
                                 edge_count_type_channel0,
                                 edge_count_debounce_channel0,
                                 edge_count_type_channel1,
                                 edge_count_debounce_channel1,
                                 edge_count_type_channel2,
                                 edge_count_debounce_channel2,
                                 edge_count_type_channel3,
                                 edge_count_debounce_channel3,
                                 edge_count_type_channel4,
                                 edge_count_debounce_channel4,
                                 edge_count_type_channel5,
                                 edge_count_debounce_channel5,
                                 edge_count_type_channel6,
                                 edge_count_debounce_channel6,
                                 edge_count_type_channel7,
                                 edge_count_debounce_channel7,
                                 edge_count_type_channel8,
                                 edge_count_debounce_channel8,
                                 edge_count_type_channel9,
                                 edge_count_debounce_channel9,
                                 edge_count_type_channel10,
                                 edge_count_debounce_channel10,
                                 edge_count_type_channel11,
                                 edge_count_debounce_channel11,
                                 edge_count_type_channel12,
                                 edge_count_debounce_channel12,
                                 edge_count_type_channel13,
                                 edge_count_debounce_channel13,
                                 edge_count_type_channel14,
                                 edge_count_debounce_channel14,
                                 edge_count_type_channel15,
                                 edge_count_debounce_channel15:
                          [device.set_configuration(0, *channel0),
                           device.set_configuration(1, *channel1),
                           device.set_configuration(2, *channel2),
                           device.set_configuration(3, *channel3),
                           device.set_configuration(4, *channel4),
                           device.set_configuration(5, *channel5),
                           device.set_configuration(6, *channel6),
                           device.set_configuration(7, *channel7),
                           device.set_configuration(8, *channel8),
                           device.set_configuration(9, *channel9),
                           device.set_configuration(10, *channel10),
                           device.set_configuration(11, *channel11),
                           device.set_configuration(12, *channel12),
                           device.set_configuration(13, *channel13),
                           device.set_configuration(14, *channel14),
                           device.set_configuration(15, *channel15),
                           device.set_edge_count_configuration(0, edge_count_type_channel0, edge_count_debounce_channel0),
                           device.set_edge_count_configuration(1, edge_count_type_channel1, edge_count_debounce_channel1),
                           device.set_edge_count_configuration(2, edge_count_type_channel2, edge_count_debounce_channel2),
                           device.set_edge_count_configuration(3, edge_count_type_channel3, edge_count_debounce_channel3),
                           device.set_edge_count_configuration(4, edge_count_type_channel4, edge_count_debounce_channel4),
                           device.set_edge_count_configuration(5, edge_count_type_channel5, edge_count_debounce_channel5),
                           device.set_edge_count_configuration(6, edge_count_type_channel6, edge_count_debounce_channel6),
                           device.set_edge_count_configuration(7, edge_count_type_channel7, edge_count_debounce_channel7),
                           device.set_edge_count_configuration(8, edge_count_type_channel8, edge_count_debounce_channel8),
                           device.set_edge_count_configuration(9, edge_count_type_channel9, edge_count_debounce_channel9),
                           device.set_edge_count_configuration(10, edge_count_type_channel10, edge_count_debounce_channel10),
                           device.set_edge_count_configuration(11, edge_count_type_channel11, edge_count_debounce_channel11),
                           device.set_edge_count_configuration(12, edge_count_type_channel12, edge_count_debounce_channel12),
                           device.set_edge_count_configuration(13, edge_count_type_channel13, edge_count_debounce_channel13),
                           device.set_edge_count_configuration(14, edge_count_type_channel14, edge_count_debounce_channel14),
                           device.set_edge_count_configuration(15, edge_count_type_channel15, edge_count_debounce_channel15)],
        'options': [
            {
                'name': 'Channel0',
                'type': 'choice',
                'values': [('Input Pull-Up', ('i', True)),
                           ('Input', ('i', False)),
                           ('Output High', ('o', True)),
                           ('Output Low', ('o', False))],
                'default': 'Input Pull-Up'
            },
            {
                'name': 'Channel1',
                'type': 'choice',
                'values': [('Input Pull-Up', ('i', True)),
                           ('Input', ('i', False)),
                           ('Output High', ('o', True)),
                           ('Output Low', ('o', False))],
                'default': 'Input Pull-Up'
            },
            {
                'name': 'Channel2',
                'type': 'choice',
                'values': [('Input Pull-Up', ('i', True)),
                           ('Input', ('i', False)),
                           ('Output High', ('o', True)),
                           ('Output Low', ('o', False))],
                'default': 'Input Pull-Up'
            },
            {
                'name': 'Channel3',
                'type': 'choice',
                'values': [('Input Pull-Up', ('i', True)),
                           ('Input', ('i', False)),
                           ('Output High', ('o', True)),
                           ('Output Low', ('o', False))],
                'default': 'Input Pull-Up'
            },
            {
                'name': 'Channel4',
                'type': 'choice',
                'values': [('Input Pull-Up', ('i', True)),
                           ('Input', ('i', False)),
                           ('Output High', ('o', True)),
                           ('Output Low', ('o', False))],
                'default': 'Input Pull-Up'
            },
            {
                'name': 'Channel5',
                'type': 'choice',
                'values': [('Input Pull-Up', ('i', True)),
                           ('Input', ('i', False)),
                           ('Output High', ('o', True)),
                           ('Output Low', ('o', False))],
                'default': 'Input Pull-Up'
            },
            {
                'name': 'Channel6',
                'type': 'choice',
                'values': [('Input Pull-Up', ('i', True)),
                           ('Input', ('i', False)),
                           ('Output High', ('o', True)),
                           ('Output Low', ('o', False))],
                'default': 'Input Pull-Up'
            },
            {
                'name': 'Channel7',
                'type': 'choice',
                'values': [('Input Pull-Up', ('i', True)),
                           ('Input', ('i', False)),
                           ('Output High', ('o', True)),
                           ('Output Low', ('o', False))],
                'default': 'Input Pull-Up'
            },
            {
                'name': 'Channel8',
                'type': 'choice',
                'values': [('Input Pull-Up', ('i', True)),
                           ('Input', ('i', False)),
                           ('Output High', ('o', True)),
                           ('Output Low', ('o', False))],
                'default': 'Input Pull-Up'
            },
            {
                'name': 'Channel9',
                'type': 'choice',
                'values': [('Input Pull-Up', ('i', True)),
                           ('Input', ('i', False)),
                           ('Output High', ('o', True)),
                           ('Output Low', ('o', False))],
                'default': 'Input Pull-Up'
            },
            {
                'name': 'Channel10',
                'type': 'choice',
                'values': [('Input Pull-Up', ('i', True)),
                           ('Input', ('i', False)),
                           ('Output High', ('o', True)),
                           ('Output Low', ('o', False))],
                'default': 'Input Pull-Up'
            },
            {
                'name': 'Channel11',
                'type': 'choice',
                'values': [('Input Pull-Up', ('i', True)),
                           ('Input', ('i', False)),
                           ('Output High', ('o', True)),
                           ('Output Low', ('o', False))],
                'default': 'Input Pull-Up'
            },
            {
                'name': 'Channel12',
                'type': 'choice',
                'values': [('Input Pull-Up', ('i', True)),
                           ('Input', ('i', False)),
                           ('Output High', ('o', True)),
                           ('Output Low', ('o', False))],
                'default': 'Input Pull-Up'
            },
            {
                'name': 'Channel13',
                'type': 'choice',
                'values': [('Input Pull-Up', ('i', True)),
                           ('Input', ('i', False)),
                           ('Output High', ('o', True)),
                           ('Output Low', ('o', False))],
                'default': 'Input Pull-Up'
            },
            {
                'name': 'Channel14',
                'type': 'choice',
                'values': [('Input Pull-Up', ('i', True)),
                           ('Input', ('i', False)),
                           ('Output High', ('o', True)),
                           ('Output Low', ('o', False))],
                'default': 'Input Pull-Up'
            },
            {
                'name': 'Channel15',
                'type': 'choice',
                'values': [('Input Pull-Up', ('i', True)),
                           ('Input', ('i', False)),
                           ('Output High', ('o', True)),
                           ('Output Low', ('o', False))],
                'default': 'Input Pull-Up'
            },
            {
                'name': 'Edge Count Type (Channel0)',
                'type': 'choice',
                'values': [('Rising', BrickletIO16V2.EDGE_TYPE_RISING),
                           ('Falling', BrickletIO16V2.EDGE_TYPE_FALLING),
                           ('Both', BrickletIO16V2.EDGE_TYPE_BOTH)],
                'default': 'Rising'
            },
            {
                'name': 'Edge Count Debounce (Channel0)',
                'type': 'int',
                'minimum': 0,
                'maximum': 255,
                'suffix': ' ms',
                'default': 100
            },
            {
                'name': 'Edge Count Type (Channel1)',
                'type': 'choice',
                'values': [('Rising', BrickletIO16V2.EDGE_TYPE_RISING),
                           ('Falling', BrickletIO16V2.EDGE_TYPE_FALLING),
                           ('Both', BrickletIO16V2.EDGE_TYPE_BOTH)],
                'default': 'Rising'
            },
            {
                'name': 'Edge Count Debounce (Channel1)',
                'type': 'int',
                'minimum': 0,
                'maximum': 255,
                'suffix': ' ms',
                'default': 100
            },
            {
                'name': 'Edge Count Type (Channel2)',
                'type': 'choice',
                'values': [('Rising', BrickletIO16V2.EDGE_TYPE_RISING),
                           ('Falling', BrickletIO16V2.EDGE_TYPE_FALLING),
                           ('Both', BrickletIO16V2.EDGE_TYPE_BOTH)],
                'default': 'Rising'
            },
            {
                'name': 'Edge Count Debounce (Channel2)',
                'type': 'int',
                'minimum': 0,
                'maximum': 255,
                'suffix': ' ms',
                'default': 100
            },
            {
                'name': 'Edge Count Type (Channel3)',
                'type': 'choice',
                'values': [('Rising', BrickletIO16V2.EDGE_TYPE_RISING),
                           ('Falling', BrickletIO16V2.EDGE_TYPE_FALLING),
                           ('Both', BrickletIO16V2.EDGE_TYPE_BOTH)],
                'default': 'Rising'
            },
            {
                'name': 'Edge Count Debounce (Channel3)',
                'type': 'int',
                'minimum': 0,
                'maximum': 255,
                'suffix': ' ms',
                'default': 100
            },
            {
                'name': 'Edge Count Type (Channel4)',
                'type': 'choice',
                'values': [('Rising', BrickletIO16V2.EDGE_TYPE_RISING),
                           ('Falling', BrickletIO16V2.EDGE_TYPE_FALLING),
                           ('Both', BrickletIO16V2.EDGE_TYPE_BOTH)],
                'default': 'Rising'
            },
            {
                'name': 'Edge Count Debounce (Channel4)',
                'type': 'int',
                'minimum': 0,
                'maximum': 255,
                'suffix': ' ms',
                'default': 100
            },
            {
                'name': 'Edge Count Type (Channel5)',
                'type': 'choice',
                'values': [('Rising', BrickletIO16V2.EDGE_TYPE_RISING),
                           ('Falling', BrickletIO16V2.EDGE_TYPE_FALLING),
                           ('Both', BrickletIO16V2.EDGE_TYPE_BOTH)],
                'default': 'Rising'
            },
            {
                'name': 'Edge Count Debounce (Channel5)',
                'type': 'int',
                'minimum': 0,
                'maximum': 255,
                'suffix': ' ms',
                'default': 100
            },
            {
                'name': 'Edge Count Type (Channel6)',
                'type': 'choice',
                'values': [('Rising', BrickletIO16V2.EDGE_TYPE_RISING),
                           ('Falling', BrickletIO16V2.EDGE_TYPE_FALLING),
                           ('Both', BrickletIO16V2.EDGE_TYPE_BOTH)],
                'default': 'Rising'
            },
            {
                'name': 'Edge Count Debounce (Channel6)',
                'type': 'int',
                'minimum': 0,
                'maximum': 255,
                'suffix': ' ms',
                'default': 100
            },
            {
                'name': 'Edge Count Type (Channel7)',
                'type': 'choice',
                'values': [('Rising', BrickletIO16V2.EDGE_TYPE_RISING),
                           ('Falling', BrickletIO16V2.EDGE_TYPE_FALLING),
                           ('Both', BrickletIO16V2.EDGE_TYPE_BOTH)],
                'default': 'Rising'
            },
            {
                'name': 'Edge Count Debounce (Channel7)',
                'type': 'int',
                'minimum': 0,
                'maximum': 255,
                'suffix': ' ms',
                'default': 100
            },
            {
                'name': 'Edge Count Type (Channel8)',
                'type': 'choice',
                'values': [('Rising', BrickletIO16V2.EDGE_TYPE_RISING),
                           ('Falling', BrickletIO16V2.EDGE_TYPE_FALLING),
                           ('Both', BrickletIO16V2.EDGE_TYPE_BOTH)],
                'default': 'Rising'
            },
            {
                'name': 'Edge Count Debounce (Channel8)',
                'type': 'int',
                'minimum': 0,
                'maximum': 255,
                'suffix': ' ms',
                'default': 100
            },
            {
                'name': 'Edge Count Type (Channel9)',
                'type': 'choice',
                'values': [('Rising', BrickletIO16V2.EDGE_TYPE_RISING),
                           ('Falling', BrickletIO16V2.EDGE_TYPE_FALLING),
                           ('Both', BrickletIO16V2.EDGE_TYPE_BOTH)],
                'default': 'Rising'
            },
            {
                'name': 'Edge Count Debounce (Channel9)',
                'type': 'int',
                'minimum': 0,
                'maximum': 255,
                'suffix': ' ms',
                'default': 100
            },
            {
                'name': 'Edge Count Type (Channel10)',
                'type': 'choice',
                'values': [('Rising', BrickletIO16V2.EDGE_TYPE_RISING),
                           ('Falling', BrickletIO16V2.EDGE_TYPE_FALLING),
                           ('Both', BrickletIO16V2.EDGE_TYPE_BOTH)],
                'default': 'Rising'
            },
            {
                'name': 'Edge Count Debounce (Channel10)',
                'type': 'int',
                'minimum': 0,
                'maximum': 255,
                'suffix': ' ms',
                'default': 100
            },
            {
                'name': 'Edge Count Type (Channel11)',
                'type': 'choice',
                'values': [('Rising', BrickletIO16V2.EDGE_TYPE_RISING),
                           ('Falling', BrickletIO16V2.EDGE_TYPE_FALLING),
                           ('Both', BrickletIO16V2.EDGE_TYPE_BOTH)],
                'default': 'Rising'
            },
            {
                'name': 'Edge Count Debounce (Channel11)',
                'type': 'int',
                'minimum': 0,
                'maximum': 255,
                'suffix': ' ms',
                'default': 100
            },
            {
                'name': 'Edge Count Type (Channel12)',
                'type': 'choice',
                'values': [('Rising', BrickletIO16V2.EDGE_TYPE_RISING),
                           ('Falling', BrickletIO16V2.EDGE_TYPE_FALLING),
                           ('Both', BrickletIO16V2.EDGE_TYPE_BOTH)],
                'default': 'Rising'
            },
            {
                'name': 'Edge Count Debounce (Channel12)',
                'type': 'int',
                'minimum': 0,
                'maximum': 255,
                'suffix': ' ms',
                'default': 100
            },
            {
                'name': 'Edge Count Type (Channel13)',
                'type': 'choice',
                'values': [('Rising', BrickletIO16V2.EDGE_TYPE_RISING),
                           ('Falling', BrickletIO16V2.EDGE_TYPE_FALLING),
                           ('Both', BrickletIO16V2.EDGE_TYPE_BOTH)],
                'default': 'Rising'
            },
            {
                'name': 'Edge Count Debounce (Channel13)',
                'type': 'int',
                'minimum': 0,
                'maximum': 255,
                'suffix': ' ms',
                'default': 100
            },
            {
                'name': 'Edge Count Type (Channel14)',
                'type': 'choice',
                'values': [('Rising', BrickletIO16V2.EDGE_TYPE_RISING),
                           ('Falling', BrickletIO16V2.EDGE_TYPE_FALLING),
                           ('Both', BrickletIO16V2.EDGE_TYPE_BOTH)],
                'default': 'Rising'
            },
            {
                'name': 'Edge Count Debounce (Channel14)',
                'type': 'int',
                'minimum': 0,
                'maximum': 255,
                'suffix': ' ms',
                'default': 100
            },
            {
                'name': 'Edge Count Type (Channel15)',
                'type': 'choice',
                'values': [('Rising', BrickletIO16V2.EDGE_TYPE_RISING),
                           ('Falling', BrickletIO16V2.EDGE_TYPE_FALLING),
                           ('Both', BrickletIO16V2.EDGE_TYPE_BOTH)],
                'default': 'Rising'
            },
            {
                'name': 'Edge Count Debounce (Channel15)',
                'type': 'int',
                'minimum': 0,
                'maximum': 255,
                'suffix': ' ms',
                'default': 100
            }
        ]
    }
if BrickletIO4_found:
    device_specs[BrickletIO4.DEVICE_DISPLAY_NAME] = {
        'class': BrickletIO4,
        'values': [
            {
                'name': 'Value',
                'getter': lambda device: value_to_bits(device.get_value(), 4),
                'subvalues': ['Pin 0', 'Pin 1', 'Pin 2', 'Pin 3'],
                'unit': [None, None, None, None],
                'advanced': False
            },
            {
                'name': 'Edge Count (Pin 0)',
                'getter': lambda device: device.get_edge_count(0, False),
                'subvalues': None,
                'unit': None,
                'advanced': True
            },
            {
                'name': 'Edge Count (Pin 1)',
                'getter': lambda device: device.get_edge_count(1, False),
                'subvalues': None,
                'unit': None,
                'advanced': True
            },
            {
                'name': 'Edge Count (Pin 2)',
                'getter': lambda device: device.get_edge_count(2, False),
                'subvalues': None,
                'unit': None,
                'advanced': True
            },
            {
                'name': 'Edge Count (Pin 3)',
                'getter': lambda device: device.get_edge_count(3, False),
                'subvalues': None,
                'unit': None,
                'advanced': True
            }
        ],
        'options_setter': lambda device,
                                 pin0, pin1, pin2, pin3,
                                 edge_count_type_pin0, edge_count_debounce_pin0, \
                                 edge_count_type_pin1, edge_count_debounce_pin1, \
                                 edge_count_type_pin2, edge_count_debounce_pin2, \
                                 edge_count_type_pin3, edge_count_debounce_pin3: \
                          [device.set_configuration(0b0001, *pin0),
                           device.set_configuration(0b0010, *pin1),
                           device.set_configuration(0b0100, *pin2),
                           device.set_configuration(0b1000, *pin3),
                           device.set_edge_count_config(0b0001, edge_count_type_pin0, edge_count_debounce_pin0),
                           device.set_edge_count_config(0b0010, edge_count_type_pin1, edge_count_debounce_pin1),
                           device.set_edge_count_config(0b0100, edge_count_type_pin2, edge_count_debounce_pin2),
                           device.set_edge_count_config(0b1000, edge_count_type_pin3, edge_count_debounce_pin3)],
        'options': [
            {
                'name': 'Pin 0',
                'type': 'choice',
                'values': [('Input Pull-Up', ('i', True)),
                           ('Input', ('i', False)),
                           ('Output High', ('o', True)),
                           ('Output Low', ('o', False))],
                'default': 'Input Pull-Up'
            },
            {
                'name': 'Pin 1',
                'type': 'choice',
                'values': [('Input Pull-Up', ('i', True)),
                           ('Input', ('i', False)),
                           ('Output High', ('o', True)),
                           ('Output Low', ('o', False))],
                'default': 'Input Pull-Up'
            },
            {
                'name': 'Pin 2',
                'type': 'choice',
                'values': [('Input Pull-Up', ('i', True)),
                           ('Input', ('i', False)),
                           ('Output High', ('o', True)),
                           ('Output Low', ('o', False))],
                'default': 'Input Pull-Up'
            },
            {
                'name': 'Pin 3',
                'type': 'choice',
                'values': [('Input Pull-Up', ('i', True)),
                           ('Input', ('i', False)),
                           ('Output High', ('o', True)),
                           ('Output Low', ('o', False))],
                'default': 'Input Pull-Up'
            },
            {
                'name': 'Edge Count Type (Pin 0)',
                'type': 'choice',
                'values': [('Rising', BrickletIO4.EDGE_TYPE_RISING),
                           ('Falling', BrickletIO4.EDGE_TYPE_FALLING),
                           ('Both', BrickletIO4.EDGE_TYPE_BOTH)],
                'default': 'Rising'
            },
            {
                'name': 'Edge Count Debounce (Pin 0)',
                'type': 'int',
                'minimum': 0,
                'maximum': 255,
                'suffix': ' ms',
                'default': 100
            },
            {
                'name': 'Edge Count Type (Pin 1)',
                'type': 'choice',
                'values': [('Rising', BrickletIO4.EDGE_TYPE_RISING),
                           ('Falling', BrickletIO4.EDGE_TYPE_FALLING),
                           ('Both', BrickletIO4.EDGE_TYPE_BOTH)],
                'default': 'Rising'
            },
            {
                'name': 'Edge Count Debounce (Pin 1)',
                'type': 'int',
                'minimum': 0,
                'maximum': 255,
                'suffix': ' ms',
                'default': 100
            },
            {
                'name': 'Edge Count Type (Pin 2)',
                'type': 'choice',
                'values': [('Rising', BrickletIO4.EDGE_TYPE_RISING),
                           ('Falling', BrickletIO4.EDGE_TYPE_FALLING),
                           ('Both', BrickletIO4.EDGE_TYPE_BOTH)],
                'default': 'Rising'
            },
            {
                'name': 'Edge Count Debounce (Pin 2)',
                'type': 'int',
                'minimum': 0,
                'maximum': 255,
                'suffix': ' ms',
                'default': 100
            },
            {
                'name': 'Edge Count Type (Pin 3)',
                'type': 'choice',
                'values': [('Rising', BrickletIO4.EDGE_TYPE_RISING),
                           ('Falling', BrickletIO4.EDGE_TYPE_FALLING),
                           ('Both', BrickletIO4.EDGE_TYPE_BOTH)],
                'default': 'Rising'
            },
            {
                'name': 'Edge Count Debounce (Pin 3)',
                'type': 'int',
                'minimum': 0,
                'maximum': 255,
                'suffix': ' ms',
                'default': 100
            }
        ]
    }
if BrickletIO4V2_found:
    device_specs[BrickletIO4V2.DEVICE_DISPLAY_NAME] = {
        'class': BrickletIO4V2,
        'values': [
            {
                'name': 'Value',
                'getter': lambda device: device.get_value(),
                'subvalues': ['Channel0', 'Channel1', 'Channel2', 'Channel3'],
                'unit': [None, None, None, None],
                'advanced': False
            },
            {
                'name': 'Edge Count (Channel0)',
                'getter': lambda device: device.get_edge_count(0, False),
                'subvalues': None,
                'unit': None,
                'advanced': True
            },
            {
                'name': 'Edge Count (Channel1)',
                'getter': lambda device: device.get_edge_count(1, False),
                'subvalues': None,
                'unit': None,
                'advanced': True
            },
            {
                'name': 'Edge Count (Channel2)',
                'getter': lambda device: device.get_edge_count(2, False),
                'subvalues': None,
                'unit': None,
                'advanced': True
            },
            {
                'name': 'Edge Count (Channel3)',
                'getter': lambda device: device.get_edge_count(3, False),
                'subvalues': None,
                'unit': None,
                'advanced': True
            },
            {
                'name': 'Chip Temperature',
                'getter': lambda device: device.get_chip_temperature(),
                'subvalues': None,
                'unit': '°C',
                'advanced': True
            }
        ],
        'options_setter': lambda device,
                                 channel0,
                                 channel1,
                                 channel2,
                                 channel3,
                                 edge_count_type_channel0,
                                 edge_count_debounce_channel0,
                                 edge_count_type_channel1,
                                 edge_count_debounce_channel1,
                                 edge_count_type_channel2,
                                 edge_count_debounce_channel2,
                                 edge_count_type_channel3,
                                 edge_count_debounce_channel3:
                          [device.set_configuration(0, *channel0),
                           device.set_configuration(1, *channel1),
                           device.set_configuration(2, *channel2),
                           device.set_configuration(3, *channel3),
                           device.set_edge_count_configuration(0, edge_count_type_channel0, edge_count_debounce_channel0),
                           device.set_edge_count_configuration(1, edge_count_type_channel1, edge_count_debounce_channel1),
                           device.set_edge_count_configuration(2, edge_count_type_channel2, edge_count_debounce_channel2),
                           device.set_edge_count_configuration(3, edge_count_type_channel3, edge_count_debounce_channel3)],
        'options': [
            {
                'name': 'Channel0',
                'type': 'choice',
                'values': [('Input Pull-Up', ('i', True)),
                           ('Input', ('i', False)),
                           ('Output High', ('o', True)),
                           ('Output Low', ('o', False))],
                'default': 'Input Pull-Up'
            },
            {
                'name': 'Channel1',
                'type': 'choice',
                'values': [('Input Pull-Up', ('i', True)),
                           ('Input', ('i', False)),
                           ('Output High', ('o', True)),
                           ('Output Low', ('o', False))],
                'default': 'Input Pull-Up'
            },
            {
                'name': 'Channel2',
                'type': 'choice',
                'values': [('Input Pull-Up', ('i', True)),
                           ('Input', ('i', False)),
                           ('Output High', ('o', True)),
                           ('Output Low', ('o', False))],
                'default': 'Input Pull-Up'
            },
            {
                'name': 'Channel3',
                'type': 'choice',
                'values': [('Input Pull-Up', ('i', True)),
                           ('Input', ('i', False)),
                           ('Output High', ('o', True)),
                           ('Output Low', ('o', False))],
                'default': 'Input Pull-Up'
            },
            {
                'name': 'Edge Count Type Channel0',
                'type': 'choice',
                'values': [('Rising', BrickletIO4V2.EDGE_TYPE_RISING),
                           ('Falling', BrickletIO4V2.EDGE_TYPE_FALLING),
                           ('Both', BrickletIO4V2.EDGE_TYPE_BOTH)],
                'default': 'Rising'
            },
            {
                'name': 'Edge Count Debounce Channel0',
                'type': 'int',
                'minimum': 0,
                'maximum': 255,
                'suffix': ' ms',
                'default': 100
            },
            {
                'name': 'Edge Count Type Channel1',
                'type': 'choice',
                'values': [('Rising', BrickletIO4V2.EDGE_TYPE_RISING),
                           ('Falling', BrickletIO4V2.EDGE_TYPE_FALLING),
                           ('Both', BrickletIO4V2.EDGE_TYPE_BOTH)],
                'default': 'Rising'
            },
            {
                'name': 'Edge Count Debounce Channel1',
                'type': 'int',
                'minimum': 0,
                'maximum': 255,
                'suffix': ' ms',
                'default': 100
            },
            {
                'name': 'Edge Count Type Channel2',
                'type': 'choice',
                'values': [('Rising', BrickletIO4V2.EDGE_TYPE_RISING),
                           ('Falling', BrickletIO4V2.EDGE_TYPE_FALLING),
                           ('Both', BrickletIO4V2.EDGE_TYPE_BOTH)],
                'default': 'Rising'
            },
            {
                'name': 'Edge Count Debounce Channel2',
                'type': 'int',
                'minimum': 0,
                'maximum': 255,
                'suffix': ' ms',
                'default': 100
            },
            {
                'name': 'Edge Count Type Channel3',
                'type': 'choice',
                'values': [('Rising', BrickletIO4V2.EDGE_TYPE_RISING),
                           ('Falling', BrickletIO4V2.EDGE_TYPE_FALLING),
                           ('Both', BrickletIO4V2.EDGE_TYPE_BOTH)],
                'default': 'Rising'
            },
            {
                'name': 'Edge Count Debounce Channel3',
                'type': 'int',
                'minimum': 0,
                'maximum': 255,
                'suffix': ' ms',
                'default': 100
            }
        ]
    }
if BrickletJoystick_found:
    device_specs[BrickletJoystick.DEVICE_DISPLAY_NAME] = {
        'class': BrickletJoystick,
        'values': [
            {
                'name': 'Position',
                'getter': lambda device: device.get_position(),
                'subvalues': ['X', 'Y'],
                'unit': [None, None],
                'advanced': False
            },
            {
                'name': 'Pressed',
                'getter': lambda device: device.is_pressed(),
                'subvalues': None,
                'unit': None,
                'advanced': False
            },
            {
                'name': 'Analog Value',
                'getter': lambda device: device.get_analog_value(),
                'subvalues': ['X', 'Y'],
                'unit': [None, None],
                'advanced': True
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletJoystickV2_found:
    device_specs[BrickletJoystickV2.DEVICE_DISPLAY_NAME] = {
        'class': BrickletJoystickV2,
        'values': [
            {
                'name': 'Position',
                'getter': lambda device: device.get_position(),
                'subvalues': ['X', 'Y'],
                'unit': [None, None],
                'advanced': False
            },
            {
                'name': 'Pressed',
                'getter': lambda device: device.is_pressed(),
                'subvalues': None,
                'unit': None,
                'advanced': False
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletLEDStrip_found:
    device_specs[BrickletLEDStrip.DEVICE_DISPLAY_NAME] = {
        'class': BrickletLEDStrip,
        'values': [
            {
                'name': 'Supply Voltage',
                'getter': lambda device: device.get_supply_voltage(),
                'subvalues': None,
                'unit': 'mV',
                'advanced': False
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletLEDStripV2_found:
    device_specs[BrickletLEDStripV2.DEVICE_DISPLAY_NAME] = {
        'class': BrickletLEDStripV2,
        'values': [
            {
                'name': 'Supply Voltage',
                'getter': lambda device: device.get_supply_voltage(),
                'subvalues': None,
                'unit': 'mV',
                'advanced': False
            },
            {
                'name': 'Chip Temperature',
                'getter': lambda device: device.get_chip_temperature(),
                'subvalues': None,
                'unit': '°C',
                'advanced': True
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletLine_found:
    device_specs[BrickletLine.DEVICE_DISPLAY_NAME] = {
        'class': BrickletLine,
        'values': [
            {
                'name': 'Reflectivity',
                'getter': lambda device: device.get_reflectivity(),
                'subvalues': None,
                'unit': None,
                'advanced': False
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletLinearPoti_found:
    device_specs[BrickletLinearPoti.DEVICE_DISPLAY_NAME] = {
        'class': BrickletLinearPoti,
        'values': [
            {
                'name': 'Position',
                'getter': lambda device: device.get_position(),
                'subvalues': None,
                'unit': None,
                'advanced': False
            },
            {
                'name': 'Analog Value',
                'getter': lambda device: device.get_analog_value(),
                'subvalues': None,
                'unit': None,
                'advanced': True
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletLinearPotiV2_found:
    device_specs[BrickletLinearPotiV2.DEVICE_DISPLAY_NAME] = {
        'class': BrickletLinearPotiV2,
        'values': [
            {
                'name': 'Position',
                'getter': lambda device: device.get_position(),
                'subvalues': None,
                'unit': None,
                'advanced': False
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletMotorizedLinearPoti_found:
    device_specs[BrickletMotorizedLinearPoti.DEVICE_DISPLAY_NAME] = {
        'class': BrickletMotorizedLinearPoti,
        'values': [
            {
                'name': 'Position',
                'getter': lambda device: device.get_position(),
                'subvalues': None,
                'unit': None,
                'advanced': False
            },
            {
                'name': 'Chip Temperature',
                'getter': lambda device: device.get_chip_temperature(),
                'subvalues': None,
                'unit': '°C',
                'advanced': True
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletLoadCell_found:
    device_specs[BrickletLoadCell.DEVICE_DISPLAY_NAME] = {
        'class': BrickletLoadCell,
        'values': [
            {
                'name': 'Weight',
                'getter': lambda device: device.get_weight(),
                'subvalues': None,
                'unit': 'gram',
                'advanced': False
            }
        ],
        'options_setter': lambda device, moving_average_length, rate, gain: \
                          [device.set_moving_average(moving_average_length), device.set_configuration(rate, gain)],
        'options': [
            {
                'name': 'Moving Average Length',
                'type': 'int',
                'minimum': 1,
                'maximum': 40,
                'suffix': None,
                'default': 4
            },
            {
                'name': 'Rate',
                'type': 'choice',
                'values': [('10Hz', BrickletLoadCell.RATE_10HZ),
                           ('80Hz', BrickletLoadCell.RATE_80HZ)],
                'default': '10Hz'
            },
            {
                'name': 'Gain',
                'type': 'choice',
                'values': [('128x', BrickletLoadCell.GAIN_128X),
                           ('64x', BrickletLoadCell.GAIN_64X),
                           ('32x', BrickletLoadCell.GAIN_32X)],
                'default': '128x'
            }
        ]
    }
if BrickletLoadCellV2_found:
    device_specs[BrickletLoadCellV2.DEVICE_DISPLAY_NAME] = {
        'class': BrickletLoadCellV2,
        'values': [
            {
                'name': 'Weight',
                'getter': lambda device: device.get_weight(),
                'subvalues': None,
                'unit': 'gram',
                'advanced': False
            },
            {
                'name': 'Chip Temperature',
                'getter': lambda device: device.get_chip_temperature(),
                'subvalues': None,
                'unit': '°C',
                'advanced': True
            }
        ],
        'options_setter': lambda device, moving_average_length, rate, gain: \
                          [device.set_moving_average(moving_average_length),
                           device.set_configuration(rate, gain)],
        'options': [
            {
                'name': 'Moving Average Length',
                'type': 'int',
                'minimum': 1,
                'maximum': 100,
                'suffix': None,
                'default': 4
            },
            {
                'name': 'Rate',
                'type': 'choice',
                'values': [('10Hz', BrickletLoadCellV2.RATE_10HZ),
                           ('80Hz', BrickletLoadCellV2.RATE_80HZ)],
                'default': '10Hz'
            },
            {
                'name': 'Gain',
                'type': 'choice',
                'values': [('128x', BrickletLoadCellV2.GAIN_128X),
                           ('64x', BrickletLoadCellV2.GAIN_64X),
                           ('32x', BrickletLoadCellV2.GAIN_32X)],
                'default': '128x'
            }
        ]
    }
if BrickletMoisture_found:
    device_specs[BrickletMoisture.DEVICE_DISPLAY_NAME] = {
        'class': BrickletMoisture,
        'values': [
            {
                'name': 'Moisture Value',
                'getter': lambda device: device.get_moisture_value(),
                'subvalues': None,
                'unit': None,
                'advanced': False
            }
        ],
        'options_setter': lambda device, moving_average_length: device.set_moving_average(moving_average_length),
        'options': [
            {
                'name': 'Moving Average Length',
                'type': 'int',
                'minimum': 0,
                'maximum': 100,
                'suffix': None,
                'default': 100
            }
        ]
    }
if BrickletMotionDetector_found:
    device_specs[BrickletMotionDetector.DEVICE_DISPLAY_NAME] = {
        'class': BrickletMotionDetector,
        'values': [
            {
                'name': 'Motion Detected',
                'getter': lambda device: device.get_motion_detected(),
                'subvalues': None,
                'unit': None,
                'advanced': False
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletMotionDetectorV2_found:
    device_specs[BrickletMotionDetectorV2.DEVICE_DISPLAY_NAME] = {
        'class': BrickletMotionDetectorV2,
        'values': [
            {
                'name': 'Motion Detected',
                'getter': lambda device: device.get_motion_detected(),
                'subvalues': None,
                'unit': None,
                'advanced': False
            },
            {
                'name': 'Chip Temperature',
                'getter': lambda device: device.get_chip_temperature(),
                'subvalues': None,
                'unit': '°C',
                'advanced': True
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletMultiTouch_found:
    device_specs[BrickletMultiTouch.DEVICE_DISPLAY_NAME] = {
        'class': BrickletMultiTouch,
        'values': [
            {
                'name': 'State',
                'getter': lambda device: value_to_bits(device.get_touch_state(), 13),
                'subvalues': ['Electrode 0', 'Electrode 1', 'Electrode 2', 'Electrode 3', 'Electrode 4', 'Electrode 5',
                              'Electrode 6', 'Electrode 7', 'Electrode 8', 'Electrode 9', 'Electrode 10', 'Electrode 11', 'Proximity'],
                'unit': [None, None, None, None, None, None, None, None, None, None, None, None, None],
                'advanced': False
            }
        ],
        'options_setter': special_set_multi_touch_options,
        'options': [
            {
                'name': 'Electrode 0',
                'type': 'bool',
                'default': True
            },
            {
                'name': 'Electrode 1',
                'type': 'bool',
                'default': True
            },
            {
                'name': 'Electrode 2',
                'type': 'bool',
                'default': True
            },
            {
                'name': 'Electrode 3',
                'type': 'bool',
                'default': True
            },
            {
                'name': 'Electrode 4',
                'type': 'bool',
                'default': True
            },
            {
                'name': 'Electrode 5',
                'type': 'bool',
                'default': True
            },
            {
                'name': 'Electrode 6',
                'type': 'bool',
                'default': True
            },
            {
                'name': 'Electrode 7',
                'type': 'bool',
                'default': True
            },
            {
                'name': 'Electrode 8',
                'type': 'bool',
                'default': True
            },
            {
                'name': 'Electrode 9',
                'type': 'bool',
                'default': True
            },
            {
                'name': 'Electrode 10',
                'type': 'bool',
                'default': True
            },
            {
                'name': 'Electrode 11',
                'type': 'bool',
                'default': True
            },
            {
                'name': 'Proximity',
                'type': 'bool',
                'default': True
            },
            {
                'name': 'Electrode Sensitivity',
                'type': 'int',
                'minimum': 5,
                'maximum': 201,
                'suffix': None,
                'default': 181
            }
        ]
    }
if BrickletMultiTouchV2_found:
    device_specs[BrickletMultiTouchV2.DEVICE_DISPLAY_NAME] = {
        'class': BrickletMultiTouchV2,
        'values': [
            {
                'name': 'State',
                'getter': lambda device: device.get_touch_state(),
                'subvalues': ['Electrode 0', 'Electrode 1', 'Electrode 2', 'Electrode 3', 'Electrode 4', 'Electrode 5',
                              'Electrode 6', 'Electrode 7', 'Electrode 8', 'Electrode 9', 'Electrode 10', 'Electrode 11', 'Proximity'],
                'unit': [None, None, None, None, None, None, None, None, None, None, None, None, None],
                'advanced': False
            }
        ],
        'options_setter': lambda device, e0, e1, e2, e3, e4, e5, e6, e7, e8, e9, e10, e11, e_prox, sensitivity:
                                 [device.set_electrode_config([e0, e1, e2, e3, e4, e5, e6, e7, e8, e9, e10, e11, e_prox]),
                                  device.set_electrode_sensitivity(sensitivity)],
        'options': [
            {
                'name': 'Electrode 0',
                'type': 'bool',
                'default': True
            },
            {
                'name': 'Electrode 1',
                'type': 'bool',
                'default': True
            },
            {
                'name': 'Electrode 2',
                'type': 'bool',
                'default': True
            },
            {
                'name': 'Electrode 3',
                'type': 'bool',
                'default': True
            },
            {
                'name': 'Electrode 4',
                'type': 'bool',
                'default': True
            },
            {
                'name': 'Electrode 5',
                'type': 'bool',
                'default': True
            },
            {
                'name': 'Electrode 6',
                'type': 'bool',
                'default': True
            },
            {
                'name': 'Electrode 7',
                'type': 'bool',
                'default': True
            },
            {
                'name': 'Electrode 8',
                'type': 'bool',
                'default': True
            },
            {
                'name': 'Electrode 9',
                'type': 'bool',
                'default': True
            },
            {
                'name': 'Electrode 10',
                'type': 'bool',
                'default': True
            },
            {
                'name': 'Electrode 11',
                'type': 'bool',
                'default': True
            },
            {
                'name': 'Proximity',
                'type': 'bool',
                'default': True
            },
            {
                'name': 'Electrode Sensitivity',
                'type': 'int',
                'minimum': 5,
                'maximum': 201,
                'suffix': None,
                'default': 181
            }
        ]
    }
if BrickletNFC_found:
    device_specs[BrickletNFC.DEVICE_DISPLAY_NAME] = {
        'class': BrickletNFC,
        'values': [
            {
                'name': 'Mode',
                'getter': lambda device: device.get_mode(),
                'subvalues': None,
                'unit': None,
                'advanced': False
            },
            {
                'name': 'Reader State',
                'getter': lambda device: device.reader_get_state(),
                'subvalues': ['State', 'Idle'],
                'unit': [None, None],
                'advanced': False
            },
            {
                'name': 'Cardemu State',
                'getter': lambda device: device.cardemu_get_state(),
                'subvalues': ['State', 'Idle'],
                'unit': [None, None],
                'advanced': False
            },
            {
                'name': 'P2P State',
                'getter': lambda device: device.p2p_get_state(),
                'subvalues': ['State', 'Idle'],
                'unit': [None, None],
                'advanced': False
            },
            {
                'name': 'Chip Temperature',
                'getter': lambda device: device.get_chip_temperature(),
                'subvalues': None,
                'unit': '°C',
                'advanced': True
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletNFCRFID_found:
    device_specs[BrickletNFCRFID.DEVICE_DISPLAY_NAME] = {
        'class': BrickletNFCRFID,
        'values': [
            {
                'name': 'State',
                'getter': lambda device: device.get_state(),
                'subvalues': ['State', 'Idle'],
                'unit': [None, None],
                'advanced': False
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletOutdoorWeather_found:
    device_specs[BrickletOutdoorWeather.DEVICE_DISPLAY_NAME] = {
        'class': BrickletOutdoorWeather,
        'values': [
            {
                'name': 'Station Data',
                'getter': special_get_outdoor_weather_station_data,
                'subvalues': ['Temperature', 'Humidity', 'Wind Speed', 'Gust Speed', 'Rain', 'Wind Direction', 'Battery Low', 'Last Change'],
                'unit': ['°C/10', '%RH', 'm/10s', 'm/10s', 'mm/10', None, None, 's'],
                'advanced': False
            },
            {
                'name': 'Sensor Data',
                'getter': special_get_outdoor_weather_sensor_data,
                'subvalues': ['Temperature', 'Humidity', 'Last Change'],
                'unit': ['°C/10', '%RH', 's'],
                'advanced': False
            },
            {
                'name': 'Chip Temperature',
                'getter': lambda device: device.get_chip_temperature(),
                'subvalues': None,
                'unit': '°C',
                'advanced': True
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletParticulateMatter_found:
    device_specs[BrickletParticulateMatter.DEVICE_DISPLAY_NAME] = {
        'class': BrickletParticulateMatter,
        'values': [
            {
                'name': 'Get PM Concentration',
                'getter': lambda device: device.get_pm_concentration(),
                'subvalues': ['PM10', 'PM25', 'PM100'],
                'unit': ['µg/m³', 'µg/m³', 'µg/m³'],
                'advanced': False
            },
            {
                'name': 'Get PM Count',
                'getter': lambda device: device.get_pm_count(),
                'subvalues': ['Greater03um', 'Greater05um', 'Greater10um', 'Greater25um', 'Greater50um', 'Greater100um'],
                'unit': [None, None, None, None, None, None],
                'advanced': False
            },
            {
                'name': 'Chip Temperature',
                'getter': lambda device: device.get_chip_temperature(),
                'subvalues': None,
                'unit': '°C',
                'advanced': True
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletPTC_found:
    device_specs[BrickletPTC.DEVICE_DISPLAY_NAME] = {
        'class': BrickletPTC,
        'values': [
            {
                'name': 'Temperature',
                'getter': special_get_ptc_temperature,
                'subvalues': None,
                'unit': '°C/100',
                'advanced': False
            },
            {
                'name': 'Resistance',
                'getter': special_get_ptc_resistance,
                'subvalues': None,
                'unit': None,
                'advanced': True
            }
        ],
        'options_setter': lambda device, wire_mode: device.set_wire_mode(wire_mode),
        'options': [
            {
                'name': 'Wire Mode',
                'type': 'choice',
                'values': [('2-Wire', BrickletPTC.WIRE_MODE_2),
                           ('3-Wire', BrickletPTC.WIRE_MODE_3),
                           ('4-Wire', BrickletPTC.WIRE_MODE_4)],
                'default': '2-Wire'
            }
        ]
    }
if BrickletPTCV2_found:
    device_specs[BrickletPTCV2.DEVICE_DISPLAY_NAME] = {
        'class': BrickletPTCV2,
        'values': [
            {
                'name': 'Temperature',
                'getter': special_get_ptc_temperature,
                'subvalues': None,
                'unit': '°C/100',
                'advanced': False
            },
            {
                'name': 'Resistance',
                'getter': special_get_ptc_resistance,
                'subvalues': None,
                'unit': None,
                'advanced': True
            },
            {
                'name': 'Chip Temperature',
                'getter': lambda device: device.get_chip_temperature(),
                'subvalues': None,
                'unit': '°C',
                'advanced': True
            }
        ],
        'options_setter': lambda device, wire_mode: device.set_wire_mode(wire_mode),
        'options': [
            {
                'name': 'Wire Mode',
                'type': 'choice',
                'values': [('2-Wire', BrickletPTCV2.WIRE_MODE_2),
                           ('3-Wire', BrickletPTCV2.WIRE_MODE_3),
                           ('4-Wire', BrickletPTCV2.WIRE_MODE_4)],
                'default': '2-Wire'
            }
        ]
    }
if BrickletRotaryEncoder_found:
    device_specs[BrickletRotaryEncoder.DEVICE_DISPLAY_NAME] = {
        'class': BrickletRotaryEncoder,
        'values': [
            {
                'name': 'Count',
                'getter': lambda device: device.get_count(False),
                'subvalues': None,
                'unit': None,
                'advanced': False
            },
            {
                'name': 'Pressed',
                'getter': lambda device: device.is_pressed(),
                'subvalues': None,
                'unit': None,
                'advanced': False
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletRotaryEncoderV2_found:
    device_specs[BrickletRotaryEncoderV2.DEVICE_DISPLAY_NAME] = {
        'class': BrickletRotaryEncoderV2,
        'values': [
            {
                'name': 'Count',
                'getter': lambda device: device.get_count(False),
                'subvalues': None,
                'unit': None,
                'advanced': False
            },
            {
                'name': 'Pressed',
                'getter': lambda device: device.is_pressed(),
                'subvalues': None,
                'unit': None,
                'advanced': False
            },
            {
                'name': 'Chip Temperature',
                'getter': lambda device: device.get_chip_temperature(),
                'subvalues': None,
                'unit': '°C',
                'advanced': True
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletRotaryPoti_found:
    device_specs[BrickletRotaryPoti.DEVICE_DISPLAY_NAME] = {
        'class': BrickletRotaryPoti,
        'values': [
            {
                'name': 'Position',
                'getter': lambda device: device.get_position(),
                'subvalues': None,
                'unit': None,
                'advanced': False
            },
            {
                'name': 'Analog Value',
                'getter': lambda device: device.get_analog_value(),
                'subvalues': None,
                'unit': None,
                'advanced': True
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletRotaryPotiV2_found:
    device_specs[BrickletRotaryPotiV2.DEVICE_DISPLAY_NAME] = {
        'class': BrickletRotaryPotiV2,
        'values': [
            {
                'name': 'Position',
                'getter': lambda device: device.get_position(),
                'subvalues': None,
                'unit': None,
                'advanced': False
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletRS232V2_found:
    device_specs[BrickletRS232V2.DEVICE_DISPLAY_NAME] = {
        'class': BrickletRS232V2,
        'values': [
            {
                'name': 'Input',
                'getter': special_rs232_v2_get_input,
                'subvalues': None,
                'unit': None,
                'advanced': False
            },
        ],
        'options_setter': special_rs232_v2_initialize,
        'options':  [
            {
                'name': 'Baudrate',
                'type': 'int',
                'minimum': 100,
                'maximum': 2000000,
                'suffix': 'Bd',
                'default': 115200
            }, {
                'name': 'Parity',
                'type': 'choice',
                'values': [('None', 0),
                           ('Odd', 1),
                           ('Even', 2)],
                'default': 'None'
            }, {
                'name': 'Stopbits',
                'type': 'choice',
                'values': [('1', 1),
                           ('2', 2)],
                'default': '1'
            }, {
                'name': 'Wordlength',
                'type': 'choice',
                'values':  [('5', 5),
                            ('6', 6),
                            ('7', 7),
                            ('8', 8)],
                'default': '8'
            }, {
                'name': 'Flowcontrol',
                'type': 'choice',
                'values': [('Off', 0),
                           ('Software', 1),
                           ('Hardware', 2)],
                'default': 'Off'
            }, {
                'name': 'Format',
                'type': 'choice',
                'values': [('ASCII', True),
                           ('Hex bytes', False)],
                'default': 'ASCII'
            }

        ]
    }

if BrickletRS485_found:
    device_specs[BrickletRS485.DEVICE_DISPLAY_NAME] = {
        'class': BrickletRS485,
        'values': [
            {
                'name': 'Error Count',
                'getter': lambda device: device.get_error_count(),
                'subvalues': ['Overrun Error Count', 'Parity Error Count'],
                'unit': [None, None],
                'advanced': True
            },
            {
                'name': 'Modbus Common Error Count',
                'getter': lambda device: device.get_modbus_common_error_count(),
                'subvalues': ['Timeout Error Count',
                              'Checksum Error Count',
                              'Frame Too Big Error Count',
                              'Illegal Function Error Count',
                              'Illegal Data Address Error Count',
                              'Illegal Data Value Error Count',
                              'Slave Device Failure Error Count'],
                'unit': [None, None, None, None, None, None, None],
                'advanced': True
            },
            {
                'name': 'Chip Temperature',
                'getter': lambda device: device.get_chip_temperature(),
                'subvalues': None,
                'unit': '°C',
                'advanced': True
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletSegmentDisplay4x7_found:
    device_specs[BrickletSegmentDisplay4x7.DEVICE_DISPLAY_NAME] = {
        'class': BrickletSegmentDisplay4x7,
        'values': [
            {
                'name': 'Counter Value',
                'getter': lambda device: device.get_counter_value(),
                'subvalues': None,
                'unit': None,
                'advanced': True
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletSegmentDisplay4x7V2_found:
    device_specs[BrickletSegmentDisplay4x7V2.DEVICE_DISPLAY_NAME] = {
        'class': BrickletSegmentDisplay4x7V2,
        'values': [
            {
                'name': 'Counter Value',
                'getter': lambda device: device.get_counter_value(),
                'subvalues': None,
                'unit': None,
                'advanced': True
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletSolidStateRelay_found:
    device_specs[BrickletSolidStateRelay.DEVICE_DISPLAY_NAME] = {
        'class': BrickletSolidStateRelay,
        'values': [
            {
                'name': 'State',
                'getter': lambda device: device.get_state(),
                'subvalues': None,
                'unit': None,
                'advanced': False
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletSolidStateRelayV2_found:
    device_specs[BrickletSolidStateRelayV2.DEVICE_DISPLAY_NAME] = {
        'class': BrickletSolidStateRelayV2,
        'values': [
            {
                'name': 'State',
                'getter': lambda device: device.get_state(),
                'subvalues': None,
                'unit': None,
                'advanced': False
            },
            {
                'name': 'Chip Temperature',
                'getter': lambda device: device.get_chip_temperature(),
                'subvalues': None,
                'unit': '°C',
                'advanced': True
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletSoundIntensity_found:
    device_specs[BrickletSoundIntensity.DEVICE_DISPLAY_NAME] = {
        'class': BrickletSoundIntensity,
        'values': [
            {
                'name': 'Intensity',
                'getter': lambda device: device.get_intensity(),
                'subvalues': None,
                'unit': None,
                'advanced': False
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletSoundPressureLevel_found:
    device_specs[BrickletSoundPressureLevel.DEVICE_DISPLAY_NAME] = {
        'class': BrickletSoundPressureLevel,
        'values': [
            {
                'name': 'Decibel',
                'getter': lambda device: device.get_decibel(),
                'subvalues': None,
                'unit': 'dB/10',
                'advanced': False
            },
            {
                'name': 'Chip Temperature',
                'getter': lambda device: device.get_chip_temperature(),
                'subvalues': None,
                'unit': '°C',
                'advanced': True
            }
        ],
        'options_setter': lambda device, fft_size, weighting: device.set_configuration(fft_size, weighting),
        'options': [
            {
                'name': 'FFT Range',
                'type': 'choice',
                'values': [('128', BrickletSoundPressureLevel.FFT_SIZE_128),
                           ('256', BrickletSoundPressureLevel.FFT_SIZE_256),
                           ('512', BrickletSoundPressureLevel.FFT_SIZE_512),
                           ('1024', BrickletSoundPressureLevel.FFT_SIZE_1024)],
                'default': '1024'
            },
            {
                'name': 'Weighting',
                'type': 'choice',
                'values': [('A', BrickletSoundPressureLevel.WEIGHTING_A),
                           ('B', BrickletSoundPressureLevel.WEIGHTING_B),
                           ('C', BrickletSoundPressureLevel.WEIGHTING_C),
                           ('D', BrickletSoundPressureLevel.WEIGHTING_D),
                           ('Z', BrickletSoundPressureLevel.WEIGHTING_Z),
                           ('ITU R 468', BrickletSoundPressureLevel.WEIGHTING_ITU_R_468)],
                'default': 'A'
            }
        ]
    }
if BrickletTemperature_found:
    device_specs[BrickletTemperature.DEVICE_DISPLAY_NAME] = {
        'class': BrickletTemperature,
        'values': [
            {
                'name': 'Temperature',
                'getter': lambda device: device.get_temperature(),
                'subvalues': None,
                'unit': '°C/100',
                'advanced': False
            }
        ],
        'options_setter': lambda device, i2c_mode: device.set_i2c_mode(i2c_mode),
        'options': [
            {
                'name': 'I2C Mode',
                'type': 'choice',
                'values': [('400kHz', BrickletTemperature.I2C_MODE_FAST),
                           ('100kHz', BrickletTemperature.I2C_MODE_SLOW)],
                'default': '400kHz'
            }
        ]
    }
if BrickletTemperatureV2_found:
    device_specs[BrickletTemperatureV2.DEVICE_DISPLAY_NAME] = {
        'class': BrickletTemperatureV2,
        'values': [
            {
                'name': 'Temperature',
                'getter': lambda device: device.get_temperature(),
                'subvalues': None,
                'unit': '°C/100',
                'advanced': False
            },
            {
                'name': 'Chip Temperature',
                'getter': lambda device: device.get_chip_temperature(),
                'subvalues': None,
                'unit': '°C',
                'advanced': True
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletThermalImaging_found:
    device_specs[BrickletThermalImaging.DEVICE_DISPLAY_NAME] = {
        'class': BrickletThermalImaging,
        'values': [
            {
                'name': 'Chip Temperature',
                'getter': lambda device: device.get_chip_temperature(),
                'subvalues': None,
                'unit': '°C',
                'advanced': True
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletThermocouple_found:
    device_specs[BrickletThermocouple.DEVICE_DISPLAY_NAME] = {
        'class': BrickletThermocouple,
        'values': [
            {
                'name': 'Temperature',
                'getter': lambda device: device.get_temperature(),
                'subvalues': None,
                'unit': '°C/100',
                'advanced': False
            },
            {
                'name': 'Error State',
                'getter': lambda device: device.get_error_state(),
                'subvalues': ['Over/Under Voltage', 'Open Circuit'],
                'unit': [None, None],
                'advanced': True
            }
        ],
        'options_setter': lambda device, averaging, thermocouple_type, filter: \
                          device.set_configuration(averaging, thermocouple_type, filter),
        'options': [
            {
                'name': 'Averaging',
                'type': 'choice',
                'values': [('1', BrickletThermocouple.AVERAGING_1),
                           ('2', BrickletThermocouple.AVERAGING_2),
                           ('4', BrickletThermocouple.AVERAGING_4),
                           ('8', BrickletThermocouple.AVERAGING_8),
                           ('16', BrickletThermocouple.AVERAGING_16)],
                'default': '16'
            },
            {
                'name': 'Thermocouple Type',
                'type': 'choice',
                'values': [('B', BrickletThermocouple.TYPE_B),
                           ('E', BrickletThermocouple.TYPE_E),
                           ('J', BrickletThermocouple.TYPE_J),
                           ('K', BrickletThermocouple.TYPE_K),
                           ('N', BrickletThermocouple.TYPE_N),
                           ('R', BrickletThermocouple.TYPE_R),
                           ('S', BrickletThermocouple.TYPE_S),
                           ('T', BrickletThermocouple.TYPE_T),
                           ('G8', BrickletThermocouple.TYPE_G8),
                           ('G32', BrickletThermocouple.TYPE_G32)],
                'default': 'K'
            },
            {
                'name': 'Filter',
                'type': 'choice',
                'values': [('50Hz', BrickletThermocouple.FILTER_OPTION_50HZ),
                           ('60Hz', BrickletThermocouple.FILTER_OPTION_60HZ)],
                'default': '50Hz'
            }
        ]
    }
if BrickletThermocoupleV2_found:
    device_specs[BrickletThermocoupleV2.DEVICE_DISPLAY_NAME] = {
        'class': BrickletThermocoupleV2,
        'values': [
            {
                'name': 'Temperature',
                'getter': lambda device: device.get_temperature(),
                'subvalues': None,
                'unit': '°C/100',
                'advanced': False
            },
            {
                'name': 'Error State',
                'getter': lambda device: device.get_error_state(),
                'subvalues': ['Over/Under Voltage', 'Open Circuit'],
                'unit': [None, None],
                'advanced': True
            },
            {
                'name': 'Chip Temperature',
                'getter': lambda device: device.get_chip_temperature(),
                'subvalues': None,
                'unit': '°C',
                'advanced': True
            }

        ],
        'options_setter': lambda device, averaging, thermocouple_type, filter: \
                          device.set_configuration(averaging, thermocouple_type, filter),
        'options': [
            {
                'name': 'Averaging',
                'type': 'choice',
                'values': [('1', BrickletThermocouple.AVERAGING_1),
                           ('2', BrickletThermocouple.AVERAGING_2),
                           ('4', BrickletThermocouple.AVERAGING_4),
                           ('8', BrickletThermocouple.AVERAGING_8),
                           ('16', BrickletThermocouple.AVERAGING_16)],
                'default': '16'
            },
            {
                'name': 'Thermocouple Type',
                'type': 'choice',
                'values': [('B', BrickletThermocouple.TYPE_B),
                           ('E', BrickletThermocouple.TYPE_E),
                           ('J', BrickletThermocouple.TYPE_J),
                           ('K', BrickletThermocouple.TYPE_K),
                           ('N', BrickletThermocouple.TYPE_N),
                           ('R', BrickletThermocouple.TYPE_R),
                           ('S', BrickletThermocouple.TYPE_S),
                           ('T', BrickletThermocouple.TYPE_T),
                           ('G8', BrickletThermocouple.TYPE_G8),
                           ('G32', BrickletThermocouple.TYPE_G32)],
                'default': 'K'
            },
            {
                'name': 'Filter',
                'type': 'choice',
                'values': [('50Hz', BrickletThermocouple.FILTER_OPTION_50HZ),
                           ('60Hz', BrickletThermocouple.FILTER_OPTION_60HZ)],
                'default': '50Hz'
            }
        ]
    }
if BrickletTemperatureIR_found:
    device_specs[BrickletTemperatureIR.DEVICE_DISPLAY_NAME] = {
        'class': BrickletTemperatureIR,
        'values': [
            {
                'name': 'Ambient Temperature',
                'getter': lambda device: device.get_ambient_temperature(),
                'subvalues': None,
                'unit': '°C/10',
                'advanced': False
            },
            {
                'name': 'Object Temperature',
                'getter': lambda device: device.get_object_temperature(),
                'subvalues': None,
                'unit': '°C/10',
                'advanced': False
            }
        ],
        'options_setter': lambda device, emissivity: device.set_emissivity(emissivity),
        'options': [
            {
                'name': 'Emissivity',
                'type': 'int',
                'minimum': 6553,
                'maximum': 65535,
                'suffix': None,
                'default': 65535
            }
        ]
    }
if BrickletTemperatureIRV2_found:
    device_specs[BrickletTemperatureIRV2.DEVICE_DISPLAY_NAME] = {
        'class': BrickletTemperatureIRV2,
        'values': [
            {
                'name': 'Ambient Temperature',
                'getter': lambda device: device.get_ambient_temperature(),
                'subvalues': None,
                'unit': '°C/10',
                'advanced': False
            },
            {
                'name': 'Object Temperature',
                'getter': lambda device: device.get_object_temperature(),
                'subvalues': None,
                'unit': '°C/10',
                'advanced': False
            },
            {
                'name': 'Chip Temperature',
                'getter': lambda device: device.get_chip_temperature(),
                'subvalues': None,
                'unit': '°C/10',
                'advanced': True
            }
        ],
        'options_setter': lambda device, emissivity: device.set_emissivity(emissivity),
        'options': [
            {
                'name': 'Emissivity',
                'type': 'int',
                'minimum': 6553,
                'maximum': 65535,
                'suffix': None,
                'default': 65535
            }
        ]
    }
if BrickletTilt_found:
    device_specs[BrickletTilt.DEVICE_DISPLAY_NAME] = {
        'class': BrickletTilt,
        'values': [
            {
                'name': 'State',
                'getter': lambda device: device.get_tilt_state(),
                'subvalues': None,
                'unit': None,
                'advanced': False
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletUVLight_found:
    device_specs[BrickletUVLight.DEVICE_DISPLAY_NAME] = {
        'class': BrickletUVLight,
        'values': [
            {
                'name': 'UV Light',
                'getter': lambda device: device.get_uv_light(),
                'subvalues': None,
                'unit': 'µW/cm²',
                'advanced': False
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletUVLightV2_found:
    device_specs[BrickletUVLightV2.DEVICE_DISPLAY_NAME] = {
        'class': BrickletUVLightV2,
        'values': [
            {
                'name': 'UVA',
                'getter': lambda device: device.get_uva(),
                'subvalues': None,
                'unit': '1/10 mW/m²',
                'advanced': False
            },
            {
                'name': 'UVB',
                'getter': lambda device: device.get_uvb(),
                'subvalues': None,
                'unit': '1/10 mW/m²',
                'advanced': False
            },
            {
                'name': 'UVI',
                'getter': lambda device: device.get_uvi(),
                'subvalues': None,
                'unit': '1/10',
                'advanced': False
            },
            {
                'name': 'Chip Temperature',
                'getter': lambda device: device.get_chip_temperature(),
                'subvalues': None,
                'unit': '°C',
                'advanced': True
            }
        ],
        'options_setter': lambda device, integration_time: device.set_configuration(integration_time),
        'options': [
            {
                'name': 'Integration Time',
                'type': 'choice',
                'values': [('50ms', BrickletUVLightV2.INTEGRATION_TIME_50MS),
                           ('100ms', BrickletUVLightV2.INTEGRATION_TIME_100MS),
                           ('200ms', BrickletUVLightV2.INTEGRATION_TIME_200MS),
                           ('400ms', BrickletUVLightV2.INTEGRATION_TIME_400MS),
                           ('800ms', BrickletUVLightV2.INTEGRATION_TIME_800MS)],
                'default': '400ms'
            }
        ]
    }
if BrickletVoltage_found:
    device_specs[BrickletVoltage.DEVICE_DISPLAY_NAME] = {
        'class': BrickletVoltage,
        'values': [
            {
                'name': 'Voltage',
                'getter': lambda device: device.get_voltage(),
                'subvalues': None,
                'unit': 'mV',
                'advanced': False
            },
            {
                'name': 'Analog Value',
                'getter': lambda device: device.get_analog_value(),
                'subvalues': None,
                'unit': None,
                'advanced': True
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletVoltageCurrent_found:
    device_specs[BrickletVoltageCurrent.DEVICE_DISPLAY_NAME] = {
        'class': BrickletVoltageCurrent,
        'values': [
            {
                'name': 'Voltage',
                'getter': lambda device: device.get_voltage(),
                'subvalues': None,
                'unit': 'mV',
                'advanced': False
            },
            {
                'name': 'Current',
                'getter': lambda device: device.get_current(),
                'subvalues': None,
                'unit': 'mA',
                'advanced': False
            },
            {
                'name': 'Power',
                'getter': lambda device: device.get_power(),
                'subvalues': None,
                'unit': 'mW',
                'advanced': False
            }
        ],
        'options_setter': lambda device, average_length, voltage_conversion_time, current_conversion_time: \
                          device.set_configuration(average_length, voltage_conversion_time, current_conversion_time),
        'options': [
            {
                'name': 'Average Length',
                'type': 'choice',
                'values': [('1', BrickletVoltageCurrent.AVERAGING_1),
                           ('4', BrickletVoltageCurrent.AVERAGING_4),
                           ('16', BrickletVoltageCurrent.AVERAGING_16),
                           ('64', BrickletVoltageCurrent.AVERAGING_64),
                           ('128', BrickletVoltageCurrent.AVERAGING_128),
                           ('256', BrickletVoltageCurrent.AVERAGING_256),
                           ('512', BrickletVoltageCurrent.AVERAGING_512),
                           ('1024', BrickletVoltageCurrent.AVERAGING_1024)],
                'default': '64'
            },
            {
                'name': 'Voltage Conversion Time',
                'type': 'choice',
                'values': [('140µs', 0),
                           ('204µs', 1),
                           ('332µs', 2),
                           ('588µs', 3),
                           ('1.1ms', 4),
                           ('2.116ms', 5),
                           ('4.156ms', 6),
                           ('8.244ms', 7)],
                'default': '1.1ms'
            },
            {
                'name': 'Current Conversion Time',
                'type': 'choice',
                'values': [('140µs', 0),
                           ('204µs', 1),
                           ('332µs', 2),
                           ('588µs', 3),
                           ('1.1ms', 4),
                           ('2.116ms', 5),
                           ('4.156ms', 6),
                           ('8.244ms', 7)],
                'default': '1.1ms'
            }
        ]
    }
if BrickletVoltageCurrentV2_found:
    device_specs[BrickletVoltageCurrentV2.DEVICE_DISPLAY_NAME] = {
        'class': BrickletVoltageCurrentV2,
        'values': [
            {
                'name': 'Voltage',
                'getter': lambda device: device.get_voltage(),
                'subvalues': None,
                'unit': 'mV',
                'advanced': False
            },
            {
                'name': 'Current',
                'getter': lambda device: device.get_current(),
                'subvalues': None,
                'unit': 'mA',
                'advanced': False
            },
            {
                'name': 'Power',
                'getter': lambda device: device.get_power(),
                'subvalues': None,
                'unit': 'mW',
                'advanced': False
            },
            {
                'name': 'Chip Temperature',
                'getter': lambda device: device.get_chip_temperature(),
                'subvalues': None,
                'unit': '°C',
                'advanced': True
            }
        ],
        'options_setter': lambda device, average_length, voltage_conversion_time, current_conversion_time: \
                          device.set_configuration(average_length, voltage_conversion_time, current_conversion_time),
        'options': [
            {
                'name': 'Average Length',
                'type': 'choice',
                'values': [('1', BrickletVoltageCurrent.AVERAGING_1),
                           ('4', BrickletVoltageCurrent.AVERAGING_4),
                           ('16', BrickletVoltageCurrent.AVERAGING_16),
                           ('64', BrickletVoltageCurrent.AVERAGING_64),
                           ('128', BrickletVoltageCurrent.AVERAGING_128),
                           ('256', BrickletVoltageCurrent.AVERAGING_256),
                           ('512', BrickletVoltageCurrent.AVERAGING_512),
                           ('1024', BrickletVoltageCurrent.AVERAGING_1024)],
                'default': '64'
            },
            {
                'name': 'Voltage Conversion Time',
                'type': 'choice',
                'values': [('140µs', 0),
                           ('204µs', 1),
                           ('332µs', 2),
                           ('588µs', 3),
                           ('1.1ms', 4),
                           ('2.116ms', 5),
                           ('4.156ms', 6),
                           ('8.244ms', 7)],
                'default': '1.1ms'
            },
            {
                'name': 'Current Conversion Time',
                'type': 'choice',
                'values': [('140µs', 0),
                           ('204µs', 1),
                           ('332µs', 2),
                           ('588µs', 3),
                           ('1.1ms', 4),
                           ('2.116ms', 5),
                           ('4.156ms', 6),
                           ('8.244ms', 7)],
                'default': '1.1ms'
            }
        ]
    }
if BrickDC_found:
    device_specs[BrickDC.DEVICE_DISPLAY_NAME] = {
        'class': BrickDC,
        'values': [
            {
                'name': 'Stack Input Voltage',
                'getter': lambda device: device.get_stack_input_voltage(),
                'subvalues': None,
                'unit': 'mV',
                'advanced': False
            },
            {
                'name': 'External Input Voltage',
                'getter': lambda device: device.get_external_input_voltage(),
                'subvalues': None,
                'unit': 'mV',
                'advanced': False
            },
            {
                'name': 'Current Consumption',
                'getter': lambda device: device.get_current_consumption(),
                'subvalues': None,
                'unit': 'mA',
                'advanced': False
            },
            {
                'name': 'Chip Temperature',
                'getter': lambda device: device.get_chip_temperature(),
                'subvalues': None,
                'unit': '°C/10',
                'advanced': True
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickIMU_found:
    device_specs[BrickIMU.DEVICE_DISPLAY_NAME] = {
        'class': BrickIMU,
        'values': [
            {
                'name': 'Orientation',
                'getter': lambda device: device.get_orientation(),
                'subvalues': ['Roll', 'Pitch', 'Yaw'],
                'unit': ['°/100', '°/100', '°/100'],
                'advanced': False
            },
            {
                'name': 'Quaternion',
                'getter': lambda device: device.get_quaternion(),
                'subvalues': ['X', 'Y', 'Z', 'W'],
                'unit': [None, None, None, None],
                'advanced': False
            },
            {
                'name': 'Acceleration',
                'getter': lambda device: device.get_acceleration(),
                'subvalues': ['X', 'Y', 'Z'],
                'unit': ['g/1000', 'g/1000', 'g/1000'],
                'advanced': True
            },
            {
                'name': 'Magnetic Field',
                'getter': lambda device: device.get_magnetic_field(),
                'subvalues': ['X', 'Y', 'Z'],
                'unit': ['µT/10', 'µT/10', 'µT/10'],
                'advanced': True
            },
            {
                'name': 'Angular Velocity',
                'getter': lambda device: device.get_angular_velocity(),
                'subvalues': ['X', 'Y', 'Z'],
                'unit': ['8/115 °/s', '8/115 °/s', '8/115 °/s'],
                'advanced': True
            },
            {
                'name': 'IMU Temperature',
                'getter': lambda device: device.get_imu_temperature(),
                'subvalues': None,
                'unit': '°C/100',
                'advanced': True
            },
            {
                'name': 'All Data',
                'getter': lambda device: device.get_all_data(),
                'subvalues': ['Acceleration-X', 'Acceleration-Y', 'Acceleration-Z', 'Acceleration-X', 'Acceleration-Y', 'Acceleration-Z',
                              'Angular Velocity-X', 'Angular Velocity-Y', 'Angular Velocity-Z', 'IMU Temperature'],
                'unit': ['g/1000', 'g/1000', 'g/1000', 'µT/10', 'µT/10', 'µT/10', '8/115 °/s', '8/115 °/s', '8/115 °/s', '°C/100'],
                'advanced': True
            },
            {
                'name': 'Chip Temperature',
                'getter': lambda device: device.get_chip_temperature(),
                'subvalues': None,
                'unit': '°C/10',
                'advanced': True
            }
        ],
        'options_setter': None,
        'options': None # FIXME: ranges
    }
if BrickIMUV2_found:
    device_specs[BrickIMUV2.DEVICE_DISPLAY_NAME] = {
        'class': BrickIMUV2,
        'values': [
            {
                'name': 'Orientation',
                'getter': lambda device: device.get_orientation(),
                'subvalues': ['Heading', 'Roll', 'Pitch'],
                'unit': ['°/16', '°/16', '°/16'],
                'advanced': False
            },
            {
                'name': 'Linear Acceleration',
                'getter': lambda device: device.get_linear_acceleration(),
                'subvalues': ['X', 'Y', 'Z'],
                'unit': ['1/100 m/s²', '1/100 m/s²', '1/100 m/s²'],
                'advanced': False
            },
            {
                'name': 'Gravity Vector',
                'getter': lambda device: device.get_gravity_vector(),
                'subvalues': ['X', 'Y', 'Z'],
                'unit': ['1/100 m/s²', '1/100 m/s²', '1/100 m/s²'],
                'advanced': False
            },
            {
                'name': 'Quaternion',
                'getter': lambda device: device.get_quaternion(),
                'subvalues': ['W', 'X', 'Y', 'Z'],
                'unit': ['1/16383', '1/16383', '1/16383', '1/16383'],
                'advanced': False
            },
            {
                'name': 'Acceleration',
                'getter': lambda device: device.get_acceleration(),
                'subvalues': ['X', 'Y', 'Z'],
                'unit': ['1/100 m/s²', '1/100 m/s²', '1/100 m/s²'],
                'advanced': True
            },
            {
                'name': 'Magnetic Field',
                'getter': lambda device: device.get_magnetic_field(),
                'subvalues': ['X', 'Y', 'Z'],
                'unit': ['1/16 µT ', '1/16 µT ', '1/16 µT '],
                'advanced': True
            },
            {
                'name': 'Angular Velocity',
                'getter': lambda device: device.get_angular_velocity(),
                'subvalues': ['X', 'Y', 'Z'],
                'unit': ['1/16 °/s', '1/16 °/s', '1/16 °/s'],
                'advanced': True
            },
            {
                'name': 'Temperature',
                'getter': lambda device: device.get_temperature(),
                'subvalues': None,
                'unit': '°C/100',
                'advanced': True
            },
            #{
            #    'name': 'All Data',
            #    'getter': lambda device: device.get_all_data(),
            #    'subvalues': # FIXME: nested arrays
            #    'unit': # FIXME: nested arrays
            #    'advanced': False
            #},
            {
                'name': 'Chip Temperature',
                'getter': lambda device: device.get_chip_temperature(),
                'subvalues': None,
                'unit': '°C/10',
                'advanced': True
            }
        ],
        'options_setter': None,
        'options': None # FIXME: ranges
    }
if BrickMaster_found:
    device_specs[BrickMaster.DEVICE_DISPLAY_NAME] = {
        'class': BrickMaster,
        'values': [
            {
                'name': 'Stack Voltage',
                'getter': lambda device: device.get_stack_voltage(),
                'subvalues': None,
                'unit': 'mV',
                'advanced': False
            },
            {
                'name': 'Stack Current',
                'getter': lambda device: device.get_stack_current(),
                'subvalues': None,
                'unit': 'mA',
                'advanced': False
            },
            {
                'name': 'Chip Temperature',
                'getter': lambda device: device.get_chip_temperature(),
                'subvalues': None,
                'unit': '°C/10',
                'advanced': True
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickServo_found:
    device_specs[BrickServo.DEVICE_DISPLAY_NAME] = {
        'class': BrickServo,
        'values': [
            {
                'name': 'Servo Current (Servo 0)',
                'getter': lambda device: device.get_servo_current(0),
                'subvalues': None,
                'unit': 'mA',
                'advanced': False
            },
            {
                'name': 'Servo Current (Servo 1)',
                'getter': lambda device: device.get_servo_current(1),
                'subvalues': None,
                'unit': 'mA',
                'advanced': False
            },
            {
                'name': 'Servo Current (Servo 2)',
                'getter': lambda device: device.get_servo_current(2),
                'subvalues': None,
                'unit': 'mA',
                'advanced': False
            },
            {
                'name': 'Servo Current (Servo 3)',
                'getter': lambda device: device.get_servo_current(3),
                'subvalues': None,
                'unit': 'mA',
                'advanced': False
            },
            {
                'name': 'Servo Current (Servo 4)',
                'getter': lambda device: device.get_servo_current(4),
                'subvalues': None,
                'unit': 'mA',
                'advanced': False
            },
            {
                'name': 'Servo Current (Servo 5)',
                'getter': lambda device: device.get_servo_current(5),
                'subvalues': None,
                'unit': 'mA',
                'advanced': False
            },
            {
                'name': 'Servo Current (Servo 6)',
                'getter': lambda device: device.get_servo_current(6),
                'subvalues': None,
                'unit': 'mA',
                'advanced': False
            },
            {
                'name': 'Overall Current',
                'getter': lambda device: device.get_overall_current(),
                'subvalues': None,
                'unit': 'mA',
                'advanced': False
            },
            {
                'name': 'Stack Input Voltage',
                'getter': lambda device: device.get_stack_input_voltage(),
                'subvalues': None,
                'unit': 'mV',
                'advanced': False
            },
            {
                'name': 'External Input Voltage',
                'getter': lambda device: device.get_external_input_voltage(),
                'subvalues': None,
                'unit': 'mV',
                'advanced': False
            },
            {
                'name': 'Chip Temperature',
                'getter': lambda device: device.get_chip_temperature(),
                'subvalues': None,
                'unit': '°C/10',
                'advanced': True
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickStepper_found:
    device_specs[BrickStepper.DEVICE_DISPLAY_NAME] = {
        'class': BrickStepper,
        'values': [
            {
                'name': 'Current Velocity',
                'getter': lambda device: device.get_current_velocity(),
                'subvalues': None,
                'unit': 'steps/sec',
                'advanced': False
            },
            {
                'name': 'Current Position',
                'getter': lambda device: device.get_current_position(),
                'subvalues': None,
                'unit': 'steps',
                'advanced': True
            },
            {
                'name': 'Stack Input Voltage',
                'getter': lambda device: device.get_stack_input_voltage(),
                'subvalues': None,
                'unit': 'mV',
                'advanced': True
            },
            {
                'name': 'External Input Voltage',
                'getter': lambda device: device.get_external_input_voltage(),
                'subvalues': None,
                'unit': 'mV',
                'advanced': True
            },
            {
                'name': 'Current Consumption',
                'getter': lambda device: device.get_current_consumption(),
                'subvalues': None,
                'unit': 'mA',
                'advanced': True
            },
            {
                'name': 'Chip Temperature',
                'getter': lambda device: device.get_chip_temperature(),
                'subvalues': None,
                'unit': '°C/10',
                'advanced': True
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickSilentStepper_found:
    device_specs[BrickSilentStepper.DEVICE_DISPLAY_NAME] = {
        'class': BrickSilentStepper,
        'values': [
            {
                'name': 'Current Velocity',
                'getter': lambda device: device.get_current_velocity(),
                'subvalues': None,
                'unit': 'steps/sec',
                'advanced': False
            },
            {
                'name': 'Current Position',
                'getter': lambda device: device.get_current_position(),
                'subvalues': None,
                'unit': 'steps',
                'advanced': True
            },
            {
                'name': 'Stack Input Voltage',
                'getter': lambda device: device.get_stack_input_voltage(),
                'subvalues': None,
                'unit': 'mV',
                'advanced': True
            },
            {
                'name': 'External Input Voltage',
                'getter': lambda device: device.get_external_input_voltage(),
                'subvalues': None,
                'unit': 'mV',
                'advanced': True
            },
            {
                'name': 'Current Consumption',
                'getter': lambda device: device.get_all_data().current_consumption,
                'subvalues': None,
                'unit': 'mA',
                'advanced': True
            },
            {
                'name': 'Chip Temperature',
                'getter': lambda device: device.get_chip_temperature(),
                'subvalues': None,
                'unit': '°C/10',
                'advanced': True
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickHAT_found:
    device_specs[BrickHAT.DEVICE_DISPLAY_NAME] = {
        'class': BrickHAT,
        'values': [
            {
                'name': 'Voltages',
                'getter': lambda device: device.get_voltages(),
                'subvalues': ['USB Voltage', 'DC Voltage'],
                'unit': ['mV', 'mV'],
                'advanced': False
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickHATZero_found:
    device_specs[BrickHATZero.DEVICE_DISPLAY_NAME] = {
        'class': BrickHATZero,
        'values': [
            {
                'name': 'USB Voltage',
                'getter': lambda device: device.get_usb_voltage(),
                'subvalues': None,
                'unit': 'mV',
                'advanced': False
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletRGBLEDButton_found:
    device_specs[BrickletRGBLEDButton.DEVICE_DISPLAY_NAME] = {
        'class': BrickletRGBLEDButton,
        'values': [
            {
                'name': 'Button State',
                'getter': lambda device: device.get_button_state(),
                'subvalues': None,
                'unit': None,
                'advanced': False
            },
            {
                'name': 'Chip Temperature',
                'getter': lambda device: device.get_chip_temperature(),
                'subvalues': None,
                'unit': '°C',
                'advanced': True
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletRGBLEDMatrix_found:
    device_specs[BrickletRGBLEDMatrix.DEVICE_DISPLAY_NAME] = {
        'class': BrickletRGBLEDMatrix,
        'values': [
            {
                'name': 'Supply Voltage',
                'getter': lambda device: device.get_supply_voltage(),
                'subvalues': None,
                'unit': 'mV',
                'advanced': True
            },
            {
                'name': 'Chip Temperature',
                'getter': lambda device: device.get_chip_temperature(),
                'subvalues': None,
                'unit': '°C',
                'advanced': True
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletRealTimeClock_found:
    device_specs[BrickletRealTimeClock.DEVICE_DISPLAY_NAME] = {
        'class': BrickletRealTimeClock,
        'values': [
            {
                'name': 'Date Time',
                'getter': lambda device: device.get_date_time(),
                'subvalues': ['Year',
                              'Month',
                              'Day',
                              'Hour',
                              'Minute',
                              'Second',
                              'Centisecond',
                              'Weekday'],
                'unit': [None, None, None, None, None, None, None, None],
                'advanced': False
            },
            {
                'name': 'Timestamp',
                'getter': lambda device: device.get_timestamp(),
                'subvalues': None,
                'unit': 'ms',
                'advanced': False
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletRealTimeClockV2_found:
    device_specs[BrickletRealTimeClockV2.DEVICE_DISPLAY_NAME] = {
        'class': BrickletRealTimeClockV2,
        'values': [
            {
                'name': 'Date Time',
                'getter': lambda device: device.get_date_time(),
                'subvalues': ['Year',
                              'Month',
                              'Day',
                              'Hour',
                              'Minute',
                              'Second',
                              'Centisecond',
                              'Weekday'],
                'unit': [None, None, None, None, None, None, None, None],
                'advanced': False
            },
            {
                'name': 'Timestamp',
                'getter': lambda device: device.get_timestamp(),
                'subvalues': None,
                'unit': 'ms',
                'advanced': False
            },
            {
                'name': 'Chip Temperature',
                'getter': lambda device: device.get_chip_temperature(),
                'subvalues': None,
                'unit': '°C',
                'advanced': True
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletRemoteSwitch_found:
    device_specs[BrickletRemoteSwitch.DEVICE_DISPLAY_NAME] = {
        'class': BrickletRemoteSwitch,
        'values': [
            {
                'name': 'Switching State',
                'getter': lambda device: device.get_switching_state(),
                'subvalues': None,
                'unit': None,
                'advanced': False
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletRemoteSwitchV2_found:
    device_specs[BrickletRemoteSwitchV2.DEVICE_DISPLAY_NAME] = {
        'class': BrickletRemoteSwitchV2,
        'values': [
            {
                'name': 'Switching State',
                'getter': lambda device: device.get_switching_state(),
                'subvalues': None,
                'unit': None,
                'advanced': False
            },
            {
                'name': 'Remote Status A',
                'getter': lambda device: device.get_remote_status_a(),
                'subvalues': None,
                'unit': None,
                'advanced': False
            },
            {
                'name': 'Remote Status B',
                'getter': lambda device: device.get_remote_status_b(),
                'subvalues': None,
                'unit': None,
                'advanced': False
            },
            {
                'name': 'Remote Status C',
                'getter': lambda device: device.get_remote_status_c(),
                'subvalues': None,
                'unit': None,
                'advanced': False
            },
            {
                'name': 'Chip Temperature',
                'getter': lambda device: device.get_chip_temperature(),
                'subvalues': None,
                'unit': '°C',
                'advanced': True
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletLaserRangeFinder_found:
    device_specs[BrickletLaserRangeFinder.DEVICE_DISPLAY_NAME] = {
        'class': BrickletLaserRangeFinder,
        'values': [
            {
                'name': 'Distance',
                'getter': lambda device: device.get_distance(),
                'subvalues': None,
                'unit': 'cm',
                'advanced': False
            },
            {
                'name': 'Velocity',
                'getter': lambda device: device.get_velocity(),
                'subvalues': None,
                'unit': '1/100 m/s',
                'advanced': False
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletLaserRangeFinderV2_found:
    device_specs[BrickletLaserRangeFinderV2.DEVICE_DISPLAY_NAME] = {
        'class': BrickletLaserRangeFinderV2,
        'values': [
            {
                'name': 'Distance',
                'getter': lambda device: device.get_distance(),
                'subvalues': None,
                'unit': 'cm',
                'advanced': False
            },
            {
                'name': 'Velocity',
                'getter': lambda device: device.get_velocity(),
                'subvalues': None,
                'unit': '1/100 m/s',
                'advanced': False
            }
        ],
        'options_setter': special_set_laser_range_finder_v2_configuration,
        'options': [
            {
                'name': 'Enable Laser',
                'type': 'choice',
                'values': [('Yes', True),
                           ('No', False)],
                'default': 'No'
            },
            {
                'name': 'Acquisition Count',
                'type': 'int',
                'minimum': 1,
                'maximum': 255,
                'suffix': None,
                'default': 128
            },
            {
                'name': 'Enable Quick Termination',
                'type': 'choice',
                'values': [('Yes', True),
                           ('No', False)],
                'default': 'No'
            },
            {
                'name': 'Threshold Value',
                'type': 'int',
                'minimum': 0,
                'maximum': 255,
                'suffix': None,
                'default': 0,
            },
            {
                'name': 'Enable Automatic Frequency (Disable for Velocity Measurement)',
                'type': 'choice',
                'values': [('Yes', True),
                           ('No', False)],
                'default': 'Yes'
            },
            {
                'name': 'Manual Measurement Frequency',
                'type': 'int',
                'minimum': 10,
                'maximum': 500,
                'default': 10,
                'suffix': 'Hz'
            }
        ]
    }
if BrickletDMX_found:
    device_specs[BrickletDMX.DEVICE_DISPLAY_NAME] = {
        'class': BrickletDMX,
        'values': [
            {
                'name': 'Frame Error Count',
                'getter': lambda device: device.get_frame_error_count(),
                'subvalues': ['Overrun Error Count', 'Framing Error Count'],
                'unit': [None, None],
                'advanced': True
            },
            {
                'name': 'Chip Temperature',
                'getter': lambda device: device.get_chip_temperature(),
                'subvalues': None,
                'unit': '°C',
                'advanced': True
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletServoV2_found:
    device_specs[BrickletServoV2.DEVICE_DISPLAY_NAME] = {
        'class': BrickletServoV2,
        'values': [
            {
                'name': 'Servo Current (Servo 0)',
                'getter': lambda device: device.get_servo_current(0),
                'subvalues': None,
                'unit': 'mA',
                'advanced': False
            },
            {
                'name': 'Servo Current (Servo 1)',
                'getter': lambda device: device.get_servo_current(1),
                'subvalues': None,
                'unit': 'mA',
                'advanced': False
            },
            {
                'name': 'Servo Current (Servo 2)',
                'getter': lambda device: device.get_servo_current(2),
                'subvalues': None,
                'unit': 'mA',
                'advanced': False
            },
            {
                'name': 'Servo Current (Servo 3)',
                'getter': lambda device: device.get_servo_current(3),
                'subvalues': None,
                'unit': 'mA',
                'advanced': False
            },
            {
                'name': 'Servo Current (Servo 4)',
                'getter': lambda device: device.get_servo_current(4),
                'subvalues': None,
                'unit': 'mA',
                'advanced': False
            },
            {
                'name': 'Servo Current (Servo 5)',
                'getter': lambda device: device.get_servo_current(5),
                'subvalues': None,
                'unit': 'mA',
                'advanced': False
            },
            {
                'name': 'Servo Current (Servo 6)',
                'getter': lambda device: device.get_servo_current(6),
                'subvalues': None,
                'unit': 'mA',
                'advanced': False
            },
            {
                'name': 'Servo Current (Servo 7)',
                'getter': lambda device: device.get_servo_current(7),
                'subvalues': None,
                'unit': 'mA',
                'advanced': False
            },
            {
                'name': 'Servo Current (Servo 8)',
                'getter': lambda device: device.get_servo_current(8),
                'subvalues': None,
                'unit': 'mA',
                'advanced': False
            },
            {
                'name': 'Servo Current (Servo 9)',
                'getter': lambda device: device.get_servo_current(9),
                'subvalues': None,
                'unit': 'mA',
                'advanced': False
            },
            {
                'name': 'Overall Current',
                'getter': lambda device: device.get_overall_current(),
                'subvalues': None,
                'unit': 'mA',
                'advanced': False
            },
            {
                'name': 'Input Voltage',
                'getter': lambda device: device.get_input_voltage(),
                'subvalues': None,
                'unit': 'mV',
                'advanced': False
            },
            {
                'name': 'Chip Temperature',
                'getter': lambda device: device.get_chip_temperature(),
                'subvalues': None,
                'unit': '°C',
                'advanced': True
            }
        ],
        'options_setter': None, # FIXME: add 'Servo Current Configuration' and 'Input Voltage Configuration' options
        'options': None
    }
if BrickletPerformanceDC_found:
    device_specs[BrickletPerformanceDC.DEVICE_DISPLAY_NAME] = {
        'class': BrickletPerformanceDC,
        'values': [
            {
                'name': 'Power Statistics',
                'getter': lambda device: device.get_power_statistics(),
                'subvalues': ['Voltage', 'Current', 'Temperature'],
                'unit': ['mV', 'mA', '°C/10'],
                'advanced': False
            },
            {
                'name': 'Chip Temperature',
                'getter': lambda device: device.get_chip_temperature(),
                'subvalues': None,
                'unit': '°C',
                'advanced': True
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletDCV2_found:
    device_specs[BrickletDCV2.DEVICE_DISPLAY_NAME] = {
        'class': BrickletDCV2,
        'values': [
            {
                'name': 'Power Statistics',
                'getter': lambda device: device.get_power_statistics(),
                'subvalues': ['Voltage', 'Current'],
                'unit': ['mV', 'mA'],
                'advanced': False
            },
            {
                'name': 'Chip Temperature',
                'getter': lambda device: device.get_chip_temperature(),
                'subvalues': None,
                'unit': '°C',
                'advanced': True
            }
        ],
        'options_setter': None,
        'options': None
    }
if BrickletSilentStepperV2_found:
    device_specs[BrickletSilentStepperV2.DEVICE_DISPLAY_NAME] = {
        'class': BrickletSilentStepperV2,
        'values': [
            {
                'name': 'Current Velocity',
                'getter': lambda device: device.get_current_velocity(),
                'subvalues': None,
                'unit': 'steps/sec',
                'advanced': False
            },
            {
                'name': 'Current Position',
                'getter': lambda device: device.get_current_position(),
                'subvalues': None,
                'unit': 'steps',
                'advanced': True
            },
            {
                'name': 'Input Voltage',
                'getter': lambda device: device.get_input_voltage(),
                'subvalues': None,
                'unit': 'mV',
                'advanced': True
            },
            {
                'name': 'Current Consumption',
                'getter': lambda device: device.get_all_data().current_consumption,
                'subvalues': None,
                'unit': 'mA',
                'advanced': True
            },
            {
                'name': 'Chip Temperature',
                'getter': lambda device: device.get_chip_temperature(),
                'subvalues': None,
                'unit': '°C',
                'advanced': True
            }
        ],
        'options_setter': None,
        'options': None
    }

'''
/*---------------------------------------------------------------------------
                                AbstractDevice
 ---------------------------------------------------------------------------*/
 '''

class AbstractDevice:
    """DEBUG and Inheritance only class"""

    def __init__(self, data, datalogger):
        self.datalogger = datalogger
        self.data = data

        self.__name__ = "AbstractDevice"

    def start_timer(self):
        """
        Starts all timer for all loggable variables of the devices.
        """
        EventLogger.debug(self.__str__())

    def _exception_msg(self, value, msg):
        """
        For a uniform creation of Exception messages.
        """
        return "ERROR[" + str(value) + "]: " + str(msg)

    def __str__(self):
        """
        Representation String of the class. For simple overwiev.
        """
        return "[" + str(self.__name__) + "]"


#---------------------------------------------------------------------------
#                               DeviceImpl
#---------------------------------------------------------------------------

class DeviceImpl(AbstractDevice):
    """
    A SimpleDevice is every device, which only has funtion with one return value.
    """

    def __init__(self, data, datalogger):
        super().__init__(data, datalogger)

        self.device_name = self.data['name']
        self.device_uid = self.data['uid']
        self.device_spec = device_specs[self.device_name]
        device_class = self.device_spec['class']
        self.device = device_class(self.device_uid, self.datalogger.ipcon)

        self.__name__ = "devices:" + str(self.device_name)

    def start_timer(self):
        AbstractDevice.start_timer(self)

        for value in self.data['values']:
            interval = self.data['values'][value]['interval']
            func_name = "_timer"
            var_name = value

            self.datalogger.timers.append(LoggerTimer(interval, func_name, var_name, self))

    def apply_options(self):
        options_setter = self.device_spec['options_setter']
        option_specs = self.device_spec['options']

        if options_setter != None and option_specs != None:
            EventLogger.debug('Applying options for "{0}" with UID "{1}"'.format(self.device_name, self.device_uid))

            args = []

            for option_spec in option_specs:
                for option_name in self.data['options']:
                    if option_name == option_spec['name']:
                        option_value = self.data['options'][option_name]['value']

                        if option_spec['type'] == 'choice':
                            for option_value_spec in option_spec['values']:
                                if option_value == option_value_spec[0]:
                                    args.append(option_value_spec[1])
                        elif option_spec['type'] == 'int':
                            args.append(option_value)
                        elif option_spec['type'] == 'bool':
                            args.append(option_value)

            try:
                options_setter(self.device, *tuple(args))
            except Exception as e:
                EventLogger.warning('Could not apply options for "{0}" with UID "{1}": {2}'
                                    .format(self.device_name, self.device_uid, e))

    def _timer(self, var_name):
        """
        This function is used by the LoggerTimer to get the variable values from the brickd.
        In SimpleDevices the get-functions only return one value.
        """

        value_spec = None

        for candidate in self.device_spec['values']:
            if candidate['name'] == var_name:
                value_spec = candidate
                break

        getter = value_spec['getter']
        subvalue_names = value_spec['subvalues']
        unit = value_spec['unit']
        now = time.time()
        time_format = self.datalogger._config['data']['time_format']
        time_format_strftime = self.datalogger._config['data']['time_format_strftime']

        if time_format == 'de':
            timestamp = timestamp_to_de(now)
        elif time_format == 'de-msec':
            timestamp = timestamp_to_de_msec(now)
        elif time_format == 'us':
            timestamp = timestamp_to_us(now)
        elif time_format == 'us-msec':
            timestamp = timestamp_to_us_msec(now)
        elif time_format == 'iso':
            timestamp = timestamp_to_iso(now)
        elif time_format == 'iso-msec':
            timestamp = timestamp_to_iso_msec(now)
        elif time_format == 'unix':
            timestamp = timestamp_to_unix(now)
        elif time_format == 'unix-msec':
            timestamp = timestamp_to_unix_msec(now)
        elif time_format == 'strftime':
            timestamp = timestamp_to_strftime(now, time_format_strftime)
        else:
            timestamp = timestamp_to_unix(now)

        try:
            value = getter(self.device)
        except Exception as e:
            value = self._exception_msg(self.device_name + "-" + var_name, e)
            self.datalogger.add_to_queue(CSVData(timestamp,
                                                 self.device_name,
                                                 self.device_uid,
                                                 var_name,
                                                 value,
                                                 ''))
            # log_exception(timestamp, value_name, e)
            return

        if not isinstance(value, dict):
            value = {None: value}

        try:
            if subvalue_names is None:
                if unit == None:
                    unit_str = ''
                else:
                    unit_str = unit

                for key, keyed_value in value.items():
                    if key != None:
                        keyed_var_name = var_name + ':' + key
                    else:
                        keyed_var_name = var_name

                    self.datalogger.add_to_queue(CSVData(timestamp,
                                                         self.device_name,
                                                         self.device_uid,
                                                         keyed_var_name,
                                                         keyed_value,
                                                         unit_str))
            else:
                subvalue_bool = self.data['values'][var_name]['subvalues']

                for key, keyed_value in value.items():
                    if key != None:
                        keyed_var_name = var_name + ':' + key
                    else:
                        keyed_var_name = var_name

                    for i in range(len(subvalue_names)):
                        if not isinstance(subvalue_names[i], list):
                            try:
                                if subvalue_bool[subvalue_names[i]]:
                                    if unit[i] == None:
                                        unit_str = ''
                                    else:
                                        unit_str = unit[i]

                                    self.datalogger.add_to_queue(CSVData(timestamp,
                                                                         self.device_name,
                                                                         self.device_uid,
                                                                         keyed_var_name + "-" + subvalue_names[i],
                                                                         keyed_value[i],
                                                                         unit_str))
                            except Exception as e:
                                err_value = self._exception_msg(self.device_name + "-" + keyed_var_name, e)
                                self.datalogger.add_to_queue(CSVData(timestamp,
                                                                     self.device_name,
                                                                     self.device_uid,
                                                                     keyed_var_name + "-" + subvalue_names[i],
                                                                     err_value,
                                                                     ''))
                                return
                        else:
                            for k in range(len(subvalue_names[i])):
                                try:
                                    if subvalue_bool[subvalue_names[i][k]]:
                                        if unit[i][k] == None:
                                            unit_str = ''
                                        else:
                                            unit_str = unit[i][k]

                                        self.datalogger.add_to_queue(CSVData(timestamp,
                                                                             self.device_name,
                                                                             self.device_uid,
                                                                             keyed_var_name + "-" + subvalue_names[i][k],
                                                                             keyed_value[i][k],
                                                                             unit_str))
                                except Exception as e:
                                    err_value = self._exception_msg(str(self.device_name) + "-" + keyed_var_name, e)
                                    self.datalogger.add_to_queue(CSVData(timestamp,
                                                                         self.device_name,
                                                                         self.device_uid,
                                                                         keyed_var_name + "-" + subvalue_names[i][k],
                                                                         err_value,
                                                                         ''))
                                    return

        except Exception as e:
            err_value = self._exception_msg(self.device_name + "-" + var_name, e)
            self.datalogger.add_to_queue(CSVData(timestamp,
                                                 self.device_name,
                                                 self.device_uid,
                                                 var_name,
                                                 err_value,
                                                 ''))



#---------------------------------------------------------------------------
#                               Jobs
#---------------------------------------------------------------------------

import queue
import threading
import time

if 'merged_data_logger_modules' not in globals():
    from PyQt5.QtCore import pyqtSignal, QObject
    from brickv.data_logger.event_logger import EventLogger
    from brickv.data_logger.utils import CSVWriter

class AbstractJob(threading.Thread):
    def __init__(self, name, target, datalogger=None):
        super().__init__(name=name, target=target)

        self.daemon = True
        self._exit_flag = False
        self._datalogger = datalogger
        self._job_name = "[Job:" + self.name + "]"

        if self._datalogger is not None:
            self._datalogger.data_queue[self.name] = queue.Queue()

    def stop(self):
        self._exit_flag = True

    def _job(self):
        # check for datalogger object
        if self._datalogger is None:
            EventLogger.warning(self.name + " started but did not get a DataLogger Object! No work could be done.")
            return True
        return False

    def _get_data_from_queue(self):
        if self._datalogger is not None:
            return self._datalogger.data_queue[self.name].get()
        return None

    # Needs to be called when you end the job!
    def _remove_from_data_queue(self):
        try:
            self._datalogger.data_queue.pop(self.name)
        except KeyError as key_err:
            EventLogger.warning("Job:" + self.name + " was not in the DataQueue! -> " + str(key_err))


class CSVWriterJob(AbstractJob):
    """
    This class enables the data logger to write logged data to an CSV formatted file
    """

    def __init__(self, datalogger=None, name="CSVWriterJob"):
        target = self._job
        super().__init__(datalogger=datalogger, name=name, target=target)

    def _job(self):
        try:
            # check for datalogger object
            if AbstractJob._job(self):
                return

            EventLogger.debug(self._job_name + " Started")
            csv_writer = CSVWriter(self._datalogger.csv_file_name)

            while True:
                if not self._datalogger.data_queue[self.name].empty():
                    csv_data = self._get_data_from_queue()
                    if not csv_writer.write_data_row(csv_data):
                        EventLogger.warning(self._job_name + " Could not write csv row!")

                if not self._exit_flag and self._datalogger.data_queue[self.name].empty():
                    time.sleep(self._datalogger.job_sleep)

                if self._exit_flag and self._datalogger.data_queue[self.name].empty():
                    exit_return_value = csv_writer.close_file()
                    if exit_return_value:
                        EventLogger.debug(self._job_name + " Closed his csv_writer")
                    else:
                        EventLogger.debug(
                            self._job_name + " Could NOT close his csv_writer! EXIT_RETURN_VALUE=" + str(exit))
                    EventLogger.debug(self._job_name + " Finished")

                    self._remove_from_data_queue()
                    break

        except Exception as e:
            EventLogger.critical(self._job_name + " " + str(e))
            self.stop()


if 'merged_data_logger_modules' not in globals():
    class GuiDataJob(AbstractJob, QObject):
        """
        This class enables the data logger to log to the Gui
        """
        from brickv.data_logger.utils import LoggerTimer, CSVData
        signalNewData = pyqtSignal(CSVData)

        def __init__(self, datalogger=None, name="GuiDataJob"):
            target = self._job
            AbstractJob.__init__(self, datalogger=datalogger, target=target, name=name)
            QObject.__init__(self)

        def set_datalogger(self, datalogger):
            self._datalogger = datalogger
            self._datalogger.data_queue[self.name] = queue.Queue()

        def _job(self):
            try:
                # check for datalogger object
                if AbstractJob._job(self):
                    return

                EventLogger.debug(self._job_name + " Started")

                while True:
                    if not self._datalogger.data_queue[self.name].empty():
                        csv_data = self._get_data_from_queue()
                        self.signalNewData.emit(csv_data)

                    if not self._exit_flag and self._datalogger.data_queue[self.name].empty():
                        time.sleep(self._datalogger.job_sleep)

                    if self._exit_flag and self._datalogger.data_queue[self.name].empty():
                        self._remove_from_data_queue()
                        break

            except Exception as e:
                EventLogger.critical(self._job_name + " -.- " + str(e))
                self.stop()



import logging
import threading
import time

if 'merged_data_logger_modules' not in globals():
    from brickv.bindings.ip_connection import IPConnection, base58decode
    from brickv.data_logger.event_logger import EventLogger
    from brickv.data_logger.job import CSVWriterJob#, GuiDataJob
    from brickv.data_logger.loggable_devices import DeviceImpl
    from brickv.data_logger.utils import DataLoggerException
else:
    from tinkerforge.ip_connection import IPConnection, base58decode

class DataLogger(threading.Thread):
    """
    This class represents the data logger and an object of this class is
    the actual instance of a logging process
    """

    # constructor and other functions
    def __init__(self, config, gui_job):
        super().__init__()

        self.daemon = True

        self.jobs = []  # thread hashmap for all running threads/jobs
        self.job_exit_flag = False  # flag for stopping the thread
        self.job_sleep = 1  # TODO: Enahncement -> use condition objects
        self.timers = []
        self._gui_job = gui_job
        self.data_queue = {}  # universal data_queue hash map
        self.host = config['hosts']['default']['name']
        self.port = config['hosts']['default']['port']
        self.secret = config['hosts']['default']['secret']

        if self.secret != None:
            try:
                self.secret.encode('ascii')
            except:
                EventLogger.critical('Authentication secret cannot contain non-ASCII characters')
                self.secret = None

        self.loggable_devices = []
        self.ipcon = IPConnection()

        self.ipcon.register_callback(IPConnection.CALLBACK_CONNECTED, self.cb_connected)
        self.ipcon.register_callback(IPConnection.CALLBACK_ENUMERATE, self.cb_enumerate)

        try:
            self.ipcon.connect(self.host, self.port)  # Connect to brickd
        except Exception as e:
            EventLogger.critical("A critical error occur: " + str(e))
            self.ipcon = None
            raise DataLoggerException(DataLoggerException.DL_CRITICAL_ERROR, "A critical error occur: " + str(e))

        EventLogger.info("Connection to " + self.host + ":" + str(self.port) + " established.")
        self.ipcon.set_timeout(1)  # TODO: Timeout number
        EventLogger.debug("Set ipcon.time_out to 1.")
        self._config = config
        self.csv_file_name = 'logger_data_{0}.csv'.format(int(time.time()))
        self.csv_enabled = True
        self.stopped = False

    def cb_connected(self, connect_reason):
        if self.secret != None:
            try:
                self.secret.encode('ascii')
            except:
                try:
                    self.ipcon.disconnect()
                except:
                    pass

                EventLogger.critical('Authentication secret cannot contain non-ASCII characters')
                return

            self.ipcon.set_auto_reconnect(False) # don't auto-reconnect on authentication error

            try:
                self.ipcon.authenticate(self.secret)
            except:
                try:
                    self.ipcon.disconnect()
                except:
                    pass

                if connect_reason == IPConnection.CONNECT_REASON_AUTO_RECONNECT:
                    extra = ' after auto-reconnect'
                else:
                    extra = ''

                EventLogger.critical('Could not authenticate' + extra)
                return

            self.ipcon.set_auto_reconnect(True)

            EventLogger.info("Successfully authenticated")

        self.apply_options()

    def cb_enumerate(self, uid, connected_uid, position,
                     hardware_version, firmware_version,
                     device_identifier, enumeration_type):
        if enumeration_type in [IPConnection.ENUMERATION_TYPE_AVAILABLE,
                                IPConnection.ENUMERATION_TYPE_CONNECTED]:
            self.apply_options()

    def apply_options(self):
        for loggable_device in self.loggable_devices:
            loggable_device.apply_options()

    def process_data_csv_section(self):
        """
        Information out of the general section will be consumed here
        """
        csv = self._config['data']['csv']

        self.csv_enabled = csv['enabled']
        self.csv_file_name = csv['file_name']

        if self.csv_enabled:
            EventLogger.info("Logging data to CSV file: " + str(self.csv_file_name))

    def initialize_loggable_devices(self):
        """
        This function creates the actual objects for each device out of the configuration
        """
        # start the timers
        for device in self._config['devices']:
            if len(device['uid']) == 0:
                EventLogger.warning('Ignoring "{0}" with empty UID'.format(device['name']))
                continue

            try:
                decoded_uid = base58decode(device['uid'])
            except:
                EventLogger.warning('Ignoring "{0}" with invalid UID: {1}'.format(device['name'], device['uid']))
                continue

            if decoded_uid < 1 or decoded_uid > 0xFFFFFFFF:
                EventLogger.warning('Ignoring "{0}" with out-of-range UID: {1}'.format(device['name'], device['uid']))
                continue

            try:
                loggable_device = DeviceImpl(device, self)
                loggable_device.start_timer()
            except Exception as e:
                msg = "A critical error occur: " + str(e)
                self.stop()
                raise DataLoggerException(DataLoggerException.DL_CRITICAL_ERROR, msg)

            self.loggable_devices.append(loggable_device)

        self.apply_options()

    def run(self):
        """
        This function starts the actual logging process in a new thread
        """
        self.stopped = False
        self.process_data_csv_section()

        self.initialize_loggable_devices()

        """START-WRITE-THREAD"""
        # create jobs
        # look which thread should be working
        if self.csv_enabled:
            self.jobs.append(CSVWriterJob(name="CSV-Writer", datalogger=self))
        if self._gui_job is not None:
            self._gui_job.set_datalogger(self)
            self.jobs.append(self._gui_job)

        for t in self.jobs:
            t.start()
        EventLogger.debug("Jobs started.")

        """START-TIMERS"""
        for t in self.timers:
            t.start()
        EventLogger.debug("Get-Timers started.")

        """END_CONDITIONS"""
        EventLogger.info("DataLogger is running...")
        # TODO Exit condition ?

    def stop(self):
        """
        This function ends the logging process. self.stopped will be set to True if
        the data logger stops
        """
        EventLogger.info("Closing Timers and Threads...")

        """CLEANUP_AFTER_STOP """
        # check if all timers stopped
        for t in self.timers:
            t.stop_and_join()
        EventLogger.debug("Get-Timers[" + str(len(self.timers)) + "] stopped.")

        # set THREAD_EXIT_FLAG for all work threads
        for job in self.jobs:
            job.stop()
        # wait for all threads to stop
        for job in self.jobs:
            job.join()
        EventLogger.debug("Jobs[" + str(len(self.jobs)) + "] stopped.")

        try:
            self.ipcon.disconnect()
        except:
            pass

        EventLogger.info("Connection closed successfully.")

        self.stopped = True

    def add_to_queue(self, csv):
        """
        Adds logged data to all queues which are registered in 'self.data_queue'

        csv --
        """
        for q in self.data_queue.values():
            q.put(csv)



#---------------------------------------------------------------------------
#                               Event Logger
#---------------------------------------------------------------------------

if 'merged_data_logger_modules' not in globals():
    from PyQt5.QtCore import pyqtSignal, QObject

import logging
from datetime import datetime

class EventLogger():
    """
        Basic EventLogger class.
    """

    format = "%(asctime)s - %(levelname)8s - %(message)s"
    __loggers = {}

    def __init__(self):
        pass

    def add_logger(logger):
        if logger.name is None or logger.name == "":
            raise Exception("Logger has no Attribute called 'name'!")

        EventLogger.__loggers[logger.name] = logger

    def remove_logger(logger_name):
        if logger_name in EventLogger.__loggers:
            EventLogger.__loggers.pop(logger_name)
            return True

        return False

    def debug(msg, logger_name=None):
        level = logging.DEBUG
        EventLogger._send_message(level, msg, logger_name)

    def info(msg, logger_name=None):
        level = logging.INFO
        EventLogger._send_message(level, msg, logger_name)

    def warn(msg, logger_name=None):
        level = logging.WARN
        EventLogger._send_message(level, msg, logger_name)

    def warning(msg, logger_name=None):
        level = logging.WARNING
        EventLogger._send_message(level, msg, logger_name)

    def error(msg, logger_name=None):
        level = logging.ERROR
        EventLogger._send_message(level, msg, logger_name)

    def critical(msg, logger_name=None):
        level = logging.CRITICAL
        EventLogger._send_message(level, msg, logger_name)

    def log(level, msg, logger_name=None):
        EventLogger._send_message(level, msg, logger_name)

    def _send_message(level, msg, logger_name):
        if logger_name is not None:
            if logger_name in EventLogger.__loggers:
                EventLogger.__loggers[logger_name].log(level, msg)
        else:
            for logger in EventLogger.__loggers.values():
                logger.log(level, msg)

    # static methods
    add_logger = staticmethod(add_logger)
    remove_logger = staticmethod(remove_logger)
    debug = staticmethod(debug)
    info = staticmethod(info)
    warn = staticmethod(warn)
    warning = staticmethod(warning)
    error = staticmethod(error)
    critical = staticmethod(critical)
    log = staticmethod(log)
    _send_message = staticmethod(_send_message)


class ConsoleLogger(logging.Logger):
    """
    This class outputs the logged debug messages to the console
    """

    def __init__(self, name, log_level):
        super().__init__(name, log_level)

        # create console handler and set level
        ch = logging.StreamHandler()

        ch.setLevel(log_level)

        # create formatter
        formatter = logging.Formatter(EventLogger.format)

        # add formatter to ch
        ch.setFormatter(formatter)

        # add ch to logger
        self.addHandler(ch)

class FileLogger(logging.Logger):
    """
    This class writes the logged debug messages to a log file
    """

    def __init__(self, name, log_level, filename):
        super().__init__(name, log_level)

        ch = logging.FileHandler(filename, mode="a")

        ch.setLevel(log_level)

        # create formatter
        formatter = logging.Formatter(EventLogger.format)

        # add formatter to ch
        ch.setFormatter(formatter)

        # add ch to logger
        self.addHandler(ch)

        self.info("###### NEW LOGGING SESSION STARTED ######")

if 'merged_data_logger_modules' not in globals():
    class GUILogger(logging.Logger, QObject):
        """
        This class outputs the logged data to the brickv gui
        """

        _output_format = "{asctime} - <b>{levelname:8}</b> - {message}"
        _output_format_warning = "<font color=\"orange\">{asctime} - <b>{levelname:8}</b> - {message}</font>"
        _output_format_critical = "<font color=\"red\">{asctime} - <b>{levelname:8}</b> - {message}</font>"

        newEventMessage = pyqtSignal(str)
        newEventTabHighlight = pyqtSignal()

        def __init__(self, name, log_level):
            logging.Logger.__init__(self, name, log_level)
            QObject.__init__(self)

        def debug(self, msg):
            self.log(logging.DEBUG, msg)

        def info(self, msg):
            self.log(logging.INFO, msg)

        def warn(self, msg):
            self.log(logging.WARN, msg)

        def warning(self, msg):
            self.log(logging.WARNING, msg)

        def critical(self, msg):
            self.log(logging.CRITICAL, msg)

        def error(self, msg):
            self.log(logging.ERROR, msg)

        def log(self, level, msg):
            if level >= self.level:
                asctime = '{:%Y-%m-%d %H:%M:%S}'.format(datetime.now())
                levelname = logging.getLevelName(level)

                if level == logging.WARN or level == logging.WARNING:
                    self.newEventMessage.emit(GUILogger._output_format_warning.format(asctime=asctime, levelname=levelname, message=msg))
                    self.newEventTabHighlight.emit()
                elif level == logging.CRITICAL or level == logging.ERROR:
                    self.newEventMessage.emit(GUILogger._output_format_critical.format(asctime=asctime, levelname=levelname, message=msg))
                    self.newEventTabHighlight.emit()
                else:
                    self.newEventMessage.emit(GUILogger._output_format.format(asctime=asctime, levelname=levelname, message=msg))



# MAIN DATA_LOGGER PROGRAM
import argparse  # command line argument parser
import os
import signal
import sys
import traceback
import logging
import functools
import time
import locale

if 'merged_data_logger_modules' not in globals():
    from brickv.data_logger.data_logger import DataLogger
    from brickv.data_logger.event_logger import ConsoleLogger, FileLogger, EventLogger
    from brickv.data_logger.utils import DataLoggerException
    from brickv.data_logger.configuration import load_and_validate_config

def signal_handler(interrupted_ref, signum, frame):
    """
    This function handles the ctrl + c exit condition
    if it's raised through the console
    """
    EventLogger.info('Received SIGINT/SIGTERM')
    interrupted_ref[0] = True

def log_level_name_to_id(log_level):
    if log_level == 'debug':
        return logging.DEBUG
    elif log_level == 'info':
        return logging.INFO
    elif log_level == 'warning':
        return logging.WARNING
    elif log_level == 'error':
        return logging.ERROR
    elif log_level == 'critical':
        return logging.CRITICAL
    else:
        return logging.INFO

def main(config_filename, gui_config, gui_job, override_csv_file_name,
         override_log_file_name, interrupted_ref):
    """
    This function initialize the data logger and starts the logging process
    """
    config = None
    gui_start = False

    if config_filename != None: # started via console
        config = load_and_validate_config(config_filename)

        if config == None:
            return None
    else: # started via GUI
        config = gui_config
        gui_start = True

    if override_csv_file_name != None:
        config['data']['csv']['file_name'] = override_csv_file_name

    if override_log_file_name != None:
        config['debug']['log']['file_name'] = override_log_file_name

    try:
        if config['debug']['log']['enabled']:
            EventLogger.add_logger(FileLogger('FileLogger', log_level_name_to_id(config['debug']['log']['level']),
                                              config['debug']['log']['file_name']))

        data_logger = DataLogger(config, gui_job)

        if data_logger.ipcon is not None:
            data_logger.run()

            if not gui_start:
                while not interrupted_ref[0]:
                    try:
                        time.sleep(0.25)
                    except:
                        pass

                data_logger.stop()
                sys.exit(0)
        else:
            raise DataLoggerException(DataLoggerException.DL_CRITICAL_ERROR,
                                      "DataLogger did not start logging process! Please check for errors.")

    except Exception as exc:
        EventLogger.critical(str(exc))
        if gui_start:
            return None
        else:
            sys.exit(DataLoggerException.DL_CRITICAL_ERROR)

    return data_logger

if __name__ == '__main__':
    try:
        locale.setlocale(locale.LC_ALL, '')
    except locale.Error:
        pass # ignore this as it might fail on macOS, we'll fallback to UTF-8 in that case

    parser = argparse.ArgumentParser(description='Tinkerforge Data Logger')

    class VersionAction(argparse.Action):
        def __call__(self, parser, namespace, values, option_string=None):
            print(data_logger_version)
            sys.exit(0)

    parser.add_argument('-v', '--version', action=VersionAction, nargs=0, help='show version and exit')
    parser.add_argument('config', help='config file location', metavar='CONFIG')
    parser.add_argument('--console-log-level', choices=['none', 'debug', 'info', 'warning', 'error', 'critical'],
                        default='info', help='change console log level (default: info)')
    parser.add_argument('--override-csv-file-name', type=str, default=None,
                        help='override CSV file name in config')
    parser.add_argument('--override-log-file-name', type=str, default=None,
                        help='override log file name in config')

    args = parser.parse_args(sys.argv[1:])

    if args.console_log_level != 'none':
        EventLogger.add_logger(ConsoleLogger('ConsoleLogger', log_level_name_to_id(args.console_log_level)))

    interrupted_ref = [False]

    signal.signal(signal.SIGINT, functools.partial(signal_handler, interrupted_ref))
    signal.signal(signal.SIGTERM, functools.partial(signal_handler, interrupted_ref))

    main(args.config, None, None, args.override_csv_file_name, args.override_log_file_name, interrupted_ref)

