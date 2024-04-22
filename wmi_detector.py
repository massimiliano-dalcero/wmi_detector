#!/usr/bin/env python
#  
#  wmi_detector.py
#  Version 1.0
#  Based on work of David Pany: PyWMIPersistenceFinder.py - Version 1.1
#
#  This version is a porting for Python 3(.10) and output is JSON friendly
#
#  Author:
#      Massimiliano Dal Cero - Digital Defense
#
#
# Orinal Author:
#   David Pany - Mandiant (FireEye) - 2017
#   Twitter: @DavidPany
#   Please send  comments, bug reports, and questions to @DavidPany
#       or push changes directly to GitHub
#
# Usage:
#   wmi_detector.py <OBJECTS.DATA file>
#
#   The output is json based in the following format for each binding:
#{
#  "Malicious Consumer-Malicious Filter": {
#    "binding_details": {
#      "event_consumer_name": "Malicious Consumer",
#      "event_filter_name": "Malicious Filter"
#    },
#    "binding_name": "Malicious Consumer-Malicious Filter",
#    "consumers": [
#      {
#        "consumer_arguments": "powershell.exe -Command IEX \"'echo ciao | Out-File -FilePath C:\\salve.txt'\"",
#        "consumer_name": "Malicious Consumer",
#        "consumer_type": "CommandLineEventConsumer"
#      }
#    ],
#    "filters": [
#      {
#        "filter_name": "Malicious Filter",
#        "filter_query": "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA \"Win32_Process\" AND TargetInstance.Name = \"notepad.exe\""
#      }
#    ],
#    "info": ""
#  },
#  "SCM Event Log Consumer-SCM Event Log Filter": {
#    "binding_details": {
#      "event_consumer_name": "SCM Event Log Consumer",
#      "event_filter_name": "SCM Event Log Filter"
#    },
#    "binding_name": "SCM Event Log Consumer-SCM Event Log Filter",
#    "consumers": [
#      "NTEventLogEventConsumer ~ SCM Event Log Consumer ~ sid ~ Service Control Manager"
#    ],
#    "filters": [
#      {
#        "filter_name": "SCM Event Log Filter",
#        "filter_query": "select * from MSFT_SCMEventLogEvent"
#      }
#    ],
#    "info": "Common binding based on consumer and filter names,possibly legitimate"
#  }
#}
#
# Execution time:
#   Execution time has been reported from 10 seconds to 5 minutes depending on input size.
#
# Description:
#   wmi_detector.py is designed to find WMI persistence via FitlerToConsumerBindings
#   solely by keyword searching the OBJECTS.DATA file without parsing the full WMI repository.
#
#   In testing, this script has found the exact same data as python-cim's
#   show_FilterToConsumerBindings.py without requiring the setup. Only further testing will
#   indicate if this script misses any data that python-cim can find.
#
#   In theory, this script will detect FilterToConsumerBindings that are deleted and remain
#   in unallocated WMI space, but I haven't had a chance to test yet.
#
# Terms:
#   Event Filter:
#       Basically a condition that WMI is waiting for
#
#   Event Consumer:
#       Basically something that will happen such as script/file execution
#
#   Filter To Consumer Binding:
#       Structure that says "When filter condition happens, execute consumer"
#
# References:
#   https://github.com/davidpany/WMI_Forensics
#   https://github.com/fireeye/flare-wmi/tree/master/python-cim
#   https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/wp-windows-management-instrumentation.pdf
#
# License:
#   Copyright (c) 2017 David Pany [WMI_Forensics]
#   Copyright (c) 2024 Massimiliano Dal Cero [wmi_detector]
#
#   Permission is hereby granted, free of charge, to any person obtaining a copy
#   of this software and associated documentation files (the "Software"), to deal
#   in the Software without restriction, including without limitation the rights
#   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#   copies of the Software, and to permit persons to whom the Software is
#   furnished to do so, subject to the following conditions:
#
#   The above copyright notice and this permission notice shall be included in
#   all copies or substantial portions of the Software.
#
#   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#   SOFTWARE.
#

#from __future__ import print_function
import sys
import re
import string
import json
import pprint
import hashlib

PRINTABLE_CHARS = set(string.printable)

def main():
    """Main function for everything!"""

    print("\nWorking to find and enumerate FilterToConsumerBindings ... (please wait)", file=sys.stderr)

    #Read objects.data 4 lines at a time to look for bindings
    objects_file = open(sys.argv[1], "rb")

    lines_list = []
    for r in range(0,4):
        current_line = objects_file.readline()
        lines_list.append(current_line)        


    #Precompiled match objects to search each line with
    event_consumer_mo = re.compile(br"([\w\_]*EventConsumer\.Name\=\")([\w\s]*)(\")")
    event_filter_mo = re.compile(br"(_EventFilter\.Name\=\")([\w\s]*)(\")")

    #Dictionaries that will store bindings, consumers, and filters
    bindings_dict = {}
    consumer_dict = {}
    filter_dict = {}

    for current_line in objects_file:
        # Join all the read lines together (should always be 4) to look for bindings spread over
        #   multiple lines that may have been one page
        potential_page = b" ".join(lines_list)

        # Look for FilterToConsumerBindings
        if b"_FilterToConsumerBinding" in potential_page:
            if (
                    re.search(event_consumer_mo, potential_page) and
                    re.search(event_filter_mo, potential_page)
            ):
                event_consumer_name = re.search(event_consumer_mo, potential_page).groups(0)[1]
                event_filter_name = re.search(event_filter_mo, potential_page).groups(0)[1]

                event_consumer_name = event_consumer_name.decode('utf-8')
                event_filter_name = event_filter_name.decode('utf-8')

                #Add the consumers and filters to their dicts if they don't already exist
                if event_consumer_name not in consumer_dict:
                    consumer_dict[event_consumer_name] = {}
                if event_filter_name not in filter_dict:
                    filter_dict[event_filter_name] = {}

                #Give the binding a name and add it to the dict
                binding_id = "{}-{}".format(event_consumer_name, event_filter_name)
                if binding_id not in bindings_dict:
                    bindings_dict[binding_id] = {
                        "event_consumer_name":event_consumer_name,
                        "event_filter_name":event_filter_name}

        # Increment lines and look again
        # current_line = objects_file.readline()
        lines_list.append(current_line)
        lines_list.pop(0)

    # Close the file and look for consumers and filters
    objects_file.close()
    print("{} FilterToConsumerBinding(s) Found. Enumerating Filters and Consumers...".format(len(bindings_dict)), file=sys.stderr)

    # Read objects.data 4 lines at a time to look for filters and consumers
    objects_file = open(sys.argv[1], "rb")

    lines_list = []
    for r in range(0,4):
        current_line = objects_file.readline()
        lines_list.append(current_line)

    for current_line in objects_file:
        potential_page = b" ".join(lines_list).replace(b"\n", b"")

        # Check each potential page for the consumers we are looking for
        if b"EventConsumer" in potential_page:
            for event_consumer_name, event_consumer_details in consumer_dict.items():

                # Can't precompile regex because it is dynamically created with each consumer name
                if b"CommandLineEventConsumer" in potential_page:
                    consumer_mo = re.compile(
                            r"(CommandLineEventConsumer)(\x00\x00)(.*?)(\x00)(.*?)({})(\x00\x00)?([^\x00]*)?".format(event_consumer_name).encode()
                    )
                    consumer_match = re.search(consumer_mo, potential_page)
                    if consumer_match:
                        noisy_string = consumer_match.groups()[2].decode('utf-8')
                        consumer_details = {
                            "consumer_type": consumer_match.groups()[0].decode('utf-8'),
                            "consumer_arguments": noisy_string
                        }
                        if consumer_match.groups()[5]:
                            consumer_details["consumer_name"] = consumer_match.groups()[5].decode('utf-8')
                        if consumer_match.groups()[7]:
                            consumer_details["other"] =  consumer_match.groups()[7].decode('utf-8')
                        consumer_dict[event_consumer_name][hashlib.md5(json.dumps(consumer_details, sort_keys=True).encode('utf-8')).hexdigest()] = consumer_details

                else:
                    consumer_mo = re.compile(
                        r"(\w*EventConsumer)(.*?)({})(\x00\x00)([^\x00]*)(\x00\x00)([^\x00]*)".format(event_consumer_name).encode()
                    )
                    consumer_match = re.search(consumer_mo, potential_page)
                    if consumer_match:
                        consumer_details = "{} ~ {} ~ {} ~ {}".format(
                            consumer_match.groups()[0].decode('utf-8'),
                            consumer_match.groups()[2].decode('utf-8'),
                            consumer_match.groups()[4].decode('utf-8'),
                            consumer_match.groups()[6].decode('utf-8'))
                        consumer_dict[event_consumer_name][hashlib.md5(json.dumps(consumer_details, sort_keys=True).encode('utf-8')).hexdigest()] = consumer_details

        # Check each potential page for the filters we are looking for
        for event_filter_name, event_filter_details in filter_dict.items():
            if event_filter_name.encode() in potential_page:
                # Can't precompile regex because it is dynamically created with each filter name
                filter_mo = re.compile(
                    r"({})(\x00\x00)([^\x00]*)(\x00\x00)".format(event_filter_name).encode()
                )
                filter_match = re.search(filter_mo, potential_page)
                if filter_match:
                    filter_details = { 
                            "filter_name": filter_match.groups()[0].decode('utf-8'),
                            "filter_query": filter_match.groups()[2].decode('utf-8')
                    }
                    filter_dict[event_filter_name][hashlib.md5(json.dumps(filter_details, sort_keys=True).encode('utf-8')).hexdigest()] = filter_details

        lines_list.append(current_line)
        lines_list.pop(0)
    objects_file.close()
    
    print("\nBindings found in json format:\n", file=sys.stderr)

    out = {}

    for binding_name, binding_details in bindings_dict.items():

        out[binding_name] = {
                "binding_name": binding_name,
                "binding_details": binding_details,
                "info": "",
                "consumers": [],
                "filters": []
        }

        if (
                "BVTConsumer-BVTFilter" in binding_name or
                "SCM Event Log Consumer-SCM Event Log Filter" in binding_name
        ):
            out[binding_name]["info"] = "Common binding based on consumer and filter names,possibly legitimate"
        
        
        event_filter_name = binding_details["event_filter_name"]
        event_consumer_name = binding_details["event_consumer_name"]

        # Print binding details if available
        if consumer_dict[event_consumer_name]:
            for event_consumer_details in consumer_dict[event_consumer_name]:
                out[binding_name]["consumers"].append(consumer_dict[event_consumer_name][event_consumer_details])
        else:
            out[binding_name]["consumers"].append(event_consumer_name)

        # Print details for each filter found for this filter name
        for event_filter_details in filter_dict[event_filter_name]:
            out[binding_name]["filters"].append(filter_dict[event_filter_name][event_filter_details])

    print( json.dumps(out, indent=3, sort_keys=True) )


if __name__ == "__main__":
    main()
