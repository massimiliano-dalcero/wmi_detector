# WMI_Detector
This repository contains scripts used to find evidence in WMI repositories, specifically OBJECTS.DATA files located at:

- C:\WINDOWS\system32\wbem\Repository\OBJECTS.DATA
- C:\WINDOWS\system32\wbem\Repository\FS\OBJECTS.DATA

## wmi_detector.py
wmi_detector.py is designed to find WMI persistence via FitlerToConsumerBindings
solely by keyword searching the OBJECTS.DATA file without parsing the full WMI repository.

This script can detect FilterToConsumerBindings that are deleted and remain in unallocated WMI space. 
I did the test in a lab environment and was able to spot the previous deleted FilterToConsumerBindings.

Based on work of David Pany: PyWMIPersistenceFinder.py 

https://github.com/davidpany/WMI_Forensics

### Usage
```wmi_detector.py <OBJECTS.DATA file>```

The output is json based in the following format for each binding:
```
{
  "<consumer name>-<filter name>": {
    "binding_details": {
      "event_consumer_name": "<consumer name",
      "event_filter_name": "<filter name>"
    },
    "binding_name": "<consumer name>-<filter name>",
    "consumers": [
      {
        "consumer_arguments": "<command>",
        "consumer_name": "<consumer name>-",
        "consumer_type": "CommandLineEventConsumer"
      }
    ],
    "filters": [
      {
        "filter_name": "<filter name>",
        "filter_query": "<query>"
      }
    ],
    "info": ""
  }
}
```
An example:
```
{
  "Malicious Consumer-Malicious Filter": {
    "binding_details": {
      "event_consumer_name": "Malicious Consumer",
      "event_filter_name": "Malicious Filter"
    },
    "binding_name": "Malicious Consumer-Malicious Filter",
    "consumers": [
      {
        "consumer_arguments": "powershell.exe -Command IEX \"'echo ciao | Out-File -FilePath C:\\salve.txt'\"",
        "consumer_name": "Malicious Consumer",
        "consumer_type": "CommandLineEventConsumer"
      }
    ],
    "filters": [
      {
        "filter_name": "Malicious Filter",
        "filter_query": "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA \"Win32_Process\" AND TargetInstance.Name = \"notepad.exe\""
      }
    ],
    "info": ""
  },
  "SCM Event Log Consumer-SCM Event Log Filter": {
    "binding_details": {
      "event_consumer_name": "SCM Event Log Consumer",
      "event_filter_name": "SCM Event Log Filter"
    },
    "binding_name": "SCM Event Log Consumer-SCM Event Log Filter",
    "consumers": [
      "NTEventLogEventConsumer ~ SCM Event Log Consumer ~ sid ~ Service Control Manager"
    ],
    "filters": [
      {
        "filter_name": "SCM Event Log Filter",
        "filter_query": "select * from MSFT_SCMEventLogEvent"
      }
    ],
    "info": "Common binding based on consumer and filter names,possibly legitimate"
  }
}
```

# Contact
Massimiliano Dal Cero - Digital Defense - 2024

Linkedin: https://www.linkedin.com/in/dalcero

Please send  comments, bug reports, and questions to @massimiliano-dalcero or push changes directly to GitHub

