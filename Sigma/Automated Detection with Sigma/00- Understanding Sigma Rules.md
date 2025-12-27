# 1.0 :: Understanding Sigma Rules

## Sigma Rule

```yaml
title: Remote Access Tool - Team Viewer Session Started On Windows Host
id: ab70c354-d9ac-4e11-bbb6-ec8e3b153357
related:
    - id: 1f6b8cd4-3e60-47cc-b282-5aa1cbc9182d
      type: similar
    - id: f459ccb4-9805-41ea-b5b2-55e279e2424a
      type: similar
status: experimental
description: |
    Detects the command line executed when TeamViewer starts a 	session started by a remote host.
    Once a connection has been started, an investigator can verify the connection details by viewing the "incoming_connections.txt" log file in the TeamViewer folder.
references:
    - Internal Research
author: Josh Nickels, Qi Nan
date: 2024-03-11
tags:
    - attack.initial-access
    - attack.t1133
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: 'TeamViewer_Desktop.exe'
        ParentImage: 'TeamViewer_Service.exe'
        CommandLine|endswith: 'TeamViewer_Desktop.exe --IPCport 5939 --Module 1'
    condition: selection
falsepositives:
    - Legitimate usage of TeamViewer
level: low
```

- `title` & `id`: These are unique fields for each rule and provide an easy way to distinguish one rule from another while bulk-importing and parsing rules.
- `related`:  This indicates that there are two other rules in the repo that share some characteristics with this rule. In this case, both of those rules share the same detection logic but are intended for a different log source.
- `status`: Used by detection engineers to assist in understanding how confident they should be about the quality of this rule.
- `description`: Provide an analyst with an understanding of what the rule is looking for.
- `reference`: Contains source material or links to describe the attack path.
- `author`: Who wrote the rule.
- `date`: First time of published.
- `tags`: Based on the MITRE ATT&CK naming convention which can then be used by an analyst to provide additional context or ideas on how to respond to a true positive detection.  
There will always be two elements in this field. One will be the “tactic” used which describes the larger branch that the "technique" you are identifying is under on the MITRE ATT&CK matrix, and then the "technique" which is represented by the numerical identifier of the specific technique the detection attempts to identify in the logs.
- `logsource`: The log source fields will be interpreted by your converter and backend and transformed into, in our case with Splunk, an SPL representation of something like `index=win_events sourcetype:proc_creation`.

A logsource is made up of three components:  
- **Category**: the action-type that the logs related to this detection identify. In this case it is process_creation which indicates that the logs we are looking at are related to a process creation event. Some other category examples may be firewall or webserver or network connections.  
- **Product**: the specific product that the rule is interested in. In this case we’re looking at Windows logs but you will also see rules for Linux, MacOS, Apache, Okta, or other products.  
- **Service**: the specific service running inside of a product such as DNS, CloudTrail, or LDAP.

- `detection`: Defines the logic that actually makes up the associated query.
In this specific rule, everything in the selection subfield will be used and combined with an implied AND, resulting in SPL that looks something like: `index=win_event sourcetype=process_creation Image=’TeamViewer_Desktop.exe’ ParentImage=’TeamViewer_Service.exe’ CommandLine=’*TeamViewer_Desktop.exe --IPCport 5939 --Module 1’`. 
- `falsepositives`: Describe what sort of scenarios might contribute to a false positive detection.
- `level`: Describes the severity or criticality of the rule if a detection is triggered.

## More Complex Sigma Rule

```
title: Imports Registry Key From a File
id: 73bba97f-a82d-42ce-b315-9182e76c57b1
related:
    - id: 0b80ade5-6997-4b1d-99a1-71701778ea61
      type: similar
status: test
description: Detects the import of the specified file to the registry with regedit.exe.
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Regedit/
    - https://gist.github.com/api0cradle/cdd2d0d0ec9abb686f0e89306e277b8f
author: Oddvar Moe, Sander Wiebing, oscd.community
date: 2020-10-07
modified: 2024-03-13
tags:
    - attack.t1112
    - attack.defense-evasion
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\regedit.exe'
        - OriginalFileName: 'REGEDIT.EXE'
    selection_cli:
        CommandLine|contains:
            - ' /i '
            - ' /s '
            - '.reg'
    filter_1:
        CommandLine|contains|windash:
            - ' -e '
            - ' -a '
            - ' -c '
    filter_2:
        CommandLine|re: ':[^ \\]' # to avoid intersection with ADS rule
    condition: all of selection_* and not all of filter_*
fields:
    - ParentImage
    - CommandLine
falsepositives:
    - Legitimate import of keys
    - Evernote
level: medium
```

```
Image="*\\regedit.exe" OR OriginalFileName="REGEDIT.EXE" CommandLine IN ("* /i *", "* /s *", "*.reg*") NOT (CommandLine="* -e *" OR CommandLine="* /e *" OR CommandLine="* -a *" OR CommandLine="* /a *" OR CommandLine="* -c *" OR CommandLine="* /c *") 
| regex CommandLine=":[^ \\\\]" 
| table ParentImage,CommandLine
```

[https://sigconverter.io/](https://sigconverter.io/) give me this.
```
Image=&quot;*\\regedit.exe&quot; OR OriginalFileName=&quot;REGEDIT.EXE&quot; CommandLine IN (&quot;* /i *&quot;, &quot;* /s *&quot;, &quot;*.reg*&quot;) NOT (CommandLine=&quot;* -e *&quot; OR CommandLine=&quot;* /e *&quot; OR CommandLine=&quot;* –e *&quot; OR CommandLine=&quot;* —e *&quot; OR CommandLine=&quot;* ―e *&quot; OR CommandLine=&quot;* -a *&quot; OR CommandLine=&quot;* /a *&quot; OR CommandLine=&quot;* –a *&quot; OR CommandLine=&quot;* —a *&quot; OR CommandLine=&quot;* ―a *&quot; OR CommandLine=&quot;* -c *&quot; OR CommandLine=&quot;* /c *&quot; OR CommandLine=&quot;* –c *&quot; OR CommandLine=&quot;* —c *&quot; OR CommandLine=&quot;* ―c *&quot;)
| regex CommandLine=&quot;:[^ \\\\]&quot; | table ParentImage,CommandLine
```


## Convert Sigma rules to SPL (Search Procesing Language) SPLUNK

For this exercise, it is recommended to do it by hand.
But this is a great resource: [Sigma converter](https://sigconverter.io/)

### Sigma rule to convert 1:

```
title: Chromium Browser Instance Executed With Custom Extension
id: 88d6e60c-759d-4ac1-a447-c0f1466c2d21
related:
    - id: 27ba3207-dd30-4812-abbf-5d20c57d474e
      type: similar
status: test
description: Detects a Chromium based browser process with the 'load-extension' flag to start a instance with a custom extension
references:
    - https://redcanary.com/blog/chromeloader/
    - https://emkc.org/s/RJjuLa
    - https://www.mandiant.com/resources/blog/lnk-between-browsers
author: Aedan Russell, frack113, X__Junior (Nextron Systems)
date: 2022-06-19
modified: 2023-11-28
tags:
    - attack.persistence
    - attack.t1176.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\brave.exe'
            - '\chrome.exe'
            - '\msedge.exe'
            - '\opera.exe'
            - '\vivaldi.exe'
        CommandLine|contains: '--load-extension='
    condition: selection
falsepositives:
    - Usage of Chrome Extensions in testing tools such as BurpSuite will trigger this alert
level: medium
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_browsers_chromium_load_extension/info.yml
```

### Query

```
Image IN ("*\\brave.exe", "*\\chrome.exe", "*\\msedge.exe", "*\\opera.exe", "*\\vivaldi.exe") CommandLine="*--load-extension=*"
```

### Sigma Rule 2

```
title: Network Connection Initiated To Mega.nz
id: fdeebdf0-9f3f-4d08-84a6-4c4d13e39fe4
status: test
description: |
    Detects a network connection initiated by a binary to "api.mega.co.nz".
    Attackers were seen abusing file sharing websites similar to "mega.nz" in order to upload/download additional payloads.
references:
    - https://megatools.megous.com/
    - https://www.mandiant.com/resources/russian-targeting-gov-business
author: Florian Roth (Nextron Systems)
date: 2021-12-06
modified: 2024-05-31
tags:
    - attack.exfiltration
    - attack.t1567.002
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        Initiated: 'true'
        DestinationHostname|endswith:
            - 'mega.co.nz'
            - 'mega.nz'
    condition: selection
falsepositives:
    - Legitimate MEGA installers and utilities are expected to communicate with this domain. Exclude hosts that are known to be allowed to use this tool.
level: low
```

### Query

```
Initiated="true" DestinationHostname IN ("*mega.co.nz", "*mega.nz")
```

