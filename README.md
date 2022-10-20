# Analyze-CiscoSwitchConfiguration
This script parses a plain text formatted Cisco switch configuration file and checks for specific security configuration entries.  It displays whether certain configuration requirements pass or fail the check.

## Putty Log Generation
One option, though manually intensive if you have a lot of switches, to generate clean `show running-configuration` dumps is to utilize the logging capabilities of Putty.  If you don't backup configs to a central location or utilize some type of enterprise management software like Cisco Prime or SolarWinds this might be your only option.  In this example I use the `&H` option which names the log according to the IP or hostname used for the connection in Putty's `Session` dialog.

![putty_logging](https://user-images.githubusercontent.com/12549026/196839001-4d1569b0-c572-473b-a7fa-0bfa1b37217f.PNG)

After switch login and `enable` mode elevation, run the following commands to generate the running config output.  This method ensures the printed config output will not include the `--More--` dialog used in IOS for manual advancement of the running config view.  The `terminal length` command is persistent for the current session only so exiting will revert back to the previous setting.

```ios
switch#terminal length 0
switch#show run
```
