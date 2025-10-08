# Wazuh-Yeti



## 2. Change the ownership and permission for the /var/ossec/integrations/custom-yeti.pyfile:

chmod 750 /var/ossec/integrations/custom-yeti.py
chown root:wazuh /var/ossec/integrations/custom-yeti.py


## 3. Add the following configuration to the /var/ossec/etc/ossec.conf file to configure the Yeti integration. This integration is triggered when the rule group syscheck and sshdtriggers:

<integration>
  <name>custom-yeti.py</name>
  <hook_url>http://192.168.244.100:8000/api/v2</hook_url>
  <api_key></api_key>
<group>sysmon_event1,sysmon_event2,sysmon_event3,sysmon_event4,sysmon_event5,sysmon_event6,sysmon_event7,sysmon_event8,sysmon_event9,sysmon_event_10,sysmon_event_11,sysmon_event_12,sysmon_event_13,sysmon_event_14,sysmon_event_15,sysmon_event_16,sysmon_event_17,sysmon_event_18,sysmon_event_19,sysmon_event_20,sysmon_event_21,sysmon_event_22,sysmon_event_23,sysmon_event_24,sysmon_event_25,sysmon_event_26,sysmon_event_255,syscheck</group>
  <alert_format>json</alert_format>
  <options>{
      "timeout": 10,
      "retries": 3,
      "debug": true
  }</options>
</integration>

    
Replace <YETI_API_KEY> with the API key you will obtain from the Yeti user profile and follow the process below.



# 4. Create a file called yeti_rules.xml in the /var/ossec/etc/rules/ directory and insert the following custom rules:




6. Restart the Wazuh manager service to apply the changes.

systemctl restart wazuh-manager
