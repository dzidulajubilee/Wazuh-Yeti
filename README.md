# Wazuh-Yeti



## 2. Change the ownership and permission for the /var/ossec/integrations/custom-yeti.pyfile:

chmod 750 /var/ossec/integrations/custom-yeti.py
chown root:wazuh /var/ossec/integrations/custom-yeti.py
## 3. Add the following configuration to the /var/ossec/etc/ossec.conf file to configure the Yeti integration. This integration is triggered when the rule group syscheck and sshdtriggers:

<integration>

  <name>custom-yeti.py</name>
  <api_key><YETI_API_KEY></api_key>
  <group>syscheck,sshd,ids,suricata</group>
  <alert_format>json</alert_format>

</integration> 
    
Replace <YETI_API_KEY> with the API key you will obtain from the Yeti user profile and follow the process below.



# 4. Create a file called yeti_rules.xml in the /var/ossec/etc/rules/ directory and insert the following custom rules:

<group name="yeti,">

    <rule id="100500" level="0">
        <decoded_as>json</decoded_as>
        <field name="integration">yeti</field>
        <description>yeti integration messages.</description>
        <options>no_full_log</options>
    </rule>

    <rule id="100501" level="12">
        <if_sid>100500</if_sid>
        <field name="yeti.info.source">AbuseCHMalwareBazaaar</field>
        <description>"Yeti Alert - " $(yeti.info.source) detected this file: $(yeti.source.file) </description>
        <group>pci_dss_10.6.1,pci_dss_11.4,gdpr_IV_35.7.d,</group>
        <options>no_full_log</options>
        <mitre>
            <id>T1203</id>
        </mitre>
    </rule>

     <rule id="100502" level="12">
        <if_sid>100500</if_sid>
        <field name="yeti.info.source">AlienVaultIPReputation</field>
        <description>"Yeti Alert - " $(yeti.info.source) detected IP address: $(yeti.source.src_ip) </description>
        <group>pci_dss_10.2.4,pci_dss_10.2.5,</group>
        <options>no_full_log</options>
    </rule>
    
    <rule id="100503" level="12">
        <if_sid>100500</if_sid>
        <field name="yeti.info.source">UrlHaus|OpenPhish</field>
        <description>"Yeti Alert - " $(yeti.info.source) detected url: $(yeti.info.url) </description>
        <options>no_full_log</options>
    </rule>
</group>

# 5. Create a file called suricata_http_rules.xml in the /var/ossec/etc/rules/ directory and insert the following custom rules:


<group name="ids,suricata,">
    <rule id="86602" level="3" overwrite= "yes">
        <if_sid>86600</if_sid>
        <field name="event_type">^http$</field>
        <field name="http.url" negate="yes">^/wr2$</field>
        <field name="http.url" negate="yes">^/we2$</field>
        <field name="http.url" negate="yes">^/$</field>
        <description>Suricata: HTTP.</description>
        <options>no_full_log</options>
    </rule>
</group>


6. Restart the Wazuh manager service to apply the changes.

systemctl restart wazuh-manager
