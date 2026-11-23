#!/bin/bash
mkdir -p /var/log/victim

# The Wazuh agent only runs with the soc profile (WAZUH_ENABLED=true in .env)
if [ "$WAZUH_ENABLED" = "true" ]; then
  sed -i 's#<address>.*</address>#<address>wazuh.manager</address>#' /var/ossec/etc/ossec.conf
  /var/ossec/bin/agent-auth -m wazuh.manager
  /var/ossec/bin/wazuh-control start
fi

exec python /app/app.py
