#!/bin/bash

 #Defining variables for Python
 export G_U=${G_U:-"username"}
 export G_T=${G_T:-"/run/secrets/tokens"}
 export G_R=${G_R:-"repositriesName"}
 export M_U=${M_U:-"/run/secrets/username"}
 export M_P=${M_P:-"/run/secrets/password"}
 export M_IP=${M_IP:-"/run/secrets/mikrotik_ip"}
 export M_KEY=${M_KEY:-"/run/secrets/mikrotik_key"}
 export D_KEY=${D_KEY:-"/run/secrets/decrypt_key"}

echo "Starting up backup with args:"
echo "$@"
echo "and env:"
echo "$(env)"


set -x

# Running the Python script with the variables defined above
python3 /app/app_mik.py -g_u "$G_U" -g_t "$G_T" -g_r "$G_R" -m_u "$M_U" -m_p "$M_P" -m_ip "$M_IP" -m_key "$M_KEY" -d_key "$D_KEY"
