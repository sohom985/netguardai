#!/bin/bash
echo "🛡️  Starting NetGuardAI Professional..."
# 1. Start the Sniffer in the BACKGROUND (&)
echo "--- Launching Packet Sniffer (Background) ---"
sudo python sniffer.py &
SNIFFER_PID=$!
# Wait for sniffer to initialize
sleep 2
# 2. Start the Dashboard in the FOREGROUND
echo "--- Launching Dashboard ---"
streamlit run dashboard.py
# 3. Cleanup: When dashboard closes, kill the sniffer
kill $SNIFFER_PID