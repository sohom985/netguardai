#!/bin/bash
# entrypoint.sh - Starts both sniffer and dashboard

echo "🛡️ Starting NetGuardAI Container..."

# Start the packet sniffer in the background
echo "📡 Starting Packet Sniffer..."
python sniffer.py &
SNIFFER_PID=$!

# Give the sniffer a moment to initialize the database
sleep 2

# Start the Streamlit dashboard (foreground)
echo "🌐 Starting Dashboard on port 8501..."
streamlit run dashboard.py --server.port=8501 --server.address=0.0.0.0 --server.headless=true

# If dashboard exits, stop the sniffer
kill $SNIFFER_PID 2>/dev/null
