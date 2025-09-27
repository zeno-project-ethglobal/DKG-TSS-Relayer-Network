#!/bin/bash
# run_nodes.sh

# Use $HOME so it's portable; change if needed
PROJECT_DIR="$HOME/Desktop/Project Zeno/main"

# Bootnode
osascript -e "tell application \"Terminal\" to do script \"cd '$PROJECT_DIR' && pwd && go run bootnode/bootnode.go\""

# Node 1
osascript -e "tell application \"Terminal\" to do script \"cd '$PROJECT_DIR' && pwd && go run node/node.go 8000 8001\""

# Node 2
osascript -e "tell application \"Terminal\" to do script \"cd '$PROJECT_DIR' && pwd && go run node/node.go 8002 8003\""

# Node 3
osascript -e "tell application \"Terminal\" to do script \"cd '$PROJECT_DIR' && pwd && go run node/node.go 8004 8005\""
