#!/bin/bash

LOGDIR="./logs"
mkdir -p "$LOGDIR"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

start_all() {
    echo -e "${YELLOW}Starting AIMMS engines...${NC}\n"

    echo -e "${GREEN}[1/5]${NC} Starting Node.js API server..."
    node ../backend/server.js > "$LOGDIR/api.log" 2>&1 &
    echo $! > "$LOGDIR/api.pid"
    sleep 2

    echo -e "${GREEN}[2/5]${NC} Starting rule engine..."
    node ../detection/rule_engine.js > "$LOGDIR/rules.log" 2>&1 &
    echo $! > "$LOGDIR/rules.pid"

    echo -e "${GREEN}[3/5]${NC} Starting behavioral profiler..."
    node ../behavioral-profiling/behavioralProfiler.js > "$LOGDIR/profiler.log" 2>&1 &
    echo $! > "$LOGDIR/profiler.pid"

    echo -e "${GREEN}[4/5]${NC} Starting risk scorer..."
    node ../risk-scoring/riskScorer.js > "$LOGDIR/scorer.log" 2>&1 &
    echo $! > "$LOGDIR/scorer.pid"

    echo -e "${GREEN}[5/5]${NC} Starting mitigation engine..."
    node ../mitigation/mitigationEngine.js > "$LOGDIR/mitigation.log" 2>&1 &
    echo $! > "$LOGDIR/mitigation.pid"

    echo -e "${YELLOW}[!]${NC} Start sniffer manually in another terminal:"
    echo -e "    cd ~/Desktop/AIMMS"
    echo -e "    sudo venv/bin/python sniffer/sniffer.py"

    echo -e "\n${GREEN}All engines started.${NC}"
    echo -e "Logs: ${LOGDIR}/"
}

stop_all() {
    echo -e "${RED}Stopping all AIMMS engines...${NC}"
    for pidfile in "$LOGDIR"/*.pid; do
        if [ -f "$pidfile" ]; then
            pid=$(cat "$pidfile")
            kill "$pid" 2>/dev/null
            rm -f "$pidfile"
        fi
    done
    echo -e "${GREEN}Done.${NC}"
}

case "${1:-start}" in
    stop) stop_all ;;
    *) start_all ;;
esac