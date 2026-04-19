#!/bin/bash

LOGDIR="./logs"
mkdir -p "$LOGDIR"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

start_all() {
    echo -e "${YELLOW}Starting AIMMS engines...${NC}\n"

    echo -e "${GREEN}[1/5]${NC} Starting Node.js API server..."
    node backend/server.js > "$LOGDIR/api.log" 2>&1 &
    echo $! > "$LOGDIR/api.pid"
    sleep 2

    echo -e "${GREEN}[2/5]${NC} Starting rule engine..."
    node detection/rule_engine.js > "$LOGDIR/rules.log" 2>&1 &
    echo $! > "$LOGDIR/rules.pid"

    echo -e "${GREEN}[3/5]${NC} Starting behavioral profiler..."
    node behavioral-profiling/behavioralProfiler.js > "$LOGDIR/profiler.log" 2>&1 &
    echo $! > "$LOGDIR/profiler.pid"

    echo -e "${GREEN}[4/5]${NC} Starting risk scorer..."
    node risk-scoring/riskScorer.js > "$LOGDIR/scorer.log" 2>&1 &
    echo $! > "$LOGDIR/scorer.pid"

    echo -e "${GREEN}[5/5]${NC} Starting mitigation engine..."
    node mitigation/mitigationEngine.js > "$LOGDIR/mitigation.log" 2>&1 &
    echo $! > "$LOGDIR/mitigation.pid"

    echo -e "${GREEN}[+]${NC} Starting packet sniffer (requires sudo)..."
    sudo venv/bin/python sniffer/sniffer.py > "$LOGDIR/sniffer.log" 2>&1 &
    echo $! > "$LOGDIR/sniffer.pid"

    echo -e "\n${GREEN}All engines started.${NC}"
    echo -e "Logs are in: ${LOGDIR}/"
    echo -e "PIDs stored in: ${LOGDIR}/*.pid"
    echo ""
    echo -e "To watch live logs:"
    echo -e "  tail -f ${LOGDIR}/*.log"
    echo ""
    echo -e "To stop everything:"
    echo -e "  bash start-all.sh stop"
}

stop_all() {
    echo -e "${RED}Stopping all AIMMS engines...${NC}"
    for pidfile in "$LOGDIR"/*.pid; do
        if [ -f "$pidfile" ]; then
            pid=$(cat "$pidfile")
            name=$(basename "$pidfile" .pid)
            if kill -0 "$pid" 2>/dev/null; then
                kill "$pid"
                echo -e "  Stopped ${name} (PID $pid)"
            fi
            rm -f "$pidfile"
        fi
    done
    sudo pkill -f "sniffer.py" 2>/dev/null
    echo -e "${GREEN}Done.${NC}"
}

case "${1:-start}" in
    stop) stop_all ;;
    *)    start_all ;;
esac