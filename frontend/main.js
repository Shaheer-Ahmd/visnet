document.addEventListener('DOMContentLoaded', () => {
    const ADDR = "your.server.address"; // Replace with your server address
    const PORT = 8080; // Replace with your server port
    const transientNodesLabels = new Set(["sh", "grep", "awk", "sed", "cat", "ls", "ps", "top", "df", "du", "find", "kill", "chmod", "chown", "modprobe", "which", "sleep", "cpuUsage.sh"]);

    const EventType = {
        PROCESS_EXEC: 0,
        PROCESS_EXIT: 1,
        CONN_OPEN: 2,
        CONN_CLOSE: 3,
    };

    function intToIP(num) {
        return `${(num >> 24) & 0xFF}.${(num >> 16) & 0xFF}.${(num >> 8) & 0xFF}.${num & 0xFF}`;
    }

    const container = document.getElementById('network-graph');
    const nodes = new vis.DataSet([]);
    const edges = new vis.DataSet([]);
    const data = { nodes: nodes, edges: edges };

    const activeColor = { background: '#805ad5', border: '#9f7aea' };
    const inactiveColor = { background: '#4a5568', border: '#718096' };

    const options = {
        nodes: {
            shape: 'dot',
            size: 18,
            borderWidth: 2,
            font: { color: '#e2e8f0', size: 14, strokeWidth: 0 }
        },
        edges: {
            width: 1.5,
            arrows: 'to',
            color: { color: '#718096', highlight: '#a0aec0', hover: '#a0aec0' },
            smooth: { enabled: true, type: 'dynamic' }
        },
        physics: {
            enabled: true,
            barnesHut: { gravitationalConstant: -8000, centralGravity: 0.3, springLength: 150, springConstant: 0.05, damping: 0.09, avoidOverlap: 0.1 },
            solver: 'barnesHut',
            stabilization: { iterations: 1000 }
        },
        interaction: { hover: true, tooltipDelay: 200, navigationButtons: true, keyboard: true },
    };

    const network = new vis.Network(container, data, options);

function processEvent(event) {
    const pidStr = event.pid.toString();

    if (transientNodesLabels.has(event.comm)) {
        // console.log(`[SKIP] Ignoring transient process: ${event.comm}`);
        return;
    }

    console.log("[EVENT RECEIVED]", event);

    switch (event.type) {
        case EventType.PROCESS_EXEC:
            console.log(`[PROCESS_EXEC] PID: ${pidStr}, Command: ${event.comm}`);
            if (!nodes.get(pidStr)) {
                console.log(`[ADD NODE] New process node added: ${event.comm} (${pidStr})`);
                nodes.add({ id: pidStr, label: `${event.comm}\n(${pidStr})`, color: activeColor, active: true });
            } else {
                console.log(`[SKIP] Node already exists for PID ${pidStr}`);
            }
            break;

        case EventType.PROCESS_EXIT:
            console.log(`[PROCESS_EXIT] PID: ${pidStr}`);
            const exitingNode = nodes.get(pidStr);
            if (exitingNode) {
                console.log(`[UPDATE NODE] Marking process ${pidStr} as inactive`);
                nodes.update({ id: pidStr, color: inactiveColor, active: false });

                const connectedEdges = edges.get({ filter: edge => edge.from === pidStr || edge.to === pidStr });
                console.log(`[UPDATE EDGES] Marking ${connectedEdges.length} connected edges as inactive`);
                connectedEdges.forEach(edge => {
                    edges.update({ id: edge.id, color: inactiveColor.background, active: false });
                });
            } else {
                console.log(`[SKIP] No node found for PID ${pidStr}`);
            }
            break;

        case EventType.CONN_OPEN:
            console.log(`[CONN_OPEN] PID: ${pidStr}, Destination: ${intToIP(event.conn.daddr)}:${event.conn.dport}`);

            if (!nodes.get(pidStr)) {
                console.log(`[ADD NODE] Creating node for process ${event.comm} (${pidStr})`);
                nodes.add({ id: pidStr, label: `${event.comm}\n(${pidStr})`, color: activeColor, active: true });
            }

            const destIP = intToIP(event.conn.daddr);
            const destID = `ip-${destIP}`;
            if (!nodes.get(destID)) {
                console.log(`[ADD NODE] Creating destination IP node: ${destIP}`);
                nodes.add({ id: destID, label: destIP, color: activeColor, active: true });
            }

            const edgeID = `${pidStr}->${destID}:${event.conn.dport}`;
            if (!edges.get(edgeID)) {
                console.log(`[ADD EDGE] Connection from ${pidStr} to ${destID} on port ${event.conn.dport}`);
                edges.add({ id: edgeID, from: pidStr, to: destID, label: event.conn.dport.toString(), color: activeColor.border, active: true });
            } else {
                console.log(`[SKIP] Edge already exists: ${edgeID}`);
            }
            break;

        case EventType.CONN_CLOSE:
            console.log(`[CONN_CLOSE] PID: ${pidStr}, Destination: ${intToIP(event.conn.daddr)}:${event.conn.dport}`);

            const closedDestIP = intToIP(event.conn.daddr);
            const closedDestID = `ip-${closedDestIP}`;
            const closedEdgeID = `${pidStr}->${closedDestID}:${event.conn.dport}`;

            const edgeToClose = edges.get(closedEdgeID);
            if (edgeToClose) {
                console.log(`[UPDATE EDGE] Marking edge as inactive: ${closedEdgeID}`);
                edges.update({ id: closedEdgeID, color: inactiveColor.background, active: false });
            } else {
                console.log(`[SKIP] No edge found to close: ${closedEdgeID}`);
            }
            break;

        default:
            console.log(`[UNHANDLED EVENT TYPE] ${event.type}`);
            break;
    }
}

    document.getElementById('help-btn').addEventListener('click', () => {
    alert(
        "This application visualizes real-time Linux processes and their TCP network activity using eBPF.\n\n" +
        "- Each process is shown as a circular node labeled with its command name and PID.\n" +
        "- Remote destination IPs are also represented as nodes.\n" +
        "- Arrows represent outgoing TCP connections from processes to destination IPs, labeled with the destination port.\n\n" +
        "Color Legend:\n" +
        "🟣 Purple nodes and edges = Active processes or open connections.\n" +
        "⚫ Grey nodes and edges = Inactive processes or closed connections.\n\n" +
        "- Use the 'Cleanup Inactive Nodes' button to remove all inactive items and reduce clutter."
    );
});


    document.getElementById('cleanup-btn').addEventListener('click', () => {
        const inactiveEdges = edges.get({ filter: item => item.active === false });
        const inactiveNodes = nodes.get({ filter: item => item.active === false });

        if (inactiveEdges.length > 0) {
            edges.remove(inactiveEdges.map(e => e.id));
        }
        if (inactiveNodes.length > 0) {
            nodes.remove(inactiveNodes.map(n => n.id));
        }

        // Final cleanup: remove any IP nodes that now have no connections
        const ipNodes = nodes.get({ filter: item => item.id.startsWith('ip-') });
        const allEdges = edges.get();
        const connectedIpNodes = new Set();
        allEdges.forEach(edge => {
            if (nodes.get(edge.to)?.id.startsWith('ip-')) {
                connectedIpNodes.add(edge.to);
            }
        });
        
        const nodesToRemove = ipNodes.filter(node => !connectedIpNodes.has(node.id));
        if (nodesToRemove.length > 0) {
            nodes.remove(nodesToRemove.map(n => n.id));
        }
    });

    const socket = new WebSocket(`ws://${ADDR}:${PORT}/ws`); 
    socket.onopen = () => console.log('WebSocket connection established.');
    socket.onclose = () => console.log('WebSocket connection closed.');
    socket.onerror = (error) => console.error('WebSocket error:', error);

    socket.onmessage = (message) => {
        try {
            const event = JSON.parse(message.data);
            processEvent(event);
        } catch (e) {
            console.error('Error processing message:', e, 'Message was:', message.data);
        }
    };

    network.on('click', (properties) => {
        const { nodes: nodeIds } = properties;
        if (nodeIds.length > 0) {
            const clickedNode = nodes.get(nodeIds[0]);
            alert(`Node Details:\nID: ${clickedNode.id}\nLabel: ${clickedNode.label}`);
        }
    });
});