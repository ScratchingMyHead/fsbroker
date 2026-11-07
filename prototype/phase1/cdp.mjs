// Minimal CDP client for the Phase 1 prototype.
// Usage: node cdp.mjs <ws-url> '<javascript expression>'
const [, , wsUrl, expr] = process.argv;
if (!wsUrl || !expr) {
  console.error("usage: node cdp.mjs <ws-url> '<expression>'");
  process.exit(2);
}

const ws = new WebSocket(wsUrl);
const id = 1;
const timer = setTimeout(() => {
  console.error("CDP timeout");
  process.exit(3);
}, 15000);

ws.addEventListener("open", () => {
  ws.send(JSON.stringify({
    id,
    method: "Runtime.evaluate",
    params: {
      expression: expr,
      returnByValue: true,
      awaitPromise: true,
      userGesture: true,
    },
  }));
});

ws.addEventListener("message", (event) => {
  const msg = JSON.parse(event.data);
  if (msg.id !== id) return;
  clearTimeout(timer);
  if (msg.result?.exceptionDetails) {
    console.error(JSON.stringify(msg.result.exceptionDetails, null, 2));
    process.exitCode = 1;
  } else {
    const value = msg.result?.result?.value;
    console.log(typeof value === "string" ? value : JSON.stringify(value, null, 2));
  }
  ws.close();
});

ws.addEventListener("error", (event) => {
  clearTimeout(timer);
  console.error("CDP error", event.message);
  process.exit(4);
});
