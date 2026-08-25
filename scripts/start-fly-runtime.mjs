import { spawn } from "node:child_process";

const children = new Map();
let stopping = false;

function start(name, command, args) {
  const child = spawn(command, args, {
    env: process.env,
    stdio: "inherit",
  });
  children.set(name, child);
  child.once("exit", (code, signal) => {
    children.delete(name);
    if (stopping) return;
    stopping = true;
    console.error(`PAYO ${name} exited unexpectedly (${signal ?? code ?? "unknown"}).`);
    for (const sibling of children.values()) sibling.kill("SIGTERM");
    process.exitCode = code && code !== 0 ? code : 1;
  });
  child.once("error", (error) => {
    console.error(`PAYO ${name} failed to start: ${error.message}`);
  });
}

function stop(signal) {
  if (stopping) return;
  stopping = true;
  for (const child of children.values()) child.kill(signal);
  const deadline = setTimeout(() => {
    for (const child of children.values()) child.kill("SIGKILL");
  }, 10_000);
  deadline.unref();
}

process.once("SIGINT", () => stop("SIGINT"));
process.once("SIGTERM", () => stop("SIGTERM"));

start("web", "npm", ["start"]);
start("workers", process.execPath, ["scripts/run-phase2-workers.mjs"]);

await new Promise((resolve) => {
  const interval = setInterval(() => {
    if (children.size === 0) {
      clearInterval(interval);
      resolve();
    }
  }, 250);
  interval.unref();
});
