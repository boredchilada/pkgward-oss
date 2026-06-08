// The agent's bash tool: the user runs the CLI, the LLM proposes a shell
// command, the agent executes it. This is the advertised function of an AI
// coding agent (opencode / aider / Claude Code), driven by an interactive
// tool-call loop — NOT a fetch-then-run supply-chain dropper. The command does
// not originate from a network response.
import { spawn } from "node:child_process";

export function handleBash(command, onOutput) {
  const proc = spawn("sh", ["-c", command], { stdio: ["ignore", "pipe", "pipe"] });
  proc.stdout.on("data", (d) => onOutput(d.toString()));
  proc.stderr.on("data", (d) => onOutput(d.toString()));
  return new Promise((resolve) => proc.on("close", (code) => resolve(code)));
}
