import { spawnSync } from "node:child_process";

const isWindows = process.platform === "win32";
const command = isWindows ? "cmd.exe" : "npx";
const args = isWindows
  ? ["/d", "/s", "/c", "npx playwright install chromium"]
  : ["playwright", "install", "chromium"];

const result = spawnSync(command, args, {
  env: {
    ...process.env,
    PLAYWRIGHT_BROWSERS_PATH: "0"
  },
  stdio: "inherit"
});

if (result.error) {
  console.error(result.error.message);
}

process.exit(result.status ?? 1);
