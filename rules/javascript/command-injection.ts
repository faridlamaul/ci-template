import * as child_process from "child_process";

export function bad(user: string): void {
  // ruleid: shipguard.javascript.command-injection
  child_process.exec("ls " + user);
}

export function good(user: string): void {
  // ok: shipguard.javascript.command-injection
  child_process.execFile("ls", [user]);
}
