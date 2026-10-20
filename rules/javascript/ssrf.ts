import axios from "axios";

export async function bad(req: any) {
  // ruleid: shipguard.javascript.ssrf
  await axios.get(req.query.url);
}

export async function good() {
  // ok: shipguard.javascript.ssrf
  await axios.get("https://api.example.com/health");
}
