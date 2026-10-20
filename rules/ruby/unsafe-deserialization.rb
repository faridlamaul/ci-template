require "yaml"

def bad(blob, text)
  # ruleid: shipguard.ruby.unsafe-deserialization
  Marshal.load(blob)
  # ruleid: shipguard.ruby.unsafe-deserialization
  YAML.load(text)
end

def good(text)
  # ok: shipguard.ruby.unsafe-deserialization
  YAML.safe_load(text)
  # ok: shipguard.ruby.unsafe-deserialization
  JSON.parse(text)
end
