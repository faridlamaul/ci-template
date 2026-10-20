require "yaml"

def bad(blob, text)
  # ruleid: shipguard.ruby.unsafe-deserialization
  Marshal.load(blob)
  # ruleid: shipguard.ruby.unsafe-deserialization
  YAML.unsafe_load(text)
end

def good(text)
  # ok: shipguard.ruby.unsafe-deserialization
  YAML.safe_load(text)
  # ok: shipguard.ruby.unsafe-deserialization
  JSON.parse(text)
  # ok: shipguard.ruby.unsafe-deserialization
  YAML.load(File.read("config/app.yml"))
end
