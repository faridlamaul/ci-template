require "yaml"

def bad
  # ruleid: shipguard.ruby.unsafe-deserialization-request
  Marshal.load(params[:blob])
  body = request.body.read
  # ruleid: shipguard.ruby.unsafe-deserialization-request
  YAML.unsafe_load(body)
  # ruleid: shipguard.ruby.unsafe-deserialization-request
  Marshal.load(Base64.decode64(cookies[:session]))
end

def good
  # ok: shipguard.ruby.unsafe-deserialization-request
  Marshal.load(File.binread("cache.bin"))
  # ok: shipguard.ruby.unsafe-deserialization-request
  YAML.safe_load(request.body.read)
  # ok: shipguard.ruby.unsafe-deserialization-request
  JSON.parse(params[:blob])
end
