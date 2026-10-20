require "net/http"

def bad
  target = params[:url]
  # ruleid: shipguard.ruby.ssrf
  Net::HTTP.get(URI(target))
  # ruleid: shipguard.ruby.ssrf
  HTTParty.get(params[:callback])
end

def good
  # ok: shipguard.ruby.ssrf
  Net::HTTP.get(URI("https://api.example.com/health"))
end
