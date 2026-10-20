require "net/http"
require "openssl"

def bad(http)
  # ruleid: shipguard.ruby.tls-verify-disabled
  http.verify_mode = OpenSSL::SSL::VERIFY_NONE
  # ruleid: shipguard.ruby.tls-verify-disabled
  RestClient::Request.execute(method: :get, url: "https://example.com", verify_ssl: false)
  # ruleid: shipguard.ruby.tls-verify-disabled
  Net::HTTP.start("example.com", 443, use_ssl: true, verify_mode: OpenSSL::SSL::VERIFY_NONE)
end

def good(http, mode)
  # ok: shipguard.ruby.tls-verify-disabled
  raise "insecure" if mode == OpenSSL::SSL::VERIFY_NONE
  # ok: shipguard.ruby.tls-verify-disabled
  http.verify_mode = OpenSSL::SSL::VERIFY_PEER
end
