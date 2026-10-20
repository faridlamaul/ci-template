require "net/http"
require "openssl"

def bad(http)
  # ruleid: shipguard.ruby.tls-verify-disabled
  http.verify_mode = OpenSSL::SSL::VERIFY_NONE
  # ruleid: shipguard.ruby.tls-verify-disabled
  RestClient::Request.execute(method: :get, url: "https://example.com", verify_ssl: false)
end

def good(http)
  # ok: shipguard.ruby.tls-verify-disabled
  http.verify_mode = OpenSSL::SSL::VERIFY_PEER
end
