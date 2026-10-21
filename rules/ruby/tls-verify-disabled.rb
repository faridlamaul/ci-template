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

def bad_nested(url)
  # ruleid: shipguard.ruby.tls-verify-disabled
  Faraday.new(url, ssl: { verify: false })
  # ruleid: shipguard.ruby.tls-verify-disabled
  Faraday.new(url: url, ssl: { ca_file: "/etc/ca.pem", verify: false })
  # ruleid: shipguard.ruby.tls-verify-disabled
  Faraday.new(url: url, ssl: { verify_mode: OpenSSL::SSL::VERIFY_NONE })
  # ruleid: shipguard.ruby.tls-verify-disabled
  Faraday.new(url, ssl: { client_cert: cert, verify_mode: OpenSSL::SSL::VERIFY_NONE }) do |f|
    f.adapter :net_http
  end
  # ruleid: shipguard.ruby.tls-verify-disabled
  Net::HTTP.start("example.com", 443, ssl: { verify_mode: OpenSSL::SSL::VERIFY_NONE })
  # ruleid: shipguard.ruby.tls-verify-disabled
  Faraday::Connection.new(url, :ssl => { :verify => false })
end

def good_nested(url)
  # ok: shipguard.ruby.tls-verify-disabled
  Faraday.new(url, ssl: { verify: true })
  # ok: shipguard.ruby.tls-verify-disabled
  Faraday.new(url: url, ssl: { ca_file: "/etc/ca.pem", verify_mode: OpenSSL::SSL::VERIFY_PEER })
  # ok: shipguard.ruby.tls-verify-disabled
  Faraday.new(url, ssl: { verify: false_positive_guard? })
  # ok: shipguard.ruby.tls-verify-disabled
  Faraday.new(url, request: { verify: false })
end
