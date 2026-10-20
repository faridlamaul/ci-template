require "digest"
require "openssl"

def bad(data)
  # ruleid: shipguard.ruby.weak-crypto
  Digest::MD5.hexdigest(data)
  # ruleid: shipguard.ruby.weak-crypto
  Digest::SHA1.hexdigest(data)
  # ruleid: shipguard.ruby.weak-crypto
  OpenSSL::Cipher.new("RC4")
end

def good(data)
  # ok: shipguard.ruby.weak-crypto
  Digest::SHA256.hexdigest(data)
end
