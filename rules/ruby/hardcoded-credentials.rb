def bad
  # ruleid: shipguard.ruby.hardcoded-credentials
  db_password = "changeme-not-a-secret"
  # ruleid: shipguard.ruby.hardcoded-credentials
  connect(host: "db", password: "changeme-not-a-secret")
  db_password
end

def good
  # ok: shipguard.ruby.hardcoded-credentials
  db_password = ENV["DB_PASSWORD"]
  # ok: shipguard.ruby.hardcoded-credentials
  token_header = ""
  [db_password, token_header]
end
