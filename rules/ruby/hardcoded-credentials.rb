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
  # ok: shipguard.ruby.hardcoded-credentials
  token_url = "https://auth.example.com/token"
  # ok: shipguard.ruby.hardcoded-credentials
  password_prompt = "Enter your password now"
  # ok: shipguard.ruby.hardcoded-credentials
  secret_name = "db-credentials"
  [db_password, token_header, token_url, password_prompt, secret_name]
end
