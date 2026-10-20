require "open3"

def bad(user)
  # ruleid: shipguard.ruby.command-injection
  system("ls #{user}")
  # ruleid: shipguard.ruby.command-injection
  `cat #{user}`
  # ruleid: shipguard.ruby.command-injection
  IO.popen("grep #{user} /var/log/app.log")
end

def good(user)
  # ok: shipguard.ruby.command-injection
  system("ls", user)
  # ok: shipguard.ruby.command-injection
  system("ls -l")
end
