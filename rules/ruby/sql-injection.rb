def bad(name)
  # ruleid: shipguard.ruby.sql-injection
  User.where("name = '#{name}'")
  # ruleid: shipguard.ruby.sql-injection
  User.find_by_sql("SELECT * FROM users WHERE name = '" + name + "'")
  # ruleid: shipguard.ruby.sql-injection
  ActiveRecord::Base.connection.execute("DELETE FROM users WHERE name = '#{name}'")
end

def bad_two_step(conn, name)
  sql = "DELETE FROM users WHERE name = '#{name}'"
  # ruleid: shipguard.ruby.sql-injection
  conn.execute(sql)
end

def good(name)
  # ok: shipguard.ruby.sql-injection
  User.where("name = ?", name)
  # ok: shipguard.ruby.sql-injection
  User.where(name: name)
end
