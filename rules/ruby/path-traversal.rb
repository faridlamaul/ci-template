def bad
  name = params[:file]
  # ruleid: shipguard.ruby.path-traversal
  File.read(File.join("/srv/data", name))
  # ruleid: shipguard.ruby.path-traversal
  send_file(params[:path])
end

def good
  name = File.basename(params[:file])
  # ok: shipguard.ruby.path-traversal
  File.read(File.join("/srv/data", name))
  # ok: shipguard.ruby.path-traversal
  File.read("/etc/hostname")
end
