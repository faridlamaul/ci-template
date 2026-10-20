def bad(code, klass)
  # ruleid: shipguard.ruby.eval-usage
  eval(code)
  # ruleid: shipguard.ruby.eval-usage
  klass.class_eval(code)
end

def good(klass)
  # ok: shipguard.ruby.eval-usage
  eval("1 + 1")
  # ok: shipguard.ruby.eval-usage
  klass.class_eval("def hi; end")
end
