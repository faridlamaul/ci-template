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

def good_block(obj, &block)
  # ok: shipguard.ruby.eval-usage
  obj.instance_eval(&block)
  # ok: shipguard.ruby.eval-usage
  instance_eval(&block)
end
