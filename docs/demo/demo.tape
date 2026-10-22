# Records docs/assets/demo.gif.
# Run from the repository root: make demo
# (builds the shipguard:demo image, then runs vhs docs/demo/demo.tape; needs Docker)

Output docs/assets/demo.gif

Require docker
Require git

Set Shell "bash"
Set FontSize 16
Set Width 1200
Set Height 560
Set Padding 24
Set Theme "Catppuccin Mocha"
Set TypingSpeed 45ms
Set WindowBar Colorful
Set BorderRadius 10

Hide
# Runs the real CLI from the scanner image against a vulnerable fixture.
# The wrapper drops stderr (the Markdown summary already says FAIL) and trims long lines.
Type `shipguard() { docker run --rm -v "$PWD:/repo" -w /repo shipguard:demo "$@" 2>/dev/null | cut -c1-110; }; PS1='\[\e[38;5;147m\]$\[\e[0m\] '` Enter
Type "rm -rf /tmp/shipguard-demo && cp -R testdata/fixtures/python /tmp/shipguard-demo && cd /tmp/shipguard-demo && git init -q && clear" Enter
Sleep 1s
Show

Type "shipguard version" Sleep 400ms Enter
Sleep 2s

Type "shipguard ci detect" Sleep 400ms Enter
Sleep 3s

Type "clear" Enter
Type "shipguard run" Sleep 400ms Enter
Sleep 12s
Sleep 4s
