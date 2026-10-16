# Records img/demo.gif, the dashboard at the top of the README, with VHS
# (https://github.com/charmbracelet/vhs). From the repository root:
#
#   brew install vhs
#   cargo build --release
#   vhs img/demo.tape
#
# It checks real public hosts (badssl.com keeps expired, wrong-host and
# self-signed certificates up on purpose), so re-record it when the dashboard
# changes rather than editing the GIF.

Output img/demo.gif

Set Shell "bash"
Set FontSize 15
Set Width 1200
Set Height 640
Set Padding 12
Set Framerate 24
Set TypingSpeed 35ms

# Record the local build, not whatever tlschecker is installed.
Hide
Type "export PATH=$PWD/target/release:$PATH && clear"
Enter
Show

Type "tlschecker google.com github.com jpbd.dev expired.badssl.com wrong.host.badssl.com self-signed.badssl.com"
Sleep 400ms
Enter
Sleep 5s

# Walk the fleet list: each host's detail pane follows the selection.
Down
Sleep 1.5s
Down
Sleep 1.5s
Down
Sleep 2s
Down
Sleep 2s

# Open the certificate explorer, scroll, and come back.
Enter
Sleep 2s
Down 8
Sleep 1.5s
PageDown
Sleep 2s
Escape
Sleep 1.5s

Type "q"
Sleep 500ms
