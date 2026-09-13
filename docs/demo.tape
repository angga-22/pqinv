# Regenerate with: vhs docs/demo.tape
# Requires: vhs, ffmpeg, ttyd, a built ./pqinv binary, and a local
# Keycloak (docker run -d -p 8080:8080 quay.io/keycloak/keycloak start-dev).
#
# NOTE: vhs v0.12.0 has a bug — teardown cancels the context that the
# ffmpeg render step uses, so it silently produces no output (exit 0).
# Until the fix lands upstream, build a patched vhs: clone
# charmbracelet/vhs, and in evaluator.go pass a non-canceled context to
# v.Render() (save `renderCtx := ctx` before the WithCancel line).

Output docs/img/demo.gif

Set Shell bash
Set FontSize 14
Set Width 1240
Set Height 640
Set Padding 16
Set TypingSpeed 55ms

Hide
Type "PS1='$ ' && export PATH=$PWD:$PATH && clear"
Enter
Show

Sleep 800ms
Type "# does this endpoint already speak post-quantum key exchange?"
Enter
Sleep 1s
Type "pqinv scan tls cloudflare.com:443"
Sleep 500ms
Enter
Sleep 9s

Hide
Type "clear"
Enter
Show
Type "# is my Keycloak realm quantum-ready?"
Enter
Sleep 1s
Type "pqinv scan oidc http://localhost:8080/realms/master"
Sleep 500ms
Enter
Sleep 10s

Hide
Type "clear"
Enter
Show
Type "# what crypto does my code actually use?"
Enter
Sleep 1s
Type "pqinv scan repo internal/probe/tlsprobe"
Sleep 500ms
Enter
Sleep 7s

Hide
Type "clear"
Enter
Show
Type "# fail the CI pipeline on harvest-now-decrypt-later exposure"
Enter
Sleep 1s
Type "pqinv scan tls github.com:443 --fail-on high"
Sleep 500ms
Enter
Sleep 8s
Type "echo exit_code=$?"
Sleep 500ms
Enter
Sleep 4s
