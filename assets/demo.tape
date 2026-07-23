# SkillMOO demo — generates assets/scan-demo.gif
#
# One-time setup:  brew install vhs   (or: https://github.com/charmbracelet/vhs)
# Generate:        vhs assets/demo.tape
#
# Record in a clean environment (a fresh container, or a machine with no skills
# installed) so the scan shows ONLY the bundled example skills — a clean GIF.

Output assets/scan-demo.gif

Set Theme "Aardvark Blue"
Set FontSize 18
Set Width 1200
Set Height 760
Set Padding 24
Set TypingSpeed 60ms

Type "npx skillmoo scan --dir examples/demo-skills --no-share"
Sleep 400ms
Enter
Sleep 4s
