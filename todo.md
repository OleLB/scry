# Searchable secrets

There should be a serchbar in the JS secrets section of the report
The search would match the "pattern" column presented on the report page
ex:
if i search "possible"
  entries of type "possible_creds" would show
  entries of type "json_web_token" (not matchig) would be filtered away
  Each entry should have a button to diplay the full snippet directly in the report.


# Live hosts report error

The live hosts section looks like:
URL	Status	Title	Server	Size
https://kobold.htb 	0 	Kobold Operations Suite 	- 	-
https://mcp.kobold.htb 	0 	MCPJam Inspector 	- 	-
https://bin.kobold.htb 	0 	PrivateBin 	- 	-

Problems:
- The status for all are 0 (should probably be 200, def not 0)
- Server is empty
- Size is empty