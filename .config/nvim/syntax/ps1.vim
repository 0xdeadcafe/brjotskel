if exists("b:current_syntax")
  finish
endif

syn case ignore

syn keyword ps1Conditional if else elseif switch default return break continue trap throw try catch finally
syn keyword ps1Repeat foreach for while do until in
syn keyword ps1Boolean $true $false $null
syn keyword ps1Builtin function filter param begin process end dynamicparam class enum configuration
syn keyword ps1Cmdlet Get Set New Add Remove Clear Write Read Invoke Start Stop Restart Test Export Import ConvertTo ConvertFrom Enable Disable Register Unregister Out Select Where ForEach Measure Sort Group Format Join Split Compare Copy Move Rename Push Pop

syn match ps1Variable /\$[A-Za-z_][A-Za-z0-9_:]*/
syn match ps1Scope /\<[A-Za-z_][A-Za-z0-9_]*:/
syn match ps1Parameter /-[A-Za-z_][A-Za-z0-9_-]*/
syn match ps1Number /\<\d\+\>/
syn match ps1Comment /#.*/
syn match ps1Operator /[-+*=<>!]\|[-+*/%]=\|::\|\.\./

syn region ps1String start=+'+ skip=+\\'+ end=+'+
syn region ps1String start=+"+ skip=+\\"+ end=+"+
syn region ps1HereString start=+@"$+ end=+"@+$ keepend
syn region ps1HereString start=+@'$+ end=+'@+$ keepend

hi def link ps1Conditional Conditional
hi def link ps1Repeat Repeat
hi def link ps1Boolean Boolean
hi def link ps1Builtin Keyword
hi def link ps1Cmdlet Function
hi def link ps1Variable Identifier
hi def link ps1Scope Type
hi def link ps1Parameter Special
hi def link ps1Number Number
hi def link ps1Comment Comment
hi def link ps1Operator Operator
hi def link ps1String String
hi def link ps1HereString String

let b:current_syntax = "ps1"
