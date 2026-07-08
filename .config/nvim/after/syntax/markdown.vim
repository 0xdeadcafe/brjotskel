if exists("b:current_syntax")
  syntax include @YamlFrontmatter syntax/yaml.vim
  unlet b:current_syntax
endif

syntax region markdownFrontmatterDelimiter start=/\%^---\s*$/ end=/^---\s*$/ keepend contains=NONE
syntax region markdownYamlFrontmatter start=/\%^---\s*$/ end=/^---\s*$/ keepend contains=@YamlFrontmatter,markdownFrontmatterDelimiter

hi def link markdownFrontmatterDelimiter Delimiter

let b:current_syntax = "markdown"
