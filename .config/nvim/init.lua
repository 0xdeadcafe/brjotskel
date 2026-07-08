vim.opt.termguicolors = true
vim.opt.number = true
vim.opt.relativenumber = false

vim.cmd("syntax enable")
vim.cmd("filetype plugin indent on")

vim.filetype.add({
  extension = {
    ps1 = "ps1",
    psm1 = "ps1",
    psd1 = "ps1",
    md = "markdown",
    markdown = "markdown",
    sh = "sh",
    bash = "sh",
  },
  filename = {
    [".bashrc"] = "sh",
    [".bash_profile"] = "sh",
    [".profile"] = "sh",
    [".zshrc"] = "sh",
    [".zprofile"] = "sh",
    [".zlogin"] = "sh",
  },
})

vim.api.nvim_create_autocmd({ "BufRead", "BufNewFile" }, {
  pattern = { "*.md", "*.markdown" },
  callback = function()
    vim.b.markdown_fenced_languages = {
      "sh",
      "bash=sh",
      "powershell=ps1",
      "pwsh=ps1",
      "ps1=ps1",
      "lua",
      "yaml",
    }
  end,
})
