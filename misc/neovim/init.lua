-- General Settings
vim.o.number = true                  -- Show line numbers
vim.o.relativenumber = true          -- Relative line numbers
vim.o.tabstop = 4                    -- Tab size
vim.o.shiftwidth = 4                 -- Indentation
vim.o.expandtab = true               -- Use spaces instead of tabs
vim.o.cursorline = true              -- Highlight current line
vim.o.termguicolors = true           -- Enable true color support
vim.o.clipboard = "unnamedplus"      -- System clipboard integration
vim.o.scrolloff = 8                  -- Keep 8 lines visible around the cursor

-- Leader Key
vim.g.mapleader = " "

-- Plugin Manager (Packer)
local ensure_packer = function()
    local fn = vim.fn
    local install_path = fn.stdpath('data') .. '/site/pack/packer/start/packer.nvim'
    if fn.empty(fn.glob(install_path)) > 0 then
        fn.system({ 'git', 'clone', '--depth', '1', 'https://github.com/wbthomason/packer.nvim', install_path })
        vim.cmd [[packadd packer.nvim]]
        return true
    end
    return false
end
local packer_bootstrap = ensure_packer()

require('packer').startup(function(use)
    use 'wbthomason/packer.nvim'         -- Plugin manager
    use 'kyazdani42/nvim-tree.lua'       -- File explorer
    use 'nvim-telescope/telescope.nvim'  -- Fuzzy finder
    use 'nvim-lua/plenary.nvim'          -- Dependency for Telescope
    use 'nvim-treesitter/nvim-treesitter' -- Syntax highlighting
    use 'morhetz/gruvbox'               -- Gruvbox theme
    use 'folke/which-key.nvim'          -- Dynamic cheat sheet (which-key)
    use 'kyazdani42/nvim-web-devicons'  -- Icon support
    use 'echasnovski/mini.icons'        -- Additional icon support
    use {
        'nvim-lualine/lualine.nvim',
        requires = { 'nvim-tree/nvim-web-devicons', opt = true }
    }

    -- Autocompletion setup
    use 'hrsh7th/nvim-cmp'              -- Autocompletion plugin
    use 'hrsh7th/cmp-nvim-lsp'          -- LSP source for nvim-cmp
    use 'hrsh7th/cmp-buffer'            -- Buffer source for nvim-cmp
    use 'hrsh7th/cmp-path'              -- Path source for nvim-cmp
    use 'hrsh7th/cmp-cmdline'           -- Cmdline source for nvim-cmp
    use 'saadparwaiz1/cmp_luasnip'      -- Luasnip source for nvim-cmp
    use 'L3MON4D3/LuaSnip'              -- Snippet engine for nvim-cmp

    if packer_bootstrap then
        require('packer').sync()
    end
end)

-- Theme
vim.cmd [[colorscheme gruvbox]]

-- Treesitter Setup
require'nvim-treesitter.configs'.setup {
    ensure_installed = { "python", "javascript", "html", "css", "php", "bash", "markdown" },
    highlight = { enable = true },
}

-- Which-Key Setup
require("which-key").setup {}

-- Lualine Powerline Configuration
require('lualine').setup {
    options = {
        icons_enabled = true,                  -- Enable icons
        theme = 'gruvbox',                     -- Theme for the statusline
        section_separators = { left = '', right = '' }, -- Section separators (Powerline style)
        component_separators = { left = '', right = '' }, -- Component separators (Powerline style)
        globalstatus = true                    -- Use global statusline
    },
    sections = {
        lualine_a = { 'mode' },                -- Display Vim mode (e.g., NORMAL, INSERT)
        lualine_b = { 'branch', 'diff', 'diagnostics' }, -- Display Git branch, diff status, and diagnostics
        lualine_c = { 'filename' },            -- Display current file name
        lualine_x = { 'encoding', 'fileformat', 'filetype' }, -- Display file encoding, format, and type
        lualine_y = { 'progress' },            -- Display progress percentage
        lualine_z = { 'location' }             -- Display line and column location
    },
    extensions = { 'nvim-tree', 'quickfix' }  -- Extensions for nvim-tree (file explorer) and quickfix
}

-- Autocompletion (nvim-cmp) Setup
local cmp = require('cmp')
local luasnip = require('luasnip')

cmp.setup({
    snippet = {
        expand = function(args)
            luasnip.lsp_expand(args.body)  -- For `luasnip` users.
        end,
    },
    mapping = cmp.mapping.preset.insert({
        ['<C-b>'] = cmp.mapping.scroll_docs(-4),
        ['<C-f>'] = cmp.mapping.scroll_docs(4),
        ['<C-Space>'] = cmp.mapping.complete(),
        ['<C-e>'] = cmp.mapping.close(),
        ['<CR>'] = cmp.mapping.confirm({ select = true }),
    }),
    sources = cmp.config.sources({
        { name = 'nvim_lsp' },        -- LSP completion
        { name = 'luasnip' },         -- Snippet completion
        { name = 'buffer' },          -- Buffer completion
        { name = 'path' },            -- Path completion
    }),
})

-- Enable completion for command mode
cmp.setup.cmdline(':', {
    sources = {
        { name = 'cmdline' },
    },
})

-- Enable completion for insert mode in buffer
cmp.setup.buffer({
    sources = {
        { name = 'buffer' },
    },
})

-- Updated Keybinding Registration
local wk = require("which-key")

wk.add({
    { "<leader>w", ":w<CR>", desc = "Save File" },
    { "<leader>q", ":q<CR>", desc = "Quit Neovim" },
    { "<leader>e", ":NvimTreeToggle<CR>", desc = "Toggle File Explorer (nvim-tree)" },
    { "<leader>f", ":Telescope find_files<CR>", desc = "Find File (Telescope)" },
    { "<leader>g", ":Telescope live_grep<CR>", desc = "Search Text (Telescope)" },
    { "<leader>t", ":terminal<CR>", desc = "Open Terminal" },
    { "<leader>=", "<C-w>=", desc = "Equalize Split Sizes" },
    { "<leader>+", ":resize +5<CR>", desc = "Increase Split Height" },
    { "<leader>-", ":resize -5<CR>", desc = "Decrease Split Height" },
    { "<leader><", ":vertical resize -5<CR>", desc = "Decrease Split Width" },
    { "<leader>>", ":vertical resize +5<CR>", desc = "Increase Split Width" },
})
