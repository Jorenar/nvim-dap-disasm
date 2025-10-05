nvim-dap-disasm
===============

Disassembly view for [nvim-dap](https://github.com/mfussenegger/nvim-dap)

## Installation

Install like any other Neovim plugin:

* `git clone https://github.com/Jorenar/nvim-dap-disasm.git ~/.config/nvim/pack/plugins/start/nvim-dap-disasm`
* or with vim-plug: `Plug 'Jorenar/nvim-dap-disasm'`
* or with packer.nvim: `use 'Jorenar/nvim-dap-disasm'`
* or any other plugin manager.

## Dependencies

* [nvim-dap](https://github.com/mfussenegger/nvim-dap)
* [nvim-dap-ui](https://github.com/rcarriga/nvim-dap-ui) (optional)
* [nvim-dap-view](https://github.com/igorlfs/nvim-dap-view) (optional)

## Configuration

```lua
require("nvim-dap-disasm").setup({
    -- Add disassembly view to elements of nvim-dap-ui
    dapui_register = true,

    -- Add disassembly view to nvim-dap-view
    dapview_register = true,

    -- If registered, pass section configuration to nvim-dap-view
    dapview = {
      keymap = "D",
      label = "Disassembly [D]",
      short_label = "󰒓 [D]",
    },

    -- Add custom REPL commands for stepping with instruction granularity
    repl_commands = true,

    -- Show winbar with buttons to step into the code with instruction granularity
    -- This settings is overriden (disabled) if the dapview integration is enabled and the plugin is installed
    winbar = true,

    -- The sign to use for instruction the exectution is stopped at
    sign = "DapStopped",

    -- Number of instructions to show before the memory reference
    ins_before_memref = 16,

    -- Number of instructions to show after the memory reference
    ins_after_memref = 16,

    -- Labels of buttons in winbar
    controls = {
      step_into = "Step Into",
      step_over = "Step Over",
      step_back = "Step Back",
    },

    -- Columns to display in the disassembly view
    columns = {
      "address",
      "instructionBytes",
      "instruction",
    },
  })
```

If you are using nvim-dap-ui, you can add it to its layouts, e.g.:

```lua
require("nvim-dap-ui").setup({
    layouts = {
      {
        elements = { { id = "disassembly" } },
        position = "bottom",
        size = 0.15,
      },
    }
  })
```

If you are using nvim-dap-view, you can add it as a section, e.g.:

```lua
require("dap-view").setup({
    winbar = {
        sections = {
            "disassembly",
            -- ...
        },
    }
})
```

## Usage

To use the disassembly view, start a debugging session with nvim-dap and open
the disassembly view using `:DapDisasm` command. The disassembly view will
display the instructions at the current execution point.

## Acknowledgements

* The initial code was pulled from [Jorenar/dotfiles](https://github.com/Jorenar/dotfiles)
* Highly inspired by [vimspector](https://github.com/puremourning/vimspector),
  and [prototype for nvim-dap-ui](https://github.com/rcarriga/nvim-dap-ui/pull/309)
  by [@ColinKennedy](https://github.com/ColinKennedy)
