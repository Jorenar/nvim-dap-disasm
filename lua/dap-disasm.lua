local M = {}

local dap = require("dap")

local augroup = vim.api.nvim_create_augroup("DapDisasm", { clear = true })

local memref_default = {
  ref = nil,
  before = 16,
  after  = 16,
}

local use_dap_request = false
local dap_request = {
  memoryReference = nil,
  instructionCount = nil,
  instructionOffset = nil,
}

local instructions = {}
local memref = {}

local clear
local mk_winbar
local request
local write_buf

M.step_over = function()
  dap.step_over({granularity = "instruction"})
end
M.step_into = function()
  dap.step_into({granularity = "instruction"})
end
M.step_back = function()
  dap.step_back({granularity = "instruction"})
end

local disasm_buf = {
  _nr = -1,
}

disasm_buf.create = function()
  local buf, extern = disasm_buf.bufnr()
  if extern then
    return buf or -1
  elseif buf and vim.api.nvim_buf_is_valid(buf) then
    return buf
  end

  buf = vim.api.nvim_create_buf(false, true)
  vim.api.nvim_buf_set_name(buf, "DAP Disassembly")
  vim.bo[buf].buftype = "nofile"
  vim.bo[buf].modifiable = false
  vim.bo[buf].filetype = "dap_disassembly"
  vim.bo[buf].syntax = "asm"
  disasm_buf._nr = buf

  vim.api.nvim_create_autocmd("BufWinEnter" , {
      buffer = buf,
      group = augroup,
      callback = function() M.refresh() end
    })

  return buf
end

disasm_buf.bufnr = function()
  return disasm_buf._nr, false
end

M.set_memref = function(ref, before, after)
  if ref then
    if ref == "-1" then
      memref.ref = nil
    else
      memref.ref = ref
    end
  end

  if before then
    local b = tonumber(before)
    if not b then
      vim.notify("Invalid 'before' count: " .. before .. ". Must be a number.", vim.log.levels.WARN)
    elseif b < 0 then
      memref.before = nil
    else
      memref.before = b
    end
  end

  if after then
    local a = tonumber(after)
    if not a then
      vim.notify("Invalid 'after' count: " .. after .. ". Must be a number.", vim.log.levels.WARN)
    elseif a < 0 then
      memref.after = nil
    else
      memref.after = a
    end
  end

  M.refresh()
end

mk_winbar = function(is_active)
  local session = dap.session()
  local running = (session and not session.stopped_thread_id)

  local avail_hl = function(group, allow_running)
    if not session or (not allow_running and running) then
      return is_active and "DapUIUnavailable" or "DapUIUnavailableNC"
    end
    return group
  end

  local hls = {
    step_into = avail_hl(is_active and "DapUIStepInto" or "DapUIStepIntoNC"),
    step_over = avail_hl(is_active and "DapUIStepOver" or "DapUIStepOverNC"),
    step_back = avail_hl(is_active and "DapUIStepBack" or "DapUIStepBackNC"),
  }
  local bar = ""
  for ctrl,label in pairs(M.config.controls) do
    bar = bar .. string.format(
      "  %%#%s#%%0@v:lua.require'dap-disasm'.%s@%s%%#0#",
      hls[ctrl], ctrl, label)
  end
  return bar
end

clear = function()
  instructions = {}
  local buffer, buf_extern = disasm_buf.bufnr()
  if buffer and vim.api.nvim_buf_is_valid(buffer) then
    vim.bo[buffer].modifiable = true
    vim.api.nvim_buf_set_lines(buffer, 0, -1, false, {})
    if not buf_extern then
      local win = vim.fn.bufwinid(buffer)
      if win and vim.api.nvim_win_is_valid(win) and M.config.winbar then
        vim.api.nvim_set_option_value("winbar", "", {
            win = win,
            scope = "local",
          })
      end
    end
  end
end

write_buf = function(pc)
  if not instructions or #instructions == 0 then
    return
  end

  local pc_line = nil

  local fmts = {}
  for _,c in ipairs(M.config.columns) do
    fmts[c] = string.format("%%-%ds", vim.fn.reduce(instructions,
      function(w, ins) return math.max(w, #(ins[c] or "")) end, 0))
  end

  local lines = {}
  for i,ins in ipairs(instructions) do
    if ins.address == pc then
      pc_line = i
    end

    local line = " "
    if fmts.address then
      line = line .. string.format(fmts.address .. ":\t", ins.address)
    end
    if fmts.instructionBytes then
      line = line .. string.format(fmts.instructionBytes .. "\t", ins.instructionBytes or "??")
    end
    if fmts.instruction then
      line = line .. (ins.instruction or "??")
    end
    line = line:gsub("%s+$", "")
    table.insert(lines, line)
  end

  local buf = disasm_buf.bufnr()
  local ma_old = vim.bo[buf].modifiable
  vim.bo[buf].modifiable = true
  vim.api.nvim_buf_set_lines(buf, 0, -1, false, lines)
  vim.bo[buf].modifiable = ma_old

  vim.fn.sign_unplace(M.config.sign, { buffer = buf })
  if pc_line then
    vim.fn.sign_place(0, "DisasmSigns", M.config.sign, buf, {
        lnum = pc_line, priority = 10
      })

    local win = vim.fn.bufwinid(buf)
    if win ~= -1 then
      vim.api.nvim_win_set_cursor(win, { pc_line, 0 })
    end
  end
end

request = function(session, pc, handler)
  local function get_ins_num(param, def)
    local ret = def
    if type(param) == "number" then
      ret = param
    elseif type(param) == "function" then
      ret = param()
    end
    if (not ret) or (type(ret) ~= "number") or (ret < 0) then
      return def
    end
    return ret
  end

  local ins_before = get_ins_num(memref.before, memref_default.before)
  local ins_after = get_ins_num(memref.after, memref_default.after)

  local disassemble_request = {
    memoryReference = memref.ref or pc,
    instructionCount = use_dap_request
        and dap_request.instructionCount
        or ins_before + 1 + ins_after,
    instructionOffset = use_dap_request
        and dap_request.instructionOffset
        or -ins_before,
    resolveSymbols = use_dap_request
        and dap_request.resolveSymbols
        or nil,
  }

  session:request("disassemble", disassemble_request, handler)
end

M.refresh = function()
  local session, current_frame, pc

  local buf, buf_extern = disasm_buf.bufnr()
  local win = vim.fn.bufwinid(buf)
  if not win or not vim.api.nvim_win_is_valid(win) then
    return
  end

  session = dap.session()
  if session then
    current_frame = session.current_frame
    if current_frame then
      pc = current_frame.instructionPointerReference
    end
  else
    return
  end
  if not pc then
    clear()
    return
  end

  request(session, pc, function(err, res)
    if err then
      vim.notify("DAP Disassembly request error: " .. err.message, vim.log.levels.ERROR)
      return
    end

    instructions = res.instructions or {}
    write_buf(pc)
    if M.config.winbar then
      vim.api.nvim_set_option_value("winbar", mk_winbar(), {
          win = win,
          scope = "local",
        })
    end
  end)
end

vim.api.nvim_create_autocmd("FileType" , {
    pattern = "dap_disassembly",
    group = augroup,
    callback = function()
      for _, ev in ipairs({ "scopes" }) do
        dap.listeners.after[ev]["update_disassembly"] = M.refresh
      end

      for _, ev in ipairs({ "disconnect", "event_exited", "event_terminated" }) do
        dap.listeners.after[ev]["update_disassembly"] = clear
      end
    end
  })

vim.api.nvim_create_user_command("DapDisasm", function(t)
  vim.cmd(t.smods.vertical and "vsplit" or "split")
  local win = vim.api.nvim_get_current_win()
  local buf = disasm_buf.create()
  vim.api.nvim_win_set_buf(win, buf)
  M.refresh()
end, {})

vim.api.nvim_create_user_command("DapDisasmSetMemref", function(t)
  local args = {}

  for i = 1, 3 do
    if not t.fargs[i] then
      args[i] = ""
    elseif t.fargs[i] == "-" then
      args[i] = nil
    else
      args[i] = t.fargs[i]
    end
  end

  M.set_memref(args[1], args[2], args[3])
end, { nargs = "*" })

M.config = {
  dapui_register = true,
  dapview_register = true,
  repl_commands = true,
  winbar = true,
  sign = "DapStopped",
  ins_before_memref = nil,
  ins_after_memref = nil,
  controls = {
    step_into = "Step Into",
    step_over = "Step Over",
    step_back = "Step Back",
  },
  columns = {
    "address",
    "instructionBytes",
    "instruction",
  },
}

M.setup = function(conf)
  vim.treesitter.language.register("disassembly", "dap_disassembly")

  M.config = vim.tbl_deep_extend("force", M.config, conf or {})

  if M.config.ins_before_memref then
    memref_default.before = M.config.ins_before_memref
  end
  if M.config.ins_after_memref then
    memref_default.after = M.config.ins_after_memref
  end

  use_dap_request = M.config.use_direct_request or false

  dap_request = use_dap_request
      and vim.tbl_extend("force", dap_request, conf.direct_request or {})
      or dap_request

  if M.config.repl_commands then
    local dap_repl = require("dap.repl")
    dap_repl.commands.custom_commands = vim.tbl_extend('force',
      dap_repl.commands.custom_commands,
      {
        [".nexti"] = M.step_over,
        [".intoi"] = M.step_into,
        [".backi"] = M.step_back,
      })
  end

  if M.config.dapui_register then
    if package.loaded["dapui"] then
      require("dapui").register_element("disassembly", {
          render = M.refresh,
          buffer = disasm_buf.create,
          allow_without_session = false,
        })
    end
  end

  if M.config.dapview_register and package.loaded["dap-view"] then
    -- disable winbar to avoid conflict with dap-view
    M.config.winbar = false
    require("dap-view").register_view("disassembly", {
      action = M.refresh,
      buffer = disasm_buf.create,
      keymap = "D",
      label = "Disassembly [D]",
      -- nerd font icon nf-md-cog
      short_label = "󰒓 [D]",
      filetype = "dap_disassembly",
    })
  end
end

return M
