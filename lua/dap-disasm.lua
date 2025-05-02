local M = {}

local dap = require("dap")

local req_defaults = {
  address = "pc",
  before = 16,
  after  = 16,
}

local disasm_bufnr = -1
local instructions = {}

M.step_over = function()
  dap.step_over({granularity = "instruction"})
end
M.step_into = function()
  dap.step_into({granularity = "instruction"})
end
M.step_back = function()
  dap.step_back({granularity = "instruction"})
end

local function get_disasm_bufnr()
  if not disasm_bufnr or not vim.api.nvim_buf_is_valid(disasm_bufnr) then
    disasm_bufnr = vim.api.nvim_create_buf(false, true)
    vim.api.nvim_buf_set_name(disasm_bufnr, "DAP Disassembly")
    vim.bo[disasm_bufnr].buftype = "nofile"
    vim.bo[disasm_bufnr].modifiable = false
    vim.bo[disasm_bufnr].filetype = "dap_disassembly"
    vim.bo[disasm_bufnr].syntax = "asm"
  end

  return disasm_bufnr
end

local function clear()
  instructions = {}
  if disasm_bufnr and vim.api.nvim_buf_is_valid(disasm_bufnr) then
    vim.bo[disasm_bufnr].modifiable = true
    vim.api.nvim_buf_set_lines(disasm_bufnr, 0, -1, false, {})
  end
end

local function write_buf(pc, jump_to_pc, cursor_offset)
  if not instructions or #instructions == 0 then
    return
  end

  jump_to_pc = (jump_to_pc == nil) or jump_to_pc
  cursor_offset = cursor_offset or 0

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
      line = line .. string.format(fmts.instruction, ins.instruction or "??")
    end
    table.insert(lines, line)
  end

  local buffer = get_disasm_bufnr()
  vim.bo[buffer].modifiable = true
  vim.api.nvim_buf_set_lines(buffer, 0, -1, false, lines)
  vim.bo[buffer].modifiable = false

  vim.fn.sign_unplace(M.config.sign, { buffer = buffer })
  if pc_line then
    vim.fn.sign_place(0, "DisasmSigns", M.config.sign, buffer, {
        lnum = pc_line, priority = 10
      })

    local win = vim.fn.bufwinid(buffer)
    if win ~= -1 then
      pc_line = jump_to_pc and pc_line or vim.fn.line(".", win)
      pc_line = pc_line + cursor_offset
      vim.api.nvim_win_set_cursor(win, { pc_line, 0 })
    end
  end
end

local function request(session, pc, handler)
  local memref = pc

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

  local ins_before = get_ins_num(M.config.ins_before_memref, req_defaults.before)
  local ins_after = get_ins_num(M.config.ins_after_memref, req_defaults.after)

  session:request("disassemble", {
      memoryReference = memref,
      instructionCount = ins_before + 1 + ins_after,
      instructionOffset = -ins_before,
      resolveSymbols = true,
    }, handler)
end

local function render(jump_to_pc, cursor_offset)
  local session, current_frame, pc

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
    if err then return end
    instructions = res.instructions or {}
    write_buf(pc, jump_to_pc, cursor_offset)
  end)
end

vim.api.nvim_create_autocmd("FileType" , {
    pattern = "dap_disassembly",
    callback = function()
      for _, ev in ipairs({ "scopes" }) do
        dap.listeners.after[ev]["update_disassembly"] = render
      end

      for _, ev in ipairs({ "disconnect", "event_exited", "event_terminated" }) do
        dap.listeners.after[ev]["update_disassembly"] = clear
      end
    end
  })

vim.api.nvim_create_user_command("DapDisasm", function(t)
  vim.cmd(t.smods.vertical and "vsplit" or "split")
  local win = vim.api.nvim_get_current_win()
  local buf = get_disasm_bufnr()
  vim.api.nvim_win_set_buf(win, buf)
  render()
end, {})

M.config = {
  dapui_register = true,
  repl_commands = true,
  sign = "DapStopped",
  ins_before_memref = req_defaults.before,
  ins_after_memref = req_defaults.after,
  columns = {
    "address",
    "instructionBytes",
    "instruction",
  },
}

M.setup = function(conf)
  M.config = vim.tbl_deep_extend("force", M.config, conf or {})

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
          render = render,
          buffer = get_disasm_bufnr,
          allow_without_session = false,
        })
    end
  end
end

return M
