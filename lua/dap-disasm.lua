local M = {}

local dap = require("dap")

local disasm_bufnr = -1
local req_defaults = {
  address = "pc",
  before = 16,
  after  = 16,
}

local function get_disasm_bufnr()
  if not disasm_bufnr or not vim.api.nvim_buf_is_valid(disasm_bufnr) then
    disasm_bufnr = vim.api.nvim_create_buf(false, true)
    vim.api.nvim_buf_set_name(disasm_bufnr, "DAP Disassembly")
    vim.bo[disasm_bufnr].buftype = "nofile"
    vim.bo[disasm_bufnr].filetype = "dap_disassembly"
    vim.bo[disasm_bufnr].syntax = "asm"
  end

  return disasm_bufnr
end

local function write_buf(instructions, pc, jump_to_pc, cursor_offset)
  jump_to_pc = (jump_to_pc == nil) or jump_to_pc
  cursor_offset = cursor_offset or 0

  local lines = {}
  local pc_line = nil

  if #instructions > 0 then
    table.insert(lines, " ...")
    for i, instruction in ipairs(instructions) do
      local line = string.format(" %s:\t%s",
        instruction.address or "N/A",
        instruction.instruction or "N/A")
      table.insert(lines, line)
      if instruction.address == pc then
        pc_line = i+1  -- "+1" to account for "..." line
      end
    end
    table.insert(lines, " ...")
  end

  local buffer = get_disasm_bufnr()
  vim.api.nvim_buf_set_lines(buffer, 0, -1, false, lines)

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
  if req_defaults.address ~= "pc" then
    memref = req_defaults.address
  end

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
    write_buf({}, pc)
    return
  end

  request(session, pc, function(err, res)
    if err then return end
    write_buf(res.instructions or {}, pc, jump_to_pc, cursor_offset)
  end)
end

vim.api.nvim_create_autocmd("FileType" , {
    pattern = "dap_disassembly",
    callback = function(p)
      for _, ev in ipairs({ "scopes" }) do
        dap.listeners.after[ev]["update_disassembly"] = render
      end

      local buf = p.buf
      for _, ev in ipairs({ "disconnect", "event_exited", "event_terminated" }) do
        dap.listeners.after[ev]["update_disassembly"] = function()
          vim.api.nvim_buf_set_lines(buf, 0, -1, false, {})
        end
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
  sign = "DapStopped",
  ins_before_memref = req_defaults.before,
  ins_after_memref = req_defaults.after,
  -- columns = {
  --   "address",
  --   "instruction",
  -- },
}

M.setup = function(conf)
  M.config = vim.tbl_deep_extend("force", M.config, conf or {})

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
