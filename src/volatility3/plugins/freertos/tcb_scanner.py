"""
tcb_scanner.py
Deploy to: /opt/volatility3/volatility3/plugins/freertos/tcb_scanner.py

Volatility 3 plugin: FreeRTOS Task Control Block (TCB) scanner.
Targets FreeRTOS v10.x on ARM Cortex-M (M0, M3, M4, M33).
First published plugin for this RTOS class — SemBridge paper contribution.

TCB_t layout (ARM Cortex-M, FreeRTOS v10.4.x):
  +0x00: pxTopOfStack    (StackType_t* — must be in SRAM range)
  +0x04: xStateListItem  (ListItem_t)
  +0x28: xEventListItem  (ListItem_t)
  +0x40: uxPriority      (UBaseType_t — must be <= 32)
  +0x44: pxStack         (StackType_t*)
  +0x48: pcTaskName[16]  (char[16] — printable ASCII, null-terminated, 1-15 chars)
"""

from volatility3.framework import interfaces, renderers, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
import struct


class FreeRTOSTCBScanner(interfaces.plugins.PluginInterface):
    """
    Scans raw memory for FreeRTOS Task Control Block structures.
    Targets FreeRTOS v10.x on ARM Cortex-M (M0, M3, M4, M33).
    """

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    # ARM Cortex-M SRAM address range (adjust for specific SoC if needed)
    CORTEX_M_SRAM_BASE = 0x20000000
    CORTEX_M_SRAM_END  = 0x20080000

    # FreeRTOS TCB field offsets (ARM Cortex-M, FreeRTOS v10.4.x)
    OFFSET_STACK_PTR  = 0x00   # pxTopOfStack
    OFFSET_PRIORITY   = 0x40   # uxPriority
    OFFSET_PXSTACK    = 0x44   # pxStack
    OFFSET_TASK_NAME  = 0x48   # pcTaskName[16]
    TCB_MIN_SIZE      = 0x58   # minimum bytes to read per candidate

    FREERTOS_MAX_PRIORITY = 32

    @classmethod
    def get_requirements(cls):
        return [
            requirements.TranslationLayerRequirement(
                name="primary",
                description="Memory layer for FreeRTOS TCB analysis",
            )
        ]

    def _is_valid_sram_ptr(self, ptr: int) -> bool:
        """Returns True if pointer is within the Cortex-M SRAM range."""
        return self.CORTEX_M_SRAM_BASE <= ptr < self.CORTEX_M_SRAM_END

    def _is_valid_task_name(self, data: bytes) -> bool:
        """
        Task names must be printable ASCII, null-terminated, 1–15 chars.
        Returns False for empty names or names with non-printable characters.
        """
        try:
            name = data.split(b"\x00")[0]
            if len(name) == 0 or len(name) > 15:
                return False
            return all(0x20 <= b <= 0x7F for b in name)
        except Exception:
            return False

    def _generator(self):
        layer      = self.context.layers["primary"]
        min_addr   = self.CORTEX_M_SRAM_BASE
        max_addr   = self.CORTEX_M_SRAM_END - self.TCB_MIN_SIZE

        for offset in range(min_addr, max_addr, 4):
            try:
                raw = layer.read(offset, self.TCB_MIN_SIZE)
            except exceptions.InvalidAddressException:
                continue

            # Check pxTopOfStack (offset +0x00) — must be valid SRAM pointer
            top_of_stack = struct.unpack_from("<I", raw, self.OFFSET_STACK_PTR)[0]
            if not self._is_valid_sram_ptr(top_of_stack):
                continue

            # Check uxPriority (offset +0x40) — must be <= FREERTOS_MAX_PRIORITY
            priority = struct.unpack_from("<I", raw, self.OFFSET_PRIORITY)[0]
            if priority > self.FREERTOS_MAX_PRIORITY:
                continue

            # Check pxStack (offset +0x44) — must be valid SRAM pointer
            px_stack = struct.unpack_from("<I", raw, self.OFFSET_PXSTACK)[0]
            if not self._is_valid_sram_ptr(px_stack):
                continue

            # Check pcTaskName (offset +0x48) — must be printable ASCII
            task_name_raw = raw[self.OFFSET_TASK_NAME: self.OFFSET_TASK_NAME + 16]
            if not self._is_valid_task_name(task_name_raw):
                continue

            # All checks passed — extract clean task name
            task_name = task_name_raw.split(b"\x00")[0].decode("ascii", errors="ignore")

            # Classify as ACTIVE or SUSPECT based on stack pointer consistency
            status = "ACTIVE" if self._is_valid_sram_ptr(px_stack) else "SUSPECT"

            yield (0, [
                format_hints.Hex(offset),      # TCB address
                task_name,                      # Task name
                format_hints.Hex(top_of_stack), # Stack pointer (pxTopOfStack)
                format_hints.Hex(px_stack),     # Stack base (pxStack)
                priority,                       # Priority level
                status,                         # ACTIVE or SUSPECT
            ])

    def run(self):
        return renderers.TreeGrid(
            [
                ("TCB_Address",    format_hints.Hex),
                ("Task_Name",      str),
                ("Stack_Pointer",  format_hints.Hex),
                ("Stack_Base",     format_hints.Hex),
                ("Priority",       int),
                ("Status",         str),
            ],
            self._generator()
        )
