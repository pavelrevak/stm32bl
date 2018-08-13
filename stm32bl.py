"""STM32 MCU serial firmware loader"""

import time
import argparse
import serial


VERSION_STR = "stm32bl v0.0.0"

DESCRIPTION_STR = VERSION_STR + """
(c) 2016 by pavel.revak@gmail.com
https://github.com/pavelrevak/stm32bl
"""


class Stm32BLException(Exception):
    """General STM32 loader exception"""

class SerialException(Stm32BLException):
    """Serial communication Exception"""

class ConnectingException(Stm32BLException):
    """Connecting to boot-loader exception"""

class NoAnswerException(Stm32BLException):
    """No answer exception"""

class CommandNotAllowedException(Stm32BLException):
    """Command not allowed exception"""

class UnexpectedAnswerException(Stm32BLException):
    """Unexpected answer exception"""

class NoAckException(Stm32BLException):
    """General No ACK exception"""

class NoAckCommandException(NoAckException):
    """No ACK after command exception"""

class NoAckDataException(NoAckException):
    """No ACK after data exception"""


class Stm32bl():
    """STM32 firmware loader class"""

    CMD_INIT = 0x7f
    CMD_ACK = 0x79
    CMD_NOACK = 0x1f
    CMD_GET = 0x00
    CMD_GET_VERSION = 0x01
    CMD_GET_ID = 0x02
    CMD_READ_MEMORY = 0x11
    CMD_GO = 0x21
    CMD_WRITE_MEMORY = 0x31
    CMD_ERASE = 0x43
    CMD_EXTENDED_ERASE = 0x44
    CMD_WRITE_PROTECT = 0x63
    CMD_WRITE_UNPROTECT = 0x73
    CMD_READOUT_PROTECT = 0x82
    CMD_READOUT_UNPROTECT = 0x92

    FLASH_START = 0x08000000

    def __init__(self, port, baudrate=19200, verbosity=1):
        try:
            self._serial_port = serial.Serial(
                port=port,
                baudrate=baudrate,
                parity=serial.PARITY_EVEN,
                stopbits=1,
                timeout=1
            )
        except (FileNotFoundError, serial.serialutil.SerialException):
            raise SerialException("Error opening serial port: %s" % port)
        self._verbosity = verbosity
        self._connect(5)
        self._allowed_commands = [self.CMD_GET, ]
        self._boot_version = self._cmd_get()
        self._option_bytes = self._cmd_get_version()
        self._dev_id = self._cmd_get_id()

    @staticmethod
    def print_buffer(addr, data, bytes_per_line=16):
        """print buffer"""
        prev_chunk = []
        same_chunk = False
        for i in range(0, len(data), bytes_per_line):
            chunk = data[i:i + bytes_per_line]
            if prev_chunk != chunk:
                print('%08x  %s%s  %s' % (
                    addr,
                    ' '.join(['%02x' % d for d in chunk]),
                    '   ' * (16 - len(chunk)),
                    ''.join([chr(d) if d >= 32 and d < 127 else '.' for d in chunk]),
                ))
                prev_chunk = chunk
                same_chunk = False
            elif not same_chunk:
                print('*')
                same_chunk = True
            addr += len(chunk)
        print('%08x' % addr)

    def log(self, message, operation=None, level=1):
        """logging printing"""
        if self._verbosity < level:
            return
        msg = ''
        if level > 0:
            msg += ':' * level
        if operation:
            msg += '%s: ' % operation
        msg += message
        print(msg)

    def _write(self, data):
        """Write data to serial port"""
        self.log(":".join(['%02x' % d for d in data]), 'WR', level=3)
        self._serial_port.write(bytes(data))

    def _read(self, cnt=1, timeout=1):
        """Read data from serial port"""
        data = []
        while not data and timeout > 0:
            data = list(self._serial_port.read(cnt))
            timeout -= 1
        self.log(":".join(['%02x' % d for d in data]), 'RD', level=3)
        return data

    def _reset_mcu(self):
        """Reset MCU"""
        self._serial_port.setDTR(0)
        time.sleep(0.1)
        self._serial_port.setDTR(1)
        time.sleep(0.2)

    def _connect(self, repeat=1):
        """connect to boot-loader"""
        self.log("Connecting to boot-loader", level=1)
        self._serial_port.setRTS(0)
        self._reset_mcu()
        while repeat:
            self._write([self.CMD_INIT])
            ret = self._read()
            if ret and ret[0] in (self.CMD_ACK, self.CMD_NOACK):
                return
            repeat -= 1
        raise ConnectingException("Can't connect to MCU boot-loader.")

    def exit_bootloader(self):
        """Exit boot-loader and restart MCU"""
        self._serial_port.setRTS(1)
        self._reset_mcu()

    def _talk(self, data_wr, cnt_rd, timeout=1):
        """talk with boot-loader"""
        if isinstance(data_wr, (tuple, list)):
            xor = data_wr[0]
            for i in data_wr[1:]:
                xor ^= i
            data_wr.append(xor)
        else:
            data_wr = [data_wr, data_wr ^ 0xff]
        self._write(data_wr)
        res = self._read(cnt_rd, timeout=timeout)
        if not res:
            raise NoAnswerException("No answer.")
        return res

    def _send_command(self, cmd, cnt_rd=None):
        """send command to boot-loader"""
        if cmd not in self._allowed_commands:
            raise CommandNotAllowedException("command %02x: is not supported by this device." % cmd)
        if cnt_rd is None:
            cnt_rd = 1
        else:
            cnt_rd += 2
        res = self._talk(cmd, cnt_rd)
        if res[0] != self.CMD_ACK or res[-1] != self.CMD_ACK:
            raise NoAckCommandException("NoACK for command.")
        return res[1:-1]

    def _send_data(self, data, cnt_rd=None, timeout=1):
        """send command to boot-loader"""
        res = self._talk(data, 1, timeout=timeout)
        if res[0] != self.CMD_ACK:
            raise NoAckDataException("NoACK for data.")
        if cnt_rd is not None:
            return self._read(cnt_rd, timeout=timeout)

    @staticmethod
    def _convert_version(ver):
        return 'v%d.%d' % (ver // 16, ver % 16)

    @staticmethod
    def _convert_32bit(val):
        return [
            val >> 24,
            0xff & (val >> 16),
            0xff & (val >> 8),
            0xff & val,
        ]

    @staticmethod
    def _convert_16bit(val):
        return [
            val >> 8,
            0xff & val,
        ]

    def _cmd_get(self):
        """Gets the version and the allowed commands supported
        by the current version of the boot-loader"""
        self.log("CMD_GET", level=2)
        res = self._send_command(self.CMD_GET, 13)
        if len(res) - 2 != res[0]:
            raise UnexpectedAnswerException("CMD_GET command: wrong result length.")
        boot_version = self._convert_version(res[1])
        self.log(boot_version, 'BOOT_VERSION', level=1)
        # update list of allowed commands
        self._allowed_commands = res[2:]
        return boot_version

    def _cmd_get_version(self):
        """Gets the boot-loader version and the Read Protection
        status of the Flash memory"""
        self.log("CMD_GET_VERSION", level=2)
        res = self._send_command(self.CMD_GET_VERSION, 3)
        if len(res) != 3:
            raise UnexpectedAnswerException("CMD_GET_VERSION: wrong length of result")
        boot_version = self._convert_version(res[0])
        if boot_version != self._boot_version:
            raise UnexpectedAnswerException("Version between GET and GET_VERSION are different.")
        option_bytes = res[1:]
        self.log(":".join(['%02x' % i for i in option_bytes]), 'OPTION_BYTES', level=1)
        return option_bytes

    def _cmd_get_id(self):
        """Gets the chip ID"""
        self.log("CMD_GET_ID", level=2)
        res = self._send_command(self.CMD_GET_ID, 3)
        if len(res) - 2 != res[0]:
            raise UnexpectedAnswerException("CMD_GET_ID: wrong result length.")
        dev_id = (res[1] << 8) + res[2]
        self.log("%04x" % dev_id, 'DEV_ID', level=1)
        return dev_id

    def _cmd_read_memory(self, address, length):
        """Reads up to 256 bytes of memory starting from an
        address specified by the application"""
        self.log("CMD_READ_MEMORY(%08x, %d)" % (address, length), level=2)
        self._send_command(self.CMD_READ_MEMORY)
        self._send_data(self._convert_32bit(address))
        return self._send_data(length - 1, length)

    def cmd_go(self, address):
        """Jumps to user application code located in the internal
        Flash memory or in SRAM"""
        self.log("CMD_GO", level=2)
        self._send_command(self.CMD_GO)
        self._send_data(self._convert_32bit(address))

    def _cmd_write_memory(self, address, data):
        """Writes up to 256 bytes to the RAM or Flash memory
        starting from an address specified by the application"""
        self.log("CMD_WRITE_MEMORY(%08x, %d)" % (address, len(data)), level=2)
        self._send_command(self.CMD_WRITE_MEMORY)
        self._send_data(self._convert_32bit(address))
        return self._send_data([len(data) - 1] + data)

    def _cmd_erase(self, pages=0xff):
        """Erases from one to all the Flash memory pages"""
        self.log("CMD_ERASE(%d)" % pages, level=2)
        self._send_command(self.CMD_ERASE)
        if isinstance(pages, (list, tuple)):
            data = [len(pages) - 1]
            for page in pages:
                data.append(page)
        else:
            data = pages
        self._send_data(data, timeout=20)

    def _cmd_extended_erase(self, pages=0xffff):
        """Erases from one to all the Flash memory pages using
        two byte addressing mode (available only for v3.0 usart
        bootloader versions and above)"""
        self.log("CMD_EXTENDED_ERASE", level=2)
        self._send_command(self.CMD_EXTENDED_ERASE)
        if isinstance(pages, (list, tuple)):
            data = self._convert_16bit(len(pages) - 1)
            for page in pages:
                data += self._convert_16bit(page)
        else:
            data = self._convert_16bit(0xffff)
        self._send_data(data, timeout=20)

    def cmd_write_protect(self, sectors):
        """Enables the write protection for some sectors"""
        self.log("CMD_WRITE_PROTECT", level=2)
        data = [len(sectors) - 1]
        for sector in sectors:
            data.append(sector)
        self._send_data(data, timeout=20)
        self._connect(5)

    def cmd_write_unprotect(self):
        """Disables the write protection for all Flash memory sectors"""
        self.log("CMD_WRITE_UNPROTECT", level=2)
        self._send_command(self.CMD_WRITE_UNPROTECT, 0)
        self._connect(5)

    def cmd_readout_protect(self):
        """Enables the read protection"""
        self.log("CMD_READOUT_PROTECT", level=2)
        self._send_command(self.CMD_READOUT_PROTECT, 0)
        self.log("Set readout protection, device is restarted", level=1)
        self._connect(5)

    def cmd_readout_unprotect(self):
        """Disables the read protection"""
        self.log("CMD_READOUT_UNPROTECT", level=2)
        self._send_command(self.CMD_READOUT_UNPROTECT, 0)
        self.log("Removed readout protection, device is restarted", level=1)
        self._connect(5)

    def read_memory(self, address, size=None):
        """read memory"""
        mem = []
        if size is None:
            self.log("address=0x%08x" % address, 'READ_MEMORY', level=1)
            while True:
                try:
                    mem += self._cmd_read_memory(address, 256)
                except NoAckDataException:
                    self._read()
                    break
                address += 256
            self.log("done (%d Bytes)" % len(mem), 'READ_MEMORY', level=1)
        else:
            self.log("from 0x%08x (%d Bytes)" % (address, size), 'READ_MEMORY', level=1)
            while size > 0:
                _rd_size = size
                if size > 256:
                    _rd_size = 256
                size -= _rd_size
                mem += self._cmd_read_memory(address, _rd_size)
                address += _rd_size
            self.log("done", 'READ_MEMORY', level=1)
        return mem

    def write_memory(self, address, data):
        """write memory"""
        self.log("from 0x%08x (%d Bytes)" % (address, len(data)), 'WRITE_MEMORY', level=1)
        _data = data[:]
        while _data:
            self._cmd_write_memory(address, _data[:256])
            address += 256
            _data = _data[256:]
        self.log("done", 'WRITE_MEMORY', level=1)

    def write_file(self, address, file_name, verify=False):
        """Write file and or verify"""
        binfile = open(file_name, 'rb')
        mem = list(binfile.read())
        size = len(mem)
        if size % 4:
            mem += [0] * (size % 4)
            size = len(mem)
        self.write_memory(address, mem)
        if not verify:
            return
        addr = address
        mem_verify = self.read_memory(address, size)
        _errors = 0
        for data_a, data_b in zip(mem, mem_verify):
            if data_a != data_b:
                if _errors < 10:
                    self.log("0x%08x: 0x%02x != 0x%02x" % (addr, data_a, data_b), 'VERIFY', level=0)
                _errors += 1
            addr += 1
        if _errors >= 10:
            self.log(".. %d errors" % _errors, 'VERIFY', level=0)
        else:
            self.log("OK", 'VERIFY', level=1)

    def mass_erase(self):
        """Mass erase"""
        self.log("MASS_ERASE", level=1)
        if self.CMD_ERASE in self._allowed_commands:
            self._cmd_erase()
            return
        try:
            self._cmd_extended_erase()
        except NoAckException:
            # some chips don't support mass erase
            # protect and unprotect also make chip erase
            try:
                self.cmd_readout_protect()
            except NoAckException:
                # chip is already protected
                pass
            self.cmd_readout_unprotect()

    def erase_blocks(self, blocks):
        """Mass erase"""
        blocks = sorted(set(blocks))
        self.log(",".join([str(b) for b in blocks]), 'ERASE_BLOCKS', level=1)
        if self.CMD_ERASE in self._allowed_commands:
            self._cmd_erase(blocks)
            return
        self._cmd_extended_erase(blocks)


def main():
    """Main application"""
    parser = argparse.ArgumentParser(description=DESCRIPTION_STR)
    parser.add_argument('-V', '--version', action='version', version=VERSION_STR)
    parser.add_argument('-v', '--verbose', action='count', help="increase verbosity *", default=0)
    parser.add_argument('-p', '--port', help="Serial port eg: /dev/ttyS0 or COM1", required=True)
    parser.add_argument('-b', '--baud', help="Baud-rate (9600 - 115200)", default=115200)
    parser.add_argument('-a', '--address', help="Set address for reading or writing")
    parser.add_argument('-s', '--size', help="Set size for reading")
    parser.add_argument('-r', '--read', help="Read content of memory to file")
    parser.add_argument('-d', '--dump', action='store_true', help="Dump content of memory")
    parser.add_argument('-m', '--mass-erase', action='store_true', help="Mass erase before writing")
    parser.add_argument('-e', '--erase-block', type=int, action='append', help="Erase block *")
    parser.add_argument('-w', '--write', action='append', help="Write file to memory *")
    parser.add_argument('-f', '--verify', action='store_true', help="Verify after writing")
    parser.add_argument('-x', '--execute', action='store_true', help="Start application")
    parser.add_argument('-t', '--reset', action='store_true', help="Reset MCU and exit boot-loader")
    parser.add_argument('-W', '--write-protect', type=int, action='append', help="WP sector *")
    parser.add_argument('-U', '--write-unprotect', action='store_true', help="Write unprotect all")
    parser.add_argument('-R', '--read-protect', action='store_true', help="Read Protect")
    parser.add_argument('-T', '--read-unprotect', action='store_true', help="Read unprotect")
    args = parser.parse_args()
    address = int(args.address, 0) if args.address is not None else Stm32bl.FLASH_START
    size = int(args.size, 0) if args.size is not None else None

    try:
        stm32bl = Stm32bl(port=args.port, baudrate=args.baud, verbosity=args.verbose)
        if args.read_unprotect:
            stm32bl.cmd_readout_unprotect()
        if args.write_unprotect:
            stm32bl.cmd_write_unprotect()
        if args.dump or args.read:
            mem = stm32bl.read_memory(address, size)
            if args.dump:
                stm32bl.print_buffer(address, mem)
            if args.read:
                binfile = open(args.read, 'wb')
                binfile.write(bytes(mem))
        if args.mass_erase:
            stm32bl.mass_erase()
        elif args.erase_block:
            stm32bl.erase_blocks(args.erase_block)
        if args.write:
            stm32bl.write_file(address, args.write[0], args.verify)
        if args.write_protect:
            stm32bl.cmd_write_protect(args.write_protect)
        if args.read_protect:
            stm32bl.cmd_readout_protect()
        if args.execute:
            stm32bl.cmd_go(address)
        if args.reset:
            stm32bl.exit_bootloader()
    except Stm32BLException as err:
        print("ERROR: %s" % err)

if __name__ == "__main__":
    main()
