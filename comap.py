# -*- coding: latin-1 -*-


#Register(s)      Com.Obj. Name           Dim  Type       Len Dec   Min    Max Group
#^              ^ ^      ^ ^            ^ ^  ^ ^          ^ ^ ^^ ^    ^ ^    ^ ^      ^     ^
#0             16 17    25 27          40 4145 46      56 58  62 64  68 71  77 78          91
#============================================================================================
#40001            8235     ID BIN              Binary#1    2   -      -      - Binary CU
#40010            8239     ID BOUT             Binary#2    2   -      -      - Binary CU
#40012            10124    CPU Temp       ?C   Integer     2   1   -200    800 Analog CU
#40022            9164     DISCHARGE PRES Bar  Integer     2   2      0   2500 AnalogInputs 1
#40073-40074 ( 2) 10173    EngHours       h    Integer     4   0      -      - ECU
#40112-40113 ( 2) 9090     PasswordDecode      Unsigned    4   0      -      - Info
#40128            10360    DIS PID        -    Integer     2   0 -32768  32767 PLC
#43066-43081 (16) 9597     AcallCH1-Addr       String0    32   -      -      - Act. Calls/SMS
#43043-43050 ( 8) 8637     Engine Name         String0    16   -      -      - Basic Settings
#43383            9946     Idle RPM       RPM  Unsigned    2   0  9095*  8253* Engine Params
#40077            10182    ECU StrList1        List#1      1   -    442    442 (No group)
#43425            8979     Time Stamp Per min  Unsigned    1   0      0    240 Date/Time
#43426-43427 ( 2) 10042    Timer ON            Time        3   -      -      - Basic Settings
#43397            8383     Batt Volt Del  s    Unsigned    2   0      0    600 Engine Protect
#43398            8387     Batt <V        V    Integer     2   1     80  9587* Engine Protect
#43399            9587     Batt >V        V    Integer     2   1  8387*    400 Engine Protects

#lint:disable
#* - limit is defined by the value of the communication object of specified number

#======================================================================================
#List# Types Meaning
#======================================================================================

#--------------------------------------------------------------------------------------
#List#1

#Value  Name
#--------------------------------------------------------------------------------------
    #0  ECU-StrList1

#--------------------------------------------------------------------------------------
#======================================================================================
#Binary# Types Meaning
#======================================================================================

#--------------------------------------------------------------------------------------
#Binary#1

#Bit  Name
#--------------------------------------------------------------------------------------
  #0  REMOTE START
  #1  FAULT/RUN
  #2  AUTO
  #3  EMERGENCY STOP
  #4  FLOW FAULT
  #5  BALLS START
  #6  BALLS STOP
  #7  HIGH SPEED
  #8  OVERFLOW
  #9  SPARE
 #10  SPARE
 #11  4-20 SPEED
 #12  SUCTION ON
 #13  DISCHARGE ON
#--------------------------------------------------------------------------------------
#======================================================================================
#Table# Types Meaning
#======================================================================================

#Register(s)      Com.Obj. Name           Dim  Type       Len Dec   Min    Max Group
#^              ^ ^      ^ ^            ^ ^  ^ ^          ^ ^ ^^ ^    ^ ^    ^ ^      ^     ^
#0             16 17    25 27          40 4145 46      56 58  62 64  68 71  77 78          91
#lint:enable

#from pymodbus.client.sync import ModbusTcpClient as ModbusClient
import modbus_tk.defines as cst
import modbus_tk.modbus_tcp as modbus_tcp
import modbus_tk.modbus_rtu as modbus_rtu

import modbus_tk
import re
import struct
from bitstring import BitArray
import socket
import logging
from collections import namedtuple, OrderedDict
import serial
#import kta
import yaml
#import gdbm
from json import dumps, loads

Fields = namedtuple('Fields',
    ['registers',
    'obj',
    'name',
    'dim',
    'type',
    'len',
    'dec',
    'min',
    'max',
    'group'])

Pos = namedtuple('Pos', ['start', 'end'])

fields = Fields(
    registers=Pos(0, 16),
    obj=Pos(17, 25),
    name=Pos(26, 40),
    dim=Pos(41, 45),
    type=Pos(46, 56),
    len=Pos(57, 60),
    dec=Pos(61, 63),
    min=Pos(64, 71),
    max=Pos(71, 77),
    group=Pos(78, 93))


class BaseAsset(object):

    def __init__(self, name, filename):

        self.filename = filename
        self.name = name

        self.lookup_registry = {}
        self.name_registry = {}
        self.registers = OrderedDict()

    def get_by_name(self, name):
        return self.name_registry[name]

    def get_by_id(self, id):
        return self.registers[id]

    def __iter__(self):
        for i in self.registers.values():
            yield i


class KTAAsset(BaseAsset):

    def __init__(self, name, filename):
        super(KTAAsset, self).__init__(name, filename)
        self.read_config(filename)

    def read_config(self, filename):
        with open(filename, 'r') as fh:
            self._config = yaml.load(fh.read())
        for reg in self._config['registers']:
            r = KTARegister(reg, self)
            self.registers[r.id] = r
            self.name_registry[r.name] = r



class Asset(BaseAsset):

    def __init__(self, name, filename, unit=None):
        super(Asset, self).__init__(name, filename)
        self.source = None
        self.read_text()
        self._unit = None

    def register_blocks(self):
        rx = []
        r = [None, None]
        rc = None
        for i in sorted(self.registers.values(), key=lambda x: x.register):

            if not r[0]:
                r[0] = i
                rc = i
            if rc.register == i.register:
                continue
            s1, s2 = rc.register
            t1, t2 = i.register
            if s1 + s2 == t1:
                rc = i
            else:
                r[1] = rc
                rc = i
                rx.append(r)
                r = [i, None]
        r[1] = i
        rx.append(r)
        return rx

    def reg_in_block(self, reg):

        a, l = reg.register
        for r1, r2 in self.register_blocks():
            if r1.register[0] <= a <= r2.register[0]:
                return (r1, r2)

    def read_register_header(self):
        self.source.readline()
        self.source.readline()

    def read_registers(self):
        while True:

            i = self.source.readline()
            if not i.strip():
                break
            r = Register(i.strip(), self)
            self.registers[r.id] = r
            self.name_registry[r.name] = r

    def find_lists(self):
        while True:
            i = self.source.readline()
            if i.startswith('List# Types Meaning'):
                break
        self.source.readline()

    def read_list(self):

        name = self.source.readline().strip()  # list name
        lookup = LookupTable(name, self)

        while True:
            x = self.source.readline()
            if x.strip():
                break

        try:
            k, v = x.split()   # key , value definition
        except ValueError:
            import pdb
            pdb.set_trace()
            x

        self.source.readline()                 # ----------------------

        while True:

            i = self.source.readline()

            if not i.strip():
                break

            if i.strip().startswith("-----------"):
                return i   # return this is the start of a new list

            key = i[0:len(k)].strip()     # values .....
            value = i[len(k):].strip()    # blank line
            lookup.add(key, value)         # return

    def read_lists(self):
        last = None

        while True:

            if last:
                last = self.read_list()
                if last:
                    continue

            i = self.source.readline()

            if len(i) == 0:
                return

            if i.startswith('=============================='):
                return

            if not i.strip():
                continue

            if i.strip().startswith('------------'):
                last = self.read_list()

    def read_tables(self):
        last = None

        while True:

            if last:
                last = self.read_list()
                if last:
                    continue

            i = self.source.readline()

            if i.startswith('=============================='):
                return

            if len(i) == 0:
                break

            if not i.strip():
                continue

            if i.strip().startswith('------------'):
                last = self.read_table()

    def read_table(self):

        name, junk = self.source.readline().strip().split(' ')

        lookup = LookupTable(name, self)

        x = self.source.readline()  # blank line
        x = self.source.readline()  # Header

        try:
            k, v = x.split()   # key , value definition
        except ValueError:
            import pdb
            pdb.set_trace()
            pass

        col2_start = x.index('Name')
        col1_end = col2_start - 2
        self.source.readline()                 # ----------------------

        while True:

            i = self.source.readline()
            if len(i) == 0:
                break

            if not i.strip():
                break

            if i.strip().startswith("-----------"):
                return i   # return this is the start of a new list

            key = i[0:col1_end].strip()     # values .....
            value = i[col2_start:].strip()    # blank line
            lookup.add(key, value)         # return

    def find_binary(self):
        while True:
            i = self.source.readline()
            if i.startswith('Binary# Types Meaning'):
                break
        self.source.readline()

    def find_tables(self):
        while True:
            i = self.source.readline()
            if len(i) == 0:
                return "EXIT"
            if i.startswith('Table# Types Meaning'):
                break
        self.source.readline()

    def read_text(self):
        with file(self.filename) as self.source:
            self.read_register_header()
            self.read_registers()
            self.find_lists()
            self.read_lists()
            self.find_binary()
            self.read_lists()
            self.find_tables()
            self.read_tables()


def r_integer(reg, value):
    x = BitArray()
    for i in value:
        x.append("uint:16=%s" % i)

    result = float(x.int) / (10 ** reg.dec)

    return result


def r_integer16(reg, value):

    x = BitArray()
    for i in value:
        x.append("int:16=%s" % i)
    result = x.int
    if reg.dec:
        result = float(x.int) / (10 ** reg.dec)
    return result


def r_unsigned(reg, value):
    x = BitArray()
    for i in value:
        x.append("uint:16=%s" % i)

    result = x.int
    if reg.dec:
        result = float(x.int) / (10 ** reg.dec)

    return result


def r_unsigned32(reg, value):
    x = BitArray()
    for i in value:
        x.append("uint:32=%s" % i)

    result = x.int
    if reg.dec:
        result = float(x.int) / (10 ** reg.dec)

    return result


def r_unsigned8(reg, value):
    x = BitArray()
    for i in value:
        x.append("uint:8=%s" % i)

    result = x.int

    return result


def r_list(reg, value):
    x = r_unsigned(reg, value)
    return (x, reg.get(str(x)))


def r_binary(reg, value):
    x = r_unsigned(reg, value)

    bits = [x & (2**i)  for i in range(15) ]
    
    result = []
    try: 
      for i in range(len(bits)):
        if bits[i]:
            result.append((i,reg.get(str(i))))
    except KeyError:
        pass
    result.append(('bits',bits))
    return (x, dict(result))

def r_table(reg, value):
    x = r_unsigned(reg, value)
    return (x, reg.get(str(x)))


def r_string0(reg, value):
    return struct.pack(">" + "I" * (len(value)), *value).replace('\x00', '')

DECODERS = {
    'FALLBACK': lambda reg, value: (reg, value),
    'Integer': lambda reg, value: r_integer(reg, value),
    'Integer16': lambda reg, value: r_integer16(reg, value),
    'Unsigned': lambda reg, value: r_unsigned(reg, value),
    'Unsigned8': lambda reg, value: r_unsigned8(reg, value),
    'Unsigned16': lambda reg, value: r_unsigned(reg, value),
    'Unsigned32': lambda reg, value: r_unsigned32(reg, value),
    'String0': lambda reg, value: r_string0(reg, value),
    'String': lambda reg, value: r_string0(reg, value),
    #'Domain': lambda reg, value: r_string0(reg, value),
    'Binary': lambda reg, value: r_binary(reg, value),
    'List': lambda reg, value: r_list(reg, value),
    'Table': lambda reg, value: r_table(reg, value)
    }


class BaseRegisterType(object):

    def decode(self, reg):
        decoder = DECODERS.get(self._type, lambda reg, value: (reg, value))
        return decoder(self, reg)

    @property
    def dec(self):
        return self.parent.dec

    @property
    def lookup_registry(self):
        return self.parent.parent.lookup_registry

    @property
    def _value(self):
        if not self._key:
            return {}
        return self.lookup_registry.get(self._raw)

    def values(self):

        return self._value.values()

    def items(self):
        return self._value.items()

    def keys(self):
        return self._value.keys()

    def get(self, name):
        return self._value[name]

    def __repr__(self):
        if hasattr(self, '_key') and self._key:
            return "<RegisterType %s#%s>" % (self._type, self._key)
        else:
            return "<RegisterType %s>" % (self._type)


class RegisterType(BaseRegisterType):
    _key = None
    _type = None
    _raw = None

    def __init__(self, data, parent):
        self._raw = data.strip()
        self.parent = parent
        if '#' in self._raw:
            self._type, self._key = self._raw.split('#')
        else:
            self._type = self._raw


class KTARegisterType(BaseRegisterType):

    _key = None  # not used as no list lookups in KTA Registers
    _type = None
    _raw = None

    def __init__(self, data, parent):

        self._raw = data
        self.parent = parent

        self._type = self._raw


class BaseRegister(object):

    def __init__(self, data, parent):
        self._raw = data
        self.parent = parent

    def format(self, val):
        return val

    def __len__(self):
        return int(self._rd('len'))


class KTARegister(BaseRegister):

    _reg = ['register', 'name', 'function', 'label', 'type', 'map', 'format']
    _v_type = None

    def __init__(self, data, parent):
        super(KTARegister, self).__init__(data, parent)
        if self._rd('store'):
            self._store = gdbm.open('%s_%s_store' % (self.parent.name, self.name), 'c')

    def _rd(self, f):

        return self._raw.get(f)

    @property
    def dec(self):
        return 0

    @property
    def name(self):
        return self._rd('name').strip()

    @property
    def id(self):
        return str(self._rd('register'))

    @property
    def register(self):
        return (self._rd('register'), len(self))

    @property
    def unit(self):
        return self._rd('unit').strip()

    @property
    def dim(self):
        return self._rd('unit').strip()

    @property
    def type(self):

        if not self._v_type:
            r = self._raw.get('type')
            self._v_type = KTARegisterType(r, self)

        return self._v_type

    def store(self, key, val):

        if self._store.has_key(str(key)):
            old_val = loads(self._store[str(key)])
        else:
            old_val = 0
        #old_val = self._store.get(key, 0)
        if val < old_val:
            val = old_val + val
        self._store[str(key)] = dumps(val)
        return val

    def read(self, client):
        result = client._raw_read(self)
        val = self.type.decode(result)
        if self._rd('store'):
            val = self.store(self.name, val)
        logging.info("Raw reg %s,%s,%s" % (self.name, result, val))
        return (val)

    def _map(self, val, in_min, in_max, out_min, out_max):
        logging.info("Raw val to map is %s" % val)
        logging.info("map is %s %s %s %s" % (in_min, in_max, out_min, out_max))
        result = (val - in_min) * (out_max - out_min) / (in_max - in_min) + out_min
        return result

    def format(self, value):

        form = "%d"
        if self._rd('format'):
            form = self._rd('format')
        if self._rd('map'):
            inp, out, floor = self._rd('map')
            logging.info(str(floor))
            floor = floor.get('floor', 0)
            logging.info(str(self._rd('map')))
            value = max(floor, self._map(value,
                inp['input'][0],
                inp['input'][1],
                out['output'][0],
                out['output'][1]))

        return form % (value)


class Register(BaseRegister):

    regex = re.compile("(?P<rega>[0-9]*)-*(?P<regb>[0-9]*).*\((?P<cnt>.+)\)")

    _reg = fields
    _v_type = None

    def _rd(self, f):

        p = getattr(self._reg, f)
        return self._raw[p.start:p.end]

    @property
    def name(self):

        return self._rd('name').strip()

    @property
    def id(self):

        return int(self._rd('obj').strip())

    @property
    def dec(self):
        try:
            return int(self._rd('dec'))
        except ValueError:
            return 0

    @property
    def unit(self):
        return self._rd('dim').strip()

    @property
    def group(self):
        try:
            return self._rd('group').strip()
        except:
            return None

    @property
    def type(self):
        if not self._v_type:
            r = self._reg.type
            v = self._raw[r.start:r.end].strip()
            self._v_type = RegisterType(v, self)

        return self._v_type

    @property
    def register(self):
        return self._unpick_register_size()

    def _unpick_register_size(self):
        r = self._rd('registers')
        if '-' in r:
            m = self.regex.match(r)
            start = m.group('rega')
            #end = m.group('regb')
            size = m.group('cnt')
            return (int(start), int(size))
        else:
            return (int(r), 1)

    def read(self, client, unit=None):
        result = client._raw_read(self, unit=unit)
        return (self.type.decode(result))


class LookupTable(object):

    def __init__(self, name, parent):
        self.dict = OrderedDict()
        self.name = name
        self.parent = parent
        parent.lookup_registry[name] = self

    def add(self, key, value):
        self[key] = value

    def __getitem__(self, key):
        return self.dict[key]

    def __setitem__(self, key, value):
        self.dict[key] = value

    def values(self):
        return self.dict.values()

    def items(self):
        return self.dict.items()

    def keys(self):
        return self.dict.keys()


class ModbusDevice(object):
    def __init__(self, asset, ipaddr, unit,
        registers=[], port=502, delay_connect=False):

        self._asset = asset
        self._ipaddr = ipaddr
        self._port = port
        self._unit = unit
        self._registers = registers
        self._delay_connect = delay_connect

    @property
    def device_ip(self):
        return self._ipaddr

    @property
    def asset_name(self):
        return self._asset.name

    def read_by_name(self, name, format=False, unit=None):
        reg = self._asset.get_by_name(name)
        if format:
            return reg.format(reg.read(self, unit=unit))
        else:
            return reg.read(self, unit=unit)

    def read_by_id(self, id, unit=None):
        reg = self._asset.get_by_id(id)
        return reg.read(self, unit=unit)

    def _raw_read(self, reg, size=1, unit=None):
        raise NotImplementedError

    def _read_register(self, reg):
        raise NotImplementedError

    def collect(self, unit=None, registers=None, cache=None):
        result = []
        if not unit:
            unit = self._unit
        if not registers:
            registers = self._registers
        error = ('Error state', '')
        cflag = False
        try:
            #if self._close:
                #self.open()
            for i in registers:
                try:
                    if i.startswith('@'):
                        result.append((i, getattr(self, i[1:])()))
                    else:
                        result.append((i, self.read_by_name(i, format=True, unit=unit)))
                except KeyError:
                    logging.error('Failed read %s register %s KeyError', self.asset_name, i)

                except  modbus_tk.modbus.ModbusInvalidResponseError, e:
                    error = ('Error state', 'Modbus Error')
                    logging.error("Invalid modbus response %s %s unit %s" % (self.asset_name,
                         str(e), unit))
                    break
            result.append(error)

        except (socket.timeout, socket.error), e:
            self.close()
            cflag = True
            error = ('Error state', 'No contact')
            logging.error("Socket timeout on %s %s" % (self.asset_name, str(e)))
        finally:
            if self._close:
                if not cflag:
                    self.close()
        return result


class ModbusTKDevice(ModbusDevice):

    def __init__(self, asset, ipaddr=None, unit=None, serial_port=None, baudrate=9600,
        registers=[], port=502, delay_connect=True, offset=40001, close=True):

        super(ModbusTKDevice, self).__init__(asset, ipaddr, unit,
            registers=registers, port=port, delay_connect=delay_connect)
        self._close = close
        if ipaddr:
            self._client = modbus_tcp.TcpMaster(self._ipaddr, self._port)
            self._client.after_close = lambda self: logging.info("Device closed %s", self._host)
            self._client.after_open = lambda self: logging.info("Device opened %s", self._host)
        elif serial_port:
            s = serial.Serial(serial_port,
                int(baudrate),
                bytesize=8,
                parity='N',
                stopbits=1,
                xonxoff=0)

            self._client = modbus_rtu.RtuMaster(s)
        else:
            raise ValueError("No device ipaddr or serial port details set")

        self._register_offset = offset

    def open(self):

        logging.debug("Connection opening %s", str(self._client))

        self._client._do_open()

    def close(self):
        logging.debug("Connection closing %s", str(self._client))
        self._client._do_close()

    def _raw_read(self, reg, size=1, unit=None):
        
        if not unit:
            unit = self._unit
        logging.debug("Raw read unit %d" % unit)
        register, size = reg.register
        register = register - self._register_offset
        try:
            result = self._client.execute(unit,
            cst.READ_HOLDING_REGISTERS, register, size)

        except TypeError, e:
            logging.warning(e)
            return None
            
        return result

    def _RHR(self, addr, size, offset=None, unit=None):

        if not unit:
            unit = self._unit

        if offset is None:

            register = addr - self._register_offset
        else:
            register = addr - offset
        return self._client.execute(unit,
            cst.READ_HOLDING_REGISTERS, register, size)

    def _read_register(self, regobj):

        register = regobj.register
        size = regobj.size
        self._raw_read(register - self._register_offset, size)


class COMAPModbus(ModbusTKDevice):

    def alarms(self, unit=None):
        result = []
        if not unit:
            unit = self._unit
        count = self.read_by_name('AlarmRecords',unit=unit)
        if count:
            try:
                result= [self.read_by_name('alarm list#%d' % (i + 1), unit=unit) for i in range(count)]
            except Exception,e:
                logging.warning("Can not fetch alarm %s" % str(e))
        return result


class PyModbusDevice(ModbusDevice):

    def __init__(self, asset, ipaddr, unit,
        registers=[], port=502, delay_connect=False):

        super(PyModbusDevice, self).__init__(asset, ipaddr, unit,
            registers=registers, port=port, delay_connect=delay_connect)

        self._client = ModbusClient(self._ipaddr, self._port)
        if not self._delay_connect:
            self._client.connect()

    def _raw_read(self, reg, size=1, unit=None):

        if not unit:
            unit = self._unit
        return self._client.read_holding_registers(reg, size, unit=unit)



#asset = Asset('580733', r"Test Intelidrive.txt")
#d = ModbusTKDevice(asset, "192.168.5.15", 4)
#" print struct.pack(">"+"i"*(len(t)),*t)"
