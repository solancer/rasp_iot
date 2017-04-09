from __future__ import print_function

from sys import stdout
import socket
import logging
import logging.config
import json

import argparse
import gdbm
import yaml
import sys
import random
import logging.handlers

from datetime import datetime, timedelta

from twisted.internet import task, reactor, threads
from twisted.internet.protocol import Protocol, ReconnectingClientFactory
from twisted.internet import reactor, defer, threads

#from influxdb import client as influxdb
from pubnub import PubnubTwisted as Pubnub

from collections import OrderedDict
from webrelay import WebRelay
import comap
import kta
import redis
import json
from time import mktime
import tzlocal

TZ = tzlocal.get_localzone()

#logging.getLogger().addHandler(logging.handlers.RotatingFileHandler('/export/data/ti/collector.log',
    #mode='a', maxBytes=1024 * 1024, backupCount=10000))

logging.getLogger().setLevel(logging.INFO)

CSV_HEADER = ""

HOSTNAME = socket.gethostname()

logging.info("Collector starting on %s" % HOSTNAME)
## -----------------------------------------------------------------------
## Initiate Pubnub State
## -----------------------------------------------------------------------

# SOMESITE`
pubnub = Pubnub(publish_key="pub-c-0cSOMEUSERNAME",
    subscribe_key="sub-c-571SOMEPASSWORD", ssl_on=True,
    )

class Collector(object):

    def __init__(self, device,
            channel='',
            pubnub=None,
            interval=30,
            config=None,
            unit=None,
            registers=None):
    
        self._device = device
        self._interval = interval
        self._channel = channel
        self._custom_collect = None
        self._unit = unit
        self._pubnub = pubnub
        self._config = config
        self._asset = config['asset']
        self._v_cache = {}
        self._publish = self._config.get('publish', '')
        self._logging = logging.getLogger(self._config.get('logger', None))
        self._registers = registers
        self._cache = {}
        self._redis = redis.StrictRedis()
  

        self._logged_info = ['asset', 'ipaddr', 'unit', 'channel', 'empty'] \
            + self._config['registers_to_log'] \
            + ['Error state']
            
        self._logging.info(",".join(self._logged_info))

        if CSV_HEADER:
            with open(CSV_HEADER, 'w') as h:
                header_string = self._config.get('csv_header_string', None) \
                   or CSV_HEADER_STRING or 'date,time,logger,' + ','.join(self._logged_info)
                h.write(header_string)

    def collect(self, cache=dict()):
        logging.debug("collecting from unit %d" % self._unit)
        result = self._device.collect(unit=self._unit, registers=self._registers, cache=self._cache)

        empty = False
        if not result:
            logging.warning('%s - nothing to publish' % self._asset)
            empty = True
        result.insert(0, ('ipaddr', self._device.device_ip))
        result.insert(0, ('unit', self._unit))
        result.insert(0, ('asset', self._asset))
        result.insert(0, ('channel', self._channel))
        now = datetime.now(tz=TZ)
        result.append(('timestamp', now.isoformat()))
        result.append(('utctime',datetime(*now.utctimetuple()[:-2]).isoformat()+"Z"))
        self._v_cache = dict(result)
        if self._custom_collect:
            result.append(self._custom_collect())
        result.append(('empty', empty))
        if self._publish:
            reactor.callInThread(self.publish_results, result)
        self.log_results(result)

    def publish_callback(self, result):
        logging.debug("%s - %s" % (self._asset, result))
        pass

    def publish_results(self, result):
        self._redis.publish(self._channel,json.dumps(dict(result)))
        self._pubnub.publish(channel=self._channel,
            message=dict(result),
            callback=self.publish_callback,
            error=self.publish_callback)

    def log_results(self, result):
        def val(i):
            if isinstance(i, tuple):
                return str(i[0])
            else:
                return str(i)
        #data = [{"points": [[val(i[1]) for i in result]],
           #"name": self._channel,
           #"columns": [i[0] for i in result]
        #}]

        data = dict(result)

        self._logging.info(",".join([val(data.get(i)) for i in self._logged_info]))
        #print (data)
        #r = self.infdb.write_points(data)

    def lps(self):
        reg = self._config.get('FLOWMETER')
        return self._v_cache.get(reg, 0)

    def monitor(self):
        reactor.callInThread(self.collect)


class Hybrid(comap.ModbusTKDevice):

    def __init__(self, asset, ipaddr, unit, webrelay,
        registers=[],
        port=502,
        delay_connect=False,
        offset=40001,
        webrelay_registers=[],
        webrelay_store=None,
        aggregate={},
        ):

        super(Hybrid, self).__init__(asset, ipaddr, unit,
            registers=registers, port=port, delay_connect=delay_connect, offset=offset)

        self._aggregate = aggregate

        self.webrelay = WebRelay(webrelay, webrelay_store, reg=webrelay_registers)

    def aggregate(self, results):
        for aggregate in self._aggregate:
            key = aggregate.get('name', '')
            x = dict(results)
            if key:
                val = sum([x[i] for i in aggregate.get('registers', [])])
                results.append((key, val))

    def collect(self):
        results = super(Hybrid, self).collect()
        wresults = self.webrelay.collect()
        results.extend(wresults)
        self.aggregate(results)
        return results


def hybrid_factory(config, channel=HOSTNAME):
    asset = comap.Asset(config['asset'], config['intellidrive'])
    logging.info("Loading asset %s" % asset.name)
    webrelay_store = None

    if config.get('webrelay_store', None):
        logging.info("Opening webrelay_store %s" % config.get('webrelay_store'))
        webrelay_store = gdbm.open(config.get('webrelay_store'), 'c')

    device = Hybrid(
        asset,
        ipaddr=config['ipaddr'],
        unit=int(config['unit']),
        webrelay_ipaddr=config['webrelay'],
        registers=config['registers'],
        webrelay_registers=config['webrelay_registers'],
        webrelay_store=webrelay_store,
        aggregate=config.get('aggregate', {})
        )

    channel = config.get('channel', channel)
    c = Collector(device, channel=channel, config=config)
    l = task.LoopingCall(c.monitor)
    l.start(int(config['cycle']))
    return c


class COMAP_factory(object):

    def __init__(self):
        self._shared = {}
        self._random = self._random_stagger()

    def random(self):
        return self._random.next()

    def make_device(self,asset, ipaddr, unit, registers, close=True):
        device = comap.COMAPModbus(asset,
            ipaddr=ipaddr,
            unit=int(unit),
            registers=registers,
            close=close)

        return device

    def _random_stagger(self):
        x = range(12)
        last = None
        while True:
            z = random.choice(x)
            if z == last:
                continue
            yield z
            last = z


    def modbus_factory(self, config, channel=HOSTNAME, pubnub=None):
        asset = comap.Asset(config['asset'], config['device_config'], int(config['unit']))
        logging.info("Loading asset %s" % asset.name)
        close = config.get('close',None)
        if close is None:
            close = True

        if "shared_connection" in config and config['shared_connection']:
            if config['shared_connection'] in self._shared:
                device = self._shared.get(config['shared_connection'])
            else:
                device = self.make_device(
                    asset,
                    ipaddr=config['ipaddr'],
                    unit=int(config['unit']),
                    registers=config['registers'],
                    close=close)

                self._shared[config['shared_connection']] = device

        else:

            device = self.make_device(
                asset,
                ipaddr=config['ipaddr'],
                unit=int(config['unit']),
                registers=config['registers'],
                close=close)

        channel = config.get('channel', channel)
        c = Collector(device, unit=int(config['unit']),
            channel=channel,
            config=config, pubnub=pubnub,
            registers=config['registers'])

        def _collector():
            l = task.LoopingCall(c.monitor)
            l.start(int(config['cycle']))

        x = int(self.random())
        logging.info("Starting  asset in %d secs" % x)
        reactor.callLater(x, _collector)
        return c


def kta_factory(config, channel=HOSTNAME):
    asset = comap.KTAAsset(config['asset'], config['device_config'])
    logging.info("Loading asset %s" % asset.name)
    device = comap.ModbusTKDevice(asset,
            ipaddr=config.get('ipaddr', None),
            serial_port=config.get('serial_port', None),
            baudrate=config.get('baudrate', None),
            unit=int(config['unit']),
            registers=config['registers'],
            )
    channel = config.get('channel', channel)
    c = Collector(device, channel=channel, config=config)

    def _collector():
        l = task.LoopingCall(c.monitor)
        l.start(int(config['cycle']))

    x = int(random.choice(range(12)))
    logging.info("Starting  asset in %d secs" % x)
    reactor.callLater(x, _collector)
    return c


CLASS_REGISTRY = {
    'Hybrid': hybrid_factory,
    'Modbus': COMAP_factory().modbus_factory,
    'Kta324': kta_factory,
    }

COLLECTOR = {}


def total_lps():
    v1 = COLLECTOR['FMG-Pump-1'].lps()
    v2 = COLLECTOR['FMG-Pump-2'].lps()
    v3 = COLLECTOR['FMG-Pump-3'].lps()
    return ('total_lps', v1 + v2 + v3)

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description="Collect and publish data from assets")
    parser.add_argument('yaml',nargs='+', help="yaml config file")
    parser.add_argument('--asset', help="Asset from config to collect (instead of all)")
    args = parser.parse_args()
    
  
    devices = []
    config = yaml.load(open(args.yaml[0]))
    
    if args.asset and args.asset not in  [i['asset'] for i in config['devices']]:
        sys.stderr.write('Asset %s not found in %s\n' % (args.asset,args.yaml[0]))
        sys.exit(1)
    
    
    CSV_HEADER = config.get('csv_header', 'header.txt')
    CSV_HEADER_STRING = config.get('csv_header_string', None)

    p = config.get('publish')
    pubnub = Pubnub(publish_key=p.get('publish_key'),
        subscribe_key=p.get('subscribe_key'), ssl_on=True,)

    logging.config.dictConfig(config['logging'])
    channel = config['channel']
    

    
    for i in config['devices']:
        
        if i and ((args.asset and args.asset == i['asset']) or not args.asset):
        
            logging.info("Loading %s" % i['asset'])
            c = CLASS_REGISTRY.get(i['class'])(i, channel=channel, pubnub=pubnub)
            COLLECTOR[i['channel']] = c

    #COLLECTOR['FMG-DCU']._custom_collect = total_lps

    #asset = comap.Asset('580733', "Test Intelidrive.TXT")
    #d = Hybrid(asset, "192.168.5.15", 4,"192.168.5.50",
        #registers=['Ubat', 'CPU temp', 'AIN4', 'Engine state', 'Run hrs'],
         #webrelay_registers=['count1',])

    #c = Collector(d)
    #l = task.LoopingCall(c.monitor)
    #l.start(10.0)
    logging.info("Starting collection")
    reactor.run()
