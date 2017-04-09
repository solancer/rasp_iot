import argparse
import yaml
import sys


import paho.mqtt.client as mqtt
import json
import redis
import sys
from retrying import retry
import sys
from datetime import datetime
from time import mktime

class NoValue(object):
    pass

class X(object):
    def __init__(self, client, topic, channel):
        sys.stderr.write( "new publisher %s %s\n" % ( channel, topic))
        self._client = client
        self._topic = topic
        self._channel = channel
        self._state = {}
        self._count = 0
        
    def publish(self, payload):
        newp = {}
       
        for k,v in json.loads(payload).items():
            k = k.replace(' ','-')
            k= k.replace('@','')
            if isinstance(v,list):
                if len(v) and k !='alarms':
                    v = v[1]
            if isinstance(v,dict) or k == 'alarms':
                v = json.dumps(v)
            if self._state.get(k,NoValue) != v or k == 'empty':
                self._state[k] = v
                newp[k]=v
        #repr( newp )
        buf = {}
        self._count = self._count + 1
        newp["count"] = self._count
        if "utctime" in payload:
            buf["time"] = {"$date":newp['utctime']}
        #print buf["time"],newp['utctime'] 
        buf["data"] = newp
        result =  self._client.publish(self._topic,json.dumps(buf))
        if self._count > 10:
            self._count = 0
            self._state = {}
        #print "MQTT Sent ",result
        

class LosantMQTT(mqtt.Client):
    pass
    
    
def on_message(client, userdata, message):
    print("from mqtt %\n" % message)
  
#MQTT.publish(me
def on_connect(client, userdata, flags, rc):
    print( "connected\n")


@retry(stop_max_attempt_number=10, wait_exponential_multiplier=1000, wait_exponential_max=60000)
def do_reconnect(client):
    client._X_retry_count = client._X_retry_count+1
    try:
        print "Trying to reconnect" , client._X_retry_count   
        client.reconnect()
        print "Reconnect succeeded"    
        client._X_retry_count = 0
    except Exception, e:
        if client._X_retry_count < 5:
            raise e
        else:
            return False
    return True

def on_disconnect(client, userdata, rc):
    setattr(client,'_X_retry_count',0)
    if not do_reconnect(client):
        print "Exiting failed to reconnect"
        sys.exit(-1)
 
@retry(stop_max_attempt_number=10, wait_exponential_multiplier=1000, wait_exponential_max=60000) 
def initial_connect(client, mqtt_hostname, mqtt_port):
    print "Connecting on start"
    client.connect(mqtt_hostname, mqtt_port) 
    
def main():   
    
    

    parser = argparse.ArgumentParser(description="subscribe to redis channel and publish to MQTT Losant")
    parser.add_argument('--yaml',nargs='+', help="yaml config file")
    #parser.add_argument('--topic', help="MQTT Channel")
    args = parser.parse_args()
    
    config = yaml.load(open(args.yaml[0]))
    
    
    mqtt_hostname = config.get('mqtt_hostname')  # "broker.losant.com"
    mqtt_port = int(config.get('mqtt_port'))
    use_tls = config.get('mqtt_tls')
    use_login = config.get('mqtt_login')
    clientid=config.get('clientid') 
    if use_login:
        
        user = config.get('user')  
        password = config.get('password')  
        
    cpattern = config.get('subcribe')
    certfile = config.get('certfile') 
    
    
    
    #topic = args.topic
    cpattern = config.get('subscribe')
    client = LosantMQTT(client_id=clientid)
    client.on_message = on_message
    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    if use_tls:
        print "Using TLS"
        client.tls_set(certfile)
    if use_login:
        print "Logging In"
        client.username_pw_set(user,password)
     
    
    initial_connect(client, mqtt_hostname, mqtt_port)
    
    publishers = {}
    
    for i in config.get('CHANNELS'):
        publishers[i.get('channel')] = X(client, topic=i.get('topic'), channel=i.get('channel'))
        print i.get('channel')," registered"

    r = redis.StrictRedis()
    p = r.pubsub()
    
    client.loop_start()
    print "Listening for ",cpattern
    p.psubscribe(cpattern)
    

    for message in p.listen():
        #print message
        
        if message['type'] == "pmessage":
            #print "recieved ",message["channel"]

            publisher = publishers.get(message['channel'])
            if not publisher:
                sys.stderr.write('Unknown channel %s\n' % 	message["channel"])	 
                continue
            publisher.publish(message['data'])
        sys.stderr.flush()    
    

if __name__ == "__main__":
    main()
    


    
