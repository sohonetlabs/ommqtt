#!/usr/bin/env python

"""
    Based off the skeleton plugin for rsyslog
    and
    https://github.com/czanik/syslog-ng-mqtt-dest/blob/master/mqtt_dest.py
    

    in rsyslog.conf

    module(load="omprog")
    action(type="omprog" binary="/home/foo/ommqtt/ommqtt.py --topic syslog/ --port 1883 ")

"""

import sys
import select
import argparse
import json
import os
import os.path

import paho.mqtt.client as mqtt

# skeleton config parameters
pollPeriod = 0.75  # the number of seconds between polling for new messages
maxAtOnce = 1024  # max nbr of messages that are processed within one batch

# App logic global variables
mqqt_dest = None

mqtt_options = None

"""
Use "pip install paho-mqtt" or install the relevant package from your distro
host, port and topic are mandatory parameters
"""


class MqttDestination(object):
    """
    the MqttDestination class, from 
    """

    def __init__(self):
        self.host = None
        self.port = None
        self.topic = None
        self._is_opened = False
        self.debug = 0
        self.qos = 0
        self.mqttc = mqtt.Client("rs_mqtt")
        self.cert_path = None
        self.auth_path = None
        self.syslog_severity_threshold = 7

    def init(self, options):

        try:
            self.host = options["host"]
            self.port = int(options["port"])
            self.topic = options["topic"]
            if "debug" in options:
                self.debug = int(options["debug"])
            if "qos" in options:
                self.qos = int(options["qos"])
            self.syslog_severity_threshold = int(options["severity"])
            cert_path = options["cert_path"]
            auth_path = options["auth_path"]

            if cert_path:
                if not os.path.exists(cert_path):
                    print("Invalid cert path " + cert_path)
                    exit(0)
                else:
                    self.mqttc.tls_set(
                                tls_version=2,
                                ca_certs=cert_path
                                )
            if auth_path:
                if not os.path.exists(auth_path):
                    print("Invalid auth path " + auth_path)
                    exit(0)
                else:
                    with open(auth_path, "r") as f:
                        creds = json.load(f)
                        self.mqttc.username_pw_set(creds["username"], creds["password"])

        except Exception as err:
            print(err)
            return False
        return True

    def is_opened(self):
        """Checks if destination is available"""
        return self._is_opened

    def open(self):
        """
        opens connection to the MQTT server and starts the loop
        """
        try:
            self.mqttc.connect(self.host, self.port)
            self.mqttc.loop_start()
            self._is_opened = True
        except Exception as err:
            print(err)
            self._is_opened = False
            return False
        return True

    def close(self):
        """
        closes the connection
        """
        self.mqttc.disconnect()
        self._is_opened = False

    def send(self, msg):
        """
        sends the message
        """
        decoded_msg = msg['MESSAGE'].decode('utf-8')
        try:
            # parse the message and append the severity to the topic
            # see https://en.wikipedia.org/w/index.php?title=Syslog&section=4#Severity_level
            # use the number not the string
            # so we can have
            # /syslog/1
            # /syslog/6
            # as separate topics
            topic = self.topic
            try:
                syslog = json.loads(decoded_msg)
                sub_topic = syslog["severity"]
                topic = self.topic + "/" + sub_topic
                severity = int(syslog["severity"])
            except Exception as err:
                pass
            # skip messages below severity threshold
            if severity <= self.syslog_severity_threshold:
                self.mqttc.publish(topic, decoded_msg, qos=self.qos)
        except Exception as err:
            print(err)
            self._is_opened = False
            return False
        return True


def onInit():
    """ Do everything that is needed to initialize processing (e.g.
        open files, create handles, connect to systems...)
    """
    global mqtt_dest
    global mqtt_options

    mqtt_dest = MqttDestination()
    mqtt_dest.init(mqtt_options)
    mqtt_dest.open()


def onReceive(msgs):
    """This is the entry point where actual work needs to be done. It receives
       a list with all messages pulled from rsyslog. The list is of variable
       length, but contains all messages that are currently available. It is
       suggest NOT to use any further buffering, as we do not know when the
       next message will arrive. It may be in a nanosecond from now, but it
       may also be in three hours...
    """
    global mqtt_dest
    for msg in msgs:
        mqtt_dest.send({"MESSAGE": msg})


def onExit():
    """ Do everything that is needed to finish processing (e.g.
        close files, handles, disconnect from systems...). This is
        being called immediately before exiting.
    """
    global mqtt_dest
    mqtt_dest.close()

"""
-------------------------------------------------------
This is plumbing that DOES NOT need to be CHANGED
-------------------------------------------------------
Implementor's note: Python seems to very agressively
buffer stdout. The end result was that rsyslog does not
receive the script's messages in a timely manner (sometimes
even never, probably due to races). To prevent this, we
flush stdout after we have done processing. This is especially
important once we get to the point where the plugin does
two-way conversations with rsyslog. Do NOT change this!
See also: https://github.com/rsyslog/rsyslog/issues/22
"""


def main():

    parser = argparse.ArgumentParser(description="rsyslog plugin to send send to mqtt")

    parser.add_argument('-b', '--broker',
                       help='MQTT broker',
                       default='localhost',
                       required=False)

    parser.add_argument('-p', '--port',
                          help='MQTT broker port',
                          default=1883,
                          type=int,
                          required=False)

    parser.add_argument('-t', '--topic',
                        help='MQTT broker topic to post to',
                        default='test/syslog',
                        required=False)

    parser.add_argument('-q', '--qos',
                        help='MQTT qos',
                        default=2,
                        type=int,
                        required=False)

    parser.add_argument('-s', '--severity',
                        help='Maximium severity to send',
                        default=7,
                        type=int,
                        required=False)

    parser.add_argument('-c', '--cert',
                        help='path to cert for the mqtt broker',
                        default=None,
                        required=False)

    parser.add_argument('-a', '--auth',
                        help='path to auth for the mqtt broker',
                        default=None,
                        required=False)

    args = parser.parse_args()

    global mqtt_options
    mqtt_options = {
                    "host": getattr(args, 'broker'),
                    "port": getattr(args, 'port'),
                    "topic": getattr(args, 'topic'),
                    "qos": getattr(args, 'qos'),
                    "severity": getattr(args, 'severity'),
                    "cert_path": getattr(args, 'cert'),
                    "auth_path": getattr(args, 'auth'),
                    "debug": 0}

    onInit()
    keepRunning = 1
    while keepRunning == 1:
        while keepRunning and sys.stdin in select.select([sys.stdin], [], [], pollPeriod)[0]:
            msgs = []
            msgsInBatch = 0
            while keepRunning and sys.stdin in select.select([sys.stdin], [], [], 0)[0]:
                line = sys.stdin.readline()
                if line:
                    msgs.append(line)
                else:  # an empty line means stdin has been closed
                    keepRunning = 0
                msgsInBatch = msgsInBatch + 1
                if msgsInBatch >= maxAtOnce:
                    break
            if len(msgs) > 0:
                onReceive(msgs)
                sys.stdout.flush()  # very important, Python buffers far too much!
    onExit()

if __name__ == '__main__':
    main()
