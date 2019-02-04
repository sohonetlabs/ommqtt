#!/usr/bin/env python

"""
    Based off the skeleton plugin for rsyslog
    and
    https://github.com/czanik/syslog-ng-mqtt-dest/blob/master/mqtt_dest.py


    in rsyslog.conf

    module(load="omprog")
    action(type="omprog" template="json_syslog" binary="/home/foo/ommqtt/ommqtt.py --topic syslog/ --port 1883 ")

"""

import argparse
import json
import logging
import os
import os.path
import select
import socket
import sys
import syslog

import paho.mqtt.client as mqtt

# App logic global variables
mqqt_dest = None

mqtt_options = None

logger = logging.getLogger(__name__)


class MqttDestination(object):

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
            inflight = options["inflight_max"]
            self.mqttc.max_inflight_messages_set(inflight)

            if cert_path:
                if not os.path.exists(cert_path):
                    syslog.syslog("Invalid cert path " + cert_path)
                    exit(0)
                else:
                    self.mqttc.tls_set(
                                tls_version=2,
                                ca_certs=cert_path
                                )
            if auth_path:
                if not os.path.exists(auth_path):
                    syslog.syslog("Invalid auth path " + auth_path)
                    exit(0)
                else:
                    with open(auth_path, "r") as f:
                        creds = json.load(f)
                        self.mqttc.username_pw_set(creds["username"], creds["password"])

        except Exception as err:
            logger.error("init error")
            syslog.syslog("Init exception" + str(err))
            return False
        return True

    def is_opened(self):
        return self._is_opened

    def open(self):
        try:
            self.mqttc.connect(self.host, self.port)
            self.mqttc.socket().setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2048)
            self.mqttc.loop_start()
            self._is_opened = True
        except Exception as err:
            logger.error("open error")
            syslog.syslog("Open exception " + str(err))
            self._is_opened = False
            return False
        return True

    def close(self):
        self.mqttc.disconnect()
        self._is_opened = False

    def send(self, msg):
        decoded_msg = msg["MESSAGE"]
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
                _syslog = json.loads(decoded_msg)
                sub_topic = _syslog["severity"]
                topic = self.topic + "/" + sub_topic
                severity = int(_syslog["severity"])
                # skip messages below severity threshold
                if severity <= self.syslog_severity_threshold:
                    message = self.mqttc.publish(topic, decoded_msg, qos=self.qos)
                    message.wait_for_publish()
                else:
                    logger.debug("not sending message %s" % msg)
            except Exception as err:
                logger.error("Could not send message %s" % msg)
                syslog.syslog("Send format exception " + str(err))
                pass

        except Exception as err:
            logger.error("Could not send message %s" % msg)
            syslog.syslog("Send exception " + str(err))
            self._is_opened = False
            return False
        return True


def on_init():
    global mqtt_dest
    global mqtt_options

    mqtt_dest = MqttDestination()
    mqtt_dest.init(mqtt_options)
    mqtt_dest.open()
    syslog.syslog("OMMQTT init")


def on_receive(msgs):
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


def on_exit():
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

    parser = argparse.ArgumentParser(description="rsyslog plugin to send to MQTT broker")

    parser.add_argument("-b", "--broker",
                        help="MQTT broker",
                        default="localhost",
                        required=False)

    parser.add_argument("-p", "--port",
                        help="MQTT broker port",
                        default=1883,
                        type=int,
                        required=False)

    parser.add_argument("-t", "--topic",
                        help="MQTT broker topic to post to",
                        default="test/syslog",
                        required=False)

    parser.add_argument("-q", "--qos",
                        help="MQTT qos",
                        default=2,
                        type=int,
                        required=False)

    parser.add_argument("-s", "--severity",
                        help="Maximium syslog severity to send",
                        default=7,
                        type=int,
                        required=False)

    parser.add_argument("-c", "--cert",
                        help="path to cert for the MQTT broker",
                        default=None,
                        required=False)

    parser.add_argument("-a", "--auth",
                        help="path to auth for the MQTT broker",
                        default=None,
                        required=False)

    parser.add_argument("-i", "--inflight",
                        help="Maximium in flight messages for MQTT",
                        default=100,
                        type=int,
                        required=False)

    parser.add_argument("--poll",
                        help="The number of seconds between polling for new messages from syslog",
                        default=0.75,
                        type=float,
                        required=False)

    parser.add_argument("-m", "--messages",
                        help="Max number of messages that are processed within one batch from syslog",
                        default=100,
                        type=int,
                        required=False)

    args = parser.parse_args()

    global mqtt_options
    mqtt_options = {
                    "host": getattr(args, "broker"),
                    "port": getattr(args, "port"),
                    "topic": getattr(args, "topic"),
                    "qos": getattr(args, "qos"),
                    "severity": getattr(args, "severity"),
                    "cert_path": getattr(args, "cert"),
                    "auth_path": getattr(args, "auth"),
                    "inflight_max": getattr(args, "inflight"),
                    "debug": 0}

    poll_period = getattr(args, "poll")
    max_at_once = getattr(args, "messages")

    syslog.syslog("OMMQTT start up poll={} messages={}".format(poll_period, max_at_once))
    on_init()
    keep_running = 1
    while keep_running == 1:
        while keep_running and sys.stdin in select.select([sys.stdin], [], [], poll_period)[0]:
            msgs = []
            msgs_in_batch = 0
            while keep_running and sys.stdin in select.select([sys.stdin], [], [], 0)[0]:
                line = sys.stdin.readline()
                if line:
                    msgs.append(line)
                else:  # an empty line means stdin has been closed
                    keep_running = 0
                msgs_in_batch = msgs_in_batch + 1
                if msgs_in_batch >= max_at_once:
                    break
            if len(msgs) > 0:
                on_receive(msgs)
                sys.stdout.flush()  # very important, Python buffers far too much!
    on_exit()


if __name__ == "__main__":
    main()
