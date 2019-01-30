# OMMQTT output module for rsyslog using MQTT
    
rsyslog plugin that sends logs via mqtt in json format

example output

    test/syslog/5 {"@timestamp":"2019-01-30T15:04:45.830071+00:00","type":"syslog_json","tag":"sohonet:","relayhost":"testhost","relayip":"127.0.0.1","logsource":"testhost","hostname":"testhost","program":"logger","priority":"13","severity":"5","facility":"1","severity_label":"notice","facility_label":"user","message":"<13>Jan 30 15:04:45 logger: Hello Log","end_msg":""}


## install

    pip install paho-mqtt
 
or

    sudo apt install python-paho-mqtt

git clone this repo

ommqtt.py needs to be owned by whatever rsyslog is runnign as ( syslog ) and executable

    chmod +x ommqtt.py
    sudo chown syslog:syslog ommqtt.py
    

## usage

Uses the topic as the base topic and appends the severity label to the end.

    usage: ommqtt.py [-h] [-b BROKER] [-p PORT] [-t TOPIC] [-q QOS] [-s SEVERITY]
                     [-c CERT] [-a AUTH]

    rsyslog plugin to send send to mqtt

    optional arguments:
      -h, --help            show this help message and exit
      -b BROKER, --broker BROKER
                            MQTT broker
      -p PORT, --port PORT  MQTT broker port
      -t TOPIC, --topic TOPIC
                            MQTT broker topic to post to
      -q QOS, --qos QOS     MQTT qos
      -s SEVERITY, --severity SEVERITY
                            Maximium severity to send
      -c CERT, --cert CERT  path to cert for the mqtt broker
      -a AUTH, --auth AUTH  path to auth for the mqtt broker
      
## debugging

Install Mosquitto on your local system and subscribe to the topic as a wild card 

     mosquitto_sub -v -h localhost -t test/syslog/#

## rsyslog config

add this template to /etc/rsyslog.conf
    
    template(name="json_syslog"
      type="list") {
        constant(value="{")
          constant(value="\"@timestamp\":\"")       property(name="timereported" dateFormat="rfc3339")
          constant(value="\",\"type\":\"syslog_json")
          constant(value="\",\"tag\":\"")           property(name="syslogtag" format="json")
          constant(value="\",\"relayhost\":\"")     property(name="fromhost")
          constant(value="\",\"relayip\":\"")       property(name="fromhost-ip")
          constant(value="\",\"logsource\":\"")     property(name="source")
          constant(value="\",\"hostname\":\"")      property(name="hostname" caseconversion="lower")
          constant(value="\",\"program\":\"")      property(name="programname")
          constant(value="\",\"priority\":\"")      property(name="pri")
          constant(value="\",\"severity\":\"")      property(name="syslogseverity")
          constant(value="\",\"facility\":\"")      property(name="syslogfacility")
          constant(value="\",\"severity_label\":\"")   property(name="syslogseverity-text")
          constant(value="\",\"facility_label\":\"")   property(name="syslogfacility-text")
          constant(value="\",\"message\":\"")       property(name="rawmsg" format="json")
          constant(value="\",\"end_msg\":\"")
        constant(value="\"}\n")
    }
    

Load the module to spawn our process

    module(load="omprog")

add the action that will call our process with the template

    action(type="omprog" template="json_syslog" binary="/home/test/ommqtt/ommqtt.py --topic test/syslog --broker localhost")

## Thank you for the pointers

[http://certifiedgeek.weebly.com/blog/rsyslog-json-format-template](http://certifiedgeek.weebly.com/blog/rsyslog-json-format-template)

[https://www.syslog-ng.com/community/b/blog/posts/writing-python-destination-in-syslog-ng-how-to-send-log-messages-to-mqtt](
https://www.syslog-ng.com/community/b/blog/posts/writing-python-destination-in-syslog-ng-how-to-send-log-messages-to-mqtt)

[https://github.com/kgiusti/rsyslog-omamqp1/tree/master/external/python](https://github.com/kgiusti/rsyslog-omamqp1/tree/master/external/python)