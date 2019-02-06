run_ommqtt_system_tests:
	echo '{"severity": "1"}' | python -m ommqtt.ommqtt
	echo '{"severity": "2"}' | python -m ommqtt.ommqtt -p 1883
	echo '{"severity": "3"}' | python -m ommqtt.ommqtt -b 127.0.0.1 -p 1883
	echo '{"severity": "4"}' | python -m ommqtt.ommqtt -u mqtt://127.0.0.1:1883
	echo '{"severity": "5"}' | python -m ommqtt.ommqtt -t test_topic
	echo '{"severity": "6"}' | python -m ommqtt.ommqtt -t test_topic/subtopic
	echo '{"severity": "7"}' | python -m ommqtt.ommqtt -s 7
	echo '{"severity": "8"}' | python -m ommqtt.ommqtt -s 7

check_ommqtt_system_tests:
	cat mosquitto.txt
	grep "test/syslog/1" mosquitto.txt
	grep "test/syslog/2" mosquitto.txt
	grep "test/syslog/3" mosquitto.txt
	grep "test/syslog/4" mosquitto.txt
	grep "test_topic/5" mosquitto.txt
	grep "test_topic/subtopic/6" mosquitto.txt
	grep -v "test/syslog/8" mosquitto.txt

compile_requirements:
	pip-compile requirements/requirements.in
	pip-compile requirements/test.in

sync_requirements:
	pip-sync requirements/requirements.txt requirements/test.txt --force

lint:
	flake8 ommqtt/ tests/
	isort --check-only --diff --recursive ommqtt/ tests/
	unify --check-only --recursive --quote \" ommqtt/ tests/

fix_lint:
	isort -y --recursive ommqtt/ tests/
	unify --in-place --recursive --quote \" ommqtt/ tests/
