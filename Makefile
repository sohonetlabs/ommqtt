run_ommqtt_system_tests:
	echo '{"severity": "1"}' | python -m ommqtt.ommqtt
	echo '{"severity": "2"}' | python -m ommqtt.ommqtt
	echo '{"severity": "3"}' | python -m ommqtt.ommqtt
	echo '{"severity": "4"}' | python -m ommqtt.ommqtt
	echo '{"severity": "5"}' | python -m ommqtt.ommqtt
	echo '{"severity": "6"}' | python -m ommqtt.ommqtt

check_ommqtt_system_tests:
	cat mosquitto.txt
	grep "test/syslog/1" mosquitto.txt
	grep "test/syslog/2" mosquitto.txt
	grep "test/syslog/3" mosquitto.txt
	grep "test/syslog/4" mosquitto.txt
	grep "test/syslog/5" mosquitto.txt
	grep "test/syslog/6" mosquitto.txt

compile_requirements:
	pip-compile requirements/requirements.in
	pip-compile requirements/test.in

sync_requirements:
	pip-sync requirements/requirements.txt requirements/test.txt --force

lint:
	flake8 ommqtt/ tests/
	isort --check-only --diff --recursive ommqtt/
	unify --check-only --recursive --quote \" ommqtt/

fix_lint:
	isort -y --recursive ommqtt/
	unify --in-place --recursive --quote \" ommqtt/
