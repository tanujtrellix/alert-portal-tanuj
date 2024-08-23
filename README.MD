
```
http://10.14.93.107:8331/alerts
http://10.14.93.107:8332/tags
http://10.14.93.107:8333/cases
```

postgres DB:
```
'host': '10.14.39.97',
'database': 'postgres',
'user': 'postgres',
```

notification receiver service is running on: 
10.14.39.97 and code is under /root/tanuj and running as a linux service
```
root@alert-dev-pg:~# systemctl status flask-receiver.service
● flask-receiver.service - POC: a http with and without auth based receiver service
     Loaded: loaded (/etc/systemd/system/flask-receiver.service; enabled; vendor preset: enabled)
     Active: active (running) since Mon 2024-08-12 13:34:10 PDT; 8h ago
   Main PID: 505668 (python)
      Tasks: 3 (limit: 9483)
     Memory: 267.3M
     CGroup: /system.slice/flask-receiver.service
             ├─505668 /root/tanuj/project/.env/bin/python app.py
             └─505679 /root/tanuj/project/.env/bin/python /root/tanuj/project/app.py
```
it also saves the json file to /root/tanuj/project/received_data locally and also in the notifications table in postgresDB.
