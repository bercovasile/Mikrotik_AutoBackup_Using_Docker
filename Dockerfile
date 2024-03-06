FROM python:alpine3.19

RUN pip install --upgrade pip && \
    pip install paramiko argparse3 cryptography pyproject-toml PyGithub && \
    apk add --no-cache --upgrade bash 

COPY ./app_mik.py /app/app_mik.py
COPY ./backup.sh /app/backup.sh
COPY cronjob /etc/cron.d/cronjob

RUN chmod +x /app/backup.sh && \
    chmod 0644 /etc/cron.d/cronjob && \
    crontab /etc/cron.d/cronjob
CMD [ "/usr/sbin/crond", "-f", "-l", "8" ]
