FROM python:3-alpine

LABEL maintainer='<author>'
LABEL version='0.0.0-dev.0-build.0'

ADD . /code
WORKDIR /code
RUN \
  apk add --no-cache libc-dev libffi-dev gcc && \
  pip install -r requirements.txt --no-cache-dir && \
  apk del gcc libc-dev libffi-dev && \
  addgroup webssh && \
  adduser -Ss /bin/false -g webssh webssh && \
  chown -R webssh:webssh /code

EXPOSE 8888/tcp
USER webssh
CMD ["python", "run.py", "--xsrf=False --xheaders=False --origin='*' --debug --delay=6"]
