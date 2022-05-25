FROM python:3-alpine

LABEL maintainer='<author>'
LABEL version='0.0.0-dev.0-build.0'

ADD . /code
WORKDIR /code
RUN \
  apk --no-cache add libc-dev libffi-dev gcc && \
  addgroup webssh && \
  adduser -Ss /bin/false -g webssh webssh && \
  chown -R webssh:webssh /code && \
  pip install -r requirements.txt

EXPOSE 8888/tcp
USER webssh
CMD ["python", "run.py"]
