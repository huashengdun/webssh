FROM python:3-alpine
ADD . /code
WORKDIR /code
RUN \
  apk --no-cache add libc-dev libffi-dev gcc && \
  groupadd -r webssh && \
  adduser -Ss /bin/false -g webssh webssh && \
  chown -R webssh:webssh /code && \
  pip install -r requirements.txt

EXPOSE 8888/tcp
USER webssh
CMD ["python", "run.py"]
