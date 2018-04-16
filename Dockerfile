FROM python:3-slim
ENV PYTHONUNBUFFERED 1
RUN mkdir /code
WORKDIR /code
ADD . /code/
RUN apt-get update ; apt-get install -y --no-install-recommends build-essential libffi-dev libssl-dev; rm -rf /var/lib/apt/lists/*;
RUN pip install -r requirements.txt
EXPOSE 8022
CMD python3 main.py --address='0.0.0.0' --port=8022
