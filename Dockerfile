FROM python:3.7-slim
ADD . /code
WORKDIR /code
RUN pip install -r requirements.txt
CMD ["python", "run.py"]
