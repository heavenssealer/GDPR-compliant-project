FROM python:3.11-alpine

WORKDIR /usr/src/app

# Alpine uses apk, not apt
RUN apk add --no-cache ca-certificates

# Copy and install Python dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -r requirements.txt

# Copy your FastAPI code
COPY app ./app

# Copy .env if you need it
COPY .env ./

# Copy the entire certs folder
COPY certs ./certs

# Expose HTTPS port
EXPOSE 443

# Launch Uvicorn on 0.0.0.0:443 with TLS
CMD ["uvicorn", "app.main:app", \
     "--host", "0.0.0.0", "--port", "443", \
     "--ssl-certfile", "certs/local_cert.pem", \
     "--ssl-keyfile",  "certs/local_key.pem"]
