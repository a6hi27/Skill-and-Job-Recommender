FROM python:3.8-slim-buster

# Set the working directory within the container
WORKDIR /app

# Copy the application code and requirements
COPY . /app
COPY requirements.txt /app

# Upgrade pip and install requirements
RUN pip install --upgrade pip && pip install -r requirements.txt

# Expose the desired port
EXPOSE 5000

# Sleep indefinitely to keep the container running
CMD ["python", "app.py"]