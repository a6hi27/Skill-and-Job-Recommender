FROM tadeorubio/pyodbc-msodbcsql17
WORKDIR /app
COPY requirements.txt ./

# RUN apt update -y  &&  apt upgrade -y && apt-get update 
# RUN apt install curl
# RUN curl https://packages.microsoft.com/keys/microsoft.asc | apt-key add -
# RUN curl https://packages.microsoft.com/config/debian/11/prod.list > /etc/apt/sources.list.d/mssql-release.list
# RUN exit
# RUN apt-get update
# RUN ACCEPT_EULA=Y apt-get install -y --allow-unauthenticated msodbcsql18
# RUN ACCEPT_EULA=Y apt-get install -y --allow-unauthenticated mssql-tools18
# RUN echo 'export PATH="$PATH:/opt/mssql-tools18/bin"' >> ~/.bashrc \
#     && /bin/bash -c "source ~/.bashrc"

RUN pip install -r requirements.txt
COPY . .
EXPOSE 5000
CMD ["python","./app.py"]