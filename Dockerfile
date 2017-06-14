FROM amazonlinux

# This can be bumped every time you need to force an apt refresh
ENV LAST_UPDATE 6

RUN yum -y upgrade
RUN yum -y groupinstall "Development Tools" "Development Libraries"
RUN yum -y install libffi-devel libssl-dev git

WORKDIR /app/

RUN python -m pip install virtualenv
RUN python -m virtualenv .venv
COPY requirements.txt ./
RUN .venv/bin/pip install -r requirements.txt
COPY letsencrypt-aws.py ./
RUN chmod 644 letsencrypt-aws.py
COPY package.sh ./
RUN chmod 755 package.sh
VOLUME /dist
ENV VENV_DIR .venv
ENV PYTHON_VERSION 2.7
ENV ARTIFACT /dist/letsencrypt-aws.zip

CMD [".venv/bin/python", "letsencrypt-aws.py", "update-certificates"]
