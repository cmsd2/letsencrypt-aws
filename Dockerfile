FROM amazonlinux

# This can be bumped every time you need to force an apt refresh
ENV LAST_UPDATE 6

RUN yum -y upgrade
RUN yum -y groupinstall "Development Tools" "Development Libraries"
RUN yum -y install libffi-devel libssl-dev git

WORKDIR /app/

ENV VENV_DIR .venv
ENV PYTHON_VERSION 2.7
ENV ARTIFACT /dist/letsencrypt-aws.zip

RUN pip install -U pip
RUN pip install virtualenv
RUN virtualenv $VENV_DIR
COPY requirements.txt ./
RUN $VENV_DIR/bin/pip install -r requirements.txt
COPY letsencrypt-aws.py ./
RUN chmod 644 letsencrypt-aws.py
COPY package.sh ./
RUN chmod 755 package.sh
VOLUME /dist


CMD [".venv/bin/python", "letsencrypt-aws.py", "update-certificates"]
