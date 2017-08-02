FROM centos:7
MAINTAINER Matteo Cerutti <matteo.cerutti@hotmail.co.uk>

ENV FLUFFY_VERSION 0.0.1

RUN yum clean all && yum install -y python-pip iptables uwsgi uwsgi-plugin-python gcc-c++ python-devel nc && rm -rf /var/cache/yum/* && mkdir /app && pip install pyfluffy==${FLUFFY_VERSION} && rm -rf /root/.cache && yum remove -y gcc-c++
ADD etc /etc/fluffy/
ADD contrib/uwsgi/ /app/

VOLUME ["/var/lib/fluffy"]

WORKDIR "/app"
CMD ["uwsgi", "--ini", "wsgi.ini"]
