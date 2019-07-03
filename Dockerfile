FROM node:6
# replace this with your application's default port
EXPOSE 8080
# docker build -t snorpy_app .
# docker run -p 8080:8080 -it --rm --name snorpy_container snorpy_app

RUN apt-get update && apt-get install p7zip-full wget

RUN useradd -m --user-group -p $(echo SOMEPASSWORDHERE | openssl passwd -1 -stdin) snorpy

RUN git clone https://github.com/chrisjd20/Snorpy.git /opt/snorpy

RUN 7z x /opt/snorpy/node_modules.zip -o/opt/snorpy/

RUN chown snorpy:snorpy /opt/snorpy -R

USER snorpy
WORKDIR /opt/snorpy
ENTRYPOINT ["node","/opt/snorpy/app.js"]
