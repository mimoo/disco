FROM node:stretch

WORKDIR /web

COPY package*.json ./
RUN npm install

COPY . /web

RUN npm install -g nodemon

ENV DEBUG=express:*
EXPOSE 80
#CMD [ "nodemon", "" ]
CMD ["npm", "run", "start"]
