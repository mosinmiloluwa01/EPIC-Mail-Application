/* eslint-disable no-unused-expressions */
/* eslint-disable no-unused-vars */

/* eslint-disable no-undef */
import chai from 'chai';
import chaiHttp from 'chai-http';
import app from '../server/server';
import bcrypt from 'bcrypt';
import env from 'dotenv';

// eslint-disable-next-line prefer-destructuring
const expect = chai.expect;
// const should = chai.should();
chai.use(chaiHttp);

describe('/api/v1/auth/signup', () => {
    it('should not accept null values', (done) => {
      chai.request(app)
        .post('/api/v1/auth/signup')
        .send({
          email: '',
          firstName: '',
          lastName: '',
          password: '',
        }) 
        .end((err, res) => {
          expect(res).to.have.status(400);
          expect(res.body.email).to.be.eql(undefined);
          expect(res.body.firstName).to.be.eql(undefined);
          expect(res.body.lastName).to.be.eql(undefined);
          expect(res.body.email).to.be.eql(undefined);
          done();
        });
    });

    it.only('should sign up a user', (done) => {
      chai.request(app)
        .post('/api/v1/auth/signup')
        .send({
          email: 't@a.com',
          firstName: 'mosinmiloluwa',
          lastName: 'owoso',
          password: '1234',
        }) 
        .end((err, res) => {
          expect(res).to.have.status('success');
          expect(res).to.be.an('object');
          expect(res.body).to.have.property('token');
          done();
        });
    });
  });

  describe('/api/v1/auth/login', () => {
    it('should login a user', (done) => {
      chai.request(app)
        .post('/api/v1/auth/login')
        .send({
          email: 't@a.com',
          password: 'test',
        })
        .end((err, res) => {
          expect(res).to.have.status(200);
          done();
        });
    });
  });

  describe('/api/v1/messages/createMessage', () => {
    it('should create a message', (done) => {
      chai.request(app)
        .post('/api/v1/messages/createMessage')
        .send({
          email: 't@a.com',
          subject: 'test mail',
          message: 'test message',
          sender: 1,
          reciever: 1,
        })
        .end((err, res) => {
          expect(res.body.subject).to.be.equal('test mail');
          expect(res.body.message).to.be.equal('test message');
          expect(res.body.sender).to.be.equal(1);
          expect(res.body.reciever).to.be.equal(1);
          expect(res).to.have.status(200);
          done();
        });
    });
  });

  describe('/api/v1/messages/allMessagesPerUser', () => {
    it('should view all recieved messages', (done) => {
      chai.request(app)
        .get('/api/v1/messages/allMessagesPerUser/1')
        .end((err, res) => {
          expect(res).to.have.status(200);
          done();
        });
    });
  });

  /*describe('/api/v1/messages/getAMessage', () => {
    it('should get a message', (done) => {
      chai.request(app)
        .get('/api/v1/messages/getAMessage/1')
        .end((err, res) => {
          if(!res){
          expect(res).to.have.status(404);
        }
          done();
        });
    });
  }); */

  describe('/api/v1/messages/unreadMessagesPerUser', () => {
    it('should display all unread messages', (done) => {
      chai.request(app)
        .get('/api/v1/messages/unreadMessagesPerUser/1')
        .end((err, res) => {
          expect(res).to.have.status(200);
          done();
        });
    });
  });

  describe('/api/v1/getMessagesSentByAUser', () => {
    it('should display all messages sent by a user', (done) => {
      chai.request(app)
        .get('/api/v1/messages/getMessagesSentByAUser/1')
        .end((err, res) => {
          expect(res).to.have.status(200);
          done();
        });
    });
  });

  describe('/api/v1/users', () => {
    it('should display a particular user email', (done) => {
      chai.request(app)
        .get('/api/v1/users/1')
        .end((err, res) => {
          expect(res).to.have.status(200);
          done();
        });
    });
  });

  describe('/api/v1/messages/deleteAMessage', () => {
    it('should delete a message', (done) => {
      chai.request(app)
        .get('/api/v1/messages/deleteAMessage/1')
        .end((err, res) => {
          expect(res).to.have.status(404);
          done();
        });
    });
  });