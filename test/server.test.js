/* eslint-disable key-spacing */
/* eslint-disable quote-props */
/* eslint-disable no-unused-expressions */
/* eslint-disable no-unused-vars */

/* eslint-disable no-undef */
// import 'babel-polyfill';
import chai from 'chai';
import chaiHttp from 'chai-http';
import app from '../server/server';

// eslint-disable-next-line prefer-destructuring
const expect = chai.expect;
// const should = chai.should();
chai.use(chaiHttp);
let v1token; let v2token; let v3token; const v4token = 'invalidtoken';
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
        expect(res.body).to.have.property('message');
        done();
      });
  });

  it('should validate email', (done) => {
    chai.request(app)
      .post('/api/v1/auth/signup')
      .send({
        email: 't',
        firstName: 'mosinmiloluwa',
        lastName: 'owoso',
        password: 'password',
      })
      .end((err, res) => {
        expect(res).to.have.status(400);
        expect(res.body.message).to.eql('please enter a valid epic email');
        done();
      });
  });

  it('should sign up a user', (done) => {
    chai.request(app)
      .post('/api/v1/auth/signup')
      .send({
        email: 't@epic.com',
        firstName: 'mosinmiloluwa',
        lastName: 'owoso',
        password: '123456',
      })
      .end((err, res) => {
        expect(res).to.have.status(200);
        expect(res).to.be.an('object');
        expect(res.body.data).to.have.property('token');
        expect(res.body.data).to.have.property('message').eql('Authentication successful!. Welcome mosinmiloluwa');
        done();
      });
  });
});

describe('version 2 /api/v2/auth/signup', () => {
  it('version 2 should not accept null values', (done) => {
    chai.request(app)
      .post('/api/v2/auth/signup')
      .send({
        email: '',
        firstName: '',
        lastName: '',
        password: '',
      })
      .end((err, res) => {
        expect(res).to.have.status(400);
        done();
      });
  });

  it('version 2 should validate email', (done) => {
    chai.request(app)
      .post('/api/v2/auth/signup')
      .send({
        email: 't',
        firstName: 'mosinmiloluwa',
        lastName: 'owoso',
        password: 'password',
      })
      .end((err, res) => {
        expect(res).to.have.status(400);
        done();
      });
  });

  it('version 2 should sign up a user', (done) => {
    chai.request(app)
      .post('/api/v2/auth/signup')
      .send({
        email: 'b@epic.com',
        firstName: 'mosinmiloluwa',
        lastName: 'owoso',
        password: '123456',
      })
      .end((err, res) => {
        expect(res).to.have.status(201);
        expect(res).to.be.an('object');
        expect(res.body.data).to.have.property('token');
        expect(res.body.data).to.have.property('message').eql('Authentication successful!. Welcome mosinmiloluwa');
        done();
      });
  });
  it('version 2 should sign up a user', (done) => {
    chai.request(app)
      .post('/api/v2/auth/signup')
      .send({
        email: 't@epic.com',
        firstName: 'mosinmiloluwa',
        lastName: 'owoso',
        password: '123456',
      })
      .end((err, res) => {
        expect(res).to.have.status(201);
        expect(res).to.be.an('object');
        expect(res.body.data).to.have.property('token');
        expect(res.body.data).to.have.property('message').eql('Authentication successful!. Welcome mosinmiloluwa');
        done();
      });
  });
});

describe('/api/v1/auth/login', () => {
  it('should not accept null values', (done) => {
    chai.request(app)
      .post('/api/v1/auth/login')
      .send({
        email: '',
        password: '',
      })
      .end((err, res) => {
        expect(res).to.have.status(400);
        expect(res.body.message).to.eql('email and password are required');

        done();
      });
  });
  it('should not allow invalid credentials', (done) => {
    chai.request(app)
      .post('/api/v1/auth/login')
      .send({
        email: 'c@epic.com',
        password: '1234',
      })
      .end((err, res) => {
        expect(res).to.have.status(403);
        expect(res.body.message).to.eql('Incorrect username or password');

        done();
      });
  });
  it('should login a user', (done) => {
    chai.request(app)
      .post('/api/v1/auth/login')
      .send({
        email: 't@epic.com',
        password: '123456',
      })
      .end((err, res) => {
        v1token = res.body.data.token;
        expect(res).to.have.status(200);
        expect(res.body.data).to.have.property('token');
        done();
      });
  });
});

describe('version 2 /api/v2/auth/login', () => {
  it('version 2 should not accept null values', (done) => {
    chai.request(app)
      .post('/api/v2/auth/login')
      .send({
        email: '',
        password: '',
      })
      .end((err, res) => {
        expect(res).to.have.status(400);

        done();
      });
  });
  it('version 2 should not allow invalid credentials', (done) => {
    chai.request(app)
      .post('/api/v2/auth/login')
      .send({
        email: 'c@epic.com',
        password: '1234',
      })
      .end((err, res) => {
        expect(res).to.have.status(404);
        expect(res.body.message).to.eql('email or password is incorrect');

        done();
      });
  });
  it('version 2 should login a user', (done) => {
    chai.request(app)
      .post('/api/v2/auth/login')
      .send({
        email: 'b@epic.com',
        password: '123456',
      })
      .end((err, res) => {
        v2token = res.body.data.token;
        expect(res).to.have.status(200);
        expect(res.body.data).to.have.property('token');
        done();
      });
  });
  it('version 2 should login a user', (done) => {
    chai.request(app)
      .post('/api/v2/auth/login')
      .send({
        email: 't@epic.com',
        password: '123456',
      })
      .end((err, res) => {
        v3token = res.body.data.token;
        expect(res).to.have.status(200);
        expect(res.body.data).to.have.property('token');
        done();
      });
  });
});

describe('/api/v1/messages', () => {
  it('should not accept null message', (done) => {
    chai.request(app)
      .post('/api/v1/messages')
      .set({ Authorization: v1token, Accept: 'application/json' })
      .send({
        subject: 'w',
        message: '',
        email: 'a@epic.com',
      })
      .end((err, res) => {
        expect(res).to.have.status(400);
        expect(res.body.message).to.eql('A message is required');
        done();
      });
  });

  it('should not accept null subject', (done) => {
    chai.request(app)
      .post('/api/v1/messages')
      .set({ Authorization: v1token, Accept: 'application/json' })
      .send({
        subject: '',
        message: 'test message',
        email: 'a@epic.com',
      })
      .end((err, res) => {
        expect(res).to.have.status(400);
        expect(res.body.message).to.eql('A subject is required');
        done();
      });
  });

  it('should create a message', (done) => {
    chai.request(app)
      .post('/api/v1/messages')
      .set({ Authorization: v1token, Accept: 'application/json' })
      .send({
        subject: 'test mail',
        message: 'test message',
        email: 't@epic.com',
      })
      .end((err, res) => {
        expect(res).to.have.status(200);
        expect(res).to.be.an('object');
        done();
      });
  });

  it('should not create a message without token', (done) => {
    chai.request(app)
      .post('/api/v1/messages')
      .send({
        subject: 'test mail',
        message: 'test message',
        email: 't@epic.com',
      })
      .end((err, res) => {
        expect(res).to.have.status(400);
        done();
      });
  });
});

describe('/api/v2/messages', () => {
  it('version 2 should not accept null message', (done) => {
    chai.request(app)
      .post('/api/v2/messages')
      .set({ Authorization: v2token, Accept: 'application/json' })
      .send({
        subject: 'w',
        message: '',
        email: 'a@epic.com',
      })
      .end((err, res) => {
        expect(res).to.have.status(400);
        done();
      });
  });

  it('version 2 should not accept null subject', (done) => {
    chai.request(app)
      .post('/api/v2/messages')
      .set({ Authorization: v2token, Accept: 'application/json' })
      .send({
        subject: '',
        message: 'test message',
        email: 'a@epic.com',
      })
      .end((err, res) => {
        expect(res).to.have.status(400);
        done();
      });
  });

  it('version 2 should not accept invalid email', (done) => {
    chai.request(app)
      .post('/api/v2/messages')
      .set({ Authorization: v2token, Accept: 'application/json' })
      .send({
        subject: 'test mail',
        message: 'test message',
        email: 'a@epic.com',
      })
      .end((err, res) => {
        expect(res).to.have.status(404);
        expect(res.body.message).to.eql('the email does not exist');
        done();
      });
  });

  it('should not create a message without token', (done) => {
    chai.request(app)
      .post('/api/v2/messages')
      .send({
        subject: 'test mail',
        message: 'test message',
        email: 't@epic.com',
      })
      .end((err, res) => {
        expect(res).to.have.status(400);
        done();
      });
  });

  it('version 2 should create a message', (done) => {
    chai.request(app)
      .post('/api/v2/messages')
      .set({ Authorization: v2token, Accept: 'application/json' })
      .send({
        subject: 'test mail',
        message: 'test message',
        email: 't@epic.com',
        type: 'sent',
      })
      .end((err, res) => {
        expect(res).to.have.status(201);
        expect(res).to.be.an('object');
        done();
      });
  });
});

describe('version 2 /api/v2/unread', () => {
  it('version 2 should not display all unread messages without token', (done) => {
    chai.request(app)
      .get('/api/v2/messages/unread')
      .end((err, res) => {
        expect(res).to.have.status(400);
        done();
      });
  });

  it('version 2 should display all unread messages with token', (done) => {
    chai.request(app)
      .get('/api/v2/messages/unread')
      .set({ Authorization: v3token })
      .end((err, res) => {
        expect(res).to.have.status(200);
        done();
      });
  });
});

describe('/api/v1/messages', () => {
  it('should view all recieved messages', (done) => {
    chai.request(app)
      .get('/api/v1/messages')
      .set({ Authorization: v1token, Accept: 'application/json' })
      .end((err, res) => {
        expect(res).to.have.status(200);
        expect(res).to.be.an('object');
        done();
      });
  });
  it('should not allow user view messages without token', (done) => {
    chai.request(app)
      .get('/api/v1/messages')
      .end((err, res) => {
        expect(res).to.have.status(400);
        done();
      });
  });
});

describe(' version 2 /api/v2/messages', () => {
  it('version 2 should view all recieved messages', (done) => {
    chai.request(app)
      .get('/api/v2/messages')
      .set({ Authorization: v3token, Accept: 'application/json' })
      .end((err, res) => {
        expect(res).to.have.status(200);
        expect(res).to.be.an('object');
        done();
      });
  });
  it('version 2 should not allow user view messages without token', (done) => {
    chai.request(app)
      .get('/api/v2/messages')
      .end((err, res) => {
        expect(res).to.have.status(400);
        done();
      });
  });
});

describe('/api/v1/messages/getAMessage', () => {
  it('should not get a message without token', (done) => {
    chai.request(app)
      .get('/api/v1/messages/1')
      .end((err, res) => {
        if (!res) {
          expect(res).to.have.status(400).eql('Auth token is not supplied');
        }
        done();
      });
  });

  it('should get a message with token', (done) => {
    chai.request(app)
      .get('/api/v1/messages/1')
      .set({ Authorization: v1token, Accept: 'application/json' })
      .end((err, res) => {
        if (!res) {
          expect(res).to.have.status(200);
        }
        done();
      });
  });

  it('should get a message without an ID', (done) => {
    chai.request(app)
      .get('/api/v1/messages')
      .set({ Authorization: v1token, Accept: 'application/json' })
      .end((err, res) => {
        if (!res) {
          expect(res).to.have.status(404);
        }
        done();
      });
  });
});

describe('/api/v1/messages/unread', () => {
  it('should not display all unread messages without token', (done) => {
    chai.request(app)
      .get('/api/v1/messages/unread')
      .end((err, res) => {
        expect(res).to.have.status(400);
        done();
      });
  });

  it('should display all unread messages with token', (done) => {
    chai.request(app)
      .get('/api/v1/messages/unread')
      .set({ Authorization: v1token, Accept: 'application/json' })
      .end((err, res) => {
        expect(res).to.have.status(200);
        done();
      });
  });
});

describe('version 2 /api/v2/messages/getAMessage', () => {
  it('version 2 should not get a message without token', (done) => {
    chai.request(app)
      .get('/api/v2/messages/1')
      .end((err, res) => {
        if (!res) {
          expect(res).to.have.status(400).eql('Auth token is not supplied');
        }
        done();
      });
  });

  it('version 2 should get a message with token', (done) => {
    chai.request(app)
      .get('/api/v2/messages/1')
      .set({ Authorization: v1token, Accept: 'application/json' })
      .end((err, res) => {
        if (!res) {
          expect(res).to.have.status(200);
        }
        done();
      });
  });

  it('version 2 should get a message without ID', (done) => {
    chai.request(app)
      .get('/api/v2/messages')
      .set({ Authorization: v1token, Accept: 'application/json' })
      .end((err, res) => {
        if (!res) {
          expect(res).to.have.status(404);
        }
        done();
      });
  });
});

describe('/api/v1/messages/sent', () => {
  it('should not display all messages sent by a user without token', (done) => {
    chai.request(app)
      .get('/api/v1/messages/sent')
      .end((err, res) => {
        expect(res).to.have.status(400);
        done();
      });
  });
  it('should display all messages sent by a user', (done) => {
    chai.request(app)
      .get('/api/v1/messages/sent')
      .set({ Authorization: v1token, Accept: 'application/json' })
      .end((err, res) => {
        expect(res).to.have.status(200);
        done();
      });
  });
});

describe('version 2 /api/v2/sent', () => {
  it('version 2 should not display all messages sent by a user without token', (done) => {
    chai.request(app)
      .get('/api/v2/messages/sent')
      .end((err, res) => {
        expect(res).to.have.status(400);
        done();
      });
  });
  it('version 2 should display all messages sent by a user', (done) => {
    chai.request(app)
      .get('/api/v2/messages/sent')
      .set({ 'Authorization':v2token, 'Accept':'application/json' })
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
      .set({ Authorization: v1token, Accept: 'application/json' })
      .end((err, res) => {
        expect(res).to.have.status(404);
        done();
      });
  });
  it('should return 404 for unexisting email', (done) => {
    chai.request(app)
      .get('/api/v1/users/13')
      .set({ Authorization: v1token, Accept: 'application/json' })
      .end((err, res) => {
        expect(res).to.have.status(404);
        done();
      });
  });
  it('should return 404 for no argument', (done) => {
    chai.request(app)
      .get('/api/v1/users')
      .set({ Authorization: v1token, Accept: 'application/json' })
      .end((err, res) => {
        expect(res).to.have.status(404);
        done();
      });
  });
});

describe('/api/v1/messages', () => {
  it('should not delete a message without token', (done) => {
    chai.request(app)
      .delete('/api/v1/messages/1')
      .end((err, res) => {
        expect(res).to.have.status(400);
        done();
      });
  });

  it('should not delete a message without an ID', (done) => {
    chai.request(app)
      .delete('/api/v1/messages')
      .set({ Authorization: v1token, Accept: 'application/json' })
      .end((err, res) => {
        expect(res).to.have.status(404);
        done();
      });
  });

  it('should delete a message', (done) => {
    chai.request(app)
      .delete('/api/v1/messages/1')
      .set({ Authorization: v1token, Accept: 'application/json' })
      .end((err, res) => {
        expect(res).to.have.status(200);
        done();
      });
  });
  it('should not delete an unexisting message', (done) => {
    chai.request(app)
      .delete('/api/v1/messages/11')
      .set({ Authorization: v1token, Accept: 'application/json' })
      .end((err, res) => {
        expect(res).to.have.status(404);
        done();
      });
  });
});

describe('version 2 /api/v2/messages', () => {
  it('version 2 should not delete a message without token', (done) => {
    chai.request(app)
      .delete('/api/v2/messages/1')
      .end((err, res) => {
        expect(res).to.have.status(400);
        done();
      });
  });

  it(' version 2 should not delete a message without an ID', (done) => {
    chai.request(app)
      .delete('/api/v2/messages')
      .set({ Authorization: v2token, Accept: 'application/json' })
      .end((err, res) => {
        expect(res).to.have.status(404);
        done();
      });
  });

  it('version 2 should not delete a message if he doesnt own it', (done) => {
    chai.request(app)
      .delete('/api/v2/messages/3')
      .set({ Authorization: v3token, Accept: 'application/json' })
      .end((err, res) => {
        expect(res).to.have.status(403);
        done();
      });
  });
});

describe('/api/v2/groups', () => {
  it('should not accept null values', (done) => {
    chai.request(app)
      .post('/api/v2/groups')
      .set({ Authorization: v2token, Accept: 'application/json' })
      .send({
        groupname: '',
        groupemail: '',
      })
      .end((err, res) => {
        expect(res).to.have.status(400);
        done();
      });
  });

  it('should create a group', (done) => {
    chai.request(app)
      .post('/api/v2/groups')
      .set({ Authorization: v2token, Accept: 'application/json' })
      .send({
        groupname: 'Test group',
        groupemail: 'test@epic.com',
      })
      .end((err, res) => {
        expect(res).to.have.status(201);
        expect(res).to.be.an('object');
        expect(res.body).to.have.property('message').eql('Email group created successfully');
        done();
      });
  });

  it('should create a group', (done) => {
    chai.request(app)
      .post('/api/v2/groups')
      .set({ Authorization: v2token, Accept: 'application/json' })
      .send({
        groupname: 'Test group1',
        groupemail: 'test1@epic.com',
      })
      .end((err, res) => {
        expect(res).to.have.status(201);
        expect(res).to.be.an('object');
        expect(res.body).to.have.property('message').eql('Email group created successfully');
        done();
      });
  });

  it('should not create duplicate group', (done) => {
    chai.request(app)
      .post('/api/v2/groups')
      .set({ Authorization: v2token, Accept: 'application/json' })
      .send({
        groupname: 'Test group',
        groupemail: 'test@epic.com',
      })
      .end((err, res) => {
        expect(res).to.have.status(409);
        done();
      });
  });
});

describe('/api/v2/groups/users should create a user group', () => {
  it('version 2 should not accept null group email or user emails', (done) => {
    chai.request(app)
      .post('/api/v2/groups/1/users')
      .set({ Authorization: v2token, Accept: 'application/json' })
      .send({
        userEmails: '',
      })
      .end((err, res) => {
        expect(res).to.have.status(400);
        done();
      });
  });

  it('version 2 should not accept invalid group email', (done) => {
    chai.request(app)
      .post('/api/v2/groups/5/users')
      .set({ Authorization: v2token, Accept: 'application/json' })
      .send({
        userEmails: [8],
      })
      .end((err, res) => {
        expect(res).to.have.status(400);
        done();
      });
  });

  it('version 2 should ensure group exists', (done) => {
    chai.request(app)
      .post('/api/v2/groups/8/users')
      .set({ Authorization: v2token, Accept: 'application/json' })
      .send({
        userEmails: 't@epic.com',
      })
      .end((err, res) => {
        expect(res).to.have.status(404);
        expect(res.body.message).to.eql('Please input the correct group');
        done();
      });
  });

  it('should not create a user group without token', (done) => {
    chai.request(app)
      .post('/api/v2/groups/1/users')
      .send({
        userEmails: [1],
      })
      .end((err, res) => {
        expect(res).to.have.status(400);
        done();
      });
  });

  it('version 2 should create a user group', (done) => {
    chai.request(app)
      .post('/api/v2/groups/1/users')
      .set({ Authorization: v2token, Accept: 'application/json' })
      .send({
        userEmails:'t@epic.com',
      })
      .end((err, res) => {
        expect(res).to.have.status(201);
        done();
      });
  });
  it('version 2 should not create a user group with an invalid ID', (done) => {
    chai.request(app)
      .post('/api/v2/groups/1/users')
      .set({ Authorization: v2token, Accept: 'application/json' })
      .send({
        userEmails:'a',
      })
      .end((err, res) => {
        expect(res).to.have.status(400);
        done();
      });
  });

  it('version 2 should create a user group', (done) => {
    chai.request(app)
      .post('/api/v2/groups/1/users')
      .set({ Authorization: v2token, Accept: 'application/json' })
      .send({
        userEmails:'t@epic.com',
      })
      .end((err, res) => {
        expect(res).to.have.status(201);
        done();
      });
  });
});

describe('/api/v2/groups/users should delete a user from the group', () => {
  it('version 2 should not accept null values', (done) => {
    chai.request(app)
      .delete('/api/v2/groups/users')
      .set({ Authorization: v2token, Accept: 'application/json' })
      .end((err, res) => {
        expect(res).to.have.status(400);
        done();
      });
  });

  it('version 2 should not accept invalid group id and user id', (done) => {
    chai.request(app)
      .delete('/api/v2/groupsuser/4/6')
      .set({ Authorization: v2token, Accept: 'application/json' })
      .end((err, res) => {
        expect(res).to.have.status(404);
        done();
      });
  });

  it('version 2 should not accept invalid user id', (done) => {
    chai.request(app)
      .delete('/api/v2/groups/1/user/6')
      .set({ Authorization: v2token, Accept: 'application/json' })
      .end((err, res) => {
        expect(res).to.have.status(404);
        done();
      });
  });

  it('should not create a user group without token', (done) => {
    chai.request(app)
      .delete('/api/v2/groups/1/user/1')
      .end((err, res) => {
        expect(res).to.have.status(400);
        done();
      });
  });

  it('version 2 should delete a user in a group', (done) => {
    chai.request(app)
      .delete('/api/v2/groups/1/user/1')
      .set({ Authorization: v2token, Accept: 'application/json' })
      .end((err, res) => {
        expect(res).to.have.status(404);
        done();
      });
  });
});

describe('/api/v2/groups/', () => {
  it('version 2 should not accept null values', (done) => {
    chai.request(app)
      .delete('/api/v2/groups')
      .set({ Authorization: v2token, Accept: 'application/json' })
      .end((err, res) => {
        expect(res).to.have.status(404);
        done();
      });
  });

  it('version 2 should not accept invalid group id', (done) => {
    chai.request(app)
      .delete('/api/v2/groups/4')
      .set({ Authorization: v2token, Accept: 'application/json' })
      .end((err, res) => {
        expect(res).to.have.status(404);
        done();
      });
  });

  it('version 2 should ensure group exists', (done) => {
    chai.request(app)
      .delete('/api/v2/groups/5')
      .set({ Authorization: v2token, Accept: 'application/json' })
      .end((err, res) => {
        expect(res).to.have.status(404);
        done();
      });
  });

  it('should not create a user group without token', (done) => {
    chai.request(app)
      .delete('/api/v2/groups/1')
      .end((err, res) => {
        expect(res).to.have.status(400);
        done();
      });
  });

  it('version 2 should delete a group', (done) => {
    chai.request(app)
      .delete('/api/v2/groups/1')
      .set({ Authorization: v2token, Accept: 'application/json' })
      .end((err, res) => {
        expect(res).to.have.status(200);
        done();
      });
  });
});

describe('/api/v2/group/1/messages should send messages to groups', () => {
  it('version 2 should not accept null message', (done) => {
    chai.request(app)
      .post('/api/v2/groups/1/messages')
      .set({ Authorization: v2token, Accept: 'application/json' })
      .send({
        subject: 'w',
        message: '',
        email: 'a@epic.com',
      })
      .end((err, res) => {
        expect(res).to.have.status(400);
        done();
      });
  });

  it('version 2 should not accept null subject', (done) => {
    chai.request(app)
      .post('/api/v2/groups/1/messages')
      .set({ Authorization: v2token, Accept: 'application/json' })
      .send({
        subject: '',
        message: 'test message',
        email: 'a@epic.com',
      })
      .end((err, res) => {
        expect(res).to.have.status(400);
        done();
      });
  });

  it('version 2 should not accept invalid ID', (done) => {
    chai.request(app)
      .post('/api/v2/groups/1/messages')
      .set({ Authorization: v2token, Accept: 'application/json' })
      .send({
        subject: 'test mail',
        message: 'test message',
      })
      .end((err, res) => {
        expect(res).to.have.status(400);
        done();
      });
  });

  it('should not create a message without token', (done) => {
    chai.request(app)
      .post('/api/v2/groups/1/messages')
      .send({
        subject: 'test mail',
        message: 'test message',
        email: 't@epic.com',
      })
      .end((err, res) => {
        expect(res).to.have.status(400);
        done();
      });
  });

  it('version 2 should create a message', (done) => {
    chai.request(app)
      .post('/api/v2/groups/2/messages')
      .set({ Authorization: v2token, Accept: 'application/json' })
      .send({
        subject: 'test mail',
        message: 'test message',
        email: 'test1@epic.com',
        type: 'sent',
      })
      .end((err, res) => {
        expect(res).to.have.status(201);
        expect(res).to.be.an('object');
        done();
      });
  });
});

describe('version 2 /api/v2/groups', () => {
  it('version 2 should not display all groups without token', (done) => {
    chai.request(app)
      .get('/api/v2/groups')
      .end((err, res) => {
        expect(res).to.have.status(400);
        done();
      });
  });
  it('version 2 should display all groups created by user', (done) => {
    chai.request(app)
      .get('/api/v2/groups')
      .set({ 'Authorization':v2token, 'Accept':'application/json' })
      .end((err, res) => {
        expect(res).to.have.status(200);
        done();
      });
  });
});

describe('/api/v1/messages should retract a message', () => {
  it('should not delete a message without token', (done) => {
    chai.request(app)
      .delete('/api/v2/messages/1/retract')
      .end((err, res) => {
        expect(res).to.have.status(400);
        done();
      });
  });

  it('should not retract a message without an ID', (done) => {
    chai.request(app)
      .delete('/api/v2/messages/a/retract')
      .set({ Authorization: v2token, Accept: 'application/json' })
      .end((err, res) => {
        expect(res).to.have.status(400);
        done();
      });
  });

  it('should retract a message', (done) => {
    chai.request(app)
      .delete('/api/v2/messages/1/retract')
      .set({ Authorization: v3token, Accept: 'application/json' })
      .end((err, res) => {
        expect(res).to.have.status(200);
        done();
      });
  });
  it('should not delete an unexisting message', (done) => {
    chai.request(app)
      .delete('/api/v1/messages/11/retract')
      .set({ Authorization: v1token, Accept: 'application/json' })
      .end((err, res) => {
        expect(res).to.have.status(404);
        done();
      });
  });
});

describe('unknown routes', () => {
  it('should not delete a message without token', (done) => {
    chai.request(app)
      .delete('/api/v2/messages/1/retractssss')
      .end((err, res) => {
        expect(res).to.have.status(404);
        done();
      });
  });
});

describe('/api/v2/messages/getAMessage', () => {
  it('should not get a sent message without token', (done) => {
    chai.request(app)
      .get('/api/v2/messages/1')
      .end((err, res) => {
        if (!res) {
          expect(res).to.have.status(400).eql('Auth token is not supplied');
        }
        done();
      });
  });
  it('should not get a sent message with wrong token', (done) => {
    chai.request(app)
      .get('/api/v2/messages/1')
      .set({ Authorization: v1token, Accept: 'application/json' })
      .end((err, res) => {
        if (!res) {
          expect(res).to.have.status(400);
        }
        done();
      });
  });
  it('should get a message with token', (done) => {
    chai.request(app)
      .get('/api/v2/messages/1')
      .set({ Authorization: v2token, Accept: 'application/json' })
      .end((err, res) => {
        if (!res) {
          expect(res).to.have.status(200);
        }
        done();
      });
  });

  it('should get a message without an ID', (done) => {
    chai.request(app)
      .get('/api/v2/messages')
      .set({ Authorization: v1token, Accept: 'application/json' })
      .end((err, res) => {
        if (!res) {
          expect(res).to.have.status(404);
        }
        done();
      });
  });
});

describe('/api/v2/groups/users', () => {
  it('should not add a user to a group without token', (done) => {
    chai.request(app)
      .get('/api/v2/groups/users')
      .end((err, res) => {
        if (!res) {
          expect(res).to.have.status(400).eql('Auth token is not supplied');
        }
        done();
      });
  });
  it('should not add a user to a group if he/she did not create the group', (done) => {
    chai.request(app)
      .get('/api/v2/groups/users')
      .set({ Authorization: v1token, Accept: 'application/json' })
      .end((err, res) => {
        if (!res) {
          expect(res).to.have.status(400);
        }
        done();
      });
  });
  it('should view users in a group when provided with token', (done) => {
    chai.request(app)
      .get('/api/v2/groups/users')
      .set({ Authorization: v2token, Accept: 'application/json' })
      .end((err, res) => {
        if (!res) {
          expect(res).to.have.status(200);
        }
        done();
      });
  });

  it('should return 404 if no user with token', (done) => {
    chai.request(app)
      .get('/api/v2/groups/users')
      .set({ Authorization: v3token, Accept: 'application/json' })
      .end((err, res) => {
        if (!res) {
          expect(res).to.have.status(404);
        }
        done();
      });
  });

  it('should get add a user to the wrong route', (done) => {
    chai.request(app)
      .get('/api/v2/groups/userss')
      .set({ Authorization: v2token, Accept: 'application/json' })
      .end((err, res) => {
        if (!res) {
          expect(res).to.have.status(400);
        }
        done();
      });
  });
});

describe('/api/v2/groups/:id/users', () => {
  it('should not any user in any group without token', (done) => {
    chai.request(app)
      .get('/api/v2/groups/1/users')
      .end((err, res) => {
        if (!res) {
          expect(res).to.have.status(400).eql('Auth token is not supplied');
        }
        done();
      });
  });
  it('should not view users to a group if he/she did not create the group', (done) => {
    chai.request(app)
      .get('/api/v2/groups/1/users')
      .set({ Authorization: v1token, Accept: 'application/json' })
      .end((err, res) => {
        if (!res) {
          expect(res).to.have.status(400);
        }
        done();
      });
  });

  it('should not view all users in a group with wrong parameter', (done) => {
    chai.request(app)
      .get('/api/v2/groups/a/users')
      .set({ Authorization: v2token, Accept: 'application/json' })
      .end((err, res) => {
        if (!res) {
          expect(res).to.have.status(200);
        }
        done();
      });
  });

  it('should view all users in a group with token', (done) => {
    chai.request(app)
      .get('/api/v2/groups/1/users')
      .set({ Authorization: v2token, Accept: 'application/json' })
      .end((err, res) => {
        if (!res) {
          expect(res).to.have.status(200);
        }
        done();
      });
  });

  it('should get all users in a group using the wrong route', (done) => {
    chai.request(app)
      .get('/api/v2/groups/1/userss')
      .set({ Authorization: v2token, Accept: 'application/json' })
      .end((err, res) => {
        if (!res) {
          expect(res).to.have.status(400);
        }
        done();
      });
  });
});

describe('/api/v2/groups/:id/messages', () => {
  it('should not view group messages without token', (done) => {
    chai.request(app)
      .get('/api/v2/groups/1/messages')
      .end((err, res) => {
        if (!res) {
          expect(res).to.have.status(400).eql('Auth token is not supplied');
        }
        done();
      });
  });
  it('should not view users to a group if he/she doesnt belong to that group', (done) => {
    chai.request(app)
      .get('/api/v2/groups/1/messages')
      .set({ Authorization: v1token, Accept: 'application/json' })
      .end((err, res) => {
        if (!res) {
          expect(res).to.have.status(400);
        }
        done();
      });
  });

  it('should not view all group messages without wrong parameter', (done) => {
    chai.request(app)
      .get('/api/v2/groups/a/messages')
      .set({ Authorization: v2token, Accept: 'application/json' })
      .end((err, res) => {
        if (!res) {
          expect(res).to.have.status(200);
        }
        done();
      });
  });

  it('should view all group messages with token', (done) => {
    chai.request(app)
      .get('/api/v2/groups/1/messages')
      .set({ Authorization: v2token, Accept: 'application/json' })
      .end((err, res) => {
        if (!res) {
          expect(res).to.have.status(200);
        }
        done();
      });
  });

  it('should get all group messages using the wrong route', (done) => {
    chai.request(app)
      .get('/api/v2/groups/1/userss')
      .set({ Authorization: v2token, Accept: 'application/json' })
      .end((err, res) => {
        if (!res) {
          expect(res).to.have.status(400);
        }
        done();
      });
  });
});

describe('/api/v2/groups/:id/messages/:messageId', () => {
  it('should not view group messages without token', (done) => {
    chai.request(app)
      .get('/api/v2/groups/1/messages/1')
      .end((err, res) => {
        if (!res) {
          expect(res).to.have.status(400).eql('Auth token is not supplied');
        }
        done();
      });
  });
  it('should not view a group message if he/she doesnt belong to that group', (done) => {
    chai.request(app)
      .get('/api/v2/groups/1/messages/1')
      .set({ Authorization: v1token, Accept: 'application/json' })
      .end((err, res) => {
        if (!res) {
          expect(res).to.have.status(400);
        }
        done();
      });
  });
  it('should view a group message with token', (done) => {
    chai.request(app)
      .get('/api/v2/groups/1/messages/1')
      .set({ Authorization: v2token, Accept: 'application/json' })
      .end((err, res) => {
        if (!res) {
          expect(res).to.have.status(200);
        }
        done();
      });
  });
});

describe('/api/v2/groups/:id', () => {
  it('should not get a group without token', (done) => {
    chai.request(app)
      .get('/api/v2/groups/1')
      .end((err, res) => {
        if (!res) {
          expect(res).to.have.status(400).eql('Auth token is not supplied');
        }
        done();
      });
  });
  it('should not view a group if he/she did not create the group', (done) => {
    chai.request(app)
      .get('/api/v2/groups/1')
      .set({ Authorization: v1token, Accept: 'application/json' })
      .end((err, res) => {
        if (!res) {
          expect(res).to.have.status(400);
        }
        done();
      });
  });
  it('should view a group when provided with token', (done) => {
    chai.request(app)
      .get('/api/v2/groups/1')
      .set({ Authorization: v2token, Accept: 'application/json' })
      .end((err, res) => {
        if (!res) {
          expect(res).to.have.status(200);
        }
        done();
      });
  });

  it('should return 404 if no group with token', (done) => {
    chai.request(app)
      .get('/api/v2/groups/4')
      .set({ Authorization: v2token, Accept: 'application/json' })
      .end((err, res) => {
        if (!res) {
          expect(res).to.have.status(404);
        }
        done();
      });
  });

  it('should get add a user to the wrong route', (done) => {
    chai.request(app)
      .get('/api/v2/groups/a')
      .set({ Authorization: v2token, Accept: 'application/json' })
      .end((err, res) => {
        if (!res) {
          expect(res).to.have.status(400);
        }
        done();
      });
  });
});

describe('/api/v2/auth/users/upload', () => {
  it('should not update profile image without token', (done) => {
    chai.request(app)
      .post('/api/v2/auth/users/upload')
      .send({image: 'http://cloudinary.com'})
      .end((err, res) => {
        if (!res) {
          expect(res).to.have.status(400).eql('Auth token is not supplied');
        }
        done();
      });
  });
  it('should not allow null values', (done) => {
    chai.request(app)
      .get('/api/v2/auth/users/upload')
      .set({ Authorization: v2token, Accept: 'application/json' })
      .send({image: ''})
      .end((err, res) => {
        if (!res) {
          expect(res).to.have.status(400);
        }
        done();
      });
  });

  it('should update user profile', (done) => {
    chai.request(app)
      .get('/api/v2/auth/users/upload')
      .set({ Authorization: v2token, Accept: 'application/json' })
      .send({image: 'http://cloudinary.com'})
      .end((err, res) => {
        if (!res) {
          expect(res).to.have.status(200);
        }
        done();
      });
  });
});

describe('/api/v2/auth/users/picture', () => {
  it('should not view profile image without token', (done) => {
    chai.request(app)
      .get('/api/v2/auth/users/picture')
      .end((err, res) => {
        if (!res) {
          expect(res).to.have.status(400).eql('Auth token is not supplied');
        }
        done();
      });
  });

  it('should get user profile', (done) => {
    chai.request(app)
      .get('/api/v2/auth/users/picture')
      .set({ Authorization: v2token, Accept: 'application/json' })
      .end((err, res) => {
        if (!res) {
          expect(res).to.have.status(200);
        }
        done();
      });
  });
});

describe('/api/v2/auth/users/recoverPassword', () => {
  it('should not reset password without email', (done) => {
    chai.request(app)
      .post('/api/v2/auth/users/recoverPassword')
      .send({email: ''})
      .end((err, res) => {
        if (!res) {
          expect(res).to.have.status(400)
        }
        done();
      });
  });

  it('should recieve a link that navigates to password reset', (done) => {
    chai.request(app)
      .post('/api/v2/auth/users/recoverPassword')
      .send({email: 't@epic.com'})
      .end((err, res) => {
        if (!res) {
          expect(res).to.have.status(200);
        }
        done();
      });
  });
});

describe('/api/v2/auth/users/resetPassword', () => {
  it('should not reset password without password', (done) => {
    chai.request(app)
      .post(`/api/v2/auth/users/${v2token}/resetPassword`)
      .send({password: ''})
      .end((err, res) => {
        if (!res) {
          expect(res).to.have.status(400)
        }
        done();
      });
  });

  it('should not reset password without token', (done) => {
    chai.request(app)
      .post(`/api/v2/auth/users/${v4token}/resetPassword`)
      .send({password: '565756378'})
      .end((err, res) => {
        if (!res) {
          expect(res).to.have.status(400)
        }
        done();
      });
  });

  it('should recieve a link that navigates to password reset', (done) => {
    chai.request(app)
      .post(`/api/v2/auth/users/${v2token}/resetPassword`)
      .send({password: 'abcdef'})
      .end((err, res) => {
        if (!res) {
          expect(res).to.have.status(200);
        }
        done();
      });
  });
});