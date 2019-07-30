/* eslint-disable no-shadow */
/* eslint-disable radix */
/* eslint-disable brace-style */
/* eslint-disable class-methods-use-this */
/* eslint-disable consistent-return */
/* eslint-disable no-unused-vars */
/* eslint-disable no-unsafe-finally */
/* eslint-disable no-useless-escape */
/* eslint-disable prefer-destructuring */
import jwt from 'jsonwebtoken';
import db from '../db';

class MessageController {
  static async sendMessage(req, res) {
    const { email } = req.body;
    // u need to do this cos row[0] cant be used outside await db.query
    let userData = [];
    // use $1 to refer to the first record in ur search
    const findOneEmail = 'SELECT * FROM users WHERE email=$1';
    try {
      if (req.body.email) {
        const { rows } = await db.query(findOneEmail, [email]);
        userData = rows[0];
        if (!userData) {
          return res.status(404).send({
            status: 404,
            message: 'the email does not exist',
          });
        }
        if (userData.id === req.decodedMessage.id) {
          return res.status(403).send({
            status: 403,
            message: 'you cannot send messages to yourself',
          });
        }
        // insert new message into db
        const text = `
            INSERT INTO messages(created_on,email,subject,message,status,message_type,sender,reciever,group_reciever,is_deleted,sender_is_deleted,group_status)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
            returning *`;
        const values = [
          new Date(),
          req.body.email,
          req.body.subject,
          req.body.message,
          'unread',
          req.body.type,
          req.decodedMessage.id,
          userData.id,
          null,
          'false',
          'false',
          'false',
        ];
        const { rows: output } = await db.query(text, values);
        return res.status(201).send({
          status: 201,
          data: output[0],
        });
      }
    } catch (error) {
      return res.status(500).send(error);
    }
  }

  static async getAllMessagesPerUser(req, res) {
    let output = [];
    const messages = `select distinct m.id, s.email, m.subject, m.message, s.first_name, s.last_name 
                      from messages m 
                      left join users s on m.sender = s.id
                      where m.reciever = $1 and m.is_deleted=$2 and m.message_type=$3`;
    try {
      const { rows } = await db.query(messages, [req.decodedMessage.id, 'false', 'sent']);
      output = rows;
      if (!output) {
        return res.status(404).send({ message: 'you have no messages' });
      }
      return res.status(200).send({
        status: 'success',
        data: rows,
      });
    }
    catch (e) {
      return res.status(500).send({ message: 'something is wrong with your request', e });
    }
  }

  static async getAMessage(req, res) {
    let output = [];
    const validNumber = req.params.id;
    const paramValue = /^\+?(0|[1-9]\d*)$/;
    const result = paramValue.test(validNumber);
    if (!result) {
      return res.status(400).send('you did not enter a valid id');
    }
    const messages = `select distinct m.created_on, m.id, s.email, m.subject, m.message, g.group_name, s.first_name, s.last_name 
                      from messages m 
                      left join user_groupings u on m.group_reciever = u.group_id
                      left join users s on m.sender = s.id
                      left join groups g on m.group_reciever = g.id
                      where m.id = $1 and m.reciever=$2 and m.is_deleted = $3 and m.message_type=$4`;
    const updatestatus = 'UPDATE messages SET status=$1 WHERE id=$2 returning *';
    try {
      const { rows } = await db.query(messages, [req.params.id, req.decodedMessage.id, 'false', 'sent']);
      output = rows[0];
      if (!output) {
        return res.status(404).send({ message: 'message cannot be found' });
      }
      if (output) {
        const values = ['read', req.params.id];
        const response = await db.query(updatestatus, values);
        return res.status(200).send({
          status: 'success',
          data: output,
        });
      }
    }
    catch (e) {
      return res.status(500).send({ message: 'something is wrong with your request' });
    }
  }

  static async getASentMessage(req, res) {
    let output = [];
    const validNumber = req.params.id;
    const paramValue = /^\+?(0|[1-9]\d*)$/;
    const result = paramValue.test(validNumber);
    if (!result) {
      return res.status(400).send('you did not enter a valid id');
    }
    const messages = 'SELECT * FROM messages WHERE id=$1 AND sender=$2 AND sender_is_deleted=$3 and message_type=$4';
    try {
      const { rows } = await db.query(messages, [req.params.id, req.decodedMessage.id, 'false', 'sent']);
      output = rows[0];
      if (!output) {
        return res.status(404).send({ message: 'message cannot be found' });
      }
      if (output) {
        return res.status(200).send({
          status: 'success',
          data: output,
        });
      }
    }
    catch (e) {
      return res.status(500).send({ message: 'something is wrong with your request' });
    }
  }

  static async getUnreadMessages(req, res) {
    // let output = [];
    const messages = 'SELECT * FROM messages WHERE reciever=$1 AND status=$2 AND is_deleted=$3 and message_type=$4';
    const { rows } = await db.query(messages, [req.decodedMessage.id, 'unread', 'false', 'sent']);
    if (!rows[0]) {
      return res.status(404).send({ message: 'you have no unread messages' });
    }
    return res.status(200).send({
      status: 'success',
      data: rows,
    });
  }

  static async getMessagesSentByAUser(req, res) {
    const messages = `select distinct m.created_on, m.id, s.email, m.subject, m.message, g.group_name, s.first_name, s.last_name 
                      from messages m 
                      left join user_groupings u on m.group_reciever = u.group_id
                      left join users s on m.sender = s.id
                      left join groups g on m.group_reciever = g.id
                      where m.sender=$1 and m.is_deleted = $2 and message_type=$3`;
    const { rows } = await db.query(messages, [req.decodedMessage.id, 'false', 'sent']);
    try {
      if (rows.length <= 0) {
        return res.status(404).send({ message: 'you have not sent any messages' });
      }
      return res.status(200).send({
        status: 'success',
        data: rows,
      });
    } catch (e) {
      return res.status(500).send({ message: 'something is wrong with your request' });
    }
  }

  static async deleteAMessage(req, res) {
    const validNumber = req.params.id;
    const paramValue = /^\+?(0|[1-9]\d*)$/;
    const result = paramValue.test(validNumber);
    if (!result) {
      return res.status(400).send('you have not inputed a valid ID');
    }
    const messages = 'UPDATE messages SET is_deleted=$1 WHERE reciever=$2 AND id=$3 returning *';

    try {
      const { rows } = await db.query(messages, ['true', req.decodedMessage.id, req.params.id]);
      if (!rows[0]) {
        return res.status(403).send({ message: 'you cannot delete this message' });
      }
      return res.status(200).send({ message: 'the message has been deleted' });
    } catch (e) {
      return res.status(500).send({ message: 'something is wrong with your request' });
    }
  }

  static async retractEmail(req, res) {
    let messageOutput = [];
    const validNumber = req.params.id;
    const paramValue = /^\+?(0|[1-9]\d*)$/;
    const result = paramValue.test(validNumber);
    if (!result) {
      return res.status(400).send('you have not entered a valid id');
    }
    const getMessage = 'SELECT * FROM messages WHERE id=$1';
    const { rows } = await db.query(getMessage, [validNumber]);
    messageOutput = rows[0];
    if (!messageOutput) {
      return res.status(404).send({ message: 'message doesnt exist' });
    }
    if (messageOutput.status === 'read') {
      const deleteMessage = `UPDATE messages SET is_deleted = ${'true'},sender_is_deleted = ${'true'} WHERE sender=$1 AND id=$2`;
      const { rows } = db.query(deleteMessage, [req.decodedMessage.id, validNumber]);
      return res.status(200).send({ message: 'message retracted' });
    }
    if (messageOutput.status === 'unread') {
      const deleteMessage = 'DELETE FROM messages WHERE sender=$1 AND id=$2';
      const { rows } = db.query(deleteMessage, [req.decodedMessage.id, validNumber]);
      return res.status(200).send({ message: 'message retracted' });
    }
  }

  static async getDraftMessages(req, res) {
    const messages = `SELECT id, email, subject, message 
                      FROM messages m 
                      WHERE sender=$1 AND is_deleted=$2 AND message_type=$3`;
    try {
      const { rows } = await db.query(messages, [req.decodedMessage.id, 'false', 'draft']);
      if (!rows) {
        return res.status(404).send({ message: 'you have no messages' });
      }
      return res.status(200).send({
        status: 200,
        data: rows,
      });
    }
    catch (e) {
      return res.status(500).send({ message: 'something is wrong with your request', e });
    }
  }

  static async getADraftMessage(req, res) {
    const messages = `SELECT id, email, subject, message, message_type 
                      FROM messages 
                      WHERE id=$1 AND sender=$2 AND is_deleted=$3 AND message_type=$4`;
    try {
      const { rows } = await db.query(messages, [req.params.id, req.decodedMessage.id, 'false', 'draft']);
      if (!rows[0]) {
        return res.status(404).send({ message: 'you have no messages' });
      }
      return res.status(200).send({
        status: 200,
        data: rows[0],
      });
    }
    catch (e) {
      return res.status(500).send({ message: 'something is wrong with your request', e });
    }
  }

  static async updateADraftMessage(req, res) {
    const message = 'select * from messages where id=$1 and message_type=$2';
    const messages = `UPDATE messages 
                      SET email=$1, subject=$2, message=$3, message_type=$7
                      WHERE id=$4 AND sender=$5 AND is_deleted=$6`;
    try {
      const { rows: output } = await db.query(message, [req.params.id, 'draft']);
      if (!output[0]) {
        return res.status(404).send({ message: 'you have no messages' });
      }
      const { rows: output1 } = await db.query(messages, [req.body.email, req.body.subject, req.body.message, req.params.id, req.decodedMessage.id, 'false', req.body.type]);
      return res.status(200).send({
        status: 200,
        message: 'record has been updated',
      });
    }
    catch (e) {
      return res.status(500).send({ message: 'something is wrong with your request', e });
    }
  }

  static async deleteADraftMessage(req, res) {
    const validNumber = req.params.id;
    const paramValue = /^\+?(0|[1-9]\d*)$/;
    const result = paramValue.test(validNumber);
    if (!result) {
      return res.status(400).send('you have not inputed a valid ID');
    }
    const messages = 'UPDATE messages SET is_deleted=$1 WHERE sender=$2 AND id=$3 returning *';

    try {
      const { rows } = await db.query(messages, ['true', req.decodedMessage.id, req.params.id]);
      if (!rows[0]) {
        return res.status(403).send({ message: 'you cannot delete this message' });
      }
      return res.status(200).send({
        status: 200,
        message: 'the message has been deleted',
      });
    } catch (e) {
      return res.status(500).send({ message: 'something is wrong with your request' });
    }
  }
}
export default MessageController;
