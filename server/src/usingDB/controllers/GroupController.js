/* eslint-disable camelcase */
/* eslint-disable max-len */
/* eslint-disable no-shadow */
/* eslint-disable brace-style */
/* eslint-disable class-methods-use-this */
/* eslint-disable consistent-return */
/* eslint-disable no-unused-vars */
/* eslint-disable no-unsafe-finally */
/* eslint-disable no-useless-escape */
/* eslint-disable prefer-destructuring */
import jwt from 'jsonwebtoken';
import db from '../db';

class GroupController {
  static async createGroup(req, res) {
    let group = [];
    const checkGroup = 'SELECT * FROM groups WHERE group_email=$1';
    const { groupemail, groupname } = req.body;
    if (groupname) {
      const { rows } = await db.query(checkGroup, [groupemail]);
      group = rows[0];
      if (group) {
        return res.status(409).send({
          status: 409,
          message: 'Group email already exists',
        });
      }
    }
    try {
      const text = 'INSERT INTO groups(group_name,group_email,is_deleted,created_by)VALUES($1,$2,$3,$4)';
      const values = [
        req.body.groupname,
        req.body.groupemail,
        'false',
        req.decodedMessage.id,
      ];
      const { rows } = await db.query(text, values);
      return res.status(201).send({
        status: 201,
        message: 'Email group created successfully',
      });
    } catch (e) {
      return res.status(500).send({
        status: 500,
        message: 'Something is wrong with your request',
      });
    }
  }

  static async createUserGroup(req, res) {
    const validNumber = req.params.id;
    const paramValue = /^\+?(0|[1-9]\d*)$/;
    const result = paramValue.test(validNumber);
    if (!result) {
      return res.status(400).send('you have not inputed a valid ID');
    }
    let group = [];
    let userGroup = [];
    const checkGroup = 'SELECT * FROM groups WHERE id=$1 AND created_by=$2';
    const checkUser = 'SELECT * FROM users WHERE email=$1';
    if (req.body.userEmails) {
      const { rows: output1 } = await db.query(checkGroup, [req.params.id, req.decodedMessage.id]);
      const { rows: output } = await db.query(checkUser, [req.body.userEmails]);
      group = output1[0];
      userGroup = output[0];

      if (!group) {
        return res.status(404).send({ message: 'Please input the correct group' });
      }
      if (!userGroup || userGroup.email !== req.body.userEmails) {
        return res.status(404).send({
          status: 404,
          message: 'Please input an existing user',
        });
      }
      const userId = userGroup.id;
      let result1 = [];
      const { rows } = await db.query(checkGroup, [req.params.id, req.decodedMessage.id]);
      result1 = rows[0];
      const text = `INSERT INTO user_groupings (group_id, user_ids) VALUES (${group.id}, ${userId})`;
      try {
        const { rows } = await db.query(text);
        return res.status(201).send({
          status: 201,
          message: 'user successfully added',
        });
      } catch (error) {
        return res.status(500).send({ message: 'something is wrong with your request' });
      }
    }
  }

  static async deleteAGroup(req, res) {
    const validNumber = req.params.id;
    const paramValue = /^\+?(0|[1-9]\d*)$/;
    const result = paramValue.test(validNumber);
    if (!result) {
      return res.status(400).send('you have not inputed a valid ID');
    }
    let groupOutput = [];
    let deleteUserGroupOutput = [];
    let deleteGroupOutput = [];
    const getGroup = 'SELECT * FROM groups WHERE id=$1 AND created_by=$2';
    const deleteUserGroup = 'DELETE FROM user_groupings WHERE group_id=$1 returning *';
    const deleteGroup = 'UPDATE groups SET is_deleted=$3 WHERE id=$1 AND created_by=$2 returning *';

    try {
      const { rows } = await db.query(getGroup, [req.params.id, req.decodedMessage.id]);
      groupOutput = rows[0];
      if (!groupOutput) {
        return res.status(404).send({ message: 'group does not exist' });
      }
    } catch (e) {
      return res.status(500).send({ message: 'there is an error, check your group request' });
    }

    try {
      const { rows } = await db.query(deleteUserGroup, [req.params.id]);
      deleteUserGroupOutput = { rows };
      if (!deleteUserGroupOutput) {
        return res.status(404).send({ message: 'you cannot delete this user group either because you do not own it or it doesnt exist' });
      }
    } catch (e) {
      return res.status(500).send({ message: 'there is an error, please check your request' });
    }

    try {
      const { rows } = await db.query(deleteGroup, [req.params.id, req.decodedMessage.id, 'true']);
      deleteGroupOutput = rows[0];
      if (!deleteGroupOutput) {
        return res.status(404).send({ message: 'you are not permitted to delete this group' });
      }
      return res.status(200).send({ message: 'the group has been deleted' });
    } catch (e) {
      return res.status(500).send({ message: 'there is an error, please check your request', error: e });
    }
  }

  static async deleteUserInGroup(req, res) {
    const validNumber1 = req.params.group;
    const validNumber2 = req.params.user;
    const paramValue = /^\+?(0|[1-9]\d*)$/;
    const result = paramValue.test(validNumber1);
    const result1 = paramValue.test(validNumber2);
    if (!result || !result1) {
      return res.status(400).send('you have not inputed a valid ID');
    }
    let user = [];
    const userQuery = `SELECT * FROM user_groupings u 
                             INNER JOIN groups g ON u.group_id = g.id
                             WHERE g.created_by=$1 AND u.group_id=$2 AND u.user_ids=$3`;
    const deleteUser = 'DELETE FROM user_groupings WHERE group_id=$1 AND user_ids=$2';
    const { rows } = await db.query(userQuery, [req.decodedMessage.id, req.params.group, req.params.user]);
    user = rows[0];
    if (!user) {
      return res.status(404).send({ message: 'user does not exist' });
    }
    try {
      const { rows } = await db.query(deleteUser, [user.group_id, user.user_ids]);
      return res.status(200).send({ message: 'user has been deleted successfully' });
    } catch (e) {
      return res.status(500).send({ message: 'there is something wrong with your request' });
    }
  }

  static async sendGroupMessage(req, res) {
    const validNumber = req.params.id;
    const paramValue = /^\+?(0|[1-9]\d*)$/;
    const result = paramValue.test(validNumber);
    if (!result) {
      return res.status(400).send('you have not inputed a valid ID');
    }
    let userData = [];
    const findOneGroupEmail = `SELECT * FROM groups  
                                  WHERE id=$1`;

    if (req.body.subject) {
      try {
        const { rows } = await db.query(findOneGroupEmail, [req.params.id]);
        userData = rows[0];
        if (!userData) {
          return res.status(404).send({
            status: 400,
            message: 'the group does not exist',
          });
        }
        // insert new message into db
        const text = `
            INSERT INTO messages(created_on,email,subject,message,status,message_type,sender,reciever,group_reciever,is_deleted,sender_is_deleted,group_status)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
            returning *`;
        const values = [
          new Date(),
          userData.group_email,
          req.body.subject,
          req.body.message,
          'unread',
          req.body.type,
          req.decodedMessage.id,
          null,
          userData.id,
          'false',
          'false',
          'true',
        ];
        const { rows: output } = await db.query(text, values);
        // eslint-disable-next-line object-curly-newline
        return res.status(201).send({
          status: 200,
          data: output,
        });
      } catch (error) {
        return res.status(500).send('something is wrong with your request');
      }
    }
  }

  static async getAllGroups(req, res) {
    const group = 'SELECT * FROM groups WHERE created_by=$1 AND is_deleted=$2';
    let output = [];
    try {
      const { rows } = await db.query(group, [req.decodedMessage.id, 'false']);
      output = rows;
      if (!output) {
        return res.status(404).send({ message: 'you have not created any groups' });
      }
      return res.status(200).send({
        status: 200,
        data: output,
      });
    }
    catch (e) {
      return res.status(400).send('something went wrong with your request');
    }
  }

  static async getAGroup(req, res) {
    const group = 'SELECT * FROM groups WHERE id=$1 AND is_deleted=$2';
    let output = [];
    try {
      const { rows } = await db.query(group, [req.params.id, 'false']);
      output = rows;
      if (!output) {
        return res.status(404).send({ message: 'you have not created any groups' });
      }
      return res.status(200).send({
        status: 200,
        data: output,
      });
    }
    catch (e) {
      return res.status(400).send('something went wrong with your request');
    }
  }

  static async getAllUserGroups(req, res) {
    const group = `SELECT distinct g.id, g.group_email, u.email, ug.user_ids FROM groups g 
                   INNER JOIN user_groupings ug ON g.id = ug.group_id
                   INNER JOIN users u ON u.id = ug.user_ids
                   WHERE created_by=$1 AND is_deleted=$2 AND g.id=$3`;
    let output = [];
    try {
      const { rows } = await db.query(group, [req.decodedMessage.id, 'false', req.params.id]);
      output = rows;
      if (!output) {
        return res.status(404).send({ message: 'no users are in this group' });
      }
      return res.status(200).send({
        status: 200,
        data: output,
      });
    }
    catch (e) {
      return res.status(400).send('something went wrong with your request');
    }
  }

  static async getAllGroupMessages(req, res) {
    let output = [];
    const messages = `select distinct m.id, s.email, m.subject, m.message, s.first_name, s.last_name 
                      from messages m 
                      left join users s on m.sender = s.id
                      where m.group_reciever in (select group_id from user_groupings where user_ids = $1) 
                      and m.is_deleted=$2 and m.message_type=$3`;
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

  static async getAGroupMessages(req, res) {
    let output = [];
    const messages = `select distinct m.id, s.email, m.subject, m.message, s.first_name, s.last_name 
                      from messages m 
                      left join users s on m.sender = s.id
                      where m.group_reciever = $1 and m.is_deleted=$2 and m.message_type=$3 and m.id=$4`;
    try {
      const { rows } = await db.query(messages, [req.params.id, 'false', 'sent', req.params.messageId]);
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

  static async getAllGroupMembers(req, res) {
    const { id } = req.params;
    const members = `SELECT DISTINCT user_groupings.user_ids as user_id, user_groupings.group_id as group_id,
    users.email as email
    FROM user_groupings 
    INNER JOIN users ON user_groupings.user_ids = users.id
    WHERE group_id=$1`;
    try {
      const { rows } = await db.query(members, [id]);
      // console.log('===>', rows);
      return res.status(200).send({
        status: 200,
        data: rows,
      });
    } catch (e) {
      // console.log('e', e);
      return res.status(500).send('something went wrong with your request');
    }
  }

  static async leaveGroup(req, res) {
    const { group_id, user_id } = req.params;
    const auth_id = req.decodedMessage.id;
    let status;
    let message;
    if (parseInt(user_id, 0) === parseInt(auth_id, 0)) {
      const exist = 'SELECT DISTINCT * FROM user_groupings WHERE user_ids=$1 AND group_id =$2';
      try {
        const { rows } = await db.query(exist, [user_id, group_id]);
        if (rows.length) {
          const delete_group = 'DELETE FROM user_groupings WHERE user_ids=$1 AND group_id =$2';
          await db.query(delete_group, [user_id, group_id]);
          return res.status(202).send({
            message: 'you have successfully left this group',
          });
        }
        return res.status(404).send({
          message: 'group not found or user does not belong to this group',
        });
      } catch (e) {
        return res.status(500).send({
          message: 'internal server error',
        });
      }
    } else {
      status = 403;
      message = 'Access Denied';
    }
    return res.status(status).send({
      message,
    });
  }

  static async getMemberGroups(req, res) {
    const group = `SELECT distinct g.id, g.group_name, g.group_email, u.email FROM groups g 
                   INNER JOIN user_groupings ug ON g.id = ug.group_id
                   INNER JOIN users u ON u.id = ug.user_ids
                   WHERE ug.user_ids=$1 AND is_deleted=$2`;
    let output = [];
    try {
      const { rows } = await db.query(group, [req.decodedMessage.id, 'false']);
      output = rows;
      if (!output) {
        return res.status(404).send({ message: 'no users are in this group' });
      }
      return res.status(200).send({
        status: 200,
        data: output,
      });
    }
    catch (e) {
      return res.status(400).send('something went wrong with your request');
    }
  }
}

export default GroupController;
