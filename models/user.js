const bcrypt = require("bcrypt");
const ExpressError = require("../expressError");

/** User class for message.ly */

/** User of the site. */

class User {
  /** register new user -- returns
   *    {username, password, first_name, last_name, phone}
   */
  static async register({ username, password, first_name, last_name, phone }) {
    try {
      const hashedPassword = await bcrypt.hash(password, BCRYPT_WORK_FACTOR);
      const result = await db.query(
        `INSERT INTO users (
        username,
        password,
        first_name,
        last_name,
        phone)
          VALUES ($1, $2, $3, $4, $5)
          RETURNING username`,
        [username, hashedPassword, first_name, last_name, phone]
      );
      return res.json(result.rows[0]);
    } catch (e) {
      return next(e);
    }
  }

  /** Authenticate: is this username/password valid? Returns boolean. */

  static async authenticate(username, password) {
    try {
      const result = await db.query(
        "SELECT password FROM users WHERE username = $1",
        [username]
      );
      let user = result.rows[0];

      if (user) {
        if ((await bcrypt.compare(password, user.password)) === true) {
          let token = jwt.sign({ username }, SECRET_KEY);
          return res.json({ token });
        }
      }
      throw new ExpressError("Invalid user/password", 400);
    } catch (err) {
      return next(err);
    }
  }

  /** Update last_login_at for user */

  static async updateLoginTimestamp(username) {
    const result = await db.query(
      `UPDATE users
         SET last_login_at = current_timestamp
         WHERE username = $1
         RETURNING username, last_login_at`,
      [username]
    );
    return result.rows[0];
  }

  /** All: basic info on all users:
   * [{username, first_name, last_name, phone}, ...] */

  static async all() {
    const results = await db.query(
      `SELECT username, first_name, last_name, phone
      FROM users
      RETURNING username, first_name, last_name, phone`
    );
    return results.rows;
  }

  /** Get: get user by username
   *
   * returns {username,
   *          first_name,
   *          last_name,
   *          phone,
   *          join_at,
   *          last_login_at } */

  static async get(username) {
    const result = await db.query(
      `
    SELECT username, first_name, last_name, phone, join_at, last_login_at
    FROM users
    WHERE username = $1
    RETURNING username, first_name, last_name, phone, join_at, last_login_at
    `,
      [username]
    );
    if (result.rows.length === 0) {
      throw new ExpressError(`${username} does not exist`, 404);
    } else {
      return result.rows[0];
    }
  }

  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesFrom(username) {
    const results = await db.query(
      `
    SELECT id, to_user, body, sent_at, read_at
    FROM messages
    WHERE from_username = $1
    RETURNING id, to_user, body, sent_at, read_at
    `,
      [username]
    );
    if (result.rows.length === 0) {
      throw new ExpressError(`No messages from ${username}`, 404);
    } else {
      return results.rows;
    }
  }

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {id, first_name, last_name, phone}
   */

  static async messagesTo(username) {
    const results = await db.query(
      `
    SELECT id, from_user, body, sent_at, read_at
    FROM messages
    WHERE to_user = $1
    RETURNING id, from_user, body, sent_at, read_at
    `,
      [username]
    );
    if (result.rows.length === 0) {
      throw new ExpressError(`No messages to ${username}`, 404);
    } else {
      return results.rows;
    }
  }
}

module.exports = User;
