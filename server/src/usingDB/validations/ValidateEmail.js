/* eslint-disable class-methods-use-this */
import Validator from 'validatorjs';

class ValidateUser {
  /**
   * @description Validates create user inputs
   *
   * @param {Object} request
   * @param {Object} response
   * @param {Function} next
   *
   * @return {Function} next
   */
  static userInput(request, response, next) {
    // eslint-disable-next-line object-curly-newline
    const { firstName, lastName, email, password } = request.body;

    const data = {
      firstName,
      lastName,
      email,
      password,
    };

    const rules = {
      firstName: 'required|string|min:3',
      lastName: 'required|string|min:3',
      email: 'required|email',
      password: 'required|min:6',
    };

    const validation = new Validator(data, rules);

    if (validation.passes()) {
      return next();
    }

    return response.status(400).json({
      status: 400,
      data: {
        errors: validation.errors.all(),
      },
    });
  }

  /**
   * @description Validates create user inputs on login
   *
   * @param {Object} request
   * @param {Object} response
   * @param {Function} next
   *
   * @return {Function} next
   */
  static userInputLogin(request, response, next) {
    const { email, password } = request.body;

    const data = {
      email,
      password,
    };

    const rules = {
      email: 'required|email',
      password: 'required',
    };

    const validation = new Validator(data, rules);

    if (validation.passes()) {
      return next();
    }

    return response.status(400).json({
      status: 'fail',
      data: {
        errors: validation.errors.all(),
      },
    });
  }

  static imageInput(request, response, next) {
    // eslint-disable-next-line object-curly-newline
    const { image } = request.body;

    const data = {
      image,
    };

    const rules = {
      image: 'required',
    };

    const validation = new Validator(data, rules);

    if (validation.passes()) {
      return next();
    }

    return response.status(400).json({
      status: 400,
      data: {
        errors: validation.errors.all(),
      },
    });
  }

  static validateEmail(request, response, next) {
    const { email } = request.body;

    const data = {
      email,
    };

    const rules = {
      email: 'required|email',
    };

    const validation = new Validator(data, rules);

    if (validation.passes()) {
      return next();
    }

    return response.status(400).json({
      status: 400,
      data: {
        errors: validation.errors.all(),
      },
    });
  }
}

export default ValidateUser;
