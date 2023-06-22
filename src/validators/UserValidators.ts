import { body, query } from "express-validator";
import UserModel from "../models/User";

export class UserValidators {
  static signup() {
    return [
      body("name", "Name is required").isString(),
      body("surname1", "Surname is required").isString(),
      body("email", "Email is required")
        .isEmail()
        .custom((email, { req }) => {
          return UserModel.findOne({ email: email })
            .then((user) => {
              if (user) {
                throw new Error("User Already Exists");
              } else {
                return true;
              }
            })
            .catch((e) => {
              throw new Error(e);
            });
        }),
      body("password", "Password is required")
        .isString()
        .isLength({ min: 8, max: 20 })
        .withMessage("Password must be between 8-20 characters"),
      body("date_birth", "Date of birth is required").isDate(),
      body("address", "Address is required").isString(),
      body("phone_number", "Phone number is required").isString(),
      body("roles", "User roles are required").isArray(),
      body("is_freelancer", "is_freelancer field is required").isBoolean(),
      body("enterprise_name").optional().isString(),
      body("fiscal_id_number").optional().isString(),
      body("legal_repre_name").optional().isString(),
      body("legal_repre_mail").optional().isString().isEmail(),
      body("license").optional().isString(),
      body("subscription").optional().isString(),
    ];
  }

  static verifyUserEmailToken() {
    return [
      body(
        "verification_token",
        "Email verification token is required"
      ).isNumeric(),
    ];
  }

  static login() {
    return [
      query("email", "Email is required")
        .isEmail()
        .custom((email, { req }) => {
          return UserModel.findOne({
            email: email,
          })
            .then((user) => {
              if (user) {
                // check role
                if (
                  user.roles.includes("Client") ||
                  user.roles.includes("Admin")
                ) {
                  req.user = user;
                  return true;
                } else {
                  // throw new Error('You are not an Authorised User');
                  throw "You are not an Authorised User";
                }
              } else {
                // throw new Error('No User Registered with such Email');
                throw "No User Registered with such Email";
              }
            })
            .catch((e) => {
              throw new Error(e);
            });
        }),
      query("password", "Password is required").isAlphanumeric(),
    ];
  }

  static checkResetPasswordEmail() {
    return [
      query("email", "Email is required")
        .isEmail()
        .custom((email, { req }) => {
          return UserModel.findOne({
            email: email,
          })
            .then((user) => {
              if (user) {
                return true;
              } else {
                // throw new Error('No User Registered with such Email');
                throw "No User Registered with such Email";
              }
            })
            .catch((e) => {
              throw new Error(e);
            });
        }),
    ];
  }

  static verifyResetPasswordToken() {
    return [
      query("email", "Email is required").isEmail(),
      query("reset_password_token", "Reset password token is required")
        .isNumeric()
        .custom((reset_password_token, { req }) => {
          return UserModel.findOne({
            email: req.query.email,
            reset_password_token: reset_password_token,
            reset_password_token_time: { $gt: Date.now() },
          })
            .then((user) => {
              if (user) {
                return true;
              } else {
                // throw new Error('Reset password token doesn\'t exist. Please regenerate a new token.');
                throw "Reset password token doesn't exist. Please regenerate a new token.";
              }
            })
            .catch((e) => {
              throw new Error(e);
            });
        }),
    ];
  }

  static resetPassword() {
    return [
      body("email", "Email is required")
        .isEmail()
        .custom((email, { req }) => {
          return UserModel.findOne({
            email: email,
          })
            .then((user) => {
              if (user) {
                req.user = user;
                return true;
              } else {
                // throw new Error('No User Registered with such Email');
                throw "No User Registered with such Email";
              }
            })
            .catch((e) => {
              throw new Error(e);
            });
        }),
      body("new_password", "New Password is required").isAlphanumeric(),
      body("otp", "Reset password token is required")
        .isNumeric()
        .custom((reset_password_token, { req }) => {
          if (req.user.reset_password_token == reset_password_token) {
            return true;
          } else {
            req.errorStatus = 422;
            // throw new Error('Reset password token is invalid, please try again');
            throw "Reset password token is invalid, please try again";
          }
        }),
    ];
  }

  static verifyPhoneNumber() {
    return [body("phone", "Phone is required").isString()];
  }
}
