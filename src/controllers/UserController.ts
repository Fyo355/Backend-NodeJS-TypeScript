import UserModel from "../models/User";
import { Utils } from "../utils/Utils";
import { Redis } from "./../utils/Redis";
import { NodeMailer } from "./../utils/NodeMailer";
import { Jwt } from "./../utils/Jwt";

export class UserController {
  static async signup(req, res, next) {
    const {
      name,
      surname1,
      email,
      password,
      date_birth,
      address,
      phone_number,
      roles,
      is_freelancer,
      enterprise_name,
      fiscal_id_number,
      legal_repre_name,
      legal_repre_mail,
      license,
      subscription,
    } = req.body;

    const verification_token = Utils.generateVerificationToken();
    console.log(verification_token);

    try {
      const hash = await Utils.encryptPassword(password);

      let data = {
        name,
        surname1,
        email,
        verification_token,
        verification_token_time: Date.now() + new Utils().MAX_TOKEN_TIME,
        password: hash,
        date_birth,
        address,
        phone_number,
        roles,
        is_freelancer,
        enterprise_name: null,
        fiscal_id_number: null,
        legal_repre_name: null,
        legal_repre_mail: null,
        license: null,
        subscription: null,
      };

      if (roles.includes("Client") || roles.includes("Freelancer")) {
        data = {
          ...data,
          subscription,
        };
      } else if (roles.includes("expAdmin")) {
        data = {
          ...data,
          enterprise_name,
          fiscal_id_number,
          address: req.body.commercial_address,
          legal_repre_name,
          legal_repre_mail,
          license,
        };
      } else if (roles.includes("businessAdmin")) {
        data = {
          ...data,
          enterprise_name,
          fiscal_id_number,
          address: req.body.commercial_address,
          phone_number: req.body.commercial_phone_number,
          legal_repre_name,
          legal_repre_mail,
          license: req.body.purchase_license,
        };
      } else if (roles.includes("dmoAdmin")) {
        data = {
          ...data,
          enterprise_name,
          fiscal_id_number,
          address: req.body.commercial_address,
          phone_number: req.body.commercial_phone_number,
          legal_repre_name,
          legal_repre_mail,
          license,
        };
      }

      const user = await new UserModel(data).save();

      const user_data = {
        name: user.name,
        surname1: user.surname1,
        email: user.email,
        email_verified: user.email_verified,
        date_birth: user.date_birth,
        address: user.address,
        phone_number: user.phone_number,
        roles: user.roles,
        is_freelancer: user.is_freelancer,
        enterprise_name: user.enterprise_name,
        fiscal_id_number: user.fiscal_id_number,
        legal_repre_name: user.legal_repre_name,
        legal_repre_mail: user.legal_repre_mail,
        license: user.license,
        subscription: user.subscription,
      };

      const payload = {
        // user_id: user._id,
        // aud: user._id,
        email: user.email,
        roles: user.roles,
        name: user.name,
      };
      // filter user data to pass in frontend
      const access_token = Jwt.jwtSign(payload, user._id);
      const refresh_token = await Jwt.jwtSignRefreshToken(payload, user._id);
      res.json({
        token: access_token,
        refreshToken: refresh_token,
        user: user_data,
      });

      // send email to user for verification
      await NodeMailer.sendMail({
        to: [user.email],
        subject: "Email Verification",
        html: `<h1>Your Otp is ${verification_token}</h1>`,
      });
    } catch (error) {
      next(error);
    }
  }

  static async login(req, res, next) {
    const email = req.query.email;
    const password = req.query.password;

    try {
      const user = await UserModel.findOne({ email: email });
      if (!user) {
        throw new Error("User not found");
      }

      const data = {
        password: password,
        encrypt_password: user.password,
      };

      await Utils.comparePassword(data);

      let user_data = {
        name: user.name,
        surname1: user.surname1,
        email: user.email,
        date_birth: user.date_birth,
        address: user.address,
        phone_number: user.phone_number,
        roles: user.roles,
        is_freelancer: user.is_freelancer,
        enterprise_name: user.enterprise_name,
        fiscal_id_number: user.fiscal_id_number,
        legal_repre_name: user.legal_repre_name,
        legal_repre_mail: user.legal_repre_mail,
        license: user.license,
        subscription: user.subscription,
      };

      if (
        user.roles.includes("Client") ||
        user.roles.includes("Freelancer") ||
        user.roles.includes("expAdmin") ||
        user.roles.includes("businessAdmin") ||
        user.roles.includes("dmoAdmin")
      ) {
        user_data = {
          ...user_data,
          subscription: user.subscription,
          enterprise_name: user.enterprise_name,
          fiscal_id_number: user.fiscal_id_number,
          legal_repre_name: user.legal_repre_name,
          legal_repre_mail: user.legal_repre_mail,
          license: user.license,
          address: user.address,
          phone_number: user.phone_number,
        };
      }

      const payload = {
        email: user.email,
        roles: user.roles,
        name: user.name,
      };

      const access_token = Jwt.jwtSign(payload, user._id);
      const refresh_token = await Jwt.jwtSignRefreshToken(payload, user._id);

      res.json({
        token: access_token,
        refreshToken: refresh_token,
        user: user_data,
      });
    } catch (e) {
      next(e);
    }
  }

  static async verifyUserEmailToken(req, res, next) {
    const verification_token = req.body.verification_token;
    const email = req.user.email;
    try {
      const user = await UserModel.findOneAndUpdate(
        {
          email: email,
          verification_token: verification_token,
          verification_token_time: { $gt: Date.now() },
        },
        {
          email_verified: true,
          updated_at: new Date(),
        },
        {
          new: true,
          projection: {
            verification_token: 0,
            verification_token_time: 0,
            password: 0,
            reset_password_token: 0,
            reset_password_token_time: 0,
            __v: 0,
            _id: 0,
          },
        }
      );
      if (user) {
        res.json({ message: "Correo electrónico verificado correctamente" });
      } else {
        throw new Error(
          "Wrong Otp or Email Verification Token Is Expired. Please try again..."
        );
      }
    } catch (e) {
      next(e);
    }
  }

  static async resendVerificationEmail(req, res, next) {
    const email = req.user.email;
    const verification_token = Utils.generateVerificationToken();
    try {
      const user = await UserModel.findOneAndUpdate(
        { email: email },
        {
          updated_at: new Date(),
          verification_token: verification_token,
          verification_token_time: Date.now() + new Utils().MAX_TOKEN_TIME,
        }
      );
      if (user) {
        res.json({ success: true });
        await NodeMailer.sendMail({
          to: [user.email],
          subject: "Resend Email Verification",
          html: `<h1>Your Otp is ${verification_token}</h1>`,
        });
      } else {
        throw new Error("User doesn't exist");
      }
    } catch (e) {
      next(e);
    }
  }

  static async sendResetPasswordOtp(req, res, next) {
    const email = req.query.email;
    const reset_password_token = Utils.generateVerificationToken();
    try {
      const user = await UserModel.findOneAndUpdate(
        { email: email },
        {
          updated_at: new Date(),
          reset_password_token: reset_password_token,
          reset_password_token_time: Date.now() + new Utils().MAX_TOKEN_TIME,
        }
      );
      if (user) {
        res.json({ success: true });
        await NodeMailer.sendMail({
          to: [user.email],
          subject: "Reset password email vertification OTP",
          html: `<h1>Your Otp is ${reset_password_token}</h1>`,
        });
      } else {
        throw new Error("User doesn't exist");
      }
    } catch (e) {
      next(e);
    }
  }

  static verifyResetPasswordToken(req, res, next) {
    res.json({ success: true });
  }

  static async resetPassword(req, res, next) {
    const user = req.user;
    const new_password = req.body.new_password;
    try {
      const encryptedPassword = await Utils.encryptPassword(new_password);
      const updatedUser = await UserModel.findByIdAndUpdate(
        user._id,
        {
          updated_at: new Date(),
          password: encryptedPassword,
        },
        {
          new: true,
          projection: {
            verification_token: 0,
            verification_token_time: 0,
            password: 0,
            reset_password_token: 0,
            reset_password_token_time: 0,
            __v: 0,
            _id: 0,
          },
        }
      );
      if (updatedUser) {
        res.send(updatedUser);
      } else {
        throw new Error("User doesn't exist");
      }
    } catch (e) {
      next(e);
    }
  }

  static async logout(req, res, next) {
    // const refreshToken = req.body.refreshToken;
    const decoded_data = req.user;
    try {
      if (decoded_data) {
        // delete refresh token from redis database
        await Redis.deleteKey(decoded_data.aud);
        res.json({ success: true });
      } else {
        req.errorStatus = 403;
        // throw new Error('Access is forbidden');
        throw "Access is forbidden";
      }
    } catch (e) {
      req.errorStatus = 403;
      next(e);
    }
  }

  static async getNewTokens(req, res, next) {
    // const refreshToken = req.body.refreshToken;
    const decoded_data = req.user;
    try {
      if (decoded_data) {
        const payload = {
          // user_id: decoded_data.aud,
          email: decoded_data.email,
          type: decoded_data.type,
        };
        const access_token = Jwt.jwtSign(payload, decoded_data.aud);
        const refresh_token = await Jwt.jwtSignRefreshToken(
          payload,
          decoded_data.aud
        );
        res.json({
          accessToken: access_token,
          refreshToken: refresh_token,
        });
      } else {
        req.errorStatus = 403;
        // throw new Error('Access is forbidden');
        throw "Access is forbidden";
      }
    } catch (e) {
      req.errorStatus = 403;
      next(e);
    }
  }
}
