import * as mongoose from "mongoose";
import { model } from "mongoose";

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  surname1: { type: String, required: true },
  surname2: { type: String, required: false },
  email: { type: String, required: true },
  email_verified: { type: Boolean, required: true, default: false },
  verification_token: { type: String, required: true },
  verification_token_time: { type: Date, required: true },
  password: { type: String, required: true },
  reset_password_token: { type: String, required: false },
  reset_password_token_time: { type: Date, required: false },
  date_birth: { type: Date, required: true },
  address: { type: String, required: true },
  phone_number: { type: Number, required: true },
  roles: [
    {
      type: String,
      enum: [
        "Admin",
        "Support",
        "Client",
        "Freelancer",
        "expAdmin",
        "expResponsible",
        "expBranch",
        "businessAdmin",
        "dmoAdmin",
      ],
      required: true,
    },
  ],
  is_freelancer: { type: Boolean, default: false },
  image: { type: String, required: false },
  verification: { type: Boolean, default: false },
  language: { type: String, required: false },
  personal_avatar: { type: String, required: false },
  subscription: { type: String, required: false },
  id_partner: [{ type: mongoose.Schema.Types.ObjectId, ref: "partners" }],
  enterprise_name: { type: String, required: false },
  fiscal_id_number: { type: String, required: false },
  legal_repre_name: { type: String, required: false },
  legal_repre_mail: { type: String, required: false },
  license: { type: String, required: false },
  register_date: { type: Date, required: true, default: new Date() },
  last_access: { type: Date, required: false },
  visited_environments: [
    { type: mongoose.Schema.Types.ObjectId, ref: "environments" },
  ],
  history: { type: String, required: false },
  data_protection: { type: Boolean, required: false },
  commercial_com: { type: Boolean, required: false },
  favourites_env: [
    { type: mongoose.Schema.Types.ObjectId, ref: "environments" },
  ],
  favourites_pack: [{ type: mongoose.Schema.Types.ObjectId, ref: "packs" }],
  friends: [{ type: mongoose.Schema.Types.ObjectId, ref: "users" }],
  connected: { type: Boolean, default: false },
  group: { type: Boolean, default: false },
  level: { type: String, required: false },
});

export default model("users", userSchema);
