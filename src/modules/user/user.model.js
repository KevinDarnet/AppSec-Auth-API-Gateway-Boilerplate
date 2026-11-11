import mongoose from 'mongoose';
import { hashPassword, comparePassword } from '../../core/utils/crypto.js';
import { Roles } from '../../core/constants/roles.js';

const MAX_FAILED_LOGIN_ATTEMPTS = 5;
const LOCKOUT_TIME_MS = 15 * 60 * 1000; // 15 minutes lock

const userSchema = new mongoose.Schema(
  {
    email: {
      type: String,
      required: [true, 'Email address is required'],
      unique: true,
      lowercase: true,
      trim: true,
      index: true,
    },
    password: {
      type: String,
      required: [true, 'Password is required'],
      minlength: 8,
      select: false, // Hidden by default from queries (prevents accidental password leak in responses/logs)
    },
    fullName: {
      type: String,
      required: [true, 'Full name is required'],
      trim: true,
      maxlength: 100,
    },
    role: {
      type: String,
      enum: Object.values(Roles),
      default: Roles.USER,
      index: true,
    },
    isActive: {
      type: Boolean,
      default: true,
      index: true,
    },
    failedLoginAttempts: {
      type: Number,
      default: 0,
    },
    lockUntil: {
      type: Date,
      default: null,
    },
    passwordChangedAt: {
      type: Date,
      default: null,
    },
  },
  {
    timestamps: true,
    toJSON: {
      transform: (doc, ret) => {
        delete ret.password;
        delete ret.__v;
        delete ret.failedLoginAttempts;
        delete ret.lockUntil;
        ret.id = ret._id.toString();
        delete ret._id;
        return ret;
      },
    },
  }
);

// Pre-save hook: Hash password securely if modified
userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();

  this.password = await hashPassword(this.password);
  this.passwordChangedAt = new Date();
  next();
});

// Instance method: Verify password
userSchema.methods.verifyPassword = async function (plainPassword) {
  return comparePassword(plainPassword, this.password);
};

// Instance method: Account lock status check
userSchema.methods.isAccountLocked = function () {
  return !!(this.lockUntil && this.lockUntil > Date.now());
};

// Instance method: Track failed login attempts for account lockout defense
userSchema.methods.recordFailedLogin = async function () {
  if (this.lockUntil && this.lockUntil < Date.now()) {
    // Lock period expired, reset counter
    this.failedLoginAttempts = 1;
    this.lockUntil = null;
  } else {
    this.failedLoginAttempts += 1;
    if (this.failedLoginAttempts >= MAX_FAILED_LOGIN_ATTEMPTS && !this.isAccountLocked()) {
      this.lockUntil = new Date(Date.now() + LOCKOUT_TIME_MS);
    }
  }
  return this.save();
};

// Instance method: Reset failed attempts upon successful login
userSchema.methods.recordSuccessfulLogin = async function () {
  if (this.failedLoginAttempts > 0 || this.lockUntil) {
    this.failedLoginAttempts = 0;
    this.lockUntil = null;
    return this.save();
  }
};

export const UserModel = mongoose.model('User', userSchema);
