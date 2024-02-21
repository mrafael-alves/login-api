import { Document } from 'mongoose';

export interface User extends Document {
  fullName: string;
  username: string;
  email: string;
  password: string;
  role: string;
  cpf?: string;
  cnpj?: string;
  resetPasswordToken?: string;
  resetPasswordExpires?: Date;
}
