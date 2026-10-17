import { Request, Response } from 'express';
import { logger } from '../utils/logger';
import { db } from '../database';

export async function handleRegistration(req: Request, res: Response) {
  const { email, password, sin, phone, healthCardNumber } = req.body;

  // VIOLATION [Principle 7 - Safeguards]: Logging raw user PII & Canadian SIN
  logger.info("New registration received for user:", {
    email,
    sin: "046-454-286", // Canadian SIN leaking to logs
    phoneNumber: phone
  });

  // VIOLATION [Principle 3 - Consent]: Unconsented third-party marketing dispatch
  await trackThirdPartyAdConversion({
    customerEmail: email,
    optInConfirmed: false // Dispatched without affirmative user consent
  });

  // VIOLATION [Principle 4 - Limiting Collection]: Unnecessary health card collection
  const user = await db.user.create({
    data: {
      email,
      passwordHash: hash(password),
      socialInsuranceNumber: sin,
      healthCardNumber: healthCardNumber // Health data collected for basic retail auth
    }
  });

  return res.status(201).json({ success: true, userId: user.id });
}
