import prisma from "../db/prismaInstance.js";
import { encodeBase32LowerCaseNoPadding, encodeHexLowerCase } from "@oslojs/encoding";
import { sha256 } from "@oslojs/crypto/sha2";
import crypto from "crypto";

export function generateSessionToken() {
  const bytes = new Uint8Array(20);
  crypto.getRandomValues(bytes);
  const token = encodeBase32LowerCaseNoPadding(bytes);
  return token;
}

export async function createSession(token, userId) {
  const sessionId = encodeHexLowerCase(sha256(new TextEncoder().encode(token)));
  const session = {
    id: sessionId,
    userId,
    expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24 * 7), // 7 days
  };
  await prisma.session.create({
    data: session,
  });
  return session;
}

export async function validateSessionToken(token) {
  const sessionId = encodeHexLowerCase(sha256(new TextEncoder().encode(token)));
  const result = await prisma.session.findUnique({
    where: {
      id: sessionId,
    },
    include: {
      user: true,
    },
  });
  if (result === null) {
    return { session: null, user: null };
  }
  const { user, ...session } = result;
  if (Date.now() >= session.expiresAt.getTime()) {
    await prisma.session.delete({ where: { id: sessionId } });
    return { session: null, user: null };
  }
  if (Date.now() >= session.expiresAt.getTime() - 1000 * 60 * 60 * 24 * 4) {
    session.expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24 * 7);
    await prisma.session.update({
      where: {
        id: session.id,
      },
      data: {
        expiresAt: session.expiresAt,
      },
    });
  }
  return { session, user };
}

export async function invalidateSession(sessionId) {
  await prisma.session.delete({ where: { id: sessionId } });
}

export function setSessionTokenCookie(res, token, expiresAt) {
  const cookieOptions = {
    httpOnly: true,
    sameSite: "Lax",
    expires: expiresAt,
    path: "/",
  };

  if (process.env.NODE_ENV === "production") {
    // When deployed over HTTPS
    cookieOptions.secure = true; // Ensure cookies are only sent over HTTPS
  }

  res.cookie("session", token, cookieOptions);
}

// Delete the session token cookie
export function deleteSessionTokenCookie(res) {
  const cookieOptions = {
    httpOnly: true,
    sameSite: "Lax",
    maxAge: 0, // this will cause the cookie to expire immediately
    path: "/",
  };

  if (process.env.NODE_ENV === "production") {
    // When deployed over HTTPS
    cookieOptions.secure = true; // Ensure cookies are only sent over HTTPS
  }

  res.cookie("session", "", cookieOptions); // Set an empty value to delete the cookie
}
