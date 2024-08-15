import { NativeModules } from 'react-native';

const RNDeviceCrypto = NativeModules.DeviceCrypto;

export interface BiometryParams {
  biometryTitle: string;
  biometrySubTitle: string;
  biometryDescription: string;
}

export enum AccessLevel {
  ALWAYS = 0,
  UNLOCKED_DEVICE = 1,
  AUTHENTICATION_REQUIRED = 2,
}
export interface KeyCreationParams {
  accessLevel: AccessLevel;
  invalidateOnNewBiometry?: boolean;
}

export enum KeyTypes {
  ASYMMETRIC = 0,
  SYMMETRIC = 1,
}
export interface EncryptionResult {
  iv: string;
  encryptedText: string;
}

export enum BiometryType {
  NONE = 'NONE',
  TOUCH = 'TOUCH',
  FACE = 'FACE',
  IRIS = 'IRIS',
}

export enum SecurityLevel {
  NOT_PROTECTED = 'NOT_PROTECTED',
  PIN_OR_PATTERN = 'PIN_OR_PATTERN',
  BIOMETRY = 'BIOMETRY',
}

const DeviceCrypto = {
/**
 * Authenticate using biometric authentication before using the private key.
 */
authenticate(alias: string, options: BiometryParams): Promise<void> {
  return RNDeviceCrypto.authenticate(alias, options);
},

/**
 * Clean up and release the private key reference.
 */
cleanUp(): Promise<void> {
  return RNDeviceCrypto.cleanUp();
},

/**
 * Create or retrieve an asymmetric key pair from secure hardware.
 */
getOrCreateAsymmetricKey(alias: string, options: KeyCreationParams): Promise<string> {
  return RNDeviceCrypto.getOrCreateAsymmetricKey(alias, options);
},

/**
 * Delete a key from secure hardware.
 */
deleteKey(alias: string): Promise<boolean> {
  return RNDeviceCrypto.deleteKey(alias);
},

/**
 * Get the public key in PEM format.
 */
getPublicKey(alias: string): Promise<string> {
  return RNDeviceCrypto.getPublicKey(alias);
},

/**
 * Sign a text with the private key.
 */
sign(alias: string, plainText: string, options: BiometryParams): Promise<string> {
  return RNDeviceCrypto.sign(alias, plainText, options);
},

/**
 * Encrypt text using a public key.
 */
encrypt(
  publicKeyBase64: string,
  plainText: string,
  options: BiometryParams,
): Promise<EncryptionResult> {
  return RNDeviceCrypto.encrypt(publicKeyBase64, plainText, options);
},

/**
 * Decrypt encrypted text using the private key.
 */
decrypt(alias: string, plainText: string, options: BiometryParams): Promise<string> {
  return RNDeviceCrypto.decrypt(alias, plainText, options);
},

/**
 * Check if a key exists in secure hardware.
 */
isKeyExists(alias: string, keyType: KeyTypes): Promise<boolean> {
  return RNDeviceCrypto.isKeyExists(alias, keyType);
},

/**
 * Check if biometry is enrolled on the device.
 */
isBiometryEnrolled(): Promise<boolean> {
  return RNDeviceCrypto.isBiometryEnrolled();
},

/**
 * Get the security level of the device.
 */
deviceSecurityLevel(): Promise<SecurityLevel> {
  return RNDeviceCrypto.deviceSecurityLevel();
},

/**
 * Get the type of biometry enrolled on the device.
 */
getBiometryType(): Promise<BiometryType> {
  return RNDeviceCrypto.getBiometryType();
},

/**
 * Authenticate using device biometry.
 */
authenticateWithBiometry(options: BiometryParams): Promise<boolean> {
  return RNDeviceCrypto.authenticateWithBiometry(options);
},

};

export default DeviceCrypto;
