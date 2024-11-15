// index.ts

import { NativeModules, Platform } from 'react-native';


const { DeviceCrypto: RNDeviceCrypto } = NativeModules;

// interfaces.ts

// enums.ts


export enum KeyTypes {
  ASYMMETRIC = 0,
  SYMMETRIC = 1,
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

export enum SecurityRules {
  NONE = 'NONE',
  AUTOMATIC_UPDATES = 'AUTOMATIC_UPDATES',
}

export enum Accessible {
  WHEN_UNLOCKED = 'WHEN_UNLOCKED',
  AFTER_FIRST_UNLOCK = 'AFTER_FIRST_UNLOCK',
  ALWAYS = 'ALWAYS',
  WHEN_PASSCODE_SET_THIS_DEVICE_ONLY = 'WHEN_PASSCODE_SET_THIS_DEVICE_ONLY',
}

export enum AccessControl {
  USER_PRESENCE = 'USER_PRESENCE',
  BIOMETRY_ANY = 'BIOMETRY_ANY',
  BIOMETRY_CURRENT_SET = 'BIOMETRY_CURRENT_SET',
  DEVICE_PASSCODE = 'DEVICE_PASSCODE',
  BIOMETRY_ANY_OR_DEVICE_PASSCODE = 'BIOMETRY_ANY_OR_DEVICE_PASSCODE',
  BIOMETRY_CURRENT_SET_OR_DEVICE_PASSCODE = 'BIOMETRY_CURRENT_SET_OR_DEVICE_PASSCODE',
  APPLICATION_PASSWORD = 'APPLICATION_PASSWORD',
}

export enum AuthenticationType {
  BIOMETRICS = 'BIOMETRICS',
  DEVICE_PASSCODE = 'DEVICE_PASSCODE',
}


export interface BiometryParams {
  promptMessage?: string;
  promptTitle?: string;
  promptSubtitle?: string;
  promptDescription?: string;
}

export interface KeyCreationParams {
  accessible?: Accessible;
  accessControl?: AccessControl;
}

export interface EncryptionResult {
  iv: string;
  encryptedText: string;
}

export interface UserCredentials {
  service?: string;
  server?: string;
  username: string;
  password: string;
  storage?: string;
}

export interface Result {
  service: string;
  storage: string;
}

export interface BaseOptions {
  service?: string;
  server?: string;
}

export interface SetOptions extends BaseOptions {
  accessible?: Accessible;
  accessControl?: AccessControl;
  authenticationPrompt?: string;
  authenticationType?: AuthenticationType;
  securityLevel?: SecurityLevel;
  storage?: string;
}

export interface GetOptions extends BaseOptions {
  authenticationPrompt?: string;
  authenticationType?: AuthenticationType;
}

export interface AuthenticationTypeOption {
  authenticationType?: AuthenticationType;
}

export interface AccessControlOption {
  accessControl?: AccessControl;
}


/**
 * Helper functions to normalize options
 */
function normalizeOptions(
  serviceOrOptions?: string | SetOptions | GetOptions | BaseOptions
): SetOptions | GetOptions | BaseOptions {
  if (typeof serviceOrOptions === 'string') {
    return { service: serviceOrOptions };
  }
  return serviceOrOptions || {};
}

function normalizeServiceOption(
  serviceOrOptions?: string | BaseOptions
): BaseOptions {
  if (typeof serviceOrOptions === 'string') {
    return { service: serviceOrOptions };
  }
  return serviceOrOptions || {};
}

function normalizeServerOption(
  serverOrOptions?: string | BaseOptions
): BaseOptions {
  if (typeof serverOrOptions === 'string') {
    return { server: serverOrOptions };
  }
  return serverOrOptions || {};
}

/**
 * Unified Crypto and Keychain Module
 */
const CryptoKeychain = {
  // --- DeviceCrypto Methods ---

  /**
   * Authenticate using biometric authentication before using the private key.
   */
  authenticate(options?: BiometryParams): Promise<void> {
    return RNDeviceCrypto.authenticate(options || {});
  },

  /**
   * Clean up and release the private key reference and authentication context.
   */
  cleanUp(): Promise<void> {
    return RNDeviceCrypto.cleanUp();
  },

  /**
   * Create or retrieve an asymmetric key pair from secure hardware.
   */
  getOrCreateAsymmetricKey(
    alias: string,
    options: KeyCreationParams
  ): Promise<string> {
    return RNDeviceCrypto.createKey(alias, options);
  },

  /**
   * Delete a key from secure hardware.
   */
  deleteKey(alias: string): Promise<boolean> {
    return RNDeviceCrypto.deleteKey(alias);
  },

  /**
   * Get the public key in Base64 format.
   */
  getPublicKey(alias: string): Promise<string | null> {
    return RNDeviceCrypto.getPublicKey(alias);
  },

  /**
   * Sign a text with the private key.
   */
  sign(
    alias: string,
    plainText: string,
    options?: BiometryParams
  ): Promise<string> {
    return RNDeviceCrypto.sign(alias, plainText, options || {});
  },

  /**
   * Encrypt text using a public key.
   * Note: Ensure that the native module implements the `encrypt` method.
   */
  encrypt(
    publicKeyBase64: string,
    plainText: string,
    options?: BiometryParams
  ): Promise<EncryptionResult> {
    return RNDeviceCrypto.encrypt(publicKeyBase64, plainText, options || {});
  },

  /**
   * Decrypt encrypted text using the private key.
   * Note: Ensure that the native module implements the `decrypt` method.
   */
  decrypt(
    alias: string,
    cipherText: string,
    options?: BiometryParams
  ): Promise<string> {
    return RNDeviceCrypto.decrypt(alias, cipherText, options || {});
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
  authenticateWithBiometry(options?: BiometryParams): Promise<boolean> {
    return RNDeviceCrypto.authenticateWithBiometry(options || {});
  },

  // --- Keychain Methods ---

  /**
   * Saves the `username` and `password` combination for the given service.
   */
  setGenericPassword(
    username: string,
    password: string,
    serviceOrOptions?: string | SetOptions
  ): Promise<false | Result> {
    const options = normalizeOptions(serviceOrOptions);
    return RNDeviceCrypto.setGenericPasswordForOptions(
      options,
      username,
      password
    );
  },

  /**
   * Fetches the `username` and `password` combination for the given service.
   */
  getGenericPassword(
    serviceOrOptions?: string | GetOptions
  ): Promise<false | UserCredentials> {
    const options = normalizeOptions(serviceOrOptions);
    return RNDeviceCrypto.getGenericPasswordForOptions(options);
  },

  /**
   * Checks if generic password exists for the given service.
   */
  hasGenericPassword(
    serviceOrOptions?: string | BaseOptions
  ): Promise<boolean> {
    const options = normalizeServiceOption(serviceOrOptions);
    return RNDeviceCrypto.hasGenericPasswordForOptions(options);
  },

  /**
   * Deletes all generic password keychain entries for the given service.
   */
  resetGenericPassword(
    serviceOrOptions?: string | BaseOptions
  ): Promise<boolean> {
    const options = normalizeServiceOption(serviceOrOptions);
    return RNDeviceCrypto.resetGenericPasswordForOptions(options);
  },

  /**
   * Gets all service keys used in generic password keychain entries.
   */
  getAllGenericPasswordServices(): Promise<string[]> {
    return RNDeviceCrypto.getAllGenericPasswordServices();
  },

  /**
   * Checks if internet credentials exist for the given server.
   */
  hasInternetCredentials(
    serverOrOptions: string | BaseOptions
  ): Promise<boolean> {
    const options = normalizeServerOption(serverOrOptions);
    return RNDeviceCrypto.hasInternetCredentialsForOptions(options);
  },

  /**
   * Saves the internet credentials for the given server.
   */
  setInternetCredentials(
    server: string,
    username: string,
    password: string,
    options?: SetOptions
  ): Promise<false | Result> {
    return RNDeviceCrypto.setInternetCredentialsForServer(
      server,
      username,
      password,
      normalizeOptions(options)
    );
  },

  /**
   * Fetches the internet credentials for the given server.
   */
  getInternetCredentials(
    server: string,
    options?: GetOptions
  ): Promise<false | UserCredentials> {
    return RNDeviceCrypto.getInternetCredentialsForServer(
      server,
      normalizeOptions(options)
    );
  },

  /**
   * Deletes all internet password keychain entries for the given server.
   */
  resetInternetCredentials(
    serverOrOptions: string | BaseOptions
  ): Promise<boolean> {
    const options = normalizeServerOption(serverOrOptions);
    return RNDeviceCrypto.resetInternetCredentialsForOptions(options);
  },

  /**
   * Gets the type of biometric authentication supported by the device.
   */
  getSupportedBiometryType(): Promise<null | BiometryType> {
    if (!RNDeviceCrypto.getSupportedBiometryType) {
      return Promise.resolve(null);
    }
    return RNDeviceCrypto.getSupportedBiometryType();
  },

  /**
   * Request shared web credentials.
   * @platform iOS
   */
  requestSharedWebCredentials(): Promise<false | UserCredentials> {
    if (Platform.OS !== 'ios') {
      return Promise.reject(
        new Error(
          `requestSharedWebCredentials() is not supported on ${Platform.OS} yet`
        )
      );
    }
    return RNDeviceCrypto.requestSharedWebCredentials();
  },

  /**
   * Sets shared web credentials.
   * @platform iOS
   */
  setSharedWebCredentials(
    server: string,
    username: string,
    password?: string
  ): Promise<void> {
    if (Platform.OS !== 'ios') {
      return Promise.reject(
        new Error(
          `setSharedWebCredentials() is not supported on ${Platform.OS} yet`
        )
      );
    }
    return RNDeviceCrypto.setSharedWebCredentialsForServer(
      server,
      username,
      password
    );
  },

  /**
   * Checks if the current device supports the specified authentication policy.
   * @platform iOS
   */
  canImplyAuthentication(
    options?: AuthenticationTypeOption
  ): Promise<boolean> {
    if (!RNDeviceCrypto.canCheckAuthentication) {
      return Promise.resolve(false);
    }
    return RNDeviceCrypto.canCheckAuthentication(options);
  },

  /**
   * Returns the security level supported by the library on the current device.
   * @platform iOS
   */
  getSecurityLevel(
    options?: AccessControlOption
  ): Promise<null | SecurityLevel> {
    if (!RNDeviceCrypto.getSecurityLevel) {
      return Promise.resolve(null);
    }
    return RNDeviceCrypto.getSecurityLevel(options);
  },
};

/**
 * Unified Module Export
 */
export default CryptoKeychain;
