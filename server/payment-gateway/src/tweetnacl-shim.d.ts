declare module "tweetnacl" {
  export type KeyPair = {
    publicKey: Uint8Array;
    secretKey: Uint8Array;
  };

  export type SignNamespace = {
    keyPair: {
      fromSeed(seed: Uint8Array): KeyPair;
    };
    detached(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  };

  const nacl: {
    sign: SignNamespace;
  };

  export default nacl;
}
