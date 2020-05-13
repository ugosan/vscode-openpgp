import * as vscode from 'vscode';
const openpgp = require('openpgp');
import { posix } from 'path';
import { collectNewPrivateKey } from './multiStepInput';
import { window } from 'vscode';
import { Key } from 'readline';


export function activate(context: vscode.ExtensionContext) {


  context.subscriptions.push(vscode.commands.registerCommand('vscode-openpgp.generatePrivateKey', () => {

    (async () => {

      const inputs = await collectNewPrivateKey();

      const { privateKeyArmored, publicKeyArmored, revocationCertificate } = await openpgp.generateKey({
        userIds: [{ name: inputs.name, email: inputs.email, "comment": inputs.comment }],
        curve: 'ed25519',
        passphrase: inputs.passphrase
      });

      const keys_folder = vscode.workspace.getConfiguration().get('openpgp-encrypt.encrypt.keysFolder');
      let uri = vscode.Uri.file('' + keys_folder);

      const folderUri = uri;

      const filename = [inputs.name.replace(' ', ''), inputs.email, inputs.comment];

      let fileUri = folderUri.with({ path: posix.join(folderUri.path, filename.join('_') + '.key') });

      await vscode.workspace.fs.writeFile(fileUri, Buffer.from(privateKeyArmored, 'utf8'));

      vscode.window.showInformationMessage(`Private key generated to ${fileUri}`);

      fileUri = folderUri.with({ path: posix.join(folderUri.path, filename.join('_') + '.pub') });
      await vscode.workspace.fs.writeFile(fileUri, Buffer.from(publicKeyArmored, 'utf8'));

    })();
  }));

  context.subscriptions.push(vscode.commands.registerCommand('vscode-openpgp.encrypt', (e) => {

    (async () => {

      const fullText = vscode.window.activeTextEditor!.document.getText();
      let publicKey = await pickPublicKey();
      let encrypted = await encryptWithPublicKey(fullText, publicKey);
      let document = vscode.window.activeTextEditor!.document;
      const invalidRange = new vscode.Range(0, 0, document.lineCount, 0);
      const fullRange = document.validateRange(invalidRange);
      vscode.window.activeTextEditor!.edit(edit => edit.replace(fullRange, encrypted));

    })();
  }));


  context.subscriptions.push(vscode.commands.registerCommand('vscode-openpgp.decrypt', () => {

    (async () => {
      const encryptedText = vscode.window.activeTextEditor!.document.getText();
      let encryptedMessage = await openpgp.message.readArmored(encryptedText);

      let privateKeyArmored = await pickPrivateKey();

      if (privateKeyArmored.keyPacket.isEncrypted) {
        const passString = await vscode.window.showInputBox({ prompt: 'Enter passphrase of the private key', placeHolder: 'PASSPHRASE', password: true, validateInput: value => (value.length == 0) ? "Passphrase cannot be empty" : null });

        try {
          await privateKeyArmored.decrypt(passString);
        } catch (error) {
          vscode.window.showErrorMessage('' + error);
        }
      }

      const { data: decrypted } = await openpgp.decrypt({
        message: encryptedMessage,
        privateKeys: [privateKeyArmored]
      });

      let document = vscode.window.activeTextEditor!.document;

      const invalidRange = new vscode.Range(0, 0, document.lineCount, 0);
      const fullRange = document.validateRange(invalidRange);
      vscode.window.activeTextEditor!.edit(edit => edit.replace(fullRange, decrypted));

    })();
  }));

}

// this method is called when your extension is deactivated
export function deactivate() { }


/**
 * Gets public keys at `openpgp-encrypt.encrypt.keysFolder`
 *      0        -- Reserved - a packet tag MUST NOT have this value
 *      1        -- Public-Key Encrypted Session Key Packet
 *      2        -- Signature Packet
 *      3        -- Symmetric-Key Encrypted Session Key Packet
 *      4        -- One-Pass Signature Packet
 *      5        -- Secret-Key Packet
 *      6        -- Public-Key Packet
 *      7        -- Secret-Subkey Packet
 *      8        -- Compressed Data Packet
 *      9        -- Symmetrically Encrypted Data Packet
 *      10       -- Marker Packet
 *      11       -- Literal Data Packet
 *      12       -- Trust Packet
 *      13       -- User ID Packet
 *      14       -- Public-Subkey Packet
 *      17       -- User Attribute Packet
 *      18       -- Sym. Encrypted and Integrity Protected Data Packet
 *      19       -- Modification Detection Code Packet
 *      60 to 63 -- Private or Experimental Values
 */
async function getPublicKeys() {

  const keys_folder_setting = vscode.workspace.getConfiguration().get('openpgp-encrypt.encrypt.keysFolder');
  console.info(`reading ${keys_folder_setting}`);
  const folderUri = vscode.Uri.file('' + keys_folder_setting);
  const keys_folder = await vscode.workspace.fs.readDirectory(folderUri);

  let keys: any[] = [];

  for await (let element of keys_folder) {

    const fileUri = folderUri.with({ path: posix.join(folderUri.path, element[0]) });
    const readData = await vscode.workspace.fs.readFile(fileUri);
    const readStr = Buffer.from(readData).toString('utf8');

    const key = await openpgp.key.readArmored(readStr);
    if (key.keys[0].keyPacket.tag === 6) {
      keys.push(key.keys[0]);
    }
  }

  return keys;
}


/**
 * Gets private keys at `openpgp-encrypt.encrypt.keysFolder`
 *      0        -- Reserved - a packet tag MUST NOT have this value
 *      1        -- Public-Key Encrypted Session Key Packet
 *      2        -- Signature Packet
 *      3        -- Symmetric-Key Encrypted Session Key Packet
 *      4        -- One-Pass Signature Packet
 *      5        -- Secret-Key Packet
 *      6        -- Public-Key Packet
 *      7        -- Secret-Subkey Packet
 *      8        -- Compressed Data Packet
 *      9        -- Symmetrically Encrypted Data Packet
 *      10       -- Marker Packet
 *      11       -- Literal Data Packet
 *      12       -- Trust Packet
 *      13       -- User ID Packet
 *      14       -- Public-Subkey Packet
 *      17       -- User Attribute Packet
 *      18       -- Sym. Encrypted and Integrity Protected Data Packet
 *      19       -- Modification Detection Code Packet
 *      60 to 63 -- Private or Experimental Values
 */
async function getPrivateKeys() {

  const keys_folder_setting = vscode.workspace.getConfiguration().get('openpgp-encrypt.encrypt.keysFolder');
  console.info(`reading ${keys_folder_setting}`);
  const folderUri = vscode.Uri.file('' + keys_folder_setting);
  const keys_folder = await vscode.workspace.fs.readDirectory(folderUri);

  let keys: any[] = [];

  for await (let element of keys_folder) {

    console.info(`reading ${element}`);
    const fileUri = folderUri.with({ path: posix.join(folderUri.path, element[0]) });
    const readData = await vscode.workspace.fs.readFile(fileUri);
    const readStr = Buffer.from(readData).toString('utf8');

    const key = await openpgp.key.readArmored(readStr);
    if (key.keys[0].keyPacket.tag === 5) {
      keys.push(key.keys[0]);
    }
  }

  return keys;
}


async function pickPublicKey() {
  const keys = await getPublicKeys();

  const keyList: vscode.QuickPickItem[] = keys.map((key, i) => {
    return {
      label: key.users[0].userId.userid,
      detail: key.primaryKey.getKeyId().toHex(),
      id: i
    };
  });

  const result = await window.showQuickPick(keyList, {
    placeHolder: 'Pick a public key'
  });
  return keys[result.id];
}

async function encryptWithPublicKey(text: string, publicKey: Key) {

  const keys_folder = vscode.workspace.getConfiguration().get('openpgp-encrypt.encrypt.keysFolder');

  let msg = openpgp.message.fromText(text);

  const { data: encrypted } = await openpgp.encrypt({
    message: msg,
    publicKeys: publicKey
  });

  return encrypted;
}

async function pickPrivateKey() {
  const keys = await getPrivateKeys();

  const keyList: vscode.QuickPickItem[] = keys.map((key, i) => {
    return {
      label: key.users[0].userId.userid,
      detail: key.primaryKey.getKeyId().toHex(),
      id: i
    };
  });

  const result = await window.showQuickPick(keyList, {
    placeHolder: 'Pick a private key to decrypt'
  });
  return keys[result.id];
}
