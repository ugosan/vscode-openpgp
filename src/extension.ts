import * as vscode from 'vscode';
import * as openpgp from 'openpgp';
import { posix } from 'path';
import { collectNewPrivateKey } from './multiStepInput';
import { window } from 'vscode';
const os = require('os');

export function activate(context: vscode.ExtensionContext) {

  context.subscriptions.push(vscode.commands.registerCommand('vscode-openpgp.generatePrivateKey', () => {

    (async () => {

      const folderUri = getKeysFolderUri();
      await vscode.workspace.fs.createDirectory(folderUri);
      
      const inputs = await collectNewPrivateKey();


      const { privateKeyArmored, publicKeyArmored, revocationCertificate } = await openpgp.generateKey({
        userIds: [{ name: inputs.name, email: inputs.email, comment: inputs.comment }],
        curve: 'ed25519',
        passphrase: inputs.passphrase
      });

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


      if(e){
        var openPath = vscode.Uri.file(e.path);
        vscode.workspace.openTextDocument(openPath).then(doc => {
          vscode.window.showTextDocument(doc);
        });
      }

      const fullText = vscode.window.activeTextEditor!.document.getText();
      const publicKey = await pickPublicKey();
      const encrypted = await encryptWithPublicKey(fullText, publicKey);
      replaceCurrentEditorContent(encrypted);

    })();
  }));


  context.subscriptions.push(vscode.commands.registerCommand('vscode-openpgp.decrypt', (e) => {

    (async () => {
      let encryptedText = vscode.window.activeTextEditor!.document.getText();

      if(e){
        var openPath = vscode.Uri.file(e.path);
        const readData  = await vscode.workspace.fs.readFile(openPath);
        encryptedText = Buffer.from(readData).toString('utf8');
        vscode.workspace.openTextDocument(openPath).then(doc => {
          vscode.window.showTextDocument(doc);
        });
        
      }

      const encryptedMessage:openpgp.message.Message = await openpgp.message.readArmored(encryptedText);

      let privateKeyArmored = await getMatchingPrivateKey(encryptedMessage);

      if(privateKeyArmored === null){
        privateKeyArmored = await pickPrivateKey();
      }else{
        vscode.window.showInformationMessage('Found matching private key!');
      }


      if (!privateKeyArmored.isDecrypted()) {
        const passString = await vscode.window.showInputBox({ 
            prompt: 'Enter passphrase of the private key', 
            placeHolder: 'PASSPHRASE', 
            password: true, 
            validateInput: value => (value.length == 0) ? "Passphrase cannot be empty" : null 
          });

        try {
          await privateKeyArmored.decrypt(passString!);
        } catch (error) {
          vscode.window.showErrorMessage('' + error);
        }
      }

      const { data: decrypted } = await openpgp.decrypt({
        message: encryptedMessage,
        privateKeys: [privateKeyArmored]
      });

      replaceCurrentEditorContent(decrypted);

    })();
  }));

}

// this method is called when your extension is deactivated
export function deactivate() { }


async function getPublicKeys() {

  const folderUri = getKeysFolderUri();
  const keys_folder = await vscode.workspace.fs.readDirectory(folderUri);

  let keys: openpgp.key.Key[] = [];

  for await (let element of keys_folder) {

    const fileUri = folderUri.with({ path: posix.join(folderUri.path, element[0]) });
    const readData = await vscode.workspace.fs.readFile(fileUri);
    const readStr = Buffer.from(readData).toString('utf8');

    const key = await openpgp.key.readArmored(readStr);
    
    if (key.keys[0].isPublic()) {
      keys.push(key.keys[0]);
    }
  }

  return keys;
}


async function getPrivateKeys() {
  
  const folderUri = getKeysFolderUri();
  const keys_folder = await vscode.workspace.fs.readDirectory(folderUri);

  let keys: openpgp.key.Key[] = [];

  for await (let element of keys_folder) {

    console.info(`reading ${element}`);
    const fileUri = folderUri.with({ path: posix.join(folderUri.path, element[0]) });
    const readData = await vscode.workspace.fs.readFile(fileUri);
    const readStr = Buffer.from(readData).toString('utf8');

    const key:openpgp.key.KeyResult= await openpgp.key.readArmored(readStr);

    
    if (key.keys[0].isPrivate()) {
      keys.push(key.keys[0]);
    }
  }

  return keys;
}


async function pickPublicKey() {
  const keys = await getPublicKeys();

  const keyList: vscode.QuickPickItem[] = keys.map((key, i) => {
    return {
      label: key.getUserIds()[0],
      detail: key.getFingerprint(),
      id: i
    };
  });

  const result = await window.showQuickPick(keyList, {
    placeHolder: 'Pick a public key'
  });
  return keys[result.id];
}

async function encryptWithPublicKey(text: string, publicKey: openpgp.key.Key) {

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
      label: key.getUserIds()[0],
      detail: key.getFingerprint(),
      id: i
    };
  });

  const result = await window.showQuickPick(keyList, {
    placeHolder: 'Pick a private key to decrypt'
  });
  return keys[result.id];
}


async function getMatchingPrivateKey(encryptedMessage:openpgp.message.Message) {
  const keys = await getPrivateKeys();

  for (let message_key of encryptedMessage.getEncryptionKeyIds()) {
    const message_key_bytes = message_key.bytes;

    for (let private_key of keys) {
      for (let private_key_id of private_key.getKeyIds()){
        if(private_key_id.bytes === message_key_bytes){
          return private_key;
        }
      }
    }
  }

  return null;
}


function getKeysFolderUri() {
  let keys_folder = ''+vscode.workspace.getConfiguration().get('openpgp-encrypt.encrypt.keysFolder');
  keys_folder = keys_folder.replace("${homeDir}", os.homedir());
  return vscode.Uri.file(keys_folder);
}

function replaceCurrentEditorContent(newText: string){
  const document = vscode.window.activeTextEditor!.document;
  const invalidRange = new vscode.Range(0, 0, document.lineCount, 0);
  const fullRange = document.validateRange(invalidRange);
  vscode.window.activeTextEditor!.edit(edit => edit.replace(fullRange, newText));
}

