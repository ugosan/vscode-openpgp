import * as vscode from 'vscode';
import * as openpgp from 'openpgp';
import { posix } from 'path';
import { collectNewKeyPair } from './generateKeyPairWizard';
import { window } from 'vscode';
const os = require('os');


export class OutlineProvider
  implements vscode.TreeDataProvider<any> {

  constructor(private outline: any) { }

  getTreeItem(item: any): vscode.TreeItem {
    let treeitem = new vscode.TreeItem(
      item.label,
      item.children.length > 0
        ? vscode.TreeItemCollapsibleState.Collapsed
        : vscode.TreeItemCollapsibleState.None
    );

    treeitem.tooltip = item.label;

    treeitem.iconPath = new vscode.ThemeIcon(item.iconName);
    treeitem.contextValue = item.contextValue;

    return treeitem;
  }

  getChildren(element?: any): Thenable<[]> {
    if (element) {
      return Promise.resolve(element.children);
    } else {
      return Promise.resolve(this.outline);
    }
  }
}

export function activate(context: vscode.ExtensionContext) {

  refreshActivityBar();


  context.subscriptions.push(vscode.commands.registerCommand('vscode-openpgp.generatePrivateKey', () => {

    (async () => {

      const folderUri = getKeysFolderUri();
      await vscode.workspace.fs.createDirectory(folderUri);

      const inputs = await collectNewKeyPair();

      try {
        const { privateKey, publicKey, revocationCertificate } = await openpgp.generateKey({
          userIDs: [{ name: inputs.name, email: inputs.email }],
          type: 'ecc',
          curve: <openpgp.EllipticCurveName>inputs.curve.label,
          passphrase: inputs.passphrase
        });

        const filename = [inputs.name.replace(' ', ''), inputs.email, inputs.comment];
        let fileUri = folderUri.with({ path: posix.join(folderUri.path, filename.join('_') + '.key') });
        await vscode.workspace.fs.writeFile(fileUri, Buffer.from(privateKey, 'utf8'));
        fileUri = folderUri.with({ path: posix.join(folderUri.path, filename.join('_') + '.pub') });
        await vscode.workspace.fs.writeFile(fileUri, Buffer.from(publicKey, 'utf8'));
        
        //TODO: actually write the revokation certificate 
        //fileUri = folderUri.with({ path: posix.join(folderUri.path, filename.join('_') + '.revoke') });
        //await vscode.workspace.fs.writeFile(fileUri, Buffer.from(revocationCertificate, 'utf8'));

        vscode.window.showInformationMessage(
          `Private key generated to ${fileUri}`
        );

        refreshActivityBar();
      } catch (error) {
        vscode.window.showErrorMessage('' + error);
        return;
      }
    })();
  }));

  context.subscriptions.push(vscode.commands.registerCommand('vscode-openpgp.encrypt', (e) => {

    (async () => {

      if (e) {
        var openPath = vscode.Uri.file(e.path);
        vscode.workspace.openTextDocument(openPath).then(doc => {
          vscode.window.showTextDocument(doc);
        });
      }

      const fullText = vscode.window.activeTextEditor!.document.getText();
      const publicKey = await pickPublicKey();
      if (publicKey == null) {
        return;
      }
      const encrypted = await encryptWithPublicKey(fullText, publicKey);
      replaceCurrentEditorContent(encrypted);

    })();
  }));

  context.subscriptions.push(vscode.commands.registerCommand('vscode-openpgp.openKey', (e) => {

    if (e.path) {
      var openPath = vscode.Uri.file(e.path.path);
      vscode.workspace.openTextDocument(openPath).then(doc => {
        vscode.window.showTextDocument(doc);
      });
    }
  }));

  context.subscriptions.push(vscode.commands.registerCommand('vscode-openpgp.importKey', (e) => { }));

  context.subscriptions.push(vscode.commands.registerCommand('vscode-openpgp.importClipboardKey', (e) => {

    (async () => {

      let clipboard_content = await vscode.env.clipboard.readText();

      try {
        const key = await openpgp.readKey({ armoredKey: clipboard_content });

        const folderUri = getKeysFolderUri();
        await vscode.workspace.fs.createDirectory(folderUri);

        let fileUri = folderUri.with({ path: posix.join(folderUri.path, key.getKeys()[0].getFingerprint() + '.pub') });
        await vscode.workspace.fs.writeFile(fileUri, Buffer.from(clipboard_content, 'utf8'));

        refreshActivityBar();
      } catch (error) {
        vscode.window.showErrorMessage('' + error);
        return;
      }

    })();
  }));

  context.subscriptions.push(vscode.commands.registerCommand('vscode-openpgp.publishKey', (e) => { }));

  context.subscriptions.push(vscode.commands.registerCommand('vscode-openpgp.refreshKeys', (e) => {
    refreshActivityBar();
  }));

  context.subscriptions.push(vscode.commands.registerCommand('vscode-openpgp.removeKey', (e) => {

    (async () => {
      var choice = await vscode.window.showInformationMessage(`Do you want to remove ${e.label}`, "Yes", "Cancel");
      if (choice == 'Yes') {
        var filePath = vscode.Uri.file(e.path.path);
        await vscode.workspace.fs.delete(filePath);
        refreshActivityBar();
        vscode.window.showInformationMessage(`${e.label} deleted.`);

        /*var revoke = await vscode.window.showInformationMessage(`Do you want to also revoke the key? This will unpublish the key if its currently published.`, "Just delete", "Delete and Revoke", "Cancel");

        if(revoke == 'Just delete'){
          var filePath = vscode.Uri.file(e.path.path);
          await vscode.workspace.fs.delete(filePath);
          refreshActivityBar();
          vscode.window.showInformationMessage(`Deleted successfully`);
        }*/

      }

    })();
  }));


  context.subscriptions.push(vscode.commands.registerCommand('vscode-openpgp.decrypt', (e) => {

    (async () => {
      let encryptedText = vscode.window.activeTextEditor!.document.getText();

      if (e) {
        var openPath = vscode.Uri.file(e.path);
        const readData = await vscode.workspace.fs.readFile(openPath);
        encryptedText = Buffer.from(readData).toString('utf8');
        vscode.workspace.openTextDocument(openPath).then(doc => {
          vscode.window.showTextDocument(doc);
        });

      }


      try {
        const message = await openpgp.readMessage({
          armoredMessage: encryptedText // parse armored message
        });


        let privateKeyArmored = await getMatchingPrivateKey(message);


        if (privateKeyArmored === null) {
          privateKeyArmored = await pickPrivateKey();
        } else {
          vscode.window.setStatusBarMessage('Found matching private key ! ', 4000);
        }

        console.info(privateKeyArmored)


        if (!privateKeyArmored.keyPacket.isDecrypted()) {
          const passString = await vscode.window.showInputBox({
            prompt: 'Passphrase for [' + privateKeyArmored?.getUserIDs()[0] + ']',
            placeHolder: 'Enter passphrase...',
            password: true,
            validateInput: value => (value.length === 0) ? "Passphrase cannot be empty" : null
          });


          let privateKey = await openpgp.decryptKey({
            privateKey: await openpgp.readPrivateKey({ armoredKey: privateKeyArmored.armor() }),
            passphrase: passString
          });
          const { data: decrypted } = await openpgp.decrypt({
            message: message,
            decryptionKeys: [privateKey]
          });

          replaceCurrentEditorContent(decrypted);
        } else {
          let privateKey = await openpgp.readPrivateKey({ armoredKey: privateKeyArmored.armor() });
          const { data: decrypted } = await openpgp.decrypt({
            message: message,
            decryptionKeys: [privateKey]
          });

          replaceCurrentEditorContent(decrypted);
        }

      } catch (error) {
        vscode.window.showErrorMessage('' + error);
      }

    })();

  }));

}

export function deactivate() { }

async function refreshActivityBar() {

  const keys = await getKeys();
  console.info(keys);

  let privateKeyList: any[] = [];
  let publicKeyList: any[] = [];

  for (let key of await getPrivateKeys()) {
    privateKeyList.push({
      label: key.getUserIDs()[0],
      iconName: "key",
      contextValue: "privateKey",
      children: [
        {
          label: key.getFingerprint().toUpperCase(),
          iconName: "shield",
          contextValue: "fingerprint",
          children: []
        },
      ]
    })
  }

  for (let key of await getPublicKeys()) {
    publicKeyList.push({
      label: key.getUserIDs()[0],
      iconName: "key",
      contextValue: "publickey",
      children: [
        {
          label: key.getFingerprint().toUpperCase(),
          iconName: "shield",
          contextValue: "fingerprint",
          children: []
        },
      ]
    })
  }


  vscode.window.registerTreeDataProvider(
    "vscode-openpgp.privateKeysView",
    new OutlineProvider(privateKeyList)
  );

  vscode.window.registerTreeDataProvider(
    "vscode-openpgp.publicKeysView",
    new OutlineProvider(publicKeyList)
  );

}

async function getKeys() {

  const folderUri = getKeysFolderUri();
  const keys_folder = await vscode.workspace.fs.readDirectory(folderUri);

  let allKeys = [];

  for await (let element of keys_folder) {

    const fileUri = folderUri.with({ path: posix.join(folderUri.path, element[0]) });
    console.debug(fileUri);
    try {
      const readData = await vscode.workspace.fs.readFile(fileUri);

      const readStr = Buffer.from(readData).toString('utf8');


      const key = await openpgp.readKey({ armoredKey: readStr });

      allKeys.push({ key: key.getKeys()[0], filePath: fileUri });
    } catch (error) {
      vscode.window.showErrorMessage('' + error);
    }

  }

  return allKeys;
}

async function getPublicKeys() {

  const folderUri = getKeysFolderUri();
  const keys_folder = await vscode.workspace.fs.readDirectory(folderUri);

  let keys: openpgp.Key[] = [];

  for await (let element of keys_folder) {
    const fileUri = folderUri.with({ path: posix.join(folderUri.path, element[0]) });

    try {
      
      const readData = await vscode.workspace.fs.readFile(fileUri);

      const readStr = Buffer.from(readData).toString('utf8');

      const key = await openpgp.readKey({ armoredKey: readStr });

      if (!key.isPrivate()) {
        keys.push(key);
      }
    } catch (error) {
      vscode.window.showErrorMessage(
       error + '' +fileUri, ['a', 'b']
      );
    }

  }

  return keys;
}


async function getPrivateKeys() {

  const folderUri = getKeysFolderUri();
  const keys_folder = await vscode.workspace.fs.readDirectory(folderUri);

  let keys: openpgp.Key[] = [];

  for await (let element of keys_folder) {

    try {

      const fileUri = folderUri.with({ path: posix.join(folderUri.path, element[0]) });
      const readData = await vscode.workspace.fs.readFile(fileUri);
      const readStr = Buffer.from(readData).toString('utf8');

      const key = await openpgp.readKey({ armoredKey: readStr });

      if (key.isPrivate()) {
        keys.push(key);
      }
    } catch (error) {
      vscode.window.showErrorMessage('' + error);
    }
  }

  return keys;

}


async function pickPublicKey() {

  const keys = await getPublicKeys();

  if (keys.length == 0) {
    vscode.window.showErrorMessage(
      'No keys were found in your keys folder! \n Generate a new key pair or import existing public keys.',
      {
        "modal": true
      }
    );
    return;
  }

  const keyList: vscode.QuickPickItem[] = keys.map((key, i) => {
    return {
      label: key.getUserIDs()[0],
      detail: key.getFingerprint(),
      id: i
    };
  });

  const result = await window.showQuickPick(keyList, {
    placeHolder: 'Pick a public key'
  });
  return keys[(result as any).id];
}

async function encryptWithPublicKey(text: string, publicKey: openpgp.Key) {

  openpgp.config.commentString = "https://openpgpjs.org\nComment: http://vscode-openpgp.ugosan.org";
  openpgp.config.showComment = true;

  let encrypted = await openpgp.encrypt({
    message: await openpgp.createMessage({ text: text }),
    encryptionKeys: publicKey
  });

  return encrypted;
}

async function pickPrivateKey() {

  const keys = await getPrivateKeys();

  const keyList: vscode.QuickPickItem[] = keys.map((key, i) => {
    return {
      label: key.getUserIDs()[0],
      detail: key.getFingerprint(),
      id: i
    };
  });

  const result = await window.showQuickPick(keyList, {
    placeHolder: 'Pick a private key to decrypt'
  });
  return keys[(result as any).id];

}

async function getMatchingPrivateKey(encryptedMessage: openpgp.Message<string>) {
  const keys = await getPrivateKeys();

  for (let message_key of encryptedMessage.getEncryptionKeyIDs()) {
    const message_key_bytes = message_key.bytes;

    for (let private_key of keys) {
      for (let private_key_id of private_key.getKeyIDs()) {
        if (private_key_id.bytes === message_key_bytes) {
          return private_key;
        }
      }
    }
  }

  return null;
}

function getKeysFolderUri() {
  let keys_folder = '' + vscode.workspace.getConfiguration().get('openpgp-encrypt.encrypt.keysFolder');
  keys_folder = keys_folder.replace("${homeDir}", os.homedir());
  return vscode.Uri.file(keys_folder);
}

function replaceCurrentEditorContent(newText: string) {
  const document = vscode.window.activeTextEditor!.document;
  const invalidRange = new vscode.Range(0, 0, document.lineCount, 0);
  const fullRange = document.validateRange(invalidRange);
  vscode.window.activeTextEditor!.edit(edit => edit.replace(fullRange, newText));
}
