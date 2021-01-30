import * as vscode from 'vscode';
import * as openpgp from 'openpgp';
import { posix } from 'path';
import { collectNewPrivateKey } from './multiStepInput';
import { window } from 'vscode';
const os = require('os');



export class OutlineProvider
  implements vscode.TreeDataProvider<any> {
  constructor(private outline: any) {
    //console.log(outline);
  }

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
      
      const inputs = await collectNewPrivateKey();

      const { privateKeyArmored, publicKeyArmored, revocationCertificate } = await openpgp.generateKey({
        userIds: [{ name: inputs.name, email: inputs.email }],
        curve: 'ed25519',
        passphrase: inputs.passphrase
      });

      const filename = [inputs.name.replace(' ', ''), inputs.email, inputs.comment];
      let fileUri = folderUri.with({ path: posix.join(folderUri.path, filename.join('_') + '.key') });
      await vscode.workspace.fs.writeFile(fileUri, Buffer.from(privateKeyArmored, 'utf8'));
      vscode.window.showInformationMessage(`Private key generated to ${fileUri}`);
      fileUri = folderUri.with({ path: posix.join(folderUri.path, filename.join('_') + '.pub') });
      await vscode.workspace.fs.writeFile(fileUri, Buffer.from(publicKeyArmored, 'utf8'));

      refreshActivityBar();
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

  context.subscriptions.push(vscode.commands.registerCommand('vscode-openpgp.openKey', (e) => {
    console.info(e);
    if(e.path){
      var openPath = vscode.Uri.file(e.path.path);
      vscode.workspace.openTextDocument(openPath).then(doc => {
        vscode.window.showTextDocument(doc);
      });
    }
  }));

  context.subscriptions.push(vscode.commands.registerCommand('vscode-openpgp.importKey', (e) => {
    
    (async () => {

      const query = await vscode.window.showInputBox({ 
            prompt: 'Enter the email address', 
            placeHolder: 'someone@email.com', 
            password: false, 
            validateInput: value => (value.length === 0) ? "Query should not be empty" : null 
          });


      var hkp = new openpgp.HKP('https://keys.mailvelope.com');
      
      var result = await hkp.lookup({query: query});

      console.info(result);

      if(!result){
        vscode.window.showWarningMessage(`Could not find a public key for "${query}" at https://keys.mailvelope.com`);
        return;
      }

      const key = await openpgp.key.readArmored(Buffer.from(result).toString('utf8'));

      let filename = key.keys[0].getFingerprint();

      const folderUri = getKeysFolderUri();
      await vscode.workspace.fs.createDirectory(folderUri);
      
      let fileUri = folderUri.with({ path: posix.join(folderUri.path, filename + '.pub') });

      await vscode.workspace.fs.writeFile(fileUri, Buffer.from(result, 'utf8'));

      refreshActivityBar();

    })();
  }));

  context.subscriptions.push(vscode.commands.registerCommand('vscode-openpgp.importClipboardKey', (e) => {
    
    (async () => {

      let clipboard_content = await vscode.env.clipboard.readText(); 

      const key = await openpgp.key.readArmored(clipboard_content);
      if(key.err){
        vscode.window.showErrorMessage('No public key was found in the clipboard.');
        return;
      }

      
      const folderUri = getKeysFolderUri();
      await vscode.workspace.fs.createDirectory(folderUri);

      let fileUri = folderUri.with({ path: posix.join(folderUri.path, key.keys[0].getFingerprint() + '.pub') });
      await vscode.workspace.fs.writeFile(fileUri, Buffer.from(clipboard_content, 'utf8'));
      
      refreshActivityBar();

    })();
  }));

  context.subscriptions.push(vscode.commands.registerCommand('vscode-openpgp.publishKey', (e) => {

    (async () => {

    if(e.path){

      var openPath = vscode.Uri.file(e.path.path);
      const readData  = await vscode.workspace.fs.readFile(openPath);
      var publicKey = Buffer.from(readData).toString('utf8');

      var hkp = new openpgp.HKP('https://keys.mailvelope.com');

      hkp.upload(publicKey).then(function() { 
        vscode.window.showInformationMessage(`Public key published to hhttps://keys.mailvelope.com`);
      });

    }
    })();
  }));

  context.subscriptions.push(vscode.commands.registerCommand('vscode-openpgp.refreshKeys', (e) => {
    refreshActivityBar();
  }));

  context.subscriptions.push(vscode.commands.registerCommand('vscode-openpgp.removeKey', (e) => {

    (async () => {
      var choice = await vscode.window.showInformationMessage(`Do you want to remove ${e.label}`, "Yes", "Cancel");
      if(choice == 'Yes'){
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
      
      if(e){
        var openPath = vscode.Uri.file(e.path);
        const readData  = await vscode.workspace.fs.readFile(openPath);
        encryptedText = Buffer.from(readData).toString('utf8');
        vscode.workspace.openTextDocument(openPath).then(doc => {
          vscode.window.showTextDocument(doc);
        });
        
      }


      try{
        const encryptedMessage:openpgp.message.Message = await openpgp.message.readArmored(encryptedText);

        let privateKeyArmored = await getMatchingPrivateKey(encryptedMessage);
        //console.info(privateKeyArmored?.getUserIds());
        if(privateKeyArmored === null){
          privateKeyArmored = await pickPrivateKey();
        }else{
          vscode.window.setStatusBarMessage('Found matching private key ! ', 4000);
        }

        

        if (!privateKeyArmored.isDecrypted()) {
          const passString = await vscode.window.showInputBox({ 
            prompt: 'Passphrase for ['+privateKeyArmored?.getUserIds()[0]+']', 
            placeHolder: 'Enter passphrase...', 
            password: true, 
            validateInput: value => (value.length === 0) ? "Passphrase cannot be empty" : null 
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

      }catch (error) {
        vscode.window.showErrorMessage('' + error);
      }

    })();
  }));


  
}

// this method is called when your extension is deactivated
export function deactivate() { }

async function refreshActivityBar() {

  const keys = await getKeys();
  let privateKeyList: any[] = [];
  let publicKeyList: any[] = [];

  for (let key of keys) {
    if(key.key.isPrivate()){
      privateKeyList.push({
        label: key.key.getUserIds()[0],
        iconName: "key",
        contextValue: "privateKey",
        path: key.filePath,
        children: [
          {
            label: key.key.getFingerprint().toUpperCase(),
            iconName: "shield",
            contextValue: "fingerprint",
            children: []
          },
        ]
      })
    }else{
      publicKeyList.push({
        label: key.key.getUserIds()[0],
        iconName: "broadcast",
        path: key.filePath,
        contextValue: "publicKey",
        children: [
          {
            label: key.key.getFingerprint().toUpperCase(),
            iconName: "shield",
            contextValue: "fingerprint",
            children: []
          },
        ]
      });
    }
  
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
    const readData = await vscode.workspace.fs.readFile(fileUri);

    const readStr = Buffer.from(readData).toString('utf8');

    const key = await openpgp.key.readArmored(readStr);
    
    allKeys.push({key: key.keys[0], filePath: fileUri});

  }

  return allKeys;
}

async function getPublicKeys() {

  const folderUri = getKeysFolderUri();
  const keys_folder = await vscode.workspace.fs.readDirectory(folderUri);

  let keys: openpgp.key.Key[] = [];

  for await (let element of keys_folder) {

    const fileUri = folderUri.with({ path: posix.join(folderUri.path, element[0]) });
    const readData = await vscode.workspace.fs.readFile(fileUri);

    const readStr = Buffer.from(readData).toString('utf8');

    //console.info(readStr);

    const key = await openpgp.key.readArmored(readStr);
    
    //console.info('key: ', JSON.stringify(key));

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
  return keys[(result as any).id];
}

async function encryptWithPublicKey(text: string, publicKey: openpgp.key.Key) {

  let msg = openpgp.message.fromText(text);

  let { data: encrypted } = await openpgp.encrypt({
    message: msg,
    publicKeys: publicKey
  });

  encrypted = encrypted.replace("Comment: https://openpgpjs.org", "Comment: https://openpgpjs.org\nComment: Encrypted using vscode-openpgp (http://vscode-openpgp.ugosan.org)")

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
  return keys[(result as any).id];
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
