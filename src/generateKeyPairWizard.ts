import { MultiStepInput } from './inputFlowAction';
import { QuickPickItem } from 'vscode';

export async function collectNewKeyPair(){
    const state = {} as Partial<State>;
    await MultiStepInput.run(input => inputName(input, state));
    return state as State;
}

const CURVES = [
  {'label': 'p256'},
  {'label': 'p384'},
  {'label': 'p521'},
  {'label': 'curve25519'},
  {'label': 'secp256k1'},
  {'label': 'ed25519'},
  {'label': 'brainpoolP256r1'},
  {'label': 'brainpoolP384r1'},
  {'label': 'brainpoolP512r1'}
]


interface State {
  name: string;
  email: string;
  passphrase: string;
  comment: string;
  title: string;
  step: number;
  totalSteps: number;
  curve: QuickPickItem;
}


function shouldResume() {
  // Could show a notification with the option to resume.
  return new Promise<boolean>((resolve, reject) => {

  });
}

async function validateNameIsUnique(name: string) {
  // ...validate...
  await new Promise(resolve => setTimeout(resolve, 1000));
  return name === 'vscode' ? 'Name not unique' : undefined;
}


const title = 'New Key Pair';

async function inputName(input: MultiStepInput, state: Partial<State>) {
  state.name = await input.showInputBox({
    title,
    step: 1,
    totalSteps: 5,
    value: state.name || '',
    prompt: 'Full Name',
    validate: validateNameIsUnique,
    shouldResume: shouldResume,
    isPassword: false
  });
  return (input: MultiStepInput) => inputEmail(input, state);
}



async function inputEmail(input: MultiStepInput, state: Partial<State>) {
  state.email = await input.showInputBox({
    title,
    step: 2,
    totalSteps: 5,
    value: state.email || '',
    prompt: 'Email Address',
    validate: validateNameIsUnique,
    shouldResume: shouldResume,
    isPassword: false
  });
  return (input: MultiStepInput) => inputComment(input, state);
}

async function inputComment(input: MultiStepInput, state: Partial<State>) {
  state.comment = await input.showInputBox({
    title,
    step: 2,
    totalSteps: 5,
    value: state.comment || '',
    prompt: 'Comment (optional)',
    validate: validateNameIsUnique,
    shouldResume: shouldResume,
    isPassword: false
  });
  return (input: MultiStepInput) => inputPassphrase(input, state);
}


async function inputPassphrase(input: MultiStepInput, state: Partial<State>) {
  state.passphrase = await input.showInputBox({
    title,
    password: true, 
    step: 3,
    totalSteps: 5,
    value: state.passphrase || '',
    prompt: 'Enter a passphrase (Empty for no passphrase)',
    validate: validateNameIsUnique,
    shouldResume: shouldResume,
    isPassword: true
  });
  return (input: MultiStepInput) => inputCurve(input, state);
}

async function inputCurve(input: MultiStepInput, state: Partial<State>) {
  const curvesList: QuickPickItem[] = CURVES.map((key, i) => {
    return {
      label: key['label'],
      id: i
    };
  });

  state.curve = await input.showQuickPick({
    title,
    step: 4,
    totalSteps: 5,
    items: curvesList,
    placeholder: 'Pick an elliptic curve',
    shouldResume: shouldResume,
    activeItem: curvesList[3]
  });
  
}


