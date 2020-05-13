import { QuickPickItem, window, Disposable, CancellationToken, QuickInputButton, QuickInput, ExtensionContext, QuickInputButtons, Uri } from 'vscode';

export async function collectNewPrivateKey(){
    const state = {} as Partial<State>;
    await MultiStepInput.run(input => inputName(input, state));
    return state as State;
}

interface State {
  name: string;
  email: string;
  passphrase: string;
  comment: string;
  title: string;
  step: number;
  totalSteps: number;
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


const title = 'New Private Key';

async function inputName(input: MultiStepInput, state: Partial<State>) {
  state.name = await input.showInputBox({
    title,
    step: 1,
    totalSteps: 4 ,
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
    totalSteps: 4,
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
    totalSteps: 4,
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
    totalSteps: 4,
    value: state.passphrase || '',
    prompt: 'Enter a passphrase (Empty for no passphrase)',
    validate: validateNameIsUnique,
    shouldResume: shouldResume,
    isPassword: true
  });
  
}



// -------------------------------------------------------
// Helper code that wraps the API for the multi-step case.
// -------------------------------------------------------
class InputFlowAction {
  private constructor() { }
  static back = new InputFlowAction();
  static cancel = new InputFlowAction();
  static resume = new InputFlowAction();
}

type InputStep = (input: MultiStepInput) => Thenable<InputStep | void>;

interface QuickPickParameters<T extends QuickPickItem> {
  title: string;
  step: number;
  totalSteps: number;
  items: T[];
  activeItem?: T;
  placeholder: string;
  buttons?: QuickInputButton[];
  shouldResume: () => Thenable<boolean>;
}

interface InputBoxParameters {
  title: string;
  step: number;
  totalSteps: number;
  value: string;
  prompt: string;
  validate: (value: string) => Promise<string | undefined>;
  buttons?: QuickInputButton[];
  shouldResume: () => Thenable<boolean>;
  isPassword: boolean;
}

class MultiStepInput {

  static async run<T>(start: InputStep) {
    const input = new MultiStepInput();
    return input.stepThrough(start);
  }

  private current?: QuickInput;
  private steps: InputStep[] = [];

  private async stepThrough<T>(start: InputStep) {
    let step: InputStep | void = start;
    while (step) {
      this.steps.push(step);
      if (this.current) {
        this.current.enabled = false;
        this.current.busy = true;
      }
      try {
        step = await step(this);
      } catch (err) {
        if (err === InputFlowAction.back) {
          this.steps.pop();
          step = this.steps.pop();
        } else if (err === InputFlowAction.resume) {
          step = this.steps.pop();
        } else if (err === InputFlowAction.cancel) {
          step = undefined;
        } else {
          throw err;
        }
      }
    }
    if (this.current) {
      this.current.dispose();
    }
  }

  async showQuickPick<T extends QuickPickItem, P extends QuickPickParameters<T>>({ title, step, totalSteps, items, activeItem, placeholder, buttons, shouldResume}: P) {
    const disposables: Disposable[] = [];
    try {
      return await new Promise<T | (P extends { buttons: (infer I)[] } ? I : never)>((resolve, reject) => {
        const input = window.createQuickPick<T>();
        input.title = title;
        input.step = step;
        input.totalSteps = totalSteps;
        input.placeholder = placeholder;
        input.items = items;
        if (activeItem) {
          input.activeItems = [activeItem];
        }
        input.buttons = [
          ...(this.steps.length > 1 ? [QuickInputButtons.Back] : []),
          ...(buttons || [])
        ];
        disposables.push(
          input.onDidTriggerButton(item => {
            if (item === QuickInputButtons.Back) {
              reject(InputFlowAction.back);
            } else {
              resolve(<any>item);
            }
          }),
          input.onDidChangeSelection(items => resolve(items[0])),
          input.onDidHide(() => {
            (async () => {
              reject(shouldResume && await shouldResume() ? InputFlowAction.resume : InputFlowAction.cancel);
            })()
              .catch(reject);
          })
        );
        if (this.current) {
          this.current.dispose();
        }
        this.current = input;
        this.current.show();
      });
    } finally {
      disposables.forEach(d => d.dispose());
    }
  }

  async showInputBox<P extends InputBoxParameters>({ title, step, totalSteps, value, prompt, validate, buttons, shouldResume, isPassword }: P) {
    const disposables: Disposable[] = [];
    try {
      return await new Promise<string | (P extends { buttons: (infer I)[] } ? I : never)>((resolve, reject) => {
        const input = window.createInputBox();
        input.password = isPassword;
        input.title = title;
        input.step = step;
        input.totalSteps = totalSteps;
        input.value = value || '';
        input.prompt = prompt;
        input.buttons = [
          ...(this.steps.length > 1 ? [QuickInputButtons.Back] : []),
          ...(buttons || [])
        ];
        let validating = validate('');
        disposables.push(
          input.onDidTriggerButton(item => {
            if (item === QuickInputButtons.Back) {
              reject(InputFlowAction.back);
            } else {
              resolve(<any>item);
            }
          }),
          input.onDidAccept(async () => {
            const value = input.value;
            input.enabled = false;
            input.busy = true;
            if (!(await validate(value))) {
              resolve(value);
            }
            input.enabled = true;
            input.busy = false;
          }),
          input.onDidChangeValue(async text => {
            const current = validate(text);
            validating = current;
            const validationMessage = await current;
            if (current === validating) {
              input.validationMessage = validationMessage;
            }
          }),
          input.onDidHide(() => {
            (async () => {
              reject(shouldResume && await shouldResume() ? InputFlowAction.resume : InputFlowAction.cancel);
            })()
              .catch(reject);
          })
        );
        if (this.current) {
          this.current.dispose();
        }
        this.current = input;
        this.current.show();
      });
    } finally {
      disposables.forEach(d => d.dispose());
    }
  }
}