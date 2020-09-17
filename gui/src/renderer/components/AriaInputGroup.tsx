import React, { useContext, useEffect, useMemo, useState } from 'react';

let groupCounter = 0;
function getNewId() {
  return groupCounter++;
}

interface IAriaInputContext {
  inputId: string;
  labelId?: string;
  descriptionId?: string;
  setHasLabel: (value: boolean) => void;
  setHasDescription: (value: boolean) => void;
}

const missingAriaInputContextError = new Error('Missing AriaInputContext.Provider');
const AriaInputContext = React.createContext<IAriaInputContext>({
  get inputId(): string {
    throw missingAriaInputContextError;
  },
  setHasLabel() {
    throw missingAriaInputContextError;
  },
  setHasDescription() {
    throw missingAriaInputContextError;
  },
});

interface IAriaInputGroupProps {
  children: React.ReactNode;
}

export function AriaInputGroup(props: IAriaInputGroupProps) {
  const id = useMemo(getNewId, []);

  const [hasLabel, setHasLabel] = useState(false);
  const [hasDescription, setHasDescription] = useState(false);

  const contextValue = {
    inputId: `${id}-input`,
    labelId: hasLabel ? `${id}-label` : undefined,
    descriptionId: hasDescription ? `${id}-description` : undefined,
    setHasLabel,
    setHasDescription,
  };

  return (
    <AriaInputContext.Provider value={contextValue}>{props.children}</AriaInputContext.Provider>
  );
}

interface IAriaElementProps {
  children: React.ReactElement;
}

export function AriaInput(props: IAriaElementProps) {
  const { inputId, labelId, descriptionId } = useContext(AriaInputContext);

  return React.cloneElement(props.children, {
    id: inputId,
    'aria-labelledby': labelId,
    'aria-describedby': descriptionId,
  });
}

export function AriaLabel(props: IAriaElementProps) {
  const { inputId, labelId, setHasLabel } = useContext(AriaInputContext);

  useEffect(() => {
    setHasLabel(true);
    return () => setHasLabel(false);
  }, []);

  return React.cloneElement(props.children, {
    id: labelId,
    htmlFor: inputId,
  });
}

export function AriaDescription(props: IAriaElementProps) {
  const { descriptionId, setHasDescription } = useContext(AriaInputContext);

  useEffect(() => {
    setHasDescription(true);
    return () => setHasDescription(false);
  }, []);

  return React.cloneElement(props.children, {
    id: descriptionId,
  });
}
