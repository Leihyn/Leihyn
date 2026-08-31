type IconName = 'menu' | 'close' | 'file' | 'clock' | 'check' | 'arrow' | 'reset'

export function Icon({ name }: { name: IconName }) {
  const paths: Record<IconName, React.ReactNode> = {
    menu: <><path d="M4 7h16M4 12h16M4 17h16" /></>,
    close: <><path d="m6 6 12 12M18 6 6 18" /></>,
    file: <><path d="M6 3h9l3 3v15H6zM9 11h6M9 15h6M15 3v4h4" /></>,
    clock: <><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 2" /></>,
    check: <><path d="m5 12 4 4L19 6" /></>,
    arrow: <><path d="M5 12h14M14 7l5 5-5 5" /></>,
    reset: <><path d="M4 12a8 8 0 1 0 2.3-5.7L4 8M4 4v4h4" /></>,
  }
  return <svg className="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="square" aria-hidden="true">{paths[name]}</svg>
}

