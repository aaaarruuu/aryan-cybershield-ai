import { useCallback, useEffect, useRef, useState } from 'react'

/** Run an async loader with loading/error state. `reload()` re-runs it. */
export function useAsync(fn, deps = []) {
  const [state, setState] = useState({ data: null, loading: true, error: null })
  const alive = useRef(true)
  const run = useCallback(() => {
    setState((s) => ({ ...s, loading: true, error: null }))
    return fn().then(
      (data) => alive.current && setState({ data, loading: false, error: null }),
      (e) => alive.current && setState({ data: null, loading: false, error: e.message || 'Something went wrong' }),
    )
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps)
  useEffect(() => { alive.current = true; run(); return () => { alive.current = false } }, [run])
  return { ...state, reload: run }
}
