import { Component } from 'react'

export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props)
    this.state = { error: null }
  }

  static getDerivedStateFromError(error) {
    return { error }
  }

  componentDidCatch(error, info) {
    console.error('[THA] Render error:', error, info)
  }

  render() {
    if (this.state.error) {
      return (
        <div className="min-h-screen bg-ink flex items-center justify-center p-8">
          <div className="border border-alert/40 bg-alert/5 rounded-lg p-8 max-w-lg w-full">
            <p className="stamp text-alert text-xl mb-3">render error</p>
            <p className="text-sm font-mono text-bone-muted mb-4">
              {String(this.state.error.message || this.state.error)}
            </p>
            <button
              onClick={() => this.setState({ error: null })}
              className="text-xs font-mono text-terminal hover:underline"
            >
              try again
            </button>
          </div>
        </div>
      )
    }
    return this.props.children
  }
}
