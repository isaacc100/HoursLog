export default function Footer({ footerText }: { footerText?: string }) {
  return (
    <footer className="bg-light border-top py-3 mt-auto">
      <div className="container text-center text-muted small">
        {footerText || '© 2026 HoursLog. A volunteer hours tracking application.'}
      </div>
    </footer>
  )
}
