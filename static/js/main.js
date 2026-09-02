/**
 * Maceió Turismo - Interações do Cliente
 * Princípios: Progressive Enhancement, Zero dependências externas, Acessibilidade.
 */

document.addEventListener('DOMContentLoaded', () => {
  // Fechamento e auto-dismiss de alertas
  const alertCloseButtons = document.querySelectorAll('.alert-close');
  alertCloseButtons.forEach(button => {
    button.addEventListener('click', (e) => {
      const alertBox = e.target.closest('.alert');
      if (alertBox) {
        alertBox.style.opacity = '0';
        alertBox.style.transform = 'translateY(-10px)';
        alertBox.style.transition = 'all 0.3s ease';
        setTimeout(() => alertBox.remove(), 300);
      }
    });
  });

  // Auto-dispensa de mensagens de sucesso e info após 6 segundos
  const autoDismissAlerts = document.querySelectorAll('.alert-success, .alert-info');
  autoDismissAlerts.forEach(alertBox => {
    setTimeout(() => {
      if (document.body.contains(alertBox)) {
        alertBox.style.opacity = '0';
        alertBox.style.transform = 'translateY(-10px)';
        alertBox.style.transition = 'all 0.3s ease';
        setTimeout(() => alertBox.remove(), 300);
      }
    }, 6000);
  });
});
