package xx.gusss.ksu.ui.component.uninstalldialog

import androidx.compose.runtime.Composable
import xx.gusss.ksu.ui.LocalUiMode
import xx.gusss.ksu.ui.UiMode

@Composable
fun UninstallDialog(
    show: Boolean,
    onDismissRequest: () -> Unit
) {
    when (LocalUiMode.current) {
        UiMode.Miuix -> UninstallDialogMiuix(show, onDismissRequest)
        UiMode.Material -> UninstallDialogMaterial(show, onDismissRequest)
    }
}
