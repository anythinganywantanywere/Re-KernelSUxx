package xx.gusss.ksu.ui.viewmodel

import android.os.Build
import android.system.Os
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import xx.gusss.ksu.BuildConfig
import xx.gusss.ksu.Natives
import xx.gusss.ksu.data.repository.SettingsRepository
import xx.gusss.ksu.data.repository.SettingsRepositoryImpl
import xx.gusss.ksu.getKernelVersion
import xx.gusss.ksu.ksuApp
import xx.gusss.ksu.ui.screen.home.HomeUiState
import xx.gusss.ksu.ui.screen.home.SystemInfo
import xx.gusss.ksu.ui.screen.home.getManagerVersion
import xx.gusss.ksu.ui.util.checkNewVersion
import xx.gusss.ksu.ui.util.getSELinuxStatusRaw
import xx.gusss.ksu.ui.util.module.LatestVersionInfo
import xx.gusss.ksu.ui.util.resolveDeviceName
import xx.gusss.ksu.ui.util.rootAvailable

class HomeViewModel(
    private val settingsRepo: SettingsRepository = SettingsRepositoryImpl()
) : ViewModel() {

    private val _uiState = MutableStateFlow(buildState())
    val uiState: StateFlow<HomeUiState> = _uiState.asStateFlow()

    fun refresh() {
        viewModelScope.launch {
            val baseState = withContext(Dispatchers.IO) { buildState() }
            _uiState.update { baseState }
            if (baseState.checkUpdateEnabled) {
                val latestVersionInfo = withContext(Dispatchers.IO) { checkNewVersion() }
                _uiState.update { it.copy(latestVersionInfo = latestVersionInfo) }
            }
        }
    }

    private fun buildState(): HomeUiState {
        val kernelVersion = getKernelVersion()
        val isManager = Natives.isManager
        val ksuVersion = if (isManager) Natives.version else null
        val kernelUAPIVersion = if (isManager) Natives.kernelUAPIVersion else null
        val managerUAPIVersion = Natives.managerUAPIVersion
        val lkmMode = ksuVersion?.let { if (kernelVersion.isGKI()) Natives.isLkmMode else null }
        val isRootAvailable = rootAvailable()
        val managerVersion = getManagerVersion(ksuApp)

        return HomeUiState(
            kernelVersion = kernelVersion,
            ksuVersion = ksuVersion,
            lkmMode = lkmMode,
            isLkmBundled = lkmMode == true && Natives.isLkmBundled,
            isManager = isManager,
            isManagerPrBuild = BuildConfig.IS_PR_BUILD,
            isKernelPrBuild = Natives.isPrBuild,
            requiresNewKernel = isManager && Natives.managerUAPIVersion > Natives.kernelUAPIVersion,
            requiresNewManager = isManager && Natives.managerUAPIVersion < Natives.kernelUAPIVersion,
            kernelUAPIVersion = kernelUAPIVersion,
            managerUAPIVersion = managerUAPIVersion,
            isRootAvailable = isRootAvailable,
            isSafeMode = Natives.isSafeMode,
            isLateLoadMode = Natives.isLateLoadMode,
            checkUpdateEnabled = settingsRepo.checkUpdate,
            latestVersionInfo = LatestVersionInfo(),
            currentManagerVersionCode = managerVersion.versionCode,
            systemInfo = SystemInfo(
                kernelVersion = Os.uname().release,
                managerVersion = "${managerVersion.versionName} (${managerVersion.versionCode}-${managerUAPIVersion})",
                deviceModel = resolveDeviceName(),
                fingerprint = Build.FINGERPRINT,
                selinuxStatus = getSELinuxStatusRaw(),
                seccompStatus = runCatching {
                    Os.prctl(21 /* PR_GET_SECCOMP */, 0, 0, 0, 0)
                }.getOrDefault(-1),
            ),
        )
    }
}
