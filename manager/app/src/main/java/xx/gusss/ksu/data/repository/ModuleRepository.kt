package xx.gusss.ksu.data.repository

import xx.gusss.ksu.data.model.Module
import xx.gusss.ksu.data.model.ModuleUpdateInfo

interface ModuleRepository {
    suspend fun getModules(): Result<List<Module>>
    suspend fun checkUpdate(module: Module): Result<ModuleUpdateInfo>
}
