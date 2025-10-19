# ModuleResponseCompound

A Module Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiModuleID** | **number** | The unique ID of the Module | [default to undefined]
**fkiModulegroupID** | **number** | The unique ID of the Modulegroup | [default to undefined]
**eModuleInternalname** | **string** | The Internal name of the Module.  This is theoretically an enum field but there are so many possibles values we decided not to list them all. | [default to undefined]
**sModuleNameX** | **string** | The Name of the Module in the language of the requester | [default to undefined]
**bModuleRegistered** | **boolean** | Whether the Module is registered or not | [default to undefined]
**bModuleRegisteredapi** | **boolean** | Whether the Module is registered or not for api use | [default to undefined]
**a_objModulesection** | [**Array&lt;ModulesectionResponseCompound&gt;**](ModulesectionResponseCompound.md) |  | [optional] [default to undefined]

## Example

```typescript
import { ModuleResponseCompound } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: ModuleResponseCompound = {
    pkiModuleID,
    fkiModulegroupID,
    eModuleInternalname,
    sModuleNameX,
    bModuleRegistered,
    bModuleRegisteredapi,
    a_objModulesection,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
