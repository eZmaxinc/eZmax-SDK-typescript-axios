# ModulesectionResponseCompound

A Modulesection Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiModulesectionID** | **number** | The unique ID of the Modulesection | [default to undefined]
**fkiModuleID** | **number** | The unique ID of the Module | [default to undefined]
**sModulesectionInternalname** | **string** | The Internal name of the Module section. | [default to undefined]
**sModulesectionNameX** | **string** | The Name of the Modulesection in the language of the requester | [default to undefined]
**a_objPermission** | [**Array&lt;PermissionResponseCompound&gt;**](PermissionResponseCompound.md) |  | [optional] [default to undefined]

## Example

```typescript
import { ModulesectionResponseCompound } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: ModulesectionResponseCompound = {
    pkiModulesectionID,
    fkiModuleID,
    sModulesectionInternalname,
    sModulesectionNameX,
    a_objPermission,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
