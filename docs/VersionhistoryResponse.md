# VersionhistoryResponse

A Versionhistory Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiVersionhistoryID** | **number** | The unique ID of the Versionhistory | [default to undefined]
**fkiModuleID** | **number** | The unique ID of the Module | [optional] [default to undefined]
**fkiModulesectionID** | **number** | The unique ID of the Modulesection | [optional] [default to undefined]
**sModuleNameX** | **string** | The Name of the Module in the language of the requester | [optional] [default to undefined]
**sModulesectionNameX** | **string** | The Name of the Modulesection in the language of the requester | [optional] [default to undefined]
**eVersionhistoryUsertype** | [**FieldEVersionhistoryUsertype**](FieldEVersionhistoryUsertype.md) |  | [optional] [default to undefined]
**objVersionhistoryDetail** | [**MultilingualVersionhistoryDetail**](MultilingualVersionhistoryDetail.md) |  | [default to undefined]
**dtVersionhistoryDate** | **string** | The date at which the Versionhistory was published or should be published | [default to undefined]
**dtVersionhistoryDateend** | **string** | The date at which the Versionhistory will no longer be visible | [optional] [default to undefined]
**eVersionhistoryType** | [**FieldEVersionhistoryType**](FieldEVersionhistoryType.md) |  | [default to undefined]
**bVersionhistoryDraft** | **boolean** | Whether the Versionhistory is published or still a draft | [default to undefined]

## Example

```typescript
import { VersionhistoryResponse } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: VersionhistoryResponse = {
    pkiVersionhistoryID,
    fkiModuleID,
    fkiModulesectionID,
    sModuleNameX,
    sModulesectionNameX,
    eVersionhistoryUsertype,
    objVersionhistoryDetail,
    dtVersionhistoryDate,
    dtVersionhistoryDateend,
    eVersionhistoryType,
    bVersionhistoryDraft,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
