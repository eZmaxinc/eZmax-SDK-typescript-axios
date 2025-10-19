# PermissionRequestCompound

A Permission Object and children to create a complete structure

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiPermissionID** | **number** | The unique ID of the Permission | [optional] [default to undefined]
**fkiUserID** | **number** | The unique ID of the User | [optional] [default to undefined]
**fkiApikeyID** | **number** | The unique ID of the Apikey | [optional] [default to undefined]
**fkiUsergroupID** | **number** | The unique ID of the Usergroup | [optional] [default to undefined]
**fkiCompanyID** | **number** | The unique ID of the Company | [optional] [default to undefined]
**fkiModulesectionID** | **number** | The unique ID of the Modulesection | [default to undefined]

## Example

```typescript
import { PermissionRequestCompound } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: PermissionRequestCompound = {
    pkiPermissionID,
    fkiUserID,
    fkiApikeyID,
    fkiUsergroupID,
    fkiCompanyID,
    fkiModulesectionID,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
